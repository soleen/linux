// SPDX-License-Identifier: GPL-2.0
/*
 * Architecture specific CPU preservation support for ARM64.
 */
#include <linux/arm-smccc.h>
#include <linux/cpu_preserve.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/irqchip/arm-gic-v3.h>
#include <linux/kexec_handover.h>
#include <linux/kho/abi/cpu.h>
#include <linux/kvm_host.h>
#include <linux/mm.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/psci.h>
#include <linux/sched/mm.h>
#include <uapi/linux/psci.h>

#include <asm/barrier.h>
#include <asm/cacheflush.h>
#include <asm/caretaker.h>
#include <asm/cpu_ops.h>
#include <asm/daifflags.h>
#include <asm/kernel-pgtable.h>
#include <asm/kvm_asm.h>
#include <asm/pgtable.h>
#include <asm/sysreg.h>
#include <asm/tlbflush.h>
#include <asm/trans_pgd.h>
#include <asm/virt.h>

#define CARETAKER_RWP_TIMEOUT_COUNT	1000000
#define CARETAKER_SGI_MASK		GENMASK(15, 0)
#define CARETAKER_HYP_TIMER_PPI		26
#define CARETAKER_HYP_VIRT_TIMER_PPI	30
#define GICR_INT_PRIORITY(intid)	(GICR_IPRIORITYR0 + (intid))
#define CARETAKER_MAX_RDIST_REGIONS	8

#define MPIDR_TO_SGI_AFFINITY(cluster_id, level) \
	(MPIDR_AFFINITY_LEVEL(cluster_id, level) \
		<< ICC_SGI1R_AFFINITY_## level ##_SHIFT)
#define MPIDR_TO_SGI_CLUSTER_ID(mpidr)	((mpidr) & ~0xFUL)
#define MPIDR_RS(mpidr)			(((mpidr) & 0xf0ULL) >> 4)
#define MPIDR_TO_SGI_RS(mpidr)		(MPIDR_RS(mpidr) << ICC_SGI1R_RS_SHIFT)

struct caretaker_rdist_region {
	phys_addr_t	pa;
	void __iomem	*va;
	size_t		size;
};

struct caretaker_gic_state {
	void __iomem			*cpu_rdist[NR_CPUS];
	struct caretaker_rdist_region	regions[CARETAKER_MAX_RDIST_REGIONS];
	int				nr_regions;
};

static enum arm_smccc_conduit arm64_psci_conduit __cpu_preserved_data;
phys_addr_t arm64_caretaker_pgd_pa __cpu_preserved_data;
static u64 arm64_cpu_mpidr[NR_CPUS] __cpu_preserved_data;
static struct caretaker_gic_state caretaker_gic __cpu_preserved_data;
__cpu_preserved_data bool arm64_caretaker_has_ptrauth;
EXPORT_SYMBOL_GPL(arm64_caretaker_has_ptrauth);

static void arm64_caretaker_gic_init(void);

/*
 * Signal or wake up a preserved physical CPU via SEV.
 */
void __cpu_preserved_text arch_cpu_preserved_kick(int cpu)
{
	dsb(ishst);
	sev();
	gicv3_caretaker_kick_cpu(cpu);
	isb();
}

/*
 * Low-power wait in parking loop.
 */
void __cpu_preserved_text arch_cpu_preserved_park_wait(void)
{
	wfe();
}

int __cpu_preserved_text arch_cpu_preserved_mpidr_to_cpu(u64 mpidr)
{
	int c;

	for (c = 0; c < ARRAY_SIZE(arm64_cpu_mpidr); c++) {
		if ((arm64_cpu_mpidr[c] & MPIDR_HWID_BITMASK) == (mpidr & MPIDR_HWID_BITMASK))
			return c;
	}
	return -EINVAL;
}
EXPORT_SYMBOL_GPL(arch_cpu_preserved_mpidr_to_cpu);

__cpu_preserved_text static void __iomem *gicv3_get_rdist_for_cpu(int cpu)
{
	if (cpu < 0) {
		u64 mpidr = read_sysreg(mpidr_el1) & MPIDR_HWID_BITMASK;

		cpu = arch_cpu_preserved_mpidr_to_cpu(mpidr);
	}
	if (cpu >= 0 && cpu < ARRAY_SIZE(caretaker_gic.cpu_rdist))
		return caretaker_gic.cpu_rdist[cpu];
	return NULL;
}

__cpu_preserved_text static inline void
gicv3_caretaker_wait_for_rwp(void __iomem *base, u32 bit)
{
	int count = CARETAKER_RWP_TIMEOUT_COUNT;

	while (count-- > 0) {
		if (!(readl_relaxed(base + GICR_CTLR) & bit))
			return;
		cpu_relax();
	}
}

__cpu_preserved_text void gicv3_caretaker_clear_active_priorities(void)
{
	u32 ctlr = read_sysreg_s(SYS_ICC_CTLR_EL1);
	u32 pribits = ((ctlr & ICC_CTLR_EL1_PRI_BITS_MASK) >>
		       ICC_CTLR_EL1_PRI_BITS_SHIFT) + 1;

	switch (pribits) {
	case 8:
	case 7:
		write_sysreg_s(0, SYS_ICC_AP1R3_EL1);
		write_sysreg_s(0, SYS_ICC_AP1R2_EL1);
		fallthrough;
	case 6:
		write_sysreg_s(0, SYS_ICC_AP1R1_EL1);
		fallthrough;
	case 5:
	case 4:
	default:
		write_sysreg_s(0, SYS_ICC_AP1R0_EL1);
		break;
	}
	isb();
}
EXPORT_SYMBOL_GPL(gicv3_caretaker_clear_active_priorities);

__cpu_preserved_text void gicv3_caretaker_enable_sgi(void)
{
	void __iomem *ptr = gicv3_get_rdist_for_cpu(-1);

	if (ptr) {
		void __iomem *rbase = ptr + SZ_64K;

		writel_relaxed(~0U, rbase + GICR_IGROUPR0);
		writel_relaxed(0, rbase + GICR_IGRPMODR0);
		writeb_relaxed(0x00, rbase + GICR_INT_PRIORITY(0));
		writeb_relaxed(0x00, rbase + GICR_INT_PRIORITY(CARETAKER_HYP_TIMER_PPI));
		writeb_relaxed(0x00, rbase + GICR_INT_PRIORITY(CARETAKER_HYP_VIRT_TIMER_PPI));
		writel_relaxed(CARETAKER_SGI_MASK |
			       BIT(CARETAKER_HYP_TIMER_PPI) |
			       BIT(CARETAKER_HYP_VIRT_TIMER_PPI),
			       rbase + GICR_ISENABLER0);
		writel_relaxed(~0U, rbase + GICR_ICACTIVER0);
		gicv3_caretaker_wait_for_rwp(ptr, GICR_CTLR_RWP);
	}

	write_sysreg_s(0, SYS_ICC_BPR1_EL1);
	gicv3_caretaker_clear_active_priorities();
}
EXPORT_SYMBOL_GPL(gicv3_caretaker_enable_sgi);

__cpu_preserved_text void gicv3_caretaker_clear_sgi(void)
{
	void __iomem *ptr = gicv3_get_rdist_for_cpu(-1);

	if (ptr) {
		void __iomem *rbase = ptr + SZ_64K;

		writel_relaxed(~0U, rbase + GICR_ICPENDR0);
		writel_relaxed(~0U, rbase + GICR_ICACTIVER0);
		gicv3_caretaker_wait_for_rwp(ptr, GICR_CTLR_RWP);
	}
}
EXPORT_SYMBOL_GPL(gicv3_caretaker_clear_sgi);

__cpu_preserved_text void gicv3_caretaker_kick_cpu(int cpu)
{
	void __iomem *ptr;
	u64 mpidr, cluster_id;
	u16 tlist;

	if (cpu < 0 || cpu >= ARRAY_SIZE(arm64_cpu_mpidr))
		return;
	if (!arch_cpu_preserved_is_active() && !caretaker_gic.nr_regions)
		arm64_caretaker_gic_init();

	mpidr = arm64_cpu_mpidr[cpu];
	if ((mpidr & MPIDR_HWID_BITMASK) == (read_sysreg(mpidr_el1) & MPIDR_HWID_BITMASK))
		return;

	ptr = gicv3_get_rdist_for_cpu(cpu);
	if (ptr) {
		void __iomem *sgi_base = ptr + SZ_64K;
		u32 val = readl_relaxed(ptr + GICR_WAKER);

		if (val & GICR_WAKER_ProcessorSleep) {
			int count = CARETAKER_RWP_TIMEOUT_COUNT;

			val &= ~GICR_WAKER_ProcessorSleep;
			writel_relaxed(val, ptr + GICR_WAKER);
			while (count-- > 0) {
				val = readl_relaxed(ptr + GICR_WAKER);
				if (!(val & GICR_WAKER_ChildrenAsleep))
					break;
				cpu_relax();
			}
		}

		writel_relaxed(~0U, sgi_base + GICR_IGROUPR0);
		writel_relaxed(0, sgi_base + GICR_IGRPMODR0);
		writel_relaxed(0, sgi_base + GICR_INT_PRIORITY(0));
		writel_relaxed(0, sgi_base + GICR_INT_PRIORITY(4));
		writel_relaxed(0, sgi_base + GICR_INT_PRIORITY(8));
		writel_relaxed(0, sgi_base + GICR_INT_PRIORITY(12));
		writel_relaxed(CARETAKER_SGI_MASK | BIT(CARETAKER_HYP_TIMER_PPI),
			       sgi_base + GICR_ISENABLER0);
		gicv3_caretaker_wait_for_rwp(ptr, GICR_CTLR_RWP);
	}

	cluster_id = MPIDR_TO_SGI_CLUSTER_ID(mpidr);
	tlist = 1 << (mpidr & 0xf);

	dsb(ishst);
	{
		u64 val = (MPIDR_TO_SGI_AFFINITY(cluster_id, 3) |
			   MPIDR_TO_SGI_AFFINITY(cluster_id, 2) |
			   (0ULL << ICC_SGI1R_SGI_ID_SHIFT) |
			   MPIDR_TO_SGI_AFFINITY(cluster_id, 1) |
			   MPIDR_TO_SGI_RS(cluster_id) |
			   ((u64)tlist << ICC_SGI1R_TARGET_LIST_SHIFT));

		write_sysreg_s(val, SYS_ICC_SGI1R_EL1);
	}
	isb();
}
EXPORT_SYMBOL_GPL(gicv3_caretaker_kick_cpu);

static void arm64_add_gicr_region(phys_addr_t pa, size_t size, u64 stride)
{
	void __iomem *va, *ptr;
	size_t map_size;
	int i;

	for (i = 0; i < caretaker_gic.nr_regions; i++)
		if (caretaker_gic.regions[i].pa == pa)
			return;

	if (caretaker_gic.nr_regions >= ARRAY_SIZE(caretaker_gic.regions))
		return;

	map_size = max_t(size_t, size, nr_cpu_ids * (stride ? : SZ_128K));
	va = ioremap(pa, map_size);
	if (!va)
		return;

	i = caretaker_gic.nr_regions++;
	caretaker_gic.regions[i].pa = pa;
	caretaker_gic.regions[i].va = va;
	caretaker_gic.regions[i].size = map_size;

	ptr = va;
	do {
		u64 typer = readq_relaxed(ptr + GICR_TYPER);
		u32 aff = typer >> 32;
		int cpu;
		bool last = !!(typer & GICR_TYPER_LAST);

		for_each_possible_cpu(cpu) {
			u64 mpidr = cpu_logical_map(cpu);
			u32 cpu_aff = (MPIDR_AFFINITY_LEVEL(mpidr, 3) << 24) |
				      (MPIDR_AFFINITY_LEVEL(mpidr, 2) << 16) |
				      (MPIDR_AFFINITY_LEVEL(mpidr, 1) << 8) |
				      MPIDR_AFFINITY_LEVEL(mpidr, 0);
			if (aff == cpu_aff)
				caretaker_gic.cpu_rdist[cpu] = ptr;
		}

		if (stride) {
			ptr += stride;
		} else {
			ptr += SZ_64K * 2;
			if (typer & GICR_TYPER_VLPIS)
				ptr += SZ_64K * 2;
		}
		if (last)
			break;
	} while ((ptr - va) < map_size);

	cpu_preserved_clean(&caretaker_gic);
}

static void arm64_discover_gicr_res(struct resource *res)
{
	for (; res; res = res->sibling) {
		if (res->name && !strcmp(res->name, "GICR"))
			arm64_add_gicr_region(res->start, resource_size(res), 0);
		if (res->child)
			arm64_discover_gicr_res(res->child);
	}
}

static void arm64_caretaker_gic_init(void)
{
	struct device_node *node;

	if (caretaker_gic.nr_regions > 0 || arch_cpu_preserved_is_active())
		return;

	node = of_find_compatible_node(NULL, NULL, "arm,gic-v3");
	if (node) {
		u32 nr_redist_regions = 1;
		u64 stride = 0;
		int i;

		of_property_read_u32(node, "#redistributor-regions",
				     &nr_redist_regions);
		of_property_read_u64(node, "redistributor-stride", &stride);
		for (i = 0; i < nr_redist_regions; i++) {
			struct resource res;

			if (of_address_to_resource(node, 1 + i, &res) == 0)
				arm64_add_gicr_region(res.start,
						      resource_size(&res),
						      stride);
		}
		of_node_put(node);
	}

	if (caretaker_gic.nr_regions == 0)
		arm64_discover_gicr_res(&iomem_resource);
}

int gicv3_caretaker_get_redist_region(int idx, phys_addr_t *pa,
				      unsigned long *va, size_t *size)
{
	arm64_caretaker_gic_init();
	if (idx < 0 || idx >= caretaker_gic.nr_regions)
		return -ENOENT;

	*pa = caretaker_gic.regions[idx].pa;
	*va = (unsigned long)caretaker_gic.regions[idx].va;
	*size = caretaker_gic.regions[idx].size;
	return 0;
}
EXPORT_SYMBOL_GPL(gicv3_caretaker_get_redist_region);

bool __cpu_preserved_text arch_cpu_preserved_is_active(void)
{
	struct cpu_preserved_stack_context *sctx = cpu_preserved_get_stack_context();
	u64 ttbr1 = read_sysreg(ttbr1_el1);

	if (sctx && sctx->session_pgd_pa && ttbr1 == sctx->session_pgd_pa)
		return true;

	if (arm64_caretaker_pgd_pa)
		return ttbr1 == arm64_caretaker_pgd_pa;

	return false;
}
EXPORT_SYMBOL_GPL(arch_cpu_preserved_is_active);

void __cpu_preserved_text arch_cpu_preserved_switch_pgd(phys_addr_t pgd_pa)
{
	if (pgd_pa && read_sysreg(ttbr1_el1) != pgd_pa) {
		write_sysreg(pgd_pa, ttbr1_el1);
		isb();
		arm64_flush_host_tlb_local();
	}
}
EXPORT_SYMBOL_GPL(arch_cpu_preserved_switch_pgd);

static pte_t *arm64_get_kernel_pte(unsigned long addr)
{
	pgd_t *pgdp = pgd_offset_k(addr);
	p4d_t *p4dp;
	pud_t *pudp;
	pmd_t *pmdp;

	if (pgd_none(READ_ONCE(*pgdp)))
		return NULL;

	p4dp = p4d_offset(pgdp, addr);
	if (p4d_none(READ_ONCE(*p4dp)))
		return NULL;

	pudp = pud_offset(p4dp, addr);
	if (pud_none(READ_ONCE(*pudp)) || pud_leaf(READ_ONCE(*pudp)))
		return NULL;

	pmdp = pmd_offset(pudp, addr);
	if (pmd_none(READ_ONCE(*pmdp)) || pmd_leaf(READ_ONCE(*pmdp)))
		return NULL;

	return pte_offset_kernel(pmdp, addr);
}

/**
 * arch_cpu_preserved_as_map - Populate an isolated page table on arm64
 * @as: Address space to map into.
 * @pa: Physical address of the range.
 * @va: Virtual address the range must appear at.
 * @size: Size of the range in bytes.
 * @prot: Protection to apply.
 *
 * Return: 0 on success, or a negative errno on failure.
 */
int arch_cpu_preserved_as_map(struct cpu_preserved_as *as, phys_addr_t pa,
			      unsigned long va, size_t size, pgprot_t prot)
{
	struct trans_pgd_info info = {
		.trans_alloc_page = cpu_preserved_as_alloc_page,
		.trans_alloc_arg = as,
	};
	unsigned long offset = va & ~PAGE_MASK;
	size_t page_size = PAGE_ALIGN(offset + size);
	unsigned long page_va = va & PAGE_MASK;
	phys_addr_t page_pa = (pa & PAGE_MASK);

	return trans_pgd_map_range(&info, as->pgd, page_pa,
				   page_va, page_size, prot);
}

void arch_cpu_preserved_as_flush_tlb(void)
{
	arm64_flush_host_tlb_all();
}

void arch_cpu_preserved_set_transition_as(struct cpu_preserved_as *as)
{
	arm64_caretaker_pgd_pa = as ? as->pgd_pa : 0;
	cpu_preserved_clean(&arm64_caretaker_pgd_pa);
}

/**
 * arch_cpu_preserved_setup_buffer - Set up runtime buffer and page tables
 * @text_page: Runtime-allocated physical page backing preserved text
 * @text_nr_pages: Number of pages in text buffer
 * @data_page: Runtime-allocated physical page backing preserved data
 * @data_nr_pages: Number of pages in data buffer
 *
 * Remap init_mm kernel mappings for __cpu_preserved_text and
 * __cpu_preserved_data to point to the runtime-allocated pages outside
 * Scratch.
 *
 * Return: 0 on success, or -ENOMEM on failure.
 */
static void arm64_split_contpte_range(unsigned long start, unsigned long end)
{
	unsigned long addr;

	if (start >= end)
		return;

	for (addr = ALIGN_DOWN(start, CONT_PTE_SIZE); addr < end; addr += CONT_PTE_SIZE) {
		pte_t *ptep = arm64_get_kernel_pte(addr);
		int i;

		if (!ptep)
			continue;

		ptep = PTR_ALIGN_DOWN(ptep, sizeof(*ptep) * CONT_PTES);

		for (i = 0; i < CONT_PTES; i++) {
			pte_t pte = __ptep_get(&ptep[i]);

			if (pte_valid_cont(pte))
				__set_pte(&ptep[i], pte_mknoncont(pte));
		}
	}

	flush_tlb_kernel_range(ALIGN_DOWN(start, CONT_PTE_SIZE),
			       ALIGN(end, CONT_PTE_SIZE));
	arm64_flush_host_tlb_all();
}

int arch_cpu_preserved_setup_buffer(struct page *text_page,
				    unsigned int text_nr_pages,
				    struct page *data_page,
				    unsigned int data_nr_pages)
{
	unsigned long text_start = (unsigned long)__cpu_preserved_text_start;
	unsigned long data_start = (unsigned long)__cpu_preserved_data_start;
	unsigned int i;

	/* Split any contiguous 64KB mappings before replacing individual PTEs */
	arm64_split_contpte_range(text_start, text_start + text_nr_pages * PAGE_SIZE);
	arm64_split_contpte_range(data_start, data_start + data_nr_pages * PAGE_SIZE);

	/* Clean old mappings before switching PTEs */
	__arch_cpu_preserved_dcache_clean(text_start, text_start + text_nr_pages * PAGE_SIZE);
	__arch_cpu_preserved_dcache_clean(data_start, data_start + data_nr_pages * PAGE_SIZE);

	/* Remap init_mm kernel mappings to point to allocated buffer pages */
	for (i = 0; i < text_nr_pages; i++) {
		unsigned long va = text_start + i * PAGE_SIZE;
		pte_t *ptep = arm64_get_kernel_pte(va);

		if (!ptep)
			return -EINVAL;

		pgprot_t prot = __pgprot(pgprot_val(pte_pgprot(*ptep)) & ~PTE_CONT);
		phys_addr_t pa = page_to_phys(text_page) + i * PAGE_SIZE;

		set_pte_at(&init_mm, va, ptep, pfn_pte(PHYS_PFN(pa), prot));
	}

	for (i = 0; i < data_nr_pages; i++) {
		unsigned long va = data_start + i * PAGE_SIZE;
		pte_t *ptep = arm64_get_kernel_pte(va);

		if (!ptep)
			return -EINVAL;

		pgprot_t prot = __pgprot(pgprot_val(pte_pgprot(*ptep)) & ~PTE_CONT);
		phys_addr_t pa = page_to_phys(data_page) + i * PAGE_SIZE;

		set_pte_at(&init_mm, va, ptep, pfn_pte(PHYS_PFN(pa), prot));
	}

	arm64_flush_host_tlb_all();
	flush_icache_range(text_start, text_start + (text_nr_pages * PAGE_SIZE));

	for (i = 0; i < nr_cpu_ids; i++)
		arm64_cpu_mpidr[i] = cpu_logical_map(i);
	cpu_preserved_clean(&arm64_cpu_mpidr);
	arm64_caretaker_gic_init();

	return 0;
}

/*
 * Masks DAIF interrupts and enables GIC CPU interface for WFx wakeups.
 */
void __cpu_preserved_text arch_cpu_preserved_park_init(int cpu)
{
	struct cpu_preserved_stack_context *sctx = cpu_preserved_get_stack_context();
	phys_addr_t pgd_pa = 0;

	if (sctx && sctx->session_pgd_pa)
		pgd_pa = sctx->session_pgd_pa;
	else
		pgd_pa = cpu_preserved_get_pgd(cpu);

	local_daif_mask();
	cpu_preserved_inval(&arm64_psci_conduit);
	cpu_preserved_inval(&arm64_cpu_mpidr);
	cpu_preserved_inval(&caretaker_gic);
	if (!pgd_pa) {
		cpu_preserved_inval(&arm64_caretaker_pgd_pa);
		pgd_pa = READ_ONCE(arm64_caretaker_pgd_pa);
	}

#if IS_ENABLED(CONFIG_KVM_CARETAKER)
	write_sysreg((unsigned long)caretaker_hyp_vector, vbar_el1);
	write_sysreg_s((unsigned long)caretaker_hyp_vector, SYS_VBAR_EL2);
	isb();
#endif

	write_sysreg(0, ttbr0_el1);
	if (pgd_pa)
		write_sysreg(pgd_pa, ttbr1_el1);
	isb();
	arm64_flush_host_tlb_local();

	write_sysreg_s(0xff, SYS_ICC_PMR_EL1);
	isb();

	write_sysreg_s(1, SYS_ICC_IGRPEN1_EL1);
	isb();
}

void arch_cpu_preserved_early_init(void)
{
	int c;

	for (c = 0; c < ARRAY_SIZE(arm64_cpu_mpidr); c++)
		arm64_cpu_mpidr[c] = cpu_logical_map(c);
	cpu_preserved_clean(&arm64_cpu_mpidr);
	arm64_caretaker_gic_init();

	cpu_preserved_inval(&arm64_psci_conduit);
	if (arm64_psci_conduit == SMCCC_CONDUIT_NONE) {
		arm64_psci_conduit = arm_smccc_1_1_get_conduit();
		cpu_preserved_clean(&arm64_psci_conduit);
	}

	arm64_caretaker_has_ptrauth = IS_ENABLED(CONFIG_ARM64_PTR_AUTH) &&
				      system_has_full_ptr_auth();
	cpu_preserved_clean(&arm64_caretaker_has_ptrauth);
}
EXPORT_SYMBOL_GPL(arch_cpu_preserved_early_init);

void __cpu_preserved_text arch_cpu_preserved_park_finish(int cpu)
{
	u32 el = (read_sysreg(CurrentEL) >> 2) & 3;
	enum arm_smccc_conduit conduit;

	cpu_preserved_inval(&arm64_psci_conduit);
	conduit = READ_ONCE(arm64_psci_conduit);

	local_daif_mask();
	write_sysreg_s(0, SYS_ICC_PMR_EL1);
	write_sysreg_s(0, SYS_ICC_IGRPEN1_EL1);
	isb();

	if (el == 2 || conduit == SMCCC_CONDUIT_NONE)
		conduit = (el == 2) ? SMCCC_CONDUIT_SMC : SMCCC_CONDUIT_HVC;

	/*
	 * Direct PSCI CPU_OFF call in preserved text without relying on
	 * unpreserved kernel data structures or function pointers.
	 *
	 * x0: PSCI_0_2_FN_CPU_OFF (0x84000002)
	 * x1: Power down state (0x00010000)
	 */
	if (conduit == SMCCC_CONDUIT_HVC) {
		asm volatile(
			"mov	x0, #0x0002\n"
			"movk	x0, #0x8400, lsl #16\n"
			"mov	x1, #0\n"
			"mov	x2, #0\n"
			"mov	x3, #0\n"
			"mov	x4, #0\n"
			"mov	x5, #0\n"
			"mov	x6, #0\n"
			"mov	x7, #0\n"
			"hvc	#0\n"
			:
			:
			: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "memory"
		);
	} else {
		asm volatile(
			"mov	x0, #0x0002\n"
			"movk	x0, #0x8400, lsl #16\n"
			"mov	x1, #0\n"
			"mov	x2, #0\n"
			"mov	x3, #0\n"
			"mov	x4, #0\n"
			"mov	x5, #0\n"
			"mov	x6, #0\n"
			"mov	x7, #0\n"
			"smc	#0\n"
			:
			:
			: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "memory"
		);
	}

	while (1) {
		wfi();
		wfe();
	}
}

void arch_cpu_preserved_wait_dead(int cpu)
{
	const struct cpu_operations *ops = get_cpu_ops(cpu);

	if (ops && ops->cpu_kill)
		ops->cpu_kill(cpu);
}

