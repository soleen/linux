// SPDX-License-Identifier: GPL-2.0
/*
 * Architecture specific CPU preservation support for ARM64.
 */
#include <linux/arm-smccc.h>
#include <linux/cpu_preserve.h>
#include <linux/irqchip/arm-gic-v3.h>
#include <linux/kexec_handover.h>
#include <linux/kho/abi/cpu.h>
#include <linux/kvm_host.h>
#include <linux/mm.h>
#include <linux/oncore.h>
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

static LIST_HEAD(arm64_caretaker_pages);
static DEFINE_MUTEX(arm64_caretaker_map_lock);
static enum arm_smccc_conduit arm64_psci_conduit __cpu_preserved_data;
static pgd_t *arm64_caretaker_pgd __cpu_preserved_data;
phys_addr_t arm64_caretaker_pgd_pa __cpu_preserved_data;
static phys_addr_t preserved_text_pa;
static unsigned long preserved_text_sz;
static phys_addr_t preserved_data_pa;
static unsigned long preserved_data_sz;
static u64 arm64_cpu_mpidr[NR_CPUS] __cpu_preserved_data;
__cpu_preserved_data bool arm64_caretaker_has_ptrauth;
EXPORT_SYMBOL_GPL(arm64_caretaker_has_ptrauth);

u64 __cpu_preserved_text arch_cpu_preserved_get_mpidr(int cpu)
{
	if ((unsigned int)cpu < ARRAY_SIZE(arm64_cpu_mpidr))
		return arm64_cpu_mpidr[cpu];
	return INVALID_HWID;
}
EXPORT_SYMBOL_GPL(arch_cpu_preserved_get_mpidr);

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

static void *arm64_caretaker_alloc_page(void *arg)
{
	void *ptr = kho_alloc_preserve(PAGE_SIZE);
	struct page *page;

	if (IS_ERR(ptr)) {
		page = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!page)
			return NULL;
		ptr = page_address(page);
		kho_preserve_pages(page, 1);
	} else {
		page = virt_to_page(ptr);
	}

	__arch_cpu_preserved_dcache_clean((unsigned long)ptr,
					  (unsigned long)ptr + PAGE_SIZE);

	list_add(&page->lru, &arm64_caretaker_pages);
	return ptr;
}

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

static int arm64_caretaker_map_range(struct trans_pgd_info *info,
				    phys_addr_t pa, unsigned long va,
				    size_t size, pgprot_t prot)
{
	unsigned long offset = va & ~PAGE_MASK;
	size_t page_size = PAGE_ALIGN(offset + size);
	unsigned long page_va = va & PAGE_MASK;
	phys_addr_t page_pa = (pa & PAGE_MASK);

	if (!arm64_caretaker_pgd || !size)
		return 0;

	return trans_pgd_map_range(info, arm64_caretaker_pgd, page_pa,
				  page_va, page_size, prot);
}

int arch_cpu_preserved_map_range(phys_addr_t pa, unsigned long va,
				 size_t size, pgprot_t prot)
{
	struct trans_pgd_info info = {
		.trans_alloc_page = arm64_caretaker_alloc_page,
	};
	struct page *page;
	int ret;

	if (!arm64_caretaker_pgd)
		return -EINVAL;

	scoped_guard(mutex, &arm64_caretaker_map_lock) {
		ret = arm64_caretaker_map_range(&info, pa, va, size, prot);
		if (ret)
			return ret;

		list_for_each_entry(page, &arm64_caretaker_pages, lru) {
			unsigned long addr = (unsigned long)page_address(page);

			__arch_cpu_preserved_dcache_clean(addr, addr + PAGE_SIZE);
			kho_preserve_pages(page, 1);
		}

		arm64_flush_host_tlb_all();
	}

	return 0;
}
EXPORT_SYMBOL_GPL(arch_cpu_preserved_map_range);

/**
 * arch_cpu_preserved_setup_buffer - Set up runtime buffer and page tables
 * @text_page: Runtime-allocated physical page backing preserved text
 * @text_nr_pages: Number of pages in text buffer
 * @data_page: Runtime-allocated physical page backing preserved data
 * @data_nr_pages: Number of pages in data buffer
 *
 * Remap init_mm kernel mappings for __cpu_preserved_text and
 * __cpu_preserved_data to point to the runtime-allocated pages outside
 * Scratch. Then allocate a fresh root PGD to construct isolated Caretaker
 * page tables mapping strictly the preserved text, data, stacks, and vCPU
 * contexts.
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
	struct trans_pgd_info info = {
		.trans_alloc_page = arm64_caretaker_alloc_page,
	};
	unsigned int i;
	int ret;

	if (arm64_caretaker_pgd)
		return 0;

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

	preserved_text_pa = page_to_phys(text_page);
	preserved_text_sz = (unsigned long)__cpu_preserved_text_end - text_start;
	preserved_data_pa = page_to_phys(data_page);
	preserved_data_sz = (unsigned long)__cpu_preserved_data_end - data_start;

	/* Allocate empty root PGD for isolated Caretaker page tables */
	arm64_caretaker_pgd = arm64_caretaker_alloc_page(NULL);
	if (!arm64_caretaker_pgd)
		return -ENOMEM;

	ret = arm64_caretaker_map_range(&info, preserved_text_pa, text_start,
					preserved_text_sz, PAGE_KERNEL_ROX);
	if (ret)
		return ret;

	ret = arm64_caretaker_map_range(&info, preserved_data_pa, data_start,
					preserved_data_sz, PAGE_KERNEL);
	if (ret)
		return ret;

	for (i = 0; i < nr_cpu_ids; i++)
		arm64_cpu_mpidr[i] = cpu_logical_map(i);
	arch_cpu_preserved_dcache_clean((unsigned long)arm64_cpu_mpidr,
					(unsigned long)arm64_cpu_mpidr + sizeof(arm64_cpu_mpidr));

	arm64_caretaker_pgd_pa = virt_to_phys(arm64_caretaker_pgd);
	arch_cpu_preserved_dcache_clean((unsigned long)&arm64_caretaker_pgd,
					(unsigned long)&arm64_caretaker_pgd +
					sizeof(arm64_caretaker_pgd));
	arch_cpu_preserved_dcache_clean((unsigned long)&arm64_caretaker_pgd_pa,
					(unsigned long)&arm64_caretaker_pgd_pa +
					sizeof(arm64_caretaker_pgd_pa));

	return 0;
}

void *arch_cpu_preserved_get_pgd(void)
{
	return arm64_caretaker_pgd;
}
EXPORT_SYMBOL_GPL(arch_cpu_preserved_get_pgd);

void arch_oncore_flush_tlb(struct oncore_session *sess)
{
	arm64_flush_host_tlb_all();
}
EXPORT_SYMBOL_GPL(arch_oncore_flush_tlb);

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
	arch_cpu_preserved_dcache_inval((unsigned long)&arm64_psci_conduit,
					(unsigned long)&arm64_psci_conduit +
					sizeof(arm64_psci_conduit));
	arch_cpu_preserved_dcache_inval((unsigned long)arm64_cpu_mpidr,
					(unsigned long)arm64_cpu_mpidr +
					sizeof(arm64_cpu_mpidr));
	if (!pgd_pa) {
		arch_cpu_preserved_dcache_inval((unsigned long)&arm64_caretaker_pgd_pa,
						(unsigned long)&arm64_caretaker_pgd_pa +
						sizeof(arm64_caretaker_pgd_pa));
		pgd_pa = READ_ONCE(arm64_caretaker_pgd_pa);
	}

	write_sysreg((unsigned long)caretaker_hyp_vector, vbar_el1);
	write_sysreg_s((unsigned long)caretaker_hyp_vector, SYS_VBAR_EL2);
	isb();

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
	arch_cpu_preserved_dcache_clean((unsigned long)arm64_cpu_mpidr,
					(unsigned long)arm64_cpu_mpidr +
					sizeof(arm64_cpu_mpidr));

	arch_cpu_preserved_dcache_inval((unsigned long)&arm64_psci_conduit,
					(unsigned long)&arm64_psci_conduit +
					sizeof(arm64_psci_conduit));
	if (arm64_psci_conduit == SMCCC_CONDUIT_NONE) {
		arm64_psci_conduit = arm_smccc_1_1_get_conduit();
		arch_cpu_preserved_dcache_clean((unsigned long)&arm64_psci_conduit,
						(unsigned long)&arm64_psci_conduit +
						sizeof(arm64_psci_conduit));
	}

	arm64_caretaker_has_ptrauth = IS_ENABLED(CONFIG_ARM64_PTR_AUTH) &&
				      system_has_full_ptr_auth();
	arch_cpu_preserved_dcache_clean((unsigned long)&arm64_caretaker_has_ptrauth,
					(unsigned long)&arm64_caretaker_has_ptrauth +
					sizeof(arm64_caretaker_has_ptrauth));
}
EXPORT_SYMBOL_GPL(arch_cpu_preserved_early_init);

void __cpu_preserved_text arch_cpu_preserved_park_finish(int cpu)
{
	u32 el = (read_sysreg(CurrentEL) >> 2) & 3;
	enum arm_smccc_conduit conduit;

	arch_cpu_preserved_dcache_inval((unsigned long)&arm64_psci_conduit,
					(unsigned long)&arm64_psci_conduit +
					sizeof(arm64_psci_conduit));
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

void __cpu_preserved_text arch_cpu_preserved_park_cancel(int cpu)
{
	arch_cpu_preserved_park_finish(cpu);
}

/*
 * Preserves kernel page tables backing caretaker execution.
 */
void arch_cpu_preserved_preserve_pagetables(void)
{
	struct page *page;

	guard(mutex)(&arm64_caretaker_map_lock);
	if (!arm64_caretaker_pgd)
		return;

	list_for_each_entry(page, &arm64_caretaker_pages, lru)
		kho_preserve_pages(page, 1);
}

void arch_cpu_preserved_unpreserve_pagetables(void)
{
	struct page *page;

	guard(mutex)(&arm64_caretaker_map_lock);
	if (!arm64_caretaker_pgd)
		return;

	list_for_each_entry(page, &arm64_caretaker_pages, lru)
		kho_unpreserve_pages(page, 1);
}

void arch_cpu_preserved_wait_dead(int cpu)
{
	const struct cpu_operations *ops = get_cpu_ops(cpu);

	if (ops && ops->cpu_kill)
		ops->cpu_kill(cpu);
}

u64 __cpu_preserved_text arch_oncore_ticks_to_ns(u64 ticks)
{
	u32 cntfrq = arch_timer_get_cntfrq();

	if (cntfrq > 0)
		return mul_u64_u32_div(ticks, 1000000000U, cntfrq);
	return ticks;
}
EXPORT_SYMBOL_GPL(arch_oncore_ticks_to_ns);

void arch_oncore_update_quantum_ticks(struct oncore_sched_config *cfg)
{
	u32 cntfrq = arch_timer_get_cntfrq();
	u32 ms = cfg->quantum_ms;

	if (cntfrq > 0)
		cfg->quantum_ticks = ((u64)ms * cntfrq) / 1000ULL;
	else
		cfg->quantum_ticks = (u64)ms * 25000000ULL / 1000ULL;
}
EXPORT_SYMBOL_GPL(arch_oncore_update_quantum_ticks);

