// SPDX-License-Identifier: GPL-2.0
/*
 * Architecture specific CPU preservation support for ARM64.
 */
#include <linux/arm-smccc.h>
#include <linux/cpu_preserve.h>
#include <linux/mm.h>
#include <linux/psci.h>
#include <linux/sched/mm.h>
#include <uapi/linux/psci.h>
#include <linux/irqchip/arm-gic-v3.h>
#include <asm/barrier.h>
#include <asm/cacheflush.h>
#include <asm/caretaker.h>
#include <linux/caretaker.h>
#include <linux/kvm_host.h>
#include <asm/cpu_ops.h>
#include <asm/daifflags.h>
#include <asm/kernel-pgtable.h>
#include <asm/kvm_asm.h>
#include <asm/pgtable.h>
#include <asm/sysreg.h>
#include <asm/tlbflush.h>
#include <asm/virt.h>
asmlinkage void __arch_cpu_preserved_dcache_clean(unsigned long start, unsigned long end);

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

#include <linux/kexec_handover.h>
#include <linux/kho/abi/cpu.h>
#include <asm/trans_pgd.h>

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
struct arm64_caretaker_diag arm64_caretaker_diag[NR_CPUS] __cpu_preserved_data;
EXPORT_SYMBOL_GPL(arm64_caretaker_diag);

void __cpu_preserved_text arch_cpu_preserved_set_stage(int cpu, u64 stage, u64 sub_stage)
{
	if (cpu < 0 || cpu >= NR_CPUS)
		cpu = arm64_caretaker_get_pcpu();
	if (cpu >= 0 && cpu < NR_CPUS) {
		struct arm64_caretaker_diag *d = &arm64_caretaker_diag[cpu];
		d->stage = stage;
		d->sub_stage = sub_stage;
		__arch_cpu_preserved_dcache_clean((unsigned long)d, (unsigned long)(d + 1));
	}
}
EXPORT_SYMBOL_GPL(arch_cpu_preserved_set_stage);

ssize_t arch_cpu_preserved_diag_show(int cpu, char *buf)
{
	struct arm64_caretaker_diag *d;
	void __iomem *rdist;
	u32 isenabler = 0;

	if (cpu < 0 || cpu >= NR_CPUS)
		return -EINVAL;

	d = &arm64_caretaker_diag[cpu];
	arch_cpu_preserved_dcache_inval((unsigned long)d, (unsigned long)(d + 1));
	arch_cpu_preserved_dcache_inval((unsigned long)&arm64_caretaker_faults[cpu],
					(unsigned long)(&arm64_caretaker_faults[cpu] + 1));

	rdist = gicv3_get_rdist_for_cpu(cpu);
	if (rdist)
		isenabler = readl_relaxed(rdist + SZ_64K + GICR_ISENABLER0);

	return sysfs_emit(buf,
			  "enter_count: %llu\n"
			  "exit_count: %llu\n"
			  "last_enter_ticks: %llu\n"
			  "last_exit_ticks: %llu\n"
			  "last_ret: 0x%llx\n"
			  "last_pc: 0x%llx\n"
			  "last_esr: 0x%llx\n"
			  "last_far: 0x%llx\n"
			  "last_hpfar: 0x%llx\n"
			  "last_exit_type: %llu\n"
			  "last_handled: %llu\n"
			  "rdist_ptr: 0x%lx\n"
			  "rdist_isenabler: 0x%x\n"
			  "cnthp_ctl: 0x%llx\n"
			  "cnthp_cval: 0x%llx\n"
			  "counter_val: %llu\n"
			  "deadline_val: %llu\n"
			  "vcpu_run_loops: %llu\n"
			  "stage: %llu\n"
			  "sub_stage: %llu\n"
			  "fault_count: %llu\n"
			  "fault_elr: 0x%llx\n"
			  "fault_esr: 0x%llx\n"
			  "fault_far: 0x%llx\n",
			  d->enter_count, d->exit_count,
			  d->last_enter_ticks, d->last_exit_ticks,
			  d->last_ret, d->last_pc, d->last_esr,
			  d->last_far, d->last_hpfar, d->last_exit_type,
			  d->last_handled, (unsigned long)rdist, isenabler,
			  d->cnthp_ctl, d->cnthp_cval, d->counter_val,
			  d->deadline_val, d->vcpu_run_loops,
			  d->stage, d->sub_stage,
			  arm64_caretaker_faults[cpu].count,
			  arm64_caretaker_faults[cpu].elr,
			  arm64_caretaker_faults[cpu].esr,
			  arm64_caretaker_faults[cpu].far);
}

void arch_cpu_preserved_dump_diag(int cpu)
{
	struct arm64_caretaker_diag *d;
	void __iomem *rdist;
	u32 isenabler = 0;

	if (cpu < 0 || cpu >= NR_CPUS)
		return;

	if (arm64_caretaker_faults[cpu].count) {
		pr_err("cpu_wait_dead: cpu=%d caretaker exception count=%llu elr=0x%llx esr=0x%llx far=0x%llx\n",
		       cpu,
		       arm64_caretaker_faults[cpu].count,
		       arm64_caretaker_faults[cpu].elr,
		       arm64_caretaker_faults[cpu].esr,
		       arm64_caretaker_faults[cpu].far);
	}

	d = &arm64_caretaker_diag[cpu];
	arch_cpu_preserved_dcache_inval((unsigned long)d, (unsigned long)(d + 1));
	rdist = gicv3_get_rdist_for_cpu(cpu);
	if (rdist)
		isenabler = readl_relaxed(rdist + SZ_64K + GICR_ISENABLER0);

	pr_err("cpu_wait_dead: cpu=%d diag: stage=%llu sub=%llu enter=%llu exit=%llu ret=0x%llx pc=0x%llx esr=0x%llx far=0x%llx hpfar=0x%llx type=%llu handled=%llu loops=%llu cnthp_ctl=0x%llx rdist=0x%lx isenable=0x%x\n",
	       cpu, d->stage, d->sub_stage, d->enter_count, d->exit_count, d->last_ret, d->last_pc,
	       d->last_esr, d->last_far, d->last_hpfar, d->last_exit_type,
	       d->last_handled, d->vcpu_run_loops, d->cnthp_ctl, (unsigned long)rdist, isenabler);
}
EXPORT_SYMBOL_GPL(arch_cpu_preserved_dump_diag);

u64 __cpu_preserved_text arch_cpu_preserved_get_mpidr(int cpu)
{
	if (cpu >= 0 && cpu < NR_CPUS)
		return arm64_cpu_mpidr[cpu];
	return INVALID_HWID;
}
EXPORT_SYMBOL_GPL(arch_cpu_preserved_get_mpidr);

int __cpu_preserved_text arch_cpu_preserved_mpidr_to_cpu(u64 mpidr)
{
	int c;

	for (c = 0; c < NR_CPUS; c++) {
		if ((arm64_cpu_mpidr[c] & MPIDR_HWID_BITMASK) == (mpidr & MPIDR_HWID_BITMASK))
			return c;
	}
	return -EINVAL;
}

bool __cpu_preserved_text arch_cpu_preserved_is_active(void)
{
	u64 ttbr1 = read_sysreg(ttbr1_el1);
	struct cpu_preserved_stack_context *sctx = cpu_preserved_get_stack_context();

	if (sctx && sctx->session_pgd_pa && ttbr1 == sctx->session_pgd_pa)
		return true;
	return arm64_caretaker_pgd_pa && (ttbr1 == arm64_caretaker_pgd_pa);
}
EXPORT_SYMBOL_GPL(arch_cpu_preserved_is_active);

void __cpu_preserved_text arch_cpu_preserved_switch_pgd(phys_addr_t pgd_pa)
{
	arch_cpu_preserved_set_stage(-1, 13, pgd_pa);
	if (pgd_pa && read_sysreg(ttbr1_el1) != pgd_pa) {
		write_sysreg(pgd_pa, ttbr1_el1);
		isb();
		arm64_flush_host_tlb_local();
	}
	arch_cpu_preserved_set_stage(-1, 14, pgd_pa);
}
EXPORT_SYMBOL_GPL(arch_cpu_preserved_switch_pgd);
EXPORT_SYMBOL_GPL(arch_cpu_preserved_mpidr_to_cpu);

static void *arm64_caretaker_alloc_page(void *arg)
{
	struct caretaker_session *sess = arg;
	void *ptr = kho_alloc_preserve(PAGE_SIZE);
	struct page *page;

	if (IS_ERR_OR_NULL(ptr)) {
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

	if (sess) {
		if (sess->nr_pgd_pages < ARRAY_SIZE(sess->pgd_pages))
			sess->pgd_pages[sess->nr_pgd_pages++] = virt_to_phys(ptr);
		else
			WARN_ON_ONCE(1);
	} else {
		list_add(&page->lru, &arm64_caretaker_pages);
	}
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
	unsigned long page_va = va & PAGE_MASK;
	unsigned long offset = va & ~PAGE_MASK;
	phys_addr_t page_pa = (pa & PAGE_MASK);
	size_t page_size = PAGE_ALIGN(offset + size);

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

		pte_clear(&init_mm, va, ptep);
		arm64_flush_host_tlb_page(va);
		set_ptes(&init_mm, va, ptep, pfn_pte(PHYS_PFN(pa), prot), 1);
		arm64_flush_host_tlb_page(va);
	}

	for (i = 0; i < data_nr_pages; i++) {
		unsigned long va = data_start + i * PAGE_SIZE;
		pte_t *ptep = arm64_get_kernel_pte(va);

		if (!ptep)
			return -EINVAL;

		pgprot_t prot = __pgprot(pgprot_val(pte_pgprot(*ptep)) & ~PTE_CONT);
		phys_addr_t pa = page_to_phys(data_page) + i * PAGE_SIZE;

		pte_clear(&init_mm, va, ptep);
		arm64_flush_host_tlb_page(va);
		set_ptes(&init_mm, va, ptep, pfn_pte(PHYS_PFN(pa), prot), 1);
		arm64_flush_host_tlb_page(va);
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
					(unsigned long)&arm64_caretaker_pgd + sizeof(arm64_caretaker_pgd));
	arch_cpu_preserved_dcache_clean((unsigned long)&arm64_caretaker_pgd_pa,
					(unsigned long)&arm64_caretaker_pgd_pa + sizeof(arm64_caretaker_pgd_pa));

	return 0;
}

void *arch_cpu_preserved_get_pgd(void)
{
	return arm64_caretaker_pgd;
}
EXPORT_SYMBOL_GPL(arch_cpu_preserved_get_pgd);

int arch_caretaker_alloc_session_pgd(struct caretaker_session *sess)
{
	struct trans_pgd_info info = {
		.trans_alloc_page = arm64_caretaker_alloc_page,
		.trans_alloc_arg = sess,
	};
	unsigned long text_start = (unsigned long)__cpu_preserved_text_start;
	unsigned long data_start = (unsigned long)__cpu_preserved_data_start;
	int ret, i;

	if (!sess)
		return -EINVAL;
	if (sess->pgd)
		return 0;

	if (!preserved_text_pa || !preserved_data_pa)
		return -EAGAIN;

	guard(mutex)(&arm64_caretaker_map_lock);

	sess->pgd = arm64_caretaker_alloc_page(sess);
	if (!sess->pgd)
		return -ENOMEM;

	ret = trans_pgd_map_range(&info, sess->pgd, preserved_text_pa,
				  text_start, preserved_text_sz, PAGE_KERNEL_ROX);
	if (ret)
		return ret;

	ret = trans_pgd_map_range(&info, sess->pgd, preserved_data_pa,
				  data_start, preserved_data_sz, PAGE_KERNEL);
	if (ret)
		return ret;

	sess->pgd_pa = virt_to_phys(sess->pgd);

	for (i = 0; i < sess->nr_pgd_pages; i++) {
		unsigned long addr = (unsigned long)phys_to_virt(sess->pgd_pages[i]);

		__arch_cpu_preserved_dcache_clean(addr, addr + PAGE_SIZE);
	}
	__arch_cpu_preserved_dcache_clean((unsigned long)&sess->pgd_pa,
					  (unsigned long)&sess->pgd_pa + sizeof(sess->pgd_pa));

	arm64_flush_host_tlb_all();

	return 0;
}
EXPORT_SYMBOL_GPL(arch_caretaker_alloc_session_pgd);

void arch_caretaker_free_session_pgd(struct caretaker_session *sess)
{
	int i;

	if (!sess || !sess->pgd)
		return;

	guard(mutex)(&arm64_caretaker_map_lock);

	for (i = 0; i < sess->nr_pgd_pages; i++) {
		void *va = phys_to_virt(sess->pgd_pages[i]);

		if (sess->is_incoming)
			kho_restore_free(va);
		else
			kho_unpreserve_free(va);
	}

	sess->nr_pgd_pages = 0;
	sess->pgd = NULL;
	sess->pgd_pa = 0;
}
EXPORT_SYMBOL_GPL(arch_caretaker_free_session_pgd);

int arch_caretaker_map_session_range(struct caretaker_session *sess,
				     phys_addr_t pa, unsigned long va,
				     size_t size, pgprot_t prot)
{
	struct trans_pgd_info info = {
		.trans_alloc_page = arm64_caretaker_alloc_page,
		.trans_alloc_arg = sess,
	};
	unsigned long page_va = va & PAGE_MASK;
	unsigned long offset = va & ~PAGE_MASK;
	phys_addr_t page_pa = (pa & PAGE_MASK);
	size_t page_size = PAGE_ALIGN(offset + size);
	int ret, i;

	if (!sess || !sess->pgd || !size)
		return 0;

	guard(mutex)(&arm64_caretaker_map_lock);

	ret = trans_pgd_map_range(&info, sess->pgd, page_pa,
				  page_va, page_size, prot);
	if (ret)
		return ret;

	for (i = 0; i < sess->nr_pgd_pages; i++) {
		unsigned long addr = (unsigned long)phys_to_virt(sess->pgd_pages[i]);

		__arch_cpu_preserved_dcache_clean(addr, addr + PAGE_SIZE);
	}
	__arch_cpu_preserved_dcache_clean((unsigned long)&sess->pgd_pa,
					  (unsigned long)&sess->pgd_pa + sizeof(sess->pgd_pa));

	arm64_flush_host_tlb_all();

	return 0;
}
EXPORT_SYMBOL_GPL(arch_caretaker_map_session_range);


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
					(unsigned long)&arm64_psci_conduit + sizeof(arm64_psci_conduit));
	arch_cpu_preserved_dcache_inval((unsigned long)arm64_cpu_mpidr,
					(unsigned long)arm64_cpu_mpidr + sizeof(arm64_cpu_mpidr));
	if (!pgd_pa) {
		arch_cpu_preserved_dcache_inval((unsigned long)&arm64_caretaker_pgd_pa,
						(unsigned long)&arm64_caretaker_pgd_pa + sizeof(arm64_caretaker_pgd_pa));
		pgd_pa = READ_ONCE(arm64_caretaker_pgd_pa);
	}

	write_sysreg((unsigned long)caretaker_hyp_vector, vbar_el1);
	write_sysreg_s((unsigned long)caretaker_hyp_vector, SYS_VBAR_EL2);
	isb();

	arch_cpu_preserved_set_stage(cpu, 10, pgd_pa);
	write_sysreg(0, ttbr0_el1);
	if (pgd_pa)
		write_sysreg(pgd_pa, ttbr1_el1);
	isb();
	arm64_flush_host_tlb_local();

	arch_cpu_preserved_set_stage(cpu, 11, 1);
	write_sysreg_s(0xff, SYS_ICC_PMR_EL1);
	isb();

	arch_cpu_preserved_set_stage(cpu, 11, 2);
	write_sysreg_s(1, SYS_ICC_IGRPEN1_EL1);
	isb();

	arch_cpu_preserved_set_stage(cpu, 12, 0);
}

void arch_cpu_preserved_early_init(void)
{
	int c;

	for (c = 0; c < nr_cpu_ids; c++)
		arm64_cpu_mpidr[c] = cpu_logical_map(c);
	arch_cpu_preserved_dcache_clean((unsigned long)arm64_cpu_mpidr,
					(unsigned long)arm64_cpu_mpidr + sizeof(arm64_cpu_mpidr));

	arch_cpu_preserved_dcache_inval((unsigned long)&arm64_psci_conduit,
					(unsigned long)&arm64_psci_conduit + sizeof(arm64_psci_conduit));
	if (arm64_psci_conduit == SMCCC_CONDUIT_NONE) {
		arm64_psci_conduit = arm_smccc_1_1_get_conduit();
		arch_cpu_preserved_dcache_clean((unsigned long)&arm64_psci_conduit,
						(unsigned long)&arm64_psci_conduit + sizeof(arm64_psci_conduit));
	}
}
EXPORT_SYMBOL_GPL(arch_cpu_preserved_early_init);

void __cpu_preserved_text arch_cpu_preserved_park_finish(int cpu)
{
	enum arm_smccc_conduit conduit;
	u32 el = (read_sysreg(CurrentEL) >> 2) & 3;

	arch_cpu_preserved_set_stage(cpu, 36, 0);

	arch_cpu_preserved_dcache_inval((unsigned long)&arm64_psci_conduit,
					(unsigned long)&arm64_psci_conduit + sizeof(arm64_psci_conduit));
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
 * Switch stack and enter park loop.
 */
asmlinkage void arch_cpu_preserved_park_on_stack(int cpu, unsigned long stack_top);
asm(
"	.pushsection \".text.cpu_preserved\", \"ax\"\n"
"	.global arch_cpu_preserved_park_on_stack\n"
"	.type arch_cpu_preserved_park_on_stack, %function\n"
"arch_cpu_preserved_park_on_stack:\n"
"	stp	x29, x30, [sp, #-32]!\n"
"	stp	x19, x20, [sp, #16]\n"
"	mov	x29, sp\n"
"	mov	x20, sp\n"
"	mov	sp, x1\n"
"	mov	x19, x0\n"
"	bl	cpu_preserved_park_loop\n"
"	mov	x0, x19\n"
"	bl	arch_cpu_preserved_park_finish\n"
"	b	.\n"
"	.size arch_cpu_preserved_park_on_stack, . - arch_cpu_preserved_park_on_stack\n"
"	.popsection\n"
);
EXPORT_SYMBOL_GPL(arch_cpu_preserved_park_on_stack);

/*
 * Clean and invalidate data cache to PoC in preserved text without external dependencies.
 */
asmlinkage void __arch_cpu_preserved_dcache_clean(unsigned long start, unsigned long end);
asmlinkage void arch_cpu_preserved_dcache_inval(unsigned long start, unsigned long end);
asm(
"	.pushsection \".text.cpu_preserved\", \"ax\"\n"
"	.global __arch_cpu_preserved_dcache_clean\n"
"	.type __arch_cpu_preserved_dcache_clean, %function\n"
"__arch_cpu_preserved_dcache_clean:\n"
"	dsb	sy\n"
"	mrs	x3, ctr_el0\n"
"	ubfx	x3, x3, #16, #4\n"
"	mov	x2, #4\n"
"	lsl	x2, x2, x3\n"
"	sub	x3, x2, #1\n"
"	bic	x0, x0, x3\n"
"1:	dc	civac, x0\n"
"	add	x0, x0, x2\n"
"	cmp	x0, x1\n"
"	b.lo	1b\n"
"	dsb	sy\n"
"	ret\n"
"	.size __arch_cpu_preserved_dcache_clean, . - __arch_cpu_preserved_dcache_clean\n"
"	.global arch_cpu_preserved_dcache_inval\n"
"	.type arch_cpu_preserved_dcache_inval, %function\n"
"arch_cpu_preserved_dcache_inval:\n"
"	dsb	sy\n"
"	mrs	x3, ctr_el0\n"
"	ubfx	x3, x3, #16, #4\n"
"	mov	x2, #4\n"
"	lsl	x2, x2, x3\n"
"	sub	x3, x2, #1\n"
"	bic	x0, x0, x3\n"
"1:	dc	civac, x0\n"
"	add	x0, x0, x2\n"
"	cmp	x0, x1\n"
"	b.lo	1b\n"
"	dsb	sy\n"
"	ret\n"
"	.size arch_cpu_preserved_dcache_inval, . - arch_cpu_preserved_dcache_inval\n"
"	.popsection\n"
);
EXPORT_SYMBOL_GPL(arch_cpu_preserved_dcache_inval);

void __cpu_preserved_text arch_cpu_preserved_dcache_clean(unsigned long start, unsigned long end)
{
	__arch_cpu_preserved_dcache_clean(start, end);
}
EXPORT_SYMBOL_GPL(arch_cpu_preserved_dcache_clean);

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

u64 __cpu_preserved_text arch_caretaker_ticks_to_ns(u64 ticks)
{
	u32 cntfrq = arch_timer_get_cntfrq();

	if (cntfrq > 0)
		return mul_u64_u32_div(ticks, 1000000000U, cntfrq);
	return ticks;
}
EXPORT_SYMBOL_GPL(arch_caretaker_ticks_to_ns);

void arch_caretaker_update_quantum_ticks(struct caretaker_sched_config *cfg)
{
	u32 ms = cfg->quantum_ms;
	u32 cntfrq = arch_timer_get_cntfrq();

	if (cntfrq > 0)
		cfg->quantum_ticks = ((u64)ms * cntfrq) / 1000ULL;
	else
		cfg->quantum_ticks = (u64)ms * 25000000ULL / 1000ULL;
}
EXPORT_SYMBOL_GPL(arch_caretaker_update_quantum_ticks);

