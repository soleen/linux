// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * Architecture specific CPU preservation support for x86.
 */
#include <linux/cc_platform.h>
#include <linux/cpu_preserve.h>
#include <linux/kexec_handover.h>
#include <linux/mm.h>
#include <linux/nospec.h>
#include <linux/objtool.h>
#include <linux/sched/mm.h>

#include <asm/apic.h>
#include <linux/cacheflush.h>
#include <linux/cpufeature.h>
#include <asm/desc.h>
#include <asm/fixmap.h>
#include <asm/msr.h>
#include <linux/pgtable.h>
#include <asm/set_memory.h>
#include <linux/smp.h>
#include <asm/trapnr.h>
#include <asm/init.h>

#include "cpu_preserve_internal.h"

/*
 * Initialize the preserved IDT with exception handlers.
 *
 * Vectors 0..31 are x86 architecture exceptions/traps.  They enter
 * x86_preserved_exc_handler_array[v] and x86_preserved_handle_exception():
 * - X86_TRAP_NMI (vector 2) is the kick sent by arch_cpu_preserved_kick().  It
 *   wakes up a CPU that sleeps in x86_preserved_idle() and returns.
 * - _ASM_EXTABLE fixups in .cpu_preserved.ex_table are applied, and the CPU
 *   resumes after a recoverable machine check.  Any other exception is recorded
 *   and stops the CPU.
 * - #DF, NMI and #MC run on IST stacks, so they work even when the current
 *   stack does not.
 *
 * Vectors >= FIRST_EXTERNAL_VECTOR (32) are external interrupts, which are not
 * delivered: the runtime keeps interrupts disabled, and the local APIC stays
 * software-disabled.  Their gates are not present, so that one would raise #NP
 * and stop the CPU.
 */
static void init_preserved_idt(void)
{
	int v;

	for (v = 0; v < NUM_EXCEPTION_VECTORS; v++) {
		unsigned long handler = (unsigned long)x86_preserved_exc_handler_array[v];
		unsigned int ist = 0;

		if (v == X86_TRAP_DF)
			ist = X86_PRESERVED_IST_DF + 1;
		else if (v == X86_TRAP_NMI)
			ist = X86_PRESERVED_IST_NMI + 1;
		else if (v == X86_TRAP_MC)
			ist = X86_PRESERVED_IST_MC + 1;

		pack_gate(&x86_preserved_idt[v], GATE_INTERRUPT, handler, 0,
			  ist, __KERNEL_CS);
	}
	x86_preserved_idt_desc.size = sizeof(x86_preserved_idt) - 1;
	x86_preserved_idt_desc.address = (unsigned long)&x86_preserved_idt[0];
	cpu_preserved_clean(&x86_preserved_idt);
	cpu_preserved_clean(&x86_preserved_idt_desc);
}

void arch_cpu_preserved_early_init(void)
{
	init_preserved_idt();
	x86_preserved_mwait = boot_cpu_has(X86_FEATURE_MWAIT) &&
			      !boot_cpu_has_bug(X86_BUG_MONITOR) &&
			      !boot_cpu_has_bug(X86_BUG_CLFLUSH_MONITOR);
	x86_preserved_sme_mask = sme_me_mask;
	x86_preserved_has_svm = boot_cpu_has(X86_FEATURE_SVM);
}

/*
 * The parked CPUs keep the APIC mode of the kernel that preserved them, and
 * their page tables its paging depth.
 */
u64 arch_cpu_preserved_mode(void)
{
	u64 mode = 0;

	if (x2apic_mode)
		mode |= CPU_PRESERVED_X86_X2APIC;
	if (pgtable_l5_enabled())
		mode |= CPU_PRESERVED_X86_LA57;
	return mode;
}

/*
 * Kick a preserved CPU with an NMI.  Use the physical destination: this kernel
 * sets up the logical destination of a CPU only when it brings the CPU up.
 */
void arch_cpu_preserved_kick(int cpu)
{
	unsigned long flags;
	u32 apicid;

	if ((unsigned int)cpu >= nr_cpu_ids || !cpu_is_preserved(cpu))
		return;

	apicid = cpu_physical_id(cpu);
	if (apicid == BAD_APICID)
		apicid = cpuid_to_apicid[cpu];
	if (apicid == BAD_APICID)
		return;

	local_irq_save(flags);
	apic_wait_icr_idle();
	apic_icr_write(APIC_DM_NMI | APIC_DEST_PHYSICAL, apicid);
	local_irq_restore(flags);
}

u64 arch_cpu_preserved_hwid(unsigned int cpu)
{
	return cpuid_to_apicid[cpu];
}

static void arch_cpu_preserved_set_max_perf(void)
{
	u64 cap;

	/* Intel HWP (Speed Shift): autonomously request maximum performance */
	if (boot_cpu_has(X86_FEATURE_HWP) &&
	    !rdmsrq_safe(MSR_HWP_CAPABILITIES, &cap)) {
		u8 highest = HWP_HIGHEST_PERF(cap);

		if (highest) {
			wrmsrq_safe(MSR_HWP_REQUEST, HWP_MIN_PERF(highest) |
				    HWP_MAX_PERF(highest) |
				    HWP_DESIRED_PERF(highest));
		}
	}

	/* Intel Energy Performance Bias: hint for maximum performance */
	if (boot_cpu_has(X86_FEATURE_EPB))
		wrmsrq_safe(MSR_IA32_ENERGY_PERF_BIAS, ENERGY_PERF_BIAS_PERFORMANCE);

	/* AMD CPPC: request maximum performance ratio and zero energy preference */
	if (boot_cpu_has(X86_FEATURE_CPPC)) {
		wrmsrq_safe(MSR_AMD_CPPC_REQ, AMD_CPPC_MAX_PERF_MASK |
			    AMD_CPPC_MIN_PERF_MASK | AMD_CPPC_DES_PERF_MASK);
	}
}

/*
 * Switch stack and enter park loop.
 */
void arch_cpu_preserved_park_on_stack(int cpu, unsigned long stack_top)
{
	arch_cpu_preserved_set_max_perf();
	arch_cpu_preserved_call_on_stack(cpu, stack_top, arch_cpu_preserved_park_worker);
}

/**
 * arch_cpu_preserved_as_map - Populate an isolated page table on x86
 * @as: Address space to map into.
 * @pa: Physical address of the range.
 * @va: Virtual address the range must appear at.
 * @size: Size of the range in bytes.
 * @prot: Protection to apply.
 *
 * Return: 0 on success, or a negative errno on failure.
 */
int arch_cpu_preserved_as_map(struct cpu_preserved_as_ser *as, phys_addr_t pa,
			      unsigned long va, size_t size, pgprot_t prot)
{
	unsigned long offset = va & ~PAGE_MASK;
	size_t page_size = PAGE_ALIGN(offset + size);
	unsigned long page_va = va & PAGE_MASK;
	phys_addr_t page_pa = (pa & PAGE_MASK);
	void *pgd = phys_to_virt(as->pgd_pa);
	struct x86_mapping_info info = {
		.alloc_pgt_page = cpu_preserved_as_alloc_page,
		.context = as,
		.page_flag = pgprot_val(prot),
		.offset = page_va - page_pa,
		.force_pte = true,
	};

	return kernel_ident_mapping_init(&info, pgd, page_pa,
					 page_pa + page_size);
}

bool arch_cpu_preserved_as_unmap(struct cpu_preserved_as_ser *as,
				 unsigned long va, size_t size)
{
	unsigned long offset = va & ~PAGE_MASK;
	size_t page_size = PAGE_ALIGN(offset + size);
	unsigned long addr = va & PAGE_MASK;
	unsigned long end = addr + page_size;
	pgd_t *root = phys_to_virt(as->pgd_pa);
	bool unmapped = false;

	for (; addr < end; addr += PAGE_SIZE) {
		pgd_t *pgdp = pgd_offset_pgd(root, addr);
		p4d_t *p4dp;
		pud_t *pudp;
		pmd_t *pmdp;
		pte_t *ptep;

		if (pgd_none(*pgdp) || !pgd_present(*pgdp))
			continue;
		p4dp = p4d_offset(pgdp, addr);
		if (p4d_none(*p4dp) || !p4d_present(*p4dp))
			continue;
		pudp = pud_offset(p4dp, addr);
		if (pud_none(*pudp) || !pud_present(*pudp) || pud_leaf(*pudp))
			continue;
		pmdp = pmd_offset(pudp, addr);
		if (pmd_none(*pmdp) || !pmd_present(*pmdp) || pmd_leaf(*pmdp))
			continue;
		ptep = pte_offset_kernel(pmdp, addr);
		if (pte_present(*ptep)) {
			set_pte(ptep, __pte(0));
			unmapped = true;
		}
	}

	return unmapped;
}

/*
 * Nothing to flush: a range is unmapped only once no preserved CPU uses it,
 * and preserved CPUs are offline, so they would not get a shootdown anyway.
 * Bringing a CPU online resets it, which flushes its TLB.
 */
void arch_cpu_preserved_as_flush_tlb(void)
{
}

/*
 * Only the isolated address spaces map the copy for execution, and only the
 * preserved CPUs write it: keep its direct map alias read-only.
 */
int arch_cpu_preserved_setup_buffer(struct page *text_page,
				    unsigned int text_nr_pages,
				    struct page *data_page,
				    unsigned int data_nr_pages)
{
	unsigned long text = (unsigned long)page_address(text_page);
	unsigned long data = (unsigned long)page_address(data_page);
	int ret;

	/* The runtime cannot handle #VC exceptions */
	if (cc_platform_has(CC_ATTR_GUEST_STATE_ENCRYPT)) {
		pr_warn("cpu_preserve: not supported with guest state encryption\n");
		return -EOPNOTSUPP;
	}

	ret = set_memory_ro(text, text_nr_pages);
	if (!ret) {
		ret = set_memory_ro(data, data_nr_pages);
		if (!ret)
			return 0;
		set_memory_rw(data, data_nr_pages);
	}
	set_memory_rw(text, text_nr_pages);
	return ret;
}

int arch_cpu_preserved_wait_dead(int cpu)
{
	struct cpu_preserved_stack_context *sctx = cpu_preserved_get_sctx(cpu);
	const struct x86_preserved_fault *f;

	if (!sctx)
		return 0;

	f = &sctx->fault;
	if (READ_ONCE(f->count))
		pr_err("cpu_preserve: CPU %d unhandled fault vec=%lu err=0x%lx ip=0x%lx cr2=0x%lx cr3=0x%lx\n",
		       cpu, f->vector, f->error_code, f->ip, f->cr2, f->cr3);
	if (READ_ONCE(f->nr_mce))
		pr_warn("cpu_preserve: CPU %d recovered from %lu machine checks\n",
			cpu, f->nr_mce);

	return 0;
}
