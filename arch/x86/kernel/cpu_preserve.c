// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * Architecture specific CPU preservation support for x86.
 */
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
#include <asm/tlbflush.h>
#include <asm/trapnr.h>
#include <asm/init.h>

#include "cpu_preserve_internal.h"

/*
 * Initialize the preserved IDT with exception and interrupt handlers.
 *
 * Vectors 0..31 are x86 architecture exceptions/traps:
 * - X86_TRAP_NMI (vector 2) is used by arch_cpu_preserved_kick() to wake up
 *   parked/running preserved CPUs and returns immediately via
 *   x86_preserved_iret_stub.
 * - All other exception vectors (0..31) enter x86_preserved_exc_handler_array[v],
 *   which resolves _ASM_EXTABLE fixups in .cpu_preserved.ex_table and records
 *   fault telemetry (vector, error_code, RIP, CR2) on unexpected faults.
 *
 * Vectors >= FIRST_EXTERNAL_VECTOR (32) are device and IPI interrupts:
 * - Handled by x86_preserved_apic_eoi_stub to issue APIC EOI before iretq.
 */
static void init_preserved_idt(void)
{
	unsigned long eoi_handler = (unsigned long)&x86_preserved_apic_eoi_stub;
	unsigned long iret_handler = (unsigned long)&x86_preserved_iret_stub;
	int v;

	for (v = 0; v < IDT_ENTRIES; v++) {
		unsigned long handler;

		if (v >= FIRST_EXTERNAL_VECTOR)
			handler = eoi_handler;
		else if (v == X86_TRAP_NMI)
			handler = iret_handler;
		else
			handler = (unsigned long)x86_preserved_exc_handler_array[v];

		pack_gate(&x86_preserved_idt[v], GATE_INTERRUPT, handler, 0,
			  0, __KERNEL_CS);
	}
	x86_preserved_idt_desc.size = sizeof(x86_preserved_idt) - 1;
	x86_preserved_idt_desc.address = (unsigned long)&x86_preserved_idt[0];
	cpu_preserved_clean(&x86_preserved_idt);
	cpu_preserved_clean(&x86_preserved_idt_desc);
}

static void init_preserved_gdt(void)
{
	struct desc_struct *gdt;
	int i;

	gdt = get_current_gdt_rw();
	for (i = 0; i < GDT_ENTRIES; i++)
		x86_preserved_gdt[i] = gdt[i];
	x86_preserved_gdt_desc.size = GDT_SIZE - 1;
	x86_preserved_gdt_desc.address = (unsigned long)&x86_preserved_gdt[0];
	cpu_preserved_clean(&x86_preserved_gdt);
	cpu_preserved_clean(&x86_preserved_gdt_desc);
}

void arch_cpu_preserved_early_init(void)
{
	x86_preserved_has_svm = boot_cpu_has(X86_FEATURE_SVM);
	cpu_preserved_clean(&x86_preserved_has_svm);

	init_preserved_idt();
	init_preserved_gdt();
}

/*
 * Signal or wake up a preserved physical CPU via APIC ICR NMI.
 */
void arch_cpu_preserved_kick(int cpu)
{
	u32 apicid;
	u64 val;

	if ((unsigned int)cpu >= nr_cpu_ids || !cpu_is_preserved(cpu))
		return;

	apicid = cpu_physical_id(cpu);
	if (apicid == BAD_APICID)
		apicid = cpuid_to_apicid[cpu];
	if (apicid == BAD_APICID)
		return;

	val = ((u64)apicid << 32) | APIC_DM_NMI;
	native_wrmsrq(APIC_BASE_MSR + (APIC_ICR >> 4), val);
}

/*
 * Switch stack and enter park loop.
 */
void arch_cpu_preserved_park_on_stack(int cpu, unsigned long stack_top)
{
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
			pte_clear(&init_mm, addr, ptep);
			unmapped = true;
		}
	}

	return unmapped;
}

void arch_cpu_preserved_as_flush_tlb(void)
{
	flush_tlb_all();
}

int arch_cpu_preserved_setup_buffer(struct page *text_page,
				    unsigned int text_nr_pages,
				    struct page *data_page,
				    unsigned int data_nr_pages)
{
	unsigned long text_start = (unsigned long)__cpu_preserved_text_start;
	unsigned long data_start = (unsigned long)__cpu_preserved_data_start;
	unsigned int i;
	int ret;

	if (!x2apic_enabled()) {
		pr_warn("cpu_preserve: x2APIC is required\n");
		return -EOPNOTSUPP;
	}

	/* Split kernel large pages into 4K PTEs */
	ret = set_memory_4k(text_start, text_nr_pages);
	if (ret)
		return ret;

	ret = set_memory_4k(data_start, data_nr_pages);
	if (ret)
		return ret;

	/* Validate all 4K PTEs before modifying any */
	for (i = 0; i < text_nr_pages; i++) {
		unsigned int level;
		pte_t *pte = lookup_address(text_start + i * PAGE_SIZE, &level);

		if (!pte || level != PG_LEVEL_4K)
			return -EINVAL;
	}

	for (i = 0; i < data_nr_pages; i++) {
		unsigned int level;
		pte_t *pte = lookup_address(data_start + i * PAGE_SIZE, &level);

		if (!pte || level != PG_LEVEL_4K)
			return -EINVAL;
	}

	/* Remap init_mm kernel mappings to point to allocated buffer pages */
	for (i = 0; i < text_nr_pages; i++) {
		unsigned int level;
		pte_t *pte = lookup_address(text_start + i * PAGE_SIZE, &level);
		phys_addr_t pa = page_to_phys(text_page) + i * PAGE_SIZE;

		set_pte(pte, pfn_pte(PHYS_PFN(pa), pte_pgprot(*pte)));
	}

	for (i = 0; i < data_nr_pages; i++) {
		unsigned int level;
		pte_t *pte = lookup_address(data_start + i * PAGE_SIZE, &level);
		phys_addr_t pa = page_to_phys(data_page) + i * PAGE_SIZE;

		set_pte(pte, pfn_pte(PHYS_PFN(pa), pte_pgprot(*pte)));
	}

	flush_tlb_all();

	/* Ensure preserved GDT, IDT, and arch flags are initialized */
	arch_cpu_preserved_early_init();

	return 0;
}

void arch_cpu_preserved_wait_dead(int cpu)
{
	struct cpu_preserved_stack_context *sctx = cpu_preserved_get_sctx(cpu);

	if (sctx && READ_ONCE(sctx->fault.count)) {
		const struct x86_preserved_fault *f = &sctx->fault;

		pr_err("cpu_preserve: CPU %d unhandled fault vec=%lu err=0x%lx ip=0x%lx (%pS) cr2=0x%lx cr3=0x%lx\n",
		       cpu, f->vector, f->error_code, f->ip,
		       (void *)f->ip, f->cr2, f->cr3);
	}
}
