// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
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
#include <linux/nospec.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/psci.h>
#include <linux/sched/mm.h>
#include <uapi/linux/psci.h>

#include <asm/barrier.h>
#include <linux/cacheflush.h>
#include <asm/cpu_ops.h>
#include <asm/daifflags.h>
#include <asm/kernel-pgtable.h>
#include <asm/kvm_asm.h>
#include <linux/pgtable.h>
#include <asm/sysreg.h>
#include <asm/tlbflush.h>
#include <asm/trans_pgd.h>
#include <asm/virt.h>

#include "cpu_preserve_internal.h"

static void arm64_cpu_preserved_gic_init(void);

static void arm64_add_gicr_region(phys_addr_t pa, size_t size, u64 stride)
{
	void __iomem *va;
	size_t map_size;
	int i;

	for (i = 0; i < cpu_preserved_gic.nr_regions; i++)
		if (cpu_preserved_gic.regions[i].pa == pa)
			return;

	if (cpu_preserved_gic.nr_regions >= ARRAY_SIZE(cpu_preserved_gic.regions))
		return;

	map_size = max_t(size_t, size, nr_cpu_ids * (stride ? : SZ_128K));
	va = ioremap(pa, map_size);
	if (!va)
		return;

	i = cpu_preserved_gic.nr_regions++;
	cpu_preserved_gic.regions[i].pa = pa;
	cpu_preserved_gic.regions[i].va = va;
	cpu_preserved_gic.regions[i].size = map_size;
	cpu_preserved_gic.regions[i].stride = stride;

	cpu_preserved_clean(&cpu_preserved_gic);
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

static void arm64_cpu_preserved_gic_init(void)
{
	struct device_node *node;

	if (cpu_preserved_gic.nr_regions > 0 || arch_cpu_preserved_is_active())
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

	if (cpu_preserved_gic.nr_regions == 0)
		arm64_discover_gicr_res(&iomem_resource);
}

int gicv3_cpu_preserved_get_redist_region(int idx, phys_addr_t *pa,
					  unsigned long *va, size_t *size)
{
	arm64_cpu_preserved_gic_init();
	if (idx < 0 || idx >= cpu_preserved_gic.nr_regions)
		return -ENOENT;

	*pa = cpu_preserved_gic.regions[idx].pa;
	*va = (unsigned long)cpu_preserved_gic.regions[idx].va;
	*size = cpu_preserved_gic.regions[idx].size;
	return 0;
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
int arch_cpu_preserved_as_map(struct cpu_preserved_as_ser *as, phys_addr_t pa,
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
	void *pgd = phys_to_virt(as->pgd_pa);
	int ret;

	ret = trans_pgd_map_range(&info, pgd, page_pa,
				  page_va, page_size, prot);
	if (!ret)
		dsb(ishst);
	return ret;
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

		if (pgd_none(READ_ONCE(*pgdp)))
			continue;
		p4dp = p4d_offset(pgdp, addr);
		if (p4d_none(READ_ONCE(*p4dp)))
			continue;
		pudp = pud_offset(p4dp, addr);
		if (pud_none(READ_ONCE(*pudp)) || pud_leaf(READ_ONCE(*pudp)))
			continue;
		pmdp = pmd_offset(pudp, addr);
		if (pmd_none(READ_ONCE(*pmdp)) || pmd_leaf(READ_ONCE(*pmdp)))
			continue;
		ptep = pte_offset_kernel(pmdp, addr);
		if (!pte_none(READ_ONCE(*ptep))) {
			__pte_clear(&init_mm, addr, ptep);
			cpu_preserved_clean(ptep);
			unmapped = true;
		}
	}

	return unmapped;
}

void arch_cpu_preserved_as_flush_tlb(void)
{
	arm64_flush_host_tlb_all();
}

/**
 * arch_cpu_preserved_setup_buffer - Set up runtime buffer and page tables
 * @text_page: Runtime-allocated physical page backing preserved text
 * @text_nr_pages: Number of pages in text buffer
 * @data_page: Runtime-allocated physical page backing preserved data
 * @data_nr_pages: Number of pages in data buffer
 *
 * Remap init_mm kernel mappings for .cpu_preserved.text and
 * .cpu_preserved.data to point to the runtime-allocated pages outside
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

	/* Validate all PTEs before modifying any */
	for (i = 0; i < text_nr_pages; i++) {
		if (!arm64_get_kernel_pte(text_start + i * PAGE_SIZE))
			return -EINVAL;
	}

	for (i = 0; i < data_nr_pages; i++) {
		if (!arm64_get_kernel_pte(data_start + i * PAGE_SIZE))
			return -EINVAL;
	}

	/* Remap init_mm kernel mappings to point to allocated buffer pages */
	for (i = 0; i < text_nr_pages; i++) {
		unsigned long va = text_start + i * PAGE_SIZE;
		pte_t *ptep = arm64_get_kernel_pte(va);
		pgprot_t prot = __pgprot(pgprot_val(pte_pgprot(*ptep)) & ~PTE_CONT);
		phys_addr_t pa = page_to_phys(text_page) + i * PAGE_SIZE;

		set_pte_at(&init_mm, va, ptep, pfn_pte(PHYS_PFN(pa), prot));
	}

	for (i = 0; i < data_nr_pages; i++) {
		unsigned long va = data_start + i * PAGE_SIZE;
		pte_t *ptep = arm64_get_kernel_pte(va);
		pgprot_t prot = __pgprot(pgprot_val(pte_pgprot(*ptep)) & ~PTE_CONT);
		phys_addr_t pa = page_to_phys(data_page) + i * PAGE_SIZE;

		set_pte_at(&init_mm, va, ptep, pfn_pte(PHYS_PFN(pa), prot));
	}

	arm64_flush_host_tlb_all();
	flush_icache_range(text_start, text_start + (text_nr_pages * PAGE_SIZE));

	arch_cpu_preserved_early_init();

	return 0;
}

void arch_cpu_preserved_early_init(void)
{
	arm64_cpu_preserved_gic_init();

	cpu_preserved_inval(&arm64_psci_conduit);
	if (arm64_psci_conduit == SMCCC_CONDUIT_NONE) {
		arm64_psci_conduit = arm_smccc_1_1_get_conduit();
		cpu_preserved_clean(&arm64_psci_conduit);
	}
}

/*
 * Signal or wake up a preserved physical CPU via SEV and GICv3 SGI.
 */
void arch_cpu_preserved_kick(int cpu)
{
	if ((unsigned int)cpu >= nr_cpu_ids || !cpu_is_preserved(cpu))
		return;

	dsb(ishst);
	sev();
	gicv3_cpu_preserved_kick_mpidr(cpu_logical_map(cpu));
	isb();
}

void arch_cpu_preserved_park_on_stack(int cpu, unsigned long stack_top)
{
	__arch_cpu_preserved_park_on_stack(cpu, stack_top);
}

void arch_cpu_preserved_wait_dead(int cpu)
{
	struct cpu_preserved_stack_context *sctx = cpu_preserved_get_sctx(cpu);
	const struct cpu_operations *ops = get_cpu_ops(cpu);

	if (sctx) {
		cpu_preserved_inval(&sctx->fault);
		if (READ_ONCE(sctx->fault.count)) {
			const struct arm64_preserved_fault *f = &sctx->fault;

			pr_err("cpu_preserve: CPU %d unhandled fault kind=%lu esr=0x%lx elr=0x%lx (%pS) far=0x%lx spsr=0x%lx\n",
			       cpu, f->kind, f->esr, f->elr,
			       (void *)f->elr, f->far, f->spsr);
		}
	}

	if (ops && ops->cpu_kill)
		ops->cpu_kill(cpu);
}

