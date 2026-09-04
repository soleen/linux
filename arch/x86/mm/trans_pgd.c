// SPDX-License-Identifier: GPL-2.0
/*
 * Transition page tables for x86_64.
 *
 * Provides generic helpers to populate page table hierarchies for transitional
 * execution (live update CPU preservation).
 */

#include <linux/mm.h>
#include <linux/pgtable.h>

#include <asm/io.h>
#include <asm/pgalloc.h>
#include <asm/trans_pgd.h>

static void *trans_alloc(struct trans_pgd_info *info)
{
	return info->trans_alloc_page(info->trans_alloc_arg);
}

/**
 * trans_pgd_map_range - Map a physical address range into a transition page table
 * @info: Transition page table allocation info containing the page allocator
 * @trans_pgd: Root transition page table pointer
 * @pa: Physical address to map
 * @va: Virtual address to map to
 * @size: Size of the range to map in bytes (page-aligned)
 * @prot: Page protection attributes (e.g. PAGE_KERNEL, PAGE_KERNEL_ROX)
 *
 * Populates the page table hierarchy (P4D, PUD, PMD, PTE) allocating new
 * intermediate tables using info->trans_alloc_page() as needed. Used by
 * liveupdate Caretaker to construct isolated page tables.
 *
 * Return: 0 on success, negative error code on failure.
 */
int trans_pgd_map_range(struct trans_pgd_info *info, pgd_t *trans_pgd,
			phys_addr_t pa, unsigned long va, size_t size,
			pgprot_t prot)
{
	unsigned long end = va + size;
	unsigned long addr = va;

	if (!info || !trans_pgd || !size)
		return -EINVAL;

	while (addr < end) {
		pgd_t *pgdp = pgd_offset_pgd(trans_pgd, addr);
		p4d_t *p4dp;
		pud_t *pudp;
		pmd_t *pmdp;
		pte_t *ptep;

		if (pgtable_l5_enabled()) {
			if (pgd_none(READ_ONCE(*pgdp))) {
				p4dp = trans_alloc(info);
				if (!p4dp)
					return -ENOMEM;
				set_pgd(pgdp, __pgd(virt_to_phys(p4dp) | _KERNPG_TABLE));
			}
		}
		p4dp = p4d_offset(pgdp, addr);

		if (p4d_none(READ_ONCE(*p4dp))) {
			pudp = trans_alloc(info);
			if (!pudp)
				return -ENOMEM;
			set_p4d(p4dp, __p4d(virt_to_phys(pudp) | _KERNPG_TABLE));
		}
		pudp = pud_offset(p4dp, addr);

		if (pud_none(READ_ONCE(*pudp)) || (pud_val(READ_ONCE(*pudp)) & _PAGE_PSE)) {
			pmdp = trans_alloc(info);
			if (!pmdp)
				return -ENOMEM;
			set_pud(pudp, __pud(virt_to_phys(pmdp) | _KERNPG_TABLE));
		}
		pmdp = pmd_offset(pudp, addr);

		if (pmd_none(READ_ONCE(*pmdp)) || (pmd_val(READ_ONCE(*pmdp)) & _PAGE_PSE)) {
			ptep = trans_alloc(info);
			if (!ptep)
				return -ENOMEM;
			set_pmd(pmdp, __pmd(virt_to_phys(ptep) | _KERNPG_TABLE));
		}
		ptep = pte_offset_kernel(pmdp, addr);

		set_pte(ptep, pfn_pte(PHYS_PFN(pa), prot));

		addr += PAGE_SIZE;
		pa += PAGE_SIZE;
	}

	return 0;
}

