// SPDX-License-Identifier: GPL-2.0
/*
 * Transition page tables for x86_64.
 *
 * Provides generic helpers to clone page table hierarchies for transitional
 * execution (kexec, hibernation, live update CPU preservation).
 */

#include <asm/trans_pgd.h>
#include <linux/pgtable.h>
#include <linux/mm.h>
#include <asm/pgalloc.h>
#include <asm/io.h>

static void *trans_alloc(struct trans_pgd_info *info)
{
	return info->trans_alloc_page(info->trans_alloc_arg);
}

static pte_t *clone_pte_table(struct trans_pgd_info *info, pte_t *orig_pte)
{
	pte_t *new_pte = trans_alloc(info);

	if (!new_pte)
		return NULL;
	memcpy(new_pte, orig_pte, PAGE_SIZE);
	return new_pte;
}

static pmd_t *clone_pmd_table(struct trans_pgd_info *info, pmd_t *orig_pmd)
{
	pmd_t *new_pmd = trans_alloc(info);
	int i;

	if (!new_pmd)
		return NULL;

	for (i = 0; i < PTRS_PER_PMD; i++) {
		pmd_t pmd = orig_pmd[i];

		if (pmd_present(pmd) && !(pmd_val(pmd) & _PAGE_PSE)) {
			pte_t *orig_pte = (pte_t *)pmd_page_vaddr(pmd);
			pte_t *new_pte = clone_pte_table(info, orig_pte);

			if (new_pte) {
				phys_addr_t new_pte_pa = virt_to_phys(new_pte);
				new_pmd[i] = __pmd(new_pte_pa | pmd_flags(pmd));
				continue;
			}
		}
		new_pmd[i] = pmd;
	}
	return new_pmd;
}

static pud_t *clone_pud_table(struct trans_pgd_info *info, pud_t *orig_pud)
{
	pud_t *new_pud = trans_alloc(info);
	int i;

	if (!new_pud)
		return NULL;

	for (i = 0; i < PTRS_PER_PUD; i++) {
		pud_t pud = orig_pud[i];

		if (pud_present(pud) && !(pud_val(pud) & _PAGE_PSE)) {
			pmd_t *orig_pmd = pud_pgtable(pud);
			pmd_t *new_pmd = clone_pmd_table(info, orig_pmd);

			if (new_pmd) {
				phys_addr_t new_pmd_pa = virt_to_phys(new_pmd);
				new_pud[i] = __pud(new_pmd_pa | pud_flags(pud));
				continue;
			}
		}
		new_pud[i] = pud;
	}
	return new_pud;
}

static p4d_t *clone_p4d_table(struct trans_pgd_info *info, p4d_t *orig_p4d)
{
	p4d_t *new_p4d = trans_alloc(info);
	int i;

	if (!new_p4d)
		return NULL;

	for (i = 0; i < PTRS_PER_P4D; i++) {
		p4d_t p4d = orig_p4d[i];

		if (p4d_present(p4d)) {
			pud_t *orig_pud = p4d_pgtable(p4d);
			pud_t *new_pud = clone_pud_table(info, orig_pud);

			if (new_pud) {
				phys_addr_t new_pud_pa = virt_to_phys(new_pud);
				new_p4d[i] = __p4d(new_pud_pa | p4d_flags(p4d));
				continue;
			}
		}
		new_p4d[i] = p4d;
	}
	return new_p4d;
}

int trans_pgd_create_copy(struct trans_pgd_info *info, pgd_t **dst_pgdp,
			  unsigned long start, unsigned long end)
{
	pgd_t *new_pgd = trans_alloc(info);
	int start_idx = pgd_index(start);
	int end_idx = end ? pgd_index(end) : PTRS_PER_PGD;
	int i;

	if (!new_pgd)
		return -ENOMEM;

	for (i = 0; i < PTRS_PER_PGD; i++) {
		pgd_t pgd = init_top_pgt[i];

		if (i >= start_idx && i < end_idx && (pgd_val(pgd) & _PAGE_PRESENT)) {
			if (pgtable_l5_enabled()) {
				p4d_t *orig_p4d = (p4d_t *)pgd_page_vaddr(pgd);
				p4d_t *new_p4d = clone_p4d_table(info, orig_p4d);

				if (new_p4d) {
					phys_addr_t new_p4d_pa = virt_to_phys(new_p4d);
					new_pgd[i] = __pgd(new_p4d_pa | (pgd_val(pgd) & PTE_FLAGS_MASK));
					continue;
				}
				return -ENOMEM;
			} else {
				pud_t *orig_pud = (pud_t *)pgd_page_vaddr(pgd);
				pud_t *new_pud = clone_pud_table(info, orig_pud);

				if (new_pud) {
					phys_addr_t new_pud_pa = virt_to_phys(new_pud);
					new_pgd[i] = __pgd(new_pud_pa | (pgd_val(pgd) & PTE_FLAGS_MASK));
					continue;
				}
				return -ENOMEM;
			}
		}
		new_pgd[i] = pgd;
	}

	*dst_pgdp = new_pgd;
	return 0;
}

static int trans_pgd_map_pte(struct trans_pgd_info *info, pmd_t *pmdp,
			     phys_addr_t pa, unsigned long va,
			     unsigned long end, pgprot_t prot)
{
	pte_t *ptep;

	if (pmd_none(*pmdp) || (pmd_val(*pmdp) & _PAGE_PSE)) {
		ptep = trans_alloc(info);
		if (!ptep)
			return -ENOMEM;
		set_pmd(pmdp, __pmd(virt_to_phys(ptep) | _KERNPG_TABLE));
	} else {
		ptep = (pte_t *)pmd_page_vaddr(*pmdp);
	}

	for (; va < end; va += PAGE_SIZE, pa += PAGE_SIZE)
		set_pte(ptep + pte_index(va), pfn_pte(PHYS_PFN(pa), prot));

	return 0;
}

static int trans_pgd_map_pmd(struct trans_pgd_info *info, pud_t *pudp,
			     phys_addr_t pa, unsigned long va,
			     unsigned long end, pgprot_t prot)
{
	pmd_t *pmdp;
	unsigned long next;
	int ret;

	if (pud_none(*pudp) || (pud_val(*pudp) & _PAGE_PSE)) {
		pmdp = trans_alloc(info);
		if (!pmdp)
			return -ENOMEM;
		set_pud(pudp, __pud(virt_to_phys(pmdp) | _KERNPG_TABLE));
	} else {
		pmdp = pud_pgtable(*pudp);
	}

	for (; va < end; va = next) {
		next = pmd_addr_end(va, end);
		ret = trans_pgd_map_pte(info, pmdp + pmd_index(va), pa, va, next, prot);
		if (ret)
			return ret;
		pa += next - va;
	}
	return 0;
}

static int trans_pgd_map_pud(struct trans_pgd_info *info, p4d_t *p4dp,
			     phys_addr_t pa, unsigned long va,
			     unsigned long end, pgprot_t prot)
{
	pud_t *pudp;
	unsigned long next;
	int ret;

	if (p4d_none(*p4dp)) {
		pudp = trans_alloc(info);
		if (!pudp)
			return -ENOMEM;
		set_p4d(p4dp, __p4d(virt_to_phys(pudp) | _KERNPG_TABLE));
	} else {
		pudp = p4d_pgtable(*p4dp);
	}

	for (; va < end; va = next) {
		next = pud_addr_end(va, end);
		ret = trans_pgd_map_pmd(info, pudp + pud_index(va), pa, va, next, prot);
		if (ret)
			return ret;
		pa += next - va;
	}
	return 0;
}

static int trans_pgd_map_p4d(struct trans_pgd_info *info, pgd_t *pgdp,
			     phys_addr_t pa, unsigned long va,
			     unsigned long end, pgprot_t prot)
{
	p4d_t *p4dp;
	unsigned long next;
	int ret;

	if (pgtable_l5_enabled()) {
		if (pgd_none(*pgdp)) {
			p4dp = trans_alloc(info);
			if (!p4dp)
				return -ENOMEM;
			set_pgd(pgdp, __pgd(virt_to_phys(p4dp) | _KERNPG_TABLE));
		} else {
			p4dp = (p4d_t *)pgd_page_vaddr(*pgdp);
		}

		for (; va < end; va = next) {
			next = p4d_addr_end(va, end);
			ret = trans_pgd_map_pud(info, p4dp + p4d_index(va), pa, va, next, prot);
			if (ret)
				return ret;
			pa += next - va;
		}
		return 0;
	}

	return trans_pgd_map_pud(info, (p4d_t *)pgdp, pa, va, end, prot);
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
	unsigned long next;
	int ret;

	if (!info || !trans_pgd || !size)
		return -EINVAL;

	for (; va < end; va = next) {
		next = pgd_addr_end(va, end);
		ret = trans_pgd_map_p4d(info, trans_pgd + pgd_index(va), pa, va, next, prot);
		if (ret)
			return ret;
		pa += next - va;
	}
	return 0;
}

