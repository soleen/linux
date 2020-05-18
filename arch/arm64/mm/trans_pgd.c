// SPDX-License-Identifier: GPL-2.0

/*
 * Transitional page tables for kexec and hibernate
 *
 * This file derived from: arch/arm64/kernel/hibernate.c
 *
 * Copyright (c) 2020, Microsoft Corporation.
 * Pavel Tatashin <pasha.tatashin@soleen.com>
 *
 */

/*
 * Transitional tables are used during system transferring from one world to
 * another: such as during hibernate restore, and kexec reboots. During these
 * phases one cannot rely on page table not being overwritten. This is because
 * hibernate and kexec can overwrite the current page tables during transition.
 */

#include <linux/suspend.h>
#include <linux/bug.h>
#include <linux/mm.h>
#include <linux/mmzone.h>

#include <asm/pgalloc.h>
#include <asm/trans_pgd.h>

static void *trans_alloc(const struct trans_pgd_info *info)
{
	return info->trans_alloc_page(info->trans_alloc_arg);
}

static void _copy_pte(pte_t *dst_ptep, pte_t *src_ptep, unsigned long addr)
{
	pte_t pte = READ_ONCE(*src_ptep);

	if (pte_valid(pte)) {
		/*
		 * Resume will overwrite areas that may be marked
		 * read only (code, rodata). Clear the RDONLY bit from
		 * the temporary mappings we use during restore.
		 */
		set_pte(dst_ptep, pte_mkwrite(pte));
	} else if (debug_pagealloc_enabled() && !pte_none(pte)) {
		/*
		 * debug_pagealloc will removed the PTE_VALID bit if
		 * the page isn't in use by the resume kernel. It may have
		 * been in use by the original kernel, in which case we need
		 * to put it back in our copy to do the restore.
		 *
		 * Before marking this entry valid, check the pfn should
		 * be mapped.
		 */
		BUG_ON(!pfn_valid(pte_pfn(pte)));

		set_pte(dst_ptep, pte_mkpresent(pte_mkwrite(pte)));
	}
}

static int copy_pte(const struct trans_pgd_info *info,
		    pmd_t *dst_pmdp, pmd_t *src_pmdp, unsigned long start,
		    unsigned long end)
{
	pte_t *src_ptep;
	pte_t *dst_ptep;
	unsigned long addr = start;

	dst_ptep = trans_alloc(info);
	if (!dst_ptep)
		return -ENOMEM;
	pmd_populate_kernel(&init_mm, dst_pmdp, dst_ptep);
	dst_ptep = pte_offset_kernel(dst_pmdp, start);

	src_ptep = pte_offset_kernel(src_pmdp, start);
	do {
		_copy_pte(dst_ptep, src_ptep, addr);
	} while (dst_ptep++, src_ptep++, addr += PAGE_SIZE, addr != end);

	return 0;
}

static int copy_pmd(const struct trans_pgd_info *info,
		    pud_t *dst_pudp, pud_t *src_pudp, unsigned long start,
		    unsigned long end)
{
	pmd_t *src_pmdp;
	pmd_t *dst_pmdp;
	unsigned long next;
	unsigned long addr = start;

	if (pud_none(READ_ONCE(*dst_pudp))) {
		dst_pmdp = trans_alloc(info);
		if (!dst_pmdp)
			return -ENOMEM;
		pud_populate(&init_mm, dst_pudp, dst_pmdp);
	}
	dst_pmdp = pmd_offset(dst_pudp, start);

	src_pmdp = pmd_offset(src_pudp, start);
	do {
		pmd_t pmd = READ_ONCE(*src_pmdp);

		next = pmd_addr_end(addr, end);
		if (pmd_none(pmd))
			continue;
		if (pmd_table(pmd)) {
			if (copy_pte(info, dst_pmdp, src_pmdp, addr, next))
				return -ENOMEM;
		} else {
			set_pmd(dst_pmdp,
				__pmd(pmd_val(pmd) & ~PMD_SECT_RDONLY));
		}
	} while (dst_pmdp++, src_pmdp++, addr = next, addr != end);

	return 0;
}

static int copy_pud(const struct trans_pgd_info *info,
		    p4d_t *dst_p4dp, p4d_t *src_p4dp, unsigned long start,
		    unsigned long end)
{
	pud_t *dst_pudp;
	pud_t *src_pudp;
	unsigned long next;
	unsigned long addr = start;

	if (p4d_none(READ_ONCE(*dst_p4dp))) {
		dst_pudp = trans_alloc(info);
		if (!dst_pudp)
			return -ENOMEM;
		p4d_populate(&init_mm, dst_p4dp, dst_pudp);
	}
	dst_pudp = pud_offset(dst_p4dp, start);

	src_pudp = pud_offset(src_p4dp, start);
	do {
		pud_t pud = READ_ONCE(*src_pudp);

		next = pud_addr_end(addr, end);
		if (pud_none(pud))
			continue;
		if (pud_table(pud)) {
			if (copy_pmd(info, dst_pudp, src_pudp, addr, next))
				return -ENOMEM;
		} else {
			set_pud(dst_pudp,
				__pud(pud_val(pud) & ~PUD_SECT_RDONLY));
		}
	} while (dst_pudp++, src_pudp++, addr = next, addr != end);

	return 0;
}

static int copy_p4d(const struct trans_pgd_info *info,
		    pgd_t *dst_pgdp, pgd_t *src_pgdp, unsigned long start,
		    unsigned long end)
{
	p4d_t *dst_p4dp;
	p4d_t *src_p4dp;
	unsigned long next;
	unsigned long addr = start;

	dst_p4dp = p4d_offset(dst_pgdp, start);
	src_p4dp = p4d_offset(src_pgdp, start);
	do {
		next = p4d_addr_end(addr, end);
		if (p4d_none(READ_ONCE(*src_p4dp)))
			continue;
		if (copy_pud(info, dst_p4dp, src_p4dp, addr, next))
			return -ENOMEM;
	} while (dst_p4dp++, src_p4dp++, addr = next, addr != end);

	return 0;
}

static int copy_page_tables(const struct trans_pgd_info *info,
			    pgd_t *dst_pgdp, unsigned long start,
			    unsigned long end)
{
	unsigned long next;
	unsigned long addr = start;
	pgd_t *src_pgdp = pgd_offset_k(start);

	dst_pgdp = pgd_offset_pgd(dst_pgdp, start);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none(READ_ONCE(*src_pgdp)))
			continue;
		if (copy_p4d(info, dst_pgdp, src_pgdp, addr, next))
			return -ENOMEM;
	} while (dst_pgdp++, src_pgdp++, addr = next, addr != end);

	return 0;
}

/*
 * Create trans_pgd and copy linear map.
 * info:	contains allocator and its argument
 * dst_pgdp:	new page table that is created, and to which map is copied.
 * start:	Start of the interval (inclusive).
 * end:	End of the interval (exclusive).
 *
 * Returns 0 on success, and -ENOMEM on failure.
 */
int trans_pgd_create_copy(const struct trans_pgd_info *info,
			  pgd_t **dst_pgdp, unsigned long start,
			  unsigned long end)
{
	int rc;
	pgd_t *trans_pgd = trans_alloc(info);

	if (!trans_pgd) {
		pr_err("Failed to allocate memory for temporary page tables.\n");
		return -ENOMEM;
	}

	rc = copy_page_tables(info, trans_pgd, start, end);
	if (!rc)
		*dst_pgdp = trans_pgd;

	return rc;
}

int trans_idmap_single_page(const struct trans_pgd_info *info,
			    phys_addr_t phys_dst_addr, pgprot_t pgprot,
			    unsigned long *idmap_t0sz, pgd_t **idmap)
{
	unsigned long level_mask;
	int this_level, index;
	unsigned long *levels[4] = { };
	int bits_mapped = PAGE_SHIFT - 4;
	unsigned int level_lsb, level_msb, max_msb;
	unsigned long pfn = __phys_to_pfn(phys_dst_addr);
	unsigned long prev_level_entry, *this_level_table;

	if (phys_dst_addr & GENMASK(52, 48))
		max_msb = 51;
	else
		max_msb = 47;

	/*
	 * The page we want to idmap may be outside the range covered by
	 * VA_BITS that can be built using the kernel's p?d_populate() helpers.
	 *
	 * As a one off, for a single page, we build these page tables bottom
	 * up and just assume that we will need the maximum T0SZ.
	 *
	 * Each table points its single entry at the lower level's table, but
	 * the lowest level points to phys_dst_addr, and is built first:
	 */
	phys_dst_addr &= PAGE_MASK;
	prev_level_entry = pte_val(pfn_pte(pfn, PAGE_KERNEL_EXEC));

	for (this_level = 3; this_level >= 0; this_level--) {
		this_level_table = (unsigned long *)trans_alloc(info);

		if (!this_level_table)
			return -ENOMEM;

		level_lsb = ARM64_HW_PGTABLE_LEVEL_SHIFT(this_level);
		level_msb = min(level_lsb + bits_mapped, max_msb);
		level_mask = GENMASK_ULL(level_msb, level_lsb);

		index = (phys_dst_addr & level_mask) >> level_lsb;
		this_level_table[index] = prev_level_entry;
		levels[this_level] = this_level_table;

		pfn = virt_to_pfn(this_level_table);
		prev_level_entry = pte_val(pfn_pte(pfn,
						    __pgprot(PMD_TYPE_TABLE)));

		if (level_msb == max_msb)
			break;
	}

	*idmap_t0sz = TCR_T0SZ(max_msb + 1);
	*idmap = (pgd_t *)this_level_table;

	return 0;
}

int arm64_copy_hyp_stub(const struct trans_pgd_info *info,
			phys_addr_t *el2_vectors)
{
	void *hyp_stub;
	unsigned long hyp_stub_end;

	/*
	 * EL2 vectors may get overwritten. Create a temporary copy of the
	 * hyp-stub we can use to call HVC_SET_VECTORS or HVC_SOFT_RESTART.
	 */
	hyp_stub = trans_alloc(info);
	if (!hyp_stub)
		return -ENOMEM;

	memcpy(hyp_stub, &__hyp_stub_vectors, SZ_2K);

	/* The hyp-stub executes at el2 with the mmu off */
	hyp_stub_end = (unsigned long)((char *)hyp_stub + SZ_2K);
	__flush_icache_range((unsigned long)hyp_stub, hyp_stub_end);
	__flush_dcache_area(hyp_stub, SZ_2K);

	*el2_vectors = virt_to_phys(hyp_stub);

	return 0;
}
