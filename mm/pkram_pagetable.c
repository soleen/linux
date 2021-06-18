// SPDX-License-Identifier: GPL-2.0
#include <linux/bitops.h>
//#include <asm/pgtable.h>
#include <linux/mm.h>

static pgd_t *pkram_pgd;
static DEFINE_SPINLOCK(pkram_pgd_lock);

#define PKRAM_PTE_BM_BYTES	(PTRS_PER_PTE / BITS_PER_BYTE)
#define PKRAM_PTE_BM_MASK	(PAGE_SIZE / PKRAM_PTE_BM_BYTES - 1)

static pmd_t make_bitmap_pmd(unsigned long *bitmap)
{
	unsigned long val;

	val = __pa(ALIGN_DOWN((unsigned long)bitmap, PAGE_SIZE));
	val |= (((unsigned long)bitmap & ~PAGE_MASK) / PKRAM_PTE_BM_BYTES);

	return __pmd(val);
}

static unsigned long *get_bitmap_addr(pmd_t pmd)
{
	unsigned long val, off;

	val = pmd_val(pmd);
	off = (val & PKRAM_PTE_BM_MASK) * PKRAM_PTE_BM_BYTES;

	val = (val & PAGE_MASK) + off;

	return __va(val);
}

int pkram_add_identity_map(struct page *page)
{
	unsigned long paddr;
	unsigned long *bitmap;
	unsigned int index;
	struct page *pg;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	if (!pkram_pgd) {
		spin_lock(&pkram_pgd_lock);
		if (!pkram_pgd) {
			pg = alloc_page(GFP_ATOMIC|__GFP_ZERO);
			if (!pg)
				goto nomem;
			pkram_pgd = page_address(pg);
		}
		spin_unlock(&pkram_pgd_lock);
	}

	paddr = __pa(page_address(page));
	pgd = pkram_pgd;
	pgd += pgd_index(paddr);
	if (pgd_none(*pgd)) {
		spin_lock(&pkram_pgd_lock);
		if (pgd_none(*pgd)) {
			pg = alloc_page(GFP_ATOMIC|__GFP_ZERO);
			if (!pg)
				goto nomem;
			p4d = page_address(pg);
			set_pgd(pgd, __pgd(__pa(p4d)));
		}
		spin_unlock(&pkram_pgd_lock);
	}
	p4d = p4d_offset(pgd, paddr);
	if (p4d_none(*p4d)) {
		spin_lock(&pkram_pgd_lock);
		if (p4d_none(*p4d)) {
			pg = alloc_page(GFP_ATOMIC|__GFP_ZERO);
			if (!pg)
				goto nomem;
			pud = page_address(pg);
			set_p4d(p4d, __p4d(__pa(pud)));
		}
		spin_unlock(&pkram_pgd_lock);
	}
	pud = pud_offset(p4d, paddr);
	if (pud_none(*pud)) {
		spin_lock(&pkram_pgd_lock);
		if (pud_none(*pud)) {
			pg = alloc_page(GFP_ATOMIC|__GFP_ZERO);
			if (!pg)
				goto nomem;
			pmd = page_address(pg);
			set_pud(pud, __pud(__pa(pmd)));
		}
		spin_unlock(&pkram_pgd_lock);
	}
	pmd = pmd_offset(pud, paddr);
	if (pmd_none(*pmd)) {
		spin_lock(&pkram_pgd_lock);
		if (pmd_none(*pmd)) {
			if (PageTransHuge(page)) {
				set_pmd(pmd, pmd_mkhuge(*pmd));
				spin_unlock(&pkram_pgd_lock);
				goto done;
			}
			bitmap = bitmap_zalloc(PTRS_PER_PTE, GFP_ATOMIC);
			if (!bitmap)
				goto nomem;
			set_pmd(pmd, make_bitmap_pmd(bitmap));
		} else {
			BUG_ON(pmd_large(*pmd));
			bitmap = get_bitmap_addr(*pmd);
		}
		spin_unlock(&pkram_pgd_lock);
	} else {
		BUG_ON(pmd_large(*pmd));
		bitmap = get_bitmap_addr(*pmd);
	}

	index = pte_index(paddr);
	set_bit(index, bitmap);
	smp_mb__after_atomic();
	if (bitmap_full(bitmap, PTRS_PER_PTE))
		set_pmd(pmd, pmd_mkhuge(*pmd));
done:
	return 0;
nomem:
	return -ENOMEM;
}

void pkram_remove_identity_map(struct page *page)
{
	unsigned long *bitmap;
	unsigned long paddr;
	unsigned int index;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	/*
	 * pkram_pgd will be null when freeing metadata pages after a reboot
	 */
	if (!pkram_pgd)
		return;

	paddr = __pa(page_address(page));
	pgd = pkram_pgd;
	pgd += pgd_index(paddr);
	if (pgd_none(*pgd)) {
		WARN_ONCE(1, "PKRAM: %s: no pgd for 0x%lx\n", __func__, paddr);
		return;
	}
	p4d = p4d_offset(pgd, paddr);
	if (p4d_none(*p4d)) {
		WARN_ONCE(1, "PKRAM: %s: no p4d for 0x%lx\n", __func__, paddr);
		return;
	}
	pud = pud_offset(p4d, paddr);
	if (pud_none(*pud)) {
		WARN_ONCE(1, "PKRAM: %s: no pud for 0x%lx\n", __func__, paddr);
		return;
	}
	pmd = pmd_offset(pud, paddr);
	if (pmd_none(*pmd)) {
		WARN_ONCE(1, "PKRAM: %s: no pmd for 0x%lx\n", __func__, paddr);
		return;
	}
	if (PageTransHuge(page)) {
		BUG_ON(!pmd_large(*pmd));
		pmd_clear(pmd);
		return;
	}

	if (pmd_large(*pmd)) {
		spin_lock(&pkram_pgd_lock);
		if (pmd_large(*pmd))
			set_pmd(pmd, __pmd(pte_val(pte_clrhuge(*(pte_t *)pmd))));
		spin_unlock(&pkram_pgd_lock);
	}

	bitmap = get_bitmap_addr(*pmd);
	index = pte_index(paddr);
	clear_bit(index, bitmap);
	smp_mb__after_atomic();

	spin_lock(&pkram_pgd_lock);
	if (!pmd_none(*pmd) && bitmap_empty(bitmap, PTRS_PER_PTE)) {
		pmd_clear(pmd);
		spin_unlock(&pkram_pgd_lock);
		bitmap_free(bitmap);
	} else {
		spin_unlock(&pkram_pgd_lock);
	}
}

struct pkram_pg_state {
	int (*range_cb)(unsigned long base, unsigned long size, void *private);
	unsigned long start_addr;
	unsigned long curr_addr;
	unsigned long min_addr;
	unsigned long max_addr;
	void *private;
	bool tracking;
};

#define pgd_none(a)  (pgtable_l5_enabled() ? pgd_none(a) : p4d_none(__p4d(pgd_val(a))))

static int note_page(struct pkram_pg_state *st, unsigned long addr, bool present)
{
	if (!st->tracking && present) {
		if (addr >= st->max_addr)
			return 1;
		/*
		 * addr can be < min_addr if the page straddles the
		 * boundary
		 */
		st->start_addr = max(addr, st->min_addr);
		st->tracking = true;
	} else if (st->tracking) {
		unsigned long base, size;
		int ret;

		/* Continue tracking if upper bound has not been reached */
		if (present && addr < st->max_addr)
			return 0;

		addr = min(addr, st->max_addr);

		base = st->start_addr;
		size = addr - st->start_addr;
		st->tracking = false;

		ret = st->range_cb(base, size, st->private);

		if (addr == st->max_addr)
			return 1;
		else
			return ret;
	}

	return 0;
}

static int walk_pte_level(struct pkram_pg_state *st, pmd_t addr, unsigned long P)
{
	unsigned long *bitmap;
	int present;
	int i, ret;

	bitmap = get_bitmap_addr(addr);
	for (i = 0; i < PTRS_PER_PTE; i++) {
		unsigned long curr_addr = P + i * PAGE_SIZE;

		if (curr_addr < st->min_addr)
			continue;
		present = test_bit(i, bitmap);
		ret = note_page(st, curr_addr, present);
		if (ret)
			break;
	}

	return ret;
}

static int walk_pmd_level(struct pkram_pg_state *st, pud_t addr, unsigned long P)
{
	pmd_t *start;
	int i, ret;

	start = (pmd_t *)pud_page_vaddr(addr);
	for (i = 0; i < PTRS_PER_PMD; i++, start++) {
		unsigned long curr_addr = P + i * PMD_SIZE;

		if (curr_addr + PMD_SIZE <= st->min_addr)
			continue;
		if (!pmd_none(*start)) {
			if (pmd_large(*start))
				ret = note_page(st, curr_addr, true);
			else
				ret = walk_pte_level(st, *start, curr_addr);
		} else
			ret = note_page(st, curr_addr, false);
		if (ret)
			break;
	}

	return ret;
}

static int walk_pud_level(struct pkram_pg_state *st, p4d_t addr, unsigned long P)
{
	pud_t *start;
	int i, ret;

	start = (pud_t *)p4d_page_vaddr(addr);
	for (i = 0; i < PTRS_PER_PUD; i++, start++) {
		unsigned long curr_addr = P + i * PUD_SIZE;

		if (curr_addr + PUD_SIZE <= st->min_addr)
			continue;
		if (!pud_none(*start)) {
			if (pud_large(*start))
				ret = note_page(st, curr_addr, true);
			else
				ret = walk_pmd_level(st, *start, curr_addr);
		} else
			ret = note_page(st, curr_addr, false);
		if (ret)
			break;
	}

	return ret;
}

static int walk_p4d_level(struct pkram_pg_state *st, pgd_t addr, unsigned long P)
{
	p4d_t *start;
	int i, ret;

	if (PTRS_PER_P4D == 1)
		return walk_pud_level(st, __p4d(pgd_val(addr)), P);

	start = (p4d_t *)pgd_page_vaddr(addr);
	for (i = 0; i < PTRS_PER_P4D; i++, start++) {
		unsigned long curr_addr = P + i * P4D_SIZE;

		if (curr_addr + P4D_SIZE <= st->min_addr)
			continue;
		if (!p4d_none(*start)) {
			if (p4d_large(*start))
				ret = note_page(st, curr_addr, true);
			else
				ret = walk_pud_level(st, *start, curr_addr);
		} else
			ret = note_page(st, curr_addr, false);
		if (ret)
			break;
	}

	return ret;
}

void pkram_walk_pgt(struct pkram_pg_state *st, pgd_t *pgd)
{
	pgd_t *start = pgd;
	int i, ret = 0;

	for (i = 0; i < PTRS_PER_PGD; i++, start++) {
		unsigned long curr_addr = i * PGDIR_SIZE;

		if (curr_addr + PGDIR_SIZE <= st->min_addr)
			continue;
		if (!pgd_none(*start))
			ret = walk_p4d_level(st, *start, curr_addr);
		else
			ret = note_page(st, curr_addr, false);
		if (ret)
			break;
	}
}

void pkram_find_preserved(unsigned long start, unsigned long end, void *private, int (*callback)(unsigned long base, unsigned long size, void *private))
{
	struct pkram_pg_state st = {
		.range_cb = callback,
		.min_addr = start,
		.max_addr = end,
		.private = private,
	};

	if (!pkram_pgd)
		return;

	pkram_walk_pgt(&st, pkram_pgd);
}
