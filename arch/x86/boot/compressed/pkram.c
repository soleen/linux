// SPDX-License-Identifier: GPL-2.0

#include "misc.h"

#define PKRAM_MAGIC		0x706B726D

struct pkram_super_block {
	__u32	magic;

	__u64	node_pfn;
	__u64	region_list_pfn;
	__u64	nr_regions;
};

struct pkram_region {
	phys_addr_t base;
	phys_addr_t size;
};

struct pkram_region_list {
	__u64	prev_pfn;
	__u64	next_pfn;

	struct pkram_region regions[0];
};

#define PKRAM_REGIONS_LIST_MAX \
	((PAGE_SIZE-sizeof(struct pkram_region_list))/sizeof(struct pkram_region))

static u64 pkram_sb_pfn;
static struct pkram_super_block *pkram_sb;

void pkram_init(void)
{
	struct pkram_super_block *sb;
	char arg[32];

	if (cmdline_find_option("pkram", arg, sizeof(arg)) > 0) {
		if (kstrtoull(arg, 16, &pkram_sb_pfn) != 0)
			return;
	} else
		return;

	sb = (struct pkram_super_block *)(pkram_sb_pfn << PAGE_SHIFT);
	if (sb->magic != PKRAM_MAGIC) {
		debug_putstr("PKRAM: invalid super block\n");
		return;
	}

	pkram_sb = sb;
}

static struct pkram_region *pkram_first_region(struct pkram_super_block *sb, struct pkram_region_list **rlp, int *idx)
{
	if (!sb || !sb->region_list_pfn)
		return NULL;

	*rlp = (struct pkram_region_list *)(sb->region_list_pfn << PAGE_SHIFT);
	*idx = 0;

	return &(*rlp)->regions[0];
}

static struct pkram_region *pkram_next_region(struct pkram_region_list **rlp, int *idx)
{
	struct pkram_region_list *rl = *rlp;
	int i = *idx;

	i++;
	if (i >= PKRAM_REGIONS_LIST_MAX) {
		if (!rl->next_pfn) {
			debug_putstr("PKRAM: no more pkram_region_list pages\n");
			return NULL;
		}
		rl = (struct pkram_region_list *)(rl->next_pfn << PAGE_SHIFT);
		*rlp = rl;
		i = 0;
	}
	*idx = i;

	if (rl->regions[i].size == 0)
		return NULL;

	return &rl->regions[i];
}

int pkram_has_overlap(struct mem_vector *entry, struct mem_vector *overlap)
{
	struct pkram_region_list *rl;
	struct pkram_region *r;
	int idx;

	r = pkram_first_region(pkram_sb, &rl, &idx);

	while (r) {
		if (r->base + r->size <= entry->start) {
			r = pkram_next_region(&rl, &idx);
			continue;
		}
		if (r->base >= entry->start + entry->size)
			return 0;

		overlap->start = r->base;
		overlap->size = r->size;
		return 1;
	}

	return 0;
}
