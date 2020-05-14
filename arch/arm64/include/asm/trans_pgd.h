/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2020, Microsoft Corporation.
 * Pavel Tatashin <pasha.tatashin@soleen.com>
 */

#ifndef _ASM_TRANS_TABLE_H
#define _ASM_TRANS_TABLE_H

#include <linux/bits.h>
#include <linux/types.h>
#include <asm/pgtable-types.h>

/*
 * trans_alloc_page
 *	- Allocator that should return exactly one zeroed page, if this
 *	allocator fails, trans_pgd returns -ENOMEM error.
 *
 * trans_alloc_arg
 *	- Passed to trans_alloc_page as an argument
 */
struct trans_pgd_info {
	void * (*trans_alloc_page)(void *arg);
	void *trans_alloc_arg;
};

int trans_pgd_create_copy(pgd_t **dst_pgdp, unsigned long start,
			  unsigned long end);

int trans_idmap_single_page(const struct trans_pgd_info *info,
			    phys_addr_t phys_dst_addr, pgprot_t pgprot,
			    unsigned long *idmap_t0sz, pgd_t **idmap);


#endif /* _ASM_TRANS_TABLE_H */

