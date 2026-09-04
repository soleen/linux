/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2021, Microsoft Corporation.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 */

#ifndef _ASM_TRANS_TABLE_H
#define _ASM_TRANS_TABLE_H

#include <linux/bits.h>
#include <linux/types.h>
#include <asm/pgtable-types.h>

/*
 * trans_alloc_page
 *	- Allocator that should return exactly one zeroed page, if this
 *	  allocator fails, trans_pgd_create_copy() and trans_pgd_idmap_page()
 *	  return -ENOMEM error.
 *
 * trans_alloc_arg
 *	- Passed to trans_alloc_page as an argument
 */

struct trans_pgd_info {
	void * (*trans_alloc_page)(void *arg);
	void *trans_alloc_arg;
};

/**
 * DOC: Transition Page Tables Isolated Mappings Specification
 *
 * For physical CPU preservation across live update and transitional phases,
 * transition page tables construct an isolated address space containing ONLY
 * the minimal virtual mappings required for on-core execution:
 *
 * 1. Caretaker Executable Text & Rodata (PAGE_KERNEL_ROX):
 *    [__cpu_preserved_text_start .. __cpu_preserved_text_end) and
 *    [__cpu_preserved_rodata_start .. __cpu_preserved_rodata_end).
 *    Contains parking loops, low-level world switch routines, ops vector
 *    tables, and exception stub vectors.
 *
 * 2. Caretaker Writable Global Data (PAGE_KERNEL, NX):
 *    [__cpu_preserved_data_start .. __cpu_preserved_data_end).
 *    Contains global state machines, session descriptors, per-CPU control
 *    blocks, and preserved CPU bitmasks.
 *
 * 3. Preserved Per-CPU Private Stacks (PAGE_KERNEL, NX):
 *    [pcpu->stack .. pcpu->stack + THREAD_SIZE) for each preserved CPU.
 *    Dedicated stack frames used exclusively by preserved cores.
 *
 * 4. Workload Attachment & vCPU Context Pages (PAGE_KERNEL, NX):
 *    KHO-preserved vCPU architectural state pages (struct caretaker_arm64_page)
 *    holding EL1/EL2 sysregs, GPRs, FP/SIMD, and VGICv3 redistributor state.
 *
 * 5. Hardware Control MMIO (Conditional):
 *    GIC CPU interface mapped as PAGE_KERNEL_IO only if using legacy GICv2 MMIO.
 *    In modern GICv3 system register mode, no MMIO mapping is created.
 *
 * Explicitly UNMAPPED (Forbidden):
 * - Direct physical memory linear map (PAGE_OFFSET).
 * - User space address ranges.
 * - Kernel heap, vmalloc, modules, and BPF JIT areas.
 * - Guest physical memory (translated directly via Stage-2 paging).
 */

int trans_pgd_create_copy(struct trans_pgd_info *info, pgd_t **trans_pgd,
			  unsigned long start, unsigned long end);

/**
 * trans_pgd_map_range - Map a virtual address range into a transition page table
 * @info: Transition page table allocation info containing the page allocator
 * @trans_pgd: Root transition page table pointer
 * @pa: Physical address to map
 * @va: Virtual address to map to
 * @size: Size of the range to map in bytes (page-aligned)
 * @prot: Page protection attributes (e.g. PAGE_KERNEL, PAGE_KERNEL_ROX)
 *
 * Return: 0 on success, negative error code on allocation failure.
 */
int trans_pgd_map_range(struct trans_pgd_info *info, pgd_t *trans_pgd,
			phys_addr_t pa, unsigned long va, size_t size,
			pgprot_t prot);

int trans_pgd_idmap_page(struct trans_pgd_info *info, phys_addr_t *trans_ttbr0,
			 unsigned long *t0sz, void *page);

int trans_pgd_copy_el2_vectors(struct trans_pgd_info *info,
			       phys_addr_t *el2_vectors);

extern char trans_pgd_stub_vectors[];

#endif /* _ASM_TRANS_TABLE_H */
