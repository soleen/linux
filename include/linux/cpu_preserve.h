/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * Preserved CPU across Live Update
 */
#ifndef _LINUX_CPU_PRESERVE_H
#define _LINUX_CPU_PRESERVE_H

#include <linux/compiler.h>
#include <linux/cpumask.h>
#include <linux/errno.h>
#include <linux/kho/abi/cpu.h>
#include <linux/list.h>
#include <linux/smp.h>
#include <linux/types.h>

#ifndef __CPU_PRESERVED_RUNTIME__
#define cpu_preserved_sym(sym)		__cpu_preserved_##sym
#define __cpu_preserved_sym_asm(sym)	__asm__("__cpu_preserved_" #sym)
#else
#define cpu_preserved_sym(sym)		sym
#define __cpu_preserved_sym_asm(sym)
#endif

#ifdef CONFIG_LIVEUPDATE_CPU

#include <asm/cpu_preserve.h>
#include <asm/page.h>

#define CPU_PRESERVED_STACK_SIZE	THREAD_SIZE
#define CPU_PRESERVED_STACK_HEADROOM	256
#define CPU_PRESERVED_STACK_MAGIC	0x435055505354414bULL	/* "CPUPSTAK" */

struct cpu_preserved_ser;

/**
 * struct cpu_preserved_stack_context - Context header at base of preserved CPU stack
 * @magic:            Validation signature (%CPU_PRESERVED_STACK_MAGIC).
 * @cpu:              Logical CPU identifier of the preserved physical core.
 * @session_pgd_pa:   Session root page table physical address, or 0.
 * @ser:              Preserved CPU descriptor in isolated address space.
 *
 * This structure lives at the base of a preserved CPU's dedicated stack and is
 * accessed by the preserved CPU during parking. It is private to the preserved
 * CPU execution context of the kernel that allocated it.
 */
struct cpu_preserved_stack_context {
	u64 magic;
	u32 cpu;
	u64 session_pgd_pa;
	struct cpu_preserved_ser *ser;
};

static_assert(offsetof(struct cpu_preserved_stack_context, magic) == 0,
	      "magic must lead: the struct is found by masking the stack pointer");

/**
 * cpu_preserved_get_stack_context - Return the context block at the base of the preserved stack
 *
 * Masks the current stack pointer to %CPU_PRESERVED_STACK_SIZE alignment and
 * validates %CPU_PRESERVED_STACK_MAGIC.
 *
 * Return: Pointer to &struct cpu_preserved_stack_context if executing on a
 *         preserved CPU stack, or %NULL otherwise.
 */
static __always_inline struct cpu_preserved_stack_context *
cpu_preserved_get_stack_context(void)
{
	struct cpu_preserved_stack_context *sctx;
	unsigned long sp;

#if defined(CONFIG_X86_64)
	asm volatile("mov %%rsp, %0" : "=r"(sp));
#elif defined(CONFIG_ARM64)
	asm volatile("mov %0, sp" : "=r"(sp));
#else
	return NULL;
#endif
	sctx = (struct cpu_preserved_stack_context *)(sp & ~(CPU_PRESERVED_STACK_SIZE - 1));
	if (sctx && sctx->magic == CPU_PRESERVED_STACK_MAGIC)
		return sctx;
	return NULL;
}

extern char __cpu_preserved_text_start[], __cpu_preserved_text_end[];
extern char __cpu_preserved_data_start[], __cpu_preserved_data_end[];
bool cpu_is_preserved(int cpu) __cpu_preserved_sym_asm(cpu_is_preserved);
void cpu_preserved_set_dead(void) __cpu_preserved_sym_asm(cpu_preserved_set_dead);
void cpu_preserved_park_loop(int cpu) __cpu_preserved_sym_asm(cpu_preserved_park_loop);

void arch_cpu_preserved_park_wait(void);
void arch_cpu_preserved_park_init(int cpu);
void arch_cpu_preserved_dcache_clean(unsigned long start, unsigned long end);
void arch_cpu_preserved_dcache_inval(unsigned long start, unsigned long end);

const struct cpumask *cpu_get_preserved_mask(void);
struct cpu_preserved_stack_context *cpu_preserved_get_sctx(int cpu);

struct page;

/**
 * arch_cpu_preserved_setup_buffer - Map preserved execution buffer outside Scratch
 * @text_page: Head page of allocated preserved text memory.
 * @text_nr_pages: Number of pages in the preserved text buffer.
 * @data_page: Head page of allocated preserved data memory.
 * @data_nr_pages: Number of pages in the preserved data buffer.
 *
 * Architecture backend hook to remap kernel page table entries for
 * .cpu_preserved.text and .cpu_preserved.data to the newly allocated
 * pages outside Scratch memory.
 *
 * Return: 0 on success, or a negative errno on failure.
 */
int arch_cpu_preserved_setup_buffer(struct page *text_page,
				    unsigned int text_nr_pages,
				    struct page *data_page,
				    unsigned int data_nr_pages);

struct cpu_preserved_as_ser *cpu_preserved_as_create(void);
void cpu_preserved_as_adopt(struct cpu_preserved_as_ser *ser);
void cpu_preserved_as_unpreserve(struct cpu_preserved_as_ser *ser);
void cpu_preserved_as_restore_free(struct cpu_preserved_as_ser *ser);
int cpu_preserved_as_map(struct cpu_preserved_as_ser *as, phys_addr_t pa,
			 unsigned long va, size_t size, pgprot_t prot);
void cpu_preserved_as_unmap(struct cpu_preserved_as_ser *as,
			    unsigned long va, size_t size);
void cpu_preserved_free_kho(void *va, bool is_incoming);
void *cpu_preserved_as_alloc_page(void *arg);

/**
 * arch_cpu_preserved_as_map - Add one range to a preserved address space
 * @as: Address space to map into; its root PGD is at @as->pgd_pa.
 * @pa: Physical address of the range.
 * @va: Virtual address the range must appear at.
 * @size: Size of the range in bytes.
 * @prot: Protection to apply.
 *
 * Architecture backend for cpu_preserved_as_map(). Page table pages must be
 * obtained from cpu_preserved_as_alloc_page() with @as as its argument, so
 * that the core layer can preserve and later free them; the caller holds the
 * mapping lock and takes care of cache maintenance and of the TLB.
 *
 * Return: 0 on success, or a negative errno on failure.
 */
int arch_cpu_preserved_as_map(struct cpu_preserved_as_ser *as, phys_addr_t pa,
			      unsigned long va, size_t size, pgprot_t prot);

/**
 * arch_cpu_preserved_as_unmap - Remove one range from a preserved address space
 * @as: Address space to unmap from; its root PGD is at @as->pgd_pa.
 * @va: Virtual address of the range to unmap.
 * @size: Size of the range in bytes.
 *
 * Clears page table entries covering [@va, @va + @size) in @as.
 *
 * Return: %true if any PTE was cleared, %false otherwise.
 */
bool arch_cpu_preserved_as_unmap(struct cpu_preserved_as_ser *as,
				 unsigned long va, size_t size);

/**
 * arch_cpu_preserved_as_flush_tlb - Publish preserved page table updates
 *
 * Called after every successful arch_cpu_preserved_as_map() or
 * arch_cpu_preserved_as_unmap(). Architectures whose preserved CPUs can hold
 * stale translations for these address spaces must invalidate them here.
 */
void arch_cpu_preserved_as_flush_tlb(void);

#else /* !CONFIG_LIVEUPDATE_CPU */

#include <linux/kexec_handover.h>

struct cpu_preserved_as_ser;

static inline bool cpu_is_preserved(int cpu) { return false; }
static inline void cpu_preserved_set_dead(void) {}
static inline void arch_cpu_preserved_park_wait(void) {}
static inline void arch_cpu_preserved_park_init(int cpu) {}
static inline void arch_cpu_preserved_dcache_clean(unsigned long start,
						   unsigned long end) {}
static inline void arch_cpu_preserved_dcache_inval(unsigned long start,
						   unsigned long end) {}
static inline const struct cpumask *cpu_get_preserved_mask(void)
{
	return cpu_none_mask;
}

static inline struct cpu_preserved_stack_context *
cpu_preserved_get_sctx(int cpu)
{
	return NULL;
}

static inline void cpu_preserved_as_unmap(struct cpu_preserved_as_ser *as,
					  unsigned long va, size_t size) {}

static inline void cpu_preserved_free_kho(void *va, bool is_incoming)
{
	if (!va)
		return;
	if (is_incoming)
		kho_restore_free(va);
	else
		kho_unpreserve_free(va);
}

static inline int arch_cpu_preserved_setup_buffer(struct page *text_page,
						  unsigned int text_nr_pages,
						  struct page *data_page,
						  unsigned int data_nr_pages)
{
	return 0;
}

static __always_inline struct cpu_preserved_stack_context *
cpu_preserved_get_stack_context(void)
{
	return NULL;
}

#endif /* CONFIG_LIVEUPDATE_CPU */

#define cpu_preserved_clean_sz(p, sz)						arch_cpu_preserved_dcache_clean((unsigned long)(p),							(unsigned long)(p) + (sz))
#define cpu_preserved_inval_sz(p, sz)						arch_cpu_preserved_dcache_inval((unsigned long)(p),							(unsigned long)(p) + (sz))
#define cpu_preserved_clean(p)		cpu_preserved_clean_sz(p, sizeof(*(p)))
#define cpu_preserved_inval(p)		cpu_preserved_inval_sz(p, sizeof(*(p)))

#endif /* _LINUX_CPU_PRESERVE_H */
