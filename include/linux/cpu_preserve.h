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

/*
 * The preserved stack area holds the context block in its first page, an
 * unmapped guard page, then the stack.  It is naturally aligned, so the context
 * is found by masking the stack pointer.
 */
#ifndef CPU_PRESERVED_STACK_SIZE
#define CPU_PRESERVED_STACK_SIZE	(2 * THREAD_SIZE)
#endif
#define CPU_PRESERVED_STACK_GUARD	PAGE_SIZE
#define CPU_PRESERVED_STACK_BASE	(2 * PAGE_SIZE)
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
static_assert(sizeof(struct cpu_preserved_stack_context) <= CPU_PRESERVED_STACK_GUARD,
	      "the stack context must fit below the guard page");

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

	sctx = (struct cpu_preserved_stack_context *)
		(current_stack_pointer & ~(CPU_PRESERVED_STACK_SIZE - 1));
	if (sctx->magic == CPU_PRESERVED_STACK_MAGIC)
		return sctx;
	return NULL;
}

extern char __cpu_preserved_text_start[], __cpu_preserved_text_end[];
extern char __cpu_preserved_data_start[], __cpu_preserved_data_end[];
void cpu_preserved_set_dead(void) __cpu_preserved_sym_asm(cpu_preserved_set_dead);
void cpu_preserved_park_loop(int cpu) __cpu_preserved_sym_asm(cpu_preserved_park_loop);

/**
 * arch_cpu_preserved_park_wait - Wait in a low-power state until kicked
 *
 * Returns after arch_cpu_preserved_kick(), or spuriously, so callers re-check
 * their condition.  A kick sent before the call is not lost.
 */
void arch_cpu_preserved_park_wait(void);
void arch_cpu_preserved_park_init(int cpu);
void arch_cpu_preserved_dcache_clean(unsigned long start, unsigned long end)
	__cpu_preserved_sym_asm(arch_cpu_preserved_dcache_clean);
void arch_cpu_preserved_dcache_inval(unsigned long start, unsigned long end)
	__cpu_preserved_sym_asm(arch_cpu_preserved_dcache_inval);

#else /* !CONFIG_LIVEUPDATE_CPU */

static inline void cpu_preserved_set_dead(void) {}
static inline void arch_cpu_preserved_park_wait(void) {}
static inline void arch_cpu_preserved_park_init(int cpu) {}
static inline void arch_cpu_preserved_dcache_clean(unsigned long start,
						   unsigned long end) {}
static inline void arch_cpu_preserved_dcache_inval(unsigned long start,
						   unsigned long end) {}

static __always_inline struct cpu_preserved_stack_context *
cpu_preserved_get_stack_context(void)
{
	return NULL;
}

#endif /* CONFIG_LIVEUPDATE_CPU */

/*
 * Object-granular wrappers around the arch dcache hooks.
 *
 * Every preserved-memory handshake flushes or invalidates a whole object, so
 * spell that out once instead of open-coding (addr, addr + size) at each call
 * site: the size can then never drift from the object it is supposed to cover.
 *
 * @p is a pointer to the object.  For a statically sized array, pass &array so
 * that sizeof(*(p)) is the size of the whole array rather than of one element.
 * Use the _sz() forms for flexible-array structures and for raw page buffers,
 * where the length is not derivable from the type.
 */
static __always_inline void cpu_preserved_clean_sz(const void *p, size_t sz)
{
	arch_cpu_preserved_dcache_clean((unsigned long)p, (unsigned long)p + sz);
}

static __always_inline void cpu_preserved_inval_sz(const void *p, size_t sz)
{
	arch_cpu_preserved_dcache_inval((unsigned long)p, (unsigned long)p + sz);
}

#define cpu_preserved_clean(p)		cpu_preserved_clean_sz(p, sizeof(*(p)))
#define cpu_preserved_inval(p)		cpu_preserved_inval_sz(p, sizeof(*(p)))

#endif /* _LINUX_CPU_PRESERVE_H */
