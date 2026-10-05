/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 */
#ifndef __ASM_ARM64_CPU_PRESERVE_H
#define __ASM_ARM64_CPU_PRESERVE_H

#include <asm/memory.h>

/*
 * The context page and the guard page come out of the stack area: with 16K and
 * 64K pages, 2 * THREAD_SIZE would leave less than THREAD_SIZE of stack.
 */
#if THREAD_SIZE >= 2 * PAGE_SIZE
#define CPU_PRESERVED_STACK_SIZE	(2 * THREAD_SIZE)
#else
#define CPU_PRESERVED_STACK_SIZE	(4 * PAGE_SIZE)
#endif

#ifndef __ASSEMBLY__

#include <asm/tlbflush.h>

asmlinkage void __arch_cpu_preserved_dcache_clean(unsigned long start, unsigned long end)
	__cpu_preserved_sym_asm(__arch_cpu_preserved_dcache_clean);
asmlinkage void arch_cpu_preserved_dcache_clean(unsigned long start, unsigned long end)
	__cpu_preserved_sym_asm(arch_cpu_preserved_dcache_clean);
asmlinkage void arch_cpu_preserved_dcache_inval(unsigned long start, unsigned long end)
	__cpu_preserved_sym_asm(arch_cpu_preserved_dcache_inval);

static __always_inline void arm64_flush_host_tlb_local(void)
{
	local_flush_tlb_all();
}

static inline void arm64_flush_host_tlb_all(void)
{
	flush_tlb_all();
}

#ifdef CONFIG_LIVEUPDATE_CPU
void gicv3_cpu_preserved_clear_active_priorities(void)
	__cpu_preserved_sym_asm(gicv3_cpu_preserved_clear_active_priorities);
void gicv3_cpu_preserved_enable_sgi(void)
	__cpu_preserved_sym_asm(gicv3_cpu_preserved_enable_sgi);
void gicv3_cpu_preserved_kick_mpidr(u64 mpidr)
	__cpu_preserved_sym_asm(gicv3_cpu_preserved_kick_mpidr);
#else
static inline void gicv3_cpu_preserved_clear_active_priorities(void) {}
static inline void gicv3_cpu_preserved_enable_sgi(void) {}
static inline void gicv3_cpu_preserved_kick_mpidr(u64 mpidr) {}
#endif

#endif /* !__ASSEMBLY__ */

#endif /* __ASM_ARM64_CPU_PRESERVE_H */
