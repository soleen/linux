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
/**
 * struct arm64_preserved_fault - Exceptions taken by a preserved CPU
 * @count: Number of exceptions; the first one stopped the CPU.
 * @kind:  Vector table entry of the first exception, 0 to 15.
 * @esr:   Its exception syndrome.
 * @elr:   Its exception link address.
 * @far:   Its fault address.
 * @spsr:  Its saved program status.
 *
 * Private to the runtime, reported by arch_cpu_preserved_wait_dead().
 */
struct arm64_preserved_fault {
	unsigned long count;
	unsigned long kind;
	unsigned long esr;
	unsigned long elr;
	unsigned long far;
	unsigned long spsr;
};

extern char arm64_preserved_vectors[]
	__cpu_preserved_sym_asm(arm64_preserved_vectors);
asmlinkage void arm64_preserved_handle_exception(unsigned long kind)
	__cpu_preserved_sym_asm(arm64_preserved_handle_exception);

void gicv3_cpu_preserved_clear_active_priorities(void)
	__cpu_preserved_sym_asm(gicv3_cpu_preserved_clear_active_priorities);
void gicv3_cpu_preserved_enable_sgi(void)
	__cpu_preserved_sym_asm(gicv3_cpu_preserved_enable_sgi);
void gicv3_cpu_preserved_kick_mpidr(u64 mpidr)
	__cpu_preserved_sym_asm(gicv3_cpu_preserved_kick_mpidr);
int gicv3_cpu_preserved_get_redist_region(int idx, phys_addr_t *pa,
					  unsigned long *va, size_t *size);

u64 arch_cpu_preserved_mode(void);
#define arch_cpu_preserved_mode arch_cpu_preserved_mode
#else
static inline void gicv3_cpu_preserved_clear_active_priorities(void) {}
static inline void gicv3_cpu_preserved_enable_sgi(void) {}
static inline void gicv3_cpu_preserved_kick_mpidr(u64 mpidr) {}
static inline int gicv3_cpu_preserved_get_redist_region(int idx, phys_addr_t *pa,
							unsigned long *va,
							size_t *size)
{
	return -ENOENT;
}
#endif

#endif /* !__ASSEMBLY__ */

#endif /* __ASM_ARM64_CPU_PRESERVE_H */
