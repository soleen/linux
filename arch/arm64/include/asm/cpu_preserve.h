/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 */
#ifndef __ASM_ARM64_CPU_PRESERVE_H
#define __ASM_ARM64_CPU_PRESERVE_H

#include <asm/memory.h>
#include <asm/tlbflush.h>
#include <asm/virt.h>

bool arch_cpu_preserved_is_active(void)
	__cpu_preserved_sym_asm(arch_cpu_preserved_is_active);
asmlinkage void __arch_cpu_preserved_dcache_clean(unsigned long start, unsigned long end)
	__cpu_preserved_sym_asm(__arch_cpu_preserved_dcache_clean);
asmlinkage void arch_cpu_preserved_dcache_clean(unsigned long start, unsigned long end)
	__cpu_preserved_sym_asm(arch_cpu_preserved_dcache_clean);
asmlinkage void arch_cpu_preserved_dcache_inval(unsigned long start, unsigned long end)
	__cpu_preserved_sym_asm(arch_cpu_preserved_dcache_inval);
asmlinkage void __arch_cpu_preserved_park_on_stack(int cpu, unsigned long stack_top)
	__cpu_preserved_sym_asm(__arch_cpu_preserved_park_on_stack);

static __always_inline void arm64_flush_host_tlb_local(void)
{
	dsb(nshst);
	if (read_sysreg(CurrentEL) == CurrentEL_EL2) {
		asm volatile("tlbi alle2\n"
			     "dsb nsh\n"
			     "isb\n" ::: "memory");
	} else {
		__tlbi(vmalle1);
		dsb(nsh);
		isb();
	}
}

static inline void arm64_flush_host_tlb_all(void)
{
	dsb(ishst);
	if (is_kernel_in_hyp_mode()) {
		asm volatile("tlbi alle2is\n"
			     "dsb ish\n"
			     "isb\n" ::: "memory");
	} else {
		flush_tlb_all();
	}
}

#ifdef CONFIG_LIVEUPDATE_CPU
struct arm64_preserved_fault {
	unsigned long count;
	unsigned long kind;	/* vector entry, 0..15 */
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
#else
static inline void gicv3_cpu_preserved_clear_active_priorities(void) {}
static inline void gicv3_cpu_preserved_enable_sgi(void) {}
static inline void gicv3_cpu_preserved_kick_mpidr(u64 mpidr) {}
#endif

#endif /* __ASM_ARM64_CPU_PRESERVE_H */
