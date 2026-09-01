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

bool arch_cpu_preserved_is_active(void);
asmlinkage void __arch_cpu_preserved_dcache_clean(unsigned long start, unsigned long end);
asmlinkage void arch_cpu_preserved_dcache_clean(unsigned long start, unsigned long end);
asmlinkage void arch_cpu_preserved_dcache_inval(unsigned long start, unsigned long end);

static __always_inline void arm64_flush_host_tlb_local(void)
{
	dsb(nshst);
	if (is_kernel_in_hyp_mode()) {
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

#endif /* __ASM_ARM64_CPU_PRESERVE_H */
