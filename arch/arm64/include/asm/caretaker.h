/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 */
#ifndef __ASM_ARM64_CARETAKER_H
#define __ASM_ARM64_CARETAKER_H

#include <linux/types.h>
#include <linux/cpu_preserve.h>
#include <asm/arch_timer.h>
#include <asm/cputype.h>
#include <asm/pgtable-types.h>
#include <asm/sysreg.h>

extern char cpupr_sym(caretaker_hyp_vector)[];
#ifndef __CPUPR_RUNTIME__
#define caretaker_hyp_vector __preserved_caretaker_hyp_vector
#endif

#ifdef __CPUPR_RUNTIME__
static __always_inline int arm64_caretaker_get_pcpu(void)
{
	struct cpupr_stack_context *sctx = cpupr_get_stack_context();

	if (sctx)
		return sctx->cpu;
	return (int)MPIDR_AFFINITY_LEVEL(read_sysreg(mpidr_el1), 0);
}
#endif

#endif /* __ASM_ARM64_CARETAKER_H */
