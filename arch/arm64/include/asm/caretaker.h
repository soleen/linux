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

extern char cpu_preserved_sym(caretaker_hyp_vector)[];
#ifndef __CPU_PRESERVED_RUNTIME__
#define caretaker_hyp_vector __cpu_preserved_caretaker_hyp_vector
#endif

static __always_inline int arm64_caretaker_get_pcpu(void)
{
	struct cpu_preserved_stack_context *sctx = cpu_preserved_get_stack_context();

	if (sctx)
		return sctx->cpu;
	return (int)MPIDR_AFFINITY_LEVEL(read_sysreg(mpidr_el1), 0);
}

#endif /* __ASM_ARM64_CARETAKER_H */
