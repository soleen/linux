/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * x86 architecture hooks for On-Core execution.
 */
#ifndef _ASM_X86_ONCORE_H
#define _ASM_X86_ONCORE_H

#include <linux/types.h>
#include <asm/msr.h>

static inline u64 __cpu_preserved_text arch_oncore_read_counter(void)
{
	return rdtsc();
}

#endif /* _ASM_X86_ONCORE_H */
