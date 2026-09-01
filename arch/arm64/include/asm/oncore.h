/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * ARM64 architecture hooks for On-Core execution.
 */
#ifndef _ASM_ARM64_ONCORE_H
#define _ASM_ARM64_ONCORE_H

#include <linux/types.h>
#include <asm/sysreg.h>

static inline u64 __cpu_preserved_text arch_oncore_read_counter(void)
{
	return read_sysreg(cntpct_el0);
}

#endif /* _ASM_ARM64_ONCORE_H */
