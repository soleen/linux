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
#include <asm/arch_timer.h>

static __always_inline u64 arch_oncore_read_counter(void)
{
	isb();
	return read_sysreg(cntpct_el0);
}

static inline u64 arch_oncore_counter_freq_hz(void)
{
	return arch_timer_get_cntfrq();
}

#endif /* _ASM_ARM64_ONCORE_H */
