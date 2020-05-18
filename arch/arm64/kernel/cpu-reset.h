/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * CPU reset routines
 *
 * Copyright (C) 2015 Huawei Futurewei Technologies.
 */

#ifndef _ARM64_CPU_RESET_H
#define _ARM64_CPU_RESET_H

#include <asm/virt.h>

void __cpu_soft_restart(unsigned long entry,
	unsigned long arg0, unsigned long arg1, unsigned long arg2);

static inline void __noreturn cpu_soft_restart(unsigned long entry,
					       unsigned long arg0,
					       unsigned long arg1,
					       unsigned long arg2)
{
	typeof(__cpu_soft_restart) *restart;

	restart = (void *)__pa_symbol(__cpu_soft_restart);

	cpu_install_idmap();
	restart(entry, arg0, arg1, arg2);
	unreachable();
}

#endif
