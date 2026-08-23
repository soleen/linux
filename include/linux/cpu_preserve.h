/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * Preserved CPU across Live Update
 */
#ifndef _LINUX_CPU_PRESERVE_H
#define _LINUX_CPU_PRESERVE_H

#include <linux/compiler.h>

#ifdef CONFIG_LIVEUPDATE_CPU

/*
 * __cpu_preserved_text: Code executed by preserved physical CPUs during live
 * update kexec handover in orphan mode.
 *
 * All code in this section must run without stack protector checks because
 * per-CPU canary state may be invalid during handover and __stack_chk_fail()
 * resides in regular .text, which gets overwritten during kexec before the
 * incoming kernel boots.
 *
 * Architecture-specific requirements (such as disabling external retpolines
 * and return thunks on x86) are supplied via ARCH_CPU_PRESERVED_TEXT.
 */
#ifndef ARCH_CPU_PRESERVED_TEXT
#define ARCH_CPU_PRESERVED_TEXT
#endif

#define __cpu_preserved_text					\
	__section(".text.cpu_preserved")			\
	__no_stack_protector					\
	ARCH_CPU_PRESERVED_TEXT
#define __cpu_preserved_data	__section(".data.cpu_preserved")

extern char __cpu_preserved_text_start[], __cpu_preserved_text_end[];
extern char __cpu_preserved_data_start[], __cpu_preserved_data_end[];

#else /* !CONFIG_LIVEUPDATE_CPU */

#define __cpu_preserved_text
#define __cpu_preserved_data

#endif /* CONFIG_LIVEUPDATE_CPU */

#endif /* _LINUX_CPU_PRESERVE_H */
