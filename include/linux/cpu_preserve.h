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

#define __cpu_preserved_text	__section(".text.cpu_preserved")
#define __cpu_preserved_data	__section(".data.cpu_preserved")

extern char __cpu_preserved_text_start[], __cpu_preserved_text_end[];
extern char __cpu_preserved_data_start[], __cpu_preserved_data_end[];

#else /* !CONFIG_LIVEUPDATE_CPU */

#define __cpu_preserved_text
#define __cpu_preserved_data

#endif /* CONFIG_LIVEUPDATE_CPU */

#endif /* _LINUX_CPU_PRESERVE_H */
