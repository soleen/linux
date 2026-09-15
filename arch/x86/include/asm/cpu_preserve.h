/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 */
#ifndef __ASM_X86_CPU_PRESERVE_H
#define __ASM_X86_CPU_PRESERVE_H

#include <asm/page_types.h>

#define ARCH_CPU_PRESERVED_STACK_ORDER	THREAD_SIZE_ORDER

#ifdef CONFIG_CC_IS_GCC
#define ARCH_CPU_PRESERVED_TEXT \
	__attribute__((indirect_branch("keep"), function_return("keep")))
#else
#define ARCH_CPU_PRESERVED_TEXT
#endif

#ifdef CONFIG_LIVEUPDATE_CPU
void arch_cpu_preserved_load_desc(void);
bool arch_cpu_preserved_is_active(void);
void x86_preserved_iret_stub(void);
void x86_preserved_iret_err_stub(void);
void x86_preserved_apic_eoi_stub(void);
#else
static inline void arch_cpu_preserved_load_desc(void) {}
static inline bool arch_cpu_preserved_is_active(void) { return false; }
#endif

#endif /* __ASM_X86_CPU_PRESERVE_H */
