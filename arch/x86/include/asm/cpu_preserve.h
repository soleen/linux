/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_X86_CPU_PRESERVE_H
#define __ASM_X86_CPU_PRESERVE_H

#define ARCH_CPU_PRESERVED_STACK_ORDER	THREAD_SIZE_ORDER

#ifdef CONFIG_LIVEUPDATE_CPU
bool arch_cpu_preserved_is_active(void);
#else
static inline bool arch_cpu_preserved_is_active(void) { return false; }
#endif

#endif /* __ASM_X86_CPU_PRESERVE_H */
