/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_X86_CPU_PRESERVE_H
#define __ASM_X86_CPU_PRESERVE_H

#define ARCH_CPU_PRESERVED_STACK_ORDER	THREAD_SIZE_ORDER

#ifdef CONFIG_CC_IS_GCC
#define ARCH_CPU_PRESERVED_TEXT \
	__attribute__((indirect_branch("keep"), function_return("keep")))
#else
#define ARCH_CPU_PRESERVED_TEXT
#endif

#ifdef CONFIG_LIVEUPDATE_CPU
bool arch_cpu_preserved_is_active(void);
void x86_preserved_iret_stub(void);
void x86_preserved_iret_err_stub(void);
void x86_preserved_apic_eoi_stub(void);
u32 arch_cpu_preserved_get_apicid(int cpu);
#else
static inline bool arch_cpu_preserved_is_active(void) { return false; }
static inline u32 arch_cpu_preserved_get_apicid(int cpu) { return (u32)-1; }
#endif

#endif /* __ASM_X86_CPU_PRESERVE_H */
