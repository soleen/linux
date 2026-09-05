/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_X86_CPU_PRESERVE_H
#define __ASM_X86_CPU_PRESERVE_H

#include <asm/page_types.h>

#define ARCH_CPU_PRESERVED_STACK_ORDER	THREAD_SIZE_ORDER

#ifdef CONFIG_LIVEUPDATE_CPU
void x86_virt_reset_cpu(int cpu);
void x86_virt_vmx_preserve_kho(void);
phys_addr_t x86_virt_vmxon_pa(int cpu);
void arch_cpu_preserved_load_desc(void);
bool arch_cpu_preserved_is_active(void);
#else
static inline void x86_virt_reset_cpu(int cpu) {}
static inline void x86_virt_vmx_preserve_kho(void) {}
static inline phys_addr_t x86_virt_vmxon_pa(int cpu) { return 0; }
static inline void arch_cpu_preserved_load_desc(void) {}
static inline bool arch_cpu_preserved_is_active(void) { return false; }
#endif

#endif /* __ASM_X86_CPU_PRESERVE_H */
