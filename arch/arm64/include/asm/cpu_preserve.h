/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_ARM64_CPU_PRESERVE_H
#define __ASM_ARM64_CPU_PRESERVE_H

#include <asm/memory.h>

#define ARCH_CPU_PRESERVED_STACK_ORDER	(THREAD_SIZE_ORDER + 1)

int arch_cpu_preserved_map_range(phys_addr_t pa, unsigned long va,
				 size_t size, pgprot_t prot);
bool arch_cpu_preserved_is_active(void);

#endif /* __ASM_ARM64_CPU_PRESERVE_H */
