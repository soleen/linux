/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_ARM64_CPU_PRESERVE_H
#define __ASM_ARM64_CPU_PRESERVE_H

#include <asm/memory.h>
#include <asm/tlbflush.h>
#include <asm/virt.h>

#define ARCH_CPU_PRESERVED_STACK_ORDER	(THREAD_SIZE_ORDER + 1)

int arch_cpu_preserved_map_range(phys_addr_t pa, unsigned long va,
				 size_t size, pgprot_t prot);
bool arch_cpu_preserved_is_active(void);
asmlinkage void __arch_cpu_preserved_dcache_clean(unsigned long start, unsigned long end);
asmlinkage void arch_cpu_preserved_dcache_clean(unsigned long start, unsigned long end);
asmlinkage void arch_cpu_preserved_dcache_inval(unsigned long start, unsigned long end);
u64 arch_cpu_preserved_get_mpidr(int cpu);

static inline void arm64_flush_host_tlb_local(void)
{
	dsb(nshst);
	if (is_kernel_in_hyp_mode()) {
		asm volatile("tlbi alle2\n"
			     "dsb nsh\n"
			     "isb\n" ::: "memory");
	} else {
		local_flush_tlb_all();
	}
}

static inline void arm64_flush_host_tlb_all(void)
{
	dsb(ishst);
	if (is_kernel_in_hyp_mode()) {
		asm volatile("tlbi alle2is\n"
			     "dsb ish\n"
			     "isb\n" ::: "memory");
	} else {
		flush_tlb_all();
	}
}

#endif /* __ASM_ARM64_CPU_PRESERVE_H */
