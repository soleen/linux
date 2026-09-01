/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_ARM64_CARETAKER_H
#define __ASM_ARM64_CARETAKER_H

#include <asm/barrier.h>
#include <asm/cacheflush.h>
#include <asm/cputype.h>

static inline void caretaker_arch_park_cpu_wait(void)
{
	wfe();
}

static inline void caretaker_arch_wake_parked_cpu(void)
{
	dsb(ishst);
	sev();
}

asmlinkage void arch_cpu_preserved_dcache_clean(unsigned long start, unsigned long end);
asmlinkage void arch_cpu_preserved_dcache_inval(unsigned long start, unsigned long end);

static inline void caretaker_arch_dcache_clean_inval_poc(unsigned long start,
							 unsigned long end)
{
	arch_cpu_preserved_dcache_clean(start, end);
}

static inline void caretaker_arch_dcache_inval_poc(unsigned long start,
						   unsigned long end)
{
	arch_cpu_preserved_dcache_inval(start, end);
}

#include <asm/pgtable-types.h>

#ifdef CONFIG_LIVEUPDATE_CPU
extern phys_addr_t arm64_caretaker_pgd_pa;
#else
#define arm64_caretaker_pgd_pa 0ULL
#endif

asmlinkage void notrace caretaker_die_psci(int cpu);
extern char caretaker_hyp_vector[];

#include <asm/arch_timer.h>
#include <asm/sysreg.h>

struct caretaker_sched_config;

static inline u64 __cpu_preserved_text arch_caretaker_read_counter(void)
{
	return read_sysreg(cntpct_el0);
}

u64 arch_caretaker_ticks_to_ns(u64 ticks);
void arch_caretaker_update_quantum_ticks(struct caretaker_sched_config *cfg);

#endif /* __ASM_ARM64_CARETAKER_H */
