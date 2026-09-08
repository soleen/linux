/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_ARM64_CARETAKER_H
#define __ASM_ARM64_CARETAKER_H

#include <asm/barrier.h>
#include <asm/cacheflush.h>
#include <asm/cputype.h>
#include <asm/cpu_preserve.h>

static inline void caretaker_arch_park_cpu_wait(void)
{
	wfe();
}

static inline void caretaker_arch_wake_parked_cpu(void)
{
	dsb(ishst);
	sev();
}

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

extern bool arm64_caretaker_has_ptrauth;

int arch_cpu_preserved_mpidr_to_cpu(u64 mpidr);

static inline int arm64_caretaker_get_pcpu(void)
{
	u64 mpidr = read_cpuid_mpidr() & MPIDR_HWID_BITMASK;
	int cpu = arch_cpu_preserved_mpidr_to_cpu(mpidr);

	if (cpu >= 0 && cpu < NR_CPUS)
		return cpu;
	return (int)MPIDR_AFFINITY_LEVEL(mpidr, 0);
}

#endif /* __ASM_ARM64_CARETAKER_H */
