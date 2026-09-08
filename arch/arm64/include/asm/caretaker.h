/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_ARM64_CARETAKER_H
#define __ASM_ARM64_CARETAKER_H

#include <linux/types.h>
#include <linux/cpu_preserve.h>
#include <asm/arch_timer.h>
#include <asm/cputype.h>
#include <asm/pgtable-types.h>
#include <asm/sysreg.h>

#ifdef CONFIG_LIVEUPDATE_CPU
extern phys_addr_t arm64_caretaker_pgd_pa;
#else
#define arm64_caretaker_pgd_pa 0ULL
#endif

extern char caretaker_hyp_vector[];

static inline u64 __cpu_preserved_text arch_caretaker_read_counter(void)
{
	return read_sysreg(cntpct_el0);
}

extern bool arm64_caretaker_has_ptrauth;

static inline int arm64_caretaker_get_pcpu(void)
{
	u64 mpidr = read_cpuid_mpidr() & MPIDR_HWID_BITMASK;
	int cpu = arch_cpu_preserved_mpidr_to_cpu(mpidr);

	if (cpu >= 0)
		return cpu;
	return (int)MPIDR_AFFINITY_LEVEL(mpidr, 0);
}

#endif /* __ASM_ARM64_CARETAKER_H */
