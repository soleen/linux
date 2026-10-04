/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ARCH_ARM64_KERNEL_CPU_PRESERVE_INTERNAL_H
#define _ARCH_ARM64_KERNEL_CPU_PRESERVE_INTERNAL_H

#include <linux/arm-smccc.h>
#include <linux/cpu_preserve.h>
#include <linux/types.h>

#define CPU_PRESERVED_MAX_RDIST_REGIONS	8

struct cpu_preserved_rdist_region {
	phys_addr_t	pa;
	void __iomem	*va;
	size_t		size;
	u64		stride;
};

struct cpu_preserved_gic_state {
	struct cpu_preserved_rdist_region	regions[CPU_PRESERVED_MAX_RDIST_REGIONS];
	int					nr_regions;
};

extern enum arm_smccc_conduit arm64_psci_conduit
	__cpu_preserved_sym_asm(arm64_psci_conduit);
extern struct cpu_preserved_gic_state cpu_preserved_gic
	__cpu_preserved_sym_asm(cpu_preserved_gic);

void __arch_cpu_preserved_park_on_stack(int cpu, unsigned long stack_top)
	__cpu_preserved_sym_asm(__arch_cpu_preserved_park_on_stack);

#endif /* _ARCH_ARM64_KERNEL_CPU_PRESERVE_INTERNAL_H */
