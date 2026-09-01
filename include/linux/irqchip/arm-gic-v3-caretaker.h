/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * GICv3 helpers used by preserved physical CPUs.
 *
 * A preserved core keeps taking and acknowledging interrupts after the kernel
 * that owns the GIC driver has been replaced, so it needs a handful of
 * operations that do not go through the irqchip at all.  They live here rather
 * than in arm-gic-v3.h because only the caretaker and the GIC driver itself
 * ever call them.
 */
#ifndef __LINUX_IRQCHIP_ARM_GIC_V3_CARETAKER_H
#define __LINUX_IRQCHIP_ARM_GIC_V3_CARETAKER_H

#include <linux/types.h>

#ifdef CONFIG_ARM_GIC_V3_CARETAKER
void gicv3_caretaker_enable_sgi(void);
void gicv3_caretaker_clear_sgi(void);
void gicv3_caretaker_kick_cpu(int cpu);
void gicv3_caretaker_clear_active_priorities(void);

/**
 * gicv3_caretaker_set_rdist - Record a CPU's redistributor for caretaker use
 * @cpu: logical CPU the redistributor belongs to
 * @ptr: mapped base of that CPU's redistributor
 * @mpidr: MPIDR of that CPU, used to find the redistributor with no percpu
 * @region_pa: physical base of the enclosing redistributor region
 * @region_va: mapped base of the enclosing redistributor region
 * @stride: redistributor stride, or 0 for the architected 128K
 *
 * Called from the GIC driver as it walks the redistributors.  The enclosing
 * region is recorded too, because the caretaker has to map the whole window
 * into its isolated address space.
 */
void gicv3_caretaker_set_rdist(int cpu, void __iomem *ptr, u64 mpidr,
			       phys_addr_t region_pa, void __iomem *region_va,
			       u64 stride);

/**
 * gicv3_caretaker_get_redist_region - Enumerate recorded redistributor regions
 * @idx: region index, starting at 0
 * @pa: returns the physical base
 * @va: returns the virtual base
 * @size: returns the window size in bytes
 *
 * Return: 0, or -ENOENT once @idx is past the last region.
 */
int gicv3_caretaker_get_redist_region(int idx, phys_addr_t *pa,
				      unsigned long *va, size_t *size);
#else
static inline void gicv3_caretaker_enable_sgi(void) {}
static inline void gicv3_caretaker_clear_sgi(void) {}
static inline void gicv3_caretaker_kick_cpu(int cpu) {}
static inline void gicv3_caretaker_clear_active_priorities(void) {}
static inline void gicv3_caretaker_set_rdist(int cpu, void __iomem *ptr, u64 mpidr,
					     phys_addr_t region_pa,
					     void __iomem *region_va, u64 stride) {}
static inline int gicv3_caretaker_get_redist_region(int idx, phys_addr_t *pa,
						    unsigned long *va, size_t *size)
{
	return -ENOENT;
}
#endif

#endif /* __LINUX_IRQCHIP_ARM_GIC_V3_CARETAKER_H */
