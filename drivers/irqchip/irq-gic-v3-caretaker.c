// SPDX-License-Identifier: GPL-2.0
/*
 * Caretaker redistributor and SGI wake helpers for ARM64 GICv3.
 */

#include <linux/cpu.h>
#include <linux/cpu_preserve.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/irqchip/arm-gic-v3.h>
#include <linux/irqchip/arm-gic-v3-caretaker.h>
#include <linux/smp.h>

#include <asm/barrier.h>
#include <asm/cputype.h>
#include <asm/sysreg.h>

#define CARETAKER_RWP_TIMEOUT_COUNT	1000000
#define CARETAKER_SGI_MASK		GENMASK(15, 0)
#define CARETAKER_HYP_TIMER_PPI		26
#define CARETAKER_HYP_VIRT_TIMER_PPI	30
#define GICR_INT_PRIORITY(intid)	(GICR_IPRIORITYR0 + (intid))
/* Firmware-described redistributor windows; real systems have one or two. */
#define CARETAKER_MAX_RDIST_REGIONS	8

#define MPIDR_TO_SGI_AFFINITY(cluster_id, level) \
	(MPIDR_AFFINITY_LEVEL(cluster_id, level) \
		<< ICC_SGI1R_AFFINITY_## level ##_SHIFT)
#define MPIDR_TO_SGI_CLUSTER_ID(mpidr)	((mpidr) & ~0xFUL)
#define MPIDR_RS(mpidr)			(((mpidr) & 0xf0ULL) >> 4)
#define MPIDR_TO_SGI_RS(mpidr)		(MPIDR_RS(mpidr) << ICC_SGI1R_RS_SHIFT)

struct caretaker_cpu_rdist {
	void __iomem	*rdist_base;
	u64		mpidr;
};

/*
 * A redistributor region covers all the redistributors in one contiguous
 * window.  The caretaker needs the whole window mapped into its isolated
 * address space, so remember each distinct one as the GIC driver discovers it.
 */
struct caretaker_rdist_region {
	phys_addr_t	pa;
	void __iomem	*va;
	size_t		size;
};

struct caretaker_gic_state {
	struct caretaker_cpu_rdist cpu_rdists[NR_CPUS];
	struct caretaker_rdist_region regions[CARETAKER_MAX_RDIST_REGIONS];
	int nr_regions;
};

static struct caretaker_gic_state caretaker_gic __cpu_preserved_data;

static void gicv3_caretaker_add_region(phys_addr_t pa, void __iomem *va, u64 stride)
{
	int i;

	for (i = 0; i < caretaker_gic.nr_regions; i++)
		if (caretaker_gic.regions[i].va == va)
			return;

	if (caretaker_gic.nr_regions == ARRAY_SIZE(caretaker_gic.regions))
		return;

	i = caretaker_gic.nr_regions++;
	caretaker_gic.regions[i].pa = pa;
	caretaker_gic.regions[i].va = va;
	caretaker_gic.regions[i].size = nr_cpu_ids * (stride ? : SZ_128K);
}

void gicv3_caretaker_set_rdist(int cpu, void __iomem *ptr, u64 mpidr,
			       phys_addr_t region_pa, void __iomem *region_va,
			       u64 stride)
{
	if (cpu >= 0 && cpu < ARRAY_SIZE(caretaker_gic.cpu_rdists)) {
		caretaker_gic.cpu_rdists[cpu].rdist_base = ptr;
		caretaker_gic.cpu_rdists[cpu].mpidr = mpidr;
	}

	gicv3_caretaker_add_region(region_pa, region_va, stride);
}

int gicv3_caretaker_get_redist_region(int idx, phys_addr_t *pa,
				      unsigned long *va, size_t *size)
{
	if (idx < 0 || idx >= caretaker_gic.nr_regions)
		return -ENOENT;

	*pa = caretaker_gic.regions[idx].pa;
	*va = (unsigned long)caretaker_gic.regions[idx].va;
	*size = caretaker_gic.regions[idx].size;
	return 0;
}

__cpu_preserved_text static void __iomem *gicv3_get_rdist_for_cpu(int cpu)
{
	if (cpu < 0) {
		u64 mpidr = read_sysreg(mpidr_el1) & MPIDR_HWID_BITMASK;
		int c;

		for (c = 0; c < ARRAY_SIZE(caretaker_gic.cpu_rdists); c++) {
			if (caretaker_gic.cpu_rdists[c].rdist_base &&
			    (caretaker_gic.cpu_rdists[c].mpidr & MPIDR_HWID_BITMASK) == mpidr)
				return caretaker_gic.cpu_rdists[c].rdist_base;
		}
		return NULL;
	}

	if (cpu < ARRAY_SIZE(caretaker_gic.cpu_rdists))
		return caretaker_gic.cpu_rdists[cpu].rdist_base;

	return NULL;
}

__cpu_preserved_text static inline void gicv3_caretaker_wait_for_rwp(void __iomem *base, u32 bit)
{
	int count = CARETAKER_RWP_TIMEOUT_COUNT;
	u32 val;

	while (count-- > 0) {
		val = readl_relaxed(base + GICR_CTLR);
		if (!(val & bit))
			return;
		cpu_relax();
	}
}

__cpu_preserved_text void gicv3_caretaker_clear_active_priorities(void)
{
	u32 ctlr = read_sysreg_s(SYS_ICC_CTLR_EL1);
	u32 pribits = ((ctlr & ICC_CTLR_EL1_PRI_BITS_MASK) >> ICC_CTLR_EL1_PRI_BITS_SHIFT) + 1;

	switch (pribits) {
	case 8:
	case 7:
		write_sysreg_s(0, SYS_ICC_AP1R3_EL1);
		write_sysreg_s(0, SYS_ICC_AP1R2_EL1);
		fallthrough;
	case 6:
		write_sysreg_s(0, SYS_ICC_AP1R1_EL1);
		fallthrough;
	case 5:
	case 4:
	default:
		write_sysreg_s(0, SYS_ICC_AP1R0_EL1);
		break;
	}
	isb();
}
EXPORT_SYMBOL_GPL(gicv3_caretaker_clear_active_priorities);

__cpu_preserved_text void gicv3_caretaker_enable_sgi(void)
{
	void __iomem *ptr = gicv3_get_rdist_for_cpu(-1);
	void __iomem *rbase = NULL;

	if (ptr) {
		rbase = ptr + SZ_64K;
		writel_relaxed(~0U, rbase + GICR_IGROUPR0);
		writel_relaxed(0, rbase + GICR_IGRPMODR0);
		writeb_relaxed(0x00, rbase + GICR_INT_PRIORITY(0));
		writeb_relaxed(0x00, rbase + GICR_INT_PRIORITY(CARETAKER_HYP_TIMER_PPI));
		writeb_relaxed(0x00, rbase + GICR_INT_PRIORITY(CARETAKER_HYP_VIRT_TIMER_PPI));
		writel_relaxed(CARETAKER_SGI_MASK |
			       BIT(CARETAKER_HYP_TIMER_PPI) |
			       BIT(CARETAKER_HYP_VIRT_TIMER_PPI),
			       rbase + GICR_ISENABLER0);
		writel_relaxed(~0U, rbase + GICR_ICACTIVER0);
		gicv3_caretaker_wait_for_rwp(ptr, GICR_CTLR_RWP);
	}

	write_sysreg_s(0, SYS_ICC_BPR1_EL1);
	gicv3_caretaker_clear_active_priorities();
}
EXPORT_SYMBOL_GPL(gicv3_caretaker_enable_sgi);

__cpu_preserved_text void gicv3_caretaker_clear_sgi(void)
{
	void __iomem *ptr = gicv3_get_rdist_for_cpu(-1);
	void __iomem *rbase = NULL;

	if (ptr) {
		rbase = ptr + SZ_64K;
		writel_relaxed(~0U, rbase + GICR_ICPENDR0);
		writel_relaxed(~0U, rbase + GICR_ICACTIVER0);
		gicv3_caretaker_wait_for_rwp(ptr, GICR_CTLR_RWP);
	}
}
EXPORT_SYMBOL_GPL(gicv3_caretaker_clear_sgi);

__cpu_preserved_text void gicv3_caretaker_kick_cpu(int cpu)
{
	void __iomem *ptr, *sgi_base;
	u64 mpidr, cluster_id;
	u16 tlist;

	if (cpu < 0 || cpu >= ARRAY_SIZE(caretaker_gic.cpu_rdists))
		return;
	if ((caretaker_gic.cpu_rdists[cpu].mpidr & MPIDR_HWID_BITMASK) ==
	    (read_sysreg(mpidr_el1) & MPIDR_HWID_BITMASK))
		return;

	ptr = gicv3_get_rdist_for_cpu(cpu);
	if (ptr) {
		u32 val = readl_relaxed(ptr + GICR_WAKER);

		sgi_base = ptr + SZ_64K;

		if (val & GICR_WAKER_ProcessorSleep) {
			int count = CARETAKER_RWP_TIMEOUT_COUNT;

			val &= ~GICR_WAKER_ProcessorSleep;
			writel_relaxed(val, ptr + GICR_WAKER);
			while (count-- > 0) {
				val = readl_relaxed(ptr + GICR_WAKER);
				if (!(val & GICR_WAKER_ChildrenAsleep))
					break;
				cpu_relax();
			}
		}

		writel_relaxed(~0U, sgi_base + GICR_IGROUPR0);
		writel_relaxed(0, sgi_base + GICR_IGRPMODR0);
		writel_relaxed(0, sgi_base + GICR_INT_PRIORITY(0));
		writel_relaxed(0, sgi_base + GICR_INT_PRIORITY(4));
		writel_relaxed(0, sgi_base + GICR_INT_PRIORITY(8));
		writel_relaxed(0, sgi_base + GICR_INT_PRIORITY(12));
		writel_relaxed(CARETAKER_SGI_MASK | BIT(CARETAKER_HYP_TIMER_PPI),
			       sgi_base + GICR_ISENABLER0);
		gicv3_caretaker_wait_for_rwp(ptr, GICR_CTLR_RWP);
	}

	/*
	 * mpidr is already affinity-packed from cpu_logical_map, so
	 * extracting cluster_id and target list directly applies to
	 * ICC_SGI1R_EL1 generation without re-encoding.
	 */
	mpidr = caretaker_gic.cpu_rdists[cpu].mpidr;
	cluster_id = MPIDR_TO_SGI_CLUSTER_ID(mpidr);
	tlist = 1 << (mpidr & 0xf);

	dsb(ishst);
	{
		u64 val = (MPIDR_TO_SGI_AFFINITY(cluster_id, 3) |
			   MPIDR_TO_SGI_AFFINITY(cluster_id, 2) |
			   (0ULL << ICC_SGI1R_SGI_ID_SHIFT) |
			   MPIDR_TO_SGI_AFFINITY(cluster_id, 1) |
			   MPIDR_TO_SGI_RS(cluster_id) |
			   ((u64)tlist << ICC_SGI1R_TARGET_LIST_SHIFT));

		write_sysreg_s(val, SYS_ICC_SGI1R_EL1);
	}
	isb();
}
EXPORT_SYMBOL_GPL(gicv3_caretaker_kick_cpu);
