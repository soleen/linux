// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * Preserved-CPU runtime for ARM64.
 */
#include <linux/arm-smccc.h>
#include <linux/cpu_preserve.h>
#include <linux/errno.h>
#include <linux/io.h>
#include <linux/irqchip/arm-gic-v3.h>
#include <linux/sizes.h>

#include <asm/barrier.h>
#include <asm/caretaker.h>
#include <asm/cputype.h>
#include <asm/daifflags.h>
#include <asm/processor.h>
#include <asm/sysreg.h>
#include <asm/tlbflush.h>

#include "cpu_preserve_internal.h"

#define CPU_PRESERVED_RWP_TIMEOUT_COUNT		1000000
#define CPU_PRESERVED_SGI_MASK			GENMASK(15, 0)
#define CPU_PRESERVED_HYP_TIMER_PPI		26
#define CPU_PRESERVED_HYP_VIRT_TIMER_PPI	30
#define GICR_INT_PRIORITY(intid)	(GICR_IPRIORITYR0 + (intid))

#define MPIDR_TO_SGI_AFFINITY(cluster_id, level) \
	(MPIDR_AFFINITY_LEVEL(cluster_id, level) \
		<< ICC_SGI1R_AFFINITY_## level ##_SHIFT)
#define MPIDR_TO_SGI_CLUSTER_ID(mpidr)	((mpidr) & ~0xFUL)
#define MPIDR_RS(mpidr)			(((mpidr) & 0xf0ULL) >> 4)
#define MPIDR_TO_SGI_RS(mpidr)		(MPIDR_RS(mpidr) << ICC_SGI1R_RS_SHIFT)

enum arm_smccc_conduit arm64_psci_conduit;
struct cpu_preserved_gic_state cpu_preserved_gic;

/*
 * Low-power wait in parking loop.
 */
void arch_cpu_preserved_park_wait(void)
{
	wfe();
}

static void __iomem *gicv3_get_rdist_for_mpidr(u64 mpidr)
{
	u32 cpu_aff = (MPIDR_AFFINITY_LEVEL(mpidr, 3) << 24) |
		      (MPIDR_AFFINITY_LEVEL(mpidr, 2) << 16) |
		      (MPIDR_AFFINITY_LEVEL(mpidr, 1) << 8) |
		      MPIDR_AFFINITY_LEVEL(mpidr, 0);
	int i;

	for (i = 0; i < cpu_preserved_gic.nr_regions; i++) {
		void __iomem *va = cpu_preserved_gic.regions[i].va;
		size_t map_size = cpu_preserved_gic.regions[i].size;
		u64 stride = cpu_preserved_gic.regions[i].stride;
		void __iomem *ptr = va;

		if (!va)
			continue;

		do {
			u64 typer = __raw_readq(ptr + GICR_TYPER);
			u32 aff = typer >> 32;
			bool last = !!(typer & GICR_TYPER_LAST);

			if (aff == cpu_aff)
				return ptr;

			if (stride) {
				ptr += stride;
			} else {
				ptr += SZ_64K * 2;
				if (typer & GICR_TYPER_VLPIS)
					ptr += SZ_64K * 2;
			}
			if (last)
				break;
		} while ((ptr - va) < map_size);
	}
	return NULL;
}

static __always_inline void
gicv3_cpu_preserved_wait_for_rwp(void __iomem *base, u32 bit)
{
	int count = CPU_PRESERVED_RWP_TIMEOUT_COUNT;

	while (count-- > 0) {
		if (!(__raw_readl(base + GICR_CTLR) & bit))
			return;
		cpu_relax();
	}
}

void gicv3_cpu_preserved_clear_active_priorities(void)
{
	u32 ctlr = read_sysreg_s(SYS_ICC_CTLR_EL1);
	u32 pribits = ((ctlr & ICC_CTLR_EL1_PRI_BITS_MASK) >>
		       ICC_CTLR_EL1_PRI_BITS_SHIFT) + 1;

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

void gicv3_cpu_preserved_enable_sgi(void)
{
	void __iomem *ptr = gicv3_get_rdist_for_mpidr(read_sysreg(mpidr_el1));

	if (ptr) {
		void __iomem *rbase = ptr + SZ_64K;

		__raw_writel(~0U, rbase + GICR_IGROUPR0);
		__raw_writel(0, rbase + GICR_IGRPMODR0);
		__raw_writeb(0x00, rbase + GICR_INT_PRIORITY(0));
		__raw_writeb(0x00, rbase + GICR_INT_PRIORITY(CPU_PRESERVED_HYP_TIMER_PPI));
		__raw_writeb(0x00, rbase + GICR_INT_PRIORITY(CPU_PRESERVED_HYP_VIRT_TIMER_PPI));
		__raw_writel(CPU_PRESERVED_SGI_MASK |
			     BIT(CPU_PRESERVED_HYP_TIMER_PPI) |
			     BIT(CPU_PRESERVED_HYP_VIRT_TIMER_PPI),
			     rbase + GICR_ISENABLER0);
		__raw_writel(~0U, rbase + GICR_ICACTIVER0);
		gicv3_cpu_preserved_wait_for_rwp(ptr, GICR_CTLR_RWP);
	}

	write_sysreg_s(0, SYS_ICC_BPR1_EL1);
	gicv3_cpu_preserved_clear_active_priorities();
}

void gicv3_cpu_preserved_kick_mpidr(u64 mpidr)
{
	u64 cluster_id, sgi1r;
	void __iomem *ptr;
	u16 tlist;

	if (mpidr == INVALID_HWID)
		return;
	if ((mpidr & MPIDR_HWID_BITMASK) == (read_sysreg(mpidr_el1) & MPIDR_HWID_BITMASK))
		return;

	ptr = gicv3_get_rdist_for_mpidr(mpidr);
	if (ptr) {
		void __iomem *sgi_base = ptr + SZ_64K;
		u32 val = __raw_readl(ptr + GICR_WAKER);

		if (val & GICR_WAKER_ProcessorSleep) {
			int count = CPU_PRESERVED_RWP_TIMEOUT_COUNT;

			val &= ~GICR_WAKER_ProcessorSleep;
			__raw_writel(val, ptr + GICR_WAKER);
			while (count-- > 0) {
				val = __raw_readl(ptr + GICR_WAKER);
				if (!(val & GICR_WAKER_ChildrenAsleep))
					break;
				cpu_relax();
			}
		}

		__raw_writel(~0U, sgi_base + GICR_IGROUPR0);
		__raw_writel(0, sgi_base + GICR_IGRPMODR0);
		__raw_writel(0, sgi_base + GICR_INT_PRIORITY(0));
		__raw_writel(0, sgi_base + GICR_INT_PRIORITY(4));
		__raw_writel(0, sgi_base + GICR_INT_PRIORITY(8));
		__raw_writel(0, sgi_base + GICR_INT_PRIORITY(12));
		__raw_writel(CPU_PRESERVED_SGI_MASK | BIT(CPU_PRESERVED_HYP_TIMER_PPI),
			     sgi_base + GICR_ISENABLER0);
		gicv3_cpu_preserved_wait_for_rwp(ptr, GICR_CTLR_RWP);
	}

	cluster_id = MPIDR_TO_SGI_CLUSTER_ID(mpidr);
	tlist = 1 << (mpidr & 0xf);

	dsb(ishst);
	sgi1r = (MPIDR_TO_SGI_AFFINITY(cluster_id, 3) |
		 MPIDR_TO_SGI_AFFINITY(cluster_id, 2) |
		 (0ULL << ICC_SGI1R_SGI_ID_SHIFT) |
		 MPIDR_TO_SGI_AFFINITY(cluster_id, 1) |
		 MPIDR_TO_SGI_RS(cluster_id) |
		 ((u64)tlist << ICC_SGI1R_TARGET_LIST_SHIFT));
	write_sysreg_s(sgi1r, SYS_ICC_SGI1R_EL1);
	isb();
}

bool arch_cpu_preserved_is_active(void)
{
	struct cpu_preserved_stack_context *sctx = cpu_preserved_get_stack_context();
	u64 ttbr1 = read_sysreg(ttbr1_el1);

	return sctx && sctx->session_pgd_pa && ttbr1 == sctx->session_pgd_pa;
}

void arch_cpu_preserved_switch_pgd(phys_addr_t pgd_pa)
{
	if (pgd_pa) {
		write_sysreg(pgd_pa, ttbr1_el1);
		isb();
		arm64_flush_host_tlb_local();
	}
}

asmlinkage void arm64_preserved_handle_exception(unsigned long kind)
{
	struct cpu_preserved_stack_context *sctx;
	struct arm64_preserved_fault *f;
	int cpu = 0;

	local_daif_mask();

	sctx = cpu_preserved_get_stack_context();
	if (sctx) {
		cpu = sctx->cpu;
		f = &sctx->fault;
		f->kind = kind;
		f->esr = read_sysreg(esr_el1);
		f->elr = read_sysreg(elr_el1);
		f->far = read_sysreg(far_el1);
		f->spsr = read_sysreg(spsr_el1);
		f->count++;
		cpu_preserved_clean(f);
	}

	if (sctx && sctx->ser) {
		while (smp_load_acquire(&sctx->ser->state) ==
		       CPU_PRESERVED_WORKLOAD)
			arch_cpu_preserved_park_wait();
	}
	cpu_preserved_park_loop(cpu);

	arch_cpu_preserved_park_finish(cpu);
}

/*
 * Masks DAIF interrupts and enables GIC CPU interface for WFx wakeups.
 */
void arch_cpu_preserved_park_init(int cpu)
{
	struct cpu_preserved_stack_context *sctx = cpu_preserved_get_stack_context();

	if (!sctx || !sctx->session_pgd_pa)
		return;

	local_daif_mask();
	cpu_preserved_inval(&arm64_psci_conduit);
	cpu_preserved_inval(&cpu_preserved_gic);

	if (read_sysreg(ttbr1_el1) != sctx->session_pgd_pa)
		gicv3_cpu_preserved_enable_sgi();

	write_sysreg((unsigned long)arm64_preserved_vectors, vbar_el1);
	isb();

#if IS_ENABLED(CONFIG_KVM_CARETAKER)
	if (read_sysreg(CurrentEL) == CurrentEL_EL2) {
		write_sysreg_s((unsigned long)caretaker_hyp_vector, SYS_VBAR_EL2);
		isb();
	}
#endif

	write_sysreg(0, ttbr0_el1);
	write_sysreg(sctx->session_pgd_pa, ttbr1_el1);
	isb();
	arm64_flush_host_tlb_local();

	write_sysreg_s(ICC_CTLR_EL1_EOImode_drop, SYS_ICC_CTLR_EL1);
	write_sysreg_s(ICC_SRE_EL1_SRE, SYS_ICC_SRE_EL1);
	write_sysreg_s(0, SYS_ICC_BPR1_EL1);
	gicv3_cpu_preserved_clear_active_priorities();
	write_sysreg_s(ICC_PMR_EL1_MASK, SYS_ICC_PMR_EL1);
	write_sysreg_s(ICC_IGRPEN1_EL1_MASK, SYS_ICC_IGRPEN1_EL1);
	isb();
}

void arch_cpu_preserved_park_finish(int cpu)
{
	u32 el = (read_sysreg(CurrentEL) >> 2) & 3;
	enum arm_smccc_conduit conduit;

	cpu_preserved_inval(&arm64_psci_conduit);
	conduit = READ_ONCE(arm64_psci_conduit);

	local_daif_mask();
	gicv3_cpu_preserved_clear_active_priorities();
	write_sysreg_s(0, SYS_ICC_IGRPEN1_EL1);
	write_sysreg_s(0, SYS_ICC_PMR_EL1);
	write_sysreg_s(0, SYS_ICC_BPR1_EL1);
	arm64_flush_host_tlb_local();

	if (conduit == SMCCC_CONDUIT_NONE)
		conduit = (el == 2) ? SMCCC_CONDUIT_SMC : SMCCC_CONDUIT_HVC;

	cpu_preserved_set_dead();

	/*
	 * Direct PSCI CPU_OFF call in preserved text without relying on
	 * unpreserved kernel data structures or function pointers.
	 *
	 * x0: PSCI_0_2_FN_CPU_OFF (0x84000002)
	 * x1: Power down state (0x00010000)
	 */
	if (conduit == SMCCC_CONDUIT_HVC) {
		asm volatile("mov	x0, #0x0002\n"
			"movk	x0, #0x8400, lsl #16\n"
			"mov	x1, #0\n"
			"mov	x2, #0\n"
			"mov	x3, #0\n"
			"mov	x4, #0\n"
			"mov	x5, #0\n"
			"mov	x6, #0\n"
			"mov	x7, #0\n"
			"hvc	#0\n"
			:
			:
			: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "memory"
		);
	} else {
		asm volatile("mov	x0, #0x0002\n"
			"movk	x0, #0x8400, lsl #16\n"
			"mov	x1, #0\n"
			"mov	x2, #0\n"
			"mov	x3, #0\n"
			"mov	x4, #0\n"
			"mov	x5, #0\n"
			"mov	x6, #0\n"
			"mov	x7, #0\n"
			"smc	#0\n"
			:
			:
			: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "memory"
		);
	}

	while (1) {
		wfi();
		wfe();
	}
}
