// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 */
#include <linux/cpu_preserve.h>
#include <linux/delay.h>
#include <linux/irqchip/arm-gic-v3.h>
#include <linux/kexec_handover.h>
#include <linux/kho/abi/kvm.h>
#include <linux/kvm_host.h>
#include <linux/objtool.h>
#include <linux/oncore.h>
#include <linux/sched.h>

#include <asm/barrier.h>
#include <asm/caretaker.h>
#include <asm/cpu_ops.h>
#include <linux/cpufeature.h>
#include <asm/cputype.h>
#include <asm/fpsimd.h>
#include <asm/kernel-pgtable.h>
#include <linux/kexec.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pgtable.h>
#include <asm/kvm_ptrauth.h>
#include <linux/mmu_context.h>
#include <linux/pgtable.h>
#include <asm/smp_plat.h>
#include <asm/sysreg.h>
#include <asm/tlbflush.h>
#include <asm/vectors.h>

#include <kvm/arm_arch_timer.h>
#include <kvm/arm_vgic.h>

#include "caretaker.h"

struct caretaker_fault_info {
	u64 elr;
	u64 esr;
	u64 far;
	u64 count;
};

static struct caretaker_fault_info arm64_caretaker_faults[NR_CPUS] __cpu_preserved_data;

void __caretaker_text
arm64_caretaker_handle_invalid(u64 elr, u64 esr, u64 far)
{
	int cpu = arm64_caretaker_get_pcpu();

	if (cpu >= 0 && cpu < ARRAY_SIZE(arm64_caretaker_faults)) {
		arm64_caretaker_faults[cpu].elr = elr;
		arm64_caretaker_faults[cpu].esr = esr;
		arm64_caretaker_faults[cpu].far = far;
		arm64_caretaker_faults[cpu].count++;
	}

	while (1) {
		if (cpu_preserved_should_exit(cpu))
			arch_cpu_preserved_park_finish(cpu);
		arch_cpu_preserved_park_wait();
	}
}

__caretaker_text static inline void
arm64_caretaker_load_sysregs(struct kvm_cpu_context *ctxt)
{
	u64 mpidr = ctxt_sys_reg(ctxt, MPIDR_EL1);
	u64 midr = read_cpuid_id();

	write_sysreg(midr, vpidr_el2);
	write_sysreg(mpidr, vmpidr_el2);

	write_sysreg_el1(ctxt_sys_reg(ctxt, SCTLR_EL1), SYS_SCTLR);
	write_sysreg_el1(ctxt_sys_reg(ctxt, CPACR_EL1), SYS_CPACR);
	write_sysreg_el1(ctxt_sys_reg(ctxt, TTBR0_EL1), SYS_TTBR0);
	write_sysreg_el1(ctxt_sys_reg(ctxt, TTBR1_EL1), SYS_TTBR1);
	write_sysreg_el1(ctxt_sys_reg(ctxt, TCR_EL1), SYS_TCR);
	if (cpus_have_final_cap(ARM64_HAS_TCR2)) {
		write_sysreg_el1(ctxt_sys_reg(ctxt, TCR2_EL1), SYS_TCR2);
		if (cpus_have_final_cap(ARM64_HAS_S1PIE)) {
			write_sysreg_el1(ctxt_sys_reg(ctxt, PIR_EL1), SYS_PIR);
			write_sysreg_el1(ctxt_sys_reg(ctxt, PIRE0_EL1), SYS_PIRE0);
		}
	}
	if (cpus_have_final_cap(ARM64_HAS_SCTLR2))
		write_sysreg_el1(ctxt_sys_reg(ctxt, SCTLR2_EL1), SYS_SCTLR2);
	write_sysreg_el1(ctxt_sys_reg(ctxt, ESR_EL1), SYS_ESR);
	write_sysreg_el1(ctxt_sys_reg(ctxt, AFSR0_EL1), SYS_AFSR0);
	write_sysreg_el1(ctxt_sys_reg(ctxt, AFSR1_EL1), SYS_AFSR1);
	write_sysreg_el1(ctxt_sys_reg(ctxt, FAR_EL1), SYS_FAR);
	write_sysreg_el1(ctxt_sys_reg(ctxt, MAIR_EL1), SYS_MAIR);
	write_sysreg_el1(ctxt_sys_reg(ctxt, VBAR_EL1), SYS_VBAR);
	write_sysreg_el1(ctxt_sys_reg(ctxt, CONTEXTIDR_EL1), SYS_CONTEXTIDR);
	write_sysreg_el1(ctxt_sys_reg(ctxt, AMAIR_EL1), SYS_AMAIR);
	write_sysreg_el1(ctxt_sys_reg(ctxt, CNTKCTL_EL1), SYS_CNTKCTL);
	write_sysreg(ctxt_sys_reg(ctxt, PAR_EL1), par_el1);
	write_sysreg(ctxt_sys_reg(ctxt, TPIDR_EL1), tpidr_el1);
	write_sysreg(ctxt_sys_reg(ctxt, TPIDR_EL0), tpidr_el0);
	write_sysreg(ctxt_sys_reg(ctxt, TPIDRRO_EL0), tpidrro_el0);
	write_sysreg(ctxt_sys_reg(ctxt, SP_EL1), sp_el1);
	write_sysreg_el1(ctxt_sys_reg(ctxt, ELR_EL1), SYS_ELR);
	write_sysreg_el1(ctxt_sys_reg(ctxt, SPSR_EL1), SYS_SPSR);
	write_sysreg(ctxt_sys_reg(ctxt, MDSCR_EL1), mdscr_el1);
}

__caretaker_text static inline void
arm64_caretaker_save_sysregs(struct kvm_cpu_context *ctxt)
{
	ctxt_sys_reg(ctxt, SCTLR_EL1) = read_sysreg_el1(SYS_SCTLR);
	ctxt_sys_reg(ctxt, CPACR_EL1) = read_sysreg_el1(SYS_CPACR);
	ctxt_sys_reg(ctxt, TTBR0_EL1) = read_sysreg_el1(SYS_TTBR0);
	ctxt_sys_reg(ctxt, TTBR1_EL1) = read_sysreg_el1(SYS_TTBR1);
	ctxt_sys_reg(ctxt, TCR_EL1) = read_sysreg_el1(SYS_TCR);
	if (cpus_have_final_cap(ARM64_HAS_TCR2)) {
		ctxt_sys_reg(ctxt, TCR2_EL1) = read_sysreg_el1(SYS_TCR2);
		if (cpus_have_final_cap(ARM64_HAS_S1PIE)) {
			ctxt_sys_reg(ctxt, PIR_EL1) = read_sysreg_el1(SYS_PIR);
			ctxt_sys_reg(ctxt, PIRE0_EL1) = read_sysreg_el1(SYS_PIRE0);
		}
	}
	if (cpus_have_final_cap(ARM64_HAS_SCTLR2))
		ctxt_sys_reg(ctxt, SCTLR2_EL1) = read_sysreg_el1(SYS_SCTLR2);
	ctxt_sys_reg(ctxt, ESR_EL1) = read_sysreg_el1(SYS_ESR);
	ctxt_sys_reg(ctxt, AFSR0_EL1) = read_sysreg_el1(SYS_AFSR0);
	ctxt_sys_reg(ctxt, AFSR1_EL1) = read_sysreg_el1(SYS_AFSR1);
	ctxt_sys_reg(ctxt, FAR_EL1) = read_sysreg_el1(SYS_FAR);
	ctxt_sys_reg(ctxt, MAIR_EL1) = read_sysreg_el1(SYS_MAIR);
	ctxt_sys_reg(ctxt, VBAR_EL1) = read_sysreg_el1(SYS_VBAR);
	ctxt_sys_reg(ctxt, CONTEXTIDR_EL1) = read_sysreg_el1(SYS_CONTEXTIDR);
	ctxt_sys_reg(ctxt, AMAIR_EL1) = read_sysreg_el1(SYS_AMAIR);
	ctxt_sys_reg(ctxt, CNTKCTL_EL1) = read_sysreg_el1(SYS_CNTKCTL);
	ctxt_sys_reg(ctxt, PAR_EL1) = read_sysreg_par();
	ctxt_sys_reg(ctxt, TPIDR_EL1) = read_sysreg(tpidr_el1);
	ctxt_sys_reg(ctxt, TPIDR_EL0) = read_sysreg(tpidr_el0);
	ctxt_sys_reg(ctxt, TPIDRRO_EL0) = read_sysreg(tpidrro_el0);
	ctxt_sys_reg(ctxt, SP_EL1) = read_sysreg(sp_el1);
	ctxt_sys_reg(ctxt, ELR_EL1) = read_sysreg_el1(SYS_ELR);
	ctxt_sys_reg(ctxt, SPSR_EL1) = read_sysreg_el1(SYS_SPSR);
	ctxt_sys_reg(ctxt, MDSCR_EL1) = read_sysreg(mdscr_el1);
}

int arm64_kvm_caretaker_preserve(struct kvm_vcpu *vcpu,
				 struct kvm_vcpu_ser *ser)
{
	struct kvm_s2_mmu *mmu = vcpu->arch.hw_mmu ?
				 vcpu->arch.hw_mmu : &vcpu->kvm->arch.mmu;
	struct oncore_session *sess = oncore_job_session(vcpu->caretaker.job);
	struct arch_timer_context *vtimer;
	struct caretaker_arm64_page *head;
	struct caretaker_arm64_page *cap;

	if (!has_vhe() || is_protected_kvm_enabled() || vcpu_has_nv(vcpu))
		return -EOPNOTSUPP;
	/*
	 * Same predicate as kvm_arch_vcpu_luo_preserve() (kvm_luo.c) and
	 * kvm_arm_copy_sys_reg_indices() (sys_regs.c): what matters is whether
	 * an in-kernel irqchip exists at all, not whether it has been
	 * initialised yet.  vgic_initialized() would let a created-but-not-ready
	 * in-kernel VGICv2 through, and the caretaker cannot emulate one.
	 */
	if (irqchip_in_kernel(vcpu->kvm) &&
	    vcpu->kvm->arch.vgic.vgic_model != KVM_DEV_TYPE_ARM_VGIC_V3)
		return -EOPNOTSUPP;
	if (kvm_has_mte(vcpu->kvm) || kvm_has_s1poe(vcpu->kvm) ||
	    vcpu_has_sve(vcpu) || vcpu_has_ptrauth(vcpu) ||
	    test_bit(KVM_ARCH_FLAG_WRITABLE_IMP_ID_REGS, &vcpu->kvm->arch.flags))
		return -EOPNOTSUPP;

	cap = kho_alloc_preserve(sizeof(*cap));
	if (IS_ERR(cap)) {
		pr_err("caretaker arm64: failed to allocate preserved page\n");
		return -ENOMEM;
	}
	oncore_session_map_buffer(sess, cap, sizeof(*cap));

	memset(cap, 0, sizeof(*cap));

	kvm_caretaker_init_common_vcpu(&cap->vcpu, &cap->abi.cb, vcpu, cap,
				       sizeof(*cap), NULL, cap);

	/* Copy architectural execution state */
	cap->ctx.ctxt = vcpu->arch.ctxt;
	cap->ctx.fault = vcpu->arch.fault;
	cap->ctx.hcr_el2 = vcpu->arch.hcr_el2;
	cap->ctx.mdcr_el2 = vcpu->arch.mdcr_el2;
	cap->ctx.cflags = vcpu->arch.cflags;

	cap->ctx.vtcr_el2 = mmu->vtcr;
	cap->ctx.vttbr_el2 = kvm_get_vttbr(mmu);

	if (vgic_initialized(vcpu->kvm)) {
		int i;

		cap->ctx.vgic_initialized = true;
		cap->ctx.vgic_v3 = vcpu->arch.vgic_cpu.vgic_v3;

		for (i = 0; ; i++) {
			phys_addr_t rpa;
			unsigned long rva;
			size_t rsize;

			if (gicv3_caretaker_get_redist_region(i, &rpa, &rva, &rsize))
				break;
			oncore_session_map_range(sess, rpa, rva, rsize,
						 pgprot_device(PAGE_KERNEL));
		}
	}

	vtimer = vcpu_vtimer(vcpu);
	cap->ctx.cntvoff_el2 = timer_get_offset(vtimer);
	cap->ctx.cntv_cval_el0 = timer_get_cval(vtimer);
	cap->ctx.cntv_ctl_el0 = timer_get_ctl(vtimer);

	head = vcpu->kvm->caretaker_vm;
	if (!head) {
		cap->next_vcpu = cap;
		vcpu->kvm->caretaker_vm = cap;
	} else {
		struct caretaker_arm64_page *peer;

		cap->next_vcpu = head->next_vcpu;
		head->next_vcpu = cap;
		cpu_preserved_clean(head);

		for (peer = cap->next_vcpu; peer != cap; peer = peer->next_vcpu)
			oncore_session_map_buffer(sess, peer, sizeof(*peer));
	}

	cap->abi.vgic_initialized = cap->ctx.vgic_initialized ? 1 : 0;
	cap->abi.cntvoff_el2 = cap->ctx.cntvoff_el2;
	cap->abi.hcr_el2 = cap->ctx.hcr_el2;
	cap->abi.mdcr_el2 = cap->ctx.mdcr_el2;
	cap->abi.cflags = (u32)cap->ctx.cflags;
	if (cap->ctx.vgic_initialized) {
		int i;

		cap->abi.used_lrs = cap->ctx.vgic_v3.used_lrs;
		cap->abi.vgic_hcr = cap->ctx.vgic_v3.vgic_hcr;
		cap->abi.vgic_vmcr = cap->ctx.vgic_v3.vgic_vmcr;
		for (i = 0; i < 4; i++) {
			cap->abi.vgic_ap0r[i] = cap->ctx.vgic_v3.vgic_ap0r[i];
			cap->abi.vgic_ap1r[i] = cap->ctx.vgic_v3.vgic_ap1r[i];
		}
		for (i = 0; i < 16; i++)
			cap->abi.vgic_lr[i] = cap->ctx.vgic_v3.vgic_lr[i];
	}

	if (ser->arch_state.phys) {
		struct kvm_vcpu_arch_ser *state =
			phys_to_virt(ser->arch_state.phys);
		size_t sz = struct_size(state, sysregs, state->num_sysregs);

		cap->arch_state = state;
		oncore_session_map_buffer(sess, state, sz);
	}

	ser->cb.phys = virt_to_phys(cap);

	cpu_preserved_clean(cap);

	return 0;
}

static __always_inline void arm64_caretaker_save_ptrauth(struct arm64_caretaker_ptrauth_keys *k)
{
	if (!arm64_caretaker_has_ptrauth)
		return;

	k->apia_lo = read_sysreg_s(SYS_APIAKEYLO_EL1);
	k->apia_hi = read_sysreg_s(SYS_APIAKEYHI_EL1);
	k->apib_lo = read_sysreg_s(SYS_APIBKEYLO_EL1);
	k->apib_hi = read_sysreg_s(SYS_APIBKEYHI_EL1);
	k->apda_lo = read_sysreg_s(SYS_APDAKEYLO_EL1);
	k->apda_hi = read_sysreg_s(SYS_APDAKEYHI_EL1);
	k->apdb_lo = read_sysreg_s(SYS_APDBKEYLO_EL1);
	k->apdb_hi = read_sysreg_s(SYS_APDBKEYHI_EL1);
	k->apga_lo = read_sysreg_s(SYS_APGAKEYLO_EL1);
	k->apga_hi = read_sysreg_s(SYS_APGAKEYHI_EL1);
}

static __always_inline void
arm64_caretaker_restore_ptrauth(const struct arm64_caretaker_ptrauth_keys *k)
{
	if (!arm64_caretaker_has_ptrauth)
		return;

	write_sysreg_s(k->apia_lo, SYS_APIAKEYLO_EL1);
	write_sysreg_s(k->apia_hi, SYS_APIAKEYHI_EL1);
	write_sysreg_s(k->apib_lo, SYS_APIBKEYLO_EL1);
	write_sysreg_s(k->apib_hi, SYS_APIBKEYHI_EL1);
	write_sysreg_s(k->apda_lo, SYS_APDAKEYLO_EL1);
	write_sysreg_s(k->apda_hi, SYS_APDAKEYHI_EL1);
	write_sysreg_s(k->apdb_lo, SYS_APDBKEYLO_EL1);
	write_sysreg_s(k->apdb_hi, SYS_APDBKEYHI_EL1);
	write_sysreg_s(k->apga_lo, SYS_APGAKEYLO_EL1);
	write_sysreg_s(k->apga_hi, SYS_APGAKEYHI_EL1);
	isb();
}

#define __caretaker_apr_save(_v, _reg)		((_v) = read_sysreg_s(_reg))
#define __caretaker_apr_restore(_v, _reg)	write_sysreg_s((_v), _reg)

/*
 * ICH_AP0R<n>_EL2 and ICH_AP1R<n>_EL2 encode <n> in the instruction, so the
 * accesses cannot be put in a loop.  Generate the ladder for either group and
 * either direction from one pattern instead of writing it out four times.
 *
 * @_dir: save or restore
 * @_grp: 0 or 1, selecting ICH_AP0R<n>_EL2 or ICH_AP1R<n>_EL2
 */
#define caretaker_vgic_v3_apr(_dir, _grp, _regs, _nr_pre_bits)			\
do {										\
	switch (_nr_pre_bits) {							\
	case 7:									\
		__caretaker_apr_##_dir((_regs)[3], SYS_ICH_AP##_grp##R3_EL2);	\
		__caretaker_apr_##_dir((_regs)[2], SYS_ICH_AP##_grp##R2_EL2);	\
		fallthrough;							\
	case 6:									\
		__caretaker_apr_##_dir((_regs)[1], SYS_ICH_AP##_grp##R1_EL2);	\
		fallthrough;							\
	default:								\
		__caretaker_apr_##_dir((_regs)[0], SYS_ICH_AP##_grp##R0_EL2);	\
	}									\
} while (0)

/*
 * Acknowledge and retire whichever Group 1 interrupt is pending on this CPU.
 * EOImode is 1 (priority drop and deactivation are separate), so a real INTID
 * needs both an EOIR1 and a DIR write.  The special INTIDs (1020-1023) mean
 * "nothing pending" and must not be written back.
 */
__caretaker_text static void caretaker_gic_drain_iar(void)
{
	u32 iar = read_sysreg_s(SYS_ICC_IAR1_EL1);

	if (iar < GIC_SPECIAL_INTID_START) {
		write_sysreg_s(iar, SYS_ICC_EOIR1_EL1);
		write_sysreg_s(iar, SYS_ICC_DIR_EL1);
	}
}

/*
 * Put EL2 back into host (VHE) configuration.  Both vector bases are pointed
 * at the caretaker's own hyp vectors: while a preserved core is running a
 * guest the caretaker owns EL2, and the kernel that installed kvm_hyp_vector
 * may no longer exist.
 */
__caretaker_text static void caretaker_restore_host_el2(void)
{
	write_sysreg_hcr(HCR_HOST_VHE_FLAGS);
	write_sysreg((unsigned long)caretaker_hyp_vector, vbar_el1);
	write_sysreg_s((unsigned long)caretaker_hyp_vector, SYS_VBAR_EL2);
	dsb(sy);
	isb();
}

__caretaker_text static u64 caretaker_gic_v3_get_lr(unsigned int lr)
{
	switch (lr & 0xf) {
	case 0:
		return read_gicreg(ICH_LR0_EL2);
	case 1:
		return read_gicreg(ICH_LR1_EL2);
	case 2:
		return read_gicreg(ICH_LR2_EL2);
	case 3:
		return read_gicreg(ICH_LR3_EL2);
	case 4:
		return read_gicreg(ICH_LR4_EL2);
	case 5:
		return read_gicreg(ICH_LR5_EL2);
	case 6:
		return read_gicreg(ICH_LR6_EL2);
	case 7:
		return read_gicreg(ICH_LR7_EL2);
	case 8:
		return read_gicreg(ICH_LR8_EL2);
	case 9:
		return read_gicreg(ICH_LR9_EL2);
	case 10:
		return read_gicreg(ICH_LR10_EL2);
	case 11:
		return read_gicreg(ICH_LR11_EL2);
	case 12:
		return read_gicreg(ICH_LR12_EL2);
	case 13:
		return read_gicreg(ICH_LR13_EL2);
	case 14:
		return read_gicreg(ICH_LR14_EL2);
	default:
		return read_gicreg(ICH_LR15_EL2);
	}
}

__caretaker_text static void caretaker_gic_v3_set_lr(u64 val, unsigned int lr)
{
	switch (lr & 0xf) {
	case 0:
		write_gicreg(val, ICH_LR0_EL2);
		break;
	case 1:
		write_gicreg(val, ICH_LR1_EL2);
		break;
	case 2:
		write_gicreg(val, ICH_LR2_EL2);
		break;
	case 3:
		write_gicreg(val, ICH_LR3_EL2);
		break;
	case 4:
		write_gicreg(val, ICH_LR4_EL2);
		break;
	case 5:
		write_gicreg(val, ICH_LR5_EL2);
		break;
	case 6:
		write_gicreg(val, ICH_LR6_EL2);
		break;
	case 7:
		write_gicreg(val, ICH_LR7_EL2);
		break;
	case 8:
		write_gicreg(val, ICH_LR8_EL2);
		break;
	case 9:
		write_gicreg(val, ICH_LR9_EL2);
		break;
	case 10:
		write_gicreg(val, ICH_LR10_EL2);
		break;
	case 11:
		write_gicreg(val, ICH_LR11_EL2);
		break;
	case 12:
		write_gicreg(val, ICH_LR12_EL2);
		break;
	case 13:
		write_gicreg(val, ICH_LR13_EL2);
		break;
	case 14:
		write_gicreg(val, ICH_LR14_EL2);
		break;
	default:
		write_gicreg(val, ICH_LR15_EL2);
		break;
	}
}

__caretaker_text static void caretaker_vgic_v3_restore(struct caretaker_arm64_page *cap)
{
	struct vgic_v3_cpu_if *cpu_if = &cap->ctx.vgic_v3;
	unsigned int used_lrs = cpu_if->used_lrs;
	u64 vtr = read_sysreg_s(SYS_ICH_VTR_EL2);
	unsigned int max_lrs = FIELD_GET(ICH_VTR_EL2_ListRegs, vtr) + 1;
	u32 nr_pre_bits = FIELD_GET(ICH_VTR_EL2_PREbits, vtr) + 1;
	unsigned int i;

	/* Drain any pending software-generated SGIs into empty LRs */
	if (cap->ctx.pending_sgis) {
		for (i = 0; i < max_lrs && cap->ctx.pending_sgis; i++) {
			if (i >= used_lrs || (cpu_if->vgic_lr[i] & ICH_LR_STATE) == 0) {
				int sgi = __ffs(cap->ctx.pending_sgis);

				cap->ctx.pending_sgis &= ~BIT(sgi);
				cpu_if->vgic_lr[i] = ((u64)sgi & 0xf) |
						     ICH_LR_PENDING_BIT |
						     ICH_LR_GROUP |
						     ((u64)GIC_DEFAULT_SGI_PRIO <<
						      ICH_LR_PRIORITY_SHIFT);
				if (i >= used_lrs)
					used_lrs = i + 1;
			}
		}
		cpu_if->used_lrs = used_lrs;
	}

	write_sysreg_s(cpu_if->vgic_vmcr, SYS_ICH_VMCR_EL2);

	caretaker_vgic_v3_apr(restore, 0, cpu_if->vgic_ap0r, nr_pre_bits);
	caretaker_vgic_v3_apr(restore, 1, cpu_if->vgic_ap1r, nr_pre_bits);

	write_sysreg_s(cpu_if->vgic_hcr | ICH_HCR_EL2_En, SYS_ICH_HCR_EL2);

	used_lrs = min3(used_lrs, max_lrs, (unsigned int)VGIC_V3_MAX_LRS);

	for (i = 0; i < used_lrs; i++)
		caretaker_gic_v3_set_lr(cpu_if->vgic_lr[i], i);
	isb();
}

__caretaker_text static void caretaker_vgic_v3_save(struct vgic_v3_cpu_if *cpu_if)
{
	u64 vtr = read_sysreg_s(SYS_ICH_VTR_EL2);
	unsigned int max_lrs = FIELD_GET(ICH_VTR_EL2_ListRegs, vtr) + 1;
	u32 nr_pre_bits = FIELD_GET(ICH_VTR_EL2_PREbits, vtr) + 1;
	unsigned int used_lrs = cpu_if->used_lrs;
	unsigned int i;

	used_lrs = min3(used_lrs, max_lrs, (unsigned int)VGIC_V3_MAX_LRS);

	for (i = 0; i < used_lrs; i++) {
		cpu_if->vgic_lr[i] = __gic_v3_get_lr(i);
		__gic_v3_set_lr(0, i);
	}

	cpu_if->vgic_vmcr = read_sysreg_s(SYS_ICH_VMCR_EL2);

	caretaker_vgic_v3_apr(save, 0, cpu_if->vgic_ap0r, nr_pre_bits);
	caretaker_vgic_v3_apr(save, 1, cpu_if->vgic_ap1r, nr_pre_bits);

	write_sysreg_s(0, SYS_ICH_HCR_EL2);
	isb();
}

__caretaker_text static void
caretaker_arm64_inject_sgi(struct caretaker_arm64_page *target_cap, u32 sgi)
{
	int slot = -1;
	int i;

	if (!target_cap)
		return;

	cpu_preserved_inval(target_cap);

	/* Check if the SGI is already pending or active */
	for (i = 0; i < target_cap->ctx.vgic_v3.used_lrs; i++) {
		u64 lr = target_cap->ctx.vgic_v3.vgic_lr[i];

		if ((lr & ICH_LR_VIRTUAL_ID_MASK) == (sgi & 0xf) && (lr & ICH_LR_STATE))
			return;
		if ((lr & ICH_LR_STATE) == 0 && slot < 0)
			slot = i;
	}

	if (slot < 0 && target_cap->ctx.vgic_v3.used_lrs < VGIC_V3_MAX_LRS) {
		slot = target_cap->ctx.vgic_v3.used_lrs;
		target_cap->ctx.vgic_v3.used_lrs++;
	}

	if (slot >= 0) {
		target_cap->ctx.vgic_v3.vgic_lr[slot] =
			((u64)sgi & 0xf) |
			ICH_LR_PENDING_BIT |
			ICH_LR_GROUP |
			(GIC_DEFAULT_SGI_PRIO << ICH_LR_PRIORITY_SHIFT);
	} else {
		target_cap->ctx.pending_sgis |= BIT(sgi & 0xf);
	}

	cpu_preserved_clean(target_cap);

	/* If target vCPU is running on a remote physical CPU, kick it */
	if (target_cap->abi.cb.pcpu_id >= 0 &&
	    target_cap->abi.cb.pcpu_id != arm64_caretaker_get_pcpu()) {
		arch_cpu_preserved_kick(target_cap->abi.cb.pcpu_id);
	}
}

__caretaker_text static void
caretaker_arm64_handle_sgi(struct caretaker_arm64_page *src_cap, u64 reg)
{
	struct caretaker_arm64_page *target;
	u32 sgi = FIELD_GET(ICC_SGI1R_SGI_ID_MASK, reg);
	unsigned int i;

	if (!src_cap || !src_cap->next_vcpu)
		return;

	if (reg & BIT_ULL(ICC_SGI1R_IRQ_ROUTING_MODE_BIT)) {
		/* Broadcast to all other vCPUs */
		for (target = src_cap->next_vcpu;
		     target && target != src_cap;
		     target = target->next_vcpu) {
			cpu_preserved_inval(target);
			caretaker_arm64_inject_sgi(target, sgi);
		}
	} else {
		u64 aff3 = FIELD_GET(ICC_SGI1R_AFFINITY_3_MASK, reg);
		u64 aff2 = FIELD_GET(ICC_SGI1R_AFFINITY_2_MASK, reg);
		u64 aff1 = FIELD_GET(ICC_SGI1R_AFFINITY_1_MASK, reg);
		u64 rs = FIELD_GET(ICC_SGI1R_RS_MASK, reg);
		u64 cluster_mpidr = (aff3 << MPIDR_LEVEL_SHIFT(3)) |
				    (aff2 << MPIDR_LEVEL_SHIFT(2)) |
				    (aff1 << MPIDR_LEVEL_SHIFT(1));
		u64 target_list = FIELD_GET(ICC_SGI1R_TARGET_LIST_MASK, reg);

		for (i = 0; i < 16; i++) {
			u64 target_mpidr;

			if (!(target_list & BIT(i)))
				continue;

			target_mpidr = cluster_mpidr |
				       ((rs * 16 + i) << MPIDR_LEVEL_SHIFT(0));

			target = src_cap;
			do {
				cpu_preserved_inval(target);
				if ((ctxt_sys_reg(&target->ctx.ctxt, MPIDR_EL1) &
				     MPIDR_HWID_BITMASK) == target_mpidr) {
					caretaker_arm64_inject_sgi(target, sgi);
					break;
				}
				target = target->next_vcpu;
			} while (target && target != src_cap);
		}
	}
}

static __caretaker_text int arm64_caretaker_op_enter(void *data)
{
	struct caretaker_arm64_page *cap = data;
	u64 guest_hcr;

	gicv3_caretaker_clear_active_priorities();
	write_sysreg_s(ICC_PMR_EL1_MASK, SYS_ICC_PMR_EL1);
	write_sysreg_s(ICC_CTLR_EL1_EOImode_drop, SYS_ICC_CTLR_EL1);
	write_sysreg_s(ICC_IGRPEN1_EL1_MASK, SYS_ICC_IGRPEN1_EL1);
	pmr_sync();

	guest_hcr = (cap->ctx.hcr_el2 | HCR_AMO | HCR_IMO | HCR_FMO | HCR_E2H) & ~HCR_TGE;
	write_sysreg_hcr(guest_hcr);
	isb();

	cap->last_ret = caretaker_guest_enter(&cap->ctx);

	write_sysreg_hcr(HCR_HOST_VHE_FLAGS);
	isb();

	return 0;
}

static __caretaker_text void
arm64_caretaker_op_arm_timer(void *data, u64 deadline_ticks)
{
	if (deadline_ticks) {
		write_sysreg_s(deadline_ticks, SYS_CNTHP_CVAL_EL2);
		isb();
		write_sysreg_s(1, SYS_CNTHP_CTL_EL2);
	} else {
		write_sysreg_s(0, SYS_CNTHP_CTL_EL2);
	}
	isb();
}

static __caretaker_text void
arm64_caretaker_op_disarm_timer(void *data)
{
	write_sysreg_s(0, SYS_CNTHP_CTL_EL2);
	isb();
}

static __caretaker_text void
arm64_caretaker_op_decode_exit(void *data, struct kvm_caretaker_exit *exit)
{
	struct caretaker_arm64_page *cap = data;
	u64 ret = cap->last_ret;

	exit->rip = cap->ctx.ctxt.regs.pc;
	exit->insn_len = 0;
	exit->type = KVM_CARETAKER_EXIT_UNKNOWN;

	if (ARM_EXCEPTION_CODE(ret) == ARM_EXCEPTION_IRQ) {
		caretaker_gic_drain_iar();
		gicv3_caretaker_clear_active_priorities();
		dsb(sy);
		isb();

		exit->type = KVM_CARETAKER_EXIT_PREEMPT_TIMER;
		return;
	}

	if (ARM_EXCEPTION_IS_TRAP(ret)) {
		u64 esr = cap->ctx.fault.esr_el2;
		u8 ec = ESR_ELx_EC(esr);

		exit->insn_len = 4;

		if (ec == ESR_ELx_EC_WFx) {
			exit->type = KVM_CARETAKER_EXIT_IDLE;
			return;
		}

		if (ec == ESR_ELx_EC_SYS64) {
			u32 iss = ESR_ELx_ISS(esr);
			u32 sys_op = iss & ESR_ELx_SYS64_ISS_SYS_OP_MASK;

			if (sys_op == ESR_ELx_SYS64_ISS_SYS_ICC_SGI1R_EL1 ||
			    sys_op == ESR_ELx_SYS64_ISS_SYS_ICC_ASGI1R_EL1 ||
			    sys_op == ESR_ELx_SYS64_ISS_SYS_ICC_SGI0R_EL1) {
				u32 rt = ESR_ELx_SYS64_ISS_RT(esr);
				u64 val = (rt < 31) ? cap->ctx.ctxt.regs.regs[rt] : 0;

				exit->type = KVM_CARETAKER_EXIT_CROSS_VCPU;
				exit->sgi.sgi_id = FIELD_GET(ICC_SGI1R_SGI_ID_MASK, val);
				exit->sgi.target_mask = val;
				return;
			}
		}

		if (ec == ESR_ELx_EC_DABT_LOW || ec == ESR_ELx_EC_IABT_LOW) {
			/*
			 * Stage-2 abort on a non-RAM IPA (e.g. MMIO device).
			 * Do not advance PC: yield this vCPU out of guest mode
			 * so the incoming kernel's real KVM + VMM handles the
			 * fault on re-attachment.
			 */
			exit->type = KVM_CARETAKER_EXIT_IDLE;
			exit->insn_len = 0;
			return;
		}

		exit->type = KVM_CARETAKER_EXIT_ARCH;
		exit->raw_reason = esr;
		return;
	}

	exit->type = KVM_CARETAKER_EXIT_ARCH;
}

static __caretaker_text void
arm64_caretaker_op_advance_rip(void *data, u64 next_rip)
{
	struct caretaker_arm64_page *cap = data;

	cap->ctx.ctxt.regs.pc = next_rip;
}

static __caretaker_text bool
arm64_caretaker_op_handle_exit(void *data, struct kvm_caretaker_exit *exit)
{
	struct caretaker_arm64_page *cap = data;

	if (exit->type == KVM_CARETAKER_EXIT_CROSS_VCPU) {
		caretaker_arm64_handle_sgi(cap, exit->sgi.target_mask);
		exit->rip += exit->insn_len;
		return true;
	}

	/*
	 * KVM_CARETAKER_EXIT_ARCH is the fallback type assigned by
	 * arm64_caretaker_op_decode_exit() to every trap it did not decode,
	 * including system register accesses.  Skipping the instruction here
	 * would leave the destination register holding whatever it held
	 * before the trap and bypass KVM's ID register sanitisation, with the
	 * guest none the wiser.
	 *
	 * Leave PC pointing at the trapping instruction and report the exit
	 * as unhandled so the vCPU parks until the incoming kernel reclaims
	 * it and full KVM handles the trap.
	 */
	return false;
}

static __caretaker_text inline u64 arm64_sysreg_to_uapi_id(u32 reg)
{
	if (reg == SYS_CNTV_CVAL_EL0)
		return KVM_REG_ARM_TIMER_CVAL;
	return (KVM_REG_ARM64 | KVM_REG_SIZE_U64 |
		KVM_REG_ARM64_SYSREG |
		((u64)sys_reg_Op0(reg) << KVM_REG_ARM64_SYSREG_OP0_SHIFT) |
		((u64)sys_reg_Op1(reg) << KVM_REG_ARM64_SYSREG_OP1_SHIFT) |
		((u64)sys_reg_CRn(reg) << KVM_REG_ARM64_SYSREG_CRN_SHIFT) |
		((u64)sys_reg_CRm(reg) << KVM_REG_ARM64_SYSREG_CRM_SHIFT) |
		((u64)sys_reg_Op2(reg) << KVM_REG_ARM64_SYSREG_OP2_SHIFT));
}

static __caretaker_text void
arm64_caretaker_update_sysreg(struct kvm_vcpu_arch_ser *state,
			      u32 reg, u64 val)
{
	u64 id = arm64_sysreg_to_uapi_id(reg);
	u32 i;

	for (i = 0; i < state->num_sysregs; i++) {
		if (state->sysregs[i].id == id) {
			state->sysregs[i].addr = val;
			return;
		}
	}
}

static __caretaker_text void
arm64_caretaker_detach_serialize(struct caretaker_arm64_page *cap)
{
	cap->abi.vgic_initialized = cap->ctx.vgic_initialized ? 1 : 0;
	cap->abi.cntvoff_el2 = cap->ctx.cntvoff_el2;
	cap->abi.hcr_el2 = cap->ctx.hcr_el2;
	cap->abi.mdcr_el2 = cap->ctx.mdcr_el2;
	cap->abi.cflags = (u32)cap->ctx.cflags;
	if (cap->ctx.vgic_initialized) {
		int i;

		cap->abi.used_lrs = cap->ctx.vgic_v3.used_lrs;
		cap->abi.vgic_hcr = cap->ctx.vgic_v3.vgic_hcr;
		cap->abi.vgic_vmcr = cap->ctx.vgic_v3.vgic_vmcr;
		for (i = 0; i < 4; i++) {
			cap->abi.vgic_ap0r[i] = cap->ctx.vgic_v3.vgic_ap0r[i];
			cap->abi.vgic_ap1r[i] = cap->ctx.vgic_v3.vgic_ap1r[i];
		}
		for (i = 0; i < 16; i++)
			cap->abi.vgic_lr[i] = cap->ctx.vgic_v3.vgic_lr[i];
	}

	if (cap->arch_state) {
		struct kvm_vcpu_arch_ser *state = cap->arch_state;

		cpu_preserved_memcpy(&state->regs.regs, &cap->ctx.ctxt.regs,
				     sizeof(state->regs.regs));
		state->regs.sp_el1 = ctxt_sys_reg(&cap->ctx.ctxt, SP_EL1);
		state->regs.elr_el1 = ctxt_sys_reg(&cap->ctx.ctxt, ELR_EL1);
		state->regs.spsr[KVM_SPSR_EL1] = ctxt_sys_reg(&cap->ctx.ctxt, SPSR_EL1);
		state->regs.spsr[KVM_SPSR_ABT] = cap->ctx.ctxt.spsr_abt;
		state->regs.spsr[KVM_SPSR_UND] = cap->ctx.ctxt.spsr_und;
		state->regs.spsr[KVM_SPSR_IRQ] = cap->ctx.ctxt.spsr_irq;
		state->regs.spsr[KVM_SPSR_FIQ] = cap->ctx.ctxt.spsr_fiq;
		cpu_preserved_memcpy(&state->regs.fp_regs, &cap->ctx.ctxt.fp_regs,
				     sizeof(state->regs.fp_regs));

		arm64_caretaker_update_sysreg(state, SYS_SCTLR_EL1,
					      ctxt_sys_reg(&cap->ctx.ctxt, SCTLR_EL1));
		arm64_caretaker_update_sysreg(state, SYS_CPACR_EL1,
					      ctxt_sys_reg(&cap->ctx.ctxt, CPACR_EL1));
		arm64_caretaker_update_sysreg(state, SYS_TTBR0_EL1,
					      ctxt_sys_reg(&cap->ctx.ctxt, TTBR0_EL1));
		arm64_caretaker_update_sysreg(state, SYS_TTBR1_EL1,
					      ctxt_sys_reg(&cap->ctx.ctxt, TTBR1_EL1));
		arm64_caretaker_update_sysreg(state, SYS_TCR_EL1,
					      ctxt_sys_reg(&cap->ctx.ctxt, TCR_EL1));
		arm64_caretaker_update_sysreg(state, SYS_ESR_EL1,
					      ctxt_sys_reg(&cap->ctx.ctxt, ESR_EL1));
		arm64_caretaker_update_sysreg(state, SYS_AFSR0_EL1,
					      ctxt_sys_reg(&cap->ctx.ctxt, AFSR0_EL1));
		arm64_caretaker_update_sysreg(state, SYS_AFSR1_EL1,
					      ctxt_sys_reg(&cap->ctx.ctxt, AFSR1_EL1));
		arm64_caretaker_update_sysreg(state, SYS_FAR_EL1,
					      ctxt_sys_reg(&cap->ctx.ctxt, FAR_EL1));
		arm64_caretaker_update_sysreg(state, SYS_MAIR_EL1,
					      ctxt_sys_reg(&cap->ctx.ctxt, MAIR_EL1));
		arm64_caretaker_update_sysreg(state, SYS_VBAR_EL1,
					      ctxt_sys_reg(&cap->ctx.ctxt, VBAR_EL1));
		arm64_caretaker_update_sysreg(state, SYS_CONTEXTIDR_EL1,
					      ctxt_sys_reg(&cap->ctx.ctxt, CONTEXTIDR_EL1));
		arm64_caretaker_update_sysreg(state, SYS_AMAIR_EL1,
					      ctxt_sys_reg(&cap->ctx.ctxt, AMAIR_EL1));
		arm64_caretaker_update_sysreg(state, SYS_CNTKCTL_EL1,
					      ctxt_sys_reg(&cap->ctx.ctxt, CNTKCTL_EL1));
		arm64_caretaker_update_sysreg(state, SYS_PAR_EL1,
					      ctxt_sys_reg(&cap->ctx.ctxt, PAR_EL1));
		arm64_caretaker_update_sysreg(state, SYS_TPIDR_EL1,
					      ctxt_sys_reg(&cap->ctx.ctxt, TPIDR_EL1));
		arm64_caretaker_update_sysreg(state, SYS_TPIDR_EL0,
					      ctxt_sys_reg(&cap->ctx.ctxt, TPIDR_EL0));
		arm64_caretaker_update_sysreg(state, SYS_TPIDRRO_EL0,
					      ctxt_sys_reg(&cap->ctx.ctxt, TPIDRRO_EL0));
		arm64_caretaker_update_sysreg(state, SYS_SP_EL1,
					      ctxt_sys_reg(&cap->ctx.ctxt, SP_EL1));
		arm64_caretaker_update_sysreg(state, SYS_ELR_EL1,
					      ctxt_sys_reg(&cap->ctx.ctxt, ELR_EL1));
		arm64_caretaker_update_sysreg(state, SYS_SPSR_EL1,
					      ctxt_sys_reg(&cap->ctx.ctxt, SPSR_EL1));
		arm64_caretaker_update_sysreg(state, SYS_MDSCR_EL1,
					      ctxt_sys_reg(&cap->ctx.ctxt, MDSCR_EL1));
		arm64_caretaker_update_sysreg(state, SYS_CNTV_CVAL_EL0,
					      cap->ctx.cntv_cval_el0);
		arm64_caretaker_update_sysreg(state, SYS_CNTV_CTL_EL0,
					      cap->ctx.cntv_ctl_el0);
		cpu_preserved_clean_sz(state,
				       struct_size(state, sysregs, state->num_sysregs));
	}

	cpu_preserved_clean(&cap->abi);
}

static void arm64_caretaker_sync_vcpu(struct kvm_vcpu *vcpu,
				      void *data)
{
	struct arch_timer_context *vtimer = vcpu_vtimer(vcpu);
	struct kvm_caretaker_arch_ser *abi = data;
	u64 cval, ctl;
	int t;

	/* Sync handover ABI prefix back into incoming vcpu */
	vcpu->arch.hcr_el2 = abi->hcr_el2;
	vcpu->arch.mdcr_el2 = abi->mdcr_el2;
	vcpu->arch.cflags = abi->cflags;

	if (abi->vgic_initialized) {
		int i;

		vcpu->arch.vgic_cpu.vgic_v3.used_lrs = abi->used_lrs;
		vcpu->arch.vgic_cpu.vgic_v3.vgic_hcr = abi->vgic_hcr;
		vcpu->arch.vgic_cpu.vgic_v3.vgic_vmcr = abi->vgic_vmcr;
		for (i = 0; i < 4; i++) {
			vcpu->arch.vgic_cpu.vgic_v3.vgic_ap0r[i] = abi->vgic_ap0r[i];
			vcpu->arch.vgic_cpu.vgic_v3.vgic_ap1r[i] = abi->vgic_ap1r[i];
		}
		for (i = 0; i < 16; i++)
			vcpu->arch.vgic_cpu.vgic_v3.vgic_lr[i] = abi->vgic_lr[i];
	}

	cval = __vcpu_sys_reg(vcpu, CNTV_CVAL_EL0);
	ctl = __vcpu_sys_reg(vcpu, CNTV_CTL_EL0);
	timer_set_offset(vtimer, abi->cntvoff_el2);
	write_sysreg(abi->cntvoff_el2, cntvoff_el2);
	write_sysreg_el0(cval, SYS_CNTV_CVAL);
	write_sysreg_el0(ctl, SYS_CNTV_CTL);
	isb();

	vcpu_set_flag(vcpu, VCPU_INITIALIZED);

	for (t = 0; t < NR_KVM_TIMERS; t++)
		vcpu->arch.timer_cpu.timers[t].loaded = false;

	kvm_make_request(KVM_REQ_IRQ_PENDING, vcpu);
}

