// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * ARM64 KVM Caretaker isolated EL2 runtime execution loop.
 */

#include <hyp/switch.h>
#include <hyp/sysreg-sr.h>

#include <linux/cpu_preserve.h>
#include <linux/irqchip/arm-gic-v3.h>
#include <linux/kho/abi/kvm.h>
#include <linux/kvm_host.h>
#include <linux/oncore.h>
#include <linux/string.h>

#include <asm/barrier.h>
#include <asm/caretaker.h>
#include <asm/cpufeature.h>
#include <asm/cputype.h>
#include <asm/fpsimd.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/sysreg.h>
#include <asm/tlbflush.h>

#include <kvm/arm_arch_timer.h>
#include <kvm/arm_vgic.h>

#include "caretaker.h"
#include "vgic/vgic.h"

struct kvm_host_data kvm_host_data[1];
struct kvm_cpu_context kvm_hyp_ctxt[1];

struct kvm_host_data *caretaker_current_host_data(void)
{
	struct cpu_preserved_stack_context *sctx =
		cpu_preserved_get_stack_context();

	if (sctx && sctx->running_priv) {
		struct caretaker_arm64_page *cap = sctx->running_priv;

		return &cap->host_data;
	}
	return &kvm_host_data[0];
}

DEFINE_STATIC_KEY_FALSE(vgic_v3_cpuif_trap);
DEFINE_STATIC_KEY_FALSE(vgic_v3_has_v2_compat);
DEFINE_STATIC_KEY_FALSE(broken_cntvoff_key);

/*
 * Acknowledge and retire whichever Group 1 interrupt is pending on this CPU.
 * EOImode is 1 (priority drop and deactivation are separate), so a real INTID
 * needs both an EOIR1 and a DIR write.  The special INTIDs (1020-1023) mean
 * "nothing pending" and must not be written back.
 */
static void caretaker_gic_drain_iar(void)
{
	u32 iar = read_sysreg_s(SYS_ICC_IAR1_EL1);

	if (iar < ICC_IAR1_EL1_SPECIAL_START) {
		write_sysreg_s(iar, SYS_ICC_EOIR1_EL1);
		write_sysreg_s(iar, SYS_ICC_DIR_EL1);
	}
}

/*
 * Put EL2 back into host (VHE) configuration.  The vector base is pointed
 * at the caretaker's own hyp vectors: while a preserved core is running a
 * guest the caretaker owns EL2, and the kernel that installed kvm_hyp_vector
 * may no longer exist.
 */
static void caretaker_restore_host_el2(void)
{
	write_sysreg_hcr(HCR_HOST_VHE_FLAGS);
	write_sysreg_s((unsigned long)caretaker_hyp_vector, SYS_VBAR_EL2);
	dsb(sy);
	isb();
}

void arm64_caretaker_handle_invalid(u64 elr, u64 esr, u64 far)
{
	struct cpu_preserved_stack_context *sctx;
	struct caretaker_arm64_page *cap = NULL;
	int cpu = arm64_caretaker_get_pcpu();

	local_daif_mask();
	write_sysreg_s(0, SYS_CNTHP_CTL_EL2);
	caretaker_restore_host_el2();

	sctx = cpu_preserved_get_stack_context();
	if (sctx) {
		cpu = sctx->cpu;
		cap = sctx->running_priv;
	}

	write_sysreg(0, ttbr0_el1);
	if (sctx && sctx->session_pgd_pa) {
		write_sysreg(sctx->session_pgd_pa, ttbr1_el1);
		isb();
		arm64_flush_host_tlb_local();
	}

	if (cap) {
		struct kvm_vcpu *vcpu = &cap->kvm_vcpu;
		struct kvm_cpu_context *host_ctxt = &cap->host_data.host_ctxt;

		if (cap->vgic_initialized) {
			__vgic_v3_deactivate_traps(&vcpu->arch.vgic_cpu.vgic_v3);
			isb();
		}
		__deactivate_cptr_traps_vhe(vcpu);
		__deactivate_traps_common(vcpu);
		write_sysreg(cap->host_cnthctl_el2, cnthctl_el2);
		write_sysreg(cap->host_data.host_debug_state.mdcr_el2, mdcr_el2);
		__sysreg_restore_user_state(host_ctxt);
		__sysreg_restore_common_state(host_ctxt);

		caretaker_gic_drain_iar();
		gicv3_cpu_preserved_clear_active_priorities();
		dsb(sy);
		isb();

		kvm_caretaker_telemetry_stall(&cap->vcpu,
					      KVM_CARETAKER_FAULT_STALL_BASE | (u32)esr,
					      elr);
		kvm_caretaker_telemetry_record_exit(&cap->vcpu, far, elr);
		kvm_caretaker_telemetry_flush(&cap->vcpu);
		smp_mb(); /* Order telemetry flush before publishing FAILED */
		WRITE_ONCE(cap->abi.cb.state, KVM_CARETAKER_FAILED);
		cpu_preserved_clean(&cap->abi.cb);
	}
	if (sctx)
		sctx->running_priv = NULL;

	if (sctx && sctx->ser) {
		while (smp_load_acquire(&sctx->ser->state) == CPU_PRESERVED_WORKLOAD)
			arch_cpu_preserved_park_wait();
	}
	if (cpu >= 0) {
		cpu_preserved_park_loop(cpu);
		arch_cpu_preserved_park_finish(cpu);
	}
	while (1)
		arch_cpu_preserved_park_wait();
}

void __noreturn hyp_panic(void)
{
	arm64_caretaker_handle_invalid(read_sysreg_el2(SYS_ELR),
				       read_sysreg_el2(SYS_ESR),
				       read_sysreg_el2(SYS_FAR));
	unreachable();
}

static bool caretaker_hyp_handle_wfx(struct kvm_vcpu *vcpu, u64 *exit_code)
{
	kvm_incr_pc(vcpu);
	*exit_code = ARM_EXCEPTION_TRAP;
	return false;
}

static const exit_handler_fn caretaker_exit_handlers[ESR_ELx_EC_MAX + 1] = {
	[ESR_ELx_EC_WFx]		= caretaker_hyp_handle_wfx,
	[ESR_ELx_EC_CP15_32]		= kvm_hyp_handle_cp15_32,
	[ESR_ELx_EC_SYS64]		= kvm_hyp_handle_sysreg,
	[ESR_ELx_EC_IABT_LOW]		= kvm_hyp_handle_iabt_low,
	[ESR_ELx_EC_DABT_LOW]		= kvm_hyp_handle_dabt_low,
	[ESR_ELx_EC_WATCHPT_LOW]	= kvm_hyp_handle_watchpt_low,
	[ESR_ELx_EC_MOPS]		= kvm_hyp_handle_mops,
};

static bool
arm64_caretaker_vcpu_run(struct kvm_caretaker_vcpu *cvcpu,
			 enum oncore_exit_reason *reason)
{
	struct caretaker_arm64_page *cap = cvcpu->arch_data;
	struct kvm_vcpu *vcpu = &cap->kvm_vcpu;
	struct kvm_cpu_context *guest_ctxt = &vcpu->arch.ctxt;
	u64 orig_tpidr_el2;
	u64 exit_code;
	bool handled;

	__sysreg_restore_common_state(guest_ctxt);
	__sysreg_restore_el2_return_state(guest_ctxt);

	write_sysreg_hcr(vcpu->arch.hcr_el2);
	isb();

	orig_tpidr_el2 = read_sysreg(tpidr_el2);
	write_sysreg((unsigned long)&cap->hyp_ctxt - (unsigned long)kvm_hyp_ctxt,
		     tpidr_el2);

	exit_code = __guest_enter(vcpu);

	write_sysreg(orig_tpidr_el2, tpidr_el2);

	kvm_caretaker_telemetry_run(cvcpu);
	synchronize_vcpu_pstate(vcpu);

	handled = __fixup_guest_exit(vcpu, &exit_code, caretaker_exit_handlers);

	__sysreg_save_el2_return_state(guest_ctxt);
	__sysreg_save_common_state(guest_ctxt);

	write_sysreg_hcr(HCR_HOST_VHE_FLAGS);
	isb();

	kvm_caretaker_telemetry_record_exit(cvcpu,
					    ARM_EXCEPTION_IS_TRAP(exit_code) ?
					    (u32)kvm_vcpu_get_esr(vcpu) :
					    (u32)exit_code,
					    *vcpu_pc(vcpu));

	if (kvm_caretaker_should_exit(cvcpu))
		return false;

	if (ARM_EXCEPTION_CODE(exit_code) == ARM_EXCEPTION_IRQ) {
		caretaker_gic_drain_iar();
		gicv3_cpu_preserved_clear_active_priorities();
		dsb(sy);
		isb();
		return false;
	}

	if (handled)
		return true;

	if (ARM_EXCEPTION_IS_TRAP(exit_code)) {
		u8 ec = kvm_vcpu_trap_get_class(vcpu);

		if (ec == ESR_ELx_EC_WFx ||
		    ec == ESR_ELx_EC_DABT_LOW ||
		    ec == ESR_ELx_EC_IABT_LOW) {
			*reason = ONCORE_EXIT_YIELD_IDLE;
			return false;
		}

		*reason = ONCORE_EXIT_STALL;
		kvm_caretaker_telemetry_stall(cvcpu,
					      (u32)kvm_vcpu_get_esr(vcpu),
					      *vcpu_pc(vcpu));
		return false;
	}

	*reason = ONCORE_EXIT_STALL;
	kvm_caretaker_telemetry_stall(cvcpu, (u32)exit_code, *vcpu_pc(vcpu));
	return false;
}

static __always_inline u64 arm64_sysreg_to_uapi_id(u32 reg)
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

static __always_inline struct kvm_arm64_sysregs_ser *
arm64_caretaker_sysregs(const struct kvm_vcpu_arch_ser *state)
{
	if (!state || !state->sysregs.phys)
		return NULL;
	return (struct kvm_arm64_sysregs_ser *)(state + 1);
}

static void
arm64_caretaker_update_sysreg(struct kvm_vcpu_arch_ser *state,
			      u32 reg, u64 val)
{
	struct kvm_arm64_sysregs_ser *sysregs = arm64_caretaker_sysregs(state);
	u64 id = arm64_sysreg_to_uapi_id(reg);
	u32 i;

	if (!sysregs)
		return;

	for (i = 0; i < sysregs->num_sysregs; i++) {
		if (sysregs->sysregs[i].id == id) {
			sysregs->sysregs[i].addr = val;
			return;
		}
	}
}

void
arm64_caretaker_detach_serialize(struct caretaker_arm64_page *cap)
{
	struct kvm_vcpu *vcpu = &cap->kvm_vcpu;
	struct vgic_v3_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v3;

	cap->abi.vgic_initialized = cap->vgic_initialized ? 1 : 0;
	cap->abi.cntvoff_el2 = timer_get_offset(vcpu_vtimer(vcpu));
	cap->abi.hcr_el2 = vcpu->arch.hcr_el2;
	cap->abi.mdcr_el2 = vcpu->arch.mdcr_el2;
	cap->abi.cflags = (u32)vcpu->arch.cflags;
	if (cap->vgic_initialized) {
		int i;

		cap->abi.used_lrs = cpu_if->used_lrs;
		cap->abi.vgic_hcr = cpu_if->vgic_hcr;
		cap->abi.vgic_vmcr = cpu_if->vgic_vmcr;
		for (i = 0; i < 4; i++) {
			cap->abi.vgic_ap0r[i] = cpu_if->vgic_ap0r[i];
			cap->abi.vgic_ap1r[i] = cpu_if->vgic_ap1r[i];
		}
		memcpy(cap->abi.vgic_lr,
		       cpu_if->vgic_lr,
		       sizeof(cap->abi.vgic_lr));
	}

	if (cap->arch_state) {
		struct kvm_vcpu_arch_ser *state = cap->arch_state;
		struct kvm_arm64_sysregs_ser *sysregs =
			arm64_caretaker_sysregs(state);
		u64 *sr = vcpu->arch.ctxt.sys_regs;

		memcpy(&state->regs.regs, &vcpu->arch.ctxt.regs,
		       sizeof(state->regs.regs));
		state->regs.sp_el1 = sr[SP_EL1];
		state->regs.elr_el1 = sr[ELR_EL1];
		state->regs.spsr[KVM_SPSR_EL1] = sr[SPSR_EL1];
		state->regs.spsr[KVM_SPSR_ABT] = vcpu->arch.ctxt.spsr_abt;
		state->regs.spsr[KVM_SPSR_UND] = vcpu->arch.ctxt.spsr_und;
		state->regs.spsr[KVM_SPSR_IRQ] = vcpu->arch.ctxt.spsr_irq;
		state->regs.spsr[KVM_SPSR_FIQ] = vcpu->arch.ctxt.spsr_fiq;
		memcpy(&state->regs.fp_regs, &vcpu->arch.ctxt.fp_regs,
		       sizeof(state->regs.fp_regs));

		arm64_caretaker_update_sysreg(state, SYS_SCTLR_EL1, sr[SCTLR_EL1]);
		arm64_caretaker_update_sysreg(state, SYS_CPACR_EL1, sr[CPACR_EL1]);
		arm64_caretaker_update_sysreg(state, SYS_TTBR0_EL1, sr[TTBR0_EL1]);
		arm64_caretaker_update_sysreg(state, SYS_TTBR1_EL1, sr[TTBR1_EL1]);
		arm64_caretaker_update_sysreg(state, SYS_TCR_EL1, sr[TCR_EL1]);
		arm64_caretaker_update_sysreg(state, SYS_ESR_EL1, sr[ESR_EL1]);
		arm64_caretaker_update_sysreg(state, SYS_AFSR0_EL1, sr[AFSR0_EL1]);
		arm64_caretaker_update_sysreg(state, SYS_AFSR1_EL1, sr[AFSR1_EL1]);
		arm64_caretaker_update_sysreg(state, SYS_FAR_EL1, sr[FAR_EL1]);
		arm64_caretaker_update_sysreg(state, SYS_MAIR_EL1, sr[MAIR_EL1]);
		arm64_caretaker_update_sysreg(state, SYS_VBAR_EL1, sr[VBAR_EL1]);
		arm64_caretaker_update_sysreg(state, SYS_CONTEXTIDR_EL1, sr[CONTEXTIDR_EL1]);
		arm64_caretaker_update_sysreg(state, SYS_AMAIR_EL1, sr[AMAIR_EL1]);
		arm64_caretaker_update_sysreg(state, SYS_CNTKCTL_EL1, sr[CNTKCTL_EL1]);
		arm64_caretaker_update_sysreg(state, SYS_PAR_EL1, sr[PAR_EL1]);
		arm64_caretaker_update_sysreg(state, SYS_TPIDR_EL1, sr[TPIDR_EL1]);
		arm64_caretaker_update_sysreg(state, SYS_TPIDR_EL0, sr[TPIDR_EL0]);
		arm64_caretaker_update_sysreg(state, SYS_TPIDRRO_EL0, sr[TPIDRRO_EL0]);
		arm64_caretaker_update_sysreg(state, SYS_SP_EL1, sr[SP_EL1]);
		arm64_caretaker_update_sysreg(state, SYS_ELR_EL1, sr[ELR_EL1]);
		arm64_caretaker_update_sysreg(state, SYS_SPSR_EL1, sr[SPSR_EL1]);
		arm64_caretaker_update_sysreg(state, SYS_MDSCR_EL1, sr[MDSCR_EL1]);
		arm64_caretaker_update_sysreg(state, SYS_CNTV_CVAL_EL0,
					      __vcpu_sys_reg(vcpu, CNTV_CVAL_EL0));
		arm64_caretaker_update_sysreg(state, SYS_CNTV_CTL_EL0,
					      __vcpu_sys_reg(vcpu, CNTV_CTL_EL0));
		cpu_preserved_clean_sz(state,
				       sizeof(*state) +
				       (sysregs ? struct_size(sysregs, sysregs,
							      sysregs->num_sysregs) : 0));
	}

	WRITE_ONCE(cap->serialized, true);
	cpu_preserved_clean(&cap->abi);
}

static void
arm64_caretaker_op_pre_run(void *data)
{
	struct caretaker_arm64_page *cap = data;
	struct kvm_vcpu *vcpu = &cap->kvm_vcpu;
	struct kvm_cpu_context *guest_ctxt = &vcpu->arch.ctxt;
	struct kvm_cpu_context *host_ctxt = &cap->host_data.host_ctxt;
	u64 cnthctl;

	local_daif_mask();

	__sysreg_save_common_state(host_ctxt);
	__sysreg_save_user_state(host_ctxt);

	cap->host_data.host_debug_state.mdcr_el2 = read_sysreg(mdcr_el2);
	write_sysreg(vcpu->arch.mdcr_el2, mdcr_el2);

	cap->host_cnthctl_el2 = read_sysreg(cnthctl_el2);
	cnthctl = cap->host_cnthctl_el2 &
		  ~((CNTHCTL_EL1PCEN << 10) |
		    CNTHCTL_EL1TVT | CNTHCTL_EL1TVCT);
	if (timer_get_offset(vcpu_ptimer(vcpu)))
		cnthctl &= ~(CNTHCTL_EL1PCTEN << 10);
	else
		cnthctl |= (CNTHCTL_EL1PCTEN << 10);
	write_sysreg(cnthctl, cnthctl_el2);

	__sysreg32_restore_state(vcpu);
	__sysreg_restore_user_state(guest_ctxt);
	__sysreg_restore_el1_state(guest_ctxt, ctxt_midr_el1(guest_ctxt),
				   ctxt_sys_reg(guest_ctxt, MPIDR_EL1));

	if (cap->vgic_initialized) {
		struct vgic_v3_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v3;

		__vgic_v3_restore_vmcr_aprs(cpu_if);
		__vgic_v3_activate_traps(cpu_if);
		__vgic_v3_restore_state(cpu_if);
		isb();
	}

	write_sysreg(timer_get_offset(vcpu_vtimer(vcpu)), cntvoff_el2);
	write_sysreg_el0(__vcpu_sys_reg(vcpu, CNTV_CVAL_EL0), SYS_CNTV_CVAL);
	write_sysreg_el0(__vcpu_sys_reg(vcpu, CNTV_CTL_EL0), SYS_CNTV_CTL);
	isb();

	if (vcpu->arch.hw_mmu->vtcr && cap->vttbr_el2) {
		write_sysreg(vcpu->arch.hw_mmu->vtcr, vtcr_el2);
		write_sysreg(cap->vttbr_el2, vttbr_el2);
		isb();
		write_sysreg_hcr(HCR_HOST_VHE_FLAGS & ~HCR_TGE);
		isb();
		__tlbi(vmalls12e1);
		asm volatile("ic iallu");
		dsb(nsh);
		isb();
		write_sysreg_hcr(HCR_HOST_VHE_FLAGS);
		isb();
	}

	__activate_traps_common(vcpu);
	__activate_cptr_traps_vhe(vcpu);
	isb();

	fpsimd_load_state(&guest_ctxt->fp_regs);

	caretaker_gic_drain_iar();
	dsb(sy);
	isb();
}

static void
arm64_caretaker_op_post_run(void *data)
{
	struct cpu_preserved_stack_context *sctx;
	struct caretaker_arm64_page *cap = data;
	struct kvm_vcpu *vcpu = &cap->kvm_vcpu;
	struct kvm_cpu_context *guest_ctxt = &vcpu->arch.ctxt;
	struct kvm_cpu_context *host_ctxt = &cap->host_data.host_ctxt;
	phys_addr_t pgd_pa;

	/* Post-run: disarm preemption timer and save guest context */
	write_sysreg_s(0, SYS_CNTHP_CTL_EL2);

	fpsimd_save_state(&guest_ctxt->fp_regs);

	__deactivate_cptr_traps_vhe(vcpu);
	__deactivate_traps_common(vcpu);
	write_sysreg(cap->host_cnthctl_el2, cnthctl_el2);
	write_sysreg(cap->host_data.host_debug_state.mdcr_el2, mdcr_el2);

	__vcpu_assign_sys_reg(vcpu, CNTV_CVAL_EL0, read_sysreg_el0(SYS_CNTV_CVAL));
	__vcpu_assign_sys_reg(vcpu, CNTV_CTL_EL0, read_sysreg_el0(SYS_CNTV_CTL));

	if (cap->vgic_initialized) {
		struct vgic_v3_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v3;

		__vgic_v3_save_state(cpu_if);
		__vgic_v3_save_aprs(cpu_if);
		__vgic_v3_deactivate_traps(cpu_if);
		isb();
	}

	__sysreg_save_el1_state(guest_ctxt);
	__sysreg_save_user_state(guest_ctxt);
	__sysreg32_save_state(vcpu);

	__sysreg_restore_user_state(host_ctxt);
	__sysreg_restore_common_state(host_ctxt);

	sctx = cpu_preserved_get_stack_context();
	pgd_pa = sctx ? sctx->session_pgd_pa : 0;

	write_sysreg(0, ttbr0_el1);
	if (pgd_pa) {
		write_sysreg(pgd_pa, ttbr1_el1);
		isb();
		arm64_flush_host_tlb_local();
	}
}

static struct kvm_caretaker_ops arm64_caretaker_ops = {
	.vcpu_run = arm64_caretaker_vcpu_run,
	.arm_timer = arm64_caretaker_op_arm_timer,
	.disarm_timer = arm64_caretaker_op_disarm_timer,
	.pre_run = arm64_caretaker_op_pre_run,
	.post_run = arm64_caretaker_op_post_run,
};

static enum oncore_exit_reason
caretaker_arch_run_page(struct caretaker_arm64_page *cap, u64 deadline_ticks)
{
	struct cpu_preserved_stack_context *sctx;
	enum oncore_exit_reason reason;
	int cpu;

	if (!cap)
		return ONCORE_EXIT_ERROR;

	if (cmpxchg(&cap->abi.cb.state, KVM_CARETAKER_PAUSED,
		    KVM_CARETAKER_RUNNING) != KVM_CARETAKER_PAUSED)
		return ONCORE_EXIT_ATTACH_SIGNALED;

	sctx = cpu_preserved_get_stack_context();
	cpu = sctx ? sctx->cpu : arm64_caretaker_get_pcpu();

	WRITE_ONCE(cap->abi.cb.pcpu_id, cpu);
	WRITE_ONCE(cap->pcpu_mpidr, read_sysreg(mpidr_el1) & MPIDR_HWID_BITMASK);
	if (kvm_caretaker_should_exit(&cap->vcpu)) {
		arm64_caretaker_detach_serialize(cap);
		smp_mb(); /* Order serialized state before STOPPED */
		WRITE_ONCE(cap->abi.cb.state, KVM_CARETAKER_STOPPED);
		cpu_preserved_clean(&cap->abi.cb);
		return ONCORE_EXIT_ATTACH_SIGNALED;
	}

	cap->vcpu.ops = &arm64_caretaker_ops;

	if (sctx)
		sctx->running_priv = cap;

	reason = kvm_caretaker_vcpu_run(&cap->vcpu, deadline_ticks);

	if (sctx)
		sctx->running_priv = NULL;

	if (reason == ONCORE_EXIT_ERROR) {
		smp_mb();
		WRITE_ONCE(cap->abi.cb.state, KVM_CARETAKER_FAILED);
		cpu_preserved_clean(&cap->abi.cb);
	} else if (reason == ONCORE_EXIT_ATTACH_SIGNALED ||
		   kvm_caretaker_should_exit(&cap->vcpu) ||
		   cmpxchg(&cap->abi.cb.state, KVM_CARETAKER_RUNNING,
			   KVM_CARETAKER_PAUSED) != KVM_CARETAKER_RUNNING) {
		reason = ONCORE_EXIT_ATTACH_SIGNALED;
		arm64_caretaker_detach_serialize(cap);
		smp_mb(); /* Order serialized state before STOPPED */
		WRITE_ONCE(cap->abi.cb.state, KVM_CARETAKER_STOPPED);
		cpu_preserved_clean(&cap->abi.cb);
	}

	return reason;
}

enum oncore_exit_reason
kvm_arch_vcpu_caretaker_run(void *data, u64 deadline_ticks)
{
	struct kvm_caretaker_cb_ser *cb = data;

	/*
	 * @data is always a struct kvm_caretaker_cb_ser: kvm_caretaker_vcpu_preserve()
	 * installs it with oncore_job_set_data() before activating the job.
	 */
	if (!cb)
		return ONCORE_EXIT_ERROR;

	return caretaker_arch_run_page(container_of(cb,
						    struct caretaker_arm64_page,
						    abi.cb),
				       deadline_ticks);
}
