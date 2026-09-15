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
#include <asm/cpufeature.h>
#include <asm/cputype.h>
#include <asm/fpsimd.h>
#include <asm/kernel-pgtable.h>
#include <asm/kexec.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pgtable.h>
#include <asm/kvm_ptrauth.h>
#include <asm/mmu_context.h>
#include <asm/pgtable.h>
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
		if (cpu_preserved_should_exit(cpu)) {
			cpu_preserved_set_dead(cpu);
			arch_cpu_preserved_park_finish(cpu);
		}
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

static int preserve_stage2_visitor(const struct kvm_pgtable_visit_ctx *ctx,
				   enum kvm_pgtable_walk_flags visit)
{
	if (kvm_pte_valid(ctx->old) && ctx->level != KVM_PGTABLE_LAST_LEVEL &&
	    FIELD_GET(KVM_PTE_TYPE, ctx->old) == KVM_PTE_TYPE_TABLE) {
		u64 phys = kvm_pte_to_phys(ctx->old);
		struct page *p = phys_to_page(phys);

		if (p)
			return kho_preserve_pages(p, 1);
	}
	return 0;
}

int arm64_kvm_caretaker_preserve(struct kvm_vcpu *vcpu,
				 struct kvm_vcpu_luo_ser *ser)
{
	struct kvm_s2_mmu *mmu = vcpu->arch.hw_mmu ?
				 vcpu->arch.hw_mmu : &vcpu->kvm->arch.mmu;
	struct oncore_session *sess = vcpu->caretaker.job ?
					 vcpu->caretaker.job->session : NULL;
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
	if (!vcpu->kvm->caretaker_vm)
		return -EINVAL;

	cap = kho_alloc_preserve(sizeof(*cap));
	if (IS_ERR(cap)) {
		pr_err("caretaker arm64: failed to allocate preserved page\n");
		return -ENOMEM;
	}
	oncore_session_map_buffer(sess, cap, sizeof(*cap));

	memset(cap, 0, sizeof(*cap));

	kvm_caretaker_init_common_vcpu(&cap->vcpu, vcpu, cap, sizeof(*cap),
				       NULL, cap);

	/* Copy architectural execution state */
	cap->ctx.ctxt = vcpu->arch.ctxt;
	cap->ctx.fault = vcpu->arch.fault;
	cap->ctx.hcr_el2 = vcpu->arch.hcr_el2;
	cap->ctx.mdcr_el2 = vcpu->arch.mdcr_el2;
	cap->ctx.cflags = vcpu->arch.cflags;

	cap->ctx.vtcr_el2 = mmu->vtcr;
	cap->ctx.vttbr_el2 = kvm_get_vttbr(mmu);
	cap->ctx.s2_pgd_phys = mmu->pgd_phys;

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

	{
		struct arch_timer_context *vtimer = vcpu_vtimer(vcpu);

		cap->ctx.cntvoff_el2 = timer_get_offset(vtimer);
		cap->ctx.cntv_cval_el0 = timer_get_cval(vtimer);
		cap->ctx.cntv_ctl_el0 = timer_get_ctl(vtimer);
	}

	{
		struct caretaker_arm64_vm *vm = vcpu->kvm->caretaker_vm;
		size_t sz = struct_size(vm, vcpus, vm->max_vcpus);

		oncore_session_map_buffer(sess, vm, sz);

		/*
		 * vcpus[] is sized by kvm->created_vcpus, so it is indexed by
		 * the dense vcpu_idx.  vcpu_id is chosen by userspace and may
		 * be sparse -- using it here would leave holes in the array and
		 * silently drop vCPUs from the caretaker.  nr_vcpus is already
		 * the full count (see kvm_arch_vm_luo_preserve()).
		 */
		if (vcpu->vcpu_idx < vm->max_vcpus)
			vm->vcpus[vcpu->vcpu_idx] = cap;
		cap->vm = vm;
		cpu_preserved_clean_sz(vm, sz);
	}

	bitmap_copy(cap->ctx.vcpu_features, vcpu->kvm->arch.vcpu_features,
		    KVM_VCPU_MAX_FEATURES);

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
		struct kvm_vcpu_arch_luo_state *state =
			phys_to_virt(ser->arch_state.phys);
		size_t sz = struct_size(state, sysregs, state->num_sysregs);

		cap->arch_state = state;
		cap->abi.arch_state_pa = ser->arch_state.phys;
		cap->abi.arch_state_size = sz;
		oncore_session_map_buffer(sess, state, sz);
	}

	ser->cb.phys = cap->cb.runtime_pa;

	cpu_preserved_clean(cap);

	if (mmu->pgd_phys) {
		int ret = kho_preserve_pages(phys_to_page(mmu->pgd_phys), 1);

		if (ret) {
			vcpu->caretaker.cb = NULL;
			kho_unpreserve_free(cap);
			return ret;
		}
	}

	if (mmu->pgt) {
		struct kvm_pgtable_walker walker = {
			.cb = preserve_stage2_visitor,
			.flags = KVM_PGTABLE_WALK_TABLE_PRE,
		};
		int ret = kvm_pgtable_walk(mmu->pgt, 0, BIT(mmu->pgt->ia_bits), &walker);

		if (ret) {
			vcpu->caretaker.cb = NULL;
			kho_unpreserve_free(cap);
			return ret;
		}
	}

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
