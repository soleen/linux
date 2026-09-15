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
		__gic_v3_set_lr(cpu_if->vgic_lr[i], i);
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
	if (target_cap->cb.pcpu_id >= 0 &&
	    target_cap->cb.pcpu_id != arm64_caretaker_get_pcpu()) {
		arch_cpu_preserved_kick(target_cap->cb.pcpu_id);
	}
}

__caretaker_text static void
caretaker_arm64_handle_sgi(struct caretaker_arm64_page *src_cap, u64 reg)
{
	struct caretaker_arm64_vm *vm = src_cap ? src_cap->vm : NULL;
	u32 sgi = FIELD_GET(ICC_SGI1R_SGI_ID_MASK, reg);
	unsigned int i, j;

	if (!vm)
		return;

	cpu_preserved_inval_sz(vm, struct_size(vm, vcpus, vm->max_vcpus));

	if (reg & BIT_ULL(ICC_SGI1R_IRQ_ROUTING_MODE_BIT)) {
		/* Broadcast to all other vCPUs */
		for (i = 0; i < vm->nr_vcpus; i++) {
			struct caretaker_arm64_page *target = vm->vcpus[i];

			if (target && target != src_cap)
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

			for (j = 0; j < vm->nr_vcpus; j++) {
				struct caretaker_arm64_page *target = vm->vcpus[j];

				if (!target)
					continue;

				if ((ctxt_sys_reg(&target->ctx.ctxt, MPIDR_EL1) &
				     MPIDR_HWID_BITMASK) == target_mpidr) {
					caretaker_arm64_inject_sgi(target, sgi);
					break;
				}
			}
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
	cap->vcpu.last_exit_rip = next_rip;
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

	if (exit->type == KVM_CARETAKER_EXIT_ARCH && exit->insn_len) {
		exit->rip += exit->insn_len;
		return true;
	}

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
arm64_caretaker_update_sysreg(struct kvm_vcpu_arch_luo_state *state,
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

	if (cap->arch_state && cap->abi.arch_state_size) {
		struct kvm_vcpu_arch_luo_state *state = cap->arch_state;

		oncore_memcpy(&state->regs.regs, &cap->ctx.ctxt.regs,
			      sizeof(state->regs.regs));
		state->regs.sp_el1 = ctxt_sys_reg(&cap->ctx.ctxt, SP_EL1);
		state->regs.elr_el1 = ctxt_sys_reg(&cap->ctx.ctxt, ELR_EL1);
		state->regs.spsr[KVM_SPSR_EL1] = ctxt_sys_reg(&cap->ctx.ctxt, SPSR_EL1);
		state->regs.spsr[KVM_SPSR_ABT] = cap->ctx.ctxt.spsr_abt;
		state->regs.spsr[KVM_SPSR_UND] = cap->ctx.ctxt.spsr_und;
		state->regs.spsr[KVM_SPSR_IRQ] = cap->ctx.ctxt.spsr_irq;
		state->regs.spsr[KVM_SPSR_FIQ] = cap->ctx.ctxt.spsr_fiq;
		oncore_memcpy(&state->regs.fp_regs, &cap->ctx.ctxt.fp_regs,
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
		cpu_preserved_clean_sz(state, cap->abi.arch_state_size);
	}

	cpu_preserved_clean(&cap->abi);
}

static void arm64_caretaker_sync_vcpu(struct kvm_vcpu *vcpu,
				      void *data)
{
	struct kvm_arm64_caretaker_abi *abi = data;
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

	{
		struct arch_timer_context *vtimer = vcpu_vtimer(vcpu);
		u64 cval = __vcpu_sys_reg(vcpu, CNTV_CVAL_EL0);
		u64 ctl = __vcpu_sys_reg(vcpu, CNTV_CTL_EL0);

		timer_set_offset(vtimer, abi->cntvoff_el2);
		write_sysreg(abi->cntvoff_el2, cntvoff_el2);
		write_sysreg_el0(cval, SYS_CNTV_CVAL);
		write_sysreg_el0(ctl, SYS_CNTV_CTL);
		isb();
	}

	vcpu_set_flag(vcpu, VCPU_INITIALIZED);

	for (t = 0; t < NR_KVM_TIMERS; t++)
		vcpu->arch.timer_cpu.timers[t].loaded = false;

	kvm_make_request(KVM_REQ_IRQ_PENDING, vcpu);
}

static __caretaker_text void
arm64_caretaker_op_pre_run(void *data)
{
	struct caretaker_arm64_page *cap = data;

	local_daif_mask();
	arm64_caretaker_save_ptrauth(&cap->ptrauth_keys);

	/* Pre-job: load guest context */
	cpu_preserved_inval(cap);

	arm64_caretaker_load_sysregs(&cap->ctx.ctxt);

	if (cap->ctx.vgic_initialized)
		caretaker_vgic_v3_restore(cap);

	write_sysreg(cap->ctx.cntvoff_el2, cntvoff_el2);
	write_sysreg_el0(cap->ctx.cntv_cval_el0, SYS_CNTV_CVAL);
	write_sysreg_el0(cap->ctx.cntv_ctl_el0, SYS_CNTV_CTL);
	isb();

	if (cap->ctx.vtcr_el2 && cap->ctx.vttbr_el2) {
		write_sysreg(cap->ctx.vtcr_el2, vtcr_el2);
		write_sysreg(cap->ctx.vttbr_el2, vttbr_el2);
		asm(ALTERNATIVE("nop", "isb", ARM64_WORKAROUND_SPECULATIVE_AT));
		__tlbi(vmalle1);
		asm volatile("ic iallu");
		dsb(nsh);
		isb();
	}

	write_sysreg(CPACR_EL1_FPEN_EL0EN | CPACR_EL1_FPEN_EL1EN |
		     CPACR_EL1_ZEN_EL0EN | CPACR_EL1_ZEN_EL1EN,
		     cpacr_el1);
	isb();

	fpsimd_load_state(&cap->ctx.ctxt.fp_regs);

	gicv3_caretaker_enable_sgi();
	write_sysreg_s(ICC_CTLR_EL1_EOImode_drop, SYS_ICC_CTLR_EL1);
	write_sysreg_s(ICC_SRE_EL1_SRE, SYS_ICC_SRE_EL1);
	write_sysreg_s(0, SYS_ICC_BPR1_EL1);
	gicv3_caretaker_clear_active_priorities();
	write_sysreg_s(ICC_PMR_EL1_MASK, SYS_ICC_PMR_EL1);
	write_sysreg_s(ICC_IGRPEN1_EL1_MASK, SYS_ICC_IGRPEN1_EL1);
	caretaker_gic_drain_iar();
	dsb(sy);
	isb();
}

static __caretaker_text void
arm64_caretaker_op_post_run(void *data)
{
	struct caretaker_arm64_page *cap = data;
	phys_addr_t pgd_pa;
	int cpu = cap->cb.pcpu_id;

	/* Post-run: restore host hypervisor mode then save guest context */
	write_sysreg_s(0, SYS_CNTHP_CTL_EL2);
	caretaker_restore_host_el2();

	fpsimd_save_state(&cap->ctx.ctxt.fp_regs);

	cap->ctx.cntv_cval_el0 = read_sysreg_el0(SYS_CNTV_CVAL);
	cap->ctx.cntv_ctl_el0 = read_sysreg_el0(SYS_CNTV_CTL);

	if (cap->ctx.vgic_initialized)
		caretaker_vgic_v3_save(&cap->ctx.vgic_v3);

	arm64_caretaker_save_sysregs(&cap->ctx.ctxt);

	{
		struct cpu_preserved_stack_context *sctx =
			cpu_preserved_get_stack_context();

		if (sctx && sctx->session_pgd_pa)
			pgd_pa = sctx->session_pgd_pa;
		else
			pgd_pa = cpu_preserved_get_pgd(cpu);

		if (!pgd_pa)
			pgd_pa = READ_ONCE(arm64_caretaker_pgd_pa);

		write_sysreg(0, ttbr0_el1);
		if (pgd_pa && read_sysreg(ttbr1_el1) != pgd_pa) {
			write_sysreg(pgd_pa, ttbr1_el1);
			isb();
			arm64_flush_host_tlb_local();
		}
	}

	cpu_preserved_clean(cap);

	if (READ_ONCE(cap->cb.attachment_state) >= KVM_CARETAKER_ATTACHING ||
	    kvm_caretaker_should_exit(&cap->vcpu)) {
		local_daif_mask();
		isb();

		caretaker_gic_drain_iar();
		gicv3_caretaker_clear_active_priorities();
		write_sysreg_s(0, SYS_ICC_IGRPEN1_EL1);
		write_sysreg_s(0, SYS_ICC_PMR_EL1);
		write_sysreg_s(0, SYS_ICC_BPR1_EL1);
		gicv3_caretaker_clear_sgi();
		dsb(sy);
		isb();
	}

	arm64_caretaker_detach_serialize(cap);

	arm64_caretaker_restore_ptrauth(&cap->ptrauth_keys);
	caretaker_restore_host_el2();
}

static struct kvm_caretaker_ops arm64_caretaker_ops __cpu_preserved_data = {
	.enter_guest = arm64_caretaker_op_enter,
	.decode_exit = arm64_caretaker_op_decode_exit,
	.handle_arch_exit = arm64_caretaker_op_handle_exit,
	.advance_rip = arm64_caretaker_op_advance_rip,
	.arm_timer = arm64_caretaker_op_arm_timer,
	.disarm_timer = arm64_caretaker_op_disarm_timer,
	.pre_run = arm64_caretaker_op_pre_run,
	.post_run = arm64_caretaker_op_post_run,
	.sync_vcpu = arm64_caretaker_sync_vcpu,
};

static __caretaker_text enum oncore_exit_reason
caretaker_arch_run_page(struct caretaker_arm64_page *cap, u64 deadline_ticks)
{
	enum oncore_exit_reason reason;
	int cpu;

	if (!cap)
		return ONCORE_EXIT_ERROR;

	cpu_preserved_inval(&cap->cb);
	cpu = cap->cb.pcpu_id;
	if (cpu < 0 || cpu >= ARRAY_SIZE(arm64_caretaker_faults))
		cpu = arm64_caretaker_get_pcpu();

	if (READ_ONCE(cap->cb.attachment_state) == KVM_CARETAKER_ATTACHING ||
	    cpu_preserved_should_exit(cpu)) {
		arm64_caretaker_detach_serialize(cap);
		WRITE_ONCE(cap->cb.attachment_state, KVM_CARETAKER_ATTACHED);
		cpu_preserved_clean(&cap->cb);
		return ONCORE_EXIT_ATTACH_SIGNALED;
	}

	cap->cb.pcpu_id = cpu;
	cap->cb.attachment_state = KVM_CARETAKER_DETACHED;
	cpu_preserved_clean(&cap->cb);

	cap->vcpu.ops = &arm64_caretaker_ops;
	cap->vcpu.arch_data = cap;

	reason = kvm_caretaker_vcpu_run(&cap->vcpu, deadline_ticks);

	WRITE_ONCE(cap->vcpu.running, 0);
	cpu_preserved_clean(&cap->vcpu.running);

	if (reason == ONCORE_EXIT_ATTACH_SIGNALED ||
	    reason == ONCORE_EXIT_ERROR ||
	    READ_ONCE(cap->cb.attachment_state) == KVM_CARETAKER_ATTACHING) {
		arm64_caretaker_detach_serialize(cap);
		WRITE_ONCE(cap->cb.attachment_state, KVM_CARETAKER_ATTACHED);
		cpu_preserved_clean(&cap->cb);
	}

	return reason;
}

__caretaker_text enum oncore_exit_reason
kvm_arch_vcpu_caretaker_run(void *data, u64 deadline_ticks)
{
	struct kvm_caretaker_cb *cb = data;

	/*
	 * @data is always a struct kvm_caretaker_cb: kvm_caretaker_vcpu_preserve()
	 * installs it with oncore_job_set_data() before activating the job.
	 */
	if (!cb)
		return ONCORE_EXIT_ERROR;

	return caretaker_arch_run_page(container_of(cb,
						    struct caretaker_arm64_page,
						    cb),
				       deadline_ticks);
}

void kvm_arch_vcpu_luo_pre_retrieve_caretaker(struct kvm_vcpu *vcpu,
					      struct kvm_vcpu_luo_ser *ser)
{
	if ((ser->flags & KVM_VCPU_LUO_FLAG_CARETAKER) && ser->cb.phys) {
		struct kvm_arm64_caretaker_abi *abi = phys_to_virt(ser->cb.phys);
		int pcpu = abi->cb.pcpu_id;

		if (pcpu >= 0) {
			kvm_caretaker_wait_for_attach(&abi->cb, pcpu, NULL);
			cpu_preserved_inval(abi);
			if (abi->arch_state_pa && abi->arch_state_size)
				cpu_preserved_inval_sz(phys_to_virt(abi->arch_state_pa),
						       abi->arch_state_size);
		}
	}
}

void kvm_arch_vcpu_luo_attach_caretaker(struct kvm_vcpu *vcpu,
					struct kvm_vcpu_luo_ser *ser)
{
	if ((ser->flags & KVM_VCPU_LUO_FLAG_CARETAKER) && ser->cb.phys) {
		struct kvm_arm64_caretaker_abi *abi = phys_to_virt(ser->cb.phys);

		arm64_caretaker_sync_vcpu(vcpu, abi);
		kvm_caretaker_post_attach_vcpu(vcpu, NULL);
		return;
	}

	kvm_caretaker_post_attach_vcpu(vcpu, NULL);
}

void arm64_kvm_caretaker_unpreserve(struct kvm_vcpu_luo_ser *ser)
{
	if (ser->cb.phys) {
		struct kvm_caretaker_cb *cb = phys_to_virt(ser->cb.phys);

		if (cb->runtime_pa)
			kho_unpreserve_free(phys_to_virt(cb->runtime_pa));
		ser->cb.phys = 0;
	}
}

void arm64_kvm_caretaker_finish(struct kvm_vcpu_luo_ser *ser)
{
	if (ser->cb.phys) {
		struct kvm_caretaker_cb *cb = phys_to_virt(ser->cb.phys);

		if (cb->runtime_pa)
			kho_restore_free(phys_to_virt(cb->runtime_pa));
		ser->cb.phys = 0;
	}
}
