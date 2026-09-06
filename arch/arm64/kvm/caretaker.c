// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 */
#include <linux/caretaker.h>
#include <linux/cpu_preserve.h>
#include <asm/caretaker.h>
#include <linux/delay.h>
#include <linux/kexec_handover.h>
#include <linux/kvm_host.h>
#include <linux/kho/abi/kvm.h>
#include <linux/irqchip/arm-gic-v3.h>
#include <linux/sched.h>
#include <asm/barrier.h>
#include <asm/cpu_ops.h>
#include <asm/cputype.h>
#include <asm/kexec.h>
#include <asm/kernel-pgtable.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/mmu_context.h>
#include <asm/pgtable.h>
#include <asm/sysreg.h>
#include <asm/tlbflush.h>
#include <asm/vectors.h>
#include <asm/fpsimd.h>
#include <asm/cpufeature.h>
#include <asm/kvm_ptrauth.h>
#include <kvm/arm_vgic.h>
#include <kvm/arm_arch_timer.h>
#include <hyp/sysreg-sr.h>
#include <asm/kvm_pgtable.h>
#include <asm/smp_plat.h>
#include "caretaker.h"

static_assert(offsetof(struct caretaker_arm64_context, fault.esr_el2) ==
	      CAP_FAULT_ESR);
static_assert(offsetof(struct caretaker_arm64_context, fault.far_el2) ==
	      CAP_FAULT_FAR);
static_assert(offsetof(struct caretaker_arm64_context, fault.hpfar_el2) ==
	      CAP_FAULT_HPFAR);
static_assert(offsetof(struct caretaker_arm64_context, fault.disr_el1) ==
	      CAP_FAULT_DISR);
static_assert(offsetof(struct caretaker_arm64_context, ctxt) ==
	      CAP_CTXT_OFFSET);

struct caretaker_fault_info arm64_caretaker_faults[NR_CPUS] __cpu_preserved_data;
EXPORT_SYMBOL_GPL(arm64_caretaker_faults);

void __caretaker_text __no_stack_protector arm64_caretaker_handle_invalid(u64 elr, u64 esr, u64 far)
{
	int cpu = arm64_caretaker_get_pcpu();

	if (cpu >= 0 && cpu < NR_CPUS) {
		arm64_caretaker_faults[cpu].elr = elr;
		arm64_caretaker_faults[cpu].esr = esr;
		arm64_caretaker_faults[cpu].far = far;
		arm64_caretaker_faults[cpu].count++;
		arch_cpu_preserved_dcache_clean((unsigned long)&arm64_caretaker_faults[cpu],
						(unsigned long)&arm64_caretaker_faults[cpu] + sizeof(arm64_caretaker_faults[cpu]));
		arch_cpu_preserved_set_stage(cpu, 99, esr);
	}

	while (1) {
		if (cpu_preserved_should_exit(cpu)) {
			cpu_preserved_set_dead(cpu);
			arch_cpu_preserved_park_finish(cpu);
		}
		arch_cpu_preserved_park_wait();
	}
}
EXPORT_SYMBOL_GPL(arm64_caretaker_handle_invalid);

__caretaker_text static inline void
arm64_caretaker_load_sysregs(struct kvm_cpu_context *ctxt)
{
	u64 midr = read_cpuid_id();
	u64 mpidr = ctxt_sys_reg(ctxt, MPIDR_EL1);

	write_sysreg(midr, vpidr_el2);
	write_sysreg(mpidr, vmpidr_el2);

	write_sysreg_el1(ctxt_sys_reg(ctxt, SCTLR_EL1), SYS_SCTLR);
	write_sysreg_el1(ctxt_sys_reg(ctxt, CPACR_EL1), SYS_CPACR);
	write_sysreg_el1(ctxt_sys_reg(ctxt, TTBR0_EL1), SYS_TTBR0);
	write_sysreg_el1(ctxt_sys_reg(ctxt, TTBR1_EL1), SYS_TTBR1);
	write_sysreg_el1(ctxt_sys_reg(ctxt, TCR_EL1), SYS_TCR);
	if (cpus_have_final_cap(ARM64_HAS_TCR2))
		write_sysreg_el1(ctxt_sys_reg(ctxt, TCR2_EL1), SYS_TCR2);
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
}

__caretaker_text static inline void
arm64_caretaker_save_sysregs(struct kvm_cpu_context *ctxt)
{
	ctxt_sys_reg(ctxt, SCTLR_EL1) = read_sysreg_el1(SYS_SCTLR);
	ctxt_sys_reg(ctxt, CPACR_EL1) = read_sysreg_el1(SYS_CPACR);
	ctxt_sys_reg(ctxt, TTBR0_EL1) = read_sysreg_el1(SYS_TTBR0);
	ctxt_sys_reg(ctxt, TTBR1_EL1) = read_sysreg_el1(SYS_TTBR1);
	ctxt_sys_reg(ctxt, TCR_EL1) = read_sysreg_el1(SYS_TCR);
	if (cpus_have_final_cap(ARM64_HAS_TCR2))
		ctxt_sys_reg(ctxt, TCR2_EL1) = read_sysreg_el1(SYS_TCR2);
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
}

static int preserve_stage2_visitor(const struct kvm_pgtable_visit_ctx *ctx,
				   enum kvm_pgtable_walk_flags visit)
{
	if (kvm_pte_valid(ctx->old) && ctx->level != KVM_PGTABLE_LAST_LEVEL &&
	    FIELD_GET(KVM_PTE_TYPE, ctx->old) == KVM_PTE_TYPE_TABLE) {
		u64 phys = kvm_pte_to_phys(ctx->old);
		struct page *p = phys_to_page(phys);
		if (p)
			kho_preserve_pages(p, 1);
	}
	return 0;
}

int arm64_kvm_caretaker_preserve(struct kvm_vcpu *vcpu, struct kvm_vcpu_luo_ser *ser)
{
	struct kvm_s2_mmu *mmu = vcpu->arch.hw_mmu ? vcpu->arch.hw_mmu : &vcpu->kvm->arch.mmu;
	struct caretaker_session *sess = (vcpu && vcpu->caretaker_job) ?
					 vcpu->caretaker_job->session : NULL;
	struct caretaker_arm64_page *cap;

	cap = kho_alloc_preserve(sizeof(*cap));
	if (!cap || IS_ERR(cap)) {
		pr_err("caretaker arm64: failed to allocate preserved page\n");
		return -ENOMEM;
	}
	caretaker_session_map_buffer(sess, cap, sizeof(*cap));

	memset(cap, 0, sizeof(*cap));

	kvm_caretaker_init_common_vcpu(&cap->vcpu, vcpu, cap, sizeof(*cap),
				       NULL, cap);

	/* Copy architectural execution state */
	cap->ctx.ctxt = vcpu->arch.ctxt;
	cap->ctx.fault = vcpu->arch.fault;
	cap->ctx.hcr_el2 = vcpu->arch.hcr_el2;
	cap->ctx.mdcr_el2 = vcpu->arch.mdcr_el2;
	cap->ctx.cflags = vcpu->arch.cflags;

	if (mmu) {
		cap->ctx.vtcr_el2 = mmu->vtcr;
		cap->ctx.vttbr_el2 = kvm_get_vttbr(mmu);
		cap->ctx.s2_pgd_phys = mmu->pgd_phys;
	}

	if (vcpu->kvm && vgic_initialized(vcpu->kvm)) {
		int i;

		cap->ctx.vgic_initialized = true;
		cap->ctx.vgic_v3 = vcpu->arch.vgic_cpu.vgic_v3;

		for (i = 0; ; i++) {
			phys_addr_t rpa;
			unsigned long rva;
			size_t rsize;

			if (gicv3_caretaker_get_redist_region(i, &rpa, &rva, &rsize))
				break;
			caretaker_session_map_range(sess, rpa, rva, rsize,
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
		static struct caretaker_arm64_vm *active_vm;

		if (vcpu->vcpu_id == 0 || !active_vm) {
			unsigned int max_vcpus = KVM_MAX_VCPUS;

			if (vcpu->kvm && vcpu->kvm->created_vcpus)
				max_vcpus = max_t(unsigned int, vcpu->kvm->created_vcpus, KVM_MAX_VCPUS);

			if (!active_vm)
				active_vm = kho_alloc_preserve(struct_size(active_vm, vcpus, max_vcpus));
			if (active_vm && !IS_ERR(active_vm)) {
				memset(active_vm, 0, struct_size(active_vm, vcpus, max_vcpus));
				active_vm->max_vcpus = max_vcpus;
				caretaker_session_map_buffer(sess, active_vm,
							     struct_size(active_vm, vcpus, max_vcpus));
			}
		}

		if (active_vm && !IS_ERR(active_vm)) {
			if (vcpu->vcpu_id < active_vm->max_vcpus) {
				active_vm->vcpus[vcpu->vcpu_id] = cap;
				if (vcpu->vcpu_id >= active_vm->nr_vcpus)
					active_vm->nr_vcpus = vcpu->vcpu_id + 1;
			}
			cap->vm = active_vm;
			arch_cpu_preserved_dcache_clean((unsigned long)active_vm,
							(unsigned long)active_vm +
							struct_size(active_vm, vcpus, active_vm->max_vcpus));
		}
	}

	if (vcpu->kvm)
		bitmap_copy(cap->ctx.vcpu_features, vcpu->kvm->arch.vcpu_features,
			    KVM_VCPU_MAX_FEATURES);

	vcpu->cb.runtime_pa = cap->cb.runtime_pa;
	vcpu->cb.runtime_size = cap->cb.runtime_size;
	ser->cb.phys = cap->cb.runtime_pa;

	arch_cpu_preserved_dcache_clean((unsigned long)cap,
					(unsigned long)cap + sizeof(*cap));

	if (mmu && mmu->pgd_phys)
		kho_preserve_pages(phys_to_page(mmu->pgd_phys), 1);

	if (mmu && mmu->pgt) {
		struct kvm_pgtable_walker walker = {
			.cb = preserve_stage2_visitor,
			.flags = KVM_PGTABLE_WALK_TABLE_PRE,
		};
		kvm_pgtable_walk(mmu->pgt, 0, BIT(mmu->pgt->ia_bits), &walker);
	}

	arch_cpu_preserved_get_pgd();

	return 0;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(arm64_kvm_caretaker_preserve);



struct arm64_caretaker_ptrauth_keys {
	u64 apia_lo, apia_hi;
	u64 apib_lo, apib_hi;
	u64 apda_lo, apda_hi;
	u64 apdb_lo, apdb_hi;
	u64 apga_lo, apga_hi;
};

static __always_inline void arm64_caretaker_save_ptrauth(struct arm64_caretaker_ptrauth_keys *k)
{
	if (!IS_ENABLED(CONFIG_ARM64_PTR_AUTH) || !system_has_full_ptr_auth())
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

static __always_inline void arm64_caretaker_restore_ptrauth(const struct arm64_caretaker_ptrauth_keys *k)
{
	if (!IS_ENABLED(CONFIG_ARM64_PTR_AUTH) || !system_has_full_ptr_auth())
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

__caretaker_text static inline void gicv3_caretaker_clear_active_priorities(void)
{
	u32 ctlr = read_sysreg_s(SYS_ICC_CTLR_EL1);
	u32 pribits = ((ctlr & (0x7 << 8)) >> 8) + 1;

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

__caretaker_text static void caretaker_vgic_v3_restore(struct caretaker_arm64_page *cap)
{
	struct vgic_v3_cpu_if *cpu_if = &cap->ctx.vgic_v3;
	u64 vtr = read_sysreg_s(SYS_ICH_VTR_EL2);
	u32 nr_pre_bits = ((vtr >> 26) & 7) + 1;
	unsigned int max_lrs = (vtr & 0x1f) + 1;
	unsigned int used_lrs = cpu_if->used_lrs;
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
						     (0xa0ULL << ICH_LR_PRIORITY_SHIFT);
				if (i >= used_lrs)
					used_lrs = i + 1;
			}
		}
		cpu_if->used_lrs = used_lrs;
	}

	write_sysreg_s(cpu_if->vgic_vmcr, SYS_ICH_VMCR_EL2);

	switch (nr_pre_bits) {
	case 7:
		write_sysreg_s(cpu_if->vgic_ap0r[3], SYS_ICH_AP0R3_EL2);
		write_sysreg_s(cpu_if->vgic_ap0r[2], SYS_ICH_AP0R2_EL2);
		fallthrough;
	case 6:
		write_sysreg_s(cpu_if->vgic_ap0r[1], SYS_ICH_AP0R1_EL2);
		fallthrough;
	default:
		write_sysreg_s(cpu_if->vgic_ap0r[0], SYS_ICH_AP0R0_EL2);
	}

	switch (nr_pre_bits) {
	case 7:
		write_sysreg_s(cpu_if->vgic_ap1r[3], SYS_ICH_AP1R3_EL2);
		write_sysreg_s(cpu_if->vgic_ap1r[2], SYS_ICH_AP1R2_EL2);
		fallthrough;
	case 6:
		write_sysreg_s(cpu_if->vgic_ap1r[1], SYS_ICH_AP1R1_EL2);
		fallthrough;
	default:
		write_sysreg_s(cpu_if->vgic_ap1r[0], SYS_ICH_AP1R0_EL2);
	}

	write_sysreg_s(cpu_if->vgic_hcr | ICH_HCR_EL2_En, SYS_ICH_HCR_EL2);

	if (used_lrs > max_lrs)
		used_lrs = max_lrs;
	if (used_lrs > VGIC_V3_MAX_LRS)
		used_lrs = VGIC_V3_MAX_LRS;

	for (i = 0; i < used_lrs; i++) {
		switch (i) {
		case 0:  write_sysreg_s(cpu_if->vgic_lr[0], SYS_ICH_LR0_EL2); break;
		case 1:  write_sysreg_s(cpu_if->vgic_lr[1], SYS_ICH_LR1_EL2); break;
		case 2:  write_sysreg_s(cpu_if->vgic_lr[2], SYS_ICH_LR2_EL2); break;
		case 3:  write_sysreg_s(cpu_if->vgic_lr[3], SYS_ICH_LR3_EL2); break;
		case 4:  write_sysreg_s(cpu_if->vgic_lr[4], SYS_ICH_LR4_EL2); break;
		case 5:  write_sysreg_s(cpu_if->vgic_lr[5], SYS_ICH_LR5_EL2); break;
		case 6:  write_sysreg_s(cpu_if->vgic_lr[6], SYS_ICH_LR6_EL2); break;
		case 7:  write_sysreg_s(cpu_if->vgic_lr[7], SYS_ICH_LR7_EL2); break;
		case 8:  write_sysreg_s(cpu_if->vgic_lr[8], SYS_ICH_LR8_EL2); break;
		case 9:  write_sysreg_s(cpu_if->vgic_lr[9], SYS_ICH_LR9_EL2); break;
		case 10: write_sysreg_s(cpu_if->vgic_lr[10], SYS_ICH_LR10_EL2); break;
		case 11: write_sysreg_s(cpu_if->vgic_lr[11], SYS_ICH_LR11_EL2); break;
		case 12: write_sysreg_s(cpu_if->vgic_lr[12], SYS_ICH_LR12_EL2); break;
		case 13: write_sysreg_s(cpu_if->vgic_lr[13], SYS_ICH_LR13_EL2); break;
		case 14: write_sysreg_s(cpu_if->vgic_lr[14], SYS_ICH_LR14_EL2); break;
		case 15: write_sysreg_s(cpu_if->vgic_lr[15], SYS_ICH_LR15_EL2); break;
		}
	}
	isb();
}

__caretaker_text static void caretaker_vgic_v3_save(struct vgic_v3_cpu_if *cpu_if)
{
	u64 vtr = read_sysreg_s(SYS_ICH_VTR_EL2);
	u32 nr_pre_bits = ((vtr >> 26) & 7) + 1;
	unsigned int max_lrs = (vtr & 0x1f) + 1;
	unsigned int used_lrs = cpu_if->used_lrs;
	unsigned int i;

	if (used_lrs > max_lrs)
		used_lrs = max_lrs;
	if (used_lrs > VGIC_V3_MAX_LRS)
		used_lrs = VGIC_V3_MAX_LRS;

	for (i = 0; i < used_lrs; i++) {
		switch (i) {
		case 0:  cpu_if->vgic_lr[0] = read_sysreg_s(SYS_ICH_LR0_EL2); write_sysreg_s(0, SYS_ICH_LR0_EL2); break;
		case 1:  cpu_if->vgic_lr[1] = read_sysreg_s(SYS_ICH_LR1_EL2); write_sysreg_s(0, SYS_ICH_LR1_EL2); break;
		case 2:  cpu_if->vgic_lr[2] = read_sysreg_s(SYS_ICH_LR2_EL2); write_sysreg_s(0, SYS_ICH_LR2_EL2); break;
		case 3:  cpu_if->vgic_lr[3] = read_sysreg_s(SYS_ICH_LR3_EL2); write_sysreg_s(0, SYS_ICH_LR3_EL2); break;
		case 4:  cpu_if->vgic_lr[4] = read_sysreg_s(SYS_ICH_LR4_EL2); write_sysreg_s(0, SYS_ICH_LR4_EL2); break;
		case 5:  cpu_if->vgic_lr[5] = read_sysreg_s(SYS_ICH_LR5_EL2); write_sysreg_s(0, SYS_ICH_LR5_EL2); break;
		case 6:  cpu_if->vgic_lr[6] = read_sysreg_s(SYS_ICH_LR6_EL2); write_sysreg_s(0, SYS_ICH_LR6_EL2); break;
		case 7:  cpu_if->vgic_lr[7] = read_sysreg_s(SYS_ICH_LR7_EL2); write_sysreg_s(0, SYS_ICH_LR7_EL2); break;
		case 8:  cpu_if->vgic_lr[8] = read_sysreg_s(SYS_ICH_LR8_EL2); write_sysreg_s(0, SYS_ICH_LR8_EL2); break;
		case 9:  cpu_if->vgic_lr[9] = read_sysreg_s(SYS_ICH_LR9_EL2); write_sysreg_s(0, SYS_ICH_LR9_EL2); break;
		case 10: cpu_if->vgic_lr[10] = read_sysreg_s(SYS_ICH_LR10_EL2); write_sysreg_s(0, SYS_ICH_LR10_EL2); break;
		case 11: cpu_if->vgic_lr[11] = read_sysreg_s(SYS_ICH_LR11_EL2); write_sysreg_s(0, SYS_ICH_LR11_EL2); break;
		case 12: cpu_if->vgic_lr[12] = read_sysreg_s(SYS_ICH_LR12_EL2); write_sysreg_s(0, SYS_ICH_LR12_EL2); break;
		case 13: cpu_if->vgic_lr[13] = read_sysreg_s(SYS_ICH_LR13_EL2); write_sysreg_s(0, SYS_ICH_LR13_EL2); break;
		case 14: cpu_if->vgic_lr[14] = read_sysreg_s(SYS_ICH_LR14_EL2); write_sysreg_s(0, SYS_ICH_LR14_EL2); break;
		case 15: cpu_if->vgic_lr[15] = read_sysreg_s(SYS_ICH_LR15_EL2); write_sysreg_s(0, SYS_ICH_LR15_EL2); break;
		}
	}

	cpu_if->vgic_vmcr = read_sysreg_s(SYS_ICH_VMCR_EL2);

	switch (nr_pre_bits) {
	case 7:
		cpu_if->vgic_ap0r[3] = read_sysreg_s(SYS_ICH_AP0R3_EL2);
		cpu_if->vgic_ap0r[2] = read_sysreg_s(SYS_ICH_AP0R2_EL2);
		fallthrough;
	case 6:
		cpu_if->vgic_ap0r[1] = read_sysreg_s(SYS_ICH_AP0R1_EL2);
		fallthrough;
	default:
		cpu_if->vgic_ap0r[0] = read_sysreg_s(SYS_ICH_AP0R0_EL2);
	}

	switch (nr_pre_bits) {
	case 7:
		cpu_if->vgic_ap1r[3] = read_sysreg_s(SYS_ICH_AP1R3_EL2);
		cpu_if->vgic_ap1r[2] = read_sysreg_s(SYS_ICH_AP1R2_EL2);
		fallthrough;
	case 6:
		cpu_if->vgic_ap1r[1] = read_sysreg_s(SYS_ICH_AP1R1_EL2);
		fallthrough;
	default:
		cpu_if->vgic_ap1r[0] = read_sysreg_s(SYS_ICH_AP1R0_EL2);
	}

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

	arch_cpu_preserved_dcache_inval((unsigned long)target_cap,
					(unsigned long)target_cap + sizeof(*target_cap));

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
			(0xa0ULL << ICH_LR_PRIORITY_SHIFT);
	} else {
		target_cap->ctx.pending_sgis |= BIT(sgi & 0xf);
	}

	arch_cpu_preserved_dcache_clean((unsigned long)target_cap,
					(unsigned long)target_cap + sizeof(*target_cap));

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

	arch_cpu_preserved_dcache_inval((unsigned long)vm,
					(unsigned long)vm + sizeof(*vm));
	if (vm->max_vcpus) {
		arch_cpu_preserved_dcache_inval((unsigned long)vm,
						(unsigned long)vm +
						struct_size(vm, vcpus, vm->max_vcpus));
	}

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

static __caretaker_text __no_stack_protector int arm64_caretaker_op_enter(void *data)
{
	struct caretaker_arm64_page *cap = data;
	int cpu = arm64_caretaker_get_pcpu();
	struct arm64_caretaker_diag *d = (cpu >= 0 && cpu < NR_CPUS) ? &arm64_caretaker_diag[cpu] : NULL;
	u64 guest_hcr;

	if (d) {
		d->stage = 60;
		d->sub_stage = d->enter_count;
		d->enter_count++;
		d->last_enter_ticks = arch_caretaker_read_counter();
		d->cnthp_ctl = read_sysreg_s(SYS_CNTHP_CTL_EL2);
		d->cnthp_cval = read_sysreg_s(SYS_CNTHP_CVAL_EL2);
		d->counter_val = arch_caretaker_read_counter();
		d->deadline_val = cap->vcpu.deadline_ticks;
		arch_cpu_preserved_dcache_clean((unsigned long)d, (unsigned long)(d + 1));
	}

	gicv3_caretaker_clear_active_priorities();
	write_sysreg_s(0xff, SYS_ICC_PMR_EL1);
	write_sysreg_s(ICC_CTLR_EL1_EOImode_drop, SYS_ICC_CTLR_EL1);
	write_sysreg_s(1, SYS_ICC_IGRPEN1_EL1);
	pmr_sync();

	guest_hcr = (cap->ctx.hcr_el2 | HCR_AMO | HCR_IMO | HCR_FMO | HCR_E2H) & ~HCR_TGE;
	write_sysreg_hcr(guest_hcr);
	isb();

	cap->last_ret = caretaker_guest_enter(&cap->ctx);

	write_sysreg_hcr(HCR_HOST_VHE_FLAGS);
	isb();

	if (d) {
		d->stage = 61;
		d->sub_stage = cap->last_ret;
		d->exit_count++;
		d->last_exit_ticks = arch_caretaker_read_counter();
		d->last_ret = cap->last_ret;
		d->last_pc = cap->ctx.ctxt.regs.pc;
		d->last_esr = cap->ctx.fault.esr_el2;
		d->last_far = cap->ctx.fault.far_el2;
		d->last_hpfar = cap->ctx.fault.hpfar_el2;
		arch_cpu_preserved_dcache_clean((unsigned long)d, (unsigned long)(d + 1));
	}

	return 0;
}

static __caretaker_text __no_stack_protector void arm64_caretaker_op_arm_timer(void *data, u64 deadline_ticks)
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

static __caretaker_text __no_stack_protector void arm64_caretaker_op_disarm_timer(void *data)
{
	write_sysreg_s(0, SYS_CNTHP_CTL_EL2);
	isb();
}

static __caretaker_text __no_stack_protector void arm64_caretaker_op_decode_exit(void *data, struct kvm_caretaker_exit *exit)
{
	struct caretaker_arm64_page *cap = data;
	int cpu = arm64_caretaker_get_pcpu();
	struct arm64_caretaker_diag *d = (cpu >= 0 && cpu < NR_CPUS) ? &arm64_caretaker_diag[cpu] : NULL;
	u64 ret = cap->last_ret;

	exit->rip = cap->ctx.ctxt.regs.pc;
	exit->insn_len = 0;
	exit->type = KVM_CARETAKER_EXIT_UNKNOWN;

	if (ARM_EXCEPTION_CODE(ret) == ARM_EXCEPTION_IRQ) {
		u32 iar1 = read_sysreg_s(SYS_ICC_IAR1_EL1);

		if (iar1 < 1020) {
			write_sysreg_s(iar1, SYS_ICC_EOIR1_EL1);
			write_sysreg_s(iar1, SYS_ICC_DIR_EL1);
		}
		gicv3_caretaker_clear_active_priorities();
		dsb(sy);
		isb();

		exit->type = KVM_CARETAKER_EXIT_PREEMPT_TIMER;
		if (d) {
			d->last_exit_type = exit->type;
			arch_cpu_preserved_dcache_clean((unsigned long)d, (unsigned long)(d + 1));
		}
		return;
	}

	if (ARM_EXCEPTION_IS_TRAP(ret)) {
		u64 esr = cap->ctx.fault.esr_el2;
		u8 ec = ESR_ELx_EC(esr);

		exit->insn_len = 4;

		if (ec == ESR_ELx_EC_WFx) {
			exit->type = KVM_CARETAKER_EXIT_IDLE;
			if (d) {
				d->last_exit_type = exit->type;
				arch_cpu_preserved_dcache_clean((unsigned long)d, (unsigned long)(d + 1));
			}
			return;
		}

		if (ec == ESR_ELx_EC_SYS64) {
			u32 iss = esr & 0x01ffffff;
			u32 sys_op = iss & ESR_ELx_SYS64_ISS_SYS_OP_MASK;

			if ((sys_op == (ESR_ELx_SYS64_ISS_SYS_VAL(3, 0, 5, 12, 11) | ESR_ELx_SYS64_ISS_DIR_WRITE)) ||
			    (sys_op == (ESR_ELx_SYS64_ISS_SYS_VAL(3, 0, 6, 12, 11) | ESR_ELx_SYS64_ISS_DIR_WRITE)) ||
			    (sys_op == (ESR_ELx_SYS64_ISS_SYS_VAL(3, 0, 7, 12, 11) | ESR_ELx_SYS64_ISS_DIR_WRITE))) {
				u32 rt = ESR_ELx_SYS64_ISS_RT(esr);
				u64 val = (rt < 31) ? cap->ctx.ctxt.regs.regs[rt] : 0;

				exit->type = KVM_CARETAKER_EXIT_CROSS_VCPU;
				exit->sgi.sgi_id = FIELD_GET(ICC_SGI1R_SGI_ID_MASK, val);
				exit->sgi.target_mask = val;
				if (d) {
					d->last_exit_type = exit->type;
					arch_cpu_preserved_dcache_clean((unsigned long)d, (unsigned long)(d + 1));
				}
				return;
			}
		}

		if (ec == ESR_ELx_EC_DABT_LOW) {
			u64 hpfar = cap->ctx.fault.hpfar_el2;
			u64 fault_ipa;

			if (hpfar & HPFAR_EL2_NS)
				fault_ipa = (FIELD_GET(HPFAR_EL2_FIPA, hpfar) << 12) |
					    (cap->ctx.fault.far_el2 & 0xfff);
			else
				fault_ipa = 0;

			if ((fault_ipa & ~0xfffULL) == 0x09000000ULL &&
			    (esr & ESR_ELx_ISV)) {
				u32 rt = (esr & ESR_ELx_SRT_MASK) >> ESR_ELx_SRT_SHIFT;

				exit->type = KVM_CARETAKER_EXIT_CONSOLE;
				exit->mmio_io.addr = fault_ipa;
				exit->mmio_io.is_write = (esr & ESR_ELx_WNR) != 0;
				exit->mmio_io.size = 4;
				exit->mmio_io.is_mmio = true;
				exit->mmio_io.val_ptr = (rt < 31) ? &cap->ctx.ctxt.regs.regs[rt] : NULL;
				if (d) {
					d->last_exit_type = exit->type;
					arch_cpu_preserved_dcache_clean((unsigned long)d, (unsigned long)(d + 1));
				}
				return;
			}
		}

		exit->type = KVM_CARETAKER_EXIT_ARCH;
		exit->raw_reason = esr;
		if (d) {
			d->last_exit_type = exit->type;
			arch_cpu_preserved_dcache_clean((unsigned long)d, (unsigned long)(d + 1));
		}
		return;
	}

	exit->type = KVM_CARETAKER_EXIT_ARCH;
	if (d) {
		d->last_exit_type = exit->type;
		arch_cpu_preserved_dcache_clean((unsigned long)d, (unsigned long)(d + 1));
	}
}

static __caretaker_text __no_stack_protector void arm64_caretaker_op_advance_rip(void *data, u64 next_rip)
{
	struct caretaker_arm64_page *cap = data;

	cap->ctx.ctxt.regs.pc = next_rip;
	cap->vcpu.last_exit_rip = next_rip;
}

static __caretaker_text __no_stack_protector bool arm64_caretaker_op_handle_exit(void *data, struct kvm_caretaker_exit *exit)
{
	struct caretaker_arm64_page *cap = data;
	int cpu = arm64_caretaker_get_pcpu();
	struct arm64_caretaker_diag *d = (cpu >= 0 && cpu < NR_CPUS) ? &arm64_caretaker_diag[cpu] : NULL;
	bool handled = false;

	if (exit->type == KVM_CARETAKER_EXIT_CROSS_VCPU) {
		caretaker_arm64_handle_sgi(cap, exit->sgi.target_mask);
		exit->rip += exit->insn_len;
		handled = true;
		goto out;
	}

	if (exit->type == KVM_CARETAKER_EXIT_ARCH) {
		u64 esr = cap->ctx.fault.esr_el2;
		u8 ec = ESR_ELx_EC(esr);

		if (ec == ESR_ELx_EC_DABT_LOW) {
			u64 hpfar = cap->ctx.fault.hpfar_el2;
			u64 fault_ipa;

			if (hpfar & HPFAR_EL2_NS)
				fault_ipa = (FIELD_GET(HPFAR_EL2_FIPA, hpfar) << 12) |
					    (cap->ctx.fault.far_el2 & 0xfff);
			else
				fault_ipa = 0;

			if ((fault_ipa >= 0x08000000ULL && fault_ipa < 0x08200000ULL) &&
			    (esr & ESR_ELx_ISV) && !(esr & ESR_ELx_WNR)) {
				u32 rt = (esr & ESR_ELx_SRT_MASK) >> ESR_ELx_SRT_SHIFT;
				u64 data_val = 0;

				if (fault_ipa == 0x08000000ULL)
					data_val = 0x3;
				else if ((fault_ipa & 0x1ffff) == 0x0014)
					data_val = 0x0;

				if (rt < 31)
					cap->ctx.ctxt.regs.regs[rt] = data_val;
				exit->rip += exit->insn_len;
				handled = true;
				goto out;
			}
			handled = false;
			goto out;
		}

		if (exit->insn_len) {
			exit->rip += exit->insn_len;
			handled = true;
			goto out;
		}
	}

out:
	if (d) {
		d->last_handled = handled;
		arch_cpu_preserved_dcache_clean((unsigned long)d, (unsigned long)(d + 1));
	}
	return handled;
}

static void arm64_caretaker_sync_vcpu(struct kvm_vcpu *vcpu,
				      void *data)
{
	struct caretaker_arm64_page *cap = data;
	int t;

	if (!vcpu || !cap)
		return;

	/* Sync guest architectural context back into incoming vcpu */
	vcpu->arch.ctxt = cap->ctx.ctxt;
	vcpu->arch.fault = cap->ctx.fault;
	vcpu->arch.hcr_el2 = cap->ctx.hcr_el2;
	vcpu->arch.mdcr_el2 = cap->ctx.mdcr_el2;
	vcpu->arch.cflags = cap->ctx.cflags;

	if (cap->ctx.vgic_initialized)
		vcpu->arch.vgic_cpu.vgic_v3 = cap->ctx.vgic_v3;

	{
		struct arch_timer_context *vtimer = vcpu_vtimer(vcpu);

		timer_set_offset(vtimer, cap->ctx.cntvoff_el2);
		__vcpu_assign_sys_reg(vcpu, CNTV_CVAL_EL0, cap->ctx.cntv_cval_el0);
		__vcpu_assign_sys_reg(vcpu, CNTV_CTL_EL0, cap->ctx.cntv_ctl_el0);
	}

	write_sysreg(cap->ctx.cntvoff_el2, cntvoff_el2);
	write_sysreg_el0(cap->ctx.cntv_cval_el0, SYS_CNTV_CVAL);
	write_sysreg_el0(cap->ctx.cntv_ctl_el0, SYS_CNTV_CTL);
	isb();

	vcpu_set_flag(vcpu, VCPU_INITIALIZED);
	if (vcpu->kvm) {
		bitmap_copy(vcpu->kvm->arch.vcpu_features,
			    cap->ctx.vcpu_features,
			    KVM_VCPU_MAX_FEATURES);
		set_bit(KVM_ARCH_FLAG_VCPU_FEATURES_CONFIGURED, &vcpu->kvm->arch.flags);
	}

	for (t = 0; t < NR_KVM_TIMERS; t++)
		vcpu->arch.timer_cpu.timers[t].loaded = false;

	kvm_make_request(KVM_REQ_IRQ_PENDING, vcpu);
}

static struct kvm_caretaker_ops arm64_caretaker_ops __cpu_preserved_data = {
	.enter_guest = arm64_caretaker_op_enter,
	.decode_exit = arm64_caretaker_op_decode_exit,
	.handle_arch_exit = arm64_caretaker_op_handle_exit,
	.advance_rip = arm64_caretaker_op_advance_rip,
	.arm_timer = arm64_caretaker_op_arm_timer,
	.disarm_timer = arm64_caretaker_op_disarm_timer,
	.sync_vcpu = arm64_caretaker_sync_vcpu,
};


static __caretaker_text __no_stack_protector enum caretaker_exit_reason
caretaker_arch_run_page(struct caretaker_arm64_page *cap, u64 deadline_ticks)
{
	struct arm64_caretaker_ptrauth_keys ptrauth_keys __uninitialized;
	enum caretaker_exit_reason exit_reason = CARETAKER_EXIT_QUANTUM_EXPIRED;
	int cpu;
	phys_addr_t pgd_pa;

	if (!cap)
		return CARETAKER_EXIT_ERROR;

	arch_cpu_preserved_dcache_inval((unsigned long)&cap->cb,
					(unsigned long)&cap->cb + sizeof(cap->cb));
	cpu = cap->cb.pcpu_id;
	if (cpu < 0 || cpu >= NR_CPUS)
		cpu = arm64_caretaker_get_pcpu();

	arch_cpu_preserved_set_stage(cpu, 51, deadline_ticks);

	if (READ_ONCE(cap->cb.attachment_state) == CARETAKER_KVM_ATTACHING ||
	    cpu_preserved_should_exit(cpu)) {
		WRITE_ONCE(cap->cb.attachment_state, CARETAKER_KVM_ATTACHED);
		arch_cpu_preserved_dcache_clean((unsigned long)&cap->cb,
						(unsigned long)&cap->cb + sizeof(cap->cb));
		return CARETAKER_EXIT_ATTACH_SIGNALED;
	}

	local_daif_mask();
	arm64_caretaker_save_ptrauth(&ptrauth_keys);
	arch_cpu_preserved_set_stage(cpu, 51, 1);

	cap->cb.pcpu_id = cpu;
	cap->cb.attachment_state = CARETAKER_KVM_DETACHED;
	arch_cpu_preserved_dcache_clean((unsigned long)&cap->cb,
					(unsigned long)&cap->cb + sizeof(cap->cb));

	/* 1. Pre-job: load guest context */
	arch_cpu_preserved_dcache_inval((unsigned long)cap, (unsigned long)cap + sizeof(*cap));
	arch_cpu_preserved_set_stage(cpu, 51, 2);

	arm64_caretaker_load_sysregs(&cap->ctx.ctxt);
	arch_cpu_preserved_set_stage(cpu, 52, 0);

	if (cap->ctx.vgic_initialized)
		caretaker_vgic_v3_restore(cap);
	arch_cpu_preserved_set_stage(cpu, 53, 0);

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
	local_daif_mask();
	isb();

	fpsimd_load_state(&cap->ctx.ctxt.fp_regs);
	arch_cpu_preserved_set_stage(cpu, 54, 0);

	gicv3_caretaker_enable_sgi();
	arch_cpu_preserved_set_stage(cpu, 55, 0);
	write_sysreg_s(ICC_CTLR_EL1_EOImode_drop, SYS_ICC_CTLR_EL1);
	write_sysreg_s(ICC_SRE_EL1_SRE, SYS_ICC_SRE_EL1);
	write_sysreg_s(0, SYS_ICC_BPR1_EL1);
	gicv3_caretaker_clear_active_priorities();
	write_sysreg_s(0xff, SYS_ICC_PMR_EL1);
	write_sysreg_s(1, SYS_ICC_IGRPEN1_EL1);
	{
		u32 iar = read_sysreg_s(SYS_ICC_IAR1_EL1);

		if (iar < 1020) {
			write_sysreg_s(iar, SYS_ICC_EOIR1_EL1);
			write_sysreg_s(iar, SYS_ICC_DIR_EL1);
		}
	}
	dsb(sy);
	isb();

	/* 2. Guest execution loop */
	cap->vcpu.ops = &arm64_caretaker_ops;
	cap->vcpu.arch_data = cap;

	arch_cpu_preserved_set_stage(cpu, 56, deadline_ticks);
	exit_reason = kvm_caretaker_vcpu_run(&cap->vcpu, deadline_ticks);
	arch_cpu_preserved_set_stage(cpu, 57, (u64)exit_reason);

	/* 3. Post-run: restore host hypervisor mode then save guest context */
	write_sysreg_s(0, SYS_CNTHP_CTL_EL2);
	write_sysreg_hcr(HCR_HOST_VHE_FLAGS);
	write_sysreg((unsigned long)caretaker_hyp_vector, vbar_el1);
	write_sysreg_s((unsigned long)caretaker_hyp_vector, SYS_VBAR_EL2);
	dsb(sy);
	isb();

	fpsimd_save_state(&cap->ctx.ctxt.fp_regs);

	cap->ctx.cntv_cval_el0 = read_sysreg_el0(SYS_CNTV_CVAL);
	cap->ctx.cntv_ctl_el0 = read_sysreg_el0(SYS_CNTV_CTL);

	if (cap->ctx.vgic_initialized)
		caretaker_vgic_v3_save(&cap->ctx.vgic_v3);

	arm64_caretaker_save_sysregs(&cap->ctx.ctxt);

	{
		struct cpu_preserved_stack_context *sctx = cpu_preserved_get_stack_context();

		if (sctx && sctx->session_pgd_pa)
			pgd_pa = sctx->session_pgd_pa;
		else
			pgd_pa = cpu_preserved_get_pgd(cpu);

		if (!pgd_pa) {
			unsigned long pgd_var = (unsigned long)&arm64_caretaker_pgd_pa;

			arch_cpu_preserved_dcache_inval(pgd_var, pgd_var + sizeof(arm64_caretaker_pgd_pa));
			pgd_pa = READ_ONCE(arm64_caretaker_pgd_pa);
		}

		write_sysreg(0, ttbr0_el1);
		if (pgd_pa && read_sysreg(ttbr1_el1) != pgd_pa) {
			write_sysreg(pgd_pa, ttbr1_el1);
			isb();
			arm64_flush_host_tlb_local();
		}
	}

	arch_cpu_preserved_dcache_clean((unsigned long)cap, (unsigned long)cap + sizeof(*cap));

	if (exit_reason == CARETAKER_EXIT_ATTACH_SIGNALED) {
		local_daif_mask();
		isb();

		{
			u32 iar = read_sysreg_s(SYS_ICC_IAR1_EL1);

			if (iar < 1020) {
				write_sysreg_s(iar, SYS_ICC_EOIR1_EL1);
				write_sysreg_s(iar, SYS_ICC_DIR_EL1);
			}
		}

		gicv3_caretaker_clear_active_priorities();
		write_sysreg_s(0, SYS_ICC_IGRPEN1_EL1);
		write_sysreg_s(0, SYS_ICC_PMR_EL1);
		write_sysreg_s(0, SYS_ICC_BPR1_EL1);
		gicv3_caretaker_clear_sgi();
		dsb(sy);
		isb();

		WRITE_ONCE(cap->cb.attachment_state, CARETAKER_KVM_ATTACHED);
		arch_cpu_preserved_dcache_clean((unsigned long)&cap->cb,
						(unsigned long)&cap->cb + sizeof(cap->cb));

		arm64_caretaker_restore_ptrauth(&ptrauth_keys);
		write_sysreg_hcr(HCR_HOST_VHE_FLAGS);
		write_sysreg((unsigned long)caretaker_hyp_vector, vbar_el1);
		write_sysreg_s((unsigned long)caretaker_hyp_vector, SYS_VBAR_EL2);
		dsb(sy);
		isb();
	}

	arch_cpu_preserved_set_stage(cpu, 58, (u64)exit_reason);
	return exit_reason;
}


__caretaker_text enum caretaker_exit_reason
kvm_arch_vcpu_caretaker_run(void *data, u64 deadline_ticks)
{
	struct caretaker_arm64_page *cap = NULL;

	arch_cpu_preserved_set_stage(-1, 50, (u64)data);

	if (data) {
		struct caretaker_cb *cb = data;

		if (cb->runtime_size == sizeof(struct caretaker_arm64_page) &&
		    cb->attachment_state <= CARETAKER_KVM_ATTACHING) {
			cap = container_of(cb, struct caretaker_arm64_page, cb);
		} else {
			struct kvm_vcpu *vcpu = data;

			if (vcpu->cb.runtime_pa) {
				cb = phys_to_virt(vcpu->cb.runtime_pa);
				if (cb)
					cap = container_of(cb, struct caretaker_arm64_page, cb);
			}
		}
	}

	if (!cap)
		return CARETAKER_EXIT_ERROR;

	return caretaker_arch_run_page(cap, deadline_ticks);
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vcpu_caretaker_run);

void *kvm_arch_vcpu_caretaker_data(struct kvm_vcpu *vcpu)
{
	if (!vcpu || !vcpu->cb.runtime_pa)
		return NULL;
	return phys_to_virt(vcpu->cb.runtime_pa);
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vcpu_caretaker_data);

void kvm_arch_vcpu_luo_attach_caretaker(struct kvm_vcpu *vcpu,
					struct kvm_vcpu_luo_ser *ser)
{
	if (ser && (ser->flags & KVM_VCPU_LUO_FLAG_CARETAKER) && ser->cb.phys && vcpu) {
		struct caretaker_cb *old_cb = phys_to_virt(ser->cb.phys);
		struct caretaker_arm64_page *cap = old_cb ?
			container_of(old_cb, struct caretaker_arm64_page, cb) : NULL;

		if (cap) {
			int pcpu = old_cb->pcpu_id;

			if (pcpu >= 0) {
				kvm_caretaker_wait_for_attach(&cap->cb, pcpu, NULL);
				arch_cpu_preserved_dcache_inval((unsigned long)cap,
								(unsigned long)cap + sizeof(*cap));
			}

			arm64_caretaker_sync_vcpu(vcpu, cap);
			kvm_caretaker_post_attach_vcpu(vcpu, &cap->vcpu);
			return;
		}
	}

	kvm_caretaker_post_attach_vcpu(vcpu, NULL);
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vcpu_luo_attach_caretaker);
