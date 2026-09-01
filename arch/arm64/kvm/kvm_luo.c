// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026, Google LLC.
 *
 * ARM64 KVM LUO preservation and retrieval handlers.
 */

#include <linux/kvm_host.h>
#include <linux/kexec_handover.h>
#include <linux/kho/abi/kvm.h>
#include <linux/sched.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pgtable.h>

#define KVM_ARM64_LUO_STATE_ORDER	get_order(sizeof(struct kvm_vcpu_arch_luo_state))

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

int kvm_arch_vm_luo_preserve(struct kvm *kvm, struct kvm_luo_ser *ser)
{
	ser->arch_state.phys = 0;
	return 0;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vm_luo_preserve);

int kvm_arch_vm_luo_retrieve(struct kvm *kvm, struct kvm_luo_ser *ser)
{
	return 0;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vm_luo_retrieve);

void kvm_arch_vm_luo_unpreserve(struct kvm_luo_ser *ser)
{
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vm_luo_unpreserve);

void kvm_arch_vm_luo_finish(struct kvm_luo_ser *ser)
{
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vm_luo_finish);

int kvm_arch_vcpu_luo_preserve(struct kvm_vcpu *vcpu, struct kvm_vcpu_luo_ser *ser)
{
	struct kvm_s2_mmu *mmu = vcpu->arch.hw_mmu ? vcpu->arch.hw_mmu : &vcpu->kvm->arch.mmu;
	struct kvm_vcpu_arch_luo_state *state;
	struct page *page;
	int num_sysregs;

	BUILD_BUG_ON(sizeof(struct kvm_vcpu_arch_luo_state) != 5180);

	page = alloc_pages(GFP_KERNEL | __GFP_ZERO, KVM_ARM64_LUO_STATE_ORDER);
	if (!page)
		return -ENOMEM;

	state = page_address(page);

	/* Core register state (uAPI struct kvm_regs) */
	state->regs.regs = vcpu->arch.ctxt.regs;
	state->regs.sp_el1 = vcpu->arch.ctxt.regs.sp;
	state->regs.fp_regs = vcpu->arch.ctxt.fp_regs;
	state->regs.spsr[0] = vcpu->arch.ctxt.spsr_abt;
	state->regs.spsr[1] = vcpu->arch.ctxt.spsr_und;
	state->regs.spsr[2] = vcpu->arch.ctxt.spsr_irq;
	state->regs.spsr[3] = vcpu->arch.ctxt.spsr_fiq;

	/* Architectural system registers */
	num_sysregs = min_t(int, NR_SYS_REGS, KVM_ARM64_LUO_MAX_SYSREGS);
	state->num_sysregs = num_sysregs;
	memcpy(state->sys_regs, vcpu->arch.ctxt.sys_regs, num_sysregs * sizeof(u64));

	/* EL2 controls */
	state->hcr_el2 = vcpu->arch.hcr_el2;
	state->mdcr_el2 = vcpu->arch.mdcr_el2;
	state->cflags = vcpu->arch.cflags;

	/* Stage-2 MMU & features */
	if (mmu)
		state->s2_pgd_phys = mmu->pgd_phys;
	if (vcpu->kvm)
		state->vcpu_features = vcpu->kvm->arch.vcpu_features[0];

	/* VGICv3 state */
	state->vgic_v3.vgic_hcr = vcpu->arch.vgic_cpu.vgic_v3.vgic_hcr;
	state->vgic_v3.vgic_vmcr = vcpu->arch.vgic_cpu.vgic_v3.vgic_vmcr;
	state->vgic_v3.vgic_sre = vcpu->arch.vgic_cpu.vgic_v3.vgic_sre;
	memcpy(state->vgic_v3.vgic_ap0r, vcpu->arch.vgic_cpu.vgic_v3.vgic_ap0r, sizeof(state->vgic_v3.vgic_ap0r));
	memcpy(state->vgic_v3.vgic_ap1r, vcpu->arch.vgic_cpu.vgic_v3.vgic_ap1r, sizeof(state->vgic_v3.vgic_ap1r));
	memcpy(state->vgic_v3.vgic_lr, vcpu->arch.vgic_cpu.vgic_v3.vgic_lr, sizeof(state->vgic_v3.vgic_lr));
	state->vgic_v3.used_lrs = vcpu->arch.vgic_cpu.vgic_v3.used_lrs;

	/* Stage-2 page table walk preservation */
	if (mmu && mmu->pgd_phys)
		kho_preserve_pages(phys_to_page(mmu->pgd_phys), 1);

	if (mmu && mmu->pgt) {
		struct kvm_pgtable_walker walker = {
			.cb = preserve_stage2_visitor,
			.flags = KVM_PGTABLE_WALK_TABLE_PRE,
		};
		kvm_pgtable_walk(mmu->pgt, 0, BIT(mmu->pgt->ia_bits), &walker);
	}

	kho_preserve_pages(page, 1 << KVM_ARM64_LUO_STATE_ORDER);
	KHOSER_STORE_PTR(ser->arch_state, state);
	return 0;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vcpu_luo_preserve);

int kvm_arch_vcpu_luo_retrieve(struct kvm_vcpu *vcpu, struct kvm_vcpu_luo_ser *ser)
{
	struct kvm_vcpu_arch_luo_state *state;
	int num_sysregs;

	if (!ser || !ser->arch_state.phys || !vcpu)
		return 0;

	state = KHOSER_LOAD_PTR(ser->arch_state);

	/* Restore core registers */
	vcpu->arch.ctxt.regs = state->regs.regs;
	vcpu->arch.ctxt.fp_regs = state->regs.fp_regs;
	vcpu->arch.ctxt.spsr_abt = state->regs.spsr[0];
	vcpu->arch.ctxt.spsr_und = state->regs.spsr[1];
	vcpu->arch.ctxt.spsr_irq = state->regs.spsr[2];
	vcpu->arch.ctxt.spsr_fiq = state->regs.spsr[3];

	/* Restore system registers */
	num_sysregs = min_t(int, NR_SYS_REGS, state->num_sysregs);
	memcpy(vcpu->arch.ctxt.sys_regs, state->sys_regs, num_sysregs * sizeof(u64));

	/* Restore EL2 controls */
	vcpu->arch.hcr_el2 = state->hcr_el2;
	vcpu->arch.mdcr_el2 = state->mdcr_el2;
	vcpu->arch.cflags = state->cflags;

	/* Restore VGICv3 */
	vcpu->arch.vgic_cpu.vgic_v3.vgic_hcr = state->vgic_v3.vgic_hcr;
	vcpu->arch.vgic_cpu.vgic_v3.vgic_vmcr = state->vgic_v3.vgic_vmcr;
	vcpu->arch.vgic_cpu.vgic_v3.vgic_sre = state->vgic_v3.vgic_sre;
	memcpy(vcpu->arch.vgic_cpu.vgic_v3.vgic_ap0r, state->vgic_v3.vgic_ap0r, sizeof(state->vgic_v3.vgic_ap0r));
	memcpy(vcpu->arch.vgic_cpu.vgic_v3.vgic_ap1r, state->vgic_v3.vgic_ap1r, sizeof(state->vgic_v3.vgic_ap1r));
	memcpy(vcpu->arch.vgic_cpu.vgic_v3.vgic_lr, state->vgic_v3.vgic_lr, sizeof(state->vgic_v3.vgic_lr));
	vcpu->arch.vgic_cpu.vgic_v3.used_lrs = state->vgic_v3.used_lrs;

	vcpu_set_flag(vcpu, VCPU_INITIALIZED);
	if (vcpu->kvm) {
		vcpu->kvm->arch.vcpu_features[0] = state->vcpu_features;
		set_bit(KVM_ARCH_FLAG_VCPU_FEATURES_CONFIGURED, &vcpu->kvm->arch.flags);
	}

	return 0;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vcpu_luo_retrieve);

void kvm_arch_vcpu_luo_unpreserve(struct kvm_vcpu_luo_ser *ser)
{
	if (ser && ser->arch_state.phys) {
		kho_unpreserve_pages(pfn_to_page(ser->arch_state.phys >> PAGE_SHIFT),
				     1 << KVM_ARM64_LUO_STATE_ORDER);
		__free_pages(pfn_to_page(ser->arch_state.phys >> PAGE_SHIFT),
			     KVM_ARM64_LUO_STATE_ORDER);
		ser->arch_state.phys = 0;
	}
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vcpu_luo_unpreserve);

void kvm_arch_vcpu_luo_finish(struct kvm_vcpu_luo_ser *ser)
{
	if (ser && ser->arch_state.phys) {
		kho_restore_pages(ser->arch_state.phys, 1 << KVM_ARM64_LUO_STATE_ORDER);
		__free_pages(pfn_to_page(ser->arch_state.phys >> PAGE_SHIFT),
			     KVM_ARM64_LUO_STATE_ORDER);
		ser->arch_state.phys = 0;
	}
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vcpu_luo_finish);
