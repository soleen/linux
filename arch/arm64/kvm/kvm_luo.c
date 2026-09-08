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
#include <asm/kvm_emulate.h>
#include "caretaker.h"
#include "sys_regs.h"

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

static void kvm_arm_luo_get_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	regs->regs = vcpu->arch.ctxt.regs;
	regs->sp_el1 = ctxt_sys_reg(&vcpu->arch.ctxt, SP_EL1);
	regs->elr_el1 = ctxt_sys_reg(&vcpu->arch.ctxt, ELR_EL1);
	regs->spsr[KVM_SPSR_EL1] = ctxt_sys_reg(&vcpu->arch.ctxt, SPSR_EL1);
	regs->spsr[KVM_SPSR_ABT] = vcpu->arch.ctxt.spsr_abt;
	regs->spsr[KVM_SPSR_UND] = vcpu->arch.ctxt.spsr_und;
	regs->spsr[KVM_SPSR_IRQ] = vcpu->arch.ctxt.spsr_irq;
	regs->spsr[KVM_SPSR_FIQ] = vcpu->arch.ctxt.spsr_fiq;
	regs->fp_regs = vcpu->arch.ctxt.fp_regs;
}

static void kvm_arm_luo_set_regs(struct kvm_vcpu *vcpu, const struct kvm_regs *regs)
{
	vcpu->arch.ctxt.regs = regs->regs;
	ctxt_sys_reg(&vcpu->arch.ctxt, SP_EL1) = regs->sp_el1;
	ctxt_sys_reg(&vcpu->arch.ctxt, ELR_EL1) = regs->elr_el1;
	ctxt_sys_reg(&vcpu->arch.ctxt, SPSR_EL1) = regs->spsr[KVM_SPSR_EL1];
	vcpu->arch.ctxt.spsr_abt = regs->spsr[KVM_SPSR_ABT];
	vcpu->arch.ctxt.spsr_und = regs->spsr[KVM_SPSR_UND];
	vcpu->arch.ctxt.spsr_irq = regs->spsr[KVM_SPSR_IRQ];
	vcpu->arch.ctxt.spsr_fiq = regs->spsr[KVM_SPSR_FIQ];
	vcpu->arch.ctxt.fp_regs = regs->fp_regs;
}

int kvm_arch_vcpu_luo_preserve(struct kvm_vcpu *vcpu, struct kvm_vcpu_luo_ser *ser)
{
	struct kvm_vcpu_arch_luo_state *state;
	int num_sysregs;
	size_t size;

#ifdef CONFIG_KVM_CARETAKER
	if (ser->flags & KVM_VCPU_LUO_FLAG_CARETAKER)
		return arm64_kvm_caretaker_preserve(vcpu, ser);
#endif

	u64 *indices;
	int i;

	BUILD_BUG_ON(sizeof(struct kvm_vcpu_arch_luo_state) != 968);

	num_sysregs = kvm_arm_get_sys_reg_indices(vcpu, NULL);
	indices = kmalloc_array(num_sysregs, sizeof(u64), GFP_KERNEL);
	if (!indices)
		return -ENOMEM;
	num_sysregs = kvm_arm_get_sys_reg_indices(vcpu, indices);

	size = sizeof(*state) + num_sysregs * sizeof(struct kvm_one_reg);
	state = kho_alloc_preserve(size);
	if (IS_ERR(state)) {
		kfree(indices);
		return PTR_ERR(state);
	}

	vcpu_load(vcpu);

	/* Core register state (uAPI struct kvm_regs) */
	kvm_arm_luo_get_regs(vcpu, &state->regs);

	/* Multiprocessor execution state (uAPI struct kvm_mp_state) */
	kvm_arch_vcpu_ioctl_get_mpstate(vcpu, &state->mp_state);

	/* Exception / SError injection events (uAPI struct kvm_vcpu_events) */
	__kvm_arm_vcpu_get_events(vcpu, &state->events);

	/* CPU target and feature configuration (uAPI struct kvm_vcpu_init) */
	state->init.target = KVM_ARM_TARGET_GENERIC_V8;
	if (vcpu->kvm)
		bitmap_to_arr32(state->init.features, vcpu->kvm->arch.vcpu_features,
				KVM_VCPU_MAX_FEATURES);

	/* System registers (uAPI struct kvm_one_reg array) */
	state->num_sysregs = 0;
	for (i = 0; i < num_sysregs; i++) {
		u64 val;
		if (kvm_arm_sys_reg_read(vcpu, indices[i], &val) == 0) {
			state->sysregs[state->num_sysregs].id = indices[i];
			state->sysregs[state->num_sysregs].addr = val;
			state->num_sysregs++;
		}
	}
	kfree(indices);

	vcpu_put(vcpu);

	KHOSER_STORE_PTR(ser->arch_state, state);
	return 0;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vcpu_luo_preserve);

int kvm_arch_vcpu_luo_retrieve(struct kvm_vcpu *vcpu, struct kvm_vcpu_luo_ser *ser)
{
	struct kvm_vcpu_arch_luo_state *state;
	int i;

#ifdef CONFIG_KVM_CARETAKER
	if (ser->flags & KVM_VCPU_LUO_FLAG_CARETAKER)
		return 0;
#endif

	if (!ser || !ser->arch_state.phys || !vcpu)
		return 0;

	state = KHOSER_LOAD_PTR(ser->arch_state);

	vcpu_load(vcpu);

	/* Restore vCPU features */
	if (vcpu->kvm) {
		bitmap_from_arr32(vcpu->kvm->arch.vcpu_features, state->init.features,
				  KVM_VCPU_MAX_FEATURES);
		set_bit(KVM_ARCH_FLAG_VCPU_FEATURES_CONFIGURED, &vcpu->kvm->arch.flags);
	}
	vcpu_set_flag(vcpu, VCPU_INITIALIZED);
	vcpu_reset_hcr(vcpu);

	/* Restore core registers */
	kvm_arm_luo_set_regs(vcpu, &state->regs);

	/* Restore system registers */
	for (i = 0; i < state->num_sysregs; i++)
		kvm_arm_sys_reg_write(vcpu, state->sysregs[i].id, state->sysregs[i].addr);

	/* Restore multiprocessor execution state */
	kvm_arch_vcpu_ioctl_set_mpstate(vcpu, &state->mp_state);

	/* Restore exception / SError injection events */
	__kvm_arm_vcpu_set_events(vcpu, &state->events);

	vcpu_put(vcpu);

	return 0;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vcpu_luo_retrieve);

void kvm_arch_vcpu_luo_unpreserve(struct kvm_vcpu_luo_ser *ser)
{
#ifdef CONFIG_KVM_CARETAKER
	if (ser && ser->cb.phys) {
		struct caretaker_cb *cb = phys_to_virt(ser->cb.phys);

		if (cb && cb->runtime_pa)
			kho_unpreserve_free(phys_to_virt(cb->runtime_pa));
		ser->cb.phys = 0;
	}
#endif
	if (ser && ser->arch_state.phys) {
		kho_unpreserve_free(phys_to_virt(ser->arch_state.phys));
		ser->arch_state.phys = 0;
	}
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vcpu_luo_unpreserve);

void kvm_arch_vcpu_luo_finish(struct kvm_vcpu_luo_ser *ser)
{
#ifdef CONFIG_KVM_CARETAKER
	if (ser && ser->cb.phys) {
		struct caretaker_cb *cb = phys_to_virt(ser->cb.phys);

		if (cb && cb->runtime_pa)
			kho_restore_free(phys_to_virt(cb->runtime_pa));
		ser->cb.phys = 0;
	}
#endif
	if (ser && ser->arch_state.phys) {
		kho_restore_free(phys_to_virt(ser->arch_state.phys));
		ser->arch_state.phys = 0;
	}
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vcpu_luo_finish);
