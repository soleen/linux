// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * ARM64 KVM LUO preservation and retrieval handlers.
 */

#include <linux/kexec_handover.h>
#include <linux/kho/abi/kvm.h>
#include <linux/kho/abi/kvm_arm64.h>
#include <linux/kvm_host.h>
#include <linux/slab.h>

#include <asm/kvm_emulate.h>
#include <asm/kvm_mmu.h>
#include <kvm/arm_vgic.h>

#include "sys_regs.h"
#include "vgic/vgic.h"

int kvm_arch_vm_luo_preserve(struct kvm *kvm, struct kvm_luo_ser *ser)
{
	ser->type = kvm_phys_shift(&kvm->arch.mmu);
	if (kvm_vm_is_protected(kvm))
		ser->type |= KVM_VM_TYPE_ARM_PROTECTED;

	return 0;
}

int kvm_arch_vcpu_luo_preserve(struct kvm_vcpu *vcpu, struct kvm_vcpu_ser *ser)
{
	struct kvm_arm64_sysregs_ser *sysregs;
	struct kvm_vcpu_arch_ser *state;
	u64 *indices;
	int num_sysregs;
	size_t size;
	int i;

	if (vcpu_has_nv(vcpu))
		return -EOPNOTSUPP;

	num_sysregs = kvm_arm_get_sys_reg_indices(vcpu, NULL);
	if (num_sysregs < 0)
		return num_sysregs;

	indices = kmalloc_array(num_sysregs, sizeof(*indices), GFP_KERNEL);
	if (!indices)
		return -ENOMEM;

	num_sysregs = kvm_arm_get_sys_reg_indices(vcpu, indices);
	if (num_sysregs < 0) {
		kfree(indices);
		return num_sysregs;
	}

	size = sizeof(*state) + struct_size(sysregs, sysregs, num_sysregs);
	state = kho_alloc_preserve(size);
	if (IS_ERR(state)) {
		kfree(indices);
		return PTR_ERR(state);
	}

	/* Core general-purpose and FP registers (uAPI struct kvm_regs) */
	kvm_arm_luo_get_regs(vcpu, &state->regs);

	/* Multiprocessor state (uAPI struct kvm_mp_state) */
	kvm_arch_vcpu_ioctl_get_mpstate(vcpu, &state->mp_state);
	state->pad = 0;

	/* Exception / SError injection events (uAPI struct kvm_vcpu_events) */
	__kvm_arm_vcpu_get_events(vcpu, &state->events);

	/* CPU target and feature configuration (uAPI struct kvm_vcpu_init) */
	state->init.target = KVM_ARM_TARGET_GENERIC_V8;
	bitmap_to_arr32(state->init.features, vcpu->kvm->arch.vcpu_features,
			KVM_VCPU_MAX_FEATURES);

	/* System registers (uAPI struct kvm_one_reg array) */
	sysregs = (void *)(state + 1);
	sysregs->num_sysregs = 0;
	sysregs->reserved = 0;
	for (i = 0; i < num_sysregs; i++) {
		u64 val;

		if (kvm_arm_sys_reg_read(vcpu, indices[i], &val) == 0) {
			sysregs->sysregs[sysregs->num_sysregs].id = indices[i];
			sysregs->sysregs[sysregs->num_sysregs].addr = val;
			sysregs->num_sysregs++;
		}
	}
	kfree(indices);
	KHOSER_STORE_PTR(state->sysregs, sysregs);

	KHOSER_STORE_PTR(ser->arch_state, state);

	return 0;
}

int kvm_arch_vcpu_luo_retrieve(struct kvm_vcpu *vcpu, struct kvm_vcpu_ser *ser)
{
	struct kvm_arm64_sysregs_ser *sysregs;
	struct kvm_vcpu_arch_ser *state;
	int max_sysregs;
	int i;

	if (!ser->arch_state.phys)
		return 0;

	state = KHOSER_LOAD_PTR(ser->arch_state);
	sysregs = KHOSER_LOAD_PTR(state->sysregs);
	if (!sysregs || sysregs != (struct kvm_arm64_sysregs_ser *)(state + 1) ||
	    sysregs->reserved)
		return -EINVAL;

	/* Restore vCPU features */
	bitmap_from_arr32(vcpu->kvm->arch.vcpu_features, state->init.features,
			  KVM_VCPU_MAX_FEATURES);
	set_bit(KVM_ARCH_FLAG_VCPU_FEATURES_CONFIGURED, &vcpu->kvm->arch.flags);
	kvm_reset_vcpu(vcpu);
	vcpu_set_flag(vcpu, VCPU_INITIALIZED);

	vcpu_reset_hcr(vcpu);

	/* Restore core registers */
	kvm_arm_luo_set_regs(vcpu, &state->regs);

	if (irqchip_in_kernel(vcpu->kvm) &&
	    vcpu->kvm->arch.vgic.vgic_model == KVM_DEV_TYPE_ARM_VGIC_V3) {
		vgic_v3_reset(vcpu);
	}

	max_sysregs = kvm_arm_get_sys_reg_indices(vcpu, NULL);
	if (max_sysregs < 0 || sysregs->num_sysregs > (u32)max_sysregs)
		return -EINVAL;

	/* Restore system registers */
	for (i = 0; i < sysregs->num_sysregs; i++)
		kvm_arm_sys_reg_write(vcpu, sysregs->sysregs[i].id,
				      sysregs->sysregs[i].addr);

	/* Restore multiprocessor execution state */
	kvm_arch_vcpu_ioctl_set_mpstate(vcpu, &state->mp_state);

	/* Restore exception / SError injection events */
	__kvm_arm_vcpu_set_events(vcpu, &state->events);

	if (irqchip_in_kernel(vcpu->kvm)) {
		struct vgic_irq *irq;
		unsigned long flags;

		vcpu->kvm->arch.vgic.enabled = true;

		irq = vgic_get_vcpu_irq(vcpu, timer_irq(vcpu_vtimer(vcpu)));
		if (irq) {
			raw_spin_lock_irqsave(&irq->irq_lock, flags);
			irq->enabled = true;
			raw_spin_unlock_irqrestore(&irq->irq_lock, flags);
			vgic_put_irq(vcpu->kvm, irq);
		}
		irq = vgic_get_vcpu_irq(vcpu, timer_irq(vcpu_ptimer(vcpu)));
		if (irq) {
			raw_spin_lock_irqsave(&irq->irq_lock, flags);
			irq->enabled = true;
			raw_spin_unlock_irqrestore(&irq->irq_lock, flags);
			vgic_put_irq(vcpu->kvm, irq);
		}
	}

	return 0;
}

void kvm_arch_vcpu_luo_unpreserve(struct kvm_vcpu_ser *ser)
{
	if (ser->arch_state.phys) {
		kho_unpreserve_free(phys_to_virt(ser->arch_state.phys));
		ser->arch_state.phys = 0;
	}
}

void kvm_arch_vcpu_luo_finish(struct kvm_vcpu_ser *ser)
{
	if (ser->arch_state.phys) {
		kho_restore_free(phys_to_virt(ser->arch_state.phys));
		ser->arch_state.phys = 0;
	}
}
