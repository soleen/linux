// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026, Google LLC.
 *
 * x86 KVM LUO architectural preservation and retrieval handlers.
 */

#include <linux/kvm_host.h>
#include <linux/kexec_handover.h>
#include <linux/kho/abi/kvm.h>
#include <linux/cpu.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <asm/mem_encrypt.h>
#include <asm/virt.h>
#include <asm/kvm_host.h>
#include "cpuid.h"
#include "pmu.h"
#include "x86.h"
#include "msrs.h"
#include "lapic.h"

int kvm_arch_vm_luo_preserve(struct kvm *kvm, struct kvm_luo_ser *ser)
{
	struct kvm_vm_arch_luo_state *state;
	struct kvm_vcpu *vcpu = NULL;
	unsigned long i;
	size_t size;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (vcpu->arch.cpuid_entries && vcpu->arch.cpuid_nent > 0)
			break;
	}

	if (!vcpu || !vcpu->arch.cpuid_entries || vcpu->arch.cpuid_nent == 0)
		return 0;

	size = sizeof(*state) + vcpu->arch.cpuid_nent * sizeof(struct kvm_cpuid_entry2);
	state = kho_alloc_preserve(size);
	if (IS_ERR(state))
		return PTR_ERR(state);

	state->cpuid_nent = vcpu->arch.cpuid_nent;
	memcpy(state->cpuid_entries, vcpu->arch.cpuid_entries,
	       state->cpuid_nent * sizeof(struct kvm_cpuid_entry2));

	KHOSER_STORE_PTR(ser->arch_state, state);
	return 0;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vm_luo_preserve);

int kvm_arch_vm_luo_retrieve(struct kvm *kvm, struct kvm_luo_ser *ser)
{
	struct folio *folio;

	if (!ser->arch_state.phys)
		return 0;

	folio = kho_restore_folio(__sme_clr(ser->arch_state.phys));
	if (!folio)
		return -EINVAL;

	kvm->arch.luo_cpuid = folio_address(folio);
	ser->arch_state.phys = 0;
	return 0;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vm_luo_retrieve);

void kvm_arch_vm_luo_unpreserve(struct kvm_luo_ser *ser)
{
	if (ser->arch_state.phys) {
		kho_unpreserve_free(phys_to_virt(__sme_clr(ser->arch_state.phys)));
		ser->arch_state.phys = 0;
	}
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vm_luo_unpreserve);

void kvm_arch_vm_luo_finish(struct kvm_luo_ser *ser)
{
	if (ser->arch_state.phys) {
		kho_restore_free(phys_to_virt(__sme_clr(ser->arch_state.phys)));
		ser->arch_state.phys = 0;
	}
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vm_luo_finish);

static const u32 luo_msrs_to_save[] = {
	MSR_KERNEL_GS_BASE,
	MSR_LSTAR,
	MSR_STAR,
	MSR_CSTAR,
	MSR_SYSCALL_MASK,
	MSR_TSC_AUX,
	MSR_IA32_SYSENTER_CS,
	MSR_IA32_SYSENTER_ESP,
	MSR_IA32_SYSENTER_EIP,
	MSR_IA32_CR_PAT,
	MSR_IA32_TSC_ADJUST,
	MSR_IA32_TSC_DEADLINE,
	MSR_IA32_TSC,
	MSR_IA32_SPEC_CTRL,
	MSR_IA32_TSX_CTRL,
	MSR_IA32_UMWAIT_CONTROL,
	MSR_KVM_SYSTEM_TIME,
	MSR_KVM_WALL_CLOCK,
	MSR_KVM_SYSTEM_TIME_NEW,
	MSR_KVM_WALL_CLOCK_NEW,
	MSR_KVM_ASYNC_PF_EN,
	MSR_KVM_STEAL_TIME,
	MSR_KVM_PV_EOI_EN,
	MSR_KVM_ASYNC_PF_INT,
	MSR_KVM_ASYNC_PF_ACK,
};

int kvm_arch_vcpu_luo_preserve(struct kvm_vcpu *vcpu, struct kvm_vcpu_luo_ser *ser)
{
	struct kvm_vcpu_arch_luo_state *state;
	int i;

	BUILD_BUG_ON(sizeof(struct kvm_vcpu_arch_luo_state) != 2932);

	state = kho_alloc_preserve(sizeof(*state));
	if (IS_ERR(state))
		return PTR_ERR(state);

	kvm_arch_vcpu_ioctl_get_regs(vcpu, &state->regs);
	kvm_arch_vcpu_ioctl_get_sregs(vcpu, &state->sregs);
	kvm_arch_vcpu_ioctl_get_mpstate(vcpu, &state->mp_state);
	kvm_arch_vcpu_ioctl_get_fpu(vcpu, &state->fpu);

	vcpu_load(vcpu);
	if (lapic_in_kernel(vcpu) && kvm_apic_get_state(vcpu, &state->lapic) == 0)
		state->has_lapic = 1;
	else
		state->has_lapic = 0;

	state->num_msrs = 0;
	for (i = 0; i < ARRAY_SIZE(luo_msrs_to_save); i++) {
		u32 msr = luo_msrs_to_save[i];
		u64 val = 0;

		if (kvm_msr_read(vcpu, msr, &val) == 0) {
			if (state->num_msrs < KVM_X86_LUO_MAX_MSRS) {
				state->msrs[state->num_msrs].index = msr;
				state->msrs[state->num_msrs].reserved = 0;
				state->msrs[state->num_msrs].data = val;
				state->num_msrs++;
			}
		}
	}
	vcpu_put(vcpu);

#ifdef CONFIG_KVM_CARETAKER
	if (ser->flags & KVM_VCPU_LUO_FLAG_CARETAKER) {
		kvm_arch_vcpu_caretaker_init(vcpu, &ser->cb.phys);
		if (!ser->cb.phys) {
			kho_unpreserve_free(state);
			return -ENOMEM;
		}
	}
#endif

	KHOSER_STORE_PTR(ser->arch_state, state);
	return 0;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vcpu_luo_preserve);

int kvm_arch_vcpu_luo_retrieve(struct kvm_vcpu *vcpu, struct kvm_vcpu_luo_ser *ser)
{
	struct kvm_vcpu_arch_luo_state *state;
	int ret, i;

	if (!ser->arch_state.phys)
		return 0;

	state = KHOSER_LOAD_PTR(ser->arch_state);

	if (vcpu->kvm->arch.luo_cpuid && vcpu->kvm->arch.luo_cpuid->cpuid_nent > 0) {
		struct kvm_vm_arch_luo_state *vm_state = vcpu->kvm->arch.luo_cpuid;
		struct kvm_cpuid_entry2 *entries;

		entries = kmemdup(vm_state->cpuid_entries,
				  vm_state->cpuid_nent * sizeof(*entries),
				  GFP_KERNEL);
		if (!entries)
			return -ENOMEM;

		for (i = 0; i < vm_state->cpuid_nent; i++) {
			if (entries[i].function == 1) {
				entries[i].ebx &= 0x00ffffff;
				entries[i].ebx |= (vcpu->vcpu_id & 0xff) << 24;
			} else if (entries[i].function == 0x0b ||
				   entries[i].function == 0x1f) {
				entries[i].edx = vcpu->vcpu_id;
			}
		}

		ret = kvm_set_cpuid(vcpu, entries, vm_state->cpuid_nent);
		if (ret) {
			kvfree(entries);
			return ret;
		}
	}

	ret = kvm_arch_vcpu_ioctl_set_sregs(vcpu, &state->sregs);
	if (ret)
		return ret;

	ret = kvm_arch_vcpu_ioctl_set_mpstate(vcpu, &state->mp_state);
	if (ret)
		return ret;

	if (!(ser->flags & KVM_VCPU_LUO_FLAG_CARETAKER)) {
		ret = kvm_arch_vcpu_ioctl_set_fpu(vcpu, &state->fpu);
		if (ret)
			return ret;

		vcpu_load(vcpu);
		if (state->has_lapic && lapic_in_kernel(vcpu)) {
			ret = kvm_apic_set_state(vcpu, &state->lapic);
			if (ret) {
				vcpu_put(vcpu);
				return ret;
			}
		}

		for (i = 0; i < state->num_msrs; i++)
			kvm_msr_write(vcpu, state->msrs[i].index, state->msrs[i].data);

		vcpu_put(vcpu);

		ret = kvm_arch_vcpu_ioctl_set_regs(vcpu, &state->regs);
		if (ret)
			return ret;
	}

	return 0;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vcpu_luo_retrieve);

void kvm_arch_vcpu_luo_unpreserve(struct kvm_vcpu_luo_ser *ser)
{
#ifdef CONFIG_KVM_CARETAKER
	if (ser->cb.phys) {
		struct caretaker_cb *cb = phys_to_virt(__sme_clr(ser->cb.phys));

		if (cb && cb->runtime_pa)
			kho_unpreserve_free(phys_to_virt(__sme_clr(cb->runtime_pa)));
		ser->cb.phys = 0;
	}
#endif
	if (ser->arch_state.phys) {
		struct kvm_vcpu_arch_luo_state *state =
			phys_to_virt(__sme_clr(ser->arch_state.phys));

		kho_unpreserve_free(state);
		ser->arch_state.phys = 0;
	}
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vcpu_luo_unpreserve);

void kvm_arch_vcpu_luo_finish(struct kvm_vcpu_luo_ser *ser)
{
#ifdef CONFIG_KVM_CARETAKER
	if (ser->cb.phys) {
		struct caretaker_cb *cb = phys_to_virt(__sme_clr(ser->cb.phys));

		if (cb && cb->runtime_pa)
			kho_restore_free(phys_to_virt(__sme_clr(cb->runtime_pa)));
		ser->cb.phys = 0;
	}
#endif
	if (ser->arch_state.phys) {
		struct kvm_vcpu_arch_luo_state *state =
			phys_to_virt(__sme_clr(ser->arch_state.phys));

		kho_restore_free(state);
		ser->arch_state.phys = 0;
	}
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vcpu_luo_finish);

void kvm_arch_vm_luo_destroy(struct kvm *kvm)
{
	if (kvm->arch.luo_cpuid) {
		folio_put(virt_to_folio(kvm->arch.luo_cpuid));
		kvm->arch.luo_cpuid = NULL;
	}
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vm_luo_destroy);
