// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026, Google LLC.
 *
 * x86 KVM LUO architectural preservation and retrieval handlers.
 */

#include <linux/cpu.h>
#include <linux/kexec_handover.h>
#include <linux/kho/abi/kvm.h>
#include <linux/kvm_host.h>
#include <linux/mm.h>
#include <linux/slab.h>

#include <asm/fpu/api.h>
#include <asm/fpu/xcr.h>
#include <asm/kvm_host.h>
#include <asm/mem_encrypt.h>
#include <asm/virt.h>

#include "cpuid.h"
#include "fpu.h"
#include "lapic.h"
#include "msrs.h"
#include "pmu.h"
#include "regs.h"
#include "x86.h"

int kvm_arch_vm_luo_preserve(struct kvm *kvm, struct kvm_luo_ser *ser)
{
	struct kvm_vm_arch_luo_state *state;
	struct kvm_vcpu *vcpu = NULL;
	unsigned long i;
	u32 nent = 0;
	size_t size;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (vcpu->arch.cpuid_entries && vcpu->arch.cpuid_nent > 0) {
			nent = vcpu->arch.cpuid_nent;
			break;
		}
	}

	size = sizeof(*state) + nent * sizeof(struct kvm_cpuid_entry2);
	state = kho_alloc_preserve(size);
	if (IS_ERR(state))
		return PTR_ERR(state);

	state->cpuid_nent = nent;
	if (nent && vcpu) {
		memcpy(state->cpuid_entries, vcpu->arch.cpuid_entries,
		       nent * sizeof(struct kvm_cpuid_entry2));
	}

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

int kvm_arch_vcpu_luo_preserve(struct kvm_vcpu *vcpu, struct kvm_vcpu_luo_ser *ser)
{
	struct kvm_vcpu_arch_luo_state *state;
	bool fpu_loaded = false;
	unsigned int max_msrs;
	size_t size;
	int i;

	max_msrs = kvm_num_msrs_to_save();
	size = sizeof(*state) + max_msrs * sizeof(struct kvm_msr_entry);
	state = kho_alloc_preserve(size);
	if (IS_ERR(state))
		return PTR_ERR(state);

	memset(&state->nested, 0, sizeof(state->nested));
	state->nested.size = sizeof(state->nested);
	if (kvm_nested_ops.enabled) {
		if (boot_cpu_has(X86_FEATURE_VMX)) {
			state->nested.format = KVM_STATE_NESTED_FORMAT_VMX;
			state->nested.hdr.vmx.vmxon_pa = INVALID_GPA;
			state->nested.hdr.vmx.vmcs12_pa = INVALID_GPA;
		} else if (boot_cpu_has(X86_FEATURE_SVM)) {
			state->nested.format = KVM_STATE_NESTED_FORMAT_SVM;
		}
	}

	vcpu_load(vcpu);

	__get_regs(vcpu, &state->regs);
	__get_sregs(vcpu, &state->sregs);
	__get_mpstate(vcpu, &state->mp_state);
	__get_fpu(vcpu, &state->fpu);
	state->xcrs.nr_xcrs = 1;
	state->xcrs.flags = 0;
	state->xcrs.xcrs[0].xcr = XCR_XFEATURE_ENABLED_MASK;
	state->xcrs.xcrs[0].value = vcpu->arch.xcr0;

	if (boot_cpu_has(X86_FEATURE_XSAVE) &&
	    !fpstate_is_confidential(&vcpu->arch.guest_fpu)) {
		u64 supported_xcr0 = vcpu->arch.guest_supported_xcr0 |
				     XFEATURE_MASK_FPSSE;

		fpu_copy_guest_fpstate_to_uabi(&vcpu->arch.guest_fpu,
					       state->xsave.region,
					       sizeof(state->xsave.region),
					       supported_xcr0,
					       vcpu->arch.pkru);
	}

	kvm_vcpu_ioctl_x86_get_debugregs(vcpu, &state->debugregs);
	kvm_vcpu_ioctl_x86_get_vcpu_events(vcpu, &state->events);

	if (lapic_in_kernel(vcpu))
		kvm_apic_get_state(vcpu, &state->lapic);

	if (!vcpu->arch.guest_fpu.fpstate->in_use) {
		kvm_load_guest_fpu(vcpu);
		fpu_loaded = true;
	}

	state->num_msrs = 0;
	for (i = 0; i < max_msrs; i++) {
		u32 msr = kvm_get_msr_to_save_index(i);
		u64 val = 0;

		if (kvm_msr_read(vcpu, msr, &val) == 0) {
			state->msrs[state->num_msrs].index = msr;
			state->msrs[state->num_msrs].reserved = 0;
			state->msrs[state->num_msrs].data = val;
			state->num_msrs++;
		}
	}

	if (fpu_loaded)
		kvm_put_guest_fpu(vcpu);

	vcpu_put(vcpu);

	KHOSER_STORE_PTR(ser->arch_state, state);
	return 0;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vcpu_luo_preserve);

int kvm_arch_vcpu_luo_retrieve(struct kvm_vcpu *vcpu, struct kvm_vcpu_luo_ser *ser)
{
	struct kvm_vcpu_arch_luo_state *state;
	bool fpu_loaded = false;
	int ret, i;

	if (!ser->arch_state.phys)
		return 0;

	state = KHOSER_LOAD_PTR(ser->arch_state);

	vcpu_load(vcpu);

	if (vcpu->kvm->arch.luo_cpuid && vcpu->kvm->arch.luo_cpuid->cpuid_nent > 0) {
		struct kvm_vm_arch_luo_state *vm_state = vcpu->kvm->arch.luo_cpuid;
		struct kvm_cpuid_entry2 *entries;

		entries = kmemdup(vm_state->cpuid_entries,
				  vm_state->cpuid_nent * sizeof(*entries),
				  GFP_KERNEL);
		if (!entries) {
			ret = -ENOMEM;
			goto out;
		}

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
			goto out;
		}
	}

	ret = __set_sregs(vcpu, &state->sregs);
	if (ret)
		goto out;

	if (state->xcrs.nr_xcrs > 0 && boot_cpu_has(X86_FEATURE_XSAVE)) {
		__kvm_set_xcr(vcpu, state->xcrs.xcrs[0].xcr,
			      state->xcrs.xcrs[0].value);
	}

	for (i = 0; i < state->num_msrs; i++) {
		if (state->msrs[i].index == MSR_IA32_XFD ||
		    state->msrs[i].index == MSR_IA32_XFD_ERR ||
		    state->msrs[i].index == MSR_IA32_XSS) {
			kvm_msr_write(vcpu, state->msrs[i].index, state->msrs[i].data);
		}
	}

	ret = __set_mpstate(vcpu, &state->mp_state);
	if (ret)
		goto out;

	if (boot_cpu_has(X86_FEATURE_XSAVE) &&
	    !fpstate_is_confidential(&vcpu->arch.guest_fpu)) {
		union fpregs_state *xstate = (union fpregs_state *)state->xsave.region;

		xstate->xsave.header.xfeatures &= ~vcpu->arch.guest_fpu.fpstate->xfd;
		ret = fpu_copy_uabi_to_guest_fpstate(&vcpu->arch.guest_fpu,
						      state->xsave.region,
						      kvm_caps.supported_xcr0,
						      &vcpu->arch.pkru);
		if (ret) {
			pr_warn("kvm_luo: failed to restore xsave: %d\n", ret);
			ret = __set_fpu(vcpu, &state->fpu);
			if (ret)
				goto out;
		}
	} else {
		ret = __set_fpu(vcpu, &state->fpu);
		if (ret)
			goto out;
	}

	ret = kvm_vcpu_ioctl_x86_set_debugregs(vcpu, &state->debugregs);
	if (ret)
		goto out;

	if (state->nested.size >= sizeof(state->nested) && kvm_nested_ops.enabled)
		kvm_leave_nested(vcpu);

	ret = kvm_vcpu_ioctl_x86_set_vcpu_events(vcpu, &state->events);
	if (ret)
		goto out;

	if (lapic_in_kernel(vcpu)) {
		ret = kvm_apic_set_state(vcpu, &state->lapic);
		if (ret)
			goto out;
	}

	if (!vcpu->arch.guest_fpu.fpstate->in_use) {
		kvm_load_guest_fpu(vcpu);
		fpu_loaded = true;
	}

	for (i = 0; i < state->num_msrs; i++)
		kvm_msr_write(vcpu, state->msrs[i].index, state->msrs[i].data);

	__set_regs(vcpu, &state->regs);

	ret = 0;
out:
	if (fpu_loaded)
		kvm_put_guest_fpu(vcpu);
	vcpu_put(vcpu);
	return ret;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vcpu_luo_retrieve);

void kvm_arch_vcpu_luo_unpreserve(struct kvm_vcpu_luo_ser *ser)
{
	if (ser && ser->arch_state.phys) {
		struct kvm_vcpu_arch_luo_state *state =
			phys_to_virt(__sme_clr(ser->arch_state.phys));

		kho_unpreserve_free(state);
		ser->arch_state.phys = 0;
	}
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vcpu_luo_unpreserve);

void kvm_arch_vcpu_luo_finish(struct kvm_vcpu_luo_ser *ser)
{
	if (ser && ser->arch_state.phys) {
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
