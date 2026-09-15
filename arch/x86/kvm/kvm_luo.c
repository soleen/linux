// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * x86 KVM LUO architectural preservation and retrieval handlers.
 */

#include <linux/cpu.h>
#include <linux/kexec_handover.h>
#include <linux/kho/abi/kvm_x86.h>
#include <linux/kvm_host.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <asm/fpu/api.h>
#include <asm/fpu/xcr.h>
#include <linux/kvm_host.h>
#include <linux/mem_encrypt.h>
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
	ser->type = kvm->arch.vm_type;
	return 0;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vm_luo_preserve);

int kvm_arch_vm_luo_retrieve(struct kvm *kvm, struct kvm_luo_ser *ser)
{
	return 0;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vm_luo_retrieve);

void kvm_arch_vm_luo_unpreserve(struct kvm *kvm, struct kvm_luo_ser *ser)
{
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vm_luo_unpreserve);

void kvm_arch_vm_luo_finish(struct kvm_luo_ser *ser)
{
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vm_luo_finish);

int kvm_arch_vcpu_luo_preserve(struct kvm_vcpu *vcpu, struct kvm_vcpu_ser *ser)
{
	struct kvm_vcpu_arch_ser *state;
	bool fpu_loaded = false;
	unsigned int max_msrs;
	u32 nent;
	size_t size;
	int i;

	/*
	 * The guest FPU state travels in @xsave, which can only be filled in if
	 * the host has XSAVE.  There is no second copy to fall back on, so fail
	 * the preserve rather than silently dropping the guest's FPU registers.
	 * A confidential guest keeps its FPU state in the VMSA, where KVM can
	 * neither read nor restore it, so it needs nothing from us.
	 */
	if (!boot_cpu_has(X86_FEATURE_XSAVE) &&
	    !fpstate_is_confidential(&vcpu->arch.guest_fpu))
		return -EOPNOTSUPP;

	/*
	 * Nested virtualisation state does not survive the handover.
	 * arm64 already refuses vcpu_has_nv() outright; do the same here.
	 */
	if (is_guest_mode(vcpu))
		return -EOPNOTSUPP;

	if (kvm_nested_ops.enabled && kvm_nested_ops.get_state) {
		int nested_size = kvm_nested_ops.get_state(vcpu, NULL, 0);

		if (nested_size < 0)
			return nested_size;
		if (nested_size > sizeof(struct kvm_nested_state))
			return -EOPNOTSUPP;
	}

	/*
	 * @xsave is a fixed-size struct kvm_xsave.  A guest whose XSAVE area
	 * outgrows it -- AMX today -- needs KVM_GET_XSAVE2 and would otherwise
	 * be truncated silently by fpu_copy_guest_fpstate_to_uabi() below.
	 * This mirrors the check kvm_arch_vcpu_ioctl() makes for KVM_GET_XSAVE.
	 */
	if (vcpu->arch.guest_fpu.uabi_size > sizeof(struct kvm_xsave))
		return -EOPNOTSUPP;

	max_msrs = kvm_num_msrs_to_save();
	nent = vcpu->arch.cpuid_entries ? vcpu->arch.cpuid_nent : 0;
	size = sizeof(*state) + max_msrs * sizeof(struct kvm_msr_entry) +
	       nent * sizeof(struct kvm_cpuid_entry2);
	state = kho_alloc_preserve(size);
	if (IS_ERR(state))
		return PTR_ERR(state);

	/*
	 * kvm_arch_vcpu_ioctl_{get,set}_mpstate() take the vCPU themselves, so
	 * they have to be called outside the vcpu_load() region below:
	 * vcpu_load() registers a preempt notifier and is not reentrant.
	 */
	kvm_arch_vcpu_ioctl_get_mpstate(vcpu, &state->mp_state);
	state->pad = 0;

	vcpu_load(vcpu);

	__get_regs(vcpu, &state->regs);
	__get_sregs(vcpu, &state->sregs);
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

	/*
	 * A hardware maskable interrupt can only be queued for injection when
	 * RFLAGS.IF is set.  If RFLAGS.IF is already clear, the interrupt gate
	 * delivery has already completed (e.g., under QEMU TCG where
	 * exit_int_info can remain set across the first instruction of the
	 * handler), so clear any stale injected flag to avoid delivering the
	 * same interrupt a second time with RFLAGS.IF == 0 before SWAPGS.
	 */
	if (vcpu->arch.interrupt.injected && !vcpu->arch.interrupt.soft &&
	    !(state->regs.rflags & X86_EFLAGS_IF))
		vcpu->arch.interrupt.injected = false;

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

	state->cpuid_nent = nent;
	if (nent) {
		struct kvm_cpuid_entry2 *cpuid_dst =
			(void *)&state->msrs[state->num_msrs];

		memcpy(cpuid_dst, vcpu->arch.cpuid_entries,
		       nent * sizeof(*cpuid_dst));
	}

	if (fpu_loaded)
		kvm_put_guest_fpu(vcpu);

	vcpu_put(vcpu);

	KHOSER_STORE_PTR(ser->arch_state, state);
	return 0;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vcpu_luo_preserve);

int kvm_arch_vcpu_luo_retrieve(struct kvm_vcpu *vcpu, struct kvm_vcpu_ser *ser)
{
	struct kvm_vcpu_arch_ser *state;
	bool fpu_loaded = false;
	int ret, i;

	if (!ser->arch_state.phys)
		return 0;

	state = KHOSER_LOAD_PTR(ser->arch_state);

	vcpu_load(vcpu);

	if (state->cpuid_nent > 0) {
		struct kvm_cpuid_entry2 *cpuid_src =
			(void *)&state->msrs[state->num_msrs];
		struct kvm_cpuid_entry2 *entries;

		entries = kmemdup(cpuid_src,
				  state->cpuid_nent * sizeof(*entries),
				  GFP_KERNEL);
		if (!entries) {
			ret = -ENOMEM;
			goto out;
		}

		ret = kvm_set_cpuid(vcpu, entries, state->cpuid_nent);
		if (ret) {
			kvfree(entries);
			goto out;
		}
	}

	ret = __set_sregs(vcpu, &state->sregs);
	if (ret)
		goto out;

	if (boot_cpu_has(X86_FEATURE_XSAVE)) {
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

	if (boot_cpu_has(X86_FEATURE_XSAVE) &&
	    !fpstate_is_confidential(&vcpu->arch.guest_fpu)) {
		union fpregs_state *xstate = (union fpregs_state *)state->xsave.region;

		xstate->xsave.header.xfeatures &= ~vcpu->arch.guest_fpu.fpstate->xfd;
		ret = fpu_copy_uabi_to_guest_fpstate(&vcpu->arch.guest_fpu,
						     state->xsave.region,
						     kvm_caps.supported_xcr0,
						     &vcpu->arch.pkru);
		if (ret)
			goto out;
	}

	ret = kvm_vcpu_ioctl_x86_set_debugregs(vcpu, &state->debugregs);
	if (ret)
		goto out;

	if (kvm_nested_ops.enabled)
		kvm_leave_nested(vcpu);

	if (!(ser->flags & KVM_VCPU_LUO_FLAG_CARETAKER)) {
		ret = kvm_vcpu_ioctl_x86_set_vcpu_events(vcpu, &state->events);
		if (ret)
			goto out;
	}

	if (lapic_in_kernel(vcpu)) {
		if (ser->flags & KVM_VCPU_LUO_FLAG_CARETAKER) {
			struct kvm_lapic_state lapic;
			int k;

			memcpy(&lapic, &state->lapic, sizeof(lapic));
			for (k = 0; k < 8; k++) {
				*(u32 *)(lapic.regs + APIC_ISR + 0x10 * k) = 0;
				*(u32 *)(lapic.regs + APIC_IRR + 0x10 * k) = 0;
			}
			ret = kvm_apic_set_state(vcpu, &lapic);
		} else {
			ret = kvm_apic_set_state(vcpu, &state->lapic);
		}
		if (ret)
			goto out;
	}

	if (!vcpu->arch.guest_fpu.fpstate->in_use) {
		kvm_load_guest_fpu(vcpu);
		fpu_loaded = true;
	}

	for (i = 0; i < state->num_msrs; i++) {
		if ((ser->flags & KVM_VCPU_LUO_FLAG_CARETAKER) &&
		    (state->msrs[i].index == MSR_IA32_TSC ||
		     state->msrs[i].index == MSR_IA32_TSC_ADJUST)) {
			continue;
		}
		kvm_msr_write(vcpu, state->msrs[i].index, state->msrs[i].data);
	}

	__set_regs(vcpu, &state->regs);

	ret = 0;
out:
	if (fpu_loaded)
		kvm_put_guest_fpu(vcpu);
	vcpu_put(vcpu);

	/* Takes the vCPU itself; see the comment in the preserve path. */
	if (!ret)
		ret = kvm_arch_vcpu_ioctl_set_mpstate(vcpu, &state->mp_state);

	return ret;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vcpu_luo_retrieve);

void kvm_arch_vcpu_luo_unpreserve(struct kvm_vcpu_ser *ser)
{
	if (ser->arch_state.phys) {
		struct kvm_vcpu_arch_ser *state =
			phys_to_virt(__sme_clr(ser->arch_state.phys));

		kho_unpreserve_free(state);
		ser->arch_state.phys = 0;
	}
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vcpu_luo_unpreserve);

void kvm_arch_vcpu_luo_finish(struct kvm_vcpu_ser *ser)
{
	if (ser->arch_state.phys) {
		struct kvm_vcpu_arch_ser *state =
			phys_to_virt(__sme_clr(ser->arch_state.phys));

		kho_restore_free(state);
		ser->arch_state.phys = 0;
	}
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vcpu_luo_finish);
