// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * x86 KVM LUO architectural preservation and retrieval handlers.
 */

#include <linux/cpu.h>
#include <linux/kexec_handover.h>
#include <linux/kho/abi/kvm.h>
#include <linux/kho/abi/kvm_x86.h>
#include <linux/kvm_host.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <asm/fpu/api.h>
#include <asm/fpu/xcr.h>
#include <linux/mem_encrypt.h>
#include <asm/virt.h>

#include "caretaker/caretaker.h"
#include "cpuid.h"
#include "fpu.h"
#include "lapic.h"
#include "mmu.h"
#include "msrs.h"
#include "pmu.h"
#include "regs.h"
#include "x86.h"

int kvm_arch_vm_luo_preserve(struct kvm *kvm, struct kvm_luo_ser *ser)
{
	ser->type = kvm->arch.vm_type;
	return 0;
}

void kvm_arch_vm_luo_unpreserve(struct kvm *kvm, struct kvm_luo_ser *ser)
{
}

int kvm_arch_vcpu_luo_preserve(struct kvm_vcpu *vcpu, struct kvm_vcpu_ser *ser)
{
	struct kvm_vcpu_arch_ser *state;
	struct kvm_cpuid2 *cpuid;
	struct kvm_msrs *msrs;
	unsigned int max_msrs;
	u32 nent;
	size_t size;
	int ret;

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
	size = sizeof(*state) + struct_size(msrs, entries, max_msrs) +
	       struct_size(cpuid, entries, nent);
	state = kho_alloc_preserve(size);
	if (IS_ERR(state))
		return PTR_ERR(state);

	/*
	 * kvm_arch_vcpu_ioctl_{get,set}_mpstate() take the vCPU themselves, so
	 * they have to be called outside the vcpu_load() region below:
	 * vcpu_load() registers a preempt notifier and is not reentrant.
	 */
	ret = kvm_arch_vcpu_ioctl_get_mpstate(vcpu, &state->mp_state);
	if (ret)
		goto err_free;
	state->pad = 0;

	vcpu_load(vcpu);

	__get_regs(vcpu, &state->regs);
	__get_sregs(vcpu, &state->sregs);
	ret = kvm_vcpu_ioctl_x86_get_xcrs(vcpu, &state->xcrs);
	if (ret)
		goto err_put;

	if (boot_cpu_has(X86_FEATURE_XSAVE)) {
		ret = kvm_vcpu_ioctl_x86_get_xsave(vcpu, &state->xsave);
		if (ret)
			goto err_put;
	}

	kvm_vcpu_ioctl_x86_get_debugregs(vcpu, &state->debugregs);
	get_kvmclock(vcpu->kvm, &state->clock);

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

	if (lapic_in_kernel(vcpu)) {
		ret = kvm_vcpu_ioctl_get_lapic(vcpu, &state->lapic);
		if (ret)
			goto err_put;
	}

	msrs = (void *)(state + 1);
	kvm_msrs_save(vcpu, msrs);
	KHOSER_STORE_PTR(state->msrs, msrs);

	cpuid = (void *)&msrs->entries[msrs->nmsrs];
	kvm_get_cpuid(vcpu, cpuid);
	KHOSER_STORE_PTR(state->cpuid, cpuid);

	vcpu_put(vcpu);

	KHOSER_STORE_PTR(ser->arch_state, state);

	if (IS_ENABLED(CONFIG_KVM_CARETAKER)) {
		ret = kvm_arch_vcpu_caretaker_preserve(vcpu, ser, state, size);
		if (ret) {
			ser->arch_state.phys = 0;
			goto err_free;
		}
	}

	return 0;

err_put:
	vcpu_put(vcpu);
err_free:
	kho_unpreserve_free(state);
	return ret;
}

int kvm_arch_vcpu_luo_retrieve(struct kvm_vcpu *vcpu, struct kvm_vcpu_ser *ser)
{
	struct kvm_vcpu_arch_ser *state;
	struct kvm_cpuid2 *cpuid;
	struct kvm_msrs *msrs;
	unsigned int max_msrs;
	int ret;

	if (!ser->arch_state.phys)
		return 0;

	state = KHOSER_LOAD_PTR(ser->arch_state);
	msrs = KHOSER_LOAD_PTR(state->msrs);
	cpuid = KHOSER_LOAD_PTR(state->cpuid);
	max_msrs = kvm_num_msrs_to_save();
	if (!msrs || msrs != (struct kvm_msrs *)(state + 1) ||
	    msrs->nmsrs > max_msrs)
		return -EINVAL;
	if (cpuid &&
	    (cpuid != (struct kvm_cpuid2 *)&msrs->entries[msrs->nmsrs] ||
	     cpuid->nent > KVM_MAX_CPUID_ENTRIES))
		return -EINVAL;

	vcpu_load(vcpu);

	if (cpuid && cpuid->nent > 0) {
		struct kvm_cpuid_entry2 *entries;

		entries = kmemdup(cpuid->entries,
				  flex_array_size(cpuid, entries, cpuid->nent),
				  GFP_KERNEL);
		if (!entries) {
			ret = -ENOMEM;
			goto out;
		}

		ret = kvm_set_cpuid(vcpu, entries, cpuid->nent);
		if (ret) {
			kvfree(entries);
			goto out;
		}
	}

	kvm_msrs_restore(vcpu, msrs, true);

	ret = __set_sregs(vcpu, &state->sregs);
	if (ret)
		goto out;

	if (boot_cpu_has(X86_FEATURE_XSAVE)) {
		ret = kvm_vcpu_ioctl_x86_set_xcrs(vcpu, &state->xcrs);
		if (ret)
			goto out;

		ret = kvm_vcpu_ioctl_x86_set_xsave(vcpu, &state->xsave);
		if (ret)
			goto out;
	}

	ret = kvm_vcpu_ioctl_x86_set_debugregs(vcpu, &state->debugregs);
	if (ret)
		goto out;

	if (kvm_nested_ops.enabled)
		kvm_leave_nested(vcpu);

	if (!KHOSER_LOAD_PTR(ser->cb)) {
		kvm_vcpu_srcu_read_lock(vcpu);
		ret = kvm_vcpu_ioctl_x86_set_vcpu_events(vcpu, &state->events);
		kvm_vcpu_srcu_read_unlock(vcpu);
		if (ret)
			goto out;
	}

	if (lapic_in_kernel(vcpu)) {
		if (KHOSER_LOAD_PTR(ser->cb)) {
			struct kvm_lapic_state lapic = state->lapic;
			int k;

			for (k = 0; k < 8; k++) {
				*(u32 *)(lapic.regs + APIC_ISR + 0x10 * k) = 0;
				*(u32 *)(lapic.regs + APIC_IRR + 0x10 * k) = 0;
			}
			ret = kvm_vcpu_ioctl_set_lapic(vcpu, &lapic);
		} else {
			ret = kvm_vcpu_ioctl_set_lapic(vcpu, &state->lapic);
		}
		if (ret)
			goto out;
	}

	kvm_msrs_restore(vcpu, msrs, false);

	__set_regs(vcpu, &state->regs);

	if (vcpu->vcpu_id == 0)
		kvm_set_clock(vcpu->kvm, &state->clock);

	ret = 0;
out:
	vcpu_put(vcpu);

	/* Takes the vCPU itself; see the comment in the preserve path. */
	if (!ret)
		ret = kvm_arch_vcpu_ioctl_set_mpstate(vcpu, &state->mp_state);

	return ret;
}

void kvm_arch_vcpu_luo_unpreserve(struct kvm_vcpu_ser *ser)
{
	kvm_arch_vcpu_caretaker_unpreserve(ser);
	if (WARN_ON_ONCE(ser->cb.phys))
		return;
	if (ser->arch_state.phys) {
		struct kvm_vcpu_arch_ser *state =
			phys_to_virt(__sme_clr(ser->arch_state.phys));

		kho_unpreserve_free(state);
		ser->arch_state.phys = 0;
	}
}

void kvm_arch_vcpu_luo_finish(struct kvm_vcpu_ser *ser)
{
	kvm_arch_vcpu_caretaker_finish(ser);
	if (WARN_ON_ONCE(ser->cb.phys))
		return;
	if (ser->arch_state.phys) {
		struct kvm_vcpu_arch_ser *state =
			phys_to_virt(__sme_clr(ser->arch_state.phys));

		kho_restore_free(state);
		ser->arch_state.phys = 0;
	}
}
