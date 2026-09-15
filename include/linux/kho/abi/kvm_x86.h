/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026, Google LLC.
 */
#ifndef _LINUX_KHO_ABI_KVM_X86_H
#define _LINUX_KHO_ABI_KVM_X86_H

#ifdef CONFIG_X86_64

#include <linux/build_bug.h>
#include <linux/stddef.h>
#include <linux/types.h>
#include <uapi/linux/kvm.h>
#include <uapi/asm/kvm.h>

/**
 * DOC: x86 KVM Live Update ABI
 *
 * x86 KVM uses the ABI defined below for preserving architectural VM and vCPU
 * state across a kexec reboot using LUO.
 *
 * The vCPU-level architectural state contains the compact register sets and
 * CPUID table for each vCPU.
 *
 * All sub-structures (struct kvm_regs, struct kvm_sregs, struct kvm_mp_state,
 * struct kvm_cpuid_entry2) are uAPI contracts.
 */

/**
 * struct kvm_vcpu_arch_luo_state - Preserved x86 architectural vCPU state in RAM.
 * @regs:          General-purpose registers (uAPI struct kvm_regs).
 * @sregs:         Segment and control registers (uAPI struct kvm_sregs).
 * @mp_state:      Multiprocessor state (uAPI struct kvm_mp_state).
 * @pad:           Padding to maintain 64-bit alignment after mp_state.
 * @xcrs:          Extended control registers including XCR0 (uAPI struct kvm_xcrs).
 * @lapic:         In-kernel local APIC register state (uAPI struct kvm_lapic_state).
 * @xsave:         Extended processor state (uAPI struct kvm_xsave).  This is the
 *                 only copy of the guest FPU state; there is no kvm_fpu twin.
 * @events:        vCPU exception, interrupt, NMI and SMI events (uAPI struct kvm_vcpu_events).
 * @debugregs:     Hardware debug registers DR0-DR7 (uAPI struct kvm_debugregs).
 * @nested:        Nested virtualization state (uAPI struct kvm_nested_state).
 * @num_msrs:      Number of valid MSR entries in msrs.
 * @cpuid_nent:    Number of valid CPUID entries immediately following msrs[num_msrs].
 * @msrs:          Array of preserved architectural and paravirtual MSR entries,
 *                 followed by @cpuid_nent struct kvm_cpuid_entry2 entries.
 */
struct kvm_vcpu_arch_luo_state {
	struct kvm_regs regs;
	struct kvm_sregs sregs;
	struct kvm_mp_state mp_state;
	u32 pad;
	struct kvm_xcrs xcrs;
	struct kvm_lapic_state lapic;
	struct kvm_xsave xsave;
	struct kvm_vcpu_events events;
	struct kvm_debugregs debugregs;
	struct kvm_nested_state nested;
	u32 num_msrs;
	u32 cpuid_nent;
	struct kvm_msr_entry msrs[];
} __packed;

static_assert(offsetof(struct kvm_vcpu_arch_luo_state, msrs) % sizeof(u64) == 0,
	      "msrs must be 64-bit aligned");

/**
 * struct kvm_x86_caretaker_abi - Cross-kexec ABI prefix of x86 Caretaker page
 * @cb:              Common Caretaker control block (must be at offset 0).
 * @running:         Non-zero while the preserved core is actively inside the
 *                   Caretaker run loop; polled by the incoming kernel during
 *                   re-attachment.
 * @apic_id:         Hardware APIC ID of the preserved core, used by the incoming
 *                   kernel to deliver the attach-signal IPI.
 * @vmcs_pa:         Physical address of the VMCS the Caretaker ran the vCPU on
 *                   (Intel VMX only; 0 on AMD SVM).
 * @arch_state_pa:   Physical address of struct kvm_vcpu_arch_luo_state where the
 *                   preserved Caretaker text writes live vCPU state at detach.
 * @arch_state_size: Size in bytes of the struct kvm_vcpu_arch_luo_state allocation.
 *
 * Cross-kexec invariant: the incoming kernel may only dereference structures
 * declared in include/linux/kho/abi/ headers.  Everything else in struct
 * caretaker_x86_page (GDT, TSS, IDT, standalone stack, scratch registers) is
 * private to the preserved Caretaker text and is never accessed by the incoming
 * kernel.
 */
struct kvm_x86_caretaker_abi {
	struct kvm_caretaker_cb cb;
	u32 running;
	u32 apic_id;
	u64 vmcs_pa;
	u64 arch_state_pa;
	u64 arch_state_size;
};

static_assert(sizeof(struct kvm_x86_caretaker_abi) == 64);
static_assert(offsetof(struct kvm_x86_caretaker_abi, cb) == 0);
static_assert(offsetof(struct kvm_x86_caretaker_abi, running) == 32);
static_assert(offsetof(struct kvm_x86_caretaker_abi, apic_id) == 36);
static_assert(offsetof(struct kvm_x86_caretaker_abi, vmcs_pa) == 40);
static_assert(offsetof(struct kvm_x86_caretaker_abi, arch_state_pa) == 48);
static_assert(offsetof(struct kvm_x86_caretaker_abi, arch_state_size) == 56);

#endif /* CONFIG_X86_64 */

#endif /* _LINUX_KHO_ABI_KVM_X86_H */
