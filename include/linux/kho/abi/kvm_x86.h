/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026, Google LLC.
 */
#ifndef _LINUX_KHO_ABI_KVM_X86_H
#define _LINUX_KHO_ABI_KVM_X86_H

#ifdef CONFIG_X86_64

#include <linux/types.h>
#include <uapi/linux/kvm.h>
#include <uapi/asm/kvm.h>

/**
 * DOC: x86 KVM Live Update ABI
 *
 * x86 KVM uses the ABI defined below for preserving architectural VM and vCPU
 * state across a kexec reboot using LUO.
 *
 * The VM-level architectural state contains the CPUID table, which is shared
 * across all vCPUs in the VM. The vCPU-level architectural state contains the
 * compact register sets for each vCPU.
 *
 * All sub-structures (struct kvm_regs, struct kvm_sregs, struct kvm_mp_state,
 * struct kvm_cpuid_entry2) are uAPI contracts.
 */

/**
 * struct kvm_vm_arch_luo_state - Preserved x86 architectural VM state in RAM.
 * @cpuid_nent:    Number of valid CPUID entries in cpuid_entries.
 * @cpuid_entries: CPUID leaves for the VM (uAPI struct kvm_cpuid_entry2).
 */
struct kvm_vm_arch_luo_state {
	u32 cpuid_nent;
	struct kvm_cpuid_entry2 cpuid_entries[];
} __packed;

/**
 * struct kvm_vcpu_arch_luo_state - Preserved x86 architectural vCPU state in RAM.
 * @regs:          General-purpose registers (uAPI struct kvm_regs).
 * @sregs:         Segment and control registers (uAPI struct kvm_sregs).
 * @mp_state:      Multiprocessor state (uAPI struct kvm_mp_state).
 * @fpu:           Floating point / SSE unit state (uAPI struct kvm_fpu).
 * @xcrs:          Extended control registers including XCR0 (uAPI struct kvm_xcrs).
 * @lapic:         In-kernel local APIC register state (uAPI struct kvm_lapic_state).
 * @xsave:         Extended processor state (uAPI struct kvm_xsave).
 * @events:        vCPU exception, interrupt, NMI and SMI events (uAPI struct kvm_vcpu_events).
 * @debugregs:     Hardware debug registers DR0-DR7 (uAPI struct kvm_debugregs).
 * @nested:        Nested virtualization state (uAPI struct kvm_nested_state).
 * @num_msrs:      Number of valid MSR entries in msrs.
 * @msrs:          Array of preserved architectural and paravirtual MSR entries.
 */
struct kvm_vcpu_arch_luo_state {
	struct kvm_regs regs;
	struct kvm_sregs sregs;
	struct kvm_mp_state mp_state;
	struct kvm_fpu fpu;
	struct kvm_xcrs xcrs;
	struct kvm_lapic_state lapic;
	struct kvm_xsave xsave;
	struct kvm_vcpu_events events;
	struct kvm_debugregs debugregs;
	struct kvm_nested_state nested;
	u32 num_msrs;
	struct kvm_msr_entry msrs[];
} __packed;

#endif /* CONFIG_X86_64 */

#endif /* _LINUX_KHO_ABI_KVM_X86_H */
