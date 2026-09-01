/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026, Google LLC.
 */
#ifndef _LINUX_KHO_ABI_KVM_X86_H
#define _LINUX_KHO_ABI_KVM_X86_H

#ifdef CONFIG_X86_64

#include <linux/types.h>
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

#define KVM_X86_LUO_MAX_MSRS	64

/**
 * struct kvm_luo_msr_entry - Saved MSR index and value.
 * @index:    MSR register index.
 * @reserved: Padding for 8-byte alignment.
 * @data:     MSR value.
 */
struct kvm_luo_msr_entry {
	u32 index;
	u32 reserved;
	u64 data;
} __packed;

/**
 * struct kvm_vcpu_arch_luo_state - Preserved x86 architectural vCPU state in RAM.
 * @regs:          General-purpose registers (uAPI struct kvm_regs).
 * @sregs:         Segment and control registers (uAPI struct kvm_sregs).
 * @mp_state:      Multiprocessor state (uAPI struct kvm_mp_state).
 * @fpu:           Floating point / SSE unit state (uAPI struct kvm_fpu).
 * @lapic:         In-kernel local APIC register state (uAPI struct kvm_lapic_state).
 * @has_lapic:     Flag indicating whether lapic contains valid state.
 * @num_msrs:      Number of valid MSR entries in msrs.
 * @msrs:          Array of preserved architectural and paravirtual MSR entries.
 */
struct kvm_vcpu_arch_luo_state {
	struct kvm_regs regs;
	struct kvm_sregs sregs;
	struct kvm_mp_state mp_state;
	struct kvm_fpu fpu;
	struct kvm_lapic_state lapic;
	u32 has_lapic;
	u32 num_msrs;
	struct kvm_luo_msr_entry msrs[KVM_X86_LUO_MAX_MSRS];
} __packed;

#endif /* CONFIG_X86_64 */

#endif /* _LINUX_KHO_ABI_KVM_X86_H */
