/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026, Google LLC.
 */
#ifndef _LINUX_KHO_ABI_KVM_ARM64_H
#define _LINUX_KHO_ABI_KVM_ARM64_H

#ifdef CONFIG_ARM64

#include <linux/build_bug.h>
#include <linux/stddef.h>
#include <linux/types.h>
#include <uapi/linux/kvm.h>
#include <uapi/asm/kvm.h>

/**
 * DOC: arm64 KVM vCPU Live Update ABI
 *
 * arm64 KVM uses the ABI defined below for preserving architectural vCPU state
 * across a kexec reboot using LUO.
 *
 * The state is serialized into a packed structure `struct kvm_vcpu_arch_luo_state`
 * which is handed over to the next kernel via KHO.
 *
 * The core register structure (struct kvm_regs) is a uAPI contract.
 *
 * This interface is a contract. Any modification to the structure layout
 * constitutes a breaking change. Such changes require incrementing the version
 * number in the KVM_VCPU_LUO_FH_COMPATIBLE string.
 */

struct kvm_vm_arch_luo_state {
	u64 reserved;
} __packed;

/**
 * struct kvm_vcpu_arch_luo_state - Preserved arm64 architectural vCPU state in RAM.
 * @regs:        Core general-purpose and floating-point registers (uAPI struct kvm_regs).
 * @mp_state:    Multiprocessor execution state (uAPI struct kvm_mp_state).
 * @pad:         Padding to maintain 64-bit alignment after mp_state.
 * @events:      Exception and SError injection state (uAPI struct kvm_vcpu_events).
 * @init:        Target CPU and vCPU feature bitmap (uAPI struct kvm_vcpu_init).
 * @num_sysregs: Number of serialized system registers in sysregs array.
 * @reserved:    Reserved padding for 64-bit alignment.
 * @sysregs:     Guest architectural system registers (uAPI struct kvm_one_reg array).
 */
struct kvm_vcpu_arch_luo_state {
	struct kvm_regs regs;
	struct kvm_mp_state mp_state;
	u32 pad;
	struct kvm_vcpu_events events;
	struct kvm_vcpu_init init;
	u32 num_sysregs;
	u32 reserved;
	struct kvm_one_reg sysregs[];
} __packed;

static_assert(offsetof(struct kvm_vcpu_arch_luo_state, sysregs) % sizeof(u64) == 0,
	      "sysregs must be 64-bit aligned");

#endif /* CONFIG_ARM64 */

#endif /* _LINUX_KHO_ABI_KVM_ARM64_H */
