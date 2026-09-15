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

/**
 * struct kvm_arm64_caretaker_abi - Cross-kexec ABI prefix of ARM64 Caretaker page
 * @cb:               Common Caretaker control block (must be at offset 0).
 * @running:          Non-zero while the preserved core is actively inside the
 *                    Caretaker run loop.
 * @vgic_initialized: Non-zero if @vgic_* fields hold live VGICv3 CPU interface state.
 * @arch_state_pa:    Physical address of struct kvm_vcpu_arch_luo_state where the
 *                    preserved Caretaker text writes live vCPU state at detach.
 * @arch_state_size:  Size in bytes of the struct kvm_vcpu_arch_luo_state allocation.
 * @cntvoff_el2:      Guest virtual counter offset active during Caretaker execution.
 * @hcr_el2:          Hypervisor Configuration Register active during Caretaker execution.
 * @mdcr_el2:         Monitor Debug Configuration Register active during Caretaker execution.
 * @cflags:           KVM vCPU architectural flags.
 * @used_lrs:         Number of active VGICv3 List Registers.
 * @vgic_hcr:         VGICv3 Hypervisor Control Register.
 * @vgic_vmcr:        VGICv3 Virtual Machine Control Register.
 * @vgic_ap0r:        VGICv3 Active Priorities Group 0 Registers.
 * @vgic_ap1r:        VGICv3 Active Priorities Group 1 Registers.
 * @vgic_lr:          VGICv3 List Registers.
 *
 * Cross-kexec invariant: the incoming kernel may only dereference structures
 * declared in include/linux/kho/abi/ headers.  Everything else in struct
 * caretaker_arm64_page (struct kvm_cpu_context, struct kvm_vcpu_fault_info,
 * struct vgic_v3_cpu_if, ptrauth keys) is private to the preserved Caretaker
 * text and is never accessed by the incoming kernel.
 */
struct kvm_arm64_caretaker_abi {
	struct kvm_caretaker_cb cb;
	u32 running;
	u32 vgic_initialized;
	u64 arch_state_pa;
	u64 arch_state_size;
	u64 cntvoff_el2;
	u64 hcr_el2;
	u64 mdcr_el2;
	u32 cflags;
	u32 used_lrs;
	u32 vgic_hcr;
	u32 vgic_vmcr;
	u32 vgic_ap0r[4];
	u32 vgic_ap1r[4];
	u64 vgic_lr[16];
};

static_assert(sizeof(struct kvm_arm64_caretaker_abi) == 256);
static_assert(offsetof(struct kvm_arm64_caretaker_abi, cb) == 0);
static_assert(offsetof(struct kvm_arm64_caretaker_abi, running) == 32);
static_assert(offsetof(struct kvm_arm64_caretaker_abi, vgic_initialized) == 36);
static_assert(offsetof(struct kvm_arm64_caretaker_abi, arch_state_pa) == 40);
static_assert(offsetof(struct kvm_arm64_caretaker_abi, arch_state_size) == 48);

#endif /* CONFIG_ARM64 */

#endif /* _LINUX_KHO_ABI_KVM_ARM64_H */
