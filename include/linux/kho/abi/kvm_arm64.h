/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 */
#ifndef _LINUX_KHO_ABI_KVM_ARM64_H
#define _LINUX_KHO_ABI_KVM_ARM64_H

#ifdef CONFIG_ARM64

#include <linux/build_bug.h>
#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/kho/abi/kvm.h>
#include <uapi/linux/kvm.h>
#include <uapi/asm/kvm.h>

/**
 * DOC: arm64 KVM vCPU Live Update ABI
 *
 * arm64 KVM uses the ABI defined below for preserving architectural vCPU state
 * across a kexec reboot using LUO.
 *
 * The state is serialized into a packed structure `struct kvm_vcpu_arch_ser`
 * which is handed over to the next kernel via KHO.
 *
 * The core register structure (struct kvm_regs) is a uAPI contract.
 *
 * This interface is a contract. Any modification to the structure layout
 * constitutes a breaking change. Such changes require incrementing the version
 * number in the KVM_VCPU_LUO_FH_COMPATIBLE string.
 */

/**
 * struct kvm_vcpu_arch_ser - Preserved arm64 architectural vCPU state in RAM.
 * @regs:        Core general-purpose and floating-point registers (uAPI struct kvm_regs).
 * @mp_state:    Multiprocessor execution state (uAPI struct kvm_mp_state).
 * @pad:         Padding to maintain 64-bit alignment after mp_state.
 * @events:      Exception and SError injection state (uAPI struct kvm_vcpu_events).
 * @init:        Target CPU and vCPU feature bitmap (uAPI struct kvm_vcpu_init).
 * @num_sysregs: Number of serialized system registers in sysregs array.
 * @reserved:    Reserved padding for 64-bit alignment.
 * @sysregs:     Guest architectural system registers (uAPI struct kvm_one_reg array).
 */
struct kvm_vcpu_arch_ser {
	struct kvm_regs regs;
	struct kvm_mp_state mp_state;
	u32 pad;
	struct kvm_vcpu_events events;
	struct kvm_vcpu_init init;
	u32 num_sysregs;
	u32 reserved;
	struct kvm_one_reg sysregs[];
} __packed;

static_assert(offsetof(struct kvm_vcpu_arch_ser, sysregs) % sizeof(u64) == 0,
	      "sysregs must be 64-bit aligned");

/**
 * struct kvm_caretaker_arch_ser - ARM64-specific Caretaker control block ABI
 * @cb:               Common Caretaker control block header (must be at offset 0).
 * @vgic_initialized: Non-zero if @vgic_* fields hold live VGICv3 CPU interface state.
 * @cflags:           KVM vCPU architectural flags.
 * @cntvoff_el2:      Guest virtual counter offset active during Caretaker execution.
 * @hcr_el2:          Hypervisor Configuration Register active during Caretaker execution.
 * @mdcr_el2:         Monitor Debug Configuration Register active during Caretaker execution.
 * @used_lrs:         Number of active VGICv3 List Registers.
 * @vgic_hcr:         VGICv3 Hypervisor Control Register.
 * @vgic_vmcr:        VGICv3 Virtual Machine Control Register.
 * @reserved:         Must be zero.
 * @vgic_ap0r:        VGICv3 Active Priorities Group 0 Registers.
 * @vgic_ap1r:        VGICv3 Active Priorities Group 1 Registers.
 * @vgic_lr:          VGICv3 List Registers.
 */
struct kvm_caretaker_arch_ser {
	struct kvm_caretaker_cb_ser cb;
	u32 vgic_initialized;
	u32 cflags;
	u64 cntvoff_el2;
	u64 hcr_el2;
	u64 mdcr_el2;
	u32 used_lrs;
	u32 vgic_hcr;
	u32 vgic_vmcr;
	u32 reserved;
	u32 vgic_ap0r[4];
	u32 vgic_ap1r[4];
	u64 vgic_lr[16];
} __packed;

#endif /* CONFIG_ARM64 */

#endif /* _LINUX_KHO_ABI_KVM_ARM64_H */
