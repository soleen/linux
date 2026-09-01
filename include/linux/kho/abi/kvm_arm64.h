/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026, Google LLC.
 */
#ifndef _LINUX_KHO_ABI_KVM_ARM64_H
#define _LINUX_KHO_ABI_KVM_ARM64_H

#ifdef CONFIG_ARM64

#include <linux/types.h>
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

#define KVM_ARM64_LUO_MAX_SYSREGS	512
#define KVM_ARM64_LUO_VGIC_V3_MAX_LRS	16

struct kvm_vm_arch_luo_state {
	u64 reserved;
} __packed;

/**
 * struct kvm_arm64_luo_vgic_v3 - Serialized GICv3 CPU interface state.
 * @vgic_hcr:  Hypervisor Control Register.
 * @vgic_vmcr: Virtual Machine Control Register.
 * @vgic_sre:  System Register Enable.
 * @vgic_ap0r: Active Priority Registers group 0.
 * @vgic_ap1r: Active Priority Registers group 1.
 * @vgic_lr:   List Registers.
 * @used_lrs:  Number of active List Registers.
 */
struct kvm_arm64_luo_vgic_v3 {
	u32 vgic_hcr;
	u32 vgic_vmcr;
	u32 vgic_sre;
	u32 vgic_ap0r[4];
	u32 vgic_ap1r[4];
	u64 vgic_lr[KVM_ARM64_LUO_VGIC_V3_MAX_LRS];
	u32 used_lrs;
} __packed;

/**
 * struct kvm_vcpu_arch_luo_state - Preserved arm64 architectural vCPU state in RAM.
 * @num_sysregs:   Number of valid system registers stored in sys_regs.
 * @regs:          Core registers (uAPI struct kvm_regs).
 * @hcr_el2:       Hypervisor Configuration Register.
 * @mdcr_el2:      Monitor Debug Configuration Register.
 * @cflags:        KVM vCPU compilation and runtime flags.
 * @s2_pgd_phys:   Stage-2 PGD base physical address.
 * @vcpu_features: Configured vCPU feature bitmap.
 * @vgic_v3:       GICv3 CPU interface state.
 * @sys_regs:      Guest architectural system registers.
 */
struct kvm_vcpu_arch_luo_state {
	u32 num_sysregs;
	struct kvm_regs regs;
	u64 hcr_el2;
	u64 mdcr_el2;
	u64 cflags;
	u64 s2_pgd_phys;
	u64 vcpu_features;
	struct kvm_arm64_luo_vgic_v3 vgic_v3;
	u64 sys_regs[KVM_ARM64_LUO_MAX_SYSREGS];
} __packed;

#endif /* CONFIG_ARM64 */

#endif /* _LINUX_KHO_ABI_KVM_ARM64_H */
