/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * Header for ARM64 KVM Caretaker execution engine and helpers.
 */
#ifndef __ARCH_ARM64_KVM_CARETAKER_H
#define __ARCH_ARM64_KVM_CARETAKER_H

#define CAP_FAULT_ESR		0x00
#define CAP_FAULT_FAR		0x08
#define CAP_FAULT_HPFAR		0x10
#define CAP_FAULT_DISR		0x18
#define CAP_CTXT_OFFSET		0x20

#ifndef __ASSEMBLY__

#include <linux/types.h>
#include <linux/caretaker.h>
#include <linux/kvm_host.h>
#include <linux/kvm_caretaker.h>
#include <linux/kho/abi/kvm.h>

/**
 * struct caretaker_arm64_context - Preserved ARM64 vCPU architectural context
 * @fault:            Guest fault syndrome registers from VM exits.
 * @ctxt:             CPU registers, FP/SIMD, and system registers.
 * @hcr_el2:          Hypervisor Configuration Register.
 * @mdcr_el2:         Monitor Debug Configuration Register.
 * @cflags:           vCPU execution flags.
 * @vtcr_el2:         Stage-2 translation control register.
 * @vttbr_el2:        Stage-2 translation table base register.
 * @s2_pgd_phys:      Stage-2 page table physical address.
 * @vgic_initialized: Whether VGICv3 virtual CPU interface is active.
 * @vgic_v3:          VGICv3 virtual CPU interface registers.
 * @vcpu_features:    KVM vCPU feature configuration bitmap.
 */
struct caretaker_arm64_context {
	struct kvm_vcpu_fault_info fault;
	struct kvm_cpu_context ctxt;

	u64 hcr_el2;
	u64 mdcr_el2;
	u64 cflags;

	u64 vtcr_el2;
	u64 vttbr_el2;
	u64 s2_pgd_phys;

	bool vgic_initialized;
	struct vgic_v3_cpu_if vgic_v3;

	unsigned long vcpu_features[BITS_TO_LONGS(KVM_VCPU_MAX_FEATURES)];
	u64 cntv_cval_el0;
	u64 cntv_ctl_el0;
	u64 cntvoff_el2;
	u16 pending_sgis;
};

struct caretaker_arm64_page;

/**
 * struct caretaker_arm64_vm - Preserved multi-vCPU tracking for Caretaker
 * @nr_vcpus:  Number of vCPUs in the VM.
 * @max_vcpus: Maximum capacity of the vCPUs array.
 * @vcpus:     Flexible array of pointers to preserved vCPU pages.
 */
struct caretaker_arm64_vm {
	unsigned int nr_vcpus;
	unsigned int max_vcpus;
	struct caretaker_arm64_page *vcpus[];
};

/**
 * struct caretaker_arm64_page - Standalone preserved execution page for ARM64
 * @cb:  Caretaker Control Block (stable cross-kernel ABI).
 * @ctx: Architectural guest context executed and preserved on-core.
 * @vm:  Backing VM context tracking peer vCPUs.
 */
struct caretaker_arm64_page {
	union {
		struct kvm_caretaker_vcpu vcpu __aligned(16);
		struct caretaker_cb cb;
	};
	struct caretaker_arm64_context ctx;
	struct caretaker_arm64_vm *vm;
	u64 last_ret;
};

u64 caretaker_guest_enter(struct caretaker_arm64_context *ctx);
int arm64_kvm_caretaker_preserve(struct kvm_vcpu *vcpu,
				 struct kvm_vcpu_luo_ser *ser);
void kvm_arch_vcpu_luo_attach_caretaker(struct kvm_vcpu *vcpu,
					struct kvm_vcpu_luo_ser *ser);

#endif /* !__ASSEMBLY__ */

#endif /* __ARCH_ARM64_KVM_CARETAKER_H */
