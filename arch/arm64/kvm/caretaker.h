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
#define CAP_CTXT_OFFSET		0x20

/* Special INTID range (1020-1023) reserved by GIC architecture */
#define GIC_SPECIAL_INTID_START	1020

#ifndef __ASSEMBLY__

#include <linux/types.h>
#include <linux/sizes.h>
#include <linux/oncore.h>
#include <linux/kvm_host.h>
#include <linux/kvm_caretaker.h>
#include <linux/kho/abi/kvm.h>
#include <linux/irqchip/arm-gic-v3.h>
#include <asm/esr.h>

/* Default priority for software-injected SGIs */
#define GIC_DEFAULT_SGI_PRIO		0xa0ULL


/* System register opcodes for SGI generation */
#define ESR_ELx_SYS64_ISS_SYS_ICC_SGI1R_EL1 \
	(ESR_ELx_SYS64_ISS_SYS_VAL(3, 0, 5, 12, 11) | ESR_ELx_SYS64_ISS_DIR_WRITE)
#define ESR_ELx_SYS64_ISS_SYS_ICC_ASGI1R_EL1 \
	(ESR_ELx_SYS64_ISS_SYS_VAL(3, 0, 6, 12, 11) | ESR_ELx_SYS64_ISS_DIR_WRITE)
#define ESR_ELx_SYS64_ISS_SYS_ICC_SGI0R_EL1 \
	(ESR_ELx_SYS64_ISS_SYS_VAL(3, 0, 7, 12, 11) | ESR_ELx_SYS64_ISS_DIR_WRITE)

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

struct arm64_caretaker_ptrauth_keys {
	u64 apia_lo, apia_hi;
	u64 apib_lo, apib_hi;
	u64 apda_lo, apda_hi;
	u64 apdb_lo, apdb_hi;
	u64 apga_lo, apga_hi;
};

/**
 * struct caretaker_arm64_page - Old-text-private ARM64 Caretaker execution page
 *
 * Invariant: Only the embedded @abi prefix (struct kvm_arm64_caretaker_abi,
 * offset 0, size 256) is part of the KHO handover ABI and may be dereferenced
 * by the incoming kernel.  All remaining fields are private to preserved
 * Caretaker text executing on the isolated core.
 */
struct caretaker_arm64_page {
	union {
		struct kvm_arm64_caretaker_abi abi;
		struct kvm_caretaker_vcpu vcpu __aligned(16);
		struct kvm_caretaker_cb cb;
	};
	struct caretaker_arm64_context ctx;
	struct caretaker_arm64_vm *vm;
	struct kvm_vcpu_arch_luo_state *arch_state;
	u64 last_ret;
	struct arm64_caretaker_ptrauth_keys ptrauth_keys;
};

static_assert(offsetof(struct caretaker_arm64_page, abi) == 0);
static_assert(offsetof(struct caretaker_arm64_page, cb) == 0);
static_assert(offsetof(struct caretaker_arm64_page, abi.running) ==
	      offsetof(struct caretaker_arm64_page, vcpu.running));

u64 caretaker_guest_enter(struct caretaker_arm64_context *ctx);
void kvm_arch_vcpu_luo_pre_retrieve_caretaker(struct kvm_vcpu *vcpu,
					      struct kvm_vcpu_luo_ser *ser);
void kvm_arch_vcpu_luo_attach_caretaker(struct kvm_vcpu *vcpu,
					struct kvm_vcpu_luo_ser *ser);
void arm64_caretaker_handle_invalid(u64 elr, u64 esr, u64 far);

#ifdef CONFIG_KVM_CARETAKER
int arm64_kvm_caretaker_preserve(struct kvm_vcpu *vcpu,
				 struct kvm_vcpu_luo_ser *ser);
void arm64_kvm_caretaker_unpreserve(struct kvm_vcpu_luo_ser *ser);
void arm64_kvm_caretaker_finish(struct kvm_vcpu_luo_ser *ser);
#else
static inline int arm64_kvm_caretaker_preserve(struct kvm_vcpu *vcpu,
					       struct kvm_vcpu_luo_ser *ser)
{
	return -EOPNOTSUPP;
}
static inline void arm64_kvm_caretaker_unpreserve(struct kvm_vcpu_luo_ser *ser) {}
static inline void arm64_kvm_caretaker_finish(struct kvm_vcpu_luo_ser *ser) {}
#endif

#endif /* !__ASSEMBLY__ */

#endif /* __ARCH_ARM64_KVM_CARETAKER_H */
