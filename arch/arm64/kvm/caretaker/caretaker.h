/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * Header for ARM64 KVM Caretaker execution engine and helpers.
 */
#ifndef __ARCH_ARM64_KVM_CARETAKER_H
#define __ARCH_ARM64_KVM_CARETAKER_H

#include <linux/irqchip/arm-gic-v3.h>

#ifndef __ASSEMBLY__

#include <linux/types.h>
#include <linux/refcount.h>
#include <linux/sizes.h>
#include <linux/oncore.h>
#include <linux/kvm_host.h>
#include <linux/kho/abi/kvm_arm64.h>
#include <linux/kvm_caretaker.h>
#include <linux/irqchip/arm-gic-common.h>
#include <asm/esr.h>

struct caretaker_arm64_page;

/**
 * struct caretaker_arm64_page - Old-text-private ARM64 Caretaker execution page
 *
 * Invariant: Only the embedded @abi prefix (struct kvm_caretaker_arch_ser,
 * offset 0) is part of the KHO handover ABI and may be dereferenced
 * by the incoming kernel.  All remaining fields are private to preserved
 * Caretaker text executing on the isolated core.
 */
struct caretaker_arm64_page {
	struct kvm_caretaker_arch_ser abi;
	struct kvm_caretaker_vcpu vcpu;
	struct kvm_vcpu kvm_vcpu;
	struct kvm_host_data host_data;
	struct kvm_cpu_context hyp_ctxt;
	u64 host_cnthctl_el2;
	u64 vttbr_el2;
	u64 pcpu_mpidr;
	bool vgic_initialized;
	bool serialized;
	u16 pending_sgis;
	phys_addr_t cvm_pa;
	phys_addr_t next_vcpu_pa;
	struct caretaker_arm64_page *next_vcpu;
	struct kvm_vcpu_arch_ser *arch_state;
};

static_assert(offsetof(struct caretaker_arm64_page, abi) == 0);
static_assert(offsetof(struct caretaker_arm64_page, abi.cb) == 0);

int kvm_arch_vcpu_luo_pre_retrieve_caretaker(struct kvm_vcpu *vcpu,
					     struct kvm_vcpu_ser *ser);
void kvm_arch_vcpu_luo_attach_caretaker(struct kvm_vcpu *vcpu,
					struct kvm_vcpu_ser *ser);
void arm64_caretaker_detach_serialize(struct caretaker_arm64_page *cap)
	__cpu_preserved_sym_asm(arm64_caretaker_detach_serialize);
void cpu_preserved_sym(arm64_caretaker_handle_invalid)(u64 elr, u64 esr, u64 far);

#ifdef CONFIG_KVM_CARETAKER
int arm64_kvm_caretaker_preserve(struct kvm_vcpu *vcpu,
				 struct kvm_vcpu_ser *ser);
void arm64_kvm_caretaker_unpreserve(struct kvm_vcpu_ser *ser);
void arm64_kvm_caretaker_finish(struct kvm_vcpu_ser *ser);
#else
static inline int arm64_kvm_caretaker_preserve(struct kvm_vcpu *vcpu,
					       struct kvm_vcpu_ser *ser)
{
	return -EOPNOTSUPP;
}

static inline void arm64_kvm_caretaker_unpreserve(struct kvm_vcpu_ser *ser) {}
static inline void arm64_kvm_caretaker_finish(struct kvm_vcpu_ser *ser) {}
#endif

#endif /* !__ASSEMBLY__ */

#endif /* __ARCH_ARM64_KVM_CARETAKER_H */
