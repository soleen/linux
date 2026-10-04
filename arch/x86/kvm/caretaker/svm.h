/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 */
#ifndef __SVM_CARETAKER_H
#define __SVM_CARETAKER_H

#ifndef __ASSEMBLY__
#include <linux/types.h>
#include <linux/kvm_host.h>
#include <linux/oncore.h>
#include "lapic.h"
#include "x86.h"
#include "../svm/svm.h"
#endif

#include "caretaker.h"

#ifndef __ASSEMBLY__

struct caretaker_svm_page {
	struct caretaker_x86_page common;
	struct vcpu_svm svm;
	struct kvm_lapic apic;

	/* Preserved VMCB */
	struct vmcb vmcb __aligned(PAGE_SIZE);

	/* Preserved HSAVE area */
	u8 hsave_area[PAGE_SIZE] __aligned(PAGE_SIZE);
	u64 hsave_pa;
	u64 orig_hsave_pa;
	u64 vmcb_pa;
	u64 orig_efer;

	/* Preserved MSR and I/O permission bitmaps referenced by VMCB */
	u8 msrpm[MSRPM_SIZE] __aligned(PAGE_SIZE);
	u8 iopm[IOPM_SIZE] __aligned(PAGE_SIZE);
} __aligned(PAGE_SIZE);

void svm_recalc_intercepts(struct kvm_vcpu *vcpu);

extern const struct kvm_x86_caretaker_runtime_ops cpu_preserved_sym(svm_caretaker_runtime_ops);

#ifndef __CPU_PRESERVED_RUNTIME__
#define svm_caretaker_runtime_ops	__cpu_preserved_svm_caretaker_runtime_ops
#endif

#if defined(CONFIG_KVM_CARETAKER) && defined(CONFIG_KVM_AMD)
void svm_caretaker_register(void);
void svm_caretaker_unregister(void);
void svm_caretaker_init(struct kvm_vcpu *vcpu);
#else
static inline void svm_caretaker_register(void) {}
static inline void svm_caretaker_unregister(void) {}
static inline void svm_caretaker_init(struct kvm_vcpu *vcpu) {}
#endif

#endif /* !__ASSEMBLY__ */

#endif /* __SVM_CARETAKER_H */
