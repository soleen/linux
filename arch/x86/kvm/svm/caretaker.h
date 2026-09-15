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
#include "svm.h"
#endif

#include "../caretaker.h"

#define CSP_VMCB_OFFSET		0x1000
#define CSP_HSAVE_PA_OFFSET	0x3000
#define CSP_VMCB_PA_OFFSET	0x3010
#define VMCB_RAX_OFFSET		0x5f8

#ifndef __ASSEMBLY__

struct caretaker_svm_page {
	struct caretaker_x86_page common;

	/* Page 1 (4KB): Preserved VMCB */
	struct vmcb vmcb __aligned(PAGE_SIZE);

	/* Page 2 (4KB): Preserved HSAVE area */
	u8 hsave_area[PAGE_SIZE] __aligned(PAGE_SIZE);
	u64 hsave_pa;
	u64 orig_hsave_pa;
	u64 vmcb_pa;
	u64 orig_efer;

	/* Preserved MSR and I/O permission bitmaps referenced by VMCB */
	u8 msrpm[MSRPM_SIZE] __aligned(PAGE_SIZE);
	u8 iopm[IOPM_SIZE] __aligned(PAGE_SIZE);
} __aligned(PAGE_SIZE);

static_assert(offsetof(struct caretaker_svm_page, vmcb) == CSP_VMCB_OFFSET);
static_assert(offsetof(struct caretaker_svm_page, hsave_pa) == CSP_HSAVE_PA_OFFSET);
static_assert(offsetof(struct caretaker_svm_page, vmcb_pa) == CSP_VMCB_PA_OFFSET);

void svm_recalc_intercepts(struct kvm_vcpu *vcpu);

#ifdef CONFIG_KVM_CARETAKER
int svm_caretaker_enter(void *page);
void svm_caretaker_decode_exit(void *page, struct kvm_caretaker_exit *exit);
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
