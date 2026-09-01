/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SVM_CARETAKER_H
#define __SVM_CARETAKER_H

#ifndef __ASSEMBLY__
#include <linux/types.h>
#include <linux/kvm_host.h>
#include <linux/caretaker.h>
#include "svm.h"
#endif

#include "../caretaker.h"

#define CSP_VMCB_OFFSET		0x3000
#ifndef __ASSEMBLY__
#include "../caretaker.h"

struct caretaker_svm_page {
	struct caretaker_x86_page common;

	/* Page 3 (4KB): Preserved VMCB */
	struct vmcb vmcb __aligned(PAGE_SIZE);

	/* Page 4 (4KB): Preserved HSAVE area */
	u8 hsave_area[PAGE_SIZE] __aligned(PAGE_SIZE);
} __aligned(PAGE_SIZE);

u64 svm_caretaker_enter(struct caretaker_svm_page *csp);
void svm_caretaker_decode_exit(struct caretaker_svm_page *csp, struct kvm_caretaker_exit *exit);
void svm_caretaker_register(void);
void svm_caretaker_unregister(void);
enum caretaker_exit_reason
svm_caretaker_run_page(struct caretaker_svm_page *csp,
		       struct kvm_vcpu *vcpu, u64 deadline_ticks);

void svm_recalc_intercepts(struct kvm_vcpu *vcpu);
void svm_caretaker_init(struct kvm_vcpu *vcpu, u64 *cb_pa);
void svm_caretaker_signal_attach(struct kvm_vcpu *vcpu, u64 cb_pa);
void svm_caretaker_attach(struct kvm_vcpu *vcpu, u64 cb_pa);

#endif /* !__ASSEMBLY__ */

#endif /* __SVM_CARETAKER_H */
