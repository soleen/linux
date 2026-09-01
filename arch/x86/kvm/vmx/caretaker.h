/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __VMX_CARETAKER_H
#define __VMX_CARETAKER_H

#ifndef __ASSEMBLY__
#include <linux/types.h>
#include <linux/kvm_host.h>
#include <linux/caretaker.h>
#include <asm/vmx.h>
#endif

#include "../caretaker.h"

#ifndef __ASSEMBLY__
#include <asm/desc.h>
#include <asm/processor.h>
#include "../caretaker.h"

struct caretaker_vmx_page {
	struct caretaker_x86_page common;
} __aligned(PAGE_SIZE);

static inline unsigned long vmx_vmread(unsigned long field)
{
	unsigned long val;

	asm volatile("vmread %1, %0" : "=r" (val) : "r" (field) : "cc");
	return val;
}

static inline void vmx_vmwrite(unsigned long field, unsigned long val)
{
	asm volatile("vmwrite %1, %0" : : "r" (field), "r" (val) : "cc");
}

u64 vmx_caretaker_enter(struct caretaker_vmx_page *cvp);
void vmx_caretaker_exit_handler(void);
void vmx_caretaker_register(void);
void vmx_caretaker_unregister(void);
void vmx_caretaker_decode_exit(struct caretaker_vmx_page *cvp,
			       struct kvm_caretaker_exit *exit);
void vmx_caretaker_init_host_vmcs(struct caretaker_vmx_page *cvp);
void vmx_caretaker_sync_vcpu(struct caretaker_vmx_page *cvp,
			     struct kvm_vcpu *vcpu);

enum caretaker_exit_reason
vmx_caretaker_run_page(struct caretaker_vmx_page *cvp,
		       struct kvm_vcpu *vcpu, u64 deadline_ticks);

struct loaded_vmcs;
void loaded_vmcs_clear(struct loaded_vmcs *loaded_vmcs);
void vmx_caretaker_init(struct kvm_vcpu *vcpu, u64 *cb_pa);
void vmx_caretaker_signal_attach(struct kvm_vcpu *vcpu, u64 cb_pa);
void vmx_caretaker_attach(struct kvm_vcpu *vcpu, u64 cb_pa);

#endif /* !__ASSEMBLY__ */

#endif /* __VMX_CARETAKER_H */
