/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 */
#ifndef __VMX_CARETAKER_H
#define __VMX_CARETAKER_H

#ifndef __ASSEMBLY__
#include <linux/types.h>
#include <linux/kvm_host.h>
#include <linux/oncore.h>
#include <asm/vmx.h>
#endif

#include "caretaker.h"

#ifndef __ASSEMBLY__
#include <asm/desc.h>
#include <linux/processor.h>

/* Default VMX preemption timer shift (counts down every 2^5 TSC ticks) */
#define VMX_PREEMPTION_TIMER_SHIFT	5

#include <asm/posted_intr.h>
#include "../vmx/vmx.h"

struct caretaker_vmx_page {
	struct caretaker_x86_page common;
	struct vcpu_vmx vmx;
	struct kvm_lapic apic;
	/* Guest syscall state not automatically switched by VMCS */
	u64 star;
	u64 lstar;
	u64 fmask;
	u64 vmcs_pa;
	u64 vmxon_pa;
	u32 timer_shift;
	u32 ple_supported;
	u8 vmxon_area[PAGE_SIZE] __aligned(PAGE_SIZE);
} __aligned(PAGE_SIZE);

void loaded_vmcs_clear(struct loaded_vmcs *loaded_vmcs);

extern const struct kvm_x86_caretaker_runtime_ops cpu_preserved_sym(vmx_caretaker_runtime_ops);

#ifndef __CPU_PRESERVED_RUNTIME__
#define vmx_caretaker_runtime_ops	__cpu_preserved_vmx_caretaker_runtime_ops
#endif

#if defined(CONFIG_KVM_CARETAKER) && defined(CONFIG_KVM_INTEL)
void vmx_caretaker_register(void);
void vmx_caretaker_unregister(void);
void vmx_caretaker_init(struct kvm_vcpu *vcpu);
#else
static inline void vmx_caretaker_register(void) {}
static inline void vmx_caretaker_unregister(void) {}
static inline void vmx_caretaker_init(struct kvm_vcpu *vcpu) {}
#endif

#endif /* !__ASSEMBLY__ */

#endif /* __VMX_CARETAKER_H */
