// SPDX-License-Identifier: GPL-2.0-only
/*
 * AMD SVM Caretaker Standalone Execution Engine
 *
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * Runs the AMD SVM guest execution loop in an isolated, KHO-preserved
 * context using KVM's native __svm_vcpu_run world switch and VMCB helpers.
 */

#include <linux/cpu_preserve.h>
#include <linux/kernel.h>
#include <linux/kvm_host.h>
#include <linux/oncore.h>

#include <asm/apic.h>
#include <asm/desc.h>
#include <asm/msr.h>
#include <asm/svm.h>

#include "caretaker.h"
#include "lapic.h"
#include "regs.h"
#include "svm.h"
#include "switch.h"
#include "vmenter.h"
#include "x86.h"
#include "../svm/switch.h"

static int svm_caretaker_enter(struct caretaker_x86_page *cxp, u32 *exit_code)
{
	struct caretaker_svm_page *csp =
		container_of(cxp, struct caretaker_svm_page, common);
	struct vcpu_svm *svm = &csp->svm;
	struct kvm_vcpu *vcpu = &svm->vcpu;
	unsigned long cr3 = __native_read_cr3();

	asm volatile("clgi\n\tsti" : : : "memory");

	if (csp->hsave_pa)
		asm volatile("vmsave %0" : : "a"(csp->hsave_pa) : "memory");

	svm->vmcb->save.rax = vcpu->arch.regs[VCPU_REGS_RAX];
	svm->vmcb->save.rsp = vcpu->arch.regs[VCPU_REGS_RSP];
	svm->vmcb->save.rip = vcpu->arch.rip;
	svm->vmcb->save.cr2 = vcpu->arch.cr2;
	svm->vmcb->control.next_rip = 0;
	svm->vmcb->control.insn_len = 0;
	kvm_reset_dirty_registers(vcpu);

	__svm_vcpu_run(svm, 0);
	svm->vmcb->control.tlb_ctl = TLB_CONTROL_DO_NOTHING;

	asm volatile("cli" : : : "memory");

	if (csp->hsave_pa)
		asm volatile("vmload %0" : : "a"(csp->hsave_pa) : "memory");

	if (__native_read_cr3() != cr3)
		native_write_cr3(cr3);

	asm volatile("stgi" : : : "memory");

	vcpu->arch.cr2 = svm->vmcb->save.cr2;
	vcpu->arch.regs[VCPU_REGS_RAX] = svm->vmcb->save.rax;
	vcpu->arch.regs[VCPU_REGS_RSP] = svm->vmcb->save.rsp;
	vcpu->arch.rip = svm->vmcb->save.rip;
	vcpu->arch.cr0 = svm->vmcb->save.cr0;
	vcpu->arch.cr3 = svm->vmcb->save.cr3;
	vcpu->arch.cr4 = svm->vmcb->save.cr4;
	vcpu->arch.efer = svm->vmcb->save.efer & ~EFER_SVME;
	svm->next_rip = 0;

	if (unlikely(svm->vmcb->control.exit_code == SVM_EXIT_ERR))
		return -1;

	svm->vmcb->control.exit_int_info = 0;
	*exit_code = svm->vmcb->control.exit_code;
	return 0;
}

static int svm_caretaker_handle_exit(struct caretaker_x86_page *cxp,
				     u32 exit_code,
				     enum oncore_exit_reason *reason)
{
	struct caretaker_svm_page *csp =
		container_of(cxp, struct caretaker_svm_page, common);
	struct kvm_vcpu *vcpu = &csp->svm.vcpu;
	int ret = 0;

	switch (exit_code) {
	case SVM_EXIT_INTR:
		kvm_x86_caretaker_disarm_timer();
		asm volatile("sti\n\tnop\n\tpause\n\tcli" : : : "memory");
		intr_interception(vcpu);
		return 0;
	case SVM_EXIT_NMI:
		nmi_interception(vcpu);
		return 0;
	case SVM_EXIT_SMI:
		smi_interception(vcpu);
		return 0;
	case SVM_EXIT_INIT:
		return 0;
	default:
		if (exit_code < ARRAY_SIZE(svm_exit_handlers) &&
		    svm_exit_handlers[exit_code])
			ret = svm_exit_handlers[exit_code](vcpu);
		break;
	}

	if (ret <= 0)
		return -1;

	if (exit_code == SVM_EXIT_HLT || exit_code == SVM_EXIT_IDLE_HLT ||
	    exit_code == SVM_EXIT_PAUSE) {
		*reason = ONCORE_EXIT_YIELD_IDLE;
		return 0;
	}

	return 1;
}

static void
svm_caretaker_arm_timer(void *page, u64 deadline_ticks)
{
	struct caretaker_svm_page *csp = page;

	if (deadline_ticks && deadline_ticks != U64_MAX) {
		vmcb_set_intercept(&csp->svm.vmcb->control, INTERCEPT_INTR);
		kvm_x86_caretaker_arm_timer(deadline_ticks);
	}
}

static void
svm_caretaker_disarm_timer(void *page)
{
	struct caretaker_svm_page *csp = page;

	kvm_x86_caretaker_disarm_timer();
	vmcb_clr_intercept(&csp->svm.vmcb->control, INTERCEPT_INTR);
	asm volatile("sti\n\tnop\n\tpause\n\tcli" : : : "memory");
}

static void
svm_caretaker_pre_enter(void *page)
{
	struct caretaker_svm_page *csp = page;
	u64 efer;

	csp->orig_hsave_pa = native_rdmsrq(MSR_VM_HSAVE_PA);

	/* Ensure EFER_SVME is enabled and HSAVE is configured */
	efer = native_rdmsrq(MSR_EFER);
	csp->orig_efer = efer;
	native_wrmsrq(MSR_EFER, efer | EFER_SVME);
	native_wrmsrq(MSR_VM_HSAVE_PA, csp->hsave_pa);

	csp->svm.vmcb->control.tlb_ctl = TLB_CONTROL_FLUSH_ALL_ASID;
	vmcb_set_intercept(&csp->svm.vmcb->control, INTERCEPT_INTR);
	kvm_x86_caretaker_disarm_timer();
	asm volatile("sti\n\tnop\n\tpause\n\tcli" : : : "memory");
}

static void
svm_caretaker_post_exit(void *page)
{
	struct caretaker_svm_page *csp = page;

	native_wrmsrq(MSR_VM_HSAVE_PA, csp->orig_hsave_pa);
	asm volatile("1: stgi\n\t"
		     "2:\n\t"
		     _ASM_EXTABLE(1b, 2b)
		     : : : "memory");
	if (!(csp->orig_efer & EFER_SVME))
		native_wrmsrq(MSR_EFER, native_rdmsrq(MSR_EFER) & ~EFER_SVME);
}

static const struct kvm_x86_ops svm_caretaker_x86_ops = {
	.get_msr = svm_get_msr,
	.set_msr = svm_set_msr,
	.get_segment = svm_get_segment,
	.get_gdt = svm_get_gdt,
	.get_idt = svm_get_idt,
	.get_cpl = svm_get_cpl,
	.get_cs_db_l_bits = svm_get_cs_db_l_bits,
	.cache_reg = svm_cache_reg,
	.get_rflags = svm_get_rflags,
	.set_rflags = svm_set_rflags,
	.get_interrupt_shadow = svm_get_interrupt_shadow,
	.set_interrupt_shadow = svm_set_interrupt_shadow,
	.skip_emulated_instruction = __svm_skip_emulated_insn,
};

const struct kvm_x86_caretaker_runtime_ops svm_caretaker_runtime_ops = {
	.x86_ops = &svm_caretaker_x86_ops,
	.enter = svm_caretaker_enter,
	.handle_exit = svm_caretaker_handle_exit,
	.arm_timer = svm_caretaker_arm_timer,
	.disarm_timer = svm_caretaker_disarm_timer,
	.pre_run = svm_caretaker_pre_enter,
	.post_run = svm_caretaker_post_exit,
};
