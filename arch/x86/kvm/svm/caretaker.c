// SPDX-License-Identifier: GPL-2.0-only
/*
 * AMD SVM Caretaker Standalone Execution Engine
 *
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * Runs the AMD SVM guest VMRUN loop in an isolated, KHO-preserved memory
 * page that remains alive and executing across kexec relocation and
 * kernel handover.
 */

#include <linux/caretaker.h>
#include <linux/cpu_preserve.h>
#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/kexec_handover.h>
#include <linux/kvm_host.h>
#include <linux/objtool.h>

#include <asm/apic.h>
#include <asm/cpu_entry_area.h>
#include <asm/desc.h>
#include <asm/pgtable.h>
#include <asm/processor.h>
#include <asm/set_memory.h>
#include <asm/svm.h>
#include <asm/tlbflush.h>

#include "../caretaker.h"
#include "caretaker.h"
#include "mmu.h"
#include "svm.h"
#include "svm_ops.h"

static void svm_caretaker_init_page(struct caretaker_svm_page *csp, struct kvm_vcpu *vcpu);
STACK_FRAME_NON_STANDARD(svm_caretaker_init_page);

static void svm_caretaker_init_page(struct caretaker_svm_page *csp, struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	kvm_x86_caretaker_init_common_page(&csp->common, vcpu, sizeof(*csp));

	if (svm->vmcb01.ptr)
		csp->vmcb = *svm->vmcb01.ptr;
	csp->common.vmcb_pa = virt_to_phys(&csp->vmcb);
	csp->common.hsave_pa = virt_to_phys(csp->hsave_area);

	/* Enable HLT/CPUID intercepts handled natively by standalone loop */
	vmcb_set_intercept(&csp->vmcb.control, INTERCEPT_HLT);
	vmcb_clr_intercept(&csp->vmcb.control, INTERCEPT_PAUSE);
	vmcb_clr_intercept(&csp->vmcb.control, INTERCEPT_RDTSC);
	vmcb_clr_intercept(&csp->vmcb.control, INTERCEPT_VMMCALL);
	vmcb_set_intercept(&csp->vmcb.control, INTERCEPT_CPUID);
	vmcb_clr_intercept(&csp->vmcb.control, INTERCEPT_MONITOR);
	vmcb_clr_intercept(&csp->vmcb.control, INTERCEPT_MWAIT);
	vmcb_set_intercept(&csp->vmcb.control, INTERCEPT_NMI);
	vmcb_clr_intercept(&csp->vmcb.control, INTERCEPT_INTR);
	vmcb_set_intercept(&csp->vmcb.control, INTERCEPT_INIT);

	/* Clear VMCB clean bits and flush TLB for execution on Caretaker CPU */
	csp->vmcb.control.clean = 0;
	csp->vmcb.control.tlb_ctl = TLB_CONTROL_FLUSH_ALL_ASID;
	csp->vmcb.control.int_ctl &= ~V_INTR_MASKING_MASK;
	if (csp->vmcb.control.asid == 0)
		csp->vmcb.control.asid = 1;
	csp->vmcb.save.rflags = kvm_get_rflags(vcpu);
	csp->vmcb.save.rax = csp->common.rax;
	csp->vmcb.save.rsp = kvm_rsp_read(vcpu);
	csp->vmcb.save.rip = kvm_rip_read(vcpu);
	csp->common.cr3 = csp->vmcb.save.cr3;
	csp->common.cr0 = csp->vmcb.save.cr0;
	csp->common.cr4 = csp->vmcb.save.cr4;
	csp->common.efer = csp->vmcb.save.efer;
	csp->common.last_exit_rsp = csp->vmcb.save.rsp;
	csp->common.last_exit_rip = csp->vmcb.save.rip;
	csp->common.last_exit_rflags = csp->vmcb.save.rflags;
}



void svm_caretaker_init(struct kvm_vcpu *vcpu, u64 *cb_pa)
{
	struct caretaker_svm_page *csp;

	csp = kho_alloc_preserve(sizeof(*csp));
	if (IS_ERR(csp)) {
		pr_err("caretaker svm: failed to allocate preserved page\n");
		if (cb_pa)
			*cb_pa = 0;
		return;
	}

	csp->common.hsave_pa = virt_to_phys(csp->hsave_area);

	kvm_mmu_preserve_kho(vcpu->kvm);

	svm_caretaker_init_page(csp, vcpu);
	vcpu->arch.cb_pa = virt_to_phys(&csp->common.cb);
	if (cb_pa)
		*cb_pa = vcpu->arch.cb_pa;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(svm_caretaker_init);

static void svm_caretaker_sync_vcpu(void *page, struct kvm_vcpu *vcpu)
{
	struct caretaker_svm_page *csp = page;
	struct vcpu_svm *svm = to_svm(vcpu);

	kvm_x86_caretaker_sync_vcpu_common(vcpu, &csp->common);

	if (svm->vmcb) {
		svm->vmcb->save = csp->vmcb.save;
		svm->vmcb->control.clean = 0;
		svm->vmcb->control.tlb_ctl = TLB_CONTROL_FLUSH_ALL_ASID;
		svm_set_efer(vcpu, csp->vmcb.save.efer);
		svm_set_cr0(vcpu, csp->vmcb.save.cr0);
		svm_set_cr4(vcpu, csp->vmcb.save.cr4);
		vcpu->arch.cr2 = csp->vmcb.save.cr2;
		svm_set_intercept(svm, INTERCEPT_INTR);
		svm_clr_intercept(svm, INTERCEPT_RDTSC);
		svm_clr_intercept(svm, INTERCEPT_PAUSE);
		svm_clr_intercept(svm, INTERCEPT_INIT);
		svm_recalc_intercepts(vcpu);
		svm->vmcb->control.event_inj = 0;
		svm->vmcb->control.exit_int_info = 0;
	}
}

void __cpu_preserved_text
svm_caretaker_decode_exit(struct caretaker_svm_page *csp,
			  struct kvm_caretaker_exit *exit)
{
	u64 exit_code = csp->vmcb.control.exit_code;
	u64 info1 = csp->vmcb.control.exit_info_1;
	u64 info2 = csp->vmcb.control.exit_info_2;
	struct vmcb *vmcb = &csp->vmcb;
	u64 rip = vmcb->save.rip;
	u32 insn_len;

	if (vmcb->control.next_rip && vmcb->control.next_rip > rip)
		insn_len = vmcb->control.next_rip - rip;
	else
		insn_len = vmcb->control.insn_len;

	csp->common.last_exit_code = exit_code;
	csp->common.last_exit_info1 = info1;
	csp->common.last_exit_info2 = info2;
	csp->common.last_exit_rip = rip;
	csp->common.last_exit_rsp = vmcb->save.rsp;
	csp->common.last_exit_rflags = vmcb->save.rflags;
	csp->common.cr3 = vmcb->save.cr3;
	csp->common.cr0 = vmcb->save.cr0;
	csp->common.cr4 = vmcb->save.cr4;
	csp->common.efer = vmcb->save.efer;
	vmcb->control.exit_int_info = 0;

	memset(exit, 0, sizeof(*exit));
	exit->rip = rip;
	exit->insn_len = insn_len;
	exit->raw_reason = exit_code;
	exit->type = KVM_CARETAKER_EXIT_ARCH;

	switch (exit_code) {
	case SVM_EXIT_IOIO: {
		u16 port = (u16)(info1 >> 16);

		if (!exit->insn_len && info2 > rip)
			exit->insn_len = (u32)(info2 - rip);

		if (port >= COM1_PORT_BASE && port <= COM1_PORT_END) {
			exit->type = KVM_CARETAKER_EXIT_CONSOLE;
			exit->mmio_io.addr = port;
			exit->mmio_io.is_write = !(info1 & SVM_IOIO_TYPE_MASK);
			exit->mmio_io.size = (u8)((info1 & SVM_IOIO_SIZE_MASK) >>
						  SVM_IOIO_SIZE_SHIFT);
			exit->mmio_io.is_mmio = false;
			exit->mmio_io.val_ptr = &csp->common.rax;
		}
		break;
	}
	case SVM_EXIT_HLT:
		exit->type = KVM_CARETAKER_EXIT_IDLE;
		if (!exit->insn_len)
			exit->insn_len = 1;
		break;
	case SVM_EXIT_PAUSE:
		exit->type = KVM_CARETAKER_EXIT_INSN_STEP;
		if (!exit->insn_len)
			exit->insn_len = 2;
		break;
	case SVM_EXIT_CPUID:
		exit->type = KVM_CARETAKER_EXIT_CPUID;
		if (!exit->insn_len)
			exit->insn_len = 2;
		break;
	case SVM_EXIT_MSR:
		exit->type = KVM_CARETAKER_EXIT_MSR;
		exit->msr.msr = (u32)csp->common.rcx;
		exit->msr.is_write = (info1 != 0);
		if (!exit->insn_len)
			exit->insn_len = 2;
		break;
	case SVM_EXIT_INVD:
	case SVM_EXIT_WBINVD:
		exit->type = KVM_CARETAKER_EXIT_INSN_STEP;
		if (!exit->insn_len)
			exit->insn_len = 2;
		break;
	case SVM_EXIT_XSETBV:
	case SVM_EXIT_VMMCALL:
		exit->type = KVM_CARETAKER_EXIT_INSN_STEP;
		if (!exit->insn_len)
			exit->insn_len = 3;
		break;
	case SVM_EXIT_NPF:
		exit->type = KVM_CARETAKER_EXIT_UNHANDLED;
		break;
	case SVM_EXIT_INTR:
		kvm_x86_caretaker_disarm_timer();
		asm volatile("sti\n\tnop\n\tcli" : : : "memory");
		exit->type = KVM_CARETAKER_EXIT_PREEMPT_TIMER;
		exit->insn_len = 0;
		break;
	case SVM_EXIT_NMI:
	case SVM_EXIT_INIT:
		exit->type = KVM_CARETAKER_EXIT_PREEMPT_TIMER;
		exit->insn_len = 0;
		break;
	case SVM_EXIT_RDTSC:
		exit->type = KVM_CARETAKER_EXIT_RDTSC;
		if (!exit->insn_len)
			exit->insn_len = 2;
		break;
	case SVM_EXIT_RDTSCP:
		exit->type = KVM_CARETAKER_EXIT_RDTSC;
		if (!exit->insn_len)
			exit->insn_len = 3;
		break;
	default:
		break;
	}
}

static __cpu_preserved_text void
svm_caretaker_advance_rip(void *page, u64 rip)
{
	struct caretaker_svm_page *csp = page;

	csp->vmcb.save.rip = rip;
	csp->common.last_exit_rip = rip;
	csp->common.last_exit_rsp = csp->vmcb.save.rsp;
}

static __cpu_preserved_text void
svm_caretaker_arm_timer(void *page, u64 deadline_ticks)
{
	struct caretaker_svm_page *csp = page;

	if (deadline_ticks) {
		vmcb_set_intercept(&csp->vmcb.control, INTERCEPT_INTR);
		kvm_x86_caretaker_arm_timer(deadline_ticks);
	} else {
		vmcb_clr_intercept(&csp->vmcb.control, INTERCEPT_INTR);
	}
}

static __cpu_preserved_text void
svm_caretaker_disarm_timer(void *page)
{
	struct caretaker_svm_page *csp = page;

	kvm_x86_caretaker_disarm_timer();
	vmcb_clr_intercept(&csp->vmcb.control, INTERCEPT_INTR);
}

static __cpu_preserved_text void
svm_caretaker_pre_enter(void *page)
{
	struct caretaker_svm_page *csp = page;
	u64 efer;

	/* Ensure EFER_SVME is enabled and HSAVE is configured */
	rdmsrq(MSR_EFER, efer);
	wrmsrq(MSR_EFER, efer | EFER_SVME);
	wrmsrq(MSR_VM_HSAVE_PA, csp->common.hsave_pa);
}

static __cpu_preserved_text void
svm_caretaker_post_exit(void *page)
{
	stgi();
}

static const struct kvm_x86_caretaker_ops svm_caretaker_ops __cpu_preserved_data = {
	.name = "svm",
	.init = svm_caretaker_init,
	.sync_vcpu = svm_caretaker_sync_vcpu,
	.enter_guest = (caretaker_enter_fn)svm_caretaker_enter,
	.decode_exit = (caretaker_decode_exit_fn)svm_caretaker_decode_exit,
	.advance_rip = svm_caretaker_advance_rip,
	.arm_timer = svm_caretaker_arm_timer,
	.disarm_timer = svm_caretaker_disarm_timer,
	.pre_enter = svm_caretaker_pre_enter,
	.post_exit = svm_caretaker_post_exit,
};

void svm_caretaker_register(void)
{
	kvm_x86_caretaker_register_ops(&svm_caretaker_ops);
}

void svm_caretaker_unregister(void)
{
	kvm_x86_caretaker_unregister_ops(&svm_caretaker_ops);
}
