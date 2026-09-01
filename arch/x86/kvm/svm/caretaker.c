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

#include <linux/kernel.h>
#include <linux/kvm_host.h>
#include <linux/kexec_handover.h>
#include <linux/cpu_preserve.h>
#include <linux/caretaker.h>
#include <linux/delay.h>
#include <linux/objtool.h>
#include <asm/svm.h>
#include <asm/set_memory.h>
#include <asm/pgtable.h>
#include <asm/desc.h>
#include <asm/processor.h>
#include <asm/tlbflush.h>
#include <asm/apic.h>
#include <asm/cpu_entry_area.h>
#include "svm.h"
#include "svm_ops.h"
#include "mmu.h"
#include "caretaker.h"
#include "../caretaker.h"

static_assert(offsetof(struct caretaker_svm_page, common.gdt) == CXP_GDT_BASE);
static_assert(offsetof(struct caretaker_svm_page, common.tss) == CXP_TSS_BASE);
static_assert(offsetof(struct caretaker_svm_page, common.stack) == CXP_STACK_OFFSET);
static_assert(offsetof(struct caretaker_svm_page, vmcb) == CSP_VMCB_OFFSET);
static_assert(offsetof(struct caretaker_svm_page, common.idt) == CXP_IDT_BASE);

static void svm_caretaker_init_page(struct caretaker_svm_page *csp, struct kvm_vcpu *vcpu);
STACK_FRAME_NON_STANDARD(svm_caretaker_init_page);

static void svm_caretaker_init_page(struct caretaker_svm_page *csp, struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	if (!csp || !vcpu)
		return;

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
	if (!csp || IS_ERR(csp)) {
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

void svm_caretaker_signal_attach(struct kvm_vcpu *vcpu, u64 cb_pa)
{
	if (cb_pa) {
		struct caretaker_cb *cb = phys_to_virt(__sme_clr(cb_pa));
		struct caretaker_svm_page *csp = cb ?
			container_of(cb, struct caretaker_svm_page, common.cb) : NULL;

		if (csp && cb) {
			kvm_x86_caretaker_signal_attach_common(vcpu, cb, csp->common.apic_id,
							      &csp->common.running,
							      "svm");
		}
	}
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(svm_caretaker_signal_attach);

static void svm_caretaker_sync_vcpu(struct caretaker_svm_page *csp,
				    struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	kvm_x86_caretaker_sync_vcpu_common(vcpu, &csp->common);

	if (svm && svm->vmcb) {
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

void svm_caretaker_attach(struct kvm_vcpu *vcpu, u64 cb_pa)
{
	if (cb_pa) {
		struct caretaker_cb *cb = phys_to_virt(__sme_clr(cb_pa));
		struct caretaker_svm_page *csp = cb ?
			container_of(cb, struct caretaker_svm_page, common.cb) : NULL;

		if (csp && cb) {
			if (cb->pcpu_id < nr_cpu_ids)
				vcpu->cb.pcpu_id = cb->pcpu_id;

			vcpu_load(vcpu);
			svm_caretaker_sync_vcpu(csp, vcpu);
			vcpu_put(vcpu);
		}
	}
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(svm_caretaker_attach);

void __cpu_preserved_text
svm_caretaker_decode_exit(struct caretaker_svm_page *csp,
			  struct kvm_caretaker_exit *exit)
{
	struct vmcb *vmcb = &csp->vmcb;
	u64 exit_code = vmcb->control.exit_code;
	u64 info1 = vmcb->control.exit_info_1;
	u64 info2 = vmcb->control.exit_info_2;
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

		if (port >= 0x3f8 && port <= 0x3ff) {
			exit->type = KVM_CARETAKER_EXIT_CONSOLE;
			exit->mmio_io.addr = port;
			exit->mmio_io.is_write = !(info1 & 1);
			exit->mmio_io.size = (u8)((info1 >> 4) & 7);
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
		exit->type = KVM_CARETAKER_EXIT_IDLE;
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
		kvm_x86_caretaker_disarm_timer(csp->common.apic_lvtt_va);
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

STACK_FRAME_NON_STANDARD(svm_caretaker_run_page);

static __cpu_preserved_text void
svm_caretaker_advance_rip(void *page, u64 rip)
{
	struct caretaker_svm_page *csp = page;

	csp->vmcb.save.rip = rip;
	csp->common.last_exit_rip = rip;
	csp->common.last_exit_rsp = csp->vmcb.save.rsp;
}

enum caretaker_exit_reason __cpu_preserved_text __no_stack_protector
svm_caretaker_run_page(struct caretaker_svm_page *csp,
		       struct kvm_vcpu *vcpu, u64 deadline_ticks)
{
	enum caretaker_exit_reason reason;
	struct caretaker_x86_host_state host_state;
	int pcpu;

	if (!csp)
		return CARETAKER_EXIT_ERROR;

	pcpu = csp->common.pcpu_id;
	csp->common.deadline_tsc = deadline_ticks;

	/* Ensure EFER_SVME is enabled and HSAVE is configured */
	{
		u64 efer;

		rdmsrq(MSR_EFER, efer);
		wrmsrq(MSR_EFER, efer | EFER_SVME);
		wrmsrq(MSR_VM_HSAVE_PA, csp->common.hsave_pa);
	}

	/* Save host context, switch to Caretaker descriptors and CR3 */
	kvm_x86_caretaker_save_host_state(&host_state, &csp->common);

	if (deadline_ticks) {
		vmcb_set_intercept(&csp->vmcb.control, INTERCEPT_INTR);
		kvm_x86_caretaker_arm_timer(deadline_ticks, csp->common.apic_lvtt_va);
	} else {
		vmcb_clr_intercept(&csp->vmcb.control, INTERCEPT_INTR);
	}

	reason = kvm_x86_caretaker_run(&csp->common, deadline_ticks,
				       (caretaker_enter_fn)svm_caretaker_enter,
				       (caretaker_decode_exit_fn)svm_caretaker_decode_exit,
				       svm_caretaker_advance_rip);

	if (deadline_ticks) {
		kvm_x86_caretaker_disarm_timer(csp->common.apic_lvtt_va);
		vmcb_clr_intercept(&csp->vmcb.control, INTERCEPT_INTR);
	}

	kvm_x86_caretaker_restore_host_state(&host_state, &csp->common, vcpu, pcpu);
	stgi();

	if (reason == CARETAKER_EXIT_ATTACH_SIGNALED ||
	    READ_ONCE(csp->common.cb.attachment_state) == CARETAKER_KVM_ATTACHING) {
		WRITE_ONCE(csp->common.cb.attachment_state, CARETAKER_KVM_ATTACHED);
		smp_mb();
	}

	/* Sync updated guest VMCB state and GPRs back to vcpu on cancel */
	if (reason != CARETAKER_EXIT_ATTACH_SIGNALED &&
	    vcpu && READ_ONCE(csp->common.cb.attachment_state) == CARETAKER_KVM_DETACHED)
		svm_caretaker_sync_vcpu(csp, vcpu);

	return reason;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(svm_caretaker_run_page);

static enum caretaker_exit_reason __cpu_preserved_text
svm_caretaker_run_op(void *data, u64 deadline_ticks)
{
	struct caretaker_cb *cb = data;
	struct caretaker_svm_page *csp = cb ?
		container_of(cb, struct caretaker_svm_page, common.cb) : NULL;

	return svm_caretaker_run_page(csp, NULL, deadline_ticks);
}

static const struct kvm_x86_caretaker_ops svm_caretaker_ops __cpu_preserved_data = {
	.init = svm_caretaker_init,
	.signal_attach = svm_caretaker_signal_attach,
	.attach = svm_caretaker_attach,
	.run_job = svm_caretaker_run_op,
};

void svm_caretaker_register(void)
{
	kvm_x86_caretaker_register_ops(&svm_caretaker_ops);
}

void svm_caretaker_unregister(void)
{
	kvm_x86_caretaker_unregister_ops(&svm_caretaker_ops);
}
