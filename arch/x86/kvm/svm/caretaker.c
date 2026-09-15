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

#include <linux/cpu_preserve.h>
#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/kexec_handover.h>
#include <linux/kvm_host.h>
#include <linux/objtool.h>
#include <linux/oncore.h>

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

static int svm_caretaker_init_page(struct caretaker_svm_page *csp, struct kvm_vcpu *vcpu);
STACK_FRAME_NON_STANDARD(svm_caretaker_init_page);

static int svm_caretaker_init_page(struct caretaker_svm_page *csp, struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	int ret;

	ret = kvm_x86_caretaker_init_common_page(&csp->common, vcpu, sizeof(*csp));
	if (ret)
		return ret;

	if (svm->vmcb01.ptr)
		csp->vmcb = *svm->vmcb01.ptr;
	csp->common.vmcb_pa = virt_to_phys(&csp->vmcb);
	csp->common.hsave_pa = virt_to_phys(csp->hsave_area);

	/* Enable HLT/CPUID intercepts handled natively by standalone loop */
	vmcb_set_intercept(&csp->vmcb.control, INTERCEPT_HLT);
	vmcb_set_intercept(&csp->vmcb.control, INTERCEPT_PAUSE);
	csp->vmcb.control.pause_filter_count = 4096;
	csp->vmcb.control.pause_filter_thresh = 128;
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

	return 0;
}



void svm_caretaker_init(struct kvm_vcpu *vcpu)
{
	struct caretaker_svm_page *csp;
	int err;

	csp = kho_alloc_preserve(sizeof(*csp));
	if (IS_ERR(csp)) {
		pr_err("caretaker svm: failed to allocate preserved page\n");
		return;
	}

	csp->common.hsave_pa = virt_to_phys(csp->hsave_area);

	err = svm_caretaker_init_page(csp, vcpu);
	if (err)
		goto err_free;

	return;

err_free:
	vcpu->caretaker.cb = NULL;
	kho_unpreserve_free(csp);
}

static __cpu_preserved_text void
svm_caretaker_seg_to_kvm(struct kvm_segment *var, const struct vmcb_seg *s, int seg)
{
	var->base = s->base;
	var->limit = s->limit;
	var->selector = s->selector;
	var->type = s->attrib & SVM_SELECTOR_TYPE_MASK;
	var->s = (s->attrib >> SVM_SELECTOR_S_SHIFT) & 1;
	var->dpl = (s->attrib >> SVM_SELECTOR_DPL_SHIFT) & 3;
	var->present = (s->attrib >> SVM_SELECTOR_P_SHIFT) & 1;
	var->avl = (s->attrib >> SVM_SELECTOR_AVL_SHIFT) & 1;
	var->l = (s->attrib >> SVM_SELECTOR_L_SHIFT) & 1;
	var->db = (s->attrib >> SVM_SELECTOR_DB_SHIFT) & 1;
	var->g = s->limit > 0xfffff;
	var->unusable = !var->present;
	if (seg == VCPU_SREG_TR)
		var->type |= 0x2;
}

static __cpu_preserved_text void
svm_caretaker_detach_serialize(void *page, struct kvm_vcpu_arch_luo_state *state)
{
	struct caretaker_svm_page *csp = page;
	struct vmcb_save_area *save = &csp->vmcb.save;

	csp->common.cr0 = save->cr0;
	csp->common.cr3 = save->cr3;
	csp->common.cr4 = save->cr4;
	csp->common.efer = save->efer;
	csp->common.last_exit_rip = save->rip;
	csp->common.last_exit_rsp = save->rsp;
	csp->common.last_exit_rflags = save->rflags;

	kvm_x86_caretaker_detach_serialize_common(&csp->common, state);

	state->sregs.cr2 = save->cr2;
	svm_caretaker_seg_to_kvm(&state->sregs.cs, &save->cs, VCPU_SREG_CS);
	svm_caretaker_seg_to_kvm(&state->sregs.ds, &save->ds, VCPU_SREG_DS);
	svm_caretaker_seg_to_kvm(&state->sregs.es, &save->es, VCPU_SREG_ES);
	svm_caretaker_seg_to_kvm(&state->sregs.fs, &save->fs, VCPU_SREG_FS);
	svm_caretaker_seg_to_kvm(&state->sregs.gs, &save->gs, VCPU_SREG_GS);
	svm_caretaker_seg_to_kvm(&state->sregs.ss, &save->ss, VCPU_SREG_SS);
	svm_caretaker_seg_to_kvm(&state->sregs.tr, &save->tr, VCPU_SREG_TR);
	svm_caretaker_seg_to_kvm(&state->sregs.ldt, &save->ldtr, VCPU_SREG_LDTR);
	state->sregs.gdt.base = save->gdtr.base;
	state->sregs.gdt.limit = save->gdtr.limit;
	state->sregs.idt.base = save->idtr.base;
	state->sregs.idt.limit = save->idtr.limit;

	kvm_x86_caretaker_update_msr(state, MSR_STAR, save->star);
	kvm_x86_caretaker_update_msr(state, MSR_LSTAR, save->lstar);
	kvm_x86_caretaker_update_msr(state, MSR_CSTAR, save->cstar);
	kvm_x86_caretaker_update_msr(state, MSR_SYSCALL_MASK, save->sfmask);
	kvm_x86_caretaker_update_msr(state, MSR_KERNEL_GS_BASE, save->kernel_gs_base);
	kvm_x86_caretaker_update_msr(state, MSR_IA32_SYSENTER_CS, save->sysenter_cs);
	kvm_x86_caretaker_update_msr(state, MSR_IA32_SYSENTER_ESP, save->sysenter_esp);
	kvm_x86_caretaker_update_msr(state, MSR_IA32_SYSENTER_EIP, save->sysenter_eip);
}

static void svm_caretaker_sync_vcpu(struct kvm_vcpu *vcpu, void *vcpu_data)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	struct svm_cpu_data *sd = per_cpu_ptr(&svm_data, raw_smp_processor_id());

	if (sd && sd->save_area_pa)
		wrmsrq(MSR_VM_HSAVE_PA, sd->save_area_pa);

	kvm_x86_caretaker_sync_vcpu_common(vcpu);

	if (svm->vmcb) {
		if (!svm->vmcb->control.next_rip && svm->vmcb->control.insn_len)
			svm->vmcb->control.next_rip = kvm_rip_read(vcpu) +
						      svm->vmcb->control.insn_len;
		if (!svm->vmcb->control.next_rip) {
			switch (svm->vmcb->control.exit_code) {
			case SVM_EXIT_CPUID:
			case SVM_EXIT_MSR:
			case SVM_EXIT_PAUSE:
				svm->vmcb->control.next_rip = kvm_rip_read(vcpu) + 2;
				break;
			case SVM_EXIT_HLT:
				svm->vmcb->control.next_rip = kvm_rip_read(vcpu) + 1;
				break;
			case SVM_EXIT_VMMCALL:
			case SVM_EXIT_XSETBV:
			case SVM_EXIT_INVLPGA:
				svm->vmcb->control.next_rip = kvm_rip_read(vcpu) + 3;
				break;
			default:
				break;
			}
		}

		svm->vmcb->control.clean = 0;
		svm->vmcb->control.tlb_ctl = TLB_CONTROL_FLUSH_ALL_ASID;
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
svm_caretaker_decode_exit(void *page,
			  struct kvm_caretaker_exit *exit)
{
	struct caretaker_svm_page *csp = page;
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

	csp->orig_hsave_pa = native_rdmsrq(MSR_VM_HSAVE_PA);

	/* Ensure EFER_SVME is enabled and HSAVE is configured */
	efer = native_rdmsrq(MSR_EFER);
	native_wrmsrq(MSR_EFER, efer | EFER_SVME);
	native_wrmsrq(MSR_VM_HSAVE_PA, csp->common.hsave_pa);
}

static __cpu_preserved_text void
svm_caretaker_post_exit(void *page)
{
	struct caretaker_svm_page *csp = page;

	native_wrmsrq(MSR_VM_HSAVE_PA, csp->orig_hsave_pa);
	stgi();
}

static const struct kvm_x86_caretaker_ops svm_caretaker_ops __cpu_preserved_data = {
	.name = "svm",
	.init = svm_caretaker_init,
	.detach_serialize = svm_caretaker_detach_serialize,
	.common = {
		.enter_guest = svm_caretaker_enter,
		.decode_exit = svm_caretaker_decode_exit,
		.handle_arch_exit = kvm_x86_caretaker_handle_exit,
		.advance_rip = svm_caretaker_advance_rip,
		.arm_timer = svm_caretaker_arm_timer,
		.disarm_timer = svm_caretaker_disarm_timer,
		.pre_run = svm_caretaker_pre_enter,
		.post_run = svm_caretaker_post_exit,
		.sync_vcpu = svm_caretaker_sync_vcpu,
	},
};

void svm_caretaker_register(void)
{
	kvm_x86_caretaker_register_ops(&svm_caretaker_ops);
}

void svm_caretaker_unregister(void)
{
	kvm_x86_caretaker_unregister_ops(&svm_caretaker_ops);
}
