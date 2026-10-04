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
#include <linux/oncore.h>

#include <asm/apic.h>
#include <asm/cpu_entry_area.h>
#include <asm/desc.h>
#include <linux/pgtable.h>
#include <linux/processor.h>
#include <asm/set_memory.h>
#include <asm/svm.h>
#include <asm/tlbflush.h>

#include "caretaker.h"
#include "mmu.h"
#include "svm.h"
#include "../svm/svm_ops.h"

static int svm_caretaker_init_page(struct caretaker_svm_page *csp, struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	int ret;

	if (is_guest_mode(vcpu) || is_sev_guest(vcpu) ||
	    kvm_vcpu_apicv_activated(vcpu))
		return -EOPNOTSUPP;

	ret = kvm_x86_caretaker_init_common_page(&csp->common, vcpu, sizeof(*csp));
	if (ret)
		return ret;

	if (svm->vmcb01.ptr)
		csp->vmcb = *svm->vmcb01.ptr;
	csp->vmcb_pa = virt_to_phys(&csp->vmcb);
	csp->hsave_pa = virt_to_phys(csp->hsave_area);

	if (svm->msrpm)
		memcpy(csp->msrpm, svm->msrpm, MSRPM_SIZE);
	else
		memset(csp->msrpm, 0xff, MSRPM_SIZE);
	memset(csp->iopm, 0xff, IOPM_SIZE);
	csp->vmcb.control.msrpm_base_pa = virt_to_phys(csp->msrpm);
	csp->vmcb.control.iopm_base_pa = virt_to_phys(csp->iopm);
	vmcb_set_intercept(&csp->vmcb.control, INTERCEPT_MSR_PROT);
	vmcb_set_intercept(&csp->vmcb.control, INTERCEPT_IOIO_PROT);

	/* Enable HLT/CPUID/VMMCALL intercepts handled by standalone loop */
	vmcb_set_intercept(&csp->vmcb.control, INTERCEPT_HLT);
	vmcb_set_intercept(&csp->vmcb.control, INTERCEPT_PAUSE);
	csp->vmcb.control.pause_filter_count = 4096;
	csp->vmcb.control.pause_filter_thresh = 128;
	vmcb_clr_intercept(&csp->vmcb.control, INTERCEPT_RDTSC);
	vmcb_set_intercept(&csp->vmcb.control, INTERCEPT_VMMCALL);
	vmcb_set_intercept(&csp->vmcb.control, INTERCEPT_CPUID);
	vmcb_clr_intercept(&csp->vmcb.control, INTERCEPT_MONITOR);
	vmcb_clr_intercept(&csp->vmcb.control, INTERCEPT_MWAIT);
	vmcb_set_intercept(&csp->vmcb.control, INTERCEPT_NMI);
	vmcb_clr_intercept(&csp->vmcb.control, INTERCEPT_INTR);
	vmcb_set_intercept(&csp->vmcb.control, INTERCEPT_INIT);

	/*
	 * Clear interrupt-window intercepts and virtual IRQ injection state
	 * left behind in vmcb01 if vcpu_enter_guest() was aborted while
	 * KVM had an active interrupt window open (matching VMX clearing
	 * CPU_BASED_INTR_WINDOW_EXITING | CPU_BASED_NMI_WINDOW_EXITING).
	 */
	vmcb_clr_intercept(&csp->vmcb.control, INTERCEPT_VINTR);
	vmcb_clr_intercept(&csp->vmcb.control, INTERCEPT_IRET);
	vmcb_clr_intercept(&csp->vmcb.control, INTERCEPT_STGI);
	vmcb_clr_intercept(&csp->vmcb.control, INTERCEPT_CR8_WRITE);

	/* Clear VMCB clean bits and flush TLB for execution on Caretaker CPU */
	csp->vmcb.control.clean = 0;
	csp->vmcb.control.tlb_ctl = TLB_CONTROL_FLUSH_ALL_ASID;
	csp->vmcb.control.int_ctl &= ~V_IRQ_INJECTION_BITS_MASK;
	csp->vmcb.control.int_ctl |= V_INTR_MASKING_MASK;
	if (csp->vmcb.control.int_ctl & V_GIF_ENABLE_MASK)
		csp->vmcb.control.int_ctl |= V_GIF_MASK;
	csp->vmcb.control.int_vector = 0;
	csp->vmcb.control.int_state = 0;
	csp->vmcb.control.event_inj = 0;
	csp->vmcb.control.exit_int_info = 0;
	csp->vmcb.control.next_rip = 0;
	csp->vmcb.control.insn_len = 0;
	if (csp->vmcb.control.asid == 0)
		csp->vmcb.control.asid = 1;

	(void)kvm_read_cr0(vcpu);
	(void)kvm_read_cr3(vcpu);
	(void)kvm_read_cr4(vcpu);
	(void)kvm_rip_read(vcpu);
	(void)kvm_rsp_read(vcpu);
	(void)kvm_get_rflags(vcpu);

	csp->vmcb.save.rflags = kvm_get_rflags(vcpu);
	csp->vmcb.save.rax = vcpu->arch.regs[VCPU_REGS_RAX];
	csp->vmcb.save.rsp = kvm_rsp_read(vcpu);
	csp->vmcb.save.rip = kvm_rip_read(vcpu);

	kvm_x86_caretaker_init_vcpu(&csp->svm.vcpu, vcpu, &csp->common,
				    lapic_in_kernel(vcpu) ? &csp->apic : NULL);

	csp->svm.vmcb01.ptr = &csp->vmcb;
	csp->svm.vmcb01.pa = csp->vmcb_pa;
	csp->svm.current_vmcb = &csp->svm.vmcb01;
	csp->svm.vmcb = &csp->vmcb;
	csp->svm.asid = svm->asid;
	csp->svm.sysenter_esp_hi = svm->sysenter_esp_hi;
	csp->svm.sysenter_eip_hi = svm->sysenter_eip_hi;
	csp->svm.tsc_aux = svm->tsc_aux;
	csp->svm.msr_decfg = svm->msr_decfg;
	csp->svm.spec_ctrl = svm->spec_ctrl;
	csp->svm.tsc_ratio_msr = svm->tsc_ratio_msr;
	csp->svm.virt_spec_ctrl = svm->virt_spec_ctrl;
	csp->svm.msrpm = csp->msrpm;
	csp->svm.nested.hsave_msr = svm->nested.hsave_msr;
	csp->svm.nested.vm_cr_msr = svm->nested.vm_cr_msr;
	csp->svm.guest_gif = svm->guest_gif;

	return 0;
}

void svm_caretaker_init(struct kvm_vcpu *vcpu)
{
	struct caretaker_svm_page *csp;

	csp = kho_alloc_preserve(sizeof(*csp));
	if (IS_ERR(csp)) {
		pr_err("caretaker svm: failed to allocate preserved page\n");
		return;
	}

	if (svm_caretaker_init_page(csp, vcpu)) {
		kvm_x86_caretaker_unpreserve_pages(&csp->common.abi);
		vcpu->caretaker.cb = NULL;
		cpu_preserved_free_kho(csp, false);
	}
}

static void svm_caretaker_sync_vcpu(struct kvm_vcpu *vcpu, void *vcpu_data)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	kvm_x86_caretaker_sync_vcpu_common(vcpu);

	if (svm->vmcb) {
		svm->vmcb->control.next_rip = 0;
		svm->vmcb->control.insn_len = 0;
		svm->next_rip = 0;
		svm->vmcb->control.clean = 0;
		svm->vmcb->control.tlb_ctl = TLB_CONTROL_FLUSH_ALL_ASID;
		svm->vmcb->control.int_ctl &= ~V_IRQ_INJECTION_BITS_MASK;
		svm->vmcb->control.int_ctl |= V_INTR_MASKING_MASK;
		if (vgif)
			svm_set_gif(svm, true);
		svm_clr_intercept(svm, INTERCEPT_VINTR);
		svm->vmcb->control.int_state = 0;
		svm->nmi_masked = false;
		svm->nmi_singlestep = false;
		svm->awaiting_iret_completion = false;
		svm_set_intercept(svm, INTERCEPT_INTR);
		svm_set_intercept(svm, INTERCEPT_NMI);
		svm_set_intercept(svm, INTERCEPT_INIT);
		svm_clr_intercept(svm, INTERCEPT_RDTSC);
		svm_clr_intercept(svm, INTERCEPT_PAUSE);
		svm_recalc_intercepts(vcpu);
		svm->vmcb->control.event_inj = 0;
		svm->vmcb->control.exit_int_info = 0;
	}
}

static const struct kvm_x86_caretaker_ops svm_caretaker_ops = {
	.name = "svm",
	.init = svm_caretaker_init,
	.sync_vcpu = svm_caretaker_sync_vcpu,
	.runtime = &svm_caretaker_runtime_ops,
};

void svm_caretaker_register(void)
{
	kvm_x86_caretaker_register_ops(&svm_caretaker_ops);
}

void svm_caretaker_unregister(void)
{
	kvm_x86_caretaker_unregister_ops(&svm_caretaker_ops);
}
