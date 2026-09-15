// SPDX-License-Identifier: GPL-2.0-only
/*
 * Intel VMX Caretaker Standalone Execution Engine
 *
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * Runs the Intel VMX guest execution loop in an isolated, KHO-preserved memory
 * page that remains alive and executing across kexec relocation and
 * kernel handover.
 */

#include <linux/cleanup.h>
#include <linux/cpu_preserve.h>
#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/kexec.h>
#include <linux/kexec_handover.h>
#include <linux/kvm_host.h>
#include <linux/objtool.h>
#include <linux/oncore.h>

#include <asm/apic.h>
#include <asm/cpu_entry_area.h>
#include <asm/desc.h>
#include <asm/fixmap.h>
#include <asm/pgtable.h>
#include <asm/processor.h>
#include <asm/segment.h>
#include <asm/set_memory.h>
#include <asm/virt.h>
#include <asm/vmx.h>

#include "../caretaker.h"
#include "caretaker.h"
#include "vmx.h"
#include "vmx_ops.h"
#include "x86.h"
#include "x86_ops.h"

static int vmx_caretaker_init_page(struct caretaker_vmx_page *cvp,
				   struct kvm_vcpu *vcpu);
STACK_FRAME_NON_STANDARD(vmx_caretaker_init_page);

static int vmx_caretaker_init_page(struct caretaker_vmx_page *cvp,
				   struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	u64 basic_msr, misc_msr;
	int ret;

	if (!vmx->vmcs01.vmcs)
		return -EINVAL;

	ret = kvm_x86_caretaker_init_common_page(&cvp->common, vcpu, sizeof(*cvp));
	if (ret)
		return ret;
	cvp->common.vmcs_pa = virt_to_phys(vmx->vmcs01.vmcs);
	cvp->common.abi.vmcs_pa = cvp->common.vmcs_pa;
	cvp->common.vmxon_pa = virt_to_phys(cvp->vmxon_area);

	memset(cvp->vmxon_area, 0, PAGE_SIZE);
	basic_msr = native_rdmsrq(MSR_IA32_VMX_BASIC);
	*(u32 *)cvp->vmxon_area = vmx_basic_vmcs_revision_id(basic_msr);

	if (!rdmsrq_safe(MSR_IA32_VMX_MISC, &misc_msr))
		cvp->timer_shift = vmx_misc_preemption_timer_rate(misc_msr);
	else
		cvp->timer_shift = VMX_PREEMPTION_TIMER_SHIFT;

	cvp->ple_supported = cpu_has_vmx_ple();

	vcpu_load(vcpu);

	cvp->common.kernel_gs_base = vmx->msr_guest_kernel_gs_base;
	kvm_msr_read(vcpu, MSR_STAR, &cvp->star);
	kvm_msr_read(vcpu, MSR_LSTAR, &cvp->lstar);
	kvm_msr_read(vcpu, MSR_SYSCALL_MASK, &cvp->fmask);

	/* Save current guest control registers from KVM */
	cvp->common.cr0 = kvm_read_cr0(vcpu);
	cvp->common.cr3 = kvm_read_cr3(vcpu);
	cvp->common.cr4 = kvm_read_cr4(vcpu);
	cvp->common.efer = vcpu->arch.efer;

	cvp->common.last_exit_rip = kvm_rip_read(vcpu);
	cvp->common.last_exit_rsp = kvm_rsp_read(vcpu);
	cvp->common.last_exit_rflags = kvm_get_rflags(vcpu);

	if (kvm_host.efer & EFER_NX)
		cvp->common.efer |= EFER_NX;

	vcpu_put(vcpu);

	if (vmx->loaded_vmcs)
		loaded_vmcs_clear(vmx->loaded_vmcs);

	return 0;
}

/*
 * Scope-based unwind for KHO page preservations.  A page is only assigned to
 * one of these variables *after* kho_preserve_pages() has succeeded for it, so
 * the cleanup never tries to unpreserve a page that was never preserved.
 */
DEFINE_FREE(kho_unpreserve_page, struct page *,
	if (_T)
		kho_unpreserve_pages(_T, 1))

void vmx_caretaker_init(struct kvm_vcpu *vcpu, u64 *cb_pa)
{
	struct page *msr_bitmap_pg __free(kho_unpreserve_page) = NULL;
	struct page *pid_table_pg __free(kho_unpreserve_page) = NULL;
	struct page *ve_info_pg __free(kho_unpreserve_page) = NULL;
	struct page *vmcs_pg __free(kho_unpreserve_page) = NULL;
	struct page *pml_pg __free(kho_unpreserve_page) = NULL;
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct kvm_vmx *kvm_vmx = to_kvm_vmx(vcpu->kvm);
	struct caretaker_vmx_page *cvp;
	int err;

	cvp = kho_alloc_preserve(sizeof(*cvp));
	if (IS_ERR(cvp)) {
		pr_err("caretaker vmx: failed to allocate preserved page\n");
		if (cb_pa)
			*cb_pa = 0;
		return;
	}

	if (vmx->vmcs01.vmcs) {
		struct page *pg = virt_to_page(vmx->vmcs01.vmcs);

		if (kho_preserve_pages(pg, 1))
			goto err_free;
		vmcs_pg = pg;
	}
	if (vmx->vmcs01.msr_bitmap) {
		struct page *pg = virt_to_page(vmx->vmcs01.msr_bitmap);

		if (kho_preserve_pages(pg, 1))
			goto err_free;
		msr_bitmap_pg = pg;
	}
	if (vmx->pml_pg) {
		if (kho_preserve_pages(vmx->pml_pg, 1))
			goto err_free;
		pml_pg = vmx->pml_pg;
	}
	if (vmx->ve_info) {
		struct page *pg = virt_to_page(vmx->ve_info);

		if (kho_preserve_pages(pg, 1))
			goto err_free;
		ve_info_pg = pg;
	}
	if (kvm_vmx->pid_table) {
		struct page *pg = virt_to_page(kvm_vmx->pid_table);

		if (kho_preserve_pages(pg, 1))
			goto err_free;
		pid_table_pg = pg;
	}

	err = vmx_caretaker_init_page(cvp, vcpu);
	if (err)
		goto err_free;

	/* Committed: the preservations must survive this function. */
	retain_and_null_ptr(vmcs_pg);
	retain_and_null_ptr(msr_bitmap_pg);
	retain_and_null_ptr(pml_pg);
	retain_and_null_ptr(ve_info_pg);
	retain_and_null_ptr(pid_table_pg);

	vcpu->arch.cb_pa = virt_to_phys(&cvp->common.abi.cb);
	if (cb_pa)
		*cb_pa = vcpu->arch.cb_pa;
	return;

err_free:
	kho_unpreserve_free(cvp);
	if (cb_pa)
		*cb_pa = 0;
}

static void vmx_caretaker_signal_attach(struct kvm_vcpu *vcpu, struct kvm_caretaker_cb *cb)
{
	if (vcpu) {
		struct vcpu_vmx *vmx = to_vmx(vcpu);

		if (vmx->loaded_vmcs)
			loaded_vmcs_clear(vmx->loaded_vmcs);
	}
}

static __cpu_preserved_text void vmx_caretaker_disarm_timer(void *page)
{
	u32 pin = (u32)vmx_vmread(PIN_BASED_VM_EXEC_CONTROL);

	if (pin & PIN_BASED_VMX_PREEMPTION_TIMER) {
		vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL,
			    pin & ~PIN_BASED_VMX_PREEMPTION_TIMER);
	}
}

static inline unsigned long vmx_caretaker_read_cr0(void)
{
	unsigned long mask = vmx_vmread(CR0_GUEST_HOST_MASK);

	return (vmx_vmread(CR0_READ_SHADOW) & mask) |
	       (vmx_vmread(GUEST_CR0) & ~mask);
}

static inline unsigned long vmx_caretaker_read_cr4(void)
{
	unsigned long mask = vmx_vmread(CR4_GUEST_HOST_MASK);

	return (vmx_vmread(CR4_READ_SHADOW) & mask) |
	       (vmx_vmread(GUEST_CR4) & ~mask);
}

static inline u64 vmx_caretaker_read_efer(void)
{
	u64 efer = vmx_vmread(GUEST_IA32_EFER);

	if (!efer)
		efer = native_rdmsrq(MSR_EFER);
	if (vmx_vmread(VM_ENTRY_CONTROLS) & VM_ENTRY_IA32E_MODE)
		efer |= EFER_LMA | EFER_LME;
	return efer;
}

void __cpu_preserved_text
vmx_caretaker_decode_exit(void *page,
			  struct kvm_caretaker_exit *exit)
{
	struct caretaker_vmx_page *cvp = page;
	u32 insn_len = (u32)vmx_vmread(VM_EXIT_INSTRUCTION_LEN);
	u16 exit_reason = (u16)vmx_vmread(VM_EXIT_REASON);
	u64 qual = vmx_vmread(EXIT_QUALIFICATION);
	u64 rip = vmx_vmread(GUEST_RIP);

	cvp->common.last_exit_code = exit_reason;
	cvp->common.last_exit_qual = qual;
	cvp->common.last_exit_rip = rip;
	cvp->common.last_exit_rsp = vmx_vmread(GUEST_RSP);
	cvp->common.last_exit_rflags = vmx_vmread(GUEST_RFLAGS);
	cvp->common.cr3 = vmx_vmread(GUEST_CR3);
	cvp->common.cr0 = vmx_caretaker_read_cr0();
	cvp->common.cr4 = vmx_caretaker_read_cr4();

	memset(exit, 0, sizeof(*exit));
	exit->rip = rip;
	exit->insn_len = insn_len;
	exit->raw_reason = exit_reason;
	exit->type = KVM_CARETAKER_EXIT_ARCH;

	switch (exit_reason) {
	case EXIT_REASON_IO_INSTRUCTION: {
		u16 port = (u16)(qual >> VMX_IO_PORT_SHIFT);

		if (port >= COM1_PORT_BASE && port <= COM1_PORT_END) {
			exit->type = KVM_CARETAKER_EXIT_CONSOLE;
			exit->mmio_io.addr = port;
			exit->mmio_io.is_write = !(qual & VMX_IO_DIRECTION_BIT);
			exit->mmio_io.size = (u8)((qual & VMX_IO_SIZE_MASK) + 1);
			exit->mmio_io.is_mmio = false;
			exit->mmio_io.val_ptr = &cvp->common.rax;
		}
		break;
	}
	case EXIT_REASON_HLT:
		exit->type = KVM_CARETAKER_EXIT_IDLE;
		break;
	case EXIT_REASON_PAUSE_INSTRUCTION:
		exit->type = KVM_CARETAKER_EXIT_IDLE;
		exit->insn_len = insn_len ? insn_len : PAUSE_INSN_LEN;
		break;
	case EXIT_REASON_CPUID:
		exit->type = KVM_CARETAKER_EXIT_CPUID;
		break;
	case EXIT_REASON_VMCALL:
		exit->type = KVM_CARETAKER_EXIT_CROSS_VCPU;
		exit->insn_len = insn_len ? insn_len : VMCALL_INSN_LEN;
		cvp->common.rax = 0;
		break;
	case EXIT_REASON_MSR_READ:
		exit->type = KVM_CARETAKER_EXIT_MSR;
		exit->msr.msr = (u32)cvp->common.rcx;
		exit->msr.is_write = false;
		break;
	case EXIT_REASON_MSR_WRITE:
		exit->type = KVM_CARETAKER_EXIT_MSR;
		exit->msr.msr = (u32)cvp->common.rcx;
		exit->msr.is_write = true;
		break;
	case EXIT_REASON_RDTSC:
		exit->type = KVM_CARETAKER_EXIT_RDTSC;
		break;
	case EXIT_REASON_EPT_VIOLATION:
		exit->type = KVM_CARETAKER_EXIT_UNHANDLED;
		break;
	case EXIT_REASON_PREEMPTION_TIMER:
		exit->type = KVM_CARETAKER_EXIT_PREEMPT_TIMER;
		exit->insn_len = 0;
		vmx_caretaker_disarm_timer(cvp);
		break;
	case EXIT_REASON_EOI_INDUCED:
	case EXIT_REASON_APIC_WRITE:
	case EXIT_REASON_APIC_ACCESS:
	case EXIT_REASON_INTERRUPT_WINDOW:
		exit->type = KVM_CARETAKER_EXIT_CROSS_VCPU;
		exit->insn_len = 0;
		break;
	case EXIT_REASON_EXTERNAL_INTERRUPT:
	case EXIT_REASON_EXCEPTION_NMI:
	case EXIT_REASON_INIT_SIGNAL:
	case EXIT_REASON_SIPI_SIGNAL:
		exit->type = KVM_CARETAKER_EXIT_PREEMPT_TIMER;
		exit->insn_len = 0;
		break;
	default:
		break;
	}
}

void __cpu_preserved_text
vmx_caretaker_init_host_vmcs(struct caretaker_vmx_page *cvp)
{
	u64 fs_base = 0, gs_base = 0;
	unsigned long pin, cpu_ctl;

	phys_addr_t host_cr3 = cvp->common.host_cr3;

	/* Configure Host Controls */
	vmx_vmwrite(HOST_CR0, read_cr0());
	vmx_vmwrite(HOST_CR4, __read_cr4());
	if (!host_cr3) {
		struct cpu_preserved_stack_context *sctx = oncore_get_current_context();

		if (sctx && sctx->session_pgd_pa)
			host_cr3 = sctx->session_pgd_pa;
		else
			host_cr3 = x86_caretaker_pgd_pa;
	}
	if (host_cr3)
		vmx_vmwrite(HOST_CR3, host_cr3);
