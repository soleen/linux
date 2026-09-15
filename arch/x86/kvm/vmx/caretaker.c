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
#include <linux/pgtable.h>
#include <linux/processor.h>
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
	cvp->common.abi.vmcs_pa = virt_to_phys(vmx->vmcs01.vmcs);
	cvp->vmxon_pa = virt_to_phys(cvp->vmxon_area);

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

void vmx_caretaker_init(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct caretaker_vmx_page *cvp;
	struct kvm_caretaker_arch_ser *abi;

	cvp = kho_alloc_preserve(sizeof(*cvp));
	if (IS_ERR(cvp)) {
		pr_err("caretaker vmx: failed to allocate preserved page\n");
		return;
	}

	if (vmx_caretaker_init_page(cvp, vcpu))
		goto err_free;

	abi = &cvp->common.abi;
	if (vmx->vmcs01.vmcs &&
	    kvm_x86_caretaker_preserve_page(abi, virt_to_page(vmx->vmcs01.vmcs)))
		goto err_free;
	if (vmx->vmcs01.msr_bitmap &&
	    kvm_x86_caretaker_preserve_page(abi, virt_to_page(vmx->vmcs01.msr_bitmap)))
		goto err_free;
	if (vmx->pml_pg &&
	    kvm_x86_caretaker_preserve_page(abi, vmx->pml_pg))
		goto err_free;
	if (vmx->ve_info &&
	    kvm_x86_caretaker_preserve_page(abi, virt_to_page(vmx->ve_info)))
		goto err_free;

	return;

err_free:
	kvm_x86_caretaker_unpreserve_pages(&cvp->common.abi);
	vcpu->caretaker.cb = NULL;
	kho_unpreserve_free(cvp);
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

	cvp->common.last_exit_rip = rip;
	cvp->common.last_exit_rsp = vmx_vmread(GUEST_RSP);
	cvp->common.last_exit_rflags = vmx_vmread(GUEST_RFLAGS);
	cvp->common.cr3 = vmx_vmread(GUEST_CR3);
	cvp->common.cr0 = vmx_caretaker_read_cr0();
	cvp->common.cr4 = vmx_caretaker_read_cr4();

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
		/*
		 * Do not write a return value.  The Caretaker cannot run the
		 * hypercall, and reporting success for something like
		 * KVM_HC_SEND_IPI or a PV TLB flush is worse than not
		 * answering at all.  CROSS_VCPU now stalls, so the guest
		 * stays parked on the VMCALL with RAX untouched until the
		 * incoming kernel services it.
		 */
		exit->type = KVM_CARETAKER_EXIT_CROSS_VCPU;
		exit->insn_len = insn_len ? insn_len : VMCALL_INSN_LEN;
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
		struct cpu_preserved_stack_context *sctx = cpu_preserved_get_stack_context();

		if (sctx && sctx->session_pgd_pa)
			host_cr3 = sctx->session_pgd_pa;
		else
			host_cr3 = x86_caretaker_pgd_pa;
	}
	if (host_cr3)
		vmx_vmwrite(HOST_CR3, host_cr3);
	vmx_vmwrite(HOST_RSP, (unsigned long)&cvp->common.stack[CXP_STACK_SIZE]);
	vmx_vmwrite(HOST_RIP, (unsigned long)&vmx_caretaker_exit_handler);

	/* Configure Host Selectors */
	vmx_vmwrite(HOST_CS_SELECTOR, __KERNEL_CS);
	vmx_vmwrite(HOST_SS_SELECTOR, __KERNEL_DS);
	vmx_vmwrite(HOST_DS_SELECTOR, __KERNEL_DS);
	vmx_vmwrite(HOST_ES_SELECTOR, __KERNEL_DS);
	vmx_vmwrite(HOST_FS_SELECTOR, 0);
	vmx_vmwrite(HOST_GS_SELECTOR, 0);
	vmx_vmwrite(HOST_TR_SELECTOR, GDT_ENTRY_TSS * 8);

	/* Configure Host Bases */
	fs_base = native_rdmsrq(MSR_FS_BASE);
	gs_base = native_rdmsrq(MSR_GS_BASE);
	vmx_vmwrite(HOST_FS_BASE, fs_base);
	vmx_vmwrite(HOST_GS_BASE, gs_base);
	vmx_vmwrite(HOST_TR_BASE, (unsigned long)&cvp->common.tss);
	vmx_vmwrite(HOST_GDTR_BASE, (unsigned long)&cvp->common.gdt[0]);
	vmx_vmwrite(HOST_IDTR_BASE, (unsigned long)&caretaker_x86_idt[0]);

	/* Configure PIN and CPU execution controls */
	pin = vmx_vmread(PIN_BASED_VM_EXEC_CONTROL);
	pin |= (PIN_BASED_EXT_INTR_MASK | PIN_BASED_NMI_EXITING);
	pin &= ~(PIN_BASED_VMX_PREEMPTION_TIMER | PIN_BASED_POSTED_INTR);
	vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, pin);

	cpu_ctl = vmx_vmread(CPU_BASED_VM_EXEC_CONTROL);
	cpu_ctl &= ~(CPU_BASED_INTR_WINDOW_EXITING |
		     CPU_BASED_NMI_WINDOW_EXITING);
	cpu_ctl |= (CPU_BASED_HLT_EXITING |
		    CPU_BASED_PAUSE_EXITING |
		    CPU_BASED_MWAIT_EXITING |
		    CPU_BASED_MONITOR_EXITING |
		    CPU_BASED_UNCOND_IO_EXITING);

	if (cvp && cvp->ple_supported &&
	    (cpu_ctl & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS)) {
		unsigned long sec_ctl = vmx_vmread(SECONDARY_VM_EXEC_CONTROL);

		sec_ctl |= SECONDARY_EXEC_PAUSE_LOOP_EXITING;
		vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, sec_ctl);
		vmx_vmwrite(PLE_GAP, 4096);
		vmx_vmwrite(PLE_WINDOW, 4096);
	}
	vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, cpu_ctl);
}

