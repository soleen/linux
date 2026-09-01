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

#include <linux/caretaker.h>
#include <linux/cpu_preserve.h>
#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/kexec.h>
#include <linux/kexec_handover.h>
#include <linux/kvm_host.h>
#include <linux/objtool.h>

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

static void vmx_caretaker_init_page(struct caretaker_vmx_page *cvp,
				    struct kvm_vcpu *vcpu);
STACK_FRAME_NON_STANDARD(vmx_caretaker_init_page);

static void vmx_caretaker_init_page(struct caretaker_vmx_page *cvp,
				    struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	u64 basic_msr;

	if (!cvp || !vcpu || !vmx->vmcs01.vmcs)
		return;

	kvm_x86_caretaker_init_common_page(&cvp->common, vcpu, sizeof(*cvp));
	cvp->common.vmcs_pa = virt_to_phys(vmx->vmcs01.vmcs);
	cvp->common.vmxon_pa = virt_to_phys(cvp->vmxon_area);

	memset(cvp->vmxon_area, 0, PAGE_SIZE);
	rdmsrq(MSR_IA32_VMX_BASIC, basic_msr);
	*(u32 *)cvp->vmxon_area = vmx_basic_vmcs_revision_id(basic_msr);

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

	if (vmx && vmx->loaded_vmcs)
		loaded_vmcs_clear(vmx->loaded_vmcs);
}


void vmx_caretaker_init(struct kvm_vcpu *vcpu, u64 *cb_pa)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct caretaker_vmx_page *cvp;

	cvp = kho_alloc_preserve(sizeof(*cvp));
	if (!cvp || IS_ERR(cvp)) {
		pr_err("caretaker vmx: failed to allocate preserved page\n");
		if (cb_pa)
			*cb_pa = 0;
		return;
	}

	if (vmx) {
		if (vmx->vmcs01.vmcs)
			kho_preserve_pages(virt_to_page(vmx->vmcs01.vmcs), 1);
		if (vmx->vmcs01.msr_bitmap)
			kho_preserve_pages(virt_to_page(vmx->vmcs01.msr_bitmap), 1);
		if (vmx->pml_pg)
			kho_preserve_pages(vmx->pml_pg, 1);
		if (vmx->ve_info)
			kho_preserve_pages(virt_to_page(vmx->ve_info), 1);
	}
	if (to_kvm_vmx(vcpu->kvm)->pid_table)
		kho_preserve_pages(virt_to_page(to_kvm_vmx(vcpu->kvm)->pid_table), 1);

	kvm_mmu_preserve_kho(vcpu->kvm);

	vmx_caretaker_init_page(cvp, vcpu);
	vcpu->arch.cb_pa = virt_to_phys(&cvp->common.cb);
	if (cb_pa)
		*cb_pa = vcpu->arch.cb_pa;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(vmx_caretaker_init);

static void vmx_caretaker_signal_attach(struct kvm_vcpu *vcpu, struct caretaker_cb *cb)
{
	int target_pcpu = cb->pcpu_id;

	if (target_pcpu >= 0 && target_pcpu < nr_cpu_ids)
		per_cpu(current_vmcs, target_pcpu) = NULL;

	if (vcpu) {
		struct vcpu_vmx *vmx = to_vmx(vcpu);

		if (vmx && vmx->loaded_vmcs)
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

void __cpu_preserved_text
vmx_caretaker_decode_exit(struct caretaker_vmx_page *cvp,
			  struct kvm_caretaker_exit *exit)
{
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
	cvp->common.cr0 = vmx_vmread(GUEST_CR0);
	cvp->common.cr4 = vmx_vmread(GUEST_CR4);

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
		exit->type = KVM_CARETAKER_EXIT_INSN_STEP;
		exit->insn_len = PAUSE_INSN_LEN;
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
EXPORT_SYMBOL_FOR_KVM_INTERNAL(vmx_caretaker_decode_exit);

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
		struct cpu_preserved_stack_context *sctx = caretaker_get_current_context();

		if (sctx && sctx->session_pgd_pa)
			host_cr3 = sctx->session_pgd_pa;
		else
			host_cr3 = x86_caretaker_pgd_pa;
	}
	if (host_cr3)
		vmx_vmwrite(HOST_CR3, host_cr3);
	vmx_vmwrite(HOST_RSP, cvp->common.stack_top);
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
	rdmsrq(MSR_FS_BASE, fs_base);
	rdmsrq(MSR_GS_BASE, gs_base);
	vmx_vmwrite(HOST_FS_BASE, fs_base);
	vmx_vmwrite(HOST_GS_BASE, gs_base);
	vmx_vmwrite(HOST_TR_BASE, (unsigned long)&cvp->common.tss);
	vmx_vmwrite(HOST_GDTR_BASE, (unsigned long)&cvp->common.gdt[0]);
	vmx_vmwrite(HOST_IDTR_BASE, (unsigned long)&cvp->common.idt[0]);

	/* Configure PIN and CPU execution controls */
	pin = vmx_vmread(PIN_BASED_VM_EXEC_CONTROL);
	pin |= (PIN_BASED_EXT_INTR_MASK | PIN_BASED_NMI_EXITING);
	pin &= ~PIN_BASED_VMX_PREEMPTION_TIMER;
	vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, pin);

	cpu_ctl = vmx_vmread(CPU_BASED_VM_EXEC_CONTROL);
	cpu_ctl &= ~(CPU_BASED_INTR_WINDOW_EXITING |
		     CPU_BASED_NMI_WINDOW_EXITING |
		     CPU_BASED_PAUSE_EXITING);
	cpu_ctl |= (CPU_BASED_HLT_EXITING |
		    CPU_BASED_MWAIT_EXITING |
		    CPU_BASED_MONITOR_EXITING |
		    CPU_BASED_UNCOND_IO_EXITING);
	vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, cpu_ctl);

	if (cpu_ctl & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) {
		unsigned long sec_ctl = vmx_vmread(SECONDARY_VM_EXEC_CONTROL);

		sec_ctl &= ~SECONDARY_EXEC_PAUSE_LOOP_EXITING;
		vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, sec_ctl);
	}
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(vmx_caretaker_init_host_vmcs);

static void
vmx_caretaker_sync_vcpu(void *page, struct kvm_vcpu *vcpu)
{
	struct caretaker_vmx_page *cvp = page;
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	kvm_x86_caretaker_sync_vcpu_common(vcpu, &cvp->common);

	if (vmx) {
		if (vmx->loaded_vmcs) {
			pin_controls_clearbit(vmx, PIN_BASED_VMX_PREEMPTION_TIMER);
			vmcs_write32(PIN_BASED_VM_EXEC_CONTROL, pin_controls_get(vmx));
			vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, exec_controls_get(vmx));
			vmcs_write32(VMX_PREEMPTION_TIMER_VALUE, 0);
			memset(&vmx->loaded_vmcs->host_state, 0,
			       sizeof(struct vmcs_host_state));
		}
		vmx_segment_cache_clear(vmx);
		vmx->msr_guest_kernel_gs_base = cvp->common.kernel_gs_base;
		vmx->vt.guest_state_loaded = false;
		vmx->guest_uret_msrs_loaded = false;
	}

	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, 0);
	vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, 0);
	vmcs_write32(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_ACTIVE);
	vmcs_writel(GUEST_PENDING_DBG_EXCEPTIONS, 0);
}

static __cpu_preserved_text void vmx_caretaker_arm_timer(void *page, u64 deadline_ticks)
{
	u32 timer_value = 0;
	u32 pin;

	if (deadline_ticks) {
		u64 now = arch_caretaker_read_counter();

		if (deadline_ticks > now) {
			u64 remaining = deadline_ticks - now;

			timer_value = (u32)(remaining >> VMX_PREEMPTION_TIMER_SHIFT);
			if (timer_value == 0)
				timer_value = 1;
		} else {
			timer_value = 1;
		}
	}

	if (timer_value > 0) {
		vmx_vmwrite(VMX_PREEMPTION_TIMER_VALUE, timer_value);
		pin = (u32)vmx_vmread(PIN_BASED_VM_EXEC_CONTROL);
		pin |= PIN_BASED_VMX_PREEMPTION_TIMER;
		vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, pin);
	} else {
		vmx_caretaker_disarm_timer(page);
	}
}

static __cpu_preserved_text void
vmx_caretaker_advance_rip(void *page, u64 rip)
{
	struct caretaker_vmx_page *cvp = page;

	cvp->common.last_exit_rip = rip;
	vmx_vmwrite(GUEST_RIP, rip);
}

static __cpu_preserved_text void vmx_caretaker_pre_enter(void *page)
{
	struct caretaker_vmx_page *cvp = page;

	/* Ensure VMX is active on this core */
	if (!(__read_cr4() & X86_CR4_VMXE)) {
		asm volatile("mov %0, %%cr4" : : "r" (__read_cr4() | X86_CR4_VMXE) : "memory");
		if (cvp->common.vmxon_pa) {
			asm volatile("1: vmxon %[vmxon_pa]\n\t"
				     "2:\n\t"
				     _ASM_EXTABLE(1b, 2b)
				     : : [vmxon_pa] "m" (cvp->common.vmxon_pa)
				     : "memory", "cc");
		}
	}

	/* Activate VMCS on this pCPU */
	asm volatile("vmptrld %0" : : "m" (cvp->common.vmcs_pa) : "memory", "cc");

	/* Configure Caretaker host VMCS */
	vmx_caretaker_init_host_vmcs(cvp);

	if (cvp->star)
		wrmsrq(MSR_STAR, cvp->star);
	if (cvp->lstar)
		wrmsrq(MSR_LSTAR, cvp->lstar);
	if (cvp->fmask)
		wrmsrq(MSR_SYSCALL_MASK, cvp->fmask);
}

static __cpu_preserved_text void vmx_caretaker_post_exit(void *page)
{
	struct caretaker_vmx_page *cvp = page;

	/* Flush VMCS cache so host and incoming kernel see latest guest state */
	asm volatile("vmclear %0" : : "m" (cvp->common.vmcs_pa) : "memory", "cc");
}

static const struct kvm_x86_caretaker_ops vmx_caretaker_ops __cpu_preserved_data = {
	.name = "vmx",
	.init = vmx_caretaker_init,
	.signal_attach = vmx_caretaker_signal_attach,
	.sync_vcpu = vmx_caretaker_sync_vcpu,
	.enter_guest = (caretaker_enter_fn)vmx_caretaker_enter,
	.decode_exit = (caretaker_decode_exit_fn)vmx_caretaker_decode_exit,
	.advance_rip = vmx_caretaker_advance_rip,
	.arm_timer = vmx_caretaker_arm_timer,
	.disarm_timer = vmx_caretaker_disarm_timer,
	.pre_enter = vmx_caretaker_pre_enter,
	.post_exit = vmx_caretaker_post_exit,
};

void vmx_caretaker_register(void)
{
	kvm_x86_caretaker_register_ops(&vmx_caretaker_ops);
}

void vmx_caretaker_unregister(void)
{
	kvm_x86_caretaker_unregister_ops(&vmx_caretaker_ops);
}
