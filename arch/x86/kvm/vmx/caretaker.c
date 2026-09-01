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

#include <linux/kernel.h>
#include <linux/kvm_host.h>
#include <linux/kexec_handover.h>
#include <linux/caretaker.h>
#include <linux/delay.h>
#include <linux/objtool.h>
#include <linux/cpu_preserve.h>
#include <linux/kexec.h>
#include <asm/vmx.h>
#include <asm/set_memory.h>
#include <asm/pgtable.h>
#include <asm/apic.h>
#include <asm/fixmap.h>
#include <asm/virt.h>
#include <asm/desc.h>
#include <asm/segment.h>
#include <asm/processor.h>
#include <asm/cpu_entry_area.h>
#include "x86.h"
#include "vmx.h"
#include "vmx_ops.h"
#include "x86_ops.h"
#include "../caretaker.h"
#include "caretaker.h"

static void vmx_caretaker_init_page(struct caretaker_vmx_page *cvp,
				    struct kvm_vcpu *vcpu);
STACK_FRAME_NON_STANDARD(vmx_caretaker_init_page);

static_assert(offsetof(struct caretaker_vmx_page, common.gdt) == CXP_GDT_BASE);
static_assert(offsetof(struct caretaker_vmx_page, common.tss) == CXP_TSS_BASE);
static_assert(offsetof(struct caretaker_vmx_page, common.stack) == CXP_STACK_OFFSET);
static_assert(offsetof(struct caretaker_vmx_page, common.idt) == CXP_IDT_BASE);
static_assert(offsetof(struct caretaker_vmx_page, common.uart) == CXP_UART);

static void vmx_caretaker_init_page(struct caretaker_vmx_page *cvp,
				    struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (!cvp || !vcpu || !vmx->vmcs01.vmcs)
		return;

	kvm_x86_caretaker_init_common_page(&cvp->common, vcpu, sizeof(*cvp));
	cvp->common.vmcs_pa = virt_to_phys(vmx->vmcs01.vmcs);

	vcpu_load(vcpu);

	cvp->common.kernel_gs_base = vmx->msr_guest_kernel_gs_base;

	/* Save current guest control registers from KVM */
	cvp->common.cr0 = kvm_read_cr0(vcpu);
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
	struct caretaker_vmx_page *cvp;
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	BUILD_BUG_ON(offsetof(struct caretaker_vmx_page, common.deadline_tsc) != CXP_DEADLINE_TSC);
	BUILD_BUG_ON(offsetof(struct caretaker_vmx_page, common.host_cr3) != CXP_HOST_CR3);
	BUILD_BUG_ON(offsetof(struct caretaker_vmx_page, common.orig_cr3) != CXP_ORIG_CR3);
	BUILD_BUG_ON(offsetof(struct caretaker_vmx_page, common.stack_orig) != CXP_STACK_ORIG);
	BUILD_BUG_ON(offsetof(struct caretaker_vmx_page, common.vmcs_pa) != CXP_VMCS_PA);
	BUILD_BUG_ON(offsetof(struct caretaker_vmx_page, common.last_exit_code) != CXP_LAST_EXIT_CODE);
	BUILD_BUG_ON(offsetof(struct caretaker_vmx_page, common.last_exit_qual) != CXP_LAST_EXIT_QUAL);
	BUILD_BUG_ON(offsetof(struct caretaker_vmx_page, common.last_exit_rip) != CXP_LAST_EXIT_RIP);
	BUILD_BUG_ON(offsetof(struct caretaker_vmx_page, common.kernel_gs_base) != CXP_KERNEL_GS_BASE);
	BUILD_BUG_ON(offsetof(struct caretaker_vmx_page, common.apic_eoi_va) != CXP_APIC_EOI_VA);
	BUILD_BUG_ON(offsetof(struct caretaker_vmx_page, common.stack) != CXP_STACK_OFFSET);
	BUILD_BUG_ON(offsetof(struct caretaker_vmx_page, common.gdt) != CXP_GDT_BASE);
	BUILD_BUG_ON(offsetof(struct caretaker_vmx_page, common.tss) != CXP_TSS_BASE);
	BUILD_BUG_ON(offsetof(struct caretaker_vmx_page, common.idt) != CXP_IDT_BASE);

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

	x86_virt_vmx_preserve_kho();
	kvm_mmu_preserve_kho(vcpu->kvm);

	vmx_caretaker_init_page(cvp, vcpu);
	vcpu->arch.cb_pa = virt_to_phys(&cvp->common.cb);
	if (cb_pa)
		*cb_pa = vcpu->arch.cb_pa;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(vmx_caretaker_init);

void vmx_caretaker_signal_attach(struct kvm_vcpu *vcpu, u64 cb_pa)
{
	if (cb_pa) {
		struct caretaker_cb *cb = phys_to_virt(__sme_clr(cb_pa));
		struct caretaker_vmx_page *cvp = cb ?
			container_of(cb, struct caretaker_vmx_page, common.cb) : NULL;

		if (cvp && cb) {
			int target_pcpu = cb->pcpu_id;

			if (target_pcpu >= 0 && target_pcpu < nr_cpu_ids)
				per_cpu(current_vmcs, target_pcpu) = NULL;

			kvm_x86_caretaker_signal_attach_common(vcpu, cb, cvp->common.apic_id,
							      &cvp->common.running,
							      "vmx");

			if (vcpu) {
				struct vcpu_vmx *vmx = to_vmx(vcpu);

				if (vmx && vmx->loaded_vmcs)
					loaded_vmcs_clear(vmx->loaded_vmcs);
			}
		}
	}
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(vmx_caretaker_signal_attach);

void vmx_caretaker_attach(struct kvm_vcpu *vcpu, u64 cb_pa)
{
	if (cb_pa) {
		struct caretaker_cb *cb = phys_to_virt(__sme_clr(cb_pa));
		struct caretaker_vmx_page *cvp = cb ?
			container_of(cb, struct caretaker_vmx_page, common.cb) : NULL;
		struct vcpu_vmx *vmx = to_vmx(vcpu);

		if (cvp && cb) {
			if (cb->pcpu_id < nr_cpu_ids)
				vcpu->cb.pcpu_id = cb->pcpu_id;

			vcpu_load(vcpu);
			vmx_caretaker_sync_vcpu(cvp, vcpu);
			vcpu_put(vcpu);

			if (vmx && vmx->loaded_vmcs)
				loaded_vmcs_clear(vmx->loaded_vmcs);
			vcpu->cpu = -1;
			vcpu->arch.cb_pa = 0;
		}
	}
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(vmx_caretaker_attach);

static __cpu_preserved_text void vmx_caretaker_disarm_timer(void)
{
	u32 pin = (u32)vmx_vmread(PIN_BASED_VM_EXEC_CONTROL);

	if (pin & 0x40)
		vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, pin & ~0x40);
}

void __cpu_preserved_text
vmx_caretaker_decode_exit(struct caretaker_vmx_page *cvp,
			  struct kvm_caretaker_exit *exit)
{
	u32 exit_reason = (u32)vmx_vmread(VM_EXIT_REASON) & 0xffff;
	u32 insn_len = (u32)vmx_vmread(VM_EXIT_INSTRUCTION_LEN);
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
		u16 port = (u16)(qual >> 16);

		if (port >= 0x3f8 && port <= 0x3ff) {
			exit->type = KVM_CARETAKER_EXIT_CONSOLE;
			exit->mmio_io.addr = port;
			exit->mmio_io.is_write = !(qual & 8);
			exit->mmio_io.size = (u8)((qual & 7) + 1);
			exit->mmio_io.is_mmio = false;
			exit->mmio_io.val_ptr = &cvp->common.rax;
		}
		break;
	}
	case EXIT_REASON_HLT:
	case EXIT_REASON_PAUSE_INSTRUCTION:
		exit->type = KVM_CARETAKER_EXIT_IDLE;
		break;
	case EXIT_REASON_CPUID:
		exit->type = KVM_CARETAKER_EXIT_CPUID;
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
		vmx_caretaker_disarm_timer();
		break;
	case EXIT_REASON_EOI_INDUCED:
	case EXIT_REASON_APIC_WRITE:
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

extern void vmx_caretaker_exit_handler(void);


void __cpu_preserved_text
vmx_caretaker_init_host_vmcs(struct caretaker_vmx_page *cvp)
{
	unsigned long pin, cpu_ctl;
	u64 fs_base = 0, gs_base = 0;

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
	pin |= 0x09; /* external intr | NMI */
	pin &= ~0x40; /* disable VMX-preemption timer until armed */
	vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, pin);

	cpu_ctl = vmx_vmread(CPU_BASED_VM_EXEC_CONTROL);
	cpu_ctl &= ~0x00400004;
	cpu_ctl |= 0x61000480;
	vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, cpu_ctl);
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(vmx_caretaker_init_host_vmcs);

STACK_FRAME_NON_STANDARD(vmx_caretaker_run_page);

void __cpu_preserved_text
vmx_caretaker_sync_vcpu(struct caretaker_vmx_page *cvp,
			struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	kvm_x86_caretaker_sync_vcpu_common(vcpu, &cvp->common);

	if (vmx) {
		if (vmx->loaded_vmcs) {
			pin_controls_clearbit(vmx, PIN_BASED_VMX_PREEMPTION_TIMER);
			vmcs_write32(PIN_BASED_VM_EXEC_CONTROL,
				     vmcs_read32(PIN_BASED_VM_EXEC_CONTROL) & ~0x40);
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
	vmcs_write32(IDT_VECTORING_INFO_FIELD, 0);
	vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, 0);
	vmcs_write32(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_ACTIVE);
	vmcs_writel(GUEST_PENDING_DBG_EXCEPTIONS, 0);
}

static __cpu_preserved_text void vmx_caretaker_arm_timer(u64 deadline_ticks)
{
	u32 timer_value = 0;
	u32 pin;

	if (deadline_ticks) {
		u64 now = arch_caretaker_read_counter();

		if (deadline_ticks > now) {
			u64 remaining = deadline_ticks - now;

			timer_value = (u32)(remaining >> 5);
			if (timer_value == 0)
				timer_value = 1;
		} else {
			timer_value = 1;
		}
	}

	if (timer_value > 0) {
		vmx_vmwrite(VMX_PREEMPTION_TIMER_VALUE, timer_value);
		pin = (u32)vmx_vmread(PIN_BASED_VM_EXEC_CONTROL);
		pin |= 0x40; /* enable VMX-preemption timer */
		vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, pin);
	} else {
		vmx_caretaker_disarm_timer();
	}
}

static __cpu_preserved_text void
vmx_caretaker_advance_rip(void *page, u64 rip)
{
	struct caretaker_vmx_page *cvp = page;

	cvp->common.last_exit_rip = rip;
	vmx_vmwrite(GUEST_RIP, rip);
}

enum caretaker_exit_reason __cpu_preserved_text __no_stack_protector
vmx_caretaker_run_page(struct caretaker_vmx_page *cvp,
		       struct kvm_vcpu *vcpu, u64 deadline_ticks)
{
	enum caretaker_exit_reason reason = CARETAKER_EXIT_QUANTUM_EXPIRED;
	struct caretaker_x86_host_state host_state;
	int pcpu;

	if (!cvp || !cvp->common.vmcs_pa)
		return CARETAKER_EXIT_ERROR;

	pcpu = cvp->common.pcpu_id;
	cvp->common.deadline_tsc = deadline_ticks;

	/* Ensure VMX is active on this core */
	if (!(__read_cr4() & X86_CR4_VMXE))
		asm volatile("mov %0, %%cr4" : : "r" (__read_cr4() | X86_CR4_VMXE) : "memory");

	/* Save host context, switch to Caretaker descriptors and CR3 */
	kvm_x86_caretaker_save_host_state(&host_state, &cvp->common);

	/* Activate VMCS on this pCPU */
	asm volatile("vmptrld %0" : : "m" (cvp->common.vmcs_pa) : "memory", "cc");

	/* Configure Caretaker host VMCS */
	vmx_caretaker_init_host_vmcs(cvp);

	/* Arm preemption timer if quantum deadline is specified */
	vmx_caretaker_arm_timer(deadline_ticks);

	if (cvp->common.kernel_gs_base)
		wrmsrq(MSR_KERNEL_GS_BASE, cvp->common.kernel_gs_base);

	reason = kvm_x86_caretaker_run(&cvp->common, deadline_ticks,
				       (caretaker_enter_fn)vmx_caretaker_enter,
				       (caretaker_decode_exit_fn)vmx_caretaker_decode_exit,
				       vmx_caretaker_advance_rip);

	vmx_caretaker_disarm_timer();
	rdmsrq(MSR_KERNEL_GS_BASE, cvp->common.kernel_gs_base);

	/* Flush VMCS cache so host and incoming kernel see latest guest state */
	asm volatile("vmclear %0" : : "m" (cvp->common.vmcs_pa) : "memory", "cc");

	if (reason == CARETAKER_EXIT_ATTACH_SIGNALED ||
	    READ_ONCE(cvp->common.cb.attachment_state) == CARETAKER_KVM_ATTACHING) {
		WRITE_ONCE(cvp->common.cb.attachment_state, CARETAKER_KVM_ATTACHED);
		smp_mb();
	}

	kvm_x86_caretaker_restore_host_state(&host_state, &cvp->common, vcpu, pcpu);
	if (vcpu && !cpu_is_preserved(pcpu) && !cpu_preserved_is_incoming(pcpu))
		vmx_caretaker_sync_vcpu(cvp, vcpu);

	return reason;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(vmx_caretaker_run_page);

static enum caretaker_exit_reason __cpu_preserved_text
vmx_caretaker_run_op(void *data, u64 deadline_ticks)
{
	struct caretaker_cb *cb = data;
	struct caretaker_vmx_page *cvp = cb ?
		container_of(cb, struct caretaker_vmx_page, common.cb) : NULL;

	return vmx_caretaker_run_page(cvp, NULL, deadline_ticks);
}

static const struct kvm_x86_caretaker_ops vmx_caretaker_ops __cpu_preserved_data = {
	.init = vmx_caretaker_init,
	.signal_attach = vmx_caretaker_signal_attach,
	.attach = vmx_caretaker_attach,
	.run_job = vmx_caretaker_run_op,
};

void vmx_caretaker_register(void)
{
	kvm_x86_caretaker_register_ops(&vmx_caretaker_ops);
}

void vmx_caretaker_unregister(void)
{
	kvm_x86_caretaker_unregister_ops(&vmx_caretaker_ops);
}
