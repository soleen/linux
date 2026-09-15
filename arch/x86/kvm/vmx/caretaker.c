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

void vmx_caretaker_init(struct kvm_vcpu *vcpu)
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
	return;

err_free:
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
	fs_base = native_rdmsrq(MSR_FS_BASE);
	gs_base = native_rdmsrq(MSR_GS_BASE);
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

/*
 * Guest-visible VMCS fields carried from the VMCS the caretaker ran the vCPU
 * on to the VMCS the new kernel allocated for it.
 *
 * The new kernel does not adopt the old VMCS: it belongs to the previous
 * kernel's struct loaded_vmcs, whose layout is not part of any handover ABI,
 * and the VMCS region itself is opaque and implementation defined.  So the
 * architecturally defined guest state is copied field by field instead.
 *
 * GUEST_IA32_EFER is handled separately because it is only written back when
 * the caretaker actually recorded a value for it.
 */
static const u16 vmx_caretaker_guest_fields[] = {
	GUEST_CS_SELECTOR,	GUEST_CS_LIMIT,
	GUEST_CS_AR_BYTES,	GUEST_CS_BASE,
	GUEST_SS_SELECTOR,	GUEST_SS_LIMIT,
	GUEST_SS_AR_BYTES,	GUEST_SS_BASE,
	GUEST_DS_SELECTOR,	GUEST_DS_LIMIT,
	GUEST_DS_AR_BYTES,	GUEST_DS_BASE,
	GUEST_ES_SELECTOR,	GUEST_ES_LIMIT,
	GUEST_ES_AR_BYTES,	GUEST_ES_BASE,
	GUEST_FS_SELECTOR,	GUEST_FS_LIMIT,
	GUEST_FS_AR_BYTES,	GUEST_FS_BASE,
	GUEST_GS_SELECTOR,	GUEST_GS_LIMIT,
	GUEST_GS_AR_BYTES,	GUEST_GS_BASE,
	GUEST_TR_SELECTOR,	GUEST_TR_LIMIT,
	GUEST_TR_AR_BYTES,	GUEST_TR_BASE,
	GUEST_LDTR_SELECTOR,	GUEST_LDTR_LIMIT,
	GUEST_LDTR_AR_BYTES,	GUEST_LDTR_BASE,
	GUEST_GDTR_LIMIT,	GUEST_GDTR_BASE,
	GUEST_IDTR_LIMIT,	GUEST_IDTR_BASE,
	GUEST_INTERRUPTIBILITY_INFO,
	GUEST_ACTIVITY_STATE,
	GUEST_IA32_DEBUGCTL,
	GUEST_SYSENTER_CS,
	GUEST_SYSENTER_ESP,
	GUEST_SYSENTER_EIP,
};

static void
vmx_caretaker_sync_vcpu(struct kvm_vcpu *vcpu, void *vcpu_data)
{
	struct kvm_x86_caretaker_abi *abi = vcpu_data;
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	phys_addr_t cur_vmcs_pa = vmx->loaded_vmcs ? virt_to_phys(vmx->loaded_vmcs->vmcs) : 0;
	struct vmcs *prev_vmcs;

	guard(preempt)();
	prev_vmcs = this_cpu_read(current_vmcs);

	if (abi->vmcs_pa && cur_vmcs_pa && abi->vmcs_pa != cur_vmcs_pa) {
		/* 42 * 8 bytes; this runs on the host stack, not a preserved one. */
		unsigned long val[ARRAY_SIZE(vmx_caretaker_guest_fields)];
		unsigned long guest_efer;
		int i;

		asm volatile("vmptrld %0" : : "m" (abi->vmcs_pa) : "memory", "cc");

		for (i = 0; i < ARRAY_SIZE(vmx_caretaker_guest_fields); i++)
			val[i] = vmx_vmread(vmx_caretaker_guest_fields[i]);
		guest_efer = vmx_caretaker_read_efer();

		asm volatile("vmclear %0" : : "m" (abi->vmcs_pa) : "memory", "cc");
		asm volatile("vmptrld %0" : : "m" (cur_vmcs_pa) : "memory", "cc");

		for (i = 0; i < ARRAY_SIZE(vmx_caretaker_guest_fields); i++)
			vmx_vmwrite(vmx_caretaker_guest_fields[i], val[i]);
		if (guest_efer)
			vmx_vmwrite(GUEST_IA32_EFER, guest_efer);

		abi->vmcs_pa = cur_vmcs_pa;
	} else if (cur_vmcs_pa) {
		asm volatile("vmptrld %0" : : "m" (cur_vmcs_pa) : "memory", "cc");
	}

	kvm_x86_caretaker_sync_vcpu_common(vcpu);

	if (vmx->loaded_vmcs) {
		pin_controls_clearbit(vmx, PIN_BASED_VMX_PREEMPTION_TIMER);
		vmcs_write32(PIN_BASED_VM_EXEC_CONTROL, pin_controls_get(vmx));
		vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, exec_controls_get(vmx));
		vmcs_write32(VMX_PREEMPTION_TIMER_VALUE, 0);
		memset(&vmx->loaded_vmcs->host_state, 0,
		       sizeof(struct vmcs_host_state));
		list_del_init(&vmx->loaded_vmcs->loaded_vmcss_on_cpu_link);
		vmx->loaded_vmcs->cpu = -1;
		vmx->loaded_vmcs->launched = 0;
	}
	vmx_segment_cache_clear(vmx);
	vmx->vt.guest_state_loaded = false;
	vmx->guest_uret_msrs_loaded = false;

	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, 0);
	vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, 0);
	vmcs_write32(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_ACTIVE);
	vmcs_writel(GUEST_PENDING_DBG_EXCEPTIONS, 0);

	vmcs_writel(GUEST_RIP, kvm_rip_read(vcpu));
	vmcs_writel(GUEST_RSP, kvm_rsp_read(vcpu));
	vmcs_writel(GUEST_RFLAGS, kvm_get_rflags(vcpu));
	vmx_set_cr0(vcpu, vcpu->arch.cr0);
	vmcs_writel(GUEST_CR3, vcpu->arch.cr3);
	vmx_set_cr4(vcpu, vcpu->arch.cr4);
	vmx_set_efer(vcpu, vcpu->arch.efer);

	if (vmx->loaded_vmcs)
		vmx_set_constant_host_state(vmx);

	if (cur_vmcs_pa)
		asm volatile("vmclear %0" : : "m" (cur_vmcs_pa) : "memory", "cc");

	if (prev_vmcs && (!vmx->loaded_vmcs || prev_vmcs != vmx->loaded_vmcs->vmcs)) {
		vmcs_load(prev_vmcs);
		this_cpu_write(current_vmcs, prev_vmcs);
	} else {
		this_cpu_write(current_vmcs, NULL);
	}
}

static __cpu_preserved_text void
vmx_caretaker_detach_serialize(void *page, struct kvm_vcpu_arch_luo_state *state)
{
	struct caretaker_vmx_page *cvp = page;

	kvm_x86_caretaker_detach_serialize_common(&cvp->common, state);
	kvm_x86_caretaker_update_msr(state, MSR_STAR, cvp->star);
	kvm_x86_caretaker_update_msr(state, MSR_LSTAR, cvp->lstar);
	kvm_x86_caretaker_update_msr(state, MSR_SYSCALL_MASK, cvp->fmask);
	kvm_x86_caretaker_update_msr(state, MSR_KERNEL_GS_BASE,
				     cvp->common.kernel_gs_base);
}

static __cpu_preserved_text void vmx_caretaker_arm_timer(void *page, u64 deadline_ticks)
{
	struct caretaker_vmx_page *cvp = page;
	u32 shift = (cvp && cvp->timer_shift) ? cvp->timer_shift : VMX_PREEMPTION_TIMER_SHIFT;
	u32 timer_value = 0;
	u32 pin;

	if (deadline_ticks) {
		u64 now = arch_oncore_read_counter();

		if (deadline_ticks > now) {
			u64 remaining = deadline_ticks - now;

			timer_value = (u32)(remaining >> shift);
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
		native_wrmsrq(MSR_STAR, cvp->star);
	if (cvp->lstar)
		native_wrmsrq(MSR_LSTAR, cvp->lstar);
	if (cvp->fmask)
		native_wrmsrq(MSR_SYSCALL_MASK, cvp->fmask);
}

static __cpu_preserved_text void
vmx_caretaker_read_seg(struct kvm_segment *var, u16 sel_field,
		       u16 base_field, u16 limit_field, u16 ar_field)
{
	u32 ar = (u32)vmx_vmread(ar_field);

	var->base = vmx_vmread(base_field);
	var->limit = (u32)vmx_vmread(limit_field);
	var->selector = (u16)vmx_vmread(sel_field);
	var->unusable = (ar >> 16) & 1;
	var->type = ar & 15;
	var->s = (ar >> 4) & 1;
	var->dpl = (ar >> 5) & 3;
	var->present = !var->unusable;
	var->avl = (ar >> 12) & 1;
	var->l = (ar >> 13) & 1;
	var->db = (ar >> 14) & 1;
	var->g = (ar >> 15) & 1;
}

static __cpu_preserved_text void vmx_caretaker_post_exit(void *page)
{
	struct caretaker_vmx_page *cvp = page;
	struct kvm_vcpu_arch_luo_state *state = cvp->common.arch_state;
	u64 efer;

	cvp->common.cr0 = vmx_caretaker_read_cr0();
	cvp->common.cr3 = vmx_vmread(GUEST_CR3);
	cvp->common.cr4 = vmx_caretaker_read_cr4();
	efer = vmx_caretaker_read_efer();
	if (efer)
		cvp->common.efer = efer;
	cvp->common.last_exit_rip = vmx_vmread(GUEST_RIP);
	cvp->common.last_exit_rsp = vmx_vmread(GUEST_RSP);
	cvp->common.last_exit_rflags = vmx_vmread(GUEST_RFLAGS);

	if (state) {
		vmx_caretaker_read_seg(&state->sregs.cs, GUEST_CS_SELECTOR,
				       GUEST_CS_BASE, GUEST_CS_LIMIT, GUEST_CS_AR_BYTES);
		vmx_caretaker_read_seg(&state->sregs.ds, GUEST_DS_SELECTOR,
				       GUEST_DS_BASE, GUEST_DS_LIMIT, GUEST_DS_AR_BYTES);
		vmx_caretaker_read_seg(&state->sregs.es, GUEST_ES_SELECTOR,
				       GUEST_ES_BASE, GUEST_ES_LIMIT, GUEST_ES_AR_BYTES);
		vmx_caretaker_read_seg(&state->sregs.fs, GUEST_FS_SELECTOR,
				       GUEST_FS_BASE, GUEST_FS_LIMIT, GUEST_FS_AR_BYTES);
		vmx_caretaker_read_seg(&state->sregs.gs, GUEST_GS_SELECTOR,
				       GUEST_GS_BASE, GUEST_GS_LIMIT, GUEST_GS_AR_BYTES);
		vmx_caretaker_read_seg(&state->sregs.ss, GUEST_SS_SELECTOR,
				       GUEST_SS_BASE, GUEST_SS_LIMIT, GUEST_SS_AR_BYTES);
		vmx_caretaker_read_seg(&state->sregs.tr, GUEST_TR_SELECTOR,
				       GUEST_TR_BASE, GUEST_TR_LIMIT, GUEST_TR_AR_BYTES);
		vmx_caretaker_read_seg(&state->sregs.ldt, GUEST_LDTR_SELECTOR,
				       GUEST_LDTR_BASE, GUEST_LDTR_LIMIT, GUEST_LDTR_AR_BYTES);
		state->sregs.gdt.base = vmx_vmread(GUEST_GDTR_BASE);
		state->sregs.gdt.limit = (u16)vmx_vmread(GUEST_GDTR_LIMIT);
		state->sregs.idt.base = vmx_vmread(GUEST_IDTR_BASE);
		state->sregs.idt.limit = (u16)vmx_vmread(GUEST_IDTR_LIMIT);

		kvm_x86_caretaker_update_msr(state, MSR_IA32_SYSENTER_CS,
					     vmx_vmread(GUEST_SYSENTER_CS));
		kvm_x86_caretaker_update_msr(state, MSR_IA32_SYSENTER_ESP,
					     vmx_vmread(GUEST_SYSENTER_ESP));
		kvm_x86_caretaker_update_msr(state, MSR_IA32_SYSENTER_EIP,
					     vmx_vmread(GUEST_SYSENTER_EIP));
	}

	/* Flush VMCS cache so host and incoming kernel see latest guest state */
	asm volatile("vmclear %0" : : "m" (cvp->common.vmcs_pa) : "memory", "cc");
}

static const struct kvm_x86_caretaker_ops vmx_caretaker_ops __cpu_preserved_data = {
	.name = "vmx",
	.init = vmx_caretaker_init,
	.detach_serialize = vmx_caretaker_detach_serialize,
	.common = {
		.enter_guest = vmx_caretaker_enter,
		.decode_exit = vmx_caretaker_decode_exit,
		.handle_arch_exit = kvm_x86_caretaker_handle_exit,
		.advance_rip = vmx_caretaker_advance_rip,
		.arm_timer = vmx_caretaker_arm_timer,
		.disarm_timer = vmx_caretaker_disarm_timer,
		.pre_run = vmx_caretaker_pre_enter,
		.post_run = vmx_caretaker_post_exit,
		.sync_vcpu = vmx_caretaker_sync_vcpu,
	},
};

void vmx_caretaker_register(void)
{
	kvm_x86_caretaker_register_ops(&vmx_caretaker_ops);
}

void vmx_caretaker_unregister(void)
{
	kvm_x86_caretaker_unregister_ops(&vmx_caretaker_ops);
}
