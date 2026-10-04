// SPDX-License-Identifier: GPL-2.0-only
/*
 * Intel VMX Caretaker Standalone Execution Engine
 *
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * Runs the Intel VMX guest execution loop in an isolated, KHO-preserved
 * context using KVM's native __vmx_vcpu_run world switch and VMCS helpers.
 */

#include <linux/cpu_preserve.h>
#include <linux/kernel.h>
#include <linux/kvm_host.h>
#include <linux/oncore.h>

#include <asm/apic.h>
#include <asm/desc.h>
#include <asm/msr.h>
#include <asm/segment.h>
#include <asm/vmx.h>

#include "caretaker.h"
#include "lapic.h"
#include "regs.h"
#include "switch.h"
#include "vmenter.h"
#include "vmx.h"
#include "x86.h"
#include "../vmx/posted_intr.h"
#include "../vmx/switch.h"
#include "../vmx/vmx_ops.h"

void vmx_vmexit(void);

#ifndef CONFIG_CC_HAS_ASM_GOTO_OUTPUT
noinstr void vmread_error_trampoline2(unsigned long field, bool fault)
{
}
#endif

void vmx_update_host_rsp(struct vcpu_vmx *vmx, unsigned long host_rsp)
{
	__vmx_update_host_rsp(vmx, host_rsp);
}

static void vmx_caretaker_disarm_timer(void *page)
{
	struct caretaker_vmx_page *cvp = page;

	pin_controls_clearbit(&cvp->vmx, PIN_BASED_VMX_PREEMPTION_TIMER);
}

static int vmx_caretaker_enter(struct caretaker_x86_page *cxp, u32 *exit_code)
{
	struct caretaker_vmx_page *cvp =
		container_of(cxp, struct caretaker_vmx_page, common);
	struct vcpu_vmx *vmx = &cvp->vmx;
	struct kvm_vcpu *vcpu = &vmx->vcpu;
	unsigned int flags = vmx->loaded_vmcs->launched ? KVM_ENTER_VMRESUME : 0;

	if (kvm_register_is_dirty(vcpu, VCPU_REGS_RSP))
		vmcs_writel(GUEST_RSP, vcpu->arch.regs[VCPU_REGS_RSP]);
	if (kvm_register_is_dirty(vcpu, VCPU_REG_RIP))
		vmcs_writel(GUEST_RIP, vcpu->arch.rip);
	kvm_reset_dirty_registers(vcpu);

	vmx->fail = __vmx_vcpu_run(vmx, flags);

	vcpu->arch.cr2 = native_read_cr2();
	kvm_clear_available_registers(vcpu, VMX_REGS_LAZY_LOAD_SET);
	vmx_segment_cache_clear(vmx);
	vmx->idt_vectoring_info = 0;

	if (unlikely(vmx->fail))
		return -1;

	vmx->vt.exit_reason.full = vmcs_read32(VM_EXIT_REASON);
	if (unlikely(vmx->vt.exit_reason.failed_vmentry))
		return -1;

	vmx->idt_vectoring_info = vmcs_read32(IDT_VECTORING_INFO_FIELD);
	vmx->loaded_vmcs->launched = 1;
	*exit_code = vmx->vt.exit_reason.basic;
	return 0;
}

static int vmx_caretaker_handle_exit(struct caretaker_x86_page *cxp,
				     u32 exit_reason,
				     enum oncore_exit_reason *reason)
{
	struct caretaker_vmx_page *cvp =
		container_of(cxp, struct caretaker_vmx_page, common);
	struct kvm_vcpu *vcpu = &cvp->vmx.vcpu;
	int ret = 0;

	switch (exit_reason) {
	case EXIT_REASON_PREEMPTION_TIMER:
		vmx_caretaker_disarm_timer(cvp);
		return handle_fastpath_preemption_timer(vcpu, true) ==
		       EXIT_FASTPATH_REENTER_GUEST;
	case EXIT_REASON_INIT_SIGNAL:
	case EXIT_REASON_SIPI_SIGNAL:
		return 0;
	default:
		if (exit_reason < kvm_vmx_max_exit_handlers &&
		    kvm_vmx_exit_handlers[exit_reason])
			ret = kvm_vmx_exit_handlers[exit_reason](vcpu);
		break;
	}

	if (ret <= 0)
		return -1;

	if (exit_reason == EXIT_REASON_HLT ||
	    exit_reason == EXIT_REASON_PAUSE_INSTRUCTION) {
		*reason = ONCORE_EXIT_YIELD_IDLE;
		return 0;
	}

	if (exit_reason == EXIT_REASON_EXTERNAL_INTERRUPT ||
	    exit_reason == EXIT_REASON_EXCEPTION_NMI)
		return 0;

	return 1;
}

static void vmx_caretaker_init_host_vmcs(struct caretaker_vmx_page *cvp)
{
	struct vcpu_vmx *vmx = &cvp->vmx;
	u64 fs_base = 0, gs_base = 0;
	phys_addr_t host_cr3 = cvp->common.host_cr3;

	/* Configure Host Controls */
	vmcs_writel(HOST_CR0, caretaker_read_cr0());
	vmcs_writel(HOST_CR4, caretaker_read_cr4() & ~X86_CR4_PGE);
	if (!host_cr3) {
		struct cpu_preserved_stack_context *sctx = cpu_preserved_get_stack_context();

		if (sctx && sctx->session_pgd_pa)
			host_cr3 = sctx->session_pgd_pa;
	}
	if (host_cr3)
		vmcs_writel(HOST_CR3, host_cr3);
	vmx->loaded_vmcs->host_state.rsp = 0;
	vmcs_writel(HOST_RIP, (unsigned long)vmx_vmexit);

	/* Configure Host Selectors */
	vmcs_write16(HOST_CS_SELECTOR, __KERNEL_CS);
	vmcs_write16(HOST_SS_SELECTOR, __KERNEL_DS);
	vmcs_write16(HOST_DS_SELECTOR, __KERNEL_DS);
	vmcs_write16(HOST_ES_SELECTOR, __KERNEL_DS);
	vmcs_write16(HOST_FS_SELECTOR, 0);
	vmcs_write16(HOST_GS_SELECTOR, 0);
	vmcs_write16(HOST_TR_SELECTOR, GDT_ENTRY_TSS * 8);

	/* Configure Host Bases */
	fs_base = native_rdmsrq(MSR_FS_BASE);
	gs_base = native_rdmsrq(MSR_GS_BASE);
	vmcs_writel(HOST_FS_BASE, fs_base);
	vmcs_writel(HOST_GS_BASE, gs_base);
	vmcs_writel(HOST_TR_BASE, (unsigned long)&cvp->common.tss);
	vmcs_writel(HOST_GDTR_BASE, (unsigned long)&cvp->common.gdt[0]);
	vmcs_writel(HOST_IDTR_BASE, (unsigned long)&x86_preserved_idt[0]);

	/* Configure PIN and CPU execution controls via KVM shadow helpers */
	vmx->loaded_vmcs->controls_shadow.pin = vmcs_read32(PIN_BASED_VM_EXEC_CONTROL);
	pin_controls_setbit(vmx, PIN_BASED_EXT_INTR_MASK | PIN_BASED_NMI_EXITING);
	pin_controls_clearbit(vmx, PIN_BASED_VMX_PREEMPTION_TIMER);
	if (!cvp->common.abi.pi_desc_pa)
		pin_controls_clearbit(vmx, PIN_BASED_POSTED_INTR);

	vmx->loaded_vmcs->controls_shadow.exec = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	exec_controls_clearbit(vmx, CPU_BASED_INTR_WINDOW_EXITING |
				    CPU_BASED_NMI_WINDOW_EXITING);
	exec_controls_setbit(vmx, CPU_BASED_HLT_EXITING |
				  CPU_BASED_PAUSE_EXITING |
				  CPU_BASED_MWAIT_EXITING |
				  CPU_BASED_MONITOR_EXITING |
				  CPU_BASED_UNCOND_IO_EXITING);

	if (cvp->ple_supported &&
	    (exec_controls_get(vmx) & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS)) {
		vmx->loaded_vmcs->controls_shadow.secondary_exec =
			vmcs_read32(SECONDARY_VM_EXEC_CONTROL);
		secondary_exec_controls_setbit(vmx, SECONDARY_EXEC_PAUSE_LOOP_EXITING);
		vmcs_write32(PLE_GAP, 4096);
		vmcs_write32(PLE_WINDOW, 4096);
	}

	/*
	 * Use the KHO-preserved MSR autoload/autostore arrays in cvp->vmx so
	 * atomic-switched MSRs (such as MSR_IA32_PERF_GLOBAL_CTRL) are switched
	 * on VM-entry and VM-exit without dereferencing unpreserved host memory.
	 */
	vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, vmx->msr_autoload.host.nr);
	vmcs_write32(VM_EXIT_MSR_STORE_COUNT, vmx->msr_autostore.nr);
	vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, vmx->msr_autoload.guest.nr);
}

static void vmx_caretaker_arm_timer(void *page, u64 deadline_ticks)
{
	struct caretaker_vmx_page *cvp = page;
	struct vcpu_vmx *vmx = &cvp->vmx;
	u32 shift = (cvp && cvp->timer_shift) ? cvp->timer_shift : VMX_PREEMPTION_TIMER_SHIFT;
	u32 timer_value = 0;

	if (deadline_ticks && deadline_ticks != U64_MAX) {
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
		vmcs_write32(VMX_PREEMPTION_TIMER_VALUE, timer_value);
		pin_controls_setbit(vmx, PIN_BASED_VMX_PREEMPTION_TIMER);
	} else {
		vmx_caretaker_disarm_timer(page);
	}
}

static void vmx_caretaker_pre_enter(void *page)
{
	struct caretaker_vmx_page *cvp = page;
	struct vcpu_vmx *vmx = &cvp->vmx;
	unsigned long cr4 = caretaker_read_cr4();

	/* Ensure VMX is active on this core */
	if (!(cr4 & X86_CR4_VMXE)) {
		asm volatile("mov %0, %%cr4" : : "r" (cr4 | X86_CR4_VMXE) : "memory");
		if (cvp->vmxon_pa) {
			asm volatile("1: vmxon %[vmxon_pa]\n\t"
				     "2:\n\t"
				     _ASM_EXTABLE(1b, 2b)
				     : : [vmxon_pa] "m" (cvp->vmxon_pa)
				     : "memory", "cc");
		}
	}

	/* Activate VMCS on this pCPU */
	vmcs_load_pa(cvp->vmcs_pa);
	vmx->loaded_vmcs->launched = 0;

	/* Configure Caretaker host VMCS */
	vmx_caretaker_init_host_vmcs(cvp);

	if (cvp->common.abi.pi_desc_pa) {
		pi_clear_sn(&vmx->vt.pi_desc);
		__vmx_sync_pir_to_irr(&vmx->vcpu);
	}

	if (cvp->common.arch_state) {
		vmx->vcpu.arch.cr2 = cvp->common.arch_state->sregs.cr2;
		native_write_cr2(vmx->vcpu.arch.cr2);
	}

	native_wrmsrq(MSR_STAR, cvp->star);
	native_wrmsrq(MSR_LSTAR, cvp->lstar);
	native_wrmsrq(MSR_SYSCALL_MASK, cvp->fmask);
	native_wrmsrq(MSR_KERNEL_GS_BASE, cvp->common.kernel_gs_base);
	vmx->vt.guest_state_loaded = true;
}

static void vmx_caretaker_post_exit(void *page)
{
	struct caretaker_vmx_page *cvp = page;
	struct vcpu_vmx *vmx = &cvp->vmx;
	struct kvm_vcpu *vcpu = &vmx->vcpu;

	if (kvm_register_is_dirty(vcpu, VCPU_REGS_RSP))
		vmcs_writel(GUEST_RSP, vcpu->arch.regs[VCPU_REGS_RSP]);
	if (kvm_register_is_dirty(vcpu, VCPU_REG_RIP))
		vmcs_writel(GUEST_RIP, vcpu->arch.rip);
	kvm_reset_dirty_registers(vcpu);

	cvp->star = native_rdmsrq(MSR_STAR);
	cvp->lstar = native_rdmsrq(MSR_LSTAR);
	cvp->fmask = native_rdmsrq(MSR_SYSCALL_MASK);
	cvp->common.kernel_gs_base = native_rdmsrq(MSR_KERNEL_GS_BASE);
	vmx->msr_guest_kernel_gs_base = cvp->common.kernel_gs_base;
	vmx->vt.guest_state_loaded = false;

	if (cvp->common.abi.pi_desc_pa)
		pi_set_sn(&vmx->vt.pi_desc);

	/* Flush VMCS cache so host and incoming kernel see latest guest state */
	vmcs_clear_pa(cvp->vmcs_pa);
	vmx->loaded_vmcs->launched = 0;
}

static const struct kvm_x86_ops vmx_caretaker_x86_ops = {
	.get_segment = __vmx_get_segment,
	.get_gdt = __vmx_get_gdt,
	.get_idt = __vmx_get_idt,
	.get_cs_db_l_bits = __vmx_get_cs_db_l_bits,
	.cache_reg = __vmx_cache_reg,
	.get_rflags = __vmx_get_rflags,
	.set_rflags = __vmx_set_rflags,
	.get_interrupt_shadow = __vmx_get_interrupt_shadow,
	.set_interrupt_shadow = __vmx_set_interrupt_shadow,
	.skip_emulated_instruction = __vmx_skip_emulated_instruction,
};

const struct kvm_x86_caretaker_runtime_ops vmx_caretaker_runtime_ops = {
	.x86_ops = &vmx_caretaker_x86_ops,
	.enter = vmx_caretaker_enter,
	.handle_exit = vmx_caretaker_handle_exit,
	.arm_timer = vmx_caretaker_arm_timer,
	.disarm_timer = vmx_caretaker_disarm_timer,
	.pre_run = vmx_caretaker_pre_enter,
	.post_run = vmx_caretaker_post_exit,
};
