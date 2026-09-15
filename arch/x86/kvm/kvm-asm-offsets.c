// SPDX-License-Identifier: GPL-2.0
/*
 * Generate definitions needed by assembly language modules.
 * This code generates raw asm output which is post-processed to extract
 * and format the required data.
 */
#define COMPILE_OFFSETS

#include <linux/kbuild.h>
#include "vmx/vmx.h"
#include "svm/svm.h"
#ifdef CONFIG_KVM_CARETAKER
#include "caretaker.h"
#endif

static void __used common(void)
{
	if (IS_ENABLED(CONFIG_KVM_AMD)) {
		BLANK();
		OFFSET(SVM_vcpu_arch_regs, vcpu_svm, vcpu.arch.regs);
		OFFSET(SVM_current_vmcb, vcpu_svm, current_vmcb);
		OFFSET(SVM_spec_ctrl, vcpu_svm, spec_ctrl);
		OFFSET(SVM_vmcb01, vcpu_svm, vmcb01);
		OFFSET(KVM_VMCB_pa, kvm_vmcb_info, pa);
		OFFSET(SD_save_area_pa, svm_cpu_data, save_area_pa);
	}

	if (IS_ENABLED(CONFIG_KVM_INTEL)) {
		BLANK();
		OFFSET(VMX_vcpu_arch_regs, vcpu_vmx, vcpu.arch.regs);
		OFFSET(VMX_spec_ctrl, vcpu_vmx, spec_ctrl);
	}

#ifdef CONFIG_KVM_CARETAKER
	/*
	 * Offsets into the caretaker page used by the on-core guest entry and
	 * exit paths in {vmx,svm}/caretaker_vmenter.S.  These used to be a
	 * hand-maintained table of literals in caretaker.h.
	 */
	BLANK();
	OFFSET(CXP_VMCS_PA, caretaker_x86_page, vmcs_pa);
	OFFSET(CXP_VMCB_PA, caretaker_x86_page, vmcb_pa);
	OFFSET(CXP_HSAVE_PA, caretaker_x86_page, hsave_pa);
	OFFSET(CXP_STACK_ORIG, caretaker_x86_page, stack_orig);
	OFFSET(CXP_STACK_TOP, caretaker_x86_page, stack_top);
	OFFSET(CXP_STACK_OFFSET, caretaker_x86_page, stack);
	OFFSET(CXP_TOTAL_EXITS, caretaker_x86_page, total_exits);
	OFFSET(CXP_VMENTRY_ENTRIES, caretaker_x86_page, vmentry_entries);
	OFFSET(CXP_VMRUN_ENTRIES, caretaker_x86_page, vmrun_entries);
	OFFSET(CXP_KERNEL_GS_BASE, caretaker_x86_page, kernel_gs_base);
	OFFSET(CXP_LAST_EXIT_CODE, caretaker_x86_page, last_exit_code);

	BLANK();
	OFFSET(CXP_REG_RAX, caretaker_x86_page, rax);
	OFFSET(CXP_REG_RBX, caretaker_x86_page, rbx);
	OFFSET(CXP_REG_RCX, caretaker_x86_page, rcx);
	OFFSET(CXP_REG_RDX, caretaker_x86_page, rdx);
	OFFSET(CXP_REG_RSI, caretaker_x86_page, rsi);
	OFFSET(CXP_REG_RDI, caretaker_x86_page, rdi);
	OFFSET(CXP_REG_RBP, caretaker_x86_page, rbp);
	OFFSET(CXP_REG_R8, caretaker_x86_page, r8);
	OFFSET(CXP_REG_R9, caretaker_x86_page, r9);
	OFFSET(CXP_REG_R10, caretaker_x86_page, r10);
	OFFSET(CXP_REG_R11, caretaker_x86_page, r11);
	OFFSET(CXP_REG_R12, caretaker_x86_page, r12);
	OFFSET(CXP_REG_R13, caretaker_x86_page, r13);
	OFFSET(CXP_REG_R14, caretaker_x86_page, r14);
	OFFSET(CXP_REG_R15, caretaker_x86_page, r15);
#endif
}
