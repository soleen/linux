/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/linkage.h>
#include <asm/asm.h>
#include <asm/bitsperlong.h>
#include <asm/kvm_vcpu_regs.h>
#include <asm/nospec-branch.h>
#include "caretaker.h"
#include "../caretaker_asm.h"

.section .text.cpu_preserved, "ax"

/**
 * vmx_caretaker_enter - Low-level transition to VMX guest mode and back
 * @cvp: Pointer to struct caretaker_vmx_page (%rdi)
 */
SYM_FUNC_START(vmx_caretaker_enter)
	ENDBR
	CARETAKER_PUSH_HOST_REGS
	movq %rsp, CXP_STACK_ORIG(%rdi)

	/* Switch to private preserved stack */
	movq CXP_STACK_TOP(%rdi), %rsp

	/* Activate VMCS on this pCPU */
	vmptrld CXP_VMCS_PA(%rdi)

	/* Restore guest MSR_KERNEL_GS_BASE if valid/canonical */
	movq CXP_KERNEL_GS_BASE(%rdi), %rax
	movq %rax, %rdx
	sarq $47, %rdx
	incq %rdx
	cmpq $1, %rdx
	ja 1f
	movl $0xc0000102, %ecx /* MSR_KERNEL_GS_BASE */
	movq CXP_KERNEL_GS_BASE(%rdi), %rax
	movq %rax, %rdx
	shrq $32, %rdx
	wrmsr
1:

	/* Restore guest GPRs */
	CARETAKER_RESTORE_GPRS %rdi
	incq CXP_VMENTRY_ENTRIES(%rdi)

	pushq %rdi
	movq CXP_REG_RDI(%rdi), %rdi

	/* Launch or resume */
	vmresume
	vmlaunch

	/* If both fail, record error and return */
	popq %rdi
	mov $0x00004400, %eax /* VM_INSTRUCTION_ERROR */
	vmread %rax, %rax
	movq %rax, CXP_LAST_EXIT_CODE(%rdi)
	btsq $31, %rax
	jmp .Lvmx_ret
SYM_FUNC_END(vmx_caretaker_enter)

.global vmx_caretaker_exit_handler
SYM_CODE_START(vmx_caretaker_exit_handler)
	ENDBR
	/*
	 * Hardware jumps here on VM-Exit with:
	 * RSP = HOST_RSP (CXP_STACK_TOP)
	 * CR3 = HOST_CR3
	 */
	pushq %rdi

	/* Recompute CVP pointer from RSP: CVP = (RSP & ~0xFFF) - CXP_STACK_OFFSET */
	movq %rsp, %rdi
	andq $~0xFFF, %rdi
	subq $CXP_STACK_OFFSET, %rdi

	/* Save guest GPRs into CVP */
	CARETAKER_SAVE_GPRS %rdi
	popq CXP_REG_RDI(%rdi)

	/* Record telemetry */
	incq CXP_TOTAL_EXITS(%rdi)

	/* Read guest MSR_KERNEL_GS_BASE */
	movl $0xc0000102, %ecx /* MSR_KERNEL_GS_BASE */
	rdmsr
	shlq $32, %rdx
	orq %rax, %rdx
	movq %rdx, CXP_KERNEL_GS_BASE(%rdi)

	xorq %rax, %rax
	jmp .Lvmx_ret

.Lvmx_ret:
	/* Restore caller stack */
	movq CXP_STACK_ORIG(%rdi), %rsp

	/* Restore host callee-saved registers */
	CARETAKER_POP_HOST_REGS
	ret
SYM_CODE_END(vmx_caretaker_exit_handler)
