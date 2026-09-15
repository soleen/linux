/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 */
#include <linux/linkage.h>
#include <linux/cfi_types.h>
#include <linux/objtool.h>
#include <asm/asm.h>
#include <asm/bitsperlong.h>
#include <asm/kvm_vcpu_regs.h>
#include <asm/nospec-branch.h>
#include <asm/msr-index.h>
#include <asm/page_types.h>
#include "caretaker.h"
#include "../caretaker_asm.h"

.section .text.cpu_preserved, "ax"

/**
 * vmx_caretaker_enter - Low-level transition to VMX guest mode and back
 * @cvp: Pointer to struct caretaker_vmx_page (%rdi)
 */
SYM_TYPED_FUNC_START(vmx_caretaker_enter)
	ENDBR
	CARETAKER_PUSH_HOST_REGS
	movq %rsp, CXP_STACK_ORIG(%rdi)

	/* Switch to private preserved stack at top of caretaker_x86_page */
	leaq PAGE_SIZE(%rdi), %rsp

	/* Activate VMCS on this pCPU */
	vmptrld CXP_VMCS_PA(%rdi)

	/* Restore guest MSR_KERNEL_GS_BASE if valid/canonical */
	movq CXP_KERNEL_GS_BASE(%rdi), %rax
	movq %rax, %rdx
	sarq $56, %rdx
	incq %rdx
	cmpq $1, %rdx
	ja 2f
	movl $MSR_KERNEL_GS_BASE, %ecx
	movq CXP_KERNEL_GS_BASE(%rdi), %rax
	movq %rax, %rdx
	shrq $32, %rdx
1:	wrmsr
2:
	_ASM_EXTABLE(1b, 2b)

	/* Restore guest GPRs */
	CARETAKER_RESTORE_GPRS %rdi

	pushq %rdi
	movq CXP_REG_RDI(%rdi), %rdi

	/* Clear CPU microarchitectural buffers before guest entry */
	CARETAKER_CLEAR_CPU_BUFFERS

	/* Launch or resume */
	vmresume
	vmlaunch

	/* If both fail, return error in %rax */
	popq %rdi
	mov $VMCS_VM_INSTRUCTION_ERROR, %eax
	vmread %rax, %rax
	btsq $31, %rax
	jmp .Lvmx_ret
SYM_FUNC_END(vmx_caretaker_enter)

SYM_FUNC_START(vmx_caretaker_exit_handler)
	ENDBR
	/*
	 * Hardware jumps here on VM-Exit with:
	 * RSP = HOST_RSP (top of 4 KB struct caretaker_x86_page)
	 * CR3 = HOST_CR3
	 */
	pushq %rdi

	/* Recover CVP base from RSP: stack lives in the upper half of page 0 */
	movq %rsp, %rdi
	andq $PAGE_MASK, %rdi

	/* Save guest GPRs into CVP */
	CARETAKER_SAVE_GPRS %rdi
	popq CXP_REG_RDI(%rdi)

	/* Stuff Return Stack Buffer to prevent guest RSB poisoning */
	CARETAKER_FILL_RETURN_BUFFER %rax

	/* Read guest MSR_KERNEL_GS_BASE */
	movl $MSR_KERNEL_GS_BASE, %ecx
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
SYM_FUNC_END(vmx_caretaker_exit_handler)
STACK_FRAME_NON_STANDARD(vmx_caretaker_enter)
STACK_FRAME_NON_STANDARD(vmx_caretaker_exit_handler)
