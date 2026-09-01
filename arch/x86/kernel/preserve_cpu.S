/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/linkage.h>
#include <asm/nospec-branch.h>
#include <asm/unwind_hints.h>

	.section .text.cpu_preserved, "ax"

SYM_CODE_START(x86_preserved_iret_err_stub)
	UNWIND_HINT_IRET_REGS
	ENDBR
	addq	$8, %rsp
	iretq
SYM_CODE_END(x86_preserved_iret_err_stub)

SYM_CODE_START(x86_preserved_iret_stub)
	UNWIND_HINT_IRET_REGS
	ENDBR
	iretq
SYM_CODE_END(x86_preserved_iret_stub)

SYM_CODE_START(x86_preserved_apic_eoi_stub)
	UNWIND_HINT_IRET_REGS
	ENDBR
	pushq	%rax
	pushq	%rcx
	pushq	%rdx
	movl	$0x1b, %ecx
	rdmsr
	testl	$0x400, %eax
	jz	1f
	/* x2APIC mode: MSR 0x80b (APIC_EOI) = 0 */
	movl	$0x80b, %ecx
	xorl	%eax, %eax
	xorl	%edx, %edx
	wrmsr
	jmp	2f
1:
	/* xAPIC mode: MMIO fixmap APIC EOI */
	movq	x86_preserved_apic_eoi_va(%rip), %rax
	testq	%rax, %rax
	jz	2f
	movl	$0, (%rax)
2:
	popq	%rdx
	popq	%rcx
	popq	%rax
	iretq
SYM_CODE_END(x86_preserved_apic_eoi_stub)

/*
 * arch_cpu_preserved_call_on_stack - Switch stack and call function
 * @cpu: CPU ID (%rdi)
 * @stack: Target stack top (%rsi)
 * @fn: Function pointer to invoke (%rdx)
 */
SYM_FUNC_START(arch_cpu_preserved_call_on_stack)
	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%r12

	movq	%rsp, %r12	/* save old stack pointer */
	movq	%rsi, %rsp	/* switch to target stack */

	call	*%rdx		/* call fn(cpu) */

	movq	%r12, %rsp	/* restore old stack pointer */
	popq	%r12
	leave
	ret
SYM_FUNC_END(arch_cpu_preserved_call_on_stack)
