/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 */
#include <linux/linkage.h>
#include <asm/nospec-branch.h>
#include <asm/segment.h>
#include <asm/trapnr.h>
#include <asm/unwind_hints.h>

	.text

SYM_CODE_START(x86_preserved_exc_handler_array)
	i = 0
	.rept NUM_EXCEPTION_VECTORS
	.if ((EXCEPTION_ERRCODE_MASK >> i) & 1) == 0
		UNWIND_HINT_IRET_REGS
		ENDBR
		pushq	$0	/* Dummy error code */
	.else
		UNWIND_HINT_IRET_REGS offset=8
		ENDBR
	.endif
	pushq	$i		/* Vector number */
	jmp	x86_preserved_exc_handler_common
	UNWIND_HINT_IRET_REGS
	i = i + 1
	.fill x86_preserved_exc_handler_array + i * EARLY_IDT_HANDLER_SIZE - ., 1, 0xcc
	.endr
SYM_CODE_END(x86_preserved_exc_handler_array)
	ANNOTATE_NOENDBR

SYM_CODE_START_LOCAL(x86_preserved_exc_handler_common)
	UNWIND_HINT_IRET_REGS offset=16
	cld

	/* The vector number is currently in the pt_regs->di slot. */
	pushq	%rsi
	movq	8(%rsp), %rsi		/* RSI = vector number */
	movq	%rdi, 8(%rsp)		/* pt_regs->di = RDI */
	pushq	%rdx
	pushq	%rcx
	pushq	%rax
	pushq	%r8
	pushq	%r9
	pushq	%r10
	pushq	%r11
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
	UNWIND_HINT_REGS

	movq	%rsp, %rdi		/* RDI = pt_regs; RSI = vector */
	call	x86_preserved_handle_exception

	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbp
	popq	%rbx
	popq	%r11
	popq	%r10
	popq	%r9
	popq	%r8
	popq	%rax
	popq	%rcx
	popq	%rdx
	popq	%rsi
	popq	%rdi
	addq	$8, %rsp		/* pop orig_ax / error_code */
	UNWIND_HINT_IRET_REGS
	iretq
SYM_CODE_END(x86_preserved_exc_handler_common)

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
	/* x2APIC mode: MSR 0x80b (APIC_EOI) = 0 */
	movl	$0x80b, %ecx
	xorl	%eax, %eax
	xorl	%edx, %edx
	wrmsr
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
SYM_CODE_START(arch_cpu_preserved_call_on_stack)
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
SYM_CODE_END(arch_cpu_preserved_call_on_stack)
