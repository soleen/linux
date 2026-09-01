/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * Assembly macros for x86 Caretaker host context switch and guest GPRs.
 */
#ifndef __ARCH_X86_KVM_CARETAKER_ASM_H
#define __ARCH_X86_KVM_CARETAKER_ASM_H

#include "caretaker.h"

/* Save host callee-saved registers to caller stack */
.macro CARETAKER_PUSH_HOST_REGS
	pushq %rbp
	movq %rsp, %rbp
	pushq %rbx
	pushq %r12
	pushq %r13
	pushq %r14
	pushq %r15
.endm

/* Restore host callee-saved registers from caller stack */
.macro CARETAKER_POP_HOST_REGS
	popq %r15
	popq %r14
	popq %r13
	popq %r12
	popq %rbx
	popq %rbp
.endm

/* Restore guest GPRs (RBX..R15) from preserved page structure */
.macro CARETAKER_RESTORE_GPRS_NO_RAX base:req
	movq CXP_REG_RBX(\base), %rbx
	movq CXP_REG_RCX(\base), %rcx
	movq CXP_REG_RDX(\base), %rdx
	movq CXP_REG_RSI(\base), %rsi
	movq CXP_REG_RBP(\base), %rbp
	movq CXP_REG_R8(\base),  %r8
	movq CXP_REG_R9(\base),  %r9
	movq CXP_REG_R10(\base), %r10
	movq CXP_REG_R11(\base), %r11
	movq CXP_REG_R12(\base), %r12
	movq CXP_REG_R13(\base), %r13
	movq CXP_REG_R14(\base), %r14
	movq CXP_REG_R15(\base), %r15
.endm

/* Restore guest GPRs including RAX from preserved page structure */
.macro CARETAKER_RESTORE_GPRS base:req
	movq CXP_REG_RAX(\base), %rax
	CARETAKER_RESTORE_GPRS_NO_RAX \base
.endm

/* Save guest GPRs (RBX..R15) to preserved page structure */
.macro CARETAKER_SAVE_GPRS_NO_RAX base:req
	movq %rbx, CXP_REG_RBX(\base)
	movq %rcx, CXP_REG_RCX(\base)
	movq %rdx, CXP_REG_RDX(\base)
	movq %rsi, CXP_REG_RSI(\base)
	movq %rbp, CXP_REG_RBP(\base)
	movq %r8,  CXP_REG_R8(\base)
	movq %r9,  CXP_REG_R9(\base)
	movq %r10, CXP_REG_R10(\base)
	movq %r11, CXP_REG_R11(\base)
	movq %r12, CXP_REG_R12(\base)
	movq %r13, CXP_REG_R13(\base)
	movq %r14, CXP_REG_R14(\base)
	movq %r15, CXP_REG_R15(\base)
.endm

/* Save guest GPRs including RAX to preserved page structure */
.macro CARETAKER_SAVE_GPRS base:req
	movq %rax, CXP_REG_RAX(\base)
	CARETAKER_SAVE_GPRS_NO_RAX \base
.endm

#endif /* __ARCH_X86_KVM_CARETAKER_ASM_H */
