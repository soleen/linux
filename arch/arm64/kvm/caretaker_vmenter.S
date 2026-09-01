/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Caretaker low-level guest entry/exit and vector table for ARM64 VHE.
 *
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 */

#include <linux/linkage.h>
#include <asm/assembler.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_asm.h>
#include <asm/sysreg.h>
#include "caretaker.h"

	.pushsection ".text.cpu_preserved", "ax"

.macro cventry target
	.align 7
	stp	x0, x1, [sp, #-16]!
	b	\target
.endm

	.align 11
SYM_CODE_START(caretaker_hyp_vector)
	/* Current EL with SP0 */
	cventry	caretaker_invalid
	cventry	caretaker_el2h_irq
	cventry	caretaker_el2h_irq
	cventry	caretaker_invalid

	/* Current EL with SPx (EL2h) */
	cventry	caretaker_invalid
	cventry	caretaker_el2h_irq
	cventry	caretaker_el2h_irq
	cventry	caretaker_invalid

	/* Lower EL using AArch64 (Guest EL1/EL0) */
	cventry	caretaker_el1_sync
	cventry	caretaker_el1_irq
	cventry	caretaker_el1_fiq
	cventry	caretaker_el1_error

	/* Lower EL using AArch32 */
	cventry	caretaker_el1_sync
	cventry	caretaker_el1_irq
	cventry	caretaker_el1_fiq
	cventry	caretaker_el1_error
SYM_CODE_END(caretaker_hyp_vector)

SYM_CODE_START_LOCAL(caretaker_invalid)
	b	caretaker_invalid
SYM_CODE_END(caretaker_invalid)

SYM_CODE_START_LOCAL(caretaker_el2h_irq)
	stp	x2, x3,   [sp, #-16]!
	stp	x4, x5,   [sp, #-16]!
	stp	x6, x7,   [sp, #-16]!
	stp	x8, x9,   [sp, #-16]!
	stp	x10, x11, [sp, #-16]!
	stp	x12, x13, [sp, #-16]!
	stp	x14, x15, [sp, #-16]!
	stp	x16, x17, [sp, #-16]!
	stp	x29, x30, [sp, #-16]!

	mrs_s	x0, SYS_ICC_IAR1_EL1
	cmp	x0, #1020
	b.ge	1f
	msr_s	SYS_ICC_EOIR1_EL1, x0
	msr_s	SYS_ICC_DIR_EL1, x0
1:
	mrs_s	x0, SYS_ICC_IAR0_EL1
	cmp	x0, #1020
	b.ge	2f
	msr_s	SYS_ICC_EOIR0_EL1, x0
	msr_s	SYS_ICC_DIR_EL1, x0
2:
	ldp	x29, x30, [sp], #16
	ldp	x16, x17, [sp], #16
	ldp	x14, x15, [sp], #16
	ldp	x12, x13, [sp], #16
	ldp	x10, x11, [sp], #16
	ldp	x8, x9,   [sp], #16
	ldp	x6, x7,   [sp], #16
	ldp	x4, x5,   [sp], #16
	ldp	x2, x3,   [sp], #16
	ldp	x0, x1,   [sp], #16
	eret
	sb
SYM_CODE_END(caretaker_el2h_irq)

SYM_CODE_START_LOCAL(caretaker_el1_sync)
	mov	x0, #ARM_EXCEPTION_TRAP
	b	caretaker_guest_exit
SYM_CODE_END(caretaker_el1_sync)

SYM_CODE_START_LOCAL(caretaker_el1_irq)
SYM_CODE_START_LOCAL(caretaker_el1_fiq)
	mov	x0, #ARM_EXCEPTION_IRQ
	b	caretaker_guest_exit
SYM_CODE_END(caretaker_el1_fiq)
SYM_CODE_END(caretaker_el1_irq)

SYM_CODE_START_LOCAL(caretaker_el1_error)
	mov	x0, #ARM_EXCEPTION_EL1_SERROR
	b	caretaker_guest_exit
SYM_CODE_END(caretaker_el1_error)

/*
 * u64 caretaker_guest_enter(struct kvm_vcpu *vcpu);
 *   x0: vcpu pointer
 * Returns exit code in x0.
 */
SYM_FUNC_START(caretaker_guest_enter)
	// Save host callee-saved registers on stack
	stp	x19, x20, [sp, #-112]!
	stp	x21, x22, [sp, #16]
	stp	x23, x24, [sp, #32]
	stp	x25, x26, [sp, #48]
	stp	x27, x28, [sp, #64]
	stp	x29, x30, [sp, #80]
	str	x0, [sp, #96]			// Save vcpu pointer on host stack
	mrs	x1, sp_el0
	str	x1, [sp, #104]			// Save host sp_el0 (current task)

	// Install caretaker vectors
	adr_l	x1, caretaker_hyp_vector
	msr	vbar_el1, x1
	msr	vbar_el2, x1
	isb

	// Restore guest context from ctx->ctxt
	add	x29, x0, #CAP_CTXT_OFFSET

	ldr	x1, [x29, #CPU_XREG_OFFSET(32)]	// regs.pc
	msr	elr_el2, x1
	ldr	x1, [x29, #CPU_XREG_OFFSET(33)]	// regs.pstate
	msr	spsr_el2, x1
	ldr	x1, [x29, #CPU_XREG_OFFSET(31)]	// regs.sp
	msr	sp_el0, x1

	// Restore guest GPRs x0-x28, lr (x30)
	ldp	x0, x1, [x29, #CPU_XREG_OFFSET(0)]
	ldp	x2, x3, [x29, #CPU_XREG_OFFSET(2)]
	ldp	x4, x5, [x29, #CPU_XREG_OFFSET(4)]
	ldp	x6, x7, [x29, #CPU_XREG_OFFSET(6)]
	ldp	x8, x9, [x29, #CPU_XREG_OFFSET(8)]
	ldp	x10, x11, [x29, #CPU_XREG_OFFSET(10)]
	ldp	x12, x13, [x29, #CPU_XREG_OFFSET(12)]
	ldp	x14, x15, [x29, #CPU_XREG_OFFSET(14)]
	ldp	x16, x17, [x29, #CPU_XREG_OFFSET(16)]
	ldp	x18, x19, [x29, #CPU_XREG_OFFSET(18)]
	ldp	x20, x21, [x29, #CPU_XREG_OFFSET(20)]
	ldp	x22, x23, [x29, #CPU_XREG_OFFSET(22)]
	ldp	x24, x25, [x29, #CPU_XREG_OFFSET(24)]
	ldp	x26, x27, [x29, #CPU_XREG_OFFSET(26)]
	ldr	x30,      [x29, #CPU_XREG_OFFSET(30)]
	ldp	x28, x29, [x29, #CPU_XREG_OFFSET(28)]

	eret
	sb
SYM_FUNC_END(caretaker_guest_enter)

SYM_CODE_START_LOCAL(caretaker_guest_exit)
	// Save exception code in x0 temporarily
	str	x0, [sp, #-16]!

	// Retrieve ctx pointer from host stack
	ldr	x0, [sp, #128]
	add	x1, x0, #CAP_CTXT_OFFSET

	// Save guest GPRs x2-x29, lr (x30)
	stp	x2, x3,   [x1, #CPU_XREG_OFFSET(2)]
	stp	x4, x5,   [x1, #CPU_XREG_OFFSET(4)]
	stp	x6, x7,   [x1, #CPU_XREG_OFFSET(6)]
	stp	x8, x9,   [x1, #CPU_XREG_OFFSET(8)]
	stp	x10, x11, [x1, #CPU_XREG_OFFSET(10)]
	stp	x12, x13, [x1, #CPU_XREG_OFFSET(12)]
	stp	x14, x15, [x1, #CPU_XREG_OFFSET(14)]
	stp	x16, x17, [x1, #CPU_XREG_OFFSET(16)]
	stp	x18, x19, [x1, #CPU_XREG_OFFSET(18)]
	stp	x20, x21, [x1, #CPU_XREG_OFFSET(20)]
	stp	x22, x23, [x1, #CPU_XREG_OFFSET(22)]
	stp	x24, x25, [x1, #CPU_XREG_OFFSET(24)]
	stp	x26, x27, [x1, #CPU_XREG_OFFSET(26)]
	stp	x28, x29, [x1, #CPU_XREG_OFFSET(28)]
	str	x30,      [x1, #CPU_XREG_OFFSET(30)]

	// Retrieve and save guest x0, x1 (from vector entry on stack)
	ldp	x2, x3, [sp, #16]
	stp	x2, x3, [x1, #CPU_XREG_OFFSET(0)]

	// Save guest system registers
	mrs	x2, elr_el2
	str	x2, [x1, #CPU_XREG_OFFSET(32)]	// regs.pc
	mrs	x2, spsr_el2
	str	x2, [x1, #CPU_XREG_OFFSET(33)]	// regs.pstate
	mrs	x2, sp_el0
	str	x2, [x1, #CPU_XREG_OFFSET(31)]	// regs.sp
	mrs	x2, esr_el2
	str	x2, [x0, #CAP_FAULT_ESR]
	mrs	x2, far_el2
	str	x2, [x0, #CAP_FAULT_FAR]
	mrs	x2, hpfar_el2
	str	x2, [x0, #CAP_FAULT_HPFAR]

	// Restore return value (exception code) in x0
	ldr	x0, [sp], #32			// pops exception code + saved x0,x1

	// Restore host callee-saved registers
	ldp	x19, x20, [sp, #0]
	ldp	x21, x22, [sp, #16]
	ldp	x23, x24, [sp, #32]
	ldp	x25, x26, [sp, #48]
	ldp	x27, x28, [sp, #64]
	ldp	x29, x30, [sp, #80]
	ldr	x1, [sp, #104]
	msr	sp_el0, x1
	add	sp, sp, #112

	ret
SYM_CODE_END(caretaker_guest_exit)

	.popsection
