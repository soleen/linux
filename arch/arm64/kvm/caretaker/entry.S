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

	.text

.macro cventry target
	.align 7
	esb
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
	mrs	x0, elr_el2
	mrs	x1, esr_el2
	mrs	x2, far_el2
	b	arm64_caretaker_handle_invalid
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
	cmp	x0, #ICC_IAR1_EL1_SPECIAL_START
	b.ge	1f
	msr_s	SYS_ICC_EOIR1_EL1, x0
	msr_s	SYS_ICC_DIR_EL1, x0
1:
	/*
	 * Silence the EL2 physical timer before returning.
	 *
	 * It is the only EL2 interrupt source the Caretaker arms
	 * (arm64_caretaker_op_arm_timer() writes CNTHP_CTL_EL2.ENABLE to
	 * drive the on-core quantum), and it is level-triggered off
	 * CNTHP_CTL_EL2.ISTATUS.  Neither EOIR1 nor DIR clears ISTATUS, so
	 * without disabling ENABLE here the line re-asserts the instant we
	 * eret and the core live-locks taking the same interrupt forever --
	 * it never reaches the run loop, which means it can never observe a
	 * detach request and can never be reclaimed.
	 *
	 * This is done on the special-INTID path too: a spurious read of
	 * IAR1 does not mean the timer has stopped asserting.  The run loop
	 * re-arms the timer for each new quantum, so dropping it here costs
	 * at most the remainder of the current one.
	 */
	msr_s	SYS_CNTHP_CTL_EL2, xzr
	isb

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
	get_loaded_vcpu	x1, x0
	mov	x0, #ARM_EXCEPTION_TRAP
	b	__guest_exit
SYM_CODE_END(caretaker_el1_sync)

SYM_CODE_START_LOCAL(caretaker_el1_irq)
SYM_CODE_START_LOCAL(caretaker_el1_fiq)
	get_loaded_vcpu	x1, x0
	mov	x0, #ARM_EXCEPTION_IRQ
	b	__guest_exit
SYM_CODE_END(caretaker_el1_fiq)
SYM_CODE_END(caretaker_el1_irq)

SYM_CODE_START_LOCAL(caretaker_el1_error)
	get_loaded_vcpu	x1, x0
	mov	x0, #ARM_EXCEPTION_EL1_SERROR
	b	__guest_exit
SYM_CODE_END(caretaker_el1_error)
