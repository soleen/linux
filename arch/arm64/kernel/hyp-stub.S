/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Hypervisor stub
 *
 * Copyright (C) 2012 ARM Ltd.
 * Author:	Marc Zyngier <marc.zyngier@arm.com>
 */

#include <linux/init.h>
#include <linux/linkage.h>
#include <linux/irqchip/arm-gic-v3.h>

#include <asm/assembler.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_asm.h>
#include <asm/ptrace.h>
#include <asm/virt.h>

.macro invalid_vector	label
SYM_CODE_START_LOCAL(\label)
	.align 7
	b	\label
SYM_CODE_END(\label)
.endm

.macro hyp_stub_el1_sync
SYM_CODE_START_LOCAL(hyp_stub_el1_sync)
	.align 7
	cmp	x0, #HVC_SET_VECTORS
	b.ne	2f
	msr	vbar_el2, x1
	b	9f

2:	cmp	x0, #HVC_SOFT_RESTART
	b.ne	3f
	mov	x0, x2
	mov	x2, x4
	mov	x4, x1
	mov	x1, x3
	br	x4				// no return

3:	cmp	x0, #HVC_RESET_VECTORS
	beq	9f				// Nothing to reset!

	/* Someone called kvm_call_hyp() against the hyp-stub... */
	mov_q	x0, HVC_STUB_ERR
	eret

9:	mov	x0, xzr
	eret
SYM_CODE_END(hyp_stub_el1_sync)
.endm

	.text
	.pushsection	.hyp.text, "ax"

	.align 11

SYM_CODE_START(__hyp_stub_vectors)
	invalid_vector	hyp_stub_el2t_sync_invalid	// Synchronous EL2t
	invalid_vector	hyp_stub_el2t_irq_invalid	// IRQ EL2t
	invalid_vector	hyp_stub_el2t_fiq_invalid	// FIQ EL2t
	invalid_vector	hyp_stub_el2t_error_invalid	// Error EL2t

	invalid_vector	hyp_stub_el2h_sync_invalid	// Synchronous EL2h
	invalid_vector	hyp_stub_el2h_irq_invalid	// IRQ EL2h
	invalid_vector	hyp_stub_el2h_fiq_invalid	// FIQ EL2h
	invalid_vector	hyp_stub_el2h_error_invalid	// Error EL2h

	hyp_stub_el1_sync				// Synchronous 64-bit EL1
	invalid_vector	hyp_stub_el1_irq_invalid	// IRQ 64-bit EL1
	invalid_vector	hyp_stub_el1_fiq_invalid	// FIQ 64-bit EL1
	invalid_vector	hyp_stub_el1_error_invalid	// Error 64-bit EL1

	invalid_vector	hyp_stub_32b_el1_sync_invalid	// Synchronous 32-bit EL1
	invalid_vector	hyp_stub_32b_el1_irq_invalid	// IRQ 32-bit EL1
	invalid_vector	hyp_stub_32b_el1_fiq_invalid	// FIQ 32-bit EL1
	invalid_vector	hyp_stub_32b_el1_error_invalid	// Error 32-bit EL1
	.align 11
SYM_INNER_LABEL(__hyp_stub_vectors_end, SYM_L_LOCAL)
SYM_CODE_END(__hyp_stub_vectors)

# Check the __hyp_stub_vectors didn't overflow
.org . - (__hyp_stub_vectors_end - __hyp_stub_vectors) + SZ_2K

/*
 * __hyp_set_vectors: Call this after boot to set the initial hypervisor
 * vectors as part of hypervisor installation.  On an SMP system, this should
 * be called on each CPU.
 *
 * x0 must be the physical address of the new vector table, and must be
 * 2KB aligned.
 *
 * Before calling this, you must check that the stub hypervisor is installed
 * everywhere, by waiting for any secondary CPUs to be brought up and then
 * checking that is_hyp_mode_available() is true.
 *
 * If not, there is a pre-existing hypervisor, some CPUs failed to boot, or
 * something else went wrong... in such cases, trying to install a new
 * hypervisor is unlikely to work as desired.
 *
 * When you call into your shiny new hypervisor, sp_el2 will contain junk,
 * so you will need to set that to something sensible at the new hypervisor's
 * initialisation entry point.
 */

SYM_FUNC_START(__hyp_set_vectors)
	mov	x1, x0
	mov	x0, #HVC_SET_VECTORS
	hvc	#0
	ret
SYM_FUNC_END(__hyp_set_vectors)

SYM_FUNC_START(__hyp_reset_vectors)
	mov	x0, #HVC_RESET_VECTORS
	hvc	#0
	ret
SYM_FUNC_END(__hyp_reset_vectors)

SYM_FUNC_START(__arm64_call_hyp)
	hvc	#0
	ret
SYM_FUNC_END(__arm64_call_hyp)
