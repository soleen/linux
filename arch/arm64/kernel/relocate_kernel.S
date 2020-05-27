/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * kexec for arm64
 *
 * Copyright (C) Linaro.
 * Copyright (C) Huawei Futurewei Technologies.
 */

#include <linux/kexec.h>
#include <linux/linkage.h>

#include <asm/assembler.h>
#include <asm/kexec.h>
#include <asm/page.h>
#include <asm/sysreg.h>
#include <asm/virt.h>

/*
 * arm64_relocate_new_kernel - Put a 2nd stage image in place and boot it.
 *
 * The memory that the old kernel occupies may be overwritten when coping the
 * new image to its final location.  To assure that the
 * arm64_relocate_new_kernel routine which does that copy is not overwritten,
 * all code and data needed by arm64_relocate_new_kernel must be between the
 * symbols arm64_relocate_new_kernel and arm64_relocate_new_kernel_end.  The
 * machine_kexec() routine will copy arm64_relocate_new_kernel to the kexec
 * control_code_page, a special page which has been set up to be preserved
 * during the copy operation.
 *
 * x0: physical address of the kimage
 */
SYM_CODE_START(arm64_relocate_new_kernel)

	/* Setup the list loop variables. */
	ldr	x21, [x0, #KIMAGE_ARCH_ZERO_PAGE] /* x21 = zero page for BBM */
	ldr	x20, [x0, #KIMAGE_ARCH_TTBR1]	/* x20 = linear map copy */
	ldr	x19, [x0, #KIMAGE_ARCH_HYP_STUB] /* x19 = exit via hyp stub */
	ldr	x18, [x0, #KIMAGE_ARCH_DTB_MEM]	/* x18 = dtb address */
	ldr	x17, [x0, #KIMAGE_START]		/* x17 = kimage_start */
	ldr	x16, [x0, #KIMAGE_HEAD]		/* x16 = kimage_head */
	raw_dcache_line_size x15, x0		/* x15 = dcache line size */
	mov	x14, xzr			/* x14 = entry ptr */
	mov	x13, xzr			/* x13 = copy dest */

	/* Switch to the new copy of the linear map */
	break_before_make_ttbr_switch	x21, x20, x0, x1

.Lloop:
	and	x12, x16, PAGE_MASK		/* x12 = addr */

	/* Test the entry flags. */
.Ltest_source:
	tbz	x16, IND_SOURCE_BIT, .Ltest_indirection

	/* Invalidate dest page to PoC. */
	mov	x0, x13
	mov	x1, #PAGE_SIZE
	dcache_by_myline_op ivac, sy, x0, x1, x15, x20

	mov x20, x13
	mov x21, x12
	copy_page x20, x21, x0, x1, x2, x3, x4, x5, x6, x7

	/* dest += PAGE_SIZE */
	add	x13, x13, PAGE_SIZE
	b	.Lnext

.Ltest_indirection:
	tbz	x16, IND_INDIRECTION_BIT, .Ltest_destination

	/* ptr = addr */
	mov	x14, x12
	b	.Lnext

.Ltest_destination:
	tbz	x16, IND_DESTINATION_BIT, .Lnext

	/* dest = addr */
	mov	x13, x12

.Lnext:
	/* entry = *ptr++ */
	ldr	x16, [x14], #8

	/* while (!(entry & DONE)) */
	tbz	x16, IND_DONE_BIT, .Lloop

.Ldone:
	/* wait for writes from copy_page to finish */
	dsb	nsh
	ic	iallu
	dsb	nsh
	isb

	cbz	x19, .Lstart_at_el1

	/* Start new image at EL2, calling hyp-stub. */
	mov     x0, #HVC_SOFT_RESTART
	mov	x1, x17
	mov	x2, x18
	mov	x3, xzr
	mov	x4, xzr
	hvc	#0

.Lstart_at_el1:
	/* Start new image at EL1. */
	mov	x0, x18
	mov	x1, xzr
	mov	x2, xzr
	mov	x3, xzr
	br	x17
SYM_INNER_LABEL(arm64_relocate_new_kernel_end, SYM_L_GLOBAL)
SYM_CODE_END(arm64_relocate_new_kernel)
