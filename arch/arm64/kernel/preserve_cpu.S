/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Low-level assembly routines for ARM64 physical CPU preservation.
 *
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 */
#include <linux/linkage.h>
#include <asm/assembler.h>

	.section .text.cpu_preserved, "ax"

/*
 * arch_cpu_preserved_park_on_stack - Switch stack and enter park loop
 * @cpu: Logical CPU identifier (x0)
 * @stack_top: Top of runtime allocated stack (x1)
 */
SYM_FUNC_START(arch_cpu_preserved_park_on_stack)
	stp	x29, x30, [sp, #-32]!
	stp	x19, x20, [sp, #16]
	mov	x29, sp
	mov	x20, sp
	mov	sp, x1
	mov	x19, x0
	bl	cpu_preserved_park_loop
	mov	x0, x19
	bl	arch_cpu_preserved_park_finish
	b	.
SYM_FUNC_END(arch_cpu_preserved_park_on_stack)
EXPORT_SYMBOL(arch_cpu_preserved_park_on_stack)

/*
 * __arch_cpu_preserved_dcache_clean - Clean and invalidate data cache to PoC
 * @start: Virtual start address (x0)
 * @end: Virtual end address (x1)
 */
SYM_FUNC_START(__arch_cpu_preserved_dcache_clean)
	dsb	sy
	mrs	x3, ctr_el0
	ubfx	x3, x3, #16, #4
	mov	x2, #4
	lsl	x2, x2, x3
	sub	x3, x2, #1
	bic	x0, x0, x3
1:	dc	civac, x0
	add	x0, x0, x2
	cmp	x0, x1
	b.lo	1b
	dsb	sy
	ret
SYM_FUNC_END(__arch_cpu_preserved_dcache_clean)
SYM_FUNC_ALIAS(arch_cpu_preserved_dcache_clean, __arch_cpu_preserved_dcache_clean)
SYM_FUNC_ALIAS(arch_cpu_preserved_dcache_inval, __arch_cpu_preserved_dcache_clean)
EXPORT_SYMBOL(__arch_cpu_preserved_dcache_clean)
EXPORT_SYMBOL(arch_cpu_preserved_dcache_clean)
EXPORT_SYMBOL(arch_cpu_preserved_dcache_inval)
