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
	dcache_by_line_op civac, sy, x0, x1, x2, x3
	ret
SYM_FUNC_END(__arch_cpu_preserved_dcache_clean)
SYM_FUNC_ALIAS(arch_cpu_preserved_dcache_clean, __arch_cpu_preserved_dcache_clean)
SYM_FUNC_ALIAS(arch_cpu_preserved_dcache_inval, __arch_cpu_preserved_dcache_clean)
EXPORT_SYMBOL(__arch_cpu_preserved_dcache_clean)
EXPORT_SYMBOL(arch_cpu_preserved_dcache_clean)
EXPORT_SYMBOL(arch_cpu_preserved_dcache_inval)
