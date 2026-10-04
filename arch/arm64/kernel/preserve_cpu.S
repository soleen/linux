/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Low-level assembly routines for ARM64 physical CPU preservation.
 *
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 */
#include <linux/linkage.h>
#include <asm/assembler.h>

	.text

/*
 * __arch_cpu_preserved_park_on_stack - Switch stack and enter park loop
 * @cpu: Logical CPU identifier (x0)
 * @stack_top: Top of runtime allocated stack (x1)
 */
SYM_FUNC_START(__arch_cpu_preserved_park_on_stack)
	mov	sp, x1
	mov	x19, x0
	bl	cpu_preserved_park_loop
	mov	x0, x19
	bl	arch_cpu_preserved_park_finish
	b	.
SYM_FUNC_END(__arch_cpu_preserved_park_on_stack)

/*
 * __arch_cpu_preserved_dcache_clean - Clean and invalidate data cache to PoC
 * @start: Virtual start address (x0)
 * @end: Virtual end address (x1)
 */
SYM_FUNC_START(__arch_cpu_preserved_dcache_clean)
	dsb	sy
	raw_dcache_line_size x2, x3
	dcache_by_myline_op_nosync civac, x0, x1, x2, x3
	dsb	sy
	ret
SYM_FUNC_END(__arch_cpu_preserved_dcache_clean)
SYM_FUNC_ALIAS(arch_cpu_preserved_dcache_clean, __arch_cpu_preserved_dcache_clean)
SYM_FUNC_ALIAS(arch_cpu_preserved_dcache_inval, __arch_cpu_preserved_dcache_clean)

.macro preserved_ventry kind
	.align 7
	mov	x0, #\kind
	b	arm64_preserved_vec_common
.endm

	.align 11
SYM_CODE_START(arm64_preserved_vectors)
	preserved_ventry 0
	preserved_ventry 1
	preserved_ventry 2
	preserved_ventry 3
	preserved_ventry 4
	preserved_ventry 5
	preserved_ventry 6
	preserved_ventry 7
	preserved_ventry 8
	preserved_ventry 9
	preserved_ventry 10
	preserved_ventry 11
	preserved_ventry 12
	preserved_ventry 13
	preserved_ventry 14
	preserved_ventry 15
SYM_CODE_END(arm64_preserved_vectors)

SYM_CODE_START_LOCAL(arm64_preserved_vec_common)
	mov	x1, sp
	and	x1, x1, #~(THREAD_SIZE - 1)
	add	x1, x1, #THREAD_SIZE
	sub	sp, x1, #256
	mov	x29, xzr
	bl	arm64_preserved_handle_exception
	b	.
SYM_CODE_END(arm64_preserved_vec_common)
