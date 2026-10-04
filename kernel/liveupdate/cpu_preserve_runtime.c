// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * Isolated runtime execution loop for preserved physical CPUs across Live Update.
 */

#include <linux/atomic.h>
#include <linux/cpu_preserve.h>
#include <linux/cpumask.h>
#include <linux/kho/abi/cpu.h>
#include <linux/objtool.h>
#include <linux/types.h>

cpumask_t cpu_preserved_mask;

/**
 * cpu_is_preserved - Check whether a CPU is currently preserved
 * @cpu: Logical CPU identifier.
 *
 * Return: True if @cpu is currently preserved, false otherwise.
 */
bool cpu_is_preserved(int cpu)
{
	if ((unsigned int)cpu >= CONFIG_NR_CPUS)
		return false;
	return arch_test_bit(cpu, cpumask_bits(&cpu_preserved_mask));
}

/**
 * cpu_preserved_set_dead - Mark the current preserved CPU as fully dead/stopped
 */
void cpu_preserved_set_dead(void)
{
	struct cpu_preserved_stack_context *ser = cpu_preserved_get_stack_context();

	if (ser && ser->ser) {
		u32 old = READ_ONCE(ser->ser->state);

		while (old != CPU_PRESERVED_DEAD) {
			if (try_cmpxchg_release(&ser->ser->state, &old,
						CPU_PRESERVED_DEAD)) {
				cpu_preserved_clean(ser->ser);
				break;
			}
		}
	}
}

/**
 * cpu_preserved_park_loop - Generic execution loop for a parked preserved CPU
 * @cpu: Logical CPU identifier.
 */
void cpu_preserved_park_loop(int cpu)
{
	struct cpu_preserved_stack_context *sctx = cpu_preserved_get_stack_context();
	struct cpu_preserved_ser *ser;
	u32 old;

	if (!sctx || !sctx->ser || !sctx->session_pgd_pa)
		return;

	ser = sctx->ser;
	arch_cpu_preserved_park_init(cpu);

	old = CPU_PRESERVED_PARKING;
	if (try_cmpxchg_release(&ser->state, &old, CPU_PRESERVED_PARKED))
		cpu_preserved_clean(ser);

	for (;;) {
		switch (smp_load_acquire(&ser->state)) {
		case CPU_PRESERVED_EXITING:
		case CPU_PRESERVED_DEAD:
			return;
		default:
			arch_cpu_preserved_park_wait();
			break;
		}
	}
}
STACK_FRAME_NON_STANDARD(cpu_preserved_park_loop);
