// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * Isolated runtime execution loop for preserved physical CPUs across Live Update.
 */

#include <linux/atomic.h>
#include <linux/cpu_preserve.h>
#include <linux/kho/abi/cpu.h>
#include <linux/objtool.h>
#include <linux/types.h>

/**
 * cpu_preserved_set_dead - Mark the current preserved CPU as fully dead/stopped
 */
void cpu_preserved_set_dead(void)
{
	struct cpu_preserved_stack_context *sctx = cpu_preserved_get_stack_context();

	if (sctx && sctx->ser) {
		u32 old = READ_ONCE(sctx->ser->state);

		while (old != CPU_PRESERVED_DEAD && old != CPU_PRESERVED_FAULTED) {
			if (try_cmpxchg_release(&sctx->ser->state, &old,
						CPU_PRESERVED_DEAD)) {
				cpu_preserved_clean(sctx->ser);
				break;
			}
		}
	}
}

/**
 * cpu_preserved_should_exit - Check if the running preserved workload should exit
 *
 * Return: %true if the workload on the current CPU must exit back to the park
 *         loop, %false otherwise.
 */
bool cpu_preserved_should_exit(void)
{
	struct cpu_preserved_stack_context *sctx = cpu_preserved_get_stack_context();

	if (!sctx || !sctx->ser)
		return false;

	/* Pairs with the release cmpxchg in cpu_preserved_attach_workload() */
	return smp_load_acquire(&sctx->ser->state) != CPU_PRESERVED_WORKLOAD;
}

static void cpu_preserved_run_workload(struct cpu_preserved_stack_context *sctx)
{
	struct cpu_preserved_ser *ser = sctx->ser;
	void (*fn)(void *data);
	void *arg;
	u32 old;

	fn = READ_ONCE(sctx->entry_fn);
	arg = (void *)(uintptr_t)READ_ONCE(sctx->workload_context);
	if (fn && smp_load_acquire(&ser->state) == CPU_PRESERVED_WORKLOAD)
		fn(arg);

	old = smp_load_acquire(&ser->state);
	while (old == CPU_PRESERVED_WORKLOAD ||
	       old == CPU_PRESERVED_DETACHING) {
		if (try_cmpxchg_release(&ser->state, &old,
					CPU_PRESERVED_PARKED)) {
			cpu_preserved_clean(ser);
			break;
		}
	}
}
STACK_FRAME_NON_STANDARD(cpu_preserved_run_workload);

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
		/*
		 * Pairs with the fully ordered cmpxchg in cpu_signal_exit() and
		 * with the release cmpxchg in cpu_preserved_attach_workload()
		 */
		switch (smp_load_acquire(&ser->state)) {
		case CPU_PRESERVED_EXITING:
		case CPU_PRESERVED_DEAD:
			return;
		case CPU_PRESERVED_WORKLOAD:
		case CPU_PRESERVED_DETACHING:
			cpu_preserved_run_workload(sctx);
			break;
		default:
			arch_cpu_preserved_park_wait();
			break;
		}
	}
}
STACK_FRAME_NON_STANDARD(cpu_preserved_park_loop);
