// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026, Google LLC.
 *
 * Preserved-CPU runtime callback for On-Core scheduler selftest
 */

#include <linux/cpu_preserve.h>
#include <linux/limits.h>
#include <linux/oncore.h>
#include "oncore_test.h"

enum oncore_exit_reason oncore_test_job_run(void *data, u64 deadline_ticks)
{
	struct cpu_preserved_stack_context *sctx = cpu_preserved_get_stack_context();
	struct oncore_test_state *state = data;
	struct oncore_test_buf *buf;

	if (!state)
		return ONCORE_EXIT_ERROR;

	if (READ_ONCE(state->stop) || !deadline_ticks) {
		WRITE_ONCE(state->stopped, 1);
		return ONCORE_EXIT_ATTACH_SIGNALED;
	}

	buf = (struct oncore_test_buf *)(uintptr_t)state->buf_va;
	if (!buf || READ_ONCE(buf->magic) != ONCORE_TEST_MAGIC)
		return ONCORE_EXIT_ERROR;

	if (sctx)
		WRITE_ONCE(buf->last_cpu, (s32)sctx->cpu);

	if (deadline_ticks == U64_MAX)
		WRITE_ONCE(buf->tickless_quanta, buf->tickless_quanta + 1);
	else
		WRITE_ONCE(buf->sliced_quanta, buf->sliced_quanta + 1);

	do {
		u64 ping;

		WRITE_ONCE(buf->counter, buf->counter + 1);
		ping = READ_ONCE(buf->ping_val);
		if (READ_ONCE(buf->pong_val) != ping) {
			WRITE_ONCE(buf->pong_val, ping);
			cpu_preserved_clean(buf);
		}

		if (READ_ONCE(state->stop) || cpu_preserved_should_exit()) {
			WRITE_ONCE(state->stopped, 1);
			cpu_preserved_clean(state);
			cpu_preserved_clean(buf);
			return ONCORE_EXIT_ATTACH_SIGNALED;
		}

		if (deadline_ticks == U64_MAX) {
			if (oncore_need_resched())
				break;
		} else {
			if (arch_oncore_read_counter() >= deadline_ticks)
				break;
		}
	} while (1);

	cpu_preserved_clean(buf);
	return ONCORE_EXIT_QUANTUM_EXPIRED;
}
