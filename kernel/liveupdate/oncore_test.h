/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _KERNEL_LIVEUPDATE_ONCORE_TEST_H
#define _KERNEL_LIVEUPDATE_ONCORE_TEST_H

#include <linux/cpu_preserve.h>
#include <linux/oncore.h>
#include <linux/types.h>

#define ONCORE_TEST_MAGIC		0x4f4e435254455354ULL /* "ONCRTEST" */
#define ONCORE_TEST_LUO_COMPATIBLE	"oncore-test-v1"

/**
 * struct oncore_test_buf - Shared telemetry & ping-pong page
 * @magic:           Validation magic (%ONCORE_TEST_MAGIC).
 * @counter:         Monotonically incremented by oncore_test_job_run().
 * @tickless_quanta: Quanta entered with deadline_ticks == U64_MAX.
 * @sliced_quanta:   Quanta entered with a bounded time-slice deadline.
 * @last_cpu:        Physical CPU ID of the last preserved CPU that ran the job.
 * @reserved:        Padding for 64-bit alignment.
 * @ping_val:        Written by userspace via mmap() (no syscalls).
 * @pong_val:        Updated to match @ping_val by oncore_test_job_run().
 *
 * Allocated as a dedicated KHO-preserved page (separate from &struct
 * oncore_test_state), explicitly mapped into the On-Core session's isolated
 * address space via oncore_session_map_buffer(), and mapped into userspace via
 * mmap() on /sys/kernel/debug/oncore_test or the retrieved LUO file descriptor.
 */
struct oncore_test_buf {
	u64 magic;
	u64 counter;
	u64 tickless_quanta;
	u64 sliced_quanta;
	s32 last_cpu;
	u32 reserved;
	u64 ping_val;
	u64 pong_val;
};

/**
 * struct oncore_test_state - Per-job KHO-preserved descriptor page
 * @buf_pa:   Physical address of the KHO-preserved &struct oncore_test_buf page.
 * @buf_va:   Outgoing kernel virtual address of @buf_pa (mapped in session PGD).
 * @stop:     Set by the host kernel during finish to request job termination.
 * @stopped:  Set by oncore_test_job_run() upon observing @stop or exit.
 *
 * Passed as @job->data (automatically mapped by oncore_session_activate_job()).
 */
struct oncore_test_state {
	u64 buf_pa;
	u64 buf_va;
	u32 stop;
	u32 stopped;
};

enum oncore_exit_reason oncore_test_job_run(void *data, u64 deadline_ticks)
	__cpu_preserved_sym_asm(oncore_test_job_run);

#endif /* _KERNEL_LIVEUPDATE_ONCORE_TEST_H */
