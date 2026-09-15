/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * On-Core Session and Scheduling Framework for Live Update
 */
#ifndef __LINUX_ONCORE_H
#define __LINUX_ONCORE_H

#include <linux/cpu_preserve.h>
#include <linux/cpumask.h>
#include <linux/kho/abi/oncore.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/types.h>

/*
 * Only ever used as an opaque handle here, so do not include
 * <linux/liveupdate.h>: this header is reached from <linux/kvm_host.h> via
 * <linux/kvm_caretaker.h>, and including it would drag the entire LUO header
 * stack into every KVM translation unit on every architecture.
 */
struct liveupdate_session;

#include <asm/oncore.h>

#define ONCORE_DEFAULT_QUANTUM_MS	10
#define ONCORE_CANCEL_TIMEOUT_US	1000000
#define ONCORE_CANCEL_STEP_US		100

enum oncore_job_state {
	ONCORE_JOB_NEW = 0,
	ONCORE_JOB_RUNNABLE,
	ONCORE_JOB_RUNNING,
	ONCORE_JOB_CANCELING,
	ONCORE_JOB_DEAD,
};

enum oncore_exit_reason {
	ONCORE_EXIT_QUANTUM_EXPIRED = 0,
	ONCORE_EXIT_ATTACH_SIGNALED,
	ONCORE_EXIT_YIELD_IDLE,
	ONCORE_EXIT_ERROR,
};

typedef enum oncore_exit_reason (*oncore_job_fn)(void *data,
						 u64 deadline_ticks);

struct oncore_session;

struct oncore_job {
	struct list_head		node;
	struct list_head		sess_node;
	struct oncore_session		*session;
	char				name[64];
	enum oncore_job_state		state;
	oncore_job_fn			run_fn;
	void				*data;
	int				preferred_cpu;
	int				assigned_cpu;
	int				last_cpu;

	/* Scheduling statistics & accounting */
	u64				total_runs;
	u64				total_runtime_ns;
	u64				preemptions;
	u64				yields;
};

struct oncore_sched_config {
	u32				quantum_ms;
	u64				quantum_ticks;
	u64				counter_freq_hz;
};

extern struct oncore_sched_config global_oncore_sched_config;

phys_addr_t oncore_session_get_pgd_pa(struct oncore_session *sess);
struct oncore_job *
oncore_session_submit_job(struct liveupdate_session *s,
			  const char *name, int preferred_cpu,
			  oncore_job_fn run_fn,
			  void *data);
int oncore_session_activate_job(struct liveupdate_session *s,
				struct oncore_job *job);
void oncore_job_set_data(struct oncore_job *job, void *data);
int oncore_session_cancel_job(struct liveupdate_session *s,
			      struct oncore_job *job);
int oncore_session_map_range(struct oncore_session *sess, phys_addr_t pa,
			     unsigned long va, size_t size, pgprot_t prot);
int oncore_session_map_buffer(struct oncore_session *sess, void *va,
			      size_t size);

static inline struct cpu_preserved_stack_context *
oncore_get_current_context(void)
{
	return cpu_preserved_get_stack_context();
}

static inline void *oncore_memset(void *s, int c, size_t n)
{
	unsigned char *p = s;

	while (n--)
		WRITE_ONCE(*p++, (unsigned char)c);
	return s;
}

static inline void *oncore_memcpy(void *dest, const void *src, size_t n)
{
	unsigned char *d = dest;
	const unsigned char *s = src;

	while (n--)
		WRITE_ONCE(*d++, READ_ONCE(*s++));
	return dest;
}

#endif /* __LINUX_ONCORE_H */
