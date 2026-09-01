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
#include <linux/liveupdate.h>
#include <uapi/linux/liveupdate.h>

struct liveupdate_session;

#if __has_include(<asm/oncore.h>)
#include <asm/oncore.h>
#endif
#include <asm/trans_pgd.h>

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
	u32				tsc_khz;
};

extern struct oncore_sched_config global_oncore_sched_config;

#ifdef CONFIG_ONCORE_SCHED

struct oncore_session *oncore_get_session(struct liveupdate_session *s);
phys_addr_t oncore_session_get_pgd_pa(struct oncore_session *sess);
int oncore_session_add_cpu(struct liveupdate_session *s, int cpu);
int oncore_session_remove_cpu(struct liveupdate_session *s, int cpu);
struct oncore_job *
oncore_session_submit_job(struct liveupdate_session *s,
			  const char *name, int preferred_cpu,
			  oncore_job_fn run_fn,
			  void *data);
int oncore_session_activate_job(struct liveupdate_session *s,
				struct oncore_job *job);
int oncore_session_cancel_job(struct liveupdate_session *s,
			      struct oncore_job *job);
phys_addr_t oncore_session_get_ser_pa(struct liveupdate_session *s);
int oncore_session_restore(struct liveupdate_session *s,
			   struct oncore_session_ser *ser);
int oncore_session_map_range(struct oncore_session *sess, phys_addr_t pa,
			     unsigned long va, size_t size, pgprot_t prot);
int oncore_session_map_buffer(struct oncore_session *sess, void *va,
			      size_t size);
void arch_oncore_flush_tlb(struct oncore_session *sess);

#else /* !CONFIG_ONCORE_SCHED */

static inline struct oncore_session *
oncore_get_session(struct liveupdate_session *s) { return NULL; }
static inline phys_addr_t oncore_session_get_pgd_pa(struct oncore_session *sess) { return 0; }
static inline int oncore_session_add_cpu(struct liveupdate_session *s, int cpu) { return 0; }
static inline int oncore_session_remove_cpu(struct liveupdate_session *s, int cpu) { return 0; }
static inline struct oncore_job *
oncore_session_submit_job(struct liveupdate_session *s,
			  const char *name, int preferred_cpu,
			  oncore_job_fn run_fn,
			  void *data)
{
	return ERR_PTR(-EOPNOTSUPP);
}
static inline int oncore_session_activate_job(struct liveupdate_session *s,
					      struct oncore_job *job) { return 0; }
static inline int oncore_session_cancel_job(struct liveupdate_session *s,
					    struct oncore_job *job) { return 0; }
static inline phys_addr_t oncore_session_get_ser_pa(struct liveupdate_session *s) { return 0; }
static inline int oncore_session_restore(struct liveupdate_session *s,
					 struct oncore_session_ser *ser) { return 0; }
static inline int oncore_session_map_range(struct oncore_session *sess, phys_addr_t pa,
					   unsigned long va, size_t size, pgprot_t prot) { return 0; }
static inline int oncore_session_map_buffer(struct oncore_session *sess,
					    void *va, size_t size) { return 0; }
static inline void arch_oncore_flush_tlb(struct oncore_session *sess) {}

#endif /* CONFIG_ONCORE_SCHED */

static inline struct cpu_preserved_stack_context *
oncore_get_current_context(void)
{
	return cpu_preserved_get_stack_context();
}

static inline bool oncore_is_orphaned_cpu(int cpu)
{
	return IS_ENABLED(CONFIG_ONCORE_SCHED) && cpu_is_preserved(cpu);
}

static inline bool oncore_is_enabled(void)
{
	return IS_ENABLED(CONFIG_ONCORE_SCHED);
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

u64 arch_oncore_ticks_to_ns(u64 ticks);
void arch_oncore_update_quantum_ticks(struct oncore_sched_config *cfg);

#ifndef arch_oncore_read_counter
static inline u64 arch_oncore_read_counter(void) { return 0ULL; }
#define arch_oncore_read_counter arch_oncore_read_counter
#endif

#endif /* __LINUX_ONCORE_H */
