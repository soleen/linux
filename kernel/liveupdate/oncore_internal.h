/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _KERNEL_LIVEUPDATE_ONCORE_INTERNAL_H
#define _KERNEL_LIVEUPDATE_ONCORE_INTERNAL_H

#include <linux/atomic.h>
#include <linux/cpu_preserve.h>
#include <linux/kho_block.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/oncore.h>
#include <linux/types.h>
#include <asm/cmpxchg.h>
#include <asm/processor.h>

enum oncore_job_state {
	ONCORE_JOB_NEW = 0,
	ONCORE_JOB_RUNNABLE,
	ONCORE_JOB_RUNNING,
	ONCORE_JOB_CANCELING,
	ONCORE_JOB_DEAD,
};

struct oncore_job {
	struct list_head		node;
	struct list_head		sess_node;
	struct oncore_session		*session;
	enum oncore_job_state		state;
	oncore_job_fn			run_fn;
	void				*data;
	int				assigned_cpu;
	int				last_cpu;
	u64				total_runs;
};

struct oncore_sched_config {
	u64				quantum_ticks;
};

struct oncore_runqueue {
	atomic_t			lock;
	struct list_head		runnable;
	unsigned int			nr_runnable;
	unsigned int			nr_busy;
};

struct oncore_session {
	/* Protects session state and job list */
	struct mutex			lock;
	struct list_head		jobs;
	struct kho_block_set		block_set;
	struct oncore_runqueue		rq;
	struct oncore_sched_config	sched_config;
	struct cpu_preserved_session	*cps;
	bool				workers_attached;
};

static __always_inline void oncore_rq_lock(struct oncore_runqueue *rq)
{
	while (cmpxchg(&rq->lock.counter, 0, 1) != 0) {
		while (READ_ONCE(rq->lock.counter) != 0)
			cpu_relax();
	}
}

static __always_inline void oncore_rq_unlock(struct oncore_runqueue *rq)
{
	smp_mb(); /* Order runqueue updates before releasing lock */
	WRITE_ONCE(rq->lock.counter, 0);
}

static __always_inline bool oncore_list_empty(const struct list_head *head)
{
	return READ_ONCE(head->next) == head;
}

static __always_inline void oncore_list_del_init(struct list_head *entry)
{
	struct list_head *prev = entry->prev;
	struct list_head *next = entry->next;

	next->prev = prev;
	WRITE_ONCE(prev->next, next);
	WRITE_ONCE(entry->next, entry);
	entry->prev = entry;
}

static __always_inline void oncore_list_add_tail(struct list_head *new,
						 struct list_head *head)
{
	struct list_head *prev = head->prev;

	head->prev = new;
	new->next = head;
	new->prev = prev;
	WRITE_ONCE(prev->next, new);
}

void oncore_sched_cpu_worker(void *data)
	__cpu_preserved_sym_asm(oncore_sched_cpu_worker);

#endif /* _KERNEL_LIVEUPDATE_ONCORE_INTERNAL_H */
