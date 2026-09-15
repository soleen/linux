/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * Internal definitions and interfaces for On-Core framework
 */
#ifndef _LINUX_ONCORE_INTERNAL_H
#define _LINUX_ONCORE_INTERNAL_H

#include <linux/cpu_preserve.h>
#include <linux/cpumask.h>
#include <linux/kho/abi/oncore.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/oncore.h>
#include <linux/types.h>

struct oncore_runqueue {
	atomic_t			lock;
	struct list_head		runnable;
	unsigned int			nr_runnable;
	unsigned int			nr_total;
};

struct oncore_session {
	struct list_head		node;
	char				name[LIVEUPDATE_SESSION_NAME_LENGTH];
	struct mutex			lock;
	struct list_head		jobs;
	struct oncore_runqueue		rq;
	struct oncore_sched_config	sched_config;
	struct cpu_preserved_as		*as;
	phys_addr_t			as_pa;
	struct oncore_session_ser	*ser;
	bool				is_incoming;
	unsigned int			nr_cpu_words;
	unsigned long			cpus_bitmap[];
};

static inline void oncore_rq_lock(struct oncore_runqueue *rq)
{
	while (atomic_cmpxchg_acquire(&rq->lock, 0, 1) != 0) {
		while (atomic_read(&rq->lock) != 0)
			cpu_relax();
	}
}

static inline void oncore_rq_unlock(struct oncore_runqueue *rq)
{
	atomic_set_release(&rq->lock, 0);
}

/* Scheduler internal interfaces (oncore_sched.c) */
void oncore_runqueue_init(struct oncore_runqueue *rq);
int oncore_sched_enqueue(struct oncore_runqueue *rq, struct oncore_job *job);
int oncore_sched_dequeue(struct oncore_runqueue *rq, struct oncore_job *job);
void oncore_sched_update_ticks(void);
void __cpu_preserved_text oncore_sched_cpu_worker(void *data);

#endif /* _LINUX_ONCORE_INTERNAL_H */
