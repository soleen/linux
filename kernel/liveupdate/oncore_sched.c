// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * On-Core Scheduler Framework for Live Update
 */

#define pr_fmt(fmt) "oncore_sched: " fmt

#include <linux/cpu_preserve.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/kexec.h>
#include <linux/liveupdate.h>
#include <linux/module.h>
#include <linux/oncore.h>
#include <linux/string.h>

#include "oncore_internal.h"

struct oncore_sched_config global_oncore_sched_config __cpu_preserved_data;
EXPORT_SYMBOL_GPL(global_oncore_sched_config);

static int __init parse_oncore_quantum(char *arg)
{
	u32 val;

	if (kstrtou32(arg, 0, &val) == 0 && val >= 1 && val <= 1000)
		global_oncore_sched_config.quantum_ms = val;
	return 0;
}
early_param("oncore.quantum_ms", parse_oncore_quantum);

void oncore_sched_update_ticks(void)
{
	arch_oncore_update_quantum_ticks(&global_oncore_sched_config);
}

void oncore_runqueue_init(struct oncore_runqueue *rq)
{
	atomic_set(&rq->lock, 0);
	INIT_LIST_HEAD(&rq->runnable);
	rq->nr_runnable = 0;
	rq->nr_total = 0;
}

int oncore_sched_enqueue(struct oncore_runqueue *rq,
			 struct oncore_job *job)
{
	int cpu;

	oncore_rq_lock(rq);
	job->state = ONCORE_JOB_RUNNABLE;
	list_add_tail(&job->node, &rq->runnable);
	rq->nr_runnable++;
	rq->nr_total++;
	oncore_rq_unlock(rq);

	if (job->session) {
		for_each_cpu(cpu, to_cpumask(job->session->cpus_bitmap)) {
			if (cpu_is_preserved(cpu))
				arch_cpu_preserved_kick(cpu);
		}
	} else if (job->preferred_cpu >= 0 && cpu_is_preserved(job->preferred_cpu)) {
		arch_cpu_preserved_kick(job->preferred_cpu);
	}

	return 0;
}

int oncore_sched_dequeue(struct oncore_runqueue *rq,
			 struct oncore_job *job)
{
	oncore_rq_lock(rq);
	if (!list_empty(&job->node)) {
		list_del_init(&job->node);
		rq->nr_runnable--;
	}
	rq->nr_total--;
	if (job->state == ONCORE_JOB_RUNNING)
		job->state = ONCORE_JOB_CANCELING;
	else
		job->state = ONCORE_JOB_DEAD;
	oncore_rq_unlock(rq);
	return 0;
}

static struct oncore_job *__cpu_preserved_text
oncore_sched_pick_next(struct oncore_runqueue *rq, int cpu)
{
	struct oncore_job *job = NULL, *iter;

	if (!rq || READ_ONCE(rq->nr_runnable) == 0)
		return NULL;

	oncore_rq_lock(rq);

	/* 1. Starvation avoidance: if head job has NEVER run, take it immediately */
	if (!list_empty(&rq->runnable)) {
		iter = list_first_entry(&rq->runnable, struct oncore_job, node);
		if (iter->total_runs == 0) {
			job = iter;
			goto found;
		}
	}

	/* 2. Prefer job affine to this core */
	list_for_each_entry(iter, &rq->runnable, node) {
		if (iter->preferred_cpu == cpu) {
			job = iter;
			goto found;
		}
	}

	/* 3. Work-stealing fallback: take oldest job from head of queue */
	if (!list_empty(&rq->runnable))
		job = list_first_entry(&rq->runnable, struct oncore_job, node);

found:
	if (job) {
		list_del_init(&job->node);
		rq->nr_runnable--;
	}

	oncore_rq_unlock(rq);
	return job;
}

static void __cpu_preserved_text
oncore_sched_put_prev(struct oncore_runqueue *rq,
		      struct oncore_job *job)
{
	oncore_rq_lock(rq);
	job->state = ONCORE_JOB_RUNNABLE;
	list_add_tail(&job->node, &rq->runnable);
	rq->nr_runnable++;
	oncore_rq_unlock(rq);
}

static void __cpu_preserved_text
oncore_cpu_schedule_loop(int cpu, struct oncore_runqueue *rq,
			 struct oncore_sched_config *cfg)
{
	u64 deadline, start_ticks, end_ticks;
	enum oncore_exit_reason reason;
	struct oncore_job *curr = NULL;

	if (!rq || !cfg)
		return;

	while (!cpu_preserved_should_exit(cpu)) {
		/* 1. Pick the next runnable job from the FIFO queue */
		if (!curr) {
			curr = oncore_sched_pick_next(rq, cpu);
			if (!curr) {
				/* No runnable jobs; execute low-power park wait */
				arch_cpu_preserved_park_wait();
				continue;
			}
		}

		/* 2. Compute quantum deadline */
		start_ticks = arch_oncore_read_counter();
		if (cfg->quantum_ticks)
			deadline = start_ticks + cfg->quantum_ticks;
		else
			deadline = 0;

		/* 3. Execute workload on physical silicon */
		curr->last_cpu = cpu;
		curr->state = ONCORE_JOB_RUNNING;
		reason = curr->run_fn(curr->data, deadline);

		/* 4. Update telemetry and accounting */
		end_ticks = arch_oncore_read_counter();
		curr->total_runs++;
		curr->total_runtime_ns += arch_oncore_ticks_to_ns(end_ticks - start_ticks);
		if (reason == ONCORE_EXIT_QUANTUM_EXPIRED)
			curr->preemptions++;
		else if (reason == ONCORE_EXIT_YIELD_IDLE)
			curr->yields++;

		/* Fast-path: single runnable job continues uninterrupted */
		if (READ_ONCE(rq->nr_runnable) == 0 &&
		    READ_ONCE(curr->state) == ONCORE_JOB_RUNNING &&
		    reason != ONCORE_EXIT_ATTACH_SIGNALED &&
		    reason != ONCORE_EXIT_ERROR &&
		    !cpu_preserved_should_exit(cpu)) {
			continue;
		}

		/* 5. Handle exit and return job to queue */
		oncore_rq_lock(rq);
		if (curr->state == ONCORE_JOB_CANCELING ||
		    curr->state == ONCORE_JOB_DEAD ||
		    reason == ONCORE_EXIT_ATTACH_SIGNALED ||
		    reason == ONCORE_EXIT_ERROR) {
			if (curr->state != ONCORE_JOB_CANCELING &&
			    curr->state != ONCORE_JOB_DEAD &&
			    rq->nr_total > 0) {
				rq->nr_total--;
			}
			WRITE_ONCE(curr->state, ONCORE_JOB_DEAD);
			oncore_rq_unlock(rq);
			curr = NULL;
			continue;
		}
		oncore_rq_unlock(rq);

		oncore_sched_put_prev(rq, curr);
		curr = NULL;
	}
}

void __cpu_preserved_text oncore_sched_cpu_worker(void *data)
{
	struct cpu_preserved_stack_context *sctx = oncore_get_current_context();
	struct oncore_session *sess;
	int cpu;

	sess = (sctx && sctx->workload_context) ? sctx->workload_context : data;
	cpu = sctx ? sctx->cpu : smp_processor_id();

	if (sctx && sctx->session_pgd_pa)
		arch_cpu_preserved_switch_pgd(sctx->session_pgd_pa);

	oncore_cpu_schedule_loop(cpu, &sess->rq, &sess->sched_config);
}

static int __init oncore_sched_init(void)
{
	if (!global_oncore_sched_config.quantum_ms)
		global_oncore_sched_config.quantum_ms = ONCORE_DEFAULT_QUANTUM_MS;
	oncore_sched_update_ticks();
	pr_info("Round-Robin scheduler initialized (quantum=%u ms, ticks=%llu)\n",
		global_oncore_sched_config.quantum_ms,
		global_oncore_sched_config.quantum_ticks);
	return 0;
}
early_initcall(oncore_sched_init);

u64 __weak __cpu_preserved_text arch_oncore_ticks_to_ns(u64 ticks)
{
	return ticks;
}

void __weak arch_oncore_update_quantum_ticks(struct oncore_sched_config *cfg)
{
	cfg->quantum_ticks = (u64)cfg->quantum_ms * 1000000ULL;
}
