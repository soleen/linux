// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * Preserved-CPU runtime for On-Core Session and Scheduler Framework
 */

#include <linux/cpu_preserve.h>
#include <linux/limits.h>
#include <linux/oncore.h>
#include "oncore_internal.h"

static struct oncore_job *
oncore_sched_pick_next(struct cpu_preserved_stack_context *sctx,
		       struct oncore_runqueue *rq)
{
	struct oncore_job *job = NULL, *iter;
	struct list_head *pos;
	int cpu = sctx->cpu;

	if (!rq || READ_ONCE(rq->nr_runnable) == 0)
		return NULL;

	oncore_rq_lock(rq);

	/* 1. Starvation avoidance: if head job has NEVER run, take it immediately */
	if (!oncore_list_empty(&rq->runnable)) {
		iter = list_first_entry(&rq->runnable, struct oncore_job, node);
		if (iter->total_runs == 0) {
			job = iter;
			goto found;
		}
	}

	/* 2. Prefer job affine to this core */
	for (pos = rq->runnable.next; pos != &rq->runnable; pos = pos->next) {
		iter = list_entry(pos, struct oncore_job, node);
		if (iter->assigned_cpu == cpu) {
			job = iter;
			goto found;
		}
	}

	/* 3. Work-stealing fallback: take oldest job from head of queue */
	if (!oncore_list_empty(&rq->runnable))
		job = list_first_entry(&rq->runnable, struct oncore_job, node);

found:
	if (job) {
		oncore_list_del_init(&job->node);
		WRITE_ONCE(job->state, ONCORE_JOB_RUNNING);
		WRITE_ONCE(job->last_cpu, cpu);
		rq->nr_runnable--;
		rq->nr_busy++;
		WRITE_ONCE(sctx->oncore_busy, 1);
	}

	oncore_rq_unlock(rq);
	return job;
}

/**
 * oncore_need_resched - Check whether another job is waiting on the runqueue
 *
 * Queries the current preserved physical CPU's On-Core session runqueue to
 * determine whether another runnable job is waiting to be scheduled.  Used by
 * workloads executing with an unbounded (%U64_MAX) tickless deadline to yield
 * back to the scheduler when a second job is enqueued on the same session.
 *
 * Context: Preserved physical CPU (.cpu_preserved.text).
 * Return: %true if at least one runnable job is waiting in the session
 *         runqueue, %false otherwise.
 */
bool oncore_need_resched(void)
{
	struct cpu_preserved_stack_context *sctx = cpu_preserved_get_stack_context();
	struct oncore_session *sess;

	if (!sctx || !sctx->workload_context)
		return false;

	sess = (struct oncore_session *)(uintptr_t)sctx->workload_context;
	return READ_ONCE(sess->rq.nr_runnable) > 0;
}

static void
oncore_cpu_schedule_loop(struct cpu_preserved_stack_context *sctx,
			 struct oncore_runqueue *rq,
			 struct oncore_sched_config *cfg)
{
	enum oncore_exit_reason reason;
	struct oncore_job *curr = NULL;
	u64 deadline;

	if (!sctx || !rq || !cfg)
		return;

	while (!cpu_preserved_should_exit()) {
		/* 1. Pick the next runnable job from the FIFO queue */
		if (!curr) {
			curr = oncore_sched_pick_next(sctx, rq);
			if (!curr) {
				/* No runnable jobs; execute low-power park wait */
				arch_cpu_preserved_park_wait();
				continue;
			}
		}

		/*
		 * 2. Compute quantum deadline.  When no other jobs are waiting
		 * in the runqueue (1:1 execution), pass U64_MAX so the workload
		 * can run tickless without arming a periodic hardware
		 * preemption timer.  Publish oncore_tickless before re-checking
		 * nr_runnable after a full memory barrier (pairing with
		 * oncore_rq_unlock() in oncore_sched_enqueue()) so a concurrent
		 * enqueue that transitions the session into M > N overcommit is
		 * guaranteed to either be seen here or kick this CPU out of
		 * tickless execution.
		 */
		if (READ_ONCE(rq->nr_runnable) == 0) {
			WRITE_ONCE(sctx->oncore_tickless, 1);
			smp_mb();
			if (READ_ONCE(rq->nr_runnable) == 0) {
				deadline = U64_MAX;
			} else {
				WRITE_ONCE(sctx->oncore_tickless, 0);
				deadline = arch_oncore_read_counter() +
					   cfg->quantum_ticks;
			}
		} else {
			deadline = arch_oncore_read_counter() +
				   cfg->quantum_ticks;
		}

		/* 3. Execute workload on physical silicon */
		reason = curr->run_fn(curr->data, deadline);
		if (deadline == U64_MAX)
			WRITE_ONCE(sctx->oncore_tickless, 0);

		/* 4. Update telemetry and accounting */
		curr->total_runs++;

		/*
		 * A stalled job cannot make progress until the incoming kernel
		 * reclaims it, so re-running it immediately would just repeat
		 * the same unhandled exit as fast as the hardware allows.  Back
		 * off in the architecture's low-power wait (WFE on arm64, PAUSE
		 * on x86) first.  arch_cpu_preserved_kick() wakes it, so the
		 * attach signal is still observed promptly by the checks below
		 * and at the top of the loop.
		 */
		if (reason == ONCORE_EXIT_STALL)
			arch_cpu_preserved_park_wait();

		/* Fast-path: single runnable job continues uninterrupted */
		if (READ_ONCE(rq->nr_runnable) == 0 &&
		    READ_ONCE(curr->state) == ONCORE_JOB_RUNNING &&
		    reason != ONCORE_EXIT_ATTACH_SIGNALED &&
		    reason != ONCORE_EXIT_ERROR &&
		    !cpu_preserved_should_exit()) {
			continue;
		}

		/* 5. Handle exit and return job to queue in one critical section */
		oncore_rq_lock(rq);
		if (READ_ONCE(curr->state) == ONCORE_JOB_CANCELING ||
		    READ_ONCE(curr->state) == ONCORE_JOB_DEAD ||
		    reason == ONCORE_EXIT_ATTACH_SIGNALED ||
		    reason == ONCORE_EXIT_ERROR) {
			WRITE_ONCE(curr->state, ONCORE_JOB_DEAD);
			rq->nr_busy--;
			WRITE_ONCE(sctx->oncore_busy, 0);
		} else {
			WRITE_ONCE(curr->state, ONCORE_JOB_RUNNABLE);
			oncore_list_add_tail(&curr->node, &rq->runnable);
			rq->nr_runnable++;
			rq->nr_busy--;
			WRITE_ONCE(sctx->oncore_busy, 0);
		}
		oncore_rq_unlock(rq);
		curr = NULL;
	}

	for (;;) {
		if (!curr) {
			oncore_rq_lock(rq);
			if (!oncore_list_empty(&rq->runnable)) {
				curr = list_first_entry(&rq->runnable,
							struct oncore_job, node);
				oncore_list_del_init(&curr->node);
				WRITE_ONCE(curr->state, ONCORE_JOB_RUNNING);
				rq->nr_runnable--;
				rq->nr_busy++;
				WRITE_ONCE(sctx->oncore_busy, 1);
			}
			oncore_rq_unlock(rq);
			if (!curr)
				break;
			curr->run_fn(curr->data, 0);
		}
		oncore_rq_lock(rq);
		WRITE_ONCE(curr->state, ONCORE_JOB_DEAD);
		rq->nr_busy--;
		WRITE_ONCE(sctx->oncore_busy, 0);
		oncore_rq_unlock(rq);
		curr = NULL;
	}
}

void oncore_sched_cpu_worker(void *data)
{
	struct cpu_preserved_stack_context *sctx = cpu_preserved_get_stack_context();
	struct oncore_session *sess;

	if (!sctx)
		return;

	sess = sctx->workload_context ?
		(struct oncore_session *)(uintptr_t)sctx->workload_context :
		data;
	if (!sess)
		return;

	if (sctx->session_pgd_pa)
		arch_cpu_preserved_switch_pgd(sctx->session_pgd_pa);

	oncore_cpu_schedule_loop(sctx, &sess->rq, &sess->sched_config);
}
