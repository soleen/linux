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

	/* 1. Prioritize any job that is being canceled so it drains promptly */
	for (pos = rq->runnable.next; pos != &rq->runnable; pos = pos->next) {
		iter = list_entry(pos, struct oncore_job, node);
		if (READ_ONCE(iter->state) == ONCORE_JOB_CANCELING) {
			job = iter;
			goto found;
		}
	}

	/* 2. Strict FIFO: take oldest job from head of queue */
	if (!oncore_list_empty(&rq->runnable))
		job = list_first_entry(&rq->runnable, struct oncore_job, node);

found:
	if (job) {
		oncore_list_del_init(&job->node);
		if (READ_ONCE(job->state) != ONCORE_JOB_CANCELING)
			WRITE_ONCE(job->state, ONCORE_JOB_RUNNING);
		WRITE_ONCE(job->last_cpu, cpu);
		rq->nr_runnable--;
		rq->nr_busy++;
		WRITE_ONCE(sctx->oncore_busy, 1);
	}

	oncore_rq_unlock(rq);
	return job;
}

static void oncore_sched_put_prev(struct oncore_runqueue *rq,
				  struct oncore_job *curr,
				  enum oncore_exit_reason reason)
{
	struct cpu_preserved_stack_context *sctx = cpu_preserved_get_stack_context();

	if (!curr)
		return;

	oncore_rq_lock(rq);
	if (READ_ONCE(curr->state) == ONCORE_JOB_CANCELING ||
	    READ_ONCE(curr->state) == ONCORE_JOB_DEAD ||
	    reason == ONCORE_EXIT_ATTACH_SIGNALED ||
	    reason == ONCORE_EXIT_ERROR) {
		WRITE_ONCE(curr->state, ONCORE_JOB_DEAD);
	} else {
		/*
		 * Both ONCORE_EXIT_QUANTUM_EXPIRED and ONCORE_EXIT_YIELD_IDLE
		 * return the job to the tail of the FIFO runnable queue.
		 */
		WRITE_ONCE(curr->state, ONCORE_JOB_RUNNABLE);
		oncore_list_add_tail(&curr->node, &rq->runnable);
		rq->nr_runnable++;
	}
	rq->nr_busy--;
	if (sctx)
		WRITE_ONCE(sctx->oncore_busy, 0);
	oncore_rq_unlock(rq);
}

/**
 * oncore_need_resched - Check whether the running job should yield the CPU
 *
 * Queries the current preserved physical CPU's stack context and On-Core
 * session runqueue to determine whether the running job is being canceled, the
 * CPU is being reclaimed, or another runnable job is waiting to be scheduled.
 * Used by workloads executing with an unbounded (%U64_MAX) tickless deadline.
 *
 * Context: Preserved physical CPU (.cpu_preserved.text).
 * Return: %true if the job should yield back to the scheduler, %false otherwise.
 */
bool oncore_need_resched(void)
{
	struct cpu_preserved_stack_context *sctx = cpu_preserved_get_stack_context();
	struct oncore_session *sess;
	struct oncore_job *curr;

	if (!sctx || !sctx->workload_context)
		return false;

	if (cpu_preserved_should_exit())
		return true;

	curr = (struct oncore_job *)(uintptr_t)READ_ONCE(sctx->oncore_curr_job);
	if (curr && READ_ONCE(curr->state) == ONCORE_JOB_CANCELING)
		return true;

	sess = (struct oncore_session *)(uintptr_t)sctx->workload_context;
	return READ_ONCE(sess->rq.nr_runnable) > 0;
}

static void
oncore_cpu_schedule_loop(struct cpu_preserved_stack_context *sctx,
			 struct oncore_runqueue *rq,
			 struct oncore_sched_config *cfg)
{
	enum oncore_exit_reason reason = ONCORE_EXIT_ATTACH_SIGNALED;
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
		WRITE_ONCE(sctx->oncore_curr_job, (u64)(uintptr_t)curr);
		reason = curr->run_fn(curr->data, deadline);
		WRITE_ONCE(sctx->oncore_curr_job, 0);
		if (deadline == U64_MAX)
			WRITE_ONCE(sctx->oncore_tickless, 0);

		/* 4. Update telemetry and accounting */
		WRITE_ONCE(curr->total_runs, READ_ONCE(curr->total_runs) + 1);

		/*
		 * A stalled job cannot make progress until the incoming kernel
		 * reclaims it, so re-running it immediately would just repeat
		 * the same unhandled exit as fast as the hardware allows.  If
		 * no other job is waiting, back off in the architecture's
		 * low-power wait (WFE on arm64, MWAIT or HLT on x86) first.
		 * The CPU counts as idle for the wait, so that
		 * oncore_sched_enqueue() kicks it when a job arrives; the full
		 * barrier pairs with oncore_rq_unlock() there.
		 * arch_cpu_preserved_kick() also wakes it for the attach
		 * signal, which is then observed by the checks below and at the
		 * top of the loop.
		 */
		if (reason == ONCORE_EXIT_STALL) {
			WRITE_ONCE(sctx->oncore_busy, 0);
			smp_mb();
			if (READ_ONCE(rq->nr_runnable) == 0)
				arch_cpu_preserved_park_wait();
			WRITE_ONCE(sctx->oncore_busy, 1);
		}

		/* Fast-path: single runnable job continues uninterrupted */
		if (READ_ONCE(rq->nr_runnable) == 0 &&
		    READ_ONCE(curr->state) == ONCORE_JOB_RUNNING &&
		    reason != ONCORE_EXIT_ATTACH_SIGNALED &&
		    reason != ONCORE_EXIT_ERROR &&
		    !cpu_preserved_should_exit()) {
			continue;
		}

		/* 5. Handle exit and return job to queue in one critical section */
		oncore_sched_put_prev(rq, curr, reason);
		curr = NULL;
	}

	oncore_sched_put_prev(rq, curr, reason);
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

	oncore_cpu_schedule_loop(sctx, &sess->rq, &sess->sched_config);
}
