// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * On-Core Session and Scheduler Framework for Live Update
 */

/**
 * DOC: On-Core Execution and Scheduling Framework
 *
 * The On-Core framework enables latency-sensitive workloads to continue
 * executing directly on preserved physical CPUs (.preserved.text /
 * .preserved.data) across a kexec Live Update (CONFIG_LIVEUPDATE_CPU)
 * while the outgoing host kernel shuts down and the incoming kernel boots.
 *
 * Each Live Update session (struct liveupdate_session) can create an
 * oncore_session that manages:
 *
 * 1. Isolated Address Space (struct cpupr_as_ser):
 *    Page tables containing only the preserved runtime text/data sections,
 *    the session and runqueue metadata, the jobs and the state of the
 *    workloads.  The address space owns everything it maps: workloads
 *    allocate their state with oncore_session_alloc_buffer() and never free
 *    it, and it is freed when the address space is torn down, after every CPU
 *    of the session has left it.  A page whose physical address another owner
 *    controls is mapped with oncore_session_adopt_page(), which makes the
 *    address space a co-owner, and device registers with
 *    oncore_session_map_mmio().
 *
 * 2. Preserved Physical CPU Pool:
 *    One or more physical CPUs isolated from Linux scheduling via
 *    cpu_preserve and notified to the session via oncore_cpu_preserved().
 *    Preserved CPUs remain parked in cpupr_park_loop() until a job is
 *    activated via oncore_session_activate_job(), at which point each CPU
 *    switches to the session's isolated page tables and executes
 *    oncore_cpu_schedule_loop().
 *
 * 3. Cooperative Time-Sliced Runqueue (struct oncore_runqueue):
 *    A round-robin FIFO scheduler supporting M jobs across N preserved
 *    physical CPUs (including M > N oversubscription).  It provides
 *    cancellation prioritization, strict FIFO ordering, single-job tickless
 *    fast-path continuation, and low-power backoff (WFE on arm64, MWAIT or HLT
 *    on x86) when the queue is idle or a job returns ONCORE_EXIT_STALL.
 *
 * Workload Integration
 * --------------------
 * On-Core is workload- and hypervisor-agnostic.  Any self-contained kernel
 * subsystem compiled into the preserved runtime sections (.preserved.text /
 * .preserved.data) can allocate its state from the session's isolated
 * address space and submit an oncore_job_fn(void *data, u64 deadline)
 * callback.  The callback runs until the time-slice deadline (deadline_ticks)
 * expires, yields when idle (ONCORE_EXIT_YIELD_IDLE), stalls when an operation
 * requires the incoming kernel (ONCORE_EXIT_STALL), or exits when reclaimed by
 * the incoming kernel (ONCORE_EXIT_ATTACH_SIGNALED).
 *
 * Architecture Requirements
 * -------------------------
 * To support CONFIG_LIVEUPDATE_ONCORE, an architecture must implement:
 *
 * - <asm/oncore.h>:
 *   - arch_oncore_read_counter(): Read a monotonic hardware counter directly
 *     from .preserved.text without relying on kernel timekeeping
 *     (e.g., rdtsc() on x86, __arch_counter_get_cntpct() on arm64).
 *   - arch_oncore_counter_freq_hz(): Return the hardware counter frequency in
 *     Hz used to convert the time quantum (oncore.quantum_ms) into ticks.
 *
 * - <asm/cpu_preserve.h> (from CONFIG_LIVEUPDATE_CPU):
 *   - arch_cpupr_switch_pgd(): Switch to the session's isolated PGD.
 *   - arch_cpupr_park_wait() / arch_cpupr_kick(): Low-power
 *     wait instruction and cross-CPU wakeup mechanism.
 *
 * Public Interfaces (<linux/oncore.h>)
 * ------------------------------------
 * - Session & CPU Lifecycle:
 *   oncore_cpu_preserved(), oncore_cpu_unpreserved().
 * - Session Address Space:
 *   oncore_session_alloc_buffer(), oncore_session_adopt_page(),
 *   oncore_session_map_mmio(), oncore_session_get_pgd_pa(),
 *   oncore_session_id().
 * - Job Submission & Control:
 *   oncore_session_submit_job(), oncore_job_set_data(),
 *   oncore_job_cpu(), oncore_job_session(),
 *   oncore_session_activate_job(), oncore_session_cancel_job().
 */

#define pr_fmt(fmt) "oncore: " fmt

#include <linux/build_bug.h>
#include <linux/cpu_preserve.h>
#include <linux/cpumask.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/kexec.h>
#include <linux/list.h>
#include <linux/liveupdate.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/oncore.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#include "oncore_internal.h"

static_assert(sizeof(struct oncore_session) <= PAGE_SIZE);
static_assert(sizeof(struct oncore_job) <= PAGE_SIZE);

#define ONCORE_DEFAULT_QUANTUM_MS	10
#define ONCORE_CANCEL_TIMEOUT_US	USEC_PER_SEC
#define ONCORE_CANCEL_STEP_US		100

static u32 oncore_quantum_ms = ONCORE_DEFAULT_QUANTUM_MS;
static struct oncore_sched_config global_oncore_sched_config;
static DEFINE_MUTEX(oncore_sessions_lock);

static inline const struct cpumask *
oncore_session_cpus(const struct oncore_session *sess)
{
	return cpupr_session_cpus(sess ? sess->cps : NULL);
}

static int oncore_select_job_cpu(struct oncore_session *sess);

static int __init parse_oncore_quantum(char *arg)
{
	u32 val;

	if (!arg || kstrtou32(arg, 0, &val) || val < 1 || val > 1000) {
		pr_warn("Invalid oncore.quantum_ms=%s (must be 1..1000)\n",
			arg ? arg : "");
		return -EINVAL;
	}
	oncore_quantum_ms = val;
	return 0;
}
early_param("oncore.quantum_ms", parse_oncore_quantum);

static void oncore_sched_update_ticks(void)
{
	u64 freq = arch_oncore_counter_freq_hz();

	global_oncore_sched_config.quantum_ticks =
		(freq * oncore_quantum_ms) / 1000ULL;
}

#define ONCORE_RQ_LOCK_SPIN_TRIES	1000
#define ONCORE_RQ_LOCK_TIMEOUT_US	USEC_PER_SEC
#define ONCORE_RQ_LOCK_STEP_US		100

static bool oncore_session_any_cpu_faulted(const struct oncore_session *sess)
{
	int cpu;

	if (!sess || !sess->cps)
		return false;

	for_each_cpu(cpu, oncore_session_cpus(sess)) {
		if (cpupr_state(cpu) == CPUPR_FAULTED)
			return true;
	}
	return false;
}

static int oncore_rq_lock_host(struct oncore_session *sess,
			       unsigned long *flags)
{
	u64 elapsed_us = 0;
	int i;

	for (;;) {
		local_irq_save(*flags);
		for (i = 0; i < ONCORE_RQ_LOCK_SPIN_TRIES; i++) {
			if (atomic_cmpxchg_acquire(&sess->rq.lock, 0, 1) == 0)
				return 0;
			cpu_relax();
		}
		local_irq_restore(*flags);

		if (oncore_session_any_cpu_faulted(sess)) {
			WARN_ON_ONCE(1);
			return -EIO;
		}
		if (elapsed_us >= ONCORE_RQ_LOCK_TIMEOUT_US) {
			WARN_ON_ONCE(1);
			return -ETIMEDOUT;
		}
		usleep_range(ONCORE_RQ_LOCK_STEP_US,
			     ONCORE_RQ_LOCK_STEP_US * 2);
		elapsed_us += ONCORE_RQ_LOCK_STEP_US;
	}
}

static void oncore_runqueue_init(struct oncore_runqueue *rq)
{
	atomic_set(&rq->lock, 0);
	INIT_LIST_HEAD(&rq->runnable);
	rq->nr_runnable = 0;
	rq->nr_busy = 0;
}

static int oncore_sched_enqueue(struct oncore_session *sess,
				struct oncore_job *job)
{
	struct oncore_runqueue *rq = &sess->rq;
	unsigned long flags;
	int cpu, ret;

	ret = oncore_rq_lock_host(sess, &flags);
	if (ret)
		return ret;
	WRITE_ONCE(job->state, ONCORE_JOB_RUNNABLE);
	oncore_list_add_tail(&job->node, &rq->runnable);
	rq->nr_runnable++;
	oncore_rq_unlock(rq);
	local_irq_restore(flags);

	/*
	 * Wake idle preserved CPUs in the session or CPUs currently running
	 * tickless so they observe the newly enqueued job.
	 */
	for_each_cpu(cpu, oncore_session_cpus(sess)) {
		struct cpupr_stack_context *sctx;

		if (!cpu_is_preserved(cpu))
			continue;
		sctx = cpupr_get_sctx(cpu);
		if (!sctx || !READ_ONCE(sctx->oncore_busy) ||
		    READ_ONCE(sctx->oncore_tickless))
			arch_cpupr_kick(cpu);
	}

	return 0;
}

static int oncore_sched_dequeue(struct oncore_session *sess,
				struct oncore_job *job, bool *running)
{
	struct oncore_runqueue *rq = &sess->rq;
	unsigned long flags;
	int ret;

	ret = oncore_rq_lock_host(sess, &flags);
	if (ret)
		return ret;
	if (!oncore_list_empty(&job->node)) {
		oncore_list_del_init(&job->node);
		rq->nr_runnable--;
		WRITE_ONCE(job->state, ONCORE_JOB_DEAD);
		*running = false;
	} else if (READ_ONCE(job->state) == ONCORE_JOB_RUNNING ||
		   READ_ONCE(job->state) == ONCORE_JOB_CANCELING) {
		WRITE_ONCE(job->state, ONCORE_JOB_CANCELING);
		*running = true;
	} else {
		WRITE_ONCE(job->state, ONCORE_JOB_DEAD);
		*running = false;
	}
	oncore_rq_unlock(rq);
	local_irq_restore(flags);
	return 0;
}

/**
 * oncore_session_alloc_buffer - Allocate a buffer mapped into a session
 * @sess: On-Core session.
 * @size: Size of the buffer in bytes.
 *
 * Allocates zeroed, KHO-preserved memory that the isolated address space of
 * @sess owns, mapped there at its direct-map address with %PAGE_KERNEL, for
 * state that the preserved CPUs executing workloads in @sess use across
 * kexec.  The address space frees the buffer when it is torn down, after
 * every CPU of the session has left it: callers never free it.
 *
 * Return: The page-aligned buffer, or an ERR_PTR() on failure.
 */
void *oncore_session_alloc_buffer(struct oncore_session *sess, size_t size)
{
	if (!sess || !sess->cps)
		return ERR_PTR(-EINVAL);

	return cpupr_as_alloc_buffer(sess->cps, size);
}

/**
 * oncore_session_adopt_page - Map a page of another owner into a session
 * @sess: On-Core session.
 * @page: Order-0 page whose physical address must not change.
 *
 * Makes the isolated address space of @sess a co-owner of @page and maps it
 * at its direct-map address with %PAGE_KERNEL, see
 * cpupr_as_adopt_page().  The owner keeps and drops its own
 * reference as usual.
 *
 * Return: 0 on success, or a negative errno on failure.
 */
int oncore_session_adopt_page(struct oncore_session *sess, struct page *page)
{
	if (!sess || !sess->cps)
		return -EINVAL;

	return cpupr_as_adopt_page(sess->cps, page);
}

/**
 * oncore_session_map_mmio - Map device registers into a session
 * @sess: On-Core session.
 * @pa:   Physical address of the registers.
 * @va:   Virtual address the registers must appear at.
 * @size: Size of the range in bytes.
 *
 * Return: 0 on success, or a negative errno on failure.
 */
int oncore_session_map_mmio(struct oncore_session *sess, phys_addr_t pa,
			    unsigned long va, size_t size)
{
	if (!sess || !sess->cps)
		return -EINVAL;

	return cpupr_as_map_mmio(sess->cps, pa, va, size);
}

/**
 * oncore_session_get_pgd_pa - Return the root page table physical address of a session
 * @sess: On-Core session.
 *
 * Return: Physical address of the session's isolated PGD, or 0 if @sess or its
 *         address space is %NULL.
 */
phys_addr_t oncore_session_get_pgd_pa(struct oncore_session *sess)
{
	return sess ? cpupr_session_pgd_pa(sess->cps) : 0;
}

/**
 * oncore_session_id - Return the identifier of a session
 * @sess: On-Core session.
 *
 * Return: An identifier that no other session of this kernel has, or 0 if
 *         @sess is %NULL.
 */
u64 oncore_session_id(struct oncore_session *sess)
{
	return sess ? cpupr_session_id(sess->cps) : 0;
}

static struct oncore_session *oncore_get_or_create_session(struct liveupdate_session *s)
{
	struct cpupr_session *cps;
	struct oncore_session *sess;
	int cpu;

	if (!arch_oncore_counter_freq_hz()) {
		pr_err("On-core counter frequency is unknown; refusing to create session\n");
		return ERR_PTR(-ENODEV);
	}

	guard(mutex)(&oncore_sessions_lock);

	cps = cpupr_find_session(s);
	if (!cps || cpumask_empty(cpupr_session_cpus(cps)))
		return NULL;

	sess = cpupr_session_workload(cps);
	if (sess)
		return sess;

	sess = cpupr_as_alloc_buffer(cps, sizeof(*sess));
	if (IS_ERR(sess))
		return sess;

	mutex_init(&sess->lock);
	INIT_LIST_HEAD(&sess->jobs);
	oncore_runqueue_init(&sess->rq);
	oncore_sched_update_ticks();
	sess->sched_config = global_oncore_sched_config;
	sess->cps = cps;

	cpupr_session_set_workload(cps, sess);

	for_each_cpu(cpu, oncore_session_cpus(sess))
		cpupr_set_workload_context(cpu, sess);

	return sess;
}

static void oncore_session_destroy(struct oncore_session *sess)
{
	struct cpupr_session *cps = sess->cps;

	scoped_guard(mutex, &oncore_sessions_lock) {
		if (cps)
			cpupr_session_set_workload(cps, NULL);
	}

	WARN_ON_ONCE(!list_empty(&sess->jobs));
}

/**
 * oncore_cpu_preserved - Notify On-Core that a physical CPU was preserved in @ps
 * @ps:  Preserved CPU session.
 * @cpu: Logical ID of the preserved physical CPU.
 *
 * If @ps already has an On-Core session, binds @cpu's preserved stack context
 * to the session, assigns any unassigned jobs, and attaches
 * oncore_sched_cpu_worker() if workers are already active.
 */
void oncore_cpu_preserved(struct cpupr_session *ps, int cpu)
{
	struct oncore_session *sess;
	struct oncore_job *job;

	if (!ps || cpu < 0 || cpu >= nr_cpu_ids)
		return;

	guard(mutex)(&oncore_sessions_lock);
	sess = cpupr_session_workload(ps);
	if (!sess)
		return;

	guard(mutex)(&sess->lock);

	cpupr_set_workload_context(cpu, sess);

	list_for_each_entry(job, &sess->jobs, sess_node) {
		if (READ_ONCE(job->assigned_cpu) < 0)
			WRITE_ONCE(job->assigned_cpu,
				   oncore_select_job_cpu(sess));
	}

	if (sess->workers_attached || READ_ONCE(sess->rq.nr_runnable) > 0) {
		if (!cpupr_attach_workload(cpu,
					   oncore_sched_cpu_worker,
					   sess))
			sess->workers_attached = true;
	}
}

/**
 * oncore_cpu_unpreserved - Notify On-Core that a physical CPU left @ps
 * @ps:  Preserved CPU session.
 * @cpu: Logical ID of the physical CPU being unpreserved.
 *
 * Clears @cpu's stack workload context and reassigns any jobs that were bound
 * to @cpu.
 */
void oncore_cpu_unpreserved(struct cpupr_session *ps, int cpu)
{
	struct oncore_session *sess;
	struct oncore_job *job;

	if (!ps || cpu < 0 || cpu >= nr_cpu_ids)
		return;

	cpupr_set_workload_context(cpu, NULL);

	guard(mutex)(&oncore_sessions_lock);
	sess = cpupr_session_workload(ps);
	if (!sess)
		return;

	guard(mutex)(&sess->lock);
	list_for_each_entry(job, &sess->jobs, sess_node) {
		if (READ_ONCE(job->assigned_cpu) == cpu)
			WRITE_ONCE(job->assigned_cpu,
				   oncore_select_job_cpu(sess));
	}
}

static unsigned int oncore_session_cpu_job_count(struct oncore_session *sess,
						 int cpu)
{
	struct oncore_job *j;
	unsigned int count = 0;

	list_for_each_entry(j, &sess->jobs, sess_node) {
		if (READ_ONCE(j->assigned_cpu) == cpu)
			count++;
	}

	return count;
}

static int oncore_select_job_cpu(struct oncore_session *sess)
{
	const struct cpumask *cpus = oncore_session_cpus(sess);
	unsigned int min_count = UINT_MAX, count;
	int cpu, min_cpu = -1;

	for_each_cpu(cpu, cpus) {
		if (cpupr_state(cpu) == CPUPR_FAULTED)
			continue;
		count = oncore_session_cpu_job_count(sess, cpu);
		if (count < min_count) {
			min_count = count;
			min_cpu = cpu;
		}
	}

	return min_cpu;
}

/**
 * oncore_session_submit_job - Allocate and register a workload job in an On-Core session
 * @s:      Live Update session handle.
 * @run_fn: Workload callback executed on a preserved physical CPU.
 * @data:   Opaque context pointer passed to @run_fn (may be %NULL and set
 *          later via oncore_job_set_data() before activation).
 *
 * Allocates the &struct oncore_job from the session's isolated address space
 * (see oncore_session_alloc_buffer()), assigns it to the least-loaded
 * preserved CPU in the session, and links it into @s.  The job is not placed
 * on the runqueue until oncore_session_activate_job() is called.
 *
 * A non-%NULL @data must be a buffer that oncore_session_alloc_buffer()
 * returned for the session of @s, so that the preserved CPUs can reach it and
 * it lives as long as they may run @run_fn.  Since the session does not exist
 * before its first job, a caller that needs the session to allocate @data
 * submits with %NULL and uses oncore_job_set_data().
 *
 * Return: Pointer to the allocated &struct oncore_job on success, %NULL if @s
 *         has no preserved CPUs, or an ERR_PTR() on failure.
 */
struct oncore_job *oncore_session_submit_job(struct liveupdate_session *s,
					     oncore_job_fn run_fn,
					     void *data)
{
	const struct {
		oncore_job_fn run;
		void *data;
	} _desc = { .run = run_fn, .data = data }, *desc = &_desc;
	struct oncore_session *sess;
	struct oncore_job *job;
	bool destroy = false;
	int ret;

	if (!s || !desc->run || !cpupr_is_runtime_text(desc->run))
		return ERR_PTR(-EINVAL);
	if (desc->data && (!PAGE_ALIGNED((unsigned long)desc->data) ||
			   !virt_addr_valid(desc->data)))
		return ERR_PTR(-EINVAL);

	sess = oncore_get_or_create_session(s);
	if (IS_ERR_OR_NULL(sess))
		return ERR_CAST(sess);

	scoped_guard(mutex, &sess->lock) {
		job = cpupr_as_alloc_buffer(sess->cps, sizeof(*job));
		if (IS_ERR(job)) {
			ret = PTR_ERR(job);
			goto err_check_empty;
		}

		INIT_LIST_HEAD(&job->node);
		INIT_LIST_HEAD(&job->sess_node);
		job->session = sess;
		job->state = ONCORE_JOB_NEW;
		job->run_fn = desc->run;
		job->data = desc->data;
		job->last_cpu = -1;
		WRITE_ONCE(job->assigned_cpu, oncore_select_job_cpu(sess));

		list_add_tail(&job->sess_node, &sess->jobs);
		return job;

err_check_empty:
		destroy = list_empty(&sess->jobs);
	}

	if (destroy)
		oncore_session_destroy(sess);
	return ERR_PTR(ret);
}

/**
 * oncore_session_activate_job - Enqueue a submitted job for execution
 * @s:   Live Update session handle.
 * @job: Job previously returned by oncore_session_submit_job().
 *
 * Attaches oncore_sched_cpu_worker() to the session's preserved physical CPUs
 * if not yet attached, places @job onto the session's round-robin FIFO
 * runqueue, and kicks the assigned preserved physical CPU so it wakes from
 * low-power park wait and begins executing @job.  @job->data, if set, is
 * already mapped: it is a buffer of the session, see
 * oncore_session_submit_job().
 *
 * Return: 0 on success, or a negative errno on failure.
 */
int oncore_session_activate_job(struct liveupdate_session *s,
				struct oncore_job *job)
{
	struct oncore_session *sess = job ? job->session : NULL;
	int cpu, ret;

	if (!s || !job || !sess || cpupr_session_lsession(sess->cps) != s)
		return -EINVAL;

	guard(mutex)(&sess->lock);
	if (READ_ONCE(job->state) != ONCORE_JOB_NEW)
		return -EBUSY;

	if (!sess->workers_attached && !cpumask_empty(oncore_session_cpus(sess))) {
		unsigned int attached = 0;

		for_each_cpu(cpu, oncore_session_cpus(sess)) {
			if (cpupr_state(cpu) == CPUPR_FAULTED)
				continue;
			ret = cpupr_attach_workload(cpu,
						    oncore_sched_cpu_worker,
						    sess);
			if (ret) {
				int c;

				for_each_cpu(c, oncore_session_cpus(sess)) {
					if (c == cpu)
						break;
					if (cpupr_state(c) == CPUPR_FAULTED)
						continue;
					cpupr_detach_workload(c);
				}
				return ret;
			}
			attached++;
		}
		if (!attached)
			return -EIO;
		sess->workers_attached = true;
	}

	return oncore_sched_enqueue(sess, job);
}

/**
 * oncore_job_set_data - Set the opaque argument passed to a job's run callback
 * @job:  Job to update.
 * @data: Pointer handed to @job's run_fn.  May be %NULL.
 *
 * Callers that cannot determine @data at submission time submit with %NULL and
 * call this once the object exists, before oncore_session_activate_job().
 * A non-%NULL @data must be a buffer that oncore_session_alloc_buffer()
 * returned for the session of @job, see oncore_job_session(): it is mapped
 * into the session's address space and lives as long as the session's CPUs.
 */
void oncore_job_set_data(struct oncore_job *job, void *data)
{
	if (job)
		WRITE_ONCE(job->data, data);
}

/**
 * oncore_job_cpu - Return the preserved physical CPU assigned to a job
 * @job: Job to query.
 *
 * Return: Logical CPU ID assigned to @job, or -1 if @job is %NULL.
 */
int oncore_job_cpu(const struct oncore_job *job)
{
	return job ? READ_ONCE(job->assigned_cpu) : -1;
}

/**
 * oncore_job_session - Return the On-Core session that owns a job
 * @job: Job to query.
 *
 * Return: Pointer to the owning &struct oncore_session, or %NULL if @job is %NULL.
 */
struct oncore_session *oncore_job_session(const struct oncore_job *job)
{
	return job ? job->session : NULL;
}

static bool oncore_job_poll_dead(struct oncore_job *job)
{
	int cpu;

	if (READ_ONCE(job->state) == ONCORE_JOB_DEAD)
		return true;

	cpu = READ_ONCE(job->last_cpu);
	if (cpu >= 0 && cpu_is_preserved(cpu))
		arch_cpupr_kick(cpu);

	return READ_ONCE(job->state) == ONCORE_JOB_DEAD;
}

/**
 * oncore_session_cancel_job - Stop and dequeue a submitted or running On-Core job
 * @s:   Live Update session handle.
 * @job: Job to cancel.
 *
 * Removes @job from the session and runqueue.  If @job is currently executing
 * on a preserved physical CPU (%ONCORE_JOB_CANCELING), kicks that CPU and
 * waits for the current scheduling quantum to finish.  The underlying
 * KHO-preserved @job and session folios remain owned by the session's address
 * space and are released when the address space is torn down.
 *
 * Return: 0 on success, or a negative errno on failure.
 */
int oncore_session_cancel_job(struct liveupdate_session *s,
			      struct oncore_job *job)
{
	struct oncore_session *sess = job ? job->session : NULL;
	bool destroy = false, running = false;
	int cpu, ret;

	if (!s || !job || !sess || cpupr_session_lsession(sess->cps) != s)
		return -EINVAL;

	scoped_guard(mutex, &sess->lock) {
		ret = oncore_sched_dequeue(sess, job, &running);
		if (ret)
			return ret;

		if (running) {
			unsigned long flags;
			bool dead;

			ret = read_poll_timeout(oncore_job_poll_dead, dead, dead,
						ONCORE_CANCEL_STEP_US,
						ONCORE_CANCEL_TIMEOUT_US,
						false, job);
			if (WARN_ON_ONCE(ret))
				return ret;

			ret = oncore_rq_lock_host(sess, &flags);
			if (ret)
				return ret;
			dead = (READ_ONCE(job->state) == ONCORE_JOB_DEAD);
			oncore_rq_unlock(&sess->rq);
			local_irq_restore(flags);

			if (WARN_ON_ONCE(!dead))
				return -ETIMEDOUT;
		}

		list_del_init(&job->sess_node);
		if (READ_ONCE(job->assigned_cpu) >= 0)
			WRITE_ONCE(job->assigned_cpu, -1);

		if (list_empty(&sess->jobs)) {
			bool detach_failed = false;

			for_each_cpu(cpu, oncore_session_cpus(sess)) {
				if (sess->workers_attached &&
				    cpupr_detach_workload(cpu)) {
					detach_failed = true;
					continue;
				}
				cpupr_set_workload_context(cpu, NULL);
			}
			if (!detach_failed) {
				sess->workers_attached = false;
				destroy = true;
			} else {
				WARN_ON_ONCE(1);
			}
		}
	}

	if (destroy)
		oncore_session_destroy(sess);

	return 0;
}
