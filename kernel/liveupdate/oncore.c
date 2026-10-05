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
 * executing directly on preserved physical CPUs (.cpu_preserved.text /
 * .cpu_preserved.data) across a kexec Live Update (CONFIG_LIVEUPDATE_CPU)
 * while the outgoing host kernel shuts down and the incoming kernel boots.
 *
 * Each Live Update session (struct liveupdate_session) can create an
 * oncore_session that manages:
 *
 * 1. Isolated Address Space (struct cpu_preserved_as_ser):
 *    Page tables containing only the preserved runtime text/data sections,
 *    the session and runqueue metadata, and workload-specific buffers
 *    explicitly mapped via oncore_session_map_range() or
 *    oncore_session_map_buffer().
 *
 * 2. Preserved Physical CPU Pool:
 *    One or more physical CPUs isolated from Linux scheduling via
 *    cpu_preserve and notified to the session via oncore_cpu_preserved().
 *    Preserved CPUs remain parked in cpu_preserved_park_loop() until a job is
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
 * subsystem compiled into the preserved runtime sections (.cpu_preserved.text /
 * .cpu_preserved.data) can map its KHO-preserved state into the session's
 * isolated address space and submit an oncore_job_fn(void *data, u64 deadline)
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
 *     from .cpu_preserved.text without relying on kernel timekeeping
 *     (e.g., rdtsc() on x86, __arch_counter_get_cntpct() on arm64).
 *   - arch_oncore_counter_freq_hz(): Return the hardware counter frequency in
 *     Hz used to convert the time quantum (oncore.quantum_ms) into ticks.
 *
 * - <asm/cpu_preserve.h> (from CONFIG_LIVEUPDATE_CPU):
 *   - arch_cpu_preserved_switch_pgd(): Switch to the session's isolated PGD.
 *   - arch_cpu_preserved_park_wait() / arch_cpu_preserved_kick(): Low-power
 *     wait instruction and cross-CPU wakeup mechanism.
 *
 * Public Interfaces (<linux/oncore.h>)
 * ------------------------------------
 * - Session & CPU Lifecycle:
 *   oncore_cpu_preserved(), oncore_cpu_unpreserved(),
 *   oncore_session_release().
 * - Session Address Space Mapping:
 *   oncore_session_map_range(), oncore_session_map_buffer(),
 *   oncore_session_unmap_range(), oncore_session_unmap_buffer(),
 *   oncore_session_get_pgd_pa().
 * - Job Submission & Control:
 *   oncore_session_submit_job(), oncore_job_set_data(),
 *   oncore_job_cpu(), oncore_job_session(),
 *   oncore_session_activate_job(), oncore_session_cancel_job().
 */

#define pr_fmt(fmt) "oncore: " fmt

#include <linux/cpu_preserve.h>
#include <linux/cpumask.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/kexec.h>
#include <linux/kexec_handover.h>
#include <linux/kho_block.h>
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

#define ONCORE_DEFAULT_QUANTUM_MS	10
#define ONCORE_CANCEL_TIMEOUT_US	USEC_PER_SEC
#define ONCORE_CANCEL_STEP_US		100

static u32 oncore_quantum_ms = ONCORE_DEFAULT_QUANTUM_MS;
static struct oncore_sched_config global_oncore_sched_config;
static DEFINE_MUTEX(oncore_sessions_lock);

static inline const struct cpumask *
oncore_session_cpus(const struct oncore_session *sess)
{
	return cpu_preserved_session_cpus(sess ? sess->cps : NULL);
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
		if (cpu_preserved_state(cpu) == CPU_PRESERVED_FAULTED)
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
		struct cpu_preserved_stack_context *sctx;

		if (!cpu_is_preserved(cpu))
			continue;
		sctx = cpu_preserved_get_sctx(cpu);
		if (!sctx || !READ_ONCE(sctx->oncore_busy) ||
		    READ_ONCE(sctx->oncore_tickless))
			arch_cpu_preserved_kick(cpu);
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
 * oncore_session_map_range - Map a physical memory range into the session's address space
 * @sess: On-Core session.
 * @pa:   Start physical address of the range.
 * @va:   Target virtual address in the isolated page tables.
 * @size: Size of the mapping in bytes.
 * @prot: Page protection flags.
 *
 * Maps `[pa, pa + size)` at `@va` in the isolated page tables used by
 * preserved CPUs executing workloads in @sess across kexec.
 *
 * Return: 0 on success, or a negative errno on failure.
 */
int oncore_session_map_range(struct oncore_session *sess, phys_addr_t pa,
			     unsigned long va, size_t size, pgprot_t prot)
{
	struct cpu_preserved_as_ser *as;

	as = sess ? cpu_preserved_session_as(sess->cps) : NULL;
	if (as)
		return cpu_preserved_as_map(as, pa, va, size, prot);

	return -EINVAL;
}

/**
 * oncore_session_map_buffer - Map a direct-map kernel buffer into the session's address space
 * @sess: On-Core session.
 * @va:   Kernel direct-map virtual address of the buffer (no-op if %NULL).
 * @size: Size of the buffer in bytes (no-op if 0).
 *
 * Convenience helper that resolves `virt_to_phys(@va)` and maps the buffer at
 * its existing kernel virtual address `@va` with %PAGE_KERNEL permissions in
 * the session's isolated page tables.
 *
 * Return: 0 on success, or a negative errno on failure.
 */
int oncore_session_map_buffer(struct oncore_session *sess, void *va,
			      size_t size)
{
	if (!va || !size)
		return 0;
	size = PAGE_ALIGN(size);
	if (!sess || !PAGE_ALIGNED((unsigned long)va) ||
	    !PAGE_ALIGNED(size) || !virt_addr_valid(va))
		return -EINVAL;
	return oncore_session_map_range(sess, virt_to_phys(va),
					(unsigned long)va, size, PAGE_KERNEL);
}

/**
 * oncore_session_unmap_range - Unmap a virtual address range from the session's address space
 * @sess: On-Core session (may be %NULL to unmap from all preserved address spaces).
 * @va:   Start virtual address in the isolated page tables.
 * @size: Size of the mapping in bytes.
 */
void oncore_session_unmap_range(struct oncore_session *sess, unsigned long va,
				size_t size)
{
	struct cpu_preserved_as_ser *as;

	as = sess ? cpu_preserved_session_as(sess->cps) : NULL;
	cpu_preserved_as_unmap(as, va, size);
}

/**
 * oncore_session_unmap_buffer - Unmap a direct-map kernel buffer from the session's address space
 * @sess: On-Core session (may be %NULL to unmap from all preserved address spaces).
 * @va:   Kernel direct-map virtual address of the buffer (no-op if %NULL).
 * @size: Size of the buffer in bytes (no-op if 0).
 */
void oncore_session_unmap_buffer(struct oncore_session *sess, void *va,
				 size_t size)
{
	if (!va || !size)
		return;
	oncore_session_unmap_range(sess, (unsigned long)va, PAGE_ALIGN(size));
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
	struct cpu_preserved_as_ser *as;

	as = sess ? cpu_preserved_session_as(sess->cps) : NULL;
	return as ? as->pgd_pa : 0;
}

static int oncore_sync_jobs_pa(struct oncore_session *sess)
{
	struct kho_block_set_it it;
	struct oncore_job *j;
	u64 count = 1;
	u64 *pa_entry;
	int ret;

	list_for_each_entry(j, &sess->jobs, sess_node)
		count++;

	ret = kho_block_set_grow(&sess->block_set, count);
	if (ret)
		return ret;

	kho_block_set_clear(&sess->block_set);
	kho_block_set_it_init(&it, &sess->block_set);

	pa_entry = kho_block_set_it_reserve_entry(&it);
	if (WARN_ON_ONCE(!pa_entry))
		return -ENOSPC;
	*pa_entry = virt_to_phys(sess);

	list_for_each_entry(j, &sess->jobs, sess_node) {
		pa_entry = kho_block_set_it_reserve_entry(&it);
		if (WARN_ON_ONCE(!pa_entry))
			return -ENOSPC;
		*pa_entry = virt_to_phys(j);
	}

	kho_block_set_shrink(&sess->block_set, count);
	return 0;
}

static struct oncore_session *oncore_get_or_create_session(struct liveupdate_session *s)
{
	struct cpu_preserved_session *cps;
	struct oncore_session *sess;
	int cpu, ret;

	if (!arch_oncore_counter_freq_hz()) {
		pr_err("On-core counter frequency is unknown; refusing to create session\n");
		return ERR_PTR(-ENODEV);
	}

	guard(mutex)(&oncore_sessions_lock);

	cps = cpu_preserved_find_session(s);
	if (!cps)
		return NULL;

	if (cpumask_empty(&cps->cpus)) {
		cpu_preserved_session_put(cps);
		return NULL;
	}

	sess = cpu_preserved_session_workload(cps);
	if (sess) {
		cpu_preserved_session_put(cps);
		return sess;
	}

	sess = kho_alloc_preserve(sizeof(*sess));
	if (IS_ERR(sess)) {
		cpu_preserved_session_put(cps);
		return ERR_CAST(sess);
	}

	mutex_init(&sess->lock);
	INIT_LIST_HEAD(&sess->jobs);
	kho_block_set_init(&sess->block_set, sizeof(u64));
	oncore_runqueue_init(&sess->rq);
	oncore_sched_update_ticks();
	sess->sched_config = global_oncore_sched_config;
	sess->cps = cps;

	ret = oncore_session_map_buffer(sess, sess, PAGE_SIZE);
	if (ret) {
		kho_unpreserve_free(sess);
		cpu_preserved_session_put(cps);
		return ERR_PTR(ret);
	}

	ret = oncore_sync_jobs_pa(sess);
	if (ret) {
		oncore_session_unmap_buffer(sess, sess, PAGE_SIZE);
		cpu_preserved_free_kho(sess, false);
		cpu_preserved_session_put(cps);
		return ERR_PTR(ret);
	}

	cpu_preserved_session_set_workload(cps, sess,
					   kho_block_set_head_pa(&sess->block_set));

	for_each_cpu(cpu, oncore_session_cpus(sess))
		cpu_preserved_set_workload_context(cpu, sess);

	return sess;
}

static void oncore_session_destroy(struct oncore_session *sess)
{
	struct cpu_preserved_session *cps = sess->cps;

	scoped_guard(mutex, &oncore_sessions_lock) {
		if (cps)
			cpu_preserved_session_set_workload(cps, NULL, 0);
	}

	WARN_ON_ONCE(!list_empty(&sess->jobs));

	kho_block_set_destroy(&sess->block_set);
	oncore_session_unmap_buffer(sess, sess, PAGE_SIZE);
	cpu_preserved_free_kho(sess, false);
	if (cps)
		cpu_preserved_session_put(cps);
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
void oncore_cpu_preserved(struct cpu_preserved_session *ps, int cpu)
{
	struct oncore_session *sess;
	struct oncore_job *job;

	if (!ps || cpu < 0 || cpu >= nr_cpu_ids)
		return;

	guard(mutex)(&oncore_sessions_lock);
	sess = cpu_preserved_session_workload(ps);
	if (!sess)
		return;

	guard(mutex)(&sess->lock);

	cpu_preserved_set_workload_context(cpu, sess);

	list_for_each_entry(job, &sess->jobs, sess_node) {
		if (READ_ONCE(job->assigned_cpu) < 0)
			WRITE_ONCE(job->assigned_cpu,
				   oncore_select_job_cpu(sess));
	}

	if (sess->workers_attached || READ_ONCE(sess->rq.nr_runnable) > 0) {
		if (!cpu_preserved_attach_workload(cpu,
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
void oncore_cpu_unpreserved(struct cpu_preserved_session *ps, int cpu)
{
	struct oncore_session *sess;
	struct oncore_job *job;

	if (!ps || cpu < 0 || cpu >= nr_cpu_ids)
		return;

	cpu_preserved_set_workload_context(cpu, NULL);

	guard(mutex)(&oncore_sessions_lock);
	sess = cpu_preserved_session_workload(ps);
	if (!sess)
		return;

	guard(mutex)(&sess->lock);
	list_for_each_entry(job, &sess->jobs, sess_node) {
		if (READ_ONCE(job->assigned_cpu) == cpu)
			WRITE_ONCE(job->assigned_cpu,
				   oncore_select_job_cpu(sess));
	}
}

/**
 * oncore_session_release - Release KHO-preserved On-Core session and jobs
 * @workload_pa: Physical address of the first &struct kho_block_header_ser
 *               block holding KHO-preserved session and job physical addresses.
 * @incoming:    True if releasing restored KHO state in the incoming kernel,
 *               false if unpreserving in the outgoing kernel.
 *
 * Restores the KHO block set rooted at @workload_pa and frees all preserved
 * session and job pages without dereferencing the previous kernel's runtime
 * structures.
 */
void oncore_session_release(u64 workload_pa, bool incoming)
{
	struct kho_block_set bs;
	struct kho_block_set_it it;
	u64 *pa_entry;

	if (!workload_pa)
		return;

	kho_block_set_init(&bs, sizeof(u64));
	if (!kho_block_set_restore(&bs, workload_pa)) {
		kho_block_set_it_init(&it, &bs);
		while ((pa_entry = kho_block_set_it_read_entry(&it)))
			cpu_preserved_free_kho(phys_to_virt(*pa_entry),
					       incoming);
		kho_block_set_destroy(&bs);
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
		if (cpu_preserved_state(cpu) == CPU_PRESERVED_FAULTED)
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
 * Allocates a KHO-preserved &struct oncore_job, maps it into the session's
 * isolated address space, assigns it to the least-loaded preserved CPU in the
 * session, and links it into @s.  The job is not placed on the runqueue until
 * oncore_session_activate_job() is called.
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

	if (!s || !desc->run || !cpu_preserved_is_runtime_text(desc->run))
		return ERR_PTR(-EINVAL);
	if (desc->data && (!PAGE_ALIGNED((unsigned long)desc->data) ||
			   !virt_addr_valid(desc->data)))
		return ERR_PTR(-EINVAL);

	sess = oncore_get_or_create_session(s);
	if (IS_ERR_OR_NULL(sess))
		return ERR_CAST(sess);

	scoped_guard(mutex, &sess->lock) {
		job = kho_alloc_preserve(sizeof(*job));
		if (IS_ERR(job)) {
			ret = PTR_ERR(job);
			goto err_check_empty;
		}

		ret = oncore_session_map_buffer(sess, job, PAGE_SIZE);
		if (ret) {
			cpu_preserved_free_kho(job, false);
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
		ret = oncore_sync_jobs_pa(sess);
		if (ret) {
			list_del_init(&job->sess_node);
			oncore_session_unmap_buffer(sess, job, PAGE_SIZE);
			cpu_preserved_free_kho(job, false);
			goto err_check_empty;
		}

		return job;

err_check_empty:
		destroy = list_empty(&sess->jobs);
	}

	if (destroy)
		oncore_session_destroy(sess);
	return ERR_PTR(ret);
}

/**
 * oncore_session_activate_job - Map a submitted job's data and enqueue it for execution
 * @s:   Live Update session handle.
 * @job: Job previously returned by oncore_session_submit_job().
 *
 * Maps the first page of @job->data (if non-%NULL) into the session's isolated
 * address space, attaches oncore_sched_cpu_worker() to the session's preserved
 * physical CPUs if not yet attached, places @job onto the session's round-robin
 * FIFO runqueue, and kicks the assigned preserved physical CPU so it wakes from
 * low-power park wait and begins executing @job.
 *
 * Return: 0 on success, or a negative errno on failure.
 */
int oncore_session_activate_job(struct liveupdate_session *s,
				struct oncore_job *job)
{
	struct oncore_session *sess = job ? job->session : NULL;
	int cpu, ret;

	if (!s || !job || !sess || !sess->cps || sess->cps->lsession != s)
		return -EINVAL;

	guard(mutex)(&sess->lock);
	if (READ_ONCE(job->state) != ONCORE_JOB_NEW)
		return -EBUSY;

	if (job->data) {
		ret = oncore_session_map_buffer(sess, job->data, PAGE_SIZE);
		if (ret)
			return ret;
	}

	if (!sess->workers_attached && !cpumask_empty(oncore_session_cpus(sess))) {
		unsigned int attached = 0;

		for_each_cpu(cpu, oncore_session_cpus(sess)) {
			if (cpu_preserved_state(cpu) == CPU_PRESERVED_FAULTED)
				continue;
			ret = cpu_preserved_attach_workload(cpu,
							    oncore_sched_cpu_worker,
							    sess);
			if (ret) {
				int c;

				for_each_cpu(c, oncore_session_cpus(sess)) {
					if (c == cpu)
						break;
					if (cpu_preserved_state(c) == CPU_PRESERVED_FAULTED)
						continue;
					cpu_preserved_detach_workload(c);
				}
				if (job->data)
					oncore_session_unmap_buffer(sess,
								    job->data,
								    PAGE_SIZE);
				return ret;
			}
			attached++;
		}
		if (!attached) {
			if (job->data)
				oncore_session_unmap_buffer(sess, job->data,
							    PAGE_SIZE);
			return -EIO;
		}
		sess->workers_attached = true;
	}

	ret = oncore_sched_enqueue(sess, job);
	if (ret && job->data)
		oncore_session_unmap_buffer(sess, job->data, PAGE_SIZE);
	return ret;
}

/**
 * oncore_job_set_data - Set the opaque argument passed to a job's run callback
 * @job:  Job to update.
 * @data: Pointer handed to @job's run_fn.  May be %NULL.
 *
 * Callers that cannot determine @data at submission time submit with %NULL and
 * call this once the object exists.  It must be called before
 * oncore_session_activate_job(), which is what maps @data into the session's
 * address space.
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
		arch_cpu_preserved_kick(cpu);

	return READ_ONCE(job->state) == ONCORE_JOB_DEAD;
}

/**
 * oncore_session_cancel_job - Stop and free a submitted or running On-Core job
 * @s:   Live Update session handle.
 * @job: Job to cancel.
 *
 * Removes @job from the session and runqueue.  If @job is currently executing
 * on a preserved physical CPU (%ONCORE_JOB_CANCELING), kicks that CPU and
 * waits for the current scheduling quantum to finish before unpreserving and
 * freeing @job.
 *
 * Return: 0 on success, or -EINVAL if @s or @job is invalid.
 */
int oncore_session_cancel_job(struct liveupdate_session *s,
			      struct oncore_job *job)
{
	struct oncore_session *sess = job ? job->session : NULL;
	bool destroy = false, running = false, was_active;
	int cpu, ret;

	if (!s || !job || !sess || !sess->cps || sess->cps->lsession != s)
		return -EINVAL;

	scoped_guard(mutex, &sess->lock) {
		was_active = READ_ONCE(job->state) != ONCORE_JOB_NEW;
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
		oncore_sync_jobs_pa(sess);
		if (READ_ONCE(job->assigned_cpu) >= 0)
			WRITE_ONCE(job->assigned_cpu, -1);

		if (was_active && job->data)
			oncore_session_unmap_buffer(sess, job->data, PAGE_SIZE);
		oncore_session_unmap_buffer(sess, job, PAGE_SIZE);

		if (list_empty(&sess->jobs)) {
			bool detach_failed = false;

			for_each_cpu(cpu, oncore_session_cpus(sess)) {
				if (sess->workers_attached &&
				    cpu_preserved_detach_workload(cpu)) {
					detach_failed = true;
					continue;
				}
				cpu_preserved_set_workload_context(cpu, NULL);
			}
			if (!detach_failed) {
				sess->workers_attached = false;
				destroy = true;
			} else {
				WARN_ON_ONCE(1);
			}
		}
	}

	cpu_preserved_free_kho(job, false);
	if (destroy)
		oncore_session_destroy(sess);

	return 0;
}
