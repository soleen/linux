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
 *    A lockless/atomic round-robin FIFO scheduler supporting M jobs across N
 *    preserved physical CPUs (including M > N oversubscription).  It provides
 *    initial-run starvation avoidance, least-loaded CPU assignment, work
 *    stealing, single-job fast-path continuation, and low-power backoff (WFE on
 *    arm64, PAUSE on x86) when the queue is idle or a job returns
 *    ONCORE_EXIT_STALL.
 *
 * Integration with KVM Caretaker and Future Kernel Caretaker Workloads
 * --------------------------------------------------------------------
 * On-Core is workload- and hypervisor-agnostic:
 *
 * - KVM Caretaker: During LUO prepare/freeze, KVM detaches each vCPU into a
 *   self-contained KHO-preserved Caretaker page (caretaker_x86_page on x86,
 *   caretaker_arm64_page on arm64), maps the page and guest/virtualization
 *   structures into the session's address space, and submits an oncore_job
 *   whose callback enters the guest (VMLAUNCH/VMRESUME, VMRUN, or EL2 world
 *   switch) until the time-slice deadline (deadline_ticks) expires, the vCPU
 *   yields on HLT/WFI (ONCORE_EXIT_YIELD_IDLE), hits an exit requiring the
 *   incoming kernel (ONCORE_EXIT_STALL), or observes the incoming kernel's
 *   reclaim signal (ONCORE_EXIT_ATTACH_SIGNALED).
 *
 * - Future Kernel Caretaker Workloads: Any self-contained kernel subsystem
 *   compiled into the preserved runtime sections (such as hardware watchdog
 *   feeders, health/heartbeat responders, or zero-loss network/storage
 *   polling drivers) can submit an oncore_job_fn(void *data, u64 deadline) to
 *   share preserved physical cores alongside or independently of KVM vCPUs.
 *
 * Architecture Requirements
 * -------------------------
 * To support CONFIG_LIVEUPDATE_CPU, an architecture must implement:
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
#include <linux/kexec.h>
#include <linux/kexec_handover.h>
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
#define ONCORE_CANCEL_TIMEOUT_US	1000000
#define ONCORE_CANCEL_STEP_US		100

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

	if (kstrtou32(arg, 0, &val) == 0 && val >= 1 && val <= 1000)
		global_oncore_sched_config.quantum_ms = val;
	return 0;
}
early_param("oncore.quantum_ms", parse_oncore_quantum);

static void oncore_sched_update_ticks(void)
{
	u32 ms = global_oncore_sched_config.quantum_ms ? : ONCORE_DEFAULT_QUANTUM_MS;
	u64 freq = arch_oncore_counter_freq_hz();

	global_oncore_sched_config.quantum_ticks = (freq * ms) / 1000ULL;
}

static void oncore_runqueue_init(struct oncore_runqueue *rq)
{
	atomic_set(&rq->lock, 0);
	INIT_LIST_HEAD(&rq->runnable);
	rq->nr_runnable = 0;
	rq->nr_busy = 0;
}

static int oncore_sched_enqueue(struct oncore_runqueue *rq,
				struct oncore_job *job)
{
	unsigned int nr_active, nr_cpus = 0;
	unsigned long flags;
	int cpu;

	local_irq_save(flags);
	oncore_rq_lock(rq);
	WRITE_ONCE(job->state, ONCORE_JOB_RUNNABLE);
	oncore_list_add_tail(&job->node, &rq->runnable);
	rq->nr_runnable++;
	nr_active = rq->nr_runnable + rq->nr_busy;
	oncore_rq_unlock(rq);
	local_irq_restore(flags);

	/*
	 * Wake idle preserved CPUs in the session so one of them picks up the
	 * newly runnable job without disturbing CPUs already executing 1:1
	 * jobs.
	 */
	for_each_cpu(cpu, oncore_session_cpus(job->session)) {
		struct cpu_preserved_stack_context *sctx;

		if (!cpu_is_preserved(cpu))
			continue;
		nr_cpus++;
		sctx = cpu_preserved_get_sctx(cpu);
		if (!sctx || !READ_ONCE(sctx->oncore_busy))
			arch_cpu_preserved_kick(cpu);
	}

	/*
	 * If there are more active jobs than preserved CPUs in the session
	 * (M > N overcommit), preempt any CPU currently executing with an
	 * unbounded (tickless) deadline so it switches to time-sliced
	 * round-robin scheduling.
	 */
	if (nr_active > nr_cpus) {
		for_each_cpu(cpu, oncore_session_cpus(job->session)) {
			struct cpu_preserved_stack_context *sctx;
			int retries = 0;

			if (!cpu_is_preserved(cpu))
				continue;
			sctx = cpu_preserved_get_sctx(cpu);
			while (sctx && READ_ONCE(sctx->oncore_tickless) &&
			       READ_ONCE(rq->nr_runnable) > 0 &&
			       retries < (ONCORE_CANCEL_TIMEOUT_US / ONCORE_CANCEL_STEP_US)) {
				if ((retries % 50) == 0)
					arch_cpu_preserved_kick(cpu);
				udelay(ONCORE_CANCEL_STEP_US);
				retries++;
			}
		}
	}

	return 0;
}

static bool oncore_sched_dequeue(struct oncore_runqueue *rq,
				 struct oncore_job *job)
{
	unsigned long flags;
	bool running;

	local_irq_save(flags);
	oncore_rq_lock(rq);
	if (!oncore_list_empty(&job->node)) {
		oncore_list_del_init(&job->node);
		rq->nr_runnable--;
		WRITE_ONCE(job->state, ONCORE_JOB_DEAD);
		running = false;
	} else if (READ_ONCE(job->state) == ONCORE_JOB_RUNNING ||
		   READ_ONCE(job->state) == ONCORE_JOB_CANCELING) {
		WRITE_ONCE(job->state, ONCORE_JOB_CANCELING);
		running = true;
	} else {
		WRITE_ONCE(job->state, ONCORE_JOB_DEAD);
		running = false;
	}
	oncore_rq_unlock(rq);
	local_irq_restore(flags);
	return running;
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
	oncore_session_unmap_range(sess, (unsigned long)va, size);
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

	cps = cpu_preserved_session_get(s);
	if (IS_ERR(cps))
		return ERR_CAST(cps);

	if (cpumask_empty(cpu_preserved_session_cpus(cps))) {
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
	oncore_runqueue_init(&sess->rq);
	oncore_sched_update_ticks();
	sess->sched_config = global_oncore_sched_config;
	sess->cps = cps;

	ret = oncore_session_map_range(sess, virt_to_phys(sess),
				       (unsigned long)sess, sizeof(*sess),
				       PAGE_KERNEL);
	if (ret) {
		kho_unpreserve_free(sess);
		cpu_preserved_session_put(cps);
		return ERR_PTR(ret);
	}

	cpu_preserved_session_set_workload(cps, sess, virt_to_phys(sess));

	for_each_cpu(cpu, oncore_session_cpus(sess))
		cpu_preserved_set_workload_context(cpu, sess,
						   oncore_session_get_pgd_pa(sess));

	return sess;
}

static void oncore_sync_jobs_pa(struct oncore_session *sess)
{
	phys_addr_t *tail = &sess->first_job_pa;
	struct oncore_job *j;

	list_for_each_entry(j, &sess->jobs, sess_node) {
		j->next_job_pa = 0;
		*tail = virt_to_phys(j);
		tail = &j->next_job_pa;
	}
	*tail = 0;
}

static void oncore_session_destroy(struct oncore_session *sess)
{
	struct cpu_preserved_session *cps = sess->cps;
	struct oncore_job *job, *tmp;

	scoped_guard(mutex, &oncore_sessions_lock) {
		if (cps)
			cpu_preserved_session_set_workload(cps, NULL, 0);
	}

	list_for_each_entry_safe(job, tmp, &sess->jobs, sess_node) {
		list_del_init(&job->sess_node);
		cpu_preserved_free_kho(job, false);
	}

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
 * to the session and its isolated PGD, assigns any unassigned jobs, and
 * attaches oncore_sched_cpu_worker() if workers are already active.
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

	cpu_preserved_set_workload_context(cpu, sess,
					   oncore_session_get_pgd_pa(sess));

	list_for_each_entry(job, &sess->jobs, sess_node) {
		if (job->assigned_cpu < 0)
			job->assigned_cpu = oncore_select_job_cpu(sess);
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
 * Detaches any On-Core scheduler worker from @cpu, clears its stack workload
 * context, and reassigns any jobs that were bound to @cpu.
 */
void oncore_cpu_unpreserved(struct cpu_preserved_session *ps, int cpu)
{
	struct oncore_session *sess;
	struct oncore_job *job;

	if (!ps || cpu < 0 || cpu >= nr_cpu_ids)
		return;

	cpu_preserved_detach_workload(cpu);
	cpu_preserved_set_workload_context(cpu, NULL, 0);

	guard(mutex)(&oncore_sessions_lock);
	sess = cpu_preserved_session_workload(ps);
	if (!sess)
		return;

	guard(mutex)(&sess->lock);
	list_for_each_entry(job, &sess->jobs, sess_node) {
		if (job->assigned_cpu == cpu)
			job->assigned_cpu = oncore_select_job_cpu(sess);
	}
}

/**
 * oncore_session_release - Release KHO-preserved On-Core session and jobs
 * @workload_pa: Physical address of the KHO-preserved &struct oncore_session.
 * @incoming:    True if releasing restored KHO state in the incoming kernel,
 *               false if unpreserving in the outgoing kernel.
 *
 * Walks the physical job chain rooted at @workload_pa and frees all preserved
 * job and session structures.
 */
void oncore_session_release(u64 workload_pa, bool incoming)
{
	struct oncore_session *sess;
	struct oncore_job *job;
	phys_addr_t job_pa;

	if (!workload_pa)
		return;

	sess = phys_to_virt(workload_pa);
	job_pa = sess->first_job_pa;
	while (job_pa) {
		job = phys_to_virt(job_pa);
		job_pa = job->next_job_pa;
		cpu_preserved_free_kho(job, incoming);
	}
	cpu_preserved_free_kho(sess, incoming);
}

static unsigned int oncore_session_cpu_job_count(struct oncore_session *sess,
						 int cpu)
{
	struct oncore_job *j;
	unsigned int count = 0;

	list_for_each_entry(j, &sess->jobs, sess_node) {
		if (j->assigned_cpu == cpu)
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
	struct oncore_session *sess;
	struct oncore_job *job;
	int ret;

	if (!run_fn)
		return ERR_PTR(-EINVAL);

	sess = oncore_get_or_create_session(s);
	if (IS_ERR_OR_NULL(sess))
		return ERR_CAST(sess);

	guard(mutex)(&sess->lock);

	job = kho_alloc_preserve(sizeof(*job));
	if (IS_ERR(job))
		return job;

	ret = oncore_session_map_buffer(sess, job, sizeof(*job));
	if (ret) {
		kho_unpreserve_free(job);
		return ERR_PTR(ret);
	}
	INIT_LIST_HEAD(&job->node);
	INIT_LIST_HEAD(&job->sess_node);
	job->session = sess;
	job->state = ONCORE_JOB_NEW;
	job->run_fn = run_fn;
	job->data = data;
	job->last_cpu = -1;
	job->assigned_cpu = oncore_select_job_cpu(sess);

	list_add_tail(&job->sess_node, &sess->jobs);
	oncore_sync_jobs_pa(sess);

	return job;
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

	if (!s || !sess || !job)
		return -EINVAL;

	guard(mutex)(&sess->lock);
	if (job->data) {
		ret = oncore_session_map_buffer(sess, job->data, PAGE_SIZE);
		if (ret)
			return ret;
	}

	if (!sess->workers_attached && !cpumask_empty(oncore_session_cpus(sess))) {
		for_each_cpu(cpu, oncore_session_cpus(sess)) {
			ret = cpu_preserved_attach_workload(cpu,
							    oncore_sched_cpu_worker,
							    sess);
			if (ret) {
				int c;

				for_each_cpu(c, oncore_session_cpus(sess)) {
					if (c == cpu)
						break;
					cpu_preserved_detach_workload(c);
				}
				return ret;
			}
		}
		sess->workers_attached = true;
	}

	return oncore_sched_enqueue(&sess->rq, job);
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
		job->data = data;
}

/**
 * oncore_job_cpu - Return the preserved physical CPU assigned to a job
 * @job: Job to query.
 *
 * Return: Logical CPU ID assigned to @job, or -1 if @job is %NULL.
 */
int oncore_job_cpu(const struct oncore_job *job)
{
	return job ? job->assigned_cpu : -1;
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
	bool destroy = false;
	int cpu, retries;

	if (!s || !sess || !job)
		return -EINVAL;

	scoped_guard(mutex, &sess->lock) {
		if (oncore_sched_dequeue(&sess->rq, job)) {
			unsigned long flags;
			bool dead;

			retries = 0;

			while (READ_ONCE(job->state) != ONCORE_JOB_DEAD &&
			       retries < (ONCORE_CANCEL_TIMEOUT_US / ONCORE_CANCEL_STEP_US)) {
				cpu = READ_ONCE(job->last_cpu);
				if ((retries % 50) == 0 && cpu >= 0 &&
				    cpu_is_preserved(cpu))
					arch_cpu_preserved_kick(cpu);
				udelay(ONCORE_CANCEL_STEP_US);
				retries++;
			}

			local_irq_save(flags);
			oncore_rq_lock(&sess->rq);
			dead = (READ_ONCE(job->state) == ONCORE_JOB_DEAD);
			oncore_rq_unlock(&sess->rq);
			local_irq_restore(flags);

			if (WARN_ON_ONCE(!dead))
				return -ETIMEDOUT;
		}

		list_del_init(&job->sess_node);
		oncore_sync_jobs_pa(sess);
		if (job->assigned_cpu >= 0)
			job->assigned_cpu = -1;

		if (list_empty(&sess->jobs)) {
			for_each_cpu(cpu, oncore_session_cpus(sess)) {
				if (sess->workers_attached)
					cpu_preserved_detach_workload(cpu);
				cpu_preserved_set_workload_context(cpu, NULL, 0);
			}
			sess->workers_attached = false;
			destroy = true;
		}
	}

	cpu_preserved_free_kho(job, false);
	if (destroy)
		oncore_session_destroy(sess);

	return 0;
}
