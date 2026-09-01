// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 */

/**
 * DOC: Caretaker On-Core Execution Framework for Orphaned Jobs
 *
 * Overview
 * ========
 * The Caretaker on-core execution framework coordinates orphaned jobs across
 * live update transitions.
 *
 * What is an Orphaned Job?
 * ========================
 * An orphaned job is an active execution entity (workload) whose controlling
 * userspace parent process (such as a VMM like NanoVMM/QEMU,
 * or a bare process coordinator) has detached, paused, or terminated prior to a
 * host live update (kexec reboot), but whose execution state, hardware registers,
 * and memory are preserved so that it continues running directly on-core across
 * the kernel transition.
 *
 * Types of Orphaned Jobs:
 *   1. Orphaned Virtual Machines (vCPUs):
 *      A guest vCPU whose virtualization hardware state (VMCS on Intel VMX,
 *      VMCB on AMD SVM, or Hypervisor context on ARM64), guest registers, and
 *      Second-Level Address Translation (EPT/NPT/Stage-2) tables are preserved.
 *      The vCPU executes in an autonomous on-core Caretaker loop across kexec,
 *      allowing guest operating systems and workloads to make continuous progress
 *      without experiencing host live update downtime.
 *   2. Orphaned Userspace Processes (Bare Tasks/Threads - Future Expansion):
 *      A native userspace task or high-performance compute thread that detaches
 *      from the host kernel scheduler and runs directly on an isolated,
 *      preserved physical core across the kernel transition.
 *
 * Lifecycle of an Orphaned Job:
 *   - Orphaning / Detachment: The outgoing userspace manager preserves its
 *     descriptors into an LUO session. Caretaker
 *     submits the job and attaches it to an isolated preserved physical CPU.
 *   - Autonomous In-Gap Execution: During KHO and incoming kernel
 *     initialization, the orphaned job runs on-core in preserved memory.
 *   - Adoption / Resumption: The incoming kernel userspace manager retrieves
 *     the LUO session, connects to the orphaned job, adopts its execution
 *     state, and restores standard host scheduling.
 *
 * Architectural Layering & Scope
 * ==============================
 *
 * +-------------------------------------------------------------------------+
 * | System-Wide Scope: cpu_preserve (kernel/liveupdate/cpu_preserve.c)       |
 * |   * Global physical CPU preservation, hotplug isolation, and low-power  |
 * |     parking loop in preserved memory.                                   |
 * |   * System-wide global cpumask (cpu_preserved_mask) & physical state.   |
 * +-------------------------------------------------------------------------+
 *                                     │
 *                                     ▼ (Carves out session subsets)
 * +-------------------------------------------------------------------------+
 * | Per-Session Scope: Caretaker Session Manager (kernel/liveupdate/caretaker.c) |
 * |   * Tracks per-LUO session CPU pool (session->cpus).                    |
 * |   * Unified orphaned job runqueue: orphaned jobs queue in               |
 * |     session->rq.runnable.                                               |
 * |   * Timeshared scheduling: runs uninterrupted when 1:1 pinned, and      |
 * |     round-robin timeslices when M orphaned jobs > N preserved cores.    |
 * |   * Enforces multi-tenant isolation between distinct LUO sessions.      |
 * +-------------------------------------------------------------------------+
 *                    │                                     │
 *                    ▼                                     ▼
 * +------------------------------------+   +--------------------------------+
 * | Subsystem: KVM Caretaker           |   | Subsystem: Process Caretaker   |
 * | (virt/kvm/caretaker.c)             |   | (kernel/process_caretaker.c)   |
 * |   * Encapsulates vCPUs as          |   |   * Encapsulates bare user     |
 * |     orphaned jobs                  |   |     tasks/threads as orphaned  |
 * |   * VMX/SVM/ARM hyp execution      |   |     jobs (future expansion)    |
 * +------------------------------------+   +--------------------------------+
 *
 * The Caretaker layer sits directly above cpu_preserve and manages on-core
 * execution for orphaned jobs (orphaned VMs and orphaned userspace processes).
 *
 * Dispatching & Queuing Policy
 * ============================
 * - When an orphaned job is submitted (caretaker_session_submit_job), it is
 *   assigned to an available session physical core (or balanced across cores).
 * - When activated (caretaker_session_activate_job), the job is enqueued to
 *   the session runqueue (session->rq) and scheduled on-core.
 * - If only one job runs on a physical core, it executes uninterrupted without
 *   preemption timer exits. If multiple jobs share a core, Caretaker round-
 *   robins between them according to the configured quantum.
 * - When a physical core is added (caretaker_session_add_cpu), it joins the
 *   scheduler loop to drain runnable jobs from the session runqueue.
 * - This decouples preservation order: orphaned jobs and physical CPUs can
 *   be preserved in any order. Furthermore, overcommitted orphaned jobs remain
 *   cleanly preserved in memory without failing the live update session.
 */

#define pr_fmt(fmt) "caretaker: " fmt

#include <linux/caretaker.h>
#include <linux/cpu_preserve.h>
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/kexec.h>
#include <linux/kexec_handover.h>
#include <linux/liveupdate.h>
#include <linux/module.h>
#include <linux/reboot.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>

#define CARETAKER_CANCEL_TIMEOUT_US	20000000
#define CARETAKER_CANCEL_STEP_US	100

struct caretaker_sched_config global_sched_config __cpu_preserved_data;

static int __init parse_caretaker_quantum(char *arg)
{
	u32 val;

	if (kstrtou32(arg, 0, &val) == 0 && val >= 1 && val <= 1000)
		global_sched_config.quantum_ms = val;
	return 0;
}
early_param("caretaker.quantum_ms", parse_caretaker_quantum);

static u64 __cpu_preserved_text ticks_to_ns(u64 ticks)
{
	return arch_caretaker_ticks_to_ns(ticks);
}

static void caretaker_sched_update_ticks(void)
{
	arch_caretaker_update_quantum_ticks(&global_sched_config);
}

static inline void caretaker_rq_lock(struct caretaker_runqueue *rq)
{
	while (atomic_cmpxchg_acquire(&rq->lock, 0, 1) != 0) {
		while (atomic_read(&rq->lock) != 0)
			cpu_relax();
	}
}

static inline void caretaker_rq_unlock(struct caretaker_runqueue *rq)
{
	atomic_set_release(&rq->lock, 0);
}

static void caretaker_runqueue_init(struct caretaker_runqueue *rq)
{
	if (!rq)
		return;

	atomic_set(&rq->lock, 0);
	INIT_LIST_HEAD(&rq->runnable);
	rq->nr_runnable = 0;
	rq->nr_total = 0;
}

static int caretaker_sched_enqueue(struct caretaker_runqueue *rq,
				   struct caretaker_job *job)
{
	if (!rq || !job)
		return -EINVAL;

	caretaker_rq_lock(rq);
	job->state = CARETAKER_JOB_RUNNABLE;
	list_add_tail(&job->node, &rq->runnable);
	rq->nr_runnable++;
	rq->nr_total++;
	caretaker_rq_unlock(rq);

	if (job->preferred_cpu >= 0 && cpu_is_preserved(job->preferred_cpu))
		arch_cpu_preserved_kick(job->preferred_cpu);

	return 0;
}

static int caretaker_sched_dequeue(struct caretaker_runqueue *rq,
				   struct caretaker_job *job)
{
	if (!rq || !job)
		return -EINVAL;

	caretaker_rq_lock(rq);
	if (!list_empty(&job->node)) {
		list_del_init(&job->node);
		if (rq->nr_runnable > 0)
			rq->nr_runnable--;
	}
	if (rq->nr_total > 0)
		rq->nr_total--;
	if (job->state == CARETAKER_JOB_RUNNING)
		job->state = CARETAKER_JOB_CANCELING;
	else
		job->state = CARETAKER_JOB_DEAD;
	caretaker_rq_unlock(rq);
	return 0;
}

static struct caretaker_job * __cpu_preserved_text
caretaker_sched_pick_next(struct caretaker_runqueue *rq, int cpu)
{
	struct caretaker_job *job = NULL, *iter;

	if (!rq || READ_ONCE(rq->nr_runnable) == 0)
		return NULL;

	caretaker_rq_lock(rq);

	/* 1. Search for first eligible runnable job in FIFO order */
	list_for_each_entry(iter, &rq->runnable, node) {
		if (iter->preferred_cpu == cpu ||
		    iter->preferred_cpu < 0 ||
		    !cpu_is_preserved(iter->preferred_cpu)) {
			job = iter;
			break;
		}
	}

	/* 2. Fallback: only pick jobs whose preferred CPU is not preserved */
	if (!job && !list_empty(&rq->runnable)) {
		list_for_each_entry(iter, &rq->runnable, node) {
			if (iter->preferred_cpu < 0 ||
			    !cpu_is_preserved(iter->preferred_cpu)) {
				job = iter;
				break;
			}
		}
	}

	if (job) {
		list_del_init(&job->node);
		rq->nr_runnable--;
	}

	caretaker_rq_unlock(rq);
	return job;
}

static void __cpu_preserved_text
caretaker_sched_put_prev(struct caretaker_runqueue *rq,
			 struct caretaker_job *job)
{
	if (!job)
		return;

	caretaker_rq_lock(rq);
	job->state = CARETAKER_JOB_RUNNABLE;
	list_add_tail(&job->node, &rq->runnable);
	rq->nr_runnable++;
	caretaker_rq_unlock(rq);
}

static void __cpu_preserved_text
caretaker_cpu_schedule_loop(int cpu, struct caretaker_runqueue *rq,
			    struct caretaker_sched_config *cfg)
{
	struct caretaker_job *curr = NULL;
	u64 deadline, start_ticks, end_ticks;
	enum caretaker_exit_reason reason;

	if (!rq || !cfg)
		return;

	while (!cpu_preserved_should_exit(cpu)) {
		/* 1. Pick the next runnable job from the FIFO queue */
		if (!curr) {
			curr = caretaker_sched_pick_next(rq, cpu);
			if (!curr) {
				/* No runnable jobs; execute low-power park wait */
				arch_cpu_preserved_park_wait();
				continue;
			}
		}

		/* 2. Compute quantum deadline */
		start_ticks = arch_caretaker_read_counter();
		if (cfg->quantum_ticks)
			deadline = start_ticks + cfg->quantum_ticks;
		else
			deadline = 0;

		/* 3. Execute workload on physical silicon */
		curr->last_cpu = cpu;
		curr->state = CARETAKER_JOB_RUNNING;
		reason = curr->run_fn(curr->data, deadline);

		/* 4. Update telemetry and accounting */
		end_ticks = arch_caretaker_read_counter();
		curr->total_runs++;
		curr->total_runtime_ns += ticks_to_ns(end_ticks - start_ticks);
		if (reason == CARETAKER_EXIT_QUANTUM_EXPIRED)
			curr->preemptions++;

		/* Fast-path: single runnable job continues uninterrupted */
		if (READ_ONCE(rq->nr_runnable) == 0 &&
		    READ_ONCE(curr->state) == CARETAKER_JOB_RUNNING &&
		    reason != CARETAKER_EXIT_ATTACH_SIGNALED &&
		    reason != CARETAKER_EXIT_ERROR &&
		    !cpu_preserved_should_exit(cpu))
			continue;

		/* 5. Handle exit and return job to queue */
		caretaker_rq_lock(rq);
		if (curr->state == CARETAKER_JOB_CANCELING ||
		    curr->state == CARETAKER_JOB_DEAD ||
		    reason == CARETAKER_EXIT_ATTACH_SIGNALED ||
		    reason == CARETAKER_EXIT_ERROR) {
			if (curr->state != CARETAKER_JOB_CANCELING &&
			    curr->state != CARETAKER_JOB_DEAD &&
			    rq->nr_total > 0)
				rq->nr_total--;
			WRITE_ONCE(curr->state, CARETAKER_JOB_DEAD);
			caretaker_rq_unlock(rq);
			curr = NULL;
			continue;
		}
		caretaker_rq_unlock(rq);

		caretaker_sched_put_prev(rq, curr);
		curr = NULL;
	}
}

static void __caretaker_text caretaker_sched_cpu_worker(void *data)
{
	struct caretaker_cpu_worker_arg *arg = data;
	struct cpu_preserved_stack_context *sctx = caretaker_get_current_context();
	int cpu = sctx ? sctx->cpu : arg->cpu;
	struct caretaker_session *sess = (sctx && sctx->session) ? sctx->session : arg->sess;

	if (sctx && sctx->session_pgd_pa)
		arch_cpu_preserved_switch_pgd(sctx->session_pgd_pa);

	caretaker_cpu_schedule_loop(cpu, &sess->rq, &sess->sched_config);
}

static DEFINE_MUTEX(caretaker_sessions_lock);
static LIST_HEAD(caretaker_sessions);

void caretaker_map_range_all_sessions(phys_addr_t pa, unsigned long va,
				      size_t size, pgprot_t prot)
{
	struct caretaker_session *sess;

	guard(mutex)(&caretaker_sessions_lock);
	list_for_each_entry(sess, &caretaker_sessions, node)
		arch_caretaker_map_session_range(sess, pa, va, size, prot);
}
EXPORT_SYMBOL_GPL(caretaker_map_range_all_sessions);

int caretaker_session_map_range(struct caretaker_session *sess, phys_addr_t pa,
				unsigned long va, size_t size, pgprot_t prot)
{
	if (sess && sess->pgd)
		return arch_caretaker_map_session_range(sess, pa, va, size, prot);
	return cpu_preserved_map_range(pa, va, size, prot);
}
EXPORT_SYMBOL_GPL(caretaker_session_map_range);

int caretaker_session_map_buffer(struct caretaker_session *sess, void *va,
				 size_t size)
{
	if (!va || !size)
		return 0;
	return caretaker_session_map_range(sess, virt_to_phys(va),
					   (unsigned long)va, size, PAGE_KERNEL);
}
EXPORT_SYMBOL_GPL(caretaker_session_map_buffer);

static struct caretaker_session *caretaker_get_or_create_session(struct liveupdate_session *s)
{
	const char *sname = liveupdate_session_name(s);
	struct caretaker_session *sess;

	if (!sname || !sname[0])
		sname = "none";

	scoped_guard(mutex, &caretaker_sessions_lock) {
		list_for_each_entry(sess, &caretaker_sessions, node) {
			if (strcmp(sess->name, sname) == 0)
				return sess;
		}
	}

	sess = kho_alloc_preserve(sizeof(*sess));
	if (IS_ERR_OR_NULL(sess))
		sess = kzalloc(sizeof(*sess), GFP_KERNEL);
	if (!sess)
		return NULL;

	memset(sess, 0, sizeof(*sess));
	strscpy(sess->name, sname, sizeof(sess->name));
	mutex_init(&sess->lock);
	caretaker_runqueue_init(&sess->rq);
	caretaker_sched_update_ticks();
	sess->sched_config = global_sched_config;

	cpu_preserved_init_runtime_buffer();
	arch_caretaker_alloc_session_pgd(sess);
	arch_caretaker_map_session_range(sess, virt_to_phys(sess),
					 (unsigned long)sess, sizeof(*sess),
					 PAGE_KERNEL);

	sess->ser = kho_alloc_preserve(sizeof(*sess->ser));
	if (!IS_ERR_OR_NULL(sess->ser)) {
		memset(sess->ser, 0, sizeof(*sess->ser));
		sess->ser->magic = CARETAKER_SESSION_SER_MAGIC;
		strscpy(sess->ser->session_name, sname, sizeof(sess->ser->session_name));
		sess->ser->sess_pa = virt_to_phys(sess);
		sess->ser->pgd_pa = sess->pgd_pa;
		sess->ser->runqueue_pa = virt_to_phys(&sess->rq);
	}

	scoped_guard(mutex, &caretaker_sessions_lock) {
		struct caretaker_session *existing;

		list_for_each_entry(existing, &caretaker_sessions, node) {
			if (strcmp(existing->name, sname) == 0) {
				if (sess->ser)
					kho_unpreserve_free(sess->ser);
				arch_caretaker_free_session_pgd(sess);
				kho_unpreserve_free(sess);
				return existing;
			}
		}
		list_add_tail(&sess->node, &caretaker_sessions);
	}

	return sess;
}

static struct caretaker_session *caretaker_find_session(struct liveupdate_session *s)
{
	const char *sname = liveupdate_session_name(s);
	struct caretaker_session *sess;

	if (!sname || !sname[0])
		sname = "none";

	guard(mutex)(&caretaker_sessions_lock);

	list_for_each_entry(sess, &caretaker_sessions, node) {
		if (strcmp(sess->name, sname) == 0)
			return sess;
	}

	return NULL;
}

struct caretaker_session *caretaker_get_session(struct liveupdate_session *s)
{
	return caretaker_find_session(s);
}
EXPORT_SYMBOL_GPL(caretaker_get_session);

/**
 * caretaker_session_add_cpu - Add a preserved physical CPU to a session pool
 * @s:   Owning LUO session
 * @cpu: Physical CPU ID
 *
 * If orphaned jobs are waiting in the session queue, the next job is popped and
 * assigned to @cpu.
 *
 * Return: 0 on success, negative error code on failure.
 */
int caretaker_session_add_cpu(struct liveupdate_session *s, int cpu)
{
	struct caretaker_session *sess = caretaker_get_or_create_session(s);
	int ret = 0;

	if (!sess || cpu < 0 || cpu >= nr_cpu_ids)
		return -EINVAL;

	guard(mutex)(&sess->lock);
	cpumask_set_cpu(cpu, &sess->cpus);

	sess->cpu_args[cpu].sess = sess;
	sess->cpu_args[cpu].cpu = cpu;

	if (sess->ser) {
		cpumask_set_cpu(cpu, &sess->ser->cpus);
		sess->ser->nr_cpus = cpumask_weight(&sess->cpus);
		sess->ser->pgd_pa = sess->pgd_pa;
	}

	cpu_preserved_set_session(cpu, sess);

	ret = cpu_preserved_attach_workload(cpu, "sched",
					    caretaker_sched_cpu_worker,
					    &sess->cpu_args[cpu]);
	if (ret) {
		cpu_preserved_set_session(cpu, NULL);
		cpumask_clear_cpu(cpu, &sess->cpus);
		if (sess->ser) {
			cpumask_clear_cpu(cpu, &sess->ser->cpus);
			sess->ser->nr_cpus = cpumask_weight(&sess->cpus);
		}
		return ret;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(caretaker_session_add_cpu);

/**
 * caretaker_session_remove_cpu - Remove a preserved CPU from a session pool
 * @s:   Owning LUO session
 * @cpu: Physical CPU ID
 *
 * Return: 0 on success, negative error code on failure.
 */
int caretaker_session_remove_cpu(struct liveupdate_session *s, int cpu)
{
	struct caretaker_session *sess = caretaker_find_session(s);

	if (!sess || cpu < 0 || cpu >= nr_cpu_ids)
		return -EINVAL;

	scoped_guard(mutex, &sess->lock) {
		cpumask_clear_cpu(cpu, &sess->cpus);
		if (sess->ser) {
			cpumask_clear_cpu(cpu, &sess->ser->cpus);
			sess->ser->nr_cpus = cpumask_weight(&sess->cpus);
		}
	}

	cpu_preserved_detach_workload(cpu);
	cpu_preserved_set_session(cpu, NULL);

	if (cpumask_empty(&sess->cpus)) {
		scoped_guard(mutex, &caretaker_sessions_lock) {
			list_del_init(&sess->node);
		}
		arch_caretaker_free_session_pgd(sess);
		if (sess->ser) {
			if (sess->is_incoming)
				kho_restore_free(sess->ser);
			else
				kho_unpreserve_free(sess->ser);
			sess->ser = NULL;
		}
		if (sess->is_incoming)
			kho_restore_free(sess);
		else
			kho_unpreserve_free(sess);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(caretaker_session_remove_cpu);

phys_addr_t caretaker_session_get_ser_pa(struct liveupdate_session *s)
{
	struct caretaker_session *sess = caretaker_find_session(s);

	if (!sess || !sess->ser)
		return 0;

	sess->ser->pgd_pa = sess->pgd_pa;
	sess->ser->nr_cpus = cpumask_weight(&sess->cpus);
	sess->ser->runqueue_pa = virt_to_phys(&sess->rq);
	return virt_to_phys(sess->ser);
}
EXPORT_SYMBOL_GPL(caretaker_session_get_ser_pa);

int caretaker_session_restore(struct liveupdate_session *s,
			      struct caretaker_session_ser *ser)
{
	struct caretaker_session *sess;
	const char *sname;

	if (!ser || ser->magic != CARETAKER_SESSION_SER_MAGIC)
		return -EINVAL;

	sname = liveupdate_session_name(s);
	if (!sname || !sname[0])
		sname = ser->session_name;

	scoped_guard(mutex, &caretaker_sessions_lock) {
		list_for_each_entry(sess, &caretaker_sessions, node) {
			if (strcmp(sess->name, sname) == 0)
				return 0;
		}
	}

	if (!ser->sess_pa)
		return -EINVAL;

	sess = phys_to_virt(ser->sess_pa);
	sess->ser = ser;
	sess->is_incoming = true;
	mutex_init(&sess->lock);

	scoped_guard(mutex, &caretaker_sessions_lock) {
		list_add_tail(&sess->node, &caretaker_sessions);
	}
	return 0;
}
EXPORT_SYMBOL_GPL(caretaker_session_restore);

/**
 * caretaker_session_submit_job - Submit an orphaned job to a session
 * @s:             Owning LUO session
 * @name:          Job identifier string
 * @preferred_cpu: Preferred physical CPU, or -1
 * @run_fn:        Job execution callback function
 * @data:          Workload context pointer
 *
 * Allocates and initializes a preserved job descriptor in KHO memory and
 * assigns it to an available session physical core (or balances across cores).
 *
 * Return: Pointer to allocated struct caretaker_job on success, ERR_PTR.
 */
struct caretaker_job *
caretaker_session_submit_job(struct liveupdate_session *s,
			     const char *name, int preferred_cpu,
			     caretaker_job_fn run_fn,
			     void *data)
{
	struct caretaker_session *sess = caretaker_get_or_create_session(s);
	struct caretaker_job *job;

	if (!sess || !run_fn)
		return ERR_PTR(-EINVAL);

	guard(mutex)(&sess->lock);

	job = kho_alloc_preserve(sizeof(*job));
	if (IS_ERR_OR_NULL(job))
		job = kzalloc(sizeof(*job), GFP_KERNEL);
	if (!job)
		return ERR_PTR(-ENOMEM);

	memset(job, 0, sizeof(*job));
	if (sess && sess->pgd) {
		arch_caretaker_map_session_range(sess, virt_to_phys(job),
						 (unsigned long)job, sizeof(*job),
						 PAGE_KERNEL);
	} else {
		cpu_preserved_map_buffer(job, sizeof(*job));
		if (data)
			cpu_preserved_map_buffer(data, PAGE_SIZE);
	}
	INIT_LIST_HEAD(&job->node);
	job->session = sess;
	if (name)
		strscpy(job->name, name, sizeof(job->name));
	job->state = CARETAKER_JOB_NEW;
	job->run_fn = run_fn;
	job->data = data;
	job->last_cpu = -1;

	if (preferred_cpu >= 0 && cpumask_test_cpu(preferred_cpu, &sess->cpus)) {
		job->preferred_cpu = preferred_cpu;
		job->assigned_cpu = preferred_cpu;
		sess->cpu_jobs[preferred_cpu]++;
	} else if (!cpumask_empty(&sess->cpus)) {
		int cpu, assigned = -1;
		int min_count = INT_MAX;

		for_each_cpu(cpu, &sess->cpus) {
			if (sess->cpu_jobs[cpu] < min_count) {
				min_count = sess->cpu_jobs[cpu];
				assigned = cpu;
			}
		}
		job->preferred_cpu = assigned;
		job->assigned_cpu = assigned;
		if (assigned >= 0)
			sess->cpu_jobs[assigned]++;
	} else {
		job->preferred_cpu = -1;
		job->assigned_cpu = -1;
	}

	return job;
}
EXPORT_SYMBOL_GPL(caretaker_session_submit_job);

/**
 * caretaker_session_activate_job - Activate on-core execution for an assigned job
 * @s:   Owning LUO session
 * @job: Previously submitted caretaker job
 *
 * Return: 0 on success, negative error code on failure.
 */
int caretaker_session_activate_job(struct liveupdate_session *s,
				   struct caretaker_job *job)
{
	struct caretaker_session *sess = caretaker_find_session(s);

	if (!sess || !job)
		return -EINVAL;

	guard(mutex)(&sess->lock);
	if (job->data) {
		if (sess && sess->pgd)
			arch_caretaker_map_session_range(sess, virt_to_phys(job->data),
							 (unsigned long)job->data,
							 PAGE_SIZE, PAGE_KERNEL);
		else
			cpu_preserved_map_buffer(job->data, PAGE_SIZE);
	}
	if (job->assigned_cpu >= 0) {
		caretaker_sched_enqueue(&sess->rq, job);
		if (cpu_is_preserved(job->assigned_cpu))
			arch_cpu_preserved_kick(job->assigned_cpu);
	}
	return 0;
}
EXPORT_SYMBOL_GPL(caretaker_session_activate_job);

/**
 * caretaker_session_cancel_job - Cancel an orphaned job from a session
 * @s:   Owning LUO session
 * @job: Previously submitted caretaker job
 *
 * Return: 0 on success, negative error code on failure.
 */
int caretaker_session_cancel_job(struct liveupdate_session *s,
				 struct caretaker_job *job)
{
	struct caretaker_session *sess = caretaker_find_session(s);

	if (!sess || !job)
		return -EINVAL;

	guard(mutex)(&sess->lock);
	if (job->assigned_cpu >= 0) {
		if (sess->cpu_jobs[job->assigned_cpu] > 0)
			sess->cpu_jobs[job->assigned_cpu]--;
		job->assigned_cpu = -1;
	}
	caretaker_sched_dequeue(&sess->rq, job);

	if (READ_ONCE(job->state) == CARETAKER_JOB_CANCELING) {
		int cpu = READ_ONCE(job->last_cpu);
		int retries = 0;

		while (READ_ONCE(job->state) == CARETAKER_JOB_CANCELING &&
		       retries < (CARETAKER_CANCEL_TIMEOUT_US / CARETAKER_CANCEL_STEP_US)) {
			if ((retries % 50) == 0 && cpu >= 0)
				arch_cpu_preserved_kick(cpu);
			udelay(CARETAKER_CANCEL_STEP_US);
			retries++;
		}
	}

	kho_unpreserve_free(job);
	return 0;
}
EXPORT_SYMBOL_GPL(caretaker_session_cancel_job);

static struct dentry *caretaker_sched_debugfs_dir;

static int caretaker_sched_quantum_get(void *data, u64 *val)
{
	*val = global_sched_config.quantum_ms;
	return 0;
}

static int caretaker_sched_quantum_set(void *data, u64 val)
{
	if (val < 1 || val > 1000)
		return -EINVAL;
	global_sched_config.quantum_ms = (u32)val;
	caretaker_sched_update_ticks();
	return 0;
}

DEFINE_DEBUGFS_ATTRIBUTE(fops_quantum, caretaker_sched_quantum_get,
			 caretaker_sched_quantum_set, "%llu\n");

static int __init caretaker_sched_debugfs_init(void)
{
	if (!IS_ENABLED(CONFIG_DEBUG_FS))
		return 0;

	caretaker_sched_debugfs_dir =
		debugfs_create_dir("caretaker_sched", NULL);
	if (!caretaker_sched_debugfs_dir)
		return -ENOMEM;

	debugfs_create_file("quantum_ms", 0644, caretaker_sched_debugfs_dir,
			    NULL, &fops_quantum);
	return 0;
}
late_initcall(caretaker_sched_debugfs_init);

static int __init caretaker_sched_init(void)
{
	if (!global_sched_config.quantum_ms)
		global_sched_config.quantum_ms = 10;
	caretaker_sched_update_ticks();
	pr_info("Round-Robin scheduler initialized (quantum=%u ms, ticks=%llu)\n",
		global_sched_config.quantum_ms,
		global_sched_config.quantum_ticks);
	return 0;
}
early_initcall(caretaker_sched_init);

u64 __weak __cpu_preserved_text arch_caretaker_ticks_to_ns(u64 ticks)
{
	return ticks;
}

void __weak arch_caretaker_update_quantum_ticks(struct caretaker_sched_config *cfg)
{
	cfg->quantum_ticks = (u64)cfg->quantum_ms * 1000000ULL;
}
