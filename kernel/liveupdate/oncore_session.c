// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * On-Core Session Management Framework for Live Update
 */

#define pr_fmt(fmt) "oncore_session: " fmt

#include <linux/cpu_preserve.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kexec_handover.h>
#include <linux/liveupdate.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/oncore.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "oncore_internal.h"

static DEFINE_MUTEX(oncore_sessions_lock);
static LIST_HEAD(oncore_sessions);

int oncore_session_map_range(struct oncore_session *sess, phys_addr_t pa,
			     unsigned long va, size_t size, pgprot_t prot)
{
	if (sess && sess->as)
		return cpu_preserved_as_map(sess->as, pa, va, size, prot);
	return cpu_preserved_map_range(pa, va, size, prot);
}
EXPORT_SYMBOL_GPL(oncore_session_map_range);

int oncore_session_map_buffer(struct oncore_session *sess, void *va,
			      size_t size)
{
	if (!va || !size)
		return 0;
	return oncore_session_map_range(sess, virt_to_phys(va),
					(unsigned long)va, size, PAGE_KERNEL);
}
EXPORT_SYMBOL_GPL(oncore_session_map_buffer);

phys_addr_t oncore_session_get_pgd_pa(struct oncore_session *sess)
{
	return (sess && sess->as) ? sess->as->pgd_pa : 0;
}
EXPORT_SYMBOL_GPL(oncore_session_get_pgd_pa);

static void oncore_session_sync_ser_cpus(struct oncore_session *sess)
{
	unsigned int i;

	if (!sess->ser)
		return;

	for (i = 0; i < sess->ser->nr_cpu_words; i++)
		sess->ser->cpus_bitmap[i] = 0;
	for (i = 0; i < sess->nr_cpu_words; i++) {
		unsigned int ser_word = (i * BITS_PER_LONG) / 64;
		unsigned int shift = (i * BITS_PER_LONG) % 64;

		if (ser_word < sess->ser->nr_cpu_words)
			sess->ser->cpus_bitmap[ser_word] |=
				(u64)sess->cpus_bitmap[i] << shift;
	}
	sess->ser->nr_cpus = cpumask_weight(to_cpumask(sess->cpus_bitmap));
	sess->ser->pgd_pa = oncore_session_get_pgd_pa(sess);
}

static struct oncore_session *oncore_get_or_create_session(struct liveupdate_session *s)
{
	const char *sname = liveupdate_session_name(s);
	struct oncore_session *sess;

	scoped_guard(mutex, &oncore_sessions_lock) {
		list_for_each_entry(sess, &oncore_sessions, node) {
			if (strcmp(sess->name, sname) == 0)
				return sess;
		}
	}

	unsigned int nr_cpu_words = BITS_TO_LONGS(nr_cpu_ids);
	size_t sess_sz = struct_size(sess, cpus_bitmap, nr_cpu_words);

	sess = kho_alloc_preserve(sess_sz);
	if (IS_ERR(sess))
		return NULL;

	memset(sess, 0, sess_sz);
	sess->nr_cpu_words = nr_cpu_words;
	strscpy(sess->name, sname, sizeof(sess->name));
	mutex_init(&sess->lock);
	INIT_LIST_HEAD(&sess->jobs);
	oncore_runqueue_init(&sess->rq);
	oncore_sched_update_ticks();
	sess->sched_config = global_oncore_sched_config;

	cpu_preserved_init_runtime_buffer();
	sess->as = cpu_preserved_as_create();
	if (IS_ERR(sess->as))
		sess->as = NULL;
	else
		sess->as_pa = virt_to_phys(sess->as);
	oncore_session_map_range(sess, virt_to_phys(sess),
				 (unsigned long)sess, sess_sz,
				 PAGE_KERNEL);

	{
		unsigned int nr_words = BITS_TO_U64(nr_cpu_ids);
		size_t ser_sz = struct_size(sess->ser, cpus_bitmap, nr_words);

		sess->ser = kho_alloc_preserve(ser_sz);
		if (IS_ERR(sess->ser)) {
			cpu_preserved_as_destroy(sess->as);
			kho_unpreserve_free(sess);
			return NULL;
		}

		memset(sess->ser, 0, ser_sz);
		sess->ser->nr_cpu_words = nr_words;
		strscpy(sess->ser->session_name, sname, sizeof(sess->ser->session_name));
		sess->ser->sess_pa = virt_to_phys(sess);
		sess->ser->pgd_pa = oncore_session_get_pgd_pa(sess);
		sess->ser->runqueue_pa = virt_to_phys(&sess->rq);
	}

	scoped_guard(mutex, &oncore_sessions_lock) {
		struct oncore_session *existing;

		list_for_each_entry(existing, &oncore_sessions, node) {
			if (strcmp(existing->name, sname) == 0) {
				if (sess->ser)
					kho_unpreserve_free(sess->ser);
				cpu_preserved_as_destroy(sess->as);
				kho_unpreserve_free(sess);
				return existing;
			}
		}
		list_add_tail(&sess->node, &oncore_sessions);
	}

	return sess;
}

static struct oncore_session *oncore_find_session(struct liveupdate_session *s)
{
	const char *sname = liveupdate_session_name(s);
	struct oncore_session *sess;

	guard(mutex)(&oncore_sessions_lock);

	list_for_each_entry(sess, &oncore_sessions, node) {
		if (strcmp(sess->name, sname) == 0)
			return sess;
	}

	return NULL;
}

static int oncore_session_add_cpu(struct liveupdate_session *s, int cpu)
{
	struct oncore_session *sess = oncore_get_or_create_session(s);
	phys_addr_t pa;
	unsigned long va;
	size_t sz;
	int ret = 0;

	if (!sess || cpu < 0 || cpu >= nr_cpu_ids)
		return -EINVAL;

	guard(mutex)(&sess->lock);
	cpumask_set_cpu(cpu, to_cpumask(sess->cpus_bitmap));
	oncore_session_sync_ser_cpus(sess);

	if (!cpu_preserved_get_pcpus_info(&pa, &va, &sz))
		oncore_session_map_range(sess, pa, va, sz, PAGE_KERNEL);

	if (!cpu_preserved_get_stack_info(cpu, &pa, &va, &sz))
		oncore_session_map_range(sess, pa, va, sz, PAGE_KERNEL);

	cpu_preserved_set_workload_context(cpu, sess,
					   oncore_session_get_pgd_pa(sess));

	ret = cpu_preserved_attach_workload(cpu, "sched",
					    oncore_sched_cpu_worker,
					    sess);
	if (ret) {
		cpu_preserved_set_workload_context(cpu, NULL, 0);
		cpumask_clear_cpu(cpu, to_cpumask(sess->cpus_bitmap));
		oncore_session_sync_ser_cpus(sess);
		return ret;
	}

	return 0;
}

static void oncore_session_remove_cpu(struct liveupdate_session *s, int cpu)
{
	struct oncore_session *sess = oncore_find_session(s);

	if (!sess || cpu < 0 || cpu >= nr_cpu_ids)
		return;

	scoped_guard(mutex, &sess->lock) {
		cpumask_clear_cpu(cpu, to_cpumask(sess->cpus_bitmap));
		oncore_session_sync_ser_cpus(sess);
	}

	cpu_preserved_detach_workload(cpu);
	cpu_preserved_set_workload_context(cpu, NULL, 0);

	if (cpumask_empty(to_cpumask(sess->cpus_bitmap))) {
		scoped_guard(mutex, &oncore_sessions_lock) {
			list_del_init(&sess->node);
		}
		cpu_preserved_as_destroy(sess->as);
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
}

static phys_addr_t oncore_session_get_ser_pa(struct liveupdate_session *s)
{
	struct oncore_session *sess = oncore_find_session(s);

	if (!sess || !sess->ser)
		return 0;

	oncore_session_sync_ser_cpus(sess);
	sess->ser->runqueue_pa = virt_to_phys(&sess->rq);
	return virt_to_phys(sess->ser);
}

static void oncore_session_restore(struct liveupdate_session *s,
				   phys_addr_t client_ser_pa)
{
	struct oncore_session_ser *ser;
	struct oncore_session *sess;
	const char *sname;

	if (!client_ser_pa)
		return;

	ser = phys_to_virt(client_ser_pa);
	if (!ser->sess_pa)
		return;

	sname = liveupdate_session_name(s);
	if (!sname || !sname[0])
		sname = ser->session_name;

	scoped_guard(mutex, &oncore_sessions_lock) {
		list_for_each_entry(sess, &oncore_sessions, node) {
			if (strcmp(sess->name, sname) == 0)
				return;
		}
	}

	sess = phys_to_virt(ser->sess_pa);
	sess->ser = ser;
	sess->as = sess->as_pa ? phys_to_virt(sess->as_pa) : NULL;
	sess->is_incoming = true;
	mutex_init(&sess->lock);

	cpu_preserved_as_adopt(sess->as);

	scoped_guard(mutex, &oncore_sessions_lock) {
		list_add_tail(&sess->node, &oncore_sessions);
	}
}

/*
 * On-core is the only in-tree consumer of preserved physical CPUs today.  It
 * plugs in here rather than being called by name from cpu_preserve.c, so that
 * CPU preservation carries no knowledge of what runs on a preserved core.
 */
static const struct cpu_preserved_client oncore_cpu_preserved_client = {
	.attach		= oncore_session_add_cpu,
	.detach		= oncore_session_remove_cpu,
	.serialize	= oncore_session_get_ser_pa,
	.restore	= oncore_session_restore,
};

static int __init oncore_register_cpu_preserved_client(void)
{
	return cpu_preserved_register_client(&oncore_cpu_preserved_client);
}
early_initcall(oncore_register_cpu_preserved_client);

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

struct oncore_job *
oncore_session_submit_job(struct liveupdate_session *s,
			  const char *name, int preferred_cpu,
			  oncore_job_fn run_fn,
			  void *data)
{
	struct oncore_session *sess = oncore_get_or_create_session(s);
	struct oncore_job *job;
	struct cpumask *cpus;

	if (!sess || !run_fn)
		return ERR_PTR(-EINVAL);

	guard(mutex)(&sess->lock);

	job = kho_alloc_preserve(sizeof(*job));
	if (IS_ERR(job))
		return ERR_CAST(job);

	memset(job, 0, sizeof(*job));
	oncore_session_map_buffer(sess, job, sizeof(*job));
	if (!sess->as && data)
		cpu_preserved_map_buffer(data, PAGE_SIZE);
	INIT_LIST_HEAD(&job->node);
	INIT_LIST_HEAD(&job->sess_node);
	job->session = sess;
	if (name)
		strscpy(job->name, name, sizeof(job->name));
	job->state = ONCORE_JOB_NEW;
	job->run_fn = run_fn;
	job->data = data;
	job->last_cpu = -1;

	cpus = to_cpumask(sess->cpus_bitmap);
	if (preferred_cpu >= 0 && cpumask_test_cpu(preferred_cpu, cpus) &&
	    oncore_session_cpu_job_count(sess, preferred_cpu) == 0) {
		job->preferred_cpu = preferred_cpu;
		job->assigned_cpu = preferred_cpu;
	} else if (!cpumask_empty(cpus)) {
		int cpu, assigned = -1;
		unsigned int min_count = UINT_MAX;

		for_each_cpu(cpu, cpus) {
			unsigned int count = oncore_session_cpu_job_count(sess, cpu);

			if (count < min_count) {
				min_count = count;
				assigned = cpu;
			}
		}
		if (min_count > 0 && preferred_cpu >= 0 &&
		    cpumask_test_cpu(preferred_cpu, cpus)) {
			job->preferred_cpu = preferred_cpu;
			job->assigned_cpu = preferred_cpu;
		} else {
			job->preferred_cpu = assigned;
			job->assigned_cpu = assigned;
		}
	} else {
		job->preferred_cpu = -1;
		job->assigned_cpu = -1;
	}

	list_add_tail(&job->sess_node, &sess->jobs);

	return job;
}
EXPORT_SYMBOL_GPL(oncore_session_submit_job);

int oncore_session_activate_job(struct liveupdate_session *s,
				struct oncore_job *job)
{
	struct oncore_session *sess = oncore_find_session(s);

	if (!sess || !job)
		return -EINVAL;

	guard(mutex)(&sess->lock);
	if (job->data)
		oncore_session_map_buffer(sess, job->data, PAGE_SIZE);
	if (job->assigned_cpu >= 0) {
		oncore_sched_enqueue(&sess->rq, job);
		if (cpu_is_preserved(job->assigned_cpu))
			arch_cpu_preserved_kick(job->assigned_cpu);
	}
	return 0;
}
EXPORT_SYMBOL_GPL(oncore_session_activate_job);

/**
 * oncore_job_set_data - Set the opaque argument passed to a job's run callback
 * @job: Job to update.
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
EXPORT_SYMBOL_GPL(oncore_job_set_data);

int oncore_session_cancel_job(struct liveupdate_session *s,
			      struct oncore_job *job)
{
	struct oncore_session *sess = oncore_find_session(s);

	if (!sess || !job)
		return -EINVAL;

	guard(mutex)(&sess->lock);
	list_del_init(&job->sess_node);
	if (job->assigned_cpu >= 0)
		job->assigned_cpu = -1;
	oncore_sched_dequeue(&sess->rq, job);

	if (READ_ONCE(job->state) == ONCORE_JOB_CANCELING) {
		int cpu = READ_ONCE(job->last_cpu);
		int retries = 0;

		while (READ_ONCE(job->state) == ONCORE_JOB_CANCELING &&
		       retries < (ONCORE_CANCEL_TIMEOUT_US / ONCORE_CANCEL_STEP_US)) {
			if ((retries % 50) == 0 && cpu >= 0)
				arch_cpu_preserved_kick(cpu);
			udelay(ONCORE_CANCEL_STEP_US);
			retries++;
		}
	}

	kho_unpreserve_free(job);
	return 0;
}
EXPORT_SYMBOL_GPL(oncore_session_cancel_job);
