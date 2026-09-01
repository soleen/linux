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
#include <linux/kexec_handover.h>
#include <linux/liveupdate.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/oncore.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <asm/io.h>
#include <asm/trans_pgd.h>

#include "oncore_internal.h"

static DEFINE_MUTEX(oncore_map_lock);

static void *oncore_alloc_page(void *arg)
{
	struct oncore_session *sess = arg;
	void *ptr = kho_alloc_preserve(PAGE_SIZE);
	struct page *page;

	if (IS_ERR_OR_NULL(ptr)) {
		page = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!page)
			return NULL;
		ptr = page_address(page);
		kho_preserve_pages(page, 1);
	} else {
		memset(ptr, 0, PAGE_SIZE);
	}

	arch_cpu_preserved_dcache_clean((unsigned long)ptr,
					(unsigned long)ptr + PAGE_SIZE);

	if (sess->nr_pgd_pages < ARRAY_SIZE(sess->pgd_pages))
		sess->pgd_pages[sess->nr_pgd_pages++] = virt_to_phys(ptr);
	else
		WARN_ON_ONCE(1);

	return ptr;
}

int oncore_alloc_session_pgd(struct oncore_session *sess)
{
	struct trans_pgd_info info = {
		.trans_alloc_page = oncore_alloc_page,
		.trans_alloc_arg = sess,
	};
	unsigned long text_start = (unsigned long)__cpu_preserved_text_start;
	unsigned long data_start = (unsigned long)__cpu_preserved_data_start;
	size_t text_sz = (unsigned long)__cpu_preserved_text_end - text_start;
	size_t data_sz = (unsigned long)__cpu_preserved_data_end - data_start;
	phys_addr_t text_pa, data_pa;
	int ret;

	if (!sess)
		return -EINVAL;
	if (sess->pgd)
		return 0;

	text_pa = cpu_preserved_get_text_pa();
	data_pa = cpu_preserved_get_data_pa();
	if (!text_pa || !data_pa)
		return -EAGAIN;

	guard(mutex)(&oncore_map_lock);

	sess->pgd = oncore_alloc_page(sess);
	if (!sess->pgd)
		return -ENOMEM;

	/* Map On-Core Text & Rodata (ROX) */
	ret = trans_pgd_map_range(&info, sess->pgd, text_pa,
				  text_start, text_sz, PAGE_KERNEL_ROX);
	if (ret)
		return ret;

	/* Map On-Core Writable Data (RW) */
	ret = trans_pgd_map_range(&info, sess->pgd, data_pa,
				  data_start, data_sz, PAGE_KERNEL);
	if (ret)
		return ret;

	sess->pgd_pa = virt_to_phys(sess->pgd);
	arch_oncore_flush_tlb(sess);

	return 0;
}

void oncore_free_session_pgd(struct oncore_session *sess)
{
	int i;

	if (!sess || !sess->pgd)
		return;

	guard(mutex)(&oncore_map_lock);

	for (i = 0; i < sess->nr_pgd_pages; i++) {
		void *va = phys_to_virt(sess->pgd_pages[i]);

		if (sess->is_incoming)
			kho_restore_free(va);
		else
			kho_unpreserve_free(va);
	}

	sess->nr_pgd_pages = 0;
	sess->pgd = NULL;
	sess->pgd_pa = 0;
}

int oncore_map_session_range(struct oncore_session *sess,
			     phys_addr_t pa, unsigned long va,
			     size_t size, pgprot_t prot)
{
	struct trans_pgd_info info = {
		.trans_alloc_page = oncore_alloc_page,
		.trans_alloc_arg = sess,
	};
	unsigned long page_va = va & PAGE_MASK;
	unsigned long offset = va & ~PAGE_MASK;
	phys_addr_t page_pa = (pa & PAGE_MASK);
	size_t page_size = PAGE_ALIGN(offset + size);
	int ret;

	if (!sess || !sess->pgd || !size)
		return 0;

	guard(mutex)(&oncore_map_lock);

	ret = trans_pgd_map_range(&info, sess->pgd, page_pa,
				  page_va, page_size, prot);
	if (ret)
		return ret;

	arch_oncore_flush_tlb(sess);
	return 0;
}

static DEFINE_MUTEX(oncore_sessions_lock);
static LIST_HEAD(oncore_sessions);

void oncore_map_range_all_sessions(phys_addr_t pa, unsigned long va,
				   size_t size, pgprot_t prot)
{
	struct oncore_session *sess;

	guard(mutex)(&oncore_sessions_lock);
	list_for_each_entry(sess, &oncore_sessions, node)
		oncore_map_session_range(sess, pa, va, size, prot);
}

int oncore_session_map_range(struct oncore_session *sess, phys_addr_t pa,
			     unsigned long va, size_t size, pgprot_t prot)
{
	if (sess && sess->pgd)
		return oncore_map_session_range(sess, pa, va, size, prot);
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

	sess = kho_alloc_preserve(sizeof(*sess));
	if (IS_ERR(sess))
		sess = kzalloc(sizeof(*sess), GFP_KERNEL);
	if (!sess)
		return NULL;

	memset(sess, 0, sizeof(*sess));
	strscpy(sess->name, sname, sizeof(sess->name));
	mutex_init(&sess->lock);
	oncore_runqueue_init(&sess->rq);
	oncore_sched_update_ticks();
	sess->sched_config = global_oncore_sched_config;

	cpu_preserved_init_runtime_buffer();
	oncore_alloc_session_pgd(sess);
	oncore_map_session_range(sess, virt_to_phys(sess),
				 (unsigned long)sess, sizeof(*sess),
				 PAGE_KERNEL);

	{
		unsigned int nr_words = BITS_TO_U64(nr_cpu_ids);
		size_t ser_sz = struct_size(sess->ser, cpus_bitmap, nr_words);

		sess->ser = kho_alloc_preserve(ser_sz);
		if (!IS_ERR(sess->ser)) {
			memset(sess->ser, 0, ser_sz);
			sess->ser->nr_cpu_words = nr_words;
			strscpy(sess->ser->session_name, sname, sizeof(sess->ser->session_name));
			sess->ser->sess_pa = virt_to_phys(sess);
			sess->ser->pgd_pa = sess->pgd_pa;
			sess->ser->runqueue_pa = virt_to_phys(&sess->rq);
		}
	}

	scoped_guard(mutex, &oncore_sessions_lock) {
		struct oncore_session *existing;

		list_for_each_entry(existing, &oncore_sessions, node) {
			if (strcmp(existing->name, sname) == 0) {
				if (sess->ser)
					kho_unpreserve_free(sess->ser);
				oncore_free_session_pgd(sess);
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

struct oncore_session *oncore_get_session(struct liveupdate_session *s)
{
	return oncore_find_session(s);
}
EXPORT_SYMBOL_GPL(oncore_get_session);

int oncore_session_add_cpu(struct liveupdate_session *s, int cpu)
{
	struct oncore_session *sess = oncore_get_or_create_session(s);
	phys_addr_t pa;
	unsigned long va;
	size_t sz;
	int ret = 0;

	if (!sess || cpu < 0 || cpu >= nr_cpu_ids)
		return -EINVAL;

	guard(mutex)(&sess->lock);
	cpumask_set_cpu(cpu, &sess->cpus);

	sess->cpu_args[cpu].sess = sess;
	sess->cpu_args[cpu].cpu = cpu;

	if (sess->ser) {
		unsigned int word = cpu / 64;

		if (word < sess->ser->nr_cpu_words)
			sess->ser->cpus_bitmap[word] |= BIT_ULL(cpu % 64);
		sess->ser->nr_cpus = cpumask_weight(&sess->cpus);
		sess->ser->pgd_pa = sess->pgd_pa;
	}

	if (!cpu_preserved_get_pcpus_info(&pa, &va, &sz))
		oncore_map_session_range(sess, pa, va, sz, PAGE_KERNEL);

	if (!cpu_preserved_get_stack_info(cpu, &pa, &va, &sz))
		oncore_map_session_range(sess, pa, va, sz, PAGE_KERNEL);

	cpu_preserved_set_workload_context(cpu, sess, sess->pgd_pa);

	ret = cpu_preserved_attach_workload(cpu, "sched",
					    oncore_sched_cpu_worker,
					    &sess->cpu_args[cpu]);
	if (ret) {
		cpu_preserved_set_workload_context(cpu, NULL, 0);
		cpumask_clear_cpu(cpu, &sess->cpus);
		if (sess->ser) {
			unsigned int word = cpu / 64;

			if (word < sess->ser->nr_cpu_words)
				sess->ser->cpus_bitmap[word] &= ~BIT_ULL(cpu % 64);
			sess->ser->nr_cpus = cpumask_weight(&sess->cpus);
		}
		return ret;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(oncore_session_add_cpu);

int oncore_session_remove_cpu(struct liveupdate_session *s, int cpu)
{
	struct oncore_session *sess = oncore_find_session(s);

	if (!sess || cpu < 0 || cpu >= nr_cpu_ids)
		return -EINVAL;

	scoped_guard(mutex, &sess->lock) {
		cpumask_clear_cpu(cpu, &sess->cpus);
		if (sess->ser) {
			unsigned int word = cpu / 64;

			if (word < sess->ser->nr_cpu_words)
				sess->ser->cpus_bitmap[word] &= ~BIT_ULL(cpu % 64);
			sess->ser->nr_cpus = cpumask_weight(&sess->cpus);
		}
	}

	cpu_preserved_detach_workload(cpu);
	cpu_preserved_set_workload_context(cpu, NULL, 0);

	if (cpumask_empty(&sess->cpus)) {
		scoped_guard(mutex, &oncore_sessions_lock) {
			list_del_init(&sess->node);
		}
		oncore_free_session_pgd(sess);
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
EXPORT_SYMBOL_GPL(oncore_session_remove_cpu);

phys_addr_t oncore_session_get_ser_pa(struct liveupdate_session *s)
{
	struct oncore_session *sess = oncore_find_session(s);

	if (!sess || !sess->ser)
		return 0;

	sess->ser->pgd_pa = sess->pgd_pa;
	sess->ser->nr_cpus = cpumask_weight(&sess->cpus);
	sess->ser->runqueue_pa = virt_to_phys(&sess->rq);
	return virt_to_phys(sess->ser);
}
EXPORT_SYMBOL_GPL(oncore_session_get_ser_pa);

phys_addr_t oncore_session_get_pgd_pa(struct oncore_session *sess)
{
	return sess ? sess->pgd_pa : 0;
}
EXPORT_SYMBOL_GPL(oncore_session_get_pgd_pa);

int oncore_session_restore(struct liveupdate_session *s,
			   struct oncore_session_ser *ser)
{
	struct oncore_session *sess;
	const char *sname;

	if (!ser || !ser->sess_pa)
		return -EINVAL;

	sname = liveupdate_session_name(s);
	if (!sname || !sname[0])
		sname = ser->session_name;

	scoped_guard(mutex, &oncore_sessions_lock) {
		list_for_each_entry(sess, &oncore_sessions, node) {
			if (strcmp(sess->name, sname) == 0)
				return 0;
		}
	}

	sess = phys_to_virt(ser->sess_pa);
	sess->ser = ser;
	sess->is_incoming = true;
	mutex_init(&sess->lock);

	scoped_guard(mutex, &oncore_sessions_lock) {
		list_add_tail(&sess->node, &oncore_sessions);
	}
	return 0;
}
EXPORT_SYMBOL_GPL(oncore_session_restore);

struct oncore_job *
oncore_session_submit_job(struct liveupdate_session *s,
			  const char *name, int preferred_cpu,
			  oncore_job_fn run_fn,
			  void *data)
{
	struct oncore_session *sess = oncore_get_or_create_session(s);
	struct oncore_job *job;

	if (!sess || !run_fn)
		return ERR_PTR(-EINVAL);

	guard(mutex)(&sess->lock);

	job = kho_alloc_preserve(sizeof(*job));
	if (IS_ERR(job))
		job = kzalloc(sizeof(*job), GFP_KERNEL);
	if (!job)
		return ERR_PTR(-ENOMEM);

	memset(job, 0, sizeof(*job));
	if (sess->pgd) {
		oncore_map_session_range(sess, virt_to_phys(job),
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
	job->state = ONCORE_JOB_NEW;
	job->run_fn = run_fn;
	job->data = data;
	job->last_cpu = -1;

	if (preferred_cpu >= 0 && cpumask_test_cpu(preferred_cpu, &sess->cpus) &&
	    sess->cpu_jobs[preferred_cpu] == 0) {
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
		if (min_count > 0 && preferred_cpu >= 0 &&
		    cpumask_test_cpu(preferred_cpu, &sess->cpus)) {
			job->preferred_cpu = preferred_cpu;
			job->assigned_cpu = preferred_cpu;
			sess->cpu_jobs[preferred_cpu]++;
		} else {
			job->preferred_cpu = assigned;
			job->assigned_cpu = assigned;
			if (assigned >= 0)
				sess->cpu_jobs[assigned]++;
		}
	} else {
		job->preferred_cpu = -1;
		job->assigned_cpu = -1;
	}

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
	if (job->data) {
		if (sess->pgd) {
			oncore_map_session_range(sess, virt_to_phys(job->data),
						 (unsigned long)job->data,
						 PAGE_SIZE, PAGE_KERNEL);
		} else {
			cpu_preserved_map_buffer(job->data, PAGE_SIZE);
		}
	}
	if (job->assigned_cpu >= 0) {
		oncore_sched_enqueue(&sess->rq, job);
		if (cpu_is_preserved(job->assigned_cpu))
			arch_cpu_preserved_kick(job->assigned_cpu);
	}
	return 0;
}
EXPORT_SYMBOL_GPL(oncore_session_activate_job);

int oncore_session_cancel_job(struct liveupdate_session *s,
			      struct oncore_job *job)
{
	struct oncore_session *sess = oncore_find_session(s);

	if (!sess || !job)
		return -EINVAL;

	guard(mutex)(&sess->lock);
	if (job->assigned_cpu >= 0) {
		sess->cpu_jobs[job->assigned_cpu]--;
		job->assigned_cpu = -1;
	}
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

void __weak arch_oncore_flush_tlb(struct oncore_session *sess)
{
}
