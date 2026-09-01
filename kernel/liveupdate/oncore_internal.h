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
#include <asm/trans_pgd.h>

#define ONCORE_MAX_PGD_PAGES		1024

struct oncore_runqueue {
	atomic_t			lock;
	struct list_head		runnable;
	unsigned int			nr_runnable;
	unsigned int			nr_total;
};

struct oncore_cpu_worker_arg {
	struct oncore_session		*sess;
	int				cpu;
};

struct oncore_session {
	struct list_head		node;
	char				name[LIVEUPDATE_SESSION_NAME_LENGTH];
	cpumask_t			cpus;
	unsigned int			cpu_jobs[NR_CPUS];
	struct mutex			lock;
	struct oncore_runqueue		rq;
	struct oncore_sched_config	sched_config;
	struct oncore_cpu_worker_arg	cpu_args[NR_CPUS];
	void				*pgd;
	phys_addr_t			pgd_pa;
	phys_addr_t			pgd_pages[ONCORE_MAX_PGD_PAGES];
	unsigned int			nr_pgd_pages;
	struct oncore_session_ser	*ser;
	bool				is_incoming;
};

#ifdef CONFIG_ONCORE_SCHED

/* Scheduler internal interfaces (oncore_sched.c) */
void oncore_runqueue_init(struct oncore_runqueue *rq);
int oncore_sched_enqueue(struct oncore_runqueue *rq, struct oncore_job *job);
int oncore_sched_dequeue(struct oncore_runqueue *rq, struct oncore_job *job);
void oncore_sched_update_ticks(void);
void __cpu_preserved_text oncore_sched_cpu_worker(void *data);

/* Session internal interfaces (oncore_session.c) */
int oncore_alloc_session_pgd(struct oncore_session *sess);
void oncore_free_session_pgd(struct oncore_session *sess);
int oncore_map_session_range(struct oncore_session *sess,
			     phys_addr_t pa, unsigned long va,
			     size_t size, pgprot_t prot);
void oncore_map_range_all_sessions(phys_addr_t pa, unsigned long va,
				   size_t size, pgprot_t prot);

#else /* !CONFIG_ONCORE_SCHED */

static inline void oncore_runqueue_init(struct oncore_runqueue *rq) {}
static inline int oncore_sched_enqueue(struct oncore_runqueue *rq, struct oncore_job *job) { return 0; }
static inline int oncore_sched_dequeue(struct oncore_runqueue *rq, struct oncore_job *job) { return 0; }
static inline void oncore_sched_update_ticks(void) {}
static inline void oncore_sched_cpu_worker(void *data) {}
static inline int oncore_alloc_session_pgd(struct oncore_session *sess) { return 0; }
static inline void oncore_free_session_pgd(struct oncore_session *sess) {}
static inline int oncore_map_session_range(struct oncore_session *sess,
					   phys_addr_t pa, unsigned long va,
					   size_t size, pgprot_t prot) { return 0; }
static inline void oncore_map_range_all_sessions(phys_addr_t pa, unsigned long va,
						 size_t size, pgprot_t prot) {}

#endif /* CONFIG_ONCORE_SCHED */

#ifdef CONFIG_LIVEUPDATE_CPU

/* Low-level CPU preserve interfaces used by oncore_session (cpu_preserve.c) */
int cpu_preserved_attach_workload(int cpu, const char *name,
				  void (*entry_fn)(void *data), void *data);
int cpu_preserved_detach_workload(int cpu);
void cpu_preserved_set_workload_context(int cpu, void *ctx, phys_addr_t pgd_pa);
int cpu_preserved_get_stack_info(int cpu, phys_addr_t *pa, unsigned long *va, size_t *size);
int cpu_preserved_get_pcpus_info(phys_addr_t *pa, unsigned long *va, size_t *size);
phys_addr_t cpu_preserved_get_text_pa(void);
phys_addr_t cpu_preserved_get_data_pa(void);
int cpu_preserved_init_runtime_buffer(void);

#else /* !CONFIG_LIVEUPDATE_CPU */

static inline int cpu_preserved_attach_workload(int cpu, const char *name,
						void (*entry_fn)(void *data),
						void *data)
{
	return -EOPNOTSUPP;
}
static inline int cpu_preserved_detach_workload(int cpu)
{
	return -EOPNOTSUPP;
}
static inline void cpu_preserved_set_workload_context(int cpu, void *ctx, phys_addr_t pgd_pa) {}
static inline int cpu_preserved_get_stack_info(int cpu, phys_addr_t *pa, unsigned long *va, size_t *size) { return -EOPNOTSUPP; }
static inline int cpu_preserved_get_pcpus_info(phys_addr_t *pa, unsigned long *va, size_t *size) { return -EOPNOTSUPP; }
static inline phys_addr_t cpu_preserved_get_text_pa(void) { return 0; }
static inline phys_addr_t cpu_preserved_get_data_pa(void) { return 0; }
static inline int cpu_preserved_init_runtime_buffer(void) { return 0; }

#endif /* CONFIG_LIVEUPDATE_CPU */

#endif /* _LINUX_ONCORE_INTERNAL_H */
