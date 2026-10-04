/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * On-Core Session and Scheduling Framework for Live Update
 */
#ifndef __LINUX_ONCORE_H
#define __LINUX_ONCORE_H

#include <linux/cpu_preserve.h>
#include <linux/types.h>

/*
 * Only ever used as an opaque handle here, so do not include
 * <linux/liveupdate.h>: this header is reached from <linux/kvm_host.h> via
 * <linux/kvm_caretaker.h>, and including it would drag the entire LUO header
 * stack into every KVM translation unit on every architecture.
 */
struct liveupdate_session;
struct oncore_session;
struct oncore_job;

#include <asm/oncore.h>

/**
 * enum oncore_exit_reason - Why an on-core job returned to the scheduler
 * @ONCORE_EXIT_QUANTUM_EXPIRED: Time slice elapsed; the job is still runnable.
 * @ONCORE_EXIT_ATTACH_SIGNALED: The incoming kernel asked for the CPU back.
 * @ONCORE_EXIT_YIELD_IDLE: The job has no work right now (guest HLT/WFI).
 * @ONCORE_EXIT_ERROR: The job hit an unrecoverable error and must be dropped.
 * @ONCORE_EXIT_STALL: The job hit something it cannot handle on-core and
 *                     cannot make forward progress until the incoming kernel
 *                     reclaims it.  Unlike %ONCORE_EXIT_QUANTUM_EXPIRED, an
 *                     immediate re-run is guaranteed to hit the same wall, so
 *                     the scheduler backs off instead of spinning.
 */
enum oncore_exit_reason {
	ONCORE_EXIT_QUANTUM_EXPIRED = 0,
	ONCORE_EXIT_ATTACH_SIGNALED,
	ONCORE_EXIT_YIELD_IDLE,
	ONCORE_EXIT_ERROR,
	ONCORE_EXIT_STALL,
};

typedef enum oncore_exit_reason (*oncore_job_fn)(void *data,
						 u64 deadline_ticks);

#ifdef CONFIG_LIVEUPDATE_ONCORE
void oncore_cpu_preserved(struct cpu_preserved_session *ps, int cpu);
void oncore_cpu_unpreserved(struct cpu_preserved_session *ps, int cpu);
void oncore_session_release(u64 workload_pa, bool incoming);
phys_addr_t oncore_session_get_pgd_pa(struct oncore_session *sess);
struct oncore_job *oncore_session_submit_job(struct liveupdate_session *s,
					     oncore_job_fn run_fn,
					     void *data);
int oncore_session_activate_job(struct liveupdate_session *s,
				struct oncore_job *job);
void oncore_job_set_data(struct oncore_job *job, void *data);
int oncore_job_cpu(const struct oncore_job *job);
struct oncore_session *oncore_job_session(const struct oncore_job *job);
int oncore_session_cancel_job(struct liveupdate_session *s,
			      struct oncore_job *job);
int oncore_session_map_range(struct oncore_session *sess, phys_addr_t pa,
			     unsigned long va, size_t size, pgprot_t prot);
int oncore_session_map_buffer(struct oncore_session *sess, void *va,
			      size_t size);
void oncore_session_unmap_range(struct oncore_session *sess,
				unsigned long va, size_t size);
void oncore_session_unmap_buffer(struct oncore_session *sess, void *va,
				 size_t size);
bool oncore_need_resched(void) __cpu_preserved_sym_asm(oncore_need_resched);
#else
static inline void oncore_cpu_preserved(struct cpu_preserved_session *ps,
					int cpu) {}

static inline void oncore_cpu_unpreserved(struct cpu_preserved_session *ps,
					  int cpu) {}

static inline void oncore_session_release(u64 workload_pa, bool incoming) {}

static inline phys_addr_t oncore_session_get_pgd_pa(struct oncore_session *sess) { return 0; }

static inline struct oncore_job *oncore_session_submit_job(struct liveupdate_session *s,
							   oncore_job_fn run_fn,
							   void *data)
{
	return NULL;
}

static inline int oncore_session_activate_job(struct liveupdate_session *s,
					      struct oncore_job *job)
{
	return -EOPNOTSUPP;
}

static inline void oncore_job_set_data(struct oncore_job *job, void *data) {}

static inline int oncore_job_cpu(const struct oncore_job *job) { return -1; }

static inline struct oncore_session *
oncore_job_session(const struct oncore_job *job)
{
	return NULL;
}

static inline int oncore_session_cancel_job(struct liveupdate_session *s,
					    struct oncore_job *job)
{
	return 0;
}

static inline int oncore_session_map_range(struct oncore_session *sess, phys_addr_t pa,
					   unsigned long va, size_t size, pgprot_t prot)
{
	return 0;
}

static inline int oncore_session_map_buffer(struct oncore_session *sess, void *va,
					    size_t size)
{
	return 0;
}

static inline void oncore_session_unmap_range(struct oncore_session *sess,
					      unsigned long va, size_t size) {}

static inline void oncore_session_unmap_buffer(struct oncore_session *sess,
					       void *va, size_t size) {}

static inline bool oncore_need_resched(void)
{
	return false;
}
#endif /* CONFIG_LIVEUPDATE_ONCORE */

#endif /* __LINUX_ONCORE_H */
