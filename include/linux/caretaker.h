/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 */
#ifndef __LINUX_CARETAKER_H
#define __LINUX_CARETAKER_H

#include <linux/atomic.h>
#include <linux/cpumask.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/cpu_preserve.h>
#include <linux/kho/abi/caretaker.h>
#include <uapi/linux/liveupdate.h>

struct caretaker_sched_config;

#if __has_include(<asm/caretaker.h>)
#include <asm/caretaker.h>
#else
static inline u64 __cpu_preserved_text arch_caretaker_read_counter(void) { return 0; }
u64 arch_caretaker_ticks_to_ns(u64 ticks);
void arch_caretaker_update_quantum_ticks(struct caretaker_sched_config *cfg);
#endif

struct kvm_vcpu;
struct liveupdate_session;
struct caretaker_session;

#define __caretaker_text __cpu_preserved_text
#define __caretaker_data __cpu_preserved_data

/* Execution states */
enum caretaker_job_state {
	CARETAKER_JOB_NEW = 0,
	CARETAKER_JOB_RUNNABLE,
	CARETAKER_JOB_RUNNING,
	CARETAKER_JOB_CANCELING,
	CARETAKER_JOB_DEAD,
};

/* Execution exit reasons */
enum caretaker_exit_reason {
	CARETAKER_EXIT_QUANTUM_EXPIRED = 0, /* Exhausted allocated time slice */
	CARETAKER_EXIT_ATTACH_SIGNALED,     /* Incoming kernel signaled attach */
	CARETAKER_EXIT_YIELD_IDLE,          /* Voluntary yield */
	CARETAKER_EXIT_ERROR,               /* Fatal execution error */
};

typedef enum caretaker_exit_reason (*caretaker_job_fn)(void *data,
						       u64 deadline_ticks);

/**
 * struct caretaker_job - Schedulable unit of execution in Caretaker
 * @node:              Linkage into session runqueue
 * @session:           Pointer to owning caretaker session
 * @name:              Job identifier string (e.g. "vcpu0")
 * @state:             Current scheduling state (NEW, RUNNABLE, RUNNING, DEAD)
 * @run_fn:            Job execution callback function
 * @data:              Opaque workload context (e.g. preserved page pointer)
 * @preferred_cpu:     Target physical CPU affinity, or -1 for any
 * @assigned_cpu:      Assigned physical CPU, or -1
 * @last_cpu:          Physical CPU where job last executed
 * @total_runs:        Cumulative count of job executions
 * @total_runtime_ns:  Cumulative execution time in nanoseconds
 * @preemptions:       Count of quantum expirations
 */
struct caretaker_job {
	struct list_head		node;
	struct caretaker_session	*session;
	char				name[64];
	enum caretaker_job_state	state;
	caretaker_job_fn		run_fn;
	void				*data;
	int				preferred_cpu;
	int				assigned_cpu;
	int				last_cpu;

	/* Scheduling statistics & accounting */
	u64				total_runs;
	u64				total_runtime_ns;
	u64				preemptions;
};

/**
 * struct caretaker_runqueue - Circular Round-Robin runqueue
 * @lock:        Preserved atomic spinlock protecting queue operations
 * @runnable:    Head of runnable threads list (FIFO ordering)
 * @nr_runnable: Count of currently runnable threads
 * @nr_total:    Total threads registered in this queue
 */
struct caretaker_runqueue {
	atomic_t		lock;
	struct list_head	runnable;
	unsigned int		nr_runnable;
	unsigned int		nr_total;
};

/**
 * struct caretaker_sched_config - Configuration parameters for scheduler
 * @quantum_ms:    Time slice duration in milliseconds
 * @quantum_ticks: Time slice duration converted to hardware ticks
 * @tsc_khz:       Hardware timer frequency in kHz
 */
struct caretaker_sched_config {
	u32			quantum_ms;
	u64			quantum_ticks;
	u32			tsc_khz;
};

extern struct caretaker_sched_config global_sched_config;

struct caretaker_cpu_worker_arg {
	struct caretaker_session *sess;
	int cpu;
};

#define CARETAKER_MAX_PGD_PAGES		128

/**
 * struct caretaker_session - Per-LUO session Caretaker context
 * @node:         Entry in global caretaker_sessions list
 * @name:         Session identifier string
 * @cpus:         Mask of physical CPUs reserved for this session
 * @cpu_jobs:     Count of assigned jobs per physical CPU
 * @lock:         Protects session CPU pool and job queues
 * @rq:           Unified circular runqueue of runnable jobs
 * @sched_config: Scheduler quantum and timing configuration
 * @cpu_args:     Per-CPU worker argument array
 * @pgd:          Root transition page table pointer
 * @pgd_pa:       Root transition page table physical address
 * @pgd_pages:    Array of physical addresses of pages allocated for session page table
 * @nr_pgd_pages: Count of allocated session page table pages
 * @ser:          Serialized KHO session metadata
 * @is_incoming:  True if session was restored from previous kernel
 */
struct caretaker_session {
	struct list_head		node;
	char				name[LIVEUPDATE_SESSION_NAME_LENGTH];
	cpumask_t			cpus;
	unsigned int			cpu_jobs[NR_CPUS];
	struct mutex			lock;
	struct caretaker_runqueue	rq;
	struct caretaker_sched_config	sched_config;
	struct caretaker_cpu_worker_arg	cpu_args[NR_CPUS];
	void				*pgd;
	phys_addr_t			pgd_pa;
	phys_addr_t			pgd_pages[CARETAKER_MAX_PGD_PAGES];
	unsigned int			nr_pgd_pages;
	struct caretaker_session_ser	*ser;
	bool				is_incoming;
};

#ifdef CONFIG_CARETAKER

struct caretaker_session *caretaker_get_session(struct liveupdate_session *s);
int arch_caretaker_alloc_session_pgd(struct caretaker_session *sess);
void arch_caretaker_free_session_pgd(struct caretaker_session *sess);
int arch_caretaker_map_session_range(struct caretaker_session *sess,
				     phys_addr_t pa, unsigned long va,
				     size_t size, pgprot_t prot);
void caretaker_map_range_all_sessions(phys_addr_t pa, unsigned long va,
				      size_t size, pgprot_t prot);
int caretaker_session_map_range(struct caretaker_session *sess, phys_addr_t pa,
				unsigned long va, size_t size, pgprot_t prot);
int caretaker_session_map_buffer(struct caretaker_session *sess, void *va,
				 size_t size);

static inline struct cpu_preserved_stack_context *
caretaker_get_current_context(void)
{
	return cpu_preserved_get_stack_context();
}

int caretaker_session_add_cpu(struct liveupdate_session *s, int cpu);
int caretaker_session_remove_cpu(struct liveupdate_session *s, int cpu);
struct caretaker_job *
caretaker_session_submit_job(struct liveupdate_session *s,
			     const char *name, int preferred_cpu,
			     caretaker_job_fn run_fn,
			     void *data);
int caretaker_session_activate_job(struct liveupdate_session *s,
				   struct caretaker_job *job);
int caretaker_session_cancel_job(struct liveupdate_session *s,
				 struct caretaker_job *job);
phys_addr_t caretaker_session_get_ser_pa(struct liveupdate_session *s);
int caretaker_session_restore(struct liveupdate_session *s,
			      struct caretaker_session_ser *ser);

static inline bool caretaker_is_orphaned_cpu(int cpu)
{
	return cpu_is_preserved(cpu);
}

static inline bool caretaker_is_parked_cpu(int cpu)
{
	return cpu_is_preserved(cpu);
}

static inline bool caretaker_is_enabled(void)
{
	return true;
}

#else /* !CONFIG_CARETAKER */

static inline struct caretaker_session *caretaker_get_session(struct liveupdate_session *s) { return NULL; }
static inline int arch_caretaker_alloc_session_pgd(struct caretaker_session *sess) { return 0; }
static inline void arch_caretaker_free_session_pgd(struct caretaker_session *sess) {}
static inline int arch_caretaker_map_session_range(struct caretaker_session *sess,
						   phys_addr_t pa, unsigned long va,
						   size_t size, pgprot_t prot) { return 0; }
static inline void caretaker_map_range_all_sessions(phys_addr_t pa, unsigned long va,
						    size_t size, pgprot_t prot) {}
static inline int caretaker_session_map_range(struct caretaker_session *sess,
					      phys_addr_t pa, unsigned long va,
					      size_t size, pgprot_t prot) { return 0; }
static inline int caretaker_session_map_buffer(struct caretaker_session *sess,
					       void *va, size_t size) { return 0; }

static inline struct cpu_preserved_stack_context *
caretaker_get_current_context(void)
{
	return cpu_preserved_get_stack_context();
}

static inline int caretaker_session_add_cpu(struct liveupdate_session *s, int cpu)
{
	return 0;
}

static inline int caretaker_session_remove_cpu(struct liveupdate_session *s, int cpu)
{
	return 0;
}

static inline struct caretaker_job *
caretaker_session_submit_job(struct liveupdate_session *s,
			     const char *name, int preferred_cpu,
			     caretaker_job_fn run_fn,
			     void *data)
{
	return ERR_PTR(-ENOSYS);
}

static inline int caretaker_session_activate_job(struct liveupdate_session *s,
						 struct caretaker_job *job)
{
	return 0;
}

static inline int caretaker_session_cancel_job(struct liveupdate_session *s,
					       struct caretaker_job *job)
{
	return 0;
}
static inline phys_addr_t caretaker_session_get_ser_pa(struct liveupdate_session *s) { return 0; }
static inline int caretaker_session_restore(struct liveupdate_session *s,
					     struct caretaker_session_ser *ser) { return 0; }

static inline bool caretaker_is_orphaned_cpu(int cpu) { return false; }
static inline bool caretaker_is_parked_cpu(int cpu) { return false; }
static inline bool caretaker_is_enabled(void) { return false; }

#endif /* CONFIG_CARETAKER */

#ifdef CONFIG_KVM_CARETAKER

static inline bool caretaker_kvm_is_attached(const struct caretaker_cb *cb)
{
	return !cb || READ_ONCE(cb->attachment_state) != CARETAKER_KVM_DETACHED;
}

static inline void caretaker_cb_init(struct caretaker_cb *cb, int vcpu_id)
{
	if (cb) {
		cb->attachment_state = CARETAKER_KVM_ATTACHED;
		cb->pcpu_id = CARETAKER_INVALID_PCPU;
		cb->vcpu_id = vcpu_id;
	}
}

static inline void caretaker_kvm_detach(struct caretaker_cb *cb)
{
	if (cb)
		smp_store_release(&cb->attachment_state, CARETAKER_KVM_DETACHED);
}

static inline void caretaker_kvm_attach(struct caretaker_cb *cb)
{
	if (cb)
		smp_store_release(&cb->attachment_state, CARETAKER_KVM_ATTACHED);
}

#else /* !CONFIG_KVM_CARETAKER */

static inline bool caretaker_kvm_is_attached(const struct caretaker_cb *cb) { return true; }
static inline void caretaker_cb_init(struct caretaker_cb *cb, int vcpu_id) {}
static inline void caretaker_kvm_detach(struct caretaker_cb *cb) {}
static inline void caretaker_kvm_attach(struct caretaker_cb *cb) {}

#endif /* CONFIG_KVM_CARETAKER */

void gicv3_caretaker_enable_sgi(void);
void gicv3_caretaker_clear_sgi(void);
void gicv3_caretaker_kick_cpu(int cpu);
void __iomem *gicv3_get_rdist_for_cpu(int cpu);
int gicv3_caretaker_get_redist_region(int idx, phys_addr_t *pa,
				      unsigned long *va, size_t *size);

static inline void *caretaker_memset(void *s, int c, size_t n)
{
	volatile unsigned char *p = (volatile unsigned char *)s;

	while (n--)
		*p++ = (unsigned char)c;
	return s;
}

static inline void *caretaker_memcpy(void *dest, const void *src, size_t n)
{
	volatile unsigned char *d = (volatile unsigned char *)dest;
	const volatile unsigned char *s = (const volatile unsigned char *)src;

	while (n--)
		*d++ = *s++;
	return dest;
}

#ifdef CONFIG_KEXEC_HANDOVER
void gicv3_its_preserve_kho(void);
#else
static inline void gicv3_its_preserve_kho(void) {}
#endif

#endif /* __LINUX_CARETAKER_H */
