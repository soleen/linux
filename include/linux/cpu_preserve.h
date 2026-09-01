/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * Preserved CPU across Live Update
 */
#ifndef _LINUX_CPU_PRESERVE_H
#define _LINUX_CPU_PRESERVE_H

#include <linux/compiler.h>
#include <linux/cpumask.h>
#include <linux/errno.h>
#include <linux/smp.h>
#include <linux/types.h>

struct caretaker_session;

/**
 * struct cpu_preserved_stack_context - Context header at base of preserved CPU stack
 * @magic:          Validation signature (CPU_PRESERVED_STACK_MAGIC)
 * @cpu:            Logical CPU ID of the preserved physical core
 * @session:        Owning Caretaker session
 * @session_pgd_pa: Session root page table physical address
 * @entry_data:     Private workload callback data
 */
struct cpu_preserved_stack_context {
	u64				magic;
	int				cpu;
	struct caretaker_session	*session;
	phys_addr_t			session_pgd_pa;
	void				*entry_data;
};

#include 
#ifdef CONFIG_LIVEUPDATE_CPU

#include <asm/cpu_preserve.h>
#include <asm/page.h>

#define CPU_PRESERVED_STACK_ORDER	ARCH_CPU_PRESERVED_STACK_ORDER
#define CPU_PRESERVED_STACK_SIZE	((size_t)PAGE_SIZE << CPU_PRESERVED_STACK_ORDER)
#define CPU_PRESERVED_STACK_HEADROOM	256
#define CPU_PRESERVED_STACK_MAGIC	0x435055505354414bULL /* "CPUPSTAK" */

static inline struct cpu_preserved_stack_context *
cpu_preserved_get_stack_context(void)
{
	struct cpu_preserved_stack_context *sctx;
	unsigned long sp;

#if defined(CONFIG_X86_64)
	asm volatile("mov %%rsp, %0" : "=r"(sp));
#elif defined(CONFIG_ARM64)
	asm volatile("mov %0, sp" : "=r"(sp));
#else
	return NULL;
#endif
	sctx = (struct cpu_preserved_stack_context *)(sp & ~(CPU_PRESERVED_STACK_SIZE - 1));
	if (sctx && sctx->magic == CPU_PRESERVED_STACK_MAGIC)
		return sctx;
	return NULL;
}


/*
 * __cpu_preserved_text: Code executed by preserved physical CPUs during live
 * update kexec handover in orphan mode.
 *
 * On x86, indirect branches and function returns must not use external
 * retpolines or return thunks (__x86_return_thunk) because those thunks reside
 * in regular .text (scratch memory), which gets overwritten during kexec
 * handover before the incoming kernel boots. Instead, preserved code runs
 * self-contained in a runtime preserved execution buffer and never returns to
 * the outgoing kernel text.
 */
#if defined(CONFIG_X86)
#define __cpu_preserved_text	__section(".text.cpu_preserved") __attribute__((indirect_branch("keep"), function_return("keep")))
#else
#define __cpu_preserved_text	__section(".text.cpu_preserved")
#endif
#define __cpu_preserved_data	__section(".data.cpu_preserved")

extern char __cpu_preserved_text_start[], __cpu_preserved_text_end[];
extern char __cpu_preserved_data_start[], __cpu_preserved_data_end[];
bool cpu_is_preserved(int cpu);
bool cpu_preserved_is_incoming(int cpu);
bool cpu_preserved_should_exit(int cpu);
const char *cpu_preserved_get_workload_name(int cpu);
const char *cpu_preserved_get_session_name(int cpu);
void cpu_preserved_park(int cpu);
const struct cpumask *cpu_get_preserved_mask(void);
void cpu_preserved_filter_offline_mask(struct cpumask *mask);
int cpu_preserved_attach_workload(int cpu, const char *name,
				  void (*entry_fn)(void *data), void *data);
int cpu_preserved_detach_workload(int cpu);

/**
 * cpu_preserved_report_dead - Park preserved CPU when reporting dead in hotplug
 *
 * Invoked by cpuhp_ap_report_dead() after CPU hotplug offline synchronization
 * is complete. If the calling CPU is marked for preservation across live update,
 * transition it into the preserved parking loop instead of powering down.
 */
static inline void cpu_preserved_report_dead(void)
{
	if (cpu_is_preserved(raw_smp_processor_id()))
		cpu_preserved_park(raw_smp_processor_id());
}

/*
 * Architecture-specific hooks for CPU preservation.
 */

/**
 * arch_cpu_preserved_kick - Signal or wake up a preserved physical CPU
 * @cpu: Logical CPU identifier.
 *
 * Architecture backend hook to wake up the specified preserved CPU from its
 * low-power parking state (e.g. via IPI, NMI, or SGI).
 *
 * This function must be placed in the __cpu_preserved_text section.
 */
void arch_cpu_preserved_kick(int cpu);

/**
 * arch_cpu_preserved_park_wait - Architecture low-power wait in parking loop
 *
 * Architecture backend hook to execute a low-power wait instruction
 * (e.g., cpu_relax/pause, wfe) while parked.
 *
 * This function must be placed in the __cpu_preserved_text section.
 */
void arch_cpu_preserved_park_wait(void);

/**
 * arch_cpu_preserved_park_init - Architecture setup upon entering park loop
 *
 * Architecture backend hook to configure the physical core (e.g., disable
 * or mask local interrupts) upon entering the park loop.
 *
 * This function must be placed in the __cpu_preserved_text section.
 */
void arch_cpu_preserved_park_init(int cpu);
void arch_cpu_preserved_early_init(void);
phys_addr_t cpu_preserved_get_pgd(int cpu);

/**
 * arch_cpu_preserved_park_finish - Architecture cleanup on park loop exit
 * @cpu: Logical CPU identifier.
 *
 * Architecture backend hook to execute cleanup or CPU powerdown sequence
 * when the park loop exits.
 *
 * This function must be placed in the __cpu_preserved_text section.
 */
void arch_cpu_preserved_park_finish(int cpu);
void arch_cpu_preserved_park_cancel(int cpu);

/**
 * arch_cpu_preserved_park_on_stack - Switch stack and enter park loop
 * @cpu: Logical CPU identifier.
 * @stack_top: Top address of the preserved stack.
 *
 * Architecture backend hook to switch to the preserved execution stack
 * and invoke cpu_preserved_park_loop().
 *
 * This function must be placed in the __cpu_preserved_text section.
 */
void arch_cpu_preserved_park_on_stack(int cpu, unsigned long stack_top);

/**
 * cpu_preserved_park_loop - Generic execution loop for parked preserved CPU
 * @cpu: Logical CPU identifier.
 *
 * Core execution loop executed on the dedicated preserved stack.
 * Returns 1 if unpreserved across kexec, 0 if unpreserved during cancel.
 *
 * This function is placed in the __cpu_preserved_text section.
 */
int cpu_preserved_park_loop(int cpu);

/**
 * arch_cpu_preserved_dcache_clean - Clean data cache for address range
 * @start: Starting virtual address.
 * @end: Ending virtual address.
 *
 * Architecture backend hook to flush/clean data caches to PoC for memory
 * preservation across live update.
 *
 * This function must be placed in the __cpu_preserved_text section.
 */
void arch_cpu_preserved_dcache_clean(unsigned long start, unsigned long end);

/**
 * arch_cpu_preserved_dcache_inval - Invalidate/clean data cache for range
 * @start: Starting virtual address.
 * @end: Ending virtual address.
 *
 * Architecture backend hook to clean/invalidate data caches across live
 * update transitions.
 *
 * This function must be placed in the __cpu_preserved_text section.
 */
void arch_cpu_preserved_dcache_inval(unsigned long start, unsigned long end);

/**
 * arch_cpu_preserved_preserve_pagetables - Preserve architecture page tables
 *
 * Architecture backend hook to preserve kernel page tables backing identity
 * and kernel mappings across live update.
 *
 * Executed by outgoing kernel in normal text context before kexec.
 */
void arch_cpu_preserved_preserve_pagetables(void);

/**
 * arch_cpu_preserved_wait_dead - Wait for CPU to reach dead state
 * @cpu: Logical CPU identifier.
 *
 * Architecture backend hook to wait for a CPU to be fully stopped.
 *
 * Executed in normal text context during CPU teardown.
 */
void arch_cpu_preserved_wait_dead(int cpu);

struct page;

void *arch_cpu_preserved_get_pgd(void);
/**
 * arch_cpu_preserved_setup_buffer - Map preserved execution buffer outside Scratch
 * @text_page: Head page of allocated preserved text memory.
 * @text_nr_pages: Number of pages in the preserved text buffer.
 * @data_page: Head page of allocated preserved data memory.
 * @data_nr_pages: Number of pages in the preserved data buffer.
 *
 * Architecture backend hook to remap kernel page table entries for
 * __cpu_preserved_text and __cpu_preserved_data to the newly allocated
 * pages outside Scratch memory, and clone page tables for preserved CPUs
 * across live update.
 *
 * Return: 0 on success, or a negative errno on failure.
 */
int arch_cpu_preserved_setup_buffer(struct page *text_page,
				    unsigned int text_nr_pages,
				    struct page *data_page,
				    unsigned int data_nr_pages);

/**
 * arch_cpu_preserved_unpreserve_pagetables - Unpreserve architecture page tables
 *
 * Architecture backend hook to unpreserve and release page table pages that
 * were cloned and preserved for live update handover, invoked when live
 * update is cancelled or unpreserved.
 */
void arch_cpu_preserved_unpreserve_pagetables(void);
int cpu_preserved_init_runtime_buffer(void);
void arch_cpu_preserved_switch_pgd(phys_addr_t pgd_pa);

#else /* !CONFIG_LIVEUPDATE_CPU */

#define __cpu_preserved_text
#define __cpu_preserved_data

static inline bool cpu_is_preserved(int cpu) { return false; }
static inline bool cpu_preserved_is_incoming(int cpu) { return false; }
static inline bool cpu_preserved_should_exit(int cpu) { return true; }
static inline const char *cpu_preserved_get_workload_name(int cpu)
{
	return "none";
}
static inline const char *cpu_preserved_get_session_name(int cpu)
{
	return "none";
}
static inline void cpu_preserved_park(int cpu) {}
static inline void cpu_preserved_report_dead(void) {}
static inline const struct cpumask *cpu_get_preserved_mask(void)
{
	return cpu_none_mask;
}
static inline void cpu_preserved_filter_offline_mask(struct cpumask *mask) {}

static inline int cpu_preserved_attach_workload(int cpu, const char *name,
						void (*entry_fn)(void *data),
						void *data)
{
	return -EOPNOTSUPP;
}
static inline int cpu_preserved_detach_workload(int cpu) { return -EOPNOTSUPP; }

static inline void arch_cpu_preserved_kick(int cpu) {}
static inline void arch_cpu_preserved_park_wait(void) {}
static inline void arch_cpu_preserved_park_init(int cpu) {}
static inline void arch_cpu_preserved_early_init(void) {}
static inline void arch_cpu_preserved_park_finish(int cpu) {}
static inline void arch_cpu_preserved_dcache_clean(unsigned long start,
						   unsigned long end) {}
static inline void arch_cpu_preserved_dcache_inval(unsigned long start,
						   unsigned long end) {}
static inline void arch_cpu_preserved_preserve_pagetables(void) {}
static inline void arch_cpu_preserved_wait_dead(int cpu) {}
static inline void *arch_cpu_preserved_get_pgd(void) { return NULL; }
static inline phys_addr_t cpu_preserved_get_pgd(int cpu) { return 0; }
static inline int arch_cpu_preserved_setup_buffer(struct page *text_page,
						  unsigned int text_nr_pages,
						  struct page *data_page,
						  unsigned int data_nr_pages)
{
	return 0;
}
static inline void arch_cpu_preserved_unpreserve_pagetables(void) {}
static inline int cpu_preserved_init_runtime_buffer(void) { return 0; }
static inline void arch_cpu_preserved_switch_pgd(phys_addr_t pgd_pa) {}
static inline struct cpu_preserved_stack_context *
cpu_preserved_get_stack_context(void)
{
	return NULL;
}

#endif /* CONFIG_LIVEUPDATE_CPU */

#endif /* _LINUX_CPU_PRESERVE_H */
