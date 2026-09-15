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
#include <linux/list.h>
#include <linux/smp.h>
#include <linux/types.h>

/**
 * struct cpu_preserved_stack_context - Context header at base of preserved CPU stack
 * @magic:            Validation signature (CPU_PRESERVED_STACK_MAGIC)
 * @cpu:              Logical CPU ID of the preserved physical core
 * @workload_context: Opaque owning workload or session context
 * @session_pgd_pa:   Session root page table physical address
 * @entry_data:       Private workload callback data
 */
struct cpu_preserved_stack_context {
	u64				magic;
	int				cpu;
	void				*workload_context;
	phys_addr_t			session_pgd_pa;
	void				*entry_data;
};

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
 * All code in this section must run without stack protector checks because
 * per-CPU canary state may be invalid during handover and __stack_chk_fail()
 * resides in regular .text, which gets overwritten during kexec before the
 * incoming kernel boots.
 *
 * Architecture-specific requirements (such as disabling external retpolines
 * and return thunks on x86) are supplied via ARCH_CPU_PRESERVED_TEXT.
 */
#ifndef ARCH_CPU_PRESERVED_TEXT
#define ARCH_CPU_PRESERVED_TEXT
#endif

#define __cpu_preserved_text					\
	__section(".text.cpu_preserved")			\
	__no_stack_protector					\
	ARCH_CPU_PRESERVED_TEXT
#define __cpu_preserved_data	__section(".data.cpu_preserved")

extern char __cpu_preserved_text_start[], __cpu_preserved_text_end[];
extern char __cpu_preserved_data_start[], __cpu_preserved_data_end[];
bool cpu_is_preserved(int cpu);
bool cpu_preserved_is_incoming(int cpu);
bool cpu_preserved_should_exit(int cpu);
void cpu_preserved_set_dead(int cpu);
void cpu_preserved_park(int cpu);
const struct cpumask *cpu_get_preserved_mask(void);
phys_addr_t cpu_preserved_get_text_pa(void);
phys_addr_t cpu_preserved_get_data_pa(void);
int cpu_preserved_attach_workload(int cpu, const char *name,
				  void (*entry_fn)(void *data), void *data);
int cpu_preserved_detach_workload(int cpu);
void cpu_preserved_set_workload_context(int cpu, void *ctx, phys_addr_t pgd_pa);
int cpu_preserved_get_stack_info(int cpu, phys_addr_t *pa, unsigned long *va, size_t *size);
int cpu_preserved_get_pcpus_info(phys_addr_t *pa, unsigned long *va, size_t *size);

struct liveupdate_session;

/**
 * struct cpu_preserved_client - The layer that puts preserved CPUs to work
 *
 * A preserved CPU is only useful to something that wants to run code on it.
 * That something registers here.  CPU preservation itself has no opinion about
 * what a preserved CPU ends up executing and must not acquire one: the whole
 * point of the split is that a future bare-process preserver can replace the
 * on-core scheduler without this file changing.
 *
 * Every op is mandatory; cpu_preserved_register_client() rejects a partial
 * table.  All of them are called from process context.
 *
 * @attach:    @cpu has just been preserved on behalf of @session.  Returning
 *             an error aborts the preservation.
 * @detach:    @cpu is being handed back to the host, whether because the live
 *             update was cancelled, completed, or failed part way through.
 *             Must tolerate a CPU that was never successfully attached.
 * @serialize: Return the physical address of the client's own preserved state
 *             for @session, or 0 if it has none.  The value is opaque to CPU
 *             preservation, which only stores and returns it.
 * @restore:   Hand @client_ser_pa, the value @serialize produced in the
 *             previous kernel, back to the client after kexec.
 */
struct cpu_preserved_client {
	int  (*attach)(struct liveupdate_session *session, int cpu);
	void (*detach)(struct liveupdate_session *session, int cpu);
	phys_addr_t (*serialize)(struct liveupdate_session *session);
	void (*restore)(struct liveupdate_session *session,
			phys_addr_t client_ser_pa);
};

int cpu_preserved_register_client(const struct cpu_preserved_client *client);

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
 *
 * This function is placed in the __cpu_preserved_text section.
 */
void cpu_preserved_park_loop(int cpu);

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
 * arch_cpu_preserved_wait_dead - Wait for CPU to reach dead state
 * @cpu: Logical CPU identifier.
 *
 * Architecture backend hook to wait for a CPU to be fully stopped.
 *
 * Executed in normal text context during CPU teardown.
 */
void arch_cpu_preserved_wait_dead(int cpu);

struct page;

/**
 * arch_cpu_preserved_setup_buffer - Map preserved execution buffer outside Scratch
 * @text_page: Head page of allocated preserved text memory.
 * @text_nr_pages: Number of pages in the preserved text buffer.
 * @data_page: Head page of allocated preserved data memory.
 * @data_nr_pages: Number of pages in the preserved data buffer.
 *
 * Architecture backend hook to remap kernel page table entries for
 * __cpu_preserved_text and __cpu_preserved_data to the newly allocated
 * pages outside Scratch memory.
 *
 * Return: 0 on success, or a negative errno on failure.
 */
int arch_cpu_preserved_setup_buffer(struct page *text_page,
				    unsigned int text_nr_pages,
				    struct page *data_page,
				    unsigned int data_nr_pages);

/*
 * Upper bound on page table pages in one preserved address space.  Every
 * mapping is forced down to PTE granularity and the mapped set is small (the
 * preserved text and data, the per-CPU descriptors, one stack per preserved
 * CPU and the workload buffers), so this is roughly an order of magnitude
 * more than any real configuration needs.
 */
#define CPU_PRESERVED_AS_MAX_PGTABLE_PAGES	1024

/**
 * struct cpu_preserved_as - An address space a preserved CPU can run in
 * @node:             Entry on the global list of preserved address spaces.
 * @pgd:              Root page table.
 * @pgd_pa:           Physical address of @pgd, as loaded into CR3 / TTBR1.
 * @is_incoming:      This address space was built by the previous kernel.
 * @nr_pgtable_pages: Number of valid entries in @pgtable_pages.
 * @pgtable_pages:    Physical address of every page table page, @pgd
 *                    included.  Recorded by physical address rather than on a
 *                    struct page list because the incoming kernel has to free
 *                    them and its struct pages are not the ones the outgoing
 *                    kernel linked together.
 *
 * A preserved CPU runs with the host kernel torn down underneath it, so it
 * cannot use the host page tables: it needs an address space that maps only
 * memory that has been handed over, and that no longer depends on anything the
 * incoming kernel is free to reuse.  Every such address space is built here,
 * out of pages that are themselves preserved, and is registered on a global
 * list so that a range mapped for preserved CPUs lands in all of them.
 */
struct cpu_preserved_as {
	struct list_head	node;
	void			*pgd;
	phys_addr_t		pgd_pa;
	bool			is_incoming;
	unsigned int		nr_pgtable_pages;
	phys_addr_t		pgtable_pages[CPU_PRESERVED_AS_MAX_PGTABLE_PAGES];
};

struct cpu_preserved_as *cpu_preserved_as_create(void);
void cpu_preserved_as_destroy(struct cpu_preserved_as *as);
void cpu_preserved_as_adopt(struct cpu_preserved_as *as);
int cpu_preserved_as_map(struct cpu_preserved_as *as, phys_addr_t pa,
			 unsigned long va, size_t size, pgprot_t prot);
void *cpu_preserved_as_alloc_page(void *arg);

/**
 * arch_cpu_preserved_as_map - Add one range to a preserved address space
 * @as: Address space to map into; @as->pgd is the root to populate.
 * @pa: Physical address of the range.
 * @va: Virtual address the range must appear at.
 * @size: Size of the range in bytes.
 * @prot: Protection to apply.
 *
 * Architecture backend for cpu_preserved_as_map().  Page table pages must be
 * obtained from cpu_preserved_as_alloc_page() with @as as its argument, so
 * that the core layer can preserve and later free them; the caller holds the
 * mapping lock and takes care of cache maintenance and of the TLB.
 *
 * Return: 0 on success, or a negative errno on failure.
 */
int arch_cpu_preserved_as_map(struct cpu_preserved_as *as, phys_addr_t pa,
			      unsigned long va, size_t size, pgprot_t prot);

/**
 * arch_cpu_preserved_as_flush_tlb - Publish preserved page table updates
 *
 * Called after every successful arch_cpu_preserved_as_map().  Architectures
 * whose preserved CPUs can hold stale translations for these address spaces
 * must invalidate them here; the others need do nothing.
 */
void arch_cpu_preserved_as_flush_tlb(void);

/**
 * arch_cpu_preserved_set_transition_as - Publish the default address space
 * @as: Address space a preserved CPU parks in when its workload has none.
 *
 * The value has to be readable from preserved text after the kexec, which is
 * architecture specific storage, so the core layer hands it over rather than
 * exporting a variable.
 */
void arch_cpu_preserved_set_transition_as(struct cpu_preserved_as *as);

int cpu_preserved_init_runtime_buffer(void);
int cpu_preserved_map_range(phys_addr_t pa, unsigned long va,
			    size_t size, pgprot_t prot);
int cpu_preserved_map_buffer(void *va, size_t size);
int arch_cpu_preserved_mpidr_to_cpu(u64 mpidr);
bool arch_cpu_preserved_is_active(void);
void arch_cpu_preserved_switch_pgd(phys_addr_t pgd_pa);

#else /* !CONFIG_LIVEUPDATE_CPU */

#define __cpu_preserved_text
#define __cpu_preserved_data

static inline bool cpu_is_preserved(int cpu) { return false; }
static inline bool cpu_preserved_is_incoming(int cpu) { return false; }
static inline bool cpu_preserved_should_exit(int cpu) { return true; }
static inline void cpu_preserved_park(int cpu) {}
static inline void cpu_preserved_set_dead(int cpu) {}
static inline void cpu_preserved_report_dead(void) {}
static inline const struct cpumask *cpu_get_preserved_mask(void)
{
	return cpu_none_mask;
}
static inline phys_addr_t cpu_preserved_get_text_pa(void) { return 0; }
static inline phys_addr_t cpu_preserved_get_data_pa(void) { return 0; }
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
static inline void cpu_preserved_set_workload_context(int cpu, void *ctx,
						      phys_addr_t pgd_pa) {}
static inline int cpu_preserved_get_stack_info(int cpu, phys_addr_t *pa,
					       unsigned long *va, size_t *size)
{
	return -EOPNOTSUPP;
}
static inline int cpu_preserved_get_pcpus_info(phys_addr_t *pa,
					       unsigned long *va, size_t *size)
{
	return -EOPNOTSUPP;
}
static inline void arch_cpu_preserved_kick(int cpu) {}
static inline void arch_cpu_preserved_park_wait(void) {}
static inline void arch_cpu_preserved_park_init(int cpu) {}
static inline void arch_cpu_preserved_early_init(void) {}
static inline void arch_cpu_preserved_park_finish(int cpu) {}
static inline void arch_cpu_preserved_dcache_clean(unsigned long start,
						   unsigned long end) {}
static inline void arch_cpu_preserved_dcache_inval(unsigned long start,
						   unsigned long end) {}
static inline void arch_cpu_preserved_wait_dead(int cpu) {}
static inline phys_addr_t cpu_preserved_get_pgd(int cpu) { return 0; }
static inline int arch_cpu_preserved_setup_buffer(struct page *text_page,
						  unsigned int text_nr_pages,
						  struct page *data_page,
						  unsigned int data_nr_pages)
{
	return 0;
}
static inline int cpu_preserved_init_runtime_buffer(void) { return 0; }
static inline int cpu_preserved_map_range(phys_addr_t pa, unsigned long va,
					  size_t size, pgprot_t prot) { return 0; }
static inline int cpu_preserved_map_buffer(void *va, size_t size) { return 0; }
static inline int arch_cpu_preserved_mpidr_to_cpu(u64 mpidr) { return -EINVAL; }
static inline bool arch_cpu_preserved_is_active(void) { return false; }
static inline void arch_cpu_preserved_switch_pgd(phys_addr_t pgd_pa) {}
static inline struct cpu_preserved_stack_context *
cpu_preserved_get_stack_context(void)
{
	return NULL;
}

#endif /* CONFIG_LIVEUPDATE_CPU */

/*
 * Object-granular wrappers around the arch dcache hooks.
 *
 * Every preserved-memory handshake flushes or invalidates a whole object, so
 * spell that out once instead of open-coding (addr, addr + size) at each call
 * site: the size can then never drift from the object it is supposed to cover.
 *
 * @p is a pointer to the object.  For a statically sized array, pass &array so
 * that sizeof(*(p)) is the size of the whole array rather than of one element.
 * Use the _sz() forms for flexible-array structures and for raw page buffers,
 * where the length is not derivable from the type.
 */
#define cpu_preserved_clean_sz(p, sz)					\
	arch_cpu_preserved_dcache_clean((unsigned long)(p),		\
					(unsigned long)(p) + (sz))
#define cpu_preserved_inval_sz(p, sz)					\
	arch_cpu_preserved_dcache_inval((unsigned long)(p),		\
					(unsigned long)(p) + (sz))
#define cpu_preserved_clean(p)		cpu_preserved_clean_sz(p, sizeof(*(p)))
#define cpu_preserved_inval(p)		cpu_preserved_inval_sz(p, sizeof(*(p)))

#endif /* _LINUX_CPU_PRESERVE_H */
