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
#include <linux/kho/abi/cpu.h>
#include <linux/list.h>
#include <linux/refcount.h>
#include <linux/smp.h>
#include <linux/types.h>

#ifndef __CPU_PRESERVED_RUNTIME__
#define cpu_preserved_sym(sym)		__cpu_preserved_##sym
#define __cpu_preserved_sym_asm(sym)	__asm__("__cpu_preserved_" #sym)
#else
#define cpu_preserved_sym(sym)		sym
#define __cpu_preserved_sym_asm(sym)
#endif

#ifdef CONFIG_LIVEUPDATE_CPU

#include <asm/cpu_preserve.h>
#include <asm/page.h>

/*
 * The preserved stack area holds the context block in its first page, an
 * unmapped guard page, then the stack.  It is naturally aligned, so the context
 * is found by masking the stack pointer.
 */
#ifndef CPU_PRESERVED_STACK_SIZE
#define CPU_PRESERVED_STACK_SIZE	(2 * THREAD_SIZE)
#endif
#define CPU_PRESERVED_STACK_GUARD	PAGE_SIZE
#define CPU_PRESERVED_STACK_BASE	(2 * PAGE_SIZE)
#define CPU_PRESERVED_STACK_HEADROOM	256
#define CPU_PRESERVED_STACK_MAGIC	0x435055505354414bULL	/* "CPUPSTAK" */

struct cpu_preserved_ser;

/**
 * struct cpu_preserved_stack_context - Context header at base of preserved CPU stack
 * @magic:            Validation signature (%CPU_PRESERVED_STACK_MAGIC).
 * @cpu:              Logical CPU identifier of the preserved physical core.
 * @oncore_busy:      True while an On-Core job is executing on this CPU.
 * @oncore_tickless:  True while an On-Core job is executing tickless (U64_MAX).
 * @reserved:         Must be zero.
 * @oncore_curr_job:  Pointer to the currently executing On-Core job, or 0.
 * @workload_context: Opaque owning workload or session context.
 * @session_pgd_pa:   Session root page table physical address, or 0.
 * @ser:              Preserved CPU descriptor in isolated address space.
 * @entry_fn:         Workload entry function to run.
 * @fault:            Exceptions taken by the preserved CPU (x86, arm64).
 * @x86:              Descriptor tables and exception stacks (x86).
 *
 * This structure lives at the base of a preserved CPU's dedicated stack and is
 * accessed by the preserved CPU during parking and workload execution. It is
 * private to the preserved CPU execution context of the kernel that allocated it.
 */
struct cpu_preserved_stack_context {
	u64 magic;
	u32 cpu;
	u8 oncore_busy;
	u8 oncore_tickless;
	u16 reserved;
	u64 oncore_curr_job;
	u64 workload_context;
	u64 session_pgd_pa;
	struct cpu_preserved_ser *ser;
	void (*entry_fn)(void *data);
#ifdef CONFIG_X86_64
	struct x86_preserved_fault fault;
	struct x86_preserved_cpu x86;
#elif defined(CONFIG_ARM64)
	struct arm64_preserved_fault fault;
#endif
};

static_assert(CPU_PRESERVED_STACK_SIZE > 0 &&
	      !(CPU_PRESERVED_STACK_SIZE & (CPU_PRESERVED_STACK_SIZE - 1)),
	      "the stack area size must be a power of 2 for natural alignment");
static_assert(offsetof(struct cpu_preserved_stack_context, magic) == 0,
	      "magic must lead: the struct is found by masking the stack pointer");
static_assert(sizeof(struct cpu_preserved_stack_context) <= CPU_PRESERVED_STACK_GUARD,
	      "the stack context must fit below the guard page");

/**
 * cpu_preserved_get_stack_context - Return the context block at the base of the preserved stack
 *
 * Masks the current stack pointer to %CPU_PRESERVED_STACK_SIZE alignment and
 * validates %CPU_PRESERVED_STACK_MAGIC.
 *
 * Return: Pointer to &struct cpu_preserved_stack_context if executing on a
 *         preserved CPU stack, or %NULL otherwise.
 */
static __always_inline struct cpu_preserved_stack_context *
cpu_preserved_get_stack_context(void)
{
	struct cpu_preserved_stack_context *sctx;

	sctx = (struct cpu_preserved_stack_context *)
		(current_stack_pointer & ~(CPU_PRESERVED_STACK_SIZE - 1));
	if (sctx->magic == CPU_PRESERVED_STACK_MAGIC)
		return sctx;
	return NULL;
}

extern char __cpu_preserved_text_start[], __cpu_preserved_text_end[];
extern char __cpu_preserved_data_start[], __cpu_preserved_data_end[];
extern char __cpu_preserved_rodata_end[];

static inline bool cpu_preserved_is_runtime_text(const void *fn)
{
	unsigned long addr = (unsigned long)fn;

	return addr >= (unsigned long)__cpu_preserved_text_start &&
	       addr < (unsigned long)__cpu_preserved_text_end;
}

bool cpu_is_preserved(int cpu);
bool cpu_preserved_is_stopped(int cpu);
u32 cpu_preserved_state(int cpu);
bool cpu_preserved_should_exit(void) __cpu_preserved_sym_asm(cpu_preserved_should_exit);
void cpu_preserved_set_dead(void) __cpu_preserved_sym_asm(cpu_preserved_set_dead);
void cpu_preserved_park(int cpu);
void cpu_preserved_park_loop(int cpu) __cpu_preserved_sym_asm(cpu_preserved_park_loop);

/**
 * arch_cpu_preserved_park_wait - Wait in a low-power state until kicked
 *
 * Returns after arch_cpu_preserved_kick(), or spuriously, so callers re-check
 * their condition.  A kick sent before the call is not lost.
 */
void arch_cpu_preserved_park_wait(void);
void arch_cpu_preserved_park_init(int cpu);
void arch_cpu_preserved_dcache_clean(unsigned long start, unsigned long end)
	__cpu_preserved_sym_asm(arch_cpu_preserved_dcache_clean);
void arch_cpu_preserved_dcache_inval(unsigned long start, unsigned long end)
	__cpu_preserved_sym_asm(arch_cpu_preserved_dcache_inval);

const struct cpumask *cpu_get_preserved_mask(void);
struct cpu_preserved_stack_context *cpu_preserved_get_sctx(int cpu);
int cpu_preserved_attach_workload(int cpu,
				  void (*entry_fn)(void *data), void *data);
int cpu_preserved_detach_workload(int cpu);
void cpu_preserved_set_workload_context(int cpu, void *ctx);

struct attribute_group;
extern const struct attribute_group cpu_preserve_attr_group;
extern const struct attribute_group cpu_preserve_root_attr_group;

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

/**
 * arch_cpu_preserved_kick - Signal or wake up a preserved physical CPU
 * @cpu: Logical CPU identifier.
 *
 * Architecture backend hook to wake a preserved CPU from arch_cpu_preserved_park_wait().
 *
 * Executed in normal text context.
 */
void arch_cpu_preserved_kick(int cpu);

/**
 * arch_cpu_preserved_hwid - Hardware identifier of a CPU
 * @cpu: Logical CPU identifier.
 *
 * Architecture backend hook that returns the identifier that
 * arch_match_cpu_phys_id() matches against @cpu.  It identifies a preserved
 * CPU across kernels, whose logical numbering may differ.
 *
 * Return: The hardware identifier of @cpu.
 */
u64 arch_cpu_preserved_hwid(unsigned int cpu);

/**
 * arch_cpu_preserved_early_init - Initialize the arch data of the runtime
 *
 * Architecture backend hook that initializes the data the preserved runtime
 * reads, such as the x86 preserved IDT.  Called once at boot, before the
 * runtime is copied: preserved CPUs run on the copy, which later writes to
 * the sections do not reach.
 */
void arch_cpu_preserved_early_init(void);

#ifndef arch_cpu_preserved_mode
/**
 * arch_cpu_preserved_mode - Modes of the kernel that preserved CPUs depend on
 *
 * Optional architecture backend hook.  The outgoing kernel records its value
 * in the handover data, and the incoming kernel refuses the handover unless
 * it returns the same value, such as the same x86 APIC mode.
 *
 * Return: A mask of architecture-defined bits, 0 if the hook is not provided.
 */
static inline u64 arch_cpu_preserved_mode(void)
{
	return 0;
}
#endif

/**
 * arch_cpu_preserved_park_finish - Architecture cleanup on park loop exit
 * @cpu: Logical CPU identifier.
 *
 * Architecture backend hook invoked when @cpu exits the preserved parking loop
 * (or on the fallback path if parking fails). May power down the CPU and not
 * return.
 */
void arch_cpu_preserved_park_finish(int cpu)
	__cpu_preserved_sym_asm(arch_cpu_preserved_park_finish);

/**
 * arch_cpu_preserved_park_on_stack - Switch stack and enter park loop
 * @cpu: Logical CPU identifier.
 * @stack_top: Top of the dedicated preserved stack.
 *
 * Architecture backend hook to switch to the preserved CPU stack and
 * invoke cpu_preserved_park_loop(). Does not return.
 *
 * Executed in normal text context during CPU teardown.
 */
void arch_cpu_preserved_park_on_stack(int cpu, unsigned long stack_top);

/**
 * arch_cpu_preserved_wait_dead - Finish stopping a preserved CPU
 * @cpu: Logical CPU identifier.
 *
 * Architecture backend hook called once @cpu has reported %CPU_PRESERVED_DEAD
 * or %CPU_PRESERVED_FAULTED, to report what the runtime recorded and to wait
 * for the CPU to be fully stopped.
 *
 * Executed in normal text context during CPU teardown.
 *
 * Return: 0 on success, or a negative errno if the CPU is not fully stopped.
 */
int arch_cpu_preserved_wait_dead(int cpu);

struct page;
struct liveupdate_session;

/*
 * struct cpu_preserved_session - The preserved CPUs of one LUO session
 * @node:     Entry on cpu_preserved_sessions or cpu_preserved_incoming_sessions.
 * @ref:      One reference for each CPU in @cpus, and one for each other user.
 * @lsession: The outgoing LUO session, or %NULL.
 * @ser:      KHO-preserved session metadata.
 * @as:       Isolated address space of the CPUs.
 * @cpus:     CPUs of the session that are preserved and parked.
 * @workload: Opaque host-side workload session pointer.
 * @incoming: Whether the previous kernel created the session.
 */
struct cpu_preserved_session {
	struct list_head node;
	refcount_t ref;
	struct liveupdate_session *lsession;
	struct cpu_preserved_session_ser *ser;
	struct cpu_preserved_as_ser *as;
	struct cpumask cpus;
	void *workload;
	bool incoming;
};

/**
 * arch_cpu_preserved_setup_buffer - Prepare the copy of the preserved runtime
 * @text_page: Head page of allocated preserved text memory.
 * @text_nr_pages: Number of pages in the preserved text buffer.
 * @data_page: Head page of allocated preserved data memory.
 * @data_nr_pages: Number of pages in the preserved data buffer.
 *
 * Architecture backend hook called once the .cpu_preserved.text and
 * .cpu_preserved.data sections have been copied to these pages, outside
 * Scratch memory, before any isolated address space maps them.
 *
 * Return: 0 on success, or a negative errno on failure.
 */
int arch_cpu_preserved_setup_buffer(struct page *text_page,
				    unsigned int text_nr_pages,
				    struct page *data_page,
				    unsigned int data_nr_pages);

struct cpu_preserved_as_ser *cpu_preserved_as_create(void);
void cpu_preserved_as_unpreserve(struct cpu_preserved_as_ser *ser);
void cpu_preserved_as_restore_free(struct cpu_preserved_as_ser *ser);
int cpu_preserved_as_map(struct cpu_preserved_as_ser *as, phys_addr_t pa,
			 unsigned long va, size_t size, pgprot_t prot);
void cpu_preserved_as_unmap(struct cpu_preserved_as_ser *as,
			    unsigned long va, size_t size);
void cpu_preserved_free_kho(void *va, bool is_incoming);
void *cpu_preserved_as_alloc_page(void *arg);

struct cpu_preserved_session *cpu_preserved_find_session(struct liveupdate_session *s);
struct cpu_preserved_session *cpu_preserved_session_get(struct liveupdate_session *s);
void cpu_preserved_session_put(struct cpu_preserved_session *ps);
struct cpu_preserved_as_ser *cpu_preserved_session_as(struct cpu_preserved_session *ps);
const struct cpumask *cpu_preserved_session_cpus(struct cpu_preserved_session *ps);
void cpu_preserved_session_set_workload(struct cpu_preserved_session *ps,
					void *workload, u64 pa);
void *cpu_preserved_session_workload(struct cpu_preserved_session *ps);

void arch_cpu_preserved_switch_pgd(phys_addr_t pgd_pa)
	__cpu_preserved_sym_asm(arch_cpu_preserved_switch_pgd);

/**
 * arch_cpu_preserved_as_map - Add one range to a preserved address space
 * @as: Address space to map into; its root PGD is at @as->pgd_pa.
 * @pa: Physical address of the range.
 * @va: Virtual address the range must appear at.
 * @size: Size of the range in bytes.
 * @prot: Protection to apply.
 *
 * Architecture backend for cpu_preserved_as_map(). Page table pages must be
 * obtained from cpu_preserved_as_alloc_page() with @as as its argument, so
 * that the core layer can preserve and later free them; the caller holds the
 * mapping lock.
 *
 * Return: 0 on success, or a negative errno on failure.
 */
int arch_cpu_preserved_as_map(struct cpu_preserved_as_ser *as, phys_addr_t pa,
			      unsigned long va, size_t size, pgprot_t prot);

/**
 * arch_cpu_preserved_as_unmap - Remove one range from a preserved address space
 * @as: Address space to unmap from; its root PGD is at @as->pgd_pa.
 * @va: Virtual address of the range to unmap.
 * @size: Size of the range in bytes.
 *
 * Clears page table entries covering [@va, @va + @size) in @as.
 *
 * Return: %true if any PTE was cleared, %false otherwise.
 */
bool arch_cpu_preserved_as_unmap(struct cpu_preserved_as_ser *as,
				 unsigned long va, size_t size);

/**
 * arch_cpu_preserved_as_flush_tlb - Flush translations removed by an unmap
 *
 * Called after arch_cpu_preserved_as_unmap() has cleared entries.  A range is
 * unmapped only once no preserved CPU uses it, right before it is freed, so
 * this only matters to architectures that must not leave stale translations
 * of memory that is reused.  Maps only add entries and need no flush.
 */
void arch_cpu_preserved_as_flush_tlb(void);

#else /* !CONFIG_LIVEUPDATE_CPU */

#include <linux/kexec_handover.h>

struct cpu_preserved_as_ser;
struct cpu_preserved_session;
struct liveupdate_session;

static inline struct cpu_preserved_session *
cpu_preserved_find_session(struct liveupdate_session *s)
{
	return NULL;
}

static inline bool cpu_preserved_is_runtime_text(const void *fn) { return false; }
static inline bool cpu_is_preserved(int cpu) { return false; }
static inline bool cpu_preserved_is_stopped(int cpu) { return true; }
static inline u32 cpu_preserved_state(int cpu) { return CPU_PRESERVED_DEAD; }
static inline void cpu_preserved_park(int cpu) {}
static inline void cpu_preserved_report_dead(void) {}
static inline bool cpu_preserved_should_exit(void) { return true; }
static inline void cpu_preserved_set_dead(void) {}
static inline void arch_cpu_preserved_park_wait(void) {}
static inline void arch_cpu_preserved_park_init(int cpu) {}
static inline void arch_cpu_preserved_dcache_clean(unsigned long start,
						   unsigned long end) {}
static inline void arch_cpu_preserved_kick(int cpu) {}
static inline void arch_cpu_preserved_early_init(void) {}
static inline void arch_cpu_preserved_park_finish(int cpu) {}
static inline void arch_cpu_preserved_dcache_inval(unsigned long start,
						   unsigned long end) {}
static inline int arch_cpu_preserved_wait_dead(int cpu) { return 0; }
static inline const struct cpumask *cpu_get_preserved_mask(void)
{
	return cpu_none_mask;
}

static inline struct cpu_preserved_stack_context *
cpu_preserved_get_sctx(int cpu)
{
	return NULL;
}

static inline void cpu_preserved_as_unmap(struct cpu_preserved_as_ser *as,
					  unsigned long va, size_t size) {}

static inline void cpu_preserved_free_kho(void *va, bool is_incoming)
{
	if (!va)
		return;
	if (is_incoming)
		kho_restore_free(va);
	else
		kho_unpreserve_free(va);
}

static inline int cpu_preserved_attach_workload(int cpu,
						void (*entry_fn)(void *data),
						void *data)
{
	return -EOPNOTSUPP;
}

static inline int cpu_preserved_detach_workload(int cpu)
{
	return -EOPNOTSUPP;
}

static inline void cpu_preserved_set_workload_context(int cpu, void *ctx) {}

static inline int arch_cpu_preserved_setup_buffer(struct page *text_page,
						  unsigned int text_nr_pages,
						  struct page *data_page,
						  unsigned int data_nr_pages)
{
	return 0;
}

static inline void arch_cpu_preserved_switch_pgd(phys_addr_t pgd_pa) {}
static __always_inline struct cpu_preserved_stack_context *
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
static __always_inline void cpu_preserved_clean_sz(const void *p, size_t sz)
{
	arch_cpu_preserved_dcache_clean((unsigned long)p, (unsigned long)p + sz);
}

static __always_inline void cpu_preserved_inval_sz(const void *p, size_t sz)
{
	arch_cpu_preserved_dcache_inval((unsigned long)p, (unsigned long)p + sz);
}

#define cpu_preserved_clean(p)		cpu_preserved_clean_sz(p, sizeof(*(p)))
#define cpu_preserved_inval(p)		cpu_preserved_inval_sz(p, sizeof(*(p)))

#endif /* _LINUX_CPU_PRESERVE_H */
