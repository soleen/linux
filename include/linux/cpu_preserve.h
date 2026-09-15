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
#include <linux/smp.h>
#include <linux/types.h>

#ifdef CONFIG_LIVEUPDATE_CPU

#include <asm/cpu_preserve.h>
#include <asm/page.h>

#define CPU_PRESERVED_STACK_ORDER	THREAD_SIZE_ORDER
#define CPU_PRESERVED_STACK_SIZE	THREAD_SIZE
#define CPU_PRESERVED_STACK_HEADROOM	256
#define CPU_PRESERVED_STACK_MAGIC	0x435055505354414bULL	/* "CPUPSTAK" */

struct cpu_preserved_ser;

/**
 * struct cpu_preserved_stack_context - Context header at base of preserved CPU stack
 * @magic:            Validation signature (%CPU_PRESERVED_STACK_MAGIC).
 * @cpu:              Logical CPU identifier of the preserved physical core.
 * @reserved:         Must be zero.
 * @workload_context: Opaque owning workload or session context.
 * @session_pgd_pa:   Session root page table physical address, or 0.
 * @ser:              Preserved CPU descriptor in isolated address space.
 * @entry_fn:         Workload entry function to run.
 *
 * This structure lives at the base of a preserved CPU's dedicated stack and is
 * accessed by the preserved CPU during parking and workload execution. It is
 * private to the preserved CPU execution context of the kernel that allocated it.
 */
struct cpu_preserved_stack_context {
	u64 magic;
	u32 cpu;
	u32 reserved;
	u64 workload_context;
	u64 session_pgd_pa;
	struct cpu_preserved_ser *ser;
	void (*entry_fn)(void *data);
};

static_assert(sizeof(struct cpu_preserved_stack_context) == 48);
static_assert(offsetof(struct cpu_preserved_stack_context, magic) == 0,
	      "magic must lead: the struct is found by masking the stack pointer");

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
 * All code in this section must run without compiler instrumentation, stack
 * protector checks, or shadow call stacks because per-CPU state and runtime
 * helpers in regular .text are overwritten during kexec before the incoming
 * kernel boots.
 *
 * Architecture-specific requirements (such as disabling external retpolines
 * and return thunks on x86) are supplied via ARCH_CPU_PRESERVED_TEXT.
 */
#ifndef ARCH_CPU_PRESERVED_TEXT
#define ARCH_CPU_PRESERVED_TEXT
#endif

#define __cpu_preserved_text					\
	__noinstr_section(".text.cpu_preserved")		\
	__no_stack_protector					\
	__no_sanitize_undefined					\
	__noscs							\
	ARCH_CPU_PRESERVED_TEXT
#define __cpu_preserved_data	__section(".data.cpu_preserved")

extern char __cpu_preserved_text_start[], __cpu_preserved_text_end[];
extern char __cpu_preserved_data_start[], __cpu_preserved_data_end[];
bool cpu_is_preserved(int cpu);
bool cpu_preserved_should_exit(int cpu);
void cpu_preserved_set_dead(int cpu);
void cpu_preserved_park(int cpu);
void cpu_preserved_park_loop(int cpu);
const struct cpumask *cpu_get_preserved_mask(void);
phys_addr_t cpu_preserved_get_pgd(int cpu);
int cpu_preserved_attach_workload(int cpu,
				  void (*entry_fn)(void *data), void *data);
int cpu_preserved_detach_workload(int cpu);
void cpu_preserved_set_workload_context(int cpu, void *ctx, phys_addr_t pgd_pa);

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
 * @cpu: Logical CPU identifier.
 *
 * Architecture backend hook to configure the physical core (e.g., disable
 * or mask local interrupts) upon entering the park loop.
 *
 * This function must be placed in the __cpu_preserved_text section.
 */
void arch_cpu_preserved_park_init(int cpu);

/**
 * arch_cpu_preserved_early_init - Arch early-boot init for incoming preserved CPUs
 *
 * Called during early boot in the incoming kernel when preserved physical CPUs
 * are adopted from KHO metadata.
 */
void arch_cpu_preserved_early_init(void);

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

struct cpu_preserved_as_ser *cpu_preserved_as_create(void);
void cpu_preserved_as_unpreserve(struct cpu_preserved_as_ser *ser);
void cpu_preserved_as_restore_free(struct cpu_preserved_as_ser *ser);
int cpu_preserved_as_map(struct cpu_preserved_as_ser *as, phys_addr_t pa,
			 unsigned long va, size_t size, pgprot_t prot);

#else /* !CONFIG_LIVEUPDATE_CPU */

#define __cpu_preserved_text
#define __cpu_preserved_data

static inline bool cpu_is_preserved(int cpu) { return false; }
static inline bool cpu_preserved_should_exit(int cpu) { return true; }
static inline void cpu_preserved_park(int cpu) {}
static inline void cpu_preserved_set_dead(int cpu) {}
static inline void cpu_preserved_report_dead(void) {}
static inline const struct cpumask *cpu_get_preserved_mask(void)
{
	return cpu_none_mask;
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

static inline void cpu_preserved_set_workload_context(int cpu, void *ctx,
						      phys_addr_t pgd_pa) {}
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

static inline int arch_cpu_preserved_mpidr_to_cpu(u64 mpidr) { return -EINVAL; }
static inline bool arch_cpu_preserved_is_active(void) { return false; }
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
#define cpu_preserved_clean_sz(p, sz)					\
	arch_cpu_preserved_dcache_clean((unsigned long)(p),		\
					(unsigned long)(p) + (sz))
#define cpu_preserved_inval_sz(p, sz)					\
	arch_cpu_preserved_dcache_inval((unsigned long)(p),		\
					(unsigned long)(p) + (sz))
#define cpu_preserved_clean(p)		cpu_preserved_clean_sz(p, sizeof(*(p)))
#define cpu_preserved_inval(p)		cpu_preserved_inval_sz(p, sizeof(*(p)))

/**
 * cpu_preserved_memset - Compiler-barrier-safe byte fill for preserved runtime code
 * @s: Destination buffer.
 * @c: Byte value to fill.
 * @n: Number of bytes to fill.
 *
 * Uses WRITE_ONCE() per byte so the compiler's loop-idiom pass cannot replace
 * the loop with a call to the unmapped host kernel memset() inside
 * __cpu_preserved_text.
 *
 * Return: @s.
 */
static __always_inline void *cpu_preserved_memset(void *s, int c, size_t n)
{
	unsigned char *p = s;

	while (n--)
		WRITE_ONCE(*p++, (unsigned char)c);
	return s;
}

/**
 * cpu_preserved_memcpy - Compiler-barrier-safe byte copy for preserved runtime code
 * @dest: Destination buffer.
 * @src:  Source buffer.
 * @n:    Number of bytes to copy.
 *
 * Uses READ_ONCE()/WRITE_ONCE() per byte so the compiler's loop-idiom pass
 * cannot replace the loop with a call to the unmapped host kernel memcpy()
 * inside __cpu_preserved_text.
 *
 * Return: @dest.
 */
static __always_inline void *cpu_preserved_memcpy(void *dest, const void *src, size_t n)
{
	const unsigned char *s = src;
	unsigned char *d = dest;

	while (n--)
		WRITE_ONCE(*d++, READ_ONCE(*s++));
	return dest;
}

static __always_inline void cpu_preserved_relax(void)
{
#if defined(CONFIG_ARM64)
	asm volatile("yield" ::: "memory");
#else
	cpu_relax();
#endif
}

static __always_inline u32 cpu_preserved_cmpxchg32(u32 *ptr, u32 old, u32 new)
{
#if defined(CONFIG_ARM64)
	return __lse_ll_sc_body(_cmpxchg_case_mb_32, ptr, old, new);
#else
	return raw_cmpxchg(ptr, old, new);
#endif
}

#endif /* _LINUX_CPU_PRESERVE_H */
