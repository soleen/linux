// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * Physical CPU Preservation Framework for Live Update
 */

/**
 * DOC: Preserved CPU Subsystem
 *
 * Provides mechanism to isolate running physical CPUs from host scheduling
 * and preserve their hardware execution context across a live update kexec
 * reboot without resetting the core or re-executing firmware/bootloader code.
 *
 * Design Overview
 * ===============
 *
 * Physical CPU preservation allows a running kernel to hand over dedicated
 * hardware cores to an incoming kernel across a live update kexec reboot while
 * keeping those cores active. Preserved cores do not participate in the normal
 * secondary CPU boot path of the incoming kernel, enabling workloads to run
 * with minimal interruption.
 *
 * The preservation mechanism operates in four phases:
 *
 * 1. **Preparation:** Target CPUs are removed from the host scheduler and
 *    Linux CPU hotplug machinery (remove_cpu()), placed into a dedicated
 *    per-CPU parking loop (cpu_preserved_park()) running on dedicated
 *    preserved stacks, and switched to isolated page tables.
 *
 * 2. **KHO Registration:** Preserved CPU execution state, stacks, runtime
 *    buffers, and page tables are registered with the Kexec Handover (KHO)
 *    subsystem so the physical memory survives the kexec reboot.
 *
 * 3. **Handover:** The host executes kexec. The new kernel boots on CPU 0
 *    (or designated boot CPU) while preserved CPUs continue running in their
 *    isolated parking loop in preserved memory.
 *
 * 4. **Retrieval & Reclamation:** The incoming kernel discovers preserved
 *    CPUs during early boot from KHO metadata, marks them as preserved, and
 *    skips them during normal SMP initialization. When userspace retrieves the
 *    preserved CPU file descriptors via LUO, the incoming kernel reconnects
 *    to the preserved cores, allowing workloads to re-attach or continue
 *    uninterrupted execution on-core.
 *
 * This subsystem provides the generic, hypervisor-agnostic foundation for
 * physical CPU preservation.
 *
 * Lifecycle
 * =========
 *
 * CPU lifecycle state progression::
 *
 *     +-------------------------------------------------------------+
 *     |                          ONLINE                             |
 *     |               (Normal host task scheduling)                 |
 *     +-------------------------------------------------------------+
 *                                    |
 *                                    | preserve (via LUO fd)
 *                                    v
 *     +-------------------------------------------------------------+
 *     |                     PRESERVED_PARKED                        |
 *     |          (Removed from scheduler, loops in park)            |
 *     +-------------------------------------------------------------+
 *                                    |
 *                                    | [Live Update: kexec]
 *                                    v
 *     +-------------------------------------------------------------+
 *     |                     INCOMING PRESERVED                      |
 *     |         (Parked on-core, skipped in secondary boot)         |
 *     |       (State restored upon session retrieve; stays running) |
 *     +-------------------------------------------------------------+
 *                                    |
 *                                    | unpreserve / finish (via LUO session)
 *                                    v
 *     +-------------------------------------------------------------+
 *     |                          OFFLINE                            |
 *     |            (Park loop exited, architecturally idle)         |
 *     +-------------------------------------------------------------+
 *                                    |
 *                                    | automatic add_cpu()
 *                                    v
 *     +-------------------------------------------------------------+
 *     |                          ONLINE                             |
 *     |                (Rejoined host scheduling)                   |
 *     +-------------------------------------------------------------+
 *
 * File Descriptor Binding
 * =======================
 *
 * 1. **Sysfs control file:** Each hotpluggable CPU exports a read-only sysfs
 *    attribute at ``/sys/devices/system/cpu/cpu<N>/preserve``. The file
 *    descriptor of this file handles the lifecycle of the preserved CPU.
 *
 * 2. **Preservation via LUO:** Userspace opens this file and registers the fd
 *    with LUO. Preserving the file offlines the core from host scheduling,
 *    migrates its interrupts and tasks, transitions the CPU from online into
 *    the parked state (cpu_preserved_park()), and adds the core to the
 *    preserved CPU session while keeping it parked until a workload is
 *    attached.
 *
 * 3. **KHO and memory preservation:** The parking loop, dedicated preserved
 *    CPU stacks, runtime execution buffers outside Scratch memory, and
 *    preserved CPU state reside in memory preserved across kexec via KHO.
 *
 * 4. **Incoming boot:** During early boot, the incoming kernel restores the
 *    preserved CPU mask from the KHO FLB before secondary SMP bringup and
 *    skips bringing preserved cores online, maintaining isolation.
 *
 * 5. **Retrieval and unpreservation:** When userspace retrieves the session in
 *    the incoming kernel, it receives the open ``preserve`` file descriptor.
 *    Retrieving the session reconnects the descriptors and restores the
 *    preserved CPU session state while keeping the core running. Finalizing the
 *    session (``finish``) or closing the fd unpreserves the CPU, signaling the
 *    core to exit the parking loop and automatically restoring it online via
 *    add_cpu().
 *
 * Architecture Requirements
 * =========================
 *
 * In addition to CPU hotplug (``CONFIG_HOTPLUG_CPU``), an architecture
 * selecting ``ARCH_SUPPORTS_LIVEUPDATE_CPU`` must provide:
 *
 * - **Linker script:** Include ``CPU_PRESERVED_TEXT`` in
 *   ``arch/<arch>/kernel/vmlinux.lds.S`` within the executable text section.
 *
 * - **Preserved text section:** Functions executed by a parked core or during
 *   live update transitions must be compiled into an isolated ``*.preserved.o``
 *   object so their instructions reside in the KHO-preserved
 *   ``.cpu_preserved.text`` section and their symbols are prefixed with
 *   ``__cpu_preserved_``. These are the ``arch_cpu_preserved_*()`` hooks
 *   documented in ``include/linux/cpu_preserve.h``.
 *
 * - **Address-space mapping hooks:** arch_cpu_preserved_as_map() and
 *   arch_cpu_preserved_as_flush_tlb() populate and manage isolated page tables
 *   built by the core layer using cpu_preserved_as_alloc_page().
 *
 * - **Buffer relocation hook:** arch_cpu_preserved_setup_buffer() relocates
 *   preserved text and data sections outside KHO Scratch memory so the
 *   incoming kernel can unpack safely.
 *
 * - **CPU hotplug and stop-IPI isolation:** Exclude preserved CPUs from stop
 *   signals (NMI or stop IPIs in the machine reboot and crash paths), and
 *   avoid tearing down local interrupt controllers (LAPIC, GIC CPU interface)
 *   during CPU disable when the core is being preserved.
 *
 * Isolated Address Space
 * ======================
 *
 * A preserved core does not run on the kernel's own page tables. Before it is
 * handed over, an isolated page table (struct cpu_preserved_as_ser) is created
 * per-session containing only what on-core execution needs, so that a core
 * still running a workload cannot touch memory the new kernel has taken
 * ownership of:
 *
 * - Preserved text and read-only data, ``PAGE_KERNEL_ROX``
 *   (``.cpu_preserved.text``) -- park loops, world-switch routines, ops
 *   vector tables, and exception stubs;
 * - Preserved writable globals, ``PAGE_KERNEL`` NX
 *   (``.cpu_preserved.data``) -- state machines, session descriptors,
 *   and the preserved-CPU masks;
 * - The per-CPU dedicated preserved stack, ``PAGE_KERNEL`` NX;
 * - The KHO-preserved workload state pages, ``PAGE_KERNEL`` NX;
 * - Hardware control MMIO, ``PAGE_KERNEL_IO``, only where the interrupt
 *   controller still requires it (e.g., GICv3 in system-register mode needs
 *   none).
 *
 * Deliberately absent: the linear direct map, all user address ranges, the
 * kernel heap, vmalloc, modules, and BPF JIT. Guest memory is not mapped
 * either -- it is reached through stage-2 translation.
 *
 * On arm64 these mappings are built with trans_pgd_map_range(), on x86 with
 * the identity-map helpers in ``arch/x86/mm/ident_map.c``.
 *
 * Workload Integration
 * ====================
 *
 * Physical cores preserved across live update are grouped per LUO session in a
 * &struct cpu_preserved_session (retrieved via cpu_preserved_session_get()),
 * which owns the session's isolated address space and preserved CPU bitmap:
 *
 * - When a CPU file is preserved or unpreserved, the session updates its CPU
 *   bitmap while leaving the core parked until a workload is attached.
 * - A workload subsystem attaches its entry callback to preserved cores via
 *   cpu_preserved_attach_workload() and detaches it via
 *   cpu_preserved_detach_workload().
 * - At kexec handover, the session state is serialized into the preserved CPU
 *   descriptor and reconstructed in the incoming kernel upon retrieval or
 *   session finish.
 */

#define pr_fmt(fmt) "cpu_preserve: " fmt

#include <linux/cpu.h>
#include <linux/cpu_preserve.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/device/bus.h>
#include <linux/kexec.h>
#include <linux/kexec_handover.h>
#include <linux/kho/abi/cpu.h>
#include <linux/kho_block.h>
#include <linux/liveupdate.h>
#include <linux/mm.h>
#include <linux/objtool.h>
#include <linux/reboot.h>
#include <linux/refcount.h>
#include <linux/string.h>

#include <asm/sections.h>

extern cpumask_t cpu_preserved_mask __cpu_preserved_sym_asm(cpu_preserved_mask);

/*
 * struct cpu_preserved_state - Host-side preserved CPU state (incoming or outgoing)
 * @mask: Mask of preserved CPUs.
 * @cpus: Array of pointers to per-CPU serialized state in preserved memory.
 */
struct cpu_preserved_state {
	cpumask_t mask;
	struct cpu_preserved_ser **cpus;
};

static DEFINE_MUTEX(cpu_preserved_lock);
static struct cpu_preserved_state cpu_preserved_incoming;
static struct cpu_preserved_state cpu_preserved_outgoing;
static struct cpu_preserved_global_ser *cpu_preserved_global_ser;

static struct page *cpu_preserved_text_pages;
static unsigned int cpu_preserved_text_order;
static struct page *cpu_preserved_data_pages;
static unsigned int cpu_preserved_data_order;
static bool cpu_preserved_runtime_preserved;

struct cpu_preserved_as_ctx {
	struct list_head list;
	struct cpu_preserved_as_ser *ser;
	struct kho_block_set block_set;
	struct kho_block_set_it it;
};

static DEFINE_MUTEX(cpu_preserved_as_map_lock);
static LIST_HEAD(cpu_preserved_as_list);

static struct cpu_preserved_as_ctx *
cpu_preserved_as_find_ctx(struct cpu_preserved_as_ser *as)
{
	struct cpu_preserved_as_ctx *ctx;

	list_for_each_entry(ctx, &cpu_preserved_as_list, list) {
		if (ctx->ser == as)
			return ctx;
	}
	return NULL;
}

static phys_addr_t cpu_preserved_get_text_pa(void)
{
	return cpu_preserved_text_pages ? page_to_phys(cpu_preserved_text_pages) : 0;
}

static phys_addr_t cpu_preserved_get_data_pa(void)
{
	return cpu_preserved_data_pages ? page_to_phys(cpu_preserved_data_pages) : 0;
}

static void cpu_preserved_sync_global_ser(void)
{
	struct cpu_preserved_global_ser *ser = cpu_preserved_global_ser;

	if (!ser)
		return;

	bitmap_to_arr64(ser->cpu_preserved_bitmap,
			cpumask_bits(&cpu_preserved_mask), nr_cpu_ids);
	if (cpu_preserved_text_pages) {
		ser->text_runtime_pa = page_to_phys(cpu_preserved_text_pages);
		ser->text_runtime_size =
			(1UL << cpu_preserved_text_order) * PAGE_SIZE;
	}
	if (cpu_preserved_data_pages) {
		ser->data_runtime_pa = page_to_phys(cpu_preserved_data_pages);
		ser->data_runtime_size =
			(1UL << cpu_preserved_data_order) * PAGE_SIZE;
	}
	cpu_preserved_clean_sz(ser,
			       struct_size(ser, cpu_preserved_bitmap, ser->nr_cpu_words));
}

void cpu_preserved_free_kho(void *va, bool is_incoming)
{
	struct folio *folio;

	if (!va)
		return;

	if (is_incoming) {
		folio = kho_restore_folio(__pa(va));
		if (!WARN_ON(!folio)) {
			cpu_preserved_as_unmap(NULL, (unsigned long)va,
					       folio_size(folio));
			folio_put(folio);
		}
	} else {
		folio = virt_to_folio(va);
		cpu_preserved_as_unmap(NULL, (unsigned long)va,
				       folio_size(folio));
		kho_unpreserve_folio(folio);
		folio_put(folio);
	}
}

/**
 * cpu_preserved_as_alloc_page - Allocate a page table page for @arg
 * @arg: The struct cpu_preserved_as_ser being populated.
 *
 * Page table allocator handed to the architecture page table builders.
 *
 * Return: A zeroed, preserved page, or NULL.
 */
void *cpu_preserved_as_alloc_page(void *arg)
{
	struct cpu_preserved_as_ser *as = arg;
	struct cpu_preserved_as_ctx *ctx;
	u64 *pa_entry;
	void *ptr;

	ctx = cpu_preserved_as_find_ctx(as);
	if (WARN_ON_ONCE(!ctx))
		return NULL;

	if (kho_block_set_grow(&ctx->block_set, as->nr_pgtable_pages + 1))
		return NULL;

	ptr = kho_alloc_preserve(PAGE_SIZE);
	if (IS_ERR_OR_NULL(ptr)) {
		kho_block_set_shrink(&ctx->block_set, as->nr_pgtable_pages);
		return NULL;
	}

	if (!ctx->it.block) {
		kho_block_set_it_init(&ctx->it, &ctx->block_set);
		as->pg_tables.phys = kho_block_set_head_pa(&ctx->block_set);
	}

	pa_entry = kho_block_set_it_reserve_entry(&ctx->it);
	if (WARN_ON_ONCE(!pa_entry)) {
		kho_unpreserve_free(ptr);
		kho_block_set_shrink(&ctx->block_set, as->nr_pgtable_pages);
		return NULL;
	}

	cpu_preserved_clean_sz(ptr, PAGE_SIZE);
	*pa_entry = virt_to_phys(ptr);
	as->nr_pgtable_pages++;

	return ptr;
}

/**
 * cpu_preserved_as_map - Map one range into one preserved address space
 * @as: Address space to map into.
 * @pa: Physical address of the range.
 * @va: Virtual address the range must appear at.
 * @size: Size of the range in bytes.
 * @prot: Protection to apply.
 *
 * Return: 0 on success, negative errno on failure.
 */
int cpu_preserved_as_map(struct cpu_preserved_as_ser *as, phys_addr_t pa,
			 unsigned long va, size_t size, pgprot_t prot)
{
	struct cpu_preserved_as_ctx *ctx;

	guard(mutex)(&cpu_preserved_as_map_lock);
	ctx = cpu_preserved_as_find_ctx(as);
	if (WARN_ON_ONCE(!ctx))
		return -EINVAL;

	return arch_cpu_preserved_as_map(as, pa, va, size, prot);
}

/**
 * cpu_preserved_as_unmap - Unmap a virtual address range from preserved address space(s)
 * @as:   Address space to unmap from, or %NULL to unmap from all active preserved ASes.
 * @va:   Virtual address of the range to unmap.
 * @size: Size of the range in bytes.
 */
void cpu_preserved_as_unmap(struct cpu_preserved_as_ser *as,
			    unsigned long va, size_t size)
{
	struct cpu_preserved_as_ctx *ctx;
	bool unmapped = false;

	if (!va || !size)
		return;

	guard(mutex)(&cpu_preserved_as_map_lock);
	if (as) {
		if (as->pgd_pa)
			unmapped = arch_cpu_preserved_as_unmap(as, va, size);
	} else {
		list_for_each_entry(ctx, &cpu_preserved_as_list, list) {
			if (ctx->ser && ctx->ser->pgd_pa &&
			    arch_cpu_preserved_as_unmap(ctx->ser, va, size))
				unmapped = true;
		}
	}

	if (unmapped)
		arch_cpu_preserved_as_flush_tlb();
}

static int cpu_preserved_init_runtime_buffer(void);

static int cpu_preserved_as_map_runtime(struct cpu_preserved_as_ser *as)
{
	unsigned long text_start = (unsigned long)__cpu_preserved_text_start;
	unsigned long data_start = (unsigned long)__cpu_preserved_data_start;
	size_t text_sz = (unsigned long)__cpu_preserved_text_end - text_start;
	size_t data_sz = (unsigned long)__cpu_preserved_data_end - data_start;
	int ret;

	ret = cpu_preserved_as_map(as, cpu_preserved_get_text_pa(),
				   text_start, text_sz, PAGE_KERNEL_ROX);
	if (ret)
		return ret;

	return cpu_preserved_as_map(as, cpu_preserved_get_data_pa(),
				    data_start, data_sz, PAGE_KERNEL);
}

/**
 * cpu_preserved_as_create - Build a new preserved address space
 *
 * Allocates a root page table and maps the preserved text and data into it.
 *
 * Return: The new address space, or an ERR_PTR() on failure.
 */
struct cpu_preserved_as_ser *cpu_preserved_as_create(void)
{
	struct cpu_preserved_as_ctx *ctx;
	struct cpu_preserved_as_ser *as;
	void *pgd;
	int ret;

	ret = cpu_preserved_init_runtime_buffer();
	if (ret)
		return ERR_PTR(ret);

	as = kho_alloc_preserve(sizeof(*as));
	if (IS_ERR(as))
		return as;

	memset(as, 0, sizeof(*as));

	ctx = kzalloc_obj(*ctx);
	if (!ctx) {
		kho_unpreserve_free(as);
		return ERR_PTR(-ENOMEM);
	}

	ctx->ser = as;
	kho_block_set_init(&ctx->block_set, sizeof(u64));

	scoped_guard(mutex, &cpu_preserved_as_map_lock) {
		list_add(&ctx->list, &cpu_preserved_as_list);
		pgd = cpu_preserved_as_alloc_page(as);
		if (!pgd) {
			list_del(&ctx->list);
			kho_block_set_destroy(&ctx->block_set);
			kfree(ctx);
			kho_unpreserve_free(as);
			return ERR_PTR(-ENOMEM);
		}
		as->pgd_pa = virt_to_phys(pgd);
		cpu_preserved_clean(as);
	}

	ret = cpu_preserved_as_map_runtime(as);
	if (ret) {
		cpu_preserved_as_unpreserve(as);
		return ERR_PTR(ret);
	}

	return as;
}

/**
 * cpu_preserved_as_adopt - Register an incoming preserved address space
 * @ser: Address space descriptor recovered from preserved memory.
 */
void cpu_preserved_as_adopt(struct cpu_preserved_as_ser *ser)
{
	struct cpu_preserved_as_ctx *ctx;

	if (!ser)
		return;

	guard(mutex)(&cpu_preserved_as_map_lock);
	if (cpu_preserved_as_find_ctx(ser))
		return;

	ctx = kzalloc_obj(*ctx);
	if (!ctx)
		return;

	ctx->ser = ser;
	list_add(&ctx->list, &cpu_preserved_as_list);
}

/**
 * cpu_preserved_as_unpreserve - Free an outgoing preserved address space
 * @ser: Address space descriptor to release.
 */
void cpu_preserved_as_unpreserve(struct cpu_preserved_as_ser *ser)
{
	struct cpu_preserved_as_ctx *ctx;
	struct kho_block_set_it it;
	u64 *pa_entry;

	if (!ser)
		return;

	scoped_guard(mutex, &cpu_preserved_as_map_lock) {
		ctx = cpu_preserved_as_find_ctx(ser);
		if (ctx) {
			kho_block_set_it_init(&it, &ctx->block_set);
			while ((pa_entry = kho_block_set_it_read_entry(&it)))
				kho_unpreserve_free(phys_to_virt(*pa_entry));
			list_del(&ctx->list);
			kho_block_set_destroy(&ctx->block_set);
			kfree(ctx);
		}
	}
	kho_unpreserve_free(ser);
}

/**
 * cpu_preserved_as_restore_free - Free an incoming preserved address space
 * @ser: Address space descriptor recovered from preserved memory.
 */
void cpu_preserved_as_restore_free(struct cpu_preserved_as_ser *ser)
{
	struct cpu_preserved_as_ctx *ctx;
	struct kho_block_set bs;
	struct kho_block_set_it it;
	u64 *pa_entry;

	if (!ser)
		return;

	scoped_guard(mutex, &cpu_preserved_as_map_lock) {
		ctx = cpu_preserved_as_find_ctx(ser);
		if (ctx) {
			list_del(&ctx->list);
			kfree(ctx);
		}
	}

	kho_block_set_init(&bs, sizeof(u64));
	if (!kho_block_set_restore(&bs, ser->pg_tables.phys)) {
		kho_block_set_it_init(&it, &bs);
		while ((pa_entry = kho_block_set_it_read_entry(&it)))
			kho_restore_free(phys_to_virt(*pa_entry));
		kho_block_set_destroy(&bs);
	}
	kho_restore_free(ser);
}

static void cpu_preserved_preserve_runtime_buffer(void)
{
	lockdep_assert_held(&cpu_preserved_lock);

	if (cpu_preserved_runtime_preserved)
		return;

	if (WARN_ON_ONCE(kho_preserve_pages(cpu_preserved_text_pages,
					    1 << cpu_preserved_text_order)))
		return;
	if (WARN_ON_ONCE(kho_preserve_pages(cpu_preserved_data_pages,
					    1 << cpu_preserved_data_order)))
		return;

	cpu_preserved_runtime_preserved = true;
}

static void cpu_preserved_unpreserve_runtime_buffer(void)
{
	lockdep_assert_held(&cpu_preserved_lock);

	if (!cpu_preserved_runtime_preserved)
		return;

	kho_unpreserve_pages(cpu_preserved_text_pages,
			     1 << cpu_preserved_text_order);
	kho_unpreserve_pages(cpu_preserved_data_pages,
			     1 << cpu_preserved_data_order);

	cpu_preserved_runtime_preserved = false;
}

static int cpu_preserved_init_runtime_buffer_locked(void)
{
	size_t text_size = (unsigned long)__cpu_preserved_text_end -
			   (unsigned long)__cpu_preserved_text_start;
	size_t data_size = (unsigned long)__cpu_preserved_data_end -
			   (unsigned long)__cpu_preserved_data_start;
	unsigned int text_nr_pages = DIV_ROUND_UP(text_size, PAGE_SIZE);
	unsigned int data_nr_pages = DIV_ROUND_UP(data_size, PAGE_SIZE);
	int ret;

	lockdep_assert_held(&cpu_preserved_lock);

	if (cpu_preserved_text_pages) {
		cpu_preserved_preserve_runtime_buffer();
		return 0;
	}

	cpu_preserved_text_order = get_order(text_size);
	cpu_preserved_text_pages = alloc_pages(GFP_KERNEL, cpu_preserved_text_order);
	if (!cpu_preserved_text_pages)
		return -ENOMEM;

	cpu_preserved_data_order = get_order(data_size);
	cpu_preserved_data_pages = alloc_pages(GFP_KERNEL, cpu_preserved_data_order);
	if (!cpu_preserved_data_pages) {
		__free_pages(cpu_preserved_text_pages, cpu_preserved_text_order);
		cpu_preserved_text_pages = NULL;
		return -ENOMEM;
	}

	memcpy(page_address(cpu_preserved_text_pages),
	       __cpu_preserved_text_start, text_size);
	memcpy(page_address(cpu_preserved_data_pages),
	       __cpu_preserved_data_start, data_size);

	ret = arch_cpu_preserved_setup_buffer(cpu_preserved_text_pages,
					      text_nr_pages,
					      cpu_preserved_data_pages,
					      data_nr_pages);
	if (ret)
		goto err_free;

	cpu_preserved_preserve_runtime_buffer();
	return 0;

err_free:
	__free_pages(cpu_preserved_data_pages, cpu_preserved_data_order);
	__free_pages(cpu_preserved_text_pages, cpu_preserved_text_order);
	cpu_preserved_data_pages = NULL;
	cpu_preserved_text_pages = NULL;
	return ret;
}

/**
 * cpu_preserved_init_runtime_buffer - Allocate execution buffer outside Scratch
 *
 * Return: 0 on success, or negative error code on allocation/setup failure.
 */
static int cpu_preserved_init_runtime_buffer(void)
{
	guard(mutex)(&cpu_preserved_lock);

	return cpu_preserved_init_runtime_buffer_locked();
}

static bool cpu_preserved_is_incoming(int cpu)
{
	if ((unsigned int)cpu >= CONFIG_NR_CPUS)
		return false;
	return cpumask_test_cpu(cpu, &cpu_preserved_incoming.mask);
}

static struct cpu_preserved_ser *cpu_preserved_get_ser(int cpu)
{
	if ((unsigned int)cpu >= nr_cpu_ids)
		return NULL;

	if (cpu_preserved_is_incoming(cpu))
		return cpu_preserved_incoming.cpus ? cpu_preserved_incoming.cpus[cpu] : NULL;

	return cpu_preserved_outgoing.cpus ? cpu_preserved_outgoing.cpus[cpu] : NULL;
}

static void *cpu_preserved_stack_va(int cpu)
{
	struct cpu_preserved_ser *ser;
	phys_addr_t pa;

	ser = cpu_preserved_get_ser(cpu);
	if (!ser)
		return NULL;

	cpu_preserved_inval(&ser->stack_pa);
	pa = READ_ONCE(ser->stack_pa);
	if (!pa)
		return NULL;

	return phys_to_virt(pa);
}

struct cpu_preserved_stack_context *cpu_preserved_get_sctx(int cpu)
{
	struct cpu_preserved_stack_context *sctx = cpu_preserved_stack_va(cpu);

	if (sctx && sctx->magic == CPU_PRESERVED_STACK_MAGIC)
		return sctx;
	return NULL;
}

/**
 * cpu_get_preserved_mask - Get the mask of all currently preserved CPUs
 *
 * Return: Read-only pointer to the cpumask of preserved CPUs.
 */
const struct cpumask *cpu_get_preserved_mask(void)
{
	return &cpu_preserved_mask;
}

static void cpu_signal_exit(int cpu)
{
	struct cpu_preserved_ser *ser = cpu_preserved_get_ser(cpu);

	if (ser) {
		u32 old;

		cpu_preserved_inval(ser);
		old = READ_ONCE(ser->state);
		while (old != CPU_PRESERVED_DEAD &&
		       old != CPU_PRESERVED_EXITING) {
			if (try_cmpxchg(&ser->state, &old,
					CPU_PRESERVED_EXITING)) {
				cpu_preserved_clean(ser);
				break;
			}
		}
	}
}

#define CPU_WAIT_PARKED_TIMEOUT_US	5000000
#define CPU_WAIT_PARKED_STEP_US		50

static int cpu_wait_parked(int cpu)
{
	struct cpu_preserved_ser *ser = cpu_preserved_get_ser(cpu);
	int i;

	if (!ser)
		return -ENODEV;

	for (i = 0; i < CPU_WAIT_PARKED_TIMEOUT_US / CPU_WAIT_PARKED_STEP_US; i++) {
		cpu_preserved_inval(ser);
		if (smp_load_acquire(&ser->state) == CPU_PRESERVED_PARKED)
			return 0;
		udelay(CPU_WAIT_PARKED_STEP_US);
	}

	pr_err("Timed out waiting for preserved cpu %d to park (state=%u)\n",
	       cpu, READ_ONCE(ser->state));
	return -ETIMEDOUT;
}

#define CPU_WAIT_DEAD_TIMEOUT_US	20000000
#define CPU_WAIT_DEAD_STEP_US		100
#define CPU_WAIT_DEAD_KICK_STEPS	50

static int cpu_wait_dead(int cpu)
{
	struct cpu_preserved_stack_context *sctx = cpu_preserved_stack_va(cpu);
	struct cpu_preserved_ser *ser = cpu_preserved_get_ser(cpu);
	int i;

	if (!sctx || !ser)
		return -ENODEV;

	for (i = 0; i < CPU_WAIT_DEAD_TIMEOUT_US / CPU_WAIT_DEAD_STEP_US; i++) {
		cpu_preserved_inval(ser);
		if (READ_ONCE(ser->state) == CPU_PRESERVED_DEAD) {
			arch_cpu_preserved_wait_dead(cpu);
			return 0;
		}
		if (i && (i % CPU_WAIT_DEAD_KICK_STEPS) == 0)
			arch_cpu_preserved_kick(cpu);
		udelay(CPU_WAIT_DEAD_STEP_US);
	}

	pr_err("Timed out waiting for preserved cpu %d to stop (state=%u)\n",
	       cpu, READ_ONCE(ser->state));
	return -ETIMEDOUT;
}

/**
 * cpu_preserved_park - Main execution and parking loop for a preserved CPU
 * @cpu: Logical CPU identifier of the calling core.
 */
void cpu_preserved_park(int cpu)
{
	struct cpu_preserved_stack_context *sctx = cpu_preserved_stack_va(cpu);

	if (WARN_ON_ONCE(!sctx || sctx->magic != CPU_PRESERVED_STACK_MAGIC ||
			 !sctx->session_pgd_pa)) {
		arch_cpu_preserved_park_finish(cpu);
		if (sctx && sctx->ser) {
			WRITE_ONCE(sctx->ser->state, CPU_PRESERVED_DEAD);
			cpu_preserved_clean(sctx->ser);
		}
		return;
	}

	arch_cpu_preserved_park_on_stack(cpu, (unsigned long)sctx +
		CPU_PRESERVED_STACK_SIZE - CPU_PRESERVED_STACK_HEADROOM);
}
STACK_FRAME_NON_STANDARD(cpu_preserved_park);

static void cpu_preserved_free_stack(phys_addr_t stack_pa, bool is_incoming)
{
	if (stack_pa)
		cpu_preserved_free_kho(phys_to_virt(stack_pa), is_incoming);
}

static void cpu_preserved_state_cleanup(struct cpu_preserved_state *st,
					bool is_incoming)
{
	if (!cpumask_empty(&st->mask))
		return;

	kfree(st->cpus);
	st->cpus = NULL;
}

/*
 * Drop @cpu out of the preserved state, free its preserved stack, and
 * republish the globals a parked core may still be reading.  The caller holds
 * cpu_preserved_lock and has already made the core leave the park loop.
 */
static void __cpu_unpreserve_locked(unsigned int cpu)
{
	struct cpu_preserved_state *incoming = &cpu_preserved_incoming;
	struct cpu_preserved_state *outgoing = &cpu_preserved_outgoing;
	bool is_incoming = cpu_preserved_is_incoming(cpu);
	struct cpu_preserved_as_ser *as = NULL;
	struct cpu_preserved_ser *ser = NULL;
	phys_addr_t stack_pa = 0;

	lockdep_assert_held(&cpu_preserved_lock);

	if (is_incoming && incoming->cpus)
		ser = incoming->cpus[cpu];
	else if (outgoing->cpus)
		ser = outgoing->cpus[cpu];

	if (incoming->cpus)
		incoming->cpus[cpu] = NULL;
	if (outgoing->cpus)
		outgoing->cpus[cpu] = NULL;

	cpumask_clear_cpu(cpu, &outgoing->mask);
	cpumask_clear_cpu(cpu, &incoming->mask);
	cpumask_clear_cpu(cpu, &cpu_preserved_mask);
	cpu_preserved_clean(&cpu_preserved_mask);
	set_cpu_present(cpu, true);

	if (ser) {
		struct cpu_preserved_session_ser *sser =
			KHOSER_LOAD_PTR(ser->session);

		as = sser ? KHOSER_LOAD_PTR(sser->as) : NULL;
		WRITE_ONCE(ser->state, 0);
		stack_pa = ser->stack_pa;
		ser->stack_pa = 0;
		cpu_preserved_clean(ser);
	}

	if (stack_pa && as)
		cpu_preserved_as_unmap(as, (unsigned long)phys_to_virt(stack_pa),
				       CPU_PRESERVED_STACK_SIZE);

	cpu_preserved_sync_global_ser();
	cpu_preserved_free_stack(stack_pa, is_incoming);
	cpu_preserved_state_cleanup(outgoing, false);
	cpu_preserved_state_cleanup(incoming, true);
}

static int cpu_preserved_init_outgoing(void)
{
	struct cpu_preserved_state *outgoing = &cpu_preserved_outgoing;
	int ret;

	lockdep_assert_held(&cpu_preserved_lock);

	if (outgoing->cpus)
		return 0;

	ret = cpu_preserved_init_runtime_buffer_locked();
	if (ret)
		return ret;

	outgoing->cpus = kcalloc(nr_cpu_ids, sizeof(*outgoing->cpus),
				  GFP_KERNEL);
	if (!outgoing->cpus)
		return -ENOMEM;

	return 0;
}

struct cpu_preserved_session {
	struct list_head node;
	refcount_t ref;
	struct cpu_preserved_session_ser *ser;
	struct cpu_preserved_as_ser *as;
	bool incoming;
};

static DEFINE_MUTEX(cpu_preserved_sessions_lock);
static LIST_HEAD(cpu_preserved_sessions);

static struct cpu_preserved_session *
cpu_preserved_session_find_locked(const char *sname)
{
	struct cpu_preserved_session *ps;

	if (!sname || !sname[0])
		return NULL;

	list_for_each_entry(ps, &cpu_preserved_sessions, node) {
		if (strcmp(ps->ser->session_name, sname) == 0)
			return ps;
	}

	return NULL;
}

static void cpu_preserved_session_release(struct cpu_preserved_session *ps)
{
	if (ps->incoming) {
		cpu_preserved_as_restore_free(ps->as);
		if (ps->ser)
			kho_restore_free(ps->ser);
	} else {
		cpu_preserved_as_unpreserve(ps->as);
		if (ps->ser)
			kho_unpreserve_free(ps->ser);
	}

	kfree(ps);
}

/**
 * cpu_preserved_session_get - Find or create a preserved CPU session for @s
 * @s: Live Update session handle.
 *
 * Looks up the preserved CPU session matching @s by name and increments its
 * reference count, or allocates a new session with an isolated address space
 * (&struct cpu_preserved_as_ser) and KHO-preserved metadata
 * (&struct cpu_preserved_session_ser) initialized to a reference count of 1.
 *
 * Return: Pointer to the &struct cpu_preserved_session, or an ERR_PTR() on
 *         failure.
 */
struct cpu_preserved_session *
cpu_preserved_session_get(struct liveupdate_session *s)
{
	unsigned int nr_words = BITS_TO_U64(nr_cpu_ids);
	const char *sname = liveupdate_session_name(s);
	struct cpu_preserved_session *ps;
	size_t ser_sz;

	if (!sname || !sname[0])
		return ERR_PTR(-EINVAL);

	guard(mutex)(&cpu_preserved_sessions_lock);

	ps = cpu_preserved_session_find_locked(sname);
	if (ps) {
		refcount_inc(&ps->ref);
		return ps;
	}

	ps = kzalloc_obj(*ps);
	if (!ps)
		return ERR_PTR(-ENOMEM);

	ps->as = cpu_preserved_as_create();
	if (IS_ERR(ps->as)) {
		int err = PTR_ERR(ps->as);

		kfree(ps);
		return ERR_PTR(err);
	}

	ser_sz = struct_size(ps->ser, cpus_bitmap, nr_words);
	ps->ser = kho_alloc_preserve(ser_sz);
	if (IS_ERR(ps->ser)) {
		int err = PTR_ERR(ps->ser);

		cpu_preserved_as_unpreserve(ps->as);
		kfree(ps);
		return ERR_PTR(err);
	}

	memset(ps->ser, 0, ser_sz);
	ps->ser->nr_cpu_words = nr_words;
	strscpy(ps->ser->session_name, sname, sizeof(ps->ser->session_name));
	KHOSER_STORE_PTR(ps->ser->as, ps->as);
	cpu_preserved_clean_sz(ps->ser, ser_sz);

	refcount_set(&ps->ref, 1);
	list_add_tail(&ps->node, &cpu_preserved_sessions);
	return ps;
}

/**
 * cpu_preserved_session_put - Drop a reference to a preserved CPU session
 * @ps: Preserved CPU session (may be %NULL or an ERR_PTR()).
 *
 * Decrements @ps's reference count and, when the last reference is dropped,
 * releases any attached workload state, frees the isolated address space, and
 * unpreserves or restores the KHO session metadata.
 */
void cpu_preserved_session_put(struct cpu_preserved_session *ps)
{
	if (!ps || IS_ERR(ps))
		return;

	if (!refcount_dec_and_mutex_lock(&ps->ref, &cpu_preserved_sessions_lock))
		return;

	list_del_init(&ps->node);
	mutex_unlock(&cpu_preserved_sessions_lock);

	cpu_preserved_session_release(ps);
}

/**
 * cpu_preserved_session_as - Return the isolated address space of a session
 * @ps: Preserved CPU session.
 *
 * Return: Pointer to @ps's &struct cpu_preserved_as_ser, or %NULL if @ps is
 *         %NULL or an ERR_PTR().
 */
struct cpu_preserved_as_ser *
cpu_preserved_session_as(struct cpu_preserved_session *ps)
{
	return (!ps || IS_ERR(ps)) ? NULL : ps->as;
}

/**
 * cpu_preserved_session_cpus - Return the cpumask of preserved CPUs in @ps
 * @ps: Preserved CPU session.
 *
 * Return: Read-only cpumask of physical CPUs currently preserved in @ps, or
 *         %cpu_none_mask if @ps is %NULL or has no serialized metadata.
 */
const struct cpumask *
cpu_preserved_session_cpus(struct cpu_preserved_session *ps)
{
	if (!ps || IS_ERR(ps) || !ps->ser)
		return cpu_none_mask;

	return to_cpumask((unsigned long *)ps->ser->cpus_bitmap);
}

static void cpu_preserved_session_restore(struct liveupdate_session *s,
					  struct cpu_preserved_session_ser *sser)
{
	struct cpu_preserved_as_ser *as;
	struct cpu_preserved_session *ps;
	const struct cpumask *cpus;
	unsigned int nr_cpus;
	const char *sname;

	if (!sser)
		return;

	sname = liveupdate_session_name(s);
	if (!sname || !sname[0])
		sname = sser->session_name;

	as = KHOSER_LOAD_PTR(sser->as);
	if (as)
		cpu_preserved_as_adopt(as);

	guard(mutex)(&cpu_preserved_sessions_lock);

	if (cpu_preserved_session_find_locked(sname))
		return;

	ps = kzalloc_obj(*ps);
	if (!ps)
		return;

	ps->incoming = true;
	ps->ser = sser;
	ps->as = as;
	cpus = to_cpumask((unsigned long *)sser->cpus_bitmap);
	nr_cpus = cpumask_weight(cpus);
	refcount_set(&ps->ref, max(1U, nr_cpus));
	list_add_tail(&ps->node, &cpu_preserved_sessions);
}

static void cpu_preserved_session_remove_cpu(struct liveupdate_session *s,
					     unsigned int cpu)
{
	const char *sname = liveupdate_session_name(s);
	struct cpu_preserved_session *ps;
	bool had_cpu = false;

	if (cpu >= nr_cpu_ids)
		return;

	scoped_guard(mutex, &cpu_preserved_sessions_lock) {
		struct cpumask *cpus;

		ps = cpu_preserved_session_find_locked(sname);
		if (!ps || !ps->ser)
			return;
		cpus = to_cpumask((unsigned long *)ps->ser->cpus_bitmap);
		had_cpu = cpumask_test_and_clear_cpu(cpu, cpus);
	}

	if (!had_cpu)
		return;

	cpu_preserved_session_put(ps);
}

static int cpu_unpreserve(unsigned int cpu);

static int cpu_preserve(unsigned int cpu, struct liveupdate_session *session)
{
	struct cpu_preserved_state *outgoing = &cpu_preserved_outgoing;
	struct cpu_preserved_stack_context *sctx;
	struct cpu_preserved_session *ps;
	struct cpu_preserved_as_ser *as;
	struct cpu_preserved_ser *ser;
	void *stack;
	int ret;

	cpu_maps_update_begin();
	if (!cpu_online(cpu)) {
		cpu_maps_update_done();
		return -EBUSY;
	}
	cpu_maps_update_done();

	ps = cpu_preserved_session_get(session);
	if (IS_ERR(ps))
		return PTR_ERR(ps);

	as = cpu_preserved_session_as(ps);
	if (!as || !as->pgd_pa) {
		cpu_preserved_session_put(ps);
		return -EINVAL;
	}

	stack = kho_alloc_preserve(CPU_PRESERVED_STACK_SIZE);
	if (IS_ERR(stack)) {
		cpu_preserved_session_put(ps);
		return PTR_ERR(stack);
	}

	ser = kho_alloc_preserve(sizeof(*ser));
	if (IS_ERR(ser)) {
		kho_unpreserve_free(stack);
		cpu_preserved_session_put(ps);
		return PTR_ERR(ser);
	}
	memset(ser, 0, sizeof(*ser));
	ser->cpu = cpu;
	ser->state = CPU_PRESERVED_PARKING;
	ser->stack_pa = virt_to_phys(stack);
	KHOSER_STORE_PTR(ser->session, ps->ser);
	cpu_preserved_clean(ser);

	ret = cpu_preserved_as_map(as, virt_to_phys(stack),
				   (unsigned long)stack, CPU_PRESERVED_STACK_SIZE,
				   PAGE_KERNEL);
	if (ret) {
		kho_unpreserve_free(ser);
		kho_unpreserve_free(stack);
		cpu_preserved_session_put(ps);
		return ret;
	}

	ret = cpu_preserved_as_map(as, virt_to_phys(ser),
				   (unsigned long)ser, sizeof(*ser),
				   PAGE_KERNEL);
	if (ret) {
		cpu_preserved_as_unmap(as, (unsigned long)stack,
				       CPU_PRESERVED_STACK_SIZE);
		kho_unpreserve_free(ser);
		kho_unpreserve_free(stack);
		cpu_preserved_session_put(ps);
		return ret;
	}

	sctx = stack;
	sctx->magic = CPU_PRESERVED_STACK_MAGIC;
	sctx->cpu = cpu;
	sctx->session_pgd_pa = as->pgd_pa;
	sctx->ser = ser;
	cpu_preserved_clean(sctx);

	scoped_guard(mutex, &cpu_preserved_lock) {
		if (cpu_is_preserved(cpu)) {
			cpu_preserved_as_unmap(as, (unsigned long)ser, sizeof(*ser));
			cpu_preserved_as_unmap(as, (unsigned long)stack,
					       CPU_PRESERVED_STACK_SIZE);
			kho_unpreserve_free(ser);
			kho_unpreserve_free(stack);
			cpu_preserved_session_put(ps);
			return -EBUSY;
		}

		ret = cpu_preserved_init_outgoing();
		if (ret) {
			cpu_preserved_as_unmap(as, (unsigned long)ser, sizeof(*ser));
			cpu_preserved_as_unmap(as, (unsigned long)stack,
					       CPU_PRESERVED_STACK_SIZE);
			kho_unpreserve_free(ser);
			kho_unpreserve_free(stack);
			cpu_preserved_session_put(ps);
			return ret;
		}

		cpumask_set_cpu(cpu, &outgoing->mask);
		cpumask_set_cpu(cpu, &cpu_preserved_mask);
		cpu_preserved_clean(&cpu_preserved_mask);

		outgoing->cpus[cpu] = ser;
		cpu_preserved_sync_global_ser();
	}

	ret = remove_cpu(cpu);
	if (ret != 0) {
		if (ret > 0)
			ret = -EBUSY;
		pr_err("Failed to offline preserved cpu %u: %d\n",
		       cpu, ret);
		scoped_guard(mutex, &cpu_preserved_lock)
			__cpu_unpreserve_locked(cpu);
		cpu_preserved_as_unmap(as, (unsigned long)ser, sizeof(*ser));
		cpu_preserved_session_put(ps);
		cpu_preserved_free_kho(ser, false);
		return ret;
	}

	ret = cpu_wait_parked(cpu);
	if (ret) {
		if (!cpu_unpreserve(cpu)) {
			cpu_preserved_as_unmap(as, (unsigned long)ser, sizeof(*ser));
			cpu_preserved_session_put(ps);
			cpu_preserved_free_kho(ser, false);
		}
		return ret;
	}

	set_cpu_present(cpu, false);

	scoped_guard(mutex, &cpu_preserved_sessions_lock) {
		cpumask_set_cpu(cpu,
				to_cpumask((unsigned long *)ps->ser->cpus_bitmap));
		cpu_preserved_clean_sz(ps->ser,
				       struct_size(ps->ser, cpus_bitmap,
						   ps->ser->nr_cpu_words));
	}
	return 0;
}

/**
 * cpu_unpreserve - Unpreserve a physical CPU and restore it to online state
 * @cpu: Logical CPU identifier.
 *
 * Signals the CPU to exit the parking loop, cleans up preserved stack memory,
 * and restores the core to host scheduling via standard add_cpu().
 *
 * Return: 0 on success, or negative errno if the CPU failed to stop and was
 *         quarantined.
 */
static int cpu_unpreserve(unsigned int cpu)
{
	int ret;

	scoped_guard(mutex, &cpu_preserved_lock) {
		if (!cpu_is_preserved(cpu))
			return 0;

		cpu_signal_exit(cpu);
		arch_cpu_preserved_kick(cpu);
	}

	/*
	 * cpu_wait_dead() busy-polls for up to 20 seconds.  Do not hold
	 * cpu_preserved_lock across it: the poll only reads pcpu->state, which
	 * stays valid for as long as the CPU is preserved, and holding the lock
	 * here would stall every other preservation operation and every sysfs
	 * reader for the entire window.
	 */
	ret = cpu_wait_dead(cpu);
	if (WARN_ON_ONCE(ret))
		return ret;

	scoped_guard(mutex, &cpu_preserved_lock) {
		if (!cpu_is_preserved(cpu))
			return 0;

		__cpu_unpreserve_locked(cpu);
	}

	ret = add_cpu(cpu);
	if (ret < 0)
		pr_err("Failed to bring unpreserved cpu %u back online: %d\n",
		       cpu, ret);
	return 0;
}

static int cpu_preserved_flb_preserve(struct liveupdate_flb_op_args *argp)
{
	unsigned int nr_words = BITS_TO_U64(nr_cpu_ids);
	struct cpu_preserved_global_ser *ser;
	size_t ser_sz;
	int ret;

	ser_sz = struct_size(ser, cpu_preserved_bitmap, nr_words);

	mutex_lock(&cpu_preserved_lock);
	ret = cpu_preserved_init_runtime_buffer_locked();
	if (ret) {
		mutex_unlock(&cpu_preserved_lock);
		return ret;
	}

	ser = kho_alloc_preserve(ser_sz);
	if (IS_ERR(ser)) {
		mutex_unlock(&cpu_preserved_lock);
		return PTR_ERR(ser);
	}

	memset(ser, 0, ser_sz);
	ser->nr_cpu_words = nr_words;
	cpu_preserved_global_ser = ser;
	cpu_preserved_sync_global_ser();
	mutex_unlock(&cpu_preserved_lock);

	argp->data = virt_to_phys(ser);
	argp->obj = ser;
	return 0;
}

static void cpu_preserved_flb_unpreserve(struct liveupdate_flb_op_args *argp)
{
	struct cpu_preserved_global_ser *ser;

	if (!argp->data)
		return;

	ser = phys_to_virt(argp->data);
	scoped_guard(mutex, &cpu_preserved_lock) {
		if (WARN_ON_ONCE(!cpumask_empty(&cpu_preserved_outgoing.mask)))
			return;
		cpu_preserved_global_ser = NULL;
		cpu_preserved_unpreserve_runtime_buffer();
	}

	kho_unpreserve_free(ser);
}

static int cpu_preserved_flb_retrieve(struct liveupdate_flb_op_args *argp)
{
	struct cpu_preserved_global_ser *ser;
	u64 nr_bits;
	int cpu;

	if (!argp->data)
		return -EINVAL;

	ser = phys_to_virt(argp->data);
	arch_cpu_preserved_early_init();

	/*
	 * The outgoing kernel may have been built with a larger NR_CPUS.  Any
	 * preserved CPU we cannot represent would be silently forgotten and
	 * left spinning in its park loop forever, so refuse the handover
	 * instead.
	 */
	nr_bits = (u64)ser->nr_cpu_words * BITS_PER_TYPE(u64);
	if (nr_bits > nr_cpu_ids &&
	    find_next_bit((const unsigned long *)ser->cpu_preserved_bitmap,
			  nr_bits, nr_cpu_ids) < nr_bits) {
		pr_err("preserved CPU above nr_cpu_ids=%u in handover data\n",
		       nr_cpu_ids);
		return -ERANGE;
	}

	mutex_lock(&cpu_preserved_lock);
	bitmap_from_arr64(cpumask_bits(&cpu_preserved_mask),
			  ser->cpu_preserved_bitmap, min_t(u64, nr_bits, nr_cpu_ids));
	cpumask_copy(&cpu_preserved_incoming.mask, &cpu_preserved_mask);

	cpu_preserved_clean(&cpu_preserved_mask);
	for_each_cpu(cpu, &cpu_preserved_mask)
		set_cpu_present(cpu, false);
	mutex_unlock(&cpu_preserved_lock);

	argp->obj = ser;
	return 0;
}

static void cpu_preserved_flb_finish(struct liveupdate_flb_op_args *argp)
{
	struct cpu_preserved_global_ser *ser = argp->obj;

	if (!ser)
		return;

	guard(mutex)(&cpu_preserved_lock);
	if (WARN_ON_ONCE(!cpumask_empty(&cpu_preserved_incoming.mask)))
		return;

	if (ser->text_runtime_pa && ser->text_runtime_size) {
		unsigned long nr_pages = ser->text_runtime_size >> PAGE_SHIFT;
		struct page *page = kho_restore_pages(ser->text_runtime_pa, nr_pages);

		if (page) {
			for (unsigned long i = 0; i < nr_pages; i++)
				__free_page(page + i);
		}
	}

	if (ser->data_runtime_pa && ser->data_runtime_size) {
		unsigned long nr_pages = ser->data_runtime_size >> PAGE_SHIFT;
		struct page *page = kho_restore_pages(ser->data_runtime_pa, nr_pages);

		if (page) {
			for (unsigned long i = 0; i < nr_pages; i++)
				__free_page(page + i);
		}
	}

	kho_restore_free(ser);
}

static const struct liveupdate_flb_ops cpu_preserved_flb_ops = {
	.preserve   = cpu_preserved_flb_preserve,
	.unpreserve = cpu_preserved_flb_unpreserve,
	.retrieve   = cpu_preserved_flb_retrieve,
	.finish     = cpu_preserved_flb_finish,
	.owner      = THIS_MODULE,
};

static struct liveupdate_flb cpu_preserved_flb = {
	.ops        = &cpu_preserved_flb_ops,
	.compatible = CPU_PRESERVED_LUO_FLB_COMPATIBLE,
};

static int file_to_cpu(struct file *file, unsigned int *cpup)
{
	struct dentry *dentry, *parent;
	unsigned int cpu;

	if (!file || !file->f_path.dentry)
		return -EINVAL;

	if (file_inode(file)->i_sb->s_magic != SYSFS_MAGIC)
		return -EINVAL;

	dentry = file->f_path.dentry;
	if (strcmp(dentry->d_name.name, "preserve"))
		return -EINVAL;

	parent = dentry->d_parent;
	if (!parent || sscanf(parent->d_name.name, "cpu%u", &cpu) != 1)
		return -EINVAL;

	if (cpu >= nr_cpu_ids || !cpu_possible(cpu) ||
	    !cpu_is_hotpluggable(cpu)) {
		return -EINVAL;
	}

	*cpup = cpu;
	return 0;
}

static bool cpu_preserve_can_preserve(struct liveupdate_file_handler *handler,
				      struct file *file)
{
	unsigned int cpu;

	return file_to_cpu(file, &cpu) == 0;
}

static int cpu_preserve_preserve(struct liveupdate_file_op_args *args)
{
	struct cpu_preserved_ser *ser;
	unsigned int cpu;
	int ret;

	ret = file_to_cpu(args->file, &cpu);
	if (ret)
		return ret;

	ret = cpu_preserve(cpu, args->session);
	if (ret)
		return ret;

	scoped_guard(mutex, &cpu_preserved_lock)
		ser = cpu_preserved_outgoing.cpus[cpu];

	args->serialized_data = virt_to_phys(ser);
	return 0;
}

static void cpu_preserve_unpreserve(struct liveupdate_file_op_args *args)
{
	struct cpu_preserved_session_ser *sser;
	struct cpu_preserved_as_ser *as;
	struct cpu_preserved_ser *ser;
	unsigned int cpu;

	if (!args->serialized_data)
		return;

	ser = phys_to_virt(args->serialized_data);
	cpu = ser->cpu;

	if (cpu_unpreserve(cpu))
		return;

	sser = KHOSER_LOAD_PTR(ser->session);
	as = sser ? KHOSER_LOAD_PTR(sser->as) : NULL;
	cpu_preserved_as_unmap(as, (unsigned long)ser, sizeof(*ser));
	cpu_preserved_session_remove_cpu(args->session, cpu);
	cpu_preserved_free_kho(ser, false);
}

static void cpu_preserve_restore_incoming_cpu(struct liveupdate_session *session,
					      struct cpu_preserved_ser *ser)
{
	struct cpu_preserved_session_ser *sser = KHOSER_LOAD_PTR(ser->session);
	unsigned int cpu = ser->cpu;

	if (sser)
		cpu_preserved_session_restore(session, sser);

	scoped_guard(mutex, &cpu_preserved_lock) {
		cpumask_set_cpu(cpu, &cpu_preserved_incoming.mask);
		cpumask_set_cpu(cpu, &cpu_preserved_mask);

		if (!cpu_preserved_incoming.cpus) {
			cpu_preserved_incoming.cpus =
				kcalloc(nr_cpu_ids,
					sizeof(*cpu_preserved_incoming.cpus),
					GFP_KERNEL);
		}

		if (cpu_preserved_incoming.cpus)
			cpu_preserved_incoming.cpus[cpu] = ser;

		cpu_preserved_clean(&cpu_preserved_mask);
	}
}

static int cpu_preserve_retrieve(struct liveupdate_file_op_args *args)
{
	struct cpu_preserved_ser *ser;
	struct file *file;
	char path[64];

	if (!args->serialized_data)
		return -EINVAL;

	ser = phys_to_virt(args->serialized_data);

	snprintf(path, sizeof(path),
		 "/sys/devices/system/cpu/cpu%u/preserve", ser->cpu);
	file = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(file))
		return PTR_ERR(file);

	args->file = file;
	cpu_preserve_restore_incoming_cpu(args->session, ser);

	return 0;
}

static void cpu_preserve_finish(struct liveupdate_file_op_args *args)
{
	struct cpu_preserved_session_ser *sser;
	struct cpu_preserved_as_ser *as;
	struct cpu_preserved_ser *ser;

	if (!args->serialized_data)
		return;

	ser = phys_to_virt(args->serialized_data);
	if (args->retrieve_status <= 0)
		cpu_preserve_restore_incoming_cpu(args->session, ser);

	if (cpu_unpreserve(ser->cpu))
		return;

	sser = KHOSER_LOAD_PTR(ser->session);
	as = sser ? KHOSER_LOAD_PTR(sser->as) : NULL;
	cpu_preserved_as_unmap(as, (unsigned long)ser, sizeof(*ser));
	cpu_preserved_session_remove_cpu(args->session, ser->cpu);
	cpu_preserved_free_kho(ser, true);
}

static const struct liveupdate_file_ops cpu_preserve_file_ops = {
	.can_preserve = cpu_preserve_can_preserve,
	.preserve     = cpu_preserve_preserve,
	.retrieve     = cpu_preserve_retrieve,
	.unpreserve   = cpu_preserve_unpreserve,
	.finish       = cpu_preserve_finish,
	.owner        = THIS_MODULE,
};

static struct liveupdate_file_handler cpu_preserve_handler = {
	.ops        = &cpu_preserve_file_ops,
	.compatible = CPU_PRESERVED_LUO_FH_COMPATIBLE,
};

static int __init cpu_preserve_early_init(void)
{
	void *obj;
	int err;

	if (!liveupdate_enabled())
		cpumask_clear(&cpu_preserved_mask);
	cpumask_clear(&cpu_preserved_outgoing.mask);
	cpumask_clear(&cpu_preserved_incoming.mask);
	cpu_preserved_outgoing.cpus = NULL;
	cpu_preserved_incoming.cpus = NULL;
	cpu_preserved_global_ser = NULL;

	err = liveupdate_register_file_handler(&cpu_preserve_handler);
	if (err && err != -EOPNOTSUPP) {
		pr_err("Could not register cpu_preserve file handler: %pe\n",
		       ERR_PTR(err));
		return err;
	}

	err = liveupdate_register_flb(&cpu_preserve_handler,
				      &cpu_preserved_flb);
	if (err && err != -EOPNOTSUPP) {
		pr_err("Could not register cpu_preserved FLB: %pe\n",
		       ERR_PTR(err));
		return err;
	}

	/* Retrieve incoming preserved CPUs before secondary CPU bringup */
	if (liveupdate_enabled() &&
	    !liveupdate_flb_get_incoming(&cpu_preserved_flb, &obj))
		liveupdate_flb_put_incoming(&cpu_preserved_flb);

	return 0;
}
early_initcall(cpu_preserve_early_init);

static ssize_t preserved_show(struct device *dev,
			      struct device_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%*pbl\n",
			  cpumask_pr_args(cpu_get_preserved_mask()));
}
static DEVICE_ATTR_RO(preserved);

static ssize_t preserve_show(struct device *dev,
			     struct device_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", cpu_is_preserved(dev->id));
}
static DEVICE_ATTR_RO(preserve);

static int __init cpu_preserve_sysfs_init(void)
{
	struct device *dev_root = bus_get_dev_root(&cpu_subsys);
	int cpu, ret;

	if (dev_root) {
		ret = sysfs_create_file(&dev_root->kobj, &dev_attr_preserved.attr);
		put_device(dev_root);
		if (ret)
			pr_warn("Failed to create cpu preserved sysfs attribute: %d\n", ret);
	}

	for_each_possible_cpu(cpu) {
		struct device *dev = get_cpu_device(cpu);

		if (!dev && cpu_is_preserved(cpu)) {
			set_cpu_present(cpu, true);
			arch_register_cpu(cpu);
			dev = get_cpu_device(cpu);
		}

		if (dev) {
			ret = sysfs_create_file(&dev->kobj, &dev_attr_preserve.attr);
			if (ret)
				pr_warn("Failed to create cpu%d preserve sysfs attribute: %d\n",
					cpu, ret);
		}

		if (cpu_is_preserved(cpu))
			set_cpu_present(cpu, false);
	}
	return 0;
}
late_initcall(cpu_preserve_sysfs_init);
