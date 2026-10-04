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

