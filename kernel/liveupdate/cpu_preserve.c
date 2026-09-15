// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * Physical CPU Preservation Framework for Live Update
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
 *    migrates its interrupts and tasks, and transitions the CPU from online
 *    into the parked state (cpu_preserved_park()). When CONFIG_LIVEUPDATE_ONCORE
 *    is enabled, preservation also registers the core with the On-Core session
 *    (oncore_session_add_cpu()) while keeping it parked until a job is activated.
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
 *    Retrieving the session reconnects the descriptors and restores on-core session
 *    state while keeping the core running. Finalizing the session (``finish``)
 *    or closing the fd unpreserves the CPU, signaling the core to exit the
 *    parking loop and automatically restoring it online via add_cpu().
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
 *   live update transitions must be annotated with ``__cpu_preserved_text`` so
 *   their instructions reside in the KHO-preserved ``.text.cpu_preserved``
 *   section. These are the ``arch_cpu_preserved_*()`` hooks documented in
 *   ``include/linux/cpu_preserve.h``.
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
 *   (``__cpu_preserved_text``) -- park loops, world-switch routines, ops
 *   vector tables, and exception stubs;
 * - Preserved writable globals, ``PAGE_KERNEL`` NX
 *   (``__cpu_preserved_data``) -- state machines, session descriptors,
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
 * Physical cores preserved across live update can execute payloads managed by
 * the On-Core execution framework (when CONFIG_LIVEUPDATE_ONCORE is enabled):
 *
 * - When a CPU file is preserved or unpreserved, oncore_session_add_cpu() and
 *   oncore_session_remove_cpu() update the session CPU bitmap while leaving the
 *   core parked until an on-core job is activated.
 * - On-Core attaches its scheduler worker to preserved cores via
 *   cpu_preserved_attach_workload() when a job is activated in the session.
 * - At kexec handover, oncore_session_get_ser() serializes the session state into
 *   the preserved CPU descriptor, and oncore_session_restore() reconstructs
 *   the session in the incoming kernel.
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
#include <linux/oncore.h>
#include <linux/reboot.h>

#include <asm/sections.h>

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
static cpumask_t cpu_preserved_mask __cpu_preserved_data;
static struct cpu_preserved_global_ser *cpu_preserved_global_ser;

static struct page *cpu_preserved_text_pages;
static unsigned int cpu_preserved_text_order;
static struct page *cpu_preserved_data_pages;
static unsigned int cpu_preserved_data_order;
static bool cpu_preserved_runtime_preserved;

static DEFINE_MUTEX(cpu_preserved_as_map_lock);

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

static void cpu_preserved_free_kho(void *va, bool is_incoming)
{
	if (!va)
		return;

	if (is_incoming)
		kho_restore_free(va);
	else
		kho_unpreserve_free(va);
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
	void *ptr;

	if (WARN_ON_ONCE(as->nr_pgtable_pages >= ARRAY_SIZE(as->pgtable_pages)))
		return NULL;

	ptr = kho_alloc_preserve(PAGE_SIZE);
	if (IS_ERR_OR_NULL(ptr))
		return NULL;

	cpu_preserved_clean_sz(ptr, PAGE_SIZE);
	as->pgtable_pages[as->nr_pgtable_pages++] = virt_to_phys(ptr);

	return ptr;
}
EXPORT_SYMBOL_GPL(cpu_preserved_as_alloc_page);

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
	unsigned int i;
	int ret;

	guard(mutex)(&cpu_preserved_as_map_lock);
	ret = arch_cpu_preserved_as_map(as, pa, va, size, prot);
	if (ret)
		return ret;

	for (i = 0; i < as->nr_pgtable_pages; i++)
		cpu_preserved_clean_sz(phys_to_virt(as->pgtable_pages[i]), PAGE_SIZE);
	cpu_preserved_clean(as);

	arch_cpu_preserved_as_flush_tlb();
	return 0;
}
EXPORT_SYMBOL_GPL(cpu_preserved_as_map);

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

	pgd = cpu_preserved_as_alloc_page(as);
	if (!pgd) {
		kho_unpreserve_free(as);
		return ERR_PTR(-ENOMEM);
	}
	cpu_preserved_clean(as);

	ret = cpu_preserved_as_map_runtime(as);
	if (ret) {
		cpu_preserved_as_unpreserve(as);
		return ERR_PTR(ret);
	}

	return as;
}
EXPORT_SYMBOL_GPL(cpu_preserved_as_create);

/**
 * cpu_preserved_as_unpreserve - Free an outgoing preserved address space
 * @ser: Address space descriptor to release.
 */
void cpu_preserved_as_unpreserve(struct cpu_preserved_as_ser *ser)
{
	if (!ser)
		return;

	scoped_guard(mutex, &cpu_preserved_as_map_lock) {
		for (unsigned int i = 0; i < ser->nr_pgtable_pages; i++) {
			void *va = phys_to_virt(ser->pgtable_pages[i]);

			kho_unpreserve_free(va);
		}
	}
	kho_unpreserve_free(ser);
}
EXPORT_SYMBOL_GPL(cpu_preserved_as_unpreserve);

/**
 * cpu_preserved_as_restore_free - Free an incoming preserved address space
 * @ser: Address space descriptor recovered from preserved memory.
 */
void cpu_preserved_as_restore_free(struct cpu_preserved_as_ser *ser)
{
	if (!ser)
		return;

	for (unsigned int i = 0; i < ser->nr_pgtable_pages; i++) {
		void *va = phys_to_virt(ser->pgtable_pages[i]);

		kho_restore_free(va);
	}
	kho_restore_free(ser);
}
EXPORT_SYMBOL_GPL(cpu_preserved_as_restore_free);

static void cpu_preserved_preserve_runtime_buffer(void)
{
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
	if (!cpu_preserved_runtime_preserved)
		return;

	kho_unpreserve_pages(cpu_preserved_text_pages,
			     1 << cpu_preserved_text_order);
	kho_unpreserve_pages(cpu_preserved_data_pages,
			     1 << cpu_preserved_data_order);

	cpu_preserved_runtime_preserved = false;
}

/**
 * cpu_preserved_init_runtime_buffer - Allocate execution buffer outside Scratch
 *
 * Return: 0 on success, or negative error code on allocation/setup failure.
 */
static int cpu_preserved_init_runtime_buffer(void)
{
	size_t text_size = (unsigned long)__cpu_preserved_text_end -
			   (unsigned long)__cpu_preserved_text_start;
	size_t data_size = (unsigned long)__cpu_preserved_data_end -
			   (unsigned long)__cpu_preserved_data_start;
	unsigned int text_nr_pages = DIV_ROUND_UP(text_size, PAGE_SIZE);
	unsigned int data_nr_pages = DIV_ROUND_UP(data_size, PAGE_SIZE);
	int ret;

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
 * cpu_is_preserved - Check whether a CPU is currently preserved
 * @cpu: Logical CPU identifier.
 *
 * Return: True if @cpu is currently preserved, false otherwise.
 */
bool __cpu_preserved_text cpu_is_preserved(int cpu)
{
	if ((unsigned int)cpu >= CONFIG_NR_CPUS)
		return false;
	cpu_preserved_inval(&cpu_preserved_mask);
	return arch_test_bit(cpu, cpumask_bits(&cpu_preserved_mask));
}
EXPORT_SYMBOL_GPL(cpu_is_preserved);

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

/**
 * cpu_preserved_get_pgd - Get root page table physical address for a preserved CPU
 * @cpu: Logical CPU identifier.
 *
 * Return: Root PGD physical address assigned to @cpu, or 0 if not set.
 */
phys_addr_t __cpu_preserved_text cpu_preserved_get_pgd(int cpu)
{
	struct cpu_preserved_stack_context *sctx = cpu_preserved_get_stack_context();

	if (sctx && sctx->session_pgd_pa)
		return sctx->session_pgd_pa;

	return 0;
}
EXPORT_SYMBOL_GPL(cpu_preserved_get_pgd);

/**
 * cpu_get_preserved_mask - Get the mask of all currently preserved CPUs
 *
 * Return: Read-only pointer to the cpumask of preserved CPUs.
 */
const struct cpumask *cpu_get_preserved_mask(void)
{
	return &cpu_preserved_mask;
}
EXPORT_SYMBOL_GPL(cpu_get_preserved_mask);

/**
 * cpu_preserved_set_dead - Mark a preserved CPU as fully dead/stopped
 * @cpu: Logical CPU identifier.
 */
void __cpu_preserved_text cpu_preserved_set_dead(int cpu)
{
	struct cpu_preserved_stack_context *ser = cpu_preserved_get_stack_context();

	if (ser) {
		/* Memory barrier before updating workload state */
		smp_mb();
		WRITE_ONCE(ser->ser->state, CPU_PRESERVED_DEAD);
		cpu_preserved_clean(ser->ser);
	}
}
EXPORT_SYMBOL_GPL(cpu_preserved_set_dead);

static void cpu_signal_exit(int cpu)
{
	struct cpu_preserved_stack_context *sctx = cpu_preserved_stack_va(cpu);
	struct cpu_preserved_ser *ser = cpu_preserved_get_ser(cpu);

	if (ser) {
		WRITE_ONCE(ser->state, CPU_PRESERVED_EXITING);
		cpu_preserved_clean(ser);
	}
	if (sctx) {
		WRITE_ONCE(sctx->entry_fn, NULL);
		WRITE_ONCE(sctx->workload_context, 0);
		cpu_preserved_clean(sctx);
	}
}

/**
 * cpu_preserved_should_exit - Check if a running preserved workload should exit
 * @cpu: Logical CPU identifier.
 *
 * Return: %true if the workload on @cpu must exit back to the park loop,
 *         %false otherwise.
 */
bool __cpu_preserved_text cpu_preserved_should_exit(int cpu)
{
	struct cpu_preserved_stack_context *sctx = cpu_preserved_get_stack_context();

	if (!sctx || !sctx->ser)
		return false;

	cpu_preserved_inval(sctx->ser);
	return READ_ONCE(sctx->ser->state) != CPU_PRESERVED_WORKLOAD;
}
EXPORT_SYMBOL_GPL(cpu_preserved_should_exit);

/**
 * cpu_preserved_attach_workload - Attach & start workload execution on core
 * @cpu: Logical CPU identifier.
 * @entry_fn: Workload callback to execute repeatedly on the physical core.
 * @data: Opaque argument passed to @entry_fn.
 *
 * Return: 0 on success, negative error code on failure.
 */
int cpu_preserved_attach_workload(int cpu,
				  void (*entry_fn)(void *data), void *data)
{
	struct cpu_preserved_stack_context *sctx;
	struct cpu_preserved_ser *ser;

	if ((unsigned int)cpu >= nr_cpu_ids)
		return -EINVAL;

	mutex_lock(&cpu_preserved_lock);
	if (!cpumask_test_cpu(cpu, &cpu_preserved_outgoing.mask)) {
		mutex_unlock(&cpu_preserved_lock);
		return -ENODEV;
	}

	sctx = cpu_preserved_stack_va(cpu);
	if (!sctx || sctx->magic != CPU_PRESERVED_STACK_MAGIC) {
		mutex_unlock(&cpu_preserved_lock);
		return -ENODEV;
	}

	ser = cpu_preserved_get_ser(cpu);
	if (!ser || ser->state != CPU_PRESERVED_PARKED || sctx->entry_fn) {
		mutex_unlock(&cpu_preserved_lock);
		return -EBUSY;
	}

	WRITE_ONCE(sctx->workload_context, (u64)(uintptr_t)data);
	WRITE_ONCE(sctx->entry_fn, entry_fn);
	WRITE_ONCE(ser->state, CPU_PRESERVED_WORKLOAD);

	cpu_preserved_clean(sctx);
	cpu_preserved_clean(ser);

	arch_cpu_preserved_kick(cpu);
	mutex_unlock(&cpu_preserved_lock);
	return 0;
}
EXPORT_SYMBOL_GPL(cpu_preserved_attach_workload);

/**
 * cpu_preserved_detach_workload - Detach workload and return core to idle park
 * @cpu: Logical CPU identifier.
 *
 * Return: 0 on success, negative error code on failure.
 */
int cpu_preserved_detach_workload(int cpu)
{
	struct cpu_preserved_stack_context *sctx;
	struct cpu_preserved_ser *ser;

	if ((unsigned int)cpu >= nr_cpu_ids)
		return -EINVAL;

	mutex_lock(&cpu_preserved_lock);
	if (!cpumask_test_cpu(cpu, &cpu_preserved_mask)) {
		mutex_unlock(&cpu_preserved_lock);
		return -ENODEV;
	}

	sctx = cpu_preserved_stack_va(cpu);
	if (!sctx || sctx->magic != CPU_PRESERVED_STACK_MAGIC) {
		mutex_unlock(&cpu_preserved_lock);
		return -ENODEV;
	}

	ser = cpu_preserved_get_ser(cpu);
	if (ser && READ_ONCE(ser->state) == CPU_PRESERVED_WORKLOAD) {
		WRITE_ONCE(ser->state, CPU_PRESERVED_PARKED);
		cpu_preserved_clean(ser);
	}
	WRITE_ONCE(sctx->entry_fn, NULL);
	WRITE_ONCE(sctx->workload_context, 0);
	cpu_preserved_clean(sctx);

	arch_cpu_preserved_kick(cpu);
	mutex_unlock(&cpu_preserved_lock);
	return 0;
}
EXPORT_SYMBOL_GPL(cpu_preserved_detach_workload);

/**
 * cpu_preserved_set_workload_context - Set workload context and root page table
 * @cpu: Logical CPU identifier.
 * @ctx: Opaque owning workload context pointer.
 * @pgd_pa: Physical address of workload root page table (or 0 for default).
 */
void cpu_preserved_set_workload_context(int cpu, void *ctx, phys_addr_t pgd_pa)
{
	struct cpu_preserved_stack_context *sctx;

	if (cpu < 0 || cpu >= nr_cpu_ids)
		return;

	mutex_lock(&cpu_preserved_lock);
	sctx = cpu_preserved_stack_va(cpu);
	if (sctx && sctx->magic == CPU_PRESERVED_STACK_MAGIC) {
		sctx->workload_context = (u64)(uintptr_t)ctx;
		sctx->session_pgd_pa = pgd_pa;
		cpu_preserved_clean(sctx);
	}
	mutex_unlock(&cpu_preserved_lock);
}
EXPORT_SYMBOL_GPL(cpu_preserved_set_workload_context);

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

static void __cpu_preserved_text
cpu_preserved_run_workload(struct cpu_preserved_stack_context *sctx)
{
	struct cpu_preserved_ser *ser = sctx->ser;
	void (*fn)(void *data);
	void *arg;

	cpu_preserved_inval(sctx);
	fn = READ_ONCE(sctx->entry_fn);
	arg = (void *)(uintptr_t)READ_ONCE(sctx->workload_context);
	if (fn)
		fn(arg);

	cpu_preserved_inval(ser);
	if (cpu_preserved_cmpxchg32(&ser->state, CPU_PRESERVED_WORKLOAD,
				    CPU_PRESERVED_PARKED) == CPU_PRESERVED_WORKLOAD)
		cpu_preserved_clean(ser);
}
STACK_FRAME_NON_STANDARD(cpu_preserved_run_workload);

/**
 * cpu_preserved_park_loop - Generic execution loop for a parked preserved CPU
 * @cpu: Logical CPU identifier.
 */
void __cpu_preserved_text cpu_preserved_park_loop(int cpu)
{
	struct cpu_preserved_stack_context *sctx = cpu_preserved_get_stack_context();
	struct cpu_preserved_ser *ser;

	if (!sctx || !sctx->ser)
		return;

	ser = sctx->ser;
	WRITE_ONCE(ser->state, CPU_PRESERVED_PARKED);
	cpu_preserved_clean(ser);

	arch_cpu_preserved_park_init(cpu);

	for (;;) {
		cpu_preserved_inval(ser);
		switch (READ_ONCE(ser->state)) {
		case CPU_PRESERVED_EXITING:
		case CPU_PRESERVED_DEAD:
			return;
		case CPU_PRESERVED_WORKLOAD:
			cpu_preserved_run_workload(sctx);
			break;
		default:
			arch_cpu_preserved_park_wait();
			break;
		}
	}
}
EXPORT_SYMBOL_GPL(cpu_preserved_park_loop);
STACK_FRAME_NON_STANDARD(cpu_preserved_park_loop);

/**
 * cpu_preserved_park - Main execution and parking loop for a preserved CPU
 * @cpu: Logical CPU identifier of the calling core.
 */
void cpu_preserved_park(int cpu)
{
	void *stack = cpu_preserved_stack_va(cpu);

	if (stack) {
		unsigned long top_of_stack = (unsigned long)stack +
			CPU_PRESERVED_STACK_SIZE - CPU_PRESERVED_STACK_HEADROOM;
		arch_cpu_preserved_park_on_stack(cpu, top_of_stack);
	} else {
		cpu_preserved_park_loop(cpu);
		arch_cpu_preserved_park_finish(cpu);
		cpu_preserved_set_dead(cpu);
	}
}
EXPORT_SYMBOL_GPL(cpu_preserved_park);
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
	struct cpu_preserved_ser *ser = NULL;
	phys_addr_t stack_pa = 0;

	lockdep_assert_held(&cpu_preserved_lock);

	if (is_incoming && incoming->cpus)
		ser = incoming->cpus[cpu];
	else if (outgoing->cpus)
		ser = outgoing->cpus[cpu];

	cpumask_clear_cpu(cpu, &outgoing->mask);
	cpumask_clear_cpu(cpu, &incoming->mask);
	cpumask_clear_cpu(cpu, &cpu_preserved_mask);
	cpu_preserved_clean(&cpu_preserved_mask);
	set_cpu_present(cpu, true);

	if (ser) {
		WRITE_ONCE(ser->state, 0);
		stack_pa = ser->stack_pa;
		ser->stack_pa = 0;
	}

	cpu_preserved_sync_global_ser();
	cpu_preserved_free_stack(stack_pa, is_incoming);
	cpu_preserved_state_cleanup(outgoing, false);
	cpu_preserved_state_cleanup(incoming, true);
}

static int cpu_preserved_init_outgoing(void)
{
	struct cpu_preserved_state *outgoing = &cpu_preserved_outgoing;
	int ret;

	if (outgoing->cpus)
		return 0;

	ret = cpu_preserved_init_runtime_buffer();
	if (ret)
		return ret;

	outgoing->cpus = kcalloc(nr_cpu_ids, sizeof(*outgoing->cpus),
				  GFP_KERNEL);
	if (!outgoing->cpus)
		return -ENOMEM;

	return 0;
}

static int cpu_preserve(unsigned int cpu, struct cpu_preserved_as_ser *as,
			struct oncore_session_ser *oncore)
{
	struct cpu_preserved_state *outgoing = &cpu_preserved_outgoing;
	struct cpu_preserved_stack_context *sctx;
	struct cpu_preserved_ser *ser;
	void *stack;
	int ret;

	stack = kho_alloc_preserve(CPU_PRESERVED_STACK_SIZE);
	if (IS_ERR(stack))
		return PTR_ERR(stack);

	ser = kho_alloc_preserve(sizeof(*ser));
	if (IS_ERR(ser)) {
		kho_unpreserve_free(stack);
		return PTR_ERR(ser);
	}
	memset(ser, 0, sizeof(*ser));
	ser->cpu = cpu;
	ser->state = CPU_PRESERVED_PARKED;
	ser->stack_pa = virt_to_phys(stack);
	KHOSER_STORE_PTR(ser->as, as);
	KHOSER_STORE_PTR(ser->oncore, oncore);
	cpu_preserved_clean(ser);

	if (as) {
		ret = cpu_preserved_as_map(as, virt_to_phys(stack),
					   (unsigned long)stack, CPU_PRESERVED_STACK_SIZE,
					   PAGE_KERNEL);
		if (ret) {
			kho_unpreserve_free(ser);
			kho_unpreserve_free(stack);
			return ret;
		}

		ret = cpu_preserved_as_map(as, virt_to_phys(ser),
					   (unsigned long)ser, sizeof(*ser),
					   PAGE_KERNEL);
		if (ret) {
			kho_unpreserve_free(ser);
			kho_unpreserve_free(stack);
			return ret;
		}
	}

	sctx = stack;
	sctx->magic = CPU_PRESERVED_STACK_MAGIC;
	sctx->cpu = cpu;
	sctx->reserved = 0;
	sctx->workload_context = 0;
	sctx->session_pgd_pa = (as && as->nr_pgtable_pages) ? as->pgtable_pages[0] : 0;
	sctx->ser = ser;
	sctx->entry_fn = NULL;
	cpu_preserved_clean(sctx);

	scoped_guard(mutex, &cpu_preserved_lock) {
		if (cpu_is_preserved(cpu)) {
			kho_unpreserve_free(ser);
			kho_unpreserve_free(stack);
			return -EBUSY;
		}

		ret = cpu_preserved_init_outgoing();
		if (ret) {
			kho_unpreserve_free(ser);
			kho_unpreserve_free(stack);
			return ret;
		}

		cpumask_set_cpu(cpu, &outgoing->mask);
		cpumask_set_cpu(cpu, &cpu_preserved_mask);
		cpu_preserved_clean(&cpu_preserved_mask);

		outgoing->cpus[cpu] = ser;
		cpu_preserved_sync_global_ser();
	}

	if (cpu_online(cpu)) {
		ret = remove_cpu(cpu);
		if (ret < 0) {
			pr_err("Failed to offline preserved cpu %u: %d\n",
			       cpu, ret);
			scoped_guard(mutex, &cpu_preserved_lock)
				__cpu_unpreserve_locked(cpu);
			return ret;
		}
	}

	set_cpu_present(cpu, false);
	return 0;
}

/**
 * cpu_unpreserve - Unpreserve a physical CPU and restore it to online state
 * @cpu: Logical CPU identifier.
 *
 * Signals the CPU to exit the parking loop, cleans up preserved stack memory,
 * and restores the core to host scheduling via standard add_cpu().
 */
static void cpu_unpreserve(unsigned int cpu)
{
	int ret;

	scoped_guard(mutex, &cpu_preserved_lock) {
		if (!cpu_is_preserved(cpu))
			return;

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
	if (cpu_wait_dead(cpu))
		return;

	scoped_guard(mutex, &cpu_preserved_lock) {
		if (!cpu_is_preserved(cpu))
			return;

		__cpu_unpreserve_locked(cpu);
	}

	ret = add_cpu(cpu);
	if (ret < 0)
		pr_err("Failed to bring unpreserved cpu %u back online: %d\n",
		       cpu, ret);
}

/*
 * FLB Ops for Preserved CPUs
 */
static int cpu_preserved_flb_preserve(struct liveupdate_flb_op_args *argp)
{
	unsigned int nr_words = BITS_TO_U64(nr_cpu_ids);
	struct cpu_preserved_global_ser *ser;
	size_t ser_sz;
	int ret;

	ret = cpu_preserved_init_runtime_buffer();
	if (ret)
		return ret;

	ser_sz = struct_size(ser, cpu_preserved_bitmap, nr_words);

	mutex_lock(&cpu_preserved_lock);
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
	mutex_lock(&cpu_preserved_lock);
	cpu_preserved_global_ser = NULL;
	mutex_unlock(&cpu_preserved_lock);

	cpu_preserved_unpreserve_runtime_buffer();
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
	struct cpu_preserved_global_ser *ser;

	if (!argp->obj)
		return;

	ser = argp->obj;

	scoped_guard(mutex, &cpu_preserved_lock) {
		kfree(cpu_preserved_incoming.cpus);
		cpu_preserved_incoming.cpus = NULL;
	}

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
	struct cpu_preserved_as_ser *as;
	struct oncore_session_ser *oncore;
	struct cpu_preserved_ser *ser;
	unsigned int cpu;
	int ret;

	ret = file_to_cpu(args->file, &cpu);
	if (ret)
		return ret;

	as = oncore_session_get_as(args->session);
	oncore = oncore_session_get_ser(args->session);

	ret = cpu_preserve(cpu, as, oncore);
	if (ret)
		return ret;

	ret = oncore_session_add_cpu(args->session, cpu);
	if (ret) {
		cpu_unpreserve(cpu);
		return ret;
	}


	scoped_guard(mutex, &cpu_preserved_lock)
		ser = cpu_preserved_outgoing.cpus[cpu];

	args->serialized_data = virt_to_phys(ser);
	return 0;
}

static void cpu_preserve_unpreserve(struct liveupdate_file_op_args *args)
{
	struct cpu_preserved_ser *ser;
	unsigned int cpu;

	if (!args->serialized_data)
		return;

	ser = phys_to_virt(args->serialized_data);
	cpu = ser->cpu;

	cpu_unpreserve(cpu);
	oncore_session_remove_cpu(args->session, cpu);

	kho_unpreserve_free(ser);
}

static void cpu_preserve_restore_incoming_cpu(struct liveupdate_session *session,
					      struct cpu_preserved_ser *ser)
{
	struct oncore_session_ser *oncore = KHOSER_LOAD_PTR(ser->oncore);
	unsigned int cpu = ser->cpu;

	if (oncore)
		oncore_session_restore(session, oncore);

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
	cpu_preserved_detach_workload(ser->cpu);

	return 0;
}

static void cpu_preserve_finish(struct liveupdate_file_op_args *args)
{
	struct cpu_preserved_ser *ser;

	if (!args->serialized_data)
		return;

	ser = phys_to_virt(args->serialized_data);
	if (args->retrieve_status <= 0)
		cpu_preserve_restore_incoming_cpu(args->session, ser);

	cpu_unpreserve(ser->cpu);
	oncore_session_remove_cpu(args->session, ser->cpu);

	kho_restore_free(ser);
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

static int cpu_preserve_reboot_notify(struct notifier_block *nb,
				      unsigned long action, void *data)
{
	int cpu;

	scoped_guard(mutex, &cpu_preserved_lock) {
		for_each_cpu(cpu, &cpu_preserved_mask) {
			/*
			 * If this CPU is not being preserved across an outgoing
			 * live update, signal it to exit the park loop and
			 * offline it.
			 */
			if (kexec_in_progress && liveupdate_enabled() &&
			    !cpu_preserved_is_incoming(cpu))
				continue;

			cpu_signal_exit(cpu);
			arch_cpu_preserved_kick(cpu);
			if (cpu_wait_dead(cpu))
				continue;

			__cpu_unpreserve_locked(cpu);
		}
	}

	return NOTIFY_OK;
}

static struct notifier_block cpu_preserve_reboot_nb = {
	.notifier_call = cpu_preserve_reboot_notify,
	.priority = 0,
};

/**
 * cpu_preserve_early_init - Early boot registration & retrieval of CPUs
 *
 * Registers the preserved CPU file handler and FLB with LUO, retrieves incoming
 * preserved CPU state prior to secondary SMP bringup, and registers the reboot
 * notifier.
 *
 * Return: 0 on success, or negative error code on failure.
 */
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
	if (liveupdate_enabled())
		liveupdate_flb_get_incoming(&cpu_preserved_flb, &obj);

	register_reboot_notifier(&cpu_preserve_reboot_nb);

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
