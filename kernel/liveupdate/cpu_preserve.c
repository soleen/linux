// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 */

/**
 * DOC: Preserved CPU Subsystem
 *
 * Live Update allows updating the host kernel while preserving the state of
 * hardware resources across the transition. While memfd-based memory
 * preservation is supported via LUO and PCI device preservation is handled
 * by VFIO and IOMMU, physical CPU cores represent another fundamental class
 * of hardware resource that requires preservation.
 *
 * A primary motivation is preserving virtual machine (VM) workloads across
 * host kernel updates without pausing the guest. By separating a physical
 * core from standard host scheduling and keeping it active across the kexec
 * reboot, guest vCPUs or dedicated bare-metal tasks can continue
 * uninterrupted execution on-core.
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
 *    into the parked state (cpu_preserved_park()). Preservation integrates with
 *    the On-Core framework (oncore_session_add_cpu()).
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
 * - **Address-space mapping hooks:** arch_cpu_preserved_as_map(),
 *   arch_cpu_preserved_as_flush_tlb(), and
 *   arch_cpu_preserved_set_transition_as() populate and manage isolated page
 *   tables built by the core layer using cpu_preserved_as_alloc_page().
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
 * handed over, the core layer builds a transition page table
 * (cpu_preserved_as_create()) containing only what on-core execution needs,
 * so that a core still running a workload cannot touch memory the new kernel
 * has taken ownership of:
 *
 * - Preserved text and read-only data, ``PAGE_KERNEL_ROX``
 *   (``__cpu_preserved_text``) -- park loops, world-switch routines, ops
 *   vector tables, and exception stubs;
 * - Preserved writable globals, ``PAGE_KERNEL`` NX
 *   (``__cpu_preserved_data``) -- state machines, session descriptors,
 *   per-CPU control blocks, and the preserved-CPU masks;
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
 * the identity-map helpers in ``arch/x86/mm/ident_map.c``. Custom workload
 * address spaces can also be created and adopted across kexec via
 * cpu_preserved_as_adopt().
 *
 * Workload Integration
 * ====================
 *
 * Physical cores preserved across live update execute payloads managed by the
 * On-Core execution framework. CPU preservation integrates directly with On-Core
 * session lifecycle:
 *
 * - On-Core assigns jobs to preserved cores via cpu_preserved_attach_workload().
 * - When a CPU file is preserved or unpreserved, oncore_session_add_cpu() and
 *   oncore_session_remove_cpu() update the session CPU bitmap.
 * - At kexec handover, oncore_session_get_ser() serializes the session state into
 *   the preserved CPU file descriptor, and oncore_session_restore() reconstructs
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
#include <linux/reboot.h>

#include <asm/sections.h>

/**
 * struct cpu_preserved_pcpu - Per-CPU host runtime state for CPU preservation
 * @stack_pa: Physical address of the preserved stack for this CPU.
 * @pgd_pa: Page table root PA for the preserved CPU context.
 * @entry_fn: Workload callback function executed repeatedly on the physical
 *            core while parked in cpu_preserved_park().
 * @entry_data: Opaque argument passed to @entry_fn.
 *
 * Tracks host runtime state for a preserved physical core. Allocated locally
 * in host memory; not preserved across kexec handover.
 */
struct cpu_preserved_pcpu {
	phys_addr_t stack_pa;
	phys_addr_t pgd_pa;
	void (*entry_fn)(void *data) ____cacheline_aligned;
	void *entry_data;
};

/*
 * struct cpu_preserved_state - Host-side preserved CPU state (incoming or outgoing)
 * @mask: Mask of preserved CPUs.
 * @pcpus: Host runtime state array.
 * @pcpus_ser: Per-CPU mailbox array in preserved memory.
 */
struct cpu_preserved_state {
	cpumask_t mask;
	struct cpu_preserved_pcpu *pcpus;
	struct cpu_preserved_pcpu_ser *pcpus_ser;
};

static DEFINE_MUTEX(cpu_preserved_lock);
static struct cpu_preserved_state cpu_preserved_incoming;
static struct cpu_preserved_state cpu_preserved_outgoing;
static cpumask_t cpu_preserved_mask __cpu_preserved_data;
static struct cpu_preserved_pcpu_ser *cpu_preserved_pcpus_va __cpu_preserved_data;
static struct cpu_preserved_pcpu *cpu_preserved_host_pcpus_va __cpu_preserved_data;
static struct cpu_preserved_global_ser *cpu_preserved_global_ser;

static struct page *cpu_preserved_text_pages;
static unsigned int cpu_preserved_text_order;
static struct page *cpu_preserved_data_pages;
static unsigned int cpu_preserved_data_order;
static bool cpu_preserved_runtime_preserved;

/*
 * Address spaces are mapped into under @cpu_preserved_as_map_lock and
 * enumerated under @cpu_preserved_as_list_lock.  cpu_preserved_map_range()
 * holds the list lock across the map lock; nothing takes them the other way
 * round.
 */
static DEFINE_MUTEX(cpu_preserved_as_list_lock);
static DEFINE_MUTEX(cpu_preserved_as_map_lock);
static LIST_HEAD(cpu_preserved_as_list);
static struct cpu_preserved_as *cpu_preserved_transition_as;

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
	KHOSER_STORE_PTR(ser->pcpus_runtime, cpu_preserved_outgoing.pcpus_ser);
	KHOSER_STORE_PTR(ser->transition_as,
			 cpu_preserved_transition_as ? cpu_preserved_transition_as->ser : NULL);
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
 * @arg: The struct cpu_preserved_as being populated.
 *
 * Page table allocator handed to the architecture page table builders.
 *
 * There is deliberately no alloc_page() fallback.  It would be
 * kho_alloc_preserve() open-coded, and the only way it could differ is by
 * ignoring the preservation error -- which would hand back an unpreserved
 * page table page.  The orphaned core has no fault handler, so that failure
 * is unrecoverable and must not be silent.
 *
 * Return: A zeroed, preserved page, or NULL.
 */
void *cpu_preserved_as_alloc_page(void *arg)
{
	struct cpu_preserved_as *as = arg;
	void *ptr;

	if (WARN_ON_ONCE(as->ser->nr_pgtable_pages >= ARRAY_SIZE(as->ser->pgtable_pages)))
		return NULL;

	ptr = kho_alloc_preserve(PAGE_SIZE);
	if (IS_ERR_OR_NULL(ptr))
		return NULL;

	cpu_preserved_clean_sz(ptr, PAGE_SIZE);
	as->ser->pgtable_pages[as->ser->nr_pgtable_pages++] = virt_to_phys(ptr);

	return ptr;
}
EXPORT_SYMBOL_GPL(cpu_preserved_as_alloc_page);

/*
 * Page table pages are preserved as they are allocated, but a cancelled live
 * update unpreserves everything, so state the preservation again after every
 * change.  Pages inherited from the previous kernel already belong to KHO.
 */
static int cpu_preserved_as_preserve_pgtables(struct cpu_preserved_as *as)
{
	unsigned int i;

	if (as->is_incoming)
		return 0;

	for (i = 0; i < as->ser->nr_pgtable_pages; i++) {
		void *p = phys_to_virt(as->ser->pgtable_pages[i]);
		int ret;

		cpu_preserved_clean_sz(p, PAGE_SIZE);
		ret = kho_preserve_pages(virt_to_page(p), 1);
		if (ret)
			return ret;
	}

	return 0;
}

static void cpu_preserved_as_unpreserve_pgtables(struct cpu_preserved_as *as)
{
	for (unsigned int i = 0; i < as->ser->nr_pgtable_pages; i++)
		kho_unpreserve_pages(virt_to_page(phys_to_virt(as->ser->pgtable_pages[i])), 1);
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
int cpu_preserved_as_map(struct cpu_preserved_as *as, phys_addr_t pa,
			 unsigned long va, size_t size, pgprot_t prot)
{
	int ret;

	guard(mutex)(&cpu_preserved_as_map_lock);

	ret = arch_cpu_preserved_as_map(as, pa, va, size, prot);
	if (ret)
		return ret;

	ret = cpu_preserved_as_preserve_pgtables(as);
	if (ret)
		return ret;

	arch_cpu_preserved_as_flush_tlb();

	return 0;
}
EXPORT_SYMBOL_GPL(cpu_preserved_as_map);

static int cpu_preserved_init_runtime_buffer(void);

static int cpu_preserved_as_map_buf(struct cpu_preserved_as *as,
				    void *va, size_t size)
{
	if (!va || !size)
		return 0;

	return cpu_preserved_as_map(as, virt_to_phys(va), (unsigned long)va,
				    size, PAGE_KERNEL);
}

static int cpu_preserved_as_map_runtime(struct cpu_preserved_as *as)
{
	unsigned long text_start = (unsigned long)__cpu_preserved_text_start;
	unsigned long data_start = (unsigned long)__cpu_preserved_data_start;
	size_t text_sz = (unsigned long)__cpu_preserved_text_end - text_start;
	size_t data_sz = (unsigned long)__cpu_preserved_data_end - data_start;
	struct cpu_preserved_state *outgoing = &cpu_preserved_outgoing;
	int cpu, ret;

	ret = cpu_preserved_as_map(as, cpu_preserved_get_text_pa(),
				   text_start, text_sz, PAGE_KERNEL_ROX);
	if (ret)
		return ret;

	ret = cpu_preserved_as_map(as, cpu_preserved_get_data_pa(),
				   data_start, data_sz, PAGE_KERNEL);
	if (ret)
		return ret;

	ret = cpu_preserved_as_map_buf(as, outgoing->pcpus_ser,
				       sizeof(*outgoing->pcpus_ser) * nr_cpu_ids);
	if (ret)
		return ret;

	ret = cpu_preserved_as_map_buf(as, outgoing->pcpus,
				       sizeof(*outgoing->pcpus) * nr_cpu_ids);
	if (ret)
		return ret;

	for_each_cpu(cpu, &outgoing->mask) {
		phys_addr_t spa = outgoing->pcpus[cpu].stack_pa;

		if (!spa)
			continue;
		ret = cpu_preserved_as_map_buf(as, phys_to_virt(spa),
					       CPU_PRESERVED_STACK_SIZE);
		if (ret)
			return ret;
	}

	return 0;
}

/**
 * cpu_preserved_as_create - Build a new preserved address space
 *
 * Allocates a root page table, maps the preserved text and data into it, and
 * publishes it so that subsequent cpu_preserved_map_range() calls reach it.
 *
 * Return: The new address space, or an ERR_PTR() on failure.
 */
struct cpu_preserved_as *cpu_preserved_as_create(void)
{
	struct cpu_preserved_as *as;
	int ret;

	ret = cpu_preserved_init_runtime_buffer();
	if (ret)
		return ERR_PTR(ret);

	as = kzalloc_obj(*as, GFP_KERNEL);
	if (!as)
		return ERR_PTR(-ENOMEM);
	INIT_LIST_HEAD(&as->node);

	as->ser = kho_alloc_preserve(sizeof(*as->ser));
	if (IS_ERR(as->ser)) {
		ret = PTR_ERR(as->ser);
		kfree(as);
		return ERR_PTR(ret);
	}
	memset(as->ser, 0, sizeof(*as->ser));

	as->pgd = cpu_preserved_as_alloc_page(as);
	if (!as->pgd) {
		ret = -ENOMEM;
		goto err;
	}
	as->pgd_pa = virt_to_phys(as->pgd);

	ret = cpu_preserved_as_map_runtime(as);
	if (ret)
		goto err;

	scoped_guard(mutex, &cpu_preserved_as_list_lock)
		list_add_tail(&as->node, &cpu_preserved_as_list);

	return as;

err:
	cpu_preserved_as_destroy(as);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(cpu_preserved_as_create);

/**
 * cpu_preserved_as_destroy - Tear down a preserved address space
 * @as: Address space to release.  NULL is accepted and does nothing.
 */
void cpu_preserved_as_destroy(struct cpu_preserved_as *as)
{
	if (!as)
		return;

	scoped_guard(mutex, &cpu_preserved_as_list_lock)
		list_del_init(&as->node);

	if (as->ser) {
		scoped_guard(mutex, &cpu_preserved_as_map_lock) {
			for (unsigned int i = 0; i < as->ser->nr_pgtable_pages; i++) {
				void *va = phys_to_virt(as->ser->pgtable_pages[i]);

				cpu_preserved_free_kho(va, as->is_incoming);
			}
		}
		cpu_preserved_free_kho(as->ser, as->is_incoming);
	}

	kfree(as);
}
EXPORT_SYMBOL_GPL(cpu_preserved_as_destroy);

/**
 * cpu_preserved_as_adopt - Take over an address space from the previous kernel
 * @ser: Address space serialization descriptor recovered from preserved memory.
 *
 * The page tables are left exactly as the outgoing kernel built them --
 * preserved CPUs are running out of them right now -- but the list linkage is
 * stale and has to be rebuilt, and the pages now belong to KHO rather than to
 * this kernel's allocator.
 */
struct cpu_preserved_as *cpu_preserved_as_adopt(struct cpu_preserved_as_ser *ser)
{
	struct cpu_preserved_as *as;

	if (!ser)
		return NULL;

	as = kzalloc_obj(*as, GFP_KERNEL);
	if (!as)
		return NULL;

	as->ser = ser;
	as->pgd_pa = ser->nr_pgtable_pages ? ser->pgtable_pages[0] : 0;
	as->pgd = phys_to_virt(as->pgd_pa);
	as->is_incoming = true;
	INIT_LIST_HEAD(&as->node);

	guard(mutex)(&cpu_preserved_as_list_lock);
	list_add_tail(&as->node, &cpu_preserved_as_list);

	return as;
}
EXPORT_SYMBOL_GPL(cpu_preserved_as_adopt);

static void cpu_preserved_preserve_runtime_buffer(void)
{
	if (cpu_preserved_runtime_preserved)
		return;

	/*
	 * This is the text the orphaned core executes and the data it reads
	 * after the kexec.  If either cannot be preserved there is nothing to
	 * hand over, so do not claim the runtime is preserved.
	 */
	if (WARN_ON_ONCE(kho_preserve_pages(cpu_preserved_text_pages,
					    1 << cpu_preserved_text_order)))
		return;
	if (WARN_ON_ONCE(kho_preserve_pages(cpu_preserved_data_pages,
					    1 << cpu_preserved_data_order)))
		return;

	WARN_ON_ONCE(kho_preserve_pages(virt_to_page(cpu_preserved_transition_as->ser),
					1 << get_order(sizeof(*cpu_preserved_transition_as->ser))));

	scoped_guard(mutex, &cpu_preserved_as_map_lock)
		WARN_ON_ONCE(cpu_preserved_as_preserve_pgtables(cpu_preserved_transition_as));

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
	kho_unpreserve_pages(virt_to_page(cpu_preserved_transition_as->ser),
			     1 << get_order(sizeof(*cpu_preserved_transition_as->ser)));

	scoped_guard(mutex, &cpu_preserved_as_map_lock)
		cpu_preserved_as_unpreserve_pgtables(cpu_preserved_transition_as);

	cpu_preserved_runtime_preserved = false;
}

/**
 * cpu_preserved_init_runtime_buffer - Allocate execution buffer outside Scratch
 *
 * The compiled __cpu_preserved_text and __cpu_preserved_data sections are
 * part of the host kernel binary image. During a host kexec live update, the
 * memory range occupied by the current kernel is designated as KHO Scratch
 * memory to allow the incoming kernel to be placed and unpacked. By definition,
 * Scratch memory must not contain preserved memory, as the incoming kernel
 * will overwrite Scratch during boot.
 *
 * Preserving the compiled text and data sections in-place would create a
 * conflict where preserved memory overlaps Scratch, triggering handover
 * failures or memory corruption when the incoming kernel overwrites the old
 * kernel text while preserved physical CPUs are still executing Caretaker loops
 * on their cores.
 *
 * To avoid this, we dynamically allocate dedicated text and data buffer pages
 * from free memory (outside Scratch) via alloc_pages(GFP_KERNEL), copy the
 * compiled text and data into them, remap the virtual addresses in the page
 * tables to point to these newly allocated pages, and preserve only these
 * external pages with KHO. Preserved CPUs execute out of these external pages,
 * allowing the incoming kernel to freely overwrite Scratch.
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
		if (cpu_preserved_transition_as)
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

	/*
	 * The address space a preserved CPU parks in when its workload has not
	 * given it one of its own.  It has to exist before anything can be
	 * mapped for preserved CPUs, so build it here and let the architecture
	 * record it where preserved text can reach it after the kexec.
	 */
	cpu_preserved_transition_as = cpu_preserved_as_create();
	if (IS_ERR(cpu_preserved_transition_as)) {
		ret = PTR_ERR(cpu_preserved_transition_as);
		cpu_preserved_transition_as = NULL;
		goto err_free;
	}
	arch_cpu_preserved_set_transition_as(cpu_preserved_transition_as);

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
 * cpu_preserved_map_range - Map a physical range into every preserved address space
 * @pa: Physical address
 * @va: Virtual address
 * @size: Size in bytes
 * @prot: Page protection flags
 *
 * Anything a preserved CPU may touch has to be reachable from whichever
 * address space it ends up running in, and which one that is depends on the
 * workload, so map it into all of them.
 *
 * Return: 0 on success, negative errno on failure.
 */
int cpu_preserved_map_range(phys_addr_t pa, unsigned long va,
			    size_t size, pgprot_t prot)
{
	struct cpu_preserved_as *as;
	int ret;

	guard(mutex)(&cpu_preserved_as_list_lock);

	list_for_each_entry(as, &cpu_preserved_as_list, node) {
		ret = cpu_preserved_as_map(as, pa, va, size, prot);
		if (ret)
			return ret;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(cpu_preserved_map_range);

/**
 * cpu_preserved_map_buffer - Map a virtual buffer into transition page tables
 * @va: Virtual address in kernel direct map
 * @size: Size in bytes
 *
 * Return: 0 on success, negative errno on failure.
 */
int cpu_preserved_map_buffer(void *va, size_t size)
{
	if (!va || !size)
		return 0;
	return cpu_preserved_map_range(virt_to_phys(va),
				       (unsigned long)va,
				       size, PAGE_KERNEL);
}
EXPORT_SYMBOL_GPL(cpu_preserved_map_buffer);

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
	return cpumask_test_cpu(cpu, &cpu_preserved_mask);
}
EXPORT_SYMBOL_GPL(cpu_is_preserved);

static bool cpu_preserved_is_incoming(int cpu)
{
	if ((unsigned int)cpu >= CONFIG_NR_CPUS)
		return false;
	return cpumask_test_cpu(cpu, &cpu_preserved_incoming.mask);
}

static struct cpu_preserved_pcpu_ser * __cpu_preserved_text cpu_preserved_get_pcpu_ser(int cpu)
{
	struct cpu_preserved_pcpu_ser *pcpus;

	if ((unsigned int)cpu >= CONFIG_NR_CPUS)
		return NULL;

	cpu_preserved_inval(&cpu_preserved_pcpus_va);
	pcpus = READ_ONCE(cpu_preserved_pcpus_va);
	return pcpus ? &pcpus[cpu] : NULL;
}

static struct cpu_preserved_pcpu * __cpu_preserved_text cpu_preserved_get_pcpu(int cpu)
{
	struct cpu_preserved_pcpu *pcpus;

	if ((unsigned int)cpu >= CONFIG_NR_CPUS)
		return NULL;

	cpu_preserved_inval(&cpu_preserved_host_pcpus_va);
	pcpus = READ_ONCE(cpu_preserved_host_pcpus_va);
	return pcpus ? &pcpus[cpu] : NULL;
}

/*
 * The preserved stack is handed over by physical address: the same page need
 * not be mapped at the same virtual address by two different kernels, so each
 * side derives its own VA rather than sharing one.
 */
static void * __cpu_preserved_text
cpu_preserved_stack_va(int cpu)
{
	struct cpu_preserved_pcpu *pcpu = cpu_preserved_get_pcpu(cpu);
	phys_addr_t pa;

	if (!pcpu)
		return NULL;

	cpu_preserved_inval(&pcpu->stack_pa);
	pa = READ_ONCE(pcpu->stack_pa);
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
	struct cpu_preserved_pcpu *pcpu = cpu_preserved_get_pcpu(cpu);

	if (!pcpu)
		return 0;

	cpu_preserved_inval(&pcpu->pgd_pa);
	return READ_ONCE(pcpu->pgd_pa);
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
 *
 * Publishes %CPU_PRESERVED_DEAD in the KHO-preserved per-CPU state block when
 * @cpu finishes exiting the preserved parking loop.
 */
void __cpu_preserved_text cpu_preserved_set_dead(int cpu)
{
	struct cpu_preserved_pcpu_ser *ser = cpu_preserved_get_pcpu_ser(cpu);

	if (ser)
		WRITE_ONCE(ser->workload, CPU_PRESERVED_DEAD);
}
EXPORT_SYMBOL_GPL(cpu_preserved_set_dead);

static void cpu_signal_exit(int cpu)
{
	struct cpu_preserved_pcpu_ser *ser = cpu_preserved_get_pcpu_ser(cpu);
	struct cpu_preserved_pcpu *pcpu = cpu_preserved_get_pcpu(cpu);

	if (ser) {
		WRITE_ONCE(ser->workload, CPU_PRESERVED_EXITING);
		cpu_preserved_clean(ser);
	}
	if (pcpu) {
		WRITE_ONCE(pcpu->entry_fn, NULL);
		WRITE_ONCE(pcpu->entry_data, NULL);
		cpu_preserved_clean(pcpu);
	}
}

/**
 * cpu_preserved_should_exit - Check if a running preserved workload should exit
 * @cpu: Logical CPU identifier.
 *
 * Polled by workloads executing on preserved physical CPUs to detect when the
 * host kernel has requested workload detachment or CPU reclamation.
 *
 * Return: %true if the workload on @cpu must exit back to the park loop,
 *         %false otherwise.
 */
bool __cpu_preserved_text cpu_preserved_should_exit(int cpu)
{
	struct cpu_preserved_pcpu_ser *ser = cpu_preserved_get_pcpu_ser(cpu);

	if (!ser)
		return false;

	cpu_preserved_inval(ser);
	return READ_ONCE(ser->workload) != CPU_PRESERVED_WORKLOAD;
}
EXPORT_SYMBOL_GPL(cpu_preserved_should_exit);

/**
 * cpu_preserved_attach_workload - Attach & start workload execution on core
 * @cpu: Logical CPU identifier.
 * @entry_fn: Workload callback to execute repeatedly on the physical core.
 * @data: Opaque argument passed to @entry_fn.
 *
 * Transitions @cpu from idle parking to executing @entry_fn(@data) on the
 * physical core, and kicks the CPU to begin execution immediately.
 *
 * Return: 0 on success, -EINVAL if @cpu is invalid, -ENODEV if not preserved,
 * or -EBUSY if a workload is already attached.
 */
int cpu_preserved_attach_workload(int cpu,
				  void (*entry_fn)(void *data), void *data)
{
	struct cpu_preserved_pcpu_ser *ser;
	struct cpu_preserved_pcpu *pcpu;

	if ((unsigned int)cpu >= nr_cpu_ids)
		return -EINVAL;

	mutex_lock(&cpu_preserved_lock);
	if (!cpumask_test_cpu(cpu, &cpu_preserved_outgoing.mask)) {
		mutex_unlock(&cpu_preserved_lock);
		return -ENODEV;
	}

	ser = &cpu_preserved_outgoing.pcpus_ser[cpu];
	pcpu = &cpu_preserved_outgoing.pcpus[cpu];
	if (ser->workload != CPU_PRESERVED_PARKED || pcpu->entry_fn) {
		mutex_unlock(&cpu_preserved_lock);
		return -EBUSY;
	}

	WRITE_ONCE(pcpu->entry_data, data);
	WRITE_ONCE(pcpu->entry_fn, entry_fn);
	WRITE_ONCE(ser->workload, CPU_PRESERVED_WORKLOAD);

	cpu_preserved_clean(pcpu);
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
 * Clears any attached workload on @cpu, returning the core to the default
 * idle parking loop.
 *
 * Return: 0 on success, -EINVAL if @cpu is invalid, or -ENODEV if
 * not preserved.
 */
int cpu_preserved_detach_workload(int cpu)
{
	struct cpu_preserved_pcpu_ser *ser;
	struct cpu_preserved_pcpu *pcpu;

	if ((unsigned int)cpu >= nr_cpu_ids)
		return -EINVAL;

	mutex_lock(&cpu_preserved_lock);
	if (!cpumask_test_cpu(cpu, &cpu_preserved_mask)) {
		mutex_unlock(&cpu_preserved_lock);
		return -ENODEV;
	}

	ser = cpu_preserved_get_pcpu_ser(cpu);
	pcpu = cpu_preserved_get_pcpu(cpu);
	if (!ser) {
		mutex_unlock(&cpu_preserved_lock);
		return -ENODEV;
	}

	if (READ_ONCE(ser->workload) == CPU_PRESERVED_WORKLOAD) {
		WRITE_ONCE(ser->workload, CPU_PRESERVED_PARKED);
		cpu_preserved_clean(ser);
	}
	if (pcpu) {
		WRITE_ONCE(pcpu->entry_fn, NULL);
		WRITE_ONCE(pcpu->entry_data, NULL);
		cpu_preserved_clean(pcpu);
	}

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
	struct cpu_preserved_pcpu *pcpu;

	if (cpu < 0 || cpu >= nr_cpu_ids)
		return;

	mutex_lock(&cpu_preserved_lock);
	pcpu = cpu_preserved_get_pcpu(cpu);
	sctx = cpu_preserved_stack_va(cpu);
	/*
	 * Validate the signature before writing through it.  The read side
	 * (cpu_preserved_get_stack_context()) has always done this; this path
	 * did not, so a stale or not-yet-initialised stack_pa would have been
	 * scribbled over.
	 */
	if (sctx && sctx->magic == CPU_PRESERVED_STACK_MAGIC) {
		sctx->workload_context = (u64)(uintptr_t)ctx;
		sctx->session_pgd_pa = pgd_pa;
		pcpu->pgd_pa = pgd_pa;
	}
	mutex_unlock(&cpu_preserved_lock);
}
EXPORT_SYMBOL_GPL(cpu_preserved_set_workload_context);

#define CPU_WAIT_DEAD_TIMEOUT_US	20000000
#define CPU_WAIT_DEAD_STEP_US		100
#define CPU_WAIT_DEAD_KICK_STEPS	50

/**
 * cpu_wait_dead - Wait for a preserved CPU to exit the park loop and power down
 * @cpu: Logical CPU identifier.
 *
 * Polls the KHO-preserved per-CPU state block until @cpu observes
 * %CPU_PRESERVED_EXITING, leaves cpu_preserved_park_loop(), and publishes
 * %CPU_PRESERVED_DEAD, periodically sending an IPI kick to wake it from any
 * low-power wait state.  Once %CPU_PRESERVED_DEAD is observed, invokes
 * arch_cpu_preserved_wait_dead() to wait for final hardware teardown.
 *
 * Return: 0 on success, -ENODEV if @cpu has no preserved state block, or
 *         -ETIMEDOUT if @cpu did not reach %CPU_PRESERVED_DEAD within
 *         %CPU_WAIT_DEAD_TIMEOUT_US microseconds.
 */
static int cpu_wait_dead(int cpu)
{
	struct cpu_preserved_pcpu_ser *ser = cpu_preserved_get_pcpu_ser(cpu);
	int i;

	if (!ser)
		return -ENODEV;

	for (i = 0; i < CPU_WAIT_DEAD_TIMEOUT_US / CPU_WAIT_DEAD_STEP_US; i++) {
		cpu_preserved_inval(ser);
		if (READ_ONCE(ser->workload) == CPU_PRESERVED_DEAD) {
			arch_cpu_preserved_wait_dead(cpu);
			return 0;
		}
		if (i % CPU_WAIT_DEAD_KICK_STEPS == 0)
			arch_cpu_preserved_kick(cpu);
		udelay(CPU_WAIT_DEAD_STEP_US);
	}

	pr_err("Timed out waiting for preserved cpu %d to stop (workload=%u)\n",
	       cpu, READ_ONCE(ser->workload));
	return -ETIMEDOUT;
}

static void __cpu_preserved_text
cpu_preserved_run_workload(struct cpu_preserved_pcpu_ser *ser,
			   struct cpu_preserved_pcpu *pcpu)
{
	void (*fn)(void *data);
	void *arg;

	if (!pcpu)
		return;

	cpu_preserved_inval(pcpu);
	fn = READ_ONCE(pcpu->entry_fn);
	arg = READ_ONCE(pcpu->entry_data);
	if (fn)
		fn(arg);

	cpu_preserved_inval(ser);
	if (cmpxchg(&ser->workload, CPU_PRESERVED_WORKLOAD,
		    CPU_PRESERVED_PARKED) == CPU_PRESERVED_WORKLOAD)
		cpu_preserved_clean(ser);
}
STACK_FRAME_NON_STANDARD(cpu_preserved_run_workload);

/**
 * cpu_preserved_park_loop - Generic execution loop for a parked preserved CPU
 * @cpu: Logical CPU identifier.
 *
 * Core execution loop executed on the dedicated preserved stack in
 * __cpu_preserved_text.  Waits in low-power park state, dispatches attached
 * workload callbacks, and exits when the CPU is unpreserved and reclaimed.
 */
void __cpu_preserved_text cpu_preserved_park_loop(int cpu)
{
	struct cpu_preserved_pcpu_ser *ser = cpu_preserved_get_pcpu_ser(cpu);
	struct cpu_preserved_pcpu *pcpu = cpu_preserved_get_pcpu(cpu);

	if (!ser)
		return;

	WRITE_ONCE(ser->workload, CPU_PRESERVED_PARKED);
	cpu_preserved_clean(ser);

	arch_cpu_preserved_park_init(cpu);

	for (;;) {
		cpu_preserved_inval(ser);
		switch (READ_ONCE(ser->workload)) {
		case CPU_PRESERVED_EXITING:
		case CPU_PRESERVED_DEAD:
			WRITE_ONCE(ser->workload, CPU_PRESERVED_DEAD);
			cpu_preserved_clean(ser);
			return;
		case CPU_PRESERVED_WORKLOAD:
			cpu_preserved_run_workload(ser, pcpu);
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
 *
 * Called on the physical CPU being offlined/preserved. Enters a dedicated
 * low-power parking loop in preserved memory, repeatedly executing any
 * attached workload callback, until signaled to exit upon unpreservation.
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
	}
}
EXPORT_SYMBOL_GPL(cpu_preserved_park);

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

	cpu_preserved_free_kho(st->pcpus_ser, is_incoming);
	st->pcpus_ser = NULL;
	kfree(st->pcpus);
	st->pcpus = NULL;
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
	struct cpu_preserved_pcpu_ser *ser = cpu_preserved_get_pcpu_ser(cpu);
	struct cpu_preserved_pcpu *pcpu = cpu_preserved_get_pcpu(cpu);
	bool is_incoming = cpu_preserved_is_incoming(cpu);
	phys_addr_t stack_pa = 0;

	lockdep_assert_held(&cpu_preserved_lock);

	cpumask_clear_cpu(cpu, &outgoing->mask);
	cpumask_clear_cpu(cpu, &incoming->mask);
	cpumask_clear_cpu(cpu, &cpu_preserved_mask);
	cpu_preserved_clean(&cpu_preserved_mask);
	set_cpu_present(cpu, true);

	if (ser)
		WRITE_ONCE(ser->workload, 0);

	if (pcpu) {
		stack_pa = pcpu->stack_pa;
		memset(pcpu, 0, sizeof(*pcpu));
	}

	cpu_preserved_free_stack(stack_pa, is_incoming);

	/* @pcpu and @ser point into these arrays: do not touch past this point. */
	cpu_preserved_state_cleanup(outgoing, false);
	cpu_preserved_state_cleanup(incoming, true);

	if (cpumask_empty(&cpu_preserved_mask)) {
		WRITE_ONCE(cpu_preserved_pcpus_va, NULL);
		WRITE_ONCE(cpu_preserved_host_pcpus_va, NULL);
		cpu_preserved_clean(&cpu_preserved_pcpus_va);
		cpu_preserved_clean(&cpu_preserved_host_pcpus_va);
	}

	cpu_preserved_sync_global_ser();
}

static int cpu_preserved_init_outgoing(void)
{
	struct cpu_preserved_state *outgoing = &cpu_preserved_outgoing;
	size_t ser_sz = sizeof(*outgoing->pcpus_ser) * nr_cpu_ids;
	int ret;

	if (outgoing->pcpus_ser)
		return 0;

	ret = cpu_preserved_init_runtime_buffer();
	if (ret)
		return ret;

	outgoing->pcpus = kcalloc(nr_cpu_ids, sizeof(*outgoing->pcpus),
				  GFP_KERNEL);
	if (!outgoing->pcpus)
		return -ENOMEM;

	outgoing->pcpus_ser = kho_alloc_preserve(ser_sz);
	if (IS_ERR(outgoing->pcpus_ser)) {
		ret = PTR_ERR(outgoing->pcpus_ser);
		kfree(outgoing->pcpus);
		outgoing->pcpus = NULL;
		outgoing->pcpus_ser = NULL;
		return ret;
	}
	memset(outgoing->pcpus_ser, 0, ser_sz);

	WRITE_ONCE(cpu_preserved_pcpus_va, outgoing->pcpus_ser);
	WRITE_ONCE(cpu_preserved_host_pcpus_va, outgoing->pcpus);

	cpu_preserved_map_buffer(outgoing->pcpus_ser, ser_sz);
	cpu_preserved_map_buffer(outgoing->pcpus,
				 sizeof(*outgoing->pcpus) * nr_cpu_ids);

	cpu_preserved_clean(&cpu_preserved_pcpus_va);
	cpu_preserved_clean(&cpu_preserved_host_pcpus_va);

	return 0;
}

static int cpu_preserve(unsigned int cpu)
{
	struct cpu_preserved_state *outgoing = &cpu_preserved_outgoing;
	struct cpu_preserved_stack_context *sctx;
	struct cpu_preserved_pcpu_ser *ser;
	struct cpu_preserved_pcpu *pcpu;
	void *stack;
	int ret;

	stack = kho_alloc_preserve(CPU_PRESERVED_STACK_SIZE);
	if (IS_ERR(stack))
		return PTR_ERR(stack);

	sctx = stack;
	sctx->magic = CPU_PRESERVED_STACK_MAGIC;
	sctx->cpu = cpu;

	scoped_guard(mutex, &cpu_preserved_lock) {
		if (cpu_is_preserved(cpu)) {
			kho_unpreserve_free(stack);
			return -EBUSY;
		}

		ret = cpu_preserved_init_outgoing();
		if (ret) {
			kho_unpreserve_free(stack);
			return ret;
		}

		cpumask_set_cpu(cpu, &outgoing->mask);
		cpumask_set_cpu(cpu, &cpu_preserved_mask);
		cpu_preserved_clean(&cpu_preserved_mask);

		ser = &outgoing->pcpus_ser[cpu];
		pcpu = &outgoing->pcpus[cpu];
		WRITE_ONCE(ser->workload, CPU_PRESERVED_PARKED);
		pcpu->stack_pa = virt_to_phys(stack);
		cpu_preserved_map_buffer(stack, CPU_PRESERVED_STACK_SIZE);
		pcpu->pgd_pa = cpu_preserved_transition_as->pgd_pa;
		WRITE_ONCE(pcpu->entry_fn, NULL);
		WRITE_ONCE(pcpu->entry_data, NULL);
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
	struct cpu_preserved_pcpu_ser *pcpus;
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
	pcpus = KHOSER_LOAD_PTR(ser->pcpus_runtime);

	if (pcpus) {
		cpu_preserved_incoming.pcpus_ser = pcpus;
		WRITE_ONCE(cpu_preserved_pcpus_va, pcpus);
		cpu_preserved_clean(&cpu_preserved_pcpus_va);
	}
	cpu_preserved_clean(&cpu_preserved_mask);
	for_each_cpu(cpu, &cpu_preserved_mask)
		set_cpu_present(cpu, false);
	mutex_unlock(&cpu_preserved_lock);

	argp->obj = ser;
	return 0;
}

static void cpu_preserved_flb_finish(struct liveupdate_flb_op_args *argp)
{
	struct cpu_preserved_as_ser *trans_as;
	struct cpu_preserved_global_ser *ser;

	if (!argp->obj)
		return;

	ser = argp->obj;

	trans_as = KHOSER_LOAD_PTR(ser->transition_as);
	if (trans_as)
		cpu_preserved_as_destroy(cpu_preserved_as_adopt(trans_as));

	scoped_guard(mutex, &cpu_preserved_lock) {
		if (cpu_preserved_incoming.pcpus_ser) {
			kho_restore_free(cpu_preserved_incoming.pcpus_ser);
			cpu_preserved_incoming.pcpus_ser = NULL;
		}
		kfree(cpu_preserved_incoming.pcpus);
		cpu_preserved_incoming.pcpus = NULL;
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
	cpu_preserved_outgoing.pcpus = NULL;
	cpu_preserved_outgoing.pcpus_ser = NULL;
	cpu_preserved_incoming.pcpus = NULL;
	cpu_preserved_incoming.pcpus_ser = NULL;
	cpu_preserved_global_ser = NULL;

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
