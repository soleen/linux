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
	struct cpu_preserved_global_ser *ser;

	if (!argp->obj)
		return;

	ser = argp->obj;

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
