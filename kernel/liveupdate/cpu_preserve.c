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

