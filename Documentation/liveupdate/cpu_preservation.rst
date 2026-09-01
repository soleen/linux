.. SPDX-License-Identifier: GPL-2.0-or-later

=========================
Physical CPU Preservation
=========================

.. kernel-doc:: kernel/liveupdate/cpu_preserve.c
   :doc: Preserved CPU Subsystem

Lifecycle
=========

CPU lifecycle state progression::

    +-------------------------------------------------------------+
    |                          ONLINE                             |
    |               (Normal host task scheduling)                 |
    +-------------------------------------------------------------+
                                   |
                                   | preserve (via LUO fd)
                                   v
    +-------------------------------------------------------------+
    |                     PRESERVED_PARKED                        |
    |          (Removed from scheduler, loops in park)            |
    +-------------------------------------------------------------+
                                   |
                                   | [Live Update: kexec]
                                   v
    +-------------------------------------------------------------+
    |                     INCOMING PRESERVED                      |
    |         (Parked on-core, skipped in secondary boot)         |
    +-------------------------------------------------------------+
                                   |
                                   | unpreserve / retrieve (via LUO session)
                                   v
    +-------------------------------------------------------------+
    |                          OFFLINE                            |
    |            (Park loop exited, architecturally idle)         |
    +-------------------------------------------------------------+
                                   |
                                   | cpu_up()
                                   v
    +-------------------------------------------------------------+
    |                          ONLINE                             |
    |                (Rejoined host scheduling)                   |
    +-------------------------------------------------------------+

File descriptor binding
=======================

1. **Sysfs control file.** Each hotpluggable CPU exports a read-only sysfs
   attribute at ``/sys/devices/system/cpu/cpu<N>/preserve``. The file
   descriptor of this file handles the lifecycle of the preserved CPU.
2. **Preservation via LUO.** Userspace opens this file and registers the fd
   with LUO. Preserving the file offlines the core from host scheduling,
   migrates its interrupts and tasks, and transitions the CPU from online into
   the parked state (``cpu_preserved_park()``).
3. **KHO and memory preservation.** The parking loop, dedicated preserved CPU
   stacks, kernel page tables, and preserved CPU state reside in memory
   preserved across kexec via KHO.
4. **Incoming boot.** During early boot, the incoming kernel restores the
   preserved CPU mask before secondary SMP bringup and skips bringing
   preserved cores online, maintaining isolation.
5. **Retrieval and unpreservation.** When userspace retrieves the session in
   the incoming kernel, it receives the open ``preserve`` file descriptor.
   Retrieving the session or closing the fd unpreserves the CPU, signaling the
   core to exit the parking loop, drop into an offline state, and return
   online via standard ``cpu_up()``.

Architecture requirements
=========================

In addition to CPU hotplug (``CONFIG_HOTPLUG_CPU``), an architecture selecting
``ARCH_SUPPORTS_LIVEUPDATE_CPU`` must provide:

- **Linker script.** Include ``CPU_PRESERVED_TEXT`` in
  ``arch/<arch>/kernel/vmlinux.lds.S`` within the executable text section.

- **Preserved text section.** Functions executed by a parked core or during
  live update transitions must be annotated with ``__cpu_preserved_text`` so
  their instructions reside in the KHO-preserved ``.text.cpu_preserved``
  section. These are the ``arch_cpu_preserved_*()`` hooks documented under
  `Architecture Backend Interface`_ below.

- **Address-space mapping hooks.** ``arch_cpu_preserved_as_map()`` and
  ``arch_cpu_preserved_set_transition_as()`` populate isolated page tables built
  by the core layer using ``cpu_preserved_as_alloc_page()``.

- **CPU hotplug and stop-IPI isolation.** Exclude preserved CPUs from stop
  signals (NMI or stop IPIs in the machine reboot and crash paths), and avoid
  tearing down local interrupt controllers (LAPIC, GIC CPU interface) during
  CPU disable when the core is being preserved.

Isolated address space
======================

A preserved core does not run on the kernel's own page tables.  Before it is
handed over, ``cpu_preserve()`` builds a transition page table containing only
what on-core execution needs, so that a core still running a workload cannot
touch memory the new kernel has taken ownership of:

* preserved text and rodata, ``PAGE_KERNEL_ROX``
  (``__cpu_preserved_text``, ``__cpu_preserved_rodata``) -- park loops,
  world-switch routines, ops vector tables and exception stubs;
* preserved writable globals, ``PAGE_KERNEL`` NX
  (``__cpu_preserved_data``) -- state machines, session descriptors, per-CPU
  control blocks and the preserved-CPU masks;
* the per-CPU preserved stack, ``PAGE_KERNEL`` NX;
* the KHO-preserved workload state pages, ``PAGE_KERNEL`` NX;
* hardware control MMIO, ``PAGE_KERNEL_IO``, only where the interrupt
  controller still requires it.  GICv3 in system-register mode needs none.

Deliberately absent: the linear map, all user address ranges, the kernel heap,
vmalloc, modules and BPF JIT.  Guest memory is not mapped either -- it is
reached through stage-2 translation.

On arm64 these mappings are built with ``trans_pgd_map_range()``, on x86 with
the identity-map helpers in ``arch/x86/mm/ident_map.c``.

CPU Preservation Workload API
=============================

.. kernel-doc:: kernel/liveupdate/cpu_preserve.c
   :export:

Architecture Backend Interface
==============================

.. kernel-doc:: include/linux/cpu_preserve.h

CPU Preservation ABI
====================

.. kernel-doc:: include/linux/kho/abi/cpu.h
   :doc: CPU Preservation Live Update ABI

.. kernel-doc:: include/linux/kho/abi/cpu.h

See Also
========

- :doc:`/core-api/liveupdate`
- :doc:`/liveupdate/vmm`
- :doc:`/mm/memfd_preservation`
