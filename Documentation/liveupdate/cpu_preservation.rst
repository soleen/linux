.. SPDX-License-Identifier: GPL-2.0-or-later

=========================
Physical CPU Preservation
=========================

.. kernel-doc:: kernel/liveupdate/cpu_preserve.c
   :doc: Preserved CPU Subsystem

Architecture Backend Interface
==============================

.. kernel-doc:: include/linux/cpu_preserve.h

On-Core Execution and Scheduling Framework
==========================================

When physical CPUs are preserved across a kexec Live Update, the On-Core
Execution and Scheduling Framework (``CONFIG_LIVEUPDATE_ONCORE``) allows kernel
workloads to run on those isolated cores while the outgoing kernel tears down
and the incoming kernel boots.

Each Live Update session that preserves one or more physical CPUs can host an
On-Core session. The On-Core session binds the session's isolated address space
and preserved CPU pool to a cooperative round-robin FIFO runqueue located in
KHO-preserved memory. When the number of runnable jobs does not exceed the
number of preserved CPUs in the session (1:1 execution), each job runs
tickless with an unbounded (``U64_MAX``) deadline and polls
``oncore_need_resched()`` and ``cpupr_should_exit()``. When more jobs
are active than preserved CPUs (``M > N`` overcommit), the scheduler assigns
hardware counter deadlines (configured via ``oncore.quantum_ms``) so jobs share
the preserved CPUs fairly.

.. kernel-doc:: kernel/liveupdate/oncore.c
   :doc: On-Core Execution and Scheduling Framework

On-Core Session & Job API
=========================

Kernel subsystems submit jobs to a Live Update session with
``oncore_session_submit_job()``, allocate the memory that the preserved runtime
uses from the session's isolated address space with
``oncore_session_alloc_buffer()``, adopt a page that must keep its physical
address with ``oncore_session_adopt_page()``, map device registers with
``oncore_session_map_mmio()``, and start execution with
``oncore_session_activate_job()``. During an intra-kernel abort or session
teardown, ``oncore_session_cancel_job()`` dequeues the job and waits for any
in-flight quantum to complete. The session, its jobs and the buffers are
KHO-preserved folios owned by the session's isolated address space (``struct
cpupr_as_ser``): callers never free them, and they are released
together when the address space is torn down, once every preserved CPU of the
session has left it.

.. kernel-doc:: include/linux/oncore.h

.. kernel-doc:: kernel/liveupdate/oncore.c
   :identifiers:

CPU Preservation ABI
====================

.. kernel-doc:: include/linux/kho/abi/cpu.h
   :doc: CPU Preservation Live Update ABI

.. kernel-doc:: include/linux/kho/abi/cpu.h

.. kernel-doc:: include/linux/kho/abi/cpu_x86.h

.. kernel-doc:: include/linux/kho/abi/cpu_arm64.h

See Also
========

- :doc:`/core-api/liveupdate`
- :doc:`/liveupdate/vmm`
- :doc:`/mm/memfd_preservation`
