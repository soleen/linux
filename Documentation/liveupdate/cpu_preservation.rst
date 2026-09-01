.. SPDX-License-Identifier: GPL-2.0-or-later

=========================
Physical CPU Preservation
=========================

.. kernel-doc:: kernel/liveupdate/cpu_preserve.c
   :doc: Preserved CPU Subsystem

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
