/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 */

#ifndef _LINUX_KHO_ABI_CPU_H
#define _LINUX_KHO_ABI_CPU_H

#include <linux/cpumask.h>
#include <linux/types.h>
#include <uapi/linux/liveupdate.h>

/**
 * DOC: CPU Preservation Live Update ABI
 *
 * Physical CPU preservation uses the ABI defined below to serialize
 * and restore the state of preserved CPUs across a live update kexec
 * reboot using the LUO.
 *
 * Preserved CPUs are isolated from host scheduling and remain active
 * in a parking loop or running workload across the live update reboot.
 * This ABI provides the contract for communicating which cores are
 * preserved, their active workload type (such as parked), and
 * human-readable identifiers to the incoming kernel.
 *
 * The state is serialized into packed structures
 * (struct cpu_preserved_global_ser and struct cpu_preserved_file_ser) which
 * are handed over to the next kernel via the KHO mechanism.
 *
 * This interface is a contract. Any modification to the structure
 * fields, compatible strings, or the layout of the `__packed`
 * serialization structures defined here constitutes a breaking change.
 * Such changes require incrementing the version number in the
 * CPU_PRESERVED_LUO_FLB_COMPATIBLE or CPU_PRESERVED_LUO_FH_COMPATIBLE
 * compatibility strings to prevent a new kernel from misinterpreting
 * data from an old kernel.
 *
 * Changes are allowed provided the compatibility version is
 * incremented; however, backward/forward compatibility is only
 * guaranteed for kernels supporting the same ABI version.
 */

/* The compatibility string for preserved CPU FLB */
#define CPU_PRESERVED_LUO_FLB_COMPATIBLE	"cpu_flb_v1"

/* The compatibility string for preserved CPU file handler */
#define CPU_PRESERVED_LUO_FH_COMPATIBLE		"cpu_fh_v1"

#define CPU_PRESERVED_NAME_LENGTH		64

/**
 * enum cpu_preserved_workload - Workload running on a preserved CPU
 * @CPU_PRESERVED_PARKED: Parked in idle loop.
 */
enum cpu_preserved_workload {
	CPU_PRESERVED_PARKED = 1,
};

/**
 * struct cpu_preserved_entry_ser - Serialized state of a single preserved CPU
 * @cpu: Logical CPU identifier.
 * @workload: Preserved workload type (enum cpu_preserved_workload).
 * @stack_pa: Physical address of the dedicated preserved stack pages.
 * @stack_order: Allocation order of the preserved stack (%THREAD_SIZE_ORDER).
 * @name: Human-readable workload description name.
 * @session: Name of the owning LUO session.
 */
struct cpu_preserved_entry_ser {
	u32 cpu;
	u32 workload;
	u64 stack_pa;
	u32 stack_order;
	char name[CPU_PRESERVED_NAME_LENGTH];
	char session[LIVEUPDATE_SESSION_NAME_LENGTH];
} __packed;

/**
 * struct cpu_preserved_global_ser - Minimal global FLB serialization header
 * @cpu_preserved_mask: Bitmask of physical CPUs preserved across live update.
 * @text_runtime_pa:    Physical address of preserved Caretaker text.
 * @text_runtime_size:  Size of preserved Caretaker text in bytes.
 * @data_runtime_pa:    Physical address of preserved Caretaker data.
 * @data_runtime_size:  Size of preserved Caretaker data in bytes.
 * @pcpus_runtime_pa:   Physical address of preserved cpu_preserved_pcpus array.
 */
struct cpu_preserved_global_ser {
	cpumask_t cpu_preserved_mask;
	u64 text_runtime_pa;
	u64 text_runtime_size;
	u64 data_runtime_pa;
	u64 data_runtime_size;
	u64 pcpus_runtime_pa;
} __packed;

#define CPU_PRESERVED_FILE_MAGIC	0x43505546	/* "CPUF" */

/**
 * struct cpu_preserved_file_ser - Per-file serialized state for preserved CPU fd
 * @magic:          Magic identifier (CPU_PRESERVED_FILE_MAGIC).
 * @cpu:            Logical CPU identifier.
 * @session_ser_pa: Physical address of owning struct caretaker_session_ser.
 * @stack_pa:       Physical address of this CPU's preserved stack.
 * @stack_order:    Allocation order of this CPU's preserved stack.
 * @pcpu_pa:        Physical address of this CPU's preserved pcpu descriptor.
 */
struct cpu_preserved_file_ser {
	u32 magic;
	u32 cpu;
	u64 session_ser_pa;
	u64 stack_pa;
	u32 stack_order;
	u64 pcpu_pa;
} __packed;

#endif /* _LINUX_KHO_ABI_CPU_H */
