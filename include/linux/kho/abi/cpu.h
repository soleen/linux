/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 */

#ifndef _LINUX_KHO_ABI_CPU_H
#define _LINUX_KHO_ABI_CPU_H

#include <linux/build_bug.h>
#include <linux/kho/abi/block.h>
#include <linux/kho/abi/kexec_handover.h>
#include <linux/stddef.h>
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
 * This ABI provides the contract for communicating preserved core metadata
 * and per-file descriptor state to the incoming kernel.
 *
 * The state is serialized into packed structures
 * (struct cpu_preserved_global_ser and struct cpu_preserved_ser) which
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

enum cpu_preserved_workload {
	CPU_PRESERVED_PARKING = 0,
	CPU_PRESERVED_PARKED = 1,
	CPU_PRESERVED_EXITING = 2,
	CPU_PRESERVED_DEAD = 3,
	CPU_PRESERVED_WORKLOAD = 4,
};

/**
 * struct cpu_preserved_global_ser - Global FLB serialization header
 * @nr_cpu_words:       Number of u64 words in @cpu_preserved_bitmap.
 * @reserved:           Must be zero.
 * @text_runtime_pa:    Physical address of preserved CPU runtime text.
 * @text_runtime_size:  Size of preserved CPU runtime text in bytes.
 * @data_runtime_pa:    Physical address of preserved CPU runtime data.
 * @data_runtime_size:  Size of preserved CPU runtime data in bytes.
 * @cpu_preserved_bitmap: Bitmap of physical CPUs preserved across live update.
 *
 * The preserved-CPU bitmap is serialized as an explicitly sized array of u64
 * rather than as a cpumask_t: sizeof(cpumask_t) depends on NR_CPUS, so
 * embedding one would make the offset of every subsequent field depend on the
 * .config of the kernel that wrote it.
 */
struct cpu_preserved_global_ser {
	u32 nr_cpu_words;
	u32 reserved;
	u64 text_runtime_pa;
	u64 text_runtime_size;
	u64 data_runtime_pa;
	u64 data_runtime_size;
	u64 cpu_preserved_bitmap[];
} __packed;

static_assert(offsetof(struct cpu_preserved_global_ser,
		       cpu_preserved_bitmap) % sizeof(u64) == 0,
	      "cpu_preserved_bitmap must be 64-bit aligned");

/**
 * struct cpu_preserved_as_ser - Serialized preserved address space metadata
 * @pgd_pa:           Physical address of the root page table (PGD).
 * @nr_pgtable_pages: Total number of allocated page table pages.
 * @pg_tables:        Preservation pointer to the first struct kho_block_header_ser
 *                    containing u64 physical addresses of all page table pages.
 */
struct cpu_preserved_as_ser {
	u64 pgd_pa;
	u64 nr_pgtable_pages;
	DECLARE_KHOSER_PTR(pg_tables, struct kho_block_header_ser *);
} __packed;

/**
 * struct cpu_preserved_session_ser - Serialized preserved CPU session metadata
 * @session_name:  LUO session name.
 * @workload_pa:   Opaque physical address of preserved workload session
 *                 (retained for freeing across kexec, never dereferenced).
 * @as:            Preservation pointer to struct cpu_preserved_as_ser.
 * @nr_cpu_words:  Number of 64-bit words in @cpus_bitmap.
 * @reserved:      Must be zero.
 * @cpus_bitmap:   Bitmap of physical CPUs assigned to this session.
 */
struct cpu_preserved_session_ser {
	char session_name[LIVEUPDATE_SESSION_NAME_LENGTH];
	u64 workload_pa;
	DECLARE_KHOSER_PTR(as, struct cpu_preserved_as_ser *);
	u32 nr_cpu_words;
	u32 reserved;
	u64 cpus_bitmap[];
} __packed;

static_assert(offsetof(struct cpu_preserved_session_ser, cpus_bitmap) % sizeof(u64) == 0,
	      "cpus_bitmap must be 64-bit aligned");

/**
 * struct cpu_preserved_ser - Serialized state for preserved CPU
 * @cpu:      Logical CPU identifier.
 * @state:    Preserved workload state (enum cpu_preserved_workload).
 * @stack_pa: Physical address of this CPU's preserved stack.
 * @session:  Preservation pointer to preserved CPU session serialized metadata.
 */
struct cpu_preserved_ser {
	u32 cpu;
	u32 state;
	u64 stack_pa;
	DECLARE_KHOSER_PTR(session, struct cpu_preserved_session_ser *);
} __packed;

#endif /* _LINUX_KHO_ABI_CPU_H */
