/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 */

#ifndef _LINUX_KHO_ABI_CPU_H
#define _LINUX_KHO_ABI_CPU_H

#include <linux/bits.h>
#include <linux/build_bug.h>
#include <linux/kho/abi/block.h>
#include <linux/kho/abi/kexec_handover.h>
#include <linux/stddef.h>
#include <linux/types.h>

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
 * The state is serialized into the structures defined below
 * (struct cpu_preserved_global_ser, struct cpu_preserved_ser and the
 * structures they point to), which are handed over to the next kernel via
 * the KHO mechanism.  Their fields are naturally aligned, without implicit
 * padding.
 *
 * This interface is a contract. Any modification to the structure
 * fields, compatible strings, or the layout of the serialization
 * structures defined here constitutes a breaking change.
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
	CPU_PRESERVED_FAULTED = 4,
	CPU_PRESERVED_WORKLOAD = 5,
	CPU_PRESERVED_DETACHING = 6,
	CPU_PRESERVED_NR_STATES
};

/* Bits of cpu_preserved_global_ser.arch_mode on x86 */
#define CPU_PRESERVED_X86_X2APIC	BIT_ULL(0)
#define CPU_PRESERVED_X86_LA57		BIT_ULL(1)

/* Fields of cpu_preserved_global_ser.arch_mode on arm64 */
#define CPU_PRESERVED_ARM64_PAGE_SHIFT_MASK	GENMASK_ULL(7, 0)
#define CPU_PRESERVED_ARM64_VA_BITS_MASK	GENMASK_ULL(15, 8)
#define CPU_PRESERVED_ARM64_PGTABLE_LEVELS_MASK	GENMASK_ULL(19, 16)
#define CPU_PRESERVED_ARM64_LPA2		BIT_ULL(20)
#define CPU_PRESERVED_ARM64_VHE			BIT_ULL(21)
#define CPU_PRESERVED_ARM64_BE			BIT_ULL(22)

/**
 * struct cpu_preserved_global_ser - Global FLB serialization header
 * @text_runtime_pa:    Physical address of preserved CPU runtime text.
 * @text_runtime_size:  Size of preserved CPU runtime text in bytes.
 * @data_runtime_pa:    Physical address of preserved CPU runtime data.
 * @data_runtime_size:  Size of preserved CPU runtime data in bytes.
 * @cpus:               Preservation pointer to the struct cpu_preserved_ser of
 *                      the first CPU handed over, or 0.
 * @arch_mode:          Modes of the outgoing kernel that the parked CPUs
 *                      depend on, as arch_cpu_preserved_mode() returns them.
 *
 * Only the CPUs preserved by the outgoing kernel are handed over, on a list
 * linked through cpu_preserved_ser.next.  The list lets the incoming kernel
 * find each parked CPU's state at early boot, before any file is retrieved.
 * The incoming kernel refuses the handover unless it runs in @arch_mode.
 */
struct cpu_preserved_global_ser {
	u64 text_runtime_pa;
	u64 text_runtime_size;
	u64 data_runtime_pa;
	u64 data_runtime_size;
	DECLARE_KHOSER_PTR(cpus, struct cpu_preserved_ser *);
	u64 arch_mode;
};

static_assert(sizeof(struct cpu_preserved_global_ser) == 48);

/**
 * struct cpu_preserved_as_ser - Serialized preserved address space metadata
 * @pgd_pa:            Physical address of the root page table (PGD).
 * @nr_pgtable_pages:  Total number of allocated page table pages.
 * @pg_tables:         Preservation pointer to the first struct kho_block_header_ser
 *                     containing u64 physical addresses of all page table pages.
 * @direct_map_offset: Virtual minus physical address in the direct map of the
 *                     kernel that created the address space.  The stacks and
 *                     descriptors are mapped at their direct map address.
 */
struct cpu_preserved_as_ser {
	u64 pgd_pa;
	u64 nr_pgtable_pages;
	DECLARE_KHOSER_PTR(pg_tables, struct kho_block_header_ser *);
	u64 direct_map_offset;
};

static_assert(sizeof(struct cpu_preserved_as_ser) == 32);

/**
 * struct cpu_preserved_session_ser - Serialized preserved CPU session metadata
 * @as: Preservation pointer to struct cpu_preserved_as_ser.
 *
 * The CPUs of a session are the handed-over CPUs whose descriptors point to
 * it.
 */
struct cpu_preserved_session_ser {
	DECLARE_KHOSER_PTR(as, struct cpu_preserved_as_ser *);
};

static_assert(sizeof(struct cpu_preserved_session_ser) == 8);

/**
 * struct cpu_preserved_ser - Serialized state for preserved CPU
 * @cpu:      Logical CPU number in the preserving kernel, for information.
 * @state:    Preserved workload state (enum cpu_preserved_workload).
 * @stack_pa: Physical address of this CPU's preserved stack.
 * @session:  Preservation pointer to preserved CPU session serialized metadata.
 * @hwid:     Hardware identifier of the CPU, as arch_match_cpu_phys_id() takes.
 * @next:     Preservation pointer to the next CPU handed over, or 0.
 *
 * Logical CPU numbers are not stable across kernels: the incoming kernel finds
 * the CPU by @hwid, and refuses the handover if no CPU matches.
 */
struct cpu_preserved_ser {
	u32 cpu;
	u32 state;
	u64 stack_pa;
	DECLARE_KHOSER_PTR(session, struct cpu_preserved_session_ser *);
	u64 hwid;
	DECLARE_KHOSER_PTR(next, struct cpu_preserved_ser *);
};

static_assert(offsetof(struct cpu_preserved_ser, state) == 4,
	      "state is updated with cmpxchg and must be naturally aligned");
static_assert(sizeof(struct cpu_preserved_ser) == 40);

#endif /* _LINUX_KHO_ABI_CPU_H */
