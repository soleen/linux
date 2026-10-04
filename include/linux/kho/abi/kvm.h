/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026, Google LLC.
 * Tarun Sahu <tarunsahu@google.com>
 *
 * KVM Preservation ABI for Live Update Orchestrator (LUO)
 */
#ifndef _LINUX_KHO_ABI_KVM_H
#define _LINUX_KHO_ABI_KVM_H

#include <linux/types.h>
#include <linux/bits.h>
#include <linux/kho/abi/kexec_handover.h>

/**
 * DOC: KVM and guest_memfd Live Update ABI
 *
 * KVM and guest_memfd use the ABI defined below for preserving their states
 * across a kexec reboot using the LUO.
 *
 * The state is serialized into packed structures (struct kvm_luo_ser and
 * struct guest_memfd_luo_ser) which are handed over to the next kernel via
 * the KHO mechanism.
 *
 * This interface is a contract. Any modification to the structure layouts
 * constitutes a breaking change. Such changes require incrementing the
 * version number in the KVM_LUO_FH_COMPATIBLE or
 * GUEST_MEMFD_LUO_FH_COMPATIBLE compatibility strings.
 */

/**
 * struct kvm_luo_ser - Main serialization structure for a KVM VM.
 * @type:       The type of VM.
 * @kho_folios: Preservation pointer to VM-wide KHO-preserved folios.
 */
struct kvm_luo_ser {
	u64 type;
	DECLARE_KHOSER_PTR(kho_folios, struct kvm_kho_folios_ser *);
} __packed;

/* The compatibility string for KVM VM file handler */
#define KVM_LUO_FH_COMPATIBLE	"kvm_vm_luo_v1"

struct kvm_caretaker_cb_ser;

/**
 * enum kvm_caretaker_pcpu - Special Caretaker physical CPU identifiers
 * @KVM_CARETAKER_INVALID_PCPU: Unassigned physical CPU identifier.
 */
enum kvm_caretaker_pcpu {
	KVM_CARETAKER_INVALID_PCPU = U32_MAX,
};

/**
 * enum kvm_caretaker_state - Caretaker vCPU execution state machine
 * @KVM_CARETAKER_PAUSED:   Initial state upon preservation and between
 *                          oncore_sched time-sharing quantums (or when parked
 *                          after an unhandled VM exit).  Live architectural
 *                          state is fully serialized in @arch_state.
 * @KVM_CARETAKER_RUNNING:  Actively executing a time-sharing quantum on the
 *                          preserved physical CPU.  Hardware registers and
 *                          VMCS/VMCB/EL2 state are live on silicon; @arch_state
 *                          in memory is stale until the quantum exits.
 * @KVM_CARETAKER_STOPPING: Host requested reclaim while in
 *                          %KVM_CARETAKER_RUNNING and sent a physical IPI kick.
 *                          Caretaker will exit guest mode, serialize live
 *                          hardware state into @arch_state, and transition to
 *                          %KVM_CARETAKER_STOPPED.
 * @KVM_CARETAKER_STOPPED:  Terminal state.  Caretaker execution has permanently
 *                          ceased and @arch_state is valid in memory.  Reached
 *                          either directly via host cmpxchg from
 *                          %KVM_CARETAKER_PAUSED, or by the preserved CPU from
 *                          %KVM_CARETAKER_STOPPING after serialization completes.
 * @KVM_CARETAKER_FAILED:   Terminal error state.  Caretaker execution aborted
 *                          due to an unrecoverable fault or invalid exception
 *                          in the preserved runtime; @arch_state may be stale,
 *                          so host retrieve/unpreserve must fail and mark the
 *                          VM bugged.
 *
 * State transitions are coordinated locklessly via atomic cmpxchg(&cb->state):
 *   - Each scheduler quantum on the preserved CPU transitions
 *     %KVM_CARETAKER_PAUSED -> %KVM_CARETAKER_RUNNING on entry and
 *     %KVM_CARETAKER_RUNNING -> %KVM_CARETAKER_PAUSED after serializing guest
 *     state on quantum exit.
 *   - When host KVM reclaims the vCPU (kvm_caretaker_wait_for_attach()):
 *     1. If @cb->state is %KVM_CARETAKER_PAUSED, host atomically transitions it
 *        to %KVM_CARETAKER_STOPPED in 0 ns; if the preserved CPU later attempts
 *        to start a quantum, its cmpxchg(%KVM_CARETAKER_PAUSED ->
 *        %KVM_CARETAKER_RUNNING) fails and it immediately exits.
 *     2. If @cb->state is %KVM_CARETAKER_RUNNING, host atomically transitions
 *        it to %KVM_CARETAKER_STOPPING, sends an IPI to preempt guest mode, and
 *        spins until the preserved CPU finishes detach_serialize() and stores
 *        %KVM_CARETAKER_STOPPED.
 */
enum kvm_caretaker_state {
	KVM_CARETAKER_PAUSED = 0,
	KVM_CARETAKER_RUNNING = 1,
	KVM_CARETAKER_STOPPING = 2,
	KVM_CARETAKER_STOPPED = 3,
	KVM_CARETAKER_FAILED = 4,
};

/**
 * struct kvm_kho_folios_ser - Serialized list of KHO-preserved folios for a VM
 * @nr_folios: Number of physical folio addresses in @folios_pa.
 * @folios_pa: Physical addresses of folios preserved via kho_preserve_folio().
 */
struct kvm_kho_folios_ser {
	u64 nr_folios;
	u64 folios_pa[];
} __packed;

/**
 * struct kvm_caretaker_cb_ser - KVM Caretaker Control Block
 * @state:     Current Caretaker execution state (enum kvm_caretaker_state).
 * @pcpu_id:   Physical CPU ID where this vCPU runs while in Caretaker.
 * @vcpu_id:   Guest vCPU identifier.
 * @reserved:  Must be zero.
 *
 * Coordinates vCPU execution state across hypervisor detachment,
 * live update, and Caretaker CPU preservation.
 */
struct kvm_caretaker_cb_ser {
	u32 state;
	u32 pcpu_id;
	u32 vcpu_id;
	u32 reserved;
} __packed;

/**
 * struct kvm_vcpu_ser - Main serialization structure for a KVM vCPU.
 * @vcpu_id:    The ID of the virtual CPU.
 * @reserved:   Must be zero.
 * @vm_token:   Token of the associated KVM VM instance.
 * @cb:         Preservation pointer to Caretaker Control Block.
 * @arch_state: Preservation pointer to vCPU architectural state.
 *
 * Cross-kexec invariant: the incoming kernel may only dereference structures
 * declared in include/linux/kho/abi/ headers.  When @cb is non-NULL, the
 * preserved Caretaker text writes live guest state into @arch_state at detach
 * time before transitioning @cb to %KVM_CARETAKER_STOPPED; the incoming kernel
 * reads only @cb and @arch_state.
 */
struct kvm_vcpu_ser {
	u32 vcpu_id;
	u32 reserved;
	u64 vm_token;
	DECLARE_KHOSER_PTR(cb, struct kvm_caretaker_cb_ser *);
	DECLARE_KHOSER_PTR(arch_state, struct kvm_vcpu_arch_ser *);
} __packed;

/* The compatibility string for KVM vCPU file handler */
#define KVM_VCPU_LUO_FH_COMPATIBLE	"kvm_vcpu_luo_v1"

/**
 * struct guest_memfd_luo_folio_ser - Serialization layout for a single folio in guest_memfd.
 * @pfn:   Page Frame Number of the folio.
 * @index: Page offset of the folio within the file.
 * @flags: State flags associated with the folio.
 */
struct guest_memfd_luo_folio_ser {
	u64 pfn:52;
	u64 flags:12;
	u64 index;
} __packed;

/**
 * GUEST_MEMFD_LUO_FOLIO_UPTODATE - The folio is up-to-date.
 *
 * This flag is per folio to check if the folio is uptodate.
 */
#define GUEST_MEMFD_LUO_FOLIO_UPTODATE	BIT(0)


/**
 * GUEST_MEMFD_LUO_FLAG_MMAP - The guest_memfd supports mmap.
 *
 * This flag indicates that the guest_memfd supports host-side mmap.
 */
#define GUEST_MEMFD_LUO_FLAG_MMAP		BIT(0)

/**
 * GUEST_MEMFD_LUO_FLAG_INIT_SHARED - Initialize memory as shared.
 *
 * This flag indicates that the guest_memfd has been initialized as shared
 * memory.
 */
#define GUEST_MEMFD_LUO_FLAG_INIT_SHARED	BIT(1)

/**
 * GUEST_MEMFD_LUO_SUPPORTED_FLAGS - Supported guest_memfd LUO flags mask.
 *
 * A mask of all guest_memfd preservation flags supported by this version
 * of the KVM LUO ABI.
 */
#define GUEST_MEMFD_LUO_SUPPORTED_FLAGS	(GUEST_MEMFD_LUO_FLAG_MMAP | \
						 GUEST_MEMFD_LUO_FLAG_INIT_SHARED)

/**
 * struct guest_memfd_luo_ser - Main serialization structure for guest_memfd.
 * @size:      The size of the file in bytes.
 * @flags:     File-level flags.
 * @nr_folios: Number of folios in the folios array.
 * @vm_token:  Token of the associated KVM VM instance.
 * @folios:    KHO vmalloc descriptor pointing to the array of
 *             struct guest_memfd_luo_folio_ser.
 */
struct guest_memfd_luo_ser {
	u64 size;
	u64 flags;
	u64 nr_folios;
	u64 vm_token;
	struct kho_vmalloc folios;
} __packed;

/* The compatibility string for GUEST_MEMFD file handler */
#define GUEST_MEMFD_LUO_FH_COMPATIBLE	"guest_memfd_luo_v1"

#endif /* _LINUX_KHO_ABI_KVM_H */
