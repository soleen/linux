/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026, Google LLC.
 * Tarun Sahu <tarunsahu@google.com>
 *
 * KVM Preservation ABI for Live Update Orchestrator (LUO)
 */
#ifndef _LINUX_KHO_ABI_KVM_H
#define _LINUX_KHO_ABI_KVM_H

#include <linux/build_bug.h>
#include <linux/stddef.h>
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

#define KVM_VCPU_LUO_FLAG_CARETAKER	BIT(0)

/* KVM Caretaker attachment states */
#define KVM_CARETAKER_ATTACHED		0	/* Normal host KVM handling */
#define KVM_CARETAKER_DETACHED		1	/* Exits run in Caretaker */
#define KVM_CARETAKER_ATTACHING		2	/* Transitioning from Caretaker to host KVM */
#define KVM_CARETAKER_INVALID_PCPU	U32_MAX	/* Unassigned pCPU identifier */

/**
 * struct kvm_caretaker_cb - KVM Caretaker Control Block
 * @attachment_state: Current attachment state (%KVM_CARETAKER_ATTACHED or
 *                    %KVM_CARETAKER_DETACHED).
 * @pcpu_id: Physical CPU ID where this vCPU runs while detached.
 * @vcpu_id: Guest vCPU identifier.
 * @runtime_pa: Hypervisor private runtime execution context physical address.
 * @runtime_size: Hypervisor private runtime execution context size in bytes.
 *
 * Coordinates vCPU execution state across hypervisor detachment,
 * live update, and Caretaker CPU preservation.
 *
 * Deliberately not __packed.  @attachment_state is written with
 * smp_store_release() by both the host kernel and the preserved Caretaker
 * text, and __packed sets the struct alignment to 1, which lets the compiler
 * assume that store may be misaligned: on arm64 that makes STLR fault, and on
 * any architecture it permits the store to be split, destroying the
 * single-copy atomicity the release is there for.  The layout below is
 * naturally aligned with no padding, so __packed bought nothing.  The
 * static_asserts make the layout a checked property rather than a hoped-for
 * one, which is what a cross-kexec ABI actually needs.
 */
struct kvm_caretaker_cb {
	u64 attachment_state;
	u32 pcpu_id;
	u32 vcpu_id;
	u64 runtime_pa;
	u64 runtime_size;
};

static_assert(sizeof(struct kvm_caretaker_cb) == 32);
static_assert(offsetof(struct kvm_caretaker_cb, attachment_state) == 0);
static_assert(offsetof(struct kvm_caretaker_cb, pcpu_id) == 8);
static_assert(offsetof(struct kvm_caretaker_cb, vcpu_id) == 12);
static_assert(offsetof(struct kvm_caretaker_cb, runtime_pa) == 16);
static_assert(offsetof(struct kvm_caretaker_cb, runtime_size) == 24);

#if defined(CONFIG_X86_64)
#include <linux/kho/abi/kvm_x86.h>
#elif defined(CONFIG_ARM64)
#include <linux/kho/abi/kvm_arm64.h>
#else
struct kvm_vm_arch_luo_state;
struct kvm_vcpu_arch_luo_state;
#endif

/**
 * struct kvm_luo_ser - Main serialization structure for a KVM VM.
 * @type:       The type of VM.
 * @arch_state: Preservation pointer to VM architectural state.
 */
struct kvm_luo_ser {
	u64 type;
	DECLARE_KHOSER_PTR(arch_state, struct kvm_vm_arch_luo_state *);
} __packed;

/* The compatibility string for KVM VM file handler */
#define KVM_LUO_FH_COMPATIBLE	"kvm_vm_luo_v1"

/**
 * struct kvm_vcpu_luo_ser - Main serialization structure for a KVM vCPU.
 * @vcpu_id:    The ID of the virtual CPU.
 * @flags:      Flags for vCPU preservation.
 * @vm_token:   Token of the associated KVM VM instance.
 * @arch_state: Preservation pointer to vCPU architectural state.
 * @cb:         Preservation pointer to Caretaker Control Block.
 *
 * Cross-kexec invariant: the incoming kernel may only dereference structures
 * declared in include/linux/kho/abi/ headers.  When @flags includes
 * %KVM_VCPU_LUO_FLAG_CARETAKER, the preserved Caretaker text writes live guest
 * state into @arch_state at detach time before transitioning @cb to
 * %KVM_CARETAKER_ATTACHED; the incoming kernel reads only @cb (via the
 * arch-specific ABI prefix) and @arch_state.
 */
struct kvm_vcpu_luo_ser {
	u32 vcpu_id;
	u32 flags;
	u64 vm_token;
	DECLARE_KHOSER_PTR(arch_state, struct kvm_vcpu_arch_luo_state *);
	DECLARE_KHOSER_PTR(cb, struct kvm_caretaker_cb *);
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
