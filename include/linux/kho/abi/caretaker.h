/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * Caretaker Preservation ABI for Live Update
 */
#ifndef _LINUX_KHO_ABI_CARETAKER_H
#define _LINUX_KHO_ABI_CARETAKER_H

#include <linux/cpumask.h>
#include <linux/types.h>
#include <uapi/linux/liveupdate.h>

/**
 * DOC: Caretaker Live Update ABI
 *
 * Caretaker uses the ABI defined below for tracking detached vCPU execution
 * across a live update.
 */

/* Attachment states */
#define CARETAKER_KVM_ATTACHED	0	/* Normal host KVM handling */
#define CARETAKER_KVM_DETACHED	1	/* Exits run in Caretaker */
#define CARETAKER_KVM_ATTACHING	2	/* Transitioning from Caretaker to host KVM */
#define CARETAKER_INVALID_PCPU	U32_MAX	/* Unassigned pCPU identifier */

/**
 * struct caretaker_cb - Caretaker Control Block
 * @attachment_state: Current attachment state (%CARETAKER_KVM_ATTACHED or
 *                    %CARETAKER_KVM_DETACHED).
 * @pcpu_id: Physical CPU ID where this vCPU runs while detached.
 * @vcpu_id: Guest vCPU identifier.
 * @vm_token: Preserved VM token for LUO lookup and validation.
 * @vcpu_token: Preserved vCPU token for LUO lookup and validation.
 * @runtime_pa: Hypervisor private runtime execution context physical address.
 * @runtime_size: Hypervisor private runtime execution context size in bytes.
 *
 * Coordinates vCPU execution state across hypervisor detachment,
 * live update, and Caretaker CPU preservation.
 */
struct caretaker_cb {
	u64 attachment_state;
	u32 pcpu_id;
	u32 vcpu_id;
	u64 vm_token;
	u64 vcpu_token;
	u64 runtime_pa;
	u64 runtime_size;
} __packed;

#define CARETAKER_SESSION_SER_MAGIC	0x43545353	/* "CTSS" */

/**
 * struct caretaker_session_ser - Serialized Caretaker session metadata
 * @magic:         Magic number (CARETAKER_SESSION_SER_MAGIC).
 * @nr_cpus:       Count of physical CPUs assigned to this session.
 * @session_name:  LUO session name.
 * @sess_pa:       Physical address of preserved struct caretaker_session.
 * @pgd_pa:        Physical address of session PGD.
 * @cpus:          Bitmask of physical CPUs assigned to this session.
 * @runqueue_pa:   Physical address of Caretaker runqueue.
 */
struct caretaker_session_ser {
	u32 magic;
	u32 nr_cpus;
	char session_name[LIVEUPDATE_SESSION_NAME_LENGTH];
	u64 sess_pa;
	u64 pgd_pa;
	cpumask_t cpus;
	u64 runqueue_pa;
} __packed;

#endif /* _LINUX_KHO_ABI_CARETAKER_H */
