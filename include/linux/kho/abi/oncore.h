/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * On-Core Session Preservation ABI for Live Update
 */
#ifndef _LINUX_KHO_ABI_ONCORE_H
#define _LINUX_KHO_ABI_ONCORE_H

#include <linux/build_bug.h>
#include <linux/stddef.h>
#include <linux/types.h>
#include <uapi/linux/liveupdate.h>

/**
 * struct oncore_session_ser - Serialized on-core session metadata
 * @nr_cpus:       Count of physical CPUs assigned to this session.
 * @nr_cpu_words:  Number of 64-bit words in cpus_bitmap.
 * @session_name:  LUO session name.
 * @sess_pa:       Physical address of preserved struct oncore_session.
 * @pgd_pa:        Physical address of session PGD.
 * @runqueue_pa:   Physical address of oncore runqueue.
 * @cpus_bitmap:   Variable-length bitmask of physical CPUs assigned to session.
 */
struct oncore_session_ser {
	u32 nr_cpus;
	u32 nr_cpu_words;
	char session_name[LIVEUPDATE_SESSION_NAME_LENGTH];
	u64 sess_pa;
	u64 pgd_pa;
	u64 runqueue_pa;
	u64 cpus_bitmap[];
} __packed;

static_assert(offsetof(struct oncore_session_ser, cpus_bitmap) % sizeof(u64) == 0,
	      "cpus_bitmap must be 64-bit aligned");

#endif /* _LINUX_KHO_ABI_ONCORE_H */
