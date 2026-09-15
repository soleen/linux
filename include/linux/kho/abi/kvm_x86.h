/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 */
#ifndef _LINUX_KHO_ABI_KVM_X86_H
#define _LINUX_KHO_ABI_KVM_X86_H

#ifdef CONFIG_X86_64

#include <linux/build_bug.h>
#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/kho/abi/kvm.h>
#include <uapi/linux/kvm.h>
#include <uapi/asm/kvm.h>

/**
 * DOC: x86 KVM Live Update ABI
 *
 * x86 KVM uses the ABI defined below for preserving architectural VM and vCPU
 * state across a kexec reboot using LUO.
 *
 * The vCPU-level architectural state contains the compact register sets and
 * CPUID table for each vCPU.
 *
 * All sub-structures (struct kvm_regs, struct kvm_sregs, struct kvm_mp_state,
 * struct kvm_cpuid_entry2) are uAPI contracts.
 */

/**
 * struct kvm_vcpu_arch_ser - Preserved x86 architectural vCPU state in RAM.
 * @regs:          General-purpose registers (uAPI struct kvm_regs).
 * @sregs:         Segment and control registers (uAPI struct kvm_sregs).
 * @mp_state:      Multiprocessor state (uAPI struct kvm_mp_state).
 * @pad:           Padding to maintain 64-bit alignment after mp_state.
 * @xcrs:          Extended control registers including XCR0 (uAPI struct kvm_xcrs).
 * @lapic:         In-kernel local APIC register state (uAPI struct kvm_lapic_state).
 * @pad_xsave:     Padding that aligns @xsave to 64 bytes; see the static_assert
 *                 below.  Must be zero.
 * @xsave:         Extended processor state (uAPI struct kvm_xsave).  This is the
 *                 only copy of the guest FPU state; there is no kvm_fpu twin.
 * @events:        vCPU exception, interrupt, NMI and SMI events (uAPI struct kvm_vcpu_events).
 * @debugregs:     Hardware debug registers DR0-DR7 (uAPI struct kvm_debugregs).
 * @num_msrs:      Number of valid MSR entries in msrs.
 * @cpuid_nent:    Number of valid CPUID entries immediately following msrs[num_msrs].
 * @msrs:          Array of preserved architectural and paravirtual MSR entries,
 *                 followed by @cpuid_nent struct kvm_cpuid_entry2 entries.
 */
struct kvm_vcpu_arch_ser {
	struct kvm_regs regs;
	struct kvm_sregs sregs;
	struct kvm_mp_state mp_state;
	u32 pad;
	struct kvm_xcrs xcrs;
	struct kvm_lapic_state lapic;
	u8 pad_xsave[40];
	struct kvm_xsave xsave;
	struct kvm_vcpu_events events;
	struct kvm_debugregs debugregs;
	u32 num_msrs;
	u32 cpuid_nent;
	struct kvm_msr_entry msrs[];
} __packed;

static_assert(offsetof(struct kvm_vcpu_arch_ser, msrs) % sizeof(u64) == 0,
	      "msrs must be 64-bit aligned");

/*
 * @xsave must be a legal XSAVE destination.  The structure is __packed, so
 * without @pad_xsave the member lands at offset 1880, which is not even
 * 16-byte aligned, and the XSAVE/XRSTOR family faults on anything less than
 * 64.  The allocation itself is fine: kho_alloc_preserve() returns a folio
 * address, so the base is page aligned.
 *
 * If this assert fires, a member above @xsave changed size; adjust
 * @pad_xsave rather than deleting the assert.
 */
static_assert(offsetof(struct kvm_vcpu_arch_ser, xsave) % 64 == 0,
	      "xsave must be 64-byte aligned to be XSAVE-able in place");

#endif /* CONFIG_X86_64 */

#endif /* _LINUX_KHO_ABI_KVM_X86_H */
