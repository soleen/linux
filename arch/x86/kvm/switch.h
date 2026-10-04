/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Shared x86 KVM fastpath exit and register helpers used by both the normal
 * host KVM world-switch paths and the isolated Caretaker preserved runtime.
 *
 * Modeled after arch/arm64/kvm/hyp/include/hyp/switch.h.
 */
#ifndef __ARCH_X86_KVM_SWITCH_H
#define __ARCH_X86_KVM_SWITCH_H

#include <linux/kvm_host.h>
#include <asm/apic.h>
#include <asm/cpuid/api.h>
#include <asm/posted_intr.h>

#include "cpuid.h"
#include "lapic.h"
#include "msrs.h"
#include "regs.h"
#include "x86.h"

/*
 * Shared LAPIC register and IRR/PIR helpers (used by lapic.c and Caretaker).
 */
static inline int apic_lvtt_tscdeadline(struct kvm_lapic *apic)
{
	return apic->lapic_timer.timer_mode == APIC_LVT_TIMER_TSCDEADLINE;
}

static inline bool ____kvm_apic_update_irr(unsigned long *pir, void *regs,
					   int *max_irr)
{
	unsigned long pir_vals[NR_PIR_WORDS];
	u32 *__pir = (void *)pir_vals;
	u32 i, vec;
	u32 irr_val, prev_irr_val;
	int max_new_irr;

	if (!pi_harvest_pir(pir, pir_vals)) {
		*max_irr = apic_find_highest_vector(regs + APIC_IRR);
		return false;
	}

	max_new_irr = -1;
	*max_irr = -1;

	for (i = vec = 0; i <= 7; i++, vec += 32) {
		u32 *p_irr = (u32 *)(regs + APIC_IRR + i * 0x10);

		irr_val = READ_ONCE(*p_irr);

		if (__pir[i]) {
			prev_irr_val = irr_val;
			do {
				irr_val = prev_irr_val | __pir[i];
			} while (prev_irr_val != irr_val &&
				 !try_cmpxchg(p_irr, &prev_irr_val, irr_val));

			if (prev_irr_val != irr_val)
				max_new_irr = __fls(irr_val ^ prev_irr_val) + vec;
		}
		if (irr_val)
			*max_irr = __fls(irr_val) + vec;
	}

	return max_new_irr != -1 && max_new_irr == *max_irr;
}

static inline bool __kvm_apic_update_irr_vcpu(struct kvm_vcpu *vcpu,
					      unsigned long *pir, int *max_irr)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	bool max_irr_is_from_pir;

	max_irr_is_from_pir = ____kvm_apic_update_irr(pir, apic->regs, max_irr);
	if (unlikely(!apic->apicv_active && max_irr_is_from_pir))
		apic->irr_pending = true;
	return max_irr_is_from_pir;
}

static inline int apic_search_irr(struct kvm_lapic *apic)
{
	return apic_find_highest_vector(apic->regs + APIC_IRR);
}

static inline int apic_find_highest_irr(struct kvm_lapic *apic)
{
	/*
	 * Note that irr_pending is just a hint. It will be always
	 * true with virtual interrupt delivery enabled.
	 */
	if (!apic->irr_pending)
		return -1;

	return apic_search_irr(apic);
}

static inline u64 __kvm_get_lapic_tscdeadline_msr(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	if (!kvm_apic_present(vcpu) || !apic_lvtt_tscdeadline(apic))
		return 0;

	return apic->lapic_timer.tscdeadline;
}

/*
 * Shared CPUID lookup helpers (used by cpuid.c and Caretaker).
 */
static inline struct kvm_cpuid_entry2 *__kvm_find_cpuid_entry2(
	struct kvm_cpuid_entry2 *entries, int nent, u32 function, u64 index)
{
	struct kvm_cpuid_entry2 *e;
	int i;

	for (i = 0; i < nent; i++) {
		e = &entries[i];

		if (e->function != function)
			continue;

		if (!(e->flags & KVM_CPUID_FLAG_SIGNIFCANT_INDEX) || e->index == index)
			return e;

		if (index == KVM_CPUID_INDEX_NOT_SIGNIFICANT) {
			WARN_ON_ONCE(cpuid_function_is_indexed(function));
			return e;
		}
	}

	return NULL;
}

#ifdef __CPU_PRESERVED_RUNTIME__
#include "caretaker/caretaker.h"
#endif

static inline unsigned long __kvm_get_rflags(struct kvm_vcpu *vcpu)
{
	unsigned long rflags;

	rflags = kvm_x86_call(get_rflags)(vcpu);
	if (vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP)
		rflags &= ~X86_EFLAGS_TF;
	return rflags;
}

#ifdef __CPU_PRESERVED_RUNTIME__
static inline unsigned long kvm_get_rflags(struct kvm_vcpu *vcpu)
{
	return __kvm_get_rflags(vcpu);
}

static inline bool kvm_apic_update_irr(struct kvm_vcpu *vcpu,
				       unsigned long *pir, int *max_irr)
{
	return __kvm_apic_update_irr_vcpu(vcpu, pir, max_irr);
}

static inline int kvm_lapic_find_highest_irr(struct kvm_vcpu *vcpu)
{
	return apic_find_highest_irr(vcpu->arch.apic);
}

static inline u64 kvm_get_lapic_tscdeadline_msr(struct kvm_vcpu *vcpu)
{
	return __kvm_get_lapic_tscdeadline_msr(vcpu);
}

static inline struct kvm_cpuid_entry2 *kvm_find_cpuid_entry2(
	struct kvm_cpuid_entry2 *entries, int nent, u32 function, u64 index)
{
	return __kvm_find_cpuid_entry2(entries, nent, function, index);
}
#endif /* __CPU_PRESERVED_RUNTIME__ */

static inline struct kvm_cpuid_entry2 *
get_out_of_range_cpuid_entry(struct kvm_vcpu *vcpu, u32 *fn_ptr, u32 index)
{
	struct kvm_cpuid_entry2 *basic, *class;
	u32 function = *fn_ptr;

	basic = kvm_find_cpuid_entry(vcpu, 0);
	if (!basic)
		return NULL;

	if (is_guest_vendor_amd(basic->ebx, basic->ecx, basic->edx) ||
	    is_guest_vendor_hygon(basic->ebx, basic->ecx, basic->edx))
		return NULL;

	if (function >= 0x40000000 && function <= 0x4fffffff)
		class = kvm_find_cpuid_entry(vcpu, function & 0xffffff00);
	else if (function >= 0xc0000000)
		class = kvm_find_cpuid_entry(vcpu, 0xc0000000);
	else
		class = kvm_find_cpuid_entry(vcpu, function & 0x80000000);

	if (class && function <= class->eax)
		return NULL;

	*fn_ptr = basic->eax;

	return kvm_find_cpuid_entry_index(vcpu, basic->eax, index);
}

static inline struct kvm_cpuid_entry2 *__kvm_cpuid(struct kvm_vcpu *vcpu,
						   u32 *function, u32 index,
						   u32 *eax, u32 *ebx,
						   u32 *ecx, u32 *edx,
						   bool exact_only,
						   bool *exact,
						   bool *used_max_basic)
{
	struct kvm_cpuid_entry2 *entry;

	entry = kvm_find_cpuid_entry_index(vcpu, *function, index);
	*exact = !!entry;
	*used_max_basic = false;

	if (!entry && !exact_only) {
		entry = get_out_of_range_cpuid_entry(vcpu, function, index);
		*used_max_basic = !!entry;
	}

	if (entry) {
		*eax = entry->eax;
		*ebx = entry->ebx;
		*ecx = entry->ecx;
		*edx = entry->edx;
	} else {
		*eax = *ebx = *ecx = *edx = 0;
		if (*function == 0xb || *function == 0x1f) {
			struct kvm_cpuid_entry2 *sub =
				kvm_find_cpuid_entry_index(vcpu, *function, 1);
			if (sub) {
				*ecx = index & 0xff;
				*edx = sub->edx;
			}
		}
	}

	return entry;
}

#ifdef __CPU_PRESERVED_RUNTIME__
static inline bool kvm_cpuid(struct kvm_vcpu *vcpu, u32 *eax, u32 *ebx,
			     u32 *ecx, u32 *edx, bool exact_only)
{
	u32 function = *eax, index = *ecx;
	bool exact, used_max_basic;

	__kvm_cpuid(vcpu, &function, index, eax, ebx, ecx, edx, exact_only,
		    &exact, &used_max_basic);
	return exact;
}

static inline int kvm_skip_emulated_instruction(struct kvm_vcpu *vcpu)
{
	return kvm_x86_call(skip_emulated_instruction)(vcpu);
}

static inline int kvm_emulate_halt(struct kvm_vcpu *vcpu)
{
	++vcpu->stat.halt_exits;
	cpu_relax();
	return kvm_skip_emulated_instruction(vcpu);
}

static inline int kvm_emulate_cpuid(struct kvm_vcpu *vcpu)
{
	u32 eax, ebx, ecx, edx;

	if (!kvm_is_cpuid_allowed(vcpu))
		return 0;

	eax = kvm_eax_read(vcpu);
	ecx = kvm_ecx_read(vcpu);
	kvm_cpuid(vcpu, &eax, &ebx, &ecx, &edx, false);
	kvm_eax_write(vcpu, eax);
	kvm_ebx_write(vcpu, ebx);
	kvm_ecx_write(vcpu, ecx);
	kvm_edx_write(vcpu, edx);
	return kvm_skip_emulated_instruction(vcpu);
}

static inline int kvm_emulate_wbinvd(struct kvm_vcpu *vcpu)
{
	return kvm_skip_emulated_instruction(vcpu);
}

static inline int kvm_emulate_as_nop(struct kvm_vcpu *vcpu)
{
	return kvm_skip_emulated_instruction(vcpu);
}

static inline int kvm_emulate_invd(struct kvm_vcpu *vcpu)
{
	return kvm_emulate_as_nop(vcpu);
}

static inline int kvm_emulate_rdtsc(struct kvm_vcpu *vcpu)
{
	u64 tsc = kvm_read_l1_tsc(vcpu, rdtsc());

	kvm_eax_write(vcpu, (u32)tsc);
	kvm_edx_write(vcpu, tsc >> 32);
	return kvm_skip_emulated_instruction(vcpu);
}
#endif /* __CPU_PRESERVED_RUNTIME__ */

#endif /* __ARCH_X86_KVM_SWITCH_H */
