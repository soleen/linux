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
#include <asm/posted_intr.h>

#include "lapic.h"

/*
 * Shared LAPIC register and IRR/PIR helpers (used by lapic.c and Caretaker).
 */
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

#endif /* __ARCH_X86_KVM_SWITCH_H */
