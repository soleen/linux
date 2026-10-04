/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Shared AMD SVM fastpath exit and register helpers used by both the normal
 * host KVM world-switch paths (svm.c) and the Caretaker preserved runtime.
 *
 * Modeled after arch/arm64/kvm/hyp/include/hyp/switch.h.
 */
#ifndef __KVM_X86_SVM_SWITCH_H
#define __KVM_X86_SVM_SWITCH_H

#include <linux/kvm_host.h>

#include "svm.h"
#include "../cpuid.h"
#include "../lapic.h"
#include "../msrs.h"
#include "../switch.h"
#include "../x86.h"

static inline int svm_get_cpl(struct kvm_vcpu *vcpu);

#ifdef __CPU_PRESERVED_RUNTIME__
static inline void svm_switch_cache_pdptrs(struct kvm_vcpu *vcpu) {}
#else /* !__CPU_PRESERVED_RUNTIME__ */
static inline void svm_switch_cache_pdptrs(struct kvm_vcpu *vcpu)
{
	if (npt_enabled)
		load_pdptrs(vcpu, kvm_read_cr3(vcpu));
}
#endif /* __CPU_PRESERVED_RUNTIME__ */

static inline unsigned long svm_get_rflags(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	unsigned long rflags = svm->vmcb->save.rflags;

	if (svm->nmi_singlestep) {
		/* Hide our flags if they were not set by the guest */
		if (!(svm->nmi_singlestep_guest_rflags & X86_EFLAGS_TF))
			rflags &= ~X86_EFLAGS_TF;
		if (!(svm->nmi_singlestep_guest_rflags & X86_EFLAGS_RF))
			rflags &= ~X86_EFLAGS_RF;
	}
	return rflags;
}

static inline void svm_set_rflags(struct kvm_vcpu *vcpu, unsigned long rflags)
{
	if (to_svm(vcpu)->nmi_singlestep)
		rflags |= (X86_EFLAGS_TF | X86_EFLAGS_RF);

	/*
	 * Any change of EFLAGS.VM is accompanied by a reload of SS
	 * (caused by either a task switch or an inter-privilege IRET),
	 * so we do not need to update the CPL here.
	 */
	to_svm(vcpu)->vmcb->save.rflags = rflags;
}

static inline void svm_cache_reg(struct kvm_vcpu *vcpu, enum kvm_reg reg)
{
	kvm_register_mark_available(vcpu, reg);

	switch (reg) {
	case VCPU_REG_PDPTR:
		/*
		 * When !npt_enabled, vcpu->pdptrs[] is already available since
		 * it is always updated per SDM when moving to CRs.
		 */
		svm_switch_cache_pdptrs(vcpu);
		break;
	default:
		KVM_BUG_ON(1, vcpu->kvm);
	}
}

static inline struct vmcb_seg *svm_seg(struct kvm_vcpu *vcpu, int seg)
{
	struct vmcb_save_area *save = &to_svm(vcpu)->vmcb->save;
	struct vmcb_save_area *save01 = &to_svm(vcpu)->vmcb01.ptr->save;

	switch (seg) {
	case VCPU_SREG_CS: return &save->cs;
	case VCPU_SREG_DS: return &save->ds;
	case VCPU_SREG_ES: return &save->es;
	case VCPU_SREG_FS: return &save01->fs;
	case VCPU_SREG_GS: return &save01->gs;
	case VCPU_SREG_SS: return &save->ss;
	case VCPU_SREG_TR: return &save01->tr;
	case VCPU_SREG_LDTR: return &save01->ldtr;
	}
	BUG();
	return NULL;
}

static inline void svm_get_segment(struct kvm_vcpu *vcpu,
				   struct kvm_segment *var, int seg)
{
	struct vmcb_seg *s = svm_seg(vcpu, seg);

	var->base = s->base;
	var->limit = s->limit;
	var->selector = s->selector;
	var->type = s->attrib & SVM_SELECTOR_TYPE_MASK;
	var->s = (s->attrib >> SVM_SELECTOR_S_SHIFT) & 1;
	var->dpl = (s->attrib >> SVM_SELECTOR_DPL_SHIFT) & 3;
	var->present = (s->attrib >> SVM_SELECTOR_P_SHIFT) & 1;
	var->avl = (s->attrib >> SVM_SELECTOR_AVL_SHIFT) & 1;
	var->l = (s->attrib >> SVM_SELECTOR_L_SHIFT) & 1;
	var->db = (s->attrib >> SVM_SELECTOR_DB_SHIFT) & 1;

	/*
	 * AMD CPUs circa 2014 track the G bit for all segments except CS.
	 * However, the SVM spec states that the G bit is not observed by the
	 * CPU, and some VMware virtual CPUs drop the G bit for all segments.
	 * So let's synthesize a legal G bit for all segments, this helps
	 * running KVM nested. It also helps cross-vendor migration, because
	 * Intel's vmentry has a check on the 'G' bit.
	 */
	var->g = s->limit > 0xfffff;

	/*
	 * AMD's VMCB does not have an explicit unusable field, so emulate it
	 * for cross vendor migration purposes by "not present"
	 */
	var->unusable = !var->present;

	switch (seg) {
	case VCPU_SREG_TR:
		/*
		 * Work around a bug where the busy flag in the tr selector
		 * isn't exposed
		 */
		var->type |= 0x2;
		break;
	case VCPU_SREG_DS:
	case VCPU_SREG_ES:
	case VCPU_SREG_FS:
	case VCPU_SREG_GS:
		/*
		 * The accessed bit must always be set in the segment
		 * descriptor cache, although it can be cleared in the
		 * descriptor, the cached bit always remains at 1. Since
		 * Intel has a check on this, set it here to support
		 * cross-vendor migration.
		 */
		if (!var->unusable)
			var->type |= 0x1;
		break;
	case VCPU_SREG_SS:
		/*
		 * On AMD CPUs sometimes the DB bit in the segment
		 * descriptor is left as 1, although the whole segment has
		 * been made unusable. Clear it here to pass an Intel VMX
		 * entry check when cross vendor migrating.
		 */
		if (var->unusable)
			var->db = 0;
		/* This is symmetric with svm_set_segment() */
		var->dpl = to_svm(vcpu)->vmcb->save.cpl;
		break;
	}
}

static inline int svm_get_cpl(struct kvm_vcpu *vcpu)
{
	struct vmcb_save_area *save = &to_svm(vcpu)->vmcb->save;

	return save->cpl;
}

static inline void svm_get_cs_db_l_bits(struct kvm_vcpu *vcpu, int *db, int *l)
{
	struct kvm_segment cs;

	svm_get_segment(vcpu, &cs, VCPU_SREG_CS);
	*db = cs.db;
	*l = cs.l;
}

static inline void svm_get_idt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	dt->size = svm->vmcb->save.idtr.limit;
	dt->address = svm->vmcb->save.idtr.base;
}

static inline void svm_get_gdt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	dt->size = svm->vmcb->save.gdtr.limit;
	dt->address = svm->vmcb->save.gdtr.base;
}

#endif /* __KVM_X86_SVM_SWITCH_H */
