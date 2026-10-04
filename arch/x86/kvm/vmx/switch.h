/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Shared Intel VMX fastpath exit and register helpers used by both the normal
 * host KVM world-switch paths (vmx.c) and the Caretaker preserved runtime.
 *
 * Modeled after arch/arm64/kvm/hyp/include/hyp/switch.h.
 */
#ifndef __KVM_X86_VMX_SWITCH_H
#define __KVM_X86_VMX_SWITCH_H

#include <linux/kvm_host.h>

#include "capabilities.h"
#include "posted_intr.h"
#include "vmcs.h"
#include "vmx.h"
#include "vmx_ops.h"
#include "../lapic.h"
#include "../msrs.h"
#include "../switch.h"
#include "../x86.h"

#ifdef __CPU_PRESERVED_RUNTIME__
static inline void vmx_switch_update_emulated_ref_flags(struct vcpu_vmx *vmx,
							unsigned long old_rflags)
{
}

static inline void vmx_switch_update_emulated_instruction(struct kvm_vcpu *vcpu)
{
}

static inline bool vmx_switch_use_exit_instr_len(union vmx_exit_reason exit_reason)
{
	return true;
}

static inline int vmx_switch_emulate_skip(struct kvm_vcpu *vcpu)
{
	return 0;
}
#else /* !__CPU_PRESERVED_RUNTIME__ */
#include "x86_ops.h"

static inline void vmx_switch_update_emulated_ref_flags(struct vcpu_vmx *vmx,
							unsigned long old_rflags)
{
	if ((old_rflags ^ vmx->rflags) & X86_EFLAGS_VM)
		vmx->vt.emulation_required = vmx_emulation_required(&vmx->vcpu);
}

static inline void vmx_switch_update_emulated_instruction(struct kvm_vcpu *vcpu)
{
	vmx_update_emulated_instruction(vcpu);
}

static inline bool vmx_switch_use_exit_instr_len(union vmx_exit_reason exit_reason)
{
	return !cpu_feature_enabled(X86_FEATURE_HYPERVISOR) ||
	       exit_reason.basic != EXIT_REASON_EPT_MISCONFIG;
}

static inline int vmx_switch_emulate_skip(struct kvm_vcpu *vcpu)
{
	return kvm_emulate_instruction(vcpu, EMULTYPE_SKIP);
}
#endif /* __CPU_PRESERVED_RUNTIME__ */

#define RMODE_GUEST_OWNED_EFLAGS_BITS (~(X86_EFLAGS_IOPL | X86_EFLAGS_VM))

#define VMX_SEGMENT_FIELD(seg)					\
	[VCPU_SREG_##seg] = {					\
		.selector = GUEST_##seg##_SELECTOR,		\
		.base = GUEST_##seg##_BASE,			\
		.limit = GUEST_##seg##_LIMIT,			\
		.ar_bytes = GUEST_##seg##_AR_BYTES,		\
	}

static const struct kvm_vmx_segment_field {
	unsigned int selector;
	unsigned int base;
	unsigned int limit;
	unsigned int ar_bytes;
} kvm_vmx_segment_fields[] = {
	VMX_SEGMENT_FIELD(CS),
	VMX_SEGMENT_FIELD(DS),
	VMX_SEGMENT_FIELD(ES),
	VMX_SEGMENT_FIELD(FS),
	VMX_SEGMENT_FIELD(GS),
	VMX_SEGMENT_FIELD(SS),
	VMX_SEGMENT_FIELD(TR),
	VMX_SEGMENT_FIELD(LDTR),
};

static inline bool vmx_segment_cache_test_set(struct vcpu_vmx *vmx,
					      unsigned int seg,
					      unsigned int field)
{
	bool ret;
	u32 mask = 1 << (seg * SEG_FIELD_NR + field);

	if (!kvm_register_is_available(&vmx->vcpu, VCPU_REG_SEGMENTS)) {
		kvm_register_mark_available(&vmx->vcpu, VCPU_REG_SEGMENTS);
		vmx->segment_cache.bitmask = 0;
	}
	ret = vmx->segment_cache.bitmask & mask;
	vmx->segment_cache.bitmask |= mask;
	return ret;
}

static inline u16 vmx_read_guest_seg_selector(struct vcpu_vmx *vmx,
					      unsigned int seg)
{
	u16 *p = &vmx->segment_cache.seg[seg].selector;

	if (!vmx_segment_cache_test_set(vmx, seg, SEG_FIELD_SEL))
		*p = vmcs_read16(kvm_vmx_segment_fields[seg].selector);
	return *p;
}

static inline ulong vmx_read_guest_seg_base(struct vcpu_vmx *vmx,
					    unsigned int seg)
{
	ulong *p = &vmx->segment_cache.seg[seg].base;

	if (!vmx_segment_cache_test_set(vmx, seg, SEG_FIELD_BASE))
		*p = vmcs_readl(kvm_vmx_segment_fields[seg].base);
	return *p;
}

static inline u32 vmx_read_guest_seg_limit(struct vcpu_vmx *vmx,
					   unsigned int seg)
{
	u32 *p = &vmx->segment_cache.seg[seg].limit;

	if (!vmx_segment_cache_test_set(vmx, seg, SEG_FIELD_LIMIT))
		*p = vmcs_read32(kvm_vmx_segment_fields[seg].limit);
	return *p;
}

static inline u32 vmx_read_guest_seg_ar(struct vcpu_vmx *vmx,
					unsigned int seg)
{
	u32 *p = &vmx->segment_cache.seg[seg].ar;

	if (!vmx_segment_cache_test_set(vmx, seg, SEG_FIELD_AR))
		*p = vmcs_read32(kvm_vmx_segment_fields[seg].ar_bytes);
	return *p;
}

static inline void __vmx_get_segment(struct kvm_vcpu *vcpu,
				     struct kvm_segment *var, int seg)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	u32 ar;

	if (vmx->rmode.vm86_active && seg != VCPU_SREG_LDTR) {
		*var = vmx->rmode.segs[seg];
		if (seg == VCPU_SREG_TR ||
		    var->selector == vmx_read_guest_seg_selector(vmx, seg))
			return;
		var->base = vmx_read_guest_seg_base(vmx, seg);
		var->selector = vmx_read_guest_seg_selector(vmx, seg);
		return;
	}
	var->base = vmx_read_guest_seg_base(vmx, seg);
	var->limit = vmx_read_guest_seg_limit(vmx, seg);
	var->selector = vmx_read_guest_seg_selector(vmx, seg);
	ar = vmx_read_guest_seg_ar(vmx, seg);
	var->unusable = (ar >> 16) & 1;
	var->type = ar & 15;
	var->s = (ar >> 4) & 1;
	var->dpl = (ar >> 5) & 3;
	/*
	 * Some userspaces do not preserve unusable property. Since usable
	 * segment has to be present according to VMX spec we can use present
	 * property to amend userspace bug by making unusable segment always
	 * nonpresent. vmx_segment_access_rights() already marks nonpresent
	 * segment as unusable.
	 */
	var->present = !var->unusable;
	var->avl = (ar >> 12) & 1;
	var->l = (ar >> 13) & 1;
	var->db = (ar >> 14) & 1;
	var->g = (ar >> 15) & 1;
}

static inline void __vmx_get_cs_db_l_bits(struct kvm_vcpu *vcpu, int *db, int *l)
{
	u32 ar = vmx_read_guest_seg_ar(to_vmx(vcpu), VCPU_SREG_CS);

	*db = (ar >> 14) & 1;
	*l = (ar >> 13) & 1;
}

static inline int __vmx_get_cpl(struct kvm_vcpu *vcpu, bool no_cache)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	int ar;

	if (unlikely(vmx->rmode.vm86_active))
		return 0;

	if (no_cache)
		ar = vmcs_read32(GUEST_SS_AR_BYTES);
	else
		ar = vmx_read_guest_seg_ar(vmx, VCPU_SREG_SS);
	return VMX_AR_DPL(ar);
}

static inline void __vmx_get_idt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	dt->size = vmcs_read32(GUEST_IDTR_LIMIT);
	dt->address = vmcs_readl(GUEST_IDTR_BASE);
}

static inline void __vmx_get_gdt(struct kvm_vcpu *vcpu, struct desc_ptr *dt)
{
	dt->size = vmcs_read32(GUEST_GDTR_LIMIT);
	dt->address = vmcs_readl(GUEST_GDTR_BASE);
}

static inline void __ept_save_pdptrs(struct kvm_vcpu *vcpu)
{
	if (WARN_ON_ONCE(!is_pae_paging(vcpu)))
		return;

	vcpu->arch.pdptrs[0] = vmcs_read64(GUEST_PDPTR0);
	vcpu->arch.pdptrs[1] = vmcs_read64(GUEST_PDPTR1);
	vcpu->arch.pdptrs[2] = vmcs_read64(GUEST_PDPTR2);
	vcpu->arch.pdptrs[3] = vmcs_read64(GUEST_PDPTR3);

	kvm_register_mark_available(vcpu, VCPU_REG_PDPTR);
}

static inline void __vmx_cache_reg(struct kvm_vcpu *vcpu, enum kvm_reg reg)
{
	unsigned long guest_owned_bits;

	kvm_register_mark_available(vcpu, reg);

	switch (reg) {
	case VCPU_REGS_RSP:
		vcpu->arch.regs[VCPU_REGS_RSP] = vmcs_readl(GUEST_RSP);
		break;
	case VCPU_REG_RIP:
		vcpu->arch.rip = vmcs_readl(GUEST_RIP);
		break;
	case VCPU_REG_PDPTR:
		if (enable_ept)
			__ept_save_pdptrs(vcpu);
		break;
	case VCPU_REG_CR0:
		guest_owned_bits = vcpu->arch.cr0_guest_owned_bits;

		vcpu->arch.cr0 &= ~guest_owned_bits;
		vcpu->arch.cr0 |= vmcs_readl(GUEST_CR0) & guest_owned_bits;
		break;
	case VCPU_REG_CR3:
		/*
		 * When intercepting CR3 loads, e.g. for shadowing paging, KVM's
		 * CR3 is loaded into hardware, not the guest's CR3.
		 */
		if (!(exec_controls_get(to_vmx(vcpu)) & CPU_BASED_CR3_LOAD_EXITING))
			vcpu->arch.cr3 = vmcs_readl(GUEST_CR3);
		break;
	case VCPU_REG_CR4:
		guest_owned_bits = vcpu->arch.cr4_guest_owned_bits;

		vcpu->arch.cr4 &= ~guest_owned_bits;
		vcpu->arch.cr4 |= vmcs_readl(GUEST_CR4) & guest_owned_bits;
		break;
	default:
		KVM_BUG_ON(1, vcpu->kvm);
		break;
	}
}

static inline unsigned long __vmx_get_rflags(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	unsigned long rflags, save_rflags;

	if (!kvm_register_is_available(vcpu, VCPU_REG_RFLAGS)) {
		kvm_register_mark_available(vcpu, VCPU_REG_RFLAGS);
		rflags = vmcs_readl(GUEST_RFLAGS);
		if (vmx->rmode.vm86_active) {
			rflags &= RMODE_GUEST_OWNED_EFLAGS_BITS;
			save_rflags = vmx->rmode.save_rflags;
			rflags |= save_rflags & ~RMODE_GUEST_OWNED_EFLAGS_BITS;
		}
		vmx->rflags = rflags;
	}
	return vmx->rflags;
}

static inline void __vmx_set_rflags(struct kvm_vcpu *vcpu, unsigned long rflags)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	unsigned long old_rflags;

	/*
	 * Unlike CR0 and CR4, RFLAGS handling requires checking if the vCPU
	 * is an unrestricted guest in order to mark L2 as needing emulation
	 * if L1 runs L2 as a restricted guest.
	 */
	if (is_unrestricted_guest(vcpu)) {
		kvm_register_mark_available(vcpu, VCPU_REG_RFLAGS);
		vmx->rflags = rflags;
		vmcs_writel(GUEST_RFLAGS, rflags);
		return;
	}

	old_rflags = __vmx_get_rflags(vcpu);
	vmx->rflags = rflags;
	if (vmx->rmode.vm86_active) {
		vmx->rmode.save_rflags = rflags;
		rflags |= X86_EFLAGS_IOPL | X86_EFLAGS_VM;
	}
	vmcs_writel(GUEST_RFLAGS, rflags);

	vmx_switch_update_emulated_ref_flags(vmx, old_rflags);
}

static inline u32 __vmx_get_interrupt_shadow(struct kvm_vcpu *vcpu)
{
	u32 interruptibility = vmcs_read32(GUEST_INTERRUPTIBILITY_INFO);
	int ret = 0;

	if (interruptibility & GUEST_INTR_STATE_STI)
		ret |= KVM_X86_SHADOW_INT_STI;
	if (interruptibility & GUEST_INTR_STATE_MOV_SS)
		ret |= KVM_X86_SHADOW_INT_MOV_SS;

	return ret;
}

static inline void __vmx_set_interrupt_shadow(struct kvm_vcpu *vcpu, int mask)
{
	u32 interruptibility_old = vmcs_read32(GUEST_INTERRUPTIBILITY_INFO);
	u32 interruptibility = interruptibility_old;

	interruptibility &= ~(GUEST_INTR_STATE_STI | GUEST_INTR_STATE_MOV_SS);

	if (mask & KVM_X86_SHADOW_INT_MOV_SS)
		interruptibility |= GUEST_INTR_STATE_MOV_SS;
	else if (mask & KVM_X86_SHADOW_INT_STI)
		interruptibility |= GUEST_INTR_STATE_STI;

	if ((interruptibility != interruptibility_old))
		vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, interruptibility);
}

static inline int skip_emulated_instruction(struct kvm_vcpu *vcpu)
{
	union vmx_exit_reason exit_reason = vmx_get_exit_reason(vcpu);
	unsigned long rip, orig_rip;
	u32 instr_len;

	/*
	 * Using VMCS.VM_EXIT_INSTRUCTION_LEN on EPT misconfig depends on
	 * undefined behavior: Intel's SDM doesn't mandate the VMCS field be
	 * set when EPT misconfig occurs.  In practice, real hardware updates
	 * VM_EXIT_INSTRUCTION_LEN on EPT misconfig, but other hypervisors
	 * (namely Hyper-V) don't set it due to it being undefined behavior,
	 * i.e. we end up advancing IP with some random value.
	 */
	if (vmx_switch_use_exit_instr_len(exit_reason)) {
		instr_len = vmcs_read32(VM_EXIT_INSTRUCTION_LEN);

		if (!instr_len)
			goto rip_updated;

		WARN_ONCE(exit_reason.enclave_mode,
			  "skipping instruction after SGX enclave VM-Exit");

		orig_rip = kvm_rip_read(vcpu);
		rip = orig_rip + instr_len;
#ifdef CONFIG_X86_64
		/*
		 * We need to mask out the high 32 bits of RIP if not in 64-bit
		 * mode, but just finding out that we are in 64-bit mode is
		 * quite expensive.  Only do it if there was a carry.
		 */
		if (unlikely(((rip ^ orig_rip) >> 31) == 3) && !is_64_bit_mode(vcpu))
			rip = (u32)rip;
#endif
		kvm_rip_write(vcpu, rip);
	} else {
		if (!vmx_switch_emulate_skip(vcpu))
			return 0;
	}

rip_updated:
	/* skipping an emulated instruction also counts */
	__vmx_set_interrupt_shadow(vcpu, 0);

	return 1;
}

static inline int __vmx_skip_emulated_instruction(struct kvm_vcpu *vcpu)
{
	vmx_switch_update_emulated_instruction(vcpu);
	return skip_emulated_instruction(vcpu);
}

#endif /* __KVM_X86_VMX_SWITCH_H */
