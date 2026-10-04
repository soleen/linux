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

static inline void kvm_set_lapic_tscdeadline_msr(struct kvm_vcpu *vcpu, u64 data)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	if (!kvm_apic_present(vcpu) || !apic_lvtt_tscdeadline(apic))
		return;

	apic->lapic_timer.tscdeadline = data;
}

static inline int kvm_x2apic_msr_read(struct kvm_vcpu *vcpu, u32 msr, u64 *data)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	u32 reg = (msr - APIC_BASE_MSR) << 4;

	if (!lapic_in_kernel(vcpu) || !apic_x2apic_mode(apic))
		return 1;

	switch (reg) {
	case APIC_ID:
	case APIC_LVR:
	case APIC_TASKPRI:
	case APIC_LDR:
	case APIC_SPIV:
	case APIC_ESR:
	case APIC_LVTT:
	case APIC_LVTTHMR:
	case APIC_LVTPC:
	case APIC_LVT0:
	case APIC_LVT1:
	case APIC_LVTERR:
	case APIC_TMICT:
	case APIC_TDCR:
		*data = kvm_lapic_get_reg(apic, reg);
		return 0;
	default:
		return 1;
	}
}

static inline int kvm_x2apic_msr_write(struct kvm_vcpu *vcpu, u32 msr, u64 data)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	u32 reg = (msr - APIC_BASE_MSR) << 4;

	if (!lapic_in_kernel(vcpu) || !apic_x2apic_mode(apic))
		return 1;

	if (reg != APIC_ICR && (data >> 32))
		return 1;

	if (reg == APIC_EOI)
		return 0;

	return 1;
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

static inline int kvm_set_msr_common(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	u32 msr = msr_info->index;
	u64 data = msr_info->data;

	switch (msr) {
	case MSR_AMD64_NB_CFG:
	case MSR_IA32_UCODE_REV:
	case MSR_IA32_UCODE_WRITE:
	case MSR_VM_HSAVE_PA:
	case MSR_AMD64_PATCH_LOADER:
	case MSR_AMD64_BU_CFG2:
	case MSR_AMD64_DC_CFG:
	case MSR_AMD64_TW_CFG:
	case MSR_F15H_EX_CFG:
	case MSR_IA32_BBL_CR_CTL3:
		break;
	case APIC_BASE_MSR ... APIC_BASE_MSR + 0xff:
		return kvm_x2apic_msr_write(vcpu, msr, data);
	case MSR_IA32_TSC_DEADLINE:
		kvm_set_lapic_tscdeadline_msr(vcpu, data);
		break;
	default:
		return KVM_MSR_RET_UNSUPPORTED;
	}
	return 0;
}

static inline int kvm_get_msr_common(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	switch (msr_info->index) {
	case MSR_IA32_PLATFORM_ID:
	case MSR_IA32_EBL_CR_POWERON:
	case MSR_IA32_LASTBRANCHFROMIP:
	case MSR_IA32_LASTBRANCHTOIP:
	case MSR_IA32_LASTINTFROMIP:
	case MSR_IA32_LASTINTTOIP:
	case MSR_AMD64_SYSCFG:
	case MSR_K8_TSEG_ADDR:
	case MSR_K8_TSEG_MASK:
	case MSR_VM_HSAVE_PA:
	case MSR_K8_INT_PENDING_MSG:
	case MSR_AMD64_NB_CFG:
	case MSR_FAM10H_MMIO_CONF_BASE:
	case MSR_AMD64_BU_CFG2:
	case MSR_IA32_PERF_CTL:
	case MSR_AMD64_DC_CFG:
	case MSR_AMD64_TW_CFG:
	case MSR_F15H_EX_CFG:
	case MSR_RAPL_POWER_UNIT:
	case MSR_PP0_ENERGY_STATUS:
	case MSR_PP1_ENERGY_STATUS:
	case MSR_PKG_ENERGY_STATUS:
	case MSR_DRAM_ENERGY_STATUS:
		msr_info->data = 0;
		break;
	case MSR_IA32_UCODE_REV:
		msr_info->data = vcpu->arch.microcode_version;
		break;
	case MSR_IA32_ARCH_CAPABILITIES:
		if (!guest_cpu_cap_has(vcpu, X86_FEATURE_ARCH_CAPABILITIES))
			return KVM_MSR_RET_UNSUPPORTED;
		msr_info->data = vcpu->arch.arch_capabilities;
		break;
	case MSR_IA32_PERF_CAPABILITIES:
		if (!guest_cpu_cap_has(vcpu, X86_FEATURE_PDCM))
			return KVM_MSR_RET_UNSUPPORTED;
		msr_info->data = vcpu->arch.perf_capabilities;
		break;
	case MSR_IA32_POWER_CTL:
		msr_info->data = vcpu->arch.msr_ia32_power_ctl;
		break;
	case MSR_IA32_TSC: {
		u64 offset = msr_info->host_initiated ? vcpu->arch.l1_tsc_offset :
							vcpu->arch.tsc_offset;
		u64 ratio = msr_info->host_initiated ? vcpu->arch.l1_tsc_scaling_ratio :
						       vcpu->arch.tsc_scaling_ratio;

		msr_info->data = kvm_scale_tsc(rdtsc(), ratio) + offset;
		break;
	}
	case MSR_IA32_CR_PAT:
		msr_info->data = vcpu->arch.pat;
		break;
	case MSR_MTRRcap:
		if (!msr_info->host_initiated &&
		    !guest_cpu_cap_has(vcpu, X86_FEATURE_MTRR))
			return 1;
		msr_info->data = 0x500 | KVM_NR_VAR_MTRR;
		break;
	case MSR_IA32_APICBASE:
		msr_info->data = vcpu->arch.apic_base;
		break;
	case APIC_BASE_MSR ... APIC_BASE_MSR + 0xff:
		return kvm_x2apic_msr_read(vcpu, msr_info->index, &msr_info->data);
	case MSR_IA32_TSC_DEADLINE:
		msr_info->data = kvm_get_lapic_tscdeadline_msr(vcpu);
		break;
	case MSR_IA32_TSC_ADJUST:
		msr_info->data = (u64)vcpu->arch.ia32_tsc_adjust_msr;
		break;
	case MSR_IA32_MISC_ENABLE:
		msr_info->data = vcpu->arch.ia32_misc_enable_msr;
		break;
	case MSR_IA32_SMBASE:
		if (!msr_info->host_initiated)
			return 1;
		msr_info->data = vcpu->arch.smbase;
		break;
	case MSR_SMI_COUNT:
		msr_info->data = vcpu->arch.smi_count;
		break;
	case MSR_EFER:
		msr_info->data = vcpu->arch.efer;
		break;
	case MSR_K7_HWCR:
		msr_info->data = vcpu->arch.msr_hwcr;
		break;
	case MSR_PLATFORM_INFO:
		if (!msr_info->host_initiated &&
		    !(vcpu->arch.msr_platform_info & MSR_PLATFORM_INFO_CPUID_FAULT))
			return 1;
		msr_info->data = vcpu->arch.msr_platform_info;
		break;
	case MSR_MISC_FEATURES_ENABLES:
		msr_info->data = vcpu->arch.msr_misc_features_enables;
		break;
	default:
		return KVM_MSR_RET_UNSUPPORTED;
	}
	return 0;
}

static inline int __kvm_set_msr(struct kvm_vcpu *vcpu, u32 index, u64 data,
				bool host_initiated)
{
	struct msr_data msr;

	switch (index) {
	case MSR_FS_BASE:
	case MSR_GS_BASE:
	case MSR_KERNEL_GS_BASE:
	case MSR_CSTAR:
	case MSR_LSTAR:
		if (is_noncanonical_msr_address(data, vcpu))
			return 1;
		break;
	case MSR_IA32_SYSENTER_EIP:
	case MSR_IA32_SYSENTER_ESP:
		data = __canonical_address(data, max_host_virt_addr_bits());
		break;
	default:
		break;
	}

	msr.data = data;
	msr.index = index;
	msr.host_initiated = host_initiated;

	return kvm_x86_call(set_msr)(vcpu, &msr);
}

static inline int __kvm_get_msr(struct kvm_vcpu *vcpu, u32 index, u64 *data,
				bool host_initiated)
{
	struct msr_data msr = {
		.index = index,
		.host_initiated = host_initiated,
	};
	int ret;

	ret = kvm_x86_call(get_msr)(vcpu, &msr);
	if (!ret)
		*data = msr.data;
	return ret;
}

static inline int kvm_emulate_rdmsr(struct kvm_vcpu *vcpu)
{
	u32 ecx = kvm_ecx_read(vcpu);
	u64 data;

	if (__kvm_get_msr(vcpu, ecx, &data, false))
		return 0;

	kvm_eax_write(vcpu, data & -1u);
	kvm_edx_write(vcpu, (data >> 32) & -1u);
	return kvm_skip_emulated_instruction(vcpu);
}

static inline int kvm_emulate_wrmsr(struct kvm_vcpu *vcpu)
{
	u32 ecx = kvm_ecx_read(vcpu);
	u64 data = kvm_read_edx_eax(vcpu);

	if (__kvm_set_msr(vcpu, ecx, data, false))
		return 0;

	return kvm_skip_emulated_instruction(vcpu);
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
