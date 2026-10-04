// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * x86 KVM Caretaker host lifecycle and hardware virtualization attachment.
 */

#include <linux/cc_platform.h>
#include <linux/cpu.h>
#include <linux/cpu_preserve.h>
#include <linux/delay.h>
#include <linux/kexec_handover.h>
#include <linux/kho/abi/kvm.h>
#include <linux/kvm_host.h>
#include <linux/oncore.h>
#include <linux/smp.h>

#include <asm/apic.h>
#include <asm/cpu_entry_area.h>
#include <asm/desc.h>
#include <asm/fpu/api.h>
#include <asm/fpu/xcr.h>
#include <asm/fixmap.h>
#include <asm/irq_vectors.h>
#include <asm/msr.h>
#include <linux/sync_core.h>
#include <asm/trapnr.h>
#include <asm/virt.h>

#include "caretaker.h"
#include "cpuid.h"
#include "lapic.h"
#include "pmu.h"
#include "regs.h"
#include "x86.h"

/* Defined below its first use. */
static void kvm_x86_caretaker_init_gdt_tss(struct desc_struct *gdt,
					   struct x86_hw_tss *tss,
					   unsigned long stack_top);

static const struct kvm_x86_caretaker_ops *kvm_x86_caretaker_host_ops;

void kvm_x86_caretaker_register_ops(const struct kvm_x86_caretaker_ops *ops)
{
	WRITE_ONCE(kvm_x86_caretaker_host_ops, ops);
	WRITE_ONCE(kvm_x86_caretaker_ops, ops ? ops->runtime : NULL);
	WRITE_ONCE(kvm_x86_ops_ptr, (ops && ops->runtime) ? ops->runtime->x86_ops : NULL);
	cpu_preserved_clean(&kvm_x86_caretaker_ops);
	cpu_preserved_clean(&kvm_x86_ops_ptr);
}

void kvm_x86_caretaker_unregister_ops(const struct kvm_x86_caretaker_ops *ops)
{
	if (kvm_x86_caretaker_host_ops == ops) {
		WRITE_ONCE(kvm_x86_caretaker_host_ops, NULL);
		WRITE_ONCE(kvm_x86_caretaker_ops, NULL);
		WRITE_ONCE(kvm_x86_ops_ptr, NULL);
		cpu_preserved_clean(&kvm_x86_caretaker_ops);
		cpu_preserved_clean(&kvm_x86_ops_ptr);
	}
}

static void kvm_arch_vcpu_caretaker_init(struct kvm_vcpu *vcpu)
{
	if (kvm_x86_caretaker_host_ops && kvm_x86_caretaker_host_ops->init)
		kvm_x86_caretaker_host_ops->init(vcpu);
}

static bool kvm_x86_caretaker_has_hw_mitigations(void)
{
	/*
	 * The preserved Caretaker runtime executes in an isolated address
	 * space without full host software speculation mitigations. Require a
	 * reasonably recent CPU with hardware mitigations (e.g., eIBRS on
	 * Intel or Zen 3+ on AMD, and hardware immunity to Meltdown, L1TF,
	 * MDS, TAA, SRBDS, and Retbleed).
	 */
	if (boot_cpu_has_bug(X86_BUG_CPU_MELTDOWN) ||
	    boot_cpu_has_bug(X86_BUG_L1TF) ||
	    boot_cpu_has_bug(X86_BUG_MDS) ||
	    boot_cpu_has_bug(X86_BUG_TAA) ||
	    boot_cpu_has_bug(X86_BUG_SRBDS) ||
	    boot_cpu_has_bug(X86_BUG_RETBLEED))
		return false;

	if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL &&
	    !boot_cpu_has(X86_FEATURE_IBRS_ENHANCED))
		return false;

	if (boot_cpu_data.x86_vendor == X86_VENDOR_AMD &&
	    boot_cpu_data.x86 < 0x19)
		return false;

	return true;
}

int kvm_arch_vcpu_caretaker_preserve(struct kvm_vcpu *vcpu,
				     struct kvm_vcpu_ser *ser,
				     struct kvm_vcpu_arch_ser *state, size_t size)
{
	struct kvm_caretaker_arch_ser *abi;
	struct caretaker_x86_page *cxp;
	struct kvm_cpuid2 *cpuid;
	struct oncore_session *sess;
	int ret;

	if (!vcpu->caretaker.job)
		return 0;

	if (!kvm_x86_caretaker_has_hw_mitigations())
		return -EOPNOTSUPP;

	/*
	 * The Caretaker programs the local APIC through the x2APIC MSRs, and
	 * gives the hardware physical addresses without the encryption bit.
	 */
	if (!x2apic_mode || cc_platform_has(CC_ATTR_HOST_MEM_ENCRYPT))
		return -EOPNOTSUPP;

	/*
	 * Caretaker only saves/restores architectural user XSAVE state fitting
	 * within struct kvm_xsave and does not switch IA32_XSS or mediated PMU
	 * counters across co-scheduled VMs.
	 */
	if (kvm_vcpu_has_mediated_pmu(vcpu) || vcpu->arch.ia32_xss)
		return -EOPNOTSUPP;

	if (boot_cpu_has(X86_FEATURE_XSAVE)) {
		u64 host_xcr0 = xgetbv(XCR_XFEATURE_ENABLED_MASK);

		if ((vcpu->arch.xcr0 & ~host_xcr0) ||
		    (vcpu->arch.guest_fpu.fpstate &&
		     vcpu->arch.guest_fpu.fpstate->user_size > sizeof(struct kvm_xsave)))
			return -EOPNOTSUPP;
	}

	kvm_arch_vcpu_caretaker_init(vcpu);
	if (!vcpu->caretaker.cb)
		return -ENOMEM;

	sess = oncore_job_session(vcpu->caretaker.job);
	ser->cb.phys = virt_to_phys(vcpu->caretaker.cb);
	abi = phys_to_virt(ser->cb.phys);
	cxp = container_of(abi, struct caretaker_x86_page, abi);
	cxp->arch_state = state;
	cpuid = KHOSER_LOAD_PTR(state->cpuid);
	if (cxp->kvm_vcpu && cpuid) {
		cxp->kvm_vcpu->arch.cpuid_entries = cpuid->entries;
		cxp->kvm_vcpu->arch.cpuid_nent = cpuid->nent;
	}
	ret = oncore_session_map_buffer(sess, state, size);
	if (ret) {
		ser->arch_state.phys = 0;
		kvm_caretaker_stop(&abi->cb);
		kvm_arch_vcpu_caretaker_unpreserve(ser);
		vcpu->caretaker.cb = NULL;
		return ret;
	}

	return 0;
}

static int kvm_x86_caretaker_signal_attach(struct kvm_vcpu *vcpu, u64 cb_pa)
{
	struct kvm_caretaker_arch_ser *abi;
	struct kvm_caretaker_cb_ser *cb;
	int target_pcpu, err;

	if (!cb_pa)
		return 0;

	abi = caretaker_pa_to_va(cb_pa);
	cb = &abi->cb;
	target_pcpu = cb->pcpu_id;

	err = kvm_caretaker_wait_for_attach(cb, target_pcpu);
	if (!err && vcpu) {
		lockdep_assert_held(&vcpu->mutex);
		vcpu->cpu = -1;
	}
	return err;
}

static void kvm_x86_caretaker_attach(struct kvm_vcpu *vcpu, u64 cb_pa)
{
	const struct kvm_x86_caretaker_ops *ops = kvm_x86_caretaker_host_ops;

	if (cb_pa) {
		struct kvm_caretaker_arch_ser *abi = caretaker_pa_to_va(cb_pa);

		vcpu_load(vcpu);
		if (ops && ops->sync_vcpu)
			ops->sync_vcpu(vcpu, abi);
		vcpu_put(vcpu);
	}
}

int kvm_arch_vcpu_luo_pre_retrieve_caretaker(struct kvm_vcpu *vcpu,
					     struct kvm_vcpu_ser *ser)
{
	if (!ser || !KHOSER_LOAD_PTR(ser->cb))
		return 0;

	return kvm_x86_caretaker_signal_attach(vcpu, ser->cb.phys);
}

void kvm_arch_vcpu_luo_attach_caretaker(struct kvm_vcpu *vcpu,
					struct kvm_vcpu_ser *ser)
{
	if (!ser || !KHOSER_LOAD_PTR(ser->cb))
		return;

	kvm_x86_caretaker_attach(vcpu, ser->cb.phys);
	kvm_caretaker_post_attach_vcpu(vcpu);
}

int kvm_x86_caretaker_preserve_page(struct kvm_caretaker_arch_ser *abi,
				    struct page *page)
{
	int ret;

	if (WARN_ON_ONCE(abi->nr_preserved_pages >= KVM_X86_CARETAKER_MAX_PAGES))
		return -ENOSPC;

	ret = kho_preserve_pages(page, 1);
	if (ret)
		return ret;

	abi->preserved_pages_pa[abi->nr_preserved_pages++] = page_to_phys(page);
	return 0;
}

void kvm_x86_caretaker_unpreserve_pages(struct kvm_caretaker_arch_ser *abi)
{
	struct kvm_caretaker_telemetry_ser *tel;
	u32 i;

	tel = KHOSER_LOAD_PTR(abi->cb.telemetry);
	if (tel) {
		abi->cb.telemetry.phys = 0;
		cpu_preserved_free_kho(tel, false);
	}

	for (i = 0; i < abi->nr_preserved_pages; i++) {
		phys_addr_t pa = __sme_clr(abi->preserved_pages_pa[i]);

		cpu_preserved_as_unmap(NULL, (unsigned long)phys_to_virt(pa),
				       PAGE_SIZE);
		kho_unpreserve_pages(phys_to_page(pa), 1);
	}
	abi->nr_preserved_pages = 0;
}

/*
 * The preserved CPUs run on a copy of the preserved data that is made when CPU
 * preservation is first used: set up what the Caretaker reads from it once the
 * vendor module has initialized KVM.
 */
static int __init kvm_x86_caretaker_init_runtime_data(void)
{
	__cpu_preserved_kvm_caps = kvm_caps;
	memcpy(__cpu_preserved_kvm_cpu_caps, kvm_cpu_caps, sizeof(kvm_cpu_caps));
	caretaker_x86_has_tsc_deadline = boot_cpu_has(X86_FEATURE_TSC_DEADLINE_TIMER);
	caretaker_x86_lapic_timer_period = lapic_timer_period;
	caretaker_x86_tsc_khz = tsc_khz;
	return 0;
}
late_initcall(kvm_x86_caretaker_init_runtime_data);

int kvm_x86_caretaker_init_common_page(struct caretaker_x86_page *cxp,
				       struct kvm_vcpu *vcpu,
				       size_t full_page_size)
{
	struct oncore_session *sess;
	phys_addr_t pgd_pa;
	int ret;

	if (!cxp || !vcpu)
		return -EINVAL;

	sess = oncore_job_session(vcpu->caretaker.job);
	pgd_pa = oncore_session_get_pgd_pa(sess);
	if (!pgd_pa)
		return -EINVAL;

	memset(cxp, 0, full_page_size);

	ret = kvm_caretaker_init_common_vcpu(&cxp->vcpu, &cxp->abi.cb, vcpu, cxp,
					     full_page_size, NULL, cxp);
	if (ret)
		return ret;

	cxp->save_guest_fpu = boot_cpu_has(X86_FEATURE_XSAVE) &&
			      !fpstate_is_confidential(&vcpu->arch.guest_fpu);
	if (cxp->save_guest_fpu)
		cxp->host_xcr0 = xgetbv(XCR_XFEATURE_ENABLED_MASK);

	/* Preserved CR3 from session */
	cxp->host_cr3 = pgd_pa;

	/* Build KHO-preserved Host GDT and TSS */
	kvm_x86_caretaker_init_gdt_tss(cxp->gdt, &cxp->tss,
				       (unsigned long)&cxp->stack[CXP_STACK_SIZE]);

	/* Preserve in-kernel local APIC register page across kexec */
	if (vcpu->arch.apic && vcpu->arch.apic->regs) {
		ret = kvm_x86_caretaker_preserve_page(&cxp->abi,
						      virt_to_page(vcpu->arch.apic->regs));
		if (ret)
			return ret;
		ret = oncore_session_map_buffer(sess, vcpu->arch.apic->regs, PAGE_SIZE);
		if (ret)
			return ret;
		cxp->apic_regs = vcpu->arch.apic->regs;
	}

	return 0;
}

void kvm_x86_caretaker_init_vcpu(struct kvm_vcpu *dst,
				 const struct kvm_vcpu *src,
				 struct caretaker_x86_page *cxp,
				 struct kvm_lapic *dst_apic)
{
	const struct kvm_vcpu_arch *sarch = &src->arch;
	struct kvm_vcpu_arch *darch = &dst->arch;

	dst->vcpu_id = src->vcpu_id;
	dst->vcpu_idx = src->vcpu_idx;
	dst->caretaker.cb = &cxp->abi.cb;

	memcpy(darch->regs, sarch->regs, sizeof(darch->regs));
	darch->rip = sarch->rip;
	bitmap_copy(darch->regs_avail, sarch->regs_avail, NR_VCPU_TOTAL_REGS);
	bitmap_copy(darch->regs_dirty, sarch->regs_dirty, NR_VCPU_TOTAL_REGS);

	darch->cr0 = sarch->cr0;
	darch->cr0_guest_owned_bits = sarch->cr0_guest_owned_bits;
	darch->cr2 = sarch->cr2;
	darch->cr3 = sarch->cr3;
	darch->cr4 = sarch->cr4;
	darch->cr4_guest_owned_bits = sarch->cr4_guest_owned_bits;
	darch->cr4_guest_rsvd_bits = sarch->cr4_guest_rsvd_bits;
	darch->cr8 = sarch->cr8;
	darch->pkru = sarch->pkru;
	darch->hflags = sarch->hflags;
	darch->efer = sarch->efer;
	darch->host_debugctl = sarch->host_debugctl;
	darch->apic_base = sarch->apic_base;
	darch->mp_state = sarch->mp_state;
	darch->ia32_misc_enable_msr = sarch->ia32_misc_enable_msr;
	darch->smbase = sarch->smbase;
	darch->smi_count = sarch->smi_count;
	darch->microcode_version = sarch->microcode_version;
	darch->arch_capabilities = sarch->arch_capabilities;
	darch->perf_capabilities = sarch->perf_capabilities;

	memcpy(darch->pdptrs, sarch->pdptrs, sizeof(darch->pdptrs));

	darch->xcr0 = sarch->xcr0;
	darch->guest_supported_xcr0 = sarch->guest_supported_xcr0;
	darch->ia32_xss = sarch->ia32_xss;
	darch->guest_supported_xss = sarch->guest_supported_xss;

	darch->is_amd_compatible = sarch->is_amd_compatible;
	memcpy(darch->cpu_caps, sarch->cpu_caps, sizeof(darch->cpu_caps));
	darch->reserved_gpa_bits = sarch->reserved_gpa_bits;
	darch->maxphyaddr = sarch->maxphyaddr;

	darch->l1_tsc_offset = sarch->l1_tsc_offset;
	darch->tsc_offset = sarch->tsc_offset;
	darch->virtual_tsc_shift = sarch->virtual_tsc_shift;
	darch->virtual_tsc_mult = sarch->virtual_tsc_mult;
	darch->virtual_tsc_khz = sarch->virtual_tsc_khz;
	darch->ia32_tsc_adjust_msr = sarch->ia32_tsc_adjust_msr;
	darch->msr_ia32_power_ctl = sarch->msr_ia32_power_ctl;
	darch->l1_tsc_scaling_ratio = sarch->l1_tsc_scaling_ratio;
	darch->tsc_scaling_ratio = sarch->tsc_scaling_ratio;

	darch->pat = sarch->pat;
	darch->dr6 = sarch->dr6;
	darch->dr7 = sarch->dr7;
	darch->msr_platform_info = sarch->msr_platform_info;
	darch->msr_misc_features_enables = sarch->msr_misc_features_enables;
	darch->mcg_cap = sarch->mcg_cap;
	darch->mcg_status = sarch->mcg_status;
	darch->mcg_ctl = sarch->mcg_ctl;
	darch->mcg_ext_ctl = sarch->mcg_ext_ctl;
	darch->last_vmentry_cpu = sarch->last_vmentry_cpu;
	darch->msr_hwcr = sarch->msr_hwcr;
	darch->pv_cpuid = sarch->pv_cpuid;

	cxp->kvm_vcpu = dst;

	if (dst_apic && sarch->apic && cxp->apic_regs) {
		const struct kvm_lapic *sapic = sarch->apic;

		dst_apic->base_address = sapic->base_address;
		dst_apic->lapic_timer.period = sapic->lapic_timer.period;
		dst_apic->lapic_timer.timer_mode = sapic->lapic_timer.timer_mode;
		dst_apic->lapic_timer.timer_mode_mask = sapic->lapic_timer.timer_mode_mask;
		dst_apic->lapic_timer.tscdeadline = sapic->lapic_timer.tscdeadline;
		dst_apic->lapic_timer.expired_tscdeadline = sapic->lapic_timer.expired_tscdeadline;
		dst_apic->divide_count = sapic->divide_count;
		dst_apic->vcpu = dst;
		dst_apic->apicv_active = sapic->apicv_active;
		dst_apic->sw_enabled = sapic->sw_enabled;
		dst_apic->irr_pending = sapic->irr_pending;
		dst_apic->lvt0_in_nmi_mode = sapic->lvt0_in_nmi_mode;
		dst_apic->guest_apic_protected = sapic->guest_apic_protected;
		dst_apic->isr_count = sapic->isr_count;
		dst_apic->highest_isr_cache = sapic->highest_isr_cache;
		dst_apic->regs = cxp->apic_regs;
		dst_apic->nr_lvt_entries = sapic->nr_lvt_entries;
		darch->apic = dst_apic;
	}
}

static void kvm_x86_caretaker_init_gdt_tss(struct desc_struct *gdt,
					   struct x86_hw_tss *tss,
					   unsigned long stack_top)
{
	memcpy(gdt, get_current_gdt_ro(), sizeof(struct desc_struct) * GDT_ENTRIES);
	memset(tss, 0, sizeof(*tss));
	tss->sp0 = stack_top;
	tss->io_bitmap_base = sizeof(*tss);

	caretaker_set_tss_desc(gdt, (unsigned long)tss, sizeof(struct x86_hw_tss) - 1);
}

void kvm_x86_caretaker_sync_vcpu_common(struct kvm_vcpu *vcpu)
{
	kvm_register_mark_dirty(vcpu, VCPU_REG_CR3);
	kvm_clear_interrupt_queue(vcpu);
	kvm_clear_exception_queue(vcpu);

	vcpu->cpu = -1;
	kvm_make_request(KVM_REQ_LOAD_MMU_PGD, vcpu);
	kvm_make_request(KVM_REQ_TLB_FLUSH_CURRENT, vcpu);
	kvm_make_request(KVM_REQ_RECALC_INTERCEPTS, vcpu);
}

void kvm_arch_vcpu_caretaker_unpreserve(struct kvm_vcpu_ser *ser)
{
	if (ser->cb.phys) {
		struct kvm_caretaker_arch_ser *abi = caretaker_pa_to_va(ser->cb.phys);

		if (WARN_ON_ONCE(!kvm_caretaker_is_stopped(&abi->cb)))
			return;

		if (ser->arch_state.phys) {
			cpu_preserved_free_kho(phys_to_virt(__sme_clr(ser->arch_state.phys)),
					       false);
			ser->arch_state.phys = 0;
		}
		kvm_x86_caretaker_unpreserve_pages(abi);
		cpu_preserved_free_kho(abi, false);
		ser->cb.phys = 0;
	}
}

void kvm_arch_vcpu_caretaker_finish(struct kvm_vcpu_ser *ser)
{
	if (ser->cb.phys) {
		struct kvm_caretaker_arch_ser *abi = caretaker_pa_to_va(ser->cb.phys);
		u32 i;

		if (WARN_ON_ONCE(!kvm_caretaker_is_stopped(&abi->cb)))
			return;

		if (ser->arch_state.phys) {
			cpu_preserved_free_kho(phys_to_virt(__sme_clr(ser->arch_state.phys)),
					       true);
			ser->arch_state.phys = 0;
		}
		for (i = 0; i < abi->nr_preserved_pages; i++) {
			phys_addr_t pa = __sme_clr(abi->preserved_pages_pa[i]);
			struct page *page;

			cpu_preserved_as_unmap(NULL,
					       (unsigned long)phys_to_virt(pa),
					       PAGE_SIZE);
			page = kho_restore_pages(pa, 1);
			if (page)
				__free_pages(page, 0);
		}
		abi->nr_preserved_pages = 0;
		cpu_preserved_free_kho(abi, true);
		ser->cb.phys = 0;
	}
}

int kvm_arch_vm_luo_freeze(struct kvm *kvm, struct kvm_luo_ser *ser)
{
	int ret;

	/*
	 * Shadow/TDP page tables are a VM-wide resource: an orphaned vCPU keeps
	 * running the guest out of them while the VM is detached, so they must
	 * survive the kexec.  Preserve them at freeze time when all vCPUs are
	 * detached from KVM_RUN and the MMU is quiescent.
	 */
	ret = kvm_mmu_preserve_kho(kvm);
	if (ret)
		return ret;

	KHOSER_STORE_PTR(ser->kho_folios, kvm->kho_folios);
	return 0;
}
