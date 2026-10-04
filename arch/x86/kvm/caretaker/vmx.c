// SPDX-License-Identifier: GPL-2.0-only
/*
 * Intel VMX Caretaker Host Lifecycle Management
 *
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 */

#include <linux/cleanup.h>
#include <linux/cpu_preserve.h>
#include <linux/kernel.h>
#include <linux/kexec_handover.h>
#include <linux/kvm_host.h>
#include <linux/oncore.h>

#include <asm/apic.h>
#include <asm/vmx.h>

#include "caretaker.h"
#include "lapic.h"
#include "regs.h"
#include "vmx.h"
#include "x86.h"
#include "../vmx/posted_intr.h"
#include "../vmx/vmx_ops.h"
#include "../vmx/x86_ops.h"

static int vmx_caretaker_init_page(struct caretaker_vmx_page *cvp,
				   struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	u64 basic_msr, misc_msr;
	int ret;

	if (!vmx->vmcs01.vmcs || is_guest_mode(vcpu))
		return -EOPNOTSUPP;

	ret = kvm_x86_caretaker_init_common_page(&cvp->common, vcpu, sizeof(*cvp));
	if (ret)
		return ret;
	cvp->vmcs_pa = virt_to_phys(vmx->vmcs01.vmcs);
	cvp->vmxon_pa = virt_to_phys(cvp->vmxon_area);

	memset(cvp->vmxon_area, 0, PAGE_SIZE);
	basic_msr = native_rdmsrq(MSR_IA32_VMX_BASIC);
	*(u32 *)cvp->vmxon_area = vmx_basic_vmcs_revision_id(basic_msr);

	if (!rdmsrq_safe(MSR_IA32_VMX_MISC, &misc_msr))
		cvp->timer_shift = vmx_misc_preemption_timer_rate(misc_msr);
	else
		cvp->timer_shift = VMX_PREEMPTION_TIMER_SHIFT;

	cvp->ple_supported = cpu_has_vmx_ple();

	vcpu_load(vcpu);

	cvp->common.kernel_gs_base = vmx->msr_guest_kernel_gs_base;
	kvm_msr_read(vcpu, MSR_STAR, &cvp->star);
	kvm_msr_read(vcpu, MSR_LSTAR, &cvp->lstar);
	kvm_msr_read(vcpu, MSR_SYSCALL_MASK, &cvp->fmask);

	/* Cache current guest control and instruction/stack registers on vcpu */
	(void)kvm_read_cr0(vcpu);
	(void)kvm_read_cr3(vcpu);
	(void)kvm_read_cr4(vcpu);
	(void)kvm_rip_read(vcpu);
	(void)kvm_rsp_read(vcpu);
	(void)kvm_get_rflags(vcpu);

	if (kvm_register_is_dirty(vcpu, VCPU_REGS_RSP))
		vmcs_writel(GUEST_RSP, vcpu->arch.regs[VCPU_REGS_RSP]);
	if (kvm_register_is_dirty(vcpu, VCPU_REG_RIP))
		vmcs_writel(GUEST_RIP, vcpu->arch.rip);
	kvm_reset_dirty_registers(vcpu);

	kvm_x86_caretaker_init_vcpu(&cvp->vmx.vcpu, vcpu, &cvp->common,
				    lapic_in_kernel(vcpu) ? &cvp->apic : NULL);

	cvp->vmx.vt.pi_desc = vmx->vt.pi_desc;
	cvp->vmx.vt.guest_state_loaded = vmx->vt.guest_state_loaded;
	cvp->vmx.x2apic_msr_bitmap_mode = vmx->x2apic_msr_bitmap_mode;
	cvp->vmx.rflags = vmx->rflags;
	memcpy(cvp->vmx.guest_uret_msrs, vmx->guest_uret_msrs,
	       sizeof(cvp->vmx.guest_uret_msrs));
#ifdef CONFIG_X86_64
	cvp->vmx.msr_guest_kernel_gs_base = vmx->msr_guest_kernel_gs_base;
#endif
	cvp->vmx.spec_ctrl = vmx->spec_ctrl;
	cvp->vmx.msr_ia32_umwait_control = vmx->msr_ia32_umwait_control;
	cvp->vmx.vmcs01.controls_shadow = vmx->vmcs01.controls_shadow;
	cvp->vmx.vmcs01.hv_timer_soft_disabled = vmx->vmcs01.hv_timer_soft_disabled;
	cvp->vmx.loaded_vmcs = &cvp->vmx.vmcs01;
	cvp->vmx.msr_autoload = vmx->msr_autoload;
	cvp->vmx.msr_autostore = vmx->msr_autostore;
	vmcs_write64(VM_EXIT_MSR_STORE_ADDR, __pa(cvp->vmx.msr_autostore.val));
	vmcs_write64(VM_EXIT_MSR_LOAD_ADDR, __pa(cvp->vmx.msr_autoload.host.val));
	vmcs_write64(VM_ENTRY_MSR_LOAD_ADDR, __pa(cvp->vmx.msr_autoload.guest.val));
	cvp->vmx.rmode = vmx->rmode;
	cvp->vmx.segment_cache = vmx->segment_cache;
	cvp->vmx.vpid = vmx->vpid;
	cvp->vmx.msr_ia32_feature_control = vmx->msr_ia32_feature_control;
	cvp->vmx.msr_ia32_feature_control_valid_bits =
		vmx->msr_ia32_feature_control_valid_bits;
	memcpy(cvp->vmx.msr_ia32_sgxlepubkeyhash,
	       vmx->msr_ia32_sgxlepubkeyhash,
	       sizeof(cvp->vmx.msr_ia32_sgxlepubkeyhash));
	cvp->vmx.msr_ia32_mcu_opt_ctrl = vmx->msr_ia32_mcu_opt_ctrl;
	cvp->vmx.disable_fb_clear = vmx->disable_fb_clear;
	cvp->vmx.pt_desc = vmx->pt_desc;

	if (lapic_in_kernel(vcpu) && enable_apicv) {
		cvp->common.abi.pi_desc_pa = virt_to_phys(&cvp->vmx.vt.pi_desc);
		vmcs_write64(POSTED_INTR_DESC_ADDR, cvp->common.abi.pi_desc_pa);
		if (to_kvm_vmx(vcpu->kvm)->pid_table)
			WRITE_ONCE(to_kvm_vmx(vcpu->kvm)->pid_table[vcpu->vcpu_id],
				   cvp->common.abi.pi_desc_pa | PID_TABLE_ENTRY_VALID);
	}

	vcpu_put(vcpu);

	if (vmx->loaded_vmcs)
		loaded_vmcs_clear(vmx->loaded_vmcs);

	return 0;
}

void vmx_caretaker_init(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct caretaker_vmx_page *cvp;
	struct kvm_caretaker_arch_ser *abi;

	cvp = kho_alloc_preserve(sizeof(*cvp));
	if (IS_ERR(cvp)) {
		pr_err("caretaker vmx: failed to allocate preserved page\n");
		return;
	}

	if (vmx_caretaker_init_page(cvp, vcpu))
		goto err_free;

	abi = &cvp->common.abi;
	if (vmx->vmcs01.vmcs &&
	    kvm_x86_caretaker_preserve_page(abi, virt_to_page(vmx->vmcs01.vmcs)))
		goto err_free;
	if (vmx->vmcs01.msr_bitmap &&
	    kvm_x86_caretaker_preserve_page(abi, virt_to_page(vmx->vmcs01.msr_bitmap)))
		goto err_free;
	if (vmx->pml_pg &&
	    kvm_x86_caretaker_preserve_page(abi, vmx->pml_pg))
		goto err_free;
	if (vmx->ve_info &&
	    kvm_x86_caretaker_preserve_page(abi, virt_to_page(vmx->ve_info)))
		goto err_free;

	return;

err_free:
	kvm_x86_caretaker_unpreserve_pages(&cvp->common.abi);
	vcpu->caretaker.cb = NULL;
	cpu_preserved_free_kho(cvp, false);
}

static void
vmx_caretaker_sync_vcpu(struct kvm_vcpu *vcpu, void *vcpu_data)
{
	struct kvm_caretaker_arch_ser *abi = vcpu_data;
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	phys_addr_t cur_vmcs_pa = vmx->loaded_vmcs ? virt_to_phys(vmx->loaded_vmcs->vmcs) : 0;
	struct vmcs *prev_vmcs;

	guard(preempt)();
	prev_vmcs = this_cpu_read(current_vmcs);

	if (cur_vmcs_pa)
		vmcs_load_pa(cur_vmcs_pa);

	kvm_x86_caretaker_sync_vcpu_common(vcpu);

	if (vmx->loaded_vmcs) {
		pin_controls_clearbit(vmx, PIN_BASED_VMX_PREEMPTION_TIMER);
		vmcs_write32(PIN_BASED_VM_EXEC_CONTROL, pin_controls_get(vmx));
		vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, exec_controls_get(vmx));
		if (cpu_has_secondary_exec_ctrls())
			vmcs_write32(SECONDARY_VM_EXEC_CONTROL,
				     secondary_exec_controls_get(vmx));
		vmcs_write32(VMX_PREEMPTION_TIMER_VALUE, 0);
		vmcs_write32(VM_EXIT_MSR_STORE_COUNT, vmx->msr_autostore.nr);
		vmcs_write64(VM_EXIT_MSR_STORE_ADDR, __pa(vmx->msr_autostore.val));
		vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, vmx->msr_autoload.host.nr);
		vmcs_write64(VM_EXIT_MSR_LOAD_ADDR, __pa(vmx->msr_autoload.host.val));
		vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, vmx->msr_autoload.guest.nr);
		vmcs_write64(VM_ENTRY_MSR_LOAD_ADDR, __pa(vmx->msr_autoload.guest.val));
		memset(&vmx->loaded_vmcs->host_state, 0,
		       sizeof(struct vmcs_host_state));
		list_del_init(&vmx->loaded_vmcs->loaded_vmcss_on_cpu_link);
		vmx->loaded_vmcs->cpu = -1;
		vmx->loaded_vmcs->launched = 0;
	}
	vmx_segment_cache_clear(vmx);
	vmx->vt.guest_state_loaded = false;
	vmx->guest_uret_msrs_loaded = false;

	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, 0);
	vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, 0);
	vmcs_write32(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_ACTIVE);
	vmcs_writel(GUEST_PENDING_DBG_EXCEPTIONS, 0);

	vmcs_writel(GUEST_RIP, kvm_rip_read(vcpu));
	vmcs_writel(GUEST_RSP, kvm_rsp_read(vcpu));
	vmcs_writel(GUEST_RFLAGS, kvm_get_rflags(vcpu));
	vmx_set_cr0(vcpu, vcpu->arch.cr0);
	vmcs_writel(GUEST_CR3, vcpu->arch.cr3);
	vmx_set_cr4(vcpu, vcpu->arch.cr4);
	vmx_set_efer(vcpu, vcpu->arch.efer);

	if (abi->pi_desc_pa) {
		struct pi_desc *old_pi = phys_to_virt(__sme_clr(abi->pi_desc_pa));
		unsigned long pir_vals[NR_PIR_WORDS];

		if (pi_harvest_pir(old_pi->pir, pir_vals)) {
			int i;

			for (i = 0; i < NR_PIR_WORDS; i++) {
				if (pir_vals[i])
					arch_atomic64_or(pir_vals[i],
							 (atomic64_t *)&vmx->vt.pi_desc.pir[i]);
			}
			pi_set_on(&vmx->vt.pi_desc);
		}
		vmcs_write64(POSTED_INTR_DESC_ADDR, virt_to_phys(&vmx->vt.pi_desc));
		if (to_kvm_vmx(vcpu->kvm)->pid_table)
			WRITE_ONCE(to_kvm_vmx(vcpu->kvm)->pid_table[vcpu->vcpu_id],
				   virt_to_phys(&vmx->vt.pi_desc) | PID_TABLE_ENTRY_VALID);
	}

	if (vmx->loaded_vmcs)
		vmx_set_constant_host_state(vmx);

	if (cur_vmcs_pa)
		vmcs_clear_pa(cur_vmcs_pa);

	if (prev_vmcs && (!vmx->loaded_vmcs || prev_vmcs != vmx->loaded_vmcs->vmcs)) {
		vmcs_load(prev_vmcs);
		this_cpu_write(current_vmcs, prev_vmcs);
	} else {
		this_cpu_write(current_vmcs, NULL);
	}
}

static const struct kvm_x86_caretaker_ops vmx_caretaker_ops = {
	.name = "vmx",
	.init = vmx_caretaker_init,
	.sync_vcpu = vmx_caretaker_sync_vcpu,
	.runtime = &vmx_caretaker_runtime_ops,
};

void vmx_caretaker_register(void)
{
	kvm_x86_caretaker_register_ops(&vmx_caretaker_ops);
}

void vmx_caretaker_unregister(void)
{
	kvm_x86_caretaker_unregister_ops(&vmx_caretaker_ops);
}
