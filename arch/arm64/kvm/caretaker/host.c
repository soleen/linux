// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * ARM64 KVM Caretaker host lifecycle and hardware virtualization attachment.
 */
#include <linux/cpu_preserve.h>
#include <linux/delay.h>
#include <linux/irqchip/arm-gic-v3.h>
#include <linux/kexec_handover.h>
#include <linux/kho/abi/kvm.h>
#include <linux/kvm_host.h>
#include <linux/oncore.h>
#include <linux/sched.h>

#include <asm/barrier.h>
#include <asm/caretaker.h>
#include <asm/cpu_ops.h>
#include <linux/cpufeature.h>
#include <asm/cputype.h>
#include <asm/fpsimd.h>
#include <asm/kernel-pgtable.h>
#include <linux/kexec.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pgtable.h>
#include <linux/mmu_context.h>
#include <linux/pgtable.h>
#include <asm/smp_plat.h>
#include <asm/sysreg.h>
#include <asm/tlbflush.h>
#include <asm/vectors.h>

#include <kvm/arm_arch_timer.h>
#include <kvm/arm_pmu.h>
#include <kvm/arm_vgic.h>

#include "caretaker.h"

/* Protects &kvm->caretaker_vm and &kvm->caretaker_sess_id of every VM */
static DEFINE_MUTEX(arm64_caretaker_vm_lock);

/**
 * arm64_kvm_caretaker_forget_vm - Forget the Caretaker vCPUs of a VM
 * @kvm: VM whose vCPUs no longer link to the Caretaker vCPUs preserved so far.
 */
void arm64_kvm_caretaker_forget_vm(struct kvm *kvm)
{
	guard(mutex)(&arm64_caretaker_vm_lock);
	kvm->caretaker_vm = NULL;
	kvm->caretaker_sess_id = 0;
}

int arm64_kvm_caretaker_preserve(struct kvm_vcpu *vcpu,
				 struct kvm_vcpu_ser *ser)
{
	struct kvm_s2_mmu *mmu = vcpu->arch.hw_mmu ?
				 vcpu->arch.hw_mmu : &vcpu->kvm->arch.mmu;
	struct oncore_session *sess = oncore_job_session(vcpu->caretaker.job);
	struct arch_timer_context *vtimer;
	struct caretaker_arm64_page *head;
	struct caretaker_arm64_page *cap;
	struct vgic_v3_cpu_if *cpu_if;
	bool vmid_pinned = false;
	struct kvm *kvm_vm;
	int ret;

	if (!vcpu->caretaker.job)
		return 0;

	if (!has_vhe() || is_protected_kvm_enabled() || vcpu_has_nv(vcpu))
		return -EOPNOTSUPP;
	if (cpus_have_cap(ARM64_SPECTRE_V2) ||
	    cpus_have_cap(ARM64_SPECTRE_V3A))
		return -EOPNOTSUPP;
	/*
	 * Same predicate as kvm_arch_vcpu_luo_preserve() (kvm_luo.c) and
	 * kvm_arm_copy_sys_reg_indices() (sys_regs.c): what matters is whether
	 * an in-kernel irqchip exists at all, not whether it has been
	 * initialised yet.  vgic_initialized() would let a created-but-not-ready
	 * in-kernel VGICv2 through, and the caretaker cannot emulate one.
	 */
	if (irqchip_in_kernel(vcpu->kvm) &&
	    vcpu->kvm->arch.vgic.vgic_model != KVM_DEV_TYPE_ARM_VGIC_V3)
		return -EOPNOTSUPP;
	if (kvm_has_mte(vcpu->kvm) || kvm_has_s1poe(vcpu->kvm) ||
	    vcpu_has_sve(vcpu) || vcpu_has_ptrauth(vcpu) ||
	    kvm_vcpu_has_pmu(vcpu) ||
	    test_bit(KVM_ARCH_FLAG_WRITABLE_IMP_ID_REGS, &vcpu->kvm->arch.flags))
		return -EOPNOTSUPP;

	/*
	 * The Caretaker vCPUs of a VM share its struct kvm copy, and the
	 * preserved runtime follows the ring of their pages, so they all live
	 * in the address space of the session of the first of them.  Session
	 * IDs, unlike pointers, are never reused: the head that an ended
	 * session leaves behind is never dereferenced.
	 */
	guard(mutex)(&arm64_caretaker_vm_lock);
	head = vcpu->kvm->caretaker_vm;
	if (head && vcpu->kvm->caretaker_sess_id != oncore_session_id(sess))
		return -EBUSY;

	/* The address space of the session owns the page: never freed here */
	cap = oncore_session_alloc_buffer(sess, sizeof(*cap));
	if (IS_ERR(cap)) {
		pr_err("caretaker arm64: failed to allocate preserved page\n");
		return PTR_ERR(cap);
	}

	ret = kvm_caretaker_init_common_vcpu(&cap->vcpu, &cap->abi.cb, vcpu,
					     NULL, cap);
	if (ret)
		goto err;

	cap->pcpu_mpidr = cpu_logical_map(cap->abi.cb.pcpu_id) & MPIDR_HWID_BITMASK;

	/* Populate embedded struct kvm_vcpu and VM-shared struct kvm */
	cap->kvm_vcpu.vcpu_id = vcpu->vcpu_id;
	cap->kvm_vcpu.vcpu_idx = vcpu->vcpu_idx;
	cap->kvm_vcpu.arch.ctxt = vcpu->arch.ctxt;
	cap->kvm_vcpu.arch.ctxt.__hyp_running_vcpu = NULL;
	cap->kvm_vcpu.arch.ctxt.vncr_array = NULL;
	cap->kvm_vcpu.arch.fp_type = vcpu->arch.fp_type;
	cap->kvm_vcpu.arch.sve_max_vl = vcpu->arch.sve_max_vl;
	cap->kvm_vcpu.arch.hcr_el2 = vcpu->arch.hcr_el2;
	cap->kvm_vcpu.arch.hcrx_el2 = vcpu->arch.hcrx_el2;
	cap->kvm_vcpu.arch.mdcr_el2 = vcpu->arch.mdcr_el2;
	memcpy(cap->kvm_vcpu.arch.fgt, vcpu->arch.fgt,
	       sizeof(cap->kvm_vcpu.arch.fgt));
	cap->kvm_vcpu.arch.fault = vcpu->arch.fault;
	cap->kvm_vcpu.arch.cflags = vcpu->arch.cflags;
	cap->kvm_vcpu.arch.iflags = vcpu->arch.iflags;
	cap->kvm_vcpu.arch.sflags = vcpu->arch.sflags;
	cap->kvm_vcpu.arch.vsesr_el2 = vcpu->arch.vsesr_el2;

	vtimer = vcpu_vtimer(vcpu);
	if (!head) {
		/* Shared by the vCPUs of the VM, owned by the address space */
		kvm_vm = oncore_session_alloc_buffer(sess, sizeof(*kvm_vm));
		if (IS_ERR(kvm_vm)) {
			ret = PTR_ERR(kvm_vm);
			goto err;
		}
		ret = kvm_arm_vmid_pin(&mmu->vmid, &cap->abi.vmid);
		if (ret)
			goto err;
		vmid_pinned = true;
		kvm_vm->arch.flags = vcpu->kvm->arch.flags;
		memcpy(kvm_vm->arch.vcpu_features,
		       vcpu->kvm->arch.vcpu_features,
		       sizeof(kvm_vm->arch.vcpu_features));
		memcpy(kvm_vm->arch.id_regs, vcpu->kvm->arch.id_regs,
		       sizeof(kvm_vm->arch.id_regs));
		kvm_vm->arch.midr_el1 = vcpu->kvm->arch.midr_el1;
		kvm_vm->arch.revidr_el1 = vcpu->kvm->arch.revidr_el1;
		kvm_vm->arch.aidr_el1 = vcpu->kvm->arch.aidr_el1;
		kvm_vm->arch.ctr_el0 = vcpu->kvm->arch.ctr_el0;
		kvm_vm->arch.vgic.vgic_model = vcpu->kvm->arch.vgic.vgic_model;
		kvm_vm->arch.vgic.implementation_rev =
			vcpu->kvm->arch.vgic.implementation_rev;
		kvm_vm->arch.mmu.vtcr = mmu->vtcr;
		kvm_vm->arch.timer_data.voffset = timer_get_offset(vtimer);
		kvm_vm->arch.timer_data.poffset =
			timer_get_offset(vcpu_ptimer(vcpu));
		cpupr_clean_sz(kvm_vm, sizeof(*kvm_vm));
	} else {
		cap->abi.vmid = head->abi.vmid;
		kvm_vm = phys_to_virt(head->cvm_pa);
	}

	cap->cvm_pa = virt_to_phys(kvm_vm);
	cap->vttbr_el2 = kvm_get_vttbr(mmu) & ~VTTBR_CNP_BIT;
	cap->kvm_vcpu.kvm = kvm_vm;
	cap->kvm_vcpu.arch.hw_mmu = &kvm_vm->arch.mmu;
	cap->host_data.host_ctxt.__hyp_running_vcpu = &cap->kvm_vcpu;
	cap->host_data.fp_owner = FP_STATE_GUEST_OWNED;

	if (irqchip_in_kernel(vcpu->kvm) && !vgic_initialized(vcpu->kvm))
		kvm_vgic_map_resources(vcpu->kvm);

	cpu_if = &cap->kvm_vcpu.arch.vgic_cpu.vgic_v3;
	if (vgic_initialized(vcpu->kvm)) {
		const struct vgic_v3_cpu_if *src_if =
			&vcpu->arch.vgic_cpu.vgic_v3;
		int i;

		cap->vgic_initialized = true;
		cpu_if->vgic_hcr = src_if->vgic_hcr | ICH_HCR_EL2_En;
		cpu_if->vgic_vmcr = src_if->vgic_vmcr;
		cpu_if->vgic_sre = 1;
		cpu_if->used_lrs = src_if->used_lrs;
		memcpy(cpu_if->vgic_ap0r, src_if->vgic_ap0r,
		       sizeof(cpu_if->vgic_ap0r));
		memcpy(cpu_if->vgic_ap1r, src_if->vgic_ap1r,
		       sizeof(cpu_if->vgic_ap1r));
		memcpy(cpu_if->vgic_lr, src_if->vgic_lr,
		       sizeof(cpu_if->vgic_lr));

		for (i = 0; ; i++) {
			phys_addr_t rpa;
			unsigned long rva;
			size_t rsize;

			if (gicv3_cpupr_get_redist_region(i, &rpa, &rva, &rsize))
				break;
			ret = oncore_session_map_mmio(sess, rpa, rva, rsize);
			if (ret)
				goto err;
		}
	}

	vcpu_vtimer(&cap->kvm_vcpu)->offset.vm_offset =
		&kvm_vm->arch.timer_data.voffset;
	vcpu_vtimer(&cap->kvm_vcpu)->offset.vcpu_offset = NULL;
	vcpu_ptimer(&cap->kvm_vcpu)->offset.vm_offset =
		&kvm_vm->arch.timer_data.poffset;
	vcpu_ptimer(&cap->kvm_vcpu)->offset.vcpu_offset = NULL;
	__vcpu_assign_sys_reg(&cap->kvm_vcpu, CNTV_CVAL_EL0, timer_get_cval(vtimer));
	__vcpu_assign_sys_reg(&cap->kvm_vcpu, CNTV_CTL_EL0, timer_get_ctl(vtimer));

	/* From the address space of the session: kvm_caretaker_alloc_arch_state() */
	if (ser->arch_state.phys)
		cap->arch_state = phys_to_virt(ser->arch_state.phys);

	if (!head) {
		cap->next_vcpu = cap;
		cap->next_vcpu_pa = virt_to_phys(cap);
		vcpu->kvm->caretaker_vm = cap;
		vcpu->kvm->caretaker_sess_id = oncore_session_id(sess);
	} else {
		cap->next_vcpu = head->next_vcpu;
		cap->next_vcpu_pa = head->next_vcpu_pa;
		head->next_vcpu = cap;
		head->next_vcpu_pa = virt_to_phys(cap);
		cpupr_clean(head);
	}

	cap->abi.vgic_initialized = cap->vgic_initialized ? 1 : 0;
	cap->abi.cntvoff_el2 = kvm_vm->arch.timer_data.voffset;
	cap->abi.hcr_el2 = cap->kvm_vcpu.arch.hcr_el2;
	cap->abi.mdcr_el2 = cap->kvm_vcpu.arch.mdcr_el2;
	cap->abi.cflags = (u32)cap->kvm_vcpu.arch.cflags;
	if (cap->vgic_initialized) {
		int i;

		cap->abi.used_lrs = cpu_if->used_lrs;
		cap->abi.vgic_hcr = cpu_if->vgic_hcr;
		cap->abi.vgic_vmcr = cpu_if->vgic_vmcr;
		for (i = 0; i < 4; i++) {
			cap->abi.vgic_ap0r[i] = cpu_if->vgic_ap0r[i];
			cap->abi.vgic_ap1r[i] = cpu_if->vgic_ap1r[i];
		}
		for (i = 0; i < 16; i++)
			cap->abi.vgic_lr[i] = cpu_if->vgic_lr[i];
	}

	ser->cb.phys = virt_to_phys(cap);

	cpupr_clean(cap);

	return 0;

err:
	/* The address space of the session frees what was allocated from it */
	if (vmid_pinned)
		kvm_arm_vmid_unpin(cap->abi.vmid);
	vcpu->caretaker.cb = NULL;
	return ret;
}

static void arm64_caretaker_sync_vcpu(struct kvm_vcpu *vcpu,
				      void *data)
{
	struct arch_timer_context *vtimer = vcpu_vtimer(vcpu);
	struct kvm_caretaker_arch_ser *abi = data;
	u64 cval, ctl;
	int t;

	/* Sync handover ABI prefix back into incoming vcpu */
	vcpu->arch.hcr_el2 = abi->hcr_el2;
	vcpu->arch.mdcr_el2 = abi->mdcr_el2;
	vcpu->arch.cflags = abi->cflags;

	if (abi->vgic_initialized) {
		int i;

		vcpu->arch.vgic_cpu.vgic_v3.used_lrs = abi->used_lrs;
		vcpu->arch.vgic_cpu.vgic_v3.vgic_hcr = abi->vgic_hcr;
		vcpu->arch.vgic_cpu.vgic_v3.vgic_vmcr = abi->vgic_vmcr;
		for (i = 0; i < 4; i++) {
			vcpu->arch.vgic_cpu.vgic_v3.vgic_ap0r[i] = abi->vgic_ap0r[i];
			vcpu->arch.vgic_cpu.vgic_v3.vgic_ap1r[i] = abi->vgic_ap1r[i];
		}
		for (i = 0; i < 16; i++)
			vcpu->arch.vgic_cpu.vgic_v3.vgic_lr[i] = abi->vgic_lr[i];
	}

	cval = __vcpu_sys_reg(vcpu, CNTV_CVAL_EL0);
	ctl = __vcpu_sys_reg(vcpu, CNTV_CTL_EL0);
	timer_set_offset(vtimer, abi->cntvoff_el2);
	write_sysreg(abi->cntvoff_el2, cntvoff_el2);
	write_sysreg_el0(cval, SYS_CNTV_CVAL);
	write_sysreg_el0(ctl, SYS_CNTV_CTL);
	isb();

	vcpu_set_flag(vcpu, VCPU_INITIALIZED);

	for (t = 0; t < NR_KVM_TIMERS; t++)
		vcpu->arch.timer_cpu.timers[t].loaded = false;

	kvm_make_request(KVM_REQ_IRQ_PENDING, vcpu);
}

static int arm64_caretaker_stop_vm_vcpus(struct caretaker_arm64_page *cap)
{
	struct caretaker_arm64_page *cur = cap;
	unsigned int steps = 0;
	int err = 0;

	if (!cap)
		return 0;

	do {
		int ret;

		cpupr_clean(cur);
		ret = kvm_caretaker_wait_for_attach(&cur->abi.cb,
						    cur->abi.cb.pcpu_id);
		if (ret && !err)
			err = ret;
		if (!cur->next_vcpu_pa)
			break;
		cur = phys_to_virt(cur->next_vcpu_pa);
	} while (cur != cap && ++steps < KVM_MAX_VCPUS);

	return err;
}

static bool arm64_caretaker_unlink_vcpu(struct caretaker_arm64_page *cap)
{
	struct caretaker_arm64_page *prev = cap;
	unsigned int steps = 0;

	if (!cap->next_vcpu_pa || cap->next_vcpu_pa == virt_to_phys(cap)) {
		cap->next_vcpu = NULL;
		cap->next_vcpu_pa = 0;
		return true;
	}

	while (prev->next_vcpu_pa &&
	       prev->next_vcpu_pa != virt_to_phys(cap) &&
	       ++steps < KVM_MAX_VCPUS)
		prev = phys_to_virt(prev->next_vcpu_pa);

	if (prev->next_vcpu_pa == virt_to_phys(cap)) {
		prev->next_vcpu = cap->next_vcpu;
		prev->next_vcpu_pa = cap->next_vcpu_pa;
		cpupr_clean(prev);
	}
	cap->next_vcpu = cap;
	cap->next_vcpu_pa = virt_to_phys(cap);
	return false;
}

int kvm_arch_vcpu_luo_pre_retrieve_caretaker(struct kvm_vcpu *vcpu,
					     struct kvm_vcpu_ser *ser)
{
	if (KHOSER_LOAD_PTR(ser->cb)) {
		struct caretaker_arm64_page *cap = phys_to_virt(ser->cb.phys);
		struct kvm_caretaker_arch_ser *abi = &cap->abi;
		int err;

		err = arm64_caretaker_stop_vm_vcpus(cap);
		if (err)
			return err;

		if (!READ_ONCE(cap->serialized)) {
			cap->arch_state = ser->arch_state.phys ?
					  phys_to_virt(ser->arch_state.phys) :
					  NULL;
			arm64_caretaker_detach_serialize(cap);
		}

		cpupr_clean(abi);
		if (ser->arch_state.phys) {
			struct kvm_vcpu_arch_ser *state =
				phys_to_virt(ser->arch_state.phys);
			struct kvm_arm64_sysregs_ser *sysregs;

			cpupr_clean(state);
			sysregs = KHOSER_LOAD_PTR(state->sysregs);
			if (sysregs) {
				cpupr_clean_sz(sysregs,
					       struct_size(sysregs, sysregs,
							   sysregs->num_sysregs));
			}
		}
	}

	return 0;
}

void kvm_arch_vcpu_luo_attach_caretaker(struct kvm_vcpu *vcpu,
					struct kvm_vcpu_ser *ser)
{
	if (KHOSER_LOAD_PTR(ser->cb)) {
		struct kvm_caretaker_arch_ser *abi = phys_to_virt(ser->cb.phys);

		arm64_caretaker_sync_vcpu(vcpu, abi);
	}

	kvm_caretaker_post_attach_vcpu(vcpu);
}

/*
 * The Caretaker page, the vCPU state and the struct kvm copy of the VM belong
 * to the address space of the session, which frees them once every CPU of the
 * session has left it: only unlink the page from the ring of the VM, and unpin
 * the VMID with the last vCPU of the VM.
 */
static void arm64_kvm_caretaker_release(struct kvm_vcpu_ser *ser)
{
	struct caretaker_arm64_page *cap;
	u32 vmid;

	if (!ser->cb.phys)
		return;

	cap = phys_to_virt(ser->cb.phys);
	if (arm64_caretaker_stop_vm_vcpus(cap) ||
	    WARN_ON_ONCE(!kvm_caretaker_is_stopped(&cap->abi.cb)))
		return;

	ser->arch_state.phys = 0;
	vmid = cap->abi.vmid;
	if (arm64_caretaker_unlink_vcpu(cap) && vmid)
		kvm_arm_vmid_unpin(vmid);
	ser->cb.phys = 0;
}

void arm64_kvm_caretaker_unpreserve(struct kvm_vcpu_ser *ser)
{
	arm64_kvm_caretaker_release(ser);
}

/*
 * The Caretaker page is still valid here: LUO finishes the files of a session
 * in the reverse order of preservation, and the job of this vCPU needed a
 * preserved CPU of the session, whose file holds the address space of the
 * session and is finished after this one.
 */
void arm64_kvm_caretaker_finish(struct kvm_vcpu_ser *ser)
{
	arm64_kvm_caretaker_release(ser);
}

static int stage2_kho_visitor(const struct kvm_pgtable_visit_ctx *ctx,
			      enum kvm_pgtable_walk_flags visit)
{
	struct kvm_kho_pages *acc = ctx->arg;

	if (kvm_pte_valid(ctx->old) && ctx->level != KVM_PGTABLE_LAST_LEVEL &&
	    FIELD_GET(KVM_PTE_TYPE, ctx->old) == KVM_PTE_TYPE_TABLE) {
		u64 phys = kvm_pte_to_phys(ctx->old);

		kvm_kho_pages_add(acc, phys_to_page(phys));
	}
	return 0;
}

static int arm64_stage2_collect_all(struct kvm *kvm, struct kvm_kho_pages *acc)
{
	struct kvm_s2_mmu *mmu = &kvm->arch.mmu;
	struct kvm_pgtable_walker walker = {
		.cb = stage2_kho_visitor,
		.flags = KVM_PGTABLE_WALK_TABLE_PRE,
		.arg = acc,
	};

	lockdep_assert_held_write(&kvm->mmu_lock);

	if (mmu->pgd_phys) {
		size_t pgd_pages = kvm_pgtable_stage2_pgd_size(mmu->vtcr) >> PAGE_SHIFT;
		size_t p;

		for (p = 0; p < pgd_pages; p++)
			kvm_kho_pages_add(acc,
					  phys_to_page(mmu->pgd_phys + (p << PAGE_SHIFT)));
	}
	if (mmu->pgt)
		return kvm_pgtable_walk(mmu->pgt, 0, BIT(mmu->pgt->ia_bits), &walker);
	return 0;
}

int kvm_arch_vm_luo_freeze(struct kvm *kvm, struct kvm_luo_ser *ser)
{
	arm64_kvm_caretaker_forget_vm(kvm);
	return kvm_kho_preserve_vm_pages(kvm, ser, arm64_stage2_collect_all);
}
