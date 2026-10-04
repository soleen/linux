// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * x86 KVM Caretaker isolated runtime execution loop.
 */

#include <linux/cpu_preserve.h>
#include <linux/kho/abi/kvm.h>
#include <linux/kvm_host.h>
#include <linux/oncore.h>
#include <linux/string.h>

#include <asm/apic.h>
#include <asm/desc.h>
#include <asm/fpu/api.h>
#include <asm/fpu/xcr.h>
#include <asm/irq_vectors.h>
#include <asm/msr.h>

#include "caretaker.h"
#include "lapic.h"
#include "regs.h"
#include "switch.h"
#include "x86.h"

/* Host register state saved around an on-core caretaker run. */
struct caretaker_x86_host_state {
	unsigned long orig_cr2;
	unsigned long orig_cr4;
	unsigned long orig_cr8;
	unsigned long orig_fs_base;
	unsigned long orig_gs_base;
	unsigned long orig_kernel_gs_base;
	u64 orig_star;
	u64 orig_lstar;
	u64 orig_fmask;
	u64 orig_xcr0;
};

const struct kvm_x86_caretaker_runtime_ops *kvm_x86_caretaker_ops;
const struct kvm_x86_ops *kvm_x86_ops_ptr;
struct kvm_caps kvm_caps;
u32 kvm_cpu_caps[NR_KVM_CPU_CAPS];
bool caretaker_x86_has_tsc_deadline;
u32 caretaker_x86_lapic_timer_period;
u32 caretaker_x86_tsc_khz;

static void
kvm_x86_caretaker_load_desc(struct desc_struct *gdt, size_t gdt_size,
			    void *tss)
{
	struct desc_ptr gdt_desc = {
		.size = gdt_size - 1,
		.address = (unsigned long)gdt,
	};

	caretaker_set_tss_desc(gdt, (unsigned long)tss, sizeof(struct x86_hw_tss) - 1);
	asm volatile("lgdt %0" : : "m" (gdt_desc));
	native_load_idt(&x86_preserved_idt_desc);
	asm volatile("ltr %w0" : : "q" ((u16)(GDT_ENTRY_TSS * 8)));
}

static void
kvm_x86_caretaker_save_host_state(struct caretaker_x86_host_state *host,
				  struct caretaker_x86_page *cxp)
{
	struct cpu_preserved_stack_context *sctx;
	u64 apic_base;

	host->orig_cr2 = native_read_cr2();
	host->orig_cr4 = caretaker_read_cr4();
	asm volatile("mov %%cr8, %0" : "=r" (host->orig_cr8));
	asm volatile("mov %0, %%cr8" : : "r" (0UL) : "memory");
	/*
	 * MSR_FS_BASE is in the guest-writable passthrough set below, so it
	 * has to be saved here or a guest WRMSR to it survives the run and
	 * corrupts the host's FS base.
	 */
	host->orig_fs_base = native_rdmsrq(MSR_FS_BASE);
	host->orig_gs_base = native_rdmsrq(MSR_GS_BASE);
	host->orig_kernel_gs_base = native_rdmsrq(MSR_KERNEL_GS_BASE);
	host->orig_star = native_rdmsrq(MSR_STAR);
	host->orig_lstar = native_rdmsrq(MSR_LSTAR);
	host->orig_fmask = native_rdmsrq(MSR_SYSCALL_MASK);
	host->orig_xcr0 = cxp->host_xcr0;

	/* Ensure Local APIC is software enabled */
	apic_base = native_rdmsrq(MSR_IA32_APICBASE);
	if (!(apic_base & MSR_IA32_APICBASE_ENABLE))
		native_wrmsrq(MSR_IA32_APICBASE,
			      apic_base | MSR_IA32_APICBASE_ENABLE);

	/* Switch to self-contained Caretaker GDT, IDT, and TSS before CR3 switch */
	kvm_x86_caretaker_load_desc(cxp->gdt, sizeof(cxp->gdt), &cxp->tss);

	/*
	 * Switch to preserved CR3 and clear X86_CR4_PGE so no global TLB
	 * entries from the host kernel survive into Caretaker execution.
	 */
	sctx = cpu_preserved_get_stack_context();
	if (sctx && sctx->session_pgd_pa)
		cxp->host_cr3 = sctx->session_pgd_pa;
	if (cxp->host_cr3) {
		/*
		 * Always reload CR3 to flush any non-global TLB entries even
		 * if CR3 already holds cxp->host_cr3.
		 */
		native_write_cr3(cxp->host_cr3);
		if (host->orig_cr4 & X86_CR4_PGE)
			asm volatile("mov %0, %%cr4"
				     : : "r" (host->orig_cr4 & ~X86_CR4_PGE)
				     : "memory");
	}

	raw_local_irq_disable();
}

static void
kvm_x86_caretaker_restore_host_state(const struct caretaker_x86_host_state *host)
{
	/*
	 * Restore unconditionally.  These are all in the guest-writable
	 * passthrough set, so skipping the write when the saved value happens
	 * to be zero leaves the *guest's* value live in the host MSR.
	 */
	native_write_cr2(host->orig_cr2);
	asm volatile("mov %0, %%cr8" : : "r" (host->orig_cr8) : "memory");
	native_wrmsrq(MSR_FS_BASE, host->orig_fs_base);
	native_wrmsrq(MSR_GS_BASE, host->orig_gs_base);
	native_wrmsrq(MSR_KERNEL_GS_BASE, host->orig_kernel_gs_base);
	native_wrmsrq(MSR_LSTAR, host->orig_lstar);
	native_wrmsrq(MSR_STAR, host->orig_star);
	native_wrmsrq(MSR_SYSCALL_MASK, host->orig_fmask);
	if (host->orig_xcr0)
		xsetbv(XCR_XFEATURE_ENABLED_MASK, host->orig_xcr0);
	arch_cpu_preserved_load_desc();
}

static __always_inline struct kvm_msrs *
kvm_x86_caretaker_msrs(const struct kvm_vcpu_arch_ser *state)
{
	if (!state || !state->msrs.phys)
		return NULL;
	return (struct kvm_msrs *)(state + 1);
}

static void kvm_x86_caretaker_update_msr(struct kvm_vcpu_arch_ser *state,
					 u32 msr, u64 val)
{
	struct kvm_msrs *msrs = kvm_x86_caretaker_msrs(state);
	u32 i;

	if (!msrs)
		return;

	for (i = 0; i < msrs->nmsrs; i++) {
		if (msrs->entries[i].index == msr) {
			msrs->entries[i].data = val;
			return;
		}
	}
}

static void
caretaker_save_guest_fpu(struct caretaker_x86_page *cxp,
			 struct kvm_vcpu_arch_ser *state)
{
	union fpregs_state *xstate;
	u64 guest_xcr0, rfbm;

	if (!cxp || !state || !cxp->save_guest_fpu)
		return;

	xstate = (union fpregs_state *)state->xsave.region;
	guest_xcr0 = cxp->kvm_vcpu ? cxp->kvm_vcpu->arch.xcr0 :
				     state->xcrs.xcrs[0].value;
	state->xcrs.xcrs[0].value = guest_xcr0;
	rfbm = guest_xcr0 | XFEATURE_MASK_FPSSE;

	if (caretaker_read_cr0() & X86_CR0_TS)
		asm volatile("clts" : : : "memory");

	if (cxp->host_xcr0)
		xsetbv(XCR_XFEATURE_ENABLED_MASK, cxp->host_xcr0);

	asm volatile("1: xsave64 %[buf]\n\t"
		     "2:\n\t"
		     _ASM_EXTABLE(1b, 2b)
		     : [buf] "=m" (*xstate)
		     : "a" ((u32)rfbm), "d" ((u32)(rfbm >> 32))
		     : "memory");
}

static const u32 caretaker_sync_msrs[] = {
	MSR_STAR,
	MSR_LSTAR,
	MSR_CSTAR,
	MSR_SYSCALL_MASK,
	MSR_KERNEL_GS_BASE,
	MSR_IA32_SYSENTER_CS,
	MSR_IA32_SYSENTER_ESP,
	MSR_IA32_SYSENTER_EIP,
	MSR_IA32_DEBUGCTLMSR,
};

static void
kvm_x86_caretaker_detach_serialize_common(struct caretaker_x86_page *cxp,
					  struct kvm_vcpu_arch_ser *state)
{
	struct kvm_vcpu *vcpu;
	struct desc_ptr dt;
	int i;

	if (!cxp || !state || !cxp->kvm_vcpu)
		return;

	vcpu = cxp->kvm_vcpu;
	state->regs.rax = kvm_rax_read_raw(vcpu);
	state->regs.rbx = kvm_rbx_read_raw(vcpu);
	state->regs.rcx = kvm_rcx_read_raw(vcpu);
	state->regs.rdx = kvm_rdx_read_raw(vcpu);
	state->regs.rsi = kvm_rsi_read_raw(vcpu);
	state->regs.rdi = kvm_rdi_read_raw(vcpu);
	state->regs.rbp = kvm_rbp_read_raw(vcpu);
	state->regs.r8  = kvm_r8_read_raw(vcpu);
	state->regs.r9  = kvm_r9_read_raw(vcpu);
	state->regs.r10 = kvm_r10_read_raw(vcpu);
	state->regs.r11 = kvm_r11_read_raw(vcpu);
	state->regs.r12 = kvm_r12_read_raw(vcpu);
	state->regs.r13 = kvm_r13_read_raw(vcpu);
	state->regs.r14 = kvm_r14_read_raw(vcpu);
	state->regs.r15 = kvm_r15_read_raw(vcpu);

	state->regs.rip = kvm_rip_read(vcpu);
	state->regs.rsp = kvm_rsp_read(vcpu);
	state->regs.rflags = kvm_get_rflags(vcpu);

	state->sregs.cr0 = kvm_read_cr0(vcpu);
	state->sregs.cr2 = vcpu->arch.cr2;
	state->sregs.cr3 = kvm_read_cr3(vcpu);
	state->sregs.cr4 = kvm_read_cr4(vcpu);
	state->sregs.efer = vcpu->arch.efer;

	kvm_x86_call(get_segment)(vcpu, &state->sregs.cs, VCPU_SREG_CS);
	kvm_x86_call(get_segment)(vcpu, &state->sregs.ds, VCPU_SREG_DS);
	kvm_x86_call(get_segment)(vcpu, &state->sregs.es, VCPU_SREG_ES);
	kvm_x86_call(get_segment)(vcpu, &state->sregs.fs, VCPU_SREG_FS);
	kvm_x86_call(get_segment)(vcpu, &state->sregs.gs, VCPU_SREG_GS);
	kvm_x86_call(get_segment)(vcpu, &state->sregs.ss, VCPU_SREG_SS);
	kvm_x86_call(get_segment)(vcpu, &state->sregs.tr, VCPU_SREG_TR);
	kvm_x86_call(get_segment)(vcpu, &state->sregs.ldt, VCPU_SREG_LDTR);

	kvm_x86_call(get_gdt)(vcpu, &dt);
	state->sregs.gdt.base = dt.address;
	state->sregs.gdt.limit = dt.size;

	kvm_x86_call(get_idt)(vcpu, &dt);
	state->sregs.idt.base = dt.address;
	state->sregs.idt.limit = dt.size;

	for (i = 0; i < ARRAY_SIZE(caretaker_sync_msrs); i++) {
		struct msr_data msr_info = {
			.index = caretaker_sync_msrs[i],
			.host_initiated = true,
		};

		if (kvm_x86_call(get_msr)(vcpu, &msr_info) == 0)
			kvm_x86_caretaker_update_msr(state, msr_info.index,
						     msr_info.data);
	}

	/*
	 * Refresh MSR_IA32_TSC at exit time so kvm_synchronize_tsc() on
	 * retrieve computes the preserved TSC_OFFSET rather than a stale
	 * pre-kexec timestamp.
	 */
	kvm_x86_caretaker_update_msr(state, MSR_IA32_TSC,
				     kvm_read_l1_tsc(vcpu, rdtsc()));

	if (lapic_in_kernel(vcpu))
		kvm_x86_caretaker_update_msr(state, MSR_IA32_TSC_DEADLINE,
					     kvm_get_lapic_tscdeadline_msr(vcpu));

	state->events.exception.injected = 0;
	state->events.interrupt.injected = 0;

	caretaker_save_guest_fpu(cxp, state);
}

static void
caretaker_restore_guest_fpu(struct caretaker_x86_page *cxp,
			    struct kvm_vcpu_arch_ser *state)
{
	union fpregs_state *xstate;
	u64 guest_xcr0, rfbm;

	if (!cxp || !state || !cxp->save_guest_fpu)
		return;

	xstate = (union fpregs_state *)state->xsave.region;
	guest_xcr0 = (cxp->kvm_vcpu ? cxp->kvm_vcpu->arch.xcr0 :
				      state->xcrs.xcrs[0].value) |
		     XFEATURE_MASK_FP;
	rfbm = cxp->host_xcr0 ? : (guest_xcr0 | XFEATURE_MASK_FPSSE);

	if (caretaker_read_cr0() & X86_CR0_TS)
		asm volatile("clts" : : : "memory");

	/*
	 * Enable host XCR0 first, mask xstate.header.xfeatures to the guest's
	 * valid state, and XRSTOR with rfbm = host_xcr0 so any host-enabled
	 * components not in the guest's XCR0 are hardware-initialized (cleared)
	 * rather than leaked across co-scheduled VMs, without reading beyond
	 * the guest's XSAVE region.  Then load the guest's actual XCR0.
	 */
	if (cxp->host_xcr0)
		xsetbv(XCR_XFEATURE_ENABLED_MASK, cxp->host_xcr0);

	xstate->xsave.header.xfeatures &= guest_xcr0 | XFEATURE_MASK_FPSSE;

	asm volatile("1: xrstor64 %[buf]\n\t"
		     "2:\n\t"
		     _ASM_EXTABLE(1b, 2b)
		     :
		     : [buf] "m" (*xstate),
		       "a" ((u32)rfbm), "d" ((u32)(rfbm >> 32))
		     : "memory");

	if (cxp->host_xcr0 && guest_xcr0 != cxp->host_xcr0)
		xsetbv(XCR_XFEATURE_ENABLED_MASK, guest_xcr0);
}

static bool
kvm_x86_caretaker_vcpu_run(struct kvm_caretaker_vcpu *cvcpu,
			   enum oncore_exit_reason *reason)
{
	const struct kvm_x86_caretaker_runtime_ops *ops = kvm_x86_caretaker_ops;
	struct caretaker_x86_page *cxp = cvcpu->arch_data;
	struct kvm_vcpu *vcpu = cxp->kvm_vcpu;
	u32 exit_code = 0;
	u64 rip;
	int ret;

	ret = ops->enter(cxp, &exit_code);
	kvm_caretaker_telemetry_run(cvcpu);
	if (unlikely(ret)) {
		cxp->run_failed = true;
		*reason = ONCORE_EXIT_ERROR;
		kvm_caretaker_telemetry_stall(cvcpu, (u32)ret, 0);
		return false;
	}

	rip = kvm_rip_read(vcpu);
	kvm_caretaker_telemetry_record_exit(cvcpu, exit_code, rip);
	if (kvm_caretaker_should_exit(cvcpu))
		return false;

	ret = ops->handle_exit(cxp, exit_code, reason);
	if (ret < 0) {
		*reason = ONCORE_EXIT_STALL;
		kvm_caretaker_telemetry_stall(cvcpu, exit_code, rip);
		return false;
	}

	return ret > 0;
}

static void kvm_x86_caretaker_op_arm_timer(void *vcpu_data, u64 deadline_ticks)
{
	if (kvm_x86_caretaker_ops->arm_timer)
		kvm_x86_caretaker_ops->arm_timer(vcpu_data, deadline_ticks);
}

static void kvm_x86_caretaker_op_disarm_timer(void *vcpu_data)
{
	if (kvm_x86_caretaker_ops->disarm_timer)
		kvm_x86_caretaker_ops->disarm_timer(vcpu_data);
}

static void kvm_x86_caretaker_op_pre_run(void *vcpu_data)
{
	if (kvm_x86_caretaker_ops->pre_run)
		kvm_x86_caretaker_ops->pre_run(vcpu_data);
}

static void kvm_x86_caretaker_op_post_run(void *vcpu_data)
{
	struct caretaker_x86_page *cxp = vcpu_data;

	if (!cxp->run_failed && cxp->arch_state)
		kvm_x86_caretaker_detach_serialize_common(cxp, cxp->arch_state);
	if (kvm_x86_caretaker_ops->post_run)
		kvm_x86_caretaker_ops->post_run(vcpu_data);
}

static const struct kvm_caretaker_ops kvm_x86_caretaker_common_ops = {
	.vcpu_run = kvm_x86_caretaker_vcpu_run,
	.arm_timer = kvm_x86_caretaker_op_arm_timer,
	.disarm_timer = kvm_x86_caretaker_op_disarm_timer,
	.pre_run = kvm_x86_caretaker_op_pre_run,
	.post_run = kvm_x86_caretaker_op_post_run,
};

struct caretaker_x86_abort_ctx {
	struct caretaker_x86_page *cxp;
	struct caretaker_x86_host_state *host_state;
};

static void
kvm_x86_caretaker_fault_abort(int cpu, const struct x86_preserved_fault *f)
{
	const struct caretaker_x86_abort_ctx *ctx = f->abort_data;
	struct caretaker_x86_page *cxp;

	if (!ctx || !ctx->cxp)
		return;

	cxp = ctx->cxp;
	if (kvm_x86_caretaker_ops && kvm_x86_caretaker_ops->disarm_timer)
		kvm_x86_caretaker_ops->disarm_timer(cxp);
	if (kvm_x86_caretaker_ops && kvm_x86_caretaker_ops->post_run)
		kvm_x86_caretaker_ops->post_run(cxp);
	if (ctx->host_state)
		kvm_x86_caretaker_restore_host_state(ctx->host_state);

	kvm_caretaker_telemetry_stall(&cxp->vcpu,
				      KVM_CARETAKER_FAULT_STALL_BASE | (u32)f->vector,
				      f->ip);
	kvm_caretaker_telemetry_record_exit(&cxp->vcpu, f->cr2, f->ip);
	kvm_caretaker_telemetry_flush(&cxp->vcpu);
	smp_mb(); /* Order telemetry flush before publishing FAILED */
	WRITE_ONCE(cxp->abi.cb.state, KVM_CARETAKER_FAILED);
	cpu_preserved_clean(&cxp->abi.cb);
}

static enum oncore_exit_reason
kvm_x86_caretaker_run_page(struct caretaker_x86_page *cxp, u64 deadline_ticks)
{
	const struct kvm_x86_caretaker_runtime_ops *ops = kvm_x86_caretaker_ops;
	enum oncore_exit_reason reason = ONCORE_EXIT_QUANTUM_EXPIRED;
	struct cpu_preserved_stack_context *sctx;
	struct caretaker_x86_host_state host_state;
	struct caretaker_x86_abort_ctx abort_ctx;
	int pcpu;

	if (!cxp || !ops)
		return ONCORE_EXIT_ERROR;

	if (cmpxchg(&cxp->abi.cb.state, KVM_CARETAKER_PAUSED,
		    KVM_CARETAKER_RUNNING) != KVM_CARETAKER_PAUSED)
		return ONCORE_EXIT_ATTACH_SIGNALED;

	sctx = cpu_preserved_get_stack_context();
	pcpu = sctx ? sctx->cpu : cxp->abi.cb.pcpu_id;
	WRITE_ONCE(cxp->abi.cb.pcpu_id, pcpu);

	if (kvm_caretaker_should_exit(&cxp->vcpu)) {
		smp_mb(); /* Order serialized state before STOPPED */
		WRITE_ONCE(cxp->abi.cb.state, KVM_CARETAKER_STOPPED);
		return ONCORE_EXIT_ATTACH_SIGNALED;
	}

	/* Save host context, switch to Caretaker descriptors and CR3 */
	kvm_x86_caretaker_save_host_state(&host_state, cxp);

	abort_ctx.cxp = cxp;
	abort_ctx.host_state = &host_state;
	if (sctx) {
		sctx->fault.abort_data = &abort_ctx;
		sctx->fault.abort_fn = kvm_x86_caretaker_fault_abort;
	}

	if (cxp->arch_state)
		caretaker_restore_guest_fpu(cxp, cxp->arch_state);

	cxp->run_failed = false;
	cxp->vcpu.ops = &kvm_x86_caretaker_common_ops;

	reason = kvm_caretaker_vcpu_run(&cxp->vcpu, deadline_ticks);

	iret_to_self();

	if (sctx) {
		sctx->fault.abort_fn = NULL;
		sctx->fault.abort_data = NULL;
	}

	kvm_x86_caretaker_restore_host_state(&host_state);

	if (reason == ONCORE_EXIT_ERROR) {
		smp_mb();
		WRITE_ONCE(cxp->abi.cb.state, KVM_CARETAKER_FAILED);
		cpu_preserved_clean(&cxp->abi.cb);
	} else if (reason == ONCORE_EXIT_ATTACH_SIGNALED ||
		   kvm_caretaker_should_exit(&cxp->vcpu) ||
		   cmpxchg(&cxp->abi.cb.state, KVM_CARETAKER_RUNNING,
			   KVM_CARETAKER_PAUSED) != KVM_CARETAKER_RUNNING) {
		reason = ONCORE_EXIT_ATTACH_SIGNALED;
		smp_mb(); /* Order serialized state before STOPPED */
		WRITE_ONCE(cxp->abi.cb.state, KVM_CARETAKER_STOPPED);
		cpu_preserved_clean(&cxp->abi.cb);
	}

	return reason;
}

enum oncore_exit_reason
kvm_arch_vcpu_caretaker_run(void *data, u64 deadline_ticks)
{
	struct kvm_caretaker_cb_ser *cb = data;

	if (!cb)
		return ONCORE_EXIT_ERROR;

	return kvm_x86_caretaker_run_page(cxp_from_cb(cb), deadline_ticks);
}

void kvm_x86_caretaker_arm_timer(u64 deadline_ticks)
{
	if (!deadline_ticks || deadline_ticks == U64_MAX)
		return;

	if (caretaker_x86_has_tsc_deadline) {
		u32 lvtt = LOCAL_TIMER_VECTOR | APIC_LVT_TIMER_TSCDEADLINE;

		native_wrmsrq(APIC_BASE_MSR + (APIC_LVTT >> 4), lvtt);
		native_wrmsrq(MSR_IA32_TSC_DEADLINE, deadline_ticks);
	} else {
		u64 now = rdtsc();
		u64 delta_tsc = (deadline_ticks > now) ? (deadline_ticks - now) : 1;
		u32 lvtt = LOCAL_TIMER_VECTOR;
		u64 count;

		if (caretaker_x86_tsc_khz != 0 && caretaker_x86_lapic_timer_period != 0) {
			u64 period = caretaker_x86_lapic_timer_period;
			u64 apic_khz = (period * HZ) / 1000ULL;

			count = (delta_tsc * apic_khz) /
				((u64)caretaker_x86_tsc_khz * 16ULL);
		} else {
			count = delta_tsc >> 4;
		}
		if (count == 0)
			count = 1;
		if (count > U32_MAX)
			count = U32_MAX;

		native_wrmsrq(APIC_BASE_MSR + (APIC_TDCR >> 4),
			      APIC_TDR_DIV_16);
		native_wrmsrq(APIC_BASE_MSR + (APIC_LVTT >> 4), lvtt);
		native_wrmsrq(APIC_BASE_MSR + (APIC_TMICT >> 4), (u32)count);
	}
}

void kvm_x86_caretaker_disarm_timer(void)
{
	if (caretaker_x86_has_tsc_deadline)
		native_wrmsrq(MSR_IA32_TSC_DEADLINE, 0);
	else
		native_wrmsrq(APIC_BASE_MSR + (APIC_TMICT >> 4), 0);

	native_wrmsrq(APIC_BASE_MSR + (APIC_LVTT >> 4),
		      APIC_LVT_MASKED | LOCAL_TIMER_VECTOR);
}
