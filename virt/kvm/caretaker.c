// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * Core KVM Caretaker common execution engine and lifecycle management.
 */

/**
 * DOC: KVM Caretaker Architecture Integration Interface
 *
 * The KVM Caretaker framework provides on-core execution of preserved guest
 * vCPUs during a live kernel update (kexec). The common framework in virt/kvm/
 * handles quantum scheduling, exit dispatching, idle relaxation (HLT/WFI),
 * and attach synchronization.
 *
 * Each architecture supporting Caretaker (e.g., arch/x86/kvm/ and
 * arch/arm64/kvm/) implements hardware-specific execution, exit decoding, and
 * lifecycle handover across three primary interface groups:
 *
 * 1. Global Architecture Entry Points (exported for KVM LUO and Caretaker):
 *    ---------------------------------------------------------------------
 *    - kvm_arch_vcpu_caretaker_run(data, deadline_ticks):
 *        Executes the guest vCPU on the preserved physical CPU until the
 *        preemption deadline expires, an attach is signaled by the incoming
 *        kernel, the vCPU yields in idle, or an unhandled exit occurs.
 *        Called directly by the Caretaker job scheduler.
 *
 *    - kvm_arch_vcpu_caretaker_data(vcpu):
 *        Returns the architecture-specific runtime descriptor (e.g.,
 *        struct caretaker_vmx_page, struct caretaker_svm_page, or struct
 *        kvm_vcpu) associated with the vCPU, to be stored in the Caretaker
 *        job and passed into kvm_arch_vcpu_caretaker_run().
 *
 *    - kvm_arch_vcpu_luo_attach_caretaker(vcpu, ser):
 *        Invoked by the incoming kernel during vCPU adoption. Signals the
 *        running Caretaker loop on the preserved core, waits for
 *        acknowledgment, and synchronizes architecture register/hypervisor
 *        state into the newly allocated incoming vCPU structures.
 *
 * 2. Architecture Operations Vector (struct kvm_caretaker_ops):
 *    ----------------------------------------------------------
 *    Arch backends populate and register this ops table when initializing a
 *    Caretaker vCPU descriptor (struct kvm_caretaker_vcpu):
 *
 *    - enter_guest(vcpu_data):
 *        Performs low-level hardware guest entry (VMENTRY, VMRUN, or ERET).
 *        Runs with local CPU state configured for preserved execution.
 *
 *    - decode_exit(vcpu_data, exit):
 *        Reads hardware exit reasons/qualifications from VMCS, VMCB, or
 *        ESR_EL2 and normalizes them into struct kvm_caretaker_exit (e.g.,
 *        port I/O, MMIO, CPUID, MSR, preempt timer, idle, cross-vCPU IPI).
 *
 *    - handle_arch_exit(vcpu_data, exit):
 *        Handles architecture-specific exits that cannot be resolved by the
 *        common engine (e.g., CPUID leaves, vendor MSRs, APIC ICR dispatch).
 *
 *    - advance_rip(vcpu_data, next_rip):
 *        Advances guest program counter (RIP / PC) past emulated instructions.
 *
 *    - arm_timer(vcpu_data, deadline_ticks):
 *        Programs hardware timer (VMX preemption timer, APIC timer, or ARM
 *        CNTHP) to fire when the time-sharing quantum expires.
 *
 *    - disarm_timer(vcpu_data):
 *        Clears the programmed preemption timer.
 *
 *    - pre_run(vcpu_data) / post_run(vcpu_data):
 *        Optional per-quantum setup and teardown callbacks invoked
 *        immediately before and after the inner vCPU execution loop.
 *
 *    - sync_vcpu(vcpu, vcpu_data):
 *        Copies guest register state from preserved hardware memory into the
 *        target struct kvm_vcpu when attaching.
 *
 * 3. Architecture LUO Lifecycle Hooks:
 *    ---------------------------------
 *    - kvm_arch_vcpu_luo_preserve(vcpu, ser):
 *        Serializes arch vCPU state to KHO and sets up Caretaker runtime pages.
 *
 *    - kvm_arch_vcpu_luo_retrieve(vcpu, ser):
 *        Restores serialized vCPU state from KHO in the incoming kernel.
 *
 *    - kvm_arch_vcpu_luo_unpreserve(ser):
 *        Frees preserved memory buffers if live update is cancelled.
 *
 *    - kvm_arch_vcpu_luo_finish(ser):
 *        Finalizes state and releases KHO buffers after successful handover.
 */

#include <linux/cpu_preserve.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/kho/abi/kvm.h>
#include <linux/kvm_caretaker.h>
#include <linux/kvm_host.h>
#include <linux/liveupdate.h>
#include <linux/objtool.h>
#include <linux/oncore.h>
#include <linux/sched/task.h>

/*
 * The four wrappers below operate on the host-side copy of the control block
 * embedded in struct kvm_vcpu.  They are one-liners onto the control-block
 * helpers; see the comment on struct kvm_vcpu_caretaker for why the host copy
 * and the preserved copy are separate objects, and kvm_caretaker.h for why
 * these cannot be inlines.
 */
void kvm_caretaker_vcpu_init(struct kvm_vcpu *vcpu, int vcpu_id)
{
	kvm_caretaker_cb_init(&vcpu->caretaker.cb, vcpu_id);
	vcpu->caretaker.job = NULL;
}

bool kvm_caretaker_vcpu_is_attached(struct kvm_vcpu *vcpu)
{
	return kvm_caretaker_is_attached(&vcpu->caretaker.cb);
}

void kvm_caretaker_vcpu_detach(struct kvm_vcpu *vcpu)
{
	kvm_caretaker_detach(&vcpu->caretaker.cb);
}

void kvm_caretaker_vcpu_attach(struct kvm_vcpu *vcpu)
{
	kvm_caretaker_attach(&vcpu->caretaker.cb);
}

void kvm_caretaker_init_common_vcpu(struct kvm_caretaker_vcpu *cvcpu,
				   struct kvm_vcpu *vcpu,
				   void *runtime_va,
				   size_t runtime_size,
				   const struct kvm_caretaker_ops *ops,
				   void *arch_data)
{
	int pcpu;

	if (!cvcpu || !vcpu)
		return;

	pcpu = (vcpu->caretaker.cb.pcpu_id != KVM_CARETAKER_INVALID_PCPU &&
		vcpu->caretaker.cb.pcpu_id < nr_cpu_ids) ?
	       vcpu->caretaker.cb.pcpu_id :
	       (vcpu->cpu >= 0 && vcpu->cpu < nr_cpu_ids ? vcpu->cpu : 0);

	cvcpu->cb.attachment_state = KVM_CARETAKER_DETACHED;
	cvcpu->cb.pcpu_id = pcpu;
	cvcpu->cb.vcpu_id = vcpu->vcpu_id;
	cvcpu->cb.runtime_pa = virt_to_phys(runtime_va ? runtime_va : cvcpu);
	cvcpu->cb.runtime_size = runtime_size;

	cvcpu->running = 0;
	cvcpu->total_exits = 0;
	cvcpu->deadline_ticks = 0;
	cvcpu->last_exit_rip = 0;
	cvcpu->ops = ops;
	cvcpu->arch_data = arch_data;

	{
		struct oncore_session *sess = vcpu->caretaker.job ?
						 vcpu->caretaker.job->session : NULL;
		void *buf = runtime_va ? runtime_va : cvcpu;
		size_t sz = runtime_va && runtime_size ? runtime_size : sizeof(*cvcpu);

		oncore_session_map_buffer(sess, buf, sz);
	}
}

bool __cpu_preserved_text
kvm_caretaker_should_exit(struct kvm_caretaker_vcpu *cvcpu)
{
	struct cpu_preserved_stack_context *sctx;
	int pcpu;

	if (!cvcpu)
		return true;

	cpu_preserved_inval(&cvcpu->cb);

	if (READ_ONCE(cvcpu->cb.attachment_state) != KVM_CARETAKER_DETACHED)
		return true;

	sctx = cpu_preserved_get_stack_context();
	if (sctx && sctx->cpu >= 0 && sctx->cpu < CONFIG_NR_CPUS) {
		if (cpu_preserved_should_exit(sctx->cpu))
			return true;
	} else {
		pcpu = cvcpu->cb.pcpu_id;
		if (pcpu >= 0 && pcpu < CONFIG_NR_CPUS && cpu_preserved_should_exit(pcpu))
			return true;
	}

	return false;
}

static bool __cpu_preserved_text
kvm_caretaker_handle_idle(struct kvm_caretaker_vcpu *cvcpu)
{
	cpu_relax();
	if (cvcpu->deadline_ticks)
		return false;
	return true;
}
STACK_FRAME_NON_STANDARD(kvm_caretaker_handle_idle);

static bool __cpu_preserved_text
kvm_caretaker_dispatch_exit(struct kvm_caretaker_vcpu *cvcpu,
			    struct kvm_caretaker_exit *exit)
{
	bool handled = false;

	if (!cvcpu || !exit)
		return false;

	if (kvm_caretaker_should_exit(cvcpu))
		return false;

	cvcpu->total_exits++;

	switch (exit->type) {
	case KVM_CARETAKER_EXIT_IDLE:
		handled = kvm_caretaker_handle_idle(cvcpu);
		exit->rip += exit->insn_len;
		return handled;

	case KVM_CARETAKER_EXIT_PREEMPT_TIMER:
	case KVM_CARETAKER_EXIT_UNHANDLED:
	case KVM_CARETAKER_EXIT_UNKNOWN:
		return false;

	case KVM_CARETAKER_EXIT_CONSOLE:
	case KVM_CARETAKER_EXIT_CROSS_VCPU:
	case KVM_CARETAKER_EXIT_INSN_STEP:
	case KVM_CARETAKER_EXIT_ARCH:
	default:
		if (cvcpu->ops && cvcpu->ops->handle_arch_exit) {
			void *arch_data = cvcpu->arch_data ? cvcpu->arch_data : cvcpu;

			return cvcpu->ops->handle_arch_exit(arch_data, exit);
		}
		return false;
	}
}
STACK_FRAME_NON_STANDARD(kvm_caretaker_dispatch_exit);

STACK_FRAME_NON_STANDARD(kvm_caretaker_vcpu_run);

enum oncore_exit_reason __cpu_preserved_text
kvm_caretaker_vcpu_run(struct kvm_caretaker_vcpu *cvcpu, u64 deadline_ticks)
{
	struct cpu_preserved_stack_context *sctx;
	const struct kvm_caretaker_ops *ops;
	enum oncore_exit_reason reason = ONCORE_EXIT_QUANTUM_EXPIRED;
	int enter_res = 0;
	void *arch_data;

	if (!cvcpu || !cvcpu->ops)
		return ONCORE_EXIT_ERROR;

	sctx = cpu_preserved_get_stack_context();
	cvcpu->deadline_ticks = deadline_ticks;
	ops = cvcpu->ops;
	arch_data = cvcpu->arch_data ? cvcpu->arch_data : cvcpu;

	if (sctx && sctx->cpu >= 0 && sctx->cpu < CONFIG_NR_CPUS)
		cvcpu->cb.pcpu_id = sctx->cpu;

	if (kvm_caretaker_should_exit(cvcpu))
		return ONCORE_EXIT_ATTACH_SIGNALED;

	WRITE_ONCE(cvcpu->running, 1);
	/* Ensure vCPU running flag is visible before entering guest mode */
	smp_wmb();

	if (ops->pre_run)
		ops->pre_run(arch_data);

	if (ops->arm_timer)
		ops->arm_timer(arch_data, deadline_ticks);

	while (true) {
		struct kvm_caretaker_exit exit __uninitialized;
		bool handled = false;

		oncore_memset(&exit, 0, sizeof(exit));

		if (kvm_caretaker_should_exit(cvcpu))
			break;

		if (deadline_ticks && arch_oncore_read_counter() >= deadline_ticks)
			break;

		enter_res = ops->enter_guest(arch_data);
		if (enter_res != 0) {
			if (!kvm_caretaker_should_exit(cvcpu)) {
				cpu_relax();
				enter_res = ops->enter_guest(arch_data);
