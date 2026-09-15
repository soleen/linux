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
			}
			if (enter_res != 0)
				break;
		}

		if (ops->decode_exit)
			ops->decode_exit(arch_data, &exit);

		if (kvm_caretaker_should_exit(cvcpu))
			break;

		handled = kvm_caretaker_dispatch_exit(cvcpu, &exit);

		if (ops->advance_rip)
			ops->advance_rip(arch_data, exit.rip);
		else
			cvcpu->last_exit_rip = exit.rip;

		if (!handled) {
			if (exit.type == KVM_CARETAKER_EXIT_IDLE)
				reason = ONCORE_EXIT_YIELD_IDLE;
			break;
		}

		if (deadline_ticks && arch_oncore_read_counter() >= deadline_ticks)
			break;
	}

	if (ops->disarm_timer)
		ops->disarm_timer(arch_data);

	if (ops->post_run)
		ops->post_run(arch_data);

	if (kvm_caretaker_should_exit(cvcpu))
		return ONCORE_EXIT_ATTACH_SIGNALED;

	if (enter_res != 0)
		return ONCORE_EXIT_ERROR;

	return reason;
}

int kvm_caretaker_wait_for_attach(struct kvm_caretaker_cb *cb, int pcpu,
				  void (*arch_kick)(int pcpu))
{
	struct kvm_caretaker_vcpu *cvcpu;
	int i;

	if (!cb)
		return 0;

	cvcpu = container_of(cb, struct kvm_caretaker_vcpu, cb);

	cpu_preserved_inval(cb);

	if (READ_ONCE(cb->attachment_state) == KVM_CARETAKER_ATTACHED)
		return 0;

	/*
	 * If vCPU is not currently running on physical silicon, its
	 * register state is already completely saved in memory.
	 */
	if (!READ_ONCE(cvcpu->running)) {
		WRITE_ONCE(cb->attachment_state, KVM_CARETAKER_ATTACHED);
		cpu_preserved_clean(cb);
		/* Ensure attachment state update is visible across CPUs */
		smp_wmb();
		return 0;
	}

	if (pcpu < 0 || pcpu >= nr_cpu_ids ||
	    pcpu == raw_smp_processor_id() ||
	    cpu_online(pcpu)) {
		WRITE_ONCE(cb->attachment_state, KVM_CARETAKER_ATTACHED);
		cpu_preserved_clean(cb);
		/* Ensure attachment state update is visible across CPUs */
		smp_wmb();
		return 0;
	}

	WRITE_ONCE(cb->attachment_state, KVM_CARETAKER_ATTACHING);
	cpu_preserved_clean(cb);
	/* Ensure attaching state is committed before issuing kick */
	smp_wmb();

	/* Send kick to target preserved physical CPU */
	if (arch_kick)
		arch_kick(pcpu);
	else
		arch_cpu_preserved_kick(pcpu);

	/* Deterministic spin-wait for Caretaker CPU to exit guest and save context */
	for (i = 0; i < KVM_CARETAKER_ATTACH_TIMEOUT_US / KVM_CARETAKER_ATTACH_STEP_US; i++) {
		cpu_preserved_inval(cb);
		if (READ_ONCE(cb->attachment_state) == KVM_CARETAKER_ATTACHED ||
		    !READ_ONCE(cvcpu->running)) {
			WRITE_ONCE(cb->attachment_state, KVM_CARETAKER_ATTACHED);
			cpu_preserved_clean(cb);
			break;
		}
		if ((i % 100) == 0 && i > 0) {
			if (arch_kick)
				arch_kick(pcpu);
			else
				arch_cpu_preserved_kick(pcpu);
		}
		udelay(KVM_CARETAKER_ATTACH_STEP_US);
	}

	if (READ_ONCE(cb->attachment_state) != KVM_CARETAKER_ATTACHED) {
		pr_warn("kvm: caretaker attach handshake timed out for pCPU %d\n", pcpu);
		return -ETIMEDOUT;
	}

	return 0;
}
STACK_FRAME_NON_STANDARD(kvm_caretaker_wait_for_attach);

void kvm_caretaker_post_attach_vcpu(struct kvm_vcpu *vcpu,
				    struct kvm_caretaker_vcpu *cvcpu)
{
	int pcpu = -1;

	if (!vcpu)
		return;

	if (cvcpu)
		pcpu = cvcpu->cb.pcpu_id;
	else if (vcpu->caretaker.cb.pcpu_id != KVM_CARETAKER_INVALID_PCPU)
		pcpu = vcpu->caretaker.cb.pcpu_id;

	if (pcpu >= 0 && pcpu < CONFIG_NR_CPUS)
		vcpu->caretaker.cb.pcpu_id = pcpu;

	vcpu->caretaker.cb.runtime_pa = 0;
	vcpu->caretaker.cb.runtime_size = 0;
	/* Ensure vCPU mode update is globally visible before clearing cpu */
	smp_store_mb(vcpu->mode, EXITING_GUEST_MODE);
	vcpu->cpu = -1;

	if (pcpu >= 0)
		kvm_caretaker_vcpu_attach(vcpu);
}

int kvm_caretaker_vcpu_pre_preserve(struct kvm_vcpu *vcpu,
				    struct liveupdate_session *session,
				    struct kvm_vcpu_luo_ser *ser)
{
	char name[LIVEUPDATE_SESSION_NAME_LENGTH];
	struct task_struct *task = NULL;
	struct oncore_job *job;
	int target_cpu = -1;

	read_lock(&vcpu->pid_lock);
	task = vcpu->pid ? pid_task(vcpu->pid, PIDTYPE_PID) : NULL;
	if (task)
		get_task_struct(task);
	read_unlock(&vcpu->pid_lock);

	if (task) {
		if (task->nr_cpus_allowed == 1) {
			int cpu = cpumask_first(task->cpus_ptr);

			if (cpu >= 0 && cpu < nr_cpu_ids)
				target_cpu = cpu;
		}
		put_task_struct(task);
	}

	if (target_cpu < 0 && vcpu->caretaker.cb.pcpu_id < nr_cpu_ids)
		target_cpu = vcpu->caretaker.cb.pcpu_id;

	snprintf(name, sizeof(name), "vcpu%d", vcpu->vcpu_id);

	/*
	 * Submit with no data: the run callback's argument is the caretaker
	 * control block, which does not exist until the architecture's
	 * kvm_arch_vcpu_luo_preserve() has allocated it.  It is installed with
	 * oncore_job_set_data() from _post_preserve(), before activation.
	 */
	job = oncore_session_submit_job(session, name, target_cpu,
					kvm_arch_vcpu_caretaker_run, NULL);
	if (IS_ERR(job))
		return PTR_ERR(job);

	vcpu->caretaker.job = job;
	target_cpu = job->assigned_cpu;

	/*
	 * The architecture hook keys off this flag to decide whether to
	 * allocate a control block at all, so it has to be set before the hook
	 * runs -- which is the whole reason preserve is split in two.
	 */
	if (target_cpu >= 0) {
		ser->flags |= KVM_VCPU_LUO_FLAG_CARETAKER;
		vcpu->caretaker.cb.pcpu_id = target_cpu;
	} else {
		vcpu->caretaker.cb.pcpu_id = KVM_CARETAKER_INVALID_PCPU;
	}

	return 0;
}

int kvm_caretaker_vcpu_post_preserve(struct kvm_vcpu *vcpu,
				     struct liveupdate_session *session,
				     struct kvm_vcpu_luo_ser *ser,
				     int arch_err)
{
	struct oncore_job *job = vcpu->caretaker.job;
	struct kvm_caretaker_cb *cb;
	int err;

	if (arch_err) {
		oncore_session_cancel_job(session, job);
		vcpu->caretaker.job = NULL;
		return arch_err;
	}

	if (!(ser->flags & KVM_VCPU_LUO_FLAG_CARETAKER))
		return 0;

	cb = kvm_arch_vcpu_caretaker_data(vcpu);
	oncore_job_set_data(job, cb);
	if (!cb)
		return 0;

	cb->pcpu_id = job->assigned_cpu;
	if (cb->runtime_size && cb->runtime_pa) {
		cpu_preserved_map_range(cb->runtime_pa,
					(unsigned long)phys_to_virt(cb->runtime_pa),
					cb->runtime_size, PAGE_KERNEL);
	}

	/*
	 * Two control blocks, two address spaces, one transition.  The host
	 * copy is what kvm_vcpu_ioctl(KVM_RUN) consults to refuse to run a
	 * detached vCPU; the preserved copy is what the orphaned core reads
	 * once it is running without us.  Both must flip, and they cannot flip
	 * atomically -- see struct kvm_vcpu_caretaker.
	 */
	kvm_caretaker_vcpu_detach(vcpu);
	kvm_caretaker_detach(cb);
	cpu_preserved_clean(cb);

	err = oncore_session_activate_job(session, job);
	if (err) {
		oncore_session_cancel_job(session, job);
		vcpu->caretaker.job = NULL;
		kvm_caretaker_vcpu_attach(vcpu);
		kvm_caretaker_attach(cb);
		return err;
	}

	return 0;
}

void kvm_caretaker_vcpu_pre_retrieve(struct kvm_vcpu *vcpu,
				     struct kvm_vcpu_luo_ser *ser)
{
	kvm_arch_vcpu_luo_pre_retrieve_caretaker(vcpu, ser);
}

void kvm_caretaker_vcpu_retrieve(struct kvm_vcpu *vcpu,
				 struct kvm_vcpu_luo_ser *ser)
{
	kvm_arch_vcpu_luo_attach_caretaker(vcpu, ser);
	vcpu->caretaker.cb.vcpu_id = ser->vcpu_id;
}

void kvm_caretaker_vcpu_unpreserve(struct kvm_vcpu *vcpu,
				   struct liveupdate_session *session,
				   struct kvm_vcpu_luo_ser *ser)
{
	if (!vcpu)
		return;

	kvm_arch_vcpu_luo_pre_retrieve_caretaker(vcpu, ser);
	kvm_arch_vcpu_luo_retrieve(vcpu, ser);
	kvm_arch_vcpu_luo_attach_caretaker(vcpu, ser);
	if (vcpu->caretaker.job) {
		oncore_session_cancel_job(session, vcpu->caretaker.job);
		vcpu->caretaker.job = NULL;
	}
	vcpu->caretaker.cb.pcpu_id = KVM_CARETAKER_INVALID_PCPU;
}

void kvm_caretaker_vcpu_finish(struct kvm_vcpu *vcpu,
			       struct liveupdate_session *session)
{
	if (vcpu && vcpu->caretaker.job) {
		oncore_session_cancel_job(session, vcpu->caretaker.job);
		vcpu->caretaker.job = NULL;
	}
	if (vcpu)
		vcpu->caretaker.cb.pcpu_id = KVM_CARETAKER_INVALID_PCPU;
}
