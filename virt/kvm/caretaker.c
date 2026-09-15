// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * Core KVM Caretaker common execution engine and lifecycle management.
 */

/**
 * DOC: KVM Caretaker Architecture and Lifecycle
 *
 * Overview: Orphaned Virtual Machines During Live Update
 * ------------------------------------------------------
 * During a host kernel Live Update (kexec), the userspace VMM and the outgoing
 * Linux kernel tear down and vanish while the incoming kernel boots and a new
 * userspace VMM process adopts the preserved state.  Throughout this handover
 * window, preserved virtual machines are temporarily "orphaned" from any full
 * host operating system or userspace VMM.
 *
 * Instead of freezing all guest vCPUs in RAM for the duration of kexec, the KVM
 * Caretaker framework keeps preserved guest vCPUs actively executing on
 * preserved physical CPUs (CONFIG_LIVEUPDATE_CPU) scheduled by the On-Core
 * runtime (CONFIG_LIVEUPDATE_ONCORE).  When a Live Update session has preserved
 * physical CPUs attached, Caretaker detaches each vCPU into a self-contained
 * KHO-preserved runtime page and schedules it on the preserved cores.  If a
 * session has zero preserved physical CPUs, Caretaker transparently falls back
 * to RAM-only vCPU preservation.
 *
 * System Layering
 * ---------------
 * Orphaned VM execution is structured across four layers:
 *
 * 1. Physical CPU Preservation (kernel/liveupdate/cpu_preserve.c):
 *    Isolates physical CPU cores from Linux hotplug teardown on dedicated
 *    KHO-preserved stacks (&struct cpu_preserved_stack_context), switches them
 *    to isolated page tables (&struct cpu_preserved_as_ser) mapping only
 *    .text.cpu_preserved and .data.cpu_preserved outside KHO Scratch memory,
 *    and provides cache-coherency and cross-CPU wake primitives.
 *
 * 2. On-Core Session & Scheduler (kernel/liveupdate/oncore.c):
 *    Groups preserved physical CPUs and an isolated address space per
 *    &struct liveupdate_session, and runs a lockless round-robin FIFO
 *    scheduler (oncore_cpu_schedule_loop()) that time-slices M workload jobs
 *    across N preserved physical CPUs (supporting both 1:1 dedicated pinning
 *    and M > N oversubscription).
 *
 * 3. Common KVM Caretaker Engine:
 *    Implements the architecture-neutral vCPU quantum loop
 *    (kvm_caretaker_vcpu_run()), normalized VM-exit dispatch
 *    (kvm_caretaker_dispatch_exit()), guest idle handling (HLT/PAUSE/WFI),
 *    unhandled-exit stall parking (%ONCORE_EXIT_STALL), lockless control-block
 *    state transitions (&struct kvm_caretaker_cb_ser), and KVM LUO lifecycle
 *    hooks.
 *
 * 4. Architecture & Vendor Backends (arch/x86/kvm/ and arch/arm64/kvm/):
 *    Implement &struct kvm_caretaker_ops (guest entry/exit assembly, hardware
 *    timer programming, and VMCS/VMCB/EL2 context management) and self-contained
 *    on-core emulation for performance-critical exits (early UART console,
 *    CPUID, MSRs, RDTSC, GICv3 CPU interface / SGI delivery, and architectural
 *    timers) while keeping guest EPT/NPT/Stage-2 page tables live in hardware.
 *
 * Orphaned vCPU Lifecycle and State Machine
 * -----------------------------------------
 * Each vCPU's KHO-preserved control block (&struct kvm_caretaker_cb_ser)
 * transitions through four phases across a live update:
 *
 * 1. Pre-Preserve & Activation (Outgoing Kernel -- LUO Prepare/Freeze):
 *    - kvm_caretaker_vcpu_pre_preserve() submits an &struct oncore_job for
 *      kvm_arch_vcpu_caretaker_run() to the session's least-loaded preserved
 *      physical CPU and records it in @vcpu->caretaker.job.
 *    - kvm_arch_vcpu_luo_preserve() allocates the architecture Caretaker page,
 *      preserves stage-2/TDP MMU page tables, captures guest register and
 *      virtualization hardware state, and calls kvm_caretaker_init_common_vcpu()
 *      to map the runtime page into the session's isolated PGD and initialize
 *      @cb->state to %KVM_CARETAKER_PAUSED.
 *    - kvm_caretaker_vcpu_post_preserve() binds @cb to the job, cleans @cb to
 *      PoC, and calls oncore_session_activate_job() to enqueue the job and kick
 *      the assigned preserved physical CPU.
 *
 * 2. Orphaned On-Core Execution (Across Kexec Handover):
 *    - The preserved CPU invokes kvm_arch_vcpu_caretaker_run(), which
 *      atomically transitions @cb->state from %KVM_CARETAKER_PAUSED to
 *      %KVM_CARETAKER_RUNNING and calls kvm_caretaker_vcpu_run().
 *    - kvm_caretaker_vcpu_run() arms the preemption timer for @deadline_ticks
 *      and repeatedly enters the guest (ops->enter_guest()), decodes exits
 *      (ops->decode_exit()), and dispatches on-core handlers.
 *    - When the time quantum expires (%ONCORE_EXIT_QUANTUM_EXPIRED), the guest
 *      executes HLT/WFI (%ONCORE_EXIT_YIELD_IDLE), or an exit cannot be
 *      emulated on-core (%ONCORE_EXIT_STALL, leaving RIP/PC on the faulting
 *      instruction), the backend serializes live hardware state into
 *      @ser->arch_state, transitions @cb->state back to %KVM_CARETAKER_PAUSED,
 *      and returns to the On-Core scheduler.
 *
 * 3. Re-Attachment & Adoption (Incoming Kernel -- LUO Retrieve/Finish):
 *    - During LUO retrieve, kvm_caretaker_vcpu_pre_retrieve() invokes
 *      kvm_arch_vcpu_luo_pre_retrieve_caretaker(), which calls
 *      kvm_caretaker_wait_for_attach().
 *    - Fast path: if @cb->state is %KVM_CARETAKER_PAUSED, a single cmpxchg()
 *      transitions it to %KVM_CARETAKER_STOPPED immediately.
 *    - Slow path: if @cb->state is %KVM_CARETAKER_RUNNING, it transitions to
 *      %KVM_CARETAKER_STOPPING and sends an IPI kick to force a VM exit.  The
 *      preserved CPU observes kvm_caretaker_should_exit(), serializes final
 *      guest state into @ser->arch_state, publishes %KVM_CARETAKER_STOPPED, and
 *      exits with %ONCORE_EXIT_ATTACH_SIGNALED.
 *    - kvm_arch_vcpu_luo_retrieve() and kvm_caretaker_vcpu_retrieve() then
 *      load the updated state into the incoming &struct kvm_vcpu and resume
 *      normal KVM execution.
 *
 * 4. Cancellation / Rollback (Outgoing Kernel -- LUO Unpreserve):
 *    - If live update is cancelled before kexec, kvm_caretaker_vcpu_unpreserve()
 *      executes the same attach handshake to stop the vCPU on the preserved
 *      core, synchronizes any guest state changes back into the outgoing
 *      &struct kvm_vcpu, and cancels the job via oncore_session_cancel_job().
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

/**
 * kvm_caretaker_vcpu_is_attached - Check whether a vCPU has attached back to host KVM
 * @vcpu: Target KVM vCPU.
 *
 * Return: %true if @vcpu is not running under Caretaker (control block is %NULL
 *         or in %KVM_CARETAKER_STOPPED), %false if still owned by Caretaker.
 */
bool kvm_caretaker_vcpu_is_attached(struct kvm_vcpu *vcpu)
{
	return kvm_caretaker_is_stopped(vcpu->caretaker.cb);
}

/**
 * kvm_caretaker_init_common_vcpu - Initialize common Caretaker vCPU runtime state
 * @cvcpu:        Common Caretaker vCPU descriptor to initialize.
 * @cb:           KHO-preserved Caretaker control block embedded in the arch page.
 * @vcpu:         Host KVM vCPU being preserved.
 * @runtime_va:   Virtual address of the architecture Caretaker runtime page.
 * @runtime_size: Size in bytes of @runtime_va.
 * @ops:          Architecture operations table (&struct kvm_caretaker_ops).
 * @arch_data:    Architecture context pointer passed to @ops callbacks.
 *
 * Initializes @cb in %KVM_CARETAKER_PAUSED state with the preserved physical
 * CPU ID assigned to @vcpu->caretaker.job, maps the runtime buffer into the
 * On-Core session's isolated page tables, and allocates KHO telemetry state.
 */
void kvm_caretaker_init_common_vcpu(struct kvm_caretaker_vcpu *cvcpu,
				    struct kvm_caretaker_cb_ser *cb,
				    struct kvm_vcpu *vcpu,
				    void *runtime_va,
				    size_t runtime_size,
				    const struct kvm_caretaker_ops *ops,
				    void *arch_data)
{
	struct oncore_session *sess = oncore_job_session(vcpu->caretaker.job);

	cb->state = KVM_CARETAKER_PAUSED;
	cb->pcpu_id = oncore_job_cpu(vcpu->caretaker.job);
	cb->vcpu_id = vcpu->vcpu_id;
	cb->reserved = 0;
	cb->telemetry.phys = 0;

	cvcpu->cb = cb;
	cvcpu->ops = ops;
	cvcpu->arch_data = arch_data ? arch_data : cvcpu;
	cvcpu->telemetry = NULL;

	vcpu->caretaker.cb = cb;

	oncore_session_map_buffer(sess, runtime_va, runtime_size);
	kvm_caretaker_telemetry_init(cvcpu, sess);
}

/**
 * kvm_caretaker_should_exit - Check whether the Caretaker vCPU loop must exit for attachment
 * @cvcpu: Common Caretaker vCPU descriptor.
 *
 * Invalidates cache lines for @cvcpu->cb and checks whether the host kernel has
 * requested attachment (%KVM_CARETAKER_STOPPING / %KVM_CARETAKER_STOPPED) or
 * whether the underlying preserved physical CPU is exiting its workload loop.
 *
 * Return: %true if the vCPU must immediately exit guest execution and serialize
 *         its state for host attachment, %false otherwise.
 */
bool __cpu_preserved_text
kvm_caretaker_should_exit(struct kvm_caretaker_vcpu *cvcpu)
{
	struct cpu_preserved_stack_context *sctx;
	u32 st;

	cpu_preserved_inval(cvcpu->cb);

	st = READ_ONCE(cvcpu->cb->state);
	if (st != KVM_CARETAKER_PAUSED && st != KVM_CARETAKER_RUNNING)
		return true;

	sctx = cpu_preserved_get_stack_context();
	return cpu_preserved_should_exit(sctx ? sctx->cpu : cvcpu->cb->pcpu_id);
}

static bool __cpu_preserved_text
kvm_caretaker_dispatch_exit(struct kvm_caretaker_vcpu *cvcpu,
			    struct kvm_caretaker_exit *exit)
{
	switch (exit->type) {
	case KVM_CARETAKER_EXIT_IDLE:
		cpu_preserved_relax();
		exit->rip += exit->insn_len;
		return false;

	case KVM_CARETAKER_EXIT_PREEMPT_TIMER:
	case KVM_CARETAKER_EXIT_UNHANDLED:
	case KVM_CARETAKER_EXIT_UNKNOWN:
		return false;

	case KVM_CARETAKER_EXIT_CONSOLE:
	case KVM_CARETAKER_EXIT_CROSS_VCPU:
	case KVM_CARETAKER_EXIT_INSN_STEP:
	case KVM_CARETAKER_EXIT_ARCH:
	default:
		if (cvcpu->ops->handle_arch_exit)
			return cvcpu->ops->handle_arch_exit(cvcpu->arch_data,
							    exit);
		return false;
	}
}
STACK_FRAME_NON_STANDARD(kvm_caretaker_dispatch_exit);

static int __cpu_preserved_text
kvm_caretaker_enter_guest(struct kvm_caretaker_vcpu *cvcpu)
{
	void *arch_data = cvcpu->arch_data;
	int ret;

	ret = cvcpu->ops->enter_guest(arch_data);
	kvm_caretaker_telemetry_run(cvcpu);
	if (ret && !kvm_caretaker_should_exit(cvcpu)) {
		cpu_preserved_relax();
		ret = cvcpu->ops->enter_guest(arch_data);
		kvm_caretaker_telemetry_run(cvcpu);
	}
	if (ret)
		kvm_caretaker_telemetry_stall(cvcpu, (u32)ret, 0);

	return ret;
}
STACK_FRAME_NON_STANDARD(kvm_caretaker_enter_guest);

static bool __cpu_preserved_text
kvm_caretaker_handle_exit(struct kvm_caretaker_vcpu *cvcpu,
			  enum oncore_exit_reason *reason)
{
	const struct kvm_caretaker_ops *ops = cvcpu->ops;
	struct kvm_caretaker_exit exit __uninitialized;
	void *arch_data = cvcpu->arch_data;
	bool handled;

	cpu_preserved_memset(&exit, 0, sizeof(exit));
	if (ops->decode_exit)
		ops->decode_exit(arch_data, &exit);

	kvm_caretaker_telemetry_exit(cvcpu, &exit);
	if (kvm_caretaker_should_exit(cvcpu))
		return false;

	handled = kvm_caretaker_dispatch_exit(cvcpu, &exit);
	if (ops->advance_rip)
		ops->advance_rip(arch_data, exit.rip);
	if (handled)
		return true;

	/*
	 * A preemption-timer exit is the normal end of a time slice, so leave
	 * @reason alone for it.  For anything else nothing emulated the exit
	 * and RIP was left on the faulting instruction, so re-entering the
	 * guest would take the exact same exit again.  Tell the scheduler the
	 * job is stuck rather than letting it look like an expired time slice,
	 * so that it backs off instead of spinning on VM entry/exit until the
	 * incoming kernel reclaims the vCPU.
	 */
	if (exit.type == KVM_CARETAKER_EXIT_IDLE) {
		*reason = ONCORE_EXIT_YIELD_IDLE;
	} else if (exit.type != KVM_CARETAKER_EXIT_PREEMPT_TIMER) {
		*reason = ONCORE_EXIT_STALL;
		kvm_caretaker_telemetry_stall(cvcpu, exit.raw_reason, exit.rip);
	}

	return false;
}
STACK_FRAME_NON_STANDARD(kvm_caretaker_handle_exit);

/**
 * kvm_caretaker_vcpu_run - Common hardware vCPU execution loop for Caretaker
 * @cvcpu:          Common Caretaker vCPU descriptor.
 * @deadline_ticks: Hardware counter deadline for the current scheduling quantum.
 *
 * Arms the hardware preemption timer for @deadline_ticks and repeatedly enters
 * the guest via @cvcpu->ops->enter_guest(), decodes VM exits, and dispatches
 * on-core exit handlers until the time slice expires, the guest yields on
 * HLT/WFI, the incoming kernel signals attachment, or an unhandled exit stalls
 * the vCPU.
 *
 * Context: Preserved physical CPU (__cpu_preserved_text) with IRQs disabled.
 * Return: &enum oncore_exit_reason indicating why the vCPU left the loop.
 */
enum oncore_exit_reason __cpu_preserved_text
kvm_caretaker_vcpu_run(struct kvm_caretaker_vcpu *cvcpu, u64 deadline_ticks)
{
	struct cpu_preserved_stack_context *sctx = cpu_preserved_get_stack_context();
	enum oncore_exit_reason reason = ONCORE_EXIT_QUANTUM_EXPIRED;
	const struct kvm_caretaker_ops *ops = cvcpu->ops;
	void *arch_data = cvcpu->arch_data;

	if (sctx)
		cvcpu->cb->pcpu_id = sctx->cpu;

	if (kvm_caretaker_should_exit(cvcpu))
		return ONCORE_EXIT_ATTACH_SIGNALED;

	if (ops->pre_run)
		ops->pre_run(arch_data);

	if (deadline_ticks != U64_MAX && ops->arm_timer)
		ops->arm_timer(arch_data, deadline_ticks);

	while (!kvm_caretaker_should_exit(cvcpu)) {
		if (arch_oncore_read_counter() >= deadline_ticks ||
		    (deadline_ticks == U64_MAX && oncore_need_resched()))
			break;

		if (kvm_caretaker_enter_guest(cvcpu)) {
			reason = ONCORE_EXIT_ERROR;
			break;
		}

		if (!kvm_caretaker_handle_exit(cvcpu, &reason))
			break;
	}

	if (deadline_ticks != U64_MAX && ops->disarm_timer)
		ops->disarm_timer(arch_data);

	if (ops->post_run)
		ops->post_run(arch_data);

	kvm_caretaker_telemetry_flush(cvcpu);

	if (kvm_caretaker_should_exit(cvcpu))
		return ONCORE_EXIT_ATTACH_SIGNALED;

	return reason;
}
STACK_FRAME_NON_STANDARD(kvm_caretaker_vcpu_run);

#define KVM_CARETAKER_ATTACH_TIMEOUT_US		2000000
#define KVM_CARETAKER_ATTACH_STEP_US		10
#define KVM_CARETAKER_ATTACH_KICK_STEPS		100

static bool kvm_caretaker_try_stop(struct kvm_caretaker_cb_ser *cb)
{
	cpu_preserved_inval(cb);

	if (READ_ONCE(cb->state) == KVM_CARETAKER_STOPPED)
		return true;

	if (cmpxchg(&cb->state, KVM_CARETAKER_PAUSED,
		    KVM_CARETAKER_STOPPED) == KVM_CARETAKER_PAUSED) {
		cpu_preserved_clean(cb);
		return true;
	}

	return false;
}

/**
 * kvm_caretaker_wait_for_attach - Stop a Caretaker vCPU and wait for state serialization
 * @cb:   KHO-preserved Caretaker control block.
 * @pcpu: Logical ID of the preserved physical CPU running the vCPU.
 *
 * Synchronizes with the preserved physical CPU executing @cb so that the vCPU
 * exits guest mode, serializes its final architectural state into KHO memory,
 * and reaches %KVM_CARETAKER_STOPPED before the host kernel reads back the
 * serialized state.
 *
 * Return: 0 on success, or -ETIMEDOUT if the preserved CPU failed to stop.
 */
int kvm_caretaker_wait_for_attach(struct kvm_caretaker_cb_ser *cb, int pcpu)
{
	int i;

	if (!cb || kvm_caretaker_try_stop(cb))
		return 0;

	if (!cpu_is_preserved(pcpu)) {
		WRITE_ONCE(cb->state, KVM_CARETAKER_STOPPED);
		cpu_preserved_clean(cb);
		/* Ensure state update is visible before returning to caller */
		smp_wmb();
		return 0;
	}

	/*
	 * Slow path: the vCPU is actively executing a quantum on the preserved
	 * physical CPU (%KVM_CARETAKER_RUNNING).  Request a stop by moving it
	 * to %KVM_CARETAKER_STOPPING, send an IPI kick to force a VM exit, and
	 * spin until the preserved CPU finishes detach_serialize() and publishes
	 * %KVM_CARETAKER_STOPPED.
	 */
	cmpxchg(&cb->state, KVM_CARETAKER_RUNNING, KVM_CARETAKER_STOPPING);
	cpu_preserved_clean(cb);
	/* Order state update before kicking and polling the preserved CPU */
	smp_mb();

	for (i = 0; i < KVM_CARETAKER_ATTACH_TIMEOUT_US / KVM_CARETAKER_ATTACH_STEP_US; i++) {
		if (i % KVM_CARETAKER_ATTACH_KICK_STEPS == 0)
			arch_cpu_preserved_kick(pcpu);
		if (kvm_caretaker_try_stop(cb))
			return 0;
		udelay(KVM_CARETAKER_ATTACH_STEP_US);
	}

	pr_warn("kvm: caretaker attach handshake timed out for pCPU %d\n", pcpu);
	return -ETIMEDOUT;
}
STACK_FRAME_NON_STANDARD(kvm_caretaker_wait_for_attach);

/**
 * kvm_caretaker_post_attach_vcpu - Finalize host vCPU state after Caretaker attachment
 * @vcpu: KVM vCPU that has just re-attached from Caretaker.
 *
 * Resets @vcpu->mode and @vcpu->cpu, reports Caretaker execution telemetry to
 * the kernel log and vCPU debugfs snapshot, marks the control block stopped,
 * and clears @vcpu->caretaker.cb.
 */
void kvm_caretaker_post_attach_vcpu(struct kvm_vcpu *vcpu)
{
	/* Ensure vCPU mode update is globally visible before clearing cpu */
	smp_store_mb(vcpu->mode, EXITING_GUEST_MODE);
	vcpu->cpu = -1;

	if (vcpu->caretaker.cb) {
		kvm_caretaker_telemetry_report(vcpu, vcpu->caretaker.cb);
		kvm_caretaker_stop(vcpu->caretaker.cb);
		vcpu->caretaker.cb = NULL;
	}
}

