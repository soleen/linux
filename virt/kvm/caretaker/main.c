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
 * runtime.  When a Live Update session has preserved
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
 *    .cpu_preserved.text and .cpu_preserved.data outside KHO Scratch memory,
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
 *    (kvm_caretaker_vcpu_run()), guest idle yielding, unhandled-exit stall
 *    parking (%ONCORE_EXIT_STALL), lockless control-block state transitions
 *    (&struct kvm_caretaker_cb_ser), and KVM LUO lifecycle hooks.
 *
 * 4. Architecture & Vendor Backends (arch/x86/kvm/ and arch/arm64/kvm/):
 *    Implement &struct kvm_caretaker_ops (KVM world-switch guest entry/exit,
 *    hardware timer programming, and VMCS/VMCB/EL2 context management) and
 *    dispatch shared KVM fastpath exit handlers (early UART console, CPUID,
 *    MSRs, RDTSC, GICv3 CPU interface / SGI delivery, and architectural
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
 *      and repeatedly enters the guest and dispatches fastpath exit handlers
 *      via ops->vcpu_run().
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
#include <linux/kexec_handover.h>
#include <linux/kho/abi/kvm.h>
#include <linux/kvm_caretaker.h>
#include <linux/kvm_host.h>
#include <linux/liveupdate.h>
#include <linux/mm.h>
#include <linux/oncore.h>
#include <linux/sort.h>
#include <linux/string.h>

struct kvm_kho_folios_ser *kvm_kho_folios_alloc(unsigned int max_folios)
{
	struct kvm_kho_folios_ser *kp;
	size_t sz = struct_size(kp, folios_pa, max_folios);

	kp = kho_alloc_preserve(sz);
	if (IS_ERR(kp))
		return kp;

	kp->nr_folios = 0;
	return kp;
}

void kvm_kho_folios_unpreserve(struct kvm_kho_folios_ser *kp)
{
	unsigned int i;

	if (!kp)
		return;

	for (i = 0; i < kp->nr_folios; i++)
		kho_unpreserve_folio(page_folio(phys_to_page(kp->folios_pa[i])));

	kho_unpreserve_free(kp);
}

void kvm_kho_folios_finish(struct kvm_kho_folios_ser *kp)
{
	unsigned int i;

	if (!kp)
		return;

	for (i = 0; i < kp->nr_folios; i++)
		kho_restore_free(phys_to_virt(kp->folios_pa[i]));

	kho_restore_free(kp);
}

static int cmp_pages(const void *a, const void *b)
{
	const struct page *pa = *(const struct page **)a;
	const struct page *pb = *(const struct page **)b;

	if (pa < pb)
		return -1;
	if (pa > pb)
		return 1;
	return 0;
}

/*
 * Page-pointer accumulator.
 *
 * kho_preserve_folio() cannot be called while holding kvm->mmu_lock: it is a
 * rwlock_t, so the section is atomic, whereas kho_radix_add_key() below it
 * calls might_sleep(), takes a mutex and allocates with GFP_KERNEL.  So the
 * walk runs in two phases -- collect the pages under the lock, preserve them
 * after dropping it.
 *
 * A NULL @pages simply counts, which is how the caller sizes the array.
 */
void kvm_kho_pages_add(struct kvm_kho_pages *acc, struct page *page)
{
	if (!acc->pages) {
		acc->nr++;
		return;
	}

	if (acc->nr >= acc->capacity) {
		acc->overflow = true;
		return;
	}

	acc->pages[acc->nr++] = page;
}

int kvm_kho_preserve_vm_pages(struct kvm *kvm, struct kvm_luo_ser *ser,
			      int (*collect)(struct kvm *kvm,
					     struct kvm_kho_pages *acc))
{
	struct kvm_kho_pages acc = {};
	struct kvm_kho_folios_ser *kp;
	unsigned long i, unique_nr = 0;
	int ret = 0, attempt;

	/*
	 * Size the array, then fill it.  The guest can fault in new page
	 * tables between the two passes, so re-check for overflow and retry
	 * with a larger array; the slack makes repeated growth unlikely.
	 */
	for (attempt = 0; attempt < 5; attempt++) {
		write_lock(&kvm->mmu_lock);
		acc.nr = 0;
		acc.overflow = false;
		ret = collect(kvm, &acc);
		write_unlock(&kvm->mmu_lock);

		if (ret)
			goto out;

		if (acc.pages && !acc.overflow)
			break;

		acc.capacity = acc.nr + (acc.nr >> 2) + 16;
		kvfree(acc.pages);
		acc.pages = kvmalloc_array(acc.capacity, sizeof(*acc.pages),
					   GFP_KERNEL);
		if (!acc.pages)
			return -ENOMEM;
	}

	if (acc.overflow) {
		ret = -EAGAIN;
		goto out;
	}

	if (!acc.nr)
		goto out;

	sort(acc.pages, acc.nr, sizeof(*acc.pages), cmp_pages, NULL);
	for (i = 0; i < acc.nr; i++) {
		if (i == 0 || acc.pages[i] != acc.pages[i - 1])
			acc.pages[unique_nr++] = acc.pages[i];
	}
	acc.nr = unique_nr;

	kp = kvm_kho_folios_alloc(acc.nr);
	if (IS_ERR(kp)) {
		ret = PTR_ERR(kp);
		goto out;
	}

	for (i = 0; i < acc.nr; i++) {
		ret = kho_preserve_folio(page_folio(acc.pages[i]));
		if (ret) {
			/*
			 * Undo the partial preservation: leaving pages marked
			 * would pin them in the incoming kernel forever with
			 * nothing owning them.
			 */
			while (i--)
				kho_unpreserve_folio(page_folio(acc.pages[i]));
			kho_unpreserve_free(kp);
			goto out;
		}
		kp->folios_pa[i] = page_to_phys(acc.pages[i]);
	}

	kp->nr_folios = acc.nr;
	kvm->kho_folios = kp;
	if (ser)
		KHOSER_STORE_PTR(ser->kho_folios, kp);

out:
	kvfree(acc.pages);
	return ret;
}

/**
 * kvm_caretaker_vcpu_is_attached - Check whether a vCPU has attached back to host KVM
 * @vcpu: Target KVM vCPU.
 *
 * Return: %true if @vcpu is owned by host KVM, %false if still owned by
 *         Caretaker or in the middle of re-attaching.
 */
bool kvm_caretaker_vcpu_is_attached(struct kvm_vcpu *vcpu)
{
	return !READ_ONCE(vcpu->caretaker.owned_by_caretaker);
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
int kvm_caretaker_init_common_vcpu(struct kvm_caretaker_vcpu *cvcpu,
				   struct kvm_caretaker_cb_ser *cb,
				   struct kvm_vcpu *vcpu,
				   void *runtime_va,
				   size_t runtime_size,
				   const struct kvm_caretaker_ops *ops,
				   void *arch_data)
{
	struct oncore_session *sess = oncore_job_session(vcpu->caretaker.job);
	int ret;

	lockdep_assert_held(&vcpu->mutex);

	ret = oncore_session_map_buffer(sess, runtime_va, runtime_size);
	if (ret)
		return ret;

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
	vcpu->caretaker.attached = false;
	WRITE_ONCE(vcpu->caretaker.owned_by_caretaker, true);

	kvm_caretaker_telemetry_init(cvcpu, sess);
	return 0;
}

#define KVM_CARETAKER_ATTACH_TIMEOUT_US		2000000
#define KVM_CARETAKER_ATTACH_STEP_US		10
#define KVM_CARETAKER_ATTACH_KICK_STEPS		100

static atomic_t kvm_caretaker_quarantined_vcpus = ATOMIC_INIT(0);

bool kvm_caretaker_has_quarantined_vcpu(void)
{
	return atomic_read(&kvm_caretaker_quarantined_vcpus) > 0;
}

static int kvm_caretaker_try_stop(struct kvm_caretaker_cb_ser *cb)
{
	u32 st;

	cpu_preserved_inval(cb);

	/* Pair with smp_mb() / smp_store_release() before STOPPED / FAILED */
	st = smp_load_acquire(&cb->state);
	if (st == KVM_CARETAKER_STOPPED)
		return 1;
	if (st == KVM_CARETAKER_FAILED)
		return -EIO;

	if (cmpxchg(&cb->state, KVM_CARETAKER_PAUSED,
		    KVM_CARETAKER_STOPPED) == KVM_CARETAKER_PAUSED) {
		cpu_preserved_clean(cb);
		return 1;
	}

	if (cmpxchg(&cb->state, KVM_CARETAKER_RUNNING,
		    KVM_CARETAKER_STOPPING) == KVM_CARETAKER_RUNNING)
		cpu_preserved_clean(cb);

	return 0;
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
 * Return: 0 on success, -EIO if the vCPU entered %KVM_CARETAKER_FAILED, or
 *         -ETIMEDOUT if the preserved CPU failed to stop.
 */
int kvm_caretaker_wait_for_attach(struct kvm_caretaker_cb_ser *cb, int pcpu)
{
	int i, ret;

	if (!cb)
		return 0;

	ret = kvm_caretaker_try_stop(cb);
	if (ret > 0)
		return 0;
	if (ret < 0) {
		pr_err("kvm: caretaker vCPU %u failed in preserved runtime\n",
		       cb->vcpu_id);
		return ret;
	}

	/*
	 * Slow path: the vCPU is actively executing a quantum on a preserved
	 * physical CPU (%KVM_CARETAKER_RUNNING).  kvm_caretaker_try_stop() has
	 * transitioned it to %KVM_CARETAKER_STOPPING; send an IPI kick to force
	 * a VM exit and spin until the preserved CPU finishes detach_serialize()
	 * and publishes %KVM_CARETAKER_STOPPED.
	 *
	 * Never force %KVM_CARETAKER_STOPPED from the host when @pcpu is no
	 * longer marked preserved or on timeout: under M:N scheduling another
	 * preserved CPU may have stolen the job, or the CPU may still be live.
	 */
	smp_mb();

	for (i = 0; i < KVM_CARETAKER_ATTACH_TIMEOUT_US / KVM_CARETAKER_ATTACH_STEP_US; i++) {
		if (i % KVM_CARETAKER_ATTACH_KICK_STEPS == 0) {
			int cur_pcpu = READ_ONCE(cb->pcpu_id);

			if (cur_pcpu >= 0 && cpu_is_preserved(cur_pcpu))
				arch_cpu_preserved_kick(cur_pcpu);
			if (pcpu >= 0 && pcpu != cur_pcpu &&
			    cpu_is_preserved(pcpu))
				arch_cpu_preserved_kick(pcpu);
		}
		ret = kvm_caretaker_try_stop(cb);
		if (ret > 0)
			return 0;
		if (ret < 0) {
			pr_err("kvm: caretaker vCPU %u failed in preserved runtime\n",
			       cb->vcpu_id);
			return ret;
		}
		udelay(KVM_CARETAKER_ATTACH_STEP_US);
	}

	WARN_ON_ONCE(1);
	atomic_inc(&kvm_caretaker_quarantined_vcpus);
	pr_warn("kvm: caretaker attach handshake timed out for pCPU %d; quarantining vCPU %u\n",
		pcpu, cb->vcpu_id);
	return -ETIMEDOUT;
}

/**
 * kvm_caretaker_post_attach_vcpu - Finalize host vCPU state after Caretaker attachment
 * @vcpu: KVM vCPU that has just re-attached from Caretaker.
 *
 * Resets @vcpu->mode and @vcpu->cpu under @vcpu->mutex, reports Caretaker
 * execution telemetry to the kernel log and vCPU debugfs snapshot, marks the
 * control block stopped, clears @vcpu->caretaker.cb, and releases Caretaker
 * ownership so host vCPU ioctls may proceed.
 */
void kvm_caretaker_post_attach_vcpu(struct kvm_vcpu *vcpu)
{
	lockdep_assert_held(&vcpu->mutex);

	/* Ensure vCPU mode update is globally visible before clearing cpu */
	smp_store_mb(vcpu->mode, OUTSIDE_GUEST_MODE);
	vcpu->cpu = -1;

	if (vcpu->caretaker.cb) {
		kvm_caretaker_telemetry_report(vcpu, vcpu->caretaker.cb);
		kvm_caretaker_stop(vcpu->caretaker.cb);
		vcpu->caretaker.cb = NULL;
	}

	vcpu->caretaker.attached = true;
	WRITE_ONCE(vcpu->caretaker.owned_by_caretaker, false);
}

/**
 * kvm_caretaker_vcpu_pre_preserve - Submit an On-Core job for a vCPU prior to arch preserve
 * @vcpu:    KVM vCPU being preserved.
 * @session: Active Live Update session.
 * @ser:     Serialized KHO vCPU descriptor to populate.
 *
 * Submits a Caretaker job to @session before kvm_arch_vcpu_luo_preserve() runs.
 * If @session has preserved physical CPUs, assigns the job to the least-loaded
 * preserved CPU and stores it in @vcpu->caretaker.job so the architecture hook
 * allocates and populates a Caretaker runtime page.  If @session has no
 * preserved physical CPUs, returns 0 with @vcpu->caretaker.job left %NULL so
 * the vCPU is preserved in RAM only.
 *
 * Return: 0 on success, or a negative errno on job allocation failure.
 */
int kvm_caretaker_vcpu_pre_preserve(struct kvm_vcpu *vcpu,
				    struct liveupdate_session *session,
				    struct kvm_vcpu_ser *ser)
{
	struct oncore_job *job;

	lockdep_assert_held(&vcpu->mutex);

	/*
	 * Submit with no data: the run callback's argument is the caretaker
	 * control block, which does not exist until the architecture's
	 * kvm_arch_vcpu_luo_preserve() has allocated it.  It is installed with
	 * oncore_job_set_data() from _post_preserve(), before activation.
	 */
	job = oncore_session_submit_job(session, kvm_arch_vcpu_caretaker_run,
					NULL);
	if (IS_ERR(job))
		return PTR_ERR(job);
	if (!job)
		return 0;

	vcpu->caretaker.job = job;

	return 0;
}

/**
 * kvm_caretaker_vcpu_post_preserve - Activate the Caretaker On-Core job after arch preserve
 * @vcpu:     KVM vCPU being preserved.
 * @session:  Active Live Update session.
 * @ser:      Serialized KHO vCPU descriptor.
 * @arch_err: Result of kvm_arch_vcpu_luo_preserve() (non-zero on failure).
 *
 * If @arch_err is non-zero, cancels and frees any job created in
 * kvm_caretaker_vcpu_pre_preserve().  Otherwise, installs @vcpu->caretaker.cb
 * as the job's run argument, flushes the control block to PoC, and activates
 * the job on the session's runqueue so the preserved physical CPU begins
 * executing the vCPU.
 *
 * Return: 0 on success, or @arch_err / negative errno on failure.
 */
int kvm_caretaker_vcpu_post_preserve(struct kvm_vcpu *vcpu,
				     struct liveupdate_session *session,
				     struct kvm_vcpu_ser *ser,
				     int arch_err)
{
	struct kvm_caretaker_cb_ser *cb = vcpu->caretaker.cb;
	struct oncore_job *job = vcpu->caretaker.job;
	int err;

	lockdep_assert_held(&vcpu->mutex);

	if (arch_err) {
		if (job)
			oncore_session_cancel_job(session, job);
		vcpu->caretaker.job = NULL;
		vcpu->caretaker.cb = NULL;
		WRITE_ONCE(vcpu->caretaker.owned_by_caretaker, false);
		return arch_err;
	}

	if (!KHOSER_LOAD_PTR(ser->cb) || !cb) {
		WRITE_ONCE(vcpu->caretaker.owned_by_caretaker, false);
		return 0;
	}

	oncore_job_set_data(job, cb);

	kvm_caretaker_pause(cb);
	cpu_preserved_clean(cb);

	err = oncore_session_activate_job(session, job);
	if (err) {
		oncore_session_cancel_job(session, job);
		vcpu->caretaker.job = NULL;
		kvm_caretaker_stop(cb);
		vcpu->caretaker.cb = NULL;
		WRITE_ONCE(vcpu->caretaker.owned_by_caretaker, false);
		return err;
	}

	return 0;
}

/**
 * kvm_caretaker_vm_pre_retrieve - Stop Caretaker execution before retrieving VM state
 *
 * Detaches preserved physical CPU workloads before the incoming kernel creates
 * the restored KVM VM instance so Caretaker execution stops immediately when
 * userspace begins reclaiming the VM session.
 */
void kvm_caretaker_vm_pre_retrieve(void)
{
	int cpu;

	for_each_cpu(cpu, cpu_get_preserved_mask())
		cpu_preserved_detach_workload(cpu);
}

/**
 * kvm_caretaker_vcpu_pre_retrieve - Stop Caretaker execution before retrieving vCPU state
 * @vcpu: Incoming KVM vCPU being restored.
 * @ser:  Serialized KHO vCPU descriptor.
 *
 * Resolves @ser->cb and invokes kvm_arch_vcpu_luo_pre_retrieve_caretaker() so
 * the preserved physical CPU stops guest execution and serializes its latest
 * state into @ser->arch_state before kvm_arch_vcpu_luo_retrieve() reads it.
 *
 * Return: 0 on success, or a negative errno if stopping Caretaker failed.
 */
int kvm_caretaker_vcpu_pre_retrieve(struct kvm_vcpu *vcpu,
				    struct kvm_vcpu_ser *ser)
{
	lockdep_assert_held(&vcpu->mutex);

	if (KHOSER_LOAD_PTR(ser->cb)) {
		vcpu->caretaker.cb = KHOSER_LOAD_PTR(ser->cb);
		vcpu->caretaker.attached = false;
		WRITE_ONCE(vcpu->caretaker.owned_by_caretaker, true);
	}

	return kvm_arch_vcpu_luo_pre_retrieve_caretaker(vcpu, ser);
}

/**
 * kvm_caretaker_vcpu_retrieve - Complete Caretaker hardware attachment during vCPU retrieve
 * @vcpu: Incoming KVM vCPU being restored.
 * @ser:  Serialized KHO vCPU descriptor.
 *
 * Invokes kvm_arch_vcpu_luo_attach_caretaker() after architectural register
 * state has been restored into @vcpu.
 */
void kvm_caretaker_vcpu_retrieve(struct kvm_vcpu *vcpu,
				 struct kvm_vcpu_ser *ser)
{
	lockdep_assert_held(&vcpu->mutex);

	kvm_arch_vcpu_luo_attach_caretaker(vcpu, ser);
}

/**
 * kvm_caretaker_vcpu_unpreserve - Roll back Caretaker execution on live update cancellation
 * @vcpu:    Outgoing KVM vCPU being unpreserved.
 * @session: Live Update session being cancelled.
 * @ser:     Serialized KHO vCPU descriptor.
 *
 * Stops all Caretaker vCPUs of the VM on preserved physical CPUs, synchronizes
 * any guest state updates back into the outgoing @vcpu, cancels the On-Core
 * job, and frees KHO telemetry buffers.
 *
 * Return: 0 on success, or a negative errno if the vCPU could not be stopped.
 */
int kvm_caretaker_vcpu_unpreserve(struct kvm_vcpu *vcpu,
				  struct liveupdate_session *session,
				  struct kvm_vcpu_ser *ser)
{
	struct kvm_vcpu *other;
	unsigned long idx;
	int err = 0;

	if (vcpu)
		lockdep_assert_held(&vcpu->mutex);

	if (vcpu && vcpu->kvm) {
		kvm_for_each_vcpu(idx, other, vcpu->kvm) {
			if (other->caretaker.cb &&
			    !kvm_caretaker_is_stopped(other->caretaker.cb)) {
				int ret;

				ret = kvm_caretaker_wait_for_attach(
					other->caretaker.cb,
					other->caretaker.cb->pcpu_id);
				if (ret && !err)
					err = ret;
			}
		}
	}

	if (KHOSER_LOAD_PTR(ser->cb)) {
		int ret = kvm_arch_vcpu_luo_pre_retrieve_caretaker(vcpu, ser);

		if (ret && !err)
			err = ret;
		if (err) {
			if (vcpu && vcpu->kvm)
				kvm_vm_bugged(vcpu->kvm);
			return err;
		}
		err = kvm_arch_vcpu_luo_retrieve(vcpu, ser);
		if (err) {
			if (vcpu && vcpu->kvm)
				kvm_vm_bugged(vcpu->kvm);
			return err;
		}
		kvm_arch_vcpu_luo_attach_caretaker(vcpu, ser);
	}

	if (vcpu && vcpu->caretaker.job) {
		err = oncore_session_cancel_job(session, vcpu->caretaker.job);
		if (err) {
			if (vcpu->kvm)
				kvm_vm_bugged(vcpu->kvm);
			return err;
		}
		vcpu->caretaker.job = NULL;
	}

	if (KHOSER_LOAD_PTR(ser->cb))
		kvm_caretaker_telemetry_free(ser, false);
	if (vcpu) {
		vcpu->caretaker.cb = NULL;
		WRITE_ONCE(vcpu->caretaker.owned_by_caretaker, false);
	}
	return 0;
}

/**
 * kvm_caretaker_vcpu_finish - Release Caretaker KHO resources after live update completion
 * @vcpu:    Incoming KVM vCPU (or %NULL on retrieve failure cleanup).
 * @session: Completed Live Update session.
 * @ser:     Serialized KHO vCPU descriptor.
 *
 * Ensures the Caretaker vCPU has detached and frees KHO-preserved telemetry
 * buffers in the incoming kernel.
 *
 * Return: 0 on success, or a negative errno if the vCPU could not be stopped.
 */
int kvm_caretaker_vcpu_finish(struct kvm_vcpu *vcpu,
			      struct liveupdate_session *session,
			      struct kvm_vcpu_ser *ser)
{
	int err = 0;

	if (vcpu)
		lockdep_assert_held(&vcpu->mutex);

	if (KHOSER_LOAD_PTR(ser->cb)) {
		if (!vcpu || !vcpu->caretaker.attached) {
			err = kvm_arch_vcpu_luo_pre_retrieve_caretaker(vcpu, ser);
			if (err) {
				if (vcpu && vcpu->kvm)
					kvm_vm_bugged(vcpu->kvm);
				return err;
			}
		}
		kvm_caretaker_telemetry_free(ser, true);
	}

	if (vcpu)
		vcpu->caretaker.cb = NULL;
	return 0;
}

