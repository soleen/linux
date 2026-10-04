// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * Core KVM Caretaker isolated runtime execution loop.
 */

#include <linux/cpu_preserve.h>
#include <linux/kernel.h>
#include <linux/kho/abi/kvm.h>
#include <linux/kvm_caretaker.h>
#include <linux/oncore.h>
#include <linux/string.h>

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
bool kvm_caretaker_should_exit(struct kvm_caretaker_vcpu *cvcpu)
{
	u32 st = smp_load_acquire(&cvcpu->cb->state);

	if (st != KVM_CARETAKER_PAUSED && st != KVM_CARETAKER_RUNNING)
		return true;

	return cpu_preserved_should_exit();
}

/**
 * kvm_caretaker_vcpu_run - Common hardware vCPU execution loop for Caretaker
 * @cvcpu:          Common Caretaker vCPU descriptor.
 * @deadline_ticks: Hardware counter deadline for the current scheduling quantum.
 *
 * Arms the hardware preemption timer for @deadline_ticks and repeatedly enters
 * the guest and handles fastpath VM-exits via @cvcpu->ops->vcpu_run() until
 * the time slice expires, the guest yields on HLT/WFI, the incoming kernel
 * signals attachment, or an unhandled exit stalls the vCPU.
 *
 * Context: Preserved physical CPU (.cpu_preserved.text) with IRQs disabled.
 * Return: &enum oncore_exit_reason indicating why the vCPU left the loop.
 */
enum oncore_exit_reason
kvm_caretaker_vcpu_run(struct kvm_caretaker_vcpu *cvcpu, u64 deadline_ticks)
{
	enum oncore_exit_reason reason = ONCORE_EXIT_QUANTUM_EXPIRED;
	const struct kvm_caretaker_ops *ops = cvcpu->ops;
	void *arch_data = cvcpu->arch_data;

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

		if (!ops->vcpu_run(cvcpu, &reason))
			break;
	}

	if (deadline_ticks != U64_MAX && ops->disarm_timer)
		ops->disarm_timer(arch_data);

	if (ops->post_run)
		ops->post_run(arch_data);

	kvm_caretaker_telemetry_flush(cvcpu);

	if (reason != ONCORE_EXIT_ERROR && kvm_caretaker_should_exit(cvcpu))
		return ONCORE_EXIT_ATTACH_SIGNALED;

	return reason;
}
