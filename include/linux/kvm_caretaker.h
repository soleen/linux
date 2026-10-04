/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * Header for common KVM Caretaker framework across architectures.
 */
#ifndef __LINUX_KVM_CARETAKER_H
#define __LINUX_KVM_CARETAKER_H

#include <linux/types.h>
#include <linux/kho/abi/kvm.h>

struct kvm;
struct kvm_luo_ser;
struct kvm_vcpu;
struct kvm_vcpu_ser;
struct liveupdate_session;
struct page;

enum oncore_exit_reason;
struct kvm_caretaker_vcpu;

struct kvm_kho_pages {
	struct page **pages;
	unsigned long nr;
	unsigned long capacity;
	bool overflow;
};

/**
 * struct kvm_caretaker_ops - Architecture operations vector for Caretaker vCPU execution
 * @vcpu_run:     Perform hardware guest entry and fastpath VM-exit handling.
 *                Returns %true to immediately re-enter the guest, or %false
 *                to leave the guest loop (updating *@reason if needed).
 * @arm_timer:    Program hardware preemption timer to fire at @deadline_ticks
 *                (or disarm if @deadline_ticks is 0 or %U64_MAX).
 * @disarm_timer: Disarm the hardware preemption timer after leaving the loop.
 * @pre_run:      Optional per-quantum setup hook invoked before guest entry.
 * @post_run:     Optional per-quantum teardown hook invoked after leaving
 *                the guest loop.
 */
struct kvm_caretaker_ops {
	bool (*vcpu_run)(struct kvm_caretaker_vcpu *cvcpu,
			 enum oncore_exit_reason *reason);
	void (*arm_timer)(void *vcpu_data, u64 deadline_ticks);
	void (*disarm_timer)(void *vcpu_data);
	void (*pre_run)(void *vcpu_data);
	void (*post_run)(void *vcpu_data);
};

/**
 * struct kvm_caretaker_vcpu - Common per-vCPU Caretaker runtime descriptor
 * @cb:        Pointer to KHO-preserved Caretaker control block (&struct kvm_caretaker_cb_ser).
 * @ops:       Architecture operations vector (&struct kvm_caretaker_ops).
 * @arch_data: Architecture-specific runtime context passed to @ops callbacks.
 */
struct kvm_caretaker_vcpu {
	struct kvm_caretaker_cb_ser *cb;
	const struct kvm_caretaker_ops *ops;
	void *arch_data;
};

#ifdef CONFIG_KVM_CARETAKER

struct kvm_kho_folios_ser *kvm_kho_folios_alloc(unsigned int max_folios);
void kvm_kho_folios_unpreserve(struct kvm_kho_folios_ser *folios);
void kvm_kho_folios_finish(struct kvm_kho_folios_ser *folios);
void kvm_kho_pages_add(struct kvm_kho_pages *acc, struct page *page);
int kvm_kho_preserve_vm_pages(struct kvm *kvm, struct kvm_luo_ser *ser,
			      int (*collect)(struct kvm *kvm,
					     struct kvm_kho_pages *acc));

#include <linux/cpu_preserve.h>
#include <linux/oncore.h>

struct dentry;
struct oncore_session;

/**
 * struct kvm_vcpu_caretaker - Host-side Caretaker state embedded in struct kvm_vcpu
 * @cb:                 Pointer to the KHO-preserved Caretaker control block
 *                      while preserved, or %NULL when executing normally under
 *                      KVM.
 * @job:                On-Core scheduler job handle for this vCPU, or %NULL.
 * @owned_by_caretaker: True while Caretaker owns the vCPU; cleared under
 *                      @vcpu->mutex only after state restore and sync_vcpu
 *                      complete.
 * @attached:           True once the incoming vCPU has completed the Caretaker
 *                      attach handshake during retrieve, so session finish
 *                      does not re-run it.
 */
struct kvm_vcpu_caretaker {
	struct kvm_caretaker_cb_ser		*cb;
	struct oncore_job			*job;
	bool					owned_by_caretaker;
	bool					attached;
};

/**
 * kvm_caretaker_is_stopped - Check whether a Caretaker control block is stopped
 * @cb: Caretaker control block (may be %NULL).
 *
 * Return: %true if @cb is %NULL or in a terminal state (%KVM_CARETAKER_STOPPED
 *         or %KVM_CARETAKER_FAILED), %false otherwise.
 */
static inline bool kvm_caretaker_is_stopped(const struct kvm_caretaker_cb_ser *cb)
{
	u32 st;

	if (!cb)
		return true;
	st = smp_load_acquire(&cb->state);
	return st == KVM_CARETAKER_STOPPED || st == KVM_CARETAKER_FAILED;
}

/**
 * kvm_caretaker_pause - Transition a Caretaker control block to PAUSED state
 * @cb: Caretaker control block.
 *
 * Publishes %KVM_CARETAKER_PAUSED with release semantics so a preserved CPU
 * can claim the vCPU for on-core execution.
 */
static inline void kvm_caretaker_pause(struct kvm_caretaker_cb_ser *cb)
{
	/* Pairs with smp_load_acquire() in caretaker loop */
	smp_store_release(&cb->state, KVM_CARETAKER_PAUSED);
}

/**
 * kvm_caretaker_stop - Transition a Caretaker control block to STOPPED state
 * @cb: Caretaker control block.
 *
 * Publishes %KVM_CARETAKER_STOPPED with release semantics once the vCPU has
 * detached from Caretaker execution.
 */
static inline void kvm_caretaker_stop(struct kvm_caretaker_cb_ser *cb)
{
	/* Pairs with smp_load_acquire() in caretaker loop */
	smp_store_release(&cb->state, KVM_CARETAKER_STOPPED);
}

bool kvm_caretaker_vcpu_is_attached(struct kvm_vcpu *vcpu);
int kvm_caretaker_init_common_vcpu(struct kvm_caretaker_vcpu *cvcpu,
				   struct kvm_caretaker_cb_ser *cb,
				   struct kvm_vcpu *vcpu,
				   void *runtime_va,
				   size_t runtime_size,
				   const struct kvm_caretaker_ops *ops,
				   void *arch_data);
int kvm_caretaker_wait_for_attach(struct kvm_caretaker_cb_ser *cb, int pcpu);
bool cpu_preserved_sym(kvm_caretaker_should_exit)(struct kvm_caretaker_vcpu *cvcpu);
enum oncore_exit_reason
cpu_preserved_sym(kvm_caretaker_vcpu_run)(struct kvm_caretaker_vcpu *cvcpu, u64 deadline_ticks);
void kvm_caretaker_post_attach_vcpu(struct kvm_vcpu *vcpu);

/**
 * kvm_arch_vcpu_caretaker_run - Architecture entry point for Caretaker vCPU run
 * @data:           Pointer to KHO-preserved Caretaker control block
 *                  (&struct kvm_caretaker_cb_ser) embedded in the architecture
 *                  runtime page.
 * @deadline_ticks: Hardware counter deadline (TSC on x86, CNTPCT on arm64) at
 *                  which the current scheduling quantum expires, or %U64_MAX if
 *                  unbounded.
 *
 * Invoked by the On-Core scheduler loop on a preserved physical CPU during the
 * kexec handover window.  Atomically transitions the vCPU from
 * %KVM_CARETAKER_PAUSED to %KVM_CARETAKER_RUNNING, switches to Caretaker host
 * state and isolated page tables, invokes kvm_caretaker_vcpu_run(), and
 * serializes updated guest registers back to KHO memory upon exit.
 *
 * Context: Runs in .cpu_preserved.text with local interrupts disabled.
 * Return: &enum oncore_exit_reason indicating why the vCPU yielded the core.
 */
enum oncore_exit_reason
cpu_preserved_sym(kvm_arch_vcpu_caretaker_run)(void *data, u64 deadline_ticks);

#ifndef __CPU_PRESERVED_RUNTIME__
#define kvm_caretaker_should_exit	__cpu_preserved_kvm_caretaker_should_exit
#define kvm_caretaker_vcpu_run		__cpu_preserved_kvm_caretaker_vcpu_run
#define kvm_arch_vcpu_caretaker_run	__cpu_preserved_kvm_arch_vcpu_caretaker_run
#endif

/**
 * kvm_arch_vcpu_luo_pre_retrieve_caretaker - Signal Caretaker vCPU to stop and serialize
 * @vcpu: Incoming or cancelled-handover KVM vCPU structure.
 * @ser:  Serialized KHO vCPU metadata.
 *
 * Signals the preserved physical CPU executing this vCPU in Caretaker to exit
 * guest mode, serialize live guest hardware state into @ser->arch_state, and
 * transition to %KVM_CARETAKER_STOPPED.  Must run before
 * kvm_arch_vcpu_luo_retrieve() reads @ser->arch_state.
 *
 * Return: 0 on success, or negative errno if the preserved CPU failed to stop.
 */
int kvm_arch_vcpu_luo_pre_retrieve_caretaker(struct kvm_vcpu *vcpu,
					     struct kvm_vcpu_ser *ser);

/**
 * kvm_arch_vcpu_luo_attach_caretaker - Complete architecture vCPU attachment after retrieve
 * @vcpu: Incoming kernel vCPU structure being restored.
 * @ser:  Serialized KHO vCPU metadata containing the Caretaker control block PA.
 *
 * Runs after kvm_arch_vcpu_luo_retrieve() has restored @ser->arch_state into
 * @vcpu; synchronizes architecture-specific hardware state (VMCS/VMCB/VGIC and
 * emulated UART/timer state) from the preserved Caretaker page and completes
 * attachment via kvm_caretaker_post_attach_vcpu().
 */
void kvm_arch_vcpu_luo_attach_caretaker(struct kvm_vcpu *vcpu,
					struct kvm_vcpu_ser *ser);

void kvm_caretaker_vm_pre_retrieve(void);
int kvm_caretaker_vcpu_pre_preserve(struct kvm_vcpu *vcpu,
				    struct liveupdate_session *session,
				    struct kvm_vcpu_ser *ser);
int kvm_caretaker_vcpu_post_preserve(struct kvm_vcpu *vcpu,
				     struct liveupdate_session *session,
				     struct kvm_vcpu_ser *ser,
				     int arch_err);
int kvm_caretaker_vcpu_pre_retrieve(struct kvm_vcpu *vcpu,
				    struct kvm_vcpu_ser *ser);
void kvm_caretaker_vcpu_retrieve(struct kvm_vcpu *vcpu,
				 struct kvm_vcpu_ser *ser);
int kvm_caretaker_vcpu_unpreserve(struct kvm_vcpu *vcpu,
				  struct liveupdate_session *session,
				  struct kvm_vcpu_ser *ser);
int kvm_caretaker_vcpu_finish(struct kvm_vcpu *vcpu,
			      struct liveupdate_session *session,
			      struct kvm_vcpu_ser *ser);

static inline void kvm_caretaker_telemetry_init(struct kvm_caretaker_vcpu *cvcpu,
						struct oncore_session *sess) {}

static inline void kvm_caretaker_telemetry_report(struct kvm_vcpu *vcpu,
						  struct kvm_caretaker_cb_ser *cb) {}

static inline void kvm_caretaker_telemetry_free(struct kvm_vcpu_ser *ser,
						bool is_incoming) {}

#else /* !CONFIG_KVM_CARETAKER */

static inline void kvm_kho_folios_unpreserve(struct kvm_kho_folios_ser *folios) {}
static inline void kvm_kho_folios_finish(struct kvm_kho_folios_ser *folios) {}

static inline bool kvm_caretaker_vcpu_is_attached(struct kvm_vcpu *vcpu)
{
	return true;
}

static inline void kvm_caretaker_vm_pre_retrieve(void) {}

static inline int kvm_caretaker_vcpu_pre_preserve(struct kvm_vcpu *vcpu,
						  struct liveupdate_session *session,
						  struct kvm_vcpu_ser *ser)
{
	return 0;
}

static inline int kvm_caretaker_vcpu_post_preserve(struct kvm_vcpu *vcpu,
						   struct liveupdate_session *session,
						   struct kvm_vcpu_ser *ser,
						   int arch_err)
{
	return arch_err;
}

static inline int kvm_caretaker_vcpu_pre_retrieve(struct kvm_vcpu *vcpu,
						  struct kvm_vcpu_ser *ser)
{
	return 0;
}

static inline void kvm_caretaker_vcpu_retrieve(struct kvm_vcpu *vcpu,
					       struct kvm_vcpu_ser *ser) {}

static inline int kvm_caretaker_vcpu_unpreserve(struct kvm_vcpu *vcpu,
						struct liveupdate_session *session,
						struct kvm_vcpu_ser *ser)
{
	return 0;
}

static inline int kvm_caretaker_vcpu_finish(struct kvm_vcpu *vcpu,
					    struct liveupdate_session *session,
					    struct kvm_vcpu_ser *ser)
{
	return 0;
}

#endif /* CONFIG_KVM_CARETAKER */

#endif /* __LINUX_KVM_CARETAKER_H */
