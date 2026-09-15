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

struct kvm_vcpu;
struct kvm_vcpu_ser;
struct liveupdate_session;

/**
 * enum kvm_caretaker_exit_type - Normalized cross-architecture VM exit classification
 * @KVM_CARETAKER_EXIT_UNKNOWN:       Unclassified exit; treated as unhandled stall.
 * @KVM_CARETAKER_EXIT_IDLE:          Guest idle instruction (HLT, PAUSE, WFI, WFE).
 * @KVM_CARETAKER_EXIT_CONSOLE:       Early console port I/O or MMIO access.
 * @KVM_CARETAKER_EXIT_PREEMPT_TIMER: Hardware quantum preemption timer expired.
 * @KVM_CARETAKER_EXIT_CROSS_VCPU:    Cross-vCPU notification or IPI (e.g., SGI).
 * @KVM_CARETAKER_EXIT_INSN_STEP:     Instruction emulated by decode; advance RIP/PC.
 * @KVM_CARETAKER_EXIT_ARCH:          Architecture-specific exit routed to @handle_arch_exit.
 * @KVM_CARETAKER_EXIT_UNHANDLED:     Exit requiring full KVM/VMM; stalls the vCPU.
 */
enum kvm_caretaker_exit_type {
	KVM_CARETAKER_EXIT_UNKNOWN = 0,
	KVM_CARETAKER_EXIT_IDLE,
	KVM_CARETAKER_EXIT_CONSOLE,
	KVM_CARETAKER_EXIT_PREEMPT_TIMER,
	KVM_CARETAKER_EXIT_CROSS_VCPU,
	KVM_CARETAKER_EXIT_INSN_STEP,
	KVM_CARETAKER_EXIT_ARCH,
	KVM_CARETAKER_EXIT_UNHANDLED,
};

/**
 * struct kvm_caretaker_exit - Normalized cross-architecture VM exit representation
 * @type:       Normalized exit classification (&enum kvm_caretaker_exit_type).
 * @rip:        Guest instruction pointer (RIP on x86, PC on arm64) at exit.
 * @insn_len:   Length in bytes of the trapping instruction.
 * @raw_reason: Raw hardware exit code (VMX exit reason, SVM exit code, or ESR_EL2).
 * @mmio_io:    Decoded port I/O or MMIO access parameters.
 * @msr:        Decoded x86 MSR read/write parameters.
 * @sgi:        Decoded arm64 GICv3 Software Generated Interrupt parameters.
 */
struct kvm_caretaker_exit {
	enum kvm_caretaker_exit_type type;
	u64 rip;
	u32 insn_len;
	u64 raw_reason;
	union {
		struct {
			u64 addr;
			u64 val;
			u64 *val_ptr;
			u32 size;
			bool is_write;
			bool is_mmio;
		} mmio_io;
		struct {
			u32 msr;
			u64 val;
			bool is_write;
		} msr;
		struct {
			u32 sgi_id;
			u64 target_mask;
		} sgi;
	};
};

struct kvm_caretaker_vcpu;

/**
 * struct kvm_caretaker_ops - Architecture operations vector for Caretaker vCPU execution
 * @enter_guest:      Perform low-level hardware guest entry (VMLAUNCH/VMRESUME,
 *                    VMRUN, or EL2 ERET). Returns 0 on guest exit, or non-zero
 *                    on entry failure.
 * @decode_exit:      Read hardware exit registers and populate @exit.
 * @handle_arch_exit: Emulate an architecture-specific exit (@exit). Returns
 *                    %true if handled (and updates @exit->rip if needed), or
 *                    %false to stall the vCPU until the incoming kernel attaches.
 * @advance_rip:      Write updated @next_rip back into hardware guest state.
 * @arm_timer:        Program hardware preemption timer to fire at @deadline_ticks
 *                    (or disarm if @deadline_ticks is 0 or %U64_MAX).
 * @disarm_timer:     Disarm the hardware preemption timer after leaving the loop.
 * @pre_run:          Optional per-quantum setup hook invoked before guest entry.
 * @post_run:         Optional per-quantum teardown hook invoked after leaving
 *                    the guest loop.
 */
struct kvm_caretaker_ops {
	int (*enter_guest)(void *vcpu_data);
	void (*decode_exit)(void *vcpu_data, struct kvm_caretaker_exit *exit);
	bool (*handle_arch_exit)(void *vcpu_data, struct kvm_caretaker_exit *exit);
	void (*advance_rip)(void *vcpu_data, u64 next_rip);
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

struct kvm_kho_folios_ser *kvm_kho_folios_alloc(unsigned int max_folios);
void kvm_kho_folios_unpreserve(struct kvm_kho_folios_ser *folios);
void kvm_kho_folios_finish(struct kvm_kho_folios_ser *folios);

#ifdef CONFIG_KVM_CARETAKER

#include <linux/cpu_preserve.h>
#include <linux/oncore.h>

#define __caretaker_text __cpu_preserved_text
#define __caretaker_data __cpu_preserved_data

struct dentry;
struct oncore_session;

/**
 * struct kvm_vcpu_caretaker - Host-side Caretaker state embedded in struct kvm_vcpu
 * @cb:             Pointer to the KHO-preserved Caretaker control block while
 *                  preserved, or %NULL when executing normally under KVM.
 * @job:            On-Core scheduler job handle for this vCPU, or %NULL.
 * @last_telemetry: Snapshot of @cb->telemetry captured upon re-attachment.
 */
struct kvm_vcpu_caretaker {
	struct kvm_caretaker_cb_ser		*cb;
	struct oncore_job			*job;
	struct kvm_caretaker_telemetry_ser	last_telemetry;
};

/**
 * kvm_caretaker_is_stopped - Check whether a Caretaker control block is stopped
 * @cb: Caretaker control block (may be %NULL).
 *
 * Return: %true if @cb is %NULL or in state %KVM_CARETAKER_STOPPED, %false otherwise.
 */
static inline bool kvm_caretaker_is_stopped(const struct kvm_caretaker_cb_ser *cb)
{
	return !cb || smp_load_acquire(&cb->state) == KVM_CARETAKER_STOPPED;
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
void kvm_caretaker_init_common_vcpu(struct kvm_caretaker_vcpu *cvcpu,
				    struct kvm_caretaker_cb_ser *cb,
				    struct kvm_vcpu *vcpu,
				    void *runtime_va,
				    size_t runtime_size,
				    const struct kvm_caretaker_ops *ops,
				    void *arch_data);
bool kvm_caretaker_should_exit(struct kvm_caretaker_vcpu *cvcpu);
enum oncore_exit_reason
kvm_caretaker_vcpu_run(struct kvm_caretaker_vcpu *cvcpu, u64 deadline_ticks);
int kvm_caretaker_wait_for_attach(struct kvm_caretaker_cb_ser *cb, int pcpu);
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
 * Context: Runs in __cpu_preserved_text with local interrupts disabled.
 * Return: &enum oncore_exit_reason indicating why the vCPU yielded the core.
 */
enum oncore_exit_reason
kvm_arch_vcpu_caretaker_run(void *data, u64 deadline_ticks);

/**
 * kvm_arch_vcpu_luo_pre_retrieve_caretaker - Signal Caretaker vCPU to stop and serialize
 * @vcpu: Incoming or cancelled-handover KVM vCPU structure.
 * @ser:  Serialized KHO vCPU metadata.
 *
 * Signals the preserved physical CPU executing this vCPU in Caretaker to exit
 * guest mode, serialize live guest hardware state into @ser->arch_state, and
 * transition to %KVM_CARETAKER_STOPPED.  Must run before
 * kvm_arch_vcpu_luo_retrieve() reads @ser->arch_state.
 */
void kvm_arch_vcpu_luo_pre_retrieve_caretaker(struct kvm_vcpu *vcpu,
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
void kvm_caretaker_vcpu_pre_retrieve(struct kvm_vcpu *vcpu,
				     struct kvm_vcpu_ser *ser);
void kvm_caretaker_vcpu_retrieve(struct kvm_vcpu *vcpu,
				 struct kvm_vcpu_ser *ser);
void kvm_caretaker_vcpu_unpreserve(struct kvm_vcpu *vcpu,
				   struct liveupdate_session *session,
				   struct kvm_vcpu_ser *ser);
void kvm_caretaker_vcpu_finish(struct kvm_vcpu *vcpu,
			       struct liveupdate_session *session,
			       struct kvm_vcpu_ser *ser);

#else /* !CONFIG_KVM_CARETAKER */

#define __caretaker_text
#define __caretaker_data

static inline bool kvm_caretaker_is_stopped(const struct kvm_caretaker_cb_ser *cb)
{
	return true;
}

static inline void kvm_caretaker_pause(struct kvm_caretaker_cb_ser *cb) {}

static inline void kvm_caretaker_stop(struct kvm_caretaker_cb_ser *cb) {}

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

static inline void kvm_caretaker_init_common_vcpu(struct kvm_caretaker_vcpu *cvcpu,
						  struct kvm_caretaker_cb_ser *cb,
						 struct kvm_vcpu *vcpu,
						 void *runtime_va,
						 size_t runtime_size,
						 const struct kvm_caretaker_ops *ops,
						 void *arch_data) {}

static inline bool kvm_caretaker_should_exit(struct kvm_caretaker_vcpu *cvcpu)
{
	return true;
}

static inline int kvm_caretaker_wait_for_attach(struct kvm_caretaker_cb_ser *cb, int pcpu,
						void (*arch_kick)(int pcpu))
{
	return 0;
}

static inline void kvm_caretaker_post_attach_vcpu(struct kvm_vcpu *vcpu) {}

static inline void kvm_arch_vcpu_luo_pre_retrieve_caretaker(struct kvm_vcpu *vcpu,
							    struct kvm_vcpu_ser *ser) {}

static inline void kvm_arch_vcpu_luo_attach_caretaker(struct kvm_vcpu *vcpu,
						      struct kvm_vcpu_ser *ser) {}

static inline void kvm_caretaker_vcpu_pre_retrieve(struct kvm_vcpu *vcpu,
						   struct kvm_vcpu_ser *ser) {}

static inline void kvm_caretaker_vcpu_retrieve(struct kvm_vcpu *vcpu,
					       struct kvm_vcpu_ser *ser) {}

static inline void kvm_caretaker_vcpu_unpreserve(struct kvm_vcpu *vcpu,
						 struct liveupdate_session *session,
						 struct kvm_vcpu_ser *ser) {}

static inline void kvm_caretaker_vcpu_finish(struct kvm_vcpu *vcpu,
					     struct liveupdate_session *session,
					     struct kvm_vcpu_ser *ser) {}

#endif /* CONFIG_KVM_CARETAKER */

#endif /* __LINUX_KVM_CARETAKER_H */
