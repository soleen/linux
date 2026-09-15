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
struct kvm_vcpu_luo_ser;
struct liveupdate_session;

/* Attach handshake timeout and polling interval */
#define KVM_CARETAKER_ATTACH_TIMEOUT_US	2000000
#define KVM_CARETAKER_ATTACH_STEP_US	10

/* Normalized VM exit classification */
enum kvm_caretaker_exit_type {
	KVM_CARETAKER_EXIT_UNKNOWN = 0,
	KVM_CARETAKER_EXIT_IDLE,          /* HLT, PAUSE, WFI, WFE */
	KVM_CARETAKER_EXIT_CONSOLE,       /* Architecture console emulation */
	KVM_CARETAKER_EXIT_PREEMPT_TIMER, /* Scheduling timer expired */
	KVM_CARETAKER_EXIT_CROSS_VCPU,    /* Cross-vCPU notification / IPI */
	KVM_CARETAKER_EXIT_INSN_STEP,     /* Step past instruction */
	KVM_CARETAKER_EXIT_ARCH,          /* Handled by arch hook */
	KVM_CARETAKER_EXIT_UNHANDLED,     /* Yields quantum */
};

/* Normalized cross-architecture VM exit representation */
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

/* Common operations table registered by architecture adapters */
struct kvm_caretaker_ops {
	int (*enter_guest)(void *vcpu_data);
	void (*decode_exit)(void *vcpu_data, struct kvm_caretaker_exit *exit);
	bool (*handle_arch_exit)(void *vcpu_data, struct kvm_caretaker_exit *exit);
	void (*advance_rip)(void *vcpu_data, u64 next_rip);
	void (*arm_timer)(void *vcpu_data, u64 deadline_ticks);
	void (*disarm_timer)(void *vcpu_data);
	void (*pre_run)(void *vcpu_data);
	void (*post_run)(void *vcpu_data);
	void (*sync_vcpu)(struct kvm_vcpu *vcpu, void *vcpu_data);
};

/* Common per-vCPU Caretaker descriptor embedded in arch pages */
struct kvm_caretaker_vcpu {
	struct kvm_caretaker_cb cb;
	u32 running;
	u32 pad0;
	u64 abi_reserved[27];
	u64 total_exits;
	u64 deadline_ticks;
	u64 last_exit_rip;
	const struct kvm_caretaker_ops *ops;
	void *arch_data;
};

#ifdef CONFIG_KVM_CARETAKER

#include <linux/cpu_preserve.h>
#include <linux/oncore.h>

#define __caretaker_text __cpu_preserved_text
#define __caretaker_data __cpu_preserved_data

/**
 * struct kvm_vcpu_caretaker - Host-side Caretaker state for one vCPU
 * @cb: Pointer to the KHO-preserved Caretaker control block when preserved,
 *      or NULL when normal/unpreserved.
 * @job: On-Core job this vCPU is scheduled as, or NULL.
 */
struct kvm_vcpu_caretaker {
	struct kvm_caretaker_cb	*cb;
	struct oncore_job	*job;
};

static inline bool kvm_caretaker_is_attached(const struct kvm_caretaker_cb *cb)
{
	return !cb || READ_ONCE(cb->attachment_state) != KVM_CARETAKER_DETACHED;
}

static inline void kvm_caretaker_detach(struct kvm_caretaker_cb *cb)
{
	/* Pairs with smp_load_acquire() in caretaker loop */
	smp_store_release(&cb->attachment_state, KVM_CARETAKER_DETACHED);
}

static inline void kvm_caretaker_attach(struct kvm_caretaker_cb *cb)
{
	/* Pairs with smp_load_acquire() in caretaker loop */
	smp_store_release(&cb->attachment_state, KVM_CARETAKER_ATTACHED);
}

bool kvm_caretaker_vcpu_is_attached(struct kvm_vcpu *vcpu);

/**
 * kvm_caretaker_init_common_vcpu - Initialize common Caretaker vCPU state
 * @cvcpu: Pointer to common Caretaker vCPU descriptor
 * @vcpu: Target KVM vCPU structure
 * @runtime_va: Virtual address of preserved runtime memory page
 * @runtime_size: Size in bytes of preserved runtime memory page
 * @ops: Architecture operations table for guest entry, exits, and timers
 * @arch_data: Architecture-specific context pointer passed to ops callbacks
 */
void kvm_caretaker_init_common_vcpu(struct kvm_caretaker_vcpu *cvcpu,
				    struct kvm_vcpu *vcpu,
				    void *runtime_va,
				    size_t runtime_size,
				    const struct kvm_caretaker_ops *ops,
				    void *arch_data);

/**
 * kvm_caretaker_should_exit - Check if Caretaker execution loop should exit
 * @cvcpu: Pointer to common Caretaker vCPU descriptor
 *
 * Return: true if quantum deadline reached or attach signaled, false otherwise.
 */
bool kvm_caretaker_should_exit(struct kvm_caretaker_vcpu *cvcpu);

/**
 * kvm_caretaker_vcpu_run - Common hardware vCPU execution loop for Caretaker
 * @cvcpu: Pointer to common Caretaker vCPU descriptor
 * @deadline_ticks: Architecture timer deadline for scheduling quantum
 *
 * Loops entering guest context and dispatching exits until the quantum expires,
 * guest enters idle, incoming kernel signals attach, or unhandled exit occurs.
 *
 * Context: Preserved physical CPU with interrupts disabled.
 * Return: enum oncore_exit_reason indicating exit reason.
 */
enum oncore_exit_reason
kvm_caretaker_vcpu_run(struct kvm_caretaker_vcpu *cvcpu, u64 deadline_ticks);

/**
 * kvm_caretaker_wait_for_attach - Wait for incoming kernel to attach vCPU
 * @cb: Caretaker control block
 * @pcpu: Physical CPU ID where vCPU is running
 * @arch_kick: Optional architecture-specific kick callback to wake vCPU
 *
 * Return: 0 on success, negative errno on error.
 */
int kvm_caretaker_wait_for_attach(struct kvm_caretaker_cb *cb, int pcpu,
				  void (*arch_kick)(int pcpu));

/**
 * kvm_caretaker_post_attach_vcpu - Complete vCPU adoption after Caretaker handoff
 * @vcpu: Incoming kernel vCPU structure
 * @cvcpu: Common Caretaker vCPU descriptor from preserved memory
 */
void kvm_caretaker_post_attach_vcpu(struct kvm_vcpu *vcpu,
				    struct kvm_caretaker_vcpu *cvcpu);

/**
 * kvm_arch_vcpu_caretaker_run - Architecture entry point for Caretaker vCPU run
 * @data: Architecture-specific runtime descriptor (e.g. struct caretaker_vmx_page,
 *        struct caretaker_svm_page, or struct kvm_vcpu)
 * @deadline_ticks: Architecture timer deadline (TSC on x86, CNTVCT on ARM64)
 *                  indicating when the scheduling quantum expires
 *
 * Invoked by the generic Caretaker scheduler loop on the preserved physical CPU
 * during the kexec handover window. Executes the guest vCPU, handles early console
 * emulation and basic exits directly on-core, and returns to the scheduler when the
 * quantum expires, idle is reached, an attach is signaled by the incoming kernel, or
 * an unhandled exit requires yielding.
 *
 * Context: Runs in preserved CPU context with local interrupts disabled.
 * Return: enum oncore_exit_reason indicating exit cause.
 */
enum oncore_exit_reason
kvm_arch_vcpu_caretaker_run(void *data, u64 deadline_ticks);

/**
 * kvm_arch_vcpu_luo_pre_retrieve_caretaker - Signal Caretaker vCPU to detach
 * @vcpu: Incoming or cancelled-handover vCPU structure
 * @ser: Serialized KHO vCPU metadata
 *
 * Signals the preserved physical CPU running this vCPU in Caretaker to exit
 * guest mode, serialize live guest state into @ser->arch_state, and park in
 * %KVM_CARETAKER_ATTACHED.  Must run before kvm_arch_vcpu_luo_retrieve() reads
 * @ser->arch_state.
 */
void kvm_arch_vcpu_luo_pre_retrieve_caretaker(struct kvm_vcpu *vcpu,
					      struct kvm_vcpu_luo_ser *ser);

/**
 * kvm_arch_vcpu_luo_attach_caretaker - Complete hardware attachment after retrieve
 * @vcpu: Incoming kernel vCPU structure being restored
 * @ser: Serialized KHO vCPU metadata including the Caretaker control block PA
 *
 * Runs after kvm_arch_vcpu_luo_retrieve() has restored @ser->arch_state into
 * @vcpu; synchronizes arch-specific hardware state (VMCS/VMCB/VGIC) from the
 * ABI prefix in include/linux/kho/abi/ headers.
 */
void kvm_arch_vcpu_luo_attach_caretaker(struct kvm_vcpu *vcpu,
					struct kvm_vcpu_luo_ser *ser);

/*
 * Preserve is split in two so that the generic Caretaker layer never calls the
 * architecture hook itself: virt/kvm/kvm_luo.c sequences
 *
 *	pre_preserve() -> kvm_arch_vcpu_luo_preserve() -> post_preserve()
 *
 * _pre_preserve() reserves the on-core job and decides whether this vCPU gets
 * a preserved pCPU (setting KVM_VCPU_LUO_FLAG_CARETAKER if so), which the arch
 * hook needs to know before it allocates the control block.  _post_preserve()
 * takes the arch hook's return value, unwinds the job on failure, and
 * otherwise publishes and activates it.
 *
 * Besides removing the layering inversion, this is what lets the !CONFIG stubs
 * live in this header: neither half has to name kvm_arch_vcpu_luo_preserve(),
 * which is declared later, in kvm_host.h.
 */
int kvm_caretaker_vcpu_pre_preserve(struct kvm_vcpu *vcpu,
				    struct liveupdate_session *session,
				    struct kvm_vcpu_luo_ser *ser);
int kvm_caretaker_vcpu_post_preserve(struct kvm_vcpu *vcpu,
				     struct liveupdate_session *session,
				     struct kvm_vcpu_luo_ser *ser,
				     int arch_err);
void kvm_caretaker_vcpu_pre_retrieve(struct kvm_vcpu *vcpu,
				     struct kvm_vcpu_luo_ser *ser);
void kvm_caretaker_vcpu_retrieve(struct kvm_vcpu *vcpu,
				 struct kvm_vcpu_luo_ser *ser);
void kvm_caretaker_vcpu_unpreserve(struct kvm_vcpu *vcpu,
				   struct liveupdate_session *session,
				   struct kvm_vcpu_luo_ser *ser);
void kvm_caretaker_vcpu_finish(struct kvm_vcpu *vcpu,
			       struct liveupdate_session *session);

#else /* !CONFIG_KVM_CARETAKER */

#define __caretaker_text
#define __caretaker_data

static inline bool kvm_caretaker_is_attached(const struct kvm_caretaker_cb *cb)
{
	return true;
}

static inline void kvm_caretaker_detach(struct kvm_caretaker_cb *cb) {}
static inline void kvm_caretaker_attach(struct kvm_caretaker_cb *cb) {}

static inline bool kvm_caretaker_vcpu_is_attached(struct kvm_vcpu *vcpu)
{
	return true;
}

static inline int kvm_caretaker_vcpu_pre_preserve(struct kvm_vcpu *vcpu,
						  struct liveupdate_session *session,
						  struct kvm_vcpu_luo_ser *ser)
{
	return 0;
}
static inline int kvm_caretaker_vcpu_post_preserve(struct kvm_vcpu *vcpu,
						   struct liveupdate_session *session,
						   struct kvm_vcpu_luo_ser *ser,
						   int arch_err)
{
	return arch_err;
}

static inline void kvm_caretaker_init_common_vcpu(struct kvm_caretaker_vcpu *cvcpu,
						 struct kvm_vcpu *vcpu,
						 void *runtime_va,
						 size_t runtime_size,
						 const struct kvm_caretaker_ops *ops,
						 void *arch_data) {}
static inline bool kvm_caretaker_should_exit(struct kvm_caretaker_vcpu *cvcpu)
{
	return true;
}
static inline int kvm_caretaker_wait_for_attach(struct kvm_caretaker_cb *cb, int pcpu,
						void (*arch_kick)(int pcpu))
{
	return 0;
}
static inline void kvm_caretaker_post_attach_vcpu(struct kvm_vcpu *vcpu,
						  struct kvm_caretaker_vcpu *cvcpu) {}
static inline void kvm_arch_vcpu_luo_pre_retrieve_caretaker(struct kvm_vcpu *vcpu,
							    struct kvm_vcpu_luo_ser *ser) {}
static inline void kvm_arch_vcpu_luo_attach_caretaker(struct kvm_vcpu *vcpu,
						      struct kvm_vcpu_luo_ser *ser) {}
static inline void kvm_caretaker_vcpu_pre_retrieve(struct kvm_vcpu *vcpu,
						   struct kvm_vcpu_luo_ser *ser) {}
static inline void kvm_caretaker_vcpu_retrieve(struct kvm_vcpu *vcpu,
					       struct kvm_vcpu_luo_ser *ser) {}
static inline void kvm_caretaker_vcpu_unpreserve(struct kvm_vcpu *vcpu,
						 struct liveupdate_session *session,
						 struct kvm_vcpu_luo_ser *ser) {}
static inline void kvm_caretaker_vcpu_finish(struct kvm_vcpu *vcpu,
					     struct liveupdate_session *session) {}

#endif /* CONFIG_KVM_CARETAKER */

#endif /* __LINUX_KVM_CARETAKER_H */
