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
#include <linux/caretaker.h>
#include <linux/kho/abi/caretaker.h>

struct kvm_vcpu;
struct kvm_vcpu_luo_ser;

/* Standard PC COM1 UART base */
#define UART_COM1_BASE		0x3f8
#define UART_COM1_END		0x3ff

/* ARM virt PL011 UART MMIO region and registers */
#define ARM_VIRT_PL011_BASE	0x09000000ULL
#define ARM_VIRT_PL011_SIZE	0x1000ULL

#define PL011_UARTDR		0x000	/* Data Register */
#define PL011_UARTFR		0x018	/* Flag Register */

#define PL011_UARTFR_TXFE	(1U << 7)	/* Transmit FIFO empty */
#define PL011_UARTFR_RXFE	(1U << 4)	/* Receive FIFO empty */

/* Common UART register state for guest early printk emulation */
struct caretaker_uart {
	u8 lcr;
	u8 ier;
	u8 mcr;
	u8 scr;
	u8 dll;
	u8 dlm;
};

/* Attach handshake timeout and polling interval */
#define KVM_CARETAKER_ATTACH_TIMEOUT_US	2000000
#define KVM_CARETAKER_ATTACH_STEP_US	10

/* Normalized VM exit classification */
enum kvm_caretaker_exit_type {
	KVM_CARETAKER_EXIT_UNKNOWN = 0,
	KVM_CARETAKER_EXIT_IDLE,          /* HLT, PAUSE, WFI, WFE */
	KVM_CARETAKER_EXIT_CONSOLE,       /* UART 8250, PL011 MMIO */
	KVM_CARETAKER_EXIT_PREEMPT_TIMER, /* APIC timer, CNTHP EL2 */
	KVM_CARETAKER_EXIT_CROSS_VCPU,    /* APIC ICR, ICC_SGI1R */
	KVM_CARETAKER_EXIT_CPUID,         /* x86 CPUID instruction */
	KVM_CARETAKER_EXIT_MSR,           /* x86 MSR read / write */
	KVM_CARETAKER_EXIT_RDTSC,         /* x86 RDTSC / RDTSCP */
	KVM_CARETAKER_EXIT_INSN_STEP,     /* Step past instruction (INVD, WBINVD, etc.) */
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
	struct caretaker_cb cb;
	u32 running;
	u64 total_exits;
	u64 deadline_ticks;
	u64 last_exit_rip;
	struct caretaker_uart uart;
	const struct kvm_caretaker_ops *ops;
	void *arch_data;
};

#ifdef CONFIG_KVM_CARETAKER

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
 * Return: enum caretaker_exit_reason indicating exit reason.
 */
enum caretaker_exit_reason
kvm_caretaker_vcpu_run(struct kvm_caretaker_vcpu *cvcpu, u64 deadline_ticks);

/**
 * kvm_caretaker_wait_for_attach - Wait for incoming kernel to attach vCPU
 * @cb: Caretaker control block
 * @pcpu: Physical CPU ID where vCPU is running
 * @arch_kick: Optional architecture-specific kick callback to wake vCPU
 *
 * Return: 0 on success, negative errno on error.
 */
int kvm_caretaker_wait_for_attach(struct caretaker_cb *cb, int pcpu,
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
 * Return: enum caretaker_exit_reason indicating exit cause.
 */
enum caretaker_exit_reason
kvm_arch_vcpu_caretaker_run(void *data, u64 deadline_ticks);

/**
 * kvm_arch_vcpu_caretaker_data - Retrieve arch Caretaker descriptor for a vCPU
 * @vcpu: Target KVM vCPU structure
 *
 * Resolves the architecture-specific runtime data pointer to be stored in the
 * Caretaker job and passed into kvm_arch_vcpu_caretaker_run().
 *
 * Return: Pointer to arch runtime structure, or NULL / vcpu fallback.
 */
void *kvm_arch_vcpu_caretaker_data(struct kvm_vcpu *vcpu);

/**
 * kvm_arch_vcpu_luo_attach_caretaker - Attach incoming vCPU to Caretaker vCPU
 * @vcpu: Incoming kernel vCPU structure being restored
 * @ser: Serialized KHO vCPU metadata including the Caretaker control block PA
 *
 * Signals the running Caretaker on-core execution engine that the incoming kernel is
 * ready to take over, waits for the Caretaker loop to acknowledge and release guest
 * control, and synchronizes arch-specific hardware state (VMCS/VMCB/GIC) into
 * the newly allocated incoming kernel vCPU structures.
 */
void kvm_arch_vcpu_luo_attach_caretaker(struct kvm_vcpu *vcpu,
					struct kvm_vcpu_luo_ser *ser);

#else /* !CONFIG_KVM_CARETAKER */

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
static inline enum caretaker_exit_reason
kvm_caretaker_vcpu_run(struct kvm_caretaker_vcpu *cvcpu, u64 deadline_ticks)
{
	return CARETAKER_EXIT_ERROR;
}
static inline int kvm_caretaker_wait_for_attach(struct caretaker_cb *cb, int pcpu,
						void (*arch_kick)(int pcpu))
{
	return 0;
}
static inline void kvm_caretaker_post_attach_vcpu(struct kvm_vcpu *vcpu,
						  struct kvm_caretaker_vcpu *cvcpu) {}
static inline enum caretaker_exit_reason
kvm_arch_vcpu_caretaker_run(void *data, u64 deadline_ticks)
{
	return CARETAKER_EXIT_ERROR;
}
static inline void *kvm_arch_vcpu_caretaker_data(struct kvm_vcpu *vcpu)
{
	return vcpu;
}
static inline void kvm_arch_vcpu_luo_attach_caretaker(struct kvm_vcpu *vcpu,
						      struct kvm_vcpu_luo_ser *ser) {}

#endif /* CONFIG_KVM_CARETAKER */


#endif /* __LINUX_KVM_CARETAKER_H */
