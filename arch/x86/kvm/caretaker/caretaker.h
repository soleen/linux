/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * Header for x86 KVM Caretaker common C execution engine and helpers.
 */
#ifndef __ARCH_X86_KVM_CARETAKER_H
#define __ARCH_X86_KVM_CARETAKER_H

/*
 * Size of the caretaker's standalone VMX exit and IST stack in the upper half
 * of struct caretaker_x86_page ([2048..4096)).
 */
#define CXP_STACK_SIZE		2048

#ifndef __ASSEMBLY__

#include <linux/types.h>
#include <linux/oncore.h>
#include <linux/kho/abi/kvm_x86.h>
#include <linux/kvm_caretaker.h>
#include <linux/processor.h>
#include <asm/desc.h>
#include <asm/page.h>

static __always_inline void caretaker_set_tss_desc(struct desc_struct *gdt,
						   unsigned long addr,
						   unsigned int size)
{
	struct ldttss_desc *desc = (struct ldttss_desc *)&gdt[GDT_ENTRY_TSS];

	memset(desc, 0, sizeof(*desc));
	desc->limit0 = (u16)size;
	desc->base0 = (u16)addr;
	desc->base1 = (addr >> 16) & 0xFF;
	desc->type = DESC_TSS;
	desc->p = 1;
	desc->limit1 = (size >> 16) & 0xF;
	desc->base2 = (addr >> 24) & 0xFF;
	desc->base3 = (u32)(addr >> 32);
}

static __always_inline unsigned long caretaker_read_cr0(void)
{
	unsigned long val;

	asm volatile("mov %%cr0, %0" : "=r" (val) : : "memory");
	return val;
}

static __always_inline unsigned long caretaker_read_cr4(void)
{
	unsigned long val;

	asm volatile("mov %%cr4, %0" : "=r" (val) : : "memory");
	return val;
}

struct kvm_vcpu;
struct kvm_x86_ops;

/**
 * struct caretaker_x86_page - Vendor-common x86 Caretaker runtime page (4 KB)
 * @abi:              Cross-kexec KHO ABI header (must remain at offset 0).
 * @vcpu:             Common Caretaker vCPU execution engine descriptor.
 * @kvm_vcpu:         Pointer to preserved vendor vCPU's struct kvm_vcpu.
 * @arch_state:       Pointer to KHO-preserved vCPU architectural state buffer.
 * @apic_regs:        Pointer to KHO-preserved in-kernel LAPIC register page.
 * @host_cr3:         Isolated Caretaker page table root PA loaded during run.
 * @host_xcr0:        Host XCR0 value captured at preserve time for XSAVE/XRSTOR.
 * @kernel_gs_base:   Guest MSR_KERNEL_GS_BASE switched across VMX entry/exit.
 * @save_guest_fpu:   True if guest FPU state can be captured via XSAVE at detach.
 * @gdt:              Per-vCPU preserved GDT containing the active Caretaker TSS.
 * @tss:              Per-vCPU hardware TSS whose SP0 points to @stack. Each
 *                    run copies in the IST pointers of the CPU that runs it.
 * @stack:            2 KB standalone host stack occupying the upper half of the
 *                    page ([2048..4096)).
 *
 * Cross-kexec invariant: Only @abi (and @arch_state) may be dereferenced by the
 * incoming kernel.  All remaining fields are private to the preserved Caretaker
 * text executing on the isolated physical CPU during the kexec handover window.
 */
struct caretaker_x86_page {
	/* KHO ABI prefix (offset 0) and common scheduler descriptor */
	struct kvm_caretaker_arch_ser abi;
	struct kvm_caretaker_vcpu vcpu;
	struct kvm_vcpu *kvm_vcpu;

	struct kvm_vcpu_arch_ser *arch_state;
	void *apic_regs;
	u64 host_cr3;
	u64 host_xcr0;
	u64 kernel_gs_base;
	bool save_guest_fpu;
	bool run_failed;

	/* Isolated host descriptors loaded while Caretaker owns the pCPU */
	struct desc_struct gdt[GDT_ENTRIES] __aligned(16);
	struct x86_hw_tss tss __aligned(16);

	/* Upper half of Page 0 (2 KB): standalone VMX exit and IST stack */
	u8 stack[CXP_STACK_SIZE] __aligned(CXP_STACK_SIZE);
} __aligned(PAGE_SIZE);

static_assert(offsetof(struct caretaker_x86_page, abi) == 0);
static_assert(offsetof(struct caretaker_x86_page, abi.cb) == 0);
static_assert(offsetof(struct caretaker_x86_page, stack) == CXP_STACK_SIZE);
static_assert(sizeof(struct caretaker_x86_page) == PAGE_SIZE);

static __always_inline void *caretaker_pa_to_va(u64 pa)
{
	return phys_to_virt(__sme_clr(pa));
}

static __always_inline struct caretaker_x86_page *
cxp_from_cb(struct kvm_caretaker_cb_ser *cb)
{
	return container_of(cb, struct caretaker_x86_page, abi.cb);
}

int kvm_x86_caretaker_preserve_page(struct kvm_caretaker_arch_ser *abi,
				    struct page *page);
void kvm_x86_caretaker_unpreserve_pages(struct kvm_caretaker_arch_ser *abi);

/* Shared page table, IDT, and GPR helpers */
extern const struct kvm_x86_caretaker_runtime_ops *cpu_preserved_sym(kvm_x86_caretaker_ops);
extern const struct kvm_x86_ops *cpu_preserved_sym(kvm_x86_ops_ptr);
extern struct kvm_caps __cpu_preserved_kvm_caps;
extern u32 __cpu_preserved_kvm_cpu_caps[];
extern bool cpu_preserved_sym(caretaker_x86_has_tsc_deadline);
extern u32 cpu_preserved_sym(caretaker_x86_lapic_timer_period);
extern u32 cpu_preserved_sym(caretaker_x86_tsc_khz);

struct kvm_lapic;

int kvm_x86_caretaker_init_common_page(struct caretaker_x86_page *cxp,
				       struct kvm_vcpu *vcpu,
				       size_t full_page_size);
void kvm_x86_caretaker_init_vcpu(struct kvm_vcpu *dst,
				 const struct kvm_vcpu *src,
				 struct caretaker_x86_page *cxp,
				 struct kvm_lapic *dst_apic);

void kvm_x86_caretaker_sync_vcpu_common(struct kvm_vcpu *vcpu);

void cpu_preserved_sym(kvm_x86_caretaker_arm_timer)(u64 deadline_ticks);
void cpu_preserved_sym(kvm_x86_caretaker_disarm_timer)(void);

#ifndef __CPU_PRESERVED_RUNTIME__
#define kvm_x86_caretaker_ops			__cpu_preserved_kvm_x86_caretaker_ops
#define kvm_x86_ops_ptr				__cpu_preserved_kvm_x86_ops_ptr
#define caretaker_x86_has_tsc_deadline		__cpu_preserved_caretaker_x86_has_tsc_deadline
#define caretaker_x86_lapic_timer_period	__cpu_preserved_caretaker_x86_lapic_timer_period
#define caretaker_x86_tsc_khz			__cpu_preserved_caretaker_x86_tsc_khz
#define kvm_x86_caretaker_arm_timer		__cpu_preserved_kvm_x86_caretaker_arm_timer
#define kvm_x86_caretaker_disarm_timer		__cpu_preserved_kvm_x86_caretaker_disarm_timer
#endif

/**
 * struct kvm_x86_caretaker_runtime_ops - Preserved runtime vectors for x86 Caretaker
 * @x86_ops:      Preserved KVM x86 operations vector for kvm_x86_call().
 * @enter:        Perform hardware VM-entry and return 0 on VM-exit (setting
 *                *@exit_code) or negative on entry failure.
 * @handle_exit:  Handle VM-exit @exit_code; returns > 0 to re-enter guest,
 *                0 to leave the quantum loop, or < 0 on unhandled stall.
 * @arm_timer:    Program hardware preemption timer for @deadline_ticks.
 * @disarm_timer: Disarm hardware preemption timer.
 * @pre_run:      Vendor per-quantum setup hook.
 * @post_run:     Vendor per-quantum teardown hook.
 */
struct kvm_x86_caretaker_runtime_ops {
	const struct kvm_x86_ops *x86_ops;
	int (*enter)(struct caretaker_x86_page *cxp, u32 *exit_code);
	int (*handle_exit)(struct caretaker_x86_page *cxp, u32 exit_code,
			   enum oncore_exit_reason *reason);
	void (*arm_timer)(void *vcpu_data, u64 deadline_ticks);
	void (*disarm_timer)(void *vcpu_data);
	void (*pre_run)(void *vcpu_data);
	void (*post_run)(void *vcpu_data);
};

/**
 * struct kvm_x86_caretaker_ops - Vendor virtualization vectors for Caretaker
 * @name:      Vendor name identifier ("vmx" or "svm").
 * @init:      Initialize vendor-specific Caretaker page and hardware state for vCPU.
 * @sync_vcpu: Synchronize preserved hardware state back into @vcpu during attach.
 * @runtime:   Preserved runtime operations table placed in .cpu_preserved.data.
 */
struct kvm_x86_caretaker_ops {
	const char *name;
	void (*init)(struct kvm_vcpu *vcpu);
	void (*sync_vcpu)(struct kvm_vcpu *vcpu, void *vcpu_data);
	const struct kvm_x86_caretaker_runtime_ops *runtime;
};

void kvm_x86_caretaker_register_ops(const struct kvm_x86_caretaker_ops *ops);
void kvm_x86_caretaker_unregister_ops(const struct kvm_x86_caretaker_ops *ops);

struct kvm_vcpu_ser;

#ifdef CONFIG_KVM_CARETAKER
int kvm_arch_vcpu_caretaker_preserve(struct kvm_vcpu *vcpu,
				     struct kvm_vcpu_ser *ser,
				     struct kvm_vcpu_arch_ser *state, size_t size);
void kvm_arch_vcpu_caretaker_unpreserve(struct kvm_vcpu_ser *ser);
void kvm_arch_vcpu_caretaker_finish(struct kvm_vcpu_ser *ser);
#else
static inline int kvm_arch_vcpu_caretaker_preserve(struct kvm_vcpu *vcpu,
						   struct kvm_vcpu_ser *ser,
						   struct kvm_vcpu_arch_ser *state,
						   size_t size)
{
	return 0;
}
static inline void kvm_arch_vcpu_caretaker_unpreserve(struct kvm_vcpu_ser *ser) {}
static inline void kvm_arch_vcpu_caretaker_finish(struct kvm_vcpu_ser *ser) {}
#endif
#endif /* !__ASSEMBLY__ */

#endif /* __ARCH_X86_KVM_CARETAKER_H */
