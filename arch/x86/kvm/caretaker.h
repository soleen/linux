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

/* COM1 serial port range intercepted by Caretaker */
#define COM1_PORT_BASE		0x3f8
#define COM1_PORT_END		0x3ff

/* Number of x2APIC MSRs (0x800 - 0x83f) */
#define X2APIC_MSR_COUNT	0x40

/* Caretaker APIC version: 6 LVT entries (max index 5), version 0x14 */
#define CARETAKER_APIC_LVR	((5 << 16) | 0x14)

#ifndef __ASSEMBLY__

#include <linux/types.h>
#include <linux/oncore.h>
#include <linux/kho/abi/kvm_x86.h>
#include <linux/kvm_caretaker.h>

/* Architecture-specific VM exit types for x86 */
#define KVM_CARETAKER_EXIT_CPUID \
	((enum kvm_caretaker_exit_type)(KVM_CARETAKER_EXIT_ARCH + 1))
#define KVM_CARETAKER_EXIT_MSR \
	((enum kvm_caretaker_exit_type)(KVM_CARETAKER_EXIT_ARCH + 2))
#define KVM_CARETAKER_EXIT_RDTSC \
	((enum kvm_caretaker_exit_type)(KVM_CARETAKER_EXIT_ARCH + 3))

/* 8250 UART register state for guest early printk emulation */
struct caretaker_uart {
	u8 lcr;
	u8 ier;
	u8 mcr;
	u8 scr;
	u8 dll;
	u8 dlm;
};

#include <linux/processor.h>
#include <asm/desc.h>
#include <asm/page.h>

static __always_inline void caretaker_set_tss_desc(struct desc_struct *gdt,
						   unsigned long addr,
						   unsigned int size)
{
	struct ldttss_desc *desc = (struct ldttss_desc *)&gdt[GDT_ENTRY_TSS];

	cpu_preserved_memset(desc, 0, sizeof(*desc));
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
struct kvm_caretaker_exit;

/**
 * struct caretaker_x86_page - Vendor-common x86 Caretaker runtime page (4 KB)
 * @abi:              Cross-kexec KHO ABI header (must remain at offset 0).
 * @vcpu:             Common Caretaker vCPU execution engine descriptor.
 * @arch_state:       Pointer to KHO-preserved vCPU architectural state buffer.
 * @apic_regs:        Pointer to KHO-preserved in-kernel LAPIC register page.
 * @stack_orig:       Saved caller %rsp across vmx_caretaker_enter() guest entry.
 * @rax:              Guest RAX switched in caretaker_vmenter.S.
 * @rbx:              Guest RBX switched in caretaker_vmenter.S.
 * @rcx:              Guest RCX switched in caretaker_vmenter.S.
 * @rdx:              Guest RDX switched in caretaker_vmenter.S.
 * @rsi:              Guest RSI switched in caretaker_vmenter.S.
 * @rdi:              Guest RDI switched in caretaker_vmenter.S.
 * @rbp:              Guest RBP switched in caretaker_vmenter.S.
 * @r8:               Guest R8 switched in caretaker_vmenter.S.
 * @r9:               Guest R9 switched in caretaker_vmenter.S.
 * @r10:              Guest R10 switched in caretaker_vmenter.S.
 * @r11:              Guest R11 switched in caretaker_vmenter.S.
 * @r12:              Guest R12 switched in caretaker_vmenter.S.
 * @r13:              Guest R13 switched in caretaker_vmenter.S.
 * @r14:              Guest R14 switched in caretaker_vmenter.S.
 * @r15:              Guest R15 switched in caretaker_vmenter.S.
 * @last_exit_rip:    Guest RIP captured on VM exit and updated on instruction skip.
 * @last_exit_rsp:    Guest RSP captured on VM exit.
 * @last_exit_rflags: Guest RFLAGS captured on VM exit.
 * @host_cr3:         Isolated Caretaker page table root PA loaded during run.
 * @cr3:              Guest CR3 shadow value captured on VM exit.
 * @cr0:              Guest CR0 shadow value captured on VM exit.
 * @cr4:              Guest CR4 shadow value captured on VM exit.
 * @efer:             Guest EFER shadow value captured on VM exit.
 * @kernel_gs_base:   Guest MSR_KERNEL_GS_BASE switched across VMX entry/exit.
 * @uart:             Emulated 8250 UART register state for early guest console.
 * @save_guest_fpu:   True if guest FPU state can be captured via XSAVE at detach.
 * @gdt:              Per-vCPU preserved GDT containing the active Caretaker TSS.
 * @tss:              Per-vCPU hardware TSS whose SP0/IST point to @stack.
 * @stack:            2 KB standalone host stack occupying the upper half of the
 *                    page ([2048..4096)).  VMX sets HOST_RSP to the top of this
 *                    page so vmx_caretaker_exit_handler can recover the base
 *                    address of struct caretaker_x86_page via (%rsp & PAGE_MASK).
 *
 * Cross-kexec invariant: Only @abi (and @arch_state) may be dereferenced by the
 * incoming kernel.  All remaining fields are private to the preserved Caretaker
 * text executing on the isolated physical CPU during the kexec handover window.
 */
struct caretaker_x86_page {
	/* KHO ABI prefix (offset 0) and common scheduler descriptor */
	struct kvm_caretaker_arch_ser abi;
	struct kvm_caretaker_vcpu vcpu;

	struct kvm_vcpu_arch_ser *arch_state;
	void *apic_regs;
	u64 stack_orig;

	/* Guest GPRs switched in caretaker_vmenter.S */
	u64 rax, rbx, rcx, rdx, rsi, rdi, rbp;
	u64 r8, r9, r10, r11, r12, r13, r14, r15;

	/* Guest instruction/stack pointers and control registers at VM exit */
	u64 last_exit_rip;
	u64 last_exit_rsp;
	u64 last_exit_rflags;
	u64 host_cr3;
	u64 cr3;
	u64 cr0;
	u64 cr4;
	u64 efer;
	u64 kernel_gs_base;

	/* Emulated UART and FPU capability state */
	struct caretaker_uart uart;
	bool save_guest_fpu;

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

int kvm_x86_caretaker_preserve_page(struct kvm_caretaker_arch_ser *abi,
				    struct page *page);
void kvm_x86_caretaker_unpreserve_pages(struct kvm_caretaker_arch_ser *abi);

/* Shared page table, IDT, and GPR helpers */
extern gate_desc caretaker_x86_idt[IDT_ENTRIES];

int kvm_x86_caretaker_init_common_page(struct caretaker_x86_page *cxp,
				       struct kvm_vcpu *vcpu,
				       size_t full_page_size);

void kvm_x86_caretaker_sync_vcpu_common(struct kvm_vcpu *vcpu);
__caretaker_text void
kvm_x86_caretaker_detach_serialize_common(struct caretaker_x86_page *cxp,
					  struct kvm_vcpu_arch_ser *state);
__caretaker_text void
kvm_x86_caretaker_update_msr(struct kvm_vcpu_arch_ser *state,
			     u32 msr, u64 val);
__caretaker_text bool
kvm_x86_caretaker_handle_exit(void *data, struct kvm_caretaker_exit *exit);

void x86_preserved_iret_stub(void);
void x86_preserved_iret_err_stub(void);
void x86_preserved_apic_eoi_stub(void);
__caretaker_text void kvm_x86_caretaker_arm_timer(u64 deadline_ticks);
__caretaker_text void kvm_x86_caretaker_disarm_timer(void);

/**
 * struct kvm_x86_caretaker_runtime_ops - Preserved runtime vectors for x86 Caretaker
 * @detach_serialize: Serialize live vendor guest state into struct kvm_vcpu_arch_ser.
 * @common:           Common Caretaker operations table (enter_guest, decode_exit, etc.).
 */
struct kvm_x86_caretaker_runtime_ops {
	void (*detach_serialize)(void *page, struct kvm_vcpu_arch_ser *state);
	struct kvm_caretaker_ops common;
};

/**
 * struct kvm_x86_caretaker_ops - Vendor virtualization vectors for Caretaker
 * @name:      Vendor name identifier ("vmx" or "svm").
 * @init:      Initialize vendor-specific Caretaker page and hardware state for vCPU.
 * @sync_vcpu: Synchronize preserved hardware state back into @vcpu during attach.
 * @runtime:   Preserved runtime operations table placed in __cpu_preserved_data.
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
void kvm_arch_vcpu_caretaker_init(struct kvm_vcpu *vcpu);
void kvm_arch_vcpu_caretaker_unpreserve(struct kvm_vcpu_ser *ser);
void kvm_arch_vcpu_caretaker_finish(struct kvm_vcpu_ser *ser);
#else
static inline void kvm_arch_vcpu_caretaker_init(struct kvm_vcpu *vcpu) {}
static inline void kvm_arch_vcpu_caretaker_unpreserve(struct kvm_vcpu_ser *ser) {}
static inline void kvm_arch_vcpu_caretaker_finish(struct kvm_vcpu_ser *ser) {}
#endif
#endif /* !__ASSEMBLY__ */

#endif /* __ARCH_X86_KVM_CARETAKER_H */
