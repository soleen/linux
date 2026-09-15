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
 * Size of the caretaker's standalone execution stack.  This is part of the
 * struct definition below, so it has to be a literal; every other offset the
 * assembly needs is generated into kvm-asm-offsets.h from the struct itself.
 */
#define CXP_STACK_SIZE		4096

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
#include <asm/desc.h>
#include <asm/processor.h>
#include <asm/page.h>

static inline void caretaker_set_tss_desc(struct desc_struct *gdt,
					  unsigned long addr, unsigned int size)
{
	struct ldttss_desc *desc = (struct ldttss_desc *)&gdt[GDT_ENTRY_TSS];

	oncore_memset(desc, 0, sizeof(*desc));
	desc->limit0 = (u16)size;
	desc->base0 = (u16)addr;
	desc->base1 = (addr >> 16) & 0xFF;
	desc->type = DESC_TSS;
	desc->p = 1;
	desc->limit1 = (size >> 16) & 0xF;
	desc->base2 = (addr >> 24) & 0xFF;
	desc->base3 = (u32)(addr >> 32);
}

struct kvm_vcpu;
struct kvm_caretaker_exit;

/**
 * struct caretaker_x86_page - Standalone preserved execution page for x86
 * @abi: Cross-kexec ABI prefix declared in include/linux/kho/abi/kvm_x86.h.
 *
 * Cross-kexec invariant: the incoming kernel may only dereference @abi
 * (and @ser->arch_state).  All other fields in this structure (GDT, TSS,
 * IDT, standalone stack, GPR scratch area, exit info) are private to the
 * preserved Caretaker text and are never read by the incoming kernel.
 */
struct caretaker_x86_page {
	union {
		struct kvm_x86_caretaker_abi abi;
		struct kvm_caretaker_vcpu vcpu __aligned(16);
		struct {
			struct kvm_caretaker_cb cb;
			u32 running;
			u32 apic_id;
			union {
				u64 hw_ctrl_pa;
				u64 vmcs_pa;
				u64 vmcb_pa;
			};
			u64 arch_state_pa;
			u64 arch_state_size;
		};
	};

	u32 pcpu_id;
	u32 pad0;
	struct kvm_vcpu_arch_luo_state *arch_state;
	u64 stack_orig;
	u64 stack_top;
	u64 total_exits;

	/* Guest GPRs context switch area */
	union {
		struct {
			u64 rax, rbx, rcx, rdx, rsi, rdi, rbp;
			u64 r8, r9, r10, r11, r12, r13, r14, r15;
		};
		u64 regs[15];
	};

	/* Exit state */
	u64 last_exit_code;
	union {
		u64 last_exit_qual;
		u64 last_exit_info1;
	};
	union {
		u64 last_exit_intr_info;
		u64 last_exit_info2;
	};
	u64 last_exit_rip;
	u64 last_exit_rsp;
	u64 last_exit_rflags;

	/* Preserved Host page table and handover vectors */
	union {
		u64 host_cr3;
		u64 new_cr3;
	};
	u64 cr3;
	u64 cr0;
	u64 cr4;
	u64 efer;

	u64 loop_entries;
	union {
		u64 vmentry_entries;
		u64 vmrun_entries;
	};

	u64 kernel_gs_base;
	u64 orig_cr3;
	u64 deadline_tsc;

	union {
		u64 hsave_pa;
		u64 vmxon_pa;
	};
	struct caretaker_uart uart;
	u8 pad2[2];

	/* KHO-preserved Host GDT and TSS */
	struct desc_struct gdt[GDT_ENTRIES] __aligned(16);
	struct x86_hw_tss tss __aligned(16);

	/* Page 1 (4KB): Standalone execution stack */
	u8 stack[CXP_STACK_SIZE] __aligned(PAGE_SIZE);

	/* Page 2 (4KB): KHO-preserved IDT */
	gate_desc idt[256] __aligned(PAGE_SIZE);
} __aligned(PAGE_SIZE);

/*
 * The caretaker page is handed to a preserved core as three physically
 * contiguous pages, and the exit path in caretaker_vmenter.S recovers the
 * page base by masking the stack pointer and subtracting the stack offset.
 * Both of those only work if the control block, the stack and the IDT each
 * start on their own page.
 */
static_assert(offsetof(struct caretaker_x86_page, abi) == 0);
static_assert(offsetof(struct caretaker_x86_page, cb) == 0);
static_assert(offsetof(struct caretaker_x86_page, running) ==
	      offsetof(struct kvm_x86_caretaker_abi, running));
static_assert(offsetof(struct caretaker_x86_page, apic_id) ==
	      offsetof(struct kvm_x86_caretaker_abi, apic_id));
static_assert(offsetof(struct caretaker_x86_page, vmcs_pa) ==
	      offsetof(struct kvm_x86_caretaker_abi, vmcs_pa));
static_assert(offsetof(struct caretaker_x86_page, stack) == PAGE_SIZE);
static_assert(offsetof(struct caretaker_x86_page, idt) == 2 * PAGE_SIZE);
static_assert(sizeof(struct caretaker_x86_page) == 3 * PAGE_SIZE);

/* Shared page table and GPR helpers */
#ifdef CONFIG_LIVEUPDATE_CPU
extern phys_addr_t x86_caretaker_pgd_pa;
#else
#define x86_caretaker_pgd_pa 0ULL
#endif

int kvm_x86_caretaker_init_common_page(struct caretaker_x86_page *cxp,
				       struct kvm_vcpu *vcpu,
				       size_t full_page_size);

void kvm_x86_caretaker_sync_vcpu_common(struct kvm_vcpu *vcpu);
__caretaker_text void
kvm_x86_caretaker_detach_serialize_common(struct caretaker_x86_page *cxp,
					  struct kvm_vcpu_arch_luo_state *state);
__caretaker_text void
kvm_x86_caretaker_update_msr(struct kvm_vcpu_arch_luo_state *state,
			     u32 msr, u64 val);
__caretaker_text bool
kvm_x86_caretaker_handle_exit(void *data, struct kvm_caretaker_exit *exit);

void x86_preserved_iret_stub(void);
void x86_preserved_iret_err_stub(void);
void x86_preserved_apic_eoi_stub(void);
__caretaker_text void kvm_x86_caretaker_arm_timer(u64 deadline_ticks);
__caretaker_text void kvm_x86_caretaker_disarm_timer(void);

/**
 * struct kvm_x86_caretaker_ops - Vendor virtualization vectors for Caretaker
 * @name: Vendor name identifier ("vmx" or "svm").
 * @init: Initialize vendor-specific Caretaker page and hardware state for vCPU.
 * @detach_serialize: Serialize live vendor guest state into struct kvm_vcpu_arch_luo_state.
 * @common: Common Caretaker operations table (enter_guest, decode_exit, etc.).
 */
struct kvm_x86_caretaker_ops {
	const char *name;
	void (*init)(struct kvm_vcpu *vcpu);
	void (*detach_serialize)(void *page, struct kvm_vcpu_arch_luo_state *state);
	struct kvm_caretaker_ops common;
};

void kvm_x86_caretaker_register_ops(const struct kvm_x86_caretaker_ops *ops);
void kvm_x86_caretaker_unregister_ops(const struct kvm_x86_caretaker_ops *ops);

struct kvm_vcpu_luo_ser;

#ifdef CONFIG_KVM_CARETAKER
void kvm_arch_vcpu_caretaker_init(struct kvm_vcpu *vcpu);
void kvm_arch_vcpu_caretaker_unpreserve(struct kvm_vcpu_luo_ser *ser);
void kvm_arch_vcpu_caretaker_finish(struct kvm_vcpu_luo_ser *ser);
#else
static inline void kvm_arch_vcpu_caretaker_init(struct kvm_vcpu *vcpu) {}
static inline void kvm_arch_vcpu_caretaker_unpreserve(struct kvm_vcpu_luo_ser *ser) {}
static inline void kvm_arch_vcpu_caretaker_finish(struct kvm_vcpu_luo_ser *ser) {}
#endif
#endif /* !__ASSEMBLY__ */

#endif /* __ARCH_X86_KVM_CARETAKER_H */
