/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * Header for x86 KVM Caretaker common C execution engine and helpers.
 */
#ifndef __ARCH_X86_KVM_CARETAKER_H
#define __ARCH_X86_KVM_CARETAKER_H

/* Canonical offsets inside struct caretaker_x86_page for assembly loop */
#define CXP_RESERVED		0x00
#define CXP_HW_CTRL_PA		0x08
#define CXP_VMCS_PA		0x08
#define CXP_VMCB_PA		0x08
#define CXP_PCPU_ID		0x10
#define CXP_STACK_ORIG		0x18
#define CXP_STACK_TOP		0x20
#define CXP_TOTAL_EXITS		0x28

#define CXP_REG_RAX		0x30
#define CXP_REG_RBX		0x38
#define CXP_REG_RCX		0x40
#define CXP_REG_RDX		0x48
#define CXP_REG_RSI		0x50
#define CXP_REG_RDI		0x58
#define CXP_REG_RBP		0x60
#define CXP_REG_R8		0x68
#define CXP_REG_R9		0x70
#define CXP_REG_R10		0x78
#define CXP_REG_R11		0x80
#define CXP_REG_R12		0x88
#define CXP_REG_R13		0x90
#define CXP_REG_R14		0x98
#define CXP_REG_R15		0xa0

#define CXP_LAST_EXIT_CODE	0xa8
#define CXP_LAST_EXIT_INFO1	0xb0
#define CXP_LAST_EXIT_QUAL	0xb0
#define CXP_LAST_EXIT_INFO2	0xb8
#define CXP_LAST_EXIT_INTR_INFO	0xb8
#define CXP_LAST_EXIT_RIP	0xc0
#define CXP_LAST_EXIT_RSP	0xc8
#define CXP_LAST_EXIT_RFLAGS	0xd0
#define CXP_HOST_CR3		0xd8
#define CXP_NEW_CR3		0xd8
#define CXP_CR3			0xe0
#define CXP_CR0			0xe8
#define CXP_CR4			0xf0
#define CXP_EFER		0xf8

#define CXP_LOOP_ENTRIES	0x100
#define CXP_VMENTRY_ENTRIES	0x108
#define CXP_VMRUN_ENTRIES	0x108
#define CXP_APIC_EOI_VA		0x110
#define CXP_APIC_LVTT_VA	0x118
#define CXP_KERNEL_GS_BASE	0x120
#define CXP_ORIG_CR3		0x128
#define CXP_DEADLINE_TSC	0x130

#define CXP_APIC_ID		0x138
#define CXP_HSAVE_PA		0x140
#define CXP_UART		0x148

#define CXP_GDT_BASE		0x300
#define CXP_TSS_BASE		0x380
#define CXP_STACK_OFFSET	0x1000
#define CXP_STACK_SIZE		4096
#define CXP_IDT_BASE		0x2000

#ifndef __ASSEMBLY__

#include <linux/types.h>
#include <linux/caretaker.h>
#include <linux/kvm_caretaker.h>
#include <asm/desc.h>
#include <asm/processor.h>
#include <asm/page.h>

#undef rdmsrq
#define rdmsrq(msr, val) do { (val) = native_rdmsrq(msr); } while (0)
#undef wrmsrq
#define wrmsrq(msr, val) native_wrmsrq(msr, val)

static inline void caretaker_set_tss_desc(struct desc_struct *gdt, unsigned long addr, unsigned size)
{
	struct ldttss_desc *desc = (struct ldttss_desc *)&gdt[GDT_ENTRY_TSS];

	caretaker_memset(desc, 0, sizeof(*desc));
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

typedef u64 (*caretaker_enter_fn)(void *page);
typedef void (*caretaker_decode_exit_fn)(void *page, struct kvm_caretaker_exit *exit);
typedef void (*caretaker_advance_rip_fn)(void *page, u64 rip);

struct caretaker_x86_page {
	u32 running;
	u32 pad0;
	union {
		u64 hw_ctrl_pa;
		u64 vmcs_pa;
		u64 vmcb_pa;
	};
	u32 pcpu_id;
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

	/* APIC memory-mapped addresses */
	u64 apic_eoi_va;
	u64 apic_lvtt_va;
	u64 kernel_gs_base;
	u64 orig_cr3;
	u64 deadline_tsc;

	/* Hardware APIC ID & Per-vCPU UART state */
	u32 apic_id;
	u32 pad1;
	u64 hsave_pa;
	struct caretaker_uart uart;
	u8 pad2[2];
	caretaker_enter_fn enter_fn;
	caretaker_decode_exit_fn decode_exit_fn;
	caretaker_advance_rip_fn advance_rip_fn;

	/* Padded to offset 0x300 */
	u8 _pad[0x300 - 0x148 - sizeof(struct caretaker_uart) - 2 - 3 * sizeof(void *)];

	/* KHO-preserved Host GDT and TSS */
	struct desc_struct gdt[GDT_ENTRIES] __aligned(16);
	struct x86_hw_tss tss __aligned(16);

	/* Caretaker Control Block and Common vCPU State */
	union {
		struct kvm_caretaker_vcpu vcpu __aligned(16);
		struct caretaker_cb cb;
	};

	/* Page 1 (4KB): Standalone execution stack */
	u8 stack[CXP_STACK_SIZE] __aligned(PAGE_SIZE);

	/* Page 2 (4KB): KHO-preserved IDT */
	gate_desc idt[256] __aligned(PAGE_SIZE);
} __aligned(PAGE_SIZE);




/* Shared page table and GPR helpers */
#ifdef CONFIG_LIVEUPDATE_CPU
extern phys_addr_t x86_caretaker_pgd_pa;
#else
#define x86_caretaker_pgd_pa 0ULL
#endif

void kvm_x86_caretaker_init_common_page(struct caretaker_x86_page *cxp,
					struct kvm_vcpu *vcpu,
					size_t full_page_size);
void kvm_x86_caretaker_save_gprs(struct kvm_vcpu *vcpu, u64 *gprs);
__cpu_preserved_text void kvm_x86_caretaker_restore_gprs(struct kvm_vcpu *vcpu, const u64 *gprs);
void kvm_x86_caretaker_init_idt(gate_desc *idt);
struct x86_hw_tss;
void kvm_x86_caretaker_init_gdt_tss(struct desc_struct *gdt,
				    struct x86_hw_tss *tss,
				    unsigned long stack_top);
void kvm_x86_caretaker_load_desc(struct desc_struct *gdt, size_t gdt_size,
				 gate_desc *idt, size_t idt_size,
				 void *tss);
void kvm_x86_caretaker_restore_host_desc(int pcpu, const struct desc_ptr *orig_idt);

struct caretaker_x86_host_state {
	struct desc_ptr orig_gdt;
	struct desc_ptr orig_idt;
	unsigned long orig_cr3;
	unsigned long orig_gs_base;
	unsigned long orig_kernel_gs_base;
};

__caretaker_text void kvm_x86_caretaker_save_host_state(struct caretaker_x86_host_state *host,
							struct caretaker_x86_page *cxp);
__caretaker_text void kvm_x86_caretaker_restore_host_state(const struct caretaker_x86_host_state *host,
							   const struct caretaker_x86_page *cxp,
							   struct kvm_vcpu *vcpu, int pcpu);
__caretaker_text void kvm_x86_caretaker_sync_vcpu_common(struct kvm_vcpu *vcpu,
							 const struct caretaker_x86_page *cxp);

__caretaker_text enum caretaker_exit_reason
kvm_x86_caretaker_run(struct caretaker_x86_page *cxp,
		      u64 deadline_ticks,
		      caretaker_enter_fn enter,
		      caretaker_decode_exit_fn decode_exit,
		      caretaker_advance_rip_fn advance_rip);

void kvm_x86_caretaker_signal_attach_common(struct kvm_vcpu *vcpu,
					    struct caretaker_cb *cb,
					    u32 fallback_apic_id,
					    volatile u32 *running,
					    const char *vendor_name);

void x86_preserved_iret_stub(void);
void x86_preserved_iret_err_stub(void);
void x86_preserved_apic_eoi_stub(void);
extern unsigned long x86_preserved_apic_eoi_va;

__caretaker_text void kvm_x86_caretaker_arm_timer(u64 deadline_ticks, u64 apic_lvtt_va);
__caretaker_text void kvm_x86_caretaker_disarm_timer(u64 apic_lvtt_va);

/**
 * struct kvm_x86_caretaker_ops - Vendor virtualization vectors for Caretaker
 * @init: Initialize vendor-specific Caretaker page and hardware state for vCPU.
 * @signal_attach: Notify running Caretaker execution to prepare for handover.
 * @attach: Attach vCPU back to kernel host control, syncing guest registers.
 * @run_job: Execute guest vCPU until deadline expires or exit occurs.
 *
 * Vector table implemented by Intel VMX and AMD SVM backends to provide
 * hardware-assisted virtualization operations required during live update
 * and quantum-scheduled Caretaker execution.
 */
struct kvm_x86_caretaker_ops {
	void (*init)(struct kvm_vcpu *vcpu, u64 *cb_pa);
	void (*signal_attach)(struct kvm_vcpu *vcpu, u64 cb_pa);
	void (*attach)(struct kvm_vcpu *vcpu, u64 cb_pa);
	enum caretaker_exit_reason (*run_job)(void *data, u64 deadline_ticks);
};

void kvm_x86_caretaker_register_ops(const struct kvm_x86_caretaker_ops *ops);
void kvm_x86_caretaker_unregister_ops(const struct kvm_x86_caretaker_ops *ops);

#endif /* !__ASSEMBLY__ */

#endif /* __ARCH_X86_KVM_CARETAKER_H */
