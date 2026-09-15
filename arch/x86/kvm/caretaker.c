// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * x86 KVM Caretaker execution loop and hardware virtualization attachment.
 */

#include <linux/cpu.h>
#include <linux/cpu_preserve.h>
#include <linux/delay.h>
#include <linux/kexec_handover.h>
#include <linux/kho/abi/kvm.h>
#include <linux/kvm_host.h>
#include <linux/oncore.h>
#include <linux/smp.h>
#include <uapi/linux/serial_reg.h>

#include <asm/apic.h>
#include <asm/cpu_entry_area.h>
#include <linux/cpu_preserve.h>
#include <asm/desc.h>
#include <asm/fpu/api.h>
#include <asm/fixmap.h>
#include <asm/irq_vectors.h>
#include <linux/kvm_host.h>
#include <asm/msr.h>
#include <linux/sync_core.h>
#include <asm/trapnr.h>
#include <asm/virt.h>

#include "caretaker.h"
#include "cpuid.h"
#include "lapic.h"
#include "regs.h"
#include "x86.h"

/* Host register state saved around an on-core caretaker run. */
struct caretaker_x86_host_state {
	struct desc_ptr orig_idt;
	unsigned long orig_cr2;
	unsigned long orig_fs_base;
	unsigned long orig_gs_base;
	unsigned long orig_kernel_gs_base;
	u64 orig_star;
	u64 orig_lstar;
	u64 orig_fmask;
};

/* Defined below their first use. */
static void kvm_x86_caretaker_save_gprs(struct kvm_vcpu *vcpu, u64 *gprs);
static void kvm_x86_caretaker_init_idt(gate_desc *idt);
static void kvm_x86_caretaker_init_gdt_tss(struct desc_struct *gdt,
					   struct x86_hw_tss *tss,
					   unsigned long stack_top);

/*
 * A preserved page is handed over by physical address.  The SME/SEV C-bit is
 * an encryption attribute, not part of the address, so strip it before
 * forming a kernel virtual address.
 *
 * Both helpers are __always_inline because callers live in
 * __cpu_preserved_text: an out-of-line copy would sit outside the section
 * that survives the kexec.
 */
static __always_inline void *caretaker_pa_to_va(u64 pa)
{
	return phys_to_virt(__sme_clr(pa));
}

/* The control block is embedded in the vendor-agnostic caretaker page. */
static __always_inline struct caretaker_x86_page *
cxp_from_cb(struct kvm_caretaker_cb_ser *cb)
{
	return container_of(cb, struct caretaker_x86_page, abi.cb);
}

static const struct kvm_x86_caretaker_ops *kvm_x86_caretaker_ops __cpu_preserved_data;

void kvm_x86_caretaker_register_ops(const struct kvm_x86_caretaker_ops *ops)
{
	WRITE_ONCE(kvm_x86_caretaker_ops, ops);
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_x86_caretaker_register_ops);

void kvm_x86_caretaker_unregister_ops(const struct kvm_x86_caretaker_ops *ops)
{
	if (kvm_x86_caretaker_ops == ops)
		WRITE_ONCE(kvm_x86_caretaker_ops, NULL);
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_x86_caretaker_unregister_ops);

static bool caretaker_x86_has_tsc_deadline __cpu_preserved_data;
static u32 caretaker_x86_lapic_timer_period __cpu_preserved_data;
static u32 caretaker_x86_tsc_khz __cpu_preserved_data;
gate_desc caretaker_x86_idt[IDT_ENTRIES] __caretaker_data __aligned(16);
EXPORT_SYMBOL_FOR_KVM_INTERNAL(caretaker_x86_idt);
static bool caretaker_x86_idt_initialized;

static void kvm_x86_caretaker_init_uart(struct caretaker_uart *uart)
{
	if (!uart)
		return;

	uart->lcr = UART_LCR_WLEN8;
	uart->ier = 0x00;
	uart->mcr = UART_MCR_DTR | UART_MCR_RTS;
	uart->scr = 0x00;
	uart->dll = 0x01;
	uart->dlm = 0x00;
}

int kvm_x86_caretaker_preserve_page(struct kvm_caretaker_arch_ser *abi,
				    struct page *page)
{
	int ret;

	if (WARN_ON_ONCE(abi->nr_preserved_pages >= KVM_X86_CARETAKER_MAX_PAGES))
		return -ENOSPC;

	ret = kho_preserve_pages(page, 1);
	if (ret)
		return ret;

	abi->preserved_pages_pa[abi->nr_preserved_pages++] = page_to_phys(page);
	return 0;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_x86_caretaker_preserve_page);

void kvm_x86_caretaker_unpreserve_pages(struct kvm_caretaker_arch_ser *abi)
{
	u32 i;

	for (i = 0; i < abi->nr_preserved_pages; i++)
		kho_unpreserve_pages(phys_to_page(__sme_clr(abi->preserved_pages_pa[i])), 1);
	abi->nr_preserved_pages = 0;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_x86_caretaker_unpreserve_pages);

int kvm_x86_caretaker_init_common_page(struct caretaker_x86_page *cxp,
				       struct kvm_vcpu *vcpu,
				       size_t full_page_size)
{
	struct oncore_session *sess;
	phys_addr_t pgd_pa;
	u32 apic_id;
	int pcpu;
	int ret;

	if (!cxp || !vcpu)
		return -EINVAL;

	caretaker_x86_has_tsc_deadline = boot_cpu_has(X86_FEATURE_TSC_DEADLINE_TIMER);
	caretaker_x86_lapic_timer_period = lapic_timer_period;
	caretaker_x86_tsc_khz = tsc_khz;
	cpu_preserved_clean(&caretaker_x86_has_tsc_deadline);
	cpu_preserved_clean(&caretaker_x86_lapic_timer_period);
	cpu_preserved_clean(&caretaker_x86_tsc_khz);
	if (!caretaker_x86_idt_initialized) {
		kvm_x86_caretaker_init_idt(caretaker_x86_idt);
		cpu_preserved_clean_sz(caretaker_x86_idt, sizeof(caretaker_x86_idt));
		caretaker_x86_idt_initialized = true;
	}

	memset(cxp, 0, full_page_size);

	kvm_caretaker_init_common_vcpu(&cxp->vcpu, &cxp->abi.cb, vcpu, cxp,
				       full_page_size, NULL, cxp);

	pcpu = cxp->abi.cb.pcpu_id;

	apic_id = apic->cpu_present_to_apicid(pcpu);
	if (apic_id == BAD_APICID)
		apic_id = pcpu;
	cxp->abi.apic_id = apic_id;

	kvm_x86_caretaker_init_uart(&cxp->uart);

	cxp->save_guest_fpu = boot_cpu_has(X86_FEATURE_XSAVE) &&
			      !fpstate_is_confidential(&vcpu->arch.guest_fpu);

	/* Capture guest GPRs */
	kvm_x86_caretaker_save_gprs(vcpu, &cxp->rax);

	/* Preserved CR3 from session */
	sess = oncore_job_session(vcpu->caretaker.job);
	pgd_pa = oncore_session_get_pgd_pa(sess);
	cxp->host_cr3 = pgd_pa;
	cxp->cr3 = kvm_read_cr3(vcpu);
	cxp->cr0 = kvm_read_cr0(vcpu);
	cxp->cr4 = kvm_read_cr4(vcpu);
	cxp->efer = vcpu->arch.efer;

	/* Build KHO-preserved Host GDT and TSS */
	kvm_x86_caretaker_init_gdt_tss(cxp->gdt, &cxp->tss,
				       (unsigned long)&cxp->stack[CXP_STACK_SIZE]);

	/* Preserve in-kernel local APIC register page across kexec */
	if (vcpu->arch.apic && vcpu->arch.apic->regs) {
		ret = kvm_x86_caretaker_preserve_page(&cxp->abi,
						      virt_to_page(vcpu->arch.apic->regs));
		if (ret)
			return ret;
		cxp->apic_regs = vcpu->arch.apic->regs;
		oncore_session_map_buffer(sess, vcpu->arch.apic->regs, PAGE_SIZE);
	}

	return 0;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_x86_caretaker_init_common_page);

static void kvm_x86_caretaker_save_gprs(struct kvm_vcpu *vcpu, u64 *gprs)
{
	gprs[0]  = kvm_register_read_raw(vcpu, VCPU_REGS_RAX);
	gprs[1]  = kvm_register_read_raw(vcpu, VCPU_REGS_RBX);
	gprs[2]  = kvm_register_read_raw(vcpu, VCPU_REGS_RCX);
	gprs[3]  = kvm_register_read_raw(vcpu, VCPU_REGS_RDX);
	gprs[4]  = kvm_register_read_raw(vcpu, VCPU_REGS_RSI);
	gprs[5]  = kvm_register_read_raw(vcpu, VCPU_REGS_RDI);
	gprs[6]  = kvm_register_read_raw(vcpu, VCPU_REGS_RBP);
	gprs[7]  = kvm_register_read_raw(vcpu, VCPU_REGS_R8);
	gprs[8]  = kvm_register_read_raw(vcpu, VCPU_REGS_R9);
	gprs[9]  = kvm_register_read_raw(vcpu, VCPU_REGS_R10);
	gprs[10] = kvm_register_read_raw(vcpu, VCPU_REGS_R11);
	gprs[11] = kvm_register_read_raw(vcpu, VCPU_REGS_R12);
	gprs[12] = kvm_register_read_raw(vcpu, VCPU_REGS_R13);
	gprs[13] = kvm_register_read_raw(vcpu, VCPU_REGS_R14);
	gprs[14] = kvm_register_read_raw(vcpu, VCPU_REGS_R15);
}

static void kvm_x86_caretaker_init_idt(gate_desc *idt)
{
	int v;

	for (v = 0; v < IDT_ENTRIES; v++) {
		bool has_err = (v == X86_TRAP_DF ||
				(v >= X86_TRAP_TS && v <= X86_TRAP_PF) ||
				v == X86_TRAP_AC || v == X86_TRAP_CP ||
				v == X86_TRAP_VC || v == 30);
		unsigned long handler = (v >= FIRST_EXTERNAL_VECTOR) ?
			(unsigned long)&x86_preserved_apic_eoi_stub :
			(has_err ? (unsigned long)&x86_preserved_iret_err_stub :
				   (unsigned long)&x86_preserved_iret_stub);

		pack_gate(&idt[v], GATE_INTERRUPT, handler, 0, 0, __KERNEL_CS);
	}
}

static void kvm_x86_caretaker_init_gdt_tss(struct desc_struct *gdt,
					   struct x86_hw_tss *tss,
					   unsigned long stack_top)
{
	int k;

	memcpy(gdt, get_current_gdt_ro(), sizeof(struct desc_struct) * GDT_ENTRIES);
	memset(tss, 0, sizeof(*tss));
	tss->sp0 = stack_top;
	tss->io_bitmap_base = sizeof(*tss);
	for (k = 0; k < ARRAY_SIZE(tss->ist); k++)
		tss->ist[k] = stack_top;

	caretaker_set_tss_desc(gdt, (unsigned long)tss, sizeof(struct x86_hw_tss) - 1);
}

__caretaker_text void kvm_x86_caretaker_arm_timer(u64 deadline_ticks)
{
	if (!deadline_ticks || deadline_ticks == U64_MAX)
		return;

	if (caretaker_x86_has_tsc_deadline) {
		u32 lvtt = LOCAL_TIMER_VECTOR | APIC_LVT_TIMER_TSCDEADLINE;

		native_wrmsrq(APIC_BASE_MSR + (APIC_LVTT >> 4), lvtt);
		native_wrmsrq(MSR_IA32_TSC_DEADLINE, deadline_ticks);
	} else {
		u64 now = rdtsc();
		u64 delta_tsc = (deadline_ticks > now) ? (deadline_ticks - now) : 1;
		u32 lvtt = LOCAL_TIMER_VECTOR;
		u64 count;

		if (caretaker_x86_tsc_khz != 0 && caretaker_x86_lapic_timer_period != 0) {
			u64 period = caretaker_x86_lapic_timer_period;
			u64 apic_khz = (period * HZ) / 1000ULL;

			count = (delta_tsc * apic_khz) /
				((u64)caretaker_x86_tsc_khz * 16ULL);
		} else {
			count = delta_tsc >> 4;
		}
		if (count == 0)
			count = 1;
		if (count > U32_MAX)
			count = U32_MAX;

		native_wrmsrq(APIC_BASE_MSR + (APIC_TDCR >> 4),
			      APIC_TDR_DIV_16);
		native_wrmsrq(APIC_BASE_MSR + (APIC_LVTT >> 4), lvtt);
		native_wrmsrq(APIC_BASE_MSR + (APIC_TMICT >> 4), (u32)count);
	}
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_x86_caretaker_arm_timer);

__caretaker_text void kvm_x86_caretaker_disarm_timer(void)
{
	if (caretaker_x86_has_tsc_deadline)
		native_wrmsrq(MSR_IA32_TSC_DEADLINE, 0);
	else
		native_wrmsrq(APIC_BASE_MSR + (APIC_TMICT >> 4), 0);

	native_wrmsrq(APIC_BASE_MSR + (APIC_LVTT >> 4),
		      APIC_LVT_MASKED | LOCAL_TIMER_VECTOR);
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_x86_caretaker_disarm_timer);

