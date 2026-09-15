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
	unsigned long orig_cr8;
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
static enum oncore_exit_reason __cpu_preserved_text
kvm_x86_caretaker_run_page(struct caretaker_x86_page *cxp, u64 deadline_ticks);

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

static const struct kvm_x86_caretaker_ops *kvm_x86_caretaker_host_ops;
static const struct kvm_x86_caretaker_runtime_ops *kvm_x86_caretaker_ops __cpu_preserved_data;

void kvm_x86_caretaker_register_ops(const struct kvm_x86_caretaker_ops *ops)
{
	WRITE_ONCE(kvm_x86_caretaker_host_ops, ops);
	WRITE_ONCE(kvm_x86_caretaker_ops, ops ? ops->runtime : NULL);
	cpu_preserved_clean(&kvm_x86_caretaker_ops);
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_x86_caretaker_register_ops);

void kvm_x86_caretaker_unregister_ops(const struct kvm_x86_caretaker_ops *ops)
{
	if (kvm_x86_caretaker_host_ops == ops) {
		WRITE_ONCE(kvm_x86_caretaker_host_ops, NULL);
		WRITE_ONCE(kvm_x86_caretaker_ops, NULL);
		cpu_preserved_clean(&kvm_x86_caretaker_ops);
	}
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_x86_caretaker_unregister_ops);

enum oncore_exit_reason __cpu_preserved_text
kvm_arch_vcpu_caretaker_run(void *data, u64 deadline_ticks)
{
	struct kvm_caretaker_cb_ser *cb = data;

	/*
	 * @data is always a struct kvm_caretaker_cb_ser:
	 * kvm_caretaker_vcpu_post_preserve() installs it with
	 * oncore_job_set_data() before activating the job.
	 */
	if (!cb)
		return ONCORE_EXIT_ERROR;

	return kvm_x86_caretaker_run_page(cxp_from_cb(cb), deadline_ticks);
}

static void kvm_arch_vcpu_caretaker_init(struct kvm_vcpu *vcpu)
{
	if (kvm_x86_caretaker_host_ops && kvm_x86_caretaker_host_ops->init)
		kvm_x86_caretaker_host_ops->init(vcpu);
}

int kvm_arch_vcpu_caretaker_preserve(struct kvm_vcpu *vcpu,
				     struct kvm_vcpu_ser *ser,
				     struct kvm_vcpu_arch_ser *state, size_t size)
{
	struct kvm_caretaker_arch_ser *abi;
	struct oncore_session *sess;

	if (!vcpu->caretaker.job)
		return 0;

	kvm_arch_vcpu_caretaker_init(vcpu);
	if (!vcpu->caretaker.cb)
		return -ENOMEM;

	sess = oncore_job_session(vcpu->caretaker.job);
	ser->cb.phys = virt_to_phys(vcpu->caretaker.cb);
	abi = phys_to_virt(ser->cb.phys);
	container_of(abi, struct caretaker_x86_page, abi)->arch_state = state;
	oncore_session_map_buffer(sess, state, size);

	return 0;
}

static void kvm_x86_caretaker_signal_attach(struct kvm_vcpu *vcpu, u64 cb_pa)
{
	struct kvm_caretaker_arch_ser *abi;
	struct kvm_caretaker_cb_ser *cb;
	int target_pcpu;
	u32 apic_id;

	if (!cb_pa)
		return;

	abi = caretaker_pa_to_va(cb_pa);
	cb = &abi->cb;
	target_pcpu = cb->pcpu_id;

	if (cpu_is_preserved(target_pcpu)) {
		apic_id = apic->cpu_present_to_apicid(target_pcpu);
		if (apic_id == BAD_APICID)
			apic_id = cpuid_to_apicid[target_pcpu];
		if (apic_id == BAD_APICID)
			apic_id = abi->apic_id ? abi->apic_id : target_pcpu;
		if (apic_id != BAD_APICID && apic_id != (u32)-1 && apic_id != 0)
			per_cpu(x86_cpu_to_apicid, target_pcpu) = apic_id;
	}

	kvm_caretaker_wait_for_attach(cb, target_pcpu);
	if (vcpu)
		vcpu->cpu = -1;
}

static void kvm_x86_caretaker_attach(struct kvm_vcpu *vcpu, u64 cb_pa)
{
	const struct kvm_x86_caretaker_ops *ops = kvm_x86_caretaker_host_ops;

	if (cb_pa) {
		struct kvm_caretaker_arch_ser *abi = caretaker_pa_to_va(cb_pa);

		vcpu_load(vcpu);
		if (ops && ops->sync_vcpu)
			ops->sync_vcpu(vcpu, abi);
		vcpu_put(vcpu);
	}
}

void kvm_arch_vcpu_luo_pre_retrieve_caretaker(struct kvm_vcpu *vcpu,
					      struct kvm_vcpu_ser *ser)
{
	if (!ser || !KHOSER_LOAD_PTR(ser->cb))
		return;

	kvm_x86_caretaker_signal_attach(vcpu, ser->cb.phys);
}

void kvm_arch_vcpu_luo_attach_caretaker(struct kvm_vcpu *vcpu,
					struct kvm_vcpu_ser *ser)
{
	if (!ser || !KHOSER_LOAD_PTR(ser->cb))
		return;

	kvm_x86_caretaker_attach(vcpu, ser->cb.phys);
	kvm_caretaker_post_attach_vcpu(vcpu);
}

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

static void __cpu_preserved_text
kvm_x86_caretaker_load_desc(struct desc_struct *gdt, size_t gdt_size,
			    gate_desc *idt, size_t idt_size,
			    void *tss)
{
	struct desc_ptr gdt_desc = {
		.size = gdt_size - 1,
		.address = (unsigned long)gdt,
	};
	struct desc_ptr idt_desc = {
		.size = idt_size - 1,
		.address = (unsigned long)idt,
	};

	caretaker_set_tss_desc(gdt, (unsigned long)tss, sizeof(struct x86_hw_tss) - 1);
	asm volatile("lgdt %0" : : "m" (gdt_desc));
	native_load_idt(&idt_desc);
	asm volatile("ltr %w0" : : "q" ((u16)(GDT_ENTRY_TSS * 8)));
}

static __caretaker_text void
kvm_x86_caretaker_save_host_state(struct caretaker_x86_host_state *host,
				  struct caretaker_x86_page *cxp)
{
	struct cpu_preserved_stack_context *sctx;
	u64 apic_base;

	asm volatile("sidt %0" : "=m" (host->orig_idt));
	host->orig_cr2 = native_read_cr2();
	asm volatile("mov %%cr8, %0" : "=r" (host->orig_cr8));
	asm volatile("mov %0, %%cr8" : : "r" (0UL) : "memory");
	/*
	 * MSR_FS_BASE is in the guest-writable passthrough set below, so it
	 * has to be saved here or a guest WRMSR to it survives the run and
	 * corrupts the host's FS base.
	 */
	host->orig_fs_base = native_rdmsrq(MSR_FS_BASE);
	host->orig_gs_base = native_rdmsrq(MSR_GS_BASE);
	host->orig_kernel_gs_base = native_rdmsrq(MSR_KERNEL_GS_BASE);
	host->orig_star = native_rdmsrq(MSR_STAR);
	host->orig_lstar = native_rdmsrq(MSR_LSTAR);
	host->orig_fmask = native_rdmsrq(MSR_SYSCALL_MASK);

	/* Ensure Local APIC is software enabled */
	apic_base = native_rdmsrq(MSR_IA32_APICBASE);
	if (!(apic_base & MSR_IA32_APICBASE_ENABLE))
		native_wrmsrq(MSR_IA32_APICBASE,
			      apic_base | MSR_IA32_APICBASE_ENABLE);

	/* Switch to self-contained Caretaker GDT, IDT, and TSS before CR3 switch */
	kvm_x86_caretaker_load_desc(cxp->gdt, sizeof(cxp->gdt),
				    caretaker_x86_idt, sizeof(caretaker_x86_idt),
				    &cxp->tss);

	/* Switch to preserved CR3 if specified */
	sctx = cpu_preserved_get_stack_context();
	if (sctx && sctx->session_pgd_pa)
		cxp->host_cr3 = sctx->session_pgd_pa;
	if (cxp->host_cr3 && __native_read_cr3() != cxp->host_cr3)
		native_write_cr3(cxp->host_cr3);

	raw_local_irq_disable();
}

static __caretaker_text void
kvm_x86_caretaker_restore_host_state(const struct caretaker_x86_host_state *host,
				     int pcpu)
{
	/*
	 * Restore unconditionally.  These are all in the guest-writable
	 * passthrough set, so skipping the write when the saved value happens
	 * to be zero leaves the *guest's* value live in the host MSR.
	 */
	native_write_cr2(host->orig_cr2);
	asm volatile("mov %0, %%cr8" : : "r" (host->orig_cr8) : "memory");
	native_wrmsrq(MSR_FS_BASE, host->orig_fs_base);
	native_wrmsrq(MSR_GS_BASE, host->orig_gs_base);
	native_wrmsrq(MSR_KERNEL_GS_BASE, host->orig_kernel_gs_base);
	native_wrmsrq(MSR_LSTAR, host->orig_lstar);
	native_wrmsrq(MSR_STAR, host->orig_star);
	native_wrmsrq(MSR_SYSCALL_MASK, host->orig_fmask);

	if (cpu_is_preserved(pcpu))
		arch_cpu_preserved_load_desc();
	else if (host->orig_idt.size)
		native_load_idt(&host->orig_idt);
}

static __always_inline struct kvm_msrs *
kvm_x86_caretaker_msrs(const struct kvm_vcpu_arch_ser *state)
{
	if (!state || !state->msrs.phys)
		return NULL;
	return (struct kvm_msrs *)(state + 1);
}

__caretaker_text void
kvm_x86_caretaker_update_msr(struct kvm_vcpu_arch_ser *state,
			     u32 msr, u64 val)
{
	struct kvm_msrs *msrs = kvm_x86_caretaker_msrs(state);
	u32 i;

	if (!msrs)
		return;

	for (i = 0; i < msrs->nmsrs; i++) {
		if (msrs->entries[i].index == msr) {
			msrs->entries[i].data = val;
			return;
		}
	}
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_x86_caretaker_update_msr);

static __caretaker_text bool
kvm_x86_caretaker_read_msr(const struct kvm_vcpu_arch_ser *state,
			   u32 msr, u64 *val)
{
	const struct kvm_msrs *msrs = kvm_x86_caretaker_msrs(state);
	u32 i;

	if (!msrs)
		return false;

	for (i = 0; i < msrs->nmsrs; i++) {
		if (msrs->entries[i].index == msr) {
			*val = msrs->entries[i].data;
			return true;
		}
	}
	return false;
}

/*
 * Capture the guest FPU registers into the LUO ABI buffer.
 *
 * The Caretaker runs the guest with the guest's FPU state live in hardware,
 * restoring it via XRSTOR64 at the start of each quantum and saving it via
 * XSAVE64 at the end of each quantum and upon detach.
 *
 * XSAVE -- as opposed to XSAVES -- writes the standard, non-compacted layout,
 * which is bit-for-bit the uAPI struct kvm_xsave layout that the incoming
 * kernel feeds to fpu_copy_uabi_to_guest_fpstate().  No format conversion is
 * needed and the ABI stays uAPI.
 *
 * The requested-feature bitmap comes from the XCR0 recorded at preserve time
 * rather than from XGETBV, because XGETBV requires CR4.OSXSAVE and the guest
 * is free to clear it.  The recorded value cannot have gone stale: the
 * Caretaker never emulates XSETBV, so the guest cannot change XCR0 while it
 * runs here.
 *
 * The destination cannot overflow: kvm_arch_vcpu_luo_preserve() refuses the
 * preserve when guest_fpu.uabi_size exceeds sizeof(struct kvm_xsave), and
 * RFBM is a subset of guest_supported_xcr0, which is what uabi_size sizes.
 */
__caretaker_text static void
caretaker_save_guest_fpu(struct caretaker_x86_page *cxp,
			 struct kvm_vcpu_arch_ser *state)
{
	union fpregs_state *xstate = (union fpregs_state *)state->xsave.region;
	u64 rfbm = state->xcrs.xcrs[0].value | XFEATURE_MASK_FPSSE;

	if (!cxp->save_guest_fpu)
		return;

	if (caretaker_read_cr0() & X86_CR0_TS)
		asm volatile("clts" : : : "memory");

	/*
	 * XSAVE leaves XSTATE_BV bits for components outside RFBM untouched,
	 * so the preserve-time header would survive and advertise stale
	 * component data.  Clear it and let XSAVE set only what it writes.
	 */
	cpu_preserved_memset(&xstate->xsave.header, 0,
			     sizeof(xstate->xsave.header));

	asm volatile("1: xsave64 %[buf]\n\t"
		     "2:\n\t"
		     _ASM_EXTABLE(1b, 2b)
		     : [buf] "+m" (*xstate)
		     : "a" ((u32)rfbm), "d" ((u32)(rfbm >> 32))
		     : "memory");
}

__caretaker_text void
kvm_x86_caretaker_detach_serialize_common(struct caretaker_x86_page *cxp,
					  struct kvm_vcpu_arch_ser *state)
{
	if (!cxp || !state)
		return;

	state->regs.rax = cxp->rax;
	state->regs.rbx = cxp->rbx;
	state->regs.rcx = cxp->rcx;
	state->regs.rdx = cxp->rdx;
	state->regs.rsi = cxp->rsi;
	state->regs.rdi = cxp->rdi;
	state->regs.rbp = cxp->rbp;
	state->regs.r8  = cxp->r8;
	state->regs.r9  = cxp->r9;
	state->regs.r10 = cxp->r10;
	state->regs.r11 = cxp->r11;
	state->regs.r12 = cxp->r12;
	state->regs.r13 = cxp->r13;
	state->regs.r14 = cxp->r14;
	state->regs.r15 = cxp->r15;

	if (cxp->last_exit_rip)
		state->regs.rip = cxp->last_exit_rip;
	if (cxp->last_exit_rsp)
		state->regs.rsp = cxp->last_exit_rsp;
	if (cxp->last_exit_rflags)
		state->regs.rflags = cxp->last_exit_rflags;

	if (cxp->cr0)
		state->sregs.cr0 = cxp->cr0;
	if (cxp->cr3)
		state->sregs.cr3 = cxp->cr3;
	if (cxp->cr4)
		state->sregs.cr4 = cxp->cr4;
	if (cxp->efer)
		state->sregs.efer = cxp->efer;

	state->events.exception.injected = 0;
	state->events.interrupt.injected = 0;

	caretaker_save_guest_fpu(cxp, state);
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_x86_caretaker_detach_serialize_common);

void kvm_x86_caretaker_sync_vcpu_common(struct kvm_vcpu *vcpu)
{
	kvm_register_mark_dirty(vcpu, VCPU_REG_CR3);
	kvm_clear_interrupt_queue(vcpu);
	kvm_clear_exception_queue(vcpu);

	vcpu->cpu = -1;
	kvm_make_request(KVM_REQ_LOAD_MMU_PGD, vcpu);
	kvm_make_request(KVM_REQ_TLB_FLUSH_CURRENT, vcpu);
	kvm_make_request(KVM_REQ_RECALC_INTERCEPTS, vcpu);
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_x86_caretaker_sync_vcpu_common);

static __caretaker_text void kvm_caretaker_emulate_cpuid(u64 *rax,
							 u64 *rbx,
							 u64 *rcx,
							 u64 *rdx)
{
	unsigned int a = (unsigned int)*rax;
	unsigned int b = (unsigned int)*rbx;
	unsigned int c = (unsigned int)*rcx;
	unsigned int d = (unsigned int)*rdx;

	asm volatile("cpuid"
		     : "=a" (a), "=b" (b), "=c" (c), "=d" (d)
		     : "0" (a), "2" (c));

	*rax = a;
	*rbx = b;
	*rcx = c;
	*rdx = d;
}

static __caretaker_text bool kvm_caretaker_emulate_msr(struct caretaker_x86_page *cxp,
						       u32 msr, bool write,
						       u64 *rax,
						       u64 *rdx)
{
	bool x2apic = msr >= APIC_BASE_MSR &&
		      msr < APIC_BASE_MSR + X2APIC_MSR_COUNT;
	u32 apic_id = cxp ? cxp->abi.cb.vcpu_id : 0;
	u64 val;

	if (write) {
		val = (u32)(*rax) | ((*rdx) << 32);

		/*
		 * Guest x2APIC writes are not emulated.  ICR would send an
		 * IPI, TMICT would arm the APIC timer, and the LVT and TPR
		 * registers reprogram delivery.  The caretaker implements
		 * none of that, so absorbing the write promises the guest an
		 * interrupt that will never arrive -- it wedges rather than
		 * stalls, and it cannot tell the difference.
		 *
		 * Park instead, and let the incoming kernel's full KVM apply
		 * the write to the emulated LAPIC when it reclaims the vCPU.
		 *
		 * Exception: APIC_EOI (0x80b).  If a vCPU was caught inside an
		 * interrupt handler when detached, acknowledging EOI lets it
		 * finish the ISR and IRETQ back to user space; kvm_luo clears
		 * APIC_ISR on retrieve anyway.
		 */
		if (x2apic) {
			if (msr == APIC_BASE_MSR + (APIC_EOI >> 4))
				return true;
			return false;
		}

		switch (msr) {
		case MSR_IA32_SPEC_CTRL:
		case MSR_IA32_PRED_CMD:
			/*
			 * The guest is arming a speculation mitigation
			 * (IBRS/STIBP/SSBD, or an IBPB barrier).  The
			 * caretaker does not apply these, so acknowledging
			 * the write would leave the guest believing it is
			 * protected when it is not -- a security downgrade
			 * the guest cannot observe.
			 *
			 * Refuse the exit instead: the vCPU parks here and
			 * the incoming kernel's KVM applies the write for
			 * real when it reclaims the vCPU.
			 */
			return false;
		case MSR_IA32_TSC_DEADLINE:
			/*
			 * Record the guest's next timer deadline in preserved
			 * arch_state so full KVM restores and arms it upon
			 * reclaiming the vCPU, while allowing a guest caught
			 * in its timer ISR to return to user space.
			 */
			if (cxp && cxp->arch_state)
				kvm_x86_caretaker_update_msr(cxp->arch_state,
							     MSR_IA32_TSC_DEADLINE,
							     val);
			return true;
		case MSR_IA32_TSC:
		case MSR_IA32_TSC_ADJUST:
			/*
			 * Discarding these silently rewrites the guest's view of
			 * time.
			 */
			return false;
		case MSR_KERNEL_GS_BASE:
			/* Also cached, so the read side can answer without an rdmsr. */
			if (cxp)
				cxp->kernel_gs_base = val;
			fallthrough;
		case MSR_FS_BASE:
		case MSR_GS_BASE:
		case MSR_LSTAR:
		case MSR_STAR:
		case MSR_SYSCALL_MASK:
			native_wrmsrq(msr, val);
			return true;
		case MSR_IA32_APICBASE:
			/*
			 * This used to be passed through to native_wrmsrq(),
			 * which let the guest relocate or disable the *physical*
			 * APIC of the CPU the caretaker is running on.  Nothing
			 * saved or restored it around the run, so the damage
			 * outlived the guest: on the "staying in this kernel"
			 * path there is no INIT-SIPI-SIPI to clean up after.
			 *
			 * APIC base is host state here.  Refuse the write.
			 */
			return false;
		}
		return false;
	}

	if (x2apic) {
		switch ((msr - APIC_BASE_MSR) << 4) {
		case APIC_ID:
			val = apic_id;
			break;
		case APIC_LVR:
			val = CARETAKER_APIC_LVR;
			break;
		case APIC_SPIV:
			val = APIC_SPIV_APIC_ENABLED | APIC_VECTOR_MASK;
			break;
		case APIC_LDR:
			val = ((apic_id >> 4) << 16) | (1U << (apic_id & 0xf));
			break;
		default:
			/*
			 * ICR, IRR, ISR, TMCCT and friends.  Zero reads as
			 * "nothing pending" or "timer already expired", which
			 * the guest cannot distinguish from the truth.  The four
			 * cases above are answered because they are static
			 * identity registers whose values really are known.
			 */
			return false;
		}
		goto out;
	}

	switch (msr) {
	case MSR_IA32_SPEC_CTRL:
		/*
		 * Returning 0 here would tell the guest its speculation
		 * mitigations are disabled, which is both wrong and
		 * unobservable.  Park instead; see the write path above.
		 */
		return false;
	case MSR_IA32_TSC:
		val = rdtsc();
		break;
	case MSR_IA32_TSC_DEADLINE:
		if (cxp && kvm_x86_caretaker_read_msr(cxp->arch_state,
						      MSR_IA32_TSC_DEADLINE,
						      &val))
			break;
		return false;
	case MSR_IA32_TSC_ADJUST:
		return false;
	case MSR_KERNEL_GS_BASE:
		if (cxp && cxp->kernel_gs_base)
			val = cxp->kernel_gs_base;
		else
			val = native_rdmsrq(MSR_KERNEL_GS_BASE);
		break;
	case MSR_IA32_APICBASE:
		val = native_rdmsrq(MSR_IA32_APICBASE);
		if (!val)
			val = APIC_DEFAULT_PHYS_BASE | MSR_IA32_APICBASE_ENABLE;
		if (cxp && apic_id == 0)
			val |= MSR_IA32_APICBASE_BSP;
		else
			val &= ~MSR_IA32_APICBASE_BSP;
		break;
	case MSR_FS_BASE:
	case MSR_GS_BASE:
	case MSR_LSTAR:
	case MSR_STAR:
	case MSR_SYSCALL_MASK:
		val = native_rdmsrq(msr);
		break;
	default:
		return false;
	}

out:
	*rax = (u32)val;
	*rdx = (u32)(val >> 32);
	return true;
}

static bool __cpu_preserved_text
kvm_x86_caretaker_emulate_uart8250(struct caretaker_uart *uart,
				   u16 port, int in, int size,
				   unsigned long *rax)
{
	u8 offset;

	if (port < COM1_PORT_BASE || port > COM1_PORT_END)
		return false;

	offset = port - COM1_PORT_BASE;

	if (in) {
		unsigned long val = 0;

		switch (offset) {
		case UART_RX:
			val = (uart && (uart->lcr & UART_LCR_DLAB)) ? uart->dll : 0;
			break;
		case UART_IER:
			val = (uart && (uart->lcr & UART_LCR_DLAB)) ? uart->dlm :
				(uart ? uart->ier : 0);
			break;
		case UART_IIR:
			val = UART_IIR_NO_INT;
			break;
		case UART_LCR:
			val = uart ? uart->lcr : UART_LCR_WLEN8;
			break;
		case UART_MCR:
			val = uart ? uart->mcr : (UART_MCR_DTR | UART_MCR_RTS);
			break;
		case UART_LSR:
			val = UART_LSR_TEMT | UART_LSR_THRE;
			break;
		case UART_MSR:
			val = UART_MSR_DCD | UART_MSR_DSR | UART_MSR_CTS;
			break;
		case UART_SCR:
			val = uart ? uart->scr : 0;
			break;
		}

		if (size < (int)sizeof(unsigned long)) {
			unsigned long mask = (1UL << (size * 8)) - 1;
			*rax = (*rax & ~mask) | (val & mask);
		} else {
			*rax = val;
		}
	} else {
		u8 out_val = (u8)*rax;

		if (uart) {
			switch (offset) {
			case UART_TX:
				if (uart->lcr & UART_LCR_DLAB)
					uart->dll = out_val;
				break;
			case UART_IER:
				if (uart->lcr & UART_LCR_DLAB)
					uart->dlm = out_val;
				else
					uart->ier = out_val;
				break;
			case UART_LCR:
				uart->lcr = out_val;
				break;
			case UART_MCR:
				uart->mcr = out_val;
				break;
			case UART_SCR:
				uart->scr = out_val;
				break;
			}
		}
	}

	return true;
}
STACK_FRAME_NON_STANDARD(kvm_x86_caretaker_emulate_uart8250);

__caretaker_text bool
kvm_x86_caretaker_handle_exit(void *data, struct kvm_caretaker_exit *exit)
{
	struct caretaker_x86_page *cxp = data;
	bool handled = false;

	if (exit->type == KVM_CARETAKER_EXIT_CROSS_VCPU) {
		/*
		 * x86 has no cross-vCPU emulation.  The decoders route
		 * VMCALL, APIC_ACCESS, APIC_WRITE, EOI_INDUCED and
		 * INTERRUPT_WINDOW here, and every one of them has a
		 * guest-visible effect the Caretaker cannot produce: a
		 * hypercall it cannot service, an APIC register write it
		 * cannot apply, an EOI it cannot retire, an IPI it cannot
		 * deliver to a vCPU parked on another core.
		 *
		 * Returning true absorbed all of it.  Worse, nothing
		 * advanced RIP afterwards, so VMCALL re-executed forever.
		 *
		 * Stall instead.  The vCPU parks on the instruction and the
		 * incoming kernel's full KVM emulates it properly.  arm64
		 * does handle its CROSS_VCPU case (SGI delivery) and keeps
		 * returning true.
		 */
		return false;
	}

	switch ((int)exit->type) {
	case KVM_CARETAKER_EXIT_CONSOLE: {
		unsigned long *target = exit->mmio_io.val_ptr ?
					(unsigned long *)exit->mmio_io.val_ptr :
					(unsigned long *)&exit->mmio_io.val;

		handled = kvm_x86_caretaker_emulate_uart8250(&cxp->uart,
							     (u16)exit->mmio_io.addr,
							     !exit->mmio_io.is_write,
							     exit->mmio_io.size,
							     target);
		break;
	}
	case KVM_CARETAKER_EXIT_CPUID:
		kvm_caretaker_emulate_cpuid(&cxp->rax, &cxp->rbx, &cxp->rcx, &cxp->rdx);
		handled = true;
		break;
	case KVM_CARETAKER_EXIT_MSR:
		handled = kvm_caretaker_emulate_msr(cxp, exit->msr.msr, exit->msr.is_write,
						    &cxp->rax, &cxp->rdx);
		break;
	case KVM_CARETAKER_EXIT_RDTSC: {
		u64 tsc = rdtsc();

		cxp->rax = (u32)tsc;
		cxp->rdx = (u32)(tsc >> 32);
		handled = true;
		break;
	}
	case KVM_CARETAKER_EXIT_INSN_STEP:
		handled = true;
		break;
	case KVM_CARETAKER_EXIT_ARCH:
	default:
		/*
		 * Nothing above recognised this exit, so nothing emulated it.
		 * Advancing RIP here would step over an instruction whose
		 * architectural effect never happened (MOV to CRn, XSETBV,
		 * INVLPG, WBINVD, RDPMC, ...), leaving the guest running on
		 * silently wrong state with no way to detect it.
		 *
		 * Report the exit as unhandled instead.  The caretaker run
		 * loop stops re-entering the guest and the vCPU stays parked
		 * on this instruction until the incoming kernel reclaims it
		 * and full KVM emulates the exit properly.
		 */
		return false;
	}

	if (handled)
		exit->rip += exit->insn_len;

	return handled;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_x86_caretaker_handle_exit);

__caretaker_text static void
caretaker_restore_guest_fpu(struct caretaker_x86_page *cxp,
			    struct kvm_vcpu_arch_ser *state)
{
	union fpregs_state *xstate;
	u64 rfbm;

	if (!cxp || !state || !cxp->save_guest_fpu)
		return;

	xstate = (union fpregs_state *)state->xsave.region;
	rfbm = state->xcrs.xcrs[0].value | XFEATURE_MASK_FPSSE;

	if (caretaker_read_cr0() & X86_CR0_TS)
		asm volatile("clts" : : : "memory");

	asm volatile("1: xrstor64 %[buf]\n\t"
		     "2:\n\t"
		     _ASM_EXTABLE(1b, 2b)
		     :
		     : [buf] "m" (*xstate),
		       "a" ((u32)rfbm), "d" ((u32)(rfbm >> 32))
		     : "memory");
}

STACK_FRAME_NON_STANDARD(kvm_x86_caretaker_run_page);

static enum oncore_exit_reason __cpu_preserved_text
kvm_x86_caretaker_run_page(struct caretaker_x86_page *cxp, u64 deadline_ticks)
{
	const struct kvm_x86_caretaker_runtime_ops *ops = kvm_x86_caretaker_ops;
	enum oncore_exit_reason reason = ONCORE_EXIT_QUANTUM_EXPIRED;
	struct cpu_preserved_stack_context *sctx;
	struct caretaker_x86_host_state host_state;
	int pcpu;

	if (!cxp || !ops)
		return ONCORE_EXIT_ERROR;

	sctx = cpu_preserved_get_stack_context();
	if (sctx && sctx->cpu >= 0 && sctx->cpu < CONFIG_NR_CPUS)
		pcpu = sctx->cpu;
	else
		pcpu = cxp->abi.cb.pcpu_id;
	cxp->abi.cb.pcpu_id = pcpu;

	if (cpu_preserved_cmpxchg32(&cxp->abi.cb.state, KVM_CARETAKER_PAUSED,
				    KVM_CARETAKER_RUNNING) != KVM_CARETAKER_PAUSED ||
	    kvm_caretaker_should_exit(&cxp->vcpu)) {
		smp_mb(); /* Order serialized state before STOPPED */
		WRITE_ONCE(cxp->abi.cb.state, KVM_CARETAKER_STOPPED);
		return ONCORE_EXIT_ATTACH_SIGNALED;
	}

	/* Save host context, switch to Caretaker descriptors and CR3 */
	kvm_x86_caretaker_save_host_state(&host_state, cxp);

	if (cxp->arch_state)
		caretaker_restore_guest_fpu(cxp, cxp->arch_state);

	cxp->vcpu.ops = &ops->common;

	reason = kvm_caretaker_vcpu_run(&cxp->vcpu, deadline_ticks);

	iret_to_self();

	if (ops->detach_serialize && cxp->arch_state)
		ops->detach_serialize(cxp, cxp->arch_state);

	kvm_x86_caretaker_restore_host_state(&host_state, pcpu);

	if (reason == ONCORE_EXIT_ATTACH_SIGNALED ||
	    kvm_caretaker_should_exit(&cxp->vcpu) ||
	    cpu_preserved_cmpxchg32(&cxp->abi.cb.state, KVM_CARETAKER_RUNNING,
				    KVM_CARETAKER_PAUSED) != KVM_CARETAKER_RUNNING) {
		reason = ONCORE_EXIT_ATTACH_SIGNALED;
		smp_mb(); /* Order serialized state before STOPPED */
		WRITE_ONCE(cxp->abi.cb.state, KVM_CARETAKER_STOPPED);
	}

	return reason;
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

void kvm_arch_vcpu_caretaker_unpreserve(struct kvm_vcpu_ser *ser)
{
	if (ser->cb.phys) {
		struct kvm_caretaker_arch_ser *abi = caretaker_pa_to_va(ser->cb.phys);

		kvm_x86_caretaker_unpreserve_pages(abi);
		kho_unpreserve_free(abi);
		ser->cb.phys = 0;
	}
}

void kvm_arch_vcpu_caretaker_finish(struct kvm_vcpu_ser *ser)
{
	if (ser->cb.phys) {
		struct kvm_caretaker_arch_ser *abi = caretaker_pa_to_va(ser->cb.phys);
		u32 i;

		for (i = 0; i < abi->nr_preserved_pages; i++) {
			phys_addr_t pa = __sme_clr(abi->preserved_pages_pa[i]);
			struct page *page = kho_restore_pages(pa, 1);

			if (page)
				__free_pages(page, 0);
		}
		abi->nr_preserved_pages = 0;
		kho_restore_free(abi);
		ser->cb.phys = 0;
	}
}

int kvm_arch_vm_luo_freeze(struct kvm *kvm, struct kvm_luo_ser *ser)
{
	int ret;

	/*
	 * Shadow/TDP page tables are a VM-wide resource: an orphaned vCPU keeps
	 * running the guest out of them while the VM is detached, so they must
	 * survive the kexec.  Preserve them at freeze time when all vCPUs are
	 * detached from KVM_RUN and the MMU is quiescent.
	 */
	ret = kvm_mmu_preserve_kho(kvm);
	if (ret)
		return ret;

	KHOSER_STORE_PTR(ser->kho_folios, kvm->kho_folios);
	return 0;
}
