// SPDX-License-Identifier: GPL-2.0
/*
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
#include <asm/cpu_preserve.h>
#include <asm/desc.h>
#include <asm/fixmap.h>
#include <asm/irq_vectors.h>
#include <asm/kvm_host.h>
#include <asm/msr.h>
#include <asm/sync_core.h>
#include <asm/trapnr.h>
#include <asm/virt.h>

#include "caretaker.h"
#include "cpuid.h"
#include "lapic.h"
#include "regs.h"
#include "x86.h"

/* Host register state saved around an on-core caretaker run. */
struct caretaker_x86_host_state {
	struct desc_ptr orig_gdt;
	struct desc_ptr orig_idt;
	unsigned long orig_cr3;
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
kvm_x86_caretaker_run_page(struct caretaker_x86_page *cxp,
			   struct kvm_vcpu *vcpu, u64 deadline_ticks);

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
cxp_from_cb(struct kvm_caretaker_cb *cb)
{
	return container_of(cb, struct caretaker_x86_page, cb);
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

enum oncore_exit_reason __cpu_preserved_text
kvm_arch_vcpu_caretaker_run(void *data, u64 deadline_ticks)
{
	struct kvm_caretaker_cb *cb = data;

	/*
	 * @data is always a struct kvm_caretaker_cb: kvm_caretaker_vcpu_preserve()
	 * installs it with oncore_job_set_data() before activating the job.  It
	 * is NULL only for a vCPU that never obtained a caretaker page, in which
	 * case there is nothing to run -- just hold the core until the quantum
	 * expires.
	 */
	if (!cb) {
		while (arch_oncore_read_counter() < deadline_ticks)
			cpu_relax();
		return ONCORE_EXIT_QUANTUM_EXPIRED;
	}

	return kvm_x86_caretaker_run_page(cxp_from_cb(cb), NULL, deadline_ticks);
}

void kvm_arch_vcpu_caretaker_init(struct kvm_vcpu *vcpu)
{
	if (kvm_x86_caretaker_ops && kvm_x86_caretaker_ops->init)
		kvm_x86_caretaker_ops->init(vcpu);
}

static void kvm_x86_caretaker_signal_attach_common(struct kvm_vcpu *vcpu,
						   struct kvm_caretaker_cb *cb,
						   u32 fallback_apic_id,
						   u32 *running,
						   const char *vendor_name)
{
	int target_pcpu;
	u32 apic_id;

	if (!cb)
		return;

	target_pcpu = cb->pcpu_id;

	if (READ_ONCE(cb->attachment_state) == KVM_CARETAKER_ATTACHED ||
	    READ_ONCE(cb->attachment_state) == KVM_CARETAKER_ATTACHING ||
	    target_pcpu < 0 || target_pcpu >= nr_cpu_ids ||
	    target_pcpu == raw_smp_processor_id() ||
	    cpu_online(target_pcpu)) {
		return;
	}

	/*
	 * If vCPU is not currently running on physical silicon, its
	 * register state is already completely saved.
	 */
	if (running && !READ_ONCE(*running)) {
		WRITE_ONCE(cb->attachment_state, KVM_CARETAKER_ATTACHING);
		/* Ensure attaching state write is committed */
		smp_wmb();
		if (vcpu)
			vcpu->cpu = -1;
		return;
	}

	apic_id = apic->cpu_present_to_apicid(target_pcpu);
	if (apic_id == BAD_APICID) {
		apic_id = arch_cpu_preserved_get_apicid(target_pcpu);
		if (apic_id == BAD_APICID)
			apic_id = cpuid_to_apicid[target_pcpu];
		if (apic_id == BAD_APICID)
			apic_id = fallback_apic_id ? fallback_apic_id : target_pcpu;
	}

	if (apic_id != BAD_APICID && apic_id != (u32)-1 && apic_id != 0)
		per_cpu(x86_cpu_to_apicid, target_pcpu) = apic_id;

	kvm_caretaker_wait_for_attach(cb, target_pcpu, NULL);

	if (vcpu)
		vcpu->cpu = -1;
}

static void kvm_x86_caretaker_signal_attach(struct kvm_vcpu *vcpu, u64 cb_pa)
{
	const struct kvm_x86_caretaker_ops *ops = kvm_x86_caretaker_ops;

	if (cb_pa) {
		struct kvm_x86_caretaker_abi *abi = caretaker_pa_to_va(cb_pa);

		if (ops && ops->signal_attach)
			ops->signal_attach(vcpu, &abi->cb);

		kvm_x86_caretaker_signal_attach_common(vcpu, &abi->cb, abi->apic_id,
						      &abi->running,
						      ops ? ops->name : "x86");
	}
}

static void kvm_x86_caretaker_attach(struct kvm_vcpu *vcpu, u64 cb_pa)
{
	const struct kvm_x86_caretaker_ops *ops = kvm_x86_caretaker_ops;

	if (cb_pa) {
		struct kvm_x86_caretaker_abi *abi = caretaker_pa_to_va(cb_pa);

		vcpu_load(vcpu);
		if (ops && ops->common.sync_vcpu)
			ops->common.sync_vcpu(vcpu, abi);
		vcpu_put(vcpu);
	}
}

void kvm_arch_vcpu_luo_pre_retrieve_caretaker(struct kvm_vcpu *vcpu,
					      struct kvm_vcpu_luo_ser *ser)
{
	if (!ser || !ser->cb.phys || !(ser->flags & KVM_VCPU_LUO_FLAG_CARETAKER))
		return;

	kvm_x86_caretaker_signal_attach(vcpu, ser->cb.phys);
}

void kvm_arch_vcpu_luo_attach_caretaker(struct kvm_vcpu *vcpu,
					struct kvm_vcpu_luo_ser *ser)
{
	if (!ser || !ser->cb.phys || !(ser->flags & KVM_VCPU_LUO_FLAG_CARETAKER))
		return;

	kvm_x86_caretaker_attach(vcpu, ser->cb.phys);
	kvm_caretaker_post_attach_vcpu(vcpu, NULL);
}

static bool caretaker_x86_has_tsc_deadline __cpu_preserved_data;
static u32 caretaker_x86_lapic_timer_period __cpu_preserved_data;

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

int kvm_x86_caretaker_init_common_page(struct caretaker_x86_page *cxp,
				       struct kvm_vcpu *vcpu,
				       size_t full_page_size)
{
	int pcpu;
	u32 apic_id;
	int ret;

	if (!cxp || !vcpu)
		return -EINVAL;

	caretaker_x86_has_tsc_deadline = boot_cpu_has(X86_FEATURE_TSC_DEADLINE_TIMER);
	caretaker_x86_lapic_timer_period = lapic_timer_period;
	cpu_preserved_clean(&caretaker_x86_has_tsc_deadline);
	cpu_preserved_clean(&caretaker_x86_lapic_timer_period);

	memset(cxp, 0, full_page_size);

	kvm_caretaker_init_common_vcpu(&cxp->vcpu, vcpu, cxp, full_page_size,
				       NULL, cxp);

	pcpu = cxp->cb.pcpu_id;
	cxp->pcpu_id = pcpu;

	cxp->stack_top = (u64)&cxp->stack[CXP_STACK_SIZE];
	cxp->deadline_tsc = 0;

	apic_id = apic->cpu_present_to_apicid(pcpu);
	if (apic_id == BAD_APICID)
		apic_id = pcpu;
	cxp->apic_id = apic_id;

	kvm_x86_caretaker_init_uart(&cxp->uart);

	/* Capture guest GPRs */
	kvm_x86_caretaker_save_gprs(vcpu, &cxp->rax);

	/* Preserved CR3 from session or fallback to global cpu_preserve page table */
	{
		struct oncore_session *sess = vcpu->caretaker.job ?
						 vcpu->caretaker.job->session : NULL;

		phys_addr_t pgd_pa = oncore_session_get_pgd_pa(sess);

		if (pgd_pa)
			cxp->host_cr3 = pgd_pa;
		else
			cxp->host_cr3 = x86_caretaker_pgd_pa;
	}
	cxp->cr3 = kvm_read_cr3(vcpu);
	cxp->cr0 = kvm_read_cr0(vcpu);
	cxp->cr4 = kvm_read_cr4(vcpu);
	cxp->efer = vcpu->arch.efer;

	/* Build KHO-preserved Host GDT and TSS */
	kvm_x86_caretaker_init_gdt_tss(cxp->gdt, &cxp->tss, cxp->stack_top);

	/* Build KHO-preserved IDT */
	kvm_x86_caretaker_init_idt(cxp->idt);

	/* Preserve in-kernel local APIC register page across kexec */
	if (vcpu->arch.apic && vcpu->arch.apic->regs) {
		ret = kho_preserve_pages(virt_to_page(vcpu->arch.apic->regs), 1);
		if (ret)
			return ret;
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

	oncore_memcpy(gdt, get_current_gdt_ro(), sizeof(struct desc_struct) * GDT_ENTRIES);
	oncore_memset(tss, 0, sizeof(*tss));
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
	load_gdt(&gdt_desc);
	native_load_idt(&idt_desc);
	asm volatile("ltr %w0" : : "q" ((u16)(GDT_ENTRY_TSS * 8)));
}

static void __cpu_preserved_text
kvm_x86_caretaker_restore_host_desc(int pcpu, const struct desc_ptr *orig_idt)
{
	load_direct_gdt(pcpu);
	{
		struct desc_struct *gdt = get_cpu_gdt_rw(pcpu);
		tss_desc tss = *(tss_desc *)&gdt[GDT_ENTRY_TSS];

		tss.type = DESC_TSS;
		write_gdt_entry(gdt, GDT_ENTRY_TSS, &tss, DESC_TSS);
	}
	load_TR_desc();
	load_fixmap_gdt(pcpu);
	if (orig_idt)
		native_load_idt(orig_idt);
}

static __caretaker_text void
kvm_x86_caretaker_save_host_state(struct caretaker_x86_host_state *host,
				  struct caretaker_x86_page *cxp)
{
	native_store_gdt(&host->orig_gdt);
	store_idt(&host->orig_idt);
	host->orig_cr3 = __read_cr3();
	host->orig_gs_base = native_rdmsrq(MSR_GS_BASE);
	host->orig_kernel_gs_base = native_rdmsrq(MSR_KERNEL_GS_BASE);
	host->orig_star = native_rdmsrq(MSR_STAR);
	host->orig_lstar = native_rdmsrq(MSR_LSTAR);
	host->orig_fmask = native_rdmsrq(MSR_SYSCALL_MASK);

	/* Ensure Local APIC is software enabled */
	{
		u64 apic_base;

		apic_base = native_rdmsrq(MSR_IA32_APICBASE);
		if (!(apic_base & MSR_IA32_APICBASE_ENABLE))
			native_wrmsrq(MSR_IA32_APICBASE,
				      apic_base | MSR_IA32_APICBASE_ENABLE);
	}

	/* Switch to self-contained Caretaker GDT, IDT, and TSS before CR3 switch */
	kvm_x86_caretaker_load_desc(cxp->gdt, sizeof(cxp->gdt),
				    cxp->idt, sizeof(cxp->idt),
				    &cxp->tss);

	/* Switch to preserved CR3 if specified */
	{
		struct cpu_preserved_stack_context *sctx = oncore_get_current_context();

		if (sctx && sctx->session_pgd_pa)
			cxp->host_cr3 = sctx->session_pgd_pa;
		else if (!cxp->host_cr3 && x86_caretaker_pgd_pa)
			cxp->host_cr3 = x86_caretaker_pgd_pa;
	}
	if (cxp->host_cr3 && host->orig_cr3 != cxp->host_cr3)
		write_cr3(cxp->host_cr3);

	raw_local_irq_disable();
}

static __caretaker_text void
kvm_x86_caretaker_restore_host_state(const struct caretaker_x86_host_state *host,
				     const struct caretaker_x86_page *cxp,
				     struct kvm_vcpu *vcpu, int pcpu)
{
	/*
	 * Restore host CPU descriptor/page tables only when
	 * remaining in the current kernel context. If attaching across
	 * kexec to an incoming kernel, the pre-kexec host descriptors
	 * and page tables are obsolete and must not be restored.
	 */
	native_wrmsrq(MSR_GS_BASE, host->orig_gs_base);
	native_wrmsrq(MSR_KERNEL_GS_BASE, host->orig_kernel_gs_base);
	if (host->orig_lstar)
		native_wrmsrq(MSR_LSTAR, host->orig_lstar);
	if (host->orig_star)
		native_wrmsrq(MSR_STAR, host->orig_star);
	if (host->orig_fmask)
		native_wrmsrq(MSR_SYSCALL_MASK, host->orig_fmask);

	if (vcpu && !cpu_is_preserved(pcpu) && !cpu_preserved_is_incoming(pcpu)) {
		if (host->orig_cr3 && host->orig_cr3 != cxp->host_cr3)
			write_cr3(host->orig_cr3);

		kvm_x86_caretaker_restore_host_desc(pcpu, &host->orig_idt);
	} else if (cpu_is_preserved(pcpu)) {
		arch_cpu_preserved_load_desc();
	} else if (host->orig_idt.size) {
		native_load_idt(&host->orig_idt);
	}
}

__caretaker_text void
kvm_x86_caretaker_update_msr(struct kvm_vcpu_arch_luo_state *state,
			     u32 msr, u64 val)
{
	u32 i;

	for (i = 0; i < state->num_msrs; i++) {
		if (state->msrs[i].index == msr) {
			state->msrs[i].data = val;
			return;
		}
	}
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_x86_caretaker_update_msr);

__caretaker_text void
kvm_x86_caretaker_detach_serialize_common(struct caretaker_x86_page *cxp,
					  struct kvm_vcpu_arch_luo_state *state)
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
	u32 apic_id = cxp ? cxp->cb.vcpu_id : 0;
	u64 val;

	if (write) {
		val = (u32)(*rax) | ((*rdx) << 32);

		/* Absorb guest x2APIC writes in Caretaker mode */
		if (x2apic)
			return true;

		switch (msr) {
		case MSR_IA32_TSC:
		case MSR_IA32_TSC_DEADLINE:
		case MSR_IA32_TSC_ADJUST:
		case MSR_IA32_SPEC_CTRL:
		case MSR_IA32_PRED_CMD:
			/* Discarded: the caretaker owns these while detached. */
			return true;
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
		case MSR_IA32_APICBASE:
			native_wrmsrq(msr, val);
			return true;
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
			val = 0;
			break;
		}
		goto out;
	}

	switch (msr) {
	case MSR_IA32_TSC:
		val = rdtsc();
		break;
	case MSR_IA32_TSC_DEADLINE:
	case MSR_IA32_TSC_ADJUST:
	case MSR_IA32_SPEC_CTRL:
		val = 0;
		break;
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
