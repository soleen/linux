// SPDX-License-Identifier: GPL-2.0
/*
 * x86 KVM Caretaker execution loop and hardware virtualization attachment.
 */

#include <linux/kvm_host.h>
#include <linux/caretaker.h>
#include <linux/cpu.h>
#include <linux/smp.h>
#include <linux/delay.h>
#include <linux/kho/abi/kvm.h>
#include <linux/cpu_preserve.h>
#include <asm/virt.h>
#include <asm/kvm_host.h>
#include <asm/desc.h>
#include <asm/cpu_entry_area.h>
#include <asm/apic.h>
#include <asm/fixmap.h>
#include <asm/irq_vectors.h>
#include <asm/sync_core.h>
#include "caretaker.h"
#include "cpuid.h"
#include "x86.h"

static_assert(offsetof(struct caretaker_x86_page, running) == CXP_RESERVED);
static_assert(offsetof(struct caretaker_x86_page, hw_ctrl_pa) == CXP_HW_CTRL_PA);
static_assert(offsetof(struct caretaker_x86_page, pcpu_id) == CXP_PCPU_ID);
static_assert(offsetof(struct caretaker_x86_page, stack_orig) == CXP_STACK_ORIG);
static_assert(offsetof(struct caretaker_x86_page, stack_top) == CXP_STACK_TOP);
static_assert(offsetof(struct caretaker_x86_page, total_exits) == CXP_TOTAL_EXITS);
static_assert(offsetof(struct caretaker_x86_page, rax) == CXP_REG_RAX);
static_assert(offsetof(struct caretaker_x86_page, r15) == CXP_REG_R15);
static_assert(offsetof(struct caretaker_x86_page, last_exit_code) == CXP_LAST_EXIT_CODE);
static_assert(offsetof(struct caretaker_x86_page, last_exit_qual) == CXP_LAST_EXIT_QUAL);
static_assert(offsetof(struct caretaker_x86_page, last_exit_intr_info) == CXP_LAST_EXIT_INTR_INFO);
static_assert(offsetof(struct caretaker_x86_page, last_exit_rip) == CXP_LAST_EXIT_RIP);
static_assert(offsetof(struct caretaker_x86_page, last_exit_rsp) == CXP_LAST_EXIT_RSP);
static_assert(offsetof(struct caretaker_x86_page, last_exit_rflags) == CXP_LAST_EXIT_RFLAGS);
static_assert(offsetof(struct caretaker_x86_page, host_cr3) == CXP_HOST_CR3);
static_assert(offsetof(struct caretaker_x86_page, cr3) == CXP_CR3);
static_assert(offsetof(struct caretaker_x86_page, loop_entries) == CXP_LOOP_ENTRIES);
static_assert(offsetof(struct caretaker_x86_page, vmentry_entries) == CXP_VMENTRY_ENTRIES);
static_assert(offsetof(struct caretaker_x86_page, apic_eoi_va) == CXP_APIC_EOI_VA);
static_assert(offsetof(struct caretaker_x86_page, apic_lvtt_va) == CXP_APIC_LVTT_VA);
static_assert(offsetof(struct caretaker_x86_page, kernel_gs_base) == CXP_KERNEL_GS_BASE);
static_assert(offsetof(struct caretaker_x86_page, orig_cr3) == CXP_ORIG_CR3);
static_assert(offsetof(struct caretaker_x86_page, deadline_tsc) == CXP_DEADLINE_TSC);
static_assert(offsetof(struct caretaker_x86_page, apic_id) == CXP_APIC_ID);
static_assert(offsetof(struct caretaker_x86_page, hsave_pa) == CXP_HSAVE_PA);
static_assert(offsetof(struct caretaker_x86_page, uart) == CXP_UART);
static_assert(offsetof(struct caretaker_x86_page, gdt) == CXP_GDT_BASE);
static_assert(offsetof(struct caretaker_x86_page, tss) == CXP_TSS_BASE);
static_assert(offsetof(struct caretaker_x86_page, stack) == CXP_STACK_OFFSET);
static_assert(offsetof(struct caretaker_x86_page, idt) == CXP_IDT_BASE);
static_assert(sizeof(struct caretaker_x86_page) == 0x3000);

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


enum caretaker_exit_reason __cpu_preserved_text
kvm_arch_vcpu_caretaker_run(void *data, u64 deadline_ticks)
{
	if (!data) {
		while (arch_caretaker_read_counter() < deadline_ticks)
			cpu_relax();
		return CARETAKER_EXIT_QUANTUM_EXPIRED;
	}
	if (kvm_x86_caretaker_ops && kvm_x86_caretaker_ops->run_job)
		return kvm_x86_caretaker_ops->run_job(data, deadline_ticks);

	return CARETAKER_EXIT_ERROR;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vcpu_caretaker_run);

void *kvm_arch_vcpu_caretaker_data(struct kvm_vcpu *vcpu)
{
	if (!vcpu || !vcpu->arch.cb_pa)
		return NULL;
	return phys_to_virt(__sme_clr(vcpu->arch.cb_pa));
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vcpu_caretaker_data);

u32 kvm_arch_luo_vm_type(struct kvm *kvm)
{
	return kvm->arch.vm_type;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_luo_vm_type);

void kvm_arch_vcpu_caretaker_init(struct kvm_vcpu *vcpu, u64 *cb_pa)
{
	if (cb_pa)
		*cb_pa = 0;
	if (kvm_x86_caretaker_ops && kvm_x86_caretaker_ops->init)
		kvm_x86_caretaker_ops->init(vcpu, cb_pa);
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vcpu_caretaker_init);

void kvm_x86_caretaker_signal_attach_common(struct kvm_vcpu *vcpu,
					    struct caretaker_cb *cb,
					    u32 fallback_apic_id,
					    volatile u32 *running,
					    const char *vendor_name)
{
	int target_pcpu;
	u32 apic_id;

	if (!cb)
		return;

	target_pcpu = cb->pcpu_id;

	if (READ_ONCE(cb->attachment_state) == CARETAKER_KVM_ATTACHED ||
	    READ_ONCE(cb->attachment_state) == CARETAKER_KVM_ATTACHING ||
	    target_pcpu < 0 || target_pcpu >= nr_cpu_ids ||
	    target_pcpu == raw_smp_processor_id() ||
	    cpu_online(target_pcpu))
		return;

	/*
	 * If vCPU is not currently running on physical silicon, its
	 * register state is already completely saved.
	 */
	if (running && !READ_ONCE(*running)) {
		WRITE_ONCE(cb->attachment_state, CARETAKER_KVM_ATTACHING);
		smp_wmb();
		if (vcpu)
			vcpu->cpu = -1;
		return;
	}

	apic_id = apic->cpu_present_to_apicid(target_pcpu);
	if (apic_id == BAD_APICID) {
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
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_x86_caretaker_signal_attach_common);

static void kvm_arch_vcpu_caretaker_signal_attach(struct kvm_vcpu *vcpu, u64 cb_pa)
{
	if (kvm_x86_caretaker_ops && kvm_x86_caretaker_ops->signal_attach)
		kvm_x86_caretaker_ops->signal_attach(vcpu, cb_pa);
}

static void kvm_arch_vcpu_caretaker_attach(struct kvm_vcpu *vcpu, u64 cb_pa)
{
	if (kvm_x86_caretaker_ops && kvm_x86_caretaker_ops->attach)
		kvm_x86_caretaker_ops->attach(vcpu, cb_pa);
}

void kvm_arch_vcpu_luo_attach_caretaker(struct kvm_vcpu *vcpu,
					struct kvm_vcpu_luo_ser *ser)
{
	if (!ser || !ser->cb.phys || !(ser->flags & KVM_VCPU_LUO_FLAG_CARETAKER))
		return;

	kvm_arch_vcpu_caretaker_signal_attach(vcpu, ser->cb.phys);
	kvm_arch_vcpu_caretaker_attach(vcpu, ser->cb.phys);
	kvm_caretaker_post_attach_vcpu(vcpu, NULL);
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_arch_vcpu_luo_attach_caretaker);

#include <asm/msr.h>
#include "regs.h"

static bool caretaker_x86_has_tsc_deadline __cpu_preserved_data;
static u32 caretaker_x86_lapic_timer_period __cpu_preserved_data;

void kvm_x86_caretaker_init_common_page(struct caretaker_x86_page *cxp,
					struct kvm_vcpu *vcpu,
					size_t full_page_size)
{
	int pcpu = (vcpu && vcpu->cb.pcpu_id != CARETAKER_INVALID_PCPU &&
		    vcpu->cb.pcpu_id < nr_cpu_ids) ?
		   vcpu->cb.pcpu_id :
		   (vcpu && vcpu->cpu >= 0 && vcpu->cpu < nr_cpu_ids ?
		    vcpu->cpu : 0);
	u32 apic_id;

	if (!cxp || !vcpu)
		return;

	caretaker_x86_has_tsc_deadline = boot_cpu_has(X86_FEATURE_TSC_DEADLINE_TIMER);
	caretaker_x86_lapic_timer_period = lapic_timer_period;
	arch_cpu_preserved_dcache_clean((unsigned long)&caretaker_x86_has_tsc_deadline,
					(unsigned long)&caretaker_x86_has_tsc_deadline + sizeof(bool));
	arch_cpu_preserved_dcache_clean((unsigned long)&caretaker_x86_lapic_timer_period,
					(unsigned long)&caretaker_x86_lapic_timer_period + sizeof(u32));

	memset(cxp, 0, full_page_size);

	kvm_caretaker_init_common_vcpu(&cxp->vcpu, vcpu, cxp, full_page_size,
				       NULL, cxp);

	cxp->pcpu_id = pcpu;

	cxp->stack_top = (u64)&cxp->stack[CXP_STACK_SIZE];
	cxp->deadline_tsc = 0;

	cxp->apic_eoi_va = (u64)(fix_to_virt(FIX_APIC_BASE) + APIC_EOI);
	cxp->apic_lvtt_va = (u64)(fix_to_virt(FIX_APIC_BASE) + APIC_LVTT);

	apic_id = apic->cpu_present_to_apicid(pcpu);
	if (apic_id == BAD_APICID)
		apic_id = pcpu;
	cxp->apic_id = apic_id;

	cxp->uart = cxp->vcpu.uart;

	/* Capture guest GPRs */
	kvm_x86_caretaker_save_gprs(vcpu, &cxp->rax);

	/* Preserved CR3 from session or fallback to global cpu_preserve page table */
	{
		struct caretaker_session *sess = (vcpu && vcpu->caretaker_job) ?
						 vcpu->caretaker_job->session : NULL;

		if (sess && sess->pgd_pa)
			cxp->host_cr3 = sess->pgd_pa;
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
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_x86_caretaker_init_common_page);

void kvm_x86_caretaker_save_gprs(struct kvm_vcpu *vcpu, u64 *gprs)
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
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_x86_caretaker_save_gprs);

void __cpu_preserved_text
kvm_x86_caretaker_restore_gprs(struct kvm_vcpu *vcpu, const u64 *gprs)
{
	kvm_register_write_raw(vcpu, VCPU_REGS_RAX, gprs[0]);
	kvm_register_write_raw(vcpu, VCPU_REGS_RBX, gprs[1]);
	kvm_register_write_raw(vcpu, VCPU_REGS_RCX, gprs[2]);
	kvm_register_write_raw(vcpu, VCPU_REGS_RDX, gprs[3]);
	kvm_register_write_raw(vcpu, VCPU_REGS_RSI, gprs[4]);
	kvm_register_write_raw(vcpu, VCPU_REGS_RDI, gprs[5]);
	kvm_register_write_raw(vcpu, VCPU_REGS_RBP, gprs[6]);
	kvm_register_write_raw(vcpu, VCPU_REGS_R8,  gprs[7]);
	kvm_register_write_raw(vcpu, VCPU_REGS_R9,  gprs[8]);
	kvm_register_write_raw(vcpu, VCPU_REGS_R10, gprs[9]);
	kvm_register_write_raw(vcpu, VCPU_REGS_R11, gprs[10]);
	kvm_register_write_raw(vcpu, VCPU_REGS_R12, gprs[11]);
	kvm_register_write_raw(vcpu, VCPU_REGS_R13, gprs[12]);
	kvm_register_write_raw(vcpu, VCPU_REGS_R14, gprs[13]);
	kvm_register_write_raw(vcpu, VCPU_REGS_R15, gprs[14]);
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_x86_caretaker_restore_gprs);

void kvm_x86_caretaker_init_idt(gate_desc *idt)
{
	int v;

	for (v = 0; v < 256; v++) {
		bool has_err = (v == 8 || (v >= 10 && v <= 14) ||
				v == 17 || v == 21 || v == 29 || v == 30);
		unsigned long handler = (v >= 32) ?
			(unsigned long)&x86_preserved_apic_eoi_stub :
			(has_err ? (unsigned long)&x86_preserved_iret_err_stub :
				   (unsigned long)&x86_preserved_iret_stub);

		pack_gate(&idt[v], GATE_INTERRUPT, handler, 0, 0, __KERNEL_CS);
	}
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_x86_caretaker_init_idt);

void kvm_x86_caretaker_init_gdt_tss(struct desc_struct *gdt,
				    struct x86_hw_tss *tss,
				    unsigned long stack_top)
{
	int k;

	caretaker_memcpy(gdt, get_current_gdt_ro(), sizeof(struct desc_struct) * GDT_ENTRIES);
	caretaker_memset(tss, 0, sizeof(*tss));
	tss->sp0 = stack_top;
	tss->io_bitmap_base = sizeof(*tss);
	for (k = 0; k < 7; k++)
		tss->ist[k] = stack_top;

	caretaker_set_tss_desc(gdt, (unsigned long)tss, sizeof(struct x86_hw_tss) - 1);
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_x86_caretaker_init_gdt_tss);

void __cpu_preserved_text
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
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_x86_caretaker_load_desc);

void __cpu_preserved_text
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
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_x86_caretaker_restore_host_desc);

__caretaker_text void
kvm_x86_caretaker_save_host_state(struct caretaker_x86_host_state *host,
				  struct caretaker_x86_page *cxp)
{
	native_store_gdt(&host->orig_gdt);
	store_idt(&host->orig_idt);
	host->orig_cr3 = __read_cr3();
	rdmsrq(MSR_GS_BASE, host->orig_gs_base);
	rdmsrq(MSR_KERNEL_GS_BASE, host->orig_kernel_gs_base);

	/* Ensure Local APIC is software enabled */
	{
		u64 apic_base;

		rdmsrq(MSR_IA32_APICBASE, apic_base);
		if (!(apic_base & MSR_IA32_APICBASE_ENABLE))
			wrmsrq(MSR_IA32_APICBASE, apic_base | MSR_IA32_APICBASE_ENABLE);
	}

	/* Switch to self-contained Caretaker GDT, IDT, and TSS before CR3 switch */
	kvm_x86_caretaker_load_desc(cxp->gdt, sizeof(cxp->gdt),
				    cxp->idt, sizeof(cxp->idt),
				    &cxp->tss);

	/* Switch to preserved CR3 if specified */
	{
		struct cpu_preserved_stack_context *sctx = caretaker_get_current_context();

		if (sctx && sctx->session_pgd_pa)
			cxp->host_cr3 = sctx->session_pgd_pa;
		else if (!cxp->host_cr3 && x86_caretaker_pgd_pa)
			cxp->host_cr3 = x86_caretaker_pgd_pa;
	}
	if (cxp->host_cr3 && host->orig_cr3 != cxp->host_cr3)
		write_cr3(cxp->host_cr3);

	raw_local_irq_disable();
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_x86_caretaker_save_host_state);

__caretaker_text void
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
	if (vcpu && !cpu_is_preserved(pcpu) && !cpu_preserved_is_incoming(pcpu)) {
		if (host->orig_cr3 && host->orig_cr3 != cxp->host_cr3)
			write_cr3(host->orig_cr3);
		wrmsrq(MSR_GS_BASE, host->orig_gs_base);
		wrmsrq(MSR_KERNEL_GS_BASE, host->orig_kernel_gs_base);

		kvm_x86_caretaker_restore_host_desc(pcpu, &host->orig_idt);
	} else if (cpu_is_preserved(pcpu)) {
		arch_cpu_preserved_load_desc();
	} else if (host->orig_idt.size) {
		native_load_idt(&host->orig_idt);
	}
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_x86_caretaker_restore_host_state);

__caretaker_text void
kvm_x86_caretaker_sync_vcpu_common(struct kvm_vcpu *vcpu,
				   const struct caretaker_x86_page *cxp)
{
	if (!vcpu || !cxp)
		return;

	if (cxp->last_exit_rip)
		kvm_rip_write(vcpu, cxp->last_exit_rip);
	if (cxp->last_exit_rsp)
		kvm_rsp_write(vcpu, cxp->last_exit_rsp);
	if (cxp->last_exit_rflags)
		kvm_set_rflags(vcpu, cxp->last_exit_rflags);

	if (cxp->efer)
		vcpu->arch.efer = cxp->efer;
	if (cxp->cr0)
		vcpu->arch.cr0 = cxp->cr0;
	if (cxp->cr4)
		vcpu->arch.cr4 = cxp->cr4;
	if (cxp->cr3) {
		vcpu->arch.cr3 = cxp->cr3;
		kvm_register_mark_dirty(vcpu, VCPU_REG_CR3);
	}

	kvm_x86_caretaker_restore_gprs(vcpu, (const u64 *)&cxp->rax);

	kvm_clear_interrupt_queue(vcpu);
	kvm_clear_exception_queue(vcpu);

	vcpu->cpu = -1;
	vcpu->arch.cb_pa = 0;
	kvm_make_request(KVM_REQ_LOAD_MMU_PGD, vcpu);
	kvm_make_request(KVM_REQ_TLB_FLUSH_CURRENT, vcpu);
	kvm_make_request(KVM_REQ_RECALC_INTERCEPTS, vcpu);
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_x86_caretaker_sync_vcpu_common);

static __caretaker_text __no_stack_protector int x86_caretaker_op_enter(void *data)
{
	struct caretaker_x86_page *cxp = data;
	return (int)cxp->enter_fn(cxp);
}

static __caretaker_text __no_stack_protector void
x86_caretaker_op_decode_exit(void *data, struct kvm_caretaker_exit *exit)
{
	struct caretaker_x86_page *cxp = data;

	if (cxp->decode_exit_fn)
		cxp->decode_exit_fn(cxp, exit);
}

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
	if (write) {
		u64 val = (*rax & 0xffffffffULL) | ((*rdx) << 32);

		if (msr >= APIC_BASE_MSR && msr <= APIC_BASE_MSR + 0x3f) {
			/* Absorb guest x2APIC writes in Caretaker mode */
			return true;
		}

		switch (msr) {
		case MSR_IA32_TSC:
		case MSR_IA32_TSC_DEADLINE:
		case MSR_IA32_TSC_ADJUST:
		case MSR_IA32_SPEC_CTRL:
		case MSR_IA32_PRED_CMD:
			return true;
		case MSR_KERNEL_GS_BASE:
			if (cxp)
				cxp->kernel_gs_base = val;
			wrmsrq(MSR_KERNEL_GS_BASE, val);
			return true;
		case MSR_FS_BASE:
			wrmsrq(MSR_FS_BASE, val);
			return true;
		case MSR_GS_BASE:
			wrmsrq(MSR_GS_BASE, val);
			return true;
		case MSR_LSTAR:
			wrmsrq(MSR_LSTAR, val);
			return true;
		case MSR_STAR:
			wrmsrq(MSR_STAR, val);
			return true;
		case MSR_SYSCALL_MASK:
			wrmsrq(MSR_SYSCALL_MASK, val);
			return true;
		case MSR_IA32_APICBASE:
			wrmsrq(MSR_IA32_APICBASE, val);
			return true;
		default:
			break;
		}
	} else {
		u64 val = 0;

		if (msr >= APIC_BASE_MSR && msr <= APIC_BASE_MSR + 0x3f) {
			u32 reg = (msr - APIC_BASE_MSR) << 4;
			u32 apic_id = cxp ? cxp->cb.vcpu_id : 0;

			switch (reg) {
			case APIC_ID:
				val = apic_id;
				break;
			case APIC_LVR:
				val = 0x00050014;
				break;
			case APIC_SPIV:
				val = APIC_SPIV_APIC_ENABLED | 0xff;
				break;
			case APIC_LDR:
				val = ((apic_id >> 4) << 16) | (1U << (apic_id & 0xf));
				break;
			default:
				val = 0;
				break;
			}
			*rax = (u32)val;
			*rdx = (u32)(val >> 32);
			return true;
		}

		switch (msr) {
		case MSR_IA32_TSC: {
			u64 tsc = rdtsc();

			*rax = (u32)tsc;
			*rdx = (u32)(tsc >> 32);
			return true;
		}
		case MSR_IA32_TSC_DEADLINE:
		case MSR_IA32_TSC_ADJUST:
		case MSR_IA32_SPEC_CTRL:
			*rax = 0;
			*rdx = 0;
			return true;
		case MSR_KERNEL_GS_BASE:
			if (cxp && cxp->kernel_gs_base)
				val = cxp->kernel_gs_base;
			else
				rdmsrq(MSR_KERNEL_GS_BASE, val);
			*rax = (u32)val;
			*rdx = (u32)(val >> 32);
			return true;
		case MSR_IA32_APICBASE:
			rdmsrq(MSR_IA32_APICBASE, val);
			if (!val)
				val = APIC_DEFAULT_PHYS_BASE | MSR_IA32_APICBASE_ENABLE;
			if (cxp && cxp->cb.vcpu_id == 0)
				val |= MSR_IA32_APICBASE_BSP;
			else
				val &= ~MSR_IA32_APICBASE_BSP;
			*rax = (u32)val;
			*rdx = (u32)(val >> 32);
			return true;
		case MSR_FS_BASE:
			rdmsrq(MSR_FS_BASE, val);
			*rax = (u32)val;
			*rdx = (u32)(val >> 32);
			return true;
		case MSR_GS_BASE:
			rdmsrq(MSR_GS_BASE, val);
			*rax = (u32)val;
			*rdx = (u32)(val >> 32);
			return true;
		case MSR_LSTAR:
			rdmsrq(MSR_LSTAR, val);
			*rax = (u32)val;
			*rdx = (u32)(val >> 32);
			return true;
		case MSR_STAR:
			rdmsrq(MSR_STAR, val);
			*rax = (u32)val;
			*rdx = (u32)(val >> 32);
			return true;
		case MSR_SYSCALL_MASK:
			rdmsrq(MSR_SYSCALL_MASK, val);
			*rax = (u32)val;
			*rdx = (u32)(val >> 32);
			return true;
		default:
			break;
		}
	}

	return false;
}

static __caretaker_text __no_stack_protector bool
x86_caretaker_op_handle_exit(void *data, struct kvm_caretaker_exit *exit)
{
	struct caretaker_x86_page *cxp = data;
	bool handled = false;

	if (exit->type == KVM_CARETAKER_EXIT_CROSS_VCPU)
		return true;

	switch (exit->type) {
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
		handled = (exit->insn_len != 0);
		break;
	}

	if (handled)
		exit->rip += exit->insn_len;

	return handled;
}

static __caretaker_text __no_stack_protector void
x86_caretaker_op_advance_rip(void *data, u64 next_rip)
{
	struct caretaker_x86_page *cxp = data;

	if (cxp->advance_rip_fn)
		cxp->advance_rip_fn(cxp, next_rip);
	else
		cxp->last_exit_rip = next_rip;
}

static struct kvm_caretaker_ops x86_caretaker_ops __cpu_preserved_data = {
	.enter_guest = x86_caretaker_op_enter,
	.decode_exit = x86_caretaker_op_decode_exit,
	.handle_arch_exit = x86_caretaker_op_handle_exit,
	.advance_rip = x86_caretaker_op_advance_rip,
	.sync_vcpu = (void (*)(struct kvm_vcpu *, void *))kvm_x86_caretaker_sync_vcpu_common,
};

STACK_FRAME_NON_STANDARD(kvm_x86_caretaker_run);

__caretaker_text __no_stack_protector enum caretaker_exit_reason
kvm_x86_caretaker_run(struct caretaker_x86_page *cxp,
		      u64 deadline_ticks,
		      caretaker_enter_fn enter,
		      caretaker_decode_exit_fn decode_exit,
		      caretaker_advance_rip_fn advance_rip)
{
	enum caretaker_exit_reason reason;

	cxp->enter_fn = enter;
	cxp->decode_exit_fn = decode_exit;
	cxp->advance_rip_fn = advance_rip;
	cxp->vcpu.ops = &x86_caretaker_ops;
	cxp->vcpu.arch_data = cxp;
	cxp->running = 1;

	reason = kvm_caretaker_vcpu_run(&cxp->vcpu, deadline_ticks);

	iret_to_self();

	cxp->running = 0;
	return reason;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_x86_caretaker_run);

__caretaker_text void kvm_x86_caretaker_arm_timer(u64 deadline_ticks, u64 apic_lvtt_va)
{
	u32 apic_base_low, apic_base_high;
	bool is_x2apic;

	if (!deadline_ticks)
		return;

	if (!apic_lvtt_va)
		apic_lvtt_va = (u64)(fix_to_virt(FIX_APIC_BASE) + APIC_LVTT);

	asm volatile("rdmsr" : "=a" (apic_base_low), "=d" (apic_base_high) : "c" (MSR_IA32_APICBASE));
	is_x2apic = (apic_base_low & X2APIC_ENABLE) != 0;

	if (caretaker_x86_has_tsc_deadline) {
		u32 lvtt = LOCAL_TIMER_VECTOR | APIC_LVT_TIMER_TSCDEADLINE;

		if (is_x2apic)
			asm volatile("wrmsr" : : "c" (APIC_BASE_MSR + (APIC_LVTT >> 4)), "a" (lvtt), "d" (0) : "memory");
		else
			*(volatile u32 *)apic_lvtt_va = lvtt;

		wrmsrq(MSR_IA32_TSC_DEADLINE, deadline_ticks);
	} else {
		u64 now = rdtsc();
		u64 delta_tsc = (deadline_ticks > now) ? (deadline_ticks - now) : 1;
		u32 lvtt = LOCAL_TIMER_VECTOR;
		u64 count;

		if (global_sched_config.tsc_khz && caretaker_x86_lapic_timer_period) {
			u64 apic_khz = (u64)caretaker_x86_lapic_timer_period * HZ / 1000ULL;
			count = (delta_tsc * apic_khz) / ((u64)global_sched_config.tsc_khz);
		} else {
			count = delta_tsc >> 4;
		}
		if (count == 0)
			count = 1;
		if (count > 0xffffffffULL)
			count = 0xffffffffULL;

		if (is_x2apic) {
			asm volatile("wrmsr" : : "c" (APIC_BASE_MSR + (APIC_TDCR >> 4)), "a" (APIC_TDR_DIV_16), "d" (0) : "memory");
			asm volatile("wrmsr" : : "c" (APIC_BASE_MSR + (APIC_LVTT >> 4)), "a" (lvtt), "d" (0) : "memory");
			asm volatile("wrmsr" : : "c" (APIC_BASE_MSR + (APIC_TMICT >> 4)), "a" ((u32)count), "d" (0) : "memory");
		} else {
			*(volatile u32 *)(apic_lvtt_va + (APIC_TDCR - APIC_LVTT)) = APIC_TDR_DIV_16;
			*(volatile u32 *)apic_lvtt_va = lvtt;
			*(volatile u32 *)(apic_lvtt_va + (APIC_TMICT - APIC_LVTT)) = (u32)count;
		}
	}
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_x86_caretaker_arm_timer);

__caretaker_text void kvm_x86_caretaker_disarm_timer(u64 apic_lvtt_va)
{
	u32 apic_base_low, apic_base_high;
	bool is_x2apic;

	if (!apic_lvtt_va)
		apic_lvtt_va = (u64)(fix_to_virt(FIX_APIC_BASE) + APIC_LVTT);

	asm volatile("rdmsr" : "=a" (apic_base_low), "=d" (apic_base_high) : "c" (MSR_IA32_APICBASE));
	is_x2apic = (apic_base_low & X2APIC_ENABLE) != 0;

	if (caretaker_x86_has_tsc_deadline) {
		wrmsrq(MSR_IA32_TSC_DEADLINE, 0);
	} else {
		if (is_x2apic)
			asm volatile("wrmsr" : : "c" (APIC_BASE_MSR + (APIC_TMICT >> 4)), "a" (0), "d" (0) : "memory");
		else
			*(volatile u32 *)(apic_lvtt_va + (APIC_TMICT - APIC_LVTT)) = 0;
	}

	if (is_x2apic)
		asm volatile("wrmsr" : : "c" (APIC_BASE_MSR + (APIC_LVTT >> 4)), "a" (APIC_LVT_MASKED | LOCAL_TIMER_VECTOR), "d" (0) : "memory");
	else
		*(volatile u32 *)apic_lvtt_va = APIC_LVT_MASKED | LOCAL_TIMER_VECTOR;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_x86_caretaker_disarm_timer);
