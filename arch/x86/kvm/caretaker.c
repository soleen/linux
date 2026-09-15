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

void *kvm_arch_vcpu_caretaker_data(struct kvm_vcpu *vcpu)
{
	if (!vcpu || !vcpu->arch.cb_pa)
		return NULL;
	return caretaker_pa_to_va(vcpu->arch.cb_pa);
}

void kvm_arch_vcpu_caretaker_init(struct kvm_vcpu *vcpu, u64 *cb_pa)
{
	if (cb_pa)
		*cb_pa = 0;
	if (kvm_x86_caretaker_ops && kvm_x86_caretaker_ops->init)
		kvm_x86_caretaker_ops->init(vcpu, cb_pa);
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

		if (abi->cb.pcpu_id < nr_cpu_ids)
			vcpu->caretaker.cb.pcpu_id = abi->cb.pcpu_id;

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

	pcpu = (vcpu->caretaker.cb.pcpu_id != KVM_CARETAKER_INVALID_PCPU &&
		vcpu->caretaker.cb.pcpu_id < nr_cpu_ids) ?
	       vcpu->caretaker.cb.pcpu_id :
	       (vcpu->cpu >= 0 && vcpu->cpu < nr_cpu_ids ?
		vcpu->cpu : 0);

	caretaker_x86_has_tsc_deadline = boot_cpu_has(X86_FEATURE_TSC_DEADLINE_TIMER);
	caretaker_x86_lapic_timer_period = lapic_timer_period;
	cpu_preserved_clean(&caretaker_x86_has_tsc_deadline);
	cpu_preserved_clean(&caretaker_x86_lapic_timer_period);

	memset(cxp, 0, full_page_size);

	kvm_caretaker_init_common_vcpu(&cxp->vcpu, vcpu, cxp, full_page_size,
				       NULL, cxp);

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
