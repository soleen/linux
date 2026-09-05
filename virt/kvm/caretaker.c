// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * Core KVM Caretaker common execution engine and lifecycle management.
 */

/**
 * DOC: KVM Caretaker Architecture Integration Interface
 *
 * The KVM Caretaker framework provides on-core execution of preserved guest
 * vCPUs during a live kernel update (kexec). The common framework in virt/kvm/
 * handles quantum scheduling, exit dispatching, early console emulation (UART
 * 8250 and PL011), idle relaxation (HLT/WFI), and attach synchronization.
 *
 * Each architecture supporting Caretaker (e.g., arch/x86/kvm/ and
 * arch/arm64/kvm/) implements hardware-specific execution, exit decoding, and
 * lifecycle handover across three primary interface groups:
 *
 * 1. Global Architecture Entry Points (exported for KVM LUO and Caretaker):
 *    ---------------------------------------------------------------------
 *    - kvm_arch_vcpu_caretaker_run(data, deadline_ticks):
 *        Executes the guest vCPU on the preserved physical CPU until the
 *        preemption deadline expires, an attach is signaled by the incoming
 *        kernel, the vCPU yields in idle, or an unhandled exit occurs.
 *        Called directly by the Caretaker job scheduler.
 *
 *    - kvm_arch_vcpu_caretaker_data(vcpu):
 *        Returns the architecture-specific runtime descriptor (e.g.,
 *        struct caretaker_vmx_page, struct caretaker_svm_page, or struct
 *        kvm_vcpu) associated with the vCPU, to be stored in the Caretaker
 *        job and passed into kvm_arch_vcpu_caretaker_run().
 *
 *    - kvm_arch_vcpu_luo_attach_caretaker(vcpu, ser):
 *        Invoked by the incoming kernel during vCPU adoption. Signals the
 *        running Caretaker loop on the preserved core, waits for
 *        acknowledgment, and synchronizes architecture register/hypervisor
 *        state into the newly allocated incoming vCPU structures.
 *
 * 2. Architecture Operations Vector (struct kvm_caretaker_ops):
 *    ----------------------------------------------------------
 *    Arch backends populate and register this ops table when initializing a
 *    Caretaker vCPU descriptor (struct kvm_caretaker_vcpu):
 *
 *    - enter_guest(vcpu_data):
 *        Performs low-level hardware guest entry (VMENTRY, VMRUN, or ERET).
 *        Runs with local CPU state configured for preserved execution.
 *
 *    - decode_exit(vcpu_data, exit):
 *        Reads hardware exit reasons/qualifications from VMCS, VMCB, or
 *        ESR_EL2 and normalizes them into struct kvm_caretaker_exit (e.g.,
 *        port I/O, MMIO, CPUID, MSR, preempt timer, idle, cross-vCPU IPI).
 *
 *    - handle_arch_exit(vcpu_data, exit):
 *        Handles architecture-specific exits that cannot be resolved by the
 *        common engine (e.g., CPUID leaves, vendor MSRs, APIC ICR dispatch).
 *
 *    - advance_rip(vcpu_data, next_rip):
 *        Advances guest program counter (RIP / PC) past emulated instructions.
 *
 *    - arm_timer(vcpu_data, deadline_ticks):
 *        Programs hardware timer (VMX preemption timer, APIC timer, or ARM
 *        CNTHP) to fire when the time-sharing quantum expires.
 *
 *    - disarm_timer(vcpu_data):
 *        Clears the programmed preemption timer.
 *
 *    - pre_run(vcpu_data) / post_run(vcpu_data):
 *        Optional per-quantum setup and teardown callbacks invoked
 *        immediately before and after the inner vCPU execution loop.
 *
 *    - sync_vcpu(vcpu, vcpu_data):
 *        Copies guest register state from preserved hardware memory into the
 *        target struct kvm_vcpu when attaching.
 *
 * 3. Architecture LUO Lifecycle Hooks:
 *    ---------------------------------
 *    - kvm_arch_vcpu_luo_preserve(vcpu, ser):
 *        Serializes arch vCPU state to KHO and sets up Caretaker runtime pages.
 *
 *    - kvm_arch_vcpu_luo_retrieve(vcpu, ser):
 *        Restores serialized vCPU state from KHO in the incoming kernel.
 *
 *    - kvm_arch_vcpu_luo_unpreserve(ser):
 *        Frees preserved memory buffers if live update is cancelled.
 *
 *    - kvm_arch_vcpu_luo_finish(ser):
 *        Finalizes state and releases KHO buffers after successful handover.
 */

#include <linux/kernel.h>
#include <linux/kvm_host.h>
#include <linux/kvm_caretaker.h>
#include <linux/cpu_preserve.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/objtool.h>
#include <uapi/linux/serial_reg.h>

#define KVM_CARETAKER_ATTACH_TIMEOUT_US	2000000
#define KVM_CARETAKER_ATTACH_STEP_US	10

void kvm_caretaker_init_uart(struct caretaker_uart *uart)
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
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_caretaker_init_uart);

void kvm_caretaker_init_common_vcpu(struct kvm_caretaker_vcpu *cvcpu,
				   struct kvm_vcpu *vcpu,
				   void *runtime_va,
				   size_t runtime_size,
				   const struct kvm_caretaker_ops *ops,
				   void *arch_data)
{
	int pcpu;

	if (!cvcpu || !vcpu)
		return;

	pcpu = (vcpu->cb.pcpu_id != CARETAKER_INVALID_PCPU &&
		vcpu->cb.pcpu_id < nr_cpu_ids) ?
	       vcpu->cb.pcpu_id :
	       (vcpu->cpu >= 0 && vcpu->cpu < nr_cpu_ids ? vcpu->cpu : 0);

	cvcpu->cb.attachment_state = CARETAKER_KVM_DETACHED;
	cvcpu->cb.pcpu_id = pcpu;
	cvcpu->cb.vcpu_id = vcpu->vcpu_id;
	cvcpu->cb.vm_token = vcpu->cb.vm_token;
	cvcpu->cb.vcpu_token = vcpu->cb.vcpu_token;
	cvcpu->cb.runtime_pa = virt_to_phys(runtime_va ? runtime_va : cvcpu);
	cvcpu->cb.runtime_size = runtime_size;

	cvcpu->running = 0;
	cvcpu->total_exits = 0;
	cvcpu->deadline_ticks = 0;
	cvcpu->last_exit_rip = 0;
	cvcpu->ops = ops;
	cvcpu->arch_data = arch_data;

	kvm_caretaker_init_uart(&cvcpu->uart);
	{
		struct caretaker_session *sess = (vcpu && vcpu->caretaker_job) ?
						 vcpu->caretaker_job->session : NULL;
		void *buf = runtime_va ? runtime_va : cvcpu;
		size_t sz = runtime_va && runtime_size ? runtime_size : sizeof(*cvcpu);

		caretaker_session_map_buffer(sess, buf, sz);
	}
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_caretaker_init_common_vcpu);

bool __cpu_preserved_text __no_stack_protector
kvm_caretaker_should_exit(struct kvm_caretaker_vcpu *cvcpu)
{
	struct cpu_preserved_stack_context *sctx;
	int pcpu;

	if (!cvcpu)
		return true;

	arch_cpu_preserved_dcache_inval((unsigned long)&cvcpu->cb,
					(unsigned long)&cvcpu->cb + sizeof(cvcpu->cb));

	if (READ_ONCE(cvcpu->cb.attachment_state) != CARETAKER_KVM_DETACHED)
		return true;

	sctx = cpu_preserved_get_stack_context();
	if (sctx && sctx->cpu >= 0 && sctx->cpu < NR_CPUS &&
	    cpu_preserved_should_exit(sctx->cpu))
		return true;

	pcpu = cvcpu->cb.pcpu_id;
	if (pcpu >= 0 && pcpu < NR_CPUS && cpu_preserved_should_exit(pcpu))
		return true;

	return false;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_caretaker_should_exit);

bool __cpu_preserved_text __no_stack_protector
kvm_caretaker_handle_idle(struct kvm_caretaker_vcpu *cvcpu)
{
	cpu_relax();
	if (cvcpu->deadline_ticks)
		return false;
	return true;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_caretaker_handle_idle);
STACK_FRAME_NON_STANDARD(kvm_caretaker_handle_idle);

bool __cpu_preserved_text __no_stack_protector
kvm_caretaker_emulate_uart8250(struct caretaker_uart *uart,
			       u16 port, int in, int size,
			       unsigned long *rax)
{
	u8 offset;

	if (port < UART_COM1_BASE || port > UART_COM1_END)
		return false;

	offset = port - UART_COM1_BASE;

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
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_caretaker_emulate_uart8250);
STACK_FRAME_NON_STANDARD(kvm_caretaker_emulate_uart8250);

bool __cpu_preserved_text __no_stack_protector
kvm_caretaker_emulate_pl011(struct caretaker_uart *uart,
			    u64 addr, bool is_write,
			    u64 *val)
{
	u64 offset = addr & (ARM_VIRT_PL011_SIZE - 1);

	if ((addr & ~(ARM_VIRT_PL011_SIZE - 1)) != ARM_VIRT_PL011_BASE)
		return false;

	if (!is_write) {
		if (offset == PL011_UARTFR)
			*val = PL011_UARTFR_TXFE | PL011_UARTFR_RXFE;
		else
			*val = 0;
	} else {
		if (offset == PL011_UARTDR && uart && val)
			uart->dll = (u8)*val;
	}
	return true;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_caretaker_emulate_pl011);
STACK_FRAME_NON_STANDARD(kvm_caretaker_emulate_pl011);

bool __cpu_preserved_text __no_stack_protector
kvm_caretaker_handle_console(struct kvm_caretaker_vcpu *cvcpu,
			     struct kvm_caretaker_exit *exit)
{
	u64 *target;

	if (!cvcpu || !exit)
		return false;

	target = exit->mmio_io.val_ptr ? exit->mmio_io.val_ptr : &exit->mmio_io.val;

	if (!exit->mmio_io.is_mmio) {
		return kvm_caretaker_emulate_uart8250(&cvcpu->uart,
						     (u16)exit->mmio_io.addr,
						     !exit->mmio_io.is_write,
						     exit->mmio_io.size,
						     (unsigned long *)target);
	} else {
		return kvm_caretaker_emulate_pl011(&cvcpu->uart,
						  exit->mmio_io.addr,
						  exit->mmio_io.is_write,
						  target);
	}
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_caretaker_handle_console);
STACK_FRAME_NON_STANDARD(kvm_caretaker_handle_console);

bool __cpu_preserved_text __no_stack_protector
kvm_caretaker_dispatch_exit(struct kvm_caretaker_vcpu *cvcpu,
			    struct kvm_caretaker_exit *exit)
{
	bool handled = false;

	if (!cvcpu || !exit)
		return false;

	if (kvm_caretaker_should_exit(cvcpu))
		return false;

	cvcpu->total_exits++;

	switch (exit->type) {
	case KVM_CARETAKER_EXIT_IDLE:
		handled = kvm_caretaker_handle_idle(cvcpu);
		exit->rip += exit->insn_len;
		return handled;

	case KVM_CARETAKER_EXIT_CONSOLE:
		handled = kvm_caretaker_handle_console(cvcpu, exit);
		if (handled)
			exit->rip += exit->insn_len;
		return handled;

	case KVM_CARETAKER_EXIT_PREEMPT_TIMER:
		return false;

	case KVM_CARETAKER_EXIT_CROSS_VCPU:
	case KVM_CARETAKER_EXIT_CPUID:
	case KVM_CARETAKER_EXIT_MSR:
	case KVM_CARETAKER_EXIT_RDTSC:
	case KVM_CARETAKER_EXIT_INSN_STEP:
	case KVM_CARETAKER_EXIT_ARCH:
		if (cvcpu->ops && cvcpu->ops->handle_arch_exit) {
			void *arch_data = cvcpu->arch_data ? cvcpu->arch_data : cvcpu;
			return cvcpu->ops->handle_arch_exit(arch_data, exit);
		}
		return false;

	case KVM_CARETAKER_EXIT_UNHANDLED:
	default:
		return false;
	}
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_caretaker_dispatch_exit);
STACK_FRAME_NON_STANDARD(kvm_caretaker_dispatch_exit);

STACK_FRAME_NON_STANDARD(kvm_caretaker_vcpu_run);

enum caretaker_exit_reason __cpu_preserved_text __no_stack_protector
kvm_caretaker_vcpu_run(struct kvm_caretaker_vcpu *cvcpu, u64 deadline_ticks)
{
	const struct kvm_caretaker_ops *ops;
	void *arch_data;
	int enter_res = 0;

	if (!cvcpu || !cvcpu->ops)
		return CARETAKER_EXIT_ERROR;

	cvcpu->deadline_ticks = deadline_ticks;
	ops = cvcpu->ops;
	arch_data = cvcpu->arch_data ? cvcpu->arch_data : cvcpu;

	if (kvm_caretaker_should_exit(cvcpu))
		return CARETAKER_EXIT_ATTACH_SIGNALED;

	WRITE_ONCE(cvcpu->running, 1);
	smp_wmb();

	if (ops->pre_run)
		ops->pre_run(arch_data);

	if (ops->arm_timer)
		ops->arm_timer(arch_data, deadline_ticks);

	while (true) {
		struct kvm_caretaker_exit exit __uninitialized;
		bool handled = false;

		caretaker_memset(&exit, 0, sizeof(exit));

		if (kvm_caretaker_should_exit(cvcpu))
			break;

		if (deadline_ticks && arch_caretaker_read_counter() >= deadline_ticks)
			break;

		enter_res = ops->enter_guest(arch_data);
		if (enter_res != 0) {
			if (!kvm_caretaker_should_exit(cvcpu)) {
				cpu_relax();
				enter_res = ops->enter_guest(arch_data);
			}
			if (enter_res != 0)
				break;
		}

		if (ops->decode_exit)
			ops->decode_exit(arch_data, &exit);

		if (kvm_caretaker_should_exit(cvcpu))
			break;

		handled = kvm_caretaker_dispatch_exit(cvcpu, &exit);

		if (ops->advance_rip)
			ops->advance_rip(arch_data, exit.rip);
		else
			cvcpu->last_exit_rip = exit.rip;

		if (!handled)
			break;

		if (deadline_ticks && arch_caretaker_read_counter() >= deadline_ticks)
			break;
	}

	if (ops->disarm_timer)
		ops->disarm_timer(arch_data);

	if (ops->post_run)
		ops->post_run(arch_data);

	WRITE_ONCE(cvcpu->running, 0);
	smp_wmb();

	if (READ_ONCE(cvcpu->cb.attachment_state) == CARETAKER_KVM_ATTACHING) {
		WRITE_ONCE(cvcpu->cb.attachment_state, CARETAKER_KVM_ATTACHED);
		arch_cpu_preserved_dcache_clean((unsigned long)&cvcpu->cb,
						(unsigned long)&cvcpu->cb + sizeof(cvcpu->cb));
		smp_wmb();
	}

	if (kvm_caretaker_should_exit(cvcpu))
		return CARETAKER_EXIT_ATTACH_SIGNALED;

	if (enter_res != 0)
		return CARETAKER_EXIT_ERROR;

	return CARETAKER_EXIT_QUANTUM_EXPIRED;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_caretaker_vcpu_run);

int kvm_caretaker_wait_for_attach(struct caretaker_cb *cb, int pcpu,
				  void (*arch_kick)(int pcpu))
{
	struct kvm_caretaker_vcpu *cvcpu;
	int i;

	if (!cb)
		return 0;

	cvcpu = container_of(cb, struct kvm_caretaker_vcpu, cb);

	arch_cpu_preserved_dcache_inval((unsigned long)cb,
					(unsigned long)cb + sizeof(*cb));

	if (READ_ONCE(cb->attachment_state) == CARETAKER_KVM_ATTACHED)
		return 0;

	/*
	 * If vCPU is not currently running on physical silicon, its
	 * register state is already completely saved in memory.
	 */
	if (!READ_ONCE(cvcpu->running)) {
		WRITE_ONCE(cb->attachment_state, CARETAKER_KVM_ATTACHED);
		arch_cpu_preserved_dcache_clean((unsigned long)cb,
						(unsigned long)cb + sizeof(*cb));
		smp_wmb();
		return 0;
	}

	if (pcpu < 0 || pcpu >= nr_cpu_ids ||
	    pcpu == raw_smp_processor_id() ||
	    cpu_online(pcpu)) {
		WRITE_ONCE(cb->attachment_state, CARETAKER_KVM_ATTACHED);
		arch_cpu_preserved_dcache_clean((unsigned long)cb,
						(unsigned long)cb + sizeof(*cb));
		smp_wmb();
		return 0;
	}

	WRITE_ONCE(cb->attachment_state, CARETAKER_KVM_ATTACHING);
	arch_cpu_preserved_dcache_clean((unsigned long)cb,
					(unsigned long)cb + sizeof(*cb));
	smp_wmb();

	/* Send kick to target preserved physical CPU */
	if (arch_kick)
		arch_kick(pcpu);
	else
		arch_cpu_preserved_kick(pcpu);

	/* Deterministic spin-wait for Caretaker CPU to exit guest and save context */
	for (i = 0; i < KVM_CARETAKER_ATTACH_TIMEOUT_US / KVM_CARETAKER_ATTACH_STEP_US; i++) {
		arch_cpu_preserved_dcache_inval((unsigned long)cb,
						(unsigned long)cb + sizeof(*cb));
		if (READ_ONCE(cb->attachment_state) == CARETAKER_KVM_ATTACHED ||
		    !READ_ONCE(cvcpu->running)) {
			WRITE_ONCE(cb->attachment_state, CARETAKER_KVM_ATTACHED);
			arch_cpu_preserved_dcache_clean((unsigned long)cb,
							(unsigned long)cb + sizeof(*cb));
			break;
		}
		if ((i % 100) == 0 && i > 0) {
			if (arch_kick)
				arch_kick(pcpu);
			else
				arch_cpu_preserved_kick(pcpu);
		}
		udelay(KVM_CARETAKER_ATTACH_STEP_US);
	}

	if (READ_ONCE(cb->attachment_state) != CARETAKER_KVM_ATTACHED) {
		pr_warn("kvm: caretaker attach handshake timed out for pCPU %d\n", pcpu);
		return -ETIMEDOUT;
	}

	return 0;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_caretaker_wait_for_attach);
STACK_FRAME_NON_STANDARD(kvm_caretaker_wait_for_attach);

void kvm_caretaker_post_attach_vcpu(struct kvm_vcpu *vcpu,
				    struct kvm_caretaker_vcpu *cvcpu)
{
	int pcpu = -1;

	if (!vcpu)
		return;

	if (cvcpu)
		pcpu = cvcpu->cb.pcpu_id;
	else if (vcpu->cb.pcpu_id != CARETAKER_INVALID_PCPU)
		pcpu = vcpu->cb.pcpu_id;

	if (pcpu >= 0 && pcpu < nr_cpu_ids)
		vcpu->cb.pcpu_id = pcpu;

	vcpu->cb.attachment_state = CARETAKER_KVM_ATTACHED;
	vcpu->cb.runtime_pa = 0;
	vcpu->cb.runtime_size = 0;
	smp_store_mb(vcpu->mode, EXITING_GUEST_MODE);
	vcpu->cpu = -1;

	if (pcpu >= 0)
		caretaker_kvm_attach(&vcpu->cb);
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_caretaker_post_attach_vcpu);
