// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * Preserved-CPU runtime for x86.
 */
#include <linux/bitfield.h>
#include <linux/cpu_preserve.h>
#include <linux/objtool.h>

#include <asm/apicdef.h>
#include <asm/desc.h>
#include <asm/extable.h>
#include <asm/insn-eval.h>
#include <asm/irqflags.h>
#include <asm/msr.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/special_insns.h>

#include "cpu_preserve_internal.h"

extern const struct exception_table_entry cpu_preserved_sym(ex_table_start)[];
extern const struct exception_table_entry cpu_preserved_sym(ex_table_end)[];

gate_desc x86_preserved_idt[IDT_ENTRIES] __aligned(PAGE_SIZE);
struct desc_ptr x86_preserved_idt_desc;

struct desc_struct x86_preserved_gdt[GDT_ENTRIES] __aligned(PAGE_SIZE);
struct desc_ptr x86_preserved_gdt_desc;
bool x86_preserved_has_svm;
u16 x86_verw_sel = __KERNEL_DS;

static bool x86_preserved_fixup_exception(struct pt_regs *regs, int trapnr)
{
	const struct exception_table_entry *e;
	int type, reg, imm;

	for (e = cpu_preserved_sym(ex_table_start);
	     e < cpu_preserved_sym(ex_table_end); e++) {
		if (ex_insn_addr(e) != regs->ip)
			continue;

		type = FIELD_GET(EX_DATA_TYPE_MASK, e->data);
		reg  = FIELD_GET(EX_DATA_REG_MASK, e->data);
		imm  = FIELD_GET_SIGNED(EX_DATA_IMM_MASK, e->data);

		if (ex_fixup_basic(e, regs, type, trapnr, reg, imm))
			return true;

		switch (type) {
		case EX_TYPE_UACCESS:
			return ex_handler_default(e, regs);
		case EX_TYPE_CLEAR_FS:
			asm volatile("mov %0, %%fs" : : "rm" (0));
			return ex_handler_default(e, regs);
		case EX_TYPE_RDMSR:
			return ex_handler_msr_common(e, regs, false, false, reg);
		case EX_TYPE_WRMSR:
			return ex_handler_msr_common(e, regs, true, false, reg);
		case EX_TYPE_RDMSR_SAFE:
			return ex_handler_msr_common(e, regs, false, true, reg);
		case EX_TYPE_WRMSR_SAFE:
			return ex_handler_msr_common(e, regs, true, true, reg);
		default:
			return false;
		}
	}

	return false;
}

asmlinkage void x86_preserved_handle_exception(struct pt_regs *regs, int vector)
{
	struct cpu_preserved_stack_context *sctx;
	struct x86_preserved_fault *f;
	int cpu = 0;

	if (x86_preserved_fixup_exception(regs, vector))
		return;

	sctx = cpu_preserved_get_stack_context();
	if (sctx) {
		cpu = sctx->cpu;
		f = &sctx->fault;
		f->vector = vector;
		f->error_code = regs->orig_ax;
		f->ip = regs->ip;
		f->sp = regs->sp;
		f->cr2 = native_read_cr2();
		f->cr3 = __native_read_cr3();
		f->count++;
		cpu_preserved_clean(f);

		if (f->abort_fn) {
			void (*abort_fn)(int, const struct x86_preserved_fault *) = f->abort_fn;

			f->abort_fn = NULL;
			abort_fn(cpu, f);
		}
	}

	if (sctx && sctx->ser) {
		while (smp_load_acquire(&sctx->ser->state) == CPU_PRESERVED_WORKLOAD)
			arch_cpu_preserved_park_wait();
	}
	cpu_preserved_park_loop(cpu);

	arch_cpu_preserved_park_finish(cpu);
	native_irq_disable();
	cpu_preserved_set_dead();
	while (1) {
		native_irq_disable();
		asm volatile("hlt");
	}
}
STACK_FRAME_NON_STANDARD(x86_preserved_handle_exception);

/*
 * Low-power wait in parking loop.
 */
void arch_cpu_preserved_park_wait(void)
{
	cpu_relax();
}

void arch_cpu_preserved_load_desc(void)
{
	asm volatile("lgdt %0" : : "m" (x86_preserved_gdt_desc));
	native_load_idt(&x86_preserved_idt_desc);
}

void arch_cpu_preserved_switch_pgd(phys_addr_t pgd_pa)
{
	unsigned long cr4;

	if (!pgd_pa)
		return;

	native_write_cr3(pgd_pa);

	asm volatile("mov %%cr4, %0" : "=r" (cr4));
	if (cr4 & X86_CR4_PGE)
		asm volatile("mov %0, %%cr4" : : "r" (cr4 & ~X86_CR4_PGE) : "memory");
}

/*
 * Disables local interrupts on the physical core, loads preserved IDT/GDT,
 * and switches to the session's isolated PGD.
 */
void arch_cpu_preserved_park_init(int cpu)
{
	struct cpu_preserved_stack_context *sctx = cpu_preserved_get_stack_context();
	u32 spiv;

	if (!sctx || !sctx->session_pgd_pa)
		return;

	native_irq_disable();
	arch_cpu_preserved_load_desc();
	arch_cpu_preserved_switch_pgd(sctx->session_pgd_pa);

	spiv = (u32)native_rdmsrq(APIC_BASE_MSR + (APIC_SPIV >> 4));
	if (!(spiv & APIC_SPIV_APIC_ENABLED)) {
		spiv |= APIC_SPIV_APIC_ENABLED;
		native_wrmsrq(APIC_BASE_MSR + (APIC_SPIV >> 4), spiv);
	}
}

/*
 * Disable hardware virtualization on physical core so INIT is recognized.
 */
static void arch_cpu_preserved_virt_teardown(void)
{
	unsigned long cr4;

	asm volatile("mov %%cr4, %0" : "=r" (cr4));
	if (cr4 & X86_CR4_VMXE) {
		asm volatile("1: vmxoff\n\t"
			     "2:\n\t"
			     _ASM_EXTABLE(1b, 2b)
			     : : : "memory", "cc");
		asm volatile("mov %0, %%cr4" : : "r" (cr4 & ~X86_CR4_VMXE) : "memory");
	}

	if (x86_preserved_has_svm) {
		u64 efer = native_rdmsrq(MSR_EFER);

		if (efer & EFER_SVME) {
			asm volatile("stgi" : : : "memory");
			native_wrmsrq(MSR_EFER, efer & ~EFER_SVME);
		}
	}
}

/*
 * Architecture cleanup on park loop exit.
 */
void arch_cpu_preserved_park_finish(int cpu __maybe_unused)
{
	arch_cpu_preserved_virt_teardown();
}

bool arch_cpu_preserved_is_active(void)
{
	struct cpu_preserved_stack_context *sctx = cpu_preserved_get_stack_context();
	unsigned long cr3 = __native_read_cr3();

	return sctx && sctx->session_pgd_pa && cr3 == sctx->session_pgd_pa;
}

void arch_cpu_preserved_park_worker(int cpu)
{
	cpu_preserved_park_loop(cpu);

	arch_cpu_preserved_park_finish(cpu);
	native_irq_disable();
	cpu_preserved_set_dead();
	while (1) {
		native_irq_disable();
		asm volatile("hlt");
	}
}
STACK_FRAME_NON_STANDARD(arch_cpu_preserved_park_worker);

/*
 * x86 has hardware-coherent caches for normal memory and page-table walks.
 */
void arch_cpu_preserved_dcache_clean(unsigned long start, unsigned long end)
{
}

void arch_cpu_preserved_dcache_inval(unsigned long start, unsigned long end)
{
}
