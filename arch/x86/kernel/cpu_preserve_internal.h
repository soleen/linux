/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ARCH_X86_KERNEL_CPU_PRESERVE_INTERNAL_H
#define _ARCH_X86_KERNEL_CPU_PRESERVE_INTERNAL_H

#include <linux/cpu_preserve.h>
#include <linux/types.h>
#include <asm/desc_defs.h>
#include <asm/segment.h>

extern struct desc_struct x86_preserved_gdt[GDT_ENTRIES]
	__cpu_preserved_sym_asm(x86_preserved_gdt);
extern struct desc_ptr x86_preserved_gdt_desc
	__cpu_preserved_sym_asm(x86_preserved_gdt_desc);
extern bool x86_preserved_has_svm
	__cpu_preserved_sym_asm(x86_preserved_has_svm);
extern const char x86_preserved_exc_handler_array[NUM_EXCEPTION_VECTORS][EARLY_IDT_HANDLER_SIZE]
	__cpu_preserved_sym_asm(x86_preserved_exc_handler_array);

void x86_preserved_iret_stub(void)
	__cpu_preserved_sym_asm(x86_preserved_iret_stub);
void x86_preserved_apic_eoi_stub(void)
	__cpu_preserved_sym_asm(x86_preserved_apic_eoi_stub);

struct pt_regs;
asmlinkage void x86_preserved_handle_exception(struct pt_regs *regs, int vector)
	__cpu_preserved_sym_asm(x86_preserved_handle_exception);
void arch_cpu_preserved_park_worker(int cpu)
	__cpu_preserved_sym_asm(arch_cpu_preserved_park_worker);
asmlinkage void arch_cpu_preserved_call_on_stack(int cpu, unsigned long stack,
						 void (*fn)(int cpu))
	__cpu_preserved_sym_asm(arch_cpu_preserved_call_on_stack);

#endif /* _ARCH_X86_KERNEL_CPU_PRESERVE_INTERNAL_H */
