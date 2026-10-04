/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 */
#ifndef __ASM_X86_CPU_PRESERVE_H
#define __ASM_X86_CPU_PRESERVE_H

#include <asm/desc_defs.h>
#include <asm/page_types.h>
#include <asm/segment.h>
#include <asm/trapnr.h>

#ifdef CONFIG_LIVEUPDATE_CPU
struct x86_preserved_fault {
	unsigned long count;
	unsigned long vector;
	unsigned long error_code;
	unsigned long ip;
	unsigned long sp;
	unsigned long cr2;
	unsigned long cr3;
	void (*abort_fn)(int cpu, const struct x86_preserved_fault *fault);
	void *abort_data;
};

extern gate_desc x86_preserved_idt[IDT_ENTRIES]
	__cpu_preserved_sym_asm(x86_preserved_idt);
extern struct desc_ptr x86_preserved_idt_desc
	__cpu_preserved_sym_asm(x86_preserved_idt_desc);

void arch_cpu_preserved_load_desc(void)
	__cpu_preserved_sym_asm(arch_cpu_preserved_load_desc);
bool arch_cpu_preserved_is_active(void)
	__cpu_preserved_sym_asm(arch_cpu_preserved_is_active);
#else
static inline void arch_cpu_preserved_load_desc(void) {}
static inline bool arch_cpu_preserved_is_active(void) { return false; }
#endif

#endif /* __ASM_X86_CPU_PRESERVE_H */
