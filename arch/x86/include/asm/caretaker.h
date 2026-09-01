/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_X86_CARETAKER_H
#define __ASM_X86_CARETAKER_H

#include <linux/types.h>
#include <asm/msr.h>
#include <asm/tsc.h>

struct caretaker_sched_config;

static inline u64 __cpu_preserved_text arch_caretaker_read_counter(void)
{
	return rdtsc();
}

u64 arch_caretaker_ticks_to_ns(u64 ticks);
void arch_caretaker_update_quantum_ticks(struct caretaker_sched_config *cfg);

#endif /* __ASM_X86_CARETAKER_H */
