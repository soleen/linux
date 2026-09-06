/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_ARM64_CARETAKER_H
#define __ASM_ARM64_CARETAKER_H

#include <asm/barrier.h>
#include <asm/cacheflush.h>
#include <asm/cputype.h>

static inline void caretaker_arch_park_cpu_wait(void)
{
	wfe();
}

static inline void caretaker_arch_wake_parked_cpu(void)
{
	dsb(ishst);
	sev();
}

asmlinkage void arch_cpu_preserved_dcache_clean(unsigned long start, unsigned long end);
asmlinkage void arch_cpu_preserved_dcache_inval(unsigned long start, unsigned long end);

static inline void caretaker_arch_dcache_clean_inval_poc(unsigned long start,
							 unsigned long end)
{
	arch_cpu_preserved_dcache_clean(start, end);
}

static inline void caretaker_arch_dcache_inval_poc(unsigned long start,
						   unsigned long end)
{
	arch_cpu_preserved_dcache_inval(start, end);
}

#include <asm/pgtable-types.h>

#ifdef CONFIG_LIVEUPDATE_CPU
extern phys_addr_t arm64_caretaker_pgd_pa;
#else
#define arm64_caretaker_pgd_pa 0ULL
#endif

asmlinkage void notrace caretaker_die_psci(int cpu);
extern char caretaker_hyp_vector[];

#include <asm/arch_timer.h>
#include <asm/sysreg.h>
#include <linux/bits.h>
#include <asm/tlbflush.h>
#include <asm/virt.h>

static inline void arm64_flush_host_tlb_local(void)
{
	dsb(nshst);
	if (is_kernel_in_hyp_mode()) {
		asm volatile("tlbi alle2\n"
			     "tlbi vmalle1\n"
			     "dsb nsh\n"
			     "isb\n" ::: "memory");
	} else {
		local_flush_tlb_all();
	}
}

static inline void arm64_flush_host_tlb_all(void)
{
	dsb(ishst);
	if (is_kernel_in_hyp_mode()) {
		asm volatile("tlbi alle2is\n"
			     "tlbi vmalle1is\n"
			     "dsb ish\n"
			     "isb\n" ::: "memory");
	} else {
		flush_tlb_all();
	}
}

static inline void arm64_flush_host_tlb_page(unsigned long va)
{
	dsb(ishst);
	if (is_kernel_in_hyp_mode()) {
		u64 arg = (va >> 12) & GENMASK_ULL(43, 0);
		asm volatile("tlbi vae2is, %0\n"
			     "tlbi vaale1is, %0\n"
			     "dsb ish\n"
			     "isb\n" : : "r" (arg) : "memory");
	} else {
		flush_tlb_kernel_range(va, va + PAGE_SIZE);
	}
}

struct caretaker_sched_config;

static inline u64 __cpu_preserved_text arch_caretaker_read_counter(void)
{
	return read_sysreg(cntpct_el0);
}

u64 arch_caretaker_ticks_to_ns(u64 ticks);
void arch_caretaker_update_quantum_ticks(struct caretaker_sched_config *cfg);

struct caretaker_fault_info {
	u64 elr;
	u64 esr;
	u64 far;
	u64 count;
};

extern struct caretaker_fault_info arm64_caretaker_faults[NR_CPUS];
void arm64_caretaker_handle_invalid(u64 elr, u64 esr, u64 far);

struct arm64_caretaker_diag {
	u64 enter_count;
	u64 exit_count;
	u64 last_enter_ticks;
	u64 last_exit_ticks;
	u64 last_ret;
	u64 last_pc;
	u64 last_esr;
	u64 last_far;
	u64 last_hpfar;
	u64 last_exit_type;
	u64 last_handled;
	u64 cnthp_ctl;
	u64 cnthp_cval;
	u64 counter_val;
	u64 deadline_val;
	u64 vcpu_run_loops;
	u64 stage;
	u64 sub_stage;
};

extern struct arm64_caretaker_diag arm64_caretaker_diag[NR_CPUS];
void arch_cpu_preserved_set_stage(int cpu, u64 stage, u64 sub_stage);

int arch_cpu_preserved_mpidr_to_cpu(u64 mpidr);

static inline int arm64_caretaker_get_pcpu(void)
{
	u64 mpidr = read_cpuid_mpidr() & MPIDR_HWID_BITMASK;
	int cpu = arch_cpu_preserved_mpidr_to_cpu(mpidr);

	if (cpu >= 0 && cpu < NR_CPUS)
		return cpu;
	return (int)MPIDR_AFFINITY_LEVEL(mpidr, 0);
}

#endif /* __ASM_ARM64_CARETAKER_H */
