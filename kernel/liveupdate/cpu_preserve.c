// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 */

/**
 * DOC: Preserved CPU Subsystem
 *
 * Live Update allows updating the host kernel while preserving the state of
 * hardware resources across the transition. While memfd-based memory
 * preservation is already supported via LUO and PCI device preservation is
 * handled by VFIO and IOMMU, physical CPU cores represent another fundamental
 * class of hardware resource that requires preservation.
 *
 * A primary motivation is preserving virtual machine (VM) workloads across
 * host kernel updates without pausing the guest. By separating a physical
 * core from standard host scheduling and keeping it active across the kexec
 * reboot, guest vCPUs or dedicated bare-metal tasks can continue
 * uninterrupted execution on-core.
 *
 * This subsystem provides the generic, hypervisor-agnostic foundation for
 * physical CPU preservation.
 *
 * The lifecycle state machine, the sysfs/LUO file-descriptor binding and the
 * requirements an architecture must satisfy to select
 * CONFIG_ARCH_SUPPORTS_LIVEUPDATE_CPU are described in
 * Documentation/liveupdate/cpu_preservation.rst; the individual
 * arch_cpu_preserved_*() hooks are documented in include/linux/cpu_preserve.h.
 */

#define pr_fmt(fmt) "cpu_preserve: " fmt

#include <linux/cpu.h>
#include <linux/cpu_preserve.h>
#include <linux/delay.h>
#include <linux/kexec.h>
#include <linux/kexec_handover.h>
#include <linux/kho/abi/cpu.h>
#include <linux/kho_block.h>
#include <linux/liveupdate.h>
#include <linux/mm.h>
#include <linux/objtool.h>
#include <linux/reboot.h>

#include <asm/sections.h>

/**
 * struct cpu_preserved_pcpu - Per-CPU runtime state for CPU preservation
 * @state: Serialized KHO state of the preserved CPU (CPU ID, workload type,
 *         session name, descriptive name, stack physical address, order).
 * @entry_fn: Workload callback function executed repeatedly on the physical
 *            core while parked in cpu_preserved_park().
 * @entry_data: Opaque argument passed to @entry_fn.
 * @stack: Virtual address of the dedicated stack allocated in preserved
 *         memory.
 *
 * Tracks the live execution state of an offlined, preserved physical CPU core.
 * Allocated dynamically via kho_alloc_preserve() so that the parked physical
 * core can poll and access its state continuously across host live update.
 */
struct cpu_preserved_pcpu {
	struct cpu_preserved_entry_ser state ____cacheline_aligned;
	void (*entry_fn)(void *data) ____cacheline_aligned;
	void *entry_data;
	void *stack;
	phys_addr_t pgd_pa;
};

/*
 * struct cpu_preserved_incoming - Incoming preserved CPU state
 * @mask: Mask of CPUs preserved by the previous kernel.
 * @pcpus: Pointer to previous kernel's physical cpu_preserved_pcpu array.
 */
struct cpu_preserved_incoming {
	cpumask_t mask;
	struct cpu_preserved_pcpu *pcpus;
};

/*
 * struct cpu_preserved_outgoing - Outgoing preserved CPU state
 * @mask: Mask of CPUs currently preserved under this kernel.
 * @pcpus: Per-CPU state array in preserved memory.
 * @ser: Allocated KHO serialization structure for handover.
 * @block_set: Block set containing serialized preserved CPU entries.
 */
struct cpu_preserved_outgoing {
	cpumask_t mask;
	struct cpu_preserved_pcpu *pcpus;
};

static DEFINE_MUTEX(cpu_preserved_lock);
static struct cpu_preserved_incoming cpu_preserved_incoming __cpu_preserved_data;
static struct cpu_preserved_outgoing cpu_preserved_outgoing __cpu_preserved_data;
static cpumask_t cpu_preserved_mask __cpu_preserved_data;
static phys_addr_t cpu_preserved_pcpus_pa __cpu_preserved_data;
static struct cpu_preserved_pcpu *cpu_preserved_pcpus_va __cpu_preserved_data;

static struct page *cpu_preserved_text_pages;
static unsigned int cpu_preserved_text_order;
static struct page *cpu_preserved_data_pages;
static unsigned int cpu_preserved_data_order;

/**
 * cpu_preserved_init_runtime_buffer - Allocate execution buffer outside Scratch
 *
 * The compiled __cpu_preserved_text and __cpu_preserved_data sections are
 * part of the host kernel binary image. During a host kexec live update, the
 * memory range occupied by the current kernel is designated as KHO Scratch
 * memory to allow the incoming kernel to be placed and unpacked. By definition,
 * Scratch memory must not contain preserved memory, as the incoming kernel
 * will overwrite Scratch during boot.
 *
 * Preserving the compiled text and data sections in-place would create a
 * conflict where preserved memory overlaps Scratch, triggering handover
 * failures or memory corruption when the incoming kernel overwrites the old
 * kernel text while preserved physical CPUs are still executing Caretaker loops
 * on their cores.
 *
 * To avoid this, we dynamically allocate dedicated text and data buffer pages
 * from free memory (outside Scratch) via alloc_pages(GFP_KERNEL), copy the
 * compiled text and data into them, remap the virtual addresses in the page
 * tables to point to these newly allocated pages, and preserve only these
 * external pages with KHO. Preserved CPUs execute out of these external pages,
 * allowing the incoming kernel to freely overwrite Scratch.
 *
 * Return: 0 on success, or negative error code on allocation/setup failure.
 */
int cpu_preserved_init_runtime_buffer(void)
{
	size_t text_size = (unsigned long)__cpu_preserved_text_end -
			   (unsigned long)__cpu_preserved_text_start;
	size_t data_size = (unsigned long)__cpu_preserved_data_end -
			   (unsigned long)__cpu_preserved_data_start;
	unsigned int text_nr_pages = DIV_ROUND_UP(text_size, PAGE_SIZE);
	unsigned int data_nr_pages = DIV_ROUND_UP(data_size, PAGE_SIZE);
	int ret;

	if (cpu_preserved_text_pages) {
		cpu_preserved_preserve_runtime_buffer();
		return 0;
	}

	cpu_preserved_text_order = get_order(text_size);
	cpu_preserved_text_pages = alloc_pages(GFP_KERNEL, cpu_preserved_text_order);
	if (!cpu_preserved_text_pages)
		return -ENOMEM;

	cpu_preserved_data_order = get_order(data_size);
	cpu_preserved_data_pages = alloc_pages(GFP_KERNEL, cpu_preserved_data_order);
	if (!cpu_preserved_data_pages) {
		__free_pages(cpu_preserved_text_pages, cpu_preserved_text_order);
		cpu_preserved_text_pages = NULL;
		return -ENOMEM;
	}

	memcpy(page_address(cpu_preserved_text_pages),
	       __cpu_preserved_text_start, text_size);
	memcpy(page_address(cpu_preserved_data_pages),
	       __cpu_preserved_data_start, data_size);

	ret = arch_cpu_preserved_setup_buffer(cpu_preserved_text_pages,
					      text_nr_pages,
					      cpu_preserved_data_pages,
					      data_nr_pages);
	if (ret) {
		__free_pages(cpu_preserved_data_pages, cpu_preserved_data_order);
		__free_pages(cpu_preserved_text_pages, cpu_preserved_text_order);
		cpu_preserved_data_pages = NULL;
		cpu_preserved_text_pages = NULL;
		return ret;
	}

	return 0;
}

phys_addr_t cpu_preserved_get_text_pa(void)
{
	return cpu_preserved_text_pages ? page_to_phys(cpu_preserved_text_pages) : 0;
}

phys_addr_t cpu_preserved_get_data_pa(void)
{
	return cpu_preserved_data_pages ? page_to_phys(cpu_preserved_data_pages) : 0;
}

/**
 * cpu_is_preserved - Check whether a CPU is currently preserved
 * @cpu: Logical CPU identifier.
 *
 * Return: True if @cpu is currently preserved, false otherwise.
 */
bool __cpu_preserved_text cpu_is_preserved(int cpu)
{
	if ((unsigned int)cpu >= CONFIG_NR_CPUS)
		return false;
	cpu_preserved_inval(&cpu_preserved_mask);
	return cpumask_test_cpu(cpu, &cpu_preserved_mask);
}
EXPORT_SYMBOL_GPL(cpu_is_preserved);

/**
 * cpu_preserved_is_incoming - Check if CPU was preserved by previous kernel
 * @cpu: Logical CPU identifier.
 *
 * Return: True if @cpu was handed over as preserved from the previous kernel
 * across kexec and has not yet been unpreserved, false otherwise.
 */
bool __cpu_preserved_text cpu_preserved_is_incoming(int cpu)
{
	if ((unsigned int)cpu >= CONFIG_NR_CPUS)
		return false;
	return cpumask_test_cpu(cpu, &cpu_preserved_incoming.mask);
}
EXPORT_SYMBOL_GPL(cpu_preserved_is_incoming);

static struct cpu_preserved_pcpu * __cpu_preserved_text cpu_preserved_get_pcpu(int cpu)
{
	struct cpu_preserved_pcpu *pcpus;

	if ((unsigned int)cpu >= CONFIG_NR_CPUS)
		return NULL;

	cpu_preserved_inval(&cpu_preserved_pcpus_va);
	pcpus = READ_ONCE(cpu_preserved_pcpus_va);
	if (pcpus)
		return &pcpus[cpu];

	if (!cpu_is_preserved(cpu))
		return NULL;

	if (cpu_preserved_is_incoming(cpu)) {
		return cpu_preserved_incoming.pcpus ?
			&cpu_preserved_incoming.pcpus[cpu] : NULL;
	}
	return cpu_preserved_outgoing.pcpus ?
		&cpu_preserved_outgoing.pcpus[cpu] : NULL;
}

phys_addr_t __cpu_preserved_text cpu_preserved_get_pgd(int cpu)
{
	struct cpu_preserved_pcpu *pcpu = cpu_preserved_get_pcpu(cpu);

	if (!pcpu)
		return 0;

	cpu_preserved_inval(&pcpu->pgd_pa);
	return READ_ONCE(pcpu->pgd_pa);
}
EXPORT_SYMBOL_GPL(cpu_preserved_get_pgd);

/**
 * cpu_get_preserved_mask - Get the mask of all currently preserved CPUs
 *
 * Return: Read-only pointer to the cpumask of preserved CPUs.
 */
const struct cpumask *cpu_get_preserved_mask(void)
{
	return &cpu_preserved_mask;
}
EXPORT_SYMBOL_GPL(cpu_get_preserved_mask);

#define CPU_PRESERVED_EXITING		2
#define CPU_PRESERVED_DEAD		3

void __cpu_preserved_text cpu_preserved_set_dead(int cpu)
{
	struct cpu_preserved_pcpu *pcpu = cpu_preserved_get_pcpu(cpu);

	if (pcpu) {
		WRITE_ONCE(pcpu->state.workload, CPU_PRESERVED_DEAD);
		pcpu->state.name[0] = '\0';
	}
}
EXPORT_SYMBOL_GPL(cpu_preserved_set_dead);

static void cpu_signal_exit(int cpu)
{
	struct cpu_preserved_pcpu *pcpu = cpu_preserved_get_pcpu(cpu);

	if (!pcpu)
		return;

	WRITE_ONCE(pcpu->state.workload, CPU_PRESERVED_EXITING);
	WRITE_ONCE(pcpu->entry_fn, NULL);
	WRITE_ONCE(pcpu->entry_data, NULL);
	cpu_preserved_clean(pcpu);
}


bool __cpu_preserved_text cpu_preserved_should_exit(int cpu)
{
	struct cpu_preserved_pcpu *pcpu = cpu_preserved_get_pcpu(cpu);

	if (!pcpu)
		return false;

	cpu_preserved_inval(pcpu);
	return READ_ONCE(pcpu->state.workload) != CPU_PRESERVED_PARKED ||
	       READ_ONCE(pcpu->entry_fn) == NULL;
}
EXPORT_SYMBOL_GPL(cpu_preserved_should_exit);

/**
 * cpu_preserved_attach_workload - Attach & start workload execution on core
 * @cpu: Logical CPU identifier.
 * @name: Human-readable workload description name.
 * @entry_fn: Workload callback to execute repeatedly on the physical core.
 * @data: Opaque argument passed to @entry_fn.
 *
 * Transitions @cpu from idle parking to executing @entry_fn(@data) on the
 * physical core, and kicks the CPU to begin execution immediately.
 *
 * Return: 0 on success, -EINVAL if @cpu is invalid, -ENODEV if not preserved,
 * or -EBUSY if a workload is already attached.
 */
static int cpu_wait_dead(int cpu)
{
	struct cpu_preserved_pcpu *pcpu = cpu_preserved_get_pcpu(cpu);
	int retries = 0;

	if (!pcpu) {
		pr_err("%s: cpu=%d pcpu is NULL\n", __func__, cpu);
		return -ENODEV;
	}

	while (retries < 200000) {
		cpu_preserved_inval(pcpu);
		if (READ_ONCE(pcpu->state.workload) == CPU_PRESERVED_DEAD)
			break;
		if ((retries % 50) == 0)
			arch_cpu_preserved_kick(cpu);
		udelay(100);
		retries++;
	}

	if (READ_ONCE(pcpu->state.workload) != CPU_PRESERVED_DEAD) {
		pr_err("%s: cpu=%d workload=%d name='%s' retries=%d\n",
		       __func__, cpu, READ_ONCE(pcpu->state.workload),
		       pcpu->state.name, retries);
		return -ETIMEDOUT;
	}

	arch_cpu_preserved_wait_dead(cpu);
	return 0;
}

void __cpu_preserved_text cpu_preserved_park_loop(int cpu)
{
	struct cpu_preserved_pcpu *pcpu = cpu_preserved_get_pcpu(cpu);
	struct cpu_preserved_entry_ser *entry;

	if (!pcpu)
		return;

	entry = &pcpu->state;
	entry->cpu = cpu;
	WRITE_ONCE(entry->workload, CPU_PRESERVED_PARKED);
	if (entry->name[0] == '\0') {
		entry->name[0] = 'p';
		entry->name[1] = 'a';
		entry->name[2] = 'r';
		entry->name[3] = 'k';
		entry->name[4] = 'e';
		entry->name[5] = 'd';
		entry->name[6] = '\0';
	}
	cpu_preserved_clean(pcpu);

	arch_cpu_preserved_park_init(cpu);

	while (1) {
		void (*fn)(void *data);
		void *arg;

		cpu_preserved_inval(pcpu);
		if (READ_ONCE(entry->workload) != CPU_PRESERVED_PARKED)
			break;

		fn = READ_ONCE(pcpu->entry_fn);
		arg = READ_ONCE(pcpu->entry_data);

		if (fn) {
			fn(arg);
			WRITE_ONCE(pcpu->entry_fn, NULL);
			WRITE_ONCE(pcpu->entry_data, NULL);
			cpu_preserved_clean(&pcpu->entry_fn);
			cpu_preserved_clean(&pcpu->entry_data);
		} else {
			arch_cpu_preserved_park_wait();
		}
		barrier();
	}

	WRITE_ONCE(entry->workload, CPU_PRESERVED_DEAD);
	entry->name[0] = '\0';
	cpu_preserved_clean(&pcpu->state);
}
EXPORT_SYMBOL_GPL(cpu_preserved_park_loop);
