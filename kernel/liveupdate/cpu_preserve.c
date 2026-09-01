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
 * CPU Lifecycle State Progression::
 *
 *     +-------------------------------------------------------------+
 *     |                          ONLINE                             |
 *     |               (Normal host task scheduling)                 |
 *     +-------------------------------------------------------------+
 *                                    |
 *                                    | preserve (via LUO fd)
 *                                    v
 *     +-------------------------------------------------------------+
 *     |                     PRESERVED_PARKED                        |
 *     |          (Removed from scheduler, loops in park)            |
 *     +-------------------------------------------------------------+
 *                                    |
 *                                    | [Live Update: kexec]
 *                                    v
 *     +-------------------------------------------------------------+
 *     |                     INCOMING PRESERVED                      |
 *     |         (Parked on-core, skipped in secondary boot)         |
 *     +-------------------------------------------------------------+
 *                                    |
 *                                    | unpreserve / retrieve (via LUO session)
 *                                    v
 *     +-------------------------------------------------------------+
 *     |                          OFFLINE                            |
 *     |            (Park loop exited, architecturally idle)         |
 *     +-------------------------------------------------------------+
 *                                    |
 *                                    | cpu_up()
 *                                    v
 *     +-------------------------------------------------------------+
 *     |                          ONLINE                             |
 *     |                (Rejoined host scheduling)                   |
 *     +-------------------------------------------------------------+
 *
 * Lifecycle & File Descriptor Binding:
 *   1. Sysfs Control File: Each hotpluggable CPU exports a read-only sysfs
 *      attribute at `/sys/devices/system/cpu/cpu<N>/preserve`. The file
 *      descriptor (fd) of this file handles the lifecycle of the preserved CPU.
 *   2. Preservation via LUO: Userspace opens this file and registers the fd
 *      with LUO. Preserving the file offlines the
 *      core from host scheduling, migrates its interrupts and tasks, and
 *      transitions the CPU from online into the parked state
 *      (cpu_preserved_park()).
 *   3. KHO & Memory Preservation: The parking loop, dedicated preserved CPU
 *      stacks, kernel page tables, and preserved CPU state reside in memory
 *      preserved across kexec via KHO.
 *   4. Incoming Boot: During early boot, the incoming kernel restores the
 *      preserved CPU mask before secondary SMP bringup and skips bringing
 *      preserved cores online, maintaining isolation.
 *   5. Retrieval & Unpreservation: When userspace retrieves the session in the
 *      incoming kernel, it receives the open `preserve` file descriptor.
 *      Retrieving the session or closing the fd unpreserves the CPU, signaling
 *      the core to exit the parking loop, drop into an offline state, and
 *      return online via standard cpu_up().
 *
 * Architecture Requirements for CONFIG_ARCH_SUPPORTS_LIVEUPDATE_CPU:
 * In addition to supporting CPU hotplugging (CONFIG_HOTPLUG_CPU), the
 * following functions and linking must be implemented by the
 * architecture to support physical CPU preservation
 * (ARCH_SUPPORTS_LIVEUPDATE_CPU):
 *
 *   - Linker Script:
 *     Include CPU_PRESERVED_TEXT in `arch/<arch>/kernel/vmlinux.lds.S` within
 *     the executable text section.
 *
 *   - Preserved Text Section (__cpu_preserved_text):
 *     Functions executed by a parked core or during live update transitions
 *     must be annotated with ``__cpu_preserved_text`` so their instructions
 *     reside in the KHO-preserved ``.text.cpu_preserved`` section:
 *
 *     * arch_cpu_preserved_kick(cpu):
 *       Wake up or signal a preserved CPU (e.g. via NMI or IPI/SEV) when
 *       transitioning workload states or requesting the core to exit parking.
 *     * arch_cpu_preserved_park_wait():
 *       Low-power relax loop instruction executed while waiting in the
 *       parking loop (e.g. ``cpu_relax()`` / PAUSE on x86, ``wfe`` on arm64).
 *     * arch_cpu_preserved_park_init():
 *       Prepare architecture state upon entering the parking loop (e.g.
 *       disabling local interrupts or masking DAIF).
 *     * arch_cpu_preserved_park_finish():
 *       Cleanup or power-down upon exiting the parking loop (e.g.
 *       re-enabling local interrupts on x86, or invoking PSCI CPU_OFF on
 *       arm64 so the core can be re-enabled via PSCI CPU_ON).
 *     * arch_cpu_preserved_dcache_clean(start, end):
 *       Clean data cache lines to PoC for the specified virtual
 *       address range.
 *     * arch_cpu_preserved_dcache_inval(start, end):
 *       Invalidate data cache lines from PoC for the specified range.
 *
 *   - Page Table Preservation (Normal Text):
 *       - arch_cpu_preserved_preserve_pagetables():
 *         Executed during live update preparation before kexec to preserve
 *         kernel page table pages backing preserved text and data.
 *
 *   - CPU Hotplug & Stop IPI Isolation:
 *     Exclude preserved CPUs from being sent stop signals (such as NMI or stop
 *     IPIs in machine reboot and crash paths), and avoid tearing down local
 *     interrupt controllers (e.g. LAPIC or GIC CPU interface) during CPU
 *     disable when the core is being preserved.
 */

#define pr_fmt(fmt) "cpu_preserve: " fmt

#include <linux/cpu.h>
#include <linux/cpu_preserve.h>
#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/kexec.h>
#include <linux/kexec_handover.h>
#include <linux/kho/abi/cpu.h>
#include <linux/kho_block.h>
#include <linux/liveupdate.h>
#include <linux/mm.h>
#include <linux/reboot.h>
#include <asm/sections.h>

#define CPU_PRESERVED_STACK_ORDER	ARCH_CPU_PRESERVED_STACK_ORDER

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
	struct cpu_preserved_ser *ser;
	struct kho_block_set block_set;
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

	if (cpu_preserved_text_pages)
		return 0;

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

/**
 * cpu_is_preserved - Check whether a CPU is currently preserved
 * @cpu: Logical CPU identifier.
 *
 * Return: True if @cpu is currently preserved, false otherwise.
 */
bool __cpu_preserved_text cpu_is_preserved(int cpu)
{
	if (cpu < 0 || cpu >= NR_CPUS)
		return false;
	arch_cpu_preserved_dcache_inval((unsigned long)&cpu_preserved_mask,
					(unsigned long)&cpu_preserved_mask + sizeof(cpu_preserved_mask));
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
	if (cpu < 0 || cpu >= NR_CPUS)
		return false;
	return cpumask_test_cpu(cpu, &cpu_preserved_incoming.mask);
}
EXPORT_SYMBOL_GPL(cpu_preserved_is_incoming);

static struct cpu_preserved_pcpu * __cpu_preserved_text cpu_preserved_get_pcpu(int cpu)
{
	struct cpu_preserved_pcpu *pcpus;

	if (cpu < 0 || cpu >= NR_CPUS)
		return NULL;

	arch_cpu_preserved_dcache_inval((unsigned long)&cpu_preserved_pcpus_va,
					(unsigned long)&cpu_preserved_pcpus_va + sizeof(cpu_preserved_pcpus_va));
	pcpus = READ_ONCE(cpu_preserved_pcpus_va);
	if (pcpus)
		return &pcpus[cpu];

	if (!cpu_is_preserved(cpu))
		return NULL;

	if (cpu_preserved_is_incoming(cpu))
		return cpu_preserved_incoming.pcpus ?
			&cpu_preserved_incoming.pcpus[cpu] : NULL;
	return cpu_preserved_outgoing.pcpus ?
		&cpu_preserved_outgoing.pcpus[cpu] : NULL;
}

phys_addr_t __cpu_preserved_text cpu_preserved_get_pgd(int cpu)
{
	struct cpu_preserved_pcpu *pcpu;

	if (cpu < 0 || cpu >= NR_CPUS)
		return 0;

	pcpu = cpu_preserved_get_pcpu(cpu);
	if (!pcpu)
		return 0;

	arch_cpu_preserved_dcache_inval((unsigned long)&pcpu->pgd_pa,
					(unsigned long)&pcpu->pgd_pa + sizeof(pcpu->pgd_pa));
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

/**
 * cpu_preserved_filter_offline_mask - Remove preserved CPUs from offline mask
 * @mask: Target cpumask to filter in-place.
 *
 * Clears any currently preserved CPUs from @mask so that sysfs offline cpumask
 * does not report preserved CPUs as normal offline cores.
 */
void cpu_preserved_filter_offline_mask(struct cpumask *mask)
{
	cpumask_andnot(mask, mask, &cpu_preserved_mask);
}
EXPORT_SYMBOL_GPL(cpu_preserved_filter_offline_mask);

static const char *cpu_workload_name(enum cpu_preserved_workload workload)
{
	switch (workload) {
	case CPU_PRESERVED_PARKED:
		return "parked";
	default:
		return "none";
	}
}

/**
 * cpu_preserved_get_workload_name - Get the workload description for a CPU
 * @cpu: Logical CPU identifier.
 *
 * Return: Human-readable workload name string (e.g. "parked", custom workload
 * name, "online", or "offline").
 */
const char *cpu_preserved_get_workload_name(int cpu)
{
	struct cpu_preserved_pcpu *pcpu;

	if (cpu < 0 || cpu >= nr_cpu_ids)
		return "none";
	if (!cpu_is_preserved(cpu))
		return cpu_online(cpu) ? "online" : "offline";

	pcpu = cpu_preserved_get_pcpu(cpu);
	if (pcpu) {
		if (pcpu->state.name[0] != '\0')
			return pcpu->state.name;
		return cpu_workload_name(pcpu->state.workload);
	}
	return "none";
}
EXPORT_SYMBOL_GPL(cpu_preserved_get_workload_name);

/**
 * cpu_preserved_get_session_name - Get name of the owning LUO session for a CPU
 * @cpu: Logical CPU identifier.
 *
 * Return: String pointer to session name, or "none" if not preserved in
 * a session.
 */
const char *cpu_preserved_get_session_name(int cpu)
{
	struct cpu_preserved_pcpu *pcpu = cpu_preserved_get_pcpu(cpu);

	if (!pcpu || pcpu->state.session[0] == '\0')
		return "none";
	return pcpu->state.session;
}
EXPORT_SYMBOL_GPL(cpu_preserved_get_session_name);

#define CPU_PRESERVED_EXITING_CANCEL	2
#define CPU_PRESERVED_EXITING_KEXEC	3
#define CPU_PRESERVED_DEAD		4

static void cpu_kick(int cpu)
{
	arch_cpu_preserved_kick(cpu);
}

static void cpu_signal_exit(int cpu, bool is_incoming)
{
	struct cpu_preserved_pcpu *pcpu = cpu_preserved_get_pcpu(cpu);

	if (!pcpu)
		return;

	WRITE_ONCE(pcpu->state.workload,
		   is_incoming ? CPU_PRESERVED_EXITING_KEXEC :
				 CPU_PRESERVED_EXITING_CANCEL);
	WRITE_ONCE(pcpu->entry_fn, NULL);
	WRITE_ONCE(pcpu->entry_data, NULL);
	arch_cpu_preserved_dcache_clean((unsigned long)pcpu,
					(unsigned long)pcpu + sizeof(*pcpu));
}

static void cpu_preserved_sync_outgoing(void)
{
	struct cpu_preserved_outgoing *outgoing = &cpu_preserved_outgoing;
	struct kho_block_set_it it;
	unsigned int count;
	int cpu;

	if (!outgoing->ser || !outgoing->pcpus)
		return;

	outgoing->ser->pcpus_pa = virt_to_phys(outgoing->pcpus);
	kho_block_set_destroy(&outgoing->block_set);

	count = cpumask_weight(&outgoing->mask);
	outgoing->ser->count = count;
	outgoing->ser->entries = 0;

	if (!count)
		return;

	if (kho_block_set_grow(&outgoing->block_set, count))
		return;

	kho_block_set_it_init(&it, &outgoing->block_set);
	for_each_cpu(cpu, &outgoing->mask) {
		struct cpu_preserved_entry_ser *entry;

		entry = kho_block_set_it_reserve_entry(&it);
		if (!entry)
			break;
		*entry = outgoing->pcpus[cpu].state;
		entry->cpu = cpu;
	}

	outgoing->ser->entries = kho_block_set_head_pa(&outgoing->block_set);
}

bool __cpu_preserved_text cpu_preserved_should_exit(int cpu)
{
	struct cpu_preserved_pcpu *pcpu = cpu_preserved_get_pcpu(cpu);

	if (!pcpu)
		return false;

	arch_cpu_preserved_dcache_inval((unsigned long)pcpu,
					(unsigned long)pcpu + sizeof(*pcpu));
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
		pr_err("cpu_wait_dead: cpu=%d pcpu is NULL\n", cpu);
		return -ENODEV;
	}

	while (retries < 200000) {
		arch_cpu_preserved_dcache_inval((unsigned long)pcpu,
						(unsigned long)pcpu +
						sizeof(*pcpu));
		if (READ_ONCE(pcpu->state.workload) == CPU_PRESERVED_DEAD)
			break;
		if ((retries % 50) == 0)
			cpu_kick(cpu);
		udelay(100);
		retries++;
	}

	if (READ_ONCE(pcpu->state.workload) != CPU_PRESERVED_DEAD) {
		pr_err("cpu_wait_dead: cpu=%d workload=%d name='%s' retries=%d\n",
		       cpu, READ_ONCE(pcpu->state.workload), pcpu->state.name, retries);
		return -ETIMEDOUT;
	}

	arch_cpu_preserved_wait_dead(cpu);
	return 0;
}

int __cpu_preserved_text cpu_preserved_park_loop(int cpu)
{
	struct cpu_preserved_pcpu *pcpu = cpu_preserved_get_pcpu(cpu);
	struct cpu_preserved_entry_ser *entry;
	u32 final_workload;

	if (!pcpu)
		return 0;

	entry = &pcpu->state;
	entry->cpu = cpu;
	WRITE_ONCE(entry->workload, CPU_PRESERVED_PARKED);
	if (entry->name[0] == '\0')
		strscpy(entry->name, "parked", sizeof(entry->name));
	arch_cpu_preserved_dcache_clean((unsigned long)pcpu,
					(unsigned long)pcpu + sizeof(*pcpu));

	arch_cpu_preserved_park_init(cpu);

	while (1) {
		void (*fn)(void *);
		void *arg;

		arch_cpu_preserved_dcache_inval((unsigned long)pcpu,
						(unsigned long)pcpu +
						sizeof(*pcpu));
		if (READ_ONCE(entry->workload) != CPU_PRESERVED_PARKED)
			break;

		fn = READ_ONCE(pcpu->entry_fn);
		arg = READ_ONCE(pcpu->entry_data);

		if (fn) {
			fn(arg);
			WRITE_ONCE(pcpu->entry_fn, NULL);
			WRITE_ONCE(pcpu->entry_data, NULL);
			arch_cpu_preserved_dcache_clean((unsigned long)&pcpu->entry_fn,
							(unsigned long)(&pcpu->stack + 1));
		} else {
			arch_cpu_preserved_park_wait();
		}
		barrier();
	}

	final_workload = READ_ONCE(entry->workload);
	WRITE_ONCE(entry->workload, CPU_PRESERVED_DEAD);
	entry->name[0] = '\0';
	arch_cpu_preserved_dcache_clean((unsigned long)&pcpu->state,
					(unsigned long)(&pcpu->state + 1));

	return (final_workload == CPU_PRESERVED_EXITING_KEXEC) ? 1 : 0;
}
EXPORT_SYMBOL_GPL(cpu_preserved_park_loop);

/**
 * cpu_preserved_park - Main execution and parking loop for a preserved CPU
 * @cpu: Logical CPU identifier of the calling core.
 *
 * Called on the physical CPU being offlined/preserved. Enters a dedicated
 * low-power parking loop in preserved memory, repeatedly executing any
 * attached workload callback, until signaled to exit upon unpreservation.
 */
void __cpu_preserved_text cpu_preserved_park(int cpu)
{
	struct cpu_preserved_pcpu *pcpu = cpu_preserved_get_pcpu(cpu);

	if (pcpu && pcpu->stack) {
		unsigned long top_of_stack = (unsigned long)pcpu->stack +
			CPU_PRESERVED_STACK_SIZE - CPU_PRESERVED_STACK_HEADROOM;
		arch_cpu_preserved_park_on_stack(cpu, top_of_stack);
	} else {
		int is_kexec = cpu_preserved_park_loop(cpu);
		if (is_kexec)
			arch_cpu_preserved_park_finish(cpu);
	}
}
EXPORT_SYMBOL_GPL(cpu_preserved_park);

static int cpu_preserve(unsigned int cpu)
{
	struct cpu_preserved_outgoing *outgoing = &cpu_preserved_outgoing;
	struct cpu_preserved_pcpu *pcpu;
	struct page *stack_page;
	struct device *dev;
	void *stack;
	int ret = 0;

	if (cpu >= nr_cpu_ids || !cpu_possible(cpu))
		return -EINVAL;

	if (!cpu_is_hotpluggable(cpu))
		return -EOPNOTSUPP;

	stack_page = alloc_pages(GFP_KERNEL, CPU_PRESERVED_STACK_ORDER);
	if (!stack_page)
		return -ENOMEM;

	stack = page_address(stack_page);
	{
		struct cpu_preserved_stack_context *sctx = stack;

		memset(sctx, 0, sizeof(*sctx));
		sctx->magic = CPU_PRESERVED_STACK_MAGIC;
		sctx->cpu = cpu;
	}
	ret = kho_preserve_pages(stack_page, 1 << CPU_PRESERVED_STACK_ORDER);
	if (ret) {
		__free_pages(stack_page, CPU_PRESERVED_STACK_ORDER);
		return ret;
	}

	mutex_lock(&cpu_preserved_lock);

	if (cpu_is_preserved(cpu)) {
		mutex_unlock(&cpu_preserved_lock);
		kho_unpreserve_pages(stack_page, 1 << CPU_PRESERVED_STACK_ORDER);
		__free_pages(stack_page, CPU_PRESERVED_STACK_ORDER);
		return -EBUSY;
	}

	if (num_online_cpus() <= 1 && cpu_online(cpu)) {
		mutex_unlock(&cpu_preserved_lock);
		kho_unpreserve_pages(stack_page, 1 << CPU_PRESERVED_STACK_ORDER);
		__free_pages(stack_page, CPU_PRESERVED_STACK_ORDER);
		return -EBUSY;
	}

	if (!outgoing->pcpus) {
		ret = cpu_preserved_init_runtime_buffer();
		if (ret) {
			mutex_unlock(&cpu_preserved_lock);
			kho_unpreserve_pages(stack_page,
					     1 << CPU_PRESERVED_STACK_ORDER);
			__free_pages(stack_page, CPU_PRESERVED_STACK_ORDER);
			return ret;
		}

		outgoing->pcpus = kho_alloc_preserve(
			sizeof(*outgoing->pcpus) * nr_cpu_ids);
		if (IS_ERR(outgoing->pcpus)) {
			ret = PTR_ERR(outgoing->pcpus);
			outgoing->pcpus = NULL;
			mutex_unlock(&cpu_preserved_lock);
			kho_unpreserve_pages(stack_page,
					     1 << CPU_PRESERVED_STACK_ORDER);
			__free_pages(stack_page, CPU_PRESERVED_STACK_ORDER);
			return ret;
		}
		WRITE_ONCE(cpu_preserved_pcpus_va, outgoing->pcpus);
		WRITE_ONCE(cpu_preserved_pcpus_pa, virt_to_phys(outgoing->pcpus));
		arch_cpu_preserved_dcache_clean((unsigned long)&cpu_preserved_pcpus_va,
						(unsigned long)&cpu_preserved_pcpus_va + sizeof(cpu_preserved_pcpus_va));
		arch_cpu_preserved_dcache_clean((unsigned long)&cpu_preserved_pcpus_pa,
						(unsigned long)&cpu_preserved_pcpus_pa + sizeof(cpu_preserved_pcpus_pa));
	}

	cpumask_set_cpu(cpu, &outgoing->mask);
	cpumask_set_cpu(cpu, &cpu_preserved_mask);
	arch_cpu_preserved_dcache_clean((unsigned long)&cpu_preserved_mask,
					(unsigned long)&cpu_preserved_mask + sizeof(cpu_preserved_mask));
	pcpu = &outgoing->pcpus[cpu];
	pcpu->state.cpu = cpu;
	WRITE_ONCE(pcpu->state.workload, CPU_PRESERVED_PARKED);
	strscpy(pcpu->state.name, "parked", sizeof(pcpu->state.name));
	strscpy(pcpu->state.session, "none", sizeof(pcpu->state.session));
	pcpu->state.stack_pa = page_to_phys(stack_page);
	pcpu->state.stack_order = CPU_PRESERVED_STACK_ORDER;
	pcpu->stack = stack;
	{
		void *pgd = arch_cpu_preserved_get_pgd();
		if (pgd)
			pcpu->pgd_pa = virt_to_phys(pgd);
		else
			pcpu->pgd_pa = 0;
	}

	cpumask_clear_cpu(cpu, &cpu_preserved_incoming.mask);
	WRITE_ONCE(pcpu->entry_fn, NULL);
	WRITE_ONCE(pcpu->entry_data, NULL);
	cpu_preserved_sync_outgoing();

	mutex_unlock(&cpu_preserved_lock);

	if (cpu_online(cpu)) {
		dev = get_cpu_device(cpu);
		if (!dev) {
			mutex_lock(&cpu_preserved_lock);
			cpumask_clear_cpu(cpu, &outgoing->mask);
			cpumask_clear_cpu(cpu, &cpu_preserved_mask);
			WRITE_ONCE(pcpu->state.workload, 0);
			pcpu->state.name[0] = '\0';
			pcpu->state.session[0] = '\0';
			pcpu->state.stack_pa = 0;
			pcpu->state.stack_order = 0;
			pcpu->stack = NULL;
			if (cpumask_empty(&outgoing->mask) && !outgoing->ser) {
				kho_unpreserve_free(outgoing->pcpus);
				outgoing->pcpus = NULL;
			}
			cpu_preserved_sync_outgoing();
			mutex_unlock(&cpu_preserved_lock);
			kho_unpreserve_pages(stack_page,
					     1 << CPU_PRESERVED_STACK_ORDER);
			__free_pages(stack_page, CPU_PRESERVED_STACK_ORDER);
			return -ENODEV;
		}

		ret = cpu_device_down(dev);
		if (ret) {
			pr_err("Failed to offline preserved cpu %d: %d\n",
			       cpu, ret);
			mutex_lock(&cpu_preserved_lock);
			cpumask_clear_cpu(cpu, &outgoing->mask);
			cpumask_clear_cpu(cpu, &cpu_preserved_mask);
			WRITE_ONCE(pcpu->state.workload, 0);
			pcpu->state.name[0] = '\0';
			pcpu->state.session[0] = '\0';
			pcpu->state.stack_pa = 0;
			pcpu->state.stack_order = 0;
			pcpu->stack = NULL;
			if (cpumask_empty(&outgoing->mask) && !outgoing->ser) {
				kho_unpreserve_free(outgoing->pcpus);
				outgoing->pcpus = NULL;
			}
			cpu_preserved_sync_outgoing();
			mutex_unlock(&cpu_preserved_lock);
			kho_unpreserve_pages(stack_page,
					     1 << CPU_PRESERVED_STACK_ORDER);
			__free_pages(stack_page, CPU_PRESERVED_STACK_ORDER);
			return ret;
		}
		device_lock(dev);
		dev_set_offline(dev);
		device_unlock(dev);
	}

	/*
	 * Do not printk here: cpu_preserve() is invoked during physical
	 * CPU hotplug (dev_set_offline), which runs stop_machine().
	 * Emitting synchronous console messages here can cause deadlocks
	 * against nbcon/console locks when other CPUs are stopped.
	 */
	return 0;
}

/**
 * cpu_unpreserve - Unpreserve a physical CPU and restore it to online state
 * @cpu: Logical CPU identifier.
 *
 * Signals the CPU to exit the parking loop, cleans up preserved stack memory,
 * and restores the core to host scheduling via standard cpu_up().
 *
 * Return: 0 on success, or negative error code on failure.
 */
static int cpu_unpreserve(unsigned int cpu)
{
	struct cpu_preserved_incoming *incoming = &cpu_preserved_incoming;
	struct cpu_preserved_outgoing *outgoing = &cpu_preserved_outgoing;
	struct cpu_preserved_pcpu *pcpu;
	struct page *stack_page = NULL;
	unsigned int stack_order = 0;
	phys_addr_t stack_pa = 0;
	struct device *dev;
	void *stack;
	int ret = 0;

	if (cpu >= nr_cpu_ids || !cpu_possible(cpu))
		return -EINVAL;

	mutex_lock(&cpu_preserved_lock);

	if (!cpu_is_preserved(cpu)) {
		mutex_unlock(&cpu_preserved_lock);
		return 0;
	}

	bool is_incoming = cpu_preserved_is_incoming(cpu);

	pcpu = cpu_preserved_get_pcpu(cpu);
	cpu_signal_exit(cpu, is_incoming);
	cpu_kick(cpu);
	ret = cpu_wait_dead(cpu);
	if (ret) {
		mutex_unlock(&cpu_preserved_lock);
		return ret;
	}

	cpumask_clear_cpu(cpu, &outgoing->mask);
	cpumask_clear_cpu(cpu, &incoming->mask);
	cpumask_clear_cpu(cpu, &cpu_preserved_mask);
	arch_cpu_preserved_dcache_clean((unsigned long)&cpu_preserved_mask,
					(unsigned long)&cpu_preserved_mask + sizeof(cpu_preserved_mask));

	if (pcpu) {
		WRITE_ONCE(pcpu->state.workload, 0);
		pcpu->state.name[0] = '\0';
		pcpu->state.session[0] = '\0';
		WRITE_ONCE(pcpu->entry_fn, NULL);
		WRITE_ONCE(pcpu->entry_data, NULL);

		stack = pcpu->stack;
		stack_order = pcpu->state.stack_order;
		stack_pa = pcpu->state.stack_pa;
		if (stack_pa)
			stack_page = pfn_to_page(PHYS_PFN(stack_pa));
		else if (stack)
			stack_page = virt_to_page(stack);
		pcpu->stack = NULL;
		pcpu->state.stack_pa = 0;
		pcpu->state.stack_order = 0;
	}

	if (cpumask_empty(&outgoing->mask) && !outgoing->ser &&
	    outgoing->pcpus) {
		kho_unpreserve_free(outgoing->pcpus);
		outgoing->pcpus = NULL;
	}

	if (cpumask_empty(&incoming->mask) && incoming->pcpus) {
		kho_restore_free(incoming->pcpus);
		incoming->pcpus = NULL;
	}

	if (cpumask_empty(&cpu_preserved_mask)) {
		WRITE_ONCE(cpu_preserved_pcpus_va, NULL);
		WRITE_ONCE(cpu_preserved_pcpus_pa, 0);
		arch_cpu_preserved_dcache_clean((unsigned long)&cpu_preserved_pcpus_va,
						(unsigned long)&cpu_preserved_pcpus_va + sizeof(cpu_preserved_pcpus_va));
		arch_cpu_preserved_dcache_clean((unsigned long)&cpu_preserved_pcpus_pa,
						(unsigned long)&cpu_preserved_pcpus_pa + sizeof(cpu_preserved_pcpus_pa));
	}

	cpu_preserved_sync_outgoing();
	mutex_unlock(&cpu_preserved_lock);

	dev = get_cpu_device(cpu);
	if (dev && !cpu_online(cpu)) {
		ret = cpu_device_up(dev);
		if (ret) {
			pr_err("Failed to bring unpreserved cpu %d back online: %d\n",
			       cpu, ret);
		} else {
			device_lock(dev);
			dev_clear_offline(dev);
			device_unlock(dev);
		}
	}

	if (stack_page) {
		if (!is_incoming) {
			kho_unpreserve_pages(stack_page, 1 << stack_order);
			__free_pages(stack_page, stack_order);
		} else {
			int i;

			for (i = 0; i < (1 << stack_order); i++)
				__free_page(stack_page + i);
		}
	}

	/*
	 * Do not printk here: cpu_unpreserve() is called in the CPU
	 * hotplug return path (cpu_device_up), which runs stop_machine().
	 * Emitting synchronous console messages here can cause deadlocks
	 * against nbcon/console locks when other CPUs are stopped.
	 */
	return ret;
}

/*
 * FLB Ops for Preserved CPUs
 */
static int cpu_preserve_reboot_notify(struct notifier_block *nb,
				      unsigned long action, void *data)
{
	struct cpu_preserved_incoming *incoming =
		&cpu_preserved_incoming;
	struct cpu_preserved_outgoing *outgoing =
		&cpu_preserved_outgoing;
	int cpu;

	mutex_lock(&cpu_preserved_lock);
	for_each_cpu(cpu, &cpu_preserved_mask) {
		/*
		 * If this CPU is not being preserved across an outgoing live
		 * update, signal it to exit the park loop and offline it.
		 */
		if (!kexec_in_progress || !liveupdate_enabled() ||
		    cpumask_test_cpu(cpu, &incoming->mask)) {
			struct cpu_preserved_pcpu *pcpu;
			unsigned int stack_order;
			void *stack;

			pcpu = cpu_preserved_get_pcpu(cpu);
			bool is_inc = cpumask_test_cpu(cpu, &incoming->mask);
			cpu_signal_exit(cpu, is_inc);
			cpu_kick(cpu);
			if (cpu_wait_dead(cpu))
				continue;
			cpumask_clear_cpu(cpu, &outgoing->mask);
			cpumask_clear_cpu(cpu, &incoming->mask);
			cpumask_clear_cpu(cpu, &cpu_preserved_mask);

			if (pcpu) {
				stack = pcpu->stack;
				stack_order = pcpu->state.stack_order;
				WRITE_ONCE(pcpu->state.workload, 0);
				pcpu->state.name[0] = '\0';
				pcpu->state.session[0] = '\0';
				WRITE_ONCE(pcpu->entry_fn, NULL);
				WRITE_ONCE(pcpu->entry_data, NULL);
				if (stack) {
					struct page *page = virt_to_page(stack);

					kho_unpreserve_pages(page,
							     1 << stack_order);
					__free_pages(page, stack_order);
					pcpu->stack = NULL;
				}
				pcpu->state.stack_pa = 0;
				pcpu->state.stack_order = 0;
			}
		}
	}
	if (cpumask_empty(&outgoing->mask) && outgoing->pcpus) {
		kho_unpreserve_free(outgoing->pcpus);
		outgoing->pcpus = NULL;
	}
	if (cpumask_empty(&incoming->mask) && incoming->pcpus) {
		kho_restore_free(incoming->pcpus);
		incoming->pcpus = NULL;
	}
	cpu_preserved_sync_outgoing();
	mutex_unlock(&cpu_preserved_lock);

	return NOTIFY_OK;
}

static struct notifier_block cpu_preserve_reboot_nb = {
	.notifier_call = cpu_preserve_reboot_notify,
	.priority = 0,
};

/**
static int __init cpu_preserve_early_init(void)
{
	register_reboot_notifier(&cpu_preserve_reboot_nb);

	arch_cpu_preserved_get_pgd();

	return 0;
}
early_initcall(cpu_preserve_early_init);
