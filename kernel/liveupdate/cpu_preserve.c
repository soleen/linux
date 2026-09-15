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
#include <linux/device.h>
#include <linux/device/bus.h>
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
int cpu_preserved_attach_workload(int cpu, const char *name,
				  void (*entry_fn)(void *data), void *data)
{
	struct cpu_preserved_pcpu *pcpu;

	if ((unsigned int)cpu >= nr_cpu_ids)
		return -EINVAL;

	mutex_lock(&cpu_preserved_lock);
	if (!cpumask_test_cpu(cpu, &cpu_preserved_outgoing.mask)) {
		mutex_unlock(&cpu_preserved_lock);
		return -ENODEV;
	}

	pcpu = &cpu_preserved_outgoing.pcpus[cpu];
	if (pcpu->state.workload != CPU_PRESERVED_PARKED || pcpu->entry_fn) {
		mutex_unlock(&cpu_preserved_lock);
		return -EBUSY;
	}

	if (name && name[0] != '\0')
		strscpy(pcpu->state.name, name, sizeof(pcpu->state.name));
	WRITE_ONCE(pcpu->entry_data, data);
	WRITE_ONCE(pcpu->entry_fn, entry_fn);

	cpu_preserved_clean(pcpu);

	arch_cpu_preserved_kick(cpu);
	mutex_unlock(&cpu_preserved_lock);
	return 0;
}
EXPORT_SYMBOL_GPL(cpu_preserved_attach_workload);

/**
 * cpu_preserved_detach_workload - Detach workload and return core to idle park
 * @cpu: Logical CPU identifier.
 *
 * Clears any attached workload on @cpu, returning the core to the default
 * idle parking loop.
 *
 * Return: 0 on success, -EINVAL if @cpu is invalid, or -ENODEV if
 * not preserved.
 */
int cpu_preserved_detach_workload(int cpu)
{
	struct cpu_preserved_pcpu *pcpu;

	if ((unsigned int)cpu >= nr_cpu_ids)
		return -EINVAL;

	mutex_lock(&cpu_preserved_lock);
	pcpu = cpu_preserved_get_pcpu(cpu);
	if (!pcpu) {
		mutex_unlock(&cpu_preserved_lock);
		return -ENODEV;
	}

	strscpy(pcpu->state.name, "parked", sizeof(pcpu->state.name));
	WRITE_ONCE(pcpu->state.workload, CPU_PRESERVED_PARKED);
	WRITE_ONCE(pcpu->entry_fn, NULL);
	WRITE_ONCE(pcpu->entry_data, NULL);

	cpu_preserved_clean(pcpu);

	arch_cpu_preserved_kick(cpu);
	mutex_unlock(&cpu_preserved_lock);
	return 0;
}
EXPORT_SYMBOL_GPL(cpu_preserved_detach_workload);

/**
 * cpu_preserved_set_workload_context - Set workload context and root page table
 * @cpu: Logical CPU identifier.
 * @ctx: Opaque owning workload context pointer.
 * @pgd_pa: Physical address of workload root page table (or 0 for default).
 */
void cpu_preserved_set_workload_context(int cpu, void *ctx, phys_addr_t pgd_pa)
{
	struct cpu_preserved_pcpu *pcpu;

	if (cpu < 0 || cpu >= nr_cpu_ids)
		return;

	mutex_lock(&cpu_preserved_lock);
	pcpu = cpu_preserved_get_pcpu(cpu);
	if (pcpu && pcpu->stack) {
		struct cpu_preserved_stack_context *sctx = pcpu->stack;

		sctx->workload_context = ctx;
		sctx->session_pgd_pa = pgd_pa;
		pcpu->pgd_pa = pgd_pa;
	}
	mutex_unlock(&cpu_preserved_lock);
}

int cpu_preserved_get_stack_info(int cpu, phys_addr_t *pa, unsigned long *va, size_t *size)
{
	struct cpu_preserved_pcpu *pcpu;

	if (cpu < 0 || cpu >= nr_cpu_ids)
		return -EINVAL;

	pcpu = cpu_preserved_get_pcpu(cpu);
	if (!pcpu || !pcpu->stack)
		return -ENODEV;

	if (pa)
		*pa = pcpu->state.stack_pa;
	if (va)
		*va = (unsigned long)pcpu->stack;
	if (size)
		*size = CPU_PRESERVED_STACK_SIZE;
	return 0;
}

int cpu_preserved_get_pcpus_info(phys_addr_t *pa, unsigned long *va, size_t *size)
{
	if (!cpu_preserved_pcpus_va || !cpu_preserved_pcpus_pa)
		return -ENODEV;

	if (pa)
		*pa = cpu_preserved_pcpus_pa;
	if (va)
		*va = (unsigned long)cpu_preserved_pcpus_va;
	if (size)
		*size = sizeof(struct cpu_preserved_pcpu) * nr_cpu_ids;
	return 0;
}

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
STACK_FRAME_NON_STANDARD(cpu_preserved_park_loop);

/**
 * cpu_preserved_park - Main execution and parking loop for a preserved CPU
 * @cpu: Logical CPU identifier of the calling core.
 *
 * Called on the physical CPU being offlined/preserved. Enters a dedicated
 * low-power parking loop in preserved memory, repeatedly executing any
 * attached workload callback, until signaled to exit upon unpreservation.
 */
void cpu_preserved_park(int cpu)
{
	struct cpu_preserved_pcpu *pcpu = cpu_preserved_get_pcpu(cpu);

	if (pcpu && pcpu->stack) {
		unsigned long top_of_stack = (unsigned long)pcpu->stack +
			CPU_PRESERVED_STACK_SIZE - CPU_PRESERVED_STACK_HEADROOM;
		arch_cpu_preserved_park_on_stack(cpu, top_of_stack);
	} else {
		cpu_preserved_park_loop(cpu);
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
		ret = -EBUSY;
		goto err_unlock;
	}

	if (num_online_cpus() <= 1 && cpu_online(cpu)) {
		ret = -EBUSY;
		goto err_unlock;
	}

	if (!outgoing->pcpus) {
		ret = cpu_preserved_init_runtime_buffer();
		if (ret)
			goto err_unlock;

		outgoing->pcpus = kho_alloc_preserve(
			sizeof(*outgoing->pcpus) * nr_cpu_ids);
		if (IS_ERR(outgoing->pcpus)) {
			ret = PTR_ERR(outgoing->pcpus);
			outgoing->pcpus = NULL;
			goto err_unlock;
		}
		WRITE_ONCE(cpu_preserved_pcpus_va, outgoing->pcpus);
		WRITE_ONCE(cpu_preserved_pcpus_pa, virt_to_phys(outgoing->pcpus));
		cpu_preserved_clean(&cpu_preserved_pcpus_va);
		cpu_preserved_clean(&cpu_preserved_pcpus_pa);
	}

	cpumask_set_cpu(cpu, &outgoing->mask);
	cpumask_set_cpu(cpu, &cpu_preserved_mask);
	cpu_preserved_clean(&cpu_preserved_mask);
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

		pcpu->pgd_pa = pgd ? virt_to_phys(pgd) : 0;
	}

	cpumask_clear_cpu(cpu, &cpu_preserved_incoming.mask);
	WRITE_ONCE(pcpu->entry_fn, NULL);
	WRITE_ONCE(pcpu->entry_data, NULL);

	mutex_unlock(&cpu_preserved_lock);

	if (cpu_online(cpu)) {
		dev = get_cpu_device(cpu);
		if (!dev) {
			ret = -ENODEV;
			goto err_rollback;
		}

		ret = cpu_device_down(dev);
		if (ret) {
			pr_err("Failed to offline preserved cpu %d: %d\n",
			       cpu, ret);
			goto err_rollback;
		}
		kobject_uevent(&dev->kobj, KOBJ_OFFLINE);
		dev_set_offline(dev);
		device_unlock(dev);
		unlock_device_hotplug();
	}

	/*
	 * Do not printk here: cpu_preserve() is invoked during physical
	 * CPU hotplug (dev_set_offline), which runs stop_machine().
	 * Emitting synchronous console messages here can cause deadlocks
	 * against nbcon/console locks when other CPUs are stopped.
	 */
	return 0;

err_rollback:
	/* Undo everything published above, in the same order cpu_unpreserve() does. */
	mutex_lock(&cpu_preserved_lock);
	cpumask_clear_cpu(cpu, &outgoing->mask);
	cpumask_clear_cpu(cpu, &cpu_preserved_mask);
	cpu_preserved_clean(&cpu_preserved_mask);
	WRITE_ONCE(pcpu->state.workload, 0);
	pcpu->state.name[0] = '\0';
	pcpu->state.session[0] = '\0';
	pcpu->state.stack_pa = 0;
	pcpu->state.stack_order = 0;
	pcpu->stack = NULL;
	if (cpumask_empty(&outgoing->mask)) {
		kho_unpreserve_free(outgoing->pcpus);
		outgoing->pcpus = NULL;
	}
	if (cpumask_empty(&cpu_preserved_mask)) {
		WRITE_ONCE(cpu_preserved_pcpus_va, NULL);
		WRITE_ONCE(cpu_preserved_pcpus_pa, 0);
		cpu_preserved_clean(&cpu_preserved_pcpus_va);
		cpu_preserved_clean(&cpu_preserved_pcpus_pa);
	}
	cpu_preserved_sync_global_ser();
err_unlock:
	mutex_unlock(&cpu_preserved_lock);
	kho_unpreserve_pages(stack_page, 1 << CPU_PRESERVED_STACK_ORDER);
	__free_pages(stack_page, CPU_PRESERVED_STACK_ORDER);
	return ret;
}

/*
 * Release a preserved CPU's stack.  An incoming core's stack pages came from
 * KHO and are not preserved by this kernel, so they must not be unpreserved.
 */
static void cpu_preserved_free_stack(struct page *page, unsigned int order,
				     bool is_incoming)
{
	if (!page)
		return;

	if (is_incoming) {
		int i;

		for (i = 0; i < (1 << order); i++)
			__free_page(page + i);
	} else {
		kho_unpreserve_pages(page, 1 << order);
		__free_pages(page, order);
	}
}

/*
 * Drop @cpu out of the preserved state and republish the globals a parked core
 * may still be reading.  The caller holds cpu_preserved_lock and has already
 * made the core leave the park loop.  The stack page is handed back rather
 * than freed here because the caller knows whether it is an incoming core and
 * may want to drop the lock first.
 */
static struct page *__cpu_unpreserve_locked(unsigned int cpu,
					    unsigned int *stack_order)
{
	struct cpu_preserved_incoming *incoming = &cpu_preserved_incoming;
	struct cpu_preserved_outgoing *outgoing = &cpu_preserved_outgoing;
	struct cpu_preserved_pcpu *pcpu = cpu_preserved_get_pcpu(cpu);
	struct page *stack_page = NULL;

	lockdep_assert_held(&cpu_preserved_lock);

	cpumask_clear_cpu(cpu, &outgoing->mask);
	cpumask_clear_cpu(cpu, &incoming->mask);
	cpumask_clear_cpu(cpu, &cpu_preserved_mask);
	cpu_preserved_clean(&cpu_preserved_mask);

	WRITE_ONCE(pcpu->state.workload, 0);
	pcpu->state.name[0] = '\0';
	pcpu->state.session[0] = '\0';
	WRITE_ONCE(pcpu->entry_fn, NULL);
	WRITE_ONCE(pcpu->entry_data, NULL);

	if (pcpu->state.stack_pa)
		stack_page = pfn_to_page(PHYS_PFN(pcpu->state.stack_pa));
	*stack_order = pcpu->state.stack_order;
	pcpu->stack = NULL;
	pcpu->state.stack_pa = 0;
	pcpu->state.stack_order = 0;

	/* @pcpu points into these arrays: do not touch it past this point. */
	if (cpumask_empty(&outgoing->mask) && outgoing->pcpus) {
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
		cpu_preserved_clean(&cpu_preserved_pcpus_va);
		cpu_preserved_clean(&cpu_preserved_pcpus_pa);
	}

	cpu_preserved_sync_global_ser();
	return stack_page;
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
	struct page *stack_page = NULL;
	unsigned int stack_order = 0;
	bool is_incoming;
	int ret = 0;

	if (cpu >= nr_cpu_ids || !cpu_possible(cpu))
		return -EINVAL;

	mutex_lock(&cpu_preserved_lock);

	if (!cpu_is_preserved(cpu)) {
		mutex_unlock(&cpu_preserved_lock);
		return 0;
	}

	is_incoming = cpu_preserved_is_incoming(cpu);

	cpu_signal_exit(cpu);
	arch_cpu_preserved_kick(cpu);
	mutex_unlock(&cpu_preserved_lock);

	/*
	 * cpu_wait_dead() busy-polls for up to 20 seconds.  Do not hold
	 * cpu_preserved_lock across it: the poll only reads pcpu->state, which
	 * stays valid for as long as the CPU is preserved, and holding the lock
	 * here would stall every other preservation operation and every sysfs
	 * reader for the entire window.
	 */
	ret = cpu_wait_dead(cpu);
	if (ret)
		return ret;

	mutex_lock(&cpu_preserved_lock);

	/* Someone else may have completed the teardown while we waited. */
	if (!cpu_is_preserved(cpu)) {
		mutex_unlock(&cpu_preserved_lock);
		return 0;
	}

	stack_page = __cpu_unpreserve_locked(cpu, &stack_order);
	mutex_unlock(&cpu_preserved_lock);

	if (!cpu_online(cpu)) {
		ret = add_cpu(cpu);
		if (ret < 0) {
			pr_err("Failed to bring unpreserved cpu %d back online: %d\n",
			       cpu, ret);
		} else {
			ret = 0;
		}
	}

	cpu_preserved_free_stack(stack_page, stack_order, is_incoming);

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
	struct cpu_preserved_incoming *incoming = &cpu_preserved_incoming;
	int cpu;

	mutex_lock(&cpu_preserved_lock);
	for_each_cpu(cpu, &cpu_preserved_mask) {
		struct page *stack_page;
		unsigned int stack_order;
		bool is_incoming;

		/*
		 * If this CPU is not being preserved across an outgoing live
		 * update, signal it to exit the park loop and offline it.
		 */
		is_incoming = cpumask_test_cpu(cpu, &incoming->mask);
		if (kexec_in_progress && liveupdate_enabled() && !is_incoming)
			continue;

		cpu_signal_exit(cpu);
		arch_cpu_preserved_kick(cpu);
		if (cpu_wait_dead(cpu))
			continue;

		stack_page = __cpu_unpreserve_locked(cpu, &stack_order);
		cpu_preserved_free_stack(stack_page, stack_order, is_incoming);
	}
	mutex_unlock(&cpu_preserved_lock);

	return NOTIFY_OK;
}

static struct notifier_block cpu_preserve_reboot_nb = {
	.notifier_call = cpu_preserve_reboot_notify,
	.priority = 0,
};

static int __init cpu_preserve_early_init(void)
{
	register_reboot_notifier(&cpu_preserve_reboot_nb);

	arch_cpu_preserved_get_pgd();

	return 0;
}
early_initcall(cpu_preserve_early_init);
static ssize_t preserved_show(struct device *dev,
			      struct device_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%*pbl\n",
			  cpumask_pr_args(cpu_get_preserved_mask()));
}
static DEVICE_ATTR_RO(preserved);

static ssize_t preserve_show(struct device *dev,
			     struct device_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", cpu_is_preserved(dev->id));
}
static DEVICE_ATTR_RO(preserve);

static int __init cpu_preserve_sysfs_init(void)
{
	struct device *dev_root = bus_get_dev_root(&cpu_subsys);
	int cpu, ret;

	if (dev_root) {
		ret = sysfs_create_file(&dev_root->kobj, &dev_attr_preserved.attr);
		put_device(dev_root);
		if (ret)
			pr_warn("Failed to create cpu preserved sysfs attribute: %d\n", ret);
	}

	for_each_possible_cpu(cpu) {
		struct device *dev = get_cpu_device(cpu);

		if (dev) {
			ret = sysfs_create_file(&dev->kobj, &dev_attr_preserve.attr);
			if (ret)
				pr_warn("Failed to create cpu%d preserve sysfs attribute: %d\n",
					cpu, ret);
		}
	}
	return 0;
}
late_initcall(cpu_preserve_sysfs_init);
