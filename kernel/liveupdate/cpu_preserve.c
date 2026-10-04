// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * Physical CPU Preservation Framework for Live Update
 */

/**
 * DOC: Preserved CPU Subsystem
 *
 * Keeps physical CPUs running across a kexec-based live update, without a
 * hardware reset and without going through firmware or the secondary CPU boot
 * path of the incoming kernel.
 *
 * Design Overview
 * ===============
 *
 * A preserved CPU is taken out of Linux through CPU hotplug and waits in a
 * small runtime that lives in KHO-preserved memory and runs on its own stack
 * and page tables, so that it keeps running while the kernel is replaced.
 *
 * The preservation mechanism operates in four phases:
 *
 * 1. **Preparation:** cpu_preserve() takes the CPU down with
 *    device_offline().  When the dying CPU reports dead
 *    (cpuhp_ap_report_dead()), it enters cpu_preserved_park() instead of the
 *    architecture's dead loop, switches to its preserved stack and to the
 *    isolated page tables of its session, and waits in
 *    cpu_preserved_park_loop().
 *
 * 2. **KHO Registration:** The runtime text and data, the preserved stacks,
 *    the descriptors and the isolated page tables are preserved with Kexec
 *    Handover (KHO).  The FLB data lists the outgoing CPUs, each with its
 *    hardware identifier.
 *
 * 3. **Handover:** At kexec, the reboot notifier stops every preserved CPU
 *    that is not handed over.  The incoming kernel boots while the handed-over
 *    CPUs keep waiting in their park loop.
 *
 * 4. **Retrieval and Reclamation:** In an early initcall, before secondary
 *    CPU bringup, the incoming kernel validates the list in the FLB data,
 *    rebuilds the sessions of the listed CPUs and marks the CPUs preserved,
 *    so that smp_init() does not bring them up.  It finds each CPU by its
 *    hardware identifier, as kernels may number CPUs differently, and
 *    refuses the whole handover if an entry does not match: smp_init() then
 *    brings up the CPUs as usual, which resets them.  Retrieving a CPU file
 *    leaves the CPU parked.  Finishing the session stops the CPU and brings
 *    it online with device_online().
 *
 * This subsystem provides the generic, hypervisor-agnostic foundation for
 * physical CPU preservation.
 *
 * Lifecycle
 * =========
 *
 * CPU lifecycle state progression::
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
 *     |         (Offline, waits in cpu_preserved_park_loop())       |
 *     +-------------------------------------------------------------+
 *                                    |
 *                                    | [Live Update: kexec]
 *                                    v
 *     +-------------------------------------------------------------+
 *     |                     INCOMING PRESERVED                      |
 *     |         (Parked on-core, skipped in secondary boot)         |
 *     |          (Stays parked when its file is retrieved)          |
 *     +-------------------------------------------------------------+
 *                                    |
 *                                    | finish (via LUO session)
 *                                    v
 *     +-------------------------------------------------------------+
 *     |                          OFFLINE                            |
 *     |               (Park loop exited, CPU stopped)               |
 *     +-------------------------------------------------------------+
 *                                    |
 *                                    | device_online()
 *                                    v
 *     +-------------------------------------------------------------+
 *     |                          ONLINE                             |
 *     |                (Rejoined host scheduling)                   |
 *     +-------------------------------------------------------------+
 *
 * Unpreserving a CPU before kexec takes it from PRESERVED_PARKED through
 * OFFLINE back to ONLINE in the same way.
 *
 * File Descriptor Binding
 * =======================
 *
 * 1. **Sysfs control file:** Each hotpluggable CPU device has a read-only
 *    ``/sys/devices/system/cpu/cpu<N>/preserve`` attribute, in its attribute
 *    groups.  The file descriptor of this file handles the lifecycle of the
 *    preserved CPU.  Only hotpluggable CPUs can be preserved.
 *
 * 2. **Preservation via LUO:** Userspace opens this file and preserves the fd
 *    in a LUO session.  Preserving the file takes the CPU offline, which
 *    migrates its interrupts and tasks, parks it (cpu_preserved_park()), and
 *    adds it to the preserved CPU session of the LUO session.
 *
 * 3. **KHO and memory preservation:** The parking loop, dedicated preserved
 *    CPU stacks, runtime execution buffers outside Scratch memory, and
 *    preserved CPU state reside in memory preserved across kexec via KHO.
 *
 * 4. **Incoming boot:** During early boot, the incoming kernel reads and
 *    checks the list of preserved CPUs in the FLB data before secondary SMP
 *    bringup, and does not bring those CPUs online.
 *
 * 5. **Retrieval and finish:** When userspace retrieves the file in the
 *    incoming kernel, it receives a new ``preserve`` file descriptor, opened
 *    under the root directory of init, and the CPU stays parked.  Finishing
 *    the session (also done when the session fd is closed) signals the CPU to
 *    exit the parking loop, waits for it to stop, and brings it back online
 *    with device_online().  Before kexec, closing the session fd unpreserves
 *    the file, which does the same.  Closing the CPU file descriptor itself
 *    has no effect.
 *
 * Architecture Requirements
 * =========================
 *
 * In addition to CPU hotplug with dead-state synchronization
 * (``CONFIG_HOTPLUG_CORE_SYNC_DEAD``: cpuhp_ap_report_dead() hands a dying
 * preserved CPU to cpu_preserved_park()), an architecture selecting
 * ``ARCH_SUPPORTS_LIVEUPDATE_CPU`` must provide:
 *
 * - **Linker script:** Include ``CPU_PRESERVED_TEXT`` in the executable text
 *   section and ``CPU_PRESERVED_DATA`` in the data section of
 *   ``arch/<arch>/kernel/vmlinux.lds.S`` (RW_DATA() includes the latter).
 *
 * - **Preserved runtime objects:** Code and data used by a parked core must
 *   be compiled into isolated ``*.preserved.o`` objects, so that they reside
 *   in the KHO-preserved ``.cpu_preserved.*`` sections and their symbols are
 *   prefixed with ``__cpu_preserved_``.  These include the
 *   ``arch_cpu_preserved_*()`` hooks declared with __cpu_preserved_sym_asm()
 *   in ``include/linux/cpu_preserve.h``.
 *
 * - **Address-space mapping hooks:** arch_cpu_preserved_as_map(),
 *   arch_cpu_preserved_as_unmap() and arch_cpu_preserved_as_flush_tlb()
 *   populate and manage isolated page tables built by the core layer using
 *   cpu_preserved_as_alloc_page().
 *
 * - **Runtime copy hooks:** Preserved CPUs run a copy of the preserved text
 *   and data, allocated outside KHO Scratch memory so that the incoming
 *   kernel can unpack safely, and mapped at the address of the sections only
 *   in the isolated address spaces.  arch_cpu_preserved_early_init()
 *   initializes the runtime data at boot, before the copy is made, and
 *   arch_cpu_preserved_setup_buffer() prepares the copy.
 *
 * - **Parking hooks:** arch_cpu_preserved_park_on_stack() and
 *   arch_cpu_preserved_park_init() move a dying CPU onto its preserved stack
 *   and page tables; arch_cpu_preserved_park_wait() waits in a low-power
 *   state until arch_cpu_preserved_kick() wakes the CPU;
 *   arch_cpu_preserved_wait_dead() completes stopping it; and
 *   arch_cpu_preserved_hwid() identifies it across kernels.
 *
 * Isolated Address Space
 * ======================
 *
 * A preserved core does not run on the kernel's own page tables.  Before it is
 * handed over, an isolated page table (struct cpu_preserved_as_ser) is created
 * per-session containing only what the park loop needs, so that a parked core
 * cannot touch memory the new kernel has taken ownership of:
 *
 * - Preserved text, ``PAGE_KERNEL_ROX`` (``.cpu_preserved.text``) -- the
 *   park loop and exception stubs;
 * - Preserved read-only data, ``PAGE_KERNEL_RO`` (``.cpu_preserved.rodata``
 *   and ``.cpu_preserved.ex_table``);
 * - Preserved writable globals, ``PAGE_KERNEL`` NX (``.cpu_preserved.data``
 *   and ``.cpu_preserved.bss``);
 * - The per-CPU preserved stack area, ``PAGE_KERNEL`` NX: the context page and
 *   the stack, with an unmapped guard page between them;
 * - The per-CPU descriptor (struct cpu_preserved_ser), ``PAGE_KERNEL`` NX.
 *
 * Deliberately absent: the linear direct map, all user address ranges, the
 * kernel heap, vmalloc, modules, and BPF JIT.
 *
 * Memory is unmapped from these page tables right before it is freed, once no
 * preserved CPU uses it anymore: the stack and descriptor of a CPU after the
 * CPU has been reset by bringing it online.  The incoming kernel unmaps the
 * memory at the address where the previous kernel mapped it, which it finds
 * from the direct map offset recorded in the address space, and does not add
 * mappings to address spaces it did not create.
 *
 * On x86 these mappings are built with the identity-map helpers in
 * ``arch/x86/mm/ident_map.c``.
 *
 * Sessions
 * ========
 *
 * Physical cores preserved across live update are grouped per LUO session in a
 * &struct cpu_preserved_session (retrieved via cpu_preserved_session_get()),
 * which owns the session's isolated address space and the mask of its CPUs:
 *
 * - When a CPU file is preserved or unpreserved, the session updates its CPU
 *   mask.  Each of its CPUs holds a reference to the session.
 * - The session state lives in a KHO-preserved
 *   &struct cpu_preserved_session_ser, which the descriptor of each of its
 *   CPUs points to.  At boot, the incoming kernel rebuilds the sessions of
 *   the CPUs handed over to it.
 */

#define pr_fmt(fmt) "cpu_preserve: " fmt

#include <linux/cpu.h>
#include <linux/cpu_preserve.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/kexec.h>
#include <linux/kexec_handover.h>
#include <linux/kho/abi/cpu.h>
#include <linux/kho_block.h>
#include <linux/liveupdate.h>
#include <linux/mm.h>
#include <linux/objtool.h>
#include <linux/reboot.h>
#include <linux/refcount.h>
#include <linux/string.h>

#include <asm/sections.h>

/*
 * struct cpu_preserved_state - Host-side preserved CPU state (incoming or outgoing)
 * @mask: Mask of preserved CPUs.
 * @cpus: Array of pointers to per-CPU serialized state in preserved memory.
 */
struct cpu_preserved_state {
	cpumask_t mask;
	struct cpu_preserved_ser **cpus;
};

static DEFINE_MUTEX(cpu_preserved_lock);
static struct cpumask cpu_preserved_mask;
static struct cpu_preserved_state cpu_preserved_incoming;
static struct cpu_preserved_state cpu_preserved_outgoing;
static struct cpu_preserved_global_ser *cpu_preserved_global_ser;

static struct page *cpu_preserved_text_pages;
static unsigned int cpu_preserved_text_order;
static struct page *cpu_preserved_data_pages;
static unsigned int cpu_preserved_data_order;
static bool cpu_preserved_runtime_preserved;

struct cpu_preserved_as_ctx {
	struct list_head list;
	struct cpu_preserved_as_ser *ser;
	struct kho_block_set block_set;
	struct kho_block_set_it it;
	bool incoming;
};

static DEFINE_MUTEX(cpu_preserved_as_map_lock);
static LIST_HEAD(cpu_preserved_as_list);

static struct cpu_preserved_as_ctx *
cpu_preserved_as_find_ctx(struct cpu_preserved_as_ser *as)
{
	struct cpu_preserved_as_ctx *ctx;

	list_for_each_entry(ctx, &cpu_preserved_as_list, list) {
		if (ctx->ser == as)
			return ctx;
	}
	return NULL;
}

static phys_addr_t cpu_preserved_get_text_pa(void)
{
	return cpu_preserved_text_pages ? page_to_phys(cpu_preserved_text_pages) : 0;
}

static phys_addr_t cpu_preserved_get_data_pa(void)
{
	return cpu_preserved_data_pages ? page_to_phys(cpu_preserved_data_pages) : 0;
}

static void cpu_preserved_sync_global_ser(void)
{
	struct cpu_preserved_state *outgoing = &cpu_preserved_outgoing;
	struct cpu_preserved_global_ser *ser = cpu_preserved_global_ser;
	unsigned int cpu;
	u64 *next;

	if (!ser)
		return;

	/* Link the CPUs that this kernel hands over */
	next = &ser->cpus.phys;
	for_each_cpu(cpu, &outgoing->mask) {
		struct cpu_preserved_ser *pser = outgoing->cpus[cpu];

		if (!pser)
			continue;
		*next = virt_to_phys(pser);
		cpu_preserved_clean(next);
		next = &pser->next.phys;
	}
	*next = 0;
	cpu_preserved_clean(next);

	if (cpu_preserved_text_pages) {
		ser->text_runtime_pa = page_to_phys(cpu_preserved_text_pages);
		ser->text_runtime_size =
			(1UL << cpu_preserved_text_order) * PAGE_SIZE;
	}
	if (cpu_preserved_data_pages) {
		ser->data_runtime_pa = page_to_phys(cpu_preserved_data_pages);
		ser->data_runtime_size =
			(1UL << cpu_preserved_data_order) * PAGE_SIZE;
	}
	cpu_preserved_clean(ser);
}

void cpu_preserved_free_kho(void *va, bool is_incoming)
{
	struct folio *folio;

	if (!va)
		return;

	if (is_incoming) {
		folio = kho_restore_folio(__pa(va));
		if (!WARN_ON(!folio)) {
			cpu_preserved_as_unmap(NULL, (unsigned long)va,
					       folio_size(folio));
			folio_put(folio);
		}
	} else {
		folio = virt_to_folio(va);
		cpu_preserved_as_unmap(NULL, (unsigned long)va,
				       folio_size(folio));
		kho_unpreserve_folio(folio);
		folio_put(folio);
	}
}

/**
 * cpu_preserved_as_alloc_page - Allocate a page table page for @arg
 * @arg: The struct cpu_preserved_as_ser being populated.
 *
 * Page table allocator handed to the architecture page table builders.
 *
 * Return: A zeroed, preserved page, or NULL.
 */
void *cpu_preserved_as_alloc_page(void *arg)
{
	struct cpu_preserved_as_ser *as = arg;
	struct cpu_preserved_as_ctx *ctx;
	u64 *pa_entry;
	void *ptr;

	ctx = cpu_preserved_as_find_ctx(as);
	if (WARN_ON_ONCE(!ctx))
		return NULL;

	if (kho_block_set_grow(&ctx->block_set, as->nr_pgtable_pages + 1))
		return NULL;

	ptr = kho_alloc_preserve(PAGE_SIZE);
	if (IS_ERR_OR_NULL(ptr)) {
		kho_block_set_shrink(&ctx->block_set, as->nr_pgtable_pages);
		return NULL;
	}

	if (!ctx->it.block) {
		kho_block_set_it_init(&ctx->it, &ctx->block_set);
		as->pg_tables.phys = kho_block_set_head_pa(&ctx->block_set);
	}

	pa_entry = kho_block_set_it_reserve_entry(&ctx->it);
	if (WARN_ON_ONCE(!pa_entry)) {
		kho_unpreserve_free(ptr);
		kho_block_set_shrink(&ctx->block_set, as->nr_pgtable_pages);
		return NULL;
	}

	cpu_preserved_clean_sz(ptr, PAGE_SIZE);
	*pa_entry = virt_to_phys(ptr);
	as->nr_pgtable_pages++;

	return ptr;
}

/**
 * cpu_preserved_as_map - Map one range into one preserved address space
 * @as: Address space to map into, created by this kernel.
 * @pa: Physical address of the range.
 * @va: Virtual address the range must appear at.
 * @size: Size of the range in bytes.
 * @prot: Protection to apply.
 *
 * Return: 0 on success, negative errno on failure.
 */
int cpu_preserved_as_map(struct cpu_preserved_as_ser *as, phys_addr_t pa,
			 unsigned long va, size_t size, pgprot_t prot)
{
	struct cpu_preserved_as_ctx *ctx;

	guard(mutex)(&cpu_preserved_as_map_lock);
	ctx = cpu_preserved_as_find_ctx(as);
	if (WARN_ON_ONCE(!ctx || ctx->incoming))
		return -EINVAL;

	return arch_cpu_preserved_as_map(as, pa, va, size, prot);
}

/**
 * cpu_preserved_as_unmap - Unmap a range from preserved address spaces
 * @as:   Address space to unmap from, or %NULL to unmap from all of them.
 * @va:   Address of the range in this kernel.
 * @size: Size of the range in bytes.
 *
 * An address space that the previous kernel handed over maps the range at
 * the previous kernel's direct map address for it, so @va must then be in the
 * direct map.
 */
void cpu_preserved_as_unmap(struct cpu_preserved_as_ser *as,
			    unsigned long va, size_t size)
{
	struct cpu_preserved_as_ctx *ctx;
	bool unmapped = false;

	if (!va || !size)
		return;

	guard(mutex)(&cpu_preserved_as_map_lock);
	list_for_each_entry(ctx, &cpu_preserved_as_list, list) {
		unsigned long as_va = va;

		if (as && ctx->ser != as)
			continue;

		if (ctx->incoming) {
			if (WARN_ON_ONCE(!virt_addr_valid((void *)va)))
				continue;
			as_va = virt_to_phys((void *)va) +
				ctx->ser->direct_map_offset;
		}

		if (arch_cpu_preserved_as_unmap(ctx->ser, as_va, size))
			unmapped = true;
	}

	if (unmapped)
		arch_cpu_preserved_as_flush_tlb();
}

static int cpu_preserved_init_runtime_buffer(void);

static int cpu_preserved_as_map_runtime(struct cpu_preserved_as_ser *as)
{
	unsigned long text_start = (unsigned long)__cpu_preserved_text_start;
	unsigned long data_start = (unsigned long)__cpu_preserved_data_start;
	unsigned long rw_start = (unsigned long)__cpu_preserved_rodata_end;
	size_t text_sz = (unsigned long)__cpu_preserved_text_end - text_start;
	size_t ro_sz = rw_start - data_start;
	size_t rw_sz = (unsigned long)__cpu_preserved_data_end - rw_start;
	phys_addr_t data_pa = cpu_preserved_get_data_pa();
	int ret;

	ret = cpu_preserved_as_map(as, cpu_preserved_get_text_pa(),
				   text_start, text_sz, PAGE_KERNEL_ROX);
	if (!ret && ro_sz)
		ret = cpu_preserved_as_map(as, data_pa, data_start, ro_sz,
					   PAGE_KERNEL_RO);
	if (!ret && rw_sz)
		ret = cpu_preserved_as_map(as, data_pa + ro_sz, rw_start, rw_sz,
					   PAGE_KERNEL);
	return ret;
}

/**
 * cpu_preserved_as_create - Build a new preserved address space
 *
 * Allocates a root page table and maps the preserved text and data into it.
 *
 * Return: The new address space, or an ERR_PTR() on failure.
 */
struct cpu_preserved_as_ser *cpu_preserved_as_create(void)
{
	struct cpu_preserved_as_ctx *ctx;
	struct cpu_preserved_as_ser *as;
	void *pgd;
	int ret;

	ret = cpu_preserved_init_runtime_buffer();
	if (ret)
		return ERR_PTR(ret);

	as = kho_alloc_preserve(sizeof(*as));
	if (IS_ERR(as))
		return as;

	ctx = kzalloc_obj(*ctx);
	if (!ctx) {
		kho_unpreserve_free(as);
		return ERR_PTR(-ENOMEM);
	}

	ctx->ser = as;
	kho_block_set_init(&ctx->block_set, sizeof(u64));
	as->direct_map_offset = (unsigned long)as - virt_to_phys(as);

	scoped_guard(mutex, &cpu_preserved_as_map_lock) {
		list_add(&ctx->list, &cpu_preserved_as_list);
		pgd = cpu_preserved_as_alloc_page(as);
		if (!pgd) {
			list_del(&ctx->list);
			kho_block_set_destroy(&ctx->block_set);
			kfree(ctx);
			kho_unpreserve_free(as);
			return ERR_PTR(-ENOMEM);
		}
		as->pgd_pa = virt_to_phys(pgd);
		cpu_preserved_clean(as);
	}

	ret = cpu_preserved_as_map_runtime(as);
	if (ret) {
		cpu_preserved_as_unpreserve(as);
		return ERR_PTR(ret);
	}

	return as;
}

/*
 * Register an address space that the previous kernel handed over.  Return 0,
 * or -ENOMEM.
 */
static int cpu_preserved_as_adopt(struct cpu_preserved_as_ser *ser)
{
	struct cpu_preserved_as_ctx *ctx;

	ctx = kzalloc_obj(*ctx);
	if (!ctx)
		return -ENOMEM;

	ctx->ser = ser;
	ctx->incoming = true;
	guard(mutex)(&cpu_preserved_as_map_lock);
	list_add(&ctx->list, &cpu_preserved_as_list);
	return 0;
}

/* Unregister an address space without freeing it */
static void cpu_preserved_as_forget(struct cpu_preserved_as_ser *ser)
{
	struct cpu_preserved_as_ctx *ctx;

	guard(mutex)(&cpu_preserved_as_map_lock);
	ctx = cpu_preserved_as_find_ctx(ser);
	if (ctx) {
		list_del(&ctx->list);
		kfree(ctx);
	}
}

/**
 * cpu_preserved_as_unpreserve - Free an outgoing preserved address space
 * @ser: Address space descriptor to release.
 */
void cpu_preserved_as_unpreserve(struct cpu_preserved_as_ser *ser)
{
	struct cpu_preserved_as_ctx *ctx;
	struct kho_block_set_it it;
	u64 *pa_entry;

	if (!ser)
		return;

	scoped_guard(mutex, &cpu_preserved_as_map_lock) {
		ctx = cpu_preserved_as_find_ctx(ser);
		if (ctx) {
			kho_block_set_it_init(&it, &ctx->block_set);
			while ((pa_entry = kho_block_set_it_read_entry(&it)))
				kho_unpreserve_free(phys_to_virt(*pa_entry));
			list_del(&ctx->list);
			kho_block_set_destroy(&ctx->block_set);
			kfree(ctx);
		}
	}
	kho_unpreserve_free(ser);
}

/**
 * cpu_preserved_as_restore_free - Free an incoming preserved address space
 * @ser: Address space descriptor recovered from preserved memory.
 */
void cpu_preserved_as_restore_free(struct cpu_preserved_as_ser *ser)
{
	struct kho_block_set bs;
	struct kho_block_set_it it;
	u64 *pa_entry;

	if (!ser)
		return;

	cpu_preserved_as_forget(ser);

	kho_block_set_init(&bs, sizeof(u64));
	if (!kho_block_set_restore(&bs, ser->pg_tables.phys)) {
		kho_block_set_it_init(&it, &bs);
		while ((pa_entry = kho_block_set_it_read_entry(&it)))
			kho_restore_free(phys_to_virt(*pa_entry));
		kho_block_set_destroy(&bs);
	}
	kho_restore_free(ser);
}

static int cpu_preserved_preserve_runtime_buffer(void)
{
	int ret;

	lockdep_assert_held(&cpu_preserved_lock);

	if (cpu_preserved_runtime_preserved)
		return 0;

	ret = kho_preserve_pages(cpu_preserved_text_pages,
				 1 << cpu_preserved_text_order);
	if (ret)
		return ret;

	ret = kho_preserve_pages(cpu_preserved_data_pages,
				 1 << cpu_preserved_data_order);
	if (ret) {
		kho_unpreserve_pages(cpu_preserved_text_pages,
				     1 << cpu_preserved_text_order);
		return ret;
	}

	cpu_preserved_runtime_preserved = true;
	return 0;
}

static void cpu_preserved_unpreserve_runtime_buffer(void)
{
	lockdep_assert_held(&cpu_preserved_lock);

	if (!cpu_preserved_runtime_preserved)
		return;

	kho_unpreserve_pages(cpu_preserved_text_pages,
			     1 << cpu_preserved_text_order);
	kho_unpreserve_pages(cpu_preserved_data_pages,
			     1 << cpu_preserved_data_order);

	cpu_preserved_runtime_preserved = false;
}

static int cpu_preserved_init_runtime_buffer_locked(void)
{
	size_t text_size = (unsigned long)__cpu_preserved_text_end -
			   (unsigned long)__cpu_preserved_text_start;
	size_t data_size = (unsigned long)__cpu_preserved_data_end -
			   (unsigned long)__cpu_preserved_data_start;
	unsigned int text_nr_pages = DIV_ROUND_UP(text_size, PAGE_SIZE);
	unsigned int data_nr_pages = DIV_ROUND_UP(data_size, PAGE_SIZE);
	int ret;

	lockdep_assert_held(&cpu_preserved_lock);

	if (cpu_preserved_text_pages)
		return cpu_preserved_preserve_runtime_buffer();

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
	if (ret)
		goto err_free;

	/* The copy is in use now: keep it even if preserving it fails. */
	return cpu_preserved_preserve_runtime_buffer();

err_free:
	__free_pages(cpu_preserved_data_pages, cpu_preserved_data_order);
	__free_pages(cpu_preserved_text_pages, cpu_preserved_text_order);
	cpu_preserved_data_pages = NULL;
	cpu_preserved_text_pages = NULL;
	return ret;
}

/**
 * cpu_preserved_init_runtime_buffer - Allocate execution buffer outside Scratch
 *
 * Return: 0 on success, or negative error code on allocation/setup failure.
 */
static int cpu_preserved_init_runtime_buffer(void)
{
	guard(mutex)(&cpu_preserved_lock);

	return cpu_preserved_init_runtime_buffer_locked();
}

static bool cpu_preserved_is_incoming(int cpu)
{
	if ((unsigned int)cpu >= nr_cpu_ids)
		return false;
	return cpumask_test_cpu(cpu, &cpu_preserved_incoming.mask);
}

static struct cpu_preserved_ser *cpu_preserved_get_ser(int cpu)
{
	if ((unsigned int)cpu >= nr_cpu_ids)
		return NULL;

	if (cpu_preserved_is_incoming(cpu))
		return cpu_preserved_incoming.cpus ? cpu_preserved_incoming.cpus[cpu] : NULL;

	return cpu_preserved_outgoing.cpus ? cpu_preserved_outgoing.cpus[cpu] : NULL;
}

static void *cpu_preserved_stack_va(int cpu)
{
	struct cpu_preserved_ser *ser;
	phys_addr_t pa;

	/* The stack of an incoming CPU is private to the previous kernel */
	if (cpu_preserved_is_incoming(cpu))
		return NULL;

	ser = cpu_preserved_get_ser(cpu);
	if (!ser)
		return NULL;

	cpu_preserved_inval(&ser->stack_pa);
	pa = READ_ONCE(ser->stack_pa);
	if (!pa)
		return NULL;

	return phys_to_virt(pa);
}

/**
 * cpu_preserved_get_sctx - Return the stack context of a preserved CPU
 * @cpu: Logical CPU identifier.
 *
 * Return: The stack context of @cpu, or %NULL if @cpu is not preserved or was
 *         handed over by the previous kernel, which owns its stack context.
 */
struct cpu_preserved_stack_context *cpu_preserved_get_sctx(int cpu)
{
	struct cpu_preserved_stack_context *sctx = cpu_preserved_stack_va(cpu);

	if (sctx && sctx->magic == CPU_PRESERVED_STACK_MAGIC)
		return sctx;
	return NULL;
}

/**
 * cpu_is_preserved - Check whether a CPU is currently preserved
 * @cpu: Logical CPU identifier.
 *
 * Return: True if @cpu is currently preserved, false otherwise.
 */
bool cpu_is_preserved(int cpu)
{
	return (unsigned int)cpu < nr_cpu_ids &&
	       cpumask_test_cpu(cpu, &cpu_preserved_mask);
}

/**
 * cpu_get_preserved_mask - Get the mask of all currently preserved CPUs
 *
 * Return: Read-only pointer to the cpumask of preserved CPUs.
 */
const struct cpumask *cpu_get_preserved_mask(void)
{
	return &cpu_preserved_mask;
}

