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
#include <linux/device.h>
#include <linux/iopoll.h>
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
 * @sessions: Array of pointers to the session of each preserved CPU.
 */
struct cpu_preserved_state {
	cpumask_t mask;
	struct cpu_preserved_ser **cpus;
	struct cpu_preserved_session **sessions;
};

/*
 * Lock order: lock_device_hotplug(), cpu_preserved_sessions_lock,
 * cpu_preserved_lock, cpu_preserved_as_map_lock.
 */
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

static bool cpu_preserved_state_is_stopped(u32 state)
{
	return state == CPU_PRESERVED_DEAD || state == CPU_PRESERVED_FAULTED;
}

static void cpu_signal_exit(int cpu)
{
	struct cpu_preserved_ser *ser = cpu_preserved_get_ser(cpu);

	if (ser) {
		u32 old;

		cpu_preserved_inval(ser);
		old = READ_ONCE(ser->state);
		while (!cpu_preserved_state_is_stopped(old) &&
		       old != CPU_PRESERVED_EXITING) {
			if (try_cmpxchg(&ser->state, &old,
					CPU_PRESERVED_EXITING)) {
				cpu_preserved_clean(ser);
				break;
			}
		}
	}
}

/*
 * Parking and stopping take microseconds once the CPU runs, so the timeouts
 * only catch a wedged CPU.  They are long because a vCPU can stay descheduled
 * for seconds: parking gets 5 s after the CPU has reported dead, stopping gets
 * 20 s, twice what the hotplug core waits for a CPU to report dead.  Nothing
 * here needs better latency than a 100 us sleeping poll.
 */
#define CPU_WAIT_PARKED_TIMEOUT_US	(5 * USEC_PER_SEC)
#define CPU_WAIT_DEAD_TIMEOUT_US	(20 * USEC_PER_SEC)
#define CPU_WAIT_POLL_US		100

static u32 cpu_preserved_read_state(struct cpu_preserved_ser *ser)
{
	cpu_preserved_inval(ser);
	/* Pairs with the release cmpxchg()es of the preserved CPU */
	return smp_load_acquire(&ser->state);
}

static int cpu_wait_parked(int cpu)
{
	struct cpu_preserved_ser *ser = cpu_preserved_get_ser(cpu);
	u32 state;
	int ret;

	if (!ser)
		return -ENODEV;

	ret = read_poll_timeout(cpu_preserved_read_state, state,
				state != CPU_PRESERVED_PARKING,
				CPU_WAIT_POLL_US, CPU_WAIT_PARKED_TIMEOUT_US,
				false, ser);
	if (!ret && state == CPU_PRESERVED_PARKED)
		return 0;

	pr_err("Preserved cpu %d failed to park (state=%u)\n", cpu, state);
	return ret ?: -EIO;
}

static int cpu_wait_dead_timeout(int cpu, u64 timeout_us)
{
	struct cpu_preserved_ser *ser = cpu_preserved_get_ser(cpu);
	u32 state;
	int ret;

	if (!ser)
		return -ENODEV;

	ret = read_poll_timeout(cpu_preserved_read_state, state,
				cpu_preserved_state_is_stopped(state),
				CPU_WAIT_POLL_US, timeout_us, false, ser);
	if (ret) {
		pr_err("Timed out waiting for preserved cpu %d to stop (state=%u)\n",
		       cpu, state);
		return ret;
	}

	if (state == CPU_PRESERVED_FAULTED)
		pr_err("Preserved cpu %d stopped on a fault\n", cpu);

	arch_cpu_preserved_wait_dead(cpu);
	return 0;
}

static int cpu_wait_dead(int cpu)
{
	return cpu_wait_dead_timeout(cpu, CPU_WAIT_DEAD_TIMEOUT_US);
}

/**
 * cpu_preserved_park - Main execution and parking loop for a preserved CPU
 * @cpu: Logical CPU identifier of the calling core.
 */
void cpu_preserved_park(int cpu)
{
	struct cpu_preserved_stack_context *sctx = cpu_preserved_stack_va(cpu);

	if (WARN_ON_ONCE(!sctx || sctx->magic != CPU_PRESERVED_STACK_MAGIC ||
			 !sctx->session_pgd_pa)) {
		arch_cpu_preserved_park_finish(cpu);
		if (sctx && sctx->ser) {
			WRITE_ONCE(sctx->ser->state, CPU_PRESERVED_DEAD);
			cpu_preserved_clean(sctx->ser);
		}
		return;
	}

	arch_cpu_preserved_park_on_stack(cpu, (unsigned long)sctx +
		CPU_PRESERVED_STACK_SIZE - CPU_PRESERVED_STACK_HEADROOM);
}
STACK_FRAME_NON_STANDARD(cpu_preserved_park);

static void cpu_preserved_free_stack(phys_addr_t stack_pa, bool is_incoming)
{
	if (stack_pa)
		cpu_preserved_free_kho(phys_to_virt(stack_pa), is_incoming);
}

static void cpu_preserved_state_cleanup(struct cpu_preserved_state *st,
					bool is_incoming)
{
	if (!cpumask_empty(&st->mask))
		return;

	kfree(st->cpus);
	kfree(st->sessions);
	st->cpus = NULL;
	st->sessions = NULL;
}

/*
 * Drop @cpu out of the preserved state, free its preserved stack, and
 * republish the globals a parked core may still be reading.  The caller holds
 * cpu_preserved_lock, and the core either never parked or has been reset by
 * bringing it back online.
 */
static void __cpu_unpreserve_locked(unsigned int cpu)
{
	struct cpu_preserved_state *incoming = &cpu_preserved_incoming;
	struct cpu_preserved_state *outgoing = &cpu_preserved_outgoing;
	bool is_incoming = cpu_preserved_is_incoming(cpu);
	struct cpu_preserved_ser *ser = NULL;
	phys_addr_t stack_pa = 0;

	lockdep_assert_held(&cpu_preserved_lock);

	if (is_incoming && incoming->cpus)
		ser = incoming->cpus[cpu];
	else if (outgoing->cpus)
		ser = outgoing->cpus[cpu];

	if (incoming->cpus) {
		incoming->cpus[cpu] = NULL;
		incoming->sessions[cpu] = NULL;
	}
	if (outgoing->cpus) {
		outgoing->cpus[cpu] = NULL;
		outgoing->sessions[cpu] = NULL;
	}

	cpumask_clear_cpu(cpu, &outgoing->mask);
	cpumask_clear_cpu(cpu, &incoming->mask);
	cpumask_clear_cpu(cpu, &cpu_preserved_mask);

	if (ser) {
		WRITE_ONCE(ser->state, 0);
		stack_pa = ser->stack_pa;
		ser->stack_pa = 0;
		cpu_preserved_clean(ser);
	}

	cpu_preserved_sync_global_ser();
	cpu_preserved_free_stack(stack_pa, is_incoming);
	cpu_preserved_state_cleanup(outgoing, false);
	cpu_preserved_state_cleanup(incoming, true);
}

static int cpu_preserved_init_outgoing(void)
{
	struct cpu_preserved_state *outgoing = &cpu_preserved_outgoing;
	int ret;

	lockdep_assert_held(&cpu_preserved_lock);

	if (outgoing->cpus)
		return 0;

	ret = cpu_preserved_init_runtime_buffer_locked();
	if (ret)
		return ret;

	outgoing->cpus = kcalloc(nr_cpu_ids, sizeof(*outgoing->cpus),
				 GFP_KERNEL);
	outgoing->sessions = kcalloc(nr_cpu_ids, sizeof(*outgoing->sessions),
				     GFP_KERNEL);
	if (!outgoing->cpus || !outgoing->sessions) {
		kfree(outgoing->cpus);
		kfree(outgoing->sessions);
		outgoing->cpus = NULL;
		outgoing->sessions = NULL;
		return -ENOMEM;
	}

	return 0;
}

/*
 * struct cpu_preserved_session - The preserved CPUs of one LUO session
 * @node:     Entry on cpu_preserved_sessions or cpu_preserved_incoming_sessions.
 * @ref:      One reference for each CPU in @cpus, and one for each other user.
 * @lsession: The outgoing LUO session, or %NULL.
 * @ser:      KHO-preserved session metadata.
 * @as:       Isolated address space of the CPUs.
 * @cpus:     CPUs of the session that are preserved and parked.
 * @incoming: Whether the previous kernel created the session.
 *
 * The outgoing kernel finds a session by its LUO session.  The incoming kernel
 * creates its sessions at boot, from the CPUs that were handed over, and finds
 * them through these CPUs.
 */
struct cpu_preserved_session {
	struct list_head node;
	refcount_t ref;
	struct liveupdate_session *lsession;
	struct cpu_preserved_session_ser *ser;
	struct cpu_preserved_as_ser *as;
	struct cpumask cpus;
	bool incoming;
};

static DEFINE_MUTEX(cpu_preserved_sessions_lock);
static LIST_HEAD(cpu_preserved_sessions);
static LIST_HEAD(cpu_preserved_incoming_sessions);

static struct cpu_preserved_session *
cpu_preserved_session_find_locked(struct liveupdate_session *s)
{
	struct cpu_preserved_session *ps;

	list_for_each_entry(ps, &cpu_preserved_sessions, node) {
		if (ps->lsession == s)
			return ps;
	}

	return NULL;
}

static void cpu_preserved_session_release(struct cpu_preserved_session *ps)
{
	if (ps->incoming) {
		cpu_preserved_as_restore_free(ps->as);
		if (ps->ser)
			kho_restore_free(ps->ser);
	} else {
		cpu_preserved_as_unpreserve(ps->as);
		if (ps->ser)
			kho_unpreserve_free(ps->ser);
	}

	kfree(ps);
}

/**
 * cpu_preserved_session_get - Find or create the preserved CPU session of @s
 * @s: Outgoing Live Update session handle.
 *
 * Looks up the preserved CPU session of @s and increments its reference count,
 * or allocates a new session with an isolated address space
 * (&struct cpu_preserved_as_ser) and KHO-preserved metadata
 * (&struct cpu_preserved_session_ser) initialized to a reference count of 1.
 *
 * Return: Pointer to the &struct cpu_preserved_session, or an ERR_PTR() on
 *         failure.
 */
struct cpu_preserved_session *
cpu_preserved_session_get(struct liveupdate_session *s)
{
	struct cpu_preserved_session *ps;

	if (!s)
		return ERR_PTR(-EINVAL);

	guard(mutex)(&cpu_preserved_sessions_lock);

	ps = cpu_preserved_session_find_locked(s);
	if (ps) {
		refcount_inc(&ps->ref);
		return ps;
	}

	ps = kzalloc_obj(*ps);
	if (!ps)
		return ERR_PTR(-ENOMEM);

	ps->as = cpu_preserved_as_create();
	if (IS_ERR(ps->as)) {
		int err = PTR_ERR(ps->as);

		kfree(ps);
		return ERR_PTR(err);
	}

	ps->ser = kho_alloc_preserve(sizeof(*ps->ser));
	if (IS_ERR(ps->ser)) {
		int err = PTR_ERR(ps->ser);

		cpu_preserved_as_unpreserve(ps->as);
		kfree(ps);
		return ERR_PTR(err);
	}

	KHOSER_STORE_PTR(ps->ser->as, ps->as);
	cpu_preserved_clean(ps->ser);

	ps->lsession = s;
	refcount_set(&ps->ref, 1);
	list_add_tail(&ps->node, &cpu_preserved_sessions);
	return ps;
}

/**
 * cpu_preserved_session_put - Drop a reference to a preserved CPU session
 * @ps: Preserved CPU session (may be %NULL or an ERR_PTR()).
 *
 * Decrements @ps's reference count and, when the last reference is dropped,
 * frees the isolated address space and the KHO session metadata.
 */
void cpu_preserved_session_put(struct cpu_preserved_session *ps)
{
	if (!ps || IS_ERR(ps))
		return;

	if (!refcount_dec_and_mutex_lock(&ps->ref, &cpu_preserved_sessions_lock))
		return;

	list_del_init(&ps->node);
	mutex_unlock(&cpu_preserved_sessions_lock);

	cpu_preserved_session_release(ps);
}

/*
 * A CPU of @ps failed to stop and keeps its reference for good, so @ps can
 * outlive its LUO session.  Make sure that no later session can find @ps
 * through the stale pointer.
 */
static void cpu_preserved_session_unhash(struct cpu_preserved_session *ps)
{
	if (!ps)
		return;

	guard(mutex)(&cpu_preserved_sessions_lock);
	list_del_init(&ps->node);
	ps->lsession = NULL;
}

/**
 * cpu_preserved_session_as - Return the isolated address space of a session
 * @ps: Preserved CPU session.
 *
 * Return: Pointer to @ps's &struct cpu_preserved_as_ser, or %NULL if @ps is
 *         %NULL or an ERR_PTR().
 */
struct cpu_preserved_as_ser *
cpu_preserved_session_as(struct cpu_preserved_session *ps)
{
	return (!ps || IS_ERR(ps)) ? NULL : ps->as;
}

/**
 * cpu_preserved_session_cpus - Return the cpumask of preserved CPUs in @ps
 * @ps: Preserved CPU session.
 *
 * Return: Read-only cpumask of physical CPUs currently preserved in @ps, or
 *         %cpu_none_mask if @ps is %NULL or an ERR_PTR().
 */
const struct cpumask *
cpu_preserved_session_cpus(struct cpu_preserved_session *ps)
{
	if (!ps || IS_ERR(ps))
		return cpu_none_mask;

	return &ps->cpus;
}

/* The session of a preserved CPU, which holds a reference for it */
static struct cpu_preserved_session *cpu_preserved_session_of(unsigned int cpu)
{
	struct cpu_preserved_state *st;

	if (cpu >= nr_cpu_ids)
		return NULL;

	guard(mutex)(&cpu_preserved_lock);
	st = cpu_preserved_is_incoming(cpu) ? &cpu_preserved_incoming :
					      &cpu_preserved_outgoing;
	return st->sessions ? st->sessions[cpu] : NULL;
}

static void cpu_preserved_session_remove_cpu(struct cpu_preserved_session *ps,
					     unsigned int cpu)
{
	bool had_cpu;

	if (!ps)
		return;

	scoped_guard(mutex, &cpu_preserved_sessions_lock)
		had_cpu = cpumask_test_and_clear_cpu(cpu, &ps->cpus);

	if (!had_cpu)
		return;

	cpu_preserved_session_put(ps);
}

/*
 * Give each CPU in @cpus the incoming session that its descriptor points to,
 * with one reference per CPU.  On failure, drop the sessions again, but keep
 * the preserved memory: the files of the CPUs still point to it.
 */
static int cpu_preserved_restore_sessions(struct cpu_preserved_ser **cpus,
					  struct cpu_preserved_session **sessions)
{
	struct cpu_preserved_session *ps, *tmp;
	unsigned int cpu;

	guard(mutex)(&cpu_preserved_sessions_lock);
	for (cpu = 0; cpu < nr_cpu_ids; cpu++) {
		struct cpu_preserved_session_ser *sser;
		bool found = false;

		if (!cpus[cpu])
			continue;

		sser = KHOSER_LOAD_PTR(cpus[cpu]->session);
		list_for_each_entry(ps, &cpu_preserved_incoming_sessions, node) {
			if (ps->ser == sser) {
				found = true;
				break;
			}
		}

		if (found) {
			refcount_inc(&ps->ref);
		} else {
			ps = kzalloc_obj(*ps);
			if (!ps)
				goto err;

			ps->incoming = true;
			ps->ser = sser;
			ps->as = KHOSER_LOAD_PTR(sser->as);
			if (cpu_preserved_as_adopt(ps->as)) {
				kfree(ps);
				goto err;
			}
			refcount_set(&ps->ref, 1);
			list_add_tail(&ps->node, &cpu_preserved_incoming_sessions);
		}

		cpumask_set_cpu(cpu, &ps->cpus);
		sessions[cpu] = ps;
	}

	return 0;

err:
	list_for_each_entry_safe(ps, tmp, &cpu_preserved_incoming_sessions, node) {
		list_del(&ps->node);
		cpu_preserved_as_forget(ps->as);
		kfree(ps);
	}
	return -ENOMEM;
}

static int cpu_unpreserve(unsigned int cpu);

/* Map the context page and the stack, but not the guard page between them. */
static int cpu_preserved_map_stack(struct cpu_preserved_as_ser *as, void *stack)
{
	unsigned long va = (unsigned long)stack;
	phys_addr_t pa = virt_to_phys(stack);
	int ret;

	ret = cpu_preserved_as_map(as, pa, va, CPU_PRESERVED_STACK_GUARD,
				   PAGE_KERNEL);
	if (ret)
		return ret;

	ret = cpu_preserved_as_map(as, pa + CPU_PRESERVED_STACK_BASE,
				   va + CPU_PRESERVED_STACK_BASE,
				   CPU_PRESERVED_STACK_SIZE - CPU_PRESERVED_STACK_BASE,
				   PAGE_KERNEL);
	if (ret)
		cpu_preserved_as_unmap(as, va, CPU_PRESERVED_STACK_GUARD);
	return ret;
}

static int cpu_preserve(unsigned int cpu, struct liveupdate_session *session)
{
	struct cpu_preserved_state *outgoing = &cpu_preserved_outgoing;
	struct cpu_preserved_stack_context *sctx;
	struct cpu_preserved_session *ps;
	struct cpu_preserved_as_ser *as;
	struct cpu_preserved_ser *ser;
	void *stack;
	struct device *dev;
	int ret;

	dev = get_cpu_device(cpu);
	if (!dev)
		return -ENODEV;

	ps = cpu_preserved_session_get(session);
	if (IS_ERR(ps))
		return PTR_ERR(ps);

	as = cpu_preserved_session_as(ps);
	if (!as || !as->pgd_pa) {
		cpu_preserved_session_put(ps);
		return -EINVAL;
	}

	stack = kho_alloc_preserve(CPU_PRESERVED_STACK_SIZE);
	if (IS_ERR(stack)) {
		cpu_preserved_session_put(ps);
		return PTR_ERR(stack);
	}

	ser = kho_alloc_preserve(sizeof(*ser));
	if (IS_ERR(ser)) {
		kho_unpreserve_free(stack);
		cpu_preserved_session_put(ps);
		return PTR_ERR(ser);
	}
	ser->cpu = cpu;
	ser->hwid = arch_cpu_preserved_hwid(cpu);
	ser->state = CPU_PRESERVED_PARKING;
	ser->stack_pa = virt_to_phys(stack);
	KHOSER_STORE_PTR(ser->session, ps->ser);
	cpu_preserved_clean(ser);

	ret = cpu_preserved_map_stack(as, stack);
	if (ret) {
		kho_unpreserve_free(ser);
		kho_unpreserve_free(stack);
		cpu_preserved_session_put(ps);
		return ret;
	}

	ret = cpu_preserved_as_map(as, virt_to_phys(ser),
				   (unsigned long)ser, sizeof(*ser),
				   PAGE_KERNEL);
	if (ret) {
		cpu_preserved_as_unmap(as, (unsigned long)stack,
				       CPU_PRESERVED_STACK_SIZE);
		kho_unpreserve_free(ser);
		kho_unpreserve_free(stack);
		cpu_preserved_session_put(ps);
		return ret;
	}

	sctx = stack;
	sctx->magic = CPU_PRESERVED_STACK_MAGIC;
	sctx->cpu = cpu;
	sctx->session_pgd_pa = as->pgd_pa;
	sctx->ser = ser;
	cpu_preserved_clean(sctx);

	/*
	 * Hold the device hotplug lock from the online check until the CPU is
	 * offline, so that no other path can take the CPU down (it would park
	 * on this stack) or bring it up in between.  device_offline() returns
	 * 1 if the CPU was already offline; it is then treated as parked.
	 */
	lock_device_hotplug();
	scoped_guard(mutex, &cpu_preserved_lock) {
		if (cpu_is_preserved(cpu) || !cpu_online(cpu))
			ret = -EBUSY;
		else
			ret = cpu_preserved_init_outgoing();
		if (!ret) {
			cpumask_set_cpu(cpu, &outgoing->mask);
			cpumask_set_cpu(cpu, &cpu_preserved_mask);

			outgoing->cpus[cpu] = ser;
			outgoing->sessions[cpu] = ps;
			cpu_preserved_sync_global_ser();
		}
	}
	if (!ret) {
		ret = device_offline(dev);
		if (ret < 0) {
			pr_err("Failed to offline preserved cpu %u: %d\n",
			       cpu, ret);
			scoped_guard(mutex, &cpu_preserved_lock)
				__cpu_unpreserve_locked(cpu);
			stack = NULL;
		}
	}
	unlock_device_hotplug();
	if (ret < 0) {
		cpu_preserved_as_unmap(as, (unsigned long)ser, sizeof(*ser));
		if (stack) {
			cpu_preserved_as_unmap(as, (unsigned long)stack,
					       CPU_PRESERVED_STACK_SIZE);
			kho_unpreserve_free(stack);
		}
		kho_unpreserve_free(ser);
		cpu_preserved_session_put(ps);
		return ret;
	}

	ret = cpu_wait_parked(cpu);
	if (ret) {
		if (!cpu_unpreserve(cpu)) {
			cpu_preserved_session_put(ps);
			cpu_preserved_free_kho(ser, false);
		} else {
			cpu_preserved_session_unhash(ps);
		}
		return ret;
	}

	scoped_guard(mutex, &cpu_preserved_sessions_lock)
		cpumask_set_cpu(cpu, &ps->cpus);
	return 0;
}

/**
 * cpu_unpreserve - Unpreserve a physical CPU and restore it to online state
 * @cpu: Logical CPU identifier.
 *
 * Signals the CPU to exit the parking loop, waits for it to stop, and brings
 * it back online through CPU hotplug, which resets it.  Only then is its
 * preserved stack freed.
 *
 * Return: 0 on success, or a negative errno if the CPU did not stop or did not
 *         come back online.  The CPU then stays preserved, and everything it
 *         can reach stays allocated.
 */
static int cpu_unpreserve(unsigned int cpu)
{
	struct device *dev = get_cpu_device(cpu);
	int ret;

	scoped_guard(mutex, &cpu_preserved_lock) {
		if (!cpu_is_preserved(cpu))
			return 0;
		if (!dev)
			return -ENODEV;

		cpu_signal_exit(cpu);
		arch_cpu_preserved_kick(cpu);
	}

	/*
	 * Do not hold cpu_preserved_lock across the wait: it only reads the
	 * CPU's ser, which stays valid for as long as the CPU is preserved.
	 */
	ret = cpu_wait_dead(cpu);
	if (WARN_ON_ONCE(ret))
		return ret;

	/*
	 * The stopped CPU still runs on its preserved stack and page tables.
	 * Free them only after the hotplug core has reset it.
	 */
	lock_device_hotplug();
	scoped_guard(mutex, &cpu_preserved_lock)
		cpumask_clear_cpu(cpu, &cpu_preserved_mask);
	ret = device_online(dev);
	scoped_guard(mutex, &cpu_preserved_lock) {
		if (ret)
			cpumask_set_cpu(cpu, &cpu_preserved_mask);
		else
			__cpu_unpreserve_locked(cpu);
	}
	unlock_device_hotplug();

	if (ret) {
		pr_err("Failed to bring unpreserved cpu %u back online: %d\n",
		       cpu, ret);
		return ret < 0 ? ret : -EBUSY;
	}
	return 0;
}
