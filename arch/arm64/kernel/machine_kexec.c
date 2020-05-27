// SPDX-License-Identifier: GPL-2.0-only
/*
 * kexec for arm64
 *
 * Copyright (C) Linaro.
 * Copyright (C) Huawei Futurewei Technologies.
 */

#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/kernel.h>
#include <linux/kexec.h>
#include <linux/page-flags.h>
#include <linux/smp.h>

#include <asm/cacheflush.h>
#include <asm/cpu_ops.h>
#include <asm/daifflags.h>
#include <asm/memory.h>
#include <asm/mmu.h>
#include <asm/mmu_context.h>
#include <asm/page.h>
#include <asm/trans_pgd.h>

extern const unsigned char arm64_relocate_new_kernel[];
extern const unsigned char arm64_relocate_new_kernel_end[];

void __cpu_soft_restart(phys_addr_t entry, unsigned long arg0,
			unsigned long arg1, unsigned long arg2);

static inline size_t arm64_kexec_reloc_size(void)
{
	return arm64_relocate_new_kernel_end - arm64_relocate_new_kernel;
}

/**
 * kexec_image_info - For debugging output.
 */
#define kexec_image_info(_i) _kexec_image_info(__func__, __LINE__, _i)
static void _kexec_image_info(const char *func, int line,
	const struct kimage *kimage)
{
	unsigned long i;

	pr_debug("%s:%d:\n", func, line);
	pr_debug("  kexec kimage info:\n");
	pr_debug("    type:        %d\n", kimage->type);
	pr_debug("    start:       %lx\n", kimage->start);
	pr_debug("    head:        %lx\n", kimage->head);
	pr_debug("    nr_segments: %lu\n", kimage->nr_segments);
	pr_debug("    kern_reloc: %pa\n", &kimage->arch.kern_reloc);

	for (i = 0; i < kimage->nr_segments; i++) {
		pr_debug("      segment[%lu]: %016lx - %016lx, 0x%lx bytes, %lu pages\n",
			i,
			kimage->segment[i].mem,
			kimage->segment[i].mem + kimage->segment[i].memsz,
			kimage->segment[i].memsz,
			kimage->segment[i].memsz /  PAGE_SIZE);
	}
}

void machine_kexec_cleanup(struct kimage *kimage)
{
	/* Empty routine needed to avoid build errors. */
}

/**
 * machine_kexec_prepare - Prepare for a kexec reboot.
 *
 * Called from the core kexec code when a kernel image is loaded.
 * Forbid loading a kexec kernel if we have no way of hotplugging cpus or cpus
 * are stuck in the kernel. This avoids a panic once we hit machine_kexec().
 */
int machine_kexec_prepare(struct kimage *kimage)
{
	if (kimage->type != KEXEC_TYPE_CRASH && cpus_are_stuck_in_kernel()) {
		pr_err("Can't kexec: CPUs are stuck in the kernel.\n");
		return -EBUSY;
	}

	return 0;
}

/**
 * kexec_list_flush - Helper to flush the kimage list and source pages to PoC.
 */
static void kexec_list_flush(struct kimage *kimage)
{
	kimage_entry_t *entry;

	__flush_dcache_area(kimage, sizeof(*kimage));

	for (entry = &kimage->head; ; entry++) {
		unsigned int flag;
		void *addr;

		/* flush the list entries. */
		__flush_dcache_area(entry, sizeof(kimage_entry_t));

		flag = *entry & IND_FLAGS;
		if (flag == IND_DONE)
			break;

		addr = phys_to_virt(*entry & PAGE_MASK);

		switch (flag) {
		case IND_INDIRECTION:
			/* Set entry point just before the new list page. */
			entry = (kimage_entry_t *)addr - 1;
			break;
		case IND_SOURCE:
			/* flush the source pages. */
			__flush_dcache_area(addr, PAGE_SIZE);
			break;
		case IND_DESTINATION:
			break;
		default:
			BUG();
		}
	}
}

/**
 * kexec_segment_flush - Helper to flush the kimage segments to PoC.
 */
static void kexec_segment_flush(const struct kimage *kimage)
{
	unsigned long i;

	pr_debug("%s:\n", __func__);

	for (i = 0; i < kimage->nr_segments; i++) {
		pr_debug("  segment[%lu]: %016lx - %016lx, 0x%lx bytes, %lu pages\n",
			i,
			kimage->segment[i].mem,
			kimage->segment[i].mem + kimage->segment[i].memsz,
			kimage->segment[i].memsz,
			kimage->segment[i].memsz /  PAGE_SIZE);

		__flush_dcache_area(phys_to_virt(kimage->segment[i].mem),
			kimage->segment[i].memsz);
	}
}

static bool kexec_relocation_needed(struct kimage *kimage)
{
	/* The kdump kernel is always stored in place */
	if (kimage == kexec_crash_image)
		return false;

	/* unless the list is empty, kexec needs relocation */
	return !(kimage->head & IND_DONE);
}

/* Allocates pages for kexec page table */
static void *kexec_page_alloc(void *arg)
{
	struct kimage *kimage = (struct kimage *)arg;
	struct page *page = kimage_alloc_control_pages(kimage, 0);

	if (!page)
		return NULL;

	memset(page_address(page), 0, PAGE_SIZE);

	return page_address(page);
}

int machine_kexec_post_load(struct kimage *kimage)
{
	int rc;
	pgd_t *trans_pgd, *idmap_pgd;
	size_t reloc_size = arm64_kexec_reloc_size();
	bool relocation_needed = kexec_relocation_needed(kimage);
	struct trans_pgd_info trans_info = {
		.trans_alloc_page	= kexec_page_alloc,
		.trans_alloc_arg	= kimage,
	};
	void *reloc_code;

	/* Clean the relocation data or payload to PoC */
	if (relocation_needed)
		kexec_list_flush(kimage);
	else
		kexec_segment_flush(kimage);

	/* No relocation? Nothing more to do! */
	if (!relocation_needed) {
		kexec_image_info(kimage);
		return 0;
	}

	/* Copy and clean the relocation code that runs with the MMU off */
	reloc_code = page_to_virt(kimage->control_code_page);
	memcpy(reloc_code, arm64_relocate_new_kernel, reloc_size);
	__flush_dcache_area(reloc_code, reloc_size);
	flush_icache_range((unsigned long)reloc_code,
			   (unsigned long)reloc_code + reloc_size);
	kimage->arch.kern_reloc = __pa(reloc_code);
	rc = trans_idmap_single_page(&trans_info, kimage->arch.kern_reloc,
				     PAGE_KERNEL_EXEC, &kimage->arch.idmap_t0sz,
				     &idmap_pgd);
	if (rc)
		return rc;
	kimage->arch.idmap_pgd = idmap_pgd;

	/*
	 * Relocation will overwrite the hyp-stub, which we need to call the
	 * payload at EL2. Provide a safe copy.
	 */
	kimage->arch.hyp_stub_copy = 0;
	if (is_hyp_callable() &&
	    arm64_copy_hyp_stub(&trans_info, &kimage->arch.hyp_stub_copy))
		return -ENOMEM;

	/* Create a copy of the linear map */
	trans_pgd = kexec_page_alloc(kimage);
	if (!trans_pgd)
		return -ENOMEM;
	rc = trans_pgd_create_copy(&trans_info, &trans_pgd, PAGE_OFFSET,
				   PAGE_END);
	if (rc)
		return rc;
	kimage->arch.ttbr1_baddr = __pa(trans_pgd);
	kimage->arch.zero_page = __pa(empty_zero_page);

	kexec_image_info(kimage);

	return 0;
}

/**
 * machine_kexec - Do the kexec reboot.
 *
 * Called from the core kexec code for a sys_reboot with LINUX_REBOOT_CMD_KEXEC.
 */
void machine_kexec(struct kimage *kimage)
{
	void (*cpu_soft_restart)(phys_addr_t entry, unsigned long arg0,
				 unsigned long arg1, unsigned long arg2);
	bool in_kexec_crash = (kimage == kexec_crash_image);
	bool stuck_cpus = cpus_are_stuck_in_kernel();

	/*
	 * New cpus may have become stuck_in_kernel after we loaded the image.
	 */
	BUG_ON(!in_kexec_crash && (stuck_cpus || (num_online_cpus() > 1)));
	WARN(in_kexec_crash && (stuck_cpus || smp_crash_stop_failed()),
		"Some CPUs may be stale, kdump will be unreliable.\n");

	pr_info("Bye!\n");

	local_daif_mask();

	/*
	 * If the image is already stored in place and cleaned to the PoC.
	 * All we need to do is disable the MMU and jump in.
	 */
	if (!kexec_relocation_needed(kimage)) {
		if (is_hyp_callable())
			__arm64_call_hyp(HVC_SOFT_RESTART, kimage->start,
					 kimage->arch.dtb_mem, 0, 0, 0);

		cpu_install_idmap();
		cpu_soft_restart = (void *)__pa_symbol(__cpu_soft_restart);
		cpu_soft_restart(kimage->start, kimage->arch.dtb_mem, 0, 0);
	}

	if (is_hyp_callable())
		__hyp_set_vectors(kimage->arch.hyp_stub_copy);

	/*
	 * cpu_soft_restart will shutdown the MMU, disable data caches, then
	 * transfer control to the reboot_code_buffer which contains a copy of
	 * the arm64_relocate_new_kernel routine.  arm64_relocate_new_kernel
	 * uses physical addressing to relocate the new image to its final
	 * position and transfers control to the image entry point when the
	 * relocation is complete.
	 * In kexec case, kimage->start points to purgatory assuming that
	 * kernel entry and dtb address are embedded in purgatory by
	 * userspace (kexec-tools).
	 * In kexec_file case, the kernel starts directly without purgatory.
	 */
	cpu_install_teardown_idmap(kimage->arch.idmap_pgd,
				    kimage->arch.idmap_t0sz);
	cpu_soft_restart = (void *)kimage->arch.kern_reloc;
	cpu_soft_restart(virt_to_phys(kimage), physvirt_offset, 0, 0);

	BUG(); /* Should never get here. */
}

static void machine_kexec_mask_interrupts(void)
{
	unsigned int i;
	struct irq_desc *desc;

	for_each_irq_desc(i, desc) {
		struct irq_chip *chip;
		int ret;

		chip = irq_desc_get_chip(desc);
		if (!chip)
			continue;

		/*
		 * First try to remove the active state. If this
		 * fails, try to EOI the interrupt.
		 */
		ret = irq_set_irqchip_state(i, IRQCHIP_STATE_ACTIVE, false);

		if (ret && irqd_irq_inprogress(&desc->irq_data) &&
		    chip->irq_eoi)
			chip->irq_eoi(&desc->irq_data);

		if (chip->irq_mask)
			chip->irq_mask(&desc->irq_data);

		if (chip->irq_disable && !irqd_irq_disabled(&desc->irq_data))
			chip->irq_disable(&desc->irq_data);
	}
}

/**
 * machine_crash_shutdown - shutdown non-crashing cpus and save registers
 */
void machine_crash_shutdown(struct pt_regs *regs)
{
	local_irq_disable();

	/* shutdown non-crashing cpus */
	crash_smp_send_stop();

	/* for crashing cpu */
	crash_save_cpu(regs, smp_processor_id());
	machine_kexec_mask_interrupts();

	pr_info("Starting crashdump kernel...\n");
}

void arch_kexec_protect_crashkres(void)
{
	int i;

	for (i = 0; i < kexec_crash_image->nr_segments; i++)
		set_memory_valid(
			__phys_to_virt(kexec_crash_image->segment[i].mem),
			kexec_crash_image->segment[i].memsz >> PAGE_SHIFT, 0);
}

void arch_kexec_unprotect_crashkres(void)
{
	int i;

	for (i = 0; i < kexec_crash_image->nr_segments; i++)
		set_memory_valid(
			__phys_to_virt(kexec_crash_image->segment[i].mem),
			kexec_crash_image->segment[i].memsz >> PAGE_SHIFT, 1);
}

#ifdef CONFIG_HIBERNATION
/*
 * To preserve the crash dump kernel image, the relevant memory segments
 * should be mapped again around the hibernation.
 */
void crash_prepare_suspend(void)
{
	if (kexec_crash_image)
		arch_kexec_unprotect_crashkres();
}

void crash_post_resume(void)
{
	if (kexec_crash_image)
		arch_kexec_protect_crashkres();
}

/*
 * crash_is_nosave
 *
 * Return true only if a page is part of reserved memory for crash dump kernel,
 * but does not hold any data of loaded kernel image.
 *
 * Note that all the pages in crash dump kernel memory have been initially
 * marked as Reserved as memory was allocated via memblock_reserve().
 *
 * In hibernation, the pages which are Reserved and yet "nosave" are excluded
 * from the hibernation iamge. crash_is_nosave() does thich check for crash
 * dump kernel and will reduce the total size of hibernation image.
 */

bool crash_is_nosave(unsigned long pfn)
{
	int i;
	phys_addr_t addr;

	if (!crashk_res.end)
		return false;

	/* in reserved memory? */
	addr = __pfn_to_phys(pfn);
	if ((addr < crashk_res.start) || (crashk_res.end < addr))
		return false;

	if (!kexec_crash_image)
		return true;

	/* not part of loaded kernel image? */
	for (i = 0; i < kexec_crash_image->nr_segments; i++)
		if (addr >= kexec_crash_image->segment[i].mem &&
				addr < (kexec_crash_image->segment[i].mem +
					kexec_crash_image->segment[i].memsz))
			return false;

	return true;
}

void crash_free_reserved_phys_range(unsigned long begin, unsigned long end)
{
	unsigned long addr;
	struct page *page;

	for (addr = begin; addr < end; addr += PAGE_SIZE) {
		page = phys_to_page(addr);
		free_reserved_page(page);
	}
}
#endif /* CONFIG_HIBERNATION */
