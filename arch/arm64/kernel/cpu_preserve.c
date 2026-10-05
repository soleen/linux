// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * Architecture specific CPU preservation support for ARM64.
 */
#include <linux/arm-smccc.h>
#include <linux/bitfield.h>
#include <linux/cacheflush.h>
#include <linux/cpu_preserve.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/irqchip/arm-gic-v3.h>
#include <linux/kho/abi/cpu.h>
#include <linux/mm.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/pgtable.h>
#include <linux/psci.h>
#include <uapi/linux/psci.h>

#include <asm/barrier.h>
#include <asm/cpu_ops.h>
#include <asm/cpufeature.h>
#include <asm/sysreg.h>
#include <asm/tlbflush.h>
#include <asm/trans_pgd.h>
#include <asm/virt.h>

#include "cpu_preserve_internal.h"

static void arm64_add_gicr_region(phys_addr_t pa, size_t size, u64 stride)
{
	void __iomem *va;
	size_t map_size;
	int i;

	for (i = 0; i < cpu_preserved_gic.nr_regions; i++)
		if (cpu_preserved_gic.regions[i].pa == pa)
			return;

	if (cpu_preserved_gic.nr_regions >= ARRAY_SIZE(cpu_preserved_gic.regions))
		return;

	map_size = max_t(size_t, size, nr_cpu_ids * (stride ? : SZ_128K));
	va = ioremap(pa, map_size);
	if (!va)
		return;

	i = cpu_preserved_gic.nr_regions++;
	cpu_preserved_gic.regions[i].pa = pa;
	cpu_preserved_gic.regions[i].va = va;
	cpu_preserved_gic.regions[i].size = map_size;
	cpu_preserved_gic.regions[i].stride = stride;
}

static void arm64_discover_gicr_res(struct resource *res)
{
	for (; res; res = res->sibling) {
		if (res->name && !strcmp(res->name, "GICR"))
			arm64_add_gicr_region(res->start, resource_size(res), 0);
		if (res->child)
			arm64_discover_gicr_res(res->child);
	}
}

static void arm64_cpu_preserved_gic_init(void)
{
	struct device_node *node;

	if (!cpus_have_cap(ARM64_HAS_GICV3_CPUIF) ||
	    cpu_preserved_gic.nr_regions > 0)
		return;

	node = of_find_compatible_node(NULL, NULL, "arm,gic-v3");
	if (node) {
		u32 nr_redist_regions = 1;
		u64 stride = 0;
		int i;

		of_property_read_u32(node, "#redistributor-regions",
				     &nr_redist_regions);
		of_property_read_u64(node, "redistributor-stride", &stride);
		for (i = 0; i < nr_redist_regions; i++) {
			struct resource res;

			if (of_address_to_resource(node, 1 + i, &res) == 0)
				arm64_add_gicr_region(res.start,
						      resource_size(&res),
						      stride);
		}
		of_node_put(node);
	}

	if (cpu_preserved_gic.nr_regions == 0)
		arm64_discover_gicr_res(&iomem_resource);
}

/**
 * arch_cpu_preserved_as_map - Populate an isolated page table on arm64
 * @as: Address space to map into.
 * @pa: Physical address of the range.
 * @va: Virtual address the range must appear at.
 * @size: Size of the range in bytes.
 * @prot: Protection to apply.
 *
 * Return: 0 on success, or a negative errno on failure.
 */
int arch_cpu_preserved_as_map(struct cpu_preserved_as_ser *as, phys_addr_t pa,
			      unsigned long va, size_t size, pgprot_t prot)
{
	struct trans_pgd_info info = {
		.trans_alloc_page = cpu_preserved_as_alloc_page,
		.trans_alloc_arg = as,
	};
	unsigned long offset = va & ~PAGE_MASK;
	size_t page_size = PAGE_ALIGN(offset + size);
	unsigned long page_va = va & PAGE_MASK;
	phys_addr_t page_pa = (pa & PAGE_MASK);
	void *pgd = phys_to_virt(as->pgd_pa);
	int ret;

	ret = trans_pgd_map_range(&info, pgd, page_pa,
				  page_va, page_size, prot);
	if (!ret) {
		dsb(ishst);
	} else if (ret == -ENOMEM) {
		if (arch_cpu_preserved_as_unmap(as, page_va, page_size))
			arch_cpu_preserved_as_flush_tlb();
	}
	return ret;
}

bool arch_cpu_preserved_as_unmap(struct cpu_preserved_as_ser *as,
				 unsigned long va, size_t size)
{
	unsigned long offset = va & ~PAGE_MASK;
	size_t page_size = PAGE_ALIGN(offset + size);
	unsigned long addr = va & PAGE_MASK;
	unsigned long end = addr + page_size;
	pgd_t *root = phys_to_virt(as->pgd_pa);
	bool unmapped = false;

	for (; addr < end; addr += PAGE_SIZE) {
		pgd_t *pgdp = pgd_offset_pgd(root, addr);
		p4d_t *p4dp;
		pud_t *pudp;
		pmd_t *pmdp;
		pte_t *ptep;

		if (pgd_none(READ_ONCE(*pgdp)))
			continue;
		p4dp = p4d_offset(pgdp, addr);
		if (p4d_none(READ_ONCE(*p4dp)))
			continue;
		pudp = pud_offset(p4dp, addr);
		if (pud_none(READ_ONCE(*pudp)) || pud_leaf(READ_ONCE(*pudp)))
			continue;
		pmdp = pmd_offset(pudp, addr);
		if (pmd_none(READ_ONCE(*pmdp)) || pmd_leaf(READ_ONCE(*pmdp)))
			continue;
		ptep = pte_offset_kernel(pmdp, addr);
		if (!pte_none(READ_ONCE(*ptep))) {
			set_pte(ptep, __pte(0));
			unmapped = true;
		}
	}

	return unmapped;
}

void arch_cpu_preserved_as_flush_tlb(void)
{
	arm64_flush_host_tlb_all();
}

/**
 * arch_cpu_preserved_setup_buffer - Prepare the copy of the preserved runtime
 * @text_page: Runtime-allocated physical page backing preserved text.
 * @text_nr_pages: Number of pages in text buffer.
 * @data_page: Runtime-allocated physical page backing preserved data.
 * @data_nr_pages: Number of pages in data buffer.
 *
 * Validates platform support for CPU preservation, cleans the D-cache on the
 * linear map alias of the allocated runtime copy, and invalidates the I-cache.
 *
 * Return: 0 on success, or a negative errno on failure.
 */
int arch_cpu_preserved_setup_buffer(struct page *text_page,
				    unsigned int text_nr_pages,
				    struct page *data_page,
				    unsigned int data_nr_pages)
{
	unsigned long text = (unsigned long)page_address(text_page);
	unsigned long data = (unsigned long)page_address(data_page);
	int cpu;

	if (!cpus_have_final_cap(ARM64_HAS_GICV3_CPUIF) ||
	    cpu_preserved_gic.nr_regions <= 0 ||
	    arm64_psci_conduit == SMCCC_CONDUIT_NONE || !psci_ops.cpu_off)
		return -EOPNOTSUPP;

	for_each_present_cpu(cpu) {
		if (!gicv3_get_rdist_for_mpidr(cpu_logical_map(cpu)))
			return -EOPNOTSUPP;
	}

	__arch_cpu_preserved_dcache_clean(text, text + text_nr_pages * PAGE_SIZE);
	__arch_cpu_preserved_dcache_clean(data, data + data_nr_pages * PAGE_SIZE);
	icache_inval_all_pou();

	return 0;
}

void arch_cpu_preserved_early_init(void)
{
	arm64_cpu_preserved_gic_init();

	if (psci_ops.cpu_off && psci_ops.get_version &&
	    psci_ops.get_version() >= PSCI_VERSION(0, 2))
		arm64_psci_conduit = psci_get_conduit();
}

/*
 * Signal or wake up a preserved physical CPU via SEV and GICv3 SGI.
 */
void arch_cpu_preserved_kick(int cpu)
{
	if (!cpu_is_preserved(cpu) || cpu_preserved_is_stopped(cpu))
		return;

	dsb(ishst);
	sev();
	if (cpus_have_cap(ARM64_HAS_GICV3_CPUIF))
		gicv3_cpu_preserved_kick_mpidr(cpu_logical_map(cpu));
	isb();
}

u64 arch_cpu_preserved_hwid(unsigned int cpu)
{
	return cpu_logical_map(cpu);
}

u64 arch_cpu_preserved_mode(void)
{
	u64 mode;

	mode = FIELD_PREP(CPU_PRESERVED_ARM64_PAGE_SHIFT_MASK, PAGE_SHIFT) |
	       FIELD_PREP(CPU_PRESERVED_ARM64_VA_BITS_MASK, VA_BITS) |
	       FIELD_PREP(CPU_PRESERVED_ARM64_PGTABLE_LEVELS_MASK,
			  CONFIG_PGTABLE_LEVELS);
	if (lpa2_is_enabled())
		mode |= CPU_PRESERVED_ARM64_LPA2;
	if (is_kernel_in_hyp_mode())
		mode |= CPU_PRESERVED_ARM64_VHE;
	if (IS_ENABLED(CONFIG_CPU_BIG_ENDIAN))
		mode |= CPU_PRESERVED_ARM64_BE;

	return mode;
}

void arch_cpu_preserved_park_on_stack(int cpu, unsigned long stack_top)
{
	__arch_cpu_preserved_park_on_stack(cpu, stack_top);
}

int arch_cpu_preserved_wait_dead(int cpu)
{
	struct cpu_preserved_stack_context *sctx = cpu_preserved_get_sctx(cpu);
	const struct cpu_operations *ops = get_cpu_ops(cpu);

	if (sctx) {
		cpu_preserved_inval(&sctx->fault);
		if (READ_ONCE(sctx->fault.count)) {
			const struct arm64_preserved_fault *f = &sctx->fault;

			pr_err("cpu_preserve: CPU %d unhandled fault kind=%lu esr=0x%lx elr=0x%lx far=0x%lx spsr=0x%lx\n",
			       cpu, f->kind, f->esr, f->elr, f->far, f->spsr);
		}
	}

	if (ops && ops->cpu_kill)
		return ops->cpu_kill(cpu);

	return 0;
}
