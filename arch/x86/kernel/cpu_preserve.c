// SPDX-License-Identifier: GPL-2.0
/*
 * Architecture specific CPU preservation support for x86.
 */
#include <linux/cpu_preserve.h>
#include <linux/kexec_handover.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <asm/apic.h>
#include <asm/cacheflush.h>
#include <asm/cpufeature.h>
#include <asm/pgtable.h>
#include <asm/set_memory.h>
#include <asm/smp.h>
#include <asm/tlbflush.h>
#include <asm/caretaker.h>
#include <asm/fixmap.h>
#include <asm/trans_pgd.h>
#include <linux/caretaker.h>

static bool x86_preserved_is_x2apic __cpu_preserved_data;
unsigned long x86_preserved_apic_eoi_va __cpu_preserved_data;
EXPORT_SYMBOL_GPL(x86_preserved_apic_eoi_va);

/*
 * Signal or wake up a preserved physical CPU via APIC ICR NMI.
 */
void __cpu_preserved_text arch_cpu_preserved_kick(int cpu)
{
	u32 apicid;

	if (cpu <= 0 || cpu >= NR_CPUS || !cpu_is_preserved(cpu))
		return;

	apicid = cpuid_to_apicid[cpu];
	if (apicid == BAD_APICID)
		apicid = cpu;

	if (x86_preserved_is_x2apic) {
		u64 val = ((u64)apicid << 32) | APIC_DM_NMI;
		native_wrmsrq(APIC_BASE_MSR + (APIC_ICR >> 4), val);
	} else if (x86_preserved_apic_eoi_va) {
		void __iomem *icr_va = (void __iomem *)(x86_preserved_apic_eoi_va - APIC_EOI + APIC_ICR);
		while (readl(icr_va) & APIC_ICR_BUSY)
			cpu_relax();
		writel(apicid << 24, icr_va + 0x10);
		writel(APIC_DM_NMI, icr_va);
	}
}

/*
 * Low-power wait in parking loop.
 */
void __cpu_preserved_text arch_cpu_preserved_park_wait(void)
{
	cpu_relax();
}

#include <asm/desc.h>

extern void x86_preserved_iret_stub(void);
extern void x86_preserved_iret_err_stub(void);
extern void x86_preserved_apic_eoi_stub(void);


static gate_desc x86_preserved_idt[256] __cpu_preserved_data __aligned(PAGE_SIZE);
static bool x86_preserved_idt_initialized __cpu_preserved_data;

static struct desc_struct x86_preserved_gdt[GDT_ENTRIES] __cpu_preserved_data __aligned(PAGE_SIZE);
static bool x86_preserved_gdt_initialized __cpu_preserved_data;
static bool x86_preserved_has_svm __cpu_preserved_data;

static void init_preserved_idt(void)
{
	unsigned long iret_handler = (unsigned long)&x86_preserved_iret_stub;
	unsigned long iret_err_handler = (unsigned long)&x86_preserved_iret_err_stub;
	unsigned long eoi_handler = (unsigned long)&x86_preserved_apic_eoi_stub;
	int v;

	if (x86_preserved_idt_initialized)
		return;

	for (v = 0; v < 256; v++) {
		bool has_err = (v == 8 || (v >= 10 && v <= 14) ||
				v == 17 || v == 21 || v == 29 || v == 30);
		unsigned long handler = (v >= 32) ? eoi_handler :
			(has_err ? iret_err_handler : iret_handler);

		pack_gate(&x86_preserved_idt[v], GATE_INTERRUPT, handler, 0,
			  0, __KERNEL_CS);
	}
	x86_preserved_idt_initialized = true;
	arch_cpu_preserved_dcache_clean((unsigned long)&x86_preserved_idt,
					(unsigned long)&x86_preserved_idt + sizeof(x86_preserved_idt));
}

static void init_preserved_gdt(void)
{
	struct desc_struct *gdt;
	int i;

	if (x86_preserved_gdt_initialized)
		return;

	gdt = get_current_gdt_rw();
	for (i = 0; i < GDT_ENTRIES; i++)
		x86_preserved_gdt[i] = gdt[i];
	x86_preserved_gdt_initialized = true;
	arch_cpu_preserved_dcache_clean((unsigned long)&x86_preserved_gdt,
					(unsigned long)&x86_preserved_gdt + sizeof(x86_preserved_gdt));
}

void __cpu_preserved_text arch_cpu_preserved_load_desc(void)
{
	struct desc_ptr idt_desc = {
		.size = sizeof(x86_preserved_idt) - 1,
		.address = (unsigned long)&x86_preserved_idt[0],
	};
	struct desc_ptr gdt_desc = {
		.size = GDT_SIZE - 1,
		.address = (unsigned long)&x86_preserved_gdt[0],
	};

	native_load_gdt(&gdt_desc);
	native_load_idt(&idt_desc);
}
EXPORT_SYMBOL_GPL(arch_cpu_preserved_load_desc);

/*
 * Disables local interrupts on the physical core and loads preserved IDT and GDT.
 */
void __cpu_preserved_text arch_cpu_preserved_park_init(int cpu __maybe_unused)
{
	local_irq_disable();
	if (!x86_preserved_apic_eoi_va)
		x86_preserved_apic_eoi_va = (unsigned long)(fix_to_virt(FIX_APIC_BASE) + APIC_EOI);
	arch_cpu_preserved_load_desc();

	if (x86_preserved_is_x2apic) {
		u32 spiv = (u32)native_rdmsrq(APIC_BASE_MSR + (APIC_SPIV >> 4));
		if (!(spiv & APIC_SPIV_APIC_ENABLED)) {
			spiv |= APIC_SPIV_APIC_ENABLED;
			native_wrmsrq(APIC_BASE_MSR + (APIC_SPIV >> 4), spiv);
		}
	} else if (x86_preserved_apic_eoi_va) {
		void __iomem *spiv_va = (void __iomem *)(x86_preserved_apic_eoi_va - APIC_EOI + APIC_SPIV);
		u32 spiv = readl(spiv_va);
		if (!(spiv & APIC_SPIV_APIC_ENABLED)) {
			spiv |= APIC_SPIV_APIC_ENABLED;
			writel(spiv, spiv_va);
		}
	}
}

void arch_cpu_preserved_early_init(void)
{
	if (!x86_preserved_apic_eoi_va)
		x86_preserved_apic_eoi_va = (unsigned long)(fix_to_virt(FIX_APIC_BASE) + APIC_EOI);
	x86_preserved_has_svm = boot_cpu_has(X86_FEATURE_SVM);
	x86_preserved_is_x2apic = x2apic_enabled();
}
EXPORT_SYMBOL_GPL(arch_cpu_preserved_early_init);

/*
 * Disable hardware virtualization on physical core so INIT is recognized.
 */
static void __cpu_preserved_text arch_cpu_preserved_virt_teardown(void)
{
	if (__read_cr4() & X86_CR4_VMXE) {
		asm volatile("1: vmxoff\n\t"
			     "2:\n\t"
			     _ASM_EXTABLE(1b, 2b)
			     : : : "memory", "cc");
		asm volatile("mov %0, %%cr4" : : "r" (__read_cr4() & ~X86_CR4_VMXE) : "memory");
	}

	if (x86_preserved_has_svm) {
		u32 lo, hi;

		asm volatile("1: stgi\n\t"
			     "2:\n\t"
			     _ASM_EXTABLE(1b, 2b)
			     : : : "memory");

		asm volatile("1: rdmsr\n\t"
			     "btrl $12, %%eax\n\t"
			     "wrmsr\n\t"
			     "2:\n\t"
			     _ASM_EXTABLE(1b, 2b)
			     : "=a" (lo), "=d" (hi)
			     : "c" (MSR_EFER)
			     : "memory");
	}
}

/*
 * Architecture cleanup on park loop exit.
 */
void __cpu_preserved_text arch_cpu_preserved_park_finish(int cpu __maybe_unused)
{
	arch_cpu_preserved_load_desc();
	arch_cpu_preserved_virt_teardown();
}

void __cpu_preserved_text arch_cpu_preserved_park_cancel(int cpu)
{
	arch_cpu_preserved_park_finish(cpu);
}

static pgd_t *x86_caretaker_pgd __cpu_preserved_data;
phys_addr_t x86_caretaker_pgd_pa __cpu_preserved_data;
EXPORT_SYMBOL_GPL(x86_caretaker_pgd_pa);
static phys_addr_t preserved_text_pa;
static unsigned long preserved_text_sz;
static phys_addr_t preserved_data_pa;
static unsigned long preserved_data_sz;

bool __cpu_preserved_text arch_cpu_preserved_is_active(void)
{
	unsigned long cr3 = __read_cr3();
	struct cpu_preserved_stack_context *sctx = cpu_preserved_get_stack_context();

	if (sctx && sctx->session_pgd_pa && cr3 == sctx->session_pgd_pa)
		return true;
	return x86_caretaker_pgd_pa && (cr3 == x86_caretaker_pgd_pa);
}
EXPORT_SYMBOL_GPL(arch_cpu_preserved_is_active);

void __cpu_preserved_text arch_cpu_preserved_switch_pgd(phys_addr_t pgd_pa)
{
	if (pgd_pa && __read_cr3() != pgd_pa)
		write_cr3(pgd_pa);
}
EXPORT_SYMBOL_GPL(arch_cpu_preserved_switch_pgd);

static LIST_HEAD(x86_caretaker_pages);

asmlinkage void arch_cpu_preserved_call_on_stack(int cpu, unsigned long stack,
						 void (*fn)(int cpu));

static void __cpu_preserved_text arch_cpu_preserved_park_worker(int cpu)
{
	struct cpu_preserved_stack_context *sctx = cpu_preserved_get_stack_context();
	phys_addr_t pgd_pa = 0;

	if (sctx && sctx->session_pgd_pa)
		pgd_pa = sctx->session_pgd_pa;
	else
		pgd_pa = cpu_preserved_get_pgd(cpu);

	if (!pgd_pa)
		pgd_pa = x86_caretaker_pgd_pa;

	if (pgd_pa)
		write_cr3(pgd_pa);

	cpu_preserved_park_loop(cpu);

	arch_cpu_preserved_park_finish(cpu);
	while (1) {
		native_irq_disable();
		asm volatile("hlt");
	}
}

/*
 * Switch stack and enter park loop.
 */
void __cpu_preserved_text arch_cpu_preserved_park_on_stack(int cpu, unsigned long stack_top)
{
	arch_cpu_preserved_call_on_stack(cpu, stack_top, arch_cpu_preserved_park_worker);
}
EXPORT_SYMBOL_GPL(arch_cpu_preserved_park_on_stack);

/*
 * Clean data cache for address range. x86 has hardware coherent caches,
 * so a memory barrier suffices without calling unpreserved external routines.
 */
void __cpu_preserved_text arch_cpu_preserved_dcache_clean(unsigned long start, unsigned long end)
{
	mb();
}

/*
 * Invalidate data cache for address range.
 */
void __cpu_preserved_text arch_cpu_preserved_dcache_inval(unsigned long start, unsigned long end)
{
	mb();
}

static void *x86_caretaker_alloc_page(void *arg)
{
	struct caretaker_session *sess = arg;
	void *ptr = kho_alloc_preserve(PAGE_SIZE);
	struct page *page;

	if (IS_ERR_OR_NULL(ptr)) {
		page = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!page)
			return NULL;
		ptr = page_address(page);
		kho_preserve_pages(page, 1);
	} else {
		page = virt_to_page(ptr);
	}

	arch_cpu_preserved_dcache_clean((unsigned long)ptr,
					(unsigned long)ptr + PAGE_SIZE);

	if (sess) {
		if (sess->nr_pgd_pages < ARRAY_SIZE(sess->pgd_pages))
			sess->pgd_pages[sess->nr_pgd_pages++] = virt_to_phys(ptr);
		else
			WARN_ON_ONCE(1);
	} else {
		list_add(&page->lru, &x86_caretaker_pages);
	}
	return ptr;
}

static DEFINE_MUTEX(x86_caretaker_map_lock);

int arch_cpu_preserved_map_range(phys_addr_t pa, unsigned long va,
				 size_t size, pgprot_t prot)
{
	struct trans_pgd_info info = {
		.trans_alloc_page = x86_caretaker_alloc_page,
	};
	unsigned long page_va = va & PAGE_MASK;
	unsigned long offset = va & ~PAGE_MASK;
	phys_addr_t page_pa = (pa & PAGE_MASK);
	size_t page_size = PAGE_ALIGN(offset + size);
	struct page *page;
	int ret;

	if (!x86_caretaker_pgd || !size)
		return 0;

	scoped_guard(mutex, &x86_caretaker_map_lock) {
		ret = trans_pgd_map_range(&info, x86_caretaker_pgd, page_pa,
					  page_va, page_size, prot);
		if (ret)
			return ret;

		list_for_each_entry(page, &x86_caretaker_pages, lru)
			kho_preserve_pages(page, 1);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(arch_cpu_preserved_map_range);

int arch_cpu_preserved_setup_buffer(struct page *text_page,
				    unsigned int text_nr_pages,
				    struct page *data_page,
				    unsigned int data_nr_pages)
{
	unsigned long text_start = (unsigned long)__cpu_preserved_text_start;
	unsigned long data_start = (unsigned long)__cpu_preserved_data_start;
	preserved_text_pa = page_to_phys(text_page);
	preserved_text_sz = (unsigned long)__cpu_preserved_text_end - text_start;
	preserved_data_pa = page_to_phys(data_page);
	preserved_data_sz = (unsigned long)__cpu_preserved_data_end - data_start;
	struct trans_pgd_info info = {
		.trans_alloc_page = x86_caretaker_alloc_page,
	};
	unsigned int i;
	int ret;

	if (x86_caretaker_pgd)
		return 0;

	/* Split kernel large pages into 4K PTEs */
	ret = set_memory_4k(text_start, text_nr_pages);
	if (ret)
		return ret;

	ret = set_memory_4k(data_start, data_nr_pages);
	if (ret)
		return ret;

	/* Remap init_mm kernel mappings to point to allocated buffer pages */
	for (i = 0; i < text_nr_pages; i++) {
		unsigned int level;
		pte_t *pte = lookup_address(text_start + i * PAGE_SIZE, &level);

		if (pte && level == PG_LEVEL_4K) {
			phys_addr_t pa = page_to_phys(text_page) + i * PAGE_SIZE;
			set_pte(pte, pfn_pte(PHYS_PFN(pa), pte_pgprot(*pte)));
		}
	}

	for (i = 0; i < data_nr_pages; i++) {
		unsigned int level;
		pte_t *pte = lookup_address(data_start + i * PAGE_SIZE, &level);

		if (pte && level == PG_LEVEL_4K) {
			phys_addr_t pa = page_to_phys(data_page) + i * PAGE_SIZE;
			set_pte(pte, pfn_pte(PHYS_PFN(pa), pte_pgprot(*pte)));
		}
	}

	flush_tlb_all();

	/* Ensure preserved GDT, IDT, and arch flags are initialized */
	arch_cpu_preserved_early_init();
	init_preserved_idt();
	init_preserved_gdt();
	arch_cpu_preserved_dcache_clean((unsigned long)&x86_preserved_is_x2apic,
					(unsigned long)&x86_preserved_is_x2apic + sizeof(bool));
	arch_cpu_preserved_dcache_clean((unsigned long)&x86_preserved_has_svm,
					(unsigned long)&x86_preserved_has_svm + sizeof(bool));
	arch_cpu_preserved_dcache_clean((unsigned long)&x86_preserved_apic_eoi_va,
					(unsigned long)&x86_preserved_apic_eoi_va + sizeof(unsigned long));

	/* Allocate fresh root PGD for isolated Caretaker page table */
	x86_caretaker_pgd = x86_caretaker_alloc_page(NULL);
	if (!x86_caretaker_pgd)
		return -ENOMEM;

	/* Map Caretaker Text & Rodata (ROX) */
	ret = trans_pgd_map_range(&info, x86_caretaker_pgd, preserved_text_pa,
				  text_start, preserved_text_sz, PAGE_KERNEL_ROX);
	if (ret)
		return ret;

	/* Map Caretaker Writable Data (RW) */
	ret = trans_pgd_map_range(&info, x86_caretaker_pgd, preserved_data_pa,
				  data_start, preserved_data_sz, PAGE_KERNEL);
	if (ret)
		return ret;

	/* Map Local APIC fixmap if in legacy xAPIC MMIO mode */
	if (!x2apic_mode) {
		unsigned int level;
		pte_t *pte = lookup_address((unsigned long)fix_to_virt(FIX_APIC_BASE), &level);

		if (pte && pte_present(*pte)) {
			phys_addr_t apic_pa = pte_pfn(*pte) << PAGE_SHIFT;

			ret = trans_pgd_map_range(&info, x86_caretaker_pgd,
						  apic_pa,
						  (unsigned long)fix_to_virt(FIX_APIC_BASE),
						  PAGE_SIZE,
						  PAGE_KERNEL_IO_NOCACHE);
			if (ret)
				return ret;
		}
	}

	x86_caretaker_pgd_pa = virt_to_phys(x86_caretaker_pgd);
	return 0;
}

void arch_cpu_preserved_preserve_pagetables(void)
{
	struct page *page;

	guard(mutex)(&x86_caretaker_map_lock);
	if (!x86_caretaker_pgd)
		return;

	list_for_each_entry(page, &x86_caretaker_pages, lru)
		kho_preserve_pages(page, 1);
}

void arch_cpu_preserved_unpreserve_pagetables(void)
{
	struct page *page;

	list_for_each_entry(page, &x86_caretaker_pages, lru)
		kho_unpreserve_pages(page, 1);
}

void arch_cpu_preserved_wait_dead(int cpu)
{
	x86_virt_reset_cpu(cpu);
}

void *arch_cpu_preserved_get_pgd(void)
{
	return x86_caretaker_pgd;
}
EXPORT_SYMBOL_GPL(arch_cpu_preserved_get_pgd);

int arch_caretaker_alloc_session_pgd(struct caretaker_session *sess)
{
	struct trans_pgd_info info = {
		.trans_alloc_page = x86_caretaker_alloc_page,
		.trans_alloc_arg = sess,
	};
	unsigned long text_start = (unsigned long)__cpu_preserved_text_start;
	unsigned long data_start = (unsigned long)__cpu_preserved_data_start;
	int ret;

	if (!sess)
		return -EINVAL;
	if (sess->pgd)
		return 0;

	if (!preserved_text_pa || !preserved_data_pa)
		return -EAGAIN;

	guard(mutex)(&x86_caretaker_map_lock);

	sess->pgd = x86_caretaker_alloc_page(sess);
	if (!sess->pgd)
		return -ENOMEM;

	/* Map Caretaker Text & Rodata (ROX) */
	ret = trans_pgd_map_range(&info, sess->pgd, preserved_text_pa,
				  text_start, preserved_text_sz, PAGE_KERNEL_ROX);
	if (ret)
		return ret;

	/* Map Caretaker Writable Data (RW) */
	ret = trans_pgd_map_range(&info, sess->pgd, preserved_data_pa,
				  data_start, preserved_data_sz, PAGE_KERNEL);
	if (ret)
		return ret;

	/* Map Local APIC fixmap if in legacy xAPIC MMIO mode */
	if (!x2apic_mode) {
		unsigned int level;
		pte_t *pte = lookup_address((unsigned long)fix_to_virt(FIX_APIC_BASE), &level);

		if (pte && pte_present(*pte)) {
			phys_addr_t apic_pa = pte_pfn(*pte) << PAGE_SHIFT;

			ret = trans_pgd_map_range(&info, sess->pgd,
						  apic_pa,
						  (unsigned long)fix_to_virt(FIX_APIC_BASE),
						  PAGE_SIZE,
						  PAGE_KERNEL_IO_NOCACHE);
			if (ret)
				return ret;
		}
	}

	sess->pgd_pa = virt_to_phys(sess->pgd);
	return 0;
}
EXPORT_SYMBOL_GPL(arch_caretaker_alloc_session_pgd);

void arch_caretaker_free_session_pgd(struct caretaker_session *sess)
{
	int i;

	if (!sess || !sess->pgd)
		return;

	guard(mutex)(&x86_caretaker_map_lock);

	for (i = 0; i < sess->nr_pgd_pages; i++) {
		void *va = phys_to_virt(sess->pgd_pages[i]);

		if (sess->is_incoming)
			kho_restore_free(va);
		else
			kho_unpreserve_free(va);
	}

	sess->nr_pgd_pages = 0;
	sess->pgd = NULL;
	sess->pgd_pa = 0;
}
EXPORT_SYMBOL_GPL(arch_caretaker_free_session_pgd);

int arch_caretaker_map_session_range(struct caretaker_session *sess,
				     phys_addr_t pa, unsigned long va,
				     size_t size, pgprot_t prot)
{
	struct trans_pgd_info info = {
		.trans_alloc_page = x86_caretaker_alloc_page,
		.trans_alloc_arg = sess,
	};
	unsigned long page_va = va & PAGE_MASK;
	unsigned long offset = va & ~PAGE_MASK;
	phys_addr_t page_pa = (pa & PAGE_MASK);
	size_t page_size = PAGE_ALIGN(offset + size);

	if (!sess || !sess->pgd || !size)
		return 0;

	guard(mutex)(&x86_caretaker_map_lock);

	return trans_pgd_map_range(&info, sess->pgd, page_pa,
				   page_va, page_size, prot);
}
EXPORT_SYMBOL_GPL(arch_caretaker_map_session_range);


u64 __cpu_preserved_text arch_caretaker_ticks_to_ns(u64 ticks)
{
	u32 khz = global_sched_config.tsc_khz;

	if (khz > 0)
		return mul_u64_u32_div(ticks, 1000000U, khz);
	return ticks;
}
EXPORT_SYMBOL_GPL(arch_caretaker_ticks_to_ns);

void arch_caretaker_update_quantum_ticks(struct caretaker_sched_config *cfg)
{
	u32 ms = cfg->quantum_ms;

	if (tsc_khz > 0) {
		cfg->tsc_khz = tsc_khz;
		cfg->quantum_ticks = (u64)ms * tsc_khz;
	} else {
		cfg->quantum_ticks = (u64)ms * 2000000ULL;
	}
}
EXPORT_SYMBOL_GPL(arch_caretaker_update_quantum_ticks);
