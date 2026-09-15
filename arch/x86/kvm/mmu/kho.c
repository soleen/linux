// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * KHO preservation of the x86 KVM MMU page tables.
 *
 * An orphaned vCPU keeps running its guest out of the shadow/TDP page tables
 * while the VM is detached, so every page those tables are built from has to
 * survive the kexec.
 */

#include <linux/kexec_handover.h>
#include <linux/kvm_host.h>
#include <linux/sort.h>

#include "mmu.h"
#include "mmu_internal.h"
#include "spte.h"
#include "tdp_iter.h"
#include "tdp_mmu.h"

static int cmp_pages(const void *a, const void *b)
{
	const struct page *pa = *(const struct page **)a;
	const struct page *pb = *(const struct page **)b;

	if (pa < pb)
		return -1;
	if (pa > pb)
		return 1;
	return 0;
}

/*
 * Page-pointer accumulator.
 *
 * kho_preserve_pages() cannot be called while holding kvm->mmu_lock: it is a
 * rwlock_t, so the section is atomic, whereas kho_radix_add_key() below it
 * calls might_sleep(), takes a mutex and allocates with GFP_KERNEL.  So the
 * walk runs in two phases -- collect the pages under the lock, preserve them
 * after dropping it.
 *
 * A NULL @pages simply counts, which is how the caller sizes the array.
 */
void kvm_mmu_kho_add(struct kvm_mmu_kho_pages *acc, struct page *page)
{
	if (!acc->pages) {
		acc->nr++;
		return;
	}

	if (acc->nr >= acc->capacity) {
		acc->overflow = true;
		return;
	}

	acc->pages[acc->nr++] = page;
}

static void kvm_tdp_mmu_collect(struct kvm *kvm,
				struct kvm_mmu_kho_pages *acc)
{
	gfn_t end = kvm_mmu_max_gfn() + 1;
	struct kvm_mmu_page *root;
	struct tdp_iter iter;

	lockdep_assert_held_write(&kvm->mmu_lock);

	rcu_read_lock();
	list_for_each_entry_rcu(root, &kvm->arch.tdp_mmu_roots, link) {
		if (root->spt)
			kvm_mmu_kho_add(acc, virt_to_page(root->spt));

		for_each_tdp_pte(iter, kvm, root, 0, end) {
			struct page *page;

			if (!is_shadow_present_pte(iter.old_spte) ||
			    is_last_spte(iter.old_spte, iter.level))
				continue;

			page = pfn_to_page(spte_to_pfn(iter.old_spte));
			kvm_mmu_kho_add(acc, page);
		}
	}
	rcu_read_unlock();
}

/*
 * The per-vCPU root page tables are not linked into active_mmu_pages, so they
 * have to be walked separately.  pae_root, pml4_root and pml5_root are each
 * NULL unless the corresponding paging mode is in use.
 */
static void kvm_mmu_collect_roots(struct kvm_mmu *mmu,
				  struct kvm_mmu_kho_pages *acc)
{
	void *const roots[] = { mmu->pae_root, mmu->pml4_root, mmu->pml5_root };
	int i;

	for (i = 0; i < ARRAY_SIZE(roots); i++) {
		if (roots[i])
			kvm_mmu_kho_add(acc, virt_to_page(roots[i]));
	}
}

/* Collect every page backing this VM's MMU.  Must be called under mmu_lock. */
static void kvm_mmu_collect_all(struct kvm *kvm,
				struct kvm_mmu_kho_pages *acc)
{
	struct kvm_mmu_page *sp;
	struct kvm_vcpu *vcpu;
	unsigned long i;

	lockdep_assert_held_write(&kvm->mmu_lock);

	acc->nr = 0;
	acc->overflow = false;

	if (tdp_mmu_enabled)
		kvm_tdp_mmu_collect(kvm, acc);

	list_for_each_entry(sp, &kvm->arch.active_mmu_pages, link) {
		if (sp->spt)
			kvm_mmu_kho_add(acc, virt_to_page(sp->spt));
	}

	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (vcpu->arch.mmu)
			kvm_mmu_collect_roots(vcpu->arch.mmu, acc);
		kvm_mmu_collect_roots(&vcpu->arch.guest_mmu, acc);
	}

	if (kvm_x86_ops.vm_collect_kho)
		kvm_x86_call(vm_collect_kho)(kvm, acc);
}

int kvm_mmu_preserve_kho(struct kvm *kvm)
{
	struct kvm_mmu_kho_pages acc = {};
	struct kvm_kho_folios_ser *kp;
	unsigned long i, unique_nr = 0;
	int ret = 0;
	int attempt;

	/*
	 * Size the array, then fill it.  The guest can fault in new page
	 * tables between the two passes, so re-check for overflow and retry
	 * with a larger array; the slack makes repeated growth unlikely.
	 */
	for (attempt = 0; attempt < 5; attempt++) {
		write_lock(&kvm->mmu_lock);
		kvm_mmu_collect_all(kvm, &acc);
		write_unlock(&kvm->mmu_lock);

		if (acc.pages && !acc.overflow)
			break;

		acc.capacity = acc.nr + (acc.nr >> 2) + 16;
		kvfree(acc.pages);
		acc.pages = kvmalloc_array(acc.capacity, sizeof(*acc.pages),
					   GFP_KERNEL);
		if (!acc.pages)
			return -ENOMEM;
	}

	if (acc.overflow) {
		ret = -EAGAIN;
		goto out;
	}

	if (!acc.nr)
		goto out;

	sort(acc.pages, acc.nr, sizeof(*acc.pages), cmp_pages, NULL);
	for (i = 0; i < acc.nr; i++) {
		if (i == 0 || acc.pages[i] != acc.pages[i - 1])
			acc.pages[unique_nr++] = acc.pages[i];
	}
	acc.nr = unique_nr;

	kp = kvm_kho_folios_alloc(acc.nr);
	if (IS_ERR(kp)) {
		ret = PTR_ERR(kp);
		goto out;
	}

	for (i = 0; i < acc.nr; i++) {
		ret = kho_preserve_folio(page_folio(acc.pages[i]));
		if (ret) {
			/*
			 * Undo the partial preservation: leaving pages marked
			 * would pin them in the incoming kernel forever with
			 * nothing owning them.
			 */
			while (i--)
				kho_unpreserve_folio(page_folio(acc.pages[i]));
			kho_unpreserve_free(kp);
			goto out;
		}
		kp->folios_pa[i] = page_to_phys(acc.pages[i]);
	}

	kp->nr_folios = acc.nr;
	kvm->kho_folios = kp;

out:
	kvfree(acc.pages);
	return ret;
}
