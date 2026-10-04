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

#include <linux/kvm_caretaker.h>
#include <linux/kvm_host.h>

#include "mmu.h"
#include "mmu_internal.h"
#include "spte.h"
#include "tdp_iter.h"
#include "tdp_mmu.h"

static void kvm_tdp_mmu_collect(struct kvm *kvm,
				struct kvm_kho_pages *acc)
{
	gfn_t end = kvm_mmu_max_gfn() + 1;
	struct kvm_mmu_page *root;
	struct tdp_iter iter;

	lockdep_assert_held_write(&kvm->mmu_lock);

	rcu_read_lock();
	list_for_each_entry_rcu(root, &kvm->arch.tdp_mmu_roots, link) {
		if (root->spt)
			kvm_kho_pages_add(acc, virt_to_page(root->spt));

		for_each_tdp_pte(iter, kvm, root, 0, end) {
			struct page *page;

			if (!is_shadow_present_pte(iter.old_spte) ||
			    is_last_spte(iter.old_spte, iter.level))
				continue;

			page = pfn_to_page(spte_to_pfn(iter.old_spte));
			kvm_kho_pages_add(acc, page);
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
				  struct kvm_kho_pages *acc)
{
	void *const roots[] = { mmu->pae_root, mmu->pml4_root, mmu->pml5_root };
	int i;

	for (i = 0; i < ARRAY_SIZE(roots); i++) {
		if (roots[i])
			kvm_kho_pages_add(acc, virt_to_page(roots[i]));
	}
}

/* Collect every page backing this VM's MMU.  Must be called under mmu_lock. */
static int kvm_mmu_collect_all(struct kvm *kvm,
			       struct kvm_kho_pages *acc)
{
	struct kvm_mmu_page *sp;
	struct kvm_vcpu *vcpu;
	unsigned long i;

	lockdep_assert_held_write(&kvm->mmu_lock);

	if (tdp_mmu_enabled)
		kvm_tdp_mmu_collect(kvm, acc);

	list_for_each_entry(sp, &kvm->arch.active_mmu_pages, link) {
		if (sp->spt)
			kvm_kho_pages_add(acc, virt_to_page(sp->spt));
	}

	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (vcpu->arch.mmu)
			kvm_mmu_collect_roots(vcpu->arch.mmu, acc);
		kvm_mmu_collect_roots(&vcpu->arch.guest_mmu, acc);
	}

	if (kvm_x86_ops.vm_collect_kho)
		kvm_x86_call(vm_collect_kho)(kvm, acc);

	return 0;
}

int kvm_mmu_preserve_kho(struct kvm *kvm)
{
	return kvm_kho_preserve_vm_pages(kvm, NULL, kvm_mmu_collect_all);
}
