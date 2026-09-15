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

#include "mmu.h"
#include "mmu_internal.h"
#include "spte.h"
#include "tdp_iter.h"
#include "tdp_mmu.h"

static int kvm_tdp_mmu_preserve_kho(struct kvm *kvm)
{
	gfn_t end = kvm_mmu_max_gfn() + 1;
	struct kvm_mmu_page *root;
	struct tdp_iter iter;
	int ret = 0;

	rcu_read_lock();
	list_for_each_entry_rcu(root, &kvm->arch.tdp_mmu_roots, link) {
		if (root->spt) {
			ret = kho_preserve_pages(virt_to_page(root->spt), 1);
			if (ret)
				break;
		}
		for_each_tdp_pte(iter, kvm, root, 0, end) {
			if (is_shadow_present_pte(iter.old_spte) &&
			    !is_last_spte(iter.old_spte, iter.level)) {
				struct page *page =
					pfn_to_page(spte_to_pfn(iter.old_spte));

				ret = kho_preserve_pages(page, 1);
				if (ret)
					break;
			}
		}
		if (ret)
			break;
	}
	rcu_read_unlock();

	return ret;
}

/*
 * The per-vCPU root page tables are not linked into active_mmu_pages, so they
 * have to be walked separately.  pae_root, pml4_root and pml5_root are each
 * NULL unless the corresponding paging mode is in use.
 */
static int kvm_mmu_preserve_roots(struct kvm_mmu *mmu)
{
	void *const roots[] = { mmu->pae_root, mmu->pml4_root, mmu->pml5_root };
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(roots); i++) {
		if (!roots[i])
			continue;

		ret = kho_preserve_pages(virt_to_page(roots[i]), 1);
		if (ret)
			return ret;
	}

	return 0;
}

int kvm_mmu_preserve_kho(struct kvm *kvm)
{
	struct kvm_mmu_page *sp;
	struct kvm_vcpu *vcpu;
	unsigned long i;
	int ret = 0;

	if (tdp_mmu_enabled) {
		ret = kvm_tdp_mmu_preserve_kho(kvm);
		if (ret)
			return ret;
	}

	write_lock(&kvm->mmu_lock);
	list_for_each_entry(sp, &kvm->arch.active_mmu_pages, link) {
		if (sp->spt) {
			ret = kho_preserve_pages(virt_to_page(sp->spt), 1);
			if (ret)
				break;
		}
	}
	write_unlock(&kvm->mmu_lock);
	if (ret)
		return ret;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (vcpu->arch.mmu) {
			ret = kvm_mmu_preserve_roots(vcpu->arch.mmu);
			if (ret)
				return ret;
		}

		ret = kvm_mmu_preserve_roots(&vcpu->arch.guest_mmu);
		if (ret)
			return ret;
	}

	return 0;
}
