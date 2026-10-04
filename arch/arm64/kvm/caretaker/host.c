// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * ARM64 KVM Caretaker host lifecycle and Stage-2 preservation.
 */
#include <linux/kvm_host.h>
#include <linux/kvm_caretaker.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pgtable.h>

static int stage2_kho_visitor(const struct kvm_pgtable_visit_ctx *ctx,
			      enum kvm_pgtable_walk_flags visit)
{
	struct kvm_kho_pages *acc = ctx->arg;

	if (kvm_pte_valid(ctx->old) && ctx->level != KVM_PGTABLE_LAST_LEVEL &&
	    FIELD_GET(KVM_PTE_TYPE, ctx->old) == KVM_PTE_TYPE_TABLE) {
		u64 phys = kvm_pte_to_phys(ctx->old);

		kvm_kho_pages_add(acc, phys_to_page(phys));
	}
	return 0;
}

static int arm64_stage2_collect_all(struct kvm *kvm, struct kvm_kho_pages *acc)
{
	struct kvm_s2_mmu *mmu = &kvm->arch.mmu;
	struct kvm_pgtable_walker walker = {
		.cb = stage2_kho_visitor,
		.flags = KVM_PGTABLE_WALK_TABLE_PRE,
		.arg = acc,
	};

	lockdep_assert_held_write(&kvm->mmu_lock);

	if (mmu->pgd_phys) {
		size_t pgd_pages = kvm_pgtable_stage2_pgd_size(mmu->vtcr) >> PAGE_SHIFT;
		size_t p;

		for (p = 0; p < pgd_pages; p++)
			kvm_kho_pages_add(acc,
					  phys_to_page(mmu->pgd_phys + (p << PAGE_SHIFT)));
	}
	if (mmu->pgt)
		return kvm_pgtable_walk(mmu->pgt, 0, BIT(mmu->pgt->ia_bits), &walker);
	return 0;
}

int kvm_arch_vm_luo_freeze(struct kvm *kvm, struct kvm_luo_ser *ser)
{
	kvm->caretaker_vm = NULL;
	return kvm_kho_preserve_vm_pages(kvm, ser, arm64_stage2_collect_all);
}
