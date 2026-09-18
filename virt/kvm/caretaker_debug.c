// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * KVM Caretaker execution telemetry and debugfs reporting.
 */

#include <linux/cpu_preserve.h>
#include <linux/debugfs.h>
#include <linux/kernel.h>
#include <linux/kexec_handover.h>
#include <linux/kho/abi/kvm.h>
#include <linux/kvm_caretaker.h>
#include <linux/kvm_host.h>
#include <linux/oncore.h>
#include <linux/seq_file.h>

void kvm_caretaker_telemetry_init(struct kvm_caretaker_vcpu *cvcpu,
				  struct oncore_session *sess)
{
	struct kvm_caretaker_telemetry_ser *tel;

	tel = kho_alloc_preserve(sizeof(*tel));
	if (IS_ERR_OR_NULL(tel))
		return;

	memset(tel, 0, sizeof(*tel));
	oncore_session_map_buffer(sess, tel, sizeof(*tel));
	cpu_preserved_clean_sz(tel, sizeof(*tel));
	cvcpu->telemetry = tel;
	KHOSER_STORE_PTR(cvcpu->cb->telemetry, tel);
}

void kvm_caretaker_telemetry_report(struct kvm_vcpu *vcpu,
				    struct kvm_caretaker_cb_ser *cb)
{
	struct kvm_caretaker_telemetry_ser *tel;

	if (!vcpu || !cb)
		return;

	cpu_preserved_inval(cb);
	tel = KHOSER_LOAD_PTR(cb->telemetry);
	if (!tel)
		return;

	cpu_preserved_inval(tel);
	vcpu->caretaker.last_telemetry = *tel;

	pr_info("caretaker: vcpu %d resume: runs=%llu exits=%llu stalls=%llu last_exit=0x%llx (%llu) rip=0x%llx\n",
		vcpu->vcpu_id, tel->total_runs, tel->total_exits,
		tel->stall_count, tel->last_exit_reason,
		tel->last_exit_reason, tel->last_exit_rip);
	if (tel->stall_count) {
		pr_info("caretaker: vcpu %d stall info: reason=0x%llx (%llu) rip=0x%llx\n",
			vcpu->vcpu_id, tel->stall_exit_reason,
			tel->stall_exit_reason, tel->stall_exit_rip);
	}
}

void kvm_caretaker_telemetry_free(struct kvm_vcpu_ser *ser, bool is_incoming)
{
	struct kvm_caretaker_telemetry_ser *tel;
	struct kvm_caretaker_cb_ser *cb;

	if (!ser || !(ser->flags & KVM_VCPU_LUO_FLAG_CARETAKER))
		return;

	cb = KHOSER_LOAD_PTR(ser->cb);
	tel = cb ? KHOSER_LOAD_PTR(cb->telemetry) : NULL;
	if (tel) {
		cb->telemetry.phys = 0;
		if (is_incoming)
			kho_restore_free(tel);
		else
			kho_unpreserve_free(tel);
	}
}

static int caretaker_telemetry_show(struct seq_file *m, void *v)
{
	struct kvm_vcpu *vcpu = m->private;
	const struct kvm_caretaker_telemetry_ser *t =
		&vcpu->caretaker.last_telemetry;
	struct kvm_caretaker_cb_ser *cb = READ_ONCE(vcpu->caretaker.cb);

	if (cb) {
		struct kvm_caretaker_telemetry_ser *live;

		cpu_preserved_inval(cb);
		live = KHOSER_LOAD_PTR(cb->telemetry);
		if (live) {
			cpu_preserved_inval(live);
			t = live;
		}
	}

	seq_printf(m, "runs: %llu\n", t->total_runs);
	seq_printf(m, "exits: %llu\n", t->total_exits);
	seq_printf(m, "stalls: %llu\n", t->stall_count);
	seq_printf(m, "last_exit_reason: 0x%llx (%llu)\n",
		   t->last_exit_reason, t->last_exit_reason);
	seq_printf(m, "last_exit_rip: 0x%llx\n", t->last_exit_rip);
	seq_printf(m, "stall_exit_reason: 0x%llx (%llu)\n",
		   t->stall_exit_reason, t->stall_exit_reason);
	seq_printf(m, "stall_exit_rip: 0x%llx\n", t->stall_exit_rip);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(caretaker_telemetry);

void kvm_caretaker_create_vcpu_debugfs(struct kvm_vcpu *vcpu,
				       struct dentry *debugfs_dentry)
{
	if (!debugfs_dentry)
		return;

	debugfs_create_file("caretaker_telemetry", 0444, debugfs_dentry, vcpu,
			    &caretaker_telemetry_fops);
}
