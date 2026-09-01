// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2026, Google LLC.
 * Tarun Sahu <tarunsahu@google.com>
 *
 * KVM VM and vCPU Preservation for Live Update Orchestrator (LUO)
 */

#include <linux/liveupdate.h>
#include <linux/kvm_host.h>
#include <linux/cpu_preserve.h>
#include <linux/caretaker.h>
#include <linux/kvm_caretaker.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/err.h>
#include <linux/anon_inodes.h>
#include <linux/magic.h>
#include <linux/kexec_handover.h>
#include <linux/kho/abi/kexec_handover.h>
#include <linux/kho/abi/kvm.h>
#if defined(CONFIG_ARM64)
#include <asm/kvm_mmu.h>
#endif
#include "kvm_mm.h"

static bool kvm_luo_can_preserve(struct liveupdate_file_handler *handler,
				 struct file *file)
{
	return file_is_kvm(file);
}

static int kvm_luo_preserve(struct liveupdate_file_op_args *args)
{
	struct kvm *kvm = args->file->private_data;
	struct kvm_luo_ser *ser;
	int ret;

	if (kvm->vm_dead || kvm->vm_bugged)
		return -EINVAL;

	BUILD_BUG_ON(sizeof(*ser) != 16);

	ser = kho_alloc_preserve(sizeof(*ser));
	if (IS_ERR(ser))
		return PTR_ERR(ser);

#if defined(CONFIG_X86)
	ser->type = kvm->arch.vm_type;
#elif defined(CONFIG_ARM64)
	ser->type = kvm_phys_shift(&kvm->arch.mmu);
	if (kvm_vm_is_protected(kvm))
		ser->type |= KVM_VM_TYPE_ARM_PROTECTED;
#else
	ser->type = 0;
#endif

	ser->arch_state.phys = 0;
	ret = kvm_arch_vm_luo_preserve(kvm, ser);
	if (ret) {
		kho_unpreserve_free(ser);
		return ret;
	}

	args->serialized_data = virt_to_phys(ser);
	return 0;
}

static atomic_t restored_vm_id = ATOMIC_INIT(0);

static int kvm_luo_retrieve(struct liveupdate_file_op_args *args)
{
	char fdname[ITOA_MAX_LEN + 1];
	struct kvm_luo_ser *ser;
	struct file *file;
	struct kvm *kvm;
	int err = 0;

	if (!args->serialized_data)
		return -EINVAL;

	ser = phys_to_virt(args->serialized_data);

	snprintf(fdname, sizeof(fdname), "%d",
		 atomic_inc_return(&restored_vm_id));

	file = kvm_create_vm_file(ser->type, fdname);
	if (IS_ERR(file)) {
		err = PTR_ERR(file);
		goto err_free_ser;
	}

	kvm = file->private_data;

	err = kvm_arch_vm_luo_retrieve(kvm, ser);
	if (err) {
		fput(file);
		goto err_free_ser;
	}

	args->file = file;

	kvm_uevent_notify_vm_create(kvm);
	return 0;

err_free_ser:
	kvm_arch_vm_luo_finish(ser);
	kho_restore_free(ser);
	return err;
}

static void kvm_luo_unpreserve(struct liveupdate_file_op_args *args)
{
	struct kvm_luo_ser *ser;

	if (WARN_ON_ONCE(!args->serialized_data))
		return;

	ser = phys_to_virt(args->serialized_data);
	kvm_arch_vm_luo_unpreserve(ser);
	kho_unpreserve_free(ser);
}

static void kvm_luo_finish(struct liveupdate_file_op_args *args)
{
	struct kvm_luo_ser *ser;

	if (!args->serialized_data)
		return;

	ser = phys_to_virt(args->serialized_data);
	kvm_arch_vm_luo_finish(ser);
	kho_restore_free(ser);
}

static const struct liveupdate_file_ops kvm_luo_file_ops = {
	.can_preserve = kvm_luo_can_preserve,
	.preserve = kvm_luo_preserve,
	.retrieve = kvm_luo_retrieve,
	.unpreserve = kvm_luo_unpreserve,
	.finish = kvm_luo_finish,
	.owner = THIS_MODULE,
};

static struct liveupdate_file_handler kvm_luo_handler = {
	.ops = &kvm_luo_file_ops,
	.compatible = KVM_LUO_FH_COMPATIBLE,
};

static bool kvm_vcpu_luo_can_preserve(struct liveupdate_file_handler *handler,
				      struct file *file)
{
	return file_is_kvm_vcpu(file);
}

static int kvm_vcpu_luo_preserve(struct liveupdate_file_op_args *args)
{
	struct kvm_vcpu *vcpu = args->file->private_data;
	struct caretaker_job *job;
	struct kvm_vcpu_luo_ser *ser;
	struct task_struct *task = NULL;
	int target_cpu = -1;
	int ret;

	if (!vcpu)
		return -EINVAL;

	BUILD_BUG_ON(sizeof(*ser) != 32);

	read_lock(&vcpu->pid_lock);
	task = vcpu->pid ? pid_task(vcpu->pid, PIDTYPE_PID) : NULL;
	if (task)
		get_task_struct(task);
	read_unlock(&vcpu->pid_lock);

	if (task) {
		if (task->nr_cpus_allowed == 1) {
			int cpu = cpumask_first(task->cpus_ptr);
			if (cpu > 0)
				target_cpu = cpu;
		}
		put_task_struct(task);
	}

	if (target_cpu < 0 && vcpu->cb.pcpu_id > 0 && vcpu->cb.pcpu_id < nr_cpu_ids)
		target_cpu = vcpu->cb.pcpu_id;

	if (target_cpu < 0 && vcpu->cpu > 0)
		target_cpu = vcpu->cpu;

	char name[32];
	snprintf(name, sizeof(name), "vcpu%d", vcpu->vcpu_id);

	job = caretaker_session_submit_job(args->session, name, target_cpu,
					   kvm_arch_vcpu_caretaker_run, vcpu);
	if (IS_ERR(job))
		return PTR_ERR(job);

	vcpu->caretaker_job = job;
	target_cpu = job->assigned_cpu;

	ser = kho_alloc_preserve(sizeof(*ser));
	if (IS_ERR(ser)) {
		caretaker_session_cancel_job(args->session, job);
		vcpu->caretaker_job = NULL;
		return PTR_ERR(ser);
	}

	ser->vcpu_id = vcpu->vcpu_id;
	ser->flags = 0;
	if (target_cpu >= 0)
		ser->flags |= KVM_VCPU_LUO_FLAG_CARETAKER;
	ser->vm_token = 0;
	ser->arch_state.phys = 0;
	ser->cb.phys = 0;

	if (target_cpu >= 0) {
		vcpu->cb.pcpu_id = target_cpu;
		caretaker_kvm_detach(&vcpu->cb);
	} else {
		vcpu->cb.pcpu_id = CARETAKER_INVALID_PCPU;
	}

	ret = kvm_arch_vcpu_luo_preserve(vcpu, ser);
	if (ret) {
		caretaker_session_cancel_job(args->session, job);
		vcpu->caretaker_job = NULL;
		if (target_cpu >= 0)
			caretaker_kvm_attach(&vcpu->cb);
		kho_unpreserve_free(ser);
		return ret;
	}

	if (target_cpu >= 0) {
		job->data = kvm_arch_vcpu_caretaker_data(vcpu);
		if (job->data)
			caretaker_kvm_detach(job->data);
		ret = caretaker_session_activate_job(args->session, job);
		if (ret) {
			caretaker_session_cancel_job(args->session, job);
			vcpu->caretaker_job = NULL;
			caretaker_kvm_attach(&vcpu->cb);
			if (job->data)
				caretaker_kvm_attach(job->data);
			kho_unpreserve_free(ser);
			return ret;
		}
	}

	args->serialized_data = virt_to_phys(ser);
	return 0;
}

static int kvm_vcpu_luo_freeze(struct liveupdate_file_op_args *args)
{
	struct kvm_vcpu_luo_ser *ser;
	struct kvm_vcpu *vcpu;
	struct file *kvm_file;
	u64 vm_token;
	int err;

	if (!args->serialized_data)
		return -EINVAL;

	ser = phys_to_virt(args->serialized_data);
	vcpu = args->file->private_data;
	if (!vcpu || !vcpu->kvm)
		return -EINVAL;

	kvm_file = get_file_active(&vcpu->kvm->vm_file);
	if (!kvm_file)
		return -ENOENT;

	err = liveupdate_get_token_outgoing(args->session, kvm_file, &vm_token);
	fput(kvm_file);
	if (err)
		return err;

	ser->vm_token = vm_token;
	return 0;
}

static int kvm_vcpu_luo_retrieve(struct liveupdate_file_op_args *args)
{
	struct kvm_vcpu_luo_ser *ser;
	struct file *vm_file, *file;
	struct kvm_vcpu *vcpu;
	int fd, err;

	if (!args->serialized_data)
		return -EINVAL;

	ser = phys_to_virt(args->serialized_data);

	err = liveupdate_get_file_incoming(args->session, ser->vm_token, &vm_file);
	if (err)
		goto err_free_ser;

	fd = vm_file->f_op->unlocked_ioctl(vm_file, KVM_CREATE_VCPU, ser->vcpu_id);
	fput(vm_file);
	if (fd < 0) {
		err = fd;
		goto err_free_ser;
	}

	file = file_close_fd(fd);
	if (!file) {
		err = -EBADF;
		goto err_free_ser;
	}

	vcpu = file->private_data;
	if (vcpu) {
		err = kvm_arch_vcpu_luo_retrieve(vcpu, ser);
		if (err) {
			fput(file);
			goto err_free_ser;
		}
		kvm_arch_vcpu_luo_attach_caretaker(vcpu, ser);

		vcpu->cb.vcpu_id = ser->vcpu_id;
		vcpu->cb.vm_token = ser->vm_token;
	}

	args->file = file;
	return 0;

err_free_ser:
	kvm_arch_vcpu_luo_finish(ser);
	kho_restore_free(ser);
	return err;
}

static void kvm_vcpu_luo_unpreserve(struct liveupdate_file_op_args *args)
{
	struct kvm_vcpu *vcpu = args->file ? args->file->private_data : NULL;
	struct kvm_vcpu_luo_ser *ser;

	if (WARN_ON_ONCE(!args->serialized_data))
		return;

	ser = phys_to_virt(args->serialized_data);

	if (vcpu) {
		kvm_arch_vcpu_luo_attach_caretaker(vcpu, ser);
		if (vcpu->caretaker_job) {
			caretaker_session_cancel_job(args->session, vcpu->caretaker_job);
			vcpu->caretaker_job = NULL;
		}
	}

	kvm_arch_vcpu_luo_unpreserve(ser);
	kho_unpreserve_free(ser);
}

static void kvm_vcpu_luo_finish(struct liveupdate_file_op_args *args)
{
	struct kvm_vcpu *vcpu = args->file ? args->file->private_data : NULL;
	struct kvm_vcpu_luo_ser *ser;

	if (!args->serialized_data)
		return;

	ser = phys_to_virt(args->serialized_data);

	if (vcpu && vcpu->caretaker_job) {
		caretaker_session_cancel_job(args->session, vcpu->caretaker_job);
		vcpu->caretaker_job = NULL;
	}

	kvm_arch_vcpu_luo_finish(ser);
	kho_restore_free(ser);
}

static const struct liveupdate_file_ops kvm_vcpu_luo_file_ops = {
	.can_preserve = kvm_vcpu_luo_can_preserve,
	.preserve = kvm_vcpu_luo_preserve,
	.freeze = kvm_vcpu_luo_freeze,
	.retrieve = kvm_vcpu_luo_retrieve,
	.unpreserve = kvm_vcpu_luo_unpreserve,
	.finish = kvm_vcpu_luo_finish,
	.owner = THIS_MODULE,
};

static struct liveupdate_file_handler kvm_vcpu_luo_handler = {
	.ops = &kvm_vcpu_luo_file_ops,
	.compatible = KVM_VCPU_LUO_FH_COMPATIBLE,
};

int kvm_luo_init(void)
{
	int err = liveupdate_register_file_handler(&kvm_luo_handler);

	if (err && err != -EOPNOTSUPP) {
		pr_err("Could not register kvm_luo handler: %pe\n", ERR_PTR(err));
		return err;
	}

	err = liveupdate_register_file_handler(&kvm_vcpu_luo_handler);
	if (err && err != -EOPNOTSUPP) {
		pr_err("Could not register kvm_vcpu_luo handler: %pe\n", ERR_PTR(err));
		liveupdate_unregister_file_handler(&kvm_luo_handler);
		return err;
	}

	return 0;
}

void kvm_luo_exit(void)
{
	liveupdate_unregister_file_handler(&kvm_vcpu_luo_handler);
	liveupdate_unregister_file_handler(&kvm_luo_handler);
}
