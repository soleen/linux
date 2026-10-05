// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026, Google LLC.
 *
 * Test driver for On-Core Session and Scheduler Framework
 */

#define pr_fmt(fmt) "oncore_test: " fmt

#include <linux/anon_inodes.h>
#include <linux/cleanup.h>
#include <linux/cpu_preserve.h>
#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/kexec_handover.h>
#include <linux/liveupdate.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/oncore.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include "oncore_test.h"

#define ONCORE_TEST_STOP_TIMEOUT_US	2000000
#define ONCORE_TEST_STOP_STEP_US	100

struct oncore_test_ctx {
	struct mutex lock;
	struct oncore_test_state *state;
	struct oncore_test_buf *buf;
	struct oncore_job *job;
	struct oncore_test_buf last_snap;
	bool has_snap;
};

static int oncore_test_open(struct inode *inode, struct file *file)
{
	struct oncore_test_ctx *ctx;

	ctx = kzalloc_obj(*ctx);
	if (!ctx)
		return -ENOMEM;

	mutex_init(&ctx->lock);
	ctx->last_snap.last_cpu = -1;
	file->private_data = ctx;
	return 0;
}

static int oncore_test_release(struct inode *inode, struct file *file)
{
	struct oncore_test_ctx *ctx = file->private_data;

	if (ctx) {
		mutex_destroy(&ctx->lock);
		kfree(ctx);
	}
	return 0;
}

static ssize_t oncore_test_read(struct file *file, char __user *ubuf,
				size_t count, loff_t *ppos)
{
	struct oncore_test_ctx *ctx = file->private_data;
	struct oncore_test_buf snap = { .last_cpu = -1 };

	if (!ctx)
		return -EINVAL;

	scoped_guard(mutex, &ctx->lock) {
		if (ctx->buf) {
			cpu_preserved_inval(ctx->buf);
			snap = *ctx->buf;
		} else if (ctx->has_snap) {
			snap = ctx->last_snap;
		}
	}

	return simple_read_from_buffer(ubuf, count, ppos, &snap, sizeof(snap));
}

static int oncore_test_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct oncore_test_ctx *ctx = file->private_data;
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long pfn;

	if (!ctx || size != PAGE_SIZE || vma->vm_pgoff != 0)
		return -EINVAL;

	guard(mutex)(&ctx->lock);
	if (!ctx->buf)
		return -ENXIO;

	pfn = virt_to_phys(ctx->buf) >> PAGE_SHIFT;
	vm_flags_set(vma, VM_IO | VM_DONTEXPAND | VM_DONTDUMP);
	return remap_pfn_range(vma, vma->vm_start, pfn, PAGE_SIZE,
			       vma->vm_page_prot);
}

static const struct file_operations oncore_test_fops = {
	.owner		= THIS_MODULE,
	.open		= oncore_test_open,
	.release	= oncore_test_release,
	.read		= oncore_test_read,
	.mmap		= oncore_test_mmap,
	.llseek		= default_llseek,
};

static bool oncore_test_can_preserve(struct liveupdate_file_handler *handler,
				     struct file *file)
{
	return file && file->f_op == &oncore_test_fops;
}

static int oncore_test_preserve(struct liveupdate_file_op_args *args)
{
	struct oncore_test_ctx *ctx = args->file->private_data;
	struct oncore_test_state *state;
	struct oncore_test_buf *buf;
	struct oncore_job *job;
	int ret;

	if (!ctx)
		return -EINVAL;

	guard(mutex)(&ctx->lock);
	if (ctx->job || ctx->state || ctx->buf)
		return -EBUSY;

	job = oncore_session_submit_job(args->session, oncore_test_job_run,
					NULL);
	if (IS_ERR(job))
		return PTR_ERR(job);
	if (!job)
		return -ENOENT;

	state = kho_alloc_preserve(PAGE_SIZE);
	if (IS_ERR(state)) {
		oncore_session_cancel_job(args->session, job);
		return PTR_ERR(state);
	}

	buf = kho_alloc_preserve(PAGE_SIZE);
	if (IS_ERR(buf)) {
		cpu_preserved_free_kho(state, false);
		oncore_session_cancel_job(args->session, job);
		return PTR_ERR(buf);
	}

	buf->magic = ONCORE_TEST_MAGIC;
	buf->last_cpu = -1;
	state->buf_pa = virt_to_phys(buf);
	state->buf_va = (u64)(uintptr_t)buf;
	cpu_preserved_clean_sz(buf, PAGE_SIZE);
	cpu_preserved_clean_sz(state, PAGE_SIZE);

	ret = oncore_session_map_buffer(oncore_job_session(job), buf, PAGE_SIZE);
	if (ret) {
		cpu_preserved_free_kho(buf, false);
		cpu_preserved_free_kho(state, false);
		oncore_session_cancel_job(args->session, job);
		return ret;
	}

	oncore_job_set_data(job, state);
	ret = oncore_session_activate_job(args->session, job);
	if (ret) {
		oncore_session_unmap_buffer(oncore_job_session(job), buf,
					    PAGE_SIZE);
		cpu_preserved_free_kho(buf, false);
		cpu_preserved_free_kho(state, false);
		oncore_session_cancel_job(args->session, job);
		return ret;
	}

	ctx->state = state;
	ctx->buf = buf;
	ctx->job = job;
	ctx->has_snap = false;
	args->serialized_data = virt_to_phys(state);
	return 0;
}

static void oncore_test_unpreserve(struct liveupdate_file_op_args *args)
{
	struct oncore_test_ctx *ctx = args->file ? args->file->private_data : NULL;
	struct oncore_test_state *state;
	struct oncore_test_buf *buf = NULL;
	struct oncore_job *job = NULL;
	int err = 0;

	if (!args->serialized_data)
		return;

	state = phys_to_virt(args->serialized_data);
	if (state->buf_pa)
		buf = phys_to_virt(state->buf_pa);

	if (ctx) {
		mutex_lock(&ctx->lock);
		job = ctx->job;
		ctx->job = NULL;
		ctx->state = NULL;
		ctx->buf = NULL;
		if (args->file && args->file->f_mapping)
			unmap_mapping_range(args->file->f_mapping, 0,
					    PAGE_SIZE, 1);
	}

	WRITE_ONCE(state->stop, 1);
	cpu_preserved_clean(state);

	if (job)
		err = oncore_session_cancel_job(args->session, job);

	if (buf) {
		cpu_preserved_inval(buf);
		if (ctx) {
			ctx->last_snap = *buf;
			ctx->has_snap = true;
		}
		if (!err)
			cpu_preserved_free_kho(buf, false);
	}
	if (ctx)
		mutex_unlock(&ctx->lock);

	if (!err)
		cpu_preserved_free_kho(state, false);
}

static int oncore_test_retrieve(struct liveupdate_file_op_args *args)
{
	struct oncore_test_state *state;
	struct oncore_test_buf *buf;
	struct oncore_test_ctx *ctx;
	struct file *file;

	if (!args->serialized_data)
		return -EINVAL;

	state = phys_to_virt(args->serialized_data);
	cpu_preserved_inval(state);
	if (!state->buf_pa)
		return -EINVAL;

	buf = phys_to_virt(state->buf_pa);
	cpu_preserved_inval(buf);
	if (READ_ONCE(buf->magic) != ONCORE_TEST_MAGIC)
		return -EINVAL;

	ctx = kzalloc_obj(*ctx);
	if (!ctx)
		return -ENOMEM;

	mutex_init(&ctx->lock);
	ctx->state = state;
	ctx->buf = buf;

	file = anon_inode_getfile("[oncore_test]", &oncore_test_fops, ctx,
				  O_RDWR);
	if (IS_ERR(file)) {
		mutex_destroy(&ctx->lock);
		kfree(ctx);
		return PTR_ERR(file);
	}
	file->f_mode |= FMODE_LSEEK | FMODE_PREAD;

	args->file = file;
	return 0;
}

static bool oncore_test_poll_stopped(struct oncore_test_state *state)
{
	bool any_running = false;
	int cpu;

	cpu_preserved_inval(state);
	if (READ_ONCE(state->stopped))
		return true;

	for_each_cpu(cpu, cpu_get_preserved_mask()) {
		if (cpu_preserved_state(cpu) == CPU_PRESERVED_WORKLOAD) {
			arch_cpu_preserved_kick(cpu);
			any_running = true;
		}
	}

	return !any_running;
}

static int oncore_test_stop_job(struct oncore_test_state *state)
{
	bool stopped;

	WRITE_ONCE(state->stop, 1);
	cpu_preserved_clean(state);

	return read_poll_timeout(oncore_test_poll_stopped, stopped, stopped,
				 ONCORE_TEST_STOP_STEP_US,
				 ONCORE_TEST_STOP_TIMEOUT_US, false, state);
}

static void oncore_test_finish(struct liveupdate_file_op_args *args)
{
	struct oncore_test_ctx *ctx = args->file ? args->file->private_data : NULL;
	struct oncore_test_state *state;
	struct oncore_test_buf *buf = NULL;
	int err;

	if (!args->serialized_data)
		return;

	state = phys_to_virt(args->serialized_data);
	cpu_preserved_inval(state);
	if (state->buf_pa)
		buf = phys_to_virt(state->buf_pa);

	err = oncore_test_stop_job(state);

	if (ctx) {
		scoped_guard(mutex, &ctx->lock) {
			if (buf) {
				cpu_preserved_inval(buf);
				ctx->last_snap = *buf;
				ctx->has_snap = true;
			}
			ctx->buf = NULL;
			ctx->state = NULL;
			if (args->file && args->file->f_mapping)
				unmap_mapping_range(args->file->f_mapping, 0,
						    PAGE_SIZE, 1);
		}
	}

	if (WARN_ON_ONCE(err))
		return;

	if (buf)
		cpu_preserved_free_kho(buf, true);
	cpu_preserved_free_kho(state, true);
}

static const struct liveupdate_file_ops oncore_test_luo_file_ops = {
	.can_preserve	= oncore_test_can_preserve,
	.preserve	= oncore_test_preserve,
	.unpreserve	= oncore_test_unpreserve,
	.retrieve	= oncore_test_retrieve,
	.finish		= oncore_test_finish,
	.owner		= THIS_MODULE,
};

static struct liveupdate_file_handler oncore_test_luo_handler = {
	.ops		= &oncore_test_luo_file_ops,
	.compatible	= ONCORE_TEST_LUO_COMPATIBLE,
};

static int __init oncore_test_init(void)
{
	int err;

	err = liveupdate_register_file_handler(&oncore_test_luo_handler);
	if (err && err != -EOPNOTSUPP) {
		pr_err("Failed to register LUO file handler: %pe\n",
		       ERR_PTR(err));
		return err;
	}

	debugfs_create_file_unsafe("oncore_test", 0600, NULL, NULL,
				   &oncore_test_fops);
	return 0;
}
late_initcall(oncore_test_init);
