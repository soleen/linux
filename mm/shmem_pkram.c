// SPDX-License-Identifier: GPL-2.0
#include <linux/crash_dump.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/pkram.h>
#include <linux/seq_file.h>
#include <linux/shmem_fs.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/types.h>
#include <linux/uaccess.h>

struct file_header {
	__u32	mode;
	kuid_t	uid;
	kgid_t	gid;
	__u32	namelen;
	__u64	size;
	__u64	atime;
	__u64	mtime;
	__u64	ctime;
};

int shmem_parse_pkram(const char *str, struct shmem_pkram_info **pkram)
{
	struct shmem_pkram_info *new;
	size_t len;

	len = strlen(str);
	if (!len || len >= SHMEM_PKRAM_NAME_MAX)
		return 1;
	new = kzalloc(sizeof(*new), GFP_KERNEL);
	if (!new)
		return 1;
	strcpy(new->name, str);
	*pkram = new;
	return 0;
}

void shmem_show_pkram(struct seq_file *seq, struct shmem_pkram_info *pkram, bool preserve)
{
	if (pkram) {
		seq_printf(seq, ",pkram=%s", pkram->name);
		seq_printf(seq, ",%s", preserve ? "preserve" : "nopreserve");
	}
}

static int shmem_pkram_name(char *buf, size_t bufsize,
			   struct shmem_sb_info *sbinfo)
{
	if (snprintf(buf, bufsize, "shmem-%s", sbinfo->pkram->name) >= bufsize)
		return -ENAMETOOLONG;
	return 0;
}

static int save_page(struct page *page, struct pkram_access *pa)
{
	int err = 0;

	if (page)
		err = pkram_save_file_page(pa, page);

	return err;
}

static int save_file_content_range(struct pkram_access *pa,
				   struct address_space *mapping,
				   unsigned long start, unsigned long end)
{
	struct pagevec pvec;
	int err = 0;
	int i;

	pagevec_init(&pvec);
	for ( ; ; ) {
		pvec.nr = find_get_pages_range(mapping, &start, end,
					PAGEVEC_SIZE, pvec.pages);
		if (!pvec.nr)
			break;
		for (i = 0; i < pagevec_count(&pvec); ) {
			struct page *page = pvec.pages[i];

			lock_page(page);
			BUG_ON(page->mapping != mapping);
			err = save_page(page, pa);
			if (PageCompound(page)) {
				start = page->index + compound_nr(page);
				i += compound_nr(page);
			} else {
				i++;
			}

			unlock_page(page);
			if (err)
				break;
		}
		pagevec_release(&pvec);
		if (err || (start > end))
			break;
		cond_resched();
	}

	return err;
}

struct shmem_pkram_arg {
	int *error;
	struct pkram_stream *ps;
	struct address_space *mapping;
	struct mm_struct *mm;
	atomic64_t next;
};

unsigned long shmem_pkram_max_index_range = 512 * 512;

static int get_save_range(unsigned long max, atomic64_t *next, unsigned long *start, unsigned long *end)
{
	unsigned long index;
 
	index = atomic64_fetch_add(shmem_pkram_max_index_range, next);
	if (index >= max)
		return -ENODATA;
 
	*start = index;
	*end = index + shmem_pkram_max_index_range - 1;
 
	return 0;
}

/* Completion tracking for save_file_content_thr() threads */
static atomic_t pkram_save_n_undone;
static DECLARE_COMPLETION(pkram_save_all_done_comp);

static inline void pkram_save_report_one_done(void)
{
	if (atomic_dec_and_test(&pkram_save_n_undone))
		complete(&pkram_save_all_done_comp);
}

static int do_save_file_content(struct pkram_stream *ps,
				struct address_space *mapping,
				atomic64_t *next)
{
	PKRAM_ACCESS(pa, ps, pages);
	unsigned long start, end, max;
	int ret;
 
	max = DIV_ROUND_UP(i_size_read(mapping->host), PAGE_SIZE);
 
	do {
		ret = get_save_range(max, next, &start, &end);
		if (!ret)
			ret = save_file_content_range(&pa, mapping, start, end);
	} while (!ret);
 
	if (ret == -ENODATA)
		ret = 0;
 
	pkram_finish_access(&pa, ret == 0);
	return ret;
}

static int save_file_content_thr(void *data)
{
	struct shmem_pkram_arg *arg = data;
	int ret;

	ret = do_save_file_content(arg->ps, arg->mapping, &arg->next);
	if (ret && !*arg->error)
		*arg->error = ret;

	pkram_save_report_one_done();
	return 0;
}

static int shmem_pkram_max_threads = 16;

static int save_file_content(struct pkram_stream *ps, struct address_space *mapping)
 {
	int err = 0;
	struct shmem_pkram_arg arg = { &err, ps, mapping, NULL, ATOMIC64_INIT(0) };
	unsigned int thr, nr_threads;

	nr_threads = num_online_cpus() - 1;
	nr_threads = clamp_val(shmem_pkram_max_threads, 1, nr_threads);

	if (nr_threads == 1)
		return do_save_file_content(arg.ps, arg.mapping, &arg.next);

	atomic_set(&pkram_save_n_undone, nr_threads);
	for (thr = 0; thr < nr_threads; thr++)
		kthread_run(save_file_content_thr, &arg, "pkram_save%d", thr);

	wait_for_completion(&pkram_save_all_done_comp);

	return err;
}

static int save_file(struct dentry *dentry, struct pkram_stream *ps)
{
	PKRAM_ACCESS(pa_bytes, ps, bytes);
	struct inode *inode = dentry->d_inode;
	umode_t mode = inode->i_mode;
	struct file_header hdr;
	ssize_t ret;
	int err;

	if (WARN_ON_ONCE(!S_ISREG(mode)))
		return -EINVAL;
	if (WARN_ON_ONCE(inode->i_nlink > 1))
		return -EINVAL;

	hdr.mode = mode;
	hdr.uid = inode->i_uid;
	hdr.gid = inode->i_gid;
	hdr.namelen = dentry->d_name.len;
	hdr.size = i_size_read(inode);
	hdr.atime = timespec64_to_ns(&inode->i_atime);
	hdr.mtime = timespec64_to_ns(&inode->i_mtime);
	hdr.ctime = timespec64_to_ns(&inode->i_ctime);


	ret = pkram_write(&pa_bytes, &hdr, sizeof(hdr));
	if (ret < 0) {
		err = ret;
		goto out;
	}
	ret = pkram_write(&pa_bytes, dentry->d_name.name, dentry->d_name.len);
	if (ret < 0) {
		err = ret;
		goto out;
	}

	err = save_file_content(ps, inode->i_mapping);
out:
	pkram_finish_access(&pa_bytes, err == 0);
	return err;
}

static int save_tree(struct super_block *sb, struct pkram_stream *ps)
{
	struct dentry *dentry, *root = sb->s_root;
	int err = 0;

	inode_lock(d_inode(root));
	spin_lock(&root->d_lock);
	list_for_each_entry(dentry, &root->d_subdirs, d_child) {
		if (d_unhashed(dentry) || !dentry->d_inode)
			continue;
		dget(dentry);
		spin_unlock(&root->d_lock);

		err = pkram_prepare_save_obj(ps, PKRAM_DATA_pages|PKRAM_DATA_bytes);
		if (!err)
			err = save_file(dentry, ps);
		if (!err)
			pkram_finish_save_obj(ps);
		spin_lock(&root->d_lock);
		dput(dentry);
		if (err)
			break;
	}
	spin_unlock(&root->d_lock);
	inode_unlock(d_inode(root));

	return err;
}

int shmem_save_pkram(struct super_block *sb)
{
	struct shmem_sb_info *sbinfo = sb->s_fs_info;
	struct pkram_stream ps;
	char *buf;
	int err = -ENOMEM;

	if (!sbinfo || !sbinfo->pkram || is_kdump_kernel())
		return 0;

	buf = (void *)__get_free_page(GFP_KERNEL);
	if (!buf)
		goto out;

	err = shmem_pkram_name(buf, PAGE_SIZE, sbinfo);
	if (!err)
		err = pkram_prepare_save(&ps, buf, GFP_KERNEL);
	if (err)
		goto out_free_buf;

	err = save_tree(sb, &ps);
	if (err)
		goto out_discard_save;

	pkram_finish_save(&ps);
	goto out_free_buf;

out_discard_save:
	pkram_discard_save(&ps);
out_free_buf:
	free_page((unsigned long)buf);
out:
	if (err)
		pr_err("SHMEM: PKRAM save failed: %d\n", err);

	return err;
}

/* Completion tracking for load_file_content_thr() threads */
static atomic_t pkram_load_n_undone;
static DECLARE_COMPLETION(pkram_load_all_done_comp);

static inline void pkram_load_report_one_done(void)
{
	if (atomic_dec_and_test(&pkram_load_n_undone))
		complete(&pkram_load_all_done_comp);
}

static int do_load_file_content(struct pkram_stream *ps, struct address_space *mapping, struct mm_struct *mm)
{
	PKRAM_ACCESS(pa, ps, pages);
	struct page **pages;
	unsigned int nr_pages;
	unsigned long index;
	int i, err;

	pages = kzalloc(PKRAM_PAGES_BUFSIZE, GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	do {
		err = pkram_load_file_pages(&pa, pages, &nr_pages, &index);
		if (err) {
			if (err == -ENODATA)
				err = 0;
			break;
		}

		err = shmem_insert_pages(mm, mapping->host, index, pages, nr_pages);

		for (i = 0; i < nr_pages; i++)
			put_page(pages[i]);
		cond_resched();
	} while (!err);

	kfree(pages);
	pkram_finish_access(&pa, err == 0);
	return err;
}

static int load_file_content_thr(void *data)
{
	struct shmem_pkram_arg *arg = data;
	int ret;

	ret = do_load_file_content(arg->ps, arg->mapping, arg->mm);
	if (ret && !*arg->error)
		*arg->error = ret;

	pkram_load_report_one_done();
	return 0;
}

static int load_file_content(struct pkram_stream *ps, struct address_space *mapping, struct mm_struct *mm)
{
	int err = 0;
	struct shmem_pkram_arg arg = { &err, ps, mapping, mm };
	unsigned int thr, nr_threads;

	nr_threads = num_online_cpus() - 1;
	nr_threads = clamp_val(shmem_pkram_max_threads, 1, nr_threads);

	if (nr_threads == 1)
		return do_load_file_content(ps, mapping, mm);

	atomic_set(&pkram_load_n_undone, nr_threads);
	for (thr = 0; thr < nr_threads; thr++)
		kthread_run(load_file_content_thr, &arg, "pkram_load%d", thr);

	wait_for_completion(&pkram_load_all_done_comp);

	return err;
}

static int load_file(struct dentry *parent, struct pkram_stream *ps,
		     char *buf, size_t bufsize)
{
	PKRAM_ACCESS(pa_bytes, ps, bytes);
	struct dentry *dentry;
	struct inode *inode;
	struct file_header hdr;
	size_t ret;
	umode_t mode;
	int namelen;
	int err = -EINVAL;

	ret = pkram_read(&pa_bytes, &hdr, sizeof(hdr));
	if (ret != sizeof(hdr))
		goto out;

	mode = hdr.mode;
	namelen = hdr.namelen;
	if (!S_ISREG(mode) || namelen > bufsize)
		goto out;
	if (pkram_read(&pa_bytes, buf, namelen) != namelen)
		goto out;

	inode_lock_nested(d_inode(parent), I_MUTEX_PARENT);

	dentry = lookup_one_len(buf, parent, namelen);
	if (IS_ERR(dentry)) {
		err = PTR_ERR(dentry);
		goto out_unlock;
	}

	err = vfs_create(&init_user_ns, parent->d_inode, dentry, mode, NULL);
	dput(dentry); /* on success shmem pinned it */
	if (err)
		goto out_unlock;

	inode = dentry->d_inode;
	inode->i_mode = mode;
	inode->i_uid = hdr.uid;
	inode->i_gid = hdr.gid;
	inode->i_atime = ns_to_timespec64(hdr.atime);
	inode->i_mtime = ns_to_timespec64(hdr.mtime);
	inode->i_ctime = ns_to_timespec64(hdr.ctime);
	i_size_write(inode, hdr.size);

	err = load_file_content(ps, inode->i_mapping, current->mm);
out_unlock:
	inode_unlock(d_inode(parent));
out:
	pkram_finish_access(&pa_bytes, err == 0);
	return err;
}

static int load_tree(struct super_block *sb, struct pkram_stream *ps,
		     char *buf, size_t bufsize)
{
	int err;

	do {
		err = pkram_prepare_load_obj(ps);
		if (err) {
			if (err == -ENODATA)
				err = 0;
			break;
		}
		err = load_file(sb->s_root, ps, buf, PAGE_SIZE);
		pkram_finish_load_obj(ps);
	} while (!err);

	return err;
}

void shmem_load_pkram(struct super_block *sb)
{
	struct shmem_sb_info *sbinfo = sb->s_fs_info;
	struct pkram_stream ps;
	char *buf;
	int err = -ENOMEM;

	if (!sbinfo->pkram)
		return;

	buf = (void *)__get_free_page(GFP_KERNEL);
	if (!buf)
		goto out;

	err = shmem_pkram_name(buf, PAGE_SIZE, sbinfo);
	if (!err)
		err = pkram_prepare_load(&ps, buf);
	if (err) {
		if (err == -ENOENT)
			err = 0;
		goto out_free_buf;
	}

	err = load_tree(sb, &ps, buf, PAGE_SIZE);

	pkram_finish_load(&ps);
out_free_buf:
	free_page((unsigned long)buf);
out:
	if (err)
		pr_err("SHMEM: PKRAM load failed: %d\n", err);
}

int shmem_release_pkram(struct super_block *sb)
{
	struct shmem_sb_info *sbinfo = sb->s_fs_info;
	struct pkram_stream ps;
	char *buf;
	int err = -ENOMEM;

	if (!sbinfo->pkram)
		return 0;

	buf = (void *)__get_free_page(GFP_KERNEL);
	if (!buf)
		goto out;

	err = shmem_pkram_name(buf, PAGE_SIZE, sbinfo);
	if (!err)
		err = pkram_prepare_load(&ps, buf);
	if (err) {
		if (err == -ENOENT)
			err = 0;
		goto out_free_buf;
	}

	pkram_finish_load(&ps);
out_free_buf:
	free_page((unsigned long)buf);
out:
	if (err)
		pr_err("SHMEM: PKRAM load failed: %d\n", err);

	return err;
}
