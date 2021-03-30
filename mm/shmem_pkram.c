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

static int save_file_content(struct pkram_stream *ps, struct address_space *mapping)
{
	PKRAM_ACCESS(pa, ps, pages);
	struct pagevec pvec;
	unsigned long start, end;
	int err = 0;
	int i;

	start = 0;
	end = DIV_ROUND_UP(i_size_read(mapping->host), PAGE_SIZE);
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
			err = save_page(page, &pa);
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

	pkram_finish_access(&pa, err == 0);
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

static int load_file_content(struct pkram_stream *ps, struct address_space *mapping)
{
	PKRAM_ACCESS(pa, ps, pages);
	unsigned long index;
	struct page *page;
	int err = 0;

	do {
		page = pkram_load_file_page(&pa, &index);
		if (!page)
			break;

		err = shmem_insert_page(current->mm, mapping->host, index, page);
		put_page(page);
		cond_resched();
	} while (!err);

	pkram_finish_access(&pa, err == 0);
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

	err = load_file_content(ps, inode->i_mapping);
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
