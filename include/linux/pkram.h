/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PKRAM_H
#define _LINUX_PKRAM_H

#include <linux/gfp.h>
#include <linux/types.h>
#include <linux/mm_types.h>

struct pkram_node;
struct pkram_obj;

/**
 * enum pkram_data_flags - definition of data types contained in a pkram obj
 * @PKRAM_DATA_none: No data types configured
 */
enum pkram_data_flags {
	PKRAM_DATA_none		= 0x0,  /* No data types configured */
};

struct pkram_stream {
	gfp_t gfp_mask;
	struct pkram_node *node;
	struct pkram_obj *obj;
};

struct pkram_access;

#define PKRAM_NAME_MAX		256	/* including nul */

int pkram_prepare_save(struct pkram_stream *ps, const char *name,
		       gfp_t gfp_mask);
int pkram_prepare_save_obj(struct pkram_stream *ps, enum pkram_data_flags flags);

void pkram_finish_save(struct pkram_stream *ps);
void pkram_finish_save_obj(struct pkram_stream *ps);
void pkram_discard_save(struct pkram_stream *ps);

int pkram_prepare_load(struct pkram_stream *ps, const char *name);
int pkram_prepare_load_obj(struct pkram_stream *ps);

void pkram_finish_load(struct pkram_stream *ps);
void pkram_finish_load_obj(struct pkram_stream *ps);

#define PKRAM_ACCESS(name, stream, type)			\
	struct pkram_access name

void pkram_finish_access(struct pkram_access *pa, bool status_ok);

int pkram_save_file_page(struct pkram_access *pa, struct page *page);
struct page *pkram_load_file_page(struct pkram_access *pa, unsigned long *index);

ssize_t pkram_write(struct pkram_access *pa, const void *buf, size_t count);
size_t pkram_read(struct pkram_access *pa, void *buf, size_t count);

#endif /* _LINUX_PKRAM_H */
