/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PKRAM_H
#define _LINUX_PKRAM_H

#include <linux/gfp.h>
#include <linux/types.h>
#include <linux/mm_types.h>

struct pkram_node;
struct pkram_obj;
struct pkram_link;

/**
 * enum pkram_data_flags - definition of data types contained in a pkram obj
 * @PKRAM_DATA_none: No data types configured
 * @PKRAM_DATA_pages: obj contains file page data
 * @PKRAM_DATA_bytes: obj contains byte data
 */
enum pkram_data_flags {
	PKRAM_DATA_none		= 0x0,	/* No data types configured */
	PKRAM_DATA_pages	= 0x1,	/* Contains file page data */
	PKRAM_DATA_bytes	= 0x2,	/* Contains byte data */
};

struct pkram_data_stream {
	/* List of link pages to add/remove from */
	__u64 *head_link_pfnp;
	__u64 *tail_link_pfnp;

	struct pkram_link *link;	/* current link */
	unsigned int entry_idx;		/* next entry in link */
};

struct pkram_stream {
	gfp_t gfp_mask;
	struct pkram_node *node;
	struct pkram_obj *obj;

	__u64 *pages_head_link_pfnp;
	__u64 *pages_tail_link_pfnp;

	__u64 *bytes_head_link_pfnp;
	__u64 *bytes_tail_link_pfnp;
};

struct pkram_pages_access {
	unsigned long next_index;
};

struct pkram_bytes_access {
	struct page *data_page;		/* current page */
	unsigned int data_offset;	/* offset into current page */
};

struct pkram_access {
	enum pkram_data_flags dtype;
	struct pkram_stream *ps;
	struct pkram_data_stream pds;

	struct pkram_pages_access pages;
	struct pkram_bytes_access bytes;
};

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

#define PKRAM_PDS_INIT(name, stream, type) {			\
	.head_link_pfnp=(stream)->type##_head_link_pfnp,	\
	.tail_link_pfnp=(stream)->type##_tail_link_pfnp,	\
	}

#define PKRAM_ACCESS_INIT(name, stream, type) {			\
	.dtype = PKRAM_DATA_##type,				\
	.ps = (stream),						\
	.pds = PKRAM_PDS_INIT(name, stream, type),		\
	}

#define PKRAM_ACCESS(name, stream, type)			\
	struct pkram_access name = PKRAM_ACCESS_INIT(name, stream, type)

void pkram_finish_access(struct pkram_access *pa, bool status_ok);

int pkram_save_file_page(struct pkram_access *pa, struct page *page);
struct page *pkram_load_file_page(struct pkram_access *pa, unsigned long *index);

ssize_t pkram_write(struct pkram_access *pa, const void *buf, size_t count);
size_t pkram_read(struct pkram_access *pa, void *buf, size_t count);

#ifdef CONFIG_PKRAM
extern unsigned long pkram_reserved_pages;
void pkram_reserve(void);
void pkram_cleanup(void);
void pkram_ban_region(unsigned long start, unsigned long end);
int pkram_has_preserved_pages(unsigned long start, unsigned long end);
#else
#define pkram_reserved_pages 0UL
static inline void pkram_reserve(void) { }
static inline void pkram_cleanup(void) { }
static inline void pkram_ban_region(unsigned long start, unsigned long end) { }
static inline int pkram_has_preserved_pages(unsigned long start, unsigned long end) { return 0; }
#endif

#endif /* _LINUX_PKRAM_H */
