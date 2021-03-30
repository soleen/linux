// SPDX-License-Identifier: GPL-2.0
#include <linux/err.h>
#include <linux/gfp.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/pkram.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/types.h>

#include "internal.h"


/*
 * Represents a reference to a data page saved to PKRAM.
 */
typedef __u64 pkram_entry_t;

#define PKRAM_ENTRY_FLAGS_SHIFT	0x5
#define PKRAM_ENTRY_FLAGS_MASK	0x7f

/*
 * Keeps references to data pages saved to PKRAM.
 * The structure occupies a memory page.
 */
struct pkram_link {
	__u64	link_pfn;	/* points to the next link of the object */
	__u64	index;		/* mapping index of first pkram_entry_t */

	/*
	 * the array occupies the rest of the link page; if the link is not
	 * full, the rest of the array must be filled with zeros
	 */
	pkram_entry_t entry[0];
};

#define PKRAM_LINK_ENTRIES_MAX \
	((PAGE_SIZE-sizeof(struct pkram_link))/sizeof(pkram_entry_t))

struct pkram_obj {
	__u64	pages_head_link_pfn;	/* the first pages link of the object */
	__u64	pages_tail_link_pfn;	/* the last pages link of the object */
	__u64	obj_pfn;	/* points to the next object in the list */
};

/*
 * Preserved memory is divided into nodes that can be saved or loaded
 * independently of each other. The nodes are identified by unique name
 * strings.
 *
 * References to data pages saved to a preserved memory node are kept in a
 * singly-linked list of PKRAM link structures (see above), the node has a
 * pointer to the head of.
 *
 * The structure occupies a memory page.
 */
struct pkram_node {
	__u32	flags;
	__u64	obj_pfn;	/* points to the first obj of the node */

	__u8	name[PKRAM_NAME_MAX];
};

#define PKRAM_SAVE		1
#define PKRAM_LOAD		2
#define PKRAM_ACCMODE_MASK	3

static LIST_HEAD(pkram_nodes);			/* linked through page::lru */
static DEFINE_MUTEX(pkram_mutex);		/* serializes open/close */

static inline struct page *pkram_alloc_page(gfp_t gfp_mask)
{
	return alloc_page(gfp_mask);
}

static inline void pkram_free_page(void *addr)
{
	free_page((unsigned long)addr);
}

static inline void pkram_insert_node(struct pkram_node *node)
{
	list_add(&virt_to_page(node)->lru, &pkram_nodes);
}

static inline void pkram_delete_node(struct pkram_node *node)
{
	list_del(&virt_to_page(node)->lru);
}

static struct pkram_node *pkram_find_node(const char *name)
{
	struct page *page;
	struct pkram_node *node;

	list_for_each_entry(page, &pkram_nodes, lru) {
		node = page_address(page);
		if (strcmp(node->name, name) == 0)
			return node;
	}
	return NULL;
}

static void pkram_truncate_link(struct pkram_link *link)
{
	struct page *page;
	pkram_entry_t p;
	int i;

	for (i = 0; i < PKRAM_LINK_ENTRIES_MAX; i++) {
		p = link->entry[i];
		if (!p)
			continue;
		page = pfn_to_page(PHYS_PFN(p));
		put_page(page);
	}
}

static void pkram_truncate_links(unsigned long link_pfn)
{
	struct pkram_link *link;

	while (link_pfn) {
		link = pfn_to_kaddr(link_pfn);
		pkram_truncate_link(link);
		link_pfn = link->link_pfn;
		pkram_free_page(link);
		cond_resched();
	}
}

static void pkram_truncate_obj(struct pkram_obj *obj)
{
	pkram_truncate_links(obj->pages_head_link_pfn);
	obj->pages_head_link_pfn = 0;
	obj->pages_tail_link_pfn = 0;
}

static void pkram_truncate_node(struct pkram_node *node)
{
	unsigned long obj_pfn;
	struct pkram_obj *obj;

	obj_pfn = node->obj_pfn;
	while (obj_pfn) {
		obj = pfn_to_kaddr(obj_pfn);
		pkram_truncate_obj(obj);
		obj_pfn = obj->obj_pfn;
		pkram_free_page(obj);
		cond_resched();
	}
	node->obj_pfn = 0;
}

static void pkram_add_link(struct pkram_link *link, struct pkram_data_stream *pds)
{
	__u64 link_pfn = page_to_pfn(virt_to_page(link));

	if (!*pds->head_link_pfnp) {
		*pds->head_link_pfnp = link_pfn;
		*pds->tail_link_pfnp = link_pfn;
	} else {
		struct pkram_link *tail = pfn_to_kaddr(*pds->tail_link_pfnp);

		tail->link_pfn = link_pfn;
		*pds->tail_link_pfnp = link_pfn;
	}
}

static struct pkram_link *pkram_remove_link(struct pkram_data_stream *pds)
{
	struct pkram_link *link;

	if (!*pds->head_link_pfnp)
		return NULL;

	link = pfn_to_kaddr(*pds->head_link_pfnp);
	*pds->head_link_pfnp = link->link_pfn;
	if (!*pds->head_link_pfnp)
		*pds->tail_link_pfnp = 0;
	else
		link->link_pfn = 0;

	return link;
}

static struct pkram_link *pkram_new_link(struct pkram_data_stream *pds, gfp_t gfp_mask)
{
	struct pkram_link *link;
	struct page *link_page;

	link_page = pkram_alloc_page((gfp_mask & GFP_RECLAIM_MASK) |
				    __GFP_ZERO);
	if (!link_page)
		return NULL;

	link = page_address(link_page);
	pkram_add_link(link, pds);
	pds->link = link;
	pds->entry_idx = 0;

	return link;
}

static void pkram_add_link_entry(struct pkram_data_stream *pds, struct page *page)
{
	struct pkram_link *link = pds->link;
	pkram_entry_t p;
	short flags = 0;

	p = page_to_phys(page);
	p |= ((flags & PKRAM_ENTRY_FLAGS_MASK) << PKRAM_ENTRY_FLAGS_SHIFT);
	link->entry[pds->entry_idx] = p;
	pds->entry_idx++;
}

static int pkram_next_link(struct pkram_data_stream *pds, struct pkram_link **linkp)
{
	struct pkram_link *link;

	link = pkram_remove_link(pds);
	if (!link)
		return -ENODATA;

	pds->link = link;
	pds->entry_idx = 0;
	*linkp = link;

	return 0;
}

static void pkram_stream_init(struct pkram_stream *ps,
			     struct pkram_node *node, gfp_t gfp_mask)
{
	memset(ps, 0, sizeof(*ps));
	ps->gfp_mask = gfp_mask;
	ps->node = node;
}

/**
 * Create a preserved memory node with name @name and initialize stream @ps
 * for saving data to it.
 *
 * @gfp_mask specifies the memory allocation mask to be used when saving data.
 *
 * Error values:
 *	%ENAMETOOLONG: name len >= PKRAM_NAME_MAX
 *	%ENOMEM: insufficient memory available
 *	%EEXIST: node with specified name already exists
 *
 * Returns 0 on success, -errno on failure.
 *
 * After the save has finished, pkram_finish_save() (or pkram_discard_save() in
 * case of failure) is to be called.
 */
int pkram_prepare_save(struct pkram_stream *ps, const char *name, gfp_t gfp_mask)
{
	struct page *page;
	struct pkram_node *node;
	int err = 0;

	if (strlen(name) >= PKRAM_NAME_MAX)
		return -ENAMETOOLONG;

	page = pkram_alloc_page(gfp_mask | __GFP_ZERO);
	if (!page)
		return -ENOMEM;
	node = page_address(page);

	node->flags = PKRAM_SAVE;
	strcpy(node->name, name);

	mutex_lock(&pkram_mutex);
	if (!pkram_find_node(name))
		pkram_insert_node(node);
	else
		err = -EEXIST;
	mutex_unlock(&pkram_mutex);
	if (err) {
		pkram_free_page(node);
		return err;
	}

	pkram_stream_init(ps, node, gfp_mask);
	return 0;
}

/**
 * Create a preserved memory object and initialize stream @ps for saving data
 * to it.
 *
 * Returns 0 on success, -errno on failure.
 *
 * Error values:
 *	%ENOMEM: insufficient memory available
 *
 * After the save has finished, pkram_finish_save_obj() (or pkram_discard_save()
 * in case of failure) is to be called.
 */
int pkram_prepare_save_obj(struct pkram_stream *ps, enum pkram_data_flags flags)
{
	struct pkram_node *node = ps->node;
	struct pkram_obj *obj;
	struct page *page;

	BUG_ON((node->flags & PKRAM_ACCMODE_MASK) != PKRAM_SAVE);

	if (flags & ~PKRAM_DATA_pages)
		return -EINVAL;

	page = pkram_alloc_page(ps->gfp_mask | __GFP_ZERO);
	if (!page)
		return -ENOMEM;
	obj = page_address(page);

	if (node->obj_pfn)
		obj->obj_pfn = node->obj_pfn;
	node->obj_pfn = page_to_pfn(page);

	if (flags & PKRAM_DATA_pages) {
		ps->pages_head_link_pfnp = &obj->pages_head_link_pfn;
		ps->pages_tail_link_pfnp = &obj->pages_tail_link_pfn;
	}
	ps->obj = obj;
	return 0;
}

/**
 * Commit the object started with pkram_prepare_save_obj() to preserved memory.
 */
void pkram_finish_save_obj(struct pkram_stream *ps)
{
	struct pkram_node *node = ps->node;

	BUG_ON((node->flags & PKRAM_ACCMODE_MASK) != PKRAM_SAVE);
}

/**
 * Commit the save to preserved memory started with pkram_prepare_save().
 * After the call, the stream may not be used any more.
 */
void pkram_finish_save(struct pkram_stream *ps)
{
	struct pkram_node *node = ps->node;

	BUG_ON((node->flags & PKRAM_ACCMODE_MASK) != PKRAM_SAVE);

	smp_wmb();
	node->flags &= ~PKRAM_ACCMODE_MASK;
}

/**
 * Cancel the save to preserved memory started with pkram_prepare_save() and
 * destroy the corresponding preserved memory node freeing any data already
 * saved to it.
 */
void pkram_discard_save(struct pkram_stream *ps)
{
	struct pkram_node *node = ps->node;

	BUG_ON((node->flags & PKRAM_ACCMODE_MASK) != PKRAM_SAVE);

	mutex_lock(&pkram_mutex);
	pkram_delete_node(node);
	mutex_unlock(&pkram_mutex);

	pkram_truncate_node(node);
	pkram_free_page(node);
}

/**
 * Remove the preserved memory node with name @name and initialize stream @ps
 * for loading data from it.
 *
 * Returns 0 on success, -errno on failure.
 *
 * Error values:
 *	%ENOENT: node with specified name does not exist
 *	%EBUSY: save to required node has not finished yet
 *
 * After the load has finished, pkram_finish_load() is to be called.
 */
int pkram_prepare_load(struct pkram_stream *ps, const char *name)
{
	struct pkram_node *node;
	int err = 0;

	mutex_lock(&pkram_mutex);
	node = pkram_find_node(name);
	if (!node) {
		err = -ENOENT;
		goto out_unlock;
	}
	if (node->flags & PKRAM_ACCMODE_MASK) {
		err = -EBUSY;
		goto out_unlock;
	}
	pkram_delete_node(node);
out_unlock:
	mutex_unlock(&pkram_mutex);
	if (err)
		return err;

	node->flags |= PKRAM_LOAD;
	pkram_stream_init(ps, node, 0);
	return 0;
}

/**
 * Remove the next preserved memory object from the stream @ps and
 * initialize stream @ps for loading data from it.
 *
 * Returns 0 on success, -errno on failure.
 *
 * Error values:
 *	%ENODATA: Stream @ps has no preserved memory objects
 *
 * After the load has finished, pkram_finish_load_obj() is to be called.
 */
int pkram_prepare_load_obj(struct pkram_stream *ps)
{
	struct pkram_node *node = ps->node;
	struct pkram_obj *obj;

	BUG_ON((node->flags & PKRAM_ACCMODE_MASK) != PKRAM_LOAD);

	if (!node->obj_pfn)
		return -ENODATA;

	obj = pfn_to_kaddr(node->obj_pfn);
	if (!obj->pages_head_link_pfn) {
		WARN_ON(1);
		return -EINVAL;
	}

	node->obj_pfn = obj->obj_pfn;

	if (obj->pages_head_link_pfn) {
		ps->pages_head_link_pfnp = &obj->pages_head_link_pfn;
		ps->pages_tail_link_pfnp = &obj->pages_tail_link_pfn;
	}
	ps->obj = obj;
	return 0;
}

/**
 * Finish the load of a preserved memory object started with
 * pkram_prepare_load_obj() freeing the object and any data that has not
 * been loaded from it.
 */
void pkram_finish_load_obj(struct pkram_stream *ps)
{
	struct pkram_node *node = ps->node;
	struct pkram_obj *obj = ps->obj;

	BUG_ON((node->flags & PKRAM_ACCMODE_MASK) != PKRAM_LOAD);

	pkram_truncate_obj(obj);
	pkram_free_page(obj);
}

/**
 * Finish the load from preserved memory started with pkram_prepare_load()
 * freeing the corresponding preserved memory node and any data that has
 * not been loaded from it.
 */
void pkram_finish_load(struct pkram_stream *ps)
{
	struct pkram_node *node = ps->node;

	BUG_ON((node->flags & PKRAM_ACCMODE_MASK) != PKRAM_LOAD);

	pkram_truncate_node(node);
	pkram_free_page(node);
}

/**
 * Finish the data access to or from the preserved memory node and object
 * associated with pkram stream access @pa.  The access must have been
 * initialized with PKRAM_ACCESS(). 
 */
void pkram_finish_access(struct pkram_access *pa, bool status_ok)
{
	if (status_ok)
		return;

	if (pa->ps->node->flags == PKRAM_SAVE)
		return;

	if (pa->pds.link)
		pkram_truncate_link(pa->pds.link);
}

/*
 * Add file page to a PKRAM obj allocating a new PKRAM link if necessary.
 */
static int __pkram_save_page(struct pkram_access *pa, struct page *page,
			     unsigned long index)
{
	struct pkram_data_stream *pds = &pa->pds;
	struct pkram_link *link = pds->link;

	if (!link || pds->entry_idx >= PKRAM_LINK_ENTRIES_MAX ||
	    index != pa->pages.next_index) {
		link = pkram_new_link(pds, pa->ps->gfp_mask);
		if (!link)
			return -ENOMEM;

		pa->pages.next_index = link->index = index;
	}

	get_page(page);

	pkram_add_link_entry(pds, page);

	pa->pages.next_index++;

	return 0;
}

/**
 * Save file page @page to the preserved memory node and object associated
 * with pkram stream access @pa. The stream must have been initialized with
 * pkram_prepare_save() and pkram_prepare_save_obj() and access initialized
 * with PKRAM_ACCESS().
 *
 * Returns 0 on success, -errno on failure.
 *
 * Error values:
 *	%ENOMEM: insufficient amount of memory available
 *
 * Saving a page to preserved memory is simply incrementing its refcount so
 * that it will not get freed after the last user puts it. That means it is
 * safe to use the page as usual after it has been saved.
 */
int pkram_save_file_page(struct pkram_access *pa, struct page *page)
{
	struct pkram_node *node = pa->ps->node;

	BUG_ON((node->flags & PKRAM_ACCMODE_MASK) != PKRAM_SAVE);

	BUG_ON(PageCompound(page));

	return __pkram_save_page(pa, page, page->index);
}

static struct page *__pkram_prep_load_page(pkram_entry_t p)
{
	struct page *page;
	short flags;

	flags = (p >> PKRAM_ENTRY_FLAGS_SHIFT) & PKRAM_ENTRY_FLAGS_MASK;
	page = pfn_to_page(PHYS_PFN(p));

	return page;
}

/*
 * Extract the next page from preserved memory freeing a PKRAM link if it
 * becomes empty.
 */
static struct page *__pkram_load_page(struct pkram_access *pa, unsigned long *index)
{
	struct pkram_data_stream *pds = &pa->pds;
	struct pkram_link *link = pds->link;
	struct page *page;
	pkram_entry_t p;
	int ret;

	if (!link) {
		ret = pkram_next_link(pds, &link);
		if (ret)
			return NULL;	// XXX return error value?

		if (index)
			pa->pages.next_index = link->index;
	}

	BUG_ON(pds->entry_idx >= PKRAM_LINK_ENTRIES_MAX);

	p = link->entry[pds->entry_idx];
	BUG_ON(!p);

	page = __pkram_prep_load_page(p);

	if (index) {
		*index = pa->pages.next_index;
		pa->pages.next_index++;
	}

	/* clear to avoid double free (see pkram_truncate_link()) */
	link->entry[pds->entry_idx] = 0;

	pds->entry_idx++;
	if (pds->entry_idx >= PKRAM_LINK_ENTRIES_MAX ||
	    !link->entry[pds->entry_idx]) {
		pds->link = NULL;
		pkram_free_page(link);
	}

	return page;
}

/**
 * Load the next page from the preserved memory node and object associated
 * with pkram stream access @pa. The stream must have been initialized with
 * pkram_prepare_load() and pkram_prepare_load_obj() and access initialized
 * with PKRAM_ACCESS().
 *
 * If not NULL, @index is initialized with the preserved mapping offset of the
 * page loaded.
 *
 * Returns the page loaded or NULL if the node is empty.
 *
 * The page loaded has its refcount incremented.
 */
struct page *pkram_load_file_page(struct pkram_access *pa, unsigned long *index)
{
	struct pkram_node *node = pa->ps->node;

	BUG_ON((node->flags & PKRAM_ACCMODE_MASK) != PKRAM_LOAD);

	return __pkram_load_page(pa, index);
}

/**
 * Copy @count bytes from @buf to the preserved memory node and object
 * associated with pkram stream access @pa. The stream must have been
 * initialized with pkram_prepare_save() and pkram_prepare_save_obj()
 * and access initialized with PKRAM_ACCESS();
 *
 * On success, returns the number of bytes written, which is always equal to
 * @count. On failure, -errno is returned.
 */
ssize_t pkram_write(struct pkram_access *pa, const void *buf, size_t count)
{
	return -ENOSYS;
}

/**
 * Copy up to @count bytes from the preserved memory node and object
 * associated with pkram stream access @pa to @buf. The stream must have been
 * initialized with pkram_prepare_load() and pkram_prepare_load_obj() and
 * access initialized PKRAM_ACCESS().
 *
 * Returns the number of bytes read, which may be less than @count if the node
 * has fewer bytes available.
 */
size_t pkram_read(struct pkram_access *pa, void *buf, size_t count)
{
	return 0;
}
