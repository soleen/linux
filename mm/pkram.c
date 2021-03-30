// SPDX-License-Identifier: GPL-2.0
#include <linux/err.h>
#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/pkram.h>
#include <linux/types.h>

/**
 * Create a preserved memory node with name @name and initialize stream @ps
 * for saving data to it.
 *
 * @gfp_mask specifies the memory allocation mask to be used when saving data.
 *
 * Returns 0 on success, -errno on failure.
 *
 * After the save has finished, pkram_finish_save() (or pkram_discard_save() in
 * case of failure) is to be called.
 */
int pkram_prepare_save(struct pkram_stream *ps, const char *name, gfp_t gfp_mask)
{
	return -ENOSYS;
}

/**
 * Create a preserved memory object and initialize stream @ps for saving data
 * to it.
 *
 * Returns 0 on success, -errno on failure.
 *
 * After the save has finished, pkram_finish_save_obj() (or pkram_discard_save()
 * in case of failure) is to be called.
 */
int pkram_prepare_save_obj(struct pkram_stream *ps, enum pkram_data_flags flags)
{
	return -ENOSYS;
}

/**
 * Commit the object started with pkram_prepare_save_obj() to preserved memory.
 */
void pkram_finish_save_obj(struct pkram_stream *ps)
{
	BUG();
}

/**
 * Commit the save to preserved memory started with pkram_prepare_save().
 * After the call, the stream may not be used any more.
 */
void pkram_finish_save(struct pkram_stream *ps)
{
	BUG();
}

/**
 * Cancel the save to preserved memory started with pkram_prepare_save() and
 * destroy the corresponding preserved memory node freeing any data already
 * saved to it.
 */
void pkram_discard_save(struct pkram_stream *ps)
{
	BUG();
}

/**
 * Remove the preserved memory node with name @name and initialize stream @ps
 * for loading data from it.
 *
 * Returns 0 on success, -errno on failure.
 *
 * After the load has finished, pkram_finish_load() is to be called.
 */
int pkram_prepare_load(struct pkram_stream *ps, const char *name)
{
	return -ENOSYS;
}

/**
 * Remove the next preserved memory object from the stream @ps and
 * initialize stream @ps for loading data from it.
 *
 * Returns 0 on success, -errno on failure.
 *
 * After the load has finished, pkram_finish_load_obj() is to be called.
 */
int pkram_prepare_load_obj(struct pkram_stream *ps)
{
	return -ENOSYS;
}

/**
 * Finish the load of a preserved memory object started with
 * pkram_prepare_load_obj() freeing the object and any data that has not
 * been loaded from it.
 */
void pkram_finish_load_obj(struct pkram_stream *ps)
{
	BUG();
}

/**
 * Finish the load from preserved memory started with pkram_prepare_load()
 * freeing the corresponding preserved memory node and any data that has
 * not been loaded from it.
 */
void pkram_finish_load(struct pkram_stream *ps)
{
	BUG();
}

/**
 * Finish the data access to or from the preserved memory node and object
 * associated with pkram stream access @pa.  The access must have been
 * initialized with PKRAM_ACCESS(). 
 */
void pkram_finish_access(struct pkram_access *pa, bool status_ok)
{
	BUG();
}

/**
 * Save file page @page to the preserved memory node and object associated
 * with pkram stream access @pa. The stream must have been initialized with
 * pkram_prepare_save() and pkram_prepare_save_obj() and access initialized
 * with PKRAM_ACCESS().
 *
 * Returns 0 on success, -errno on failure.
 */
int pkram_save_file_page(struct pkram_access *pa, struct page *page)
{
	return -ENOSYS;
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
	return NULL;
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
