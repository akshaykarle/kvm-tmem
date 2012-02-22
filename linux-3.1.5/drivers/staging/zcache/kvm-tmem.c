/*
 * kvm implementation for transcendent memory (tmem)
 *
 * Copyright (C) 2009-2011 Oracle Corp.  All rights reserved.
 * Author: Dan Magenheimer
 *	   Akshay Karle
 *	   Ashutosh Tripathi
 *	   Nishant Gulhane
 *	   Shreyas Mahure
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/pagemap.h>
#include <linux/module.h>
#include <linux/cleancache.h>

/* temporary ifdef until include/linux/frontswap.h is upstream */
#ifdef CONFIG_FRONTSWAP
#include <linux/frontswap.h>
#endif

#include "kvm-tmem.h"

/* kvm tmem foundation ops/hypercalls */

static inline int kvm_tmem_op(u32 tmem_cmd, u32 tmem_pool, struct tmem_oid oid,
	u32 index, u32 tmem_offset, u32 pfn_offset, unsigned long pfn, u32 len, uint16_t cli_id)
{
	struct tmem_op op;
	int rc = 0;
	op.cmd = tmem_cmd;
	op.pool_id = tmem_pool;
	op.u.gen.oid[0] = oid.oid[0];
	op.u.gen.oid[1] = oid.oid[1];
	op.u.gen.oid[2] = oid.oid[2];
	op.u.gen.index = index;
	op.u.gen.tmem_offset = tmem_offset;
	op.u.gen.pfn_offset = pfn_offset;
	op.u.gen.pfn = pfn;
	op.u.gen.len = len;
	op.u.gen.cli_id = cli_id;
	rc = kvm_hypercall1(KVM_HC_TMEM, virt_to_phys(&op));
	rc = rc + 1000;
	return rc;
}

static int kvm_tmem_new_pool(uint16_t cli_id,
				u32 flags, unsigned long pagesize)
{
	struct tmem_op op;
	int rc, pageshift;
	for (pageshift = 0; pagesize != 1; pageshift++)
		pagesize >>= 1;
	flags |= (pageshift - 12) << TMEM_POOL_PAGESIZE_SHIFT;
	flags |= TMEM_SPEC_VERSION << TMEM_VERSION_SHIFT;
	op.cmd = TMEM_NEW_POOL;
	op.u.new.cli_id = cli_id;
	op.u.new.flags = flags;
	rc = kvm_hypercall1(KVM_HC_TMEM, virt_to_phys(&op));
	rc = rc + 1000;
	return rc;
}

/* kvm generic tmem ops */

static int kvm_tmem_put_page(u32 pool_id, struct tmem_oid oid,
			     u32 index, unsigned long pfn)
{

	return kvm_tmem_op(TMEM_PUT_PAGE, pool_id, oid, index,
		0, 0, pfn, 0, TMEM_CLI);
}

static int kvm_tmem_get_page(u32 pool_id, struct tmem_oid oid,
			     u32 index, unsigned long pfn)
{

	return kvm_tmem_op(TMEM_GET_PAGE, pool_id, oid, index,
		0, 0, pfn, 0, TMEM_CLI);
}

static int kvm_tmem_flush_page(u32 pool_id, struct tmem_oid oid, u32 index)
{
	return kvm_tmem_op(TMEM_FLUSH_PAGE, pool_id, oid, index,
		0, 0, 0, 0, TMEM_CLI);
}

static int kvm_tmem_flush_object(u32 pool_id, struct tmem_oid oid)
{
	return kvm_tmem_op(TMEM_FLUSH_OBJECT, pool_id, oid, 0, 0, 0, 0, 0, TMEM_CLI);
}

static int kvm_tmem_destroy_pool(u32 pool_id)
{
	struct tmem_oid oid = { { 0 } };

	return kvm_tmem_op(TMEM_DESTROY_POOL, pool_id, oid, 0, 0, 0, 0, 0, TMEM_CLI);
}

static int kvm_tmem_enabled;

static int __init enable_tmem_kvm(char *s)
{
	kvm_tmem_enabled = 1;
	return 1;
}
__setup("tmem", enable_tmem_kvm);

/* cleancache ops */

#ifdef CONFIG_CLEANCACHE
static void tmem_cleancache_put_page(int pool, struct cleancache_filekey key,
				     pgoff_t index, struct page *page)
{
	u32 ind = (u32) index;
	struct tmem_oid oid = *(struct tmem_oid *)&key;
	unsigned long pfn = page_to_pfn(page);

	if (pool < 0)
		return;
	if (ind != index)
		return;
	mb(); /* ensure page is quiescent; tmem may address it with an alias */
	(void)kvm_tmem_put_page((u32)pool, oid, ind, pfn);
}

static int tmem_cleancache_get_page(int pool, struct cleancache_filekey key,
				    pgoff_t index, struct page *page)
{
	u32 ind = (u32) index;
	struct tmem_oid oid = *(struct tmem_oid *)&key;
	unsigned long pfn = page_to_pfn(page);
	int ret;

	/* translate return values to linux semantics */
	if (pool < 0)
		return -1;
	if (ind != index)
		return -1;
	ret = kvm_tmem_get_page((u32)pool, oid, ind, pfn);
	return ret;
}

static void tmem_cleancache_flush_page(int pool, struct cleancache_filekey key,
				       pgoff_t index)
{
	u32 ind = (u32) index;
	struct tmem_oid oid = *(struct tmem_oid *)&key;

	if (pool < 0)
		return;
	if (ind != index)
		return;
	(void)kvm_tmem_flush_page((u32)pool, oid, ind);
}

static void tmem_cleancache_flush_inode(int pool, struct cleancache_filekey key)
{
	struct tmem_oid oid = *(struct tmem_oid *)&key;

	if (pool < 0)
		return;
	(void)kvm_tmem_flush_object((u32)pool, oid);
}

static void tmem_cleancache_flush_fs(int pool)
{
	if (pool < 0)
		return;
	(void)kvm_tmem_destroy_pool((u32)pool);
}

static int tmem_cleancache_init_fs(size_t pagesize)
{
	uint16_t cli_id=TMEM_CLI;
	return kvm_tmem_new_pool(cli_id, 0, pagesize);
}

static int tmem_cleancache_init_shared_fs(char *uuid, size_t pagesize)
{
	uint16_t cli_id=TMEM_CLI;
	return kvm_tmem_new_pool(cli_id, TMEM_POOL_SHARED, pagesize);
}

static int use_cleancache = 1;

static int __init no_cleancache(char *s)
{
	use_cleancache = 0;
	return 1;
}

__setup("nocleancache", no_cleancache);

static struct cleancache_ops tmem_cleancache_ops = {
	.put_page = tmem_cleancache_put_page,
	.get_page = tmem_cleancache_get_page,
	.invalidate_page = tmem_cleancache_flush_page,
	.invalidate_inode = tmem_cleancache_flush_inode,
	.invalidate_fs = tmem_cleancache_flush_fs,
	.init_shared_fs = tmem_cleancache_init_shared_fs,
	.init_fs = tmem_cleancache_init_fs
};
#endif

#ifdef CONFIG_FRONTSWAP
/* frontswap tmem operations */

/* a single tmem poolid is used for all frontswap "types" (swapfiles) */
static int tmem_frontswap_poolid;

/*
 * Swizzling increases objects per swaptype, increasing tmem concurrency
 * for heavy swaploads.  Later, larger nr_cpus -> larger SWIZ_BITS
 */
#define SWIZ_BITS		4
#define SWIZ_MASK		((1 << SWIZ_BITS) - 1)
#define _oswiz(_type, _ind)	((_type << SWIZ_BITS) | (_ind & SWIZ_MASK))
#define iswiz(_ind)		(_ind >> SWIZ_BITS)

static inline struct tmem_oid oswiz(unsigned type, u32 ind)
{
	struct tmem_oid oid = { .oid = { 0 } };
	oid.oid[0] = _oswiz(type, ind);
	return oid;
}

/* returns 0 if the page was successfully put into frontswap, -1 if not */
static int tmem_frontswap_put_page(unsigned type, pgoff_t offset,
				   struct page *page)
{
	u64 ind64 = (u64)offset;
	u32 ind = (u32)offset;
	unsigned long pfn = page_to_pfn(page);
	int pool = tmem_frontswap_poolid;
	int ret;

	if (pool < 0)
		return -1;
	if (ind64 != ind)
		return -1;
	mb(); /* ensure page is quiescent; tmem may address it with an alias */
	ret = kvm_tmem_put_page(pool, oswiz(type, ind), iswiz(ind), pfn);
	/* translate kvm tmem return values to linux semantics */
	return ret;
}

/*
 * returns 0 if the page was successfully gotten from frontswap, -1 if
 * was not present (should never happen!)
 */
static int tmem_frontswap_get_page(unsigned type, pgoff_t offset,
				   struct page *page)
{
	u64 ind64 = (u64)offset;
	u32 ind = (u32)offset;
	unsigned long pfn = page_to_pfn(page);
	int pool = tmem_frontswap_poolid;
	int ret;

	if (pool < 0)
		return -1;
	if (ind64 != ind)
		return -1;
	ret = kvm_tmem_get_page(pool, oswiz(type, ind), iswiz(ind), pfn);
	/* translate kvm tmem return values to linux semantics */
	return ret;
}

/* flush a single page from frontswap */
static void tmem_frontswap_flush_page(unsigned type, pgoff_t offset)
{
	u64 ind64 = (u64)offset;
	u32 ind = (u32)offset;
	int pool = tmem_frontswap_poolid;

	if (pool < 0)
		return;
	if (ind64 != ind)
		return;
	(void) kvm_tmem_flush_page(pool, oswiz(type, ind), iswiz(ind));
}

/* flush all pages from the passed swaptype */
static void tmem_frontswap_flush_area(unsigned type)
{
	int pool = tmem_frontswap_poolid;
	int ind;

	if (pool < 0)
		return;
	for (ind = SWIZ_MASK; ind >= 0; ind--)
		(void)kvm_tmem_flush_object(pool, oswiz(type, ind));
	(void)kvm_tmem_destroy_pool((u32)pool);
}

static void tmem_frontswap_init(unsigned ignored)
{
	/* a single tmem poolid is used for all frontswap "types" (swapfiles) */
	if (tmem_frontswap_poolid < 0)
		tmem_frontswap_poolid =
		    kvm_tmem_new_pool(TMEM_CLI, TMEM_POOL_PERSIST, PAGE_SIZE);
}

static int __initdata use_frontswap = 1;

static int __init no_frontswap(char *s)
{
	use_frontswap = 0;
	return 1;
}

__setup("nofrontswap", no_frontswap);

static struct frontswap_ops tmem_frontswap_ops = {
	.put_page = tmem_frontswap_put_page,
	.get_page = tmem_frontswap_get_page,
	.invalidate_page = tmem_frontswap_flush_page,
	.invalidate_area = tmem_frontswap_flush_area,
	.init = tmem_frontswap_init
};
#endif

static int __init kvm_tmem_init(void)
{
#ifdef CONFIG_FRONTSWAP
	if (kvm_tmem_enabled && use_frontswap) {
		char *s = "";
		struct frontswap_ops old_ops =
			frontswap_register_ops(&tmem_frontswap_ops);

		tmem_frontswap_poolid = -1;
		if (old_ops.init != NULL)
			s = " (WARNING: frontswap_ops overridden)";
		printk(KERN_INFO "%% frontswap enabled, RAM provided by "
				 "kvm Transcendent Memory\n");
	}
#endif
#ifdef CONFIG_CLEANCACHE
	BUG_ON(sizeof(struct cleancache_filekey) != sizeof(struct tmem_oid));
	if (kvm_tmem_enabled && use_cleancache) {
		char *s = "";
		struct cleancache_ops old_ops =
			cleancache_register_ops(&tmem_cleancache_ops);
		if (old_ops.init_fs != NULL)
			s = " (WARNING: cleancache_ops overridden)";
		printk(KERN_INFO "%% cleancache enabled, RAM provided by "
				 "kvm Transcendent Memory%s\n", s);
	}
#endif
	return 0;
}

module_init(kvm_tmem_init)
