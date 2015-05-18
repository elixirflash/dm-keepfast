/*
 * Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This file is released under the GPL.
 */

#ifndef DM_KEEPFAST_H
#define DM_KEEPFAST_H

/*----------------------------------------------------------------*/

#define DM_MSG_PREFIX "keepfast"

#include "../dm.h"
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mutex.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/device-mapper.h>
#include <linux/dm-io.h>

#include "./dm-keepfast-blocktype.h"
#include "../dm-bio-record.h"

extern int kf_debug;

//#define OVERWRITE_ON_HIT
//#define RAM_RW_BYTEALIGN

#define kfdebug(f, args...) \
        if(kf_debug)        \
                DMINFO("debug@%s() L.%d" f, __func__, __LINE__, ## args)

#define KFERR(f, args...) \
	DMERR("err@%s() " f, __func__, ## args)
#define KFWARN(f, args...) \
	DMWARN("warn@%s() " f, __func__, ## args)
#define KFINFO(f, args...) \
	DMINFO("info@%s() " f, __func__, ## args)

/*
 * The Detail of the Disk Format
 */
#define KEEPFAST_MAGIC 0x57427374
//#define UNITTEST

struct superblock_device {
	__le32 magic;
	u8 segment_size_order;
} __packed;

/*
 * Metadata of a 4KB cache line
 */
struct metablock {
        u32 oblock_packed_d; /* with dirty flag */
        u32 idx_packed_v;    /* with valid flag */
        u8 hit_count;

	struct hlist_node ht_list;
        struct list_head hot_list;
};

/*
 * On-disk metablock
 */
struct metablock_device {
	__le32 oblock_packed_d; /* with dirty flag */
        u32 idx_packed_v; /* with valid flag */
        u8 hit_count;
	u8 padding[16 - (8 + 1 + 4)];
} __packed;

#define SZ_MAX (~(size_t)0)

#define MAX_BLOCKS_IN_SEG 64
struct segment_header {
	/*
	 * ID uniformly increases.
	 * ID 0 is used to tell that the segment is invalid
	 * and valid id >= 1.
	 */
	u32 global_id;



	u32 start_idx; /* Const */
        dm_cblock_t start_sector; /* Const */

	struct list_head flush_list;

	/*
	 * This segment can not be overwritten
	 * until flushd.
	 */
	struct completion flush_done;
	atomic_t flush_io_count;
	atomic_t flush_fail_count;        
        
	wait_queue_head_t flush_wait_queue;

	DECLARE_BITMAP(replace_bitmap, MAX_BLOCKS_IN_SEG);

	atomic_t nr_inflight_ios;
	struct metablock mb_array[0];
};

/*
 * On-disk segment header.
 *
 * Must be at most 4KB large.
 */
struct segment_header_device {
	/* - FROM ------------------------------------ */
	__le32 global_id;
	DECLARE_BITMAP(replace_bitmap, MAX_BLOCKS_IN_SEG);        
	/*
	 * On what lap in rorating on cache device
	 * used to find the head and tail in the
	 * segments in cache device.
	 */
	u8 padding[512 - (4 + BITS_TO_LONGS(MAX_BLOCKS_IN_SEG))]; /* 512B */
	/* - TO -------------------------------------- */
	struct metablock_device mbarr[0]; /* 16B * N */
} __packed;

struct cache_entry {
        struct segment_header *seg;
        struct metablock *mb;

        dm_oblock_t oblock; 
        dm_cblock_t cblock;
        u32 idx;
        u8 set_partial_dirty;
        u8 dflags;
        u8 vflags;
        u8 hot;
 
        struct sub_entry {
                u8 tag;
                u8 vflag;
                u8 dflag;                
                dm_oblock_t oblock;
                dm_cblock_t cblock;
                u8 unaligned;
        } se;
};

#define INIT_CACHE_ENTRY(x) x = {0, }

struct cache_stats {
        atomic64_t whit;
        atomic64_t rhit;
        atomic64_t wmiss;
        atomic64_t rmiss;

        atomic64_t dirty;
        atomic64_t valid;
        atomic64_t hot;

        atomic64_t bypass;
        atomic64_t flush;
        atomic64_t replace;
};

struct lookup_key {
	sector_t sector;
};

struct ht_head {
	struct hlist_head ht_list;
};

struct wb_device;
struct wb_cache {
	struct wb_device *wb;
        struct policy_operation *pop;
        
	mempool_t *buf_1_pool; /* 1 sector buffer pool */
	mempool_t *buf_8_pool; /* 8 sector buffer pool */
        
	struct dm_dev *device;
	struct mutex io_lock;
	u32 nr_blocks; /* Const */
	u32 nr_segments; /* Const */
	u32 nr_sects; /* Const */
	u8 segment_size_order; /* Const */
	u8 block_size_order; /* Const */
        u32 nr_sectors_per_block_shift;
        u32 sectors_per_page;
	u8 nr_blocks_inseg; /* Const */
        u32 nr_pages_inblock;
        u32 nr_blks;
        u32 nr_pages;
        
	struct bigarray *segment_header_array;
        
	/*
	 * Chained hashtable
	 *
	 * Keepfast uses chained hashtable
	 * to cache lookup.
	 * Cache discarding often happedns
	 * This structure fits our needs.
	 */
	struct bigarray *htable;
	size_t htsize;
	struct ht_head *null_head;
        
	u32 cursor; /* Index that has been written the most lately */
	spinlock_t cursor_lock;        
	struct segment_header *current_seg;
	struct segment_header *current_flush_seg;
	struct segment_header *last_flush_seg;

	atomic_t current_flush_seg_id;        
	atomic_t last_flushed_segment_id;
	u32 last_filled_segment_id;
	int urge_flush;
        int invalidate_over;

	struct bio_list deferred_readthrough_bios;
        struct bio_list deferred_bios;

	/*
	 * Flush thread
	 *
	 * Keepfast first queue the segment to flush
	 * and flush thread asynchronously
	 * flush them to the cache device.
	 */
	struct task_struct *flush_thread;
	spinlock_t flush_queue_lock;
	struct list_head flush_queue;
	int allow_flush; /* param */
        int repeat_flush;
        u32 flush_seg;

	struct workqueue_struct *wq;        
	struct work_struct worker;
	spinlock_t lock;        

        u32 pd_array_idx;
        //	struct partial_dflag_array pd_array[10];

	/*
	 * Deferred ACK for barriers.
	 */
	struct work_struct barrier_deadline_work;
	struct timer_list barrier_deadline_timer;
	struct bio_list barrier_ios;
	unsigned long barrier_deadline_ms; /* param */

	/*
	 * Batched Flush
	 *
	 * Flush is done atomically
	 * with number of segments batched.
	 */
	wait_queue_head_t flush_wait_queue;
	atomic_t flush_fail_count;
	struct list_head flush_list;
        
	void *flush_buffer;
	u32 nr_cur_batched_flush;
        u32 nr_segs_flush_region;
	u32 nr_max_batched_flush; /* param */

        struct cache_stats stats;        
};

struct wb_device {
	struct dm_target *ti;
	struct dm_dev *device;
	struct wb_cache *cache;
	atomic64_t nr_dirty_caches;

	wait_queue_head_t blockup_wait_queue;
	int blockup;
};

/*----------------------------------------------------------------*/

void flush_current_buffer(struct wb_cache *);
void inc_nr_dirty_caches(struct wb_device *);
void cleanup_mb_if_dirty(struct wb_cache *,
			 struct segment_header *,
			 struct metablock *);
u8 atomic_read_mb_dirtiness(struct segment_header *, struct metablock *);

/*----------------------------------------------------------------*/

extern struct workqueue_struct *safe_io_wq;
extern struct dm_io_client *wb_io_client;

/*
 * I/O error on either backing or cache
 * should block up the whole system.
 * Either reading or writing a device
 * should not be done if it once returns -EIO.
 * These devices are untrustable and
 * we wait for sysadmin to remove the failure cause away.
 */

#define wait_on_blockup() \
	do { \
		BUG_ON(!wb); \
		if (ACCESS_ONCE(wb->blockup)) { \
			KFERR("system is blocked up on I/O error. set blockup to 0 after checkup."); \
			wait_event_interruptible(wb->blockup_wait_queue, \
						 !ACCESS_ONCE(wb->blockup)); \
			KFINFO("reactivated after blockup"); \
		} \
	} while (0)

#define RETRY(proc) \
	do { \
		BUG_ON(!wb); \
		r = proc; \
		if (r == -EOPNOTSUPP) { \
			r = 0;\
		} else if (r == -EIO) { /* I/O error is critical */ \
			wb->blockup = true; \
			wait_on_blockup(); \
		} else if (r == -ENOMEM) { \
			schedule_timeout_interruptible(msecs_to_jiffies(1000));\
		} else if (r) { \
			KFERR("please report!! I/O failed but no retry error code %d", r);\
			r = 0;\
		} \
	} while (r)

int dm_safe_io_internal(
		struct wb_device*,
		struct dm_io_request *,
		unsigned num_regions, struct dm_io_region *,
		unsigned long *err_bits, bool thread, const char *caller);

#define dm_safe_io(io_req, num_regions, regions, err_bits, thread) \
		dm_safe_io_internal(wb, (io_req), (num_regions), (regions), \
				    (err_bits), (thread), __func__);

sector_t dm_devsize(struct dm_dev *);

dm_cblock_t calc_segment_header_start(struct wb_cache *cache,
                                   u32 segment_idx);
int __must_check
read_segment_header_device(struct segment_header_device *dest,
			   struct wb_cache *cache, u32 segment_idx);

void inc_stat(struct wb_cache *cache, int rw, bool found, int blocks);
void inc_op_stat(struct wb_cache *cache, int op, int val);

void inc_nr_dirty_caches(struct wb_device *wb);
void dec_nr_dirty_caches(struct wb_device *wb);

extern void flush_meta(struct wb_cache *cache, struct cache_entry *ce, bool thread);
void flush_seg_header(struct wb_cache *cache, struct segment_header *seg, bool thread);
void flush_cache_entry(struct wb_cache *cache, struct policy_operation *pop, struct cache_entry *ce);
/*----------------------------------------------------------------*/

#endif
