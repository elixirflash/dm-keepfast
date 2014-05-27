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

extern int kf_debug;

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
 *
 * Whole:
 * Superblock (1MB) + Segment + Segment ...
 * We reserve the first 1MB as the superblock.
 *
 * Superblock:
 * head <----                                     ----> tail
 * superblock header (512B) + ... + superblock record (512B)
 *
 * Segment:
 * segment_header_device (512B) +
 * metablock_device * nr_caches_inseg +
 * (aligned first 4KB region)
 * data[0] (4KB) + data{1] + ... + data{nr_cache_inseg - 1]
 */

/*
 * Superblock Header
 * First one sector of the super block region.
 * The value is fixed after formatted.
 */

 /*
  * Magic Number
  * "WBst"
  */
#define KEEPFAST_MAGIC 0x57427374
struct superblock_header_device {
	__le32 magic;
	u8 segment_size_order;
} __packed;

/*
 * Superblock Record (Mutable)
 * Last one sector of the superblock region.
 * Record the current cache status in need.
 */
struct superblock_record_device {
	__le64 last_migrated_segment_id;
} __packed;

/*
 * Metadata of a 4KB cache line
 *
 * Dirtiness is defined for each sector
 * in this cache line.
 */
struct metablock {
	sector_t sector; /* key */

	u32 idx; /* Const */

	struct hlist_node ht_list;

	/*
	 * 8 bit flag for dirtiness
	 * for each sector in cache line.
	 *
	 * Current implementation
	 * only recovers dirty caches.
	 * Recovering clean caches complicates the code
	 * but couldn't be effective
	 * since only few of the caches are clean.
	 */
	u8 dirty_bits;

	struct completion flush_done;        
};

/*
 * On-disk metablock
 *
 * Its size must be a factor of one sector
 * to avoid starddling neighboring two sectors.
 * Facebook's flashcache does the same thing.
 */
struct metablock_device {
	__le64 sector;
	u8 dirty_bits;
	__le32 lap;
	u8 padding[16 - (8 + 1 + 4)];
} __packed;

#define SZ_MAX (~(size_t)0)
struct segment_header {
	/*
	 * ID uniformly increases.
	 * ID 0 is used to tell that the segment is invalid
	 * and valid id >= 1.
	 */
	u64 global_id;

	/*
	 * Segment can be flushed half-done.
	 * length is the number of
	 * metablocks that must be counted in
	 * in resuming.
	 */
	u8 length;

	u32 start_idx; /* Const */
	sector_t start_sector; /* Const */

	struct list_head migrate_list;

	/*
	 * This segment can not be migrated
	 * to backin store
	 * until flushed.
	 * Flushed segment is in cache device.
	 */
	struct completion flush_done;

	/*
	 * This segment can not be overwritten
	 * until migrated.
	 */
	struct completion migrate_done;

	spinlock_t lock;

	atomic_t nr_inflight_ios;

	struct metablock mb_array[0];
};

/*
 * (Locking)
 * Locking metablocks by their granularity
 * needs too much memory space for lock structures.
 * We only locks a metablock by locking the parent segment
 * that includes the metablock.
 */
#define lockseg(seg, flags) spin_lock_irqsave(&(seg)->lock, flags)
#define unlockseg(seg, flags) spin_unlock_irqrestore(&(seg)->lock, flags)

/*
 * On-disk segment header.
 *
 * Must be at most 4KB large.
 */
struct segment_header_device {
	/* - FROM ------------------------------------ */
	__le64 global_id;
	/*
	 * On what lap in rorating on cache device
	 * used to find the head and tail in the
	 * segments in cache device.
	 */
	__le32 lap;
	u8 padding[512 - (8 + 4)]; /* 512B */
	/* - TO -------------------------------------- */
	struct metablock_device mbarr[0]; /* 16B * N */
} __packed;

struct rambuffer {
	void *data;
	struct completion done;
};

#define STAT_OP_FLUSH       0
#define STAT_OP_INV         1
#define STAT_OP_BYPASS      2
#define STAT_OP_LEN         3

enum STATFLAG {
	STAT_HIT = 0,        
	STAT_WRITE,
	STAT_FULLSIZE,
        STAT_EOF
};
#define STATLEN (1 << STAT_EOF)

struct lookup_key {
	sector_t sector;
};

struct ht_head {
	struct hlist_head ht_list;
};

struct wb_device;
struct wb_cache {
	struct wb_device *wb;

	mempool_t *buf_1_pool; /* 1 sector buffer pool */
	mempool_t *buf_8_pool; /* 8 sector buffer pool */
	mempool_t *flush_job_pool;

	struct dm_dev *device;
	struct mutex io_lock;
	u32 nr_caches; /* Const */
	u32 nr_segments; /* Const */
	u64 nr_sects; /* Const */                
	u8 segment_size_order; /* Const */
	u8 nr_caches_inseg; /* Const */
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
        bool last_mb_in_segment;

	struct rambuffer *current_rambuf;
	u32 rambuf_pool_amount; /* kB */
	u32 nr_rambuf_pool; /* Const */
	struct rambuffer *rambuf_pool;

	atomic64_t last_migrated_segment_id;
	atomic64_t last_fulled_segment_id;
	int urge_migrate;

	/*
	 * Flush daemon
	 *
	 * Keepfast first queue the segment to flush
	 * and flush daemon asynchronously
	 * flush them to the cache device.
	 */
	struct task_struct *flush_daemon;
	spinlock_t flush_queue_lock;
	struct list_head flush_queue;

	/*
	 * Deferred ACK for barriers.
	 */
	struct work_struct barrier_deadline_work;
	struct timer_list barrier_deadline_timer;
	struct bio_list barrier_ios;
	unsigned long barrier_deadline_ms; /* param */

	/*
	 * Migration daemon
	 *
	 * Migartion also works in background.
	 *
	 * If allow_migrate is true,
	 * migrate daemon goes into migration
	 * if they are segments to migrate.
	 */
	struct task_struct *migrate_daemon;
	int allow_migrate; /* param */

	/*
	 * Batched Migration
	 *
	 * Migration is done atomically
	 * with number of segments batched.
	 */
	wait_queue_head_t migrate_wait_queue;
	atomic_t migrate_fail_count;
	atomic_t migrate_io_count;
	struct list_head migrate_list;
	u8 *dirtiness_snapshot;
	void *migrate_buffer;
	u32 nr_cur_batched_migration;
	u32 nr_max_batched_migration; /* param */

	/*
	 * Migration modulator
	 *
	 * This daemon turns on and off
	 * the migration
	 * according to the load of backing store.
	 */
	struct task_struct *modulator_daemon;
	int enable_migration_modulator; /* param */

	/*
	 * Superblock Recorder
	 *
	 * Update the superblock record
	 * periodically.
	 */
	struct task_struct *recorder_daemon;
	unsigned long update_record_interval; /* param */

	/*
	 * Cache Synchronizer
	 *
	 * Sync the dirty writes
	 * periodically.
	 */
	struct task_struct *sync_daemon;
	unsigned long sync_interval; /* param */

	atomic64_t stat[STATLEN];
	atomic64_t op_stat[STAT_OP_LEN];        
};

struct wb_device {
	struct dm_target *ti;

	struct dm_dev *device;

	struct wb_cache *cache;

	u8 high_migrate_threshold;
	u8 low_migrate_threshold;        

	atomic64_t nr_dirty_caches;

	wait_queue_head_t blockup_wait_queue;
	int blockup;
};

struct flush_job {
	struct list_head flush_queue;
	struct segment_header *seg;
	/*
	 * The data to flush to cache device.
	 */
	struct rambuffer *rambuf;
	/*
	 * List of bios with barrier flags.
	 */
	struct bio_list barrier_ios;
};

struct per_bio_data {
	void *ptr;
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

sector_t calc_segment_header_start(struct wb_cache *cache,
                                   u32 segment_idx);
int __must_check
read_segment_header_device(struct segment_header_device *dest,
			   struct wb_cache *cache, u32 segment_idx);

void inc_stat(struct wb_cache *cache, int rw, bool found, int blocks);
void inc_op_stat(struct wb_cache *cache, int op, int val);

/*----------------------------------------------------------------*/

#endif
