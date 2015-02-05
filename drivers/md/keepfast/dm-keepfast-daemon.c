/*
 * Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This file is released under the GPL.
 */

#include "dm-keepfast.h"
#include "dm-keepfast-metadata.h"
#include "dm-keepfast-daemon.h"
#include "dm-keepfast-policy.h"
#include "dm-keepfast-policy-internal.h"

#include <trace/events/keepfast.h>

/*----------------------------------------------------------------*/

static void flush_endio(unsigned long error, void *context)
{
	struct wb_cache *cache = context;

	if (error)
		atomic_inc(&cache->flush_fail_count);

	if (atomic_dec_and_test(&cache->flush_io_count))
		wake_up_interruptible(&cache->flush_wait_queue);
}

/*
 * Submit the segment data at position k
 * in flush buffer.
 * Batched flush first gather all the segments
 * to flush into a flush buffer.
 * So, there are a number of segment data
 * in the buffer.
 * This function submits the one in position k.
 */
static void submit_flush_io(struct wb_cache *cache,
			      struct segment_header *seg, size_t k)
{
	int r;
	u8 i, j;
	size_t a = cache->nr_blocks_inseg * k;
	void *p = cache->flush_buffer + ((cache->nr_blocks_inseg + cache->nr_pages_inblock) << 12) * k;

	for (i = 0; i < seg->length; i++) {
		struct metablock *mb = seg->mb_array + i;
		struct wb_device *wb = cache->wb;
		u8 dirty_bits = *(cache->dirtiness_snapshot + (a + i));

		unsigned long offset;
		void *base;

		struct dm_io_request io_req_w;
		struct dm_io_region region_w;

                dm_oblock_t oblock;
                u8 dflag = 0;

                unpack_dflag(mb->oblock_packed_d, &oblock, &dflag);

		if (!dflag)
			continue;

		offset = i << 12;
		base = p + offset; /* over seg-header */

                for(j = 0; j < 4; j++) {
                        if(dflag & (1 << i)) {
                                
                                io_req_w = (struct dm_io_request) {
                                        .client = wb_io_client,
                                        .bi_rw = WRITE,
                                        .notify.fn = flush_endio,
                                        .notify.context = cache,
                                        .mem.type = DM_IO_VMA,
                                        .mem.ptr.vma = base + (4096 << j),
                                };
                                
                                region_w = (struct dm_io_region) {
                                        .bdev = wb->device->bdev,
                                        .sector = oblock + (1 << (3 + j)),
                                        .count = (1 << 3),
                                };
                                RETRY(dm_safe_io(&io_req_w, 1, &region_w, NULL, false));
                        }
                }
                inc_op_stat(cache, STAT_OP_FLUSH, dirty_bits);
                trace_keepfast_op(seg, mb, STAT_OP_FLUSH);
	}
}

static void read_segs(struct wb_cache *cache,
				 struct segment_header *seg, size_t k,
				 size_t *flush_io_count)
{
	int r;
	u8 i, j;
	struct wb_device *wb = cache->wb;
	void *p = cache->flush_buffer + ((cache->nr_blocks_inseg + cache->nr_pages_inblock) << 12) * k;
	struct metablock *mb;
        dm_oblock_t oblock;
        u8 dflag = 0;

	struct dm_io_request io_req_r = {
		.client = wb_io_client,
		.bi_rw = READ,
		.notify.fn = NULL,
		.mem.type = DM_IO_VMA,
		.mem.ptr.vma = p,
	};
	struct dm_io_region region_r = {
		.bdev = cache->device->bdev,
		.sector = seg->start_sector + (1 << 3),
		.count = seg->length << (cache->nr_pages_inblock + 3),
	};
                  
	RETRY(dm_safe_io(&io_req_r, 1, &region_r, NULL, false));

	for (i = 0; i < seg->length; i++) {
		mb = seg->mb_array + i;

                unpack_dflag(mb->oblock_packed_d, &oblock, &dflag);

		if (!dflag)
			continue;

		if (dflag == 0xf) {
			(*flush_io_count)++;
		} else {
			for (j = 0; j < 4; j++) {
				if (dflag & (1 << j))
					(*flush_io_count)++;
			}
		}
	}        
}

static void cleanup_segment(struct wb_cache *cache, struct segment_header *seg)
{
        struct policy_operation *pop = cache->pop;
        struct cache_entry centry;
	u8 i;

        centry.seg = seg;

	for (i = 0; i < seg->length; i++) {
		struct metablock *mb = seg->mb_array + i;
                centry.mb = mb;
                
                policy_clear_dirty(pop, &centry);
	}
}

static void flush_linked_segments(struct wb_cache *cache)
{
	struct wb_device *wb = cache->wb;
        struct policy_operation *pop = cache->pop;
	int r;
	struct segment_header *seg;
	size_t k, flush_io_count = 0;

	/*
	 * Memorize the dirty state to flush before going in.
	 * - How many flush writes should be submitted atomically,
	 * - Which cache lines are dirty to migarate
	 * - etc.
	 */
	k = 0;
	list_for_each_entry(seg, &cache->flush_list, flush_list) {
		read_segs(cache, seg, k, &flush_io_count);
		k++;
	}

flush_write:
	atomic_set(&cache->flush_io_count, flush_io_count);
	atomic_set(&cache->flush_fail_count, 0);

	k = 0;
	list_for_each_entry(seg, &cache->flush_list, flush_list) {
		submit_flush_io(cache, seg, k);
		k++;
	}

	wait_event_interruptible(cache->flush_wait_queue,
				 atomic_read(&cache->flush_io_count) == 0);

	if (atomic_read(&cache->flush_fail_count)) {
		KFWARN("%u writebacks failed. retry.",
		       atomic_read(&cache->flush_fail_count));
		goto flush_write;
	}

	BUG_ON(atomic_read(&cache->flush_io_count));

	list_for_each_entry(seg, &cache->flush_list, flush_list) {
		cleanup_segment(cache, seg);
                remove_mappings_inseg(pop, seg);
	}

	/*
	 * The segment may have a block
	 * that returns ACK for persistent write
	 * on the cache device.
	 * Migrating them in non-persistent way
	 * is betrayal to the client
	 * who received the ACK and
	 * expects the data is persistent.
	 * Since it is difficult to know
	 * whether a cache in a segment
	 * is of that status
	 * we are on the safe side
	 * on this issue by always
	 * migrating those data persistently.
	 */
	RETRY(blkdev_issue_flush(cache->wb->device->bdev, GFP_NOIO, NULL));

	/*
	 * Discarding the flushd regions
	 * can avoid unnecessary wear amplifier in the future.
	 *
	 * But note that we should not discard
	 * the metablock region because
	 * whether or not to ensure
	 * the discarded block returns certain value
	 * is depends on venders
	 * and unexpected metablock data
	 * will craze the cache.
	 */
	list_for_each_entry(seg, &cache->flush_list, flush_list) {
		RETRY(blkdev_issue_discard(cache->device->bdev,
					   seg->start_sector + (1 << 3),
					   seg->length << 3,
					   GFP_NOIO, 0));
	}
}

int do_flush(void *data)
{
	struct wb_cache *cache = data;
	struct wb_device *wb = cache->wb;

	while (!kthread_should_stop()) {
		bool allow_flush;
		u32 i, victim_segs, flush_segs, nr_max_batch;
		struct segment_header *seg, *tmp;

		wait_on_blockup();

		/*
		 * If urge_flush is true
		 * Flush should be immediate.
		 */
		allow_flush = ACCESS_ONCE(cache->urge_flush) ||
				ACCESS_ONCE(cache->allow_flush);
		if (!allow_flush) {
			schedule_timeout_interruptible(msecs_to_jiffies(1000));
			continue;
		}

		victim_segs = cache->last_filled_segment_id -
                        cache->last_flushed_segment_id;

		if (!victim_segs || victim_segs <
                    cache->nr_segments * wb->low_flush_threshold / 100) {
			schedule_timeout_interruptible(msecs_to_jiffies(1000));
			continue;
		}

		nr_max_batch = ACCESS_ONCE(cache->nr_max_batched_flush);
		if (cache->nr_cur_batched_flush != nr_max_batch) {
			/*
			 * Request buffer for nr_max_batch size.
			 * If the allocation fails
			 * continue to use the current buffer.
			 */
			alloc_flush_buffer(cache, nr_max_batch);
		}

		/*
		 * Batched Flush:
		 * We will flush at most nr_max_batched_flush
		 * segments at a time.
		 */
		flush_segs = min(victim_segs,
			     cache->nr_cur_batched_flush);

                /*                printk(KERN_INFO"urge:%d,allow:%d,nrmig:%d: LF:%lld, LM:%lld, candidates:%d",
                       cache->urge_flush, cache->allow_flush,flush_segs, atomic64_read(&cache->last_filled_segment_id),
                       atomic64_read(&cache->last_flushed_segment_id), victim_segs);*/

		/*
		 * Add segments to flush atomically.
		 */
		for (i = 1; i <= flush_segs; i++) {
			seg = get_segment_header_by_id(
					cache,
					cache->last_flushed_segment_id + i);
			list_add_tail(&seg->flush_list, &cache->flush_list);
		}

		/*
		 * We insert write barrier here
		 * to make sure that flush list
		 * is complete.
		 */
		smp_wmb();

		flush_linked_segments(cache);

		/*
		 * (Locking)
		 * Only line of code changes
		 * last_flush_segment_id during runtime.
		 */
                flush_segs += cache->last_flushed_segment_id;

		list_for_each_entry_safe(seg, tmp,
					 &cache->flush_list,
					 flush_list) {
			complete_all(&seg->flush_done);
			list_del(&seg->flush_list);
		}
	}
	return 0;
}

/*
 * Wait for a segment of given ID
 * finishes its flush.
 */
void wait_for_flush(struct wb_cache *cache, u32 id)
{
	struct segment_header *seg = get_segment_header_by_id(cache, id);

	wake_up_process(cache->flush_thread);
	wait_for_completion(&seg->flush_done);
}

/*----------------------------------------------------------------*/

int do_balance_dirty(void *data)
{
	struct wb_cache *cache = data;
	struct wb_device *wb = cache->wb;

	struct hd_struct *hd = wb->device->bdev->bd_part;
	unsigned int old = 0, new, used;
	unsigned int intvl = 1000;
        u32 victim_segs;

	while (!kthread_should_stop()) {

		wait_on_blockup();

                new = jiffies_to_msecs(part_stat_read(hd, io_ticks));

		if (!ACCESS_ONCE(cache->enable_balance_dirty))
			goto modulator_update;

		victim_segs = cache->last_filled_segment_id -
                        cache->last_flushed_segment_id;
  
                used = (victim_segs * 100) / cache->nr_segments;
                
                //                kfdebug("used:%d threshold:high(%u)low(%u), candidates%d, nrsegs:%d", used, wb->high_flush_threshold,wb->low_flush_threshold, victim_segs, cache->nr_segments);

		if (used >=  ACCESS_ONCE(wb->high_flush_threshold))
			cache->allow_flush = true;
		else
			cache->allow_flush = false;

modulator_update:
		old = new;

		schedule_timeout_interruptible(msecs_to_jiffies(intvl));
	}
	return 0;
}

/*----------------------------------------------------------------*/

static void flush_sb(struct wb_cache *cache)
{
	int r;
	struct wb_device *wb = cache->wb;
	struct superblock_device o;
	void *buf;
	struct dm_io_request io_req;
	struct dm_io_region region;

	o.last_flushed_segment_id =
		cpu_to_le32(cache->last_flushed_segment_id);

	buf = mempool_alloc(cache->buf_1_pool, GFP_NOIO | __GFP_ZERO);
	memcpy(buf, &o, sizeof(o));

	io_req = (struct dm_io_request) {
		.client = wb_io_client,
		.bi_rw = WRITE_FUA,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	region = (struct dm_io_region) {
		.bdev = cache->device->bdev,
		.sector = 0,
		.count = 1,
                .rvec_count = 0,                
	};

        RETRY(dm_safe_io(&io_req, 1, &region, NULL, false));
	mempool_free(buf, cache->buf_1_pool);
}

int do_flush_sb(void *data)
{
	struct wb_cache *cache = data;
	struct wb_device *wb = cache->wb;
	unsigned long intvl;

	while (!kthread_should_stop()) {

		wait_on_blockup();

		/* sec -> ms */
		intvl = ACCESS_ONCE(cache->flush_sb_interval) * 1000;

		if (!intvl) {
			schedule_timeout_interruptible(msecs_to_jiffies(1000));
			continue;
		}

		flush_sb(cache);

		schedule_timeout_interruptible(msecs_to_jiffies(intvl));
	}
	return 0;
}

