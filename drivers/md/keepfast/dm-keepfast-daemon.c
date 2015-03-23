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
	struct segment_header *seg = context;
        int ios_nr;

	if (error)
		atomic_inc(&seg->flush_fail_count);

	if (atomic_dec_and_test(&seg->flush_io_count)) 
		wake_up_interruptible(&seg->flush_wait_queue);
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
static int flush_io(struct wb_cache *cache,
			      struct segment_header *seg, size_t k)
{
        struct wb_device *wb = cache->wb;
	struct metablock *mb;        
        struct policy_operation *pop = cache->pop;
        struct cache_entry ce;
        struct sub_entry *se = &ce.se;        
	void *p = cache->flush_buffer + ((cache->nr_blocks_inseg * cache->nr_pages_inblock) << 12) * k;        
        struct dm_io_request io_req_w;
        struct dm_io_region region_w;
        dm_oblock_t oblock;
        unsigned long offset;
	int r;
	u8 i, tag;
        void *base;
        u8 dflag;
        u32 dflag_cnt = 0;
	size_t n1 = 0, n2 = 0;
        int ret = 0;
        u8 *dflags_snapshot = cache->dflags_snapshot;
        u8 *vflags_snapshot = cache->vflags_snapshot;
        u8 *hot_snapshot = cache->hot_snapshot;
	struct dm_io_request io_req_r = {
		.client = wb_io_client,
		.bi_rw = READ,
		.notify.fn = NULL,
		.mem.type = DM_IO_VMA,
		.mem.ptr.vma = p,
	};
        
	struct dm_io_region region_r = {
		.bdev = cache->device->bdev,
		.sector = seg->start_sector + (1 << cache->nr_sectors_per_block_shift),
		.count = cache->nr_blocks_inseg << cache->nr_sectors_per_block_shift,
                .rvec_count = 0,
	};

        ce.seg = seg;

        //        snapshot_cache_entry_info(pop, &ce, dflags_snapshot, vflags_snapshot, hot_snapshot);        

	while (atomic_read(&seg->nr_inflight_ios)) {
		n1++;
		if (n1 == 150){
			KFWARN("inflight ios remained for current seg");
                }
		schedule_timeout_interruptible(msecs_to_jiffies(1));
	}        

        RETRY(dm_safe_io(&io_req_r, 1, &region_r, NULL, false));

        ce.cblock = seg->start_sector + (1 << cache->nr_sectors_per_block_shift);

#if 0
        printk(KERN_INFO"%s- CURRENT SEG:%d(%d), FLUSH SEG:%d(%d), clean region:%d\n", __FUNCTION__,
               cache->current_seg->global_id, cache->current_seg->global_id % cache->nr_segments,
               cache->current_flush_seg->global_id, cache->current_flush_seg->global_id % cache->nr_segments,
               cache->current_flush_seg->global_id % cache->nr_segments - cache->current_seg->global_id % cache->nr_segments);
#endif
	for (i = 0; i < cache->nr_blocks_inseg; i++) {
                u32 idx;
                u8 vflag;

                if(seg == cache->current_seg) {
                        printk(KERN_INFO"%s - seg is current seg", __FUNCTION__);
                        break;
                }

		mb = seg->mb_array + i;
                ce.mb = mb;

                if(entry_is_hot(pop, &ce)) {
                        //                        printk(KERN_INFO"%s - bypass hot:%d, cnt:%d", __FUNCTION__, mb->idx_packed_v >> 4, mb->hit_count);
                        continue;
                }

                //                unpack_dflag(mb->oblock_packed_d, &oblock, &dflag);
                //                unpack_dflag(mb->idx_packed_v, &idx, &vflag);
		offset = (i * cache->nr_pages_inblock) << 12;
		base = p + offset;
                //                printk(KERN_INFO"%s - idx:%d, dirty:%d)", __FUNCTION__, ce.mb->idx_packed_v>>4, ce.dflags);

                // get flags and then get unsymc cblock
                get_entry_and_clear_dirty(pop, &ce);                

                for(tag = 0; tag < 4; tag++) {
                        if(ce.vflags & (1 << tag) &&
                           ce.dflags & (1 << tag)) {
                                se->oblock = ce.oblock + (tag << 3);
                                se->cblock = ce.cblock + (tag << 3);
                                se->tag = tag;

                                io_req_w = (struct dm_io_request) {
                                        .client = wb_io_client,
                                        .bi_rw = WRITE,
                                        .notify.fn = flush_endio,
                                        .notify.context = seg,
                                        .mem.type = DM_IO_VMA,
                                        .mem.ptr.vma = base + (tag << 12),
                                };
                                
                                region_w = (struct dm_io_region) {
                                        .bdev = wb->device->bdev,
                                        .sector = ce.oblock + (tag << 3),
                                        .count = (1 << 3),
                                        .rvec_count = 0,
                                };
                                
                                atomic_inc(&seg->flush_io_count);
                                trace_keepfast_op(&ce, 6);
                                RETRY(dm_safe_io(&io_req_w, 1, &region_w, NULL, false));
                        }
                }
                //                inc_op_stat(cache, STAT_OP_FLUSH, dirty_bits);
                //                trace_keepfast_op(seg, mb, STAT_OP_FLUSH);
	}

        flush_meta(cache, &ce, 0);

        return ret;
}

static void flush_segments(struct wb_cache *cache)
{
	struct wb_device *wb = cache->wb;
        struct policy_operation *pop = cache->pop;        
	struct segment_header *seg;        
	int r;
	size_t k;
        int ret;

flush_write:
	atomic_set(&cache->flush_fail_count, 0);

	k = 0;
	list_for_each_entry(seg, &cache->flush_list, flush_list) {
                //                set_current_flush_seg(pop, seg);
                atomic_set(&cache->current_flush_seg_id, seg->global_id);
                //                cache->current_flush_seg = seg;
		ret = flush_io(cache, seg, k);
                if(ret == -1)
                        break;
		k++;
	}
        atomic_set(&cache->current_flush_seg_id, -1);        

	list_for_each_entry(seg, &cache->flush_list, flush_list) {
                wait_event_interruptible(seg->flush_wait_queue,
                                         atomic_read(&seg->flush_io_count) == 0);
                if(atomic_read(&cache->flush_fail_count)) {
                        KFWARN("%u writebacks failed. retry.",
                               atomic_read(&cache->flush_fail_count));
                        goto flush_write;
                }
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
#if 0        
	list_for_each_entry(seg, &cache->flush_list, flush_list) {
		RETRY(blkdev_issue_discard(cache->device->bdev,
					   seg->start_sector + (1 << 3),
					   seg->length << 3,
					   GFP_NOIO, 0));
	}
#endif        
}

int do_flush(void *data)
{
        struct wb_cache *cache = data;
	struct wb_device *wb = cache->wb;
        struct policy_operation *pop = cache->pop;
        int i;
        bool allow_flush;
        u32 victim_segs, flush_seg;
        struct segment_header *seg, *cur_seg, *tmp;
        u32 nr_max_batch;
        struct segment_header *last_flush_seg = cache->current_seg;
        
        while (!kthread_should_stop()) {
                wait_on_blockup();

		/*
		 * If urge_flush is true
		 * Flush should be immediate.
		 */
		allow_flush = ACCESS_ONCE(cache->allow_flush);

		if (!allow_flush) {
			schedule_timeout_interruptible(msecs_to_jiffies(1000));
			continue;
		}

		nr_max_batch = ACCESS_ONCE(cache->nr_max_batched_flush);
                victim_segs = cache->nr_segs_flush_region;
		victim_segs = min(victim_segs, nr_max_batch);
                
                cur_seg = cache->current_seg;

                for (flush_seg = 1; flush_seg <= victim_segs; flush_seg++) {

			seg = get_segment_header_by_id(
					cache,
                                        cur_seg->global_id + flush_seg);

                        if(!completion_done(&seg->flush_done) || cache->repeat_flush == 1) {
                                INIT_COMPLETION(seg->flush_done);
                                kfdebug("%s - do flush seg:%d, currentid:%d, flush_seg:%d",
                                       __FUNCTION__, seg->global_id, cache->current_seg->global_id, flush_seg);

                                list_add_tail(&seg->flush_list, &cache->flush_list);
                        } else 
                                kfdebug("bypass flush - id:%d, done:%d", seg->global_id, !completion_done(&seg->flush_done));
                }

                //                smp_wmb();
                flush_segments(cache);
                clear_idirty_list(pop);

		list_for_each_entry_safe(seg, tmp,
					 &cache->flush_list,
					 flush_list) {
			list_del(&seg->flush_list);
                        complete_all(&seg->flush_done);                           

                }

                schedule_timeout_interruptible(msecs_to_jiffies(20));                
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

