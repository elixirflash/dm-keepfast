/*
 * keepfast
 * Log-structured Caching for Linux
 *
 * Copyright (C) 2014-2015 Jungmo Ahn <jman@elixirflash.com>
 *
 * This file is released under the GPL.
 */

#include "dm-keepfast.h"
#include "dm-keepfast-metadata.h"
#include "dm-keepfast-daemon.h"
#include "dm-keepfast-policy.h"
#include "dm-keepfast-policy-internal.h"
#include "dm-keepfast-blocktype.h"
#include "../dm-bio-record.h"

#define CREATE_TRACE_POINTS
#include <trace/events/keepfast.h>

EXPORT_TRACEPOINT_SYMBOL(keepfast_op);

#define ARG_EXIST(n) {     \
	if (argc <= (n)) { \
		goto exit_parse_arg; \
	} }

int kf_debug = 0;

struct safe_io {
	struct work_struct work;
	int err;
	unsigned long err_bits;
	struct dm_io_request *io_req;
	unsigned num_regions;
	struct dm_io_region *regions;
};

static void safe_io_proc(struct work_struct *work)
{
	struct safe_io *io = container_of(work, struct safe_io, work);
	io->err_bits = 0;
	io->err = dm_io(io->io_req, io->num_regions, io->regions,
			&io->err_bits);
}

/*----------------------------------------------------------------*/

struct dm_hook_info {
	bio_end_io_t *bi_end_io;
	void *bi_private;
};

/*
 * There are a couple of places where we let a bio run, but want to do some
 * work before calling its endio function.  We do this by temporarily
 * changing the endio fn.
 */

struct per_bio_data {
	void *ptr;
	struct dm_hook_info hook_info;        

	/*
	 * writethrough fields.  These MUST remain at the end of this
	 * structure and the 'cache' member must be the first as it
	 * is used to determine the offset of the writethrough fields.
	 */
	struct wb_cache *cache;
        u8 tag;
	dm_cblock_t cblock;
	struct dm_bio_details bio_details;
};

static void remap_to_origin(struct wb_cache *cache, struct bio *bio)
{
	struct dm_dev *orig = cache->wb->device;
	bio->bi_bdev = orig->bdev;
}

static void remap_to_cache(struct wb_cache *cache, struct bio *bio, sector_t sector)
{
	struct dm_dev *cache_dev = cache->device;
	bio->bi_bdev = cache_dev->bdev;
	bio->bi_sector = sector;        
}

#if 1
static void dm_hook_bio(struct dm_hook_info *h, struct bio *bio,
			bio_end_io_t *bi_end_io, void *bi_private)
{
	h->bi_end_io = bio->bi_end_io;
	h->bi_private = bio->bi_private;

	bio->bi_end_io = bi_end_io;
        bio->bi_private = bi_private;
}

static void dm_unhook_bio(struct dm_hook_info *h, struct bio *bio)
{
	bio->bi_end_io = h->bi_end_io;
	bio->bi_private = h->bi_private;

	/*
	 * Must bump bi_remaining to allow bio to complete with
	 * restored bi_end_io.
	 */
	atomic_inc(&bio->bi_remaining);
}

/*----------------------------------------------------------------*/

static int keepfast_end_io(struct dm_target *ti, struct bio *bio, int error)
{
	struct segment_header *seg;
	struct per_bio_data *map_context =
		dm_per_bio_data(bio, ti->per_bio_data_size);

	if (!map_context->ptr) {
		return 0;
        }

	seg = map_context->ptr;
	atomic_dec(&seg->nr_inflight_ios);

	return 0;
}

#if 0
static void writemeta_endio(struct bio *bio, int err)
{
	struct per_bio_data *pb = dm_per_bio_data(bio, sizeof(struct per_bio_data));

        mb = pb->ptr;

        seg = get_segment_header_by_mb(cache, mb);        
        atomic_dec(&seg->nr_inflight_ios);

	dm_unhook_bio(&pb->hook_info, bio);

        //	dm_bio_restore(&pb->bio_details, bio);
        //	remap_to_cache(pb->cache, bio, pb->cblock);

	/*
	 * We can't issue this bio directly, since we're in interrupt
	 * context.  So it gets put on a bio list for processing by the
	 * worker thread.
	 */
	defer_writemeta_bio(pb->cache, bio);
}
#endif

static void defer_readthrough_bio(struct wb_cache *cache, struct bio *bio);

static void readthrough_endio(struct bio *bio, int err)
{
	struct per_bio_data *pb = dm_per_bio_data(bio, sizeof(struct per_bio_data));

	dm_unhook_bio(&pb->hook_info, bio);
        
	if (err) {
                printk(KERN_INFO"ERR!");
                while(1);
		bio_endio(bio, err);
		return;
	}

        dm_bio_restore(&pb->bio_details, bio);
        bio->bi_rw = WRITE;        
        //	remap_to_cache(pb->cache, bio, pb->cblock);

	/*
	 * We can't issue this bio directly, since we're in interrupt
	 * context.  So it gets put on a bio list for processing by the
	 * worker thread.
	 */

	defer_readthrough_bio(pb->cache, bio);
}

static void wake_worker(struct wb_cache *cache)
{
        queue_work(cache->wq, &cache->worker);
}

static void defer_readthrough_bio(struct wb_cache *cache, struct bio *bio)
{
	unsigned long flags;

	spin_lock_irqsave(&cache->lock, flags);
	bio_list_add(&cache->deferred_readthrough_bios, bio);
	spin_unlock_irqrestore(&cache->lock, flags);

	wake_worker(cache);
}
#if 0
static void defer_writemeta(struct wb_cache *cache, struct bio *bio)
{
	unsigned long flags;

	spin_lock_irqsave(&cache->lock, flags);
	bio_list_add(&cache->deferred_writemeta_bios, bio);
	spin_unlock_irqrestore(&cache->lock, flags);

	wake_worker(cache);
}
#endif

#if 0
static void process_deferred_writemeta_bios(struct cache *cache)
{
	unsigned long flags;
	struct bio_list bios;
	struct bio *bio;
        struct dm_io_request io_req_r, io_req_w;
        struct dm_io_region region_r, region_w;
	struct per_bio_data *pb;        
        struct segment_header *seg;
        struct metablock *mb;
        struct wb_cache *cache;
        void *buf =  mempool_alloc(cache->buf_8_pool, GFP_NOIO);                 

	bio_list_init(&bios);

	spin_lock_irqsave(&cache->lock, flags);
	bio_list_merge(&bios, &cache->deferred_writethrough_bios);
	bio_list_init(&cache->deferred_writethrough_bios);
	spin_unlock_irqrestore(&cache->lock, flags);

	/*
	 * These bios have already been through inc_ds()
	 */
	while ((bio = bio_list_pop(&bios))) {
                pb = dm_per_bio_data(bio, sizeof(struct per_bio_data));
                cache = pb->cache;
                mb = pb->ptr;
                seg = get_segment_header_by_mb(cache, mb);
                
                memset(buf, 0, 4096);
                meta_prepare_for_write(cache, seg, buf);

                io_req_w = (struct dm_io_request) {
                        .client = wb_io_client,
                        .bi_rw = WRITE_FUA, /* No need FUA for RAM */
                        .notify.fn = NULL,
                        .mem.type = DM_IO_KMEM,
                        .mem.ptr.addr = buf,
                };
                region_w = (struct dm_io_region) {
                        .bdev = cache->device->bdev,
                        .sector = seg->start_sector,
                        .count = (1 << 3),
                        .rvec_count = 0,
                };
#if 0
                if(policy_bytealign) {
                        region_w.rvec =  mempool_alloc(cache->buf_8_pool, GFP_NOIO);
                        if(seg->length == 1) {
                                region_w.rvec_count = 2;
                                region_w.rvec[rvec_idx].rv_offset = 0;
                                region_w.rvec[rvec_idx].rv_len = 12;
                                rvec_idx++;
                        } else
                                region_w.rvec_count = 1;
                
                        region_w.rvec[rvec_idx].rv_offset = 512 + sizeof(struct metablock_device) * idx_inseg;
                        region_w.rvec[rvec_idx].rv_len = sizeof(struct metablock_device);
                }
#endif
                RETRY(dm_safe_io(&io_req_w, 1, &region_w, NULL, 0));
        }
        
        mempool_free(region_w.rvec, cache->buf_1_pool);
        mempool_free(buf, cache->buf_8_pool);
}
#endif

static void process_deferred_readthrough_bios(struct wb_cache *cache)
{
	unsigned long flags;
	struct bio_list bios;
	struct bio *bio;
        struct per_bio_data *pb;
        struct metablock *mb;

	bio_list_init(&bios);
        
	spin_lock_irqsave(&cache->lock, flags);
	bio_list_merge(&bios, &cache->deferred_readthrough_bios);
	bio_list_init(&cache->deferred_readthrough_bios);
	spin_unlock_irqrestore(&cache->lock, flags);

	/*
	 * These bios have already been through inc_ds()
	 */
	while ((bio = bio_list_pop(&bios))) {
                pb = dm_per_bio_data(bio, sizeof(struct per_bio_data));

                if(bio_data_dir(bio) == READ) {
                        dm_hook_bio(&pb->hook_info, bio, readthrough_endio, NULL);
                        dm_bio_record(&pb->bio_details, bio);

                        trace_keepfast_worker((u32)bio->bi_sector, 0);
                        remap_to_origin(cache, bio);
                        generic_make_request(bio);
                } else {
                        mb = pb->ptr;
                        pb->ptr = get_segment_header_by_mb(cache, mb);
                        BUG_ON((mb->oblock_packed_d&0xf) & (1 << ((pb->cblock & 31) >> 3)));
                        trace_keepfast_worker(pb->cblock, 1);                                                
                        remap_to_cache(cache, bio, pb->cblock);
                        generic_make_request(bio);
                }
        }        
}

static void do_worker(struct work_struct *ws)
{
        struct wb_cache *cache = container_of(ws, struct wb_cache, worker);

        do {
                process_deferred_readthrough_bios(cache);
        }while(!bio_list_empty(&cache->deferred_readthrough_bios));
}

#endif

/*
 * dm_io wrapper.
 * @thread run this operation in other thread to avoid deadlock.
 */
int dm_safe_io_internal(
		struct wb_device *wb,
		struct dm_io_request *io_req,
		unsigned num_regions, struct dm_io_region *regions,
		unsigned long *err_bits, bool thread, const char *caller)
{
	int err;
	dev_t dev;

	if (thread) {
		struct safe_io io = {
			.io_req = io_req,
			.regions = regions,
			.num_regions = num_regions,
		};

		INIT_WORK_ONSTACK(&io.work, safe_io_proc);

		/*
		 * don't go on submitting I/O
		 * minimizes the risk of breaking the data.
		 */
		wait_on_blockup();
		queue_work(safe_io_wq, &io.work);
		flush_work(&io.work);

		err = io.err;
		if (err_bits)
			*err_bits = io.err_bits;
	} else {
                wait_on_blockup();
		err = dm_io(io_req, num_regions, regions, err_bits);
	}

	dev = regions->bdev->bd_dev;

	/* dm_io routines permits NULL for err_bits pointer. */
	if (err || (err_bits && *err_bits)) {
		unsigned long eb;
		if (!err_bits)
			eb = (~(unsigned long)0);
		else
			eb = *err_bits;
		KFERR("%s() I/O error err(%d, %lu), rw(%d), sector(%llu), dev(%u:%u)",
		      caller, err, eb,
		      io_req->bi_rw, (unsigned long long) regions->sector,
		      MAJOR(dev), MINOR(dev));
	}

	return err;
}

sector_t dm_devsize(struct dm_dev *dev)
{
	return i_size_read(dev->bdev->bd_inode) >> SECTOR_SHIFT;
}

/*----------------------------------------------------------------*/

/** 
 * flush seg or mb
 * 
 * @param seg 
 */
void flush_meta(struct wb_cache *cache, struct cache_entry *ce, bool thread)
{
	struct wb_device *wb = cache->wb;
        int r;
        struct dm_io_request io_req_w;
        struct dm_io_region region_w;
        struct segment_header *seg = ce->seg;
        void *buf =  mempool_alloc(cache->buf_8_pool, GFP_NOIO);
        
#if 0        
        u32 idx_inseg;
        int rvec_idx = 0;

        get_mb_idx_inseg(cache, mb->idx, &idx_inseg);
#endif

        memset(buf, 0, 4096);
        meta_prepare_for_write(cache, seg, buf);

        io_req_w = (struct dm_io_request) {
                .client = wb_io_client,
                .bi_rw = WRITE_FUA, /* No need FUA for RAM */
                .notify.fn = NULL,
                .mem.type = DM_IO_KMEM,
                .mem.ptr.addr = buf,
        };
        region_w = (struct dm_io_region) {
                .bdev = cache->device->bdev,
                .sector = seg->start_sector,
                .count = (1 << 3),
                .rvec_count = 0,
        };
#if 0
        if(policy_bytealign) {
                region_w.rvec =  mempool_alloc(cache->buf_8_pool, GFP_NOIO);
                if(seg->length == 1) {
                        region_w.rvec_count = 2;
                        region_w.rvec[rvec_idx].rv_offset = 0;
                        region_w.rvec[rvec_idx].rv_len = 12;
                        rvec_idx++;
                } else
                        region_w.rvec_count = 1;
                
                region_w.rvec[rvec_idx].rv_offset = 512 + sizeof(struct metablock_device) * idx_inseg;
                region_w.rvec[rvec_idx].rv_len = sizeof(struct metablock_device);
        }
#endif
        RETRY(dm_safe_io(&io_req_w, 1, &region_w, NULL, thread));

        mempool_free(region_w.rvec, cache->buf_1_pool);
        mempool_free(buf, cache->buf_8_pool);       
}

void flush_seg_header(struct wb_cache *cache, struct segment_header *seg, bool thread)
{
	struct wb_device *wb = cache->wb;
        struct dm_io_request io_req_w;
        struct dm_io_region region_w;
        void *buf =  mempool_alloc(cache->buf_1_pool, GFP_NOIO);
        int r;
        
        memset(buf, 0, 512);
        seg_header_prepare_for_write(cache, seg, buf);

        io_req_w = (struct dm_io_request) {
                .client = wb_io_client,
                .bi_rw = WRITE_FUA, /* No need FUA for RAM */
                .notify.fn = NULL,
                .mem.type = DM_IO_KMEM,
                .mem.ptr.addr = buf,
        };
        region_w = (struct dm_io_region) {
                .bdev = cache->device->bdev,
                .sector = seg->start_sector,
                .count = 1,
                .rvec_count = 0,
        };

        RETRY(dm_safe_io(&io_req_w, 1, &region_w, NULL, thread));

        mempool_free(region_w.rvec, cache->buf_1_pool);
        mempool_free(buf, cache->buf_1_pool);
}

/*
 * flush ce of partial dirty, first of all, read from cache-device, and then write to origin-device
 */
void flush_cache_entry(struct wb_cache *cache, struct policy_operation *pop, struct cache_entry *ce)
{
	struct wb_device *wb = cache->wb;
        struct sub_entry *se = &ce->se;                
        struct dm_io_request io_req_r, io_req_w;
        struct dm_io_region region_r, region_w;
        void *buf;
        u8 dflags = ce->dflags;
        u8 vflags = ce->vflags;
        u32 r;
        int tag;

        printk(KERN_INFO"%s - dflags:%d, vflags%d", __FUNCTION__, dflags, vflags);

        buf = mempool_alloc(cache->buf_8_pool, GFP_NOIO);

         for(tag = 0; tag < 4; tag++) {
                if(dflags & (1 << tag) && vflags & (1 << tag)) {        
                        io_req_r = (struct dm_io_request) {
                                .client = wb_io_client,
                                .bi_rw = READ,
                                .notify.fn = NULL,
                                .mem.type = DM_IO_KMEM,
                                .mem.ptr.addr = buf,
                        };
                        region_r = (struct dm_io_region) {
                                .bdev = cache->device->bdev,
                                .sector = ce->cblock + (cache->sectors_per_page * tag),
                                .count = (1 << 3),
                                .rvec_count = 0,
                        };
                        RETRY(dm_safe_io(&io_req_r, 1, &region_r, NULL, true));

                        io_req_w = (struct dm_io_request) {
                                .client = wb_io_client,
                                .bi_rw = WRITE_FUA,
                                .notify.fn = NULL,
                                .mem.type = DM_IO_KMEM,
                                .mem.ptr.addr = buf,
                        };
                        region_w = (struct dm_io_region) {
                                .bdev = wb->device->bdev, 
                                .sector = ce->oblock + (cache->sectors_per_page * tag),
                                .count = (1 << 3),
                                .rvec_count = 0,
                        };

                        RETRY(dm_safe_io(&io_req_w, 1, &region_w, NULL, true));

                        se->tag = tag;
                        policy_clear_dirty(pop, ce);
                        policy_clear_valid(pop, ce);                                        
                        printk(KERN_INFO"%s - flush a sub entry, oblock:%d, cblock:%lld", __FUNCTION__, ce->oblock + (cache->sectors_per_page * tag), region_r.sector);

                }
        }

        mempool_free(buf, cache->buf_8_pool);
        
        flush_meta(cache, ce, 1); /* meta has to write on end_io of data */
}
#if 0
static void remap_to_origin(struct wb_cache *cache, struct bio *bio)
{
	struct dm_dev *orig = cache->wb->device;
	bio->bi_bdev = orig->bdev;
}

static void remap_to_cache(struct wb_cache *cache, struct bio *bio, sector_t sector)
{
	struct dm_dev *cache = cache->device;
	bio->bi_bdev = dev->bdev;
	bio->bi_sector = sector;        
}
#endif

static void bio_remap(struct bio *bio, struct dm_dev *dev, sector_t sector)
{
	bio->bi_bdev = dev->bdev;
	bio->bi_sector = sector;
}

static dm_oblock_t get_bio_block(struct wb_cache *cache, struct bio *bio)
{
	dm_block_t block_nr = (dm_block_t)bio->bi_sector;

        return to_oblock(block_nr);
}

static int keepfast_map(struct dm_target *ti, struct bio *bio)
{
	struct wb_device *wb = ti->private;
	struct wb_cache *cache = wb->cache;
        struct cache_stats *stats = &cache->stats;
	struct dm_dev *orig = wb->device;        
	struct segment_header *uninitialized_var(seg);
        struct cache_entry ce = {0, };
	struct per_bio_data *map_context;
        struct policy_operation *pop = cache->pop;
        enum policy_operation_result presult;
        dm_oblock_t oblock;
        struct sub_entry *se;        
	sector_t bio_count;
	u8 bio_offset;
	u32 tmp32;
	bool bio_full = 0;
        bool is_partial;
	int rw;
        u8 dirty_bits = 0;
        int i;
        u8 dflags_restore = 0;
        int do_flush_meta = 0;
        struct dm_target_io *tio = bio->bi_private;

	if (ACCESS_ONCE(wb->blockup))
		return -EIO;

	map_context = dm_per_bio_data(bio, ti->per_bio_data_size);
	map_context->ptr = NULL;

	/*
	 * We only discard only the backing store because
	 * blocks on cache device are unlikely to be discarded.
	 *
	 * Discarding blocks is likely to be operated
	 * long after writing;
	 * the block is likely to be flushd before.
	 * Moreover,
	 * we discard the segment at the end of flush
	 * and that's enough for discarding blocks.
	 */
	if (bio->bi_rw & REQ_DISCARD) {
                oblock = get_bio_block(cache, bio);                
                printk(KERN_INFO"%s - DISCARD %d remap to origin", __FUNCTION__, oblock);
		bio_remap(bio, orig, bio->bi_sector);
                atomic64_inc(&stats->bypass);
		return DM_MAPIO_REMAPPED;
	}

	/*
	 * defered ACK for barrier writes
	 *
	 * bio with REQ_FLUSH is guaranteed
	 * to have no data.
	 * So, simply queue it and return.
	 */
	if (bio->bi_rw & REQ_FLUSH) {
		BUG_ON(bio->bi_size);
                if(tio->target_bio_nr) 
                        bio_remap(bio, orig, 0);
                else 
                        bio_remap(bio, cache->device, 0);

                atomic64_inc(&stats->bypass);
		return DM_MAPIO_REMAPPED;
        }

        rw = bio_data_dir(bio);
#if 0
        if(rw) {
                if((bio->bi_rw & (REQ_META | REQ_HOT))) {
                        bio_remap(bio, orig, bio->bi_sector);
                        atomic64_inc(&stats->bypass);
                        return DM_MAPIO_REMAPPED;
                }
        }        
#endif
#if 0
        if(bio->bi_rw & REQ_FUA) {
                oblock = get_bio_block(cache, bio);                
                printk(KERN_INFO"%s - FUA %d remap to origin", __FUNCTION__, oblock);
                
                bio_remap(bio, orig, bio->bi_sector);
                atomic64_inc(&stats->bypass);                
                return DM_MAPIO_REMAPPED;
        }
#endif
	bio_count = bio->bi_size >> SECTOR_SHIFT;
	bio_full = (bio_count == (1 << 3));
        
	div_u64_rem(bio->bi_sector, 1 << 3, &tmp32);
	bio_offset = tmp32;

	for (i = bio_offset; i < (bio_offset + bio_count); i++)
                dirty_bits += (1 << i);        

	rw = bio_data_dir(bio);

        oblock = get_bio_block(cache, bio);

        is_partial = (!bio_full || bio_offset);

	mutex_lock(&cache->io_lock);

        presult = policy_map(pop, oblock, &ce);

        se = &ce.se; 

#if 1
        if(is_partial) {
		mutex_unlock(&cache->io_lock);    
                if(presult == POLICY_HIT) {
                        if(se->vflag)  {
                                printk(KERN_INFO"partial hit");
                                policy_remove_mapping(pop, &ce);
                                flush_cache_entry(cache, pop, &ce);
                        } else {
                                printk(KERN_INFO"partial invalid");
                        }
                        
                        atomic_dec(&ce.seg->nr_inflight_ios);
                        rw == 0 ? atomic64_inc(&stats->rhit) : atomic64_inc(&stats->whit);
                } else {
                        printk(KERN_INFO"partial miss");
                        rw == 0 ? atomic64_inc(&stats->rmiss) : atomic64_inc(&stats->wmiss);
                }
                
                bio_remap(bio, orig, oblock);

                printk(KERN_INFO"%s - rw:%d partial sector:%lld (ofs:%d, biocnt:%lld), v:%d, d:%d",
                       __FUNCTION__, rw, bio->bi_sector, bio_offset, bio_count, se->vflag, se->dflag);

                return DM_MAPIO_REMAPPED;
        }
#endif
        
	if (!rw) { /* READ */
                BUG_ON(bio_offset);

                presult == POLICY_HIT ? atomic64_inc(&stats->rhit) : atomic64_inc(&stats->rmiss);

                if(presult == POLICY_MISS) {
                        alloc_cache_entry(pop, &ce);
                        policy_insert_mapping(pop, oblock, &ce);
                        policy_set_valid(pop, &ce);

                        trace_keepfast_op(&ce, 1);
                        atomic64_inc(&stats->rmiss);
                        kfdebug("%s - R(%lld, %d) - missed",
                               __FUNCTION__, bio_count, oblock);

                        mutex_unlock(&cache->io_lock);

                        map_context->cache = cache;
                        map_context->ptr = ce.mb;
                        map_context->cblock = se->cblock;

                        BUG_ON(ce.mb->oblock_packed_d&0xf);

                        defer_readthrough_bio(cache, bio);

                        return DM_MAPIO_SUBMITTED;
                } else if(presult == POLICY_REPLACE) { /* it is for indefinete postponement on flush*/
                        wait_event_interruptible_timeout(ce.seg->flush_wait_queue,
                                                         atomic_read(&cache->current_flush_seg_id) != ce.seg->global_id,
                                                         10*HZ);
                }

                if(!se->vflag) {
                        trace_keepfast_op(&ce, 2);
                        kfdebug("%s - R(%lld, %lld) - invalid", __FUNCTION__, bio_count, bio->bi_sector);
                        atomic64_inc(&stats->rmiss);
                                
                        if(se->dflag) {
                                wait_for_cleaned(pop, &ce);
                        }

                        policy_set_valid(pop, &ce);
                        try_lru_put_hot(pop, &ce); 

                        mutex_unlock(&cache->io_lock);

                        map_context->cache = cache;
                        map_context->ptr = ce.mb;
                        map_context->cblock = se->cblock;

                        BUG_ON(ce.mb->oblock_packed_d&(1<<se->tag));
                        defer_readthrough_bio(cache, bio);

                        return DM_MAPIO_SUBMITTED;
                }
                try_lru_put_hot(pop, &ce); //                

                mutex_unlock(&cache->io_lock);

                trace_keepfast_op(&ce, 0);
                atomic64_inc(&stats->rhit);                
                kfdebug("%s - R(%lld, %d) - hit, readfrom:%d, seg startsec:%d",
                        __FUNCTION__, bio_count, oblock, se->cblock + bio_offset, ce.seg->start_sector);
                
                bio_remap(bio,
                          cache->device,
                          (sector_t)(se->cblock + bio_offset));
                map_context->ptr = ce.seg;

                return DM_MAPIO_REMAPPED;
        } else {  /* WRITE */
                if(presult == POLICY_HIT) {
                        trace_keepfast_op(&ce, 3);
                        atomic64_inc(&stats->whit);

                        if(!(se->vflag && se->dflag))
                                do_flush_meta = 1;

                        try_lru_put_hot(pop, &ce);
                        policy_set_flag(pop, &ce);
                } else if(presult == POLICY_MISS || presult == POLICY_REPLACE) {
                        if(presult == POLICY_REPLACE) {
                                atomic_dec(&ce.seg->nr_inflight_ios);
                                policy_remove_mapping(pop, &ce);
                                dflags_restore = restore_dflag(pop, &ce);
#ifndef UNITTEST
                                if(se->vflag) {
                                        policy_clear_valid(pop, &ce);
                                }
#endif
                                atomic64_inc(&stats->replace);
                        }

                        alloc_cache_entry(pop, &ce);
                        policy_insert_mapping(pop, oblock, &ce);

                        if(presult == POLICY_REPLACE) {
                                trace_keepfast_op(&ce, 5);

                                add_replace_list(pop, &ce, dflags_restore);

                                if(dflags_restore & (1<<se->tag)) {
                                        printk("overwrited before flush.\n");
#if 1                                        
                                        while(ce.mb->oblock_packed_d & (1 << se->tag))
                                                wait_event_interruptible_timeout(ce.seg->flush_wait_queue,
                                                                                 (ce.mb->oblock_packed_d & (1 << se->tag)) == 0,
                                                                                 10*HZ);
#endif                                        
                                }
                        } else if(presult == POLICY_MISS) {
                                trace_keepfast_op(&ce, 4);
                                atomic64_inc(&stats->wmiss);
                                BUG_ON(se->dflag);
                        }

                        policy_set_flag(pop, &ce);
                        do_flush_meta = 1;
                }
        }
        
        mutex_unlock(&cache->io_lock);
        
	map_context->cache = cache;
        map_context->ptr = ce.seg;

        //        defer_writemeta();
        //	dm_hook_bio(&map_context->hook_info, bio, writemeta_endio, NULL);

        if(do_flush_meta)
                flush_meta(cache, &ce, 1); /* meta has to write on end_io of data */

        kfdebug("W(%lld) -wseg:%d, oblock:%d, cblock:%d, idx:%d (cseg:%d inflight ios:%d)] cursor:%d, valid:%lld",
               bio_count,
               ce.seg->global_id  % cache->nr_segments, oblock, se->cblock, ce.mb->idx_packed_v>>4,
               (unsigned int)cache->current_seg->global_id,
               atomic_read(&ce.seg->nr_inflight_ios),
               (unsigned int)cache->cursor,
               atomic64_read(&stats->valid));

        bio_remap(bio, cache->device,
                  (sector_t)(se->cblock + bio_offset));

        return DM_MAPIO_REMAPPED;
}

void clear_cache_stats(struct cache_stats *stats)
{
	atomic64_set(&stats->whit, 0);
	atomic64_set(&stats->rhit, 0);
	atomic64_set(&stats->wmiss, 0);
	atomic64_set(&stats->rmiss, 0);        
	atomic64_set(&stats->dirty, 0);
	atomic64_set(&stats->valid, 0);
	atomic64_set(&stats->hot, 0);        
	atomic64_set(&stats->replace, 0);
	atomic64_set(&stats->flush, 0);
	atomic64_set(&stats->bypass, 0);        
}

static int keepfast_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	bool need_format, allow_format;
	struct wb_device *wb = NULL;
	struct wb_cache *cache = NULL;
	struct dm_dev *origdev = NULL, *cachedev = NULL;
        unsigned long long nr_sects;                
	unsigned long tmp = 0;
	int r = 0;

	r = dm_set_target_max_io_len(ti, (1 << 3));
	if (r) {
		KFERR("settting max io len failed");
		return r;
	}
        
	wb = kzalloc(sizeof(*wb), GFP_KERNEL);
	if (!wb) {
		KFERR("couldn't allocate wb");
		return -ENOMEM;
	}

	init_waitqueue_head(&wb->blockup_wait_queue);
	wb->blockup = false;

	cache = kzalloc(sizeof(*cache), GFP_KERNEL);
	if (!cache) {
		r = -ENOMEM;
		KFERR("couldn'T allocate cache");
                goto bad_alloc_cache;
	}
	wb->cache = cache;
	wb->cache->wb = wb;

	r = dm_get_device(ti, argv[0], dm_table_get_mode(ti->table),
			  &origdev);
	if (r) {
		KFERR("couldn't get backing dev err(%d)", r);
                goto bad_get_device_orig;
	}
	wb->device = origdev;

	r = dm_get_device(ti, argv[1], dm_table_get_mode(ti->table),
			  &cachedev);
	if (r) {
		KFERR("couldn't get cache dev err(%d)", r);
                goto bad_get_device_cache;
	}

        /* it's by sector */
	cache->segment_size_order = 10;
        cache->block_size_order = 5;

	ARG_EXIST(2);
        if (kstrtoull(argv[2], 10, &nr_sects)) {
                KFERR();
		goto bad_segment_size_order;                
        }
        cache->nr_sects = nr_sects;        
        
	ARG_EXIST(3);        
	if (kstrtoul(argv[3], 10, &tmp)) {
		r = -EINVAL;
		goto bad_segment_size_order;
	}

	if (tmp < 4 || 10 < tmp) {
		r = -EINVAL;
		KFERR("segment size order out of range. not 4 <= %lu <= 10", tmp);
		goto bad_segment_size_order;
	}
	cache->segment_size_order = tmp;

        spin_lock_init(&cache->cursor_lock);        

exit_parse_arg:
        cache->nr_sectors_per_block_shift = 5;
                
	r = audit_cache_device(cachedev, cache, &need_format, &allow_format);
	if (r) {
		KFERR("audit cache device fails err(%d)", r);
		goto bad_audit_cache;
	}

	if (need_format) {
		if (allow_format) {
			r = format_cache_device(cachedev, cache);
			if (r) {
				KFERR("format cache device fails err(%d)", r);
				goto bad_format_cache;
			}
		} else {
			r = -EINVAL;
			KFERR("cache device not allowed to format");
			goto bad_audit_cache;
		}
	}

        clear_cache_stats(&cache->stats);

	r = resume_cache(cache, cachedev);
	if (r) {
		KFERR("failed to resume cache err(%d)", r);
		goto bad_resume_cache;
	}

	cache->wq = alloc_ordered_workqueue("dm-" "keepfast", WQ_MEM_RECLAIM);
	if (!cache->wq) {
                goto bad_wq;
	}        
        INIT_WORK(&cache->worker, do_worker);

	wb->ti = ti;
	ti->private = wb;
        
	ti->per_bio_data_size = sizeof(struct per_bio_data);
        
	/*
	 * Any write barrier requests should
	 * not be ignored for any reason.
	 *
	 * That barriers are accepted for
	 * any combination of underlying devices
	 * makes it easier to find bug regarding
	 * the barriers.
	 *
	 * dm-cache and dm-thin also turned
	 * this flag on.
	 */
	ti->flush_supported = true;

	ti->num_flush_bios = 2;
	ti->num_discard_bios = 2;
        
	ti->discard_zeroes_data_unsupported = true;

	return 0;

bad_wq:
        destroy_workqueue(cache->wq);
bad_resume_cache:
bad_format_cache:
bad_audit_cache:
bad_segment_size_order:
	dm_put_device(ti, cachedev);
bad_get_device_cache:
	dm_put_device(ti, origdev);
bad_get_device_orig:
	kfree(cache);
bad_alloc_cache:
	kfree(wb);
        
	return r;
}

static void keepfast_dtr(struct dm_target *ti)
{
	struct wb_device *wb = ti->private;
	struct wb_cache *cache = wb->cache;

        flush_workqueue(safe_io_wq);
        destroy_workqueue(cache->wq);
	free_cache(cache);
	kfree(cache);
	dm_put_device(wb->ti, cache->device);
	dm_put_device(ti, wb->device);
	ti->private = NULL;
	kfree(wb);
}
 
static int keepfast_message(struct dm_target *ti, unsigned argc, char **argv)
{
	struct wb_device *wb = ti->private;
	struct wb_cache *cache = wb->cache;
        struct policy_operation *pop = cache->pop;        
        
	char *cmd = argv[0];
	unsigned long tmp;

	if (kstrtoul(argv[1], 10, &tmp))
		return -EINVAL;

	if (!strcasecmp(cmd, "blockup")) {
		if (tmp > 1)
			return -EINVAL;
		wb->blockup = tmp;
		wake_up(&wb->blockup_wait_queue);
		return 0;
	}

	if (!strcasecmp(cmd, "allow_flush")) {
		cache->allow_flush = tmp;
		return 0;
	}

	if (!strcasecmp(cmd, "repeat_flush")) {
		if (tmp > 1)
			return -EINVAL;
		cache->repeat_flush = tmp;
                cache->nr_segs_flush_region = cache->nr_segments - 2;
		return 0;
	}

	if (!strcasecmp(cmd, "flush_region")) {
		cache->repeat_flush = 0;
                if(tmp > cache->nr_segments - 2)
                        return -EINVAL;
                cache->nr_segs_flush_region = tmp;
		return 0;
	}        

	if (!strcasecmp(cmd, "check_flags")) {
		if (tmp > 1)
			return -EINVAL;

                check_flags(pop);

		return 0;
	}        

	if (!strcasecmp(cmd, "run_around")) {
                run_around_segment(pop);
		return 0;
	}        

	if (!strcasecmp(cmd, "barrier_deadline_ms")) {
		if (tmp < 1)
			return -EINVAL;
		cache->barrier_deadline_ms = tmp;
		return 0;
	}

	if (!strcasecmp(cmd, "nr_max_batched_flush")) {
		if (tmp < 1)
			return -EINVAL;
		cache->nr_max_batched_flush = tmp;
		return 0;
	}

	return -EINVAL;
}

static int keepfast_merge(struct dm_target *ti, struct bvec_merge_data *bvm,
			    struct bio_vec *biovec, int max_size)
{
	struct wb_device *wb = ti->private;
	struct dm_dev *device = wb->device;
	struct request_queue *q = bdev_get_queue(device->bdev);

	if (!q->merge_bvec_fn)
		return max_size;

	return min(max_size, q->merge_bvec_fn(q, bvm, biovec));
	bvm->bi_bdev = device->bdev;
}

static int keepfast_iterate_devices(struct dm_target *ti,
				      iterate_devices_callout_fn fn, void *data)
{
	struct wb_device *wb = ti->private;
	struct dm_dev *orig = wb->device;
	sector_t start = 0;
	sector_t len = dm_devsize(orig);
	return fn(ti, orig, start, len, data);
}

static void keepfast_io_hints(struct dm_target *ti,
				struct queue_limits *limits)
{
	blk_limits_io_min(limits, 512);
	blk_limits_io_opt(limits, 4096);
}

static void keepfast_status(struct dm_target *ti, status_type_t type,
			      unsigned flags, char *result, unsigned maxlen)
{
	struct wb_device *wb = ti->private;
        struct wb_cache *cache = wb->cache;
        struct cache_stats *stats = &cache->stats;
        u32 sz = 0;

        u64 whit = atomic64_read(&stats->whit);
        u64 rhit = atomic64_read(&stats->rhit);
        u64 wmiss = atomic64_read(&stats->wmiss);
        u64 rmiss = atomic64_read(&stats->rmiss);
        u64 flush = atomic64_read(&stats->flush);
        u64 bypass = atomic64_read(&stats->bypass);
        u64 replace = atomic64_read(&stats->replace);
        u64 valid = atomic64_read(&stats->valid);
        u64 dirty = atomic64_read(&stats->dirty);
        u64 hot = atomic64_read(&stats->hot);

        DMEMIT("\n");
        DMEMIT("%15s : %10d\n", "current seg", cache->current_seg->global_id);
        DMEMIT("%15s : %10d\n", "victim segs", cache->nr_segs_flush_region);
        DMEMIT("%15s : %10d\n", "batched segs", cache->nr_max_batched_flush); 
        DMEMIT( "%15s : %10d segs\n", "segments", cache->nr_segments);
        DMEMIT( "%15s : %10d entries\n", "cache entries",
                cache->nr_segments * cache->nr_blocks_inseg);
        
        DMEMIT("%15s : %10d entries\n", "sub entries",
               cache->nr_segments * cache->nr_blocks_inseg * cache->nr_pages_inblock);

        DMEMIT("%15s : %10d %% \n", "cache rate",
               (u32)div_u64(valid * 100, cache->nr_segments * cache->nr_blocks_inseg * cache->nr_pages_inblock));        

        DMEMIT("%15s : %10d %% \n", "dirty rate",
               (u32)div_u64(dirty * 100, cache->nr_segments * cache->nr_blocks_inseg * cache->nr_pages_inblock));
        
        DMEMIT("%15s : %10lld sentries\n", "dirty", dirty);
        DMEMIT("%15s : %10lld sentries\n", "valid", valid);
        DMEMIT("%15s : %10lld centries\n", "hot", hot);        

        DMEMIT("%15s : %10d %% \n", "hit rate",
               (u32)div_u64((whit + rhit + replace) * 100, whit + rhit + wmiss + rmiss + replace));        
        DMEMIT("%15s : %10lld sentries\n", "write hit", whit);
        DMEMIT("%15s : %10lld sentries\n", "write miss", wmiss);
        DMEMIT("%15s : %10lld sentries\n", "read hit", rhit);
        DMEMIT("%15s : %10lld sentries\n", "read miss", rmiss);
        DMEMIT("%15s : %10lld sentries\n", "replace", replace);
        
        DMEMIT("%15s : %10lld sentries\n", "flush", flush);
        DMEMIT("%15s : %10lld sentries\n", "bypass", bypass);
}

struct target_type keepfast_target = {
	.name = "keepfast",
	.version = {0, 1, 0},
	.module = THIS_MODULE,
	.map = keepfast_map,
        .ctr = keepfast_ctr,
	.dtr = keepfast_dtr,
	.end_io = keepfast_end_io,
	.merge = keepfast_merge,
	.message = keepfast_message,
	.status = keepfast_status,
	.io_hints = keepfast_io_hints,
	.iterate_devices = keepfast_iterate_devices,
};

struct dm_io_client *wb_io_client;
struct workqueue_struct *safe_io_wq;
 
static int __init keepfast_module_init(void)
{
	int r = 0;

	r = dm_register_target(&keepfast_target);
	if (r < 0) {
		KFERR("%d", r);
		return r;
	}

	r = -ENOMEM;

	safe_io_wq = alloc_workqueue("safeiowq",
				     WQ_NON_REENTRANT | WQ_MEM_RECLAIM, 0);
	if (!safe_io_wq) {
		KFERR("failed to alloc safe_io_wq");
		goto bad_wq;
	}

	wb_io_client = dm_io_client_create();
	if (IS_ERR(wb_io_client)) {
		KFERR("failed to alloc wb_io_client");
		r = PTR_ERR(wb_io_client);
		goto bad_io_client;
	}

	return 0;

bad_io_client:
	destroy_workqueue(safe_io_wq);
bad_wq:
	dm_unregister_target(&keepfast_target);

	return r;
}

static void __exit keepfast_module_exit(void)
{
	dm_io_client_destroy(wb_io_client);
	destroy_workqueue(safe_io_wq);

	dm_unregister_target(&keepfast_target);
}

module_init(keepfast_module_init);
module_exit(keepfast_module_exit);

MODULE_AUTHOR("Jungmo Ahn <jman@elixirflash.com>");
MODULE_DESCRIPTION(DM_NAME " keepfast target");
MODULE_LICENSE("GPL");
