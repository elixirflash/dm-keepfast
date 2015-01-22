/*
 * keepfast
 * Log-structured Caching for Linux
 *
 * Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This file is released under the GPL.
 */

#include "dm-keepfast.h"
#include "dm-keepfast-metadata.h"
#include "dm-keepfast-daemon.h"
#include "dm-keepfast-policy.h"
#include "dm-keepfast-policy-internal.h"
#include "dm-keepfast-blocktype.h"

#define CREATE_TRACE_POINTS
#include <trace/events/keepfast.h>

EXPORT_TRACEPOINT_SYMBOL(keepfast_op);

#define ARG_EXIST(n) {     \
	if (argc <= (n)) { \
		goto exit_parse_arg; \
	} }

int kf_debug = 1;

#define FLAG_MASK     0x3

/* SYSFS */
static ssize_t cache_stats_show(struct device *dev,
				  struct device_attribute *attr, char *page)
{
	struct gendisk *disk = dev_to_disk(dev);
	struct mapped_device *md = disk->private_data;
        struct dm_target *ti = dm_table_get_target(dm_get_live_table(md), 0);
	struct wb_device *wb = ti->private;
        struct wb_cache *cache = wb->cache;
	struct segment_header *current_seg = cache->current_seg;
        u32 lap;
        u64 lfilled = atomic64_read(&cache->last_fulled_segment_id);
        u64 lflushed = atomic64_read(&cache->last_migrated_segment_id);
        u32 caching_segs = lfilled - lflushed;

        u64 hit_read_full = atomic64_read(&cache->stat[(1 << STAT_HIT) + (1 << STAT_FULLSIZE)]);
        u64 hit_read_partial = atomic64_read(&cache->stat[(1 << STAT_HIT)]);
        u64 hit_read = hit_read_full + hit_read_partial;
        u64 hit_write_full = atomic64_read(&cache->stat[(1 << STAT_HIT) + (1 << STAT_WRITE) + (1 << STAT_FULLSIZE)]);
        u64 hit_write_partial = atomic64_read(&cache->stat[(1 << STAT_HIT) + (1 << STAT_WRITE)]);
        u64 hit_write = hit_write_full + hit_write_partial;

        u64 miss_read_full = atomic64_read(&cache->stat[(1 << STAT_FULLSIZE)]);
        u64 miss_read_partial = atomic64_read(&cache->stat[0]);
        u64 miss_read = miss_read_full + miss_read_partial;
        u64 miss_write_full = atomic64_read(&cache->stat[(1 << STAT_WRITE) + (1 << STAT_FULLSIZE)]);
        u64 miss_write_partial = atomic64_read(&cache->stat[(1 << STAT_WRITE)]);
        u64 miss_write = miss_write_full + miss_write_partial;

        u64 bypass = atomic64_read(&cache->op_stat[STAT_OP_BYPASS]);
        u64 inv = atomic64_read(&cache->op_stat[STAT_OP_INV]);
        u64 flush = atomic64_read(&cache->op_stat[STAT_OP_FLUSH]);

        u32 segs = cache->nr_segments;

        u32 hit_rate = (u32)((hit_write + hit_read) / 8) / (u32)((hit_write + hit_read + miss_write + miss_read + bypass) / 8) * 100;

        lap = cpu_to_le32(calc_segment_lap(cache, current_seg->global_id));

        return snprintf(page, PAGE_SIZE,
                        "total segs    : %10d, segs"
                        "current seg   : %10lld, lap:%10d\n"
                        "caching segs  : %10d segments(last filled:%10lld, Last flushed:%10lld)\n"
                        "cache hit rate: %10d  \n"
                       "bypass(write) : %10lld sectors\n"                        
                        "hit read      : %10lld sectors(full:%10lld, partial:%10lld)\n"
                        "hit write     : %10lld sectors(full:%10lld, partial:%10lld)\n"
                        "miss read     : %10lld sectors(full:%10lld, partial:%10lld)\n"
                        "miss write    : %10lld sectors(full:%10lld, partial:%10lld)\n"
                        "invalidate    : %10lld sectors\n"
                        "flush         : %10lld sectors\n"
                        "8 sectors per cacheline(4k)\n",
                        segs, current_seg->global_id, lap,
                        caching_segs, lfilled, lflushed, hit_rate, bypass,
                        hit_read, hit_read_full, hit_read_partial,
                        hit_write, hit_write_full, hit_write_partial,
                        miss_read, miss_read_full, miss_read_partial,
                        miss_write, miss_write_full, miss_write_partial,
                        inv, flush);        
}

static DEVICE_ATTR(cache_stats, S_IRUGO, cache_stats_show, NULL);

static struct attribute *keepfast_attrs[] = {
	&dev_attr_cache_stats.attr,
	NULL,
};

static const struct attribute_group keepfast_attr_group = {
	.attrs = keepfast_attrs,
};

static __le64 pack_value(dm_block_t block, unsigned tag)
{
	u32 value = block;
	value <<= 2;
	value = value | (tag & FLAG_MASK);
	return cpu_to_le32(value);
}

static void unpack_value(__le32 value_le, dm_block_t *block, unsigned *tag)
{
	uint32_t value = le32_to_cpu(value_le);
	*block = value >> 2;
	*tag = value & FLAG_MASK;
}

/*----------------------------------------------------------------*/

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

void inc_nr_dirty_caches(struct wb_device *wb)
{
	BUG_ON(!wb);
	atomic64_inc(&wb->nr_dirty_caches);
}

void dec_nr_dirty_caches(struct wb_device *wb)
{
	BUG_ON(!wb);
	atomic64_dec(&wb->nr_dirty_caches);
}

u8 atomic_read_mb_dirtiness(struct segment_header *seg, struct metablock *mb)
{
	unsigned long flags;
	u8 r;

	lockseg(seg, flags);
	r = mb->dirty_bits;
	unlockseg(seg, flags);

	return r;
}

void inc_op_stat(struct wb_cache *cache, int op, int val)
 {
 	atomic64_t *v;
        int i = 0;
        u64 blocks = 0;

        if(op == STAT_OP_BYPASS)
                blocks = val;
        else {
                for (; i < 8; i++) {
                        bool b = val & (1 << i);
                        if(b)
                                blocks++;
                }
        }

        if(op == STAT_OP_FLUSH)
                v = &cache->op_stat[STAT_OP_FLUSH];
        else if(op == STAT_OP_INV)
                v = &cache->op_stat[STAT_OP_INV];
        else 
                v = &cache->op_stat[STAT_OP_BYPASS];

        atomic64_add(blocks, v); 
}

void inc_stat(struct wb_cache *cache, int rw, bool found, int blocks)
{
	atomic64_t *v;
        int i = 0;

	if (rw)
		i |= (1 << STAT_WRITE);
	if (found)
		i |= (1 << STAT_HIT);
	if (blocks == 8)
		i |= (1 << STAT_FULLSIZE);

	v = &cache->stat[i];

        atomic64_add((u64)blocks, v);
}

static void clear_stat(struct wb_cache *cache)
{
	int i;
	for (i = 0; i < STATLEN; i++) {
		atomic64_t *v = &cache->stat[i];
		atomic64_set(v, 0);
	}
}

/** 
 * flush seg or mb
 * 
 * @param seg 
 */
void flush_meta(struct wb_cache *cache, struct cache_entry *centry)
{
	struct wb_device *wb = cache->wb;
        int r;
        struct dm_io_request io_req_w;
        struct dm_io_region region_w;
        struct segment_header *seg = centry->seg;
        struct metablock *mb = centry->mb;
        u32 idx_inseg;
        int rvec_idx = 0;
        void *buf =  mempool_alloc(cache->buf_8_pool, GFP_NOIO);        

        get_mb_idx_inseg(cache, mb->idx, &idx_inseg);
        meta_prepare_for_write(buf, cache, centry->seg, idx_inseg);

        io_req_w = (struct dm_io_request) {
                .client = wb_io_client,
                .bi_rw = WRITE, /* No need FUA for RAM */
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

        RETRY(dm_safe_io(&io_req_w, 1, &region_w, NULL, true));

        mempool_free(region_w.rvec, cache->buf_1_pool);
        mempool_free(buf, cache->buf_8_pool);       
}

/*
 * Migrate a data on the cache device
 */
static void flush_cache(struct wb_cache *cache, struct cache_entry *centry, bool thread)
{
	struct wb_device *wb = cache->wb;
        struct metablock *mb = centry->mb;
        u8 dirty_bits = mb->dirty_bits;
        sector_t cblock = centry->cblock;
	int r;        

	if (!dirty_bits)
		return;

	if (dirty_bits == 255) {
		void *buf = mempool_alloc(cache->buf_8_pool, GFP_NOIO);
		struct dm_io_request io_req_r, io_req_w;
		struct dm_io_region region_r, region_w;

		io_req_r = (struct dm_io_request) {
			.client = wb_io_client,
			.bi_rw = READ,
			.notify.fn = NULL,
			.mem.type = DM_IO_KMEM,
			.mem.ptr.addr = buf,
		};
		region_r = (struct dm_io_region) {
			.bdev = cache->device->bdev,
			.sector = cblock,
			.count = (1 << 3),
		};
		RETRY(dm_safe_io(&io_req_r, 1, &region_r, NULL, thread));

		io_req_w = (struct dm_io_request) {
			.client = wb_io_client,
			.bi_rw = WRITE_FUA,
			.notify.fn = NULL,
			.mem.type = DM_IO_KMEM,
			.mem.ptr.addr = buf,
		};
		region_w = (struct dm_io_region) {
			.bdev = wb->device->bdev,
			.sector = mb->oblock,
			.count = (1 << 3),
		};
		RETRY(dm_safe_io(&io_req_w, 1, &region_w, NULL, thread));

		mempool_free(buf, cache->buf_8_pool);
	} else {
		void *buf = mempool_alloc(cache->buf_1_pool, GFP_NOIO);
		size_t i;
                
		for (i = 0; i < 8; i++) {
			bool bit_on = dirty_bits & (1 << i);
			struct dm_io_request io_req_r, io_req_w;
			struct dm_io_region region_r, region_w;
			sector_t src;

			if (!bit_on)
				continue;

			io_req_r = (struct dm_io_request) {
				.client = wb_io_client,
				.bi_rw = READ,
				.notify.fn = NULL,
				.mem.type = DM_IO_KMEM,
				.mem.ptr.addr = buf,
			};
			/* A tmp variable just to avoid 80 cols rule */
			src = cblock + i;
			region_r = (struct dm_io_region) {
				.bdev = cache->device->bdev,
				.sector = src,
				.count = 1,
			};
			RETRY(dm_safe_io(&io_req_r, 1, &region_r, NULL, thread));

			io_req_w = (struct dm_io_request) {
				.client = wb_io_client,
				.bi_rw = WRITE,
				.notify.fn = NULL,
				.mem.type = DM_IO_KMEM,
				.mem.ptr.addr = buf,
			};
			region_w = (struct dm_io_region) {
				.bdev = wb->device->bdev,
				.sector = mb->oblock + 1 * i,
				.count = 1,
			};
                        printk(KERN_INFO"read cblock:%lld, write oblock:%lld",src, region_w.sector);
			RETRY(dm_safe_io(&io_req_w, 1, &region_w, NULL, thread));
		}
		mempool_free(buf, cache->buf_1_pool);
	}
}

static void bio_remap(struct bio *bio, struct dm_dev *dev, sector_t sector)
{
	bio->bi_bdev = dev->bdev;
	bio->bi_sector = sector;
}

static dm_oblock_t get_bio_block(struct wb_cache *cache, struct bio *bio)
{
	dm_block_t block_nr = (dm_block_t)bio->bi_sector;

        //        do_div(block_nr, 1 << cache->block_size_order) * (1 << cache->block_size_order);

        return to_oblock(block_nr);
}

static int keepfast_map(struct dm_target *ti, struct bio *bio)
{
	struct segment_header *uninitialized_var(seg);
        struct cache_entry centry = {NULL, NULL, 0 , 0};
	struct per_bio_data *map_context;
	sector_t bio_count;
	u8 bio_offset;
	u32 tmp32;
	bool bio_fullsize;
	int rw;
        u8 i;
        u8 dirty_bits = 0;        

	struct wb_device *wb = ti->private;
	struct wb_cache *cache = wb->cache;
	struct dm_dev *orig = wb->device;

        struct policy_operation *pop = cache->pop;
        enum policy_operation_result presult;
        dm_oblock_t oblock;

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
	 * the block is likely to be migrated before.
	 * Moreover,
	 * we discard the segment at the end of migration
	 * and that's enough for discarding blocks.
	 */
	if (bio->bi_rw & REQ_DISCARD) {
		bio_remap(bio, orig, bio->bi_sector);
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
                bio_remap(bio, orig, bio->bi_sector);
		return DM_MAPIO_REMAPPED;
        }

        rw = bio_data_dir(bio);
#if 1
        if(rw) {
                if(!(bio->bi_rw & (REQ_META | REQ_HOT))) {
                        bio_remap(bio, orig, bio->bi_sector);
                        return DM_MAPIO_REMAPPED;
                }
       }        
#endif
        if(bio->bi_rw & REQ_FUA) {
                bio_remap(bio, orig, bio->bi_sector);
                return DM_MAPIO_REMAPPED;                       
        }

	bio_count = bio->bi_size >> SECTOR_SHIFT;
	bio_fullsize = (bio_count == (1 << 3));
	div_u64_rem(bio->bi_sector, 1 << 3, &tmp32);
	bio_offset = tmp32;

	rw = bio_data_dir(bio);

        oblock = get_bio_block(cache, bio);

	/*
	 * (Locking)
	 * Why mutex?
	 *
	 * The reason we use mutex instead of rw_semaphore
	 * that can allow truely concurrent read access
	 * is that mutex is even lighter than rw_semaphore.
	 * Since dm-writebuffer is a real performance centric software
	 * the overhead of rw_semaphore is crucial.
	 * All in all,
	 * since exclusive region in read path is enough small
	 * and cheap, using rw_semaphore and let the reads
	 * execute concurrently won't improve the performance
	 * as much as one expects.
	 */
	mutex_lock(&cache->io_lock);
        presult = policy_lookup(pop, oblock, &centry);

        //	inc_stat(cache, rw, found, bio_count);
        //        kfdebug("cache stat:RM:%d, WM:%d, RH:%d, WH:%d", (int)cache->stat[0], (unsigned int)cache->stat[1], (unsigned int)cache->stat[2], (unsigned int)cache->stat[3]);

	if (!rw) { /* READ */
		mutex_unlock(&cache->io_lock);

                if(presult == POLICY_MISS) {
			bio_remap(bio, orig, bio->bi_sector);
			return DM_MAPIO_REMAPPED;
		} else if(presult == POLICY_HIT) {
                        if (likely(centry.mb->dirty_bits == 255)) {
                                bio_remap(bio,
                                          cache->device,
                                          centry.cblock + bio_offset);
                                map_context->ptr = centry.seg;
                                //TRACING
                                centry.mb->rhits++;
                                trace_keepfast_op(centry.seg, centry.mb, STAT_OP_READ);
                        } else {
                                printk(KERN_INFO"PARTIALDIRTY read, flush cache");
                                flush_cache(cache, &centry, true);
                        
                                inc_op_stat(cache, STAT_OP_INV, dirty_bits);
                                trace_keepfast_op(centry.seg, centry.mb, STAT_OP_INV);
                        
                                policy_clear_dirty(pop, &centry);
                                atomic_dec(&centry.seg->nr_inflight_ios);

                                if(policy_overwrite)
                                        add_invalid_centry(pop, &centry);
                        
                                bio_remap(bio, orig, bio->bi_sector);
                        }
                        return DM_MAPIO_REMAPPED;
                }
	} else { /* WRITE */
                if(presult == POLICY_HIT) {
                        bool needs_cleanup_prev_cache =
                                !bio_fullsize || !(centry.mb->dirty_bits == 255);

                        if (!centry.mb->dirty_bits)
                                needs_cleanup_prev_cache = false;

                        if (unlikely(needs_cleanup_prev_cache)) {
                                //                        wait_for_completion(&seg->flush_done);
                                inc_op_stat(cache, STAT_OP_INV, centry.mb->dirty_bits);
                                //TRACEING
                                trace_keepfast_op(centry.seg, centry.mb, STAT_OP_INV);
                                flush_cache(cache, &centry, true);
                        } else
                                centry.mb->whits++;

                        policy_clear_dirty(pop, &centry);

                        if(!policy_overwrite) {
                                policy_remove_mapping(pop, &centry);
                                //???????????????? atomic_dec(&centry.seg->nr_inflight_ios);
                                
                                alloc_cache_entry(pop, &centry);
                                policy_insert_mapping(pop, oblock, &centry);
                        }
                }else if(presult == POLICY_MISS)  {
                        alloc_cache_entry(pop, &centry);
                        policy_insert_mapping(pop, oblock, &centry);
                }
        }

	mutex_unlock(&cache->io_lock);

	if (likely(bio_fullsize)) {
                policy_set_dirty(pop, &centry);
	} else {
		for (i = bio_offset; i < (bio_offset + bio_count); i++)
			dirty_bits += (1 << i);

                centry.set_partial_dirty = dirty_bits;
                policy_set_dirty(pop, &centry);
	}
	BUG_ON(!centry.mb->dirty_bits);

        flush_meta(cache, &centry);
        
        bio_remap(bio, cache->device,
                  centry.cblock + bio_offset);
        
        trace_keepfast_op(centry.seg, centry.mb, STAT_OP_WRITE);
        map_context->ptr = centry.seg;
        
        kfdebug("oblock:%d,cblock:%d inflight ios:%d, remap to cache, mb idx:%d, LM:%lld, LF:%lldi SID:%lld, cursor:%d",
                centry.mb->oblock, centry.cblock,
               atomic_read(&centry.seg->nr_inflight_ios), centry.mb->idx,
               (long long unsigned int)
               atomic64_read(&cache->last_migrated_segment_id),
               (long long unsigned int)
               atomic64_read(&cache->last_fulled_segment_id),
               (long long unsigned int)
               cache->current_seg->global_id,
               (unsigned int)
               cache->cursor);                       
        
        return DM_MAPIO_REMAPPED;
}

static int keepfast_end_io(struct dm_target *ti, struct bio *bio, int error)
{
	struct wb_device *wb = ti->private;
	struct wb_cache *cache = wb->cache;        
	struct segment_header *seg;
	struct per_bio_data *map_context =
		dm_per_bio_data(bio, ti->per_bio_data_size);
        
	if (!map_context->ptr) {
		return 0;
        }
        
	seg = map_context->ptr;
        
	atomic_dec(&seg->nr_inflight_ios);
        
        if(seg->last_mb_in_segment) {
                seg->last_mb_in_segment = 0;
		atomic64_set(&cache->last_fulled_segment_id, seg->global_id);
        }
        
	return 0;
}

/*
 * <backing dev> <cache dev>
 * [segment size order]
 * [rambuf pool amount]
 */

static int keepfast_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	bool need_format, allow_format;
	struct wb_device *wb = NULL;
	struct wb_cache *cache = NULL;
	struct dm_dev *origdev = NULL, *cachedev = NULL;
        unsigned long long nr_sects;                
	unsigned long tmp = 0;
        struct mapped_device *md = dm_table_get_md(ti->table);
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
	atomic64_set(&wb->nr_dirty_caches, 0);
	/*
	 * EMC's textbook on storage system says
	 * storage should keep its disk util less
	 * than 70%.
	 */
        wb->high_migrate_threshold = 90;
	wb->low_migrate_threshold = 70;

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

	/* Optional Parameters */
	cache->segment_size_order = 7;
        cache->block_size_order = 4;

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
	r = audit_cache_device(cachedev, cache, &need_format, &allow_format);
	if (r) {
		KFERR("audit cache device fails err(%d)", r);
		/*
		 * If something happens in auditing the cache
		 * such as read io error either go formatting
		 * or resume it trusting the cache is valid
		 * are dangerous. So we quit.
		 */
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

	r = resume_cache(cache, cachedev);
	if (r) {
		KFERR("failed to resume cache err(%d)", r);
		goto bad_resume_cache;
	}
	clear_stat(cache);

        r = sysfs_create_group(&disk_to_dev(dm_disk(md))->kobj, &keepfast_attr_group);
	if (r)
		goto bad_sysfs;        

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

	ti->num_flush_bios = 1;
	ti->num_discard_bios = 1;
        
	ti->discard_zeroes_data_unsupported = true;

	return 0;

bad_sysfs:
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
        struct mapped_device *md = dm_table_get_md(ti->table);        

	free_cache(cache);
	kfree(cache);

        sysfs_remove_group(&disk_to_dev(dm_disk(md))->kobj, &keepfast_attr_group);

	dm_put_device(wb->ti, cache->device);
	dm_put_device(ti, wb->device);

	ti->private = NULL;
	kfree(wb);
}
 
static int keepfast_message(struct dm_target *ti, unsigned argc, char **argv)
{
	struct wb_device *wb = ti->private;
	struct wb_cache *cache = wb->cache;
        
	char *cmd = argv[0];
	unsigned long tmp;

	if (!strcasecmp(cmd, "clear_stat")) {
		struct wb_cache *cache = wb->cache;
		clear_stat(cache);
		return 0;
	}

	if (kstrtoul(argv[1], 10, &tmp))
		return -EINVAL;

	if (!strcasecmp(cmd, "blockup")) {
		if (tmp > 1)
			return -EINVAL;
		wb->blockup = tmp;
		wake_up(&wb->blockup_wait_queue);
		return 0;
	}

	if (!strcasecmp(cmd, "allow_migrate")) {
		if (tmp > 1)
			return -EINVAL;
		cache->allow_migrate = tmp;
		return 0;
	}

	if (!strcasecmp(cmd, "enable_migration_modulator")) {
		if (tmp > 1)
			return -EINVAL;
		cache->enable_migration_modulator = tmp;
		return 0;
	}

	if (!strcasecmp(cmd, "barrier_deadline_ms")) {
		if (tmp < 1)
			return -EINVAL;
		cache->barrier_deadline_ms = tmp;
		return 0;
	}

	if (!strcasecmp(cmd, "nr_max_batched_migration")) {
		if (tmp < 1)
			return -EINVAL;
		cache->nr_max_batched_migration = tmp;
		return 0;
	}

	if (!strcasecmp(cmd, "migrate_threshold")) {
		wb->high_migrate_threshold = tmp;
                wb->low_migrate_threshold = tmp / 2;
		return 0;
	}

	if (!strcasecmp(cmd, "update_record_interval")) {
		cache->update_record_interval = tmp;
		return 0;
	}

	if (!strcasecmp(cmd, "sync_interval")) {
		cache->sync_interval = tmp;
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

	bvm->bi_bdev = device->bdev;
	return min(max_size, q->merge_bvec_fn(q, bvm, biovec));
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
	unsigned int sz = 0;
	struct wb_device *wb = ti->private;
	struct wb_cache *cache = wb->cache;
	size_t i;

	switch (type) {
	case STATUSTYPE_INFO:
		DMEMIT("%llu %llu %llu %llu %llu %u ",
		       (long long unsigned int)
		       atomic64_read(&wb->nr_dirty_caches),
		       (long long unsigned int)
		       cache->nr_segments,
		       (long long unsigned int)
		       atomic64_read(&cache->last_migrated_segment_id),
		       (long long unsigned int)
		       atomic64_read(&cache->last_fulled_segment_id),
		       (long long unsigned int)
		       cache->current_seg->global_id,
		       (unsigned int)
		       cache->cursor);

		for (i = 0; i < STATLEN; i++) {
			atomic64_t *v = &cache->stat[i];
			DMEMIT("%llu ", (unsigned long long) atomic64_read(v));
		}

		DMEMIT("%d ", 8);
		DMEMIT("barrier_deadline_ms %lu ",
		       cache->barrier_deadline_ms);
		DMEMIT("allow_migrate %d ",
		       cache->allow_migrate ? 1 : 0);
		DMEMIT("enable_migration_modulator %d ",
		       cache->enable_migration_modulator ? 1 : 0);
		DMEMIT("high_migrate_threshold %d ",
		       wb->high_migrate_threshold);
		DMEMIT("low_migrate_threshold %d ",
		       wb->low_migrate_threshold);                
		DMEMIT("nr_cur_batched_migration %u ",
		       cache->nr_cur_batched_migration);
		DMEMIT("sync_interval %lu ",
		       cache->sync_interval);
		DMEMIT("update_record_interval %lu ",
		       cache->update_record_interval);
		DMEMIT("blockup %d",
		       wb->blockup ? 1 : 0);
		break;

	case STATUSTYPE_TABLE:
		DMEMIT("%s %s", wb->device->name, wb->cache->device->name);
		break;
	}
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

MODULE_AUTHOR("Jungmo Ahn <jungmoan@gmail.com>");
MODULE_DESCRIPTION(DM_NAME " keepfast target");
MODULE_LICENSE("GPL");
