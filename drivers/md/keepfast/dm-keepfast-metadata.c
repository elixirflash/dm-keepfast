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

struct part {
	void *memory;
};

struct bigarray {
	struct part *parts;
	u64 nr_elems;
	u32 elemsize;
};

#define ALLOC_SIZE (1 << 16)
static u32 nr_elems_in_part(struct bigarray *arr)
{
	return div_u64(ALLOC_SIZE, arr->elemsize);
};

static u64 nr_parts(struct bigarray *arr)
{
	u64 a = arr->nr_elems;
	u32 b = nr_elems_in_part(arr);
	return div_u64(a + b - 1, b);
}

struct bigarray *make_bigarray(u32 elemsize, u64 nr_elems)
{
	u64 i, j;
	struct part *part;

	struct bigarray *arr = kmalloc(sizeof(*arr), GFP_KERNEL);
	if (!arr) {
		KFERR("failed to alloc arr");
		return NULL;
	}

	arr->elemsize = elemsize;
	arr->nr_elems = nr_elems;

        printk(KERN_INFO"nrpart:%lld", nr_parts(arr));
	arr->parts = kmalloc(sizeof(struct part) * nr_parts(arr), GFP_KERNEL);
	if (!arr->parts) {
		KFERR("failed to alloc parts");
		goto bad_alloc_parts;
	}

	for (i = 0; i < nr_parts(arr); i++) {
		part = arr->parts + i;
                part->memory = kmalloc(ALLOC_SIZE, GFP_KERNEL);
		if (!part->memory) {
			KFERR("failed to alloc part memory");
			for (j = 0; j < i; j++) {
				part = arr->parts + j;
				kfree(part->memory);
			}
			goto bad_alloc_parts_memory;
		}
	}
	return arr;

bad_alloc_parts_memory:
	kfree(arr->parts);
bad_alloc_parts:
	kfree(arr);
	return NULL;
}

void kill_bigarray(struct bigarray *arr)
{
	size_t i;

	for (i = 0; i < nr_parts(arr); i++) {
		struct part *part = arr->parts + i;
		kfree(part->memory);
	}
        
	kfree(arr->parts);
	kfree(arr);
}

void *bigarray_at(struct bigarray *arr, u64 i)
{
	u32 n = nr_elems_in_part(arr);
	u32 k;
	u64 j = div_u64_rem(i, n, &k);
	struct part *part = arr->parts + j;

	return part->memory + (arr->elemsize * k);
}

/*----------------------------------------------------------------*/

#define sizeof_segment_header(cache) \
	(sizeof(struct segment_header) + \
	 sizeof(struct metablock) * (cache)->nr_blocks_inseg)

#define sizeof_segment_header_device(cache) \
	(sizeof(struct segment_header_device) + \
	 sizeof(struct metablock_device) * (cache)->nr_blocks_inseg)

/*
 * Get the in-core metablock of the given index.
 */
struct metablock *mb_at(struct wb_cache *cache, u32 idx)
{
	u32 seg_idx = idx;        
	u32 idx_inseg;
	struct segment_header *seg;        

        idx_inseg = do_div(seg_idx, cache->nr_blocks_inseg);
	seg = bigarray_at(cache->segment_header_array, (u64)seg_idx);
	return seg->mb_array + idx_inseg;
}

static void mb_array_empty_init(struct wb_cache *cache)
{
	u32 i;
	for (i = 0; i < cache->nr_blocks; i++) {
		struct metablock *mb = mb_at(cache, i);
		INIT_HLIST_NODE(&mb->ht_list);
		INIT_LIST_HEAD(&mb->hot_list);
                
		mb->oblock_packed_d = 0;
                mb->idx_packed_v = i << 4;
                mb->hit_count = 0;
	}
}

dm_cblock_t calc_segment_header_start(struct wb_cache *cache,
					  u32 segment_idx)
{
	return (1 << 11) + (1 << cache->segment_size_order) * (segment_idx);
}

static u32 calc_nr_segments(struct dm_dev *dev, struct wb_cache *cache)
{
        u32 nr_segs = cache->nr_sects;

        nr_segs -= (1 << 11);

        do_div(nr_segs, 1 << cache->segment_size_order);

        return nr_segs;
}

sector_t calc_mb_start_sector(struct wb_cache *cache,
			      struct segment_header *seg,
			      u32 mb_idx)
{
	u32 idx_inseg;

        idx_inseg = do_div(mb_idx, cache->nr_blocks_inseg);

	return seg->start_sector + ((1 + idx_inseg) << cache->nr_sectors_per_block_shift);
}

sector_t calc_page_start_sector(struct wb_cache *cache,
			      struct segment_header *seg,
                                u32 mb_idx, u32 offset)
{
        sector_t sector;

        sector = calc_mb_start_sector(cache, seg, mb_idx);
        sector += (cache->sectors_per_page * offset);

        return sector;
}

bool is_on_curseg(struct wb_cache *cache, u32 mb_idx)
{
	u32 start = cache->current_seg->start_idx;
	if (mb_idx < start)
		return false;

	if (mb_idx >= (start + cache->nr_blocks_inseg))
		return false;

	return true;
}

/*
 * Get the segment from the segment id.
 * The Index of the segment is calculated from the segment id.
 */
struct segment_header *get_segment_header_by_id(struct wb_cache *cache,
						u32 segment_id)
{
	u32 idx;

        idx = do_div(segment_id, cache->nr_segments);
	return bigarray_at(cache->segment_header_array, idx);
}

struct segment_header *get_segment_header_by_mb(struct wb_cache *cache,
                                                struct metablock *mb)
{
        struct segment_header *seg;
        u32 idx = mb->idx_packed_v >> 4;
        u32 idx_inseg = 0;

        idx_inseg = do_div(idx, cache->nr_blocks_inseg);
        
        seg = ((void *) mb) - idx_inseg * sizeof(struct metablock)
                - sizeof(struct segment_header);

        return seg;
}

static int __must_check init_segment_header_array(struct wb_cache *cache)
{
	u32 segment_idx, nr_segments = cache->nr_segments;
        struct segment_header *dseg;        

	cache->segment_header_array =
		make_bigarray(sizeof_segment_header(cache), (u64)nr_segments);
	if (!cache->segment_header_array) {
		KFERR();
		return -ENOMEM;
	}

	for (segment_idx = 0; segment_idx < nr_segments; segment_idx++) {
		struct segment_header *seg =
			bigarray_at(cache->segment_header_array, segment_idx);
		seg->start_idx = cache->nr_blocks_inseg * segment_idx;
		seg->start_sector =
			calc_segment_header_start(cache, segment_idx);

                seg->global_id = segment_idx;
		seg->length = 0;

		atomic_set(&seg->nr_inflight_ios, 0);

		spin_lock_init(&seg->lock);
		INIT_LIST_HEAD(&seg->flush_list);

		init_completion(&seg->flush_done);
		complete_all(&seg->flush_done);
                dseg = get_segment_header_by_id(cache, segment_idx);
	}

	mb_array_empty_init(cache);

	return 0;
}

static void free_segment_header_array(struct wb_cache *cache)
{
	kill_bigarray(cache->segment_header_array);
}

static int __must_check
read_superblock(struct wb_cache *cache, struct superblock_device *sb_dev, struct dm_dev *dev)
{
	int r = 0;
	struct wb_device *wb = cache->wb;
	struct dm_io_request io_req;
	struct dm_io_region region;

	void *buf = kmalloc(1 << SECTOR_SHIFT, GFP_KERNEL);
	if (!buf) {
		KFERR();
		return -ENOMEM;
	}

	io_req = (struct dm_io_request) {
		.client = wb_io_client,
		.bi_rw = READ,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
        region = (struct dm_io_region) {
		.bdev = dev->bdev,
		.sector = 0,
		.count = 1,
                .rvec_count = 0,                
	};

	r = dm_safe_io(&io_req, 1, &region, NULL, false);
	if (r) {
		KFERR();
		goto bad_io;
	}

	memcpy(sb_dev, buf, sizeof(*sb_dev));
bad_io:
	kfree(buf);

	return r;
}

/*
 * Check if the cache device is already formatted.
 * Returns 0 iff this routine runs without failure.
 * cache_valid is stored true iff the cache device
 * is formatted and needs not to be re-fomatted.
 */
int __must_check audit_cache_device(struct dm_dev *dev, struct wb_cache *cache,
				    bool *need_format, bool *allow_format)
{
	int r = 0;
	struct superblock_device sb_dev;

	r = read_superblock(cache, &sb_dev, dev);
	if (r) {
		KFERR("read superblock failed");
		return r;
	}

	*need_format = true;
	*allow_format = false;

        cache->last_flushed_segment_id = le32_to_cpu(sb_dev.last_flushed_segment_id);

	if (le32_to_cpu(sb_dev.magic) != KEEPFAST_MAGIC) {
		KFERR("superblock header: magic number invalid");
		*allow_format = true;
		return 0;
	}

	if (sb_dev.segment_size_order != cache->segment_size_order) {
		KFERR("superblock header: segment order not same %u != %u",
		      sb_dev.segment_size_order,
		      cache->segment_size_order);
	} else {
		*need_format = false;
	}

	return r;
}

static int format_superblock_header(struct dm_dev *dev, struct wb_cache *cache)
{
	int r = 0;
	struct wb_device *wb = cache->wb;
	struct dm_io_request io_req_sb;
	struct dm_io_region region_sb;

	struct superblock_device sb_dev = {
		.magic = cpu_to_le32(KEEPFAST_MAGIC),
		.segment_size_order = cache->segment_size_order,
	};

	void *buf = kzalloc(1 << SECTOR_SHIFT, GFP_KERNEL);
	if (!buf) {
		KFERR();
		return -ENOMEM;
	}

	memcpy(buf, &sb_dev, sizeof(sb_dev));

	io_req_sb = (struct dm_io_request) {
		.client = wb_io_client,
		.bi_rw = WRITE_FUA,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	region_sb = (struct dm_io_region) {
		.bdev = dev->bdev,
		.sector = 0,
		.count = 1,
                .rvec_count = 0,                
	};
	r = dm_safe_io(&io_req_sb, 1, &region_sb, NULL, false);
	kfree(buf);

	if (r) {
		KFERR();
		return r;
	}

	return 0;
}

/*
 * Format superblock header and
 * all the metadata regions over the cache device.
 */
int __must_check format_cache_device(struct dm_dev *dev, struct wb_cache *cache)
{
	u32 i, nr_segments = calc_nr_segments(dev, cache);
	struct wb_device *wb = cache->wb;
	struct dm_io_request io_req_sb;
	struct dm_io_region region_sb;
        struct segment_header_device *seg_dev;
	void *buf;

	int r = 0;

	/*
	 * Zeroing the full superblock
	 */
	buf = kzalloc(1 << 20, GFP_KERNEL);
	if (!buf) {
		KFERR();
		return -ENOMEM;
	}

	io_req_sb = (struct dm_io_request) {
		.client = wb_io_client,
		.bi_rw = WRITE_FUA,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	region_sb = (struct dm_io_region) {
		.bdev = dev->bdev,
		.sector = 0,
		.count = (1 << 11),
                .rvec_count = 0,
	};
	r = dm_safe_io(&io_req_sb, 1, &region_sb, NULL, false);
	kfree(buf);

	if (r) {
		KFERR();
		return r;
	}

	format_superblock_header(dev, cache);

	/* Format the metadata regions */

	/*
	 * Count the number of segments
	 */

        //	atomic64_set(&context.count, nr_segments);
        //	context.err = 0;

	buf = kzalloc(1 << 12, GFP_KERNEL);
	if (!buf) {
		KFERR();
		return -ENOMEM;
	}

        printk(KERN_INFO"formatting cache device of %d segments", nr_segments);

	/*
	 * Submit all the writes asynchronously.
	 */
	for (i = 0; i < nr_segments; i++) {
		struct dm_io_request io_req_seg = {
			.client = wb_io_client,
			.bi_rw = WRITE_FUA,
                        .notify.fn = NULL,
                        //there is a bug that could not write at last area
                        //                        .notify.fn = format_segmd_endio,
                        //                        .notify.context = &context,
			.mem.type = DM_IO_KMEM,
			.mem.ptr.addr = buf,
		};
		struct dm_io_region region_seg = {
			.bdev = dev->bdev,
			.sector = calc_segment_header_start(cache, i),
			.count = (1 << 3),
                        .rvec_count = 0,                        
		};
		r = dm_safe_io(&io_req_seg, 1, &region_seg, NULL, false);
		if (r) {
			KFERR();
			break;
		}
	}
	kfree(buf);

        //        kfdebug("nrsegs:%d, i:%d,remained segs:%lld",nr_segments, i,  atomic64_read(&context.count));

	if (r) {
		KFERR();
		return r;
	}

	/*
	 * Wait for all the writes complete.
	 */
        /*	while (atomic64_read(&context.count))
		schedule_timeout_interruptible(msecs_to_jiffies(100));

	if (context.err) {
		KFERR("formatting io failed error=%d", context.err);
		return -EIO;
                }*/

	return blkdev_issue_flush(dev->bdev, GFP_KERNEL, NULL);
}

/*----------------------------------------------------------------*/
int __must_check
read_segment_header_device(struct segment_header_device *dest,
			   struct wb_cache *cache, u32 segment_idx)
{
	int r = 0;
	struct wb_device *wb = cache->wb;
	struct dm_io_request io_req;
	struct dm_io_region region;
	void *buf = kmalloc(1 << 12, GFP_KERNEL);
        
	if (!buf) {
		KFERR();
		return -ENOMEM;
	}

	io_req = (struct dm_io_request) {
		.client = wb_io_client,
		.bi_rw = READ,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	region = (struct dm_io_region) {
		.bdev = cache->device->bdev,
		.sector = calc_segment_header_start(cache, segment_idx),
		.count = (1 << 3),
                .rvec_count = 0,                
	};

	r = dm_safe_io(&io_req, 1, &region, NULL, false);
	if (r) {
		KFERR();
		goto bad_io;
	}

	memcpy(dest, buf, sizeof_segment_header_device(cache));

bad_io:
	kfree(buf);

	return r;
}

/*
 * Make a metadata in segment data to flush.
 * @dest The metadata part of the segment to flush
 */
void meta_prepare_for_write(struct wb_cache *cache, struct cache_entry *centry, struct segment_header_device *dest)
{
        struct segment_header *src = centry->seg;        
        struct metablock_device *mbdev = NULL;
        struct metablock *mb;
        u32 mb_idx_inseg;        
        u32 idx;
	u32 i;        

	dest->global_id = cpu_to_le32(src->global_id);

        if(policy_bytealign) {
                idx = centry->idx;
                mb_idx_inseg = do_div(idx, cache->nr_blocks_inseg);
                
                mb = src->mb_array + mb_idx_inseg;
                mbdev = &dest->mbarr[mb_idx_inseg];
                mbdev->oblock_packed_d = cpu_to_le32(mb->oblock_packed_d);
                mbdev->idx_packed_v = mb->idx_packed_v;
                mbdev->hit_count = mb->hit_count;
                
        } else {
                for (i = 0; i < src->length; i++) {
                        mb = src->mb_array + i;
                        mbdev = &dest->mbarr[i];
                        mbdev->oblock_packed_d = cpu_to_le32(mb->oblock_packed_d);
                        mbdev->idx_packed_v = mb->idx_packed_v;
                        mbdev->hit_count = mb->hit_count;
                }
                // maybe, to do delete
                if(i <= src->length) {
                        mb = src->mb_array + i;
                        mbdev = &dest->mbarr[i];
                }                
        }
}

/*
 * Read the on-disk metadata of the segment
 * and update the in-core cache metadata structure
 * like Hash Table.
 */
static int update_by_segment_header_device(struct wb_cache *cache,
					    struct segment_header_device *src)
{
	u32 id = le32_to_cpu(src->global_id);
	struct segment_header *seg = get_segment_header_by_id(cache, id);
	struct policy_operation *pop = cache->pop;

	u32 i;
        int is_clean_seg = 0;

        struct metablock *mb;
        struct metablock_device *mbdev;
        dm_oblock_t oblock;
        u8 dflag;                
        struct cache_entry centry;
        u32 idx;
        u8 vflag;

        seg->global_id = id;

	INIT_COMPLETION(seg->flush_done);

	for (i = 0 ; i < cache->nr_blocks_inseg; i++) {
		mb = seg->mb_array + i;
		mbdev = &src->mbarr[i];

                if(le32_to_cpu(mbdev->hit_count) == 0)
                        continue;

                mb->oblock_packed_d = le32_to_cpu(mbdev->oblock_packed_d);
                mb->hit_count = le32_to_cpu(mbdev->hit_count);
                unpack_vflag(le32_to_cpu(mbdev->idx_packed_v), &idx, &vflag);
                pack_vflag(mb->idx_packed_v >> 4, vflag);
                
                unpack_dflag(mb->oblock_packed_d, &oblock, &dflag);

                if(dflag == 0)
                        is_clean_seg = 1;

                centry.seg = seg;
                centry.mb = mb;

                try_lru_put_hot(pop, &centry);
#if 0
                presult = policy_lookup(pop, oblock, &centry);
                if(presult == POLICY_HIT)
                        policy_remove_mapping(pop, &centry);
#endif
                
                //        trace_keepfast_recovery(src, mbdev, i);
                //        kfdebug("recover - segid:%lld, mbidx:%d", id, mb_idx);
                //TODO: do increment dirty count
                
                policy_insert_mapping(pop, oblock, &centry);
        }

        return is_clean_seg;
}

static void print_hex(unsigned char *r_buf, unsigned int size)
{
        int j;

        for(j = 0; j < size; j+=16) {
                printk(KERN_INFO"0x%8x(%8d):%2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x\n", 0 + (j / 512), 0 + (j / 512),              
                       r_buf[j],r_buf[j+1],r_buf[j+2],r_buf[j+3],
                       r_buf[j+4],r_buf[j+5],r_buf[j+6],r_buf[j+7],
                       r_buf[j+8],r_buf[j+9],r_buf[j+10],r_buf[j+11],
                       r_buf[j+12],r_buf[j+13],r_buf[j+14],
                       r_buf[j+15]
                       );
        }
}

static int __must_check recover_cache(struct wb_cache *cache)
{
	struct segment_header_device *header;
	struct segment_header *seg;
        struct policy_operation *pop = cache->pop;
	u32 max_id, init_segment_id, header_id;
	struct superblock_device uninitialized_var(sb_dev);        
	u32 i, nr_segments = cache->nr_segments;
	int r = 0;
        int is_clean_seg;
        u32 lowest_clean_seg;
        int over_dirty_seg = 0;

	header = kmalloc(sizeof_segment_header_device(cache), GFP_KERNEL);
	if (!header) {
		KFERR();
		return -ENOMEM;
	}

	/*
	 * Finding the oldest, non-zero id and its index.
	 */

	max_id = SZ_MAX;
	init_segment_id = 0;

        for (i = 0; i < nr_segments; i++) {
		r = read_segment_header_device(header, cache, i);
		if (r) {
			KFERR();
			kfree(header);
			return r;
		}

		header_id = le32_to_cpu(header->global_id);
		is_clean_seg = update_by_segment_header_device(cache, header);

                if(!is_clean_seg)
                        over_dirty_seg = 1;

                if(is_clean_seg) {
                        if(header->global_id < lowest_clean_seg) 
                                lowest_clean_seg = header->global_id;
                        else {
                                if(over_dirty_seg == 1)
                                        lowest_clean_seg = header->global_id;
                                over_dirty_seg = 0;
                        }
                }
	}

	kfree(header);

	seg = get_segment_header_by_id(cache, lowest_clean_seg);
        if(seg->length != 0) // it's segment of partial dirty, we keep partial dirties 
                init_segment_id = lowest_clean_seg + 1; 
        else
                init_segment_id = lowest_clean_seg;

        printk(KERN_INFO"INIT seg:%d, lowest_clean_seg:%d", init_segment_id, lowest_clean_seg);

	seg = get_segment_header_by_id(cache, init_segment_id);

        printk(KERN_INFO"curseg id:%d, cursor:%d", seg->global_id, seg->start_idx);
	seg->global_id = init_segment_id;
	atomic_set(&seg->nr_inflight_ios, 0);

	cache->last_filled_segment_id = seg->global_id - 1;
#if 0 // i dont know why to do
	atomic64_set(&cache->last_flushed_segment_id,
		atomic64_read(&cache->last_filled_segment_id) > cache->nr_segments ?
		atomic64_read(&cache->last_filled_segment_id) - cache->nr_segments : 0);

	if (last_flushed_seg_id > atomic64_read(&cache->last_flushed_segment_id))
		atomic64_set(&cache->last_flushed_segment_id, last_flushed_seg_id);
#endif

        // should look over
        //	wait_for_flush(cache, seg->global_id);

        remove_mappings_inseg(pop, seg);
	/*
	 * cursor is set to the first element of the segment.
	 * This means that we will not use the element.
	 */
	cache->cursor = seg->start_idx;
	seg->length = 0;
        
	cache->current_seg = seg;

        printk(KERN_INFO"curseg id:%d, cursor:%d", seg->global_id, seg->start_idx);

        kfdebug("initial segment:%d, lfu:%d lfi :%d, cursor:%d",
                init_segment_id, cache->last_flushed_segment_id, cache->last_filled_segment_id, cache->cursor);

	return 0;
}

/*----------------------------------------------------------------*/
/*
 * Allocate new flush buffer by the nr_batch size.
 * On success, it frees the old buffer.
 *
 * User may set # of batches
 * that can hardly allocate the memory spaces.
 * This function is safe for that case.
 */
int alloc_flush_buffer(struct wb_cache *cache, size_t nr_batch)
{
	void *buf, *snapshot;

	buf = vmalloc(nr_batch * ((cache->nr_blocks_inseg + cache->nr_pages_inblock) << 12));
	if (!buf) {
		KFERR("couldn't allocate flush buffer");
		return -ENOMEM;
	}

	snapshot = kmalloc(nr_batch * cache->nr_blocks_inseg, GFP_KERNEL);
	if (!snapshot) {
		vfree(buf);
		KFERR("couldn't allocate dirty snapshot");
		return -ENOMEM;
	}

	if (cache->flush_buffer)
		vfree(cache->flush_buffer);

	kfree(cache->dirtiness_snapshot); /* kfree(NULL) is safe */

	cache->flush_buffer = buf;
	cache->dirtiness_snapshot = snapshot;
	cache->nr_cur_batched_flush = nr_batch;

	return 0;
}

void free_flush_buffer(struct wb_cache *cache)
{
	vfree(cache->flush_buffer);
	kfree(cache->dirtiness_snapshot);
}

/*----------------------------------------------------------------*/

#define CREATE_THREAD(name) \
	do { \
		cache->name##_thread = kthread_create(do_##name, cache, \
						      #name "_thread"); \
		if (IS_ERR(cache->name##_thread)) { \
			r = PTR_ERR(cache->name##_thread); \
			cache->name##_thread = NULL; \
			KFERR("couldn't spawn" #name "thread"); \
			goto bad_##name##_thread; \
		} \
		wake_up_process(cache->name##_thread); \
	} while (0)

int __must_check resume_cache(struct wb_cache *cache, struct dm_dev *dev)
{
	int r = 0;
	size_t nr_batch;

	cache->device = dev;
	cache->nr_segments = calc_nr_segments(cache->device, cache);

	/*
	 * The first 4KB (1<<3 sectors) in segment
	 * is for metadata.
	 */
        //	cache->nr_blks_inseg = (1 << (cache->segment_size_order - 3)) - 1;
        /*
        cache->sectors_per_cblock = 32;
        cache->sectors_per_block_shift = 5;
        cache->sectors_per_segment_shift = 7;
        cache->sectors_per_segment = 128;*/

        cache->nr_sectors_per_block_shift = 5;
        cache->sectors_per_page = 8;
        cache->nr_pages_inblock = 4;
	cache->nr_blocks_inseg = (1 << (cache->segment_size_order - cache->block_size_order)) - 1;
	cache->nr_blocks = cache->nr_segments * cache->nr_blocks_inseg;

        printk(KERN_INFO"sectors per block:%d, blocks in seg:%d, segs:%d, sectors:%lld",
               1 << cache->nr_sectors_per_block_shift,
               (1 << (cache->segment_size_order - cache->block_size_order)) - 1,
               cache->nr_segments,
               (unsigned long long)cache->nr_sects);

	mutex_init(&cache->io_lock);

	/*
	 * (i) Harmless Initializations
	 */
	cache->buf_1_pool = mempool_create_kmalloc_pool(16, 1 << SECTOR_SHIFT);
	if (!cache->buf_1_pool) {
		r = -ENOMEM;
		KFERR("couldn't alloc 1 sector pool");
		goto bad_buf_1_pool;
	}
	cache->buf_8_pool = mempool_create_kmalloc_pool(16, 8 << SECTOR_SHIFT);
	if (!cache->buf_8_pool) {
		r = -ENOMEM;
		KFERR("couldn't alloc 8 sector pool");
		goto bad_buf_8_pool;
	}

	r = init_segment_header_array(cache);
	if (r) {
		KFERR("couldn't alloc segment header array");
		goto bad_alloc_segment_header_array;
	}

        r = create_cache_policy(cache, "writeback-cold");        
	if (r) {
		KFERR("couldn't create cache");
		goto bad_alloc_ht;
	}

-	/*
	 * (2) Recovering Metadata
	 * Recovering the cache metadata
	 * prerequires the flush thread working.
	 */

	/* Flush Thread */
	atomic_set(&cache->flush_fail_count, 0);
	atomic_set(&cache->flush_io_count, 0);

	/*
	 * default number of batched flush
	 * is 1MB / segment size
	 * eMMC can consume nearly 32MB/sec writes.
	 */
        //16 -> 32MB
	nr_batch = 1 << (14 - cache->segment_size_order);
        cache->nr_max_batched_flush = nr_batch;
	if (alloc_flush_buffer(cache, nr_batch)) {
		r = -ENOMEM;
		goto bad_alloc_flush_buffer;
	}

	init_waitqueue_head(&cache->flush_wait_queue);
	INIT_LIST_HEAD(&cache->flush_list);

	cache->allow_flush = true;
	cache->urge_flush = false;
	CREATE_THREAD(flush);

	r = recover_cache(cache);
	if (r) {
		KFERR("recovering cache metadata failed");
		goto bad_recover;
	}

	/*
	 * (3) Misc Initializations
	 * These are only working
	 * after the logical device created.
	 */

	/* Migartion Modulator */
	cache->enable_balance_dirty = true;
	CREATE_THREAD(balance_dirty);

	/* Superblock Sb_Dever */
	cache->flush_sb_interval = 60;
	CREATE_THREAD(flush_sb);

	return 0;

bad_balance_dirty_thread:
	kthread_stop(cache->flush_sb_thread);
bad_flush_sb_thread:
	kthread_stop(cache->balance_dirty_thread);
bad_recover:
	kthread_stop(cache->flush_thread);
bad_flush_thread:
	free_flush_buffer(cache);
bad_alloc_flush_buffer:
        destroy_cache_policy(cache);
bad_alloc_ht:
	free_segment_header_array(cache);
bad_alloc_segment_header_array:
	mempool_destroy(cache->buf_8_pool);
bad_buf_8_pool:
	mempool_destroy(cache->buf_1_pool);
bad_buf_1_pool:
	return r;
}

void free_cache(struct wb_cache *cache)
{
	/*
	 * Must clean up all the volatile data
	 * before termination.
	 */
	kthread_stop(cache->flush_sb_thread);
	kthread_stop(cache->balance_dirty_thread);
	kthread_stop(cache->flush_thread);
	free_flush_buffer(cache);

	/* Destroy in-core structures */
        destroy_cache_policy(cache);        
	free_segment_header_array(cache);
}
