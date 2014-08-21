/*
 * Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This file is released under the GPL.
 */

#include "dm-keepfast.h"
#include "dm-keepfast-metadata.h"
#include "dm-keepfast-daemon.h"

/*----------------------------------------------------------------*/

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

static struct bigarray *make_bigarray(u32 elemsize, u64 nr_elems)
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

static void kill_bigarray(struct bigarray *arr)
{
	size_t i;
	for (i = 0; i < nr_parts(arr); i++) {
		struct part *part = arr->parts + i;
		kfree(part->memory);
	}
	kfree(arr->parts);
	kfree(arr);
}

static void *bigarray_at(struct bigarray *arr, u64 i)
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
	 sizeof(struct metablock) * (cache)->nr_caches_inseg)

#define sizeof_segment_header_device(cache) \
	(sizeof(struct segment_header_device) + \
	 sizeof(struct metablock_device) * (cache)->nr_caches_inseg)

/*
 * Get the in-core metablock of the given index.
 */
static struct metablock *mb_at(struct wb_cache *cache, u32 idx)
{
	u32 idx_inseg;
	u32 seg_idx = div_u64_rem(idx, cache->nr_caches_inseg, &idx_inseg);
	struct segment_header *seg =
		bigarray_at(cache->segment_header_array, seg_idx);
	return seg->mb_array + idx_inseg;
}

static void mb_array_empty_init(struct wb_cache *cache)
{
	u32 i;
	for (i = 0; i < cache->nr_caches; i++) {
		struct metablock *mb = mb_at(cache, i);
		INIT_HLIST_NODE(&mb->ht_list);

		mb->idx = i;
		mb->dirty_bits = 0;
	}
}

sector_t calc_segment_header_start(struct wb_cache *cache,
					  u32 segment_idx)
{
	return (1 << 11) + (1 << cache->segment_size_order) * (segment_idx);
}

u32 calc_segment_lap(struct wb_cache *cache, u64 segment_id)
{
	u64 a = div_u64(segment_id - 1, cache->nr_segments);
	return a + 1;
};

static u32 calc_nr_segments(struct dm_dev *dev, struct wb_cache *cache)
{
        sector_t devsize = (sector_t)cache->nr_sects;        
	return div_u64(devsize - (1 << 11), 1 << cache->segment_size_order);
}

sector_t calc_mb_start_sector(struct wb_cache *cache,
			      struct segment_header *seg,
			      u32 mb_idx)
{
	u32 idx;
	div_u64_rem(mb_idx, cache->nr_caches_inseg, &idx);
	return seg->start_sector + ((1 + idx) << 3);
}

bool is_on_curseg(struct wb_cache *cache, u32 mb_idx)
{
	u32 start = cache->current_seg->start_idx;
	if (mb_idx < start)
		return false;

	if (mb_idx >= (start + cache->nr_caches_inseg))
		return false;

	return true;
}

/*
 * Get the segment from the segment id.
 * The Index of the segment is calculated from the segment id.
 */
struct segment_header *get_segment_header_by_id(struct wb_cache *cache,
						u64 segment_id)
{
	u32 idx;
	div_u64_rem(segment_id - 1, cache->nr_segments, &idx);
	return bigarray_at(cache->segment_header_array, idx);
}

static int __must_check init_segment_header_array(struct wb_cache *cache)
{
	u32 segment_idx, nr_segments = cache->nr_segments;
	cache->segment_header_array =
		make_bigarray(sizeof_segment_header(cache), nr_segments);
	if (!cache->segment_header_array) {
		KFERR();
		return -ENOMEM;
	}

	for (segment_idx = 0; segment_idx < nr_segments; segment_idx++) {
		struct segment_header *seg =
			bigarray_at(cache->segment_header_array, segment_idx);
		seg->start_idx = cache->nr_caches_inseg * segment_idx;
		seg->start_sector =
			calc_segment_header_start(cache, segment_idx);

		seg->length = 0;

		atomic_set(&seg->nr_inflight_ios, 0);

		spin_lock_init(&seg->lock);

		INIT_LIST_HEAD(&seg->migrate_list);

                //		init_completion(&seg->flush_done);
                //		complete_all(&seg->flush_done);

		init_completion(&seg->migrate_done);
		complete_all(&seg->migrate_done);
	}

	mb_array_empty_init(cache);

	return 0;
}

static void free_segment_header_array(struct wb_cache *cache)
{
	kill_bigarray(cache->segment_header_array);
}

/*----------------------------------------------------------------*/

/*
 * Initialize the Hash Table.
 */
static int __must_check ht_empty_init(struct wb_cache *cache)
{
	u32 idx;
	size_t i, nr_heads;
	struct bigarray *arr;

	cache->htsize = cache->nr_caches;
	nr_heads = cache->htsize + 1;
	arr = make_bigarray(sizeof(struct ht_head), nr_heads);
	if (!arr) {
		KFERR();
		return -ENOMEM;
	}

	cache->htable = arr;

	for (i = 0; i < nr_heads; i++) {
		struct ht_head *hd = bigarray_at(arr, i);
		INIT_HLIST_HEAD(&hd->ht_list);
	}

	/*
	 * Our hashtable has one special bucket called null head.
	 * Orphan metablocks are linked to the null head.
	 */
	cache->null_head = bigarray_at(cache->htable, cache->htsize);

	for (idx = 0; idx < cache->nr_caches; idx++) {
		struct metablock *mb = mb_at(cache, idx);
		hlist_add_head(&mb->ht_list, &cache->null_head->ht_list);
	}

	return 0;
}

static void free_ht(struct wb_cache *cache)
{
	kill_bigarray(cache->htable);
}

struct ht_head *ht_get_head(struct wb_cache *cache, struct lookup_key *key)
{
	u32 idx;
	div_u64_rem(key->sector, cache->htsize, &idx);
	return bigarray_at(cache->htable, idx);
}

static bool mb_hit(struct metablock *mb, struct lookup_key *key)
{
	return mb->sector == key->sector;
}

void ht_del(struct wb_cache *cache, struct metablock *mb)
{
	struct ht_head *null_head;

	hlist_del(&mb->ht_list);

	null_head = cache->null_head;
	hlist_add_head(&mb->ht_list, &null_head->ht_list);
}

void ht_register(struct wb_cache *cache, struct ht_head *head,
		 struct lookup_key *key, struct metablock *mb)
{
	hlist_del(&mb->ht_list);
	hlist_add_head(&mb->ht_list, &head->ht_list);

	mb->sector = key->sector;
};

struct metablock *ht_lookup(struct wb_cache *cache,
			    struct ht_head *head,
			    struct lookup_key *key)
{
	struct metablock *mb, *found = NULL;
        struct hlist_node *node;        

	hlist_for_each_entry(mb, node, &head->ht_list, ht_list) {
		if (mb_hit(mb, key)) {
			found = mb;
			break;
		}
	}
	return found;
}

/*
 * Discard all the metablock in a segment.
 */
void discard_caches_inseg(struct wb_cache *cache, struct segment_header *seg)
{
	u8 i;
	for (i = 0; i < cache->nr_caches_inseg; i++) {
		struct metablock *mb = seg->mb_array + i;
		ht_del(cache, mb);
	}
}

/*----------------------------------------------------------------*/

static int read_superblock_header(struct wb_cache *cache,
				  struct superblock_header_device *sup,
				  struct dm_dev *dev)
{
	int r = 0;
	struct dm_io_request io_req_sup;
	struct dm_io_region region_sup;
	struct wb_device *wb = cache->wb;

	void *buf = kmalloc(1 << SECTOR_SHIFT, GFP_KERNEL);
	if (!buf) {
		KFERR("failed to alloc buffer");
		return -ENOMEM;
	}

	io_req_sup = (struct dm_io_request) {
		.client = wb_io_client,
		.bi_rw = READ,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	region_sup = (struct dm_io_region) {
		.bdev = dev->bdev,
		.sector = 0,
		.count = 1,
                .rvec_count = 0,                
	};
	r = dm_safe_io(&io_req_sup, 1, &region_sup, NULL, false);
	if (r) {
		KFERR("io failed in reading superblock header");
		goto bad_io;
	}

	memcpy(sup, buf, sizeof(*sup));

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
	struct superblock_header_device sup;
	r = read_superblock_header(cache, &sup, dev);
	if (r) {
		KFERR("read superblock header failed");
		return r;
	}

	*need_format = true;
	*allow_format = false;

	if (le32_to_cpu(sup.magic) != KEEPFAST_MAGIC) {
		KFERR("superblock header: magic number invalid");
		*allow_format = true;
		return 0;
	}

	if (sup.segment_size_order != cache->segment_size_order) {
		KFERR("superblock header: segment order not same %u != %u",
		      sup.segment_size_order,
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
	struct dm_io_request io_req_sup;
	struct dm_io_region region_sup;

	struct superblock_header_device sup = {
		.magic = cpu_to_le32(KEEPFAST_MAGIC),
		.segment_size_order = cache->segment_size_order,
	};

	void *buf = kzalloc(1 << SECTOR_SHIFT, GFP_KERNEL);
	if (!buf) {
		KFERR();
		return -ENOMEM;
	}

	memcpy(buf, &sup, sizeof(sup));

	io_req_sup = (struct dm_io_request) {
		.client = wb_io_client,
		.bi_rw = WRITE_FUA,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	region_sup = (struct dm_io_region) {
		.bdev = dev->bdev,
		.sector = 0,
		.count = 1,
                .rvec_count = 0,                
	};
	r = dm_safe_io(&io_req_sup, 1, &region_sup, NULL, false);
	kfree(buf);

	if (r) {
		KFERR();
		return r;
	}

	return 0;
}

struct format_segmd_context {
	int err;
	atomic64_t count;
};

static void format_segmd_endio(unsigned long error, void *__context)
{
	struct format_segmd_context *context = __context;
	if (error) {
		context->err = 1;
        }
	atomic64_dec(&context->count);
}

/*
 * Format superblock header and
 * all the metadata regions over the cache device.
 */
int __must_check format_cache_device(struct dm_dev *dev, struct wb_cache *cache)
{
	u32 i, nr_segments = calc_nr_segments(dev, cache);
	struct wb_device *wb = cache->wb;
	struct format_segmd_context context;
	struct dm_io_request io_req_sup;
	struct dm_io_region region_sup;
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

	io_req_sup = (struct dm_io_request) {
		.client = wb_io_client,
		.bi_rw = WRITE_FUA,
		.notify.fn = NULL,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buf,
	};
	region_sup = (struct dm_io_region) {
		.bdev = dev->bdev,
		.sector = 0,
		.count = (1 << 11),
                .rvec_count = 0,
	};
	r = dm_safe_io(&io_req_sup, 1, &region_sup, NULL, false);
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

	atomic64_set(&context.count, nr_segments);
	context.err = 0;

	buf = kzalloc(1 << 12, GFP_KERNEL);
	if (!buf) {
		KFERR();
		return -ENOMEM;
	}

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

        kfdebug("nrsegs:%d, i:%d,remained segs:%lld",nr_segments, i,  atomic64_read(&context.count));

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

static int __must_check
read_superblock_record(struct superblock_record_device *record,
		       struct wb_cache *cache)
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
		.bdev = cache->device->bdev,
		.sector = (1 << 11) - 1,
		.count = 1,
                .rvec_count = 0,                
	};

	r = dm_safe_io(&io_req, 1, &region, NULL, false);
	if (r) {
		KFERR();
		goto bad_io;
	}

	memcpy(record, buf, sizeof(*record));

bad_io:
	kfree(buf);

	return r;
}

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
void prepare_segment_header_device(struct segment_header_device *dest,
				   struct wb_cache *cache,
				   struct segment_header *src,
                                   u32 mb_idx)
{
	u8 left, right;
	u32 i, tmp32;
	unsigned long flags;
        u32 cursor, length;
        struct metablock_device *mbdev = NULL;
        struct metablock *mb;        

	dest->global_id = cpu_to_le64(src->global_id);
#if 0
	for (i = 0; i < src->length; i++) {        
                mb = src->mb_array + i;
                mbdev = &dest->mbarr[i];
        
                mbdev->sector = cpu_to_le64(mb->sector);
                mbdev->dirty_bits = mb->dirty_bits;
                mbdev->lap = cpu_to_le32(calc_segment_lap(cache, src->global_id));
        }
        if(i <= src->length) {
                mb = src->mb_array + i;
                mbdev = &dest->mbarr[i];
                mbdev->lap = cpu_to_le32(calc_segment_lap(cache, src->global_id)) + 1;
        }
#else
        mb = src->mb_array + mb_idx;
        mbdev = &dest->mbarr[mb_idx];
        mbdev->sector = cpu_to_le64(mb->sector);
        mbdev->dirty_bits = mb->dirty_bits;
        mbdev->lap = cpu_to_le32(calc_segment_lap(cache, src->global_id));                
#endif
        
        kfdebug("gid:%lld,seglap:%d,mbdev->lap:%d, mbidx:%d, srclength:%d,dirtybits:%x", dest->global_id, cpu_to_le32(calc_segment_lap(cache, src->global_id)), mbdev->lap, mb_idx , src->length, mbdev->dirty_bits);        
}

/*
 * Read the on-disk metadata of the segment
 * and update the in-core cache metadata structure
 * like Hash Table.
 */
static void update_by_segment_header_device(struct wb_cache *cache,
					    struct segment_header_device *src)
{
	u32 i;
	u64 id = le64_to_cpu(src->global_id);
	struct segment_header *seg = get_segment_header_by_id(cache, id);
	u32 seg_lap = calc_segment_lap(cache, id);
        u32 mb_lap = 0;

	INIT_COMPLETION(seg->migrate_done);

	for (i = 0 ; i < cache->nr_caches_inseg; i++) {
		struct lookup_key key;
		struct ht_head *head;
		struct metablock *found, *mb = seg->mb_array + i;
		struct metablock_device *mbdev = &src->mbarr[i];

                mb_lap = seg_lap;

		/*
		 * lap is kind of checksum.
		 * If the checksum are the same between
		 * original (seg_lap) and the dumped on
		 * the metadata the metadata is considered valid.
		 *
		 * This algorithm doesn't care the case
		 * metadata are partially written but it is OK.
		 *
		 * The cases are splitted by the volatility of
		 * the buffer.
		 *
		 * If the buffer is volatile, ACK to the barrier
		 * will only be done after completion of flushing
		 * to the cache device. Therefore, these metadata
		 * lost are ignored doesn't violate the semantics.
		 *
		 * If the buffer is non-volatile, ACK to the barrier
		 * is already done. However, only after FUA write to
		 * the cache device the buffer is ready to be reused.
		 * Therefore, metadata is not lost and is still on
		 * the buffer.
		 */
		if (le32_to_cpu(mbdev->lap) > mb_lap) {
                        KFERR("Invalid  mb-lap:%d with seglap:%d", le32_to_cpu(mbdev->lap), mb_lap);
			break;
                }
                
		if (le32_to_cpu(mbdev->lap) < mb_lap) {
                        kfdebug("old or last mb in seg - segid:%lld, seglap:%d,  mbidx:%d, mdevlap:%d",
                                id, seg_lap, i, le32_to_cpu(mbdev->lap));  
			break;
                }

		/*
		 * How could this be happened? But no harm.
		 * We only recover dirty caches.
		 */
		if (!mbdev->dirty_bits) {
                        kfdebug("mb(idx:%d) is cleaned", i);
			continue;
                }

		mb->sector = le64_to_cpu(mbdev->sector);
		mb->dirty_bits = mbdev->dirty_bits;

		inc_nr_dirty_caches(cache->wb);

		key = (struct lookup_key) {
			.sector = mb->sector,
		};

		head = ht_get_head(cache, &key);

		found = ht_lookup(cache, head, &key);
		if (found)
			ht_del(cache, found);
                kfdebug("recover - segid:%lld, seglap:%d,  mbidx:%d, mdevlap:%d",
                        id, seg_lap, i, le32_to_cpu(mbdev->lap));  
                ht_register(cache, head, &key, mb);
	}
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
	int r = 0;
	struct segment_header_device *header;
	struct segment_header *seg;
	u64 max_id, oldest_id, last_fulled_id, init_segment_id,
	    header_id, record_id;
	u32 i, j, oldest_idx, nr_segments = cache->nr_segments;

	struct superblock_record_device uninitialized_var(record);
	r = read_superblock_record(&record, cache);
	if (r) {
		KFERR();
		return r;
	}
	record_id = le64_to_cpu(record.last_migrated_segment_id);

	header = kmalloc(sizeof_segment_header_device(cache), GFP_KERNEL);
	if (!header) {
		KFERR();
		return -ENOMEM;
	}

	/*
	 * Finding the oldest, non-zero id and its index.
	 */

	max_id = SZ_MAX;
	oldest_id = max_id;
	oldest_idx = 0;

	for (i = 0; i < nr_segments; i++) {
		r = read_segment_header_device(header, cache, i);
		if (r) {
			KFERR();
			kfree(header);
			return r;
		}
		header_id = le64_to_cpu(header->global_id);

		if (header_id < 1){
			continue;
                }
                
                //                print_hex((unsigned char *)header, 2048);

		if (header_id < oldest_id) {
			oldest_idx = i;
			oldest_id = header_id;
		}
	}

        last_fulled_id = 0;
	init_segment_id =last_fulled_id + 1;

	/*
	 * If no segment was flushed
	 * then there is nothing to recover.
	 */
	if (oldest_id == max_id)
		goto setup_init_segment;

	/*
	 * What we have to do in the next loop is to
	 * revive the segments that are
	 * flushed but yet not migrated.
	 */

	/*
	 * Example:
	 * There are only 5 segments.
	 * The segments we will consider are of id k+2 and k+3
	 * because they are dirty but not migrated.
	 *
	 * id: [     k+3    ][  k+4   ][   k    ][     k+1     ][  K+2  ]
	 *      last_flushed  init_seg  migrated  last_migrated  flushed
	 */
	for (i = oldest_idx; i < (nr_segments + oldest_idx); i++) {
		div_u64_rem(i, nr_segments, &j);

		r = read_segment_header_device(header, cache, j);
		if (r) {
			KFERR();
			kfree(header);
			return r;
		}
		header_id = le64_to_cpu(header->global_id);

		/*
		 * Valid global_id > 0.
		 * We encounter header with global_id = 0 and
		 * we can consider
		 * this and the followings are all invalid.
		 */
		if (header_id <= last_fulled_id) {
                        kfdebug("invalid - seg header id:%lld,last filledid:%lld", header_id, last_fulled_id);
			break;
                }
                        
		/*
		 * Now the header is proven valid.
		 */

		last_fulled_id = header_id;
		init_segment_id = last_fulled_id + 1;

		/*
		 * If the data is already on the backing store,
		 * we ignore the segment.
		 */
		if (header_id <= record_id){
			continue;
                }

		update_by_segment_header_device(cache, header);
	}

setup_init_segment:
	kfree(header);
        
	seg = get_segment_header_by_id(cache, init_segment_id);
	seg->global_id = init_segment_id;
	atomic_set(&seg->nr_inflight_ios, 0);

	atomic64_set(&cache->last_fulled_segment_id,
		     seg->global_id - 1);

	atomic64_set(&cache->last_migrated_segment_id,
		atomic64_read(&cache->last_fulled_segment_id) > cache->nr_segments ?
		atomic64_read(&cache->last_fulled_segment_id) - cache->nr_segments : 0);

	if (record_id > atomic64_read(&cache->last_migrated_segment_id))
		atomic64_set(&cache->last_migrated_segment_id, record_id);

	wait_for_migration(cache, seg->global_id);

	discard_caches_inseg(cache, seg);

	/*
	 * cursor is set to the first element of the segment.
	 * This means that we will not use the element.
	 */
	cache->cursor = seg->start_idx;
	seg->length = 0;
        
	cache->current_seg = seg;

        kfdebug("initial segment:%lld, LM:%lld, cursor:%d",
                init_segment_id, atomic64_read(&cache->last_migrated_segment_id), cache->cursor);

	return 0;
}

/*----------------------------------------------------------------*/

static int __must_check init_rambuf_pool(struct wb_cache *cache)
{
	size_t i, j;
	struct rambuffer *rambuf;

	u32 nr = div_u64(cache->rambuf_pool_amount * 1000,
			 1 << (cache->segment_size_order + SECTOR_SHIFT));

	if (!nr) {
		KFERR("rambuf must be allocated at least one");
		return -EINVAL;
	}

	cache->nr_rambuf_pool = nr;
	cache->rambuf_pool = kmalloc(sizeof(struct rambuffer) * nr,
				     GFP_KERNEL);
	if (!cache->rambuf_pool) {
		KFERR();
		return -ENOMEM;
	}

	for (i = 0; i < cache->nr_rambuf_pool; i++) {
		rambuf = cache->rambuf_pool + i;
		init_completion(&rambuf->done);
		complete_all(&rambuf->done);

		rambuf->data = kmalloc(
			1 << (cache->segment_size_order + SECTOR_SHIFT),
			GFP_KERNEL);
		if (!rambuf->data) {
			KFERR();
			for (j = 0; j < i; j++) {
				rambuf = cache->rambuf_pool + j;
				kfree(rambuf->data);
			}
			kfree(cache->rambuf_pool);
			return -ENOMEM;
		}
	}

	return 0;
}

static void free_rambuf_pool(struct wb_cache *cache)
{
	struct rambuffer *rambuf;
	size_t i;
	for (i = 0; i < cache->nr_rambuf_pool; i++) {
		rambuf = cache->rambuf_pool + i;
		kfree(rambuf->data);
	}
	kfree(cache->rambuf_pool);
}

/*----------------------------------------------------------------*/

/*
 * Allocate new migration buffer by the nr_batch size.
 * On success, it frees the old buffer.
 *
 * User may set # of batches
 * that can hardly allocate the memory spaces.
 * This function is safe for that case.
 */
int alloc_migration_buffer(struct wb_cache *cache, size_t nr_batch)
{
	void *buf, *snapshot;

	buf = vmalloc(nr_batch * (cache->nr_caches_inseg << 12));
	if (!buf) {
		KFERR("couldn't allocate migration buffer");
		return -ENOMEM;
	}

	snapshot = kmalloc(nr_batch * cache->nr_caches_inseg, GFP_KERNEL);
	if (!snapshot) {
		vfree(buf);
		KFERR("couldn't allocate dirty snapshot");
		return -ENOMEM;
	}

	if (cache->migrate_buffer)
		vfree(cache->migrate_buffer);

	kfree(cache->dirtiness_snapshot); /* kfree(NULL) is safe */

	cache->migrate_buffer = buf;
	cache->dirtiness_snapshot = snapshot;
	cache->nr_cur_batched_migration = nr_batch;

	return 0;
}

void free_migration_buffer(struct wb_cache *cache)
{
	vfree(cache->migrate_buffer);
	kfree(cache->dirtiness_snapshot);
}

/*----------------------------------------------------------------*/

#define CREATE_DAEMON(name) \
	do { \
		cache->name##_daemon = kthread_create(name##_proc, cache, \
						      #name "_daemon"); \
		if (IS_ERR(cache->name##_daemon)) { \
			r = PTR_ERR(cache->name##_daemon); \
			cache->name##_daemon = NULL; \
			KFERR("couldn't spawn" #name "daemon"); \
			goto bad_##name##_daemon; \
		} \
		wake_up_process(cache->name##_daemon); \
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
	cache->nr_caches_inseg = (1 << (cache->segment_size_order - 3)) - 1;
	cache->nr_caches = cache->nr_segments * cache->nr_caches_inseg;

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

	r = init_rambuf_pool(cache);
	if (r) {
		KFERR("couldn't alloc rambuf pool");
		goto bad_init_rambuf_pool;
	}
	cache->flush_job_pool = mempool_create_kmalloc_pool(cache->nr_rambuf_pool,
							    sizeof(struct flush_job));
	if (!cache->flush_job_pool) {
		r = -ENOMEM;
		KFERR("couldn't alloc flush job pool");
		goto bad_flush_job_pool;
	}

	/* Select arbitrary one as the initial rambuffer. */
	cache->current_rambuf = cache->rambuf_pool + 0;

	r = init_segment_header_array(cache);
	if (r) {
		KFERR("couldn't alloc segment header array");
		goto bad_alloc_segment_header_array;
	}

	r = ht_empty_init(cache);
	if (r) {
		KFERR("couldn't alloc hashtable");
		goto bad_alloc_ht;
	}

-	/*
	 * (2) Recovering Metadata
	 * Recovering the cache metadata
	 * prerequires the migration daemon working.
	 */

	/* Migration Daemon */
	atomic_set(&cache->migrate_fail_count, 0);
	atomic_set(&cache->migrate_io_count, 0);

	/*
	 * default number of batched migration
	 * is 1MB / segment size
	 * eMMC can consume nearly 32MB/sec writes.
	 */
        //16 -> 32MB
	nr_batch = 1 << (14 - cache->segment_size_order);
        cache->nr_max_batched_migration = nr_batch;
	if (alloc_migration_buffer(cache, nr_batch)) {
		r = -ENOMEM;
		goto bad_alloc_migrate_buffer;
	}

	init_waitqueue_head(&cache->migrate_wait_queue);
	INIT_LIST_HEAD(&cache->migrate_list);

	cache->allow_migrate = true;
	cache->urge_migrate = false;
	CREATE_DAEMON(migrate);

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
	cache->enable_migration_modulator = true;
	CREATE_DAEMON(modulator);

	/* Superblock Recorder */
	cache->update_record_interval = 60;
	CREATE_DAEMON(recorder);

	return 0;

bad_sync_daemon:
	kthread_stop(cache->recorder_daemon);
bad_recorder_daemon:
	kthread_stop(cache->modulator_daemon);
bad_modulator_daemon:
bad_recover:
	kthread_stop(cache->migrate_daemon);
bad_migrate_daemon:
	free_migration_buffer(cache);
bad_alloc_migrate_buffer:
	free_ht(cache);
bad_alloc_ht:
	free_segment_header_array(cache);
bad_alloc_segment_header_array:
	mempool_destroy(cache->flush_job_pool);
bad_flush_job_pool:
	free_rambuf_pool(cache);
bad_init_rambuf_pool:
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
	kthread_stop(cache->recorder_daemon);
	kthread_stop(cache->modulator_daemon);

	kthread_stop(cache->migrate_daemon);
	free_migration_buffer(cache);

	/* Destroy in-core structures */
	free_ht(cache);
	free_segment_header_array(cache);

	free_rambuf_pool(cache);
}
