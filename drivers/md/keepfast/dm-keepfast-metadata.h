/*
 * Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This file is released under the GPL.
 */

#ifndef DM_WRITEBOOST_METADATA_H
#define DM_WRITEBOOST_METADATA_H

/*----------------------------------------------------------------*/

struct segment_header *get_segment_header_by_id(struct wb_cache *,
						u32 segment_id);
struct segment_header *get_segment_header_by_mb(struct wb_cache *cache,
                                                struct metablock *mb);
sector_t calc_mb_start_sector(struct wb_cache *,
			      struct segment_header *, u32 mb_idx);
bool is_on_curseg(struct wb_cache *, u32 mb_idx);

/*----------------------------------------------------------------*/

int __must_check audit_cache_device(struct dm_dev *, struct wb_cache *,
				    bool *need_format, bool *allow_format);
int __must_check format_cache_device(struct dm_dev *, struct wb_cache *);

/*----------------------------------------------------------------*/

void meta_prepare_for_write(struct wb_cache *cache, struct segment_header *seg, struct segment_header_device *dest);

/*----------------------------------------------------------------*/

int alloc_flush_buffer(struct wb_cache *cache, size_t nr_batch);
void free_flush_buffer(struct wb_cache *cache);

/*----------------------------------------------------------------*/

int __must_check resume_cache(struct wb_cache *cache, struct dm_dev *dev);
void free_cache(struct wb_cache *cache);

/*----------------------------------------------------------------*/

u32 calc_segment_lap(struct wb_cache *cache, u64 segment_id);

#define  get_mb_idx_inseg(cache, idx, idx_inseg) \
        div_u64_rem(idx, cache->nr_blocks_inseg, idx_inseg)

struct bigarray *make_bigarray(u32 elemsize, u64 nr_elems);
void kill_bigarray(struct bigarray *arr);
void *bigarray_at(struct bigarray *arr, u64 i);

struct metablock *mb_at(struct wb_cache *cache, u32 idx);

struct metablock *get_next_mb(struct wb_cache *cache);

void print_hex(unsigned char *r_buf, unsigned int size);

#endif
