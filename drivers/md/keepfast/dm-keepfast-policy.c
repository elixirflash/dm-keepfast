#include "dm-keepfast.h"
#include "dm-keepfast-metadata.h"
#include "dm-keepfast-daemon.h"
#include "dm-keepfast-policy.h"
#include "dm-keepfast-policy-internal.h"

bool policy_overwrite;
bool policy_bytealign;

struct policy {
	struct policy_operation op;
        struct wb_cache *cache;
        struct segment_header *current_flush_seg;
        struct metablock *unsync_entry[2];
        int unsync_cnt;
        int unsync_idx;
        
	spinlock_t lock;

	struct list_head hot_queue;
	struct list_head invalid_queue;
        struct list_head idirty_queue;

	/*
	 * We know exactly how many cblocks will be needed,
	 * so we can allocate them up front.
	 */
	dm_cblock_t cache_size, nr_cblocks_allocated;
        u32 nr_blocks, nr_blocks_inseg, nr_pages_inblock;
        u32 nr_sectors_per_centry;
        u32 nr_sectors_per_sentry_shift;
        u32 nr_sectors_per_centry_shift;

        u32 hot_limit_count;
        u32 hot_threshold;
        u32 hot_blocks;

	/*
	 * Chained hashtable
	 *
	 * Keepfast uses chained hashtable
	 * to cache lookup.
	 * Cache discarding often happedns
	 * This structure fits our needs.
	 */
	struct bigarray *htable;
	struct ht_head *null_head;
};

static struct policy *to_policy(struct policy_operation *p)
{
	return container_of(p, struct policy, op);
}

#define FLAG_MASK     0xF

u32 count_flag(struct policy_operation *pop, u8 flag)
{
        struct policy *p = to_policy(pop);
        u32 cnt = 0;
        int i;

        for(i = 0; i < p->nr_pages_inblock; i++)
                if(flag & (1 << i)) 
                        cnt++;

        return cnt;
}
#if 1
void snapshot_cache_entry_info(struct policy_operation *pop, struct cache_entry *ce, u8 *dflags_snapshot, u8 *vflags_snapshot, u8 *hot_snapshot)
{
        struct policy *p = to_policy(pop);
        struct segment_header *seg = ce->seg;
        struct wb_cache *cache = p->cache;        
        struct metablock *mb;
	unsigned long flags;        
        int i;

        spin_lock_irqsave(&p->lock, flags);
	for (i = 0; i < cache->nr_blocks_inseg; i++) {
		mb = seg->mb_array + i;
                dflags_snapshot[i] = mb->oblock_packed_d & FLAG_MASK;
                vflags_snapshot[i] = mb->idx_packed_v & FLAG_MASK;
                if(mb->hit_count > p->hot_limit_count)
                        hot_snapshot[i] = 1;
                else
                        hot_snapshot[i] = 0;
        }
        spin_unlock_irqrestore(&p->lock, flags);  
}
#endif
void get_entry_and_clear_dirty(struct policy_operation *pop, struct cache_entry *ce)
{
        struct policy *p = to_policy(pop);
        struct wb_cache *cache = p->cache;                
        struct cache_stats *stats = &cache->stats;
        struct metablock *mb = ce->mb;        
	unsigned long flags;        
        u8 dflags;
        u8 vflags;
        u8 tag;
        int i;
        
        spin_lock_irqsave(&p->lock, flags);
	ce->dflags = mb->oblock_packed_d & FLAG_MASK;
        ce->oblock = mb->oblock_packed_d >> 4;
	ce->vflags = mb->idx_packed_v & FLAG_MASK;
        ce->idx = mb->idx_packed_v >> 4;
        if(mb->hit_count > p->hot_limit_count)
                ce->hot = 1;
        else
                ce->hot = 0;
        
        for(tag = 0; tag < 4; tag++) {
                if(mb->idx_packed_v & (1 << tag) &
                   mb->oblock_packed_d & (1 << tag)) {
                        for(i = 0; i < p->unsync_cnt; i++) {
                                if(p->unsync_entry[i] != mb) {
                                        mb->oblock_packed_d &=  ~(1 << tag);
                                        atomic64_dec(&stats->dirty);
                                        atomic64_inc(&stats->flush);
                                        break;
                                }
                                else
                                        printk(KERN_INFO"flush thread tried to clear %d unsync entry", i);
                        }
                           
                        if(!(mb->oblock_packed_d & FLAG_MASK))
                                mb->hit_count = 0;
                }
        }

        spin_unlock_irqrestore(&p->lock, flags);
}

u32 pack_dflag(dm_block_t block, u8 dflag)
{
	u32 value = block;
	value <<= 4;
	value = value | (dflag & FLAG_MASK);
	return value;
}

void unpack_dflag(u32 value, dm_block_t *block, u8 *dflag)
{
	*block = value >> 4;
	*dflag = value & FLAG_MASK;
}

void pack_vflag(u32 *value, u8 vflag)
{
        *value &= ~FLAG_MASK;
	*value |= (vflag & FLAG_MASK);
}

void unpack_vflag(u32 value, u32 *idx, u8 *vflag)
{
	*idx = value >> 4;
	*vflag = value & FLAG_MASK;
}

int entry_is_hot(struct policy_operation *pop, struct cache_entry *ce)
{
        struct policy *p = to_policy(pop);
        struct metablock *mb = ce->mb;

        if(mb->hit_count > p->hot_limit_count)
                return 1;

        return 0;
}

#if 0
struct segment_header *set_current_flush_seg(struct policy_operation *pop, struct segment_header *seg)
{
        struct policy *p = to_policy(pop);
	unsigned long flags;
        
        spin_lock_irqsave(&p->lock, flags);
        p->current_flush_seg = seg;        

        spin_unlock_irqrestore(&p->lock, flags);

        return seg;
}

#endif
u8 restore_dflag(struct policy_operation *pop, struct cache_entry *ce)
{
        struct policy *p = to_policy(pop);
        struct metablock *mb = ce->mb;
	unsigned long flags;
        u8 dflags = 0;
        int tag;

        for(tag = 0; tag < 4; tag++) {
                if(mb->idx_packed_v & (1 << tag))
                        dflags |= (1 << tag);
        }

        return dflags;
}

void set_idirty_list(struct policy_operation *pop, struct cache_entry *ce, u8 dflags)
{
        struct policy *p = to_policy(pop);
        struct metablock *mb = ce->mb;
	unsigned long flags;                

        spin_lock_irqsave(&p->lock, flags);
        mb->oblock_packed_d &= ~FLAG_MASK;
        mb->oblock_packed_d |= dflags;
        list_add_tail(&mb->hot_list, &p->idirty_queue); //sync? with flush        
        spin_unlock_irqrestore(&p->lock, flags);
        

}

void clear_idirty_list(struct policy_operation *pop)
{
        struct policy *p = to_policy(pop);
        struct wb_cache *cache = p->cache;
        struct cache_entry ce = {0, };
        struct segment_header *seg;
        struct metablock *mb;
        int tag;
	unsigned long flags;
      
        while (!list_empty(&p->idirty_queue)) {
                spin_lock_irqsave(&p->lock, flags);                
                mb = list_entry(p->idirty_queue.next, struct metablock, hot_list);
                seg = get_segment_header_by_mb(cache, mb);                                
                list_del_init(&mb->hot_list);

                //                ce.mb = mb;
                //                get_cache_entry_info(pop, &ce);
                
                for(tag = 0; tag < 4; tag++) {
                        if(!(mb->idx_packed_v & (1 << tag)) &&
                           mb->oblock_packed_d & (1 << tag)) {
                                mb->oblock_packed_d &=  ~(1 << tag);
                        }
                }
                spin_unlock_irqrestore(&p->lock, flags);                                                
                printk(KERN_INFO"%s - clear entry of idx:%d, oblock:%d, vflags:%d, dflags:%d", __FUNCTION__,  mb->idx_packed_v>>4, mb->oblock_packed_d >>4, mb->oblock_packed_d &FLAG_MASK, mb->oblock_packed_d&FLAG_MASK);
                printk(KERN_INFO"mb oblock:%d", mb->oblock_packed_d >>4 );                                               
                wake_up_interruptible(&seg->flush_wait_queue);
        }
}
                      
void wait_for_cleaned(struct policy_operation *pop, struct cache_entry *ce)
{
        struct sub_entry *se = &ce->se;
        struct metablock *mb = ce->mb;
        struct segment_header *seg = ce->seg;
        u8 tag = se->tag;

        printk(KERN_INFO"dirty:%d", (mb->oblock_packed_d & (1 << se->tag)));
#if 0
        while(1) {
                printk(KERN_INFO"%d", (mb->oblock_packed_d & (1 << se->tag)));
        }
#endif        
        wait_event_interruptible(seg->flush_wait_queue,
                                 (mb->oblock_packed_d & (1 << tag)) == 0);

        printk(KERN_INFO"%d", mb->oblock_packed_d & FLAG_MASK);
}

int try_lru_put_hot(struct policy_operation *pop, struct cache_entry *ce)
{
        struct policy *p = to_policy(pop);
        struct wb_cache *cache = p->cache;
        struct cache_stats *stats = &cache->stats;        
        struct metablock *mb = ce->mb;
        struct metablock *mb_hot;
        int need_balance = 0;
	unsigned long flags;        

        if(mb->hit_count <= p->hot_limit_count)
                return 0;

        //        printk(KERN_INFO"hotblocks:%d, limitblocks:%d", p->nr_blocks * p->hot_threshold / 100, (unsigned int)mb->hot_list);
        if(p->hot_blocks > p->nr_blocks * p->hot_threshold / 100)
                need_balance = 1;

        //        printk(KERN_INFO"%s - bypass hot:%d, cnt:%d", __FUNCTION__, mb->idx_packed_v >> 4, mb->hit_count);

        spin_lock_irqsave(&p->lock, flags);
        if(!list_empty(&mb->hot_list)) 
                list_del(&mb->hot_list);
        else {
                if(need_balance) {
                        mb_hot = list_entry(p->hot_queue.next, struct metablock, hot_list);
                        list_del_init(&mb_hot->hot_list);
                        mb_hot->hit_count = 0;
                } else  {
                        atomic64_inc(&stats->hot);
                        p->hot_blocks++;
                }
        }

        list_add_tail(&mb->hot_list, &p->hot_queue);
        spin_unlock_irqrestore(&p->lock, flags);

        return 1;
}

static void init_policy_functions(struct policy *p);

struct ht_head *ht_get_head(struct policy *p, dm_oblock_t oblock)
{
	u32 idx;
        
	idx = do_div(oblock, p->nr_blocks);
	return bigarray_at(p->htable, idx);
}

static inline u32 ht_get_key(struct policy *p, dm_oblock_t oblock)
{
        return oblock & ~(p->nr_sectors_per_centry - 1); 
}

static inline bool cache_hit(struct metablock *mb, dm_oblock_t oblock)
{
	return (mb->oblock_packed_d >> 4) == oblock;
}

struct metablock *ht_lookup(struct policy *p, dm_oblock_t oblock)
{
	struct metablock *mb, *found = NULL;
        struct hlist_node *node;
	struct ht_head *head;

        head = ht_get_head(p, oblock);

	hlist_for_each_entry(mb, node, &head->ht_list, ht_list) {
		if (cache_hit(mb, oblock)) {
			found = mb;
			break;
		}
	}

	return found;
}

void ht_del(struct policy *p, struct metablock *mb)
{
	struct ht_head *null_head;

	hlist_del(&mb->ht_list);

	null_head = p->null_head;
	hlist_add_head(&mb->ht_list, &null_head->ht_list);
}

void ht_register(struct policy *p, dm_oblock_t oblock,
                 struct metablock *mb)
{
	struct ht_head *head;
        u8 dflags = mb->oblock_packed_d & FLAG_MASK; /* for recovery */
        
        head = ht_get_head(p, oblock);
        
	hlist_del(&mb->ht_list);
	hlist_add_head(&mb->ht_list, &head->ht_list);

        mb->oblock_packed_d = pack_dflag(oblock, dflags);
};

static void free_ht(struct bigarray *htable)
{
        kill_bigarray(htable);
}

/*
 * Initialize the Hash Table.
 */
static int __must_check ht_init(struct wb_cache *cache, struct policy *p)
{
	u32 idx;
	size_t i, nr_heads;
	struct bigarray *arr;

        p->nr_blocks = cache->nr_blocks;
        p->nr_blocks_inseg = cache->nr_blocks_inseg ;

	nr_heads = p->nr_blocks + 1;

        printk(KERN_INFO"nr_blocks(nr caches:%d)", p->nr_blocks);
	arr = make_bigarray(sizeof(struct ht_head), nr_heads);
	if (!arr) {
		KFERR();
		return -ENOMEM;
	}

	p->htable = arr;

	for (i = 0; i < nr_heads; i++) {
		struct ht_head *hd = bigarray_at(arr, i);
		INIT_HLIST_HEAD(&hd->ht_list);
	}

	/*
	 * Our hashtable has one special bucket called null head.
	 * Orphan metablocks are linked to the null head.
	 */
	p->null_head = bigarray_at(p->htable, p->nr_blocks);

	for (idx = 0; idx < p->nr_blocks; idx++) {
		struct metablock *mb = mb_at(cache, idx);
		hlist_add_head(&mb->ht_list, &p->null_head->ht_list);
	}

	return 0;
}

//------------------------------------------------------------------------

static inline u8 entry_get_tag(struct policy *p, dm_oblock_t oblock)
{
        return (oblock & (p->nr_sectors_per_centry - 1)) >> 3;
}

int wb_lookup(struct policy_operation *pop, dm_oblock_t oblock,
                            struct cache_entry *ce)
{
        struct policy *p = to_policy(pop);
        struct wb_cache *cache = p->cache;
        struct cache_stats *stats = &cache->stats;
        struct sub_entry *se = &ce->se;
        struct metablock *mb;
        struct segment_header *seg;
        dm_oblock_t oblock_unpacked;
	unsigned long flags;
        u32 key;
        u8 tag;

        key = ht_get_key(p, oblock); 
        tag = entry_get_tag(p, oblock);

        mb = ht_lookup(p, key);
        ce->oblock = key;
        ce->cblock = -1;
        ce->seg = NULL;
        ce->mb = mb;

        /* for debugging when it's missed reading */
        se->oblock = oblock & ~((1 << p->nr_sectors_per_sentry_shift) -1);

        if (mb) {
                ce->mb = mb;
                return POLICY_HIT;                
        }

        return POLICY_MISS;        
}

int wb_map(struct policy_operation *pop, dm_oblock_t oblock,
                            struct cache_entry *ce)
{
        struct policy *p = to_policy(pop);
        struct wb_cache *cache = p->cache;
        struct cache_stats *stats = &cache->stats;
        struct sub_entry *se = &ce->se;
        struct metablock *mb;
        struct segment_header *seg;
        dm_oblock_t oblock_unpacked;
	unsigned long flags;
        u32 key;
        u8 tag;

        key = ht_get_key(p, oblock); 
        tag = entry_get_tag(p, oblock);

        spin_lock_irqsave(&p->lock, flags);
        mb = ht_lookup(p, key);
        spin_unlock_irqrestore(&p->lock, flags);
        
        memset(se, 0, sizeof(struct sub_entry *));
        se->tag = tag;

        ce->oblock = key;
        ce->cblock = -1;
        ce->seg = NULL;
        ce->mb = mb;

        /* for debugging when it's missed reading */
        se->oblock = oblock & ~((1 << p->nr_sectors_per_sentry_shift) -1);

        if (mb) {
                seg = get_segment_header_by_mb(cache, mb);

                ce->seg = seg;
                ce->mb = mb;

                spin_lock_irqsave(&p->lock, flags);                
                unpack_dflag(mb->oblock_packed_d, &oblock_unpacked, &ce->dflags);
                unpack_vflag(mb->idx_packed_v, &ce->idx, &ce->vflags);
                spin_unlock_irqrestore(&p->lock, flags);                

                if(ce->dflags & (1 << tag))
                        se->dflag = 1;

                if(ce->vflags & (1 << tag))
                        se->vflag = 1;

                ce->cblock = calc_mb_start_sector(cache, seg, ce->idx);
                se->cblock = ce->cblock + (tag << p->nr_sectors_per_sentry_shift);

                atomic_inc(&seg->nr_inflight_ios);
                
                spin_lock_irqsave(&p->lock, flags);
                mb->hit_count++;
                if(mb->hit_count > p->hot_limit_count) 
                        ce->hot = 1;

                if(atomic_read(&cache->current_flush_seg_id) == seg->global_id  && !entry_is_hot(pop, ce) &&
                   cache->current_seg->global_id != seg->global_id) {
                        p->unsync_entry[p->unsync_idx] = NULL;                    
                        spin_unlock_irqrestore(&p->lock, flags);
                        
                        return POLICY_REPLACE;
                }
                p->unsync_idx ^= 1;
                p->unsync_entry[p->unsync_idx] = mb;                                        
                spin_unlock_irqrestore(&p->lock, flags);                        


                //                printk(KERN_INFO"%s - segid:%d, oblock:%d, seoblock:%d, tag:%d, dflag:%d, start_sec:%d", __FUNCTION__, seg->global_id, oblock, se->oblock, tag, ce->dflags, seg->start_sector);
                return POLICY_HIT;
	}

        p->unsync_entry[p->unsync_idx] = NULL;        

        return POLICY_MISS;
}

static void wb_set_flag(struct policy_operation *pop, struct cache_entry *ce)
{
        struct policy *p = to_policy(pop);
        struct metablock *mb = ce->mb;
        struct sub_entry *se = &ce->se;
        struct wb_cache *cache = p->cache;
        struct cache_stats *stats = &cache->stats;
	unsigned long flags;
        u32 tag = se->tag;        

        spin_lock_irqsave(&p->lock, flags);
        if(!(mb->oblock_packed_d & (1 << tag))) {
                mb->oblock_packed_d |= (1 << tag);
                atomic64_inc(&stats->dirty);                
        }
        if(!(mb->idx_packed_v & (1 << tag))) {
                mb->idx_packed_v |= (1 << tag);
                atomic64_inc(&stats->valid);                        
        }
        BUG_ON(!(mb->idx_packed_v & (1 << tag)) &&
               mb->oblock_packed_d & (1 << tag));
             
        spin_unlock_irqrestore(&p->lock, flags);
}

static void wb_set_dirty(struct policy_operation *pop, struct cache_entry *ce)
{
        struct policy *p = to_policy(pop);
        struct metablock *mb = ce->mb;
        struct sub_entry *se = &ce->se;
        u32 tag = se->tag;
	unsigned long flags;
        struct wb_cache *cache = p->cache;
        struct cache_stats *stats = &cache->stats;

        BUG_ON(tag > 3);        

        spin_lock_irqsave(&p->lock, flags);
        mb->oblock_packed_d |= (1 << tag);
        spin_unlock_irqrestore(&p->lock, flags);
        atomic64_inc(&stats->dirty);                        

        /*
        kfdebug("W - [ce idx:%d, oblock:%d, cblock:%d, flags(d:%d,v:%d), hot:%d] [se oblock:%d,cblock:%d, tag:%d hitcnt:%d]",
                mb->idx_packed_v&~0xf, ce->oblock, ce->cblock, mb->oblock_packed_d&0xf, mb->idx_packed_v&0xf, ce->hot,
                se->oblock, se->cblock, se->tag, mb->hit_count);*/
}

static void wb_clear_dirty(struct policy_operation *pop, struct cache_entry *ce)
{
        struct policy *p = to_policy(pop);
        struct metablock *mb = ce->mb;
        struct sub_entry *se = &ce->se;
        u32 tag = se->tag;        
	unsigned long flags;
        struct wb_cache *cache = p->cache;
        struct cache_stats *stats = &cache->stats;
        int i;

        BUG_ON(tag > 3);        

        spin_lock_irqsave(&p->lock, flags);
        for(i = 0; i < p->unsync_cnt; i++) {
                if(p->unsync_entry[i] != mb) 
                        mb->oblock_packed_d &=  ~(1 << tag);
                else
                        printk(KERN_INFO"flush thread tried to clear %d unsync entry(oblock:%d)", i, mb->oblock_packed_d>>4);
        }
        if(!(mb->oblock_packed_d & FLAG_MASK))
                mb->hit_count = 0;
        spin_unlock_irqrestore(&p->lock, flags);
        atomic64_dec(&stats->dirty);                
        atomic64_inc(&stats->flush);        
}

static void wb_set_valid(struct policy_operation *pop, struct cache_entry *ce)
{
        struct policy *p = to_policy(pop);
        struct metablock *mb = ce->mb;
        struct sub_entry *se = &ce->se;
        u32 tag = se->tag;
	unsigned long flags;
        struct wb_cache *cache = p->cache;
        struct cache_stats *stats = &cache->stats;

        BUG_ON(tag > 3);

        spin_lock_irqsave(&p->lock, flags);
        mb->idx_packed_v |= (1 << tag);
        spin_unlock_irqrestore(&p->lock, flags);
        atomic64_inc(&stats->valid);        
}

static void wb_clear_valid(struct policy_operation *pop, struct cache_entry *ce)
{
        struct policy *p = to_policy(pop);
        struct metablock *mb = ce->mb;
        struct sub_entry *se = &ce->se;
        u32 tag = se->tag;
        unsigned long flags;
        struct wb_cache *cache = p->cache;
        struct cache_stats *stats = &cache->stats;

        BUG_ON(tag > 3);        

        spin_lock_irqsave(&p->lock, flags);
        mb->idx_packed_v &= ~(1 << tag);
        spin_unlock_irqrestore(&p->lock, flags);
        atomic64_dec(&stats->valid);                
}

//resume
/*
void wb_load_mapping(struct policy_operation *pop, dm_oblock_t oblock)
{

}
*/

void wb_remove_mapping(struct policy_operation *pop, struct cache_entry *ce)
{
        struct policy *p = to_policy(pop);
        struct metablock *mb = ce->mb;
        unsigned long flags;

        spin_lock_irqsave(&p->lock, flags);
        //       BUG_ON(mb->oblock_packed_d & FLAG_MASK);
        ht_del(p, mb);
        spin_unlock_irqrestore(&p->lock, flags);
}

int wb_writeback_work(struct policy_operation *pop, dm_cblock_t cblock)
{
        return 0;
}

static void get_next_segment(struct policy_operation *pop, struct policy *p, struct wb_cache *cache)
{
	struct segment_header *current_seg = cache->current_seg;
	struct segment_header *next_seg;
	unsigned long flags;
	u32 next_id;        
	size_t n1 = 0, n2 = 0;

	next_id = current_seg->global_id + 1;
        kfdebug("%s - Waiting a segid:%d, curid:%d\n", __FUNCTION__, (unsigned int)next_id, current_seg->global_id);
	/*
	 * Before we get the next segment
	 * we must wait until the segment is all clean.
	 * A clean segment doesn't have
	 * log to flush and dirties to migrate.
	 */        
	wait_for_flush(cache, next_id);

	while (atomic_read(&current_seg->nr_inflight_ios)) {
		n1++;
		if (n1 == 150){
			KFWARN("inflight ios remained for current seg");
                }
		schedule_timeout_interruptible(msecs_to_jiffies(1));
	}

	INIT_COMPLETION(current_seg->flush_done);
        //	INIT_COMPLETION(current_seg->flush_done);
        //could need to be done of mb's flush !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

	next_seg = get_segment_header_by_id(cache, next_id);
	next_seg->global_id = next_id;

        //        printk(KERN_INFO"get nextseg id:%d, flight:%d", next_seg->global_id, atomic_read(&next_seg->nr_inflight_ios));

	while (atomic_read(&next_seg->nr_inflight_ios)) {
		n2++;
		if (n2 == 100)
			KFWARN("inflight ios remained for new seg:%d, ios:%d",
                               next_seg->global_id, atomic_read(&next_seg->nr_inflight_ios));
		schedule_timeout_interruptible(msecs_to_jiffies(1));
	}

        //        check_dirty_inseg(pop, next_seg);

        remove_mappings_inseg(pop, next_seg);

	/*
	 * Set the cursor to the last of the flushed segment.
	 */
        spin_lock_irqsave(&p->lock, flags);
	cache->cursor = current_seg->start_idx + (p->nr_blocks_inseg - 1);
	cache->current_seg = next_seg;        
        spin_unlock_irqrestore(&p->lock, flags);
}

void run_around_segment(struct policy_operation *pop)
{
        struct policy *p = to_policy(pop);
        struct wb_cache *cache = p->cache;
        int i;

        for(i = 0; i < cache->nr_segments; i++) 
                get_next_segment(pop, p, cache);
}

void check_flags(struct policy_operation *pop)
{
        struct policy *p = to_policy(pop);
        struct wb_cache *cache = p->cache;                
	struct segment_header *seg;
        struct metablock *mb;        
	struct segment_header *cur_seg = cache->current_seg;
        int i, j;
        int dirties = 0, valides = 0;
        int tag;
        unsigned long flags;        
        
        for (i = 0; i < cache->nr_segments; i++) {
                seg = get_segment_header_by_id(cache, cur_seg->global_id + i);

                for (j = 0; j < cache->nr_blocks_inseg; j++) {
                        mb = seg->mb_array + j;
                        for(tag = 0; tag < 4; tag++) {
                                spin_lock_irqsave(&p->lock, flags);
                                if(mb->oblock_packed_d & (1 << tag))
                                        dirties++;
                                if(mb->idx_packed_v &  (1 << tag))
                                        valides++;
                                spin_unlock_irqrestore(&p->lock, flags);
                        }
                }
        }

        printk(KERN_INFO"dirties:%d valides:%d\n", dirties, valides);
}
              
void alloc_cache_entry(struct policy_operation *pop, struct cache_entry *ce)
{
        struct policy *p = to_policy(pop);
        struct wb_cache *cache = p->cache;
        struct sub_entry *se = &ce->se;
        struct segment_header *wseg;
        struct metablock *mb = NULL;
        u32 idx_inseg;
        u32 wcursor;
        u32 ncursor;
        u8 dflags = 0xf;
        u8 vflags;
        u32 idx, oblock;
        unsigned long flags;
        u32 clean_idx;
        u32 clean_offset = 0;
        
        wseg = cache->current_seg;
        wcursor = cache->cursor;
        idx_inseg = do_div(wcursor, p->nr_blocks_inseg);

        /* find a clean cache entry and bypass dirty cache entries */
        while(dflags) {
                for(clean_idx = idx_inseg; clean_idx < p->nr_blocks_inseg; clean_idx++) {
                        //                        spin_lock_irqsave(&p->lock, flags);   
                        mb = wseg->mb_array + clean_idx;
                        unpack_dflag(mb->oblock_packed_d, &oblock, &dflags);
                        unpack_vflag(mb->idx_packed_v, &idx, &vflags);
                        //                        spin_unlock_irqrestore(&p->lock, flags);        
                        if(!dflags)
                                break;

                        if(mb->hit_count > p->hot_limit_count)
                                kfdebug("%s - bypass hot dirty,clean_idx:%d, blocksinseg:%d, segid:%d, mbidx:%d, dflags:%d, vflags:%d", __FUNCTION__, clean_idx, p->nr_blocks_inseg, wseg->global_id, idx, dflags, vflags);
                        clean_offset++;
                }

                /* it is last clean entry or there is no clean entry in seg */
                if(clean_idx == p->nr_blocks_inseg - 1 ||
                   clean_idx == p->nr_blocks_inseg) {    
                        get_next_segment(pop, p, cache); /* get next segment previously */

                        if(clean_idx == p->nr_blocks_inseg) {
                                BUG_ON(!dflags);
                                idx_inseg = 0;
                                wseg = cache->current_seg;
                        }
                }
        }

        spin_lock_irqsave(&p->lock, flags);
        ncursor = cache->cursor + clean_offset + 1;
        cache->cursor = do_div(ncursor, p->nr_blocks); /* the cursor points to the empty point. */
        spin_unlock_irqrestore(&p->lock, flags);
        
	atomic_inc(&wseg->nr_inflight_ios);
        
        ce->seg = wseg;
        ce->mb = mb;
        ce->cblock = calc_mb_start_sector(cache, wseg, mb->idx_packed_v >> 4);
        ce->idx = mb->idx_packed_v >> 4;

        kfdebug("allocate a centry(segid:%d, mbadr:%x, mbidxby cursor:%d, cblock:%d)mbidx:%d cursor:%d",
               cpu_to_le32(wseg->global_id), (unsigned int )mb, idx_inseg, (u32)ce->cblock, mb->idx_packed_v >> 4, cache->cursor);
}

void wb_insert_mapping(struct policy_operation *pop, dm_oblock_t oblock, struct cache_entry *ce)
{
        struct metablock *mb;
        struct policy *p = to_policy(pop);
        struct sub_entry *se = &ce->se;
        unsigned long flags;        
        u32 key;
        u8 tag;

        tag = entry_get_tag(p, oblock);        

        spin_lock_irqsave(&p->lock, flags);        
        key = ht_get_key(p, oblock);
        mb = ce->mb;
        ht_register(p, key, mb);
        se->vflag = mb->idx_packed_v & (1 << tag);
        se->dflag = mb->oblock_packed_d & (1 << tag);
        spin_unlock_irqrestore(&p->lock, flags);        

        se->cblock = ce->cblock + (tag << p->nr_sectors_per_sentry_shift);
        se->oblock = oblock;
        se->tag = tag;

        
}

void remove_mappings_inseg(struct policy_operation *pop, struct segment_header *seg)
{
        struct policy *p = to_policy(pop);
        struct wb_cache *cache = p->cache;
        struct cache_stats *stats = &cache->stats;
        unsigned long flags;
        u8 dflags, vflags;
        dm_oblock_t oblock;
        u32 valid_count;
        u32 idx;
	u32 i;
        u8 tag;

        spin_lock_irqsave(&p->lock, flags);
        
	for (i = 0; i < p->nr_blocks_inseg; i++) {
		struct metablock *mb = seg->mb_array + i;


#if 1
                /* find out sub entries of invalid and dirty */
                //                if(dflags && mb->hit_count < p->hot_limit_count && vflags != FLAG_MASK) 
                for(tag = 0; tag < 4; tag++) {
                        if(mb->oblock_packed_d  & (1 << tag) &&
                           !(mb->idx_packed_v & (1 << tag))) {
                                printk(KERN_INFO"%s - clear invalid dirty entry(oblock:%d, idx:%d, dflags:%d, vflags:%d)\n\n\n",
                                       __FUNCTION__, mb->oblock_packed_d >> 4, mb->idx_packed_v>>4, mb->oblock_packed_d&FLAG_MASK, mb->idx_packed_v&FLAG_MASK);
                                mb->oblock_packed_d &= ~(1 << tag);
                        }
                }

                //                atomic64_dec(&stats->dirty);                
#endif
                /* remove mapping & clear flags only clean entries
                   bypassing cache entries of dirty */
                
                if(!(mb->oblock_packed_d & FLAG_MASK)) {
                        valid_count = count_flag(pop, mb->idx_packed_v & FLAG_MASK);
                        ht_del(p, mb);
                        mb->hit_count = 0;                        
                        mb->idx_packed_v &= ~FLAG_MASK;

                        atomic64_sub(valid_count, &stats->valid);
                }
	}
        spin_unlock_irqrestore(&p->lock, flags);        
}

void destroy_cache_policy(struct wb_cache *cache)
{
        struct policy_operation *pop = cache->pop;
        struct policy *p = to_policy(pop);

        if(p->htable)
                free_ht(p->htable);

        kfree(p);
}

/*----------------------------------------------------------------------------*/
/* Init the policy plugin interface function pointers. */
static void init_policy_functions(struct policy *p)
{
	p->op.map = wb_map;
	p->op.lookup = wb_lookup;
	p->op.set_flag = wb_set_flag;        
	p->op.set_dirty = wb_set_dirty;
	p->op.clear_dirty = wb_clear_dirty;
	p->op.set_valid = wb_set_valid;
	p->op.clear_valid = wb_clear_valid;        
	p->op.load_mapping = NULL;
	p->op.walk_mappings = NULL;
	p->op.insert_mapping = wb_insert_mapping;
	p->op.remove_mapping = wb_remove_mapping;
	p->op.writeback_work = wb_writeback_work;
	p->op.force_mapping = NULL;
	p->op.residency = NULL;
	p->op.tick = NULL;
}

int create_cache_policy(struct wb_cache *cache, char *name)
{
	int r;
	struct policy *p;

	p = kzalloc(sizeof(*p), GFP_KERNEL);        
	if (!p)
		return -1;

	init_policy_functions(p);

        cache->pop = &p->op;
        p->cache = cache;

        spin_lock_init(&p->lock);

        p = to_policy(cache->pop);

        INIT_LIST_HEAD(&p->hot_queue);
        INIT_LIST_HEAD(&p->idirty_queue);        

        p->nr_sectors_per_centry = 1 << cache->nr_sectors_per_block_shift;
        p->nr_sectors_per_centry_shift = cache->nr_sectors_per_block_shift;
        p->nr_sectors_per_sentry_shift = 3;
        p->nr_pages_inblock = cache->nr_pages_inblock;

        p->hot_threshold = 20;
        p->hot_limit_count = 15;
        p->unsync_idx = 0;
        p->unsync_cnt = 2;

        r = ht_init(cache, p);
	if (r) {
		KFERR("couldn't alloc hashtable");
                goto fail;
	}

        return 0;

fail:        
        kfree(p);
        
        return r;        
}
/*
static int __init wb_ocd_init(void)
{
        return 0;
}

static void __exit wb_ocd_exit(void)
{
}

module_init(wb_ocd_init);
module_exit(wb_ocd_exit);
MODULE_AUTHOR("Jungmo Ahn <jman@elixirflash.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("writeback only cold dirty");

*/
