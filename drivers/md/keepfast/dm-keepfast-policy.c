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
	spinlock_t lock;

	struct list_head hot_queue;
	struct list_head invalid_queue;

	/*
	 * We know exactly how many cblocks will be needed,
	 * so we can allocate them up front.
	 */
	dm_cblock_t cache_size, nr_cblocks_allocated;
        u32 nr_blocks, nr_blocks_inseg, nr_pages_inseg;
        u32 nr_sectors_per_block;
        u32 nr_sectors_per_cpage_shift;
        u32 nr_sectors_per_block_shift;

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

__le32 pack_dflag(dm_block_t block, u8 dflag)
{
	u32 value = block;
	value <<= 4;
	value = value | (dflag & FLAG_MASK);
	return cpu_to_le32(value);
}

void unpack_dflag(__le32 value_le, dm_block_t *block, u8 *dflag)
{
	u32 value = le32_to_cpu(value_le);
	*block = value >> 4;
	*dflag = value & FLAG_MASK;
}

__le32 pack_vflag(u32 idx, u8 vflag)
{
	u32 value = idx;
	value <<= 4;
	value = value | (vflag & FLAG_MASK);
	return cpu_to_le32(value);
}

void unpack_vflag(__le32 value_le, u32 *idx, u8 *vflag)
{
        u32 value = le32_to_cpu(value_le);
	*idx = value >> 4;
	*vflag = value & FLAG_MASK;
}

int try_lru_put_hot(struct policy_operation *pop, struct cache_entry *ce)
{
        struct policy *p = to_policy(pop);
        struct metablock *mb = ce->mb;
        struct metablock *mb_cold;
        int need_balance = 0;
	unsigned long flags;        

        if(mb->hit_count <= p->hot_limit_count)
                return 0;

        if(p->hot_blocks > p->nr_blocks * p->hot_threshold / 100)
                need_balance = 1;

        spin_lock_irqsave(&p->lock, flags);
        if(&mb->hot_list) 
                list_del(&mb->hot_list);
        else {
                if(need_balance) {
                        mb_cold = list_entry(p->hot_queue.next, struct metablock, hot_list);
                        list_del(&mb_cold->hot_list);
                        mb_cold->hit_count = 0;
                } else 
                        p->hot_blocks++;
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
        return oblock & ~(p->nr_sectors_per_block - 1); 
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
        
        head = ht_get_head(p, oblock);
        
	hlist_del(&mb->ht_list);
	hlist_add_head(&mb->ht_list, &head->ht_list);

        mb->oblock_packed_d = pack_dflag(oblock, 0);
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

static inline u8 entry_get_tag(struct policy *p, dm_oblock_t oblock)
{
        return (oblock & (p->nr_sectors_per_block - 1)) >> 3;
}

int wb_lookup(struct policy_operation *pop, dm_oblock_t oblock,
                            struct cache_entry *ce)
{
        struct policy *p = to_policy(pop);
        struct wb_cache *cache = p->cache;
        struct sub_entry *se = &ce->se;
        struct metablock *mb;
        struct segment_header *seg;
        dm_oblock_t oblock_unpacked;
	unsigned long flags;
        u32 key;
        u32 ofs_in_block;
        u8 tag;
        u32 dflag;
        u32 vflag;
        u32 mb_idx;

        key = ht_get_key(p, oblock);
        mb = ht_lookup(p, key);

        tag = entry_get_tag(p, oblock);

        memset(se, 0, sizeof(struct sub_entry *));
        se->tag = tag;

        ce->oblock = key;

        if (mb) {
                spin_lock_irqsave(&p->lock, flags);
                mb->hit_count++;
                if(mb->hit_count > p->hot_limit_count) 
                        ce->hot = 1;
                unpack_dflag(mb->oblock_packed_d, &oblock_unpacked, &ce->dflags);
                unpack_vflag(mb->idx_packed_v, &ce->idx, &ce->vflags);
                spin_unlock_irqrestore(&p->lock, flags);

                seg = get_segment_header_by_mb(cache, mb);
                atomic_inc(&seg->nr_inflight_ios);

                if(ce->dflags & (1 << tag))
                        se->dflag = 1;

                if(ce->vflags & (1 << tag))
                        se->vflag = 1;

                ce->seg = seg;
                ce->mb = mb;
                ce->cblock = calc_mb_start_sector(cache, seg, ce->idx);
                se->cblock = ce->cblock + (tag << p->nr_sectors_per_cpage_shift);
                se->oblock = oblock;

                return POLICY_HIT;
	}

        return POLICY_MISS;
}

void wb_get_dirty(struct policy_operation *pop, struct cache_entry *ce)
{

}

static void wb_set_dirty(struct policy_operation *pop, struct cache_entry *ce)
{
        struct policy *p = to_policy(pop);
        struct metablock *mb = ce->mb;
        struct sub_entry *se = &ce->se;
        u32 tag = se->tag;
	unsigned long flags;        

        spin_lock_irqsave(&p->lock, flags);
        mb->oblock_packed_d |= (1 << tag);
        spin_unlock_irqrestore(&p->lock, flags);

        kfdebug("W - [ce idx:%d, oblock:%d, cblock:%d, flags(d:%d,v:%d), hot:%d] [se oblock:%d,cblock:%d, tag:%d hitcnt:%d]",
                mb->idx_packed_v&~0xf, ce->oblock, ce->cblock, mb->oblock_packed_d&0xf, mb->idx_packed_v&0xf, ce->hot,
                se->oblock, se->cblock, se->tag, mb->hit_count);
}

static void wb_clear_dirty(struct policy_operation *pop, struct cache_entry *ce)
{
        struct policy *p = to_policy(pop);
        struct metablock *mb = ce->mb;
        struct sub_entry *se = &ce->se;
        u32 tag = se->tag;        
	unsigned long flags;        

        spin_lock_irqsave(&p->lock, flags);
        mb->oblock_packed_d &=  ~(1 << tag);        
        spin_unlock_irqrestore(&p->lock, flags);        

        //        dec_nr_dirty_caches(cache->wb);
}

static void wb_set_valid(struct policy_operation *pop, struct cache_entry *ce)
{
        struct policy *p = to_policy(pop);
        struct metablock *mb = ce->mb;
        struct sub_entry *se = &ce->se;
        u32 tag = se->tag;
	unsigned long flags;        

        spin_lock_irqsave(&p->lock, flags);
        mb->idx_packed_v |= (1 << tag);
        spin_unlock_irqrestore(&p->lock, flags);
        
}

static void wb_clear_valid(struct policy_operation *pop, struct cache_entry *ce)
{
        struct policy *p = to_policy(pop);
        struct metablock *mb = ce->mb;
        struct sub_entry *se = &ce->se;
        u32 tag = se->tag;
        unsigned long flags;

        spin_lock_irqsave(&p->lock, flags);
        mb->idx_packed_v &= ~(1 << tag);
        spin_unlock_irqrestore(&p->lock, flags);        
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
        
        ht_del(p, mb);
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
	u64 next_id;        
	size_t n1 = 0, n2 = 0;

        printk(KERN_INFO"GET NEXT SEG");

	next_id = current_seg->global_id + 1;        
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

	while (atomic_read(&next_seg->nr_inflight_ios)) {
		n2++;
		if (n2 == 100)
			KFWARN("inflight ios remained for new seg");
		schedule_timeout_interruptible(msecs_to_jiffies(1));
	}

        //	BUG_ON(count_dirty_caches_remained(next_seg));

        remove_mappings_inseg(pop, next_seg); 

	/*
	 * Set the cursor to the last of the flushed segment.
	 */

        spin_lock_irqsave(&p->lock, flags);
	cache->cursor = current_seg->start_idx + (p->nr_blocks_inseg - 1);
	next_seg->length = 0;        
        spin_unlock_irqrestore(&p->lock, flags);

	cache->current_seg = next_seg;
}

void alloc_cache_entry(struct policy_operation *pop, struct cache_entry *ce)
{
        struct policy *p = to_policy(pop);        
        struct wb_cache *cache = p->cache;
        struct segment_header *seg = ce->seg;
        struct segment_header *wseg;
        struct metablock *mb;
        u32 idx_inseg;
        u32 tmp32;
        u32 wcursor;
        u32 ncursor;
        int i;
        
        unsigned long flags;

        spin_lock_irqsave(&p->lock, flags);
        wseg = cache->current_seg;
        wseg->length++;
        BUG_ON(wseg->length > p->nr_blocks_inseg);
        wcursor = cache->cursor;

        idx_inseg = do_div(wcursor, p->nr_blocks_inseg);

	mb = wseg->mb_array + idx_inseg;
	mb->oblock_packed_d = 0;
        mb->idx_packed_v &= ~0xf;
        spin_unlock_irqrestore(&p->lock, flags);

        ncursor = cache->cursor + 1;
        tmp32 = do_div(ncursor, p->nr_blocks_inseg);

        wseg->last_mb_in_segment = !tmp32;
        
	if(wseg->last_mb_in_segment)
                get_next_segment(pop, p, cache); /* get a next segment previously */

        ncursor = cache->cursor + 1;
        spin_lock_irqsave(&p->lock, flags);
        cache->cursor = do_div(ncursor, p->nr_blocks); /* the cursor points to the empty point. */
        spin_unlock_irqrestore(&p->lock, flags);
        
	atomic_inc(&wseg->nr_inflight_ios);

        ce->seg = wseg;
        ce->mb = mb;
        ce->cblock = calc_mb_start_sector(cache, wseg, mb->idx_packed_v >> 4);

        printk(KERN_INFO"allocate a centry(segid:%lld, mbidxby cursor:%d, cblock:%d)mbidx:%d cursor:%d", cpu_to_le64(wseg->global_id), idx_inseg, (u32)ce->cblock, mb->idx_packed_v >> 4, cache->cursor);
}

void wb_insert_mapping(struct policy_operation *pop, dm_oblock_t oblock, struct cache_entry *ce)
{
        struct metablock *mb;
        struct policy *p = to_policy(pop);
        struct sub_entry *se = &ce->se;        
        u32 ofs_in_block;
        u32 key;        
        u8 tag;

        key = ht_get_key(p, oblock);
        mb = ce->mb;
        ht_register(p, key, mb);

        tag = entry_get_tag(p, oblock);

        se->cblock = ce->cblock + (tag << p->nr_sectors_per_cpage_shift);
        se->oblock = oblock;
        se->tag = tag;
}

/*
 * Discard all the metablock in a segment.
 */
//void discard_caches_inseg(struct wb_cache *cache, struct segment_header *seg)
void remove_mappings_inseg(struct policy_operation *pop, struct segment_header *seg)
{
	u8 i;
        struct policy *p = to_policy(pop);
        
	for (i = 0; i < p->nr_blocks_inseg; i++) {
		struct metablock *mb = seg->mb_array + i;
		ht_del(p, mb);
	}
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
	p->op.map = NULL;
	p->op.lookup = wb_lookup;
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
        unsigned long flags;

	p = kzalloc(sizeof(*p), GFP_KERNEL);        
	if (!p)
		return -1;

	init_policy_functions(p);

        cache->pop = &p->op;
        p->cache = cache;

        spin_lock_init(&p->lock);

        p = to_policy(cache->pop);

        INIT_LIST_HEAD(&p->hot_queue);

        p->nr_sectors_per_block = 1 << cache->nr_sectors_per_block_shift;
        p->nr_sectors_per_block_shift = cache->nr_sectors_per_block_shift;
        p->nr_sectors_per_cpage_shift = 3;
        p->hot_limit_count = 10;

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
