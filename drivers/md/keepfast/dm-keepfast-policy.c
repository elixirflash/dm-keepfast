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

	struct list_head hot;
	struct list_head invalid_queue;

	/*
	 * We know exactly how many cblocks will be needed,
	 * so we can allocate them up front.
	 */
	dm_cblock_t cache_size, nr_cblocks_allocated;
        u32 nr_blocks, nr_blocks_inseg;

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

static void init_policy_functions(struct policy *p);

static struct policy *to_policy(struct policy_operation *p)
{
	return container_of(p, struct policy, op);
}

struct ht_head *ht_get_head(struct policy *p, dm_oblock_t oblock)
{
	u32 idx;
        
	idx = do_div(oblock, p->nr_blocks);
	return bigarray_at(p->htable, idx);
}

static bool cache_hit(struct metablock *mb, dm_oblock_t oblock)
{
	return mb->oblock == oblock;
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

	mb->oblock = oblock;
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

        p->nr_blocks = cache->nr_caches;
        p->nr_blocks_inseg = cache->nr_caches_inseg ;

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

int add_invalid_centry(struct policy_operation *pop, struct cache_entry *centry)
{
        struct policy *p = to_policy(pop);
        struct metablock *mb = centry->mb;

        list_add_tail(&mb->inv_list, &p->invalid_queue);

        return 0;
}

static int get_invalid_centry(struct policy_operation *pop, struct cache_entry *centry)
{
        struct policy *p = to_policy(pop);
	struct wb_cache *cache = p->cache;        
        struct metablock *mb;

        if(list_empty(&p->invalid_queue))
                return 0;
        
        mb = list_entry(p->invalid_queue.next, struct metablock, inv_list);
        list_del(&mb->inv_list);
        centry->seg = get_segment_header_by_mb(cache, mb);
        centry->mb = mb;

        return 1;
}

int wb_lookup(struct policy_operation *pop, dm_oblock_t oblock,
                            struct cache_entry *centry)
{
        struct policy *p = to_policy(pop);
        struct wb_cache *cache = p->cache;
        struct metablock *mb;
        struct segment_header *seg;
        
        mb = ht_lookup(p, oblock);

        if (mb) {
                seg = get_segment_header_by_mb(cache, mb);
                atomic_inc(&seg->nr_inflight_ios);

                centry->seg = seg;
                centry->mb = mb;                
                centry->cblock = calc_mb_start_sector(cache, seg, mb->idx);

                return POLICY_HIT;
	}

        return POLICY_MISS;
}

static void wb_set_dirty(struct policy_operation *pop, struct cache_entry *centry)
{
        struct policy *p = to_policy(pop);        
        struct metablock *mb = centry->mb;
	unsigned long flags;        

        spin_lock_irqsave(&p->lock, flags);
        if(centry->set_partial_dirty) {
                printk(KERN_INFO"partial dirty:%d", centry->set_partial_dirty);
                mb->dirty_bits = centry->set_partial_dirty;
        }
        
        mb->dirty_bits = 255;
        spin_unlock_irqrestore(&p->lock, flags);
}

static void wb_clear_dirty(struct policy_operation *pop, struct cache_entry *centry)
{
        struct policy *p = to_policy(pop);
        struct wb_cache *cache = p->cache;
        
        //bring from cleanup_mb_if_dirty
        struct metablock *mb = centry->mb;
	unsigned long flags;
	bool b = false;

        spin_lock_irqsave(&p->lock, flags);
	if (mb->dirty_bits) {
		mb->dirty_bits = 0;
		b = true;
	}
        spin_unlock_irqrestore(&p->lock, flags);

	if (b)
		dec_nr_dirty_caches(cache->wb);
}

//resume
/*
void wb_load_mapping(struct policy_operation *pop, dm_oblock_t oblock)
{

}
*/

void wb_remove_mapping(struct policy_operation *pop, struct cache_entry *centry)
{
        struct policy *p = to_policy(pop);        
        struct metablock *mb = centry->mb;
        
        ht_del(p, mb);
}

int wb_writeback_work(struct policy_operation *pop, dm_cblock_t cblock)
{
        return 0;
}

static u8 count_dirty_caches_remained(struct segment_header *seg)
{
	u8 i, count = 0;

	struct metablock *mb;
	for (i = 0; i < seg->length; i++) {
		mb = seg->mb_array + i;
		if (mb->dirty_bits) {
			count++;
                }
	}
	return count;
}

static void get_next_segment(struct policy_operation *pop, struct policy *p, struct wb_cache *cache)
{
	unsigned long flags;
	struct segment_header *current_seg = cache->current_seg;
	struct segment_header *next_seg;
	u64 next_id;        
	size_t n1 = 0, n2 = 0;

	next_id = current_seg->global_id + 1;        
	/*
	 * Before we get the next segment
	 * we must wait until the segment is all clean.
	 * A clean segment doesn't have
	 * log to flush and dirties to migrate.
	 */        
	wait_for_migration(cache, next_id);

	while (atomic_read(&current_seg->nr_inflight_ios)) {
		n1++;
		if (n1 == 150){
			KFWARN("inflight ios remained for current seg");
                }
		schedule_timeout_interruptible(msecs_to_jiffies(1));
	}

	INIT_COMPLETION(current_seg->migrate_done);
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

	BUG_ON(count_dirty_caches_remained(next_seg));

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

void alloc_cache_entry(struct policy_operation *pop, struct cache_entry *centry)
{
        struct policy *p = to_policy(pop);        
        struct wb_cache *cache = p->cache;
        struct segment_header *seg = centry->seg;
        struct segment_header *wseg;
        struct metablock *mb;
        u32 mb_idx;
        u32 tmp32;
        u64 wcursor;
        unsigned long flags;

        if(policy_overwrite) {
                if(get_invalid_centry(pop, centry)) {
                        atomic_inc(&seg->nr_inflight_ios);
                        return;
                }
        }

        spin_lock_irqsave(&p->lock, flags);
        wseg = cache->current_seg;
        wseg->length++;
        BUG_ON(wseg->length > p->nr_blocks_inseg);
        wcursor = cache->cursor;
        div_u64_rem(wcursor, p->nr_blocks_inseg, &mb_idx);               
	mb = wseg->mb_array + mb_idx;
	mb->dirty_bits = 0;                
        spin_unlock_irqrestore(&p->lock, flags);

 	div_u64_rem(cache->cursor + 1 , p->nr_blocks_inseg, &tmp32);
        wseg->last_mb_in_segment = !tmp32;
        
	if(wseg->last_mb_in_segment)
                get_next_segment(pop, p, cache); /* get a next segment previously */

        spin_lock_irqsave(&p->lock, flags);
	div_u64_rem(cache->cursor + 1, p->nr_blocks, &tmp32);
	cache->cursor = tmp32; /* the cursor points to the empty point. */
        spin_unlock_irqrestore(&p->lock, flags);
        
	atomic_inc(&wseg->nr_inflight_ios);

        centry->seg = wseg;
        centry->mb = mb;
        centry->cblock = calc_mb_start_sector(cache, wseg, mb->idx);
        printk(KERN_INFO"segid:%lld, mbidx:%d, cblock:%d", cpu_to_le64(wseg->global_id), mb_idx, (u32)centry->cblock);
}

void wb_insert_mapping(struct policy_operation *pop, dm_oblock_t oblock, struct cache_entry *centry)
{
        struct metablock *mb;
        struct policy *p = to_policy(pop);

        mb = centry->mb;
        ht_register(p, oblock, mb);
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

        printk(KERN_INFO"p:%x p:%x", (unsigned int)to_policy(&p->op), (unsigned int)p);

        spin_lock_init(&p->lock);

        p = to_policy(cache->pop);
        spin_lock_irqsave(&p->lock, flags);
        spin_unlock_irqrestore(&p->lock, flags);
        printk(KERN_INFO"p address:%x, lock adr:%x", (unsigned int)p, (unsigned int)&p->lock.rlock);        

        INIT_LIST_HEAD(&p->invalid_queue);        

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
