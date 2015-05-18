/*
 * Copyright (C) 2012 Red Hat. All rights reserved.
 *
 * This file is released under the GPL.
 */

#ifndef DM_CACHE_POLICY_H
#define DM_CACHE_POLICY_H

#include <linux/device-mapper.h>
#include <linux/list.h>

#include "dm-keepfast-blocktype.h"

/*----------------------------------------------------------------*/

/* FIXME: make it clear which methods are optional.  Get debug policy to
 * double check this at start.
 */

/*
 * The cache policy makes the important decisions about which blocks get to
 * live on the faster cache device.
 *
 * When the core target has to remap a bio it calls the 'map' method of the
 * policy.  This returns an instruction telling the core target what to do.
 *
 * POLICY_HIT:
 *   That block is in the cache.  Remap to the cache and carry on.
 *
 * POLICY_MISS:
 *   This block is on the origin device.  Remap and carry on.
 *
 * POLICY_NEW:
 *   This block is currently on the origin device, but the policy wants to
 *   move it.  The core should:
 *
 *   - hold any further io to this origin block
 *   - copy the origin to the given cache block
 *   - release all the held blocks
 *   - remap the original block to the cache
 *
 * POLICY_REPLACE:
 *   This block is currently on the origin device.  The policy wants to
 *   move it to the cache, with the added complication that the destination
 *   cache block needs a writeback first.  The core should:
 *
 *   - hold any further io to this origin block
 *   - hold any further io to the origin block that's being written back
 *   - writeback
 *   - copy new block to cache
 *   - release held blocks
 *   - remap bio to cache and reissue.
 *
 * Should the core run into trouble while processing a POLICY_NEW or
 * POLICY_REPLACE instruction it will roll back the policies mapping using
 * remove_mapping() or force_mapping().  These methods must not fail.  This
 * approach avoids having transactional semantics in the policy (ie, the
 * core informing the policy when a migration is complete), and hence makes
 * it easier to write new policies.
 *
 * In general policy methods should never block, except in the case of the
 * map function when can_migrate is set.  So be careful to implement using
 * bounded, preallocated memory.
 */
enum policy_operation_result {
	POLICY_HIT,
	POLICY_MISS,
	POLICY_NEW,
	POLICY_REPLACE
};

/*
 * This is the instruction passed back to the core target.
 */
struct policy_result {
	enum policy_operation_result op;
	dm_oblock_t old_oblock;	/* POLICY_REPLACE */
	dm_cblock_t cblock;	/* POLICY_HIT, POLICY_NEW, POLICY_REPLACE */
};

typedef int (*policy_walk_fn)(void *context, dm_cblock_t cblock,
			      dm_oblock_t oblock, uint32_t hint);

/*
 * The cache policy object.  Just a bunch of methods.  It is envisaged that
 * this structure will be embedded in a bigger, policy specific structure
 * (ie. use container_of()).
 */
struct policy_operation {

	/*
	 * FIXME: make it clear which methods are optional, and which may
	 * block.
	 */

	/*
	 * Destroys this object.
	 */
	void (*destroy)(struct policy_operation *pop);

	/*
	 * See large comment above.
	 *
	 * oblock      - the origin block we're interested in.
	 *
	 * can_block - indicates whether the current thread is allowed to
	 *             block.  -EWOULDBLOCK returned if it can't and would.
	 *
	 * can_migrate - gives permission for POLICY_NEW or POLICY_REPLACE
	 *               instructions.  If denied and the policy would have
	 *               returned one of these instructions it should
	 *               return -EWOULDBLOCK.
	 *
	 * discarded_oblock - indicates whether the whole origin block is
	 *               in a discarded state (FIXME: better to tell the
	 *               policy about this sooner, so it can recycle that
	 *               cache block if it wants.)
	 * bio         - the bio that triggered this call.
	 * result      - gets filled in with the instruction.
	 *
	 * May only return 0, or -EWOULDBLOCK (if !can_migrate)
	 */
	int (*map)(struct policy_operation *pop, dm_oblock_t oblock, struct cache_entry *ce);        

	/*
	 * Sometimes we want to see if a block is in the cache, without
	 * triggering any update of stats.  (ie. it's not a real hit).
	 *
	 * Must not block.
	 *
	 * Returns 0 if in cache, -ENOENT if not, < 0 for other errors
	 * (-EWOULDBLOCK would be typical).
	 */
	int (*lookup)(struct policy_operation *pop, dm_oblock_t oblock, struct cache_entry *ce);

	void (*set_flag)(struct policy_operation *pop, struct cache_entry *ce);        

	void (*set_valid)(struct policy_operation *pop, struct cache_entry *ce);
	void (*clear_valid)(struct policy_operation *pop, struct cache_entry *ce);        

	void (*set_dirty)(struct policy_operation *pop, struct cache_entry *ce);
	void (*clear_dirty)(struct policy_operation *pop, struct cache_entry *ce);

	/*
	 * Called when a cache target is first created.  Used to load a
	 * mapping from the metadata device into the policy.
	 */
	int (*load_mapping)(struct policy_operation *pop, dm_oblock_t oblock,
			    dm_cblock_t cblock, uint32_t hint, bool hint_valid);

	int (*walk_mappings)(struct policy_operation *pop, policy_walk_fn fn,
			     void *context);

	/*
	 * Override functions used on the error paths of the core target.
	 * They must succeed.
	 */
	void (*remove_mapping)(struct policy_operation *pop, struct cache_entry *ce);
	int (*insert_mapping)(struct policy_operation *pop, dm_oblock_t oblock, struct cache_entry *ce);
	void (*force_mapping)(struct policy_operation *pop, dm_oblock_t current_oblock,
			      dm_oblock_t new_oblock);

	/*
	 * This is called via the invalidate_cblocks message.  It is
	 * possible the particular cblock has already been removed due to a
	 * write io in passthrough mode.  In which case this should return
	 * -ENODATA.
	 */
	int (*remove_cblock)(struct policy_operation *pop, dm_cblock_t cblock);

	/*
	 * Provide a dirty block to be written back by the core target.
	 *
	 * Returns:
	 *
	 * 0 and @cblock,@oblock: block to write back provided
	 *
	 * -ENODATA: no dirty blocks available
	 */
	int (*writeback_work)(struct policy_operation *pop, dm_cblock_t cblock);

	/*
	 * How full is the cache?
	 */
	dm_cblock_t (*residency)(struct policy_operation *pop);

	/*
	 * Because of where we sit in the block layer, we can be asked to
	 * map a lot of little bios that are all in the same block (no
	 * queue merging has occurred).  To stop the policy being fooled by
	 * these the core target sends regular tick() calls to the policy.
	 * The policy should only count an entry as hit once per tick.
	 */
	void (*tick)(struct policy_operation *pop);

	/*
	 * Configuration.
	 */
	int (*emit_config_values)(struct policy_operation *pop,
				  char *result, unsigned maxlen);
	int (*set_config_value)(struct policy_operation *pop,
				const char *key, const char *value);

	/*
	 * Book keeping ptr for the policy register, not for general use.
	 */
	void *private;
};

/*----------------------------------------------------------------*/

/*
 * We maintain a little register of the different policy types.
 */
#define CACHE_POLICY_NAME_SIZE 16
#define CACHE_POLICY_VERSION_SIZE 3

struct dm_cache_policy_type {
	/* For use by the register code only. */
	struct list_head list;

	/*
	 * Policy writers should fill in these fields.  The name field is
	 * what gets passed on the target line to select your policy.
	 */
	char name[CACHE_POLICY_NAME_SIZE];
	unsigned version[CACHE_POLICY_VERSION_SIZE];

	/*
	 * For use by an alias dm_cache_policy_type to point to the
	 * real dm_cache_policy_type.
	 */
	struct dm_cache_policy_type *real;

	/*
	 * Policies may store a hint for each each cache block.
	 * Currently the size of this hint must be 0 or 4 bytes but we
	 * expect to relax this in future.
	 */
	size_t hint_size;

	struct module *owner;
	struct dm_cache_policy *(*create)(dm_cblock_t cache_size,
					  sector_t origin_size,
					  sector_t block_size);
};

extern int add_invalid_ce(struct policy_operation *pop, struct cache_entry *ce);
extern void remove_mappings_inseg(struct policy_operation *pop, struct segment_header *seg);
extern void alloc_cache_entry(struct policy_operation *pop, struct cache_entry *ce);
extern bool policy_bytealign;
extern int try_lru_put_hot(struct policy_operation *pop, struct cache_entry *ce);
//extern void get_cache_entry_info(struct policy_operation *pop, struct cache_entry *ce);
extern int get_entry_and_clear_dirty(struct policy_operation *pop, struct cache_entry *ce);
extern  void unpack_dflag(u32 value, dm_block_t *block, u8 *dflag);
extern u32 pack_dflag(dm_block_t block, u8 dflag);
extern void unpack_vflag(u32 value_le, u32 *idx, u8 *vflag);
extern void pack_vflag(u32 *value, u8 vflag);

extern int entry_is_hot(struct policy_operation *pop, struct cache_entry *ce);
extern u32 count_flag(struct policy_operation *pop, u8 flag);
extern void add_replace_list(struct policy_operation *pop, struct cache_entry *ce, u8 dflags);
extern void del_replace_list(struct policy_operation *pop);
extern void wait_for_cleaned(struct policy_operation *pop, struct cache_entry *ce);
extern u8 restore_dflag(struct policy_operation *pop, struct cache_entry *ce);
extern void run_around_segment(struct policy_operation *pop);
extern void check_flags(struct policy_operation *pop);
extern void snapshot_cache_entry_info(struct policy_operation *pop, struct cache_entry *ce, u8 *dflags_snapshot, u8 *vflags_snapshot, u8 *hot_snapshot);
extern struct metablock *get_unsync_entry(struct policy_operation *pop, struct cache_entry *ce);
extern struct segment_header *set_current_flush_seg(struct policy_operation *pop, struct cache_entry *ce);

/*----------------------------------------------------------------*/

#endif	/* DM_CACHE_POLICY_H */
