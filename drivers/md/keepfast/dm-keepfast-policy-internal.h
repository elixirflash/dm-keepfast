/*
 * Copyright (C) 2012 Red Hat. All rights reserved.
 *
 * This file is released under the GPL.
 */

#ifndef DM_CACHE_POLICY_INTERNAL_H
#define DM_CACHE_POLICY_INTERNAL_H

#include "dm-keepfast-policy.h"
#include "dm-keepfast-blocktype.h"

/*----------------------------------------------------------------*/

/*
 * Little inline functions that simplify calling the policy methods.
 */
static inline int policy_map(struct policy_operation *pop, dm_oblock_t oblock,
			     bool can_block, bool can_migrate, bool discarded_oblock,
			     struct bio *bio, struct policy_result *result)
{
	return pop->map(pop, oblock, can_block, can_migrate, discarded_oblock, bio, result);
}

static inline int policy_lookup(struct policy_operation *pop, dm_oblock_t oblock, struct cache_entry *centry)
{
	BUG_ON(!pop->lookup);
	return pop->lookup(pop, oblock, centry);
}

static inline void policy_set_dirty(struct policy_operation *pop, struct cache_entry *centry)
{
	if (pop->set_dirty)
		pop->set_dirty(pop, centry);
}

static inline void policy_clear_dirty(struct policy_operation *pop, struct cache_entry *centry)
{
	if (pop->clear_dirty)
		pop->clear_dirty(pop, centry);
}

static inline int policy_load_mapping(struct policy_operation *pop,
				      dm_oblock_t oblock, dm_cblock_t cblock,
				      uint32_t hint, bool hint_valid)
{
	return pop->load_mapping(pop, oblock, cblock, hint, hint_valid);
}

static inline int policy_walk_mappings(struct policy_operation *pop,
				      policy_walk_fn fn, void *context)
{
	return pop->walk_mappings ? pop->walk_mappings(pop, fn, context) : 0;
}

static inline int policy_writeback_work(struct policy_operation *pop,
					dm_cblock_t cblock)
{

	return pop->writeback_work ? pop->writeback_work(pop, cblock) : -ENOENT;
}

static inline void policy_insert_mapping(struct policy_operation *pop, dm_oblock_t oblock, struct cache_entry *centry)
{
	pop->insert_mapping(pop, oblock, centry);
}

static inline void policy_remove_mapping(struct policy_operation *pop, struct cache_entry *centry)
{
	pop->remove_mapping(pop, centry);
}

static inline int policy_remove_cblock(struct policy_operation *pop, dm_cblock_t cblock)
{
	return pop->remove_cblock(pop, cblock);
}

static inline void policy_force_mapping(struct policy_operation *pop,
					dm_oblock_t current_oblock, dm_oblock_t new_oblock)
{
	return pop->force_mapping(pop, current_oblock, new_oblock);
}

static inline int policy_set_config_value(struct policy_operation *pop,
					  const char *key, const char *value)
{
	return pop->set_config_value ? pop->set_config_value(pop, key, value) : -EINVAL;
}

/*----------------------------------------------------------------*/

/*
 * Creates a new cache policy given a policy name, a cache size, an origin size and the block size.
 */

extern int create_cache_policy(struct wb_cache *cache, char *name);

/*
 * Destroys the policy.  This drops references to the policy module as well
 * as calling it's destroy method.  So always use this rather than calling
 * the policy->destroy method directly.
 */
extern void destroy_cache_policy(struct wb_cache *cache);

/*
 * In case we've forgotten.
 */
const char *policy_get_name(struct policy_operation *pop);

const unsigned *policy_get_version(struct policy_operation *pop);

size_t policy_get_hint_size(struct policy_operation *pop);

/*----------------------------------------------------------------*/

#endif /* POLICY_INTERNAL_H */
