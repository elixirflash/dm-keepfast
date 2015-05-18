/*
 * Copyright (C) 2012 Red Hat, Inc.
 *
 * This file is released under the GPL.
 */

#ifndef DM_CACHE_BLOCK_TYPES_H
#define DM_CACHE_BLOCK_TYPES_H

typedef uint32_t dm_block_t;
typedef dm_block_t __bitwise__ dm_oblock_t;
typedef dm_block_t __bitwise__ dm_cblock_t;

static inline dm_oblock_t to_oblock(dm_block_t b)
{
	return (__force dm_oblock_t) b;
}

static inline dm_block_t from_oblock(dm_oblock_t b)
{
	return (__force dm_block_t) b;
}

static inline dm_cblock_t to_cblock(uint32_t b)
{
	return (__force dm_cblock_t) b;
}

static inline uint32_t from_cblock(dm_cblock_t b)
{
	return (__force uint32_t) b;
}

#endif /* DM_CACHE_BLOCK_TYPES_H */
