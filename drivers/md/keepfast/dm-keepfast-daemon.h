/*
 * Copyright (C) 2012-2013 Akira Hayakawa <ruby.wktk@gmail.com>
 *
 * This file is released under the GPL.
 */

#ifndef DM_WRITEBOOST_DAEMON_H
#define DM_WRITEBOOST_DAEMON_H

/*----------------------------------------------------------------*/

int flush_proc(void *);

/*----------------------------------------------------------------*/

void queue_barrier_io(struct wb_cache *, struct bio *);
void barrier_deadline_proc(unsigned long data);
void flush_barrier_ios(struct work_struct *);

/*----------------------------------------------------------------*/

int migrate_proc(void *);
void wait_for_migration(struct wb_cache *, u64 id);

/*----------------------------------------------------------------*/

int modulator_proc(void *);

/*----------------------------------------------------------------*/

int sync_proc(void *);

/*----------------------------------------------------------------*/

int recorder_proc(void *);

/*----------------------------------------------------------------*/

#endif
