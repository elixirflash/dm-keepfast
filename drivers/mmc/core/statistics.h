/*
 *  linux/include/linux/mmc/discard.h
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 *  Card driver specific definitions.
 */

#ifndef _LINUX_STATISTICS_H
#define _LINUX_STATISTICS_H

#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/delay.h>

#include <linux/vmalloc.h>
#include <linux/string.h>

#include <linux/mmc/mmc.h>
#include <linux/mmc/core.h>
#include <linux/mmc/card.h>
#include <linux/mmc/host.h>
#include <linux/blkdev.h>
#include <linux/sched.h>
#include <linux/kthread.h>

#define SECTOR_SIZE_COUNT 9
#define MIN_SECTOR_SIZE 4096

#pragma pack(1)
typedef struct _MMC_REQUEST_T{
	unsigned int chuck_size;
	unsigned long long rCnt;
	unsigned long long wCnt;
	unsigned long long r_latency_time;
	unsigned long long w_latency_time;
}mmc_request_t;

typedef struct _MMC_STATISTIC_T {
	int init;
	int enable;
	const char* hostName;		// emmc hostname
	char* filepath;
	spinlock_t lock;
	struct task_struct	*kthread;
	struct semaphore	thread_sem;
	signed long sched_timeout;
	struct completion completion;
	//unsigned long long total_blocks;
	unsigned long long total_rBlocks;
	unsigned long long total_wBlocks;
	unsigned long long high_latency;
	unsigned int high_latency_chunk;
	mmc_request_t *mmc_requests;
	mmc_request_t *last_wbuf;
	unsigned int last_blocks;
	unsigned long long start_wtime;
	unsigned long long last_done_status_time;
}mmc_statistic_t;
#pragma pack()

int init_statistics(void);
void statistic_set_hostname(const char* num);
int statistic_set_enable(int enable);
int statistic_set_file_path(char* path);
int statistic_emmc_add(struct mmc_request *mrq, unsigned long long curTime, unsigned long long latency);
int statistic_opcode_add(struct mmc_request *mrq, unsigned long long curTime, unsigned long long latency);
void statistic_mmc_request_done(struct mmc_request *mrq, struct mmc_host *host);
void statistic_mmc_request_start(struct mmc_host *host);
int statistic_result(void);

/* debug utility functions */
#ifdef CONFIG_MMC_STATISTIC_DEBUG
#define _sdbg_msg(fmt, args...) printk(KERN_INFO "[MEMLOG]//%s(%d): " fmt, __func__, __LINE__, ##args)
#else
#define _sdbg_msg(fmt, args...)
#endif /* CONFIG_MMC_MEM_LOG_BUFF_DEBUG */

#ifndef _err_msg
#define _err_msg(fmt, args...) printk(KERN_ERR "%s(%d): " fmt, __func__, __LINE__, ##args)
#endif

#endif /*_LINUX_STATISTICS_H */

