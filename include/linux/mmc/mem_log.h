/*
 *  linux/include/linux/mmc/discard.h
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 *  Card driver specific definitions.
 */

#ifndef _LINUX_MEM_LOG_H
#define _LINUX_MEM_LOG_H

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

#ifndef CONFIG_MEM_LOG_BUF_SHIFT
#define CONFIG_MEM_LOG_BUF_SHIFT	0
#endif

#ifndef R1_STATE_PRG
#define R1_STATE_PRG	7
#endif

#define __MEM_LOG_BUF_LEN	(1 << CONFIG_MEM_LOG_BUF_SHIFT)

#define MEM_LOG_IDLE		0x00	/* 000 */
#define MEM_LOG_MMC			0x01	/* 001 */
#define MEM_LOG_SCSI		0x02	/* 010 */
#define MEM_LOG_BLOCK		0x03	/* 011 */
#define MEM_LOG_APP			0x04	/* 100 */

#define MEM_LOG_READ		0x01	/* 001 */
#define MEM_LOG_WRITE		0x02	/* 010 */
#define MEM_LOG_OPCODE		0x03	/* 011 */

#define MEM_LOG_APP_END		0x00		/* 1 */
#define MEM_LOG_APP_START	0x01		/* 0 */

#define mem_target_getopt(c, opt)	(((c)->flag & 0x07) == opt)
#define mem_cmd_getopt(c, opt)	(((c)->flag >> 3 & 0x07) == opt)
#define mem_app_getopt(c, opt) (((c)->flag >> 6 & 0x01) == opt)

#define mem_target_setopt(c, opt)	((c)->flag |= opt)
#define mem_cmd_setopt(c, opt)	((c)->flag |= opt << 3)
#define mem_app_setopt(c, opt) ((c)->flag |= opt << 6)

#define mem_target_clearopt(c, opt)	((c)->flag &= ~opt)
#define mem_cmd_clearopt(c, opt)	((c)->flag &= ~opt << 3)
#define mem_app_clearopt(c, opt) ((c)->flag &= ~opt << 6)

enum MEM_APP_NAME {
	MEM_APP_CAMERA		= 0,
	MEM_APP_WEB,
	MEM_APP_CONTACTS,
	MEM_APP_INSTALL,
	MEM_APP_MEDIASCANNER,
	MEM_APP_GALLERY,
	MEM_APP_MANUAL		= 20,
};

enum MEM_RESP_STATE {
	MEM_RESP_TRANS		= 0,
	MEM_RESP_PRG 		= 1,
	MEM_RESP_SWITCHING	= 2,
};

enum MEM_CMD_TYPE {
	MEM_CT_NONE		= 0,
	MEM_CT_META 	= 1,
	MEM_CT_CONTEXT	= 2,
};

struct mem_log_config {
	int mem_enable;
	int mem_start;
	int mem_appNum;
	int mem_appCnt;
	int mem_print;
	char* mem_path;
	int stat_enable;
	char* stat_path;
};

/* total 32byte */
typedef struct _MEM_LOG_PARCER_T{
	char flag;
	char app_num;
	unsigned int sector;
	unsigned int sector_len;
	unsigned long long cur_time;
	unsigned long long latency_time;
	unsigned char opcode;			/* if block_add then opcode is queue_count */
	long tagid;
	char reserved;
} __packed mem_log_parcer_t;

typedef struct _MEM_LOG_T{
	mem_log_parcer_t* log_buf;
	int init;
	unsigned long max_index;
	unsigned long cur_index;
	int start;
	int enable;
	spinlock_t lock;
	struct task_struct	*kthread;
	struct semaphore	thread_sem;
	signed long sched_timeout;
	int resp_state;
	unsigned long long first_req_time;
	unsigned long long last_done_time;
	int emmc_req_start;
	int scsi_req_dispatch;
	const char* hostName;		// emmc hostname
	int log_print;
	char *filepath;
}mem_log_t;
//#endif /* CONFIG_MMC_MEM_LOG_BUFF */

int init_memLog(void);
void memlog_set_hostname(const char* num);
int memlog_start_config(struct mem_log_config *config);
int memlog_emmc_add(struct mmc_request *mrq, unsigned long long curTime, unsigned long long latency);
int memlog_opcode_add(struct mmc_request *mrq, unsigned long long curTime, unsigned long long latency);
int memlog_app_add(int start, int name, int cnt);
int memlog_set_enable(int enable);
int memlog_print(void);
int memlog_release(void);
void memlog_exit_print_thread(void);

void memlog_mmc_request_start(struct mmc_host *host);
void memlog_mmc_request_done(struct mmc_request *mrq, struct mmc_host *host);

extern void memlog_set_cmd_type(int type);

/* debug utility functions */
#ifdef CONFIG_MMC_MEM_LOG_DEBUG
#define _mdbg_msg(fmt, args...) printk(KERN_INFO "[MEMLOG]//%s(%d): " fmt, __func__, __LINE__, ##args)
#else
#define _mdbg_msg(fmt, args...)
#endif /* CONFIG_MMC_MEM_LOG_BUFF_DEBUG */

#ifndef _err_msg
#define _err_msg(fmt, args...) printk(KERN_ERR "%s(%d): " fmt, __func__, __LINE__, ##args)
#endif

#endif /*_LINUX_MEM_LOG_H */

