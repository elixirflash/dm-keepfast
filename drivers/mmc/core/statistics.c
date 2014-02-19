/*  Copyright 2011-2012 joys
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 */

//************************************************************************************

#include "statistics.h"
#include <linux/fs.h>

#define CONFIG_SUM_WRITE_BUSYTIME

mmc_statistic_t statistics;

int init_statistics(void)
{	
	if (statistics.init)
		return 0;
	
	memset(&statistics, 0, sizeof(mmc_statistic_t));

	if (statistics.mmc_requests == NULL)
		statistics.mmc_requests = (mmc_request_t*)vmalloc(sizeof(mmc_request_t) * SECTOR_SIZE_COUNT);
	
	if (statistics.mmc_requests == NULL) {
		_err_msg("Memorypool alloc fail!\n");
		return -1;
	}

	memset(statistics.mmc_requests, 0, sizeof(mmc_request_t) * SECTOR_SIZE_COUNT);
	statistics.hostName = NULL;
	statistics.init = 1;
	spin_lock_init(&statistics.lock);

	_err_msg("Init Success! // sizeof(mmc_request_t) : %d\n", sizeof(mmc_request_t));

	return 0;
}

void statistic_set_hostname(const char* num) {
	statistics.hostName = num;
}
/*
static int statistic_get_index(unsigned chunk_size) 
{
	int index = fls(chunk_size) - 13;

	return index * (index > 0);
}
*/
static int statistic_get_index(unsigned chunk_size) 
{
	int last = fls(chunk_size);
	int first = ffs(chunk_size);
	int index = 0;

	if (last == first) {
		index = last - fls(MIN_SECTOR_SIZE);
	}
	else {
		index = (last - fls(MIN_SECTOR_SIZE)) + 1;
	}

	if (index >= SECTOR_SIZE_COUNT)
		index = SECTOR_SIZE_COUNT - 1;
	
	return index * (index > 0);
}

static mmc_request_t* get_request_buff(unsigned int size)
{
	mmc_request_t* req_buf = NULL;
	
	int index = statistic_get_index(size);

	if (index < 0)
		return NULL;
	
	req_buf = (mmc_request_t*)(statistics.mmc_requests + index);

	return req_buf;
}

static int statistic_parcer_print(mmc_request_t* log_parcer)
{
	printk ("--------- statistic log ----------!!\n");
	printk ("request size : %d K\n", log_parcer->chuck_size);
	printk ("read count : %llu\n", log_parcer->rCnt);
	printk ("write count : %llu\n", log_parcer->wCnt);
	printk ("read laterncy : %llu\n", log_parcer->r_latency_time);
	printk ("write laterncy : %llu\n", log_parcer->w_latency_time);
	printk ("----------------------------------!!\n");
	return 0;
}

static int statistic_release(void)
{
	if (statistics.mmc_requests)
		memset(statistics.mmc_requests, 0, sizeof(mmc_request_t) * SECTOR_SIZE_COUNT);
	statistics.total_wBlocks = 0;
	statistics.total_rBlocks = 0;
	statistics.high_latency = 0;
	statistics.high_latency_chunk = 0;
	statistics.last_wbuf = NULL;
	statistics.last_blocks = 0;
	statistics.start_wtime = 0;

	if (statistics.filepath) {	
		vfree(statistics.filepath);
		statistics.filepath = NULL;
	}
	/*
	if (statistics.log_buf != NULL)
		vfree(statistics.log_buf);
	*/
	return 0;
}

static int statistic_destroy(void)
{
	if (statistics.mmc_requests)
		vfree(statistics.mmc_requests);

	statistics.init = 0;
	return 0;
}

static void statistic_init_sector_size(void)
{
	int i = 0;

	mmc_request_t* buf;

	if (!statistics.mmc_requests)
		return;
	
	for (i = 0; i < SECTOR_SIZE_COUNT; i++)
	{
		buf = statistics.mmc_requests + i;

		buf->chuck_size = (MIN_SECTOR_SIZE << i) / 1024;
	}
}

static int statistic_print(void)
{
	mmc_request_t* buf = statistics.mmc_requests;
	int index = 0;
	
	if (buf == NULL)
		return 0;
	
	do {
		statistic_parcer_print(buf + index);
		index++;
	} while (index < SECTOR_SIZE_COUNT);	
	
	return 0;
}

static int statistic_save_file(void)
{
	mmc_request_t* buf = statistics.mmc_requests;
	mmc_request_t* req;
	int index = 0;
	struct file *cfile = NULL;
	mm_segment_t old_fs = {0};
	int ret = 0;
	char *file_path = statistics.filepath;
	char bufs[100] = {0, };
	
	if (buf == NULL || file_path == NULL)
		return 0;

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	_sdbg_msg ("Save statistic info to path :  %s\n", file_path);
	cfile = filp_open(file_path, O_CREAT | O_TRUNC | O_RDWR, S_IRUGO | S_IWUGO | S_IXUGO);

	if (IS_ERR(cfile)) {
		_err_msg ("cfile open err!\n");
		set_fs(old_fs);
		return -1;
	}
	
	if (!cfile->f_op || (!cfile->f_op->read && !cfile->f_op->aio_read)) {
		_err_msg ("alloc_device: cache file not readable\n");
		goto ERR;
	}
	if (!cfile->f_op->write && !cfile->f_op->aio_write) {
		_err_msg ("alloc_device: cache file not writeable\n");
		goto ERR;
	}

	_sdbg_msg ("open success!!\n");

	do {	
		req = (mmc_request_t*)(buf + index);
		sprintf(bufs, "%d|%llu|%llu|%llu|%llu\r\n", (req->chuck_size), req->rCnt, req->wCnt, req->r_latency_time, req->w_latency_time);

		ret = vfs_write(cfile, bufs, strlen(bufs), &cfile->f_pos);
		if (ret < 0)
			_err_msg ("Write Failed!! err = %d\n", ret);	
		else
			_sdbg_msg("Write Sucess!! ret = %d\n", ret);

		index++;
	} while (index < SECTOR_SIZE_COUNT);

	/*
	*	total read blocks | total write blocks | high latency | high lathency chunk size
	*/
	sprintf(bufs, "%llu|%llu|%llu|%u\r\n", statistics.total_rBlocks, statistics.total_wBlocks, statistics.high_latency, statistics.high_latency_chunk);
	
	ret = vfs_write(cfile, bufs, strlen(bufs), &cfile->f_pos);
	if (ret < 0) {
		_err_msg ("Write Failed!! err = %d\n", ret);	
		goto ERR;
	}
	else {
		_sdbg_msg("Write Sucess!! ret = %d\n", ret);
	}

	_err_msg ("Saved statistic to path :  %s\n", file_path);
	

ERR:
	filp_close(cfile, NULL);
	set_fs(old_fs);		

	return 0;
}


int statistic_result(void)
{	
	statistic_init_sector_size();
	statistic_save_file();
	//statistic_print();
	statistic_release();
	
	return 0;
}

static void statistic_set_max_latency(unsigned int size, unsigned long long latency)
{
	if (statistics.high_latency < latency) {
		statistics.high_latency = latency;
		statistics.high_latency_chunk = size;
	}
}

int statistic_emmc_add(struct mmc_request *mrq, unsigned long long curTime, unsigned long long latency)
{
	mmc_request_t* req_buf;
	unsigned int chunk_size = 0;
	unsigned long flags;

	spin_lock_irqsave(&statistics.lock, flags);
	
	if (statistics.enable == 0 || statistics.mmc_requests == NULL)
		goto out;
	
	chunk_size = mrq->data->blocks * mrq->data->blksz;

	req_buf = get_request_buff(chunk_size);

	if (req_buf == NULL)
		goto out;

	if (mrq->data->flags == MMC_DATA_WRITE) {
#if defined (CONFIG_SUM_WRITE_BUSYTIME) && defined (CONFIG_MEM_LOG_CMD_ALL)
		statistics.last_wbuf = req_buf;
		statistics.last_blocks = mrq->data->blocks;
		statistics.start_wtime = curTime - latency;
#else
		req_buf->wCnt++;
		statistics.total_wBlocks += (unsigned long long)mrq->data->blocks;
		req_buf->w_latency_time += latency;
#endif
	}
	else if (mrq->data->flags == MMC_DATA_READ) {
		req_buf->rCnt++;
		req_buf->r_latency_time += latency;
		statistics.total_rBlocks += (unsigned long long)mrq->data->blocks;
	}
	req_buf->chuck_size = chunk_size;
	statistic_set_max_latency(req_buf->chuck_size, latency);
	
out:
	spin_unlock_irqrestore(&statistics.lock, flags);
	return 0;
}

int statistic_opcode_add(struct mmc_request *mrq, unsigned long long curTime, unsigned long long latency)
{
	unsigned long flags;
	unsigned long long write_latency;

	spin_lock_irqsave(&statistics.lock, flags);
	
	if (statistics.enable == 0 || statistics.mmc_requests == NULL)
		goto out;

	if (statistics.last_wbuf == NULL || statistics.start_wtime == 0)
		goto out;
	
	if (mrq->cmd->opcode != MMC_SEND_STATUS) {
		write_latency = statistics.last_done_status_time - statistics.start_wtime;		
	}
	else {
		if (!(mrq->cmd->resp[0] & R1_READY_FOR_DATA) || 
			(R1_CURRENT_STATE(mrq->cmd->resp[0]) == R1_STATE_PRG)) {
			statistics.last_done_status_time = curTime;
			goto out;
		}
		else 
			write_latency = curTime - statistics.start_wtime;
	}

	statistics.last_wbuf->wCnt++;
	statistics.total_wBlocks += (unsigned long long)statistics.last_blocks;
	statistics.last_wbuf->w_latency_time += write_latency;
	statistic_set_max_latency(statistics.last_wbuf->chuck_size, write_latency);
	statistics.last_wbuf = NULL;
	statistics.last_blocks = 0;
	statistics.start_wtime = 0;
out:
	spin_unlock_irqrestore(&statistics.lock, flags);
	return 0;
}

int statistic_set_enable(int enable)
{
	unsigned long flags;
#if 0
	if (enable == 0) {
		while(statistics.last_wbuf)
			mdelay(1);
	}
#endif	
	spin_lock_irqsave(&statistics.lock, flags);
	statistics.enable = enable;
	spin_unlock_irqrestore(&statistics.lock, flags);
	
	return 0;
}

int statistic_set_file_path(char* path)
{	
	if (statistics.filepath != NULL)
		vfree(statistics.filepath);

	if (path == NULL) {
		statistics.filepath = NULL;
		return 0;
	}

	statistics.filepath = (char*)vmalloc(strlen(path) + 1);

	if (statistics.filepath == NULL) {
		_err_msg("Memorypool alloc fail!\n");
		return -1;
	}
	
	memset(statistics.filepath, 0, strlen(path) + 1);
	memcpy(statistics.filepath, path, strlen(path));
	
	return 0;
}

///////////////////////////////// Log Call /////////////////////////////////////////////////////////
#if 0
void statistic_mmc_request_done(struct mmc_request *mrq, struct mmc_host *host)
{
	unsigned long long currentTime = 0;	
	unsigned int opcode = 0;

	currentTime = sched_clock();
	
	if (mrq == NULL || host == NULL || statistics.hostName == NULL || glTimeGap3 == 0) {
		glTimeGap3 = 0;
		return;
	}

	if(strcmp(mmc_hostname(host),statistics.hostName))
		return;

	opcode = mrq->cmd->opcode;
	
	if (mrq->data) {		
		/* emmc Timestamp Trace */
		if (opcode == MMC_SEND_CID || opcode == MMC_SEND_CID || opcode == MMC_SEND_CID){
			
		}
		else {
			statistic_emmc_add(mrq, currentTime, currentTime - glTimeGap3);
		}
	}
	
}

void statistic_mmc_request_start(struct mmc_host *host)
{
	if (host == NULL || statistics.hostName == NULL) {
		glTimeGap3 = 0;
		return;
	}

	if(strcmp(mmc_hostname(host),statistics.hostName))	{
		glTimeGap3 = 0;
		return;
	}
	
	glTimeGap3 = sched_clock();	
}
#endif
