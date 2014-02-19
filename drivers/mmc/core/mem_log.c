/*  Copyright 2011-2012 joys
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 */

//************************************************************************************

#include <linux/mmc/mem_log.h>
#include <linux/delay.h>
#include <scsi/scsi.h>
#include "statistics.h"

#define CONFIG_TRACE_MEMORY_STATUS_MERGE

mem_log_t tmemLog;
unsigned long long glTimeGap = 0;
unsigned long long glTimeGap2 = 0;
int cur_cmdType;

int init_memLog(void)
{		
	unsigned long buf_len = 0;

	if (tmemLog.init)
		return 0;
	
	memset(&tmemLog, 0, sizeof(mem_log_t));

	buf_len = __MEM_LOG_BUF_LEN / sizeof(mem_log_parcer_t);
	
	if (tmemLog.log_buf == NULL)
		tmemLog.log_buf = (mem_log_parcer_t*)vmalloc(sizeof(mem_log_parcer_t) * buf_len);
	
	if (tmemLog.log_buf == NULL) {
		_err_msg("Memorypool alloc fail!\n");
		return -1;
	}
	
	memset(tmemLog.log_buf, 0, sizeof(mem_log_parcer_t) * buf_len);
	tmemLog.max_index = buf_len;
	tmemLog.cur_index = 0;
	tmemLog.resp_state = MEM_RESP_TRANS;
	tmemLog.hostName = NULL;
	tmemLog.init = 1;
	tmemLog.filepath = NULL;
	spin_lock_init(&tmemLog.lock);

	_err_msg("Init Success! // Available Max Line : %lu\n", tmemLog.max_index);
	_err_msg("Init Success! // mem log buf len : %d // sizeof(mem_log_parcer_t) : %d\n", __MEM_LOG_BUF_LEN, sizeof(mem_log_parcer_t));

	init_statistics();

	return 0;
}

void memlog_set_hostname(const char* num) {
	tmemLog.hostName = num;
}

mem_log_parcer_t* get_mempool_buff(void)
{
	mem_log_parcer_t* mem_buf = NULL;

	_mdbg_msg("cur : %lu // max : %lu\n", tmemLog.cur_index, tmemLog.max_index);

	if (tmemLog.cur_index >= tmemLog.max_index) {
		_err_msg ("Memorypool buff is full!\n"
					"mem_log has been stopped!!\n");
		tmemLog.enable = 0;
		return NULL;
	}
	
	mem_buf = (mem_log_parcer_t*)(tmemLog.log_buf + tmemLog.cur_index);

	tmemLog.cur_index++;
	return mem_buf;
}

int memlog_set_app_name(int index, char* name, unsigned int cnt)
{
	switch (index) {
		case MEM_APP_CAMERA:
			sprintf(name, "%s-%d", "camera", cnt);
			break;
		case MEM_APP_WEB:
			sprintf(name, "%s-%d", "web", cnt);
			break;
		case MEM_APP_CONTACTS:
			sprintf(name, "%s-%d", "contact", cnt);
			break;
		case MEM_APP_INSTALL:
			sprintf(name, "%s-%d", "install", cnt);
			break;
		case MEM_APP_MEDIASCANNER:
			sprintf(name, "%s-%d", "mediascan", cnt);
			break;
		case MEM_APP_GALLERY:
			sprintf(name, "%s-%d", "gallery", cnt);
			break;
		case MEM_APP_MANUAL:
			sprintf(name, "%s", "manual");
			break;

		default:
			sprintf(name, "%s%d-%d", "apps", index, cnt);
			break;
		}
	return 0;
}

int memlog_set_parcer(mem_log_parcer_t* log_parcer, char* buf)
{
	char target[10] = {0,};
	char app_name[32] = {0,};
	char cmd = 0;

	if (log_parcer == NULL)
		return 0;
	
	if (mem_target_getopt(log_parcer, MEM_LOG_MMC)) 
	{
		memcpy(target, "emmc", 4);
	} 
	else if (mem_target_getopt(log_parcer, MEM_LOG_SCSI)) 
	{
		memcpy(target, "scsi", 4);
	} 
	else if (mem_target_getopt(log_parcer, MEM_LOG_BLOCK)) {
		memcpy(target, "block", 5);
	}
	else if (mem_target_getopt(log_parcer, MEM_LOG_APP)) 
	{
		memlog_set_app_name(log_parcer->app_num, app_name, (unsigned int)log_parcer->opcode);
		
		if (mem_app_getopt(log_parcer, MEM_LOG_APP_START))  
		{
			sprintf(buf, "|[EF] |start |%s |%llu\r\n", app_name, log_parcer->cur_time);			
		}
		else {
			sprintf(buf, "|[EF] |end |%s |%llu\r\n", app_name, log_parcer->cur_time);
		}
	}

	if (mem_target_getopt(log_parcer, MEM_LOG_MMC) || mem_target_getopt(log_parcer, MEM_LOG_SCSI)) {
		if (mem_cmd_getopt(log_parcer, MEM_LOG_READ))
			cmd = 'R';
		else if (mem_cmd_getopt(log_parcer, MEM_LOG_WRITE))
			cmd = 'W';
		else if (mem_cmd_getopt(log_parcer, MEM_LOG_OPCODE))
			cmd = 'C';

		//sprintf(buf, "|[EF] |%s |%c |%u |%u |%llu |%llu |%u |%ld\r\n", target, cmd, log_parcer->sector, (log_parcer->sector_len > 1024 ? 2 : log_parcer->sector_len),
		sprintf(buf, "|[EF] |%s |%c |%u |%u |%llu |%llu |%u |%ld\r\n", target, cmd, log_parcer->sector, log_parcer->sector_len, 
																log_parcer->cur_time, log_parcer->latency_time, log_parcer->opcode, log_parcer->tagid);
	}
	else if (mem_target_getopt(log_parcer, MEM_LOG_BLOCK)) {
		if (mem_cmd_getopt(log_parcer, MEM_LOG_READ))
			cmd = 'R';
		if (mem_cmd_getopt(log_parcer, MEM_LOG_WRITE))
			cmd = 'W';

		sprintf(buf, "|[EF] |%s |%c |%u |%u |%llu |%llu |%d\r\n", target, cmd, log_parcer->sector, log_parcer->sector_len, 
																log_parcer->cur_time, log_parcer->latency_time, 
																log_parcer->opcode);
	}	
	return 0;
}


int memlog_release(void)
{
	if (tmemLog.log_buf)
		memset(tmemLog.log_buf, 0, sizeof(mem_log_parcer_t) * tmemLog.max_index);
	/*
	if (tmemLog.log_buf != NULL)
		vfree(tmemLog.log_buf);
	*/
	
	tmemLog.cur_index = 0;
	tmemLog.start = MEM_LOG_APP_END;
	tmemLog.resp_state = MEM_RESP_TRANS;
	tmemLog.last_done_time = 0;
	tmemLog.first_req_time = 0;
	return 0;
}

int memlog_destroy(void)
{
	if (tmemLog.log_buf != NULL)
		vfree(tmemLog.log_buf);

	tmemLog.max_index = 0;
	tmemLog.cur_index = 0;
	tmemLog.init = 0;
	return 0;
}

void memlog_exit_print_thread(void)
{
	if (tmemLog.kthread) {
		kthread_stop(tmemLog.kthread);
	}
}

static inline void sleep(unsigned sec)
{
	current->state = TASK_INTERRUPTIBLE;
	schedule_timeout(sec * HZ);
}

static int memlog_print_log(void)
{
	unsigned long index = 0;
	unsigned long cur_index = tmemLog.cur_index;
	mem_log_parcer_t* log_buf = tmemLog.log_buf;
	char buf[100] = {0,};
	
	if (cur_index < 1)
		return 0;
	
	do {
		memlog_set_parcer(log_buf + index, buf);
		printk(KERN_INFO "%s", buf);
		index++;
	} while (index < cur_index);

	return 0;
}

static int memlog_save_file(void)
{
	unsigned long index = 0;
	unsigned long cur_index = tmemLog.cur_index;
	mem_log_parcer_t* log_buf = tmemLog.log_buf;

	struct file *cfile = NULL;
	mm_segment_t old_fs = {0};
	int ret = 0;
	char *file_path = tmemLog.filepath;
	char bufs[100] = {0, };
	
	if (cur_index < 1 || file_path == NULL)
		return 0;

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	cfile = filp_open(file_path, O_CREAT | O_APPEND| O_RDWR, 0);

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

	do {	
		memlog_set_parcer(log_buf + index, bufs);
		
		ret = vfs_write(cfile, bufs, strlen(bufs), &cfile->f_pos);
		
		if (ret < 0) {
			_err_msg ("Write Failed!! err = %d\n", ret);
			goto ERR;
		}
		else {
			_mdbg_msg("Write Sucess!! ret = %d\n", ret);
		}

		index++;
	} while (index < cur_index);

	_err_msg ("Saved memlog to path :  %s\n", file_path);
/*
	if (cfile->f_op && cfile->f_op->flush) {
		ret = cfile->f_op->flush(cfile, NULL);
		_err_msg ("=== flush!!!! ret : %d", ret);
		
	}
*/
ERR:
	filp_close(cfile, NULL);
	set_fs(old_fs);		

	return 0;
}

int memlog_result(void)
{
	if (tmemLog.log_print == 1)
		memlog_print_log();

	if (tmemLog.filepath != NULL)
		memlog_save_file();

	memlog_release();
	return 0;
}

int check_status_code(struct mmc_request *mrq, unsigned long long req_time)
{
	int state = 0;
	mem_log_parcer_t* log_parcer = 0;
	
	if (mrq->cmd->opcode != MMC_SEND_STATUS) {
		if (tmemLog.resp_state == MEM_RESP_PRG) {
			log_parcer = get_mempool_buff();
			if (!log_parcer) {
				tmemLog.resp_state = MEM_RESP_TRANS;
				return MEM_RESP_TRANS;
			}
			
			mem_target_setopt(log_parcer, MEM_LOG_MMC);
			mem_cmd_setopt(log_parcer, MEM_LOG_OPCODE);

			log_parcer->sector = 0;
			log_parcer->sector_len = 0;
			log_parcer->cur_time = tmemLog.last_done_time;
			log_parcer->opcode = MMC_SEND_STATUS;
			log_parcer->latency_time = tmemLog.last_done_time - tmemLog.first_req_time;

			tmemLog.resp_state = MEM_RESP_TRANS;
		}
		return MEM_RESP_TRANS;
	}
	
	if (!(mrq->cmd->resp[0] & R1_READY_FOR_DATA) || (R1_CURRENT_STATE(mrq->cmd->resp[0]) == R1_STATE_PRG)) {
		if (tmemLog.resp_state != MEM_RESP_PRG) {
			tmemLog.first_req_time = req_time;
		}
		tmemLog.resp_state = MEM_RESP_PRG;
		state = MEM_RESP_PRG;
		_mdbg_msg("prg_state!!!\n");
	}
	else {
		if (tmemLog.resp_state == MEM_RESP_PRG) {
			_mdbg_msg("Transfer_state before prg_state!!!\n");
			state = MEM_RESP_SWITCHING;
		}
		else {
			_mdbg_msg("Transfer_state!!!\n");
			state = MEM_RESP_TRANS;
		}
		tmemLog.resp_state = MEM_RESP_TRANS;
	}

	return state;
}

int memlog_emmc_add(struct mmc_request *mrq, unsigned long long curTime, unsigned long long latency)
{
	mem_log_parcer_t* log_parcer;
	unsigned long flags;

	spin_lock_irqsave(&tmemLog.lock, flags);
	
	if (tmemLog.enable == 0) {
		spin_unlock_irqrestore(&tmemLog.lock, flags);
		return 0;
	}

	log_parcer = get_mempool_buff();
	
	if (!log_parcer) {
		spin_unlock_irqrestore(&tmemLog.lock, flags);
		return -ENOMEM;
	}
	
	mem_target_setopt(log_parcer, MEM_LOG_MMC);

	if (mrq->data->flags == MMC_DATA_WRITE)
		mem_cmd_setopt(log_parcer, MEM_LOG_WRITE);
	else if (mrq->data->flags == MMC_DATA_READ)
		mem_cmd_setopt(log_parcer, MEM_LOG_READ);

	log_parcer->sector = (unsigned int)mrq->cmd->arg;
	log_parcer->sector_len = mrq->data->blocks;
	log_parcer->cur_time = curTime;
	log_parcer->latency_time = latency;
	log_parcer->opcode = (unsigned int)mrq->cmd->opcode;

	if(mrq->sbc) {
		int do_data_tag = (mrq->sbc->arg >> 29) & 0x1;

		if (do_data_tag)
			//log_parcer->tagid |= 1 << (sizeof(log_parcer->tagid) * 8 -1);	// MSB set is 1
			log_parcer->tagid = 0xffff;
		else
#if 1 //context_id			
			log_parcer->tagid = (unsigned long)((mrq->sbc->arg >> 25) & 0xf);
#else
			log_parcer->tagid = mrq->sbc->arg;
#endif
	}

	spin_unlock_irqrestore(&tmemLog.lock, flags);
	
	return 0;
}

int memlog_opcode_add(struct mmc_request *mrq, unsigned long long curTime, unsigned long long latency)
{
	mem_log_parcer_t* log_parcer;
	unsigned long flags = 0;
	int resp_state = MEM_RESP_TRANS;
	unsigned int opcode = 0; 

	spin_lock_irqsave(&tmemLog.lock, flags);
	
	if (tmemLog.enable == 0) {
		spin_unlock_irqrestore(&tmemLog.lock, flags);
		return 0;
	}
	
#ifdef CONFIG_TRACE_MEMORY_STATUS_MERGE
	resp_state = check_status_code(mrq, curTime - latency);
	if (resp_state == MEM_RESP_PRG) {
		tmemLog.last_done_time = curTime;
		spin_unlock_irqrestore(&tmemLog.lock, flags);
		return 0;
	}
#endif /* CONFIG_TRACE_MEMORY_STATUS_MERGE */

	log_parcer = get_mempool_buff();

	if (!log_parcer) {
		spin_unlock_irqrestore(&tmemLog.lock, flags);
		return -ENOMEM;
	}
	mem_target_setopt(log_parcer, MEM_LOG_MMC);
	mem_cmd_setopt(log_parcer, MEM_LOG_OPCODE);

	if (mrq->cmd->opcode == MMC_SWITCH) 
		log_parcer->sector = (mrq->cmd->arg >> 16) & 0xff;		// marking ext_csd index
	else
		log_parcer->sector = (unsigned int)mrq->cmd->arg;
	
	log_parcer->cur_time = curTime;
	log_parcer->opcode = (unsigned int)mrq->cmd->opcode;

	opcode = mrq->cmd->opcode;
		
	if (opcode == MMC_SEND_CID || opcode == MMC_SEND_CSD || opcode == MMC_SEND_EXT_CSD) {
		log_parcer->sector_len = mrq->data->blocks;	
	} else {
		log_parcer->sector_len = 0;
	}

#ifdef CONFIG_TRACE_MEMORY_STATUS_MERGE
	if (resp_state == MEM_RESP_SWITCHING) {
		_mdbg_msg("MEM_RESP_SWITCHING !!! cur : %llu, pre_cur : %llu\n", curTime, tmemLog.first_req_time);
		log_parcer->latency_time = curTime - tmemLog.first_req_time;
	}
	else
		log_parcer->latency_time = latency;
#else
		log_parcer->latency_time = latency;
#endif /* CONFIG_TRACE_MEMORY_STATUS_MERGE */

	spin_unlock_irqrestore(&tmemLog.lock, flags);
	
	return 0;
}

int memlog_app_add(int start, int name, int cnt)
{
	mem_log_parcer_t* log_parcer;
	unsigned long flags;

	spin_lock_irqsave(&tmemLog.lock, flags);
/*	
	if (tmemLog.enable == 0) {
		spin_unlock_irqrestore(&tmemLog.lock, flags);
		return 0;
	}
*/
	if (name < -1) {
		spin_unlock_irqrestore(&tmemLog.lock, flags);
		return 0;		
	}

	if (start == MEM_LOG_APP_END &&	tmemLog.cur_index < 1) {
		spin_unlock_irqrestore(&tmemLog.lock, flags);
		return 0;				
	}
	
	log_parcer = get_mempool_buff();
	
	if (!log_parcer) {
		spin_unlock_irqrestore(&tmemLog.lock, flags);
		return -ENOMEM;
	}

	memset(log_parcer, 0, sizeof(mem_log_parcer_t));
	
	mem_target_setopt(log_parcer, MEM_LOG_APP);

	if (name == MEM_APP_MANUAL) {
		if (tmemLog.start == 0)
			mem_app_setopt(log_parcer, MEM_LOG_APP_START);
		else
			mem_app_setopt(log_parcer, MEM_LOG_APP_END);			
	}
	else {
		if (start == MEM_LOG_APP_START)
			mem_app_setopt(log_parcer, MEM_LOG_APP_START);
		else
			mem_app_setopt(log_parcer, MEM_LOG_APP_END);
	}
	
	log_parcer->cur_time = sched_clock();
	log_parcer->app_num = name;
	log_parcer->opcode = cnt;	// opcode is app test count

	tmemLog.start = MEM_LOG_APP_START;
	if (start == MEM_LOG_APP_START)
		_mdbg_msg("flag :%d // start :%d // name : %d // time: %llu\n", log_parcer->flag, start, name, log_parcer->cur_time);

	spin_unlock_irqrestore(&tmemLog.lock, flags);
	
	return 0;
}

int memlog_set_enable(int enable)
{
	unsigned long flags = 0;
#if 0	
	mem_log_parcer_t* log_buf;
	u32 last_index = 0;
	
	if (enable == 0 && tmemLog.log_buf && tmemLog.cur_index) {
		log_buf = tmemLog.log_buf + (tmemLog.cur_index - 1);
		if ((u32)log_buf->opcode == MMC_WRITE_MULTIPLE_BLOCK ||
				(u32)log_buf->opcode == MMC_WRITE_BLOCK) {
				last_index = tmemLog.cur_index;
				do {
					spin_lock_irqsave(&tmemLog.lock, flags);
					log_buf = tmemLog.log_buf + (tmemLog.cur_index - 1);
					//printk (KERN_INFO "%s cur_index : %lu opcode : %u\n", __func__, tmemLog.cur_index, log_buf->opcode);
					if (last_index != tmemLog.cur_index) {
						tmemLog.cur_index = last_index + 1;
						tmemLog.enable = 0;
						spin_unlock_irqrestore(&tmemLog.lock, flags);
						return 0;
					}
					spin_unlock_irqrestore(&tmemLog.lock, flags);
					mdelay(1);
				} while(1);
		}
	}
#endif	
	spin_lock_irqsave(&tmemLog.lock, flags);
	tmemLog.enable = enable;
	spin_unlock_irqrestore(&tmemLog.lock, flags);
	
	return 0;
}

int memlog_set_file_path(char* path)
{	
	if (tmemLog.filepath != NULL)
		vfree(tmemLog.filepath);

	if (path == NULL) {
		tmemLog.filepath = NULL;
		return 0;
	}

	tmemLog.filepath = (char*)vmalloc(strlen(path) + 1);

	if (tmemLog.filepath == NULL) {
		_err_msg("Memorypool alloc fail!\n");
		return -1;
	}
	
	memset(tmemLog.filepath, 0, strlen(path) + 1);
	memcpy(tmemLog.filepath, path, strlen(path));
	
	return 0;
}

int memlog_start_config(struct mem_log_config *config)
{	
	statistic_set_enable(config->stat_enable);
	memlog_set_enable(config->mem_enable);

	memlog_app_add(config->mem_start, config->mem_appNum, config->mem_appCnt);

	_err_msg("%s statistic!\n", config->stat_enable ? "Enable" : "Disable");

	if (config->mem_enable == 1)
		_err_msg("Enable Memory Log! // Available Line : %lu\n", tmemLog.max_index - tmemLog.cur_index);
	else
		_err_msg("Disable Memory Log!\n");
	
	if (config->mem_enable == 0) {
		memlog_result();
	}
	else if (config->mem_enable == 1) {
		memlog_set_file_path(config->mem_path);
		tmemLog.log_print = config->mem_print;
	}

	//== statistic ========
	if (config->stat_enable == 0) {
		statistic_result();	
	}
	else if (config->stat_enable == 1) {
		statistic_set_file_path(config->stat_path);
	}
	//---------------------
	return 0;
}

///////////////////////////////// Log Call /////////////////////////////////////////////////////////
void memlog_mmc_request_done(struct mmc_request *mrq, struct mmc_host *host)
{
	unsigned long long currentTime = 0;	
	unsigned int opcode = 0;
	unsigned long tagid = 0;

	currentTime = sched_clock();
	
	if (mrq == NULL || host == NULL || tmemLog.hostName == NULL || glTimeGap2 == 0) {
		glTimeGap2 = 0;
		return;
	}

	if(strcmp(mmc_hostname(host),tmemLog.hostName))
		return;

	opcode = mrq->cmd->opcode;

	if (mrq->data) {		
#ifdef CONFIG_MEM_LOG_TRACE_REAL_TIME
		if(mrq->sbc) {
			int do_data_tag = (mrq->sbc->arg >> 29) & 0x1;

		if (do_data_tag)
			//tagid |= 1 << (sizeof(tagid) * 8 -1);	// MSB set is 1
			tagid = 0xffff;
		else
			tagid = (unsigned long)((mrq->sbc->arg >> 25) & 0xf);
		}

		/* emmc Timestamp Trace */
		if (opcode == MMC_SEND_CID || opcode == MMC_SEND_CSD || opcode == MMC_SEND_EXT_CSD){
#ifdef CONFIG_MEM_LOG_CMD_ALL		
			printk(KERN_INFO " |[EF] |emmc |C |%u |%u |%llu|%llu |%u |%ld\n",
		     		(unsigned int)mrq->cmd->arg, mrq->data->blocks, currentTime, currentTime - glTimeGap2, (unsigned int)mrq->cmd->opcode, tagid);
#endif /* CONFIG_MEM_LOG_CMD_ALL */			
		}	
		else if (mrq->data->flags == MMC_DATA_WRITE){
	    	printk(KERN_INFO " |[EF] |emmc |W |%u |%u |%llu|%llu |%u |%ld\n",
	     		(unsigned int)mrq->cmd->arg, mrq->data->blocks,currentTime, currentTime - glTimeGap2, (unsigned int)mrq->cmd->opcode, tagid);
//	    	printk(KERN_INFO " |W |%u |%u |%u\n",
//	     		(unsigned int)mrq->cmd->arg, mrq->data->blocks, (unsigned int)mrq->cmd->opcode);

	   	}
	   	else if (mrq->data->flags == MMC_DATA_READ){
	    	printk(KERN_INFO " |[EF] |emmc |R |%u |%u |%llu|%llu |%u |%ld|%llu\n",
	     		(unsigned int)mrq->cmd->arg, mrq->data->blocks,currentTime, currentTime - glTimeGap2, (unsigned int)mrq->cmd->opcode, tagid, (currentTime - glTimeGap2) - glTimeGap); 
	   	}
#else 	/* CONFIG_MEM_LOG_TRACE_MEMORY_USE */
		if (opcode == MMC_SEND_CID || opcode == MMC_SEND_CSD || opcode == MMC_SEND_EXT_CSD){
#ifdef CONFIG_MEM_LOG_CMD_ALL				
			memlog_opcode_add(mrq, currentTime, currentTime - glTimeGap2);
			statistic_opcode_add(mrq, currentTime, currentTime - glTimeGap2);
#endif
		}
		else {
			memlog_emmc_add(mrq, currentTime, currentTime - glTimeGap2);
			statistic_emmc_add(mrq, currentTime, currentTime - glTimeGap2);
		}
#endif	/* CONFIG_MEM_LOG_TRACE_REAL_TIME */

	}
	else {
#ifdef CONFIG_MEM_LOG_CMD_ALL		
#ifdef CONFIG_MEM_LOG_TRACE_REAL_TIME 
			printk(KERN_INFO " |[EF] |emmc |C |%u |%u |%llu|%llu |%u\n",
		     		(unsigned int)mrq->cmd->arg, 0, currentTime, currentTime - glTimeGap2, (unsigned int)mrq->cmd->opcode);
#else
			memlog_opcode_add(mrq, currentTime, currentTime - glTimeGap2);
			statistic_opcode_add(mrq, currentTime, currentTime - glTimeGap2);
#endif /* MEM_LOG_TRACE_REAL_TIME */
#endif /* CONFIG_MEM_LOG_CMD_ALL */
	}
	
}

void memlog_mmc_request_start(struct mmc_host *host)
{
	if (host == NULL || tmemLog.hostName == NULL) {
		glTimeGap2 = 0;
		return;
	}

	if(strcmp(mmc_hostname(host),tmemLog.hostName))	{
		glTimeGap2 = 0;
		return;
	}
	
	glTimeGap2 = sched_clock();	
}

void memlog_set_cmd_type(int type)
{
	cur_cmdType = type;
}
