/*
 *  linux/drivers/mmc/mmc_syscall.c
 *
 *  Copyright 2011-2012 joys
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 */

#include <linux/mmc/mmc_syscall.h>
#include <linux/mmc/mem_log.h>
#include "statistics.h"
#include <linux/fs.h>
#include <asm/system.h>
#include <asm/uaccess.h>

asmlinkage int sys_mmc_poweroff(int request)
{
	printk(KERN_INFO "%s\n", __func__);
	return 0;
}

asmlinkage int sys_kernel_log(char* log)
{
	printk(KERN_INFO "%s\n", log);
	return 0;
}

#ifdef CONFIG_MEM_LOG_TRACE_MEMORY_USE
static struct mem_log_config *mem_log_config_copy_from_user(
	struct mem_log_config __user *user) 
{
	struct mem_log_config *log_config;
	int err;

	log_config = kzalloc(sizeof(struct mem_log_config), GFP_KERNEL);

	if (!log_config) {
		err = -ENOMEM;
		goto out;
	}

	if (copy_from_user(log_config, user, sizeof(struct mem_log_config))) {
		err = -EFAULT;
		goto log_config_err;
	}

	return log_config;

log_config_err:
	kfree(log_config);
out:
	return ERR_PTR(err);
}
#endif

asmlinkage int sys_mem_log_start(struct mem_log_config __user *conf_ptr)
{	
	struct mem_log_config *config;
	int err = 0;
#ifdef CONFIG_MEM_LOG_TRACE_MEMORY_USE
	config = mem_log_config_copy_from_user(conf_ptr);

	if (IS_ERR(config))
		return PTR_ERR(config);
	
	err = memlog_start_config(config);
	
	kfree(config);
#endif	
	return err;
}
