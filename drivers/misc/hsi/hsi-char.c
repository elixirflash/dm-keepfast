/* linux/driver/misc/hsi/hsi-char.c
 *
 * HSI character device driver, implements the character device
 * interface.
 *
 * Copyright (C) 2009 Nokia Corporation. All rights reserved.
 * Copyright (C) 2009 Texas Instruments, Inc.
 * Copyright (C) 2012 Samsung Electronics Co.Ltd.
 *
 * Author: Andras Domokos <andras.domokos@nokia.com>
 * Author: Sebastien JAN <s-jan@ti.com>
 * Author: Donggyun Ko <donggyun.ko@samsung.com>
 *
 * This package is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * THIS PACKAGE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/clk.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/platform_device.h>
#include <linux/pm.h>
#include <linux/io.h>
#include <linux/pagemap.h>
#include <linux/interrupt.h>
#include <asm/irq.h>
#include <linux/workqueue.h>
#include <linux/types.h>

#include <linux/dma-mapping.h>
#include <mach/dma.h>
#include <plat/s3c-pl330-pdata.h>

#include <linux/cma.h>
#include <linux/hsi_driver_if.h>
#include <linux/hsi_char.h>

#include "hsi-char.h"
#include "hsi_driver.h"
#include "hsi_protocol.h"
#include "hsi_debug.h"
#include "hsi-if.h"
#include "hsi_memory.h"

#define EXYNOS_HSI_VER_MINOR        17
#define DRIVER_VERSION  "0.1.0"
#define HSI_CHAR_DEVICE_NAME  "hsi_char"

static unsigned int num_channels;
static unsigned int channels_map[HSI_MAX_CHAR_DEVS] = { 0 };
module_param_array(channels_map, uint, &num_channels, 0);
MODULE_PARM_DESC(channels_map, "HSI channels to be probed");

dev_t hsi_char_dev;

/* Function definition for platform device */

/* Function definition for file operation */
static int sechsi_fp_open(struct inode *inode, struct file *filp);
static int sechsi_fp_release(struct inode *inode, struct file *filp);
static ssize_t sechsi_fp_write(struct file *filp, const char *buf,
				size_t count, loff_t *f_pos);
static ssize_t sechsi_fp_read(struct file *filp, char *buf, size_t count,
				loff_t *f_pos);
static long sechsi_ioctl(struct file *file_ptr, unsigned int ioctl,
unsigned long ptr);
static int ioctl_send_handler(struct test_param *param);
static int ioctl_mipird_handler(struct test_param *param);
static int ioctl_mipiwr_handler(struct test_param *param);
static int ioctl_rdreg_handler(struct test_param *param);
static int ioctl_wrreg_handler(struct test_param *param);
static int ioctl_debug1_handler(struct test_param *param);
static int ioctl_debug2_handler(struct test_param *param);
static int ioctl_debug3_handler(struct test_param *param);
static int ioctl_debug4_handler(struct test_param *param);
static int ioctl_mipihsi_init_handler(struct test_param *param);
static int ioctl_mipihsi_dumpsfr_handler(struct test_param *param);
static int ioctl_mipihsi_sysstat_handler(struct test_param *param);
static int ioctl_set_busspeed_handler(struct test_param *param);
static int ioctl_send_onedw_handler(struct test_param *param);
static int ioctl_send_seqdata_handler(struct test_param *param);
static int ioctl_send_besteff_handler(struct test_param *param);
static int ioctl_open_channel_handler(struct test_param *param);
static int ioctl_send_seqdatapio_handler(struct test_param *param);
static int ioctl_send_buffer_handler(struct test_param *param);
static int ioctl_read_buffer_handler(struct test_param *param);

static int ioctl_receive_nbytes_handler(struct test_param *param);
static int ioctl_receive_cpemul_handler(struct test_param *param);

static int ioctl_setfifosize_handler(struct test_param *param);

static int ioctl_getchannel_handler(struct test_param *param);

static struct char_queue *alloc_char_queue(void);
static u8 *alloc_new_seqdata(int length);


static void cb_work_func(struct work_struct *work);

/* Simple driver functions */
static int sechsi_driver_send_echo(void);

/* File operation declaraion */
static const struct file_operations vd_fops = {
	.read = sechsi_fp_read,
	.write = sechsi_fp_write,
	.open = sechsi_fp_open,
	.release = sechsi_fp_release,
	.unlocked_ioctl = sechsi_ioctl
};

/* Structure required to create a device node /dev/Hsi dynamically */
static struct miscdevice hsi = {
	/* We don't care what minor number we end up with, so tell the
	 * kernel to just pick one.
	 */
	EXYNOS_HSI_VER_MINOR,
	/* Name ourselves /dev/Hsi.*/
	"SECHSI",
	/* What functions to call when a program performs file
	 * operations on the device. */
	&vd_fops,
	/* No parent driver */
	.parent = NULL,
};

struct char_queue {
	struct list_head list;
	int channel;		/* channel */
	u32 *data;
	unsigned int count;
};

struct hsi_char {
	unsigned int opened;
	struct work_struct wq;
	struct list_head list;	/* data list */
	spinlock_t lock;	/* Serialize access to driver data and API */
	wait_queue_head_t wait;
};

static struct hsi_char hsi_char_data[HSI_MAX_CHAR_DEVS];
/****************************************************************
 FOR DEBUG
*****************************************************************/

static int sechsi_fp_open(struct inode *inode, struct file *filp)
{
	return 0;
}

static int sechsi_fp_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static ssize_t sechsi_fp_write(struct file *filp, const char *buf, size_t count,
loff_t *f_pos)
{
	return 0;
}

static ssize_t sechsi_fp_read(struct file *filp, char *buf, size_t count,
loff_t *f_pos)
{
	return 0;
}

/** sechsi_ioctl - main ioctl function of device driver */
static long sechsi_ioctl(struct file *file_ptr, unsigned int ioctl,
			unsigned long ptr)
{
	switch (ioctl) {
	case SECHSI_SEND:
		ioctl_send_handler((struct test_param *)ptr);
		break;
	case SECHSI_SET:
		break;
	case SECHSI_RDREG:
		ioctl_rdreg_handler((struct test_param *)ptr);
		break;
	case SECHSI_WRREG:
		ioctl_wrreg_handler((struct test_param *)ptr);
		break;
	case SECHSI_MIPIRD:
		ioctl_mipird_handler((struct test_param *)ptr);
		break;
	case SECHSI_MIPIWR:
		ioctl_mipiwr_handler((struct test_param *)ptr);
		break;
	case SECHSI_DEBUG1_CMD:
		ioctl_debug1_handler((struct test_param *)ptr);
		break;
	case SECHSI_DEBUG2_CMD:
		ioctl_debug2_handler((struct test_param *)ptr);
		break;
	case SECHSI_DEBUG3_CMD:
		ioctl_debug3_handler((struct test_param *)ptr);
		break;
	case SECHSI_DEBUG4_CMD:
		ioctl_debug4_handler((struct test_param *)ptr);
		break;
	case SECHSI_HSI_INIT_CMD:
		ioctl_mipihsi_init_handler((struct test_param *)ptr);
		break;
	case SECHSI_HSI_DUMPSFR_CMD:
		ioctl_mipihsi_dumpsfr_handler((struct test_param *)ptr);
		break;
	case SECHSI_HSI_SYSSTAT_CMD:
		ioctl_mipihsi_sysstat_handler((struct test_param *)ptr);
		break;
	case SECHSI_SET_BUSSPEED_CMD:
		ioctl_set_busspeed_handler((struct test_param *)ptr);
		break;
	case SECHSI_SEND_ONEDW:
		ioctl_send_onedw_handler((struct test_param *)ptr);
		break;
	case SECHSI_SEND_SEQDATA:
		ioctl_send_seqdata_handler((struct test_param *)ptr);
		break;
	case SECHSI_SEND_BUFFER:
		ioctl_send_buffer_handler((struct test_param *)ptr);
		break;
	case SECHSI_READ_BUFFER:
		ioctl_read_buffer_handler((struct test_param *)ptr);
		break;
	case SECHSI_SEND_SEQDATAPIO:
		ioctl_send_seqdatapio_handler((struct test_param *)ptr);
		break;
	case SECHSI_SEND_BESTEFF:
		ioctl_send_besteff_handler((struct test_param *)ptr);
		break;
	case SECHSI_OPEN_CHANNEL:
		ioctl_open_channel_handler((struct test_param *)ptr);
		break;
	case SECHSI_RECV_NBYTES:
		ioctl_receive_nbytes_handler((struct test_param *)ptr);
		break;
	case SECHSI_RECV_CPEMUL:
		ioctl_receive_cpemul_handler((struct test_param *)ptr);
		break;
	case SECHSI_SETFIFOSIZE:
		ioctl_setfifosize_handler((struct test_param *)ptr);
		break;
	case SECHSI_GET_CHANNEL:
		ioctl_getchannel_handler((struct test_param *)ptr);
		break;
	default:
		break;
	}
	return 0;
}

int __init init_sechsi(void)
{
	int ret, i;

	init_platform_driver();

	/* register character device driver */
	ret = misc_register(&hsi);

	for (i = 0; i < HSI_MAX_CHAR_DEVS; i++) {
		init_waitqueue_head(&hsi_char_data[i].wait);
		spin_lock_init(&hsi_char_data[i].lock);
		hsi_char_data[i].opened = 0;
		INIT_WORK(&hsi_char_data[i].wq, cb_work_func);
		INIT_LIST_HEAD(&hsi_char_data[i].list);
	}

	interface_init();

	hsi_memory_init();
	/*
	pr_info("HSI character device version " DRIVER_VERSION "\n");
	pr_info("HSI char driver: %d channels mapped\n", num_channels);

	ret = if_hsi_init(port, channels_map, num_channels);
	if (ret)
		return ret;

	ret =
	    alloc_chrdev_region(&hsi_char_dev, 0, HSI_MAX_CHAR_DEVS,
				HSI_CHAR_DEVICE_NAME);
	if (ret < 0) {
		printk(KERN_ERR "HSI character driver: Failed to register\n");
		return ret;
	}

	cdev_init(&hsi_char_cdev, &vd_fops);
	ret = cdev_add(&hsi_char_cdev, hsi_char_dev, HSI_MAX_CHAR_DEVS);
	if (ret < 0) {
		printk(KERN_ERR "HSI character device: Failed to "
				"add char device\n");
		return ret;
	}
	*/
	return 0;
}

void __exit exit_sechsi(void)
{
}


static void cb_work_func(struct work_struct *work)
{
	struct hsi_char *p_hsi_char = container_of(work, struct hsi_char, wq);
	struct char_queue *entry;

	if (!list_empty(&p_hsi_char->list)) {
		entry = list_entry(p_hsi_char->list.next,
			struct char_queue, list);
		list_del(&p_hsi_char->list);
		kfree(entry);
		if_hsi_write(entry->channel, (unsigned char *)entry->data,
				entry->count);
	} else {
		printk(KERN_ERR "[ERROR] Work_queue - entry not found!");
	}
}

/* The definition of simple driver functions */
static int ioctl_send_handler(struct test_param *param)
{
	switch (param->param1) {
	case IOCTL_ECHO:
		sechsi_driver_send_echo();
		break;
	}
	return 0;
}

/** for read register handler */
static int ioctl_rdreg_handler(struct test_param *param)
{
	param->res.res1 = sechsi_read_register(param->param1);
	return 0;
}

/** for read register handler */
static int ioctl_wrreg_handler(struct test_param *param)
{
	param->res.res1 = sechsi_write_register(param->param1, param->param2);
	return 0;
}

/** for read register handler */
static int ioctl_mipird_handler(struct test_param *param)
{
	param->res.res1 = sechsi_mipi_read_register(param->param1);
	return 0;
}

/** for read register handler */
static int ioctl_mipiwr_handler(struct test_param *param)
{
	param->res.res1 = sechsi_mipi_write_register(param->param1,
						param->param2);
	return 0;
}

/** for read register handler */
static int ioctl_send_onedw_handler(struct test_param *param)
{
	u32 ch, val;
	ch = param->param1;
	val = param->param2;

	printk(KERN_ERR "[DEBUG] I'll write a value, 0x%08X to channel-%d",
			val, ch);
	sechsi_write_sfr(HSI_TX_DATA(ch), val);
	return 0;
}

static struct char_queue *alloc_char_queue(void)
{
	struct char_queue *pnew;
	pnew = kmalloc(sizeof(struct char_queue), GFP_ATOMIC);
	if (!pnew)
		return NULL;
	INIT_LIST_HEAD(&pnew->list);
	return pnew;
}

/* for testing seqence data */
static u8 *alloc_new_seqdata(int length)
{
	int i = 0;
	u8 *data;
	/* data = kmalloc(length, GFP_ATOMIC); */
	data = ALLOC_BYTES(length);
	if (!data)
		return NULL;
	for (i = 0; i < length; ++i)
		data[i] = i;
	return data;
}

/** for sending data with best effort */
static int ioctl_send_besteff_handler(struct test_param *param)
{
	int ret = 0;
	unsigned char *pdata = NULL;

	if_hsi_write_pio_besteff(param->channel, pdata, param->param2);
	return ret;
}

/** for sending sequential data */
static int ioctl_send_seqdatapio_handler(struct test_param *param)
{
	int ret;
	unsigned char *pdata = NULL;

	/* allocate new data_item */
	pdata = alloc_new_seqdata(param->param2);
	/* alloc & copy parameter */
	if (!pdata)
		return -ENOMEM;

	if_hsi_write_pio(param->channel, pdata, param->param2);
	return ret;
}

/** for reading buffer data in the rxbuffer */
static int ioctl_read_buffer_handler(struct test_param *param)
{
	return if_hsi_read_buffer(param->channel,
		(unsigned char *)param->param1, param->param2);
}

/** for sending a buffer data form user space*/
static int ioctl_send_buffer_handler(struct test_param *param)
{
	int ret;
	ret = if_hsi_write(param->channel, (unsigned char *)param->param1,
		param->param2);
	return ret;
}

/** for sending sequential data */
static int ioctl_send_seqdata_handler(struct test_param *param)
{
	int ret;
	struct char_queue *pnew;
	unsigned char *pdata = NULL;
	/*struct test_param *data;*/

	/* allocate new data_item */
	pnew = alloc_char_queue();
	/* alloc & copy parameter */
	if (!pnew)
		return -ENOMEM;

	/*pdata = alloc_new_seqdata(param->param2);*/
	if_hsi_write(param->channel, pdata, param->param2);

	return ret;
}

/** for receiving data in nbytes */
static int ioctl_receive_nbytes_handler(struct test_param *param)
{
	return if_hsi_read(param->channel, NULL,
		param->param2);
}

/** for receiving data using emulation of CP */
static int ioctl_receive_cpemul_handler(struct test_param *param)
{
	return if_hsi_emul_read(param->channel, NULL,
		param->param2);
}


/** for setting up fifo size */
static int ioctl_setfifosize_handler(struct test_param *param)
{
	return if_hsi_set_fifo_size(param->channel, param->param1);
}

/** for getting channel infomation */
static int ioctl_getchannel_handler(struct test_param *param)
{
	param->param2 = if_hsi_get_channel_info(param->channel, param->param1);
	return param->param2;
}


/** for openning channel. open make a channel ready. */
static int ioctl_open_channel_handler(struct test_param *param)
{
	int ret;
	struct hsi_ctx cfg;

	INIT_HSI_CTX(&cfg);
	ret = if_hsi_start(param->channel);
	if (ret < 0)
		return ret;
	if (param->param1 == CMD_CHANNEL_MODE_TX)
		ret = if_hsi_set_tx(param->channel, &cfg);
	else if (param->param1 == CMD_CHANNEL_MODE_RX)
		ret = if_hsi_set_rx(param->channel, &cfg);
	return ret;
}

/** for debugging #1 */
static int ioctl_debug1_handler(struct test_param *param)
{
	printk(KERN_ERR "[DEBUG][CHK] Now setup SFR - DEBUG1");
	setup_sechsi_system_clock();
	return 0;
}

static int ioctl_debug2_handler(struct test_param *param)
{
	return 0;
}

static int ioctl_debug3_handler(struct test_param *param)
{
	return 0;
}

static int ioctl_debug4_handler(struct test_param *param)
{
	return 0;
}

/** for debugging #1 */
static int ioctl_mipihsi_init_handler(struct test_param *param)
{
	/* 1. firstly, reset mipi-hsi */
	reset_sechsi();
	/* 2. set default */
	set_default_system_config();
	return 0;
}

/** for setting up system busspeed */
static int ioctl_set_busspeed_handler(struct test_param *param)
{
	return 0;
}


/** for display statem status */
static int ioctl_mipihsi_sysstat_handler(struct test_param *param)
{
	printk(KERN_ERR "[INFO] =============\n");
	printk(KERN_ERR "[INFO] SYSTEM STATUS\n");
	printk(KERN_ERR "[INFO] =============\n");

	hsi_mem_info();
	return 0;
}



/** for debugging #1 */
static int ioctl_mipihsi_dumpsfr_handler(struct test_param *param)
{
	unsigned int i;
	unsigned int v1, v2, v3, v4;

	for (i = 0; i < 16; ++i) {
		v1 = sechsi_mipi_read_register((i<<4)+0);
		v2 = sechsi_mipi_read_register((i<<4)+4);
		v3 = sechsi_mipi_read_register((i<<4)+8);
		v4 = sechsi_mipi_read_register((i<<4)+12);
		printk(KERN_ERR "[DEBUG] 0x%04X %08X %08X %08X %08X",
			(i<<4), v1, v2, v3, v4);
	}
	return 0;
}

/* The definition of simple driver functions */
static int sechsi_driver_send_echo(void)
{
	/* send_echo(); */
	sechsi_write_sfr(HSI_TX_DATA(HSI_CHANNEL0), 0x01234567);
	return 0;
}

module_init(init_sechsi);
module_exit(exit_sechsi);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("sechsi test driver");
MODULE_AUTHOR("Dong-gyun ko");
MODULE_VERSION(DRIVER_VERSION);
