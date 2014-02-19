/* linux/driver/misc/hsi/hsi-if.c
 *
 * Part of the HSI character driver, implements the HSI interface.
 *
 * Copyright (C) 2009 Nokia Corporation. All rights reserved.
 * Copyright (C) 2009 Texas Instruments, Inc.
 * Copyright (C) 2012 Samsung Electronics Co.Ltd
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

#include <linux/errno.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/io.h>
#include <linux/platform_device.h>
#include <asm/mach-types.h>
#include <linux/ioctl.h>
#include <linux/delay.h>
#include <linux/ktime.h>
#include <linux/bitmap.h>
#include <linux/sched.h>

#include <linux/hsi_driver_if.h>
#include <linux/hsi_char.h>

#include "hsi-char.h"
#include "hsi-if.h"
#include "hsi_driver.h"
#include "hsi_driver_tran.h"


struct if_hsi_channel g_channels[HSI_MAX_CHAR_DEVS];

/* for declaring prototype of static functions */
static int if_hsi_openchannel(struct if_hsi_channel *channel);

int if_hsi_read(int ch, unsigned char *data, int count)
{
	hsi_driver_read_dma(ch, data, count);
	return 0;
}

/* for receiving some data with emulation */
int if_hsi_emul_read(int ch, unsigned char *data, int count)
{
	hsi_driver_read_dma(ch, data, count);
	return 0;
}

int if_hsi_write_pio(int ch, unsigned char *data, int count)
{
	int ret = 0;
	struct if_hsi_channel *channel;
	channel = &g_channels[ch];

	hsi_driver_write_pio(ch, data, count);

	return ret;
}

int if_hsi_write_pio_besteff(int ch, unsigned char *data, int count)
{
	int ret = 0;
	struct if_hsi_channel *channel;
	channel = &g_channels[ch];

	hsi_driver_write_pio(ch, data, count);

	return ret;
}

int if_hsi_write(int ch, unsigned char *data, int count)
{
	int ret = 0;
	struct if_hsi_channel *channel;
	channel = &g_channels[ch];

	hsi_driver_write_dma(ch, data, count);

	return ret;
}

int if_hsi_read_buffer(int ch, unsigned char *data, int count)
{
	hsi_driver_read_buffer(ch, data, count);
	return 0;
}


int if_hsi_start(int ch)
{
	struct if_hsi_channel *channel;
	int ret = 0;

	channel = &g_channels[ch];

	spin_lock(&channel->lock);
	channel->state = 0;
	spin_unlock(&channel->lock);

	ret = if_hsi_openchannel(channel);
	/*
	if (ret < 0) {
		pr_err("Could not open channel %d\n", ch);
		goto error;
	}
	*/
	return ret;
}

int if_hsi_set_rx(int ch, struct hsi_ctx *cfg)
{
	struct if_hsi_channel *channel;
	channel = &g_channels[ch];

	printk(KERN_ERR "[DEBUG] I'll change channel-%d to RXmode\n", ch);
	return 0;
}

void if_hsi_get_rx(int ch, struct hsi_ctx *cfg)
{
	struct if_hsi_channel *channel;
	channel = &g_channels[ch];
}

int if_hsi_set_tx(int ch, struct hsi_ctx *cfg)
{
	struct if_hsi_channel *channel;
	channel = &g_channels[ch];

	printk(KERN_ERR "[DEBUG] I'll change channel-%d to TXmode\n", ch);
	return 0;
}

void if_hsi_get_tx(int ch, struct hsi_ctx *cfg)
{
	struct if_hsi_channel *channel;
	channel = &g_channels[ch];
}

/* for setting up fifo size */
int if_hsi_set_fifo_size(int ch, int size)
{
	int i = 1;
	int fsval = HSI_FS_1;
	while (size > i && fsval < HSI_FS_1024) {
		i <<= 1;
		fsval++;
	}
	printk(KERN_ERR "[INFO] Now setup FIFO size of channel-%d to val %d\n",
		ch, fsval);
	sechsi_set_tx_fifo(ch, fsval, HSI_FIFO_ALMOST);
	sechsi_set_rx_fifo(ch, fsval, HSI_FIFO_ALMOST);
	return 0;
}

/* for getting channel infomation */
int if_hsi_get_channel_info(int ch, int type)
{
	switch (type) {
	case CHANNEL_RXBUFFER:
		return hsi_get_rxbuffer(ch);
	case CHANNEL_STATUS:
		return g_channels[ch].state;
	case CHANNEL_RX_PEND_SIGNAL:
		init_completion(&g_channels[ch].rx_wait);
		spin_lock(&g_channels[ch].lock);
		g_channels[ch].rx_pend = 1;
		spin_unlock(&g_channels[ch].lock);
		wait_for_completion(&g_channels[ch].rx_wait);
		return 0;
	case CHANNEL_TX_PEND_SIGNAL:
		init_completion(&g_channels[ch].tx_wait);
		spin_lock(&g_channels[ch].lock);
		g_channels[ch].tx_pend = 1;
		spin_unlock(&g_channels[ch].lock);
		wait_for_completion(&g_channels[ch].tx_wait);
		return 0;
	default:
		return -1;
	}
}

static int if_hsi_openchannel(struct if_hsi_channel *channel)
{
	int ret = 0;
	int ch = channel->channel_id;

	printk(KERN_ERR "[DEBUG] Now turn-on channel : %d\n", ch);

	if (channel->state == HSIIF_STATUS_OPENED) {
		printk(KERN_ERR "Channel-%d is already opened\n", ch);
		return -EBUSY;
	}

	/* interrupt enable for channel to be opened */
	sechsi_clear_bit(HSI_INT_STAT_EN, 0+ch);
	sechsi_clear_bit(HSI_INT_SIG_EN,  0+ch);
	sechsi_clear_bit(HSI_ERR_INT_SIG_EN, 2+ch);
	sechsi_clear_bit(HSI_ERR_INT_STAT_EN, 2+ch);

	sechsi_enable_int(0, HSI_INT_RX_WAKE);
	sechsi_enable_int(ch, HSI_INT_SDMA_DONE);

	SECHSI_ENABLE_TX(ch);
	SECHSI_ENABLE_RX(ch);

	spin_lock(&channel->lock);
	channel->state = HSIIF_STATUS_OPENED;
	spin_unlock(&channel->lock);
	return ret;
}

int interface_init(void)
{
	int i;
	for (i = 0; i < HSI_MAX_CHAR_DEVS; ++i) {
		g_channels[i].state = HSIIF_STATUS_NOT_OPENED;
		g_channels[i].channel_id = i;
		g_channels[i].tx_pend = 0;
		g_channels[i].tx_pend = 0;
		spin_lock_init(&g_channels[i].lock);
	}

	sechsi_mipi_write_register(HSI_INT_STAT_EN, 0x00000000);
	sechsi_mipi_write_register(HSI_INT_SIG_EN,  0x00000000);
	sechsi_mipi_write_register(HSI_ERR_INT_SIG_EN, 0x00000000);
	sechsi_mipi_write_register(HSI_ERR_INT_STAT_EN, 0x00000000);

	return 0;
}

int if_tx_dma_was_finished(int channel)
{
	spin_lock(&g_channels[channel].lock);
	if (g_channels[channel].tx_pend) {
		g_channels[channel].tx_pend = 0;
		complete(&g_channels[channel].tx_wait);
	}
	spin_unlock(&g_channels[channel].lock);
	return 0;
}

int if_rx_dma_was_finished(int channel)
{
	spin_lock(&g_channels[channel].lock);
	if (g_channels[channel].rx_pend) {
		g_channels[channel].rx_pend = 0;
		complete(&g_channels[channel].rx_wait);
	}
	spin_unlock(&g_channels[channel].lock);
	return 0;
}

