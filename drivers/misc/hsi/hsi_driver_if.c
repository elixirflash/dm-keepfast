/* linux/drivers/misc/hsi/hsi_driver_if.c
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
#include <linux/clk.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/pagemap.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include <asm/irq.h>
#include <linux/err.h>
#include <asm/mach-types.h>
#include <linux/ioctl.h>
#include <linux/delay.h>
#include <linux/ktime.h>
#include <linux/bitmap.h>

#include <linux/hsi_driver_if.h>
#include <linux/hsi_char.h>

#include "hsi_driver.h"
#include "hsi-char.h"
#include "hsi-if.h"

#define NOT_SET		(-1)

int hsi_set_rx_divisor(int ch)
{
	return 0;
}

int hsi_set_rx(int ch)
{
	return 0;
}

void hsi_get_rx(int ch)
{
}

int hsi_set_tx(int ch)
{
	return 0;
}

void hsi_get_tx(int ch)
{
}

int hsi_open(int ch)
{
	return 0;
}
EXPORT_SYMBOL(hsi_open);

int hsi_write(struct if_hsi_channel *channel, u32 *data, unsigned int size)
{
	printk(KERN_ERR "[DEBUG] Now i'm trying to transmit data!");
	return 0;
}
EXPORT_SYMBOL(hsi_write);

int hsi_read(int ch, unsigned int size)
{
	return 0;
}
EXPORT_SYMBOL(hsi_read);

int hsi_write_cancel(int ch)
{
	return 0;
}
EXPORT_SYMBOL(hsi_write_cancel);

int hsi_read_cancel(int ch)
{
	return 0;
}
EXPORT_SYMBOL(hsi_read_cancel);


void hsi_close(int ch)
{
}
EXPORT_SYMBOL(hsi_close);


