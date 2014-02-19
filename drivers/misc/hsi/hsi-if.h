/* linux/driver/misc/hsi/hsi-if.h
 *
 * Part of the HSI character driver, private headers.
 *
 * Copyright (C) 2009 Nokia Corporation. All rights reserved.
 * Copyright (C) 2009 Texas Instruments, Inc.
 * Copyright (C) 2012 Samsung Electronics Co.Ltd.
 *
 * Author: Andras Domokos <andras.domokos@nokia.com>
 * Author: Sebastien JAN <s-jan@ti.com>
 *
 * This package is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * THIS PACKAGE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifndef _HSI_IF_H
#define _HSI_IF_H

enum {
	HSIIF_STATUS_NOT_OPENED,
	HSIIF_STATUS_OPENED,
	HSIIF_STATUS_WRITING,
	HSIIF_STATUS_READING,
	HSIIF_STATUS_UNKNOWN,
};

#define RXCONV(dst, src) \
	do { \
		(dst)->mode = (src)->mode; \
		(dst)->flow = (src)->flow; \
		(dst)->frame_size = (src)->frame_size; \
		(dst)->channels = (src)->channels; \
		(dst)->divisor = (src)->divisor; \
		(dst)->counters = (src)->counters; \
	} while (0)

#define TXCONV(dst, src) \
	do { \
		(dst)->mode = (src)->mode; \
		(dst)->flow = (src)->flow; \
		(dst)->frame_size = (src)->frame_size; \
		(dst)->channels = (src)->channels; \
		(dst)->divisor = (src)->divisor; \
		(dst)->arb_mode = (src)->arb_mode; \
	} while (0)

struct if_hsi_channel {
	unsigned int channel_id;
	unsigned int tx_count;  /* Number of bytes to be written */
	unsigned int rx_count;  /* Number of bytes to be read */
	unsigned int state;
	struct completion rx_wait;
	unsigned int rx_pend;
	struct completion tx_wait;
	unsigned int tx_pend;
	spinlock_t lock; /* Serializes access to channel data */
};

int if_hsi_read(int ch, unsigned char *data, int count);
int if_hsi_read_buffer(int ch, unsigned char *data, int count);
int if_hsi_emul_read(int ch, unsigned char *data, int count);
int if_hsi_write(int ch, unsigned char *data, int count);
int if_hsi_write_pio(int ch, unsigned char *data, int count);
int if_hsi_write_pio_besteff(int ch, unsigned char *data, int count);
int if_hsi_start(int ch);
int if_hsi_set_fifo_size(int ch, int size);
int if_hsi_set_rx(int ch, struct hsi_ctx *cfg);
void if_hsi_get_rx(int ch, struct hsi_ctx *cfg);
int if_hsi_set_tx(int ch, struct hsi_ctx *cfg);
void if_hsi_get_tx(int ch, struct hsi_ctx *cfg);
int interface_init(void);
int if_tx_dma_was_finished(int channel);
int if_rx_dma_was_finished(int channel);

int if_hsi_get_channel_info(int ch, int type);

#endif
