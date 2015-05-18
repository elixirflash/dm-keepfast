/* linux/drivers/misc/hsi/hsi_driver_tran.h
 *
 * Copyright 2012 Samsung Electronics Co.Ltd.
 *      Donggyun, ko <donggyun.ko@samsung.com>
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
*/

#ifndef __HSI_DRIVER_TRAN_HEADER__
#define __HSI_DRIVER_TRAN_HEADER__

#define EXYNOS_HSI_DMACHNUM		8

struct hsi_dma_channel {
	spinlock_t lock;        /* Serialize access to each channel of dma */
	u32 chnum;
};

struct hsi_driver_dma {
	struct platform_device *pdev;
	struct hsi_dma_channel dma_ch[EXYNOS_HSI_DMACHNUM];
};

struct dma_req {
	int index;
	int dma_size;
	int size_in_byte;
};

struct pio_req {
	int index;
	int fifo_size;
	int fifo_refill_size;
	int size_in_word;
	struct completion wait;
};

/** buffer chain for the MIPI-HSI. Each buffer for the  */
struct hsi_buffer_list {
	struct list_head head;
	int index;
	int size;
	unsigned char *buffer;
};

/* hsi_request */
struct hsi_request {
	struct platform_device *pdev;
	int dma_ch;
	int channel;
	union {
		struct dma_req dma;
		struct pio_req pio;
	} req;
	struct hsi_buffer_list buffer_list;
	spinlock_t lock;        /* for serializing data */
};


extern struct hsi_driver_dma g_hsi_dma;

int init_hsi_driver_dma(struct platform_device *pdev);
int hsi_driver_read_dma(int ch, unsigned char *buff, int count);
int hsi_driver_write_dma(int ch, unsigned char *buff, int count);
int hsi_driver_write_pio(int ch, unsigned char *buff, int count);
int hsi_driver_write_pio_besteff(int ch, unsigned char *buff, int count);
void setup_tx_dma(struct hsi_request *p_req);
void setup_rx_dma(struct hsi_request *p_req);
void start_tx_dma(int ch, unsigned char *p, int size);
void start_rx_dma(int ch, unsigned char *p, int size);
int hsi_get_rxbuffer(int channel);
int hsi_driver_read_buffer(int ch, unsigned char *buff, int count);


#endif
