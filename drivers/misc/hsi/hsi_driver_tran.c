/* linux/drivers/misc/hsi/hsi_driver_tran.c
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

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/completion.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/delay.h>
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
#include <linux/list.h>

#include <linux/dma-mapping.h>
#include <mach/dma.h>
#include <plat/s3c-pl330-pdata.h>

#include <linux/cma.h>
#include <linux/hsi_driver_if.h>
#include <linux/hsi_char.h>

#include "hsi_driver.h"
#include "hsi-if.h"
#include "hsi_driver_tran.h"
#include "hsi_debug.h"
#include "hsi_memory.h"

/* the registration of DMA name */
static struct s3c2410_dma_client sechsi_dma_name = {
	.name = "samsung-hsi-dma",
};

static void callback_mipihsi_tx_dma(struct s3c2410_dma_chan *chan, void *buf_id,
	int size, enum s3c2410_dma_buffresult res);
static void callback_mipihsi_rx_dma(struct s3c2410_dma_chan *chan, void *buf_id,
	int size, enum s3c2410_dma_buffresult res);

unsigned int *g_mapped_ptr;

/* for estimating time */
struct timeval kodong_t_before, kodong_t_after, kodong_t_diff;

/* for DMA channel buffer */
unsigned char *g_dma_txbuff[EXYNOS_HSI_DMACHNUM];
unsigned char *g_dma_rxbuff[EXYNOS_HSI_DMACHNUM];
/* DMA chunk size */
int g_dma_chunk_size;
/* RX buffer size */
int g_rx_buffer_size;
int g_tx_buffer_size;
/* DMA request info */
struct hsi_request g_tx_reqs[EXYNOS_HSI_DMACHNUM];
struct hsi_request g_rx_reqs[EXYNOS_HSI_DMACHNUM];

#define TX_BUFFER_HEAD_PTR(ch) (&g_tx_reqs[(ch)].buffer_list.head)
#define TX_BUFFER_FIRST_ENTRY(ch) (g_tx_reqs[(ch)].buffer_list.head.next)
#define TX_BUFFER_LAST_ENTRY(ch) (g_tx_reqs[(ch)].buffer_list.head.next)

#define RX_BUFFER_HEAD_PTR(ch) (&g_rx_reqs[(ch)].buffer_list.head)
#define RX_BUFFER_FIRST_ENTRY(ch) (g_rx_reqs[(ch)].buffer_list.head.next)
#define RX_BUFFER_LAST_ENTRY(ch) (g_rx_reqs[(ch)].buffer_list.head.next)


u32 g_dma_res[EXYNOS_HSI_DMACHNUM];
spinlock_t g_dma_lock;        /* for serializing data */

static void KodongInitGPIO(void);
static int get_available_dma_ch(int channel);

int g_hsi_tx_count;
int g_hsi_tx_fifosize;
int g_hsi_tx_hfifosize;
int g_hsi_tx_data_count;

unsigned int g_gpio_addr;
unsigned int g_val;

int init_hsi_driver_dma(struct platform_device *pdev)
{
	int i;
	struct resource *dma_res;

	g_dma_chunk_size = 4096;
	g_rx_buffer_size = 65536;
	g_tx_buffer_size = 65536;

	spin_lock_init(&g_dma_lock);

	for (i = 0; i < EXYNOS_HSI_DMACHNUM; ++i) {
		/* for initializing DMA buffer of every channels */
		g_dma_txbuff[i] = NULL;
		g_dma_rxbuff[i] = NULL;

		dma_res = platform_get_resource(pdev, IORESOURCE_DMA, i);
		if (dma_res == NULL) {
			printk(KERN_ERR "[ERROR] MIPI-HSI : Unable to get MIPI-HSI dma resource\n");
			continue;
		}
		g_dma_res[i] = dma_res->start;

		g_tx_reqs[i].dma_ch = -1;
		g_tx_reqs[i].pdev = pdev;
		g_tx_reqs[i].channel = i;
		g_tx_reqs[i].req.dma.index = 0;
		spin_lock_init(&g_tx_reqs[i].lock);

		g_rx_reqs[i].dma_ch = -1;
		g_rx_reqs[i].pdev = pdev;
		g_rx_reqs[i].channel = i;
		g_rx_reqs[i].req.dma.index = 0;
		spin_lock_init(&g_rx_reqs[i].lock);

		INIT_LIST_HEAD(TX_BUFFER_HEAD_PTR(i));
		INIT_LIST_HEAD(RX_BUFFER_HEAD_PTR(i));

	}
	return 0;
}

int kodong_timeval_subtract(struct timeval *result,
	struct timeval *t2, struct timeval *t1)
{
	long int diff = (t2->tv_usec + 1000000 * t2->tv_sec) -
		(t1->tv_usec + 1000000 * t1->tv_sec);
	result->tv_sec = diff / 1000000;
	result->tv_usec = diff % 1000000;

	return (diff < 0);
}

int assign_tx_buffer(int channel, unsigned char *buffer, int length)
{
	int i = 0, size, res;
	struct hsi_buffer_list *node;

	while (i < length) {
		if (length-i >= g_tx_buffer_size)
			size = g_tx_buffer_size;
		else
			size = length-i;
		node = (struct hsi_buffer_list *)ALLOC_BYTES(
				sizeof(struct hsi_buffer_list));

		spin_lock(&g_tx_reqs[channel].lock);
		INIT_LIST_HEAD(&node->head);

		node->index = 0;
		node->size = size;
		node->buffer = ALLOC_BYTES(size);

		list_add_tail(&node->head, TX_BUFFER_HEAD_PTR(channel));
		res = copy_from_user(node->buffer, buffer + i, size);
		spin_unlock(&g_tx_reqs[channel].lock);
		if (res < 0) {
			printk(KERN_ERR "[DEBUG] Not enough memory for MIPI-HSI");
			return -1;
		}

		if (i == 0) { /* In the first entry, copy a single chunk */
			if (size < g_dma_chunk_size) {
				memcpy(g_dma_txbuff[channel],
					node->buffer, size);
				spin_lock(&g_tx_reqs[channel].lock);
				node->index = size;
				spin_unlock(&g_tx_reqs[channel].lock);
			} else {
				memcpy(g_dma_txbuff[channel],
					node->buffer, g_dma_chunk_size);
				spin_lock(&g_tx_reqs[channel].lock);
				node->index = g_dma_chunk_size;
				spin_unlock(&g_tx_reqs[channel].lock);
			}
		}

		i += size;
	}
	return 0;
}



int assign_rx_buffer(int channel)
{
	struct hsi_buffer_list *node;

	if (list_empty(RX_BUFFER_HEAD_PTR(channel))) {
		node = (struct hsi_buffer_list *)ALLOC_BYTES(
			sizeof(struct hsi_buffer_list));
		INIT_LIST_HEAD(&node->head);
		node->index = 0;
		node->size = g_rx_buffer_size;
		node->buffer = ALLOC_BYTES(g_rx_buffer_size);
		spin_lock(&g_rx_reqs[channel].lock);
		list_add_tail(&node->head, RX_BUFFER_HEAD_PTR(channel));
		spin_unlock(&g_rx_reqs[channel].lock);
	}
	return 0;
}

/* hsi_driver_read_buffer - */
int hsi_driver_read_buffer(int ch, unsigned char *buff, int count)
{
	int res;
	int i = 0, size;
	struct list_head *n = NULL, *temp;
	struct hsi_buffer_list *node;

	if (ch >= EXYNOS_HSI_DMACHNUM)
		return -1;

	/* list_for_each(n, &g_rx_buffer[ch].head) { */
	for (n = RX_BUFFER_FIRST_ENTRY(ch); n != RX_BUFFER_HEAD_PTR(ch);) {
		node = container_of(n, struct hsi_buffer_list, head);
		if (count-i > node->index)
			size = node->index;
		else
			size = count-i;
		res = copy_to_user((void __user *)buff+i, node->buffer, size);
		if (res < 0) {
			printk(KERN_ERR "[ERROR] Buffer copy failed!\n");
			return res;
		}
		i += size;

		temp = n->next;
		FREE_BYTES(node->buffer);
		list_del(n);
		FREE_BYTES((unsigned char *)node);
		n = temp;

		if (i >= count)
			break;
	}

	return 0;
}

/* hsi_driver_read_dma - */
int hsi_driver_read_dma(int ch, unsigned char *buff, int count)
{
	int channel = ch % EXYNOS_HSI_DMACHNUM;
	int i = 0, size, dmach;
	unsigned long flag;
	u32 val;

	/*  1. check & get available DMA channel */
	if (g_rx_reqs[channel].dma_ch == -1) {
		spin_lock_irqsave(&g_dma_lock, flag);
		dmach = get_available_dma_ch(channel);
		spin_unlock_irqrestore(&g_dma_lock, flag);
		if (dmach == -1) {
			printk(KERN_ERR "[ERROR] There is no available DMA channel. "
					"DMA transmission failed.\n");
			return -1;
		}
		printk("[DEBUG] (0)DMA channel-%d was assigned for channel-%d\n",
			dmach, channel);

		/*  3. Reserve DMA channel */
		spin_lock(&g_rx_reqs[channel].lock);
		g_rx_reqs[channel].dma_ch = dmach;
		spin_unlock(&g_rx_reqs[channel].lock);

		spin_lock_irqsave(&g_dma_lock, flag);
		setup_rx_dma(&g_rx_reqs[channel]);
		spin_unlock_irqrestore(&g_dma_lock, flag);
	}
	val = MAKE_SDMA_REGVAL(1, HSI_DMA_BURST_4, (count)>>2,
		channel, 1);
	sechsi_mipi_write_register(HSI_SDMA_CONFIG(g_rx_reqs[channel].dma_ch),
		val);

	/*  2. Initialize RX buffer */
	if (g_dma_rxbuff[channel] == NULL) {
		spin_lock(&g_rx_reqs[channel].lock);
		g_dma_rxbuff[channel] = ALLOC_DMA_BYTES(g_dma_chunk_size);
		spin_unlock(&g_rx_reqs[channel].lock);
	}
	/*  4. Initial DMA request context for RX */
	if (i + g_dma_chunk_size > count)
		size = count - i;
	else
		size = g_dma_chunk_size;

	spin_lock(&g_rx_reqs[channel].lock);
	g_rx_reqs[channel].req.dma.dma_size = size;
	g_rx_reqs[channel].req.dma.size_in_byte = count;
	g_rx_reqs[channel].req.dma.index = 0;
	spin_unlock(&g_rx_reqs[channel].lock);

	/*  5. assignd RX buffer */
	assign_rx_buffer(channel);

	/*  6. start RX dma */
	spin_lock_irqsave(&g_dma_lock, flag);
	start_rx_dma(channel, g_dma_rxbuff[channel], size);
	spin_unlock_irqrestore(&g_dma_lock, flag);
	return 0;
}

/* hsi_driver_write_pio -
 * buff  - byte data to be transmitted
 * count - content length of data in bytes */
int hsi_driver_write_pio(int ch, unsigned char *buff, int count)
{
	int channel = ch % EXYNOS_HSI_DMACHNUM;
	int i = 0, size;
	int wdcount = count >> 2; /*  Length should be x4 */
	unsigned int fifo_size = 1;
	unsigned int *pwdbuff = (unsigned int *)buff;
	volatile register int reg = 0;
	int *pidx;

	fifo_size = sechsi_get_tx_fifosize(channel);

	printk(KERN_ERR
		"[DEBUG] I'll send some data with PIO - fifo_size: %d, count: %d\n",
		fifo_size, wdcount);

/*  Time estimation start!!! */
	sechsi_disable_int(channel, HSI_INT_TX);	/*  enable channel */
do_gettimeofday(&kodong_t_before);

	g_tx_reqs[channel].req.pio.index = 0;
	g_tx_reqs[channel].req.pio.fifo_size = fifo_size;
	g_tx_reqs[channel].req.pio.fifo_refill_size = (fifo_size >> 1);
	/* g_tx_reqs[channel].req.pio.fifo_refill_size = (fifo_size >> 3); */
	g_tx_reqs[channel].req.pio.size_in_word = wdcount;

	/* sechsi_clear_bit(HSI_CLK_CON, 0);*/
	i = 0;
	pidx = &g_tx_reqs[channel].req.pio.index;
	while (1) {
		init_completion(&g_tx_reqs[channel].req.pio.wait);

		spin_lock(&g_tx_reqs[channel].lock);
		if (*pidx == 0) {
			if (*pidx + g_tx_reqs[channel].req.pio.fifo_size
				> wdcount)
				size = wdcount - *pidx;
			else
				size = g_tx_reqs[channel].req.pio.fifo_size;
		} else {
			if (*pidx + g_tx_reqs[channel].req.pio.fifo_refill_size
				> wdcount)
				size = wdcount - *pidx;
			else
				size =
				g_tx_reqs[channel].req.pio.fifo_refill_size;
		}
		for (i = 0; i < size; ++i) {
			reg = pwdbuff[i];
			*((volatile int *)(g_hsi_ctrl.base +
				HSI_TX_DATA(channel))) = reg;
		}
		if (*pidx == 0)
			/* sechsi_set_bit(HSI_CLK_CON, 0); */
			/*  enable channel */
			sechsi_enable_int(channel, HSI_INT_TX);
		else
			/* sechsi_enable_int(channel, HSI_INT_TX); */
			sechsi_set_bit(HSI_INT_SIG_EN, channel);
		*pidx += size;
		spin_unlock(&g_tx_reqs[channel].lock);

		wait_for_completion(&g_tx_reqs[channel].req.pio.wait);
		if (*pidx >= g_tx_reqs[channel].req.pio.size_in_word)
			break;
	}

	sechsi_disable_int(0, HSI_INT_TX);	/*  enable channel */

do_gettimeofday(&kodong_t_after);
kodong_timeval_subtract(&kodong_t_diff, &kodong_t_after, &kodong_t_before);
printk(KERN_ERR "[DEBUG] TX(%d) TIME: %ld.%06ld\n", *pidx,
	kodong_t_diff.tv_sec, kodong_t_diff.tv_usec);

	return 0;
}

int hsi_get_rxbuffer(int channel)
{
	int size = 0;
	struct list_head *n;
	struct hsi_buffer_list *node;

	if (channel >= EXYNOS_HSI_DMACHNUM)
		return -1;

	list_for_each(n, RX_BUFFER_HEAD_PTR(channel)) {
		node = container_of(n, struct hsi_buffer_list, head);
		size += node->index;
	}
	return size;
}

void KodongInitGPIO(void)
{
	unsigned int val, addr, i;

	printk(KERN_ERR "[DEBUG] BEGIN - Kodong DEBUG GPIO!!!(001)");

	addr = (unsigned int)ioremap_nocache(
			(long unsigned int)0x10023000, 0x1000);
	val = 0x10000000;
	writel(val, addr+0x0108);
	iounmap((void *)addr);

	addr = (unsigned int)ioremap_nocache(
			(long unsigned int)0x11000000, 0x1000);

	val = readl(addr+0x02C0);
	val = ((val & 0xFFFF00FF) | 0x00001100); /*  Output for GPM3[2:3] */
	writel(val, addr+0x02C0);

	val = 0x00000000;
	writel(val, addr+0x02C8);

	val = 0x0000FFFF;
	writel(val, addr+0x02CC);

	val = 0xff; /*  Disable All P-up */
	writel(val, addr+0x02C4);

	for (i = 0; i < 1000000; ++i)
		writel(val, addr+0x02C4);
	iounmap((void *)addr);

	printk(KERN_ERR "[DEBUG] END - Kodong DEBUG GPIO!!!");
}

/* for reserving dma channel. Every channel
This function checks availalbe DMA channel */
int get_available_dma_ch(int channel)
{
	int i, flag[8];

	for (i = 0; i < sizeof(g_dma_res)/sizeof(g_dma_res[0]); ++i)
		flag[i] = 0;

	for (i = 0; i < sizeof(g_tx_reqs)/sizeof(g_tx_reqs[0]); ++i)
		if (g_tx_reqs[i].dma_ch != -1)
			flag[g_tx_reqs[i].dma_ch]++;

	for (i = 0; i < sizeof(g_rx_reqs)/sizeof(g_rx_reqs[0]); ++i)
		if (g_rx_reqs[i].dma_ch != -1)
			flag[g_rx_reqs[i].dma_ch]++;

	for (i = 0; i < sizeof(g_dma_res)/sizeof(g_dma_res[0]); ++i)
		if (flag[i] == 0)
			return i;
	return -1;
}

static int hsi_setup_tx_dmachannel(int channel, int count)
{
	int dmach;
	unsigned int val;
	unsigned long flag;

	/*  1. check & get available DMA channela when dma
	*   channel was not assigned */
	if (g_tx_reqs[channel].dma_ch == -1) {
		spin_lock_irqsave(&g_dma_lock, flag);
		dmach = get_available_dma_ch(channel);
		spin_unlock_irqrestore(&g_dma_lock, flag);
		if (dmach == -1) {
			printk(KERN_ERR "[ERROR] There is no available DMA channel. "
					"DMA transmission failed.\n");
			spin_unlock_irqrestore(&g_dma_lock, flag);
			return -1;
		}
		printk("[DEBUG] (1) DMA channel-%d was assigned "
			"for channel-%d\n", dmach, channel);

		/*  2. Reserve DMA channel */
		g_tx_reqs[channel].dma_ch = dmach;
		spin_lock_irqsave(&g_dma_lock, flag);
		setup_tx_dma(&g_tx_reqs[channel]);
		spin_unlock_irqrestore(&g_dma_lock, flag);
	}

	val = MAKE_SDMA_REGVAL(1, HSI_DMA_BURST_4,
		(count)>>2, channel, 0);
	sechsi_mipi_write_register(
		HSI_SDMA_CONFIG(g_tx_reqs[channel].dma_ch), val);
	return 0;
}

/****** For using GPIO debug
1.  Init - KodongInitGPIO();
2.  IO remap - g_gpio_addr = ioremap_nocache (0x11000000, 0x1000);
3. write values
    g_val = 0x00;
    writel(g_val, g_gpio_addr+0x02C4);
*/

/* hsi_driver_write_dma - */
int hsi_driver_write_dma(int ch, unsigned char *buff, int count)
{
	int channel = ch % EXYNOS_HSI_DMACHNUM;
	int size;
	unsigned long flag;

	if (hsi_setup_tx_dmachannel(ch, count) < 0)
		return -1;

	/*  3. Initialize DMA buffer */
	if (g_dma_txbuff[channel] == NULL) {
		spin_lock(&g_tx_reqs[channel].lock);
		g_dma_txbuff[channel] = ALLOC_DMA_BYTES(g_dma_chunk_size);
		spin_unlock(&g_tx_reqs[channel].lock);
	}

	/*  4. Initial DMA request */
	if (count < g_dma_chunk_size)
		size = count;
	else
		size = g_dma_chunk_size;

	spin_lock(&g_tx_reqs[channel].lock);
	g_tx_reqs[channel].req.dma.dma_size = size;
	g_tx_reqs[channel].req.dma.size_in_byte = count;
	g_tx_reqs[channel].req.dma.index = 0;
	spin_unlock(&g_tx_reqs[channel].lock);

	assign_tx_buffer(channel, buff, count);

/*  Time estimation start!!! */
do_gettimeofday(&kodong_t_before);

	/*  5. Now run DMA */
	spin_lock_irqsave(&g_dma_lock, flag);
	start_tx_dma(channel, g_dma_txbuff[channel], size);
	spin_unlock_irqrestore(&g_dma_lock, flag);

	return 0;
}

/* For initialize DMA API. */
void setup_tx_dma(struct hsi_request *p_dma_req)
{
	if (s3c2410_dma_request(g_dma_res[p_dma_req->dma_ch],
		&sechsi_dma_name, NULL) < 0) {
		printk(KERN_ERR "[ERROR] Cannot get DMACH for TX");
		return;
	}

	if (s3c2410_dma_set_buffdone_fn(g_dma_res[p_dma_req->dma_ch],
		callback_mipihsi_tx_dma)) {
		printk(KERN_ERR "[ERROR] Cannot assign callback for DMACH");
		return;
	}

	if (s3c2410_dma_devconfig(g_dma_res[p_dma_req->dma_ch],
		S3C2410_DMASRC_MEM,
		(g_hsi_ctrl.phy_base + HSI_TX_DATA(p_dma_req->channel))))

	{
		printk(KERN_ERR "Cannot dev configure for DMACH1");
		return;
	}
}

void setup_rx_dma(struct hsi_request *p_dma_req)
{
	if (s3c2410_dma_request(g_dma_res[p_dma_req->dma_ch],
		&sechsi_dma_name, NULL) < 0) {
		printk(KERN_ERR "[ERROR] Cannot get DMACH for RX");
		return;
	}

	if (s3c2410_dma_set_buffdone_fn(g_dma_res[p_dma_req->dma_ch],
		callback_mipihsi_rx_dma)) {
		printk(KERN_ERR "[ERROR] Cannot assign callback for DMACH");
		return;
	}

	if (s3c2410_dma_devconfig(g_dma_res[p_dma_req->dma_ch],
		S3C2410_DMASRC_HW,
		(g_hsi_ctrl.phy_base + HSI_RX_DATA(p_dma_req->channel))))

	{
		printk(KERN_ERR "Cannot dev configure for DMACH1");
		return;
	}
}


/* for transmitting a single chunk data with DMA */
void start_tx_dma(int ch, unsigned char *p, int size)
{
	g_mapped_ptr = (unsigned int *)dma_map_single(
		(struct device *)g_tx_reqs[ch].pdev, (void *)p,
		size, DMA_TO_DEVICE);

	if (dma_mapping_error((struct device *)g_tx_reqs[ch].pdev,
		(dma_addr_t)g_mapped_ptr)) {
		printk(KERN_ERR "dma_map_single Tx failed");
		return;
	}

	/*  Program DMA controller register to start DMA transfer. */
	if (s3c2410_dma_config(g_dma_res[g_tx_reqs[ch].dma_ch],
		4)) { /*  Tx 4 bytes unit */
		printk(KERN_ERR "Cannot dma_config for DMACH0");
		return;
	}

	if (s3c2410_dma_enqueue(g_dma_res[g_tx_reqs[ch].dma_ch],
		&g_tx_reqs[ch], (dma_addr_t)g_mapped_ptr, size)) {
		printk(KERN_ERR "Cannot dma_enque for DMACH0");
		return;
	}

	if (s3c2410_dma_ctrl(g_dma_res[g_tx_reqs[ch].dma_ch],
		S3C2410_DMAOP_START)) {
		printk(KERN_ERR "Cannot dma_ctrl for DMACH0");
		return;
	}
}

/* for receiving a single chunk data with DMA */
void start_rx_dma(int ch, unsigned char *p, int size)
{
	g_mapped_ptr = (unsigned int *)dma_map_single(
			(struct device *)g_rx_reqs[ch].pdev, (void *)p,
			(size_t)size, DMA_FROM_DEVICE);

	if (dma_mapping_error((struct device *)g_tx_reqs[ch].pdev,
		(dma_addr_t)g_mapped_ptr)) {
		printk(KERN_ERR "dma_map_single RX failed");
		return;
	}

	/*  Program DMA controller register to start DMA transfer.
	*   Tx 4 bytes unit */
	if (s3c2410_dma_config(g_dma_res[g_rx_reqs[ch].dma_ch], 4)) {
		printk(KERN_ERR "Cannot dma_config for DMACH for RX");
		return;
	}

	if (s3c2410_dma_enqueue(g_dma_res[g_rx_reqs[ch].dma_ch],
		&g_rx_reqs[ch], (dma_addr_t)g_mapped_ptr, size)) {
		printk(KERN_ERR "Cannot dma_enque for DMACH RX");
		return;
	}

	if (s3c2410_dma_ctrl(g_dma_res[g_rx_reqs[ch].dma_ch],
		S3C2410_DMAOP_START)) {
		printk(KERN_ERR "Cannot start for DMACH RX");
		return;
	}
}

static void callback_mipihsi_tx_dma(struct s3c2410_dma_chan *chan, void *buf_id,
				int dma_size, enum s3c2410_dma_buffresult res)
{
	int size;
	struct hsi_request *p_req = (struct hsi_request *)buf_id;
	struct hsi_buffer_list *node;
	struct list_head *next;

	dma_unmap_single((struct device *)p_req->pdev,
			(dma_addr_t)g_mapped_ptr, dma_size, DMA_TO_DEVICE);

	spin_lock(&p_req->lock);
	p_req->req.dma.index += p_req->req.dma.dma_size;
	node = container_of(TX_BUFFER_FIRST_ENTRY(p_req->channel),
		struct hsi_buffer_list, head); /* FIFO tx queue */
	spin_unlock(&p_req->lock);

	if (node->index < node->size) {
		if (node->size - node->index < g_dma_chunk_size)
			size = node->size - node->index;
		else
			size = g_dma_chunk_size;
		memcpy(g_dma_txbuff[p_req->channel],
			node->buffer+node->index, size);

		spin_lock(&p_req->lock);
		node->index += size;
		spin_unlock(&p_req->lock);

		spin_lock(&g_dma_lock);
		start_tx_dma(p_req->channel,
			g_dma_txbuff[p_req->channel], size);
		spin_unlock(&g_dma_lock);
	} else {
		spin_lock(&p_req->lock);
		next = node->head.next;
		list_del(&node->head);
		FREE_BYTES(node->buffer);
		FREE_BYTES((unsigned char *)node);
		spin_unlock(&p_req->lock);

		if (next == TX_BUFFER_HEAD_PTR(p_req->channel)) {
			/*
			int ms, spd, b,s;
			do_gettimeofday(&kodong_t_after);
			kodong_timeval_subtract(&kodong_t_diff,
				&kodong_t_after, &kodong_t_before);
			ms = kodong_t_diff.tv_sec * 1000 +
				kodong_t_diff.tv_usec;
			spd = (p_req->req.dma.size_in_byte<<3)/ms*1000;
			b = spd / 1000;
			s = spd - (b*1000);
			printk(KERN_ERR
				""[DEBUG] TX TIME: %ld.%06ld - %d.%d Mbps\n",
				kodong_t_diff.tv_sec, kodong_t_diff.tv_usec,
				b, s);
			*/
			if_tx_dma_was_finished(p_req->channel);
			return;
		}
		/* FIFO tx queue */
		node = container_of(next, struct hsi_buffer_list, head);
		if (node->size - node->index < g_dma_chunk_size)
			size = node->size - node->index;
		else
			size = g_dma_chunk_size;
		memcpy(g_dma_txbuff[p_req->channel],
			node->buffer+node->index, size);
		spin_lock(&p_req->lock);
		node->index += size;
		spin_unlock(&p_req->lock);
		spin_lock(&g_dma_lock);
		start_tx_dma(p_req->channel,
			g_dma_txbuff[p_req->channel], size);
		spin_unlock(&g_dma_lock);
	}
}


static void callback_mipihsi_rx_dma(struct s3c2410_dma_chan *chan, void *buf_id,
	int dma_size, enum s3c2410_dma_buffresult res)
{
	struct hsi_request *p_req = (struct hsi_request *)buf_id;
	struct hsi_buffer_list *node, *pnew;
	int i, size;

	dma_unmap_single((struct device *)p_req->pdev,
		(dma_addr_t)g_mapped_ptr, dma_size, DMA_FROM_DEVICE);

	spin_lock(&p_req->lock);
	p_req->req.dma.index += p_req->req.dma.dma_size;
	spin_unlock(&p_req->lock);

	node = container_of(RX_BUFFER_LAST_ENTRY(p_req->channel),
		struct hsi_buffer_list, head);
	if (node->index + p_req->req.dma.dma_size <= node->size) {
		memcpy(node->buffer+node->index, g_dma_rxbuff[p_req->channel],
		p_req->req.dma.dma_size);
		spin_lock(&p_req->lock);
		node->index += p_req->req.dma.dma_size;
		spin_unlock(&p_req->lock);
	} else {
		i = node->size - node->index;
		size = p_req->req.dma.dma_size-i;
		if (i > 0) {
			memcpy(node->buffer+node->index,
				g_dma_rxbuff[p_req->channel], i);
			node->index = node->size;
		}
		pnew = (struct hsi_buffer_list *)ALLOC_BYTES(
			sizeof(struct hsi_buffer_list));
		INIT_LIST_HEAD(&pnew->head);
		pnew->index = size;
		pnew->size = g_rx_buffer_size;
		pnew->buffer = ALLOC_BYTES(g_rx_buffer_size);
		memcpy(pnew->buffer, g_dma_rxbuff[p_req->channel] + i, size);
		spin_lock(&p_req->lock);
		list_add_tail(&pnew->head, RX_BUFFER_HEAD_PTR(p_req->channel));
		spin_unlock(&p_req->lock);
	}

	if (p_req->req.dma.index < p_req->req.dma.size_in_byte) {
		if (p_req->req.dma.index + g_dma_chunk_size >
			p_req->req.dma.size_in_byte)
			size = p_req->req.dma.size_in_byte -
				p_req->req.dma.index;
		else
			size = g_dma_chunk_size;

		spin_lock(&p_req->lock);
		p_req->req.dma.dma_size = size;
		spin_unlock(&p_req->lock);

		spin_lock(&g_dma_lock);
		start_rx_dma(p_req->channel,
			g_dma_rxbuff[p_req->channel], size);
		spin_unlock(&g_dma_lock);
	} else {
		if_rx_dma_was_finished(p_req->channel);
		/* printk(KERN_ERR "[DEBUG] rx done\n"); */
	}
}

