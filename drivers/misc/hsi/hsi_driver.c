/* linux/drivers/misc/hsi/hsi_driver.c
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
#include <linux/clk.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/pagemap.h>
#include <linux/io.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include <linux/irq.h>

#include <mach/hsi.h>
#include <plat/cpu.h>

#include "hsi_driver.h"
#include "hsi_driver_int.h"
#include "hsi_driver_tran.h"
#include "hsi_protocol.h"
#include "hsi_debug.h"

#define EXYNOS_HSI_DRIVER_NAME		"exynos_hsi"

#define WRITE_SECHSI_SFR(off, val) \
	(*((unsigned int *)(g_hsi_ctrl.base+(off))) = (val))
#define READ_SECHSI_SFR(off) \
	(*(unsigned int *)(g_hsi_ctrl.base+(off)))

#define HSI_GET_TX_FIFOSIZE(ch)	(0x01 << (((*((int *) \
	(g_hsi_ctrl.base+HSI_TXFIFO_CON1)))>>((ch)<<2)) & 0x0000000F))
#define HSI_GET_RX_FIFOSIZE(ch)	(0x01 << (((*((int *) \
	(g_hsi_ctrl.base+HSI_RXFIFO_CON1)))>>((ch)<<2)) & 0x0000000F))


/* Device declaration */
static struct platform_device_id sechsi_id_table[] = {
	{ EXYNOS_HSI_DRIVER_NAME, 0 },
	{},
};

MODULE_DEVICE_TABLE(platform, sechsi_id_table);

#ifdef CONFIG_PM
static int samsung_hsi_suspend(struct platform_device *dev, pm_message_t pm)
{
	printk(KERN_ERR "MIPI-HSI will be suspended.\n");
	return 0;
}

static int samsung_hsi_resume(struct platform_device *dev)
{
	printk(KERN_ERR "MIPI-HSI will be resumed.\n");
	return 0;
}
#else
#define samsung_hsi_suspend NULL
#define samsung_hsi_resume NULL
#endif

/* Driver declaration */
static struct platform_driver exynos_hsi_driver = {
	.driver		= {
		.owner	= THIS_MODULE,
		.name	= EXYNOS_HSI_DRIVER_NAME,
	},
	.suspend        = samsung_hsi_suspend,
	.resume         = samsung_hsi_resume,
	.id_table = sechsi_id_table,
};

struct hsi_controller g_hsi_ctrl;


static void enable_mipihsi_clock(struct platform_device *pdev);

inline unsigned int sechsi_read_sfr(unsigned int off)
{
	unsigned int val;
	unsigned long flag;
	spin_lock_irqsave(&g_hsi_ctrl.lock, flag);
	val = READ_SECHSI_SFR(off);
	spin_unlock_irqrestore(&g_hsi_ctrl.lock, flag);
	return val;
}

inline void sechsi_write_sfr(unsigned int off, unsigned int val)
{
	unsigned long flag;
	spin_lock_irqsave(&g_hsi_ctrl.lock, flag);
	WRITE_SECHSI_SFR(off, val);
	spin_unlock_irqrestore(&g_hsi_ctrl.lock, flag);
}

inline unsigned int sechsi_get_tx_fifosize(int ch)
{
	unsigned int val;
	unsigned long flag;
	spin_lock_irqsave(&g_hsi_ctrl.lock, flag);
	val = HSI_GET_TX_FIFOSIZE(ch);
	spin_unlock_irqrestore(&g_hsi_ctrl.lock, flag);
	return val;
}

inline unsigned int sechsi_get_rx_fifosize(int ch)
{
	unsigned int val;
	unsigned long flag;
	spin_lock_irqsave(&g_hsi_ctrl.lock, flag);
	val = HSI_GET_RX_FIFOSIZE(ch);
	spin_unlock_irqrestore(&g_hsi_ctrl.lock, flag);
	return val;
}

static int memorymap(struct platform_device *pdev)
{
	struct resource *mem, *ioarea;
	u32 version;

	mem = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!mem) {
		printk(KERN_ERR "HSI device does not have "
			"HSI IO memory region information\n");
		return -ENXIO;
	}
	printk(KERN_ERR "hsi_controller_init : IORESOURCE_MEM %s [%x, %x]\n",
		mem->name, mem->start, mem->end);

	ioarea = devm_request_mem_region(&pdev->dev, mem->start,
		(mem->end - mem->start) + 1,
		dev_name(&pdev->dev));
	if (!ioarea) {
		printk(KERN_ERR "Unable to request HSI IO mem region\n");
		return -EBUSY;
	}
	printk(KERN_ERR "hsi_controller_init : ioarea %s [%x, %x]\n",
		ioarea->name, ioarea->start, ioarea->end);

	g_hsi_ctrl.phy_base = mem->start;
	g_hsi_ctrl.base = devm_ioremap(&pdev->dev, mem->start,
					(mem->end - mem->start) + 1);
	if (!g_hsi_ctrl.base) {
		printk(KERN_ERR "Unable to ioremap HSI base IO address\n");
		return -ENXIO;
	}
	printk(KERN_ERR "hsi_controller_init : hsi_ctrl->base=%x\n",
		(unsigned int)g_hsi_ctrl.base);

	version = sechsi_read_sfr(HSI_VERSION);
	printk(KERN_ERR "MIPI-HSI Version : 0x%08X", version);
	return 0;
}

/*
 * get_sechsi_version - for gettting the version of sechsi */
unsigned int get_sechsi_version()
{
	unsigned int val;
	unsigned long flag;
	spin_lock_irqsave(&g_hsi_ctrl.lock, flag);
	val = READ_SECHSI_SFR(HSI_VERSION);
	spin_unlock_irqrestore(&g_hsi_ctrl.lock, flag);
	return val;
}

/*
 * sechsi_mipi_read_register - for gettting from a mipihsi register*/
unsigned int sechsi_mipi_read_register(unsigned int off)
{
	unsigned int val;
	unsigned long flag;
	spin_lock_irqsave(&g_hsi_ctrl.lock, flag);
	val = READ_SECHSI_SFR(off);
	spin_unlock_irqrestore(&g_hsi_ctrl.lock, flag);
	return val;
}

/*
 * sechsi_mipi_write_register - for writing a value to a mipihsi register */
unsigned int sechsi_mipi_write_register(unsigned int off, unsigned int val)
{
	unsigned long flag;
	spin_lock_irqsave(&g_hsi_ctrl.lock, flag);
	WRITE_SECHSI_SFR(off, val);
	spin_unlock_irqrestore(&g_hsi_ctrl.lock, flag);
	return 0;
}

/*
 * sechsi_read_register - for gettting from a mipihsi register*/
unsigned int sechsi_read_register(unsigned int addr)
{
	unsigned int maddr, val;
	maddr = (unsigned int)ioremap_nocache((addr & 0xFFFFF000), 0x1000);
	if (!maddr)
		return 0xFFFFFFFF;
	val = *(unsigned int *)(maddr + (addr & 0x00000FFF));
	iounmap((void *)maddr);
	return val;
}

/*
 * sechsi_write_register - for writing a value to a mipihsi register */
unsigned int sechsi_write_register(unsigned int addr, unsigned int val)
{
	unsigned int maddr;

	maddr = (unsigned int)ioremap_nocache((addr & 0xFFFFF000), 0x1000);
	if (!maddr)
		return 0xFFFFFFFF;
	*((unsigned int *)(maddr + (addr & 0x00000FFF))) = val;
	iounmap((void *)maddr);
	return 0;
}

int check_clock(void)
{
	unsigned int addr, clk;
	volatile unsigned int *mapped_addr;
	addr = (unsigned int)ioremap_nocache(0x12180000, 0x1000);
	mapped_addr = (unsigned int *)(addr+0x0040);
	clk = *mapped_addr;
	*mapped_addr = clk & ~(0x01<<17);
	*mapped_addr = clk | (0x01<<17);
	iounmap((void *)addr);

	return 0;
}


/** reset_sechsi - for resetting HW */
int reset_sechsi()
{
	int i;
	/* soft reset */
	sechsi_soft_reset();

	/* 2. Disable Channel */
	for (i = 0; i < 8; i++) {
		SECHSI_DISABLE_TX(i);
		SECHSI_DISABLE_RX(i);
	}

	if (soc_is_exynos5250())
		check_clock();

	/* 3. Set HSI Controller Default Value */
	/*sechsi_set_rx_clock_source(HSI_RX_CLK_INTERNAL); */

	SECHSI_SET_RX_FRAME_BURST_COUNT(0);
	SECHSI_SET_RX_TAILING_BIT_COUNT(HSI_TAILBIT_400);

	if (soc_is_exynos4212() || soc_is_exynos4412())
		SECHSI_SET_RX_CLOCK_BUFFER(2);	/* Recommand 2 at EVT1 */
	else if (soc_is_exynos5250())
		SECHSI_SET_RX_CLOCK_BUFFER(2);	/* Recommand 2 at EVT1 */

	SECHSI_SET_DATA_TIMEOUT_COUNT(14);	/* 14 */
	SECHSI_SET_RECV_TIMEOUT_COUNT(HSI_RX_TIMEOUT_14400);

	sechsi_set_tx_config(HSI_ID_3BIT, HSI_STREAM_MODE);
	sechsi_set_rx_config(HSI_ID_3BIT, HSI_STREAM_MODE, HSI_SYNC_MODE);
	sechsi_set_arbiter_priority(HSI_AP_ROUND);

	/* 4. Set Default Interrupt */
	sechsi_enable_int(0, HSI_INT_RX_WAKE);

	for (i = 0; i < 8; i++) {
		sechsi_disable_int(i, HSI_INT_TX);
		sechsi_disable_int(i, HSI_INT_RX);
		sechsi_disable_int(i, HSI_INT_SDMA_DONE);
	}

	sechsi_enable_int(0, HSI_INT_RX);

	/* 5. Set Default Error Interrupt */
	sechsi_enable_int_err(0, HSI_INT_ERR_RX_BREAK);
	sechsi_enable_int_err(0, HSI_INT_ERR_RX);
	for (i = 0; i < 8; i++)
		sechsi_enable_int_err(i, HSI_INT_ERR_DATA_TIMEOUT);

	/* 6. Enable Tx Clock */
	if (soc_is_exynos4212() || soc_is_exynos4412())
		sechsi_set_clock_divider(HSI_CLK_DIV_1, 1);
	else if (soc_is_exynos5250())
		sechsi_set_clock_divider(HSI_CLK_DIV_1, 1);

	return 0;
}

inline void sechsi_set_bit(unsigned int off, unsigned int n)
{
	register unsigned int u32val, addr =
		(unsigned int)g_hsi_ctrl.base + off;
	unsigned long flag;
	spin_lock_irqsave(&g_hsi_ctrl.lock, flag);
	u32val = *(unsigned int *)(addr);
	u32val = u32val | (1 << n);
	*((unsigned int *)(addr)) = u32val;
	spin_unlock_irqrestore(&g_hsi_ctrl.lock, flag);
}

inline void sechsi_clear_bit(unsigned int off, unsigned int n)
{
	register unsigned int u32val, addr =
		(unsigned int)g_hsi_ctrl.base + off;
	unsigned long flag;
	spin_lock_irqsave(&g_hsi_ctrl.lock, flag);
	u32val = *(unsigned int *)(addr);
	u32val = u32val & (~(1 << n));
	*((unsigned int *)(addr)) = u32val;
	spin_unlock_irqrestore(&g_hsi_ctrl.lock, flag);
}

inline void sechsi_set_masked_value(unsigned int off, unsigned int mask,
	unsigned int val, unsigned int nbit)
{
	unsigned int addr = (unsigned int)g_hsi_ctrl.base + off;
	unsigned long flag;
	register unsigned int lval;
	spin_lock_irqsave(&g_hsi_ctrl.lock, flag);
	lval = ((*(unsigned int *)(addr)) & (~(mask << nbit))) |
		((val & mask) << nbit);
	*((unsigned int *)(addr)) = lval;
	spin_unlock_irqrestore(&g_hsi_ctrl.lock, flag);
}

inline unsigned int sechsi_test_bit(unsigned int off, unsigned int n)
{
	unsigned int val;
	unsigned long flag;
	register unsigned int addr = (unsigned int)g_hsi_ctrl.base + off;
	spin_lock_irqsave(&g_hsi_ctrl.lock, flag);
	val = (*(unsigned int *)(addr)) & (1 << n);
	spin_unlock_irqrestore(&g_hsi_ctrl.lock, flag);
	return val;
}

/** sechsi_soft_reset - soft reset */
int sechsi_soft_reset(void)
{
	sechsi_set_bit(HSI_PROGRAM, 0);  /* Softwoare Reset.. */
	/* wait for clock stable */
	while (sechsi_test_bit(HSI_PROGRAM, 0))
		; /* wait until it clear */
	return 0;
}

/**
 * setup_sechsi_system_clock - for setting up MCLK as 200MHz, and enabling
 * clock source */
int setup_sechsi_system_clock()
{
	unsigned int addr, clk;
	addr = (unsigned int)ioremap_nocache(0x1003C000, 0x1000);
	*((unsigned int *)(addr+0x0540)) = 0x00300000;
	clk = (*(unsigned int *)(addr+0x0240));
	*((unsigned int *)(addr+0x0240)) = clk & 0xFEFFFFFF;
	iounmap((void *)addr);

	return 0;
}

/**
 * reset_sechsi_gpio - enalbing GPIO path for mipi-hsi */
int reset_sechsi_gpio(int enable, int drive)
{
	unsigned int addr;
	/* SET GPIO configuration */
	addr = (unsigned int)ioremap_nocache(0x11000000, 0x1000);
	if (enable) {
		/* Set HSI (EBI Path) */
		writel(0x44444444, addr + 0x01A0);
		/* Set Pull-up/down disabled */
		writel(0x00000000, addr + 0x01A8);
		switch (drive) {
		case 0:
			writel(0x00000000, addr + 0x01AC);
			break;
		case 1:
			writel(0x0000AAAA, addr + 0x01AC);
			break;
		case 2:
			writel(0x00005555, addr + 0x01AC);
			break;
		case 3:
			writel(0x0000FFFF, addr + 0x01AC);
			break;
		}
	} else {
		/* Set default (Input) */
		writel(0x00000000, addr + 0x01A0);
		/* Set defualut (Pull-down enabled) */
		writel(0x00005555, addr + 0x01A8);
		/* Set default (x2)*/
		writel(0x0000AAAA, addr + 0x01AC);
	}
	iounmap((void *)addr);
	return 0;
}

void sechsi_set_rx_clock_source(unsigned int intclk)
{
	sechsi_clear_bit(HSI_SDMA_CONFIG(0), 26);
	if (intclk)
		sechsi_set_bit(HSI_SDMA_CONFIG(0), 26);
}

void sechsi_set_tx_config(int idbit, int mode)
{
	/* Set ID Bit Length */
	sechsi_set_masked_value(HSI_PROGRAM1, 0x3, idbit, 0);
	/* Set Tx Mode */
	if (mode)
		sechsi_set_bit(HSI_PROGRAM, 8);    /* FRAME mode */
	else
		sechsi_clear_bit(HSI_PROGRAM, 8);  /* Stream mode */
}

void sechsi_set_rx_config(int idbit, int mode, int dataflow)
{
	/* Set ID Bit Length */
	sechsi_set_masked_value(HSI_PROGRAM1, 0x3, idbit, 2);

	/* Set Rx Mode */
	if (mode)
		sechsi_set_bit(HSI_PROGRAM, 30);    /* FRAME mode */
	else
		sechsi_clear_bit(HSI_PROGRAM, 30);  /* Stream mode */

	/* Set Rx Data Flow */
	sechsi_set_masked_value(HSI_PROGRAM, 0x3, dataflow, 9);
}

inline void sechsi_set_arbiter_priority(int prior)
{
	if (prior) /* HSI_AP_FIXED */
		/* Fixed Priority */
		sechsi_set_bit(HSI_ARBITER_PRI, 0);
	else
		/* Round Robin Priority */
		sechsi_clear_bit(HSI_ARBITER_PRI, 0);
}

inline void sechsi_enable_int(int ch, int intr)
{
	if (intr == HSI_INT_RX_WAKE) {
		sechsi_set_bit(HSI_INT_STAT_EN, intr);
		sechsi_set_bit(HSI_INT_SIG_EN,  intr);
	} else {
		sechsi_set_bit(HSI_INT_STAT_EN, intr+ch);
		sechsi_set_bit(HSI_INT_SIG_EN,  intr+ch);
	}
}

inline void sechsi_disable_int(int ch, int intr)
{
	if (intr == HSI_INT_RX_WAKE) {
		sechsi_clear_bit(HSI_INT_STAT_EN, intr);
		sechsi_clear_bit(HSI_INT_SIG_EN, intr);
	} else {
		sechsi_clear_bit(HSI_INT_STAT_EN, intr+ch);
		sechsi_clear_bit(HSI_INT_SIG_EN,  intr+ch);
	}
}

inline void sechsi_enable_int_err(int ch, int intr)
{
	if (intr == HSI_INT_ERR_RX_BREAK || intr == HSI_INT_ERR_RX) {
		sechsi_set_bit(HSI_ERR_INT_SIG_EN, intr);
		sechsi_set_bit(HSI_ERR_INT_STAT_EN, intr);
	} else {
		sechsi_set_bit(HSI_ERR_INT_SIG_EN, intr+ch);
		sechsi_set_bit(HSI_ERR_INT_STAT_EN, intr+ch);
	}
}

inline void sechsi_disable_int_err(int ch, int intr)
{
	if (intr == HSI_INT_ERR_RX_BREAK || intr == HSI_INT_ERR_RX) {
		sechsi_clear_bit(HSI_ERR_INT_SIG_EN, intr);
		sechsi_clear_bit(HSI_ERR_INT_STAT_EN, intr);
	} else {
		sechsi_clear_bit(HSI_ERR_INT_SIG_EN, intr+ch);
		sechsi_clear_bit(HSI_ERR_INT_STAT_EN, intr+ch);
	}
}

void sechsi_set_clock_divider(int div, int enable)
{
	sechsi_set_tx_clock(0);

	sechsi_set_masked_value(HSI_CLK_CON, 0xFF, div, 3);

	/*
	if (eDiv)
		g_sHsi.nTxClock = g_sHsi.nSrcClock / (eDiv *2);
	else
		g_sHsi.nTxClock = g_sHsi.nSrcClock;
	*/

	sechsi_set_tx_clock(enable);
}

void sechsi_set_tx_clock(int enable)
{
	unsigned int i = 0xFF;

	if (enable) {
		/* set internal clk enable */
		sechsi_set_bit(HSI_CLK_CON, 2);
		/* wait for clock stable */
		while (sechsi_test_bit(HSI_CLK_CON, 1))
			if (i-- == 0) /* for avoiding system hang */
				break;
		/* set internal clk enable */
		sechsi_set_bit(HSI_CLK_CON, 0);
	} else {
		/* set internal clk disable, stop */
		sechsi_clear_bit(HSI_CLK_CON, 2);
		sechsi_clear_bit(HSI_CLK_CON, 0);
	}
}

int set_default_system_config(void)
{
	sechsi_set_tx_config(HSI_ID_3BIT, HSI_STREAM_MODE);
	sechsi_set_rx_config(HSI_ID_3BIT, HSI_STREAM_MODE, HSI_SYNC_MODE);

	/*
	by default, control channel, channel 0 is opened and has only
		1 D-dword FIFO
	sechsi_open_tx_channel(HSI_CHANNEL0, HSI_FS_1, HSI_FIFO_ALMOST);
	sechsi_open_rx_channel(HSI_CHANNEL0, HSI_FS_1, HSI_FIFO_ALMOST);*/

	/* Send Wake-up! */
	SECHSI_WAKEUP_TX();
	return 0;
}

void sechsi_open_tx_channel(unsigned int ch, int fifosize,
	int fifolev)
{
	sechsi_set_tx_arbiter(ch, HSI_TX_PRIORITY_1, 0x00);
	sechsi_set_tx_fifo(ch, fifosize, fifolev);
	SECHSI_ENABLE_TX(ch);
}

void sechsi_open_rx_channel(unsigned int ch, int fifosize,
	int fifolev)
{
	sechsi_set_rx_fifo(ch, fifosize, fifolev);
	SECHSI_ENABLE_RX(ch);
}

/*
 * enable_mipihsi_clock - for enabling mipi hsi clock */
static void enable_mipihsi_clock(struct platform_device *pdev)
{
	struct clk *hsiclk;

	/* Now system clock enable */
	hsiclk = clk_get(&pdev->dev, "mipihsi");
	if (IS_ERR(hsiclk)) {
		printk(KERN_ERR "Getting mipi-hsi clk FAILED!");
		return;
	}
	clk_enable(hsiclk);
}


void sechsi_set_tx_arbiter(unsigned int ch, int prior,
				unsigned int bw)
{
	register unsigned int off = HSI_ARBITER_BW1 + ((ch >> 2) << 2);
	/* Set priority */
	sechsi_set_masked_value(HSI_ARBITER_PRI, 0x07, prior, 1+ch*3);
	/* Set bandwidth */
	sechsi_set_masked_value(off, 0xFF, bw, (ch & 0x00000003) << 3);
}

inline void sechsi_set_tx_fifo(unsigned int ch, int fifosize,
	int fifolev)
{
	/*Set Tx FIFO Size*/
	sechsi_set_masked_value(HSI_TXFIFO_CON1, 0x0F, fifosize, ch << 2);
	/*Set Tx FIFO Trigger Level*/
	if (fifolev == HSI_FIFO_ALMOST)
		sechsi_set_bit(HSI_TXFIFO_CON2, ch);
	else
		sechsi_clear_bit(HSI_TXFIFO_CON2, ch);
}

inline void sechsi_set_rx_fifo(unsigned int ch, int fifosize,
	int fifolev)
{
	/* Set Tx FIFO Size */
	sechsi_set_masked_value(HSI_RXFIFO_CON1, 0x0F, fifosize, ch << 2);
	/* Set Tx FIFO Trigger Level */
	if (fifolev == HSI_FIFO_ALMOST)
		sechsi_set_bit(HSI_RXFIFO_CON2, ch);
	else
		sechsi_clear_bit(HSI_RXFIFO_CON2, ch);
}

/** sechsi_system_config_debug - for debugging system config */
unsigned int sechsi_system_config_debug()
{
	unsigned int val;
	/*enable clk*/
	sechsi_set_tx_clock(0);
	sechsi_set_tx_clock(1);

	val = READ_SECHSI_SFR(HSI_PROGRAM);
	val = val & 0x00000000;
	WRITE_SECHSI_SFR(HSI_PROGRAM, val);

	/* set rx clock exnable */
	sechsi_set_masked_value(HSI_SDMA_CONFIG(0), 0x07, 0x07, 24);

	sechsi_set_masked_value(HSI_TXFIFO_CON1, 0x0F, 0x01, 0); /*2-D WORD*/
	sechsi_set_masked_value(HSI_RXFIFO_CON1, 0x0F, 0x01, 0); /*2-D WORD*/

	sechsi_clear_bit(HSI_TXFIFO_CON2, 0); /* half empty */
	sechsi_clear_bit(HSI_RXFIFO_CON2, 0); /* half empty */

	sechsi_clear_bit(HSI_PROGRAM, 8);  /* tx mode to stream */
	sechsi_clear_bit(HSI_PROGRAM, 30); /* rx mode to stream */

	/* rx data flow as synchronized */
	sechsi_set_masked_value(HSI_PROGRAM, 0x03, 0x00, 0);

	/* set arbitration priority as RR */
	sechsi_clear_bit(HSI_ARBITER_PRI, 0);

	/* Set bandwidth */
	sechsi_set_masked_value(HSI_ARBITER_BW1, 0xFF, 1, 0);

	val = 0x00010100;
	WRITE_SECHSI_SFR(HSI_INT_SIG_EN, val);

	/* val = 0x01FFFF00; */
	WRITE_SECHSI_SFR(HSI_INT_STAT_EN, val);

	val = 0x00000007;
	WRITE_SECHSI_SFR(HSI_ERR_INT_SIG_EN, val);

	/* u32Value = 0x03FF; */
	WRITE_SECHSI_SFR(HSI_ERR_INT_STAT_EN, val);

	sechsi_set_bit(HSI_PROGRAM, 12);  /* enable tx0 */
	sechsi_set_bit(HSI_PROGRAM, 20);  /* enable rx0 */

	sechsi_set_bit(HSI_PROGRAM, 31);  /* send wake up */
	return 0;
}

static int hsi_platform_device_probe(struct platform_device *pdev)
{
	struct exynos_hsi_platdata *pdata = pdev->dev.platform_data;

	printk(KERN_ERR "[DEBUG] platform driver init process");

	if (pdata->setup_gpio)
		pdata->setup_gpio(1, 3);

	/* init DMA channel resource */
	init_hsi_driver_dma(pdev);

	/* enable mipihsi system clock */
	enable_mipihsi_clock(pdev);

	/* memory map */
	memorymap(pdev);

	hsi_interrupt_init(pdev);

	return 0;
}

int init_platform_driver()
{
	int err;

	/* Register the HSI platform driver */
	err = platform_driver_probe(&exynos_hsi_driver,
		hsi_platform_device_probe);
	if (err < 0) {
		printk(KERN_ERR "Platform DRIVER register FAILED: %d\n", err);
		return err;
	}

	spin_lock_init(&g_hsi_ctrl.lock);

	return 0;
}

