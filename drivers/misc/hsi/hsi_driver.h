/* linux/drivers/misc/hsi/hsi_driver.h
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

#ifndef __HSI_SYSTEM_DRIVER_HEADER__
#define __HSI_SYSTEM_DRIVER_HEADER__

/*****************************************************************
	Register Map
******************************************************************/
/* Slave DMA Register */
#define HSI_SDMA_CONFIG(n)		(0x000+((n)<<2))

/* FIFO Control Register */
#define HSI_TXFIFO_CON1			0x040
#define HSI_TXFIFO_CON2			0x044
#define HSI_RXFIFO_CON1			0x048
#define HSI_RXFIFO_CON2			0x04C

/* HSI Core Register */
#define HSI_CLK_CON			0x050
#define HSI_STATUS			0x054
#define HSI_INT_STAT			0x058
#define HSI_INT_STAT_EN			0x05C
#define HSI_INT_SIG_EN			0x060
#define HSI_PROGRAM			0x064
#define HSI_ARBITER_PRI			0x068
#define HSI_ARBITER_BW1			0x06C
#define HSI_ARBITER_BW2			0x070
#define HSI_CAPABILITY			0x074
#define HSI_TX_DATA(n)			(0x078+0x04*(n))
#define HSI_RX_DATA(n)			(0x098+0x04*(n))
#define HSI_ERR_INT_STAT		0x0B8
#define HSI_ERR_INT_STAT_EN		0x0BC
#define HSI_ERR_INT_SIG_EN		0x0C0
#define HSI_STAT1			0x0C4
#define HSI_PROGRAM1			0x0C8
#define HSI_VERSION			0x0FC

/*****************************************************************
	Definition of ERRORS
*/
#define SECHSI_CONFIG_OK		0
#define SECHSI_IRQ_INIT_FAILED		1

/*****************************************************************
	Enumultion & Structure
*/
enum {
	HSI_INT_TX		= 0,	/* Tx Channel Threshold reached */
	HSI_INT_RX		= 8,	/* RX Channel Threshold reached */
	HSI_INT_RX_WAKE		= 16,	/* Rx Wakeup interrupt */
	HSI_INT_SDMA_DONE	= 17,	/* DMA Channel Trnsfer complete */
	HSI_INT_ERR		= 31,	/* Error status interrupt */
};

#define HSI_INT_TX_MASK		0x000000FF
#define HSI_INT_RX_MASK		0x0000FF00
#define HSI_INT_SDMA_DONE_MASK	0x01FE0000

enum {
	HSI_INT_ERR_RX_BREAK		= 0,
	HSI_INT_ERR_RX			= 1,
	HSI_INT_ERR_DATA_TIMEOUT	= 2,
};

#define HSI_INT_ERR_DATA_TIMEOUT_MASK	0x000003FC

enum {
	HSI_RX_CLK_EXT,
	HSI_RX_CLK_INTERNAL,
};

enum {
	/* base clock divided by 1 */
	HSI_CLK_DIV_1	= 0x00,
	/* base clock divided by 2 */
	HSI_CLK_DIV_2	= 0x01,
	/* base clock divided by 4 */
	HSI_CLK_DIV_4	= 0x02,
	/* base clock divided by 8 */
	HSI_CLK_DIV_8	= 0x04,
	/* base clock divided by 16 */
	HSI_CLK_DIV_16	= 0x08,
	/* base clock divided by 32 */
	HSI_CLK_DIV_32	= 0x10,
	/* base clock divided by 64 */
	HSI_CLK_DIV_64	= 0x20,
	/* base clock divided by 128 */
	HSI_CLK_DIV_128	= 0x40,
	/* base clock divided by 256 */
	HSI_CLK_DIV_256	= 0x80,
};

enum {
	/* Stream Transmission Mode */
	HSI_STREAM_MODE,
	/* Frame Transmission Mode */
	HSI_FRAME_MODE,
};

enum {
	/* Synchronized Data Flow */
	HSI_SYNC_MODE,
	/* Pipelined Data Flow */
	HSI_PIPE_MODE,
	/* Receiver Realtime Data Flow */
	HSI_REAL_MODE,
};

enum {
	/* RX TimeOut Count 200MHz AHB CLK */
	HSI_RX_TIMEOUT_14400	= 0x00,
	/* RX TimeOut Count 100MHz AHB CLK */
	HSI_RX_TIMEOUT_7200	= 0x01,
	/* RX TimeOut Count 50MHz AHB CLK */
	HSI_RX_TIMEOUT_3600	= 0x02,
	/* RX TimeOut Count 25MHz AHB CLK */
	HSI_RX_TIMEOUT_1800	= 0x04,
	/* RX TimeOut Count 12.50MHz AHB CLK*/
	HSI_RX_TIMEOUT_900	= 0x08,
	/* RX TimeOut Count 6.25MHz AHB CLK*/
	HSI_RX_TIMEOUT_450	= 0x10,
	/* RX TimeOut Count 3.12Hz AHB CLK*/
	HSI_RX_TIMEOUT_225	= 0x20,
	/* RX TimeOut Count 1.55MHz AHB CLK*/
	HSI_RX_TIMEOUT_112	= 0x40,
};

enum {
	HSI_ID_0BIT,
	HSI_ID_1BIT,
	HSI_ID_2BIT,
	HSI_ID_3BIT,
};

enum {
	/* Buffer size is 1 DWORDS*/
	HSI_FS_1 = 0,
	/* Buffer size is 2 DWORDS*/
	HSI_FS_2,
	/* Buffer size is 4 DWORDS*/
	HSI_FS_4,
	/* Buffer size is 8 DWORDS*/
	HSI_FS_8,
	/* Buffer size is 16 DWORDS*/
	HSI_FS_16,
	/* Buffer size is 32 DWORDS*/
	HSI_FS_32,
	/* Buffer size is 64 DWORDS*/
	HSI_FS_64,
	/* Buffer size is 128 DWORDS*/
	HSI_FS_128,
	/* Buffer size is 256 DWORDS*/
	HSI_FS_256,
	/* Buffer size is 512 DWORDS*/
	HSI_FS_512,
	/* Buffer size is 1024 DWORDS*/
	HSI_FS_1024,
};

enum {
	/* HALF EMPTY (FIFO SIZE / 2)*/
	HSI_FIFO_HALF,
	/* ALMOST EMPTY (FIFO DIZE / 4)*/
	HSI_FIFO_ALMOST,
};

enum {
	/* Round Robin Priority*/
	HSI_AP_ROUND = 0,
	/* Fixed Priority*/
	HSI_AP_FIXED,
};

enum {
	HSI_TX_PRIORITY_1 = 0,	/* 1st*/
	HSI_TX_PRIORITY_2,	/* 2nd*/
	HSI_TX_PRIORITY_3,	/* 3nd*/
	HSI_TX_PRIORITY_4,	/* 4nd*/
	HSI_TX_PRIORITY_5,	/* 5nd*/
	HSI_TX_PRIORITY_6,	/* 6nd*/
	HSI_TX_PRIORITY_7,	/* 7nd*/
	HSI_TX_PRIORITY_8,	/* 8nd*/
};

enum {
	HSI_DMA_TX = 0,
	HSI_DMA_RX,
};

enum {
	/* Burst SIZE 4 DWORDS*/
	HSI_DMA_BURST_4 = 0,
	/* Burst SIZE 8 DWORDS*/
	HSI_DMA_BURST_8,
	/* Burst SIZE 16 DWORDS*/
	HSI_DMA_BURST_16,
	/* Burst SIZE 32 DWORDS, PL330 does not support, */
	HSI_DMA_BURST_32,
};

enum {
	HSI_DMA_0 = 0,		/* DMA CHANNEL 0*/
	HSI_DMA_1,		/* DMA CHANNEL 1*/
	HSI_DMA_2,		/* DMA CHANNEL 2*/
	HSI_DMA_3,		/* DMA CHANNEL 3*/
	HSI_DMA_4,		/* DMA CHANNEL 4*/
	HSI_DMA_5,		/* DMA CHANNEL 5*/
	HSI_DMA_6,		/* DMA CHANNEL 6*/
	HSI_DMA_7,		/* DMA CHANNEL 7*/
	HSI_MAX_DMA_CH,
	HSI_DMA_NONE = 0xFF,
};


enum {
	/* Tailing BIt count = 400*/
	HSI_TAILBIT_400 = 0,
	/* Tailing BIt count = 200*/
	HSI_TAILBIT_200,
	/* Tailing BIt count = 100*/
	HSI_TAILBIT_100,
	/* Tailing BIt count = 50*/
	HSI_TAILBIT_50 = 4,
};

enum {
	/* Tx CH0 Threshold reached. <1<<0)*/
	TX_TS		= 0x1,
	/* RX CH0 Threshold reached. <1<<8)*/
	RX_TS		= 0x100,
	/* Rx Wakeup interrupt, (1 << 16)*/
	RX_WAKE		= 0x10000,
	/* Trnsfer complete sdma0,(1 << 17)*/
	SDMA_INT_CMPT	= 0x20000,
	/* Error status interrupt,(1 << 31)*/
	ERROR_INT	= 0x80000000,
};

enum {
	RX_BREAK_INT	= 0x1,	/* RX Break Interrupt*/
	RX_ERR_INT	= 0x2,	/* RX Error interrupt*/
	DATA_TO_INT	= 0x4,	/* Data Timeout Interrupt*/
};

enum {
	HSI_PIO_MODE,
	HSI_DMA_MODE,
};

struct __attribute__((packed)) sechsi_bit_field {
	unsigned int bit0:1;
	unsigned int bit1:1;
	unsigned int bit2:1;
	unsigned int bit3:1;
	unsigned int bit4:1;
	unsigned int bit5:1;
	unsigned int bit6:1;
	unsigned int bit7:1;
	unsigned int bit8:1;
	unsigned int bit9:1;
	unsigned int bit10:1;
	unsigned int bit11:1;
	unsigned int bit12:1;
	unsigned int bit13:1;
	unsigned int bit14:1;
	unsigned int bit15:1;
	unsigned int bit16:1;
	unsigned int bit17:1;
	unsigned int bit18:1;
	unsigned int bit19:1;
	unsigned int bit20:1;
	unsigned int bit21:1;
	unsigned int bit22:1;
	unsigned int bit23:1;
	unsigned int bit24:1;
	unsigned int bit25:1;
	unsigned int bit26:1;
	unsigned int bit27:1;
	unsigned int bit28:1;
	unsigned int bit29:1;
	unsigned int bit30:1;
	unsigned int bit31:1;
};


#define HSI_TIMEOUT_INFINITY		0
#define HSI_TIMEOUT_DEFAULT		0xFFFFF

#define SECHSI_DISABLE_TX(ch) sechsi_clear_bit(HSI_PROGRAM, (ch+12))
#define SECHSI_ENABLE_TX(ch)  sechsi_set_bit(HSI_PROGRAM, (ch+12))
#define SECHSI_WAKEUP_TX()     sechsi_set_bit(HSI_PROGRAM, 31)
#define SECHSI_DISABLE_RX(ch) sechsi_clear_bit(HSI_PROGRAM, (ch+20))
#define SECHSI_ENABLE_RX(ch)  sechsi_set_bit(HSI_PROGRAM, (ch+20))
#define SECHSI_WAKEUP_RX()     sechsi_set_bit(HSI_PROGRAM, 11)

#define SECHSI_SET_RX_FRAME_BURST_COUNT(cnt) \
	sechsi_set_masked_value(HSI_CLK_CON, 0xFF, cnt,     16)
#define SECHSI_SET_RX_TAILING_BIT_COUNT(tailbit) \
	sechsi_set_masked_value(HSI_CLK_CON, 0x03, tailbit, 24)
#define SECHSI_SET_RX_CLOCK_BUFFER(delay) \
	sechsi_set_masked_value(HSI_CLK_CON, 0x07, delay,   27)
#define SECHSI_SET_DATA_TIMEOUT_COUNT(tout) \
	sechsi_set_masked_value(HSI_CLK_CON, 0x0F, (tout) & 0xE, 11)
#define SECHSI_SET_RECV_TIMEOUT_COUNT(tout) \
	sechsi_set_masked_value(HSI_PROGRAM, 0x7F, tout, 1)

#define MAKE_SDMA_REGVAL(en, bc, cnt, ch, rt) \
	(((0x00000001&(en))<<31) | ((0x00000007&(bc))<<24) | \
	((0x000FFFFF&(cnt))<<4) | ((0x00000007&(ch))<<1) | \
	(0x00000001&(rt)))

struct sechsi_sys_config {
	unsigned int mipihsi_base_addr;
	unsigned int irq_handle;
};


struct hsi_controller {
	void __iomem *base;
	unsigned long phy_base;
	unsigned int irq_handle;
	/* Serializes access to internal data and regs */
	spinlock_t lock;
	bool clock_enabled;
	unsigned long clock_rate;
};

extern struct hsi_controller g_hsi_ctrl;

int init_system_config(struct platform_device *pdev);
unsigned int get_sechsi_version(void);
int reset_sechsi(void);
int setup_sechsi_system_clock(void);
int set_default_system_config(void);

inline void sechsi_enable_int(int ch, int intr);
inline void sechsi_disable_int(int ch, int intr);
unsigned int sechsi_mipi_read_register(unsigned int off);
unsigned int sechsi_mipi_write_register(unsigned int off, unsigned int val);
unsigned int sechsi_read_register(unsigned int off);
unsigned int sechsi_write_register(unsigned int off, unsigned int val);

unsigned int sechsi_system_config_debug(void);

/* private functions. Let's hide followings later*/
int reset_sechsi_gpio(int enable, int drive);
inline void sechsi_set_bit(unsigned int off, unsigned int n);
inline void sechsi_clear_bit(unsigned int off, unsigned int n);
inline void sechsi_set_masked_value(unsigned int off, unsigned int mask,
	unsigned int val, unsigned int nbit);
inline unsigned int sechsi_test_bit(unsigned int off, unsigned int n);
int sechsi_soft_reset(void);
void sechsi_set_rx_clock_source(unsigned int clksrc);
void sechsi_set_tx_config(int idbit, int mode);
void sechsi_set_rx_config(int idbit, int mode, int dataflow);
inline void sechsi_set_arbiter_priority(int prior);
inline void sechsi_enable_int_err(int ch, int intr);
inline void sechsi_disable_int_err(int ch, int intr);
void sechsi_set_tx_clock(int enable);
void sechsi_set_clock_divider(int div, int enable);
void sechsi_open_tx_channel(unsigned int ch, int fifosize,
	int fifolev);
void sechsi_open_rx_channel(unsigned int ch, int fifosize,
	int fifolev);
void sechsi_set_tx_arbiter(unsigned int ch, int prior,
	unsigned int bw);
int init_platform_driver(void);
inline void sechsi_set_tx_fifo(unsigned int ch, int fifosize,
	int fifolev);
inline void sechsi_set_rx_fifo(unsigned int ch, int fifosize,
	int fifolev);

inline unsigned int sechsi_read_sfr(unsigned int off);
inline void sechsi_write_sfr(unsigned int off, unsigned int val);
inline unsigned int sechsi_get_tx_fifosize(int ch);
inline unsigned int sechsi_get_rx_fifosize(int ch);

#endif
