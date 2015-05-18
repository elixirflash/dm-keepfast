/* linux/drivers/misc/hsi/hsi_driver_int.c
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
#include <linux/completion.h>
#include <asm/irq.h>

#include "hsi_driver_int.h"
#include "hsi_driver_tran.h"
#include "hsi_driver.h"
#include "hsi_debug.h"

int hsi_interrupt_init(struct platform_device *pdev)
{
	int res;
	struct resource *irq;

	/*  registration for irq */
	irq = platform_get_resource(pdev, IORESOURCE_IRQ, 0);
	if (!irq) {
		printk(KERN_ERR "Cannot get irq handle for HSI");
		return -ENXIO;
	}

	/* g_hsi_ctrl.irq_handle = SECHSI_COMBINER_IRQ(12, 1); */
	g_hsi_ctrl.irq_handle = irq->start;
	res = request_irq(g_hsi_ctrl.irq_handle,
		sechsi_interrupt_service_handler,
		IRQF_SHARED,
		"SECHSI", (void *)&g_hsi_ctrl);


	return 0;
}

extern struct hsi_request g_tx_reqs[EXYNOS_HSI_DMACHNUM];
extern struct hsi_request g_rx_reqs[EXYNOS_HSI_DMACHNUM];

#define PIO_TX_REFILL_EVENT(bitn) \
	if (intstat_field.bit##bitn) { \
		complete(&g_tx_reqs[(bitn)].req.pio.wait); \
		intstat_field.bit##bitn = 0; \
		maskval &= ~(0x00000001<<(bitn)); \
	}

#define SDMA_COMPLETED(bitn) \
	if (intstat_field.bit##bitn) { \
		intstat_field.bit##bitn = 0; \
		maskval &= ~(0x00000001<<(bitn)); \
	}



irqreturn_t sechsi_interrupt_service_handler (int irq, void *p_param)
{
	unsigned int maskval;
	unsigned int intstat;
	struct sechsi_bit_field intstat_field;

	maskval = sechsi_read_sfr(HSI_INT_SIG_EN);
	/*  mask backup */
	sechsi_write_sfr(HSI_INT_SIG_EN, 0x00000000);

	intstat = sechsi_read_sfr(HSI_INT_STAT);
	intstat_field = *(struct sechsi_bit_field *)&intstat;
	if (intstat_field.bit31) {
		unsigned int errstatus;
		errstatus = sechsi_read_sfr(HSI_ERR_INT_STAT);
		/*  clear error restore */
		sechsi_write_sfr(HSI_ERR_INT_STAT, errstatus);
		SECHSI_DEBUG("Error interrupt: err status 0x%08X",
			errstatus);
		intstat_field.bit31 = 0;
	}
	if (intstat_field.bit16) {
		SECHSI_WAKEUP_RX();
		SECHSI_DEBUG("Wakeup interrupt");
		intstat_field.bit16 = 0;
	}
	PIO_TX_REFILL_EVENT(0)
	PIO_TX_REFILL_EVENT(1)
	PIO_TX_REFILL_EVENT(2)
	PIO_TX_REFILL_EVENT(3)
	PIO_TX_REFILL_EVENT(4)
	PIO_TX_REFILL_EVENT(5)
	PIO_TX_REFILL_EVENT(6)
	PIO_TX_REFILL_EVENT(7)
	SDMA_COMPLETED(17)
	SDMA_COMPLETED(18)
	SDMA_COMPLETED(19)
	SDMA_COMPLETED(20)
	SDMA_COMPLETED(21)
	SDMA_COMPLETED(22)
	SDMA_COMPLETED(23)
	SDMA_COMPLETED(24)
	if (*(unsigned int *)&intstat_field != 0) {
		SECHSI_DEBUG("Other interrupt: 0x%08X",
			*(unsigned int *)&intstat_field);
	}
	sechsi_write_sfr(HSI_INT_STAT, intstat); /*  mask restore */

	sechsi_write_sfr(HSI_INT_SIG_EN, maskval); /*  mask restore */
	return IRQ_HANDLED;
}


