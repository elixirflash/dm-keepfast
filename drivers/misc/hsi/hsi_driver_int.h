/* linux/drivers/misc/hsi/hsi_driver_int.h
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

#ifndef __HSI_ISR_HEADER_FILE__
#define __HSI_ISR_HEADER_FILE__

irqreturn_t sechsi_interrupt_service_handler(int irq, void *p_param);
int hsi_interrupt_init(struct platform_device *pdev);

#endif
