/* linux/arch/arm/mach-exynos/dev-hsi.c
 *
 * Copyright 2012 Samsung Electronics Co., Ltd.
 *	Donggyun, ko <donggyun.ko@samsung.com>
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
*/
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/spinlock.h>
#include <linux/platform_device.h>
#include <linux/dma-mapping.h>
#include <mach/dma.h>
#include <mach/irqs.h>
#include <mach/map.h>
#include <mach/hsi.h>


static struct resource exynos_mipihsi_resource[] = {
	[0] = {
		.start = DMACH_MIPI_HSI0,
		.end   = DMACH_MIPI_HSI0,
		.flags = IORESOURCE_DMA,
	},
	[1] = {
		.start = DMACH_MIPI_HSI1,
		.end   = DMACH_MIPI_HSI1,
		.flags = IORESOURCE_DMA,
	},
	[2] = {
		.start = DMACH_MIPI_HSI2,
		.end   = DMACH_MIPI_HSI2,
		.flags = IORESOURCE_DMA,
	},
	[3] = {
		.start = DMACH_MIPI_HSI3,
		.end   = DMACH_MIPI_HSI3,
		.flags = IORESOURCE_DMA,
	},
	[4] = {
		.start = DMACH_MIPI_HSI4,
		.end   = DMACH_MIPI_HSI4,
		.flags = IORESOURCE_DMA,
	},
	[5] = {
		.start = DMACH_MIPI_HSI5,
		.end   = DMACH_MIPI_HSI5,
		.flags = IORESOURCE_DMA,
	},
	[6] = {
		.start = DMACH_MIPI_HSI6,
		.end   = DMACH_MIPI_HSI6,
		.flags = IORESOURCE_DMA,
	},
	[7] = {
		.start = DMACH_MIPI_HSI7,
		.end   = DMACH_MIPI_HSI7,
		.flags = IORESOURCE_DMA,
	},
	[8] = {
		.start = EXYNOS_PA_MIPIHSI,
		.end   = EXYNOS_PA_MIPIHSI  + 0x100 - 1,
		.flags = IORESOURCE_MEM,
	},
	[9] = {
		.start = IRQ_MIPI_HSI,
		.end   = IRQ_MIPI_HSI,
		.flags = IORESOURCE_IRQ,
	},
};

struct platform_device exynos_device_hsi = {
	.name = "exynos_hsi",
	.id = -1,
	.num_resources = ARRAY_SIZE(exynos_mipihsi_resource),
	.resource = exynos_mipihsi_resource,
};

void __init exynos_hsi_set_platdata(struct exynos_hsi_platdata *pd)
{
	struct exynos_hsi_platdata *npd = pd;

	if (!npd->setup_gpio)
		npd->setup_gpio = exynos_hsi_cfg_gpio;
	exynos_device_hsi.dev.platform_data = npd;
}
