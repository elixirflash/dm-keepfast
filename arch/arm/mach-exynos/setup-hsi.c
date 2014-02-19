/* linux/arch/arm/mach-exynos/setup-hsi.c
 *
 * Copyright (c) 2011 Samsung Electronics Co., Ltd.
 *		http:// www.samsung.com/
 *
 * EXYNOS4&5 - Helper functions for setting up HSI device(s) GPIO
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/io.h>
#include <linux/delay.h>

#include <mach/gpio.h>
#include <mach/map.h>
#include <mach/regs-clock.h>
#include <mach/hsi.h>
#include <plat/gpio-cfg.h>
#include <plat/cpu.h>

void exynos4_hsi_cfg_gpio(int enable, int drive)
{
	int i;

	printk(KERN_ERR "Setting up for mipi-hsi for exynos4");

	/* SET GPIO configuration */
	if (enable) {
		s3c_gpio_cfgrange_nopull(EXYNOS4_GPY4(0), 8, S3C_GPIO_SFN(4));
		for (i = 0; i < 8; i++)
			s5p_gpio_set_drvstr(EXYNOS4_GPY4(i), S5P_GPIO_DRVSTR_LV4 );
	} else {
		s3c_gpio_cfgrange_nopull(EXYNOS4_GPY4(0), 8, S3C_GPIO_SFN(0));
		for (i = 0; i < 8; i++)
			s5p_gpio_set_drvstr(EXYNOS4_GPY4(i), S5P_GPIO_DRVSTR_LV2 );
	}
}

void exynos5_hsi_cfg_gpio(int enable, int drive)
{
	int i;

	printk(KERN_ERR "Setting up for mipi-hsi for exynos5");

	/* SET GPIO configuration */
	if (enable) {
		s3c_gpio_cfgrange_nopull(EXYNOS5_GPY4(0), 8, S3C_GPIO_SFN(3));
		for (i = 0; i < 8; i++)
			s5p_gpio_set_drvstr(EXYNOS5_GPY4(i), S5P_GPIO_DRVSTR_LV4 );
	} else {
		s3c_gpio_cfgrange_nopull(EXYNOS5_GPY4(0), 8, S3C_GPIO_SFN(0));
		for (i = 0; i < 8; i++)
			s5p_gpio_set_drvstr(EXYNOS5_GPY4(i), S5P_GPIO_DRVSTR_LV2 );
	}
}

/**
* setup_sechsi_system_clock - for setting up MCLK as 200MHz,
* and enabling clock source */
int exynos4_hsi_setup_clock(void)
{
	unsigned int addr, clk;
	addr = (unsigned int)ioremap_nocache(0x1003C000, 0x1000);
	writel(0x00300000, addr+0x0540);
	clk = readl(addr+0x0240);
	writel(clk & 0xFEFFFFFF, addr+0x0240);
	iounmap((void *)addr);

	return 0;
}

/**
 * setup_sechsi_system_clock - for setting up MCLK as 200MHz, and enabling clock source */
int exynos5_hsi_setup_clock(void)
{
	unsigned int addr;
	addr = (unsigned int)ioremap_nocache(0x10020000, 0x1000);
	writel(0x30000000, addr+0x0514); /*  CLK_DIV_TOP1 set div to 4 */
	iounmap((void *)addr);

	return 0;
}


void exynos_hsi_cfg_gpio(int enable, int drive)
{
	if (soc_is_exynos4212() || soc_is_exynos4412()) {
		exynos4_hsi_cfg_gpio(enable, drive);
		exynos4_hsi_setup_clock();
	} else if (soc_is_exynos5250()) {
		exynos5_hsi_cfg_gpio(enable, drive);
		exynos5_hsi_setup_clock();
	}
}
