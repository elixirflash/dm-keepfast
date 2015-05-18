/*
 * linux/arch/arm/mach-exynos/setup-hs-i2c1.c
 *
 * Copyright (C) 2012 Samsung Electronics Co., Ltd.
 *
 * HS-I2C1 GPIO configuration.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#include <linux/gpio.h>
#include <plat/gpio-cfg.h>
#include <plat/cpu.h>

void exynos5_hs_i2c1_cfg_gpio(struct platform_device *dev)
{
	s3c_gpio_cfgall_range(EXYNOS5_GPB3(2), 2,
			S3C_GPIO_SFN(4), S3C_GPIO_PULL_UP);
}
