/*
 * linux/arch/arm/mach-exynos/include/mach/hs-iic.h
 *
 * Copyright (C) 2012 Samsung Electronics Co., Ltd.
 *
 * HS-I2C Controller platform_device info
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#ifndef __ASM_ARCH_HS_IIC_H
#define __ASM_ARCH_HS_IIC_H __FILE__

struct exynos5_platform_i2c {
	int bus_number;
	void (*cfg_gpio)(struct platform_device *dev);
};

extern void exynos5_hs_i2c0_set_platdata(struct exynos5_platform_i2c *i2c);
extern void exynos5_hs_i2c1_set_platdata(struct exynos5_platform_i2c *i2c);
extern void exynos5_hs_i2c2_set_platdata(struct exynos5_platform_i2c *i2c);
extern void exynos5_hs_i2c3_set_platdata(struct exynos5_platform_i2c *i2c);
extern void exynos5_hs_i2c0_cfg_gpio(struct platform_device *dev);
extern void exynos5_hs_i2c1_cfg_gpio(struct platform_device *dev);
extern void exynos5_hs_i2c2_cfg_gpio(struct platform_device *dev);
extern void exynos5_hs_i2c3_cfg_gpio(struct platform_device *dev);

extern struct exynos5_platform_i2c default_hs_i2c_data;

#endif /* __ASM_ARCH_HS_IIC_H */
