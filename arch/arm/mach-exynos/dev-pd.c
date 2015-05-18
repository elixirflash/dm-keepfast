/* linux/arch/arm/mach-exynos/dev-pd.c
 *
 * Copyright (c) 2010-2011 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 *
 * EXYNOS4 - Power Domain support
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/delay.h>

#include <mach/regs-pmu.h>
#include <mach/regs-pmu5.h>
#include <mach/regs-clock.h>

#include <plat/cpu.h>
#include <plat/pd.h>
#include <plat/bts.h>
#include <plat/map-base.h>

int exynos_pd_init(struct device *dev)
{
	struct samsung_pd_info *pdata =  dev->platform_data;
	struct exynos_pd_data *data = (struct exynos_pd_data *) pdata->data;

	if (soc_is_exynos4210() && data->read_phy_addr) {
		data->read_base = ioremap(data->read_phy_addr, SZ_4K);
		if (!data->read_base)
			return -ENOMEM;
	}

	return 0;
}

int exynos_pd_enable(struct device *dev)
{
	struct samsung_pd_info *pdata =  dev->platform_data;
	struct exynos_pd_data *data = (struct exynos_pd_data *) pdata->data;
	u32 timeout;
	u32 tmp = 0;

	/*  save IP clock gating register */
	if (data->clk_base) {
		tmp = __raw_readl(data->clk_base);

		/*  enable all the clocks of IPs in the power domain */
		__raw_writel(0xffffffff, data->clk_base);
	}

	__raw_writel(S5P_INT_LOCAL_PWR_EN, pdata->base);

	/* Wait max 1ms */
	timeout = 1000;
	while ((__raw_readl(pdata->base + 0x4) & S5P_INT_LOCAL_PWR_EN)
		!= S5P_INT_LOCAL_PWR_EN) {
		if (timeout == 0) {
			printk(KERN_ERR "Power domain %s enable failed.\n",
				dev_name(dev));
			return -ETIMEDOUT;
		}
		timeout--;
		udelay(1);
	}

	if (soc_is_exynos5250() && pdata->base == EXYNOS5_MAU_CONFIGURATION)
		__raw_writel(0x10000000, EXYNOS5_PAD_RETENTION_MAU_OPTION);

	if (data->read_base)
		/* dummy read to check the completion of power-on sequence */
		__raw_readl(data->read_base);

	/* restore IP clock gating register */
	if (data->clk_base)
		__raw_writel(tmp, data->clk_base);

	bts_enable(pdata->id);
	return 0;
}

int exynos_pd_disable(struct device *dev)
{
	struct samsung_pd_info *pdata =  dev->platform_data;
	struct exynos_pd_data *data = (struct exynos_pd_data *) pdata->data;
	u32 timeout;
	u32 tmp = 0;
	u32 tmp_pd = 0;
	u32 tmp_clk = 0;
	u32 cfg;

	/*  save clock source register */
	if (data->clksrc_base)
		tmp = __raw_readl(data->clksrc_base);

	if (soc_is_exynos5250() &&
		(samsung_rev() < EXYNOS5250_REV_1_0) &&
		(pdata->base == EXYNOS5_ISP_CONFIGURATION))
		return 0;

	/* Do not disable MFC power domain for EXYNOS5250 EVT0 */
	if (soc_is_exynos5250() &&
		(samsung_rev() < EXYNOS5250_REV_1_0) &&
		(pdata->base == EXYNOS5_MFC_CONFIGURATION))
		return 0;

	/*
	 * To ISP power domain off,
	 * first, ISP_ARM power domain be off.
	 */
	if (soc_is_exynos5250() &&
		(samsung_rev() < EXYNOS5250_REV_1_0) &&
		(pdata->base == EXYNOS5_ISP_CONFIGURATION)) {
		if (!(__raw_readl(EXYNOS5_ISP_ARM_STATUS) & 0x1)) {
			/* Disable ISP_ARM */
			timeout = __raw_readl(EXYNOS5_ISP_ARM_OPTION);
			timeout &= ~EXYNOS5_ISP_ARM_ENABLE;
			__raw_writel(timeout, EXYNOS5_ISP_ARM_OPTION);

			/* ISP_ARM power off */
			__raw_writel(0x0, EXYNOS5_ISP_ARM_CONFIGURATION);

			timeout = 1000;

			while (__raw_readl(EXYNOS5_ISP_ARM_STATUS) & 0x1) {
				if (timeout == 0) {
					printk(KERN_ERR "ISP_ARM power domain can not off\n");
					return -ETIMEDOUT;
				}
				timeout--;
				udelay(1);
			}
			/* CMU_RESET_ISP_ARM off */
			__raw_writel(0x0, EXYNOS5_CMU_RESET_ISP_SYS_PWR_REG);
		}
	}

	if (soc_is_exynos5250() && pdata->base == EXYNOS5_MAU_CONFIGURATION) {
		__raw_writel(0, EXYNOS5_CMU_CLKSTOP_MAU_SYS_PWR_REG);
		__raw_writel(0, EXYNOS5_CMU_RESET_MAU_SYS_PWR_REG);
		__raw_writel(0, EXYNOS5_PAD_RETENTION_MAU_SYS_PWR_REG);
	} else if (soc_is_exynos5250() && pdata->base == EXYNOS5_ISP_CONFIGURATION)
		__raw_writel(0x0, EXYNOS5_CMU_RESET_ISP_SYS_PWR_REG);

	if (soc_is_exynos5250_rev1 &&
			(pdata->base == EXYNOS5_DISP1_CONFIGURATION)) {
		/* GSCL clocks must be enabled
		   before GSCBLK pixelAsync FIFO s/w reset */
		tmp_pd =  __raw_readl(EXYNOS5_GSCL_CONFIGURATION);
		__raw_writel(7, EXYNOS5_GSCL_CONFIGURATION);
		tmp_clk = __raw_readl(EXYNOS5_CLKGATE_IP_GSCL);
		cfg = tmp_clk | 0xF;
		__raw_writel(cfg, EXYNOS5_CLKGATE_IP_GSCL);

		/* GSCBLK Pixel asyncy FIFO S/W reset sequence
		   set PXLASYNC_SW_RESET to 0 then,
		   set PXLASYNC_SW_RESET to 1 again */
		cfg = __raw_readl(S3C_VA_SYS + 0x0220);
		cfg &= ~(0xf);
		__raw_writel(cfg, S3C_VA_SYS + 0x0220);
		cfg |= (0xf);
		__raw_writel(cfg, S3C_VA_SYS + 0x0220);

		/* restore to the original state */
		__raw_writel(tmp_clk, EXYNOS5_CLKGATE_IP_GSCL);
		__raw_writel(tmp_pd, EXYNOS5_GSCL_CONFIGURATION);
	} else if (soc_is_exynos5250_rev1 &&
			(pdata->base == EXYNOS5_GSCL_CONFIGURATION)) {
		/* FIMD or Mixer clocks must be enabled
		   before DISPBL1 FIFO s/w reset */
		tmp_pd =  __raw_readl(EXYNOS5_DISP1_CONFIGURATION);
		__raw_writel(7, EXYNOS5_DISP1_CONFIGURATION);
		tmp_clk = __raw_readl(EXYNOS5_CLKGATE_IP_DISP1);
		cfg = tmp_clk | 0x21;
		__raw_writel(cfg, EXYNOS5_CLKGATE_IP_DISP1);

		/* DISPBLK1 FIFO S/W reset sequence
		   set FIFORST_DISP1 as 0 then, set FIFORST_DISP1 as 1 again */
		cfg = __raw_readl(S3C_VA_SYS + 0x0214);
		cfg &= ~(1 << 23);
		__raw_writel(cfg, S3C_VA_SYS + 0x0214);
		cfg |= (1 << 23);
		__raw_writel(cfg, S3C_VA_SYS + 0x0214);

		/* restore to the original state */
		__raw_writel(tmp_clk, EXYNOS5_CLKGATE_IP_DISP1);
		__raw_writel(tmp_pd, EXYNOS5_DISP1_CONFIGURATION);
	}

	__raw_writel(0, pdata->base);

	/* Wait max 1ms */
	timeout = 1000;
	while (__raw_readl(pdata->base + 0x4) & S5P_INT_LOCAL_PWR_EN) {
		if (timeout == 0) {
			printk(KERN_ERR "Power domain %s disable failed.\n",
				dev_name(dev));
			return -ETIMEDOUT;
		}
		timeout--;
		udelay(1);
	}

	/* restore clock source register */
	if (data->clksrc_base)
		__raw_writel(tmp, data->clksrc_base);
	return 0;
}
