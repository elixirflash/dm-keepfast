/* sound/soc/samsung/audss.c
 *
 * ALSA SoC Audio Layer - Samsung Audio Subsystem driver
 *
 * Copyright (c) 2010 Samsung Electronics Co. Ltd.
 *	Lakkyung Jung <lakkyung.jung@samsung.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/clk.h>
#include <linux/io.h>
#include <linux/pm_runtime.h>

#include <sound/soc.h>
#include <sound/pcm_params.h>

#include <plat/audio.h>
#include <plat/clock.h>
#include <plat/cpu.h>
#include <mach/map.h>
#include <mach/regs-audss.h>

#include "audss.h"
#include "srp_alp/srp_alp.h"

static struct audss_runtime_data {
	struct platform_device *pdev;
	struct clk *mout_audss;
	struct clk *dout_srp;
	struct clk *srp_clk;
	struct clk *bus_clk;
	struct clk *i2s_clk;

	char	*rclksrc;
	u32	clk_src_rate;
	u32	suspend_audss_clksrc;
	u32	suspend_audss_clkdiv;
	u32	suspend_audss_clkgate;

	bool	clk_enabled;
	bool	reg_saved;
	bool	pd_ctl_enable;
} audss;

static char *rclksrc[] = {
	[0] = "busclk",
	[1] = "i2sclk",
};

static DEFINE_MUTEX(audss_mutex);

bool audss_clken_stat(void)
{
	return audss.clk_enabled;
}

static void audss_pm_runtime_ctl(bool enabled)
{
	if (!audss.pd_ctl_enable)
		return;

	enabled ? pm_runtime_get_sync(&audss.pdev->dev)
		: pm_runtime_put_sync(&audss.pdev->dev);
}

static int audss_clk_div_init(struct clk *src_clk)
{
	struct clk *fout_epll;
	u32 src_clk_rate = 0;
	u64 srp_rate = 0;
	u64 bus_rate = 0;
	u64 i2s_rate = 0;
	u32 srp_div = 1;
	u32 bus_div = 2;
	u32 i2s_div = 2;
	u32 ret = -1;

	fout_epll = clk_get(NULL, "fout_epll");
	if (IS_ERR(fout_epll)) {
		pr_err("%s: failed to get fout_epll\n", __func__);
		return ret;
	}
	clk_set_parent(audss.mout_audss, fout_epll);

	pr_debug("%s: CLKSRC[0x%x]\n", __func__, readl(S5P_CLKSRC_AUDSS));

	src_clk_rate = clk_get_rate(src_clk);
	if (!src_clk_rate) {
		pr_err("%s: Can't get current clk_rate %d\n",
			__func__, src_clk_rate);
		return ret;
	}

	pr_debug("%s: SRC Clock Rate[%d]\n", __func__, src_clk_rate);

	if (src_clk_rate > 100000000) {
		srp_div <<= 1;
		bus_div <<= 1;
		i2s_div <<= 1;
	}

	if (!strcmp(audss.rclksrc, "busclk"))
		i2s_div = 16;			/* Use max div */

	srp_rate = src_clk_rate >> (srp_div - 1);
	bus_rate = src_clk_rate >> (bus_div - 1);
	i2s_rate = src_clk_rate >> (i2s_div - 1);

	if (srp_rate != src_clk_rate)
		clk_set_rate(audss.dout_srp, srp_rate);

	if (bus_rate != src_clk_rate)
		clk_set_rate(audss.bus_clk, bus_rate);

	if (i2s_rate != src_clk_rate)
		clk_set_rate(audss.i2s_clk, i2s_rate);

	pr_debug("%s: CLKDIV[0x%x]\n", __func__, readl(S5P_CLKDIV_AUDSS));
	pr_debug("%s: SRPCLK[%ld]\n", __func__, clk_get_rate(audss.srp_clk));
	pr_debug("%s: BUSCLK[%ld]\n", __func__, clk_get_rate(audss.bus_clk));
	pr_debug("%s: I2SCLK[%ld]\n", __func__, clk_get_rate(audss.i2s_clk));

	clk_disable(audss.srp_clk);
	clk_disable(audss.bus_clk);
	if (!strcmp(audss.rclksrc, "i2sclk"))
		clk_disable(audss.i2s_clk);

	pr_debug("%s: CLKGATE[0x%x]\n", __func__, readl(S5P_CLKGATE_AUDSS));

	clk_put(fout_epll);

	return 0;
}

void audss_reg_save(void)
{
	if (audss.reg_saved)
		return;

	audss.suspend_audss_clksrc = readl(S5P_CLKSRC_AUDSS);
	audss.suspend_audss_clkdiv = readl(S5P_CLKDIV_AUDSS);
	audss.suspend_audss_clkgate = readl(S5P_CLKGATE_AUDSS);
	audss.reg_saved = true;

	pr_debug("%s: Successfully saved audss reg\n", __func__);
	pr_debug("%s: SRC[0x%x], DIV[0x%x], GATE[0x%x]\n", __func__,
					audss.suspend_audss_clksrc,
					audss.suspend_audss_clkdiv,
					audss.suspend_audss_clkgate);
}

void audss_reg_restore(void)
{
	if (!audss.reg_saved)
		return;

	writel(audss.suspend_audss_clksrc, S5P_CLKSRC_AUDSS);
	writel(audss.suspend_audss_clkdiv, S5P_CLKDIV_AUDSS);
	writel(audss.suspend_audss_clkgate, S5P_CLKGATE_AUDSS);
	audss.reg_saved = false;

	pr_debug("%s: Successfully restored audss reg\n", __func__);
	pr_debug("%s: SRC[0x%x], DIV[0x%x], GATE[0x%x]\n", __func__,
					audss.suspend_audss_clksrc,
					audss.suspend_audss_clkdiv,
					audss.suspend_audss_clkgate);
}

void audss_clk_enable(bool enable)
{
	mutex_lock(&audss_mutex);

	if (audss.clk_enabled == enable) {
		pr_debug("%s: Already set audss clk %d\n",
				__func__, audss.clk_enabled);
		mutex_unlock(&audss_mutex);
		return;
	}

	if (enable) {
		audss_pm_runtime_ctl(true);
		audss_reg_restore();
		clk_enable(audss.srp_clk);
		clk_enable(audss.bus_clk);
		if (!strcmp(audss.rclksrc, "i2sclk"))
			clk_enable(audss.i2s_clk);
#ifdef CONFIG_SND_SAMSUNG_ALP
		if (soc_is_exynos5250() && audss.pd_ctl_enable)
			srp_post_reset();
#endif
	} else {
#ifdef CONFIG_SND_SAMSUNG_ALP
		if (soc_is_exynos5250() && audss.pd_ctl_enable)
			srp_prepare_suspend();
#endif

		clk_disable(audss.bus_clk);
		clk_disable(audss.srp_clk);
		if (!strcmp(audss.rclksrc, "i2sclk"))
			clk_disable(audss.i2s_clk);
		audss_reg_save();
		audss_pm_runtime_ctl(false);
	}

	audss.clk_enabled = enable;
	mutex_unlock(&audss_mutex);
	return;
}

void audss_suspend(void)
{
	if (!audss.reg_saved)
		audss_reg_save();
}

void audss_resume(void)
{
	if (audss.reg_saved)
		audss_reg_restore();
}

static int audss_init(void)
{
	int ret = 0;

	audss.mout_audss = clk_get(NULL, "mout_audss");
	if (IS_ERR(audss.mout_audss)) {
		pr_err("%s: failed to get mout audss\n", __func__);
		ret = PTR_ERR(audss.mout_audss);
		return ret;
	}

	audss.dout_srp = clk_get(NULL, "dout_srp");
	if (IS_ERR(audss.dout_srp)) {
		pr_err("%s: failed to get dout_srp\n", __func__);
		ret = PTR_ERR(audss.dout_srp);
		goto err1;
	}

	audss.srp_clk = clk_get(NULL, "srpclk");
	if (IS_ERR(audss.srp_clk)) {
		pr_err("%s:failed to get srp_clk\n", __func__);
		ret = PTR_ERR(audss.srp_clk);
		goto err2;
	}

	audss.bus_clk = clk_get(NULL, "busclk");
	if (IS_ERR(audss.bus_clk)) {
		pr_err("%s: failed to get bus clk\n", __func__);
		ret = PTR_ERR(audss.bus_clk);
		goto err3;
	}

	audss.i2s_clk = clk_get(NULL, "i2sclk");
	if (IS_ERR(audss.i2s_clk)) {
		pr_err("%s: failed to get i2s clk\n", __func__);
		ret = PTR_ERR(audss.i2s_clk);
		goto err4;
	}

	audss.rclksrc = rclksrc[BUSCLK];
	pr_debug("%s: RCLK SRC[%s]\n", __func__, audss.rclksrc);

	audss.reg_saved = false;
	audss.clk_enabled = false;
	audss_pm_runtime_ctl(true);

	clk_enable(audss.srp_clk);
	clk_enable(audss.bus_clk);
	if (!strcmp(audss.rclksrc, "i2sclk"))
		clk_enable(audss.i2s_clk);

	ret = audss_clk_div_init(audss.mout_audss);
	if (ret < 0) {
		pr_err("%s: failed to init clk div\n", __func__);
		goto err5;
	}

#ifndef CONFIG_SND_SAMSUNG_RUNTIME_PM
	audss.pd_ctl_enable = false;
#endif

	audss_reg_save();
	audss_pm_runtime_ctl(false);

	return ret;
err5:
	clk_put(audss.i2s_clk);
err4:
	clk_put(audss.bus_clk);
err3:
	clk_put(audss.srp_clk);
err2:
	clk_put(audss.dout_srp);
err1:
	clk_put(audss.mout_audss);

	return ret;
}

static int audss_deinit(void)
{
	clk_put(audss.i2s_clk);
	clk_put(audss.bus_clk);
	clk_put(audss.srp_clk);
	clk_put(audss.dout_srp);
	clk_put(audss.mout_audss);

	audss.rclksrc = NULL;

	return 0;
}

static char banner[] __initdata = "Samsung Audio Subsystem Driver, (c) 2011 Samsung Electronics";

int __init samsung_audss_init(struct platform_device *pdev)
{
	int ret = 0;

	pr_info("%s\n", banner);

#ifdef CONFIG_PM_RUNTIME
	audss.pdev = pdev;
	audss.pd_ctl_enable = soc_is_exynos5250() ? true : false;

	if (audss.pd_ctl_enable) {
		pr_debug("%s: Enabled runtime PM for audss\n", __func__);
		pm_runtime_enable(&audss.pdev->dev);
	}
#endif

	ret = audss_init();
	if (ret < 0)
		pr_err("%s:failed to init audss clock\n", __func__);

	return ret;
}

void samsung_audss_exit(void)
{
	audss_deinit();

#ifdef CONFIG_PM_RUNTIME
	if (audss.pd_ctl_enable) {
		pr_debug("%s: Disabled runtime PM for audio subsystem\n", __func__);
		pm_runtime_disable(&audss.pdev->dev);
		audss.pd_ctl_enable = false;
	}
#endif
}

/* Module information */
MODULE_AUTHOR("Lakkyung Jung, <lakkyung.jung@samsung.com>");
MODULE_DESCRIPTION("Samsung Audio subsystem Interface");
MODULE_ALIAS("platform:samsung-audss");
MODULE_LICENSE("GPL");
