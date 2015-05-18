/*
 *  arndale_wm8994.c
 *
 *  This program is free software; you can redistribute  it and/or modify it
 *  under  the terms of  the GNU General  Public License as published by the
 *  Free Software Foundation;  either version 2 of the  License, or (at your
 *  option) any later version.
 */

#include <linux/platform_device.h>
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/io.h>

#include <sound/soc.h>
#include <sound/soc-dapm.h>
#include <sound/pcm.h>
#include <sound/pcm_params.h>

#include <mach/regs-clock.h>

#include "i2s.h"
#include "../codecs/wm8994.h"

 /* From smdk_wm8994.c
  * Configure audio route as :-
  * $ amixer sset 'DAC1' on,on
  * $ amixer sset 'Right Headphone Mux' 'DAC'
  * $ amixer sset 'Left Headphone Mux' 'DAC'
  * $ amixer sset 'DAC1R Mixer AIF1.1' on
  * $ amixer sset 'DAC1L Mixer AIF1.1' on
  * $ amixer sset 'IN2L' on
  * $ amixer sset 'IN2L PGA IN2LN' on
  * $ amixer sset 'MIXINL IN2L' on
  * $ amixer sset 'AIF1ADC1L Mixer ADC/DMIC' on
  * $ amixer sset 'IN2R' on
  * $ amixer sset 'IN2R PGA IN2RN' on
  * $ amixer sset 'MIXINR IN2R' on
  * $ amixer sset 'AIF1ADC1R Mixer ADC/DMIC' on
  */

#define WM8994_FREQ 24000000

/*
 * exynos5_pmu_xclkout_set(1, 0x11);
 * XXTI = 0x10
 */
static void set_mclk(int enable)
{
	unsigned int reg, xclk_src = 0x10;

	reg = __raw_readl(S5P_PMU_DEBUG);
	reg &= ~(0xf << 8);
	reg |= (xclk_src << 8);
	__raw_writel(reg, S5P_PMU_DEBUG);

	mdelay(1);
}

static int arndale_hw_params(struct snd_pcm_substream *substream,
	struct snd_pcm_hw_params *params)
{
	struct snd_soc_pcm_runtime *rtd = substream->private_data;
	struct snd_soc_dai *cpu_dai = rtd->cpu_dai;
	struct snd_soc_dai *codec_dai = rtd->codec_dai;
	unsigned int pll_out;
	int ret;

	/* AIF1CLK should be >=3MHz for optimal performance */
	if (params_format(params) == SNDRV_PCM_FORMAT_S24_LE)
		pll_out = params_rate(params) * 384;
	else if (params_rate(params) == 8000 || params_rate(params) == 11025)
		pll_out = params_rate(params) * 512;
	else
		pll_out = params_rate(params) * 256;

	ret = snd_soc_dai_set_fmt(codec_dai, SND_SOC_DAIFMT_I2S
					 | SND_SOC_DAIFMT_NB_NF
					 | SND_SOC_DAIFMT_CBM_CFM);
	if (ret < 0)
		return ret;

	ret = snd_soc_dai_set_fmt(cpu_dai, SND_SOC_DAIFMT_I2S
					 | SND_SOC_DAIFMT_NB_NF
					 | SND_SOC_DAIFMT_CBM_CFM);
	if (ret < 0)
		return ret;

	set_mclk(1);

	ret = snd_soc_dai_set_pll(codec_dai, WM8994_FLL1, WM8994_FLL_SRC_MCLK1,
					WM8994_FREQ, pll_out);
	if (ret < 0)
		return ret;

	ret = snd_soc_dai_set_sysclk(codec_dai, WM8994_SYSCLK_FLL1,
					pll_out, SND_SOC_CLOCK_IN);
	if (ret < 0)
		return ret;

	set_mclk(0);

	ret = snd_soc_dai_set_sysclk(cpu_dai, SAMSUNG_I2S_OPCLK,
					0, MOD_OPCLK_PCLK);
	if (ret < 0)
		return ret;

	return 0;
}

static struct snd_soc_ops arndale_ops = {
	.hw_params = arndale_hw_params,
};

static struct snd_soc_dai_link arndale_dai[] = {
	{
		.name = "WM8994 AIF1",
		.stream_name = "Pri_Dai",
		.cpu_dai_name = "samsung-i2s.0",
		.codec_dai_name = "wm8994-aif1",
		.platform_name = "samsung-audio",
		.codec_name = "wm8994-codec",
		.ops = &arndale_ops,
	},
};

static struct snd_soc_card arndale = {
	.name = "Arndale",
	.dai_link = arndale_dai,
	.num_links = ARRAY_SIZE(arndale_dai),
};

static struct platform_device *arndale_snd_device;

static int __init arndale_audio_init(void)
{
	int ret;

	arndale_snd_device = platform_device_alloc("soc-audio", -1);
	if (!arndale_snd_device)
		return -ENOMEM;

	platform_set_drvdata(arndale_snd_device, &arndale);

	ret = platform_device_add(arndale_snd_device);
	if (ret)
		platform_device_put(arndale_snd_device);

	return ret;
}
module_init(arndale_audio_init);

static void __exit arndale_audio_exit(void)
{
	platform_device_unregister(arndale_snd_device);
}
module_exit(arndale_audio_exit);

MODULE_DESCRIPTION("ALSA SoC Arndale board with WM1811A");
MODULE_LICENSE("GPL");
