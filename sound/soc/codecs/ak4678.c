/*
 * ak4678.c - ASoC codec driver for AK4678
 *
 * Copyright 2012, AsahiKASEI Co., Ltd.
 * Copyright 2012, Insignal Co., Ltd.
 * Author: Claude Youn <claude@insignal.co.kr>
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/i2c.h>
#include <linux/platform_device.h>

#include <sound/core.h>
#include <sound/pcm.h>
#include <sound/pcm_params.h>
#include <sound/soc.h>
#include <sound/tlv.h>

#include "ak4678.h"

/* Codec Registers */
#define POWER_MAN0	0x00
#define POWER_MAN1	0x01
#define POWER_MAN2	0x02
#define PLL_MODE_SEL0	0x03
#define PLL_MODE_SEL1	0x04
#define IF_FMT_SEL	0x05
#define MIC_IN_SEL	0x06
#define DAC_PATH_SEL	0x09
#define POWER_MAN_LOUT	0x0A
#define POWER_MAN_HP	0x0B
#define CARGE_PUMP_CTRL	0x0C
#define POWER_MAN_SPK	0x0D
#define LOUT_VOL_CTRL	0x0E
#define HP_VOL_CTRL	0x0F
#define SPKRCV_VOL_CTRL	0x10
#define LEFT_IN_VOL 0x11
#define RIGHT_IN_VOL 0x12
#define MIX_CTRL	0x14
#define MODE_CTRL0	0x17
#define SIDETONE_VOLA 0x1C
#define LEFT_OUT_VOL 0x1D
#define RIGHT_OUT_VOL 0x1E
#define PCMIF_PM	0x1F
#define PCMIF_CON0	0x20
#define PCMIF_CON1	0x21
#define SIDETONE_VOLB 0x22
#define DATT_A_VOL	0x23
#define DATT_B_VOL	0x24
#define MIX_CTRL0	0x25
#define MIX_CTRL1	0x26

static const DECLARE_TLV_DB_MINMAX(mic_gain_amp, -6, 24);
static const DECLARE_TLV_DB_SCALE(rcv_out_vol, -3300, 300, 0);
static const DECLARE_TLV_DB_SCALE(out_vol, -5750, 50, 0);
static const DECLARE_TLV_DB_SCALE(spk_vol, -3300, 300, 0);
static const DECLARE_TLV_DB_SCALE(hp_vol, -7000, 200, 0);
static const DECLARE_TLV_DB_SCALE(lout_vol, -900, 300, 0);
static const DECLARE_TLV_DB_SCALE(side_vol, -2400, 600, 0);

static const char *ak4678_mic_left_in_sel[] = {
	"INL1", "INL2", "INL3", "INL4"
};

static const char *ak4678_mic_right_in_sel[] = {
	"INR1", "INR2", "INR3", "INR4"
};

static const char *ak4678_aif_mix_input[] = {
	"DATT-B", "BIVOL Lch", "BIVOL Rch", "((BIVOL Lch) + (BIVOL Rch)) / 2",
	"(DATT-B) + (BIVOL Lch)", "(DATT-B) + (BIVOL Rch)",
	"(((BIVOL Lch) + (BIVOL Rch) / 2) + (DATT-B)) / 2"
};

static const char *ak4678_srmx_sel[] = {
	"5EQ IN", "MIX1", "5EQ IN + MIX1"
};

static const struct soc_enum ak4678_enum[] = {
SOC_ENUM_SINGLE(MIC_IN_SEL, 0, 4, ak4678_mic_left_in_sel),
SOC_ENUM_SINGLE(MIC_IN_SEL, 2, 4, ak4678_mic_right_in_sel),
SOC_ENUM_SINGLE(MIX_CTRL0, 0, 7, ak4678_aif_mix_input),
SOC_ENUM_SINGLE(MIX_CTRL0, 3, 7, ak4678_aif_mix_input),
SOC_ENUM_SINGLE(MIX_CTRL, 4, 3, ak4678_srmx_sel),
SOC_ENUM_SINGLE(MIX_CTRL, 6, 3, ak4678_srmx_sel),
};

static const struct snd_kcontrol_new ak4678_snd_controls[] = {
SOC_DOUBLE("Master Playback Switch", POWER_MAN1, 2, 3, 1, 0),
SOC_DOUBLE_R_TLV("Master Playback Volume", LEFT_OUT_VOL, RIGHT_OUT_VOL,
			0, 127, 1, out_vol),

SOC_SINGLE("Speaker Playback Switch", POWER_MAN_SPK, 4, 1, 0),
SOC_SINGLE_TLV("Speaker Playback Volume", SPKRCV_VOL_CTRL, 0, 15, 0, spk_vol),

SOC_DOUBLE("HP Playback Switch", POWER_MAN_HP, 0, 1, 1, 0),
SOC_SINGLE_TLV("HP Playback Volume", HP_VOL_CTRL, 0, 38, 0, hp_vol),

SOC_DOUBLE("Line Out Playback Switch", POWER_MAN_LOUT, 0, 1, 1, 0),
SOC_SINGLE_TLV("Line Out Playback Volume", LOUT_VOL_CTRL, 0, 5, 0, lout_vol),

SOC_SINGLE("RCV Playback Switch", POWER_MAN_SPK, 0, 1, 0),
SOC_SINGLE_TLV("RCV Playback Volume", SPKRCV_VOL_CTRL, 4, 15, 0, rcv_out_vol),

SOC_DOUBLE("Mic Capture Switch", POWER_MAN0, 4, 5, 1, 0),
SOC_SINGLE_TLV("Mic Capture Volume", 0x7, 0, 13, 0, mic_gain_amp),

SOC_DOUBLE_TLV("Side Tone Volume A", SIDETONE_VOLA, 0, 4, 5, 1, side_vol),
SOC_SINGLE_TLV("Side Tone Volume B", SIDETONE_VOLB, 0, 5, 1, side_vol),

SOC_SINGLE_TLV("PCMA To AIF Volume", DATT_A_VOL, 0, 127, 1, out_vol),
SOC_SINGLE_TLV("PCMA To PCMB Volume", DATT_B_VOL, 0, 127, 1, out_vol),
};

static const struct snd_kcontrol_new ak4678_left_playback_path[] = {
SOC_DAPM_SINGLE("Left Speaker", DAC_PATH_SEL, 6, 1, 0),
SOC_DAPM_SINGLE("Left RCV", DAC_PATH_SEL, 4, 1, 0),
SOC_DAPM_SINGLE("Left HP", DAC_PATH_SEL, 2, 1, 0),
SOC_DAPM_SINGLE("Left LOUT", DAC_PATH_SEL, 0, 1, 0),
};

static const struct snd_kcontrol_new ak4678_right_playback_path[] = {
SOC_DAPM_SINGLE("Right Speaker", DAC_PATH_SEL, 7, 1, 0),
SOC_DAPM_SINGLE("Right RCV", DAC_PATH_SEL, 5, 1, 0),
SOC_DAPM_SINGLE("Right HP", DAC_PATH_SEL, 3, 1, 0),
SOC_DAPM_SINGLE("Right LOUT", DAC_PATH_SEL, 1, 1, 0),
};

static const struct snd_kcontrol_new ak4678_input_mux[] = {
SOC_DAPM_ENUM("Left Input Source", ak4678_enum[0]),
SOC_DAPM_ENUM("Right Input Source", ak4678_enum[1])
};

static const struct snd_kcontrol_new ak4678_aif_mixer[] = {
SOC_DAPM_ENUM("AIF Mixer", ak4678_enum[2]),
SOC_DAPM_ENUM("AIF Mixer", ak4678_enum[3])
};

static const struct snd_kcontrol_new ak4678_srmx_mixer[] = {
SOC_DAPM_ENUM("SRMX Left Mixer", ak4678_enum[4]),
SOC_DAPM_ENUM("SRMX Right Mixer", ak4678_enum[5])
};

static const struct snd_soc_dapm_widget ak4678_dapm_widgets[] = {
SND_SOC_DAPM_PGA("PMPCMA", PCMIF_PM, 0, 0, NULL, 0),
SND_SOC_DAPM_PGA("PMPCMB", PCMIF_PM, 4, 0, NULL, 0),

SND_SOC_DAPM_PGA("PMSRAI", PCMIF_PM, 1, 0, NULL, 0),
SND_SOC_DAPM_PGA("PMSRAO", PCMIF_PM, 2, 0, NULL, 0),

SND_SOC_DAPM_PGA("PMSRBI", PCMIF_PM, 5, 0, NULL, 0),
SND_SOC_DAPM_PGA("PMSRBO", PCMIF_PM, 6, 0, NULL, 0),

SND_SOC_DAPM_PGA("PMOSC", PCMIF_PM, 3, 0, NULL, 0),
SND_SOC_DAPM_PGA("PMMIX", PCMIF_PM, 7, 0, NULL, 0),

#if 0
SND_SOC_DAPM_MUX("AIF In Left Mixer", SND_SOC_NOPM, 0, 0,
		&ak4678_aif_mixer[0]),
SND_SOC_DAPM_MUX("AIF In Right Mixer", SND_SOC_NOPM, 0, 0,
		&ak4678_aif_mixer[1]),

SND_SOC_DAPM_MUX("SRMX Left Mixer", SND_SOC_NOPM, 0, 0,
		&ak4678_srmx_mixer[0]),
SND_SOC_DAPM_MUX("SRMX Right Mixer", SND_SOC_NOPM, 0, 0,
		&ak4678_srmx_mixer[1]),
#endif

SND_SOC_DAPM_DAC("DAC", "Playback", POWER_MAN0, 0, 0),

SND_SOC_DAPM_PGA("PMDAL", POWER_MAN1, 2, 0, NULL, 0),
SND_SOC_DAPM_PGA("PMDAR", POWER_MAN1, 3, 0, NULL, 0),

SND_SOC_DAPM_PGA("PMEQ", POWER_MAN1, 0, 0, NULL, 0),
SND_SOC_DAPM_PGA("5EQ", MODE_CTRL0, 3, 0, NULL, 0),

SND_SOC_DAPM_MIXER("OUTL Mixer", SND_SOC_NOPM, 0, 0,
		ak4678_left_playback_path,
		ARRAY_SIZE(ak4678_left_playback_path)),
SND_SOC_DAPM_MIXER("OUTR Mixer", SND_SOC_NOPM, 0, 0,
		ak4678_right_playback_path,
		ARRAY_SIZE(ak4678_right_playback_path)),

SND_SOC_DAPM_DAC("Speaker Switch", "Playback", POWER_MAN_SPK, 4, 0),
SND_SOC_DAPM_DAC("Left HP Switch", "Playback", POWER_MAN_HP, 0, 0),
SND_SOC_DAPM_DAC("Right HP Switch", "Playback", POWER_MAN_HP, 1, 0),
SND_SOC_DAPM_DAC("Left LOUT Switch", "Playback", POWER_MAN_LOUT, 0, 0),
SND_SOC_DAPM_DAC("Right LOUT Switch", "Playback", POWER_MAN_LOUT, 1, 0),
SND_SOC_DAPM_DAC("RCV Switch", "Playback", POWER_MAN_SPK, 0, 0),

SND_SOC_DAPM_OUTPUT("OUTR"),
SND_SOC_DAPM_OUTPUT("OUTL"),

SND_SOC_DAPM_ADC("ADC", "Capture", POWER_MAN0, 0, 0),
SND_SOC_DAPM_PGA("PMADL", POWER_MAN0, 4, 0, NULL, 0),
SND_SOC_DAPM_PGA("PMADR", POWER_MAN0, 5, 0, NULL, 0),

SND_SOC_DAPM_MICBIAS("Mic Bias1", POWER_MAN2, 0, 0),
SND_SOC_DAPM_MICBIAS("Mic Bias2", POWER_MAN2, 2, 0),

SND_SOC_DAPM_MUX("Left Capture Source", SND_SOC_NOPM, 0, 0,
		&ak4678_input_mux[0]),
SND_SOC_DAPM_MUX("Right Capture Source", SND_SOC_NOPM, 0, 0,
		&ak4678_input_mux[1]),

SND_SOC_DAPM_INPUT("INL1"),
SND_SOC_DAPM_INPUT("INR1"),

SND_SOC_DAPM_INPUT("INL2"),
SND_SOC_DAPM_INPUT("INR2"),

SND_SOC_DAPM_INPUT("INL3"),
SND_SOC_DAPM_INPUT("INR3"),

SND_SOC_DAPM_INPUT("INL4"),
SND_SOC_DAPM_INPUT("INR4"),
};

static const struct snd_soc_dapm_route ak4678_route_path[] = {
	{"PMPCMA", NULL, "PMSRAI"},
	{"PMPCMB", NULL, "PMSRBI"},

	{"PMSRAI", NULL, "PMMIX"},
	{"PMSRBI", NULL, "PMMIX"},

#if 0
	{"5EQ Left Source", "PFMX", "PFMXL"},
	{"5EQ Left Source", "SVOLA", "SVOLAL"},
	{"5EQ Left Source", "PFMX + SVOLA", "PFMXL"},
	{"5EQ Left Source", "PFMX + SVOLA", "SVOLAL"},

	{"5EQ Right Source", "PFMX", "PFMXR"},
	{"5EQ Right Source", "SVOLA", "SVOLAR"},
	{"5EQ Right Source", "PFMX + SVOLA", "PFMXR"},
	{"5EQ Right Source", "PFMX + SVOLA", "SVOLAR"},

	{"5EQ", NULL, "5EQ Left Source"},
	{"5EQ", NULL, "5EQ Left Source"},
	{"5EQ", NULL, "5EQ Right Source"},
#endif

	{"PMEQ", NULL, "5EQ"},

#if 0
	{"DAC Source", "DATT-A", "PMEQ"},
	{"DAC Source", "DRC", "DRC"},
	{"DAC Source", "SDTI", "SDIT"},
	{"DAC", NULL, "DAC Source"},

	{"PMDAL", NULL, "DAC"},
	{"PMDAR", NULL, "DAC"},
#else
	{"5EQ", NULL, "DAC"},
	{"PMDAL", NULL, "PMEQ"},
	{"PMDAR", NULL, "PMEQ"},
#endif

	{"Left HP Switch", NULL, "PMDAL"},
	{"Right HP Switch", NULL, "PMDAR"},
	{"OUTL Mixer", "Left HP", "Left HP Switch"},
	{"OUTR Mixer", "Right HP", "Right HP Switch"},

	{"Speaker Switch", NULL, "PMDAL"},
	{"Speaker Switch", NULL, "PMDAR"},
	{"OUTL Mixer", "Left Speaker", "Speaker Switch"},
	{"OUTR Mixer", "Right Speaker", "Speaker Switch"},

	{"Left LOUT Switch", NULL, "PMDAL"},
	{"Right LOUT Switch", NULL, "PMDAR"},
	{"OUTL Mixer", "Left LOUT", "Left LOUT Switch"},
	{"OUTR Mixer", "Right LOUT", "Right LOUT Switch"},

	{"RCV Switch", NULL, "PMDAL"},
	{"RCV Switch", NULL, "PMDAR"},
	{"OUTL Mixer", "Left RCV", "RCV Switch"},
	{"OUTR Mixer", "Right RCV", "RCV Switch"},

	{"OUTL", NULL, "OUTL Mixer"},
	{"OUTR", NULL, "OUTR Mixer"},

	{"INL1", NULL, "Mic Bias1"},
	{"INR1", NULL, "Mic Bias1"},
	{"INL2", NULL, "Mic Bias2"},
	{"INR2", NULL, "Mic Bias2"},

	{"Left Capture Source", "INL1", "INL1"},
	{"Left Capture Source", "INL2", "INL2"},
	{"Left Capture Source", "INL3", "INL3"},
	{"Left Capture Source", "INL4", "INL4"},

	{"Right Capture Source", "INR1", "INR1"},
	{"Right Capture Source", "INR2", "INR2"},
	{"Right Capture Source", "INR3", "INR3"},
	{"Right Capture Source", "INR4", "INR4"},

	{"PMADL", NULL, "Left Capture Source"},
	{"PMADR", NULL, "Right Capture Source"},

	{"ADC", NULL, "PMADL"},
	{"ADC", NULL, "PMADR"},
};

static int inline is_pll_master(struct snd_soc_codec *codec)
{
	return (snd_soc_read(codec, PLL_MODE_SEL1) & 0x1);
}

static int inline is_master(struct snd_soc_codec *codec)
{
	return ((snd_soc_read(codec, PLL_MODE_SEL1) & 0x2) >> 1);
}

static struct {
	unsigned int sampling_rate;
	u8 mode;
} pll_mode[] = {
	{ 8000, 0x0 },
	{ 12000, 0x1 },
	{ 16000, 0x2 },
	{ 24000, 0x3 },
	{ 11025, 0x5 },
	{ 22050, 0x7 },
	{ 32000, 0xa },
	{ 48000, 0xb },
	{ 44100, 0xf }
};

static int ak4678_hw_params(struct snd_pcm_substream *substream,
			 struct snd_pcm_hw_params *params,
			 struct snd_soc_dai *dai)
{
	struct snd_soc_pcm_runtime *rtd = substream->private_data;
	int i, ret, sampling_rate = params_rate(params);
	struct snd_soc_codec *codec = rtd->codec;
	u8 sel_mask, sel = -1;

printk("%s:%d\n\n", __func__, __LINE__);

	switch (params_format(params)) {
	case SNDRV_PCM_FORMAT_S16_LE:
	case SNDRV_PCM_FORMAT_S24_LE:
		break;
	default:
		dev_err(codec->dev, "Unsupported PCM format: %d\n",
				params_format(params));
		return -EINVAL;
	}

	sel_mask = 0xff;
	for (i=0; i<ARRAY_SIZE(pll_mode); i++) {
		if (pll_mode[i].sampling_rate == sampling_rate)
			sel = (pll_mode[i].mode << 4);
	}

	if (sel < 0) {
		dev_err(codec->dev, "Unsupported sampling rate: %d\n",
				params_rate(params));
		return -EINVAL;
	}
	ret = snd_soc_update_bits(codec, PLL_MODE_SEL0, sel_mask, sel);
	if (ret < 0)
		return ret;

	if (!is_pll_master(codec)) {
		/* Set CM bit */
		sel_mask = 0x3 << 6;
		switch(sampling_rate) {
		case 8000:
		case 11025:
		case 12000:
		case 16000:
		case 22050:
			sel = 0x1 << 6;
			break;
		case 24000:
		case 32000:
		case 44100:
		case 48000:
			sel = 0x0 << 6;
			break;
		}
		ret = snd_soc_update_bits(codec, PLL_MODE_SEL1, sel_mask, sel);
		if (ret < 0)
			return ret;
	}

	if (is_master(codec)) {
		/* Set BCKO */
		sel_mask = 0x1 << 5;
		switch(sampling_rate) {
		case 48000:
		case 44100:
		case 32000:
		case 24000:
		case 22050:
			/* set 32fs */
			sel = 0x0 << 5;
			break;
		case 16000:
		case 12000:
		case 11025:
		case 8000:
			/* set 64fs */
			sel = 0x1 << 5;
			break;
		}
		ret = snd_soc_update_bits(codec, PLL_MODE_SEL1, sel_mask, sel);
		if (ret < 0)
			return ret;
	} else {
		/* Set BCKI */
		switch(sampling_rate) {
		case 48000:
		case 44100:
		case 32000:
		case 24000:
		case 22050:
			sel = 0x2;
			break;
		case 16000:
		case 12000:
		case 11025:
		case 8000:
			sel = 0x3;
			break;
		}
		ret = snd_soc_update_bits(codec, PLL_MODE_SEL0, 0xf, sel);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int ak4678_set_fmt(struct snd_soc_dai *codec_dai,
			unsigned int fmt)
{
	struct snd_soc_codec *codec = codec_dai->codec;
	u8 sel, sel_mask;
	int ret;

	printk("codec_dai->id:%d\n", codec_dai->id);
	printk("codec->id:%d\n", codec->id);

	sel_mask = 0x3;
	switch(fmt & SND_SOC_DAIFMT_MASTER_MASK) {
	case SND_SOC_DAIFMT_CBM_CFM: /* PLL Master Mode */
		sel = 0x3;
		break;
	case SND_SOC_DAIFMT_CBS_CFM: /* EXT Master Mode */
		sel = 0x2;
		break;
	case SND_SOC_DAIFMT_CBM_CFS: /* PLL Slave Mode */
		sel = 0x1;
		break;
	case SND_SOC_DAIFMT_CBS_CFS: /* EXT Slave Mode */
	default:
		sel = 0x0;
		break;
	}
	ret = snd_soc_update_bits(codec, PLL_MODE_SEL1, sel_mask, sel);
	if (ret < 0)
		return ret;
printk("xxxxxxxxxxxxxxxxx\n");

	sel_mask = 0x3;
	if (codec_dai->id == 0) {
		switch (fmt & SND_SOC_DAIFMT_FORMAT_MASK) {
		case SND_SOC_DAIFMT_I2S:
			sel = 0x3;
			break;
		case SND_SOC_DAIFMT_MSB:
			sel = 0x2;
			break;
		case SND_SOC_DAIFMT_LSB:
			sel = 0x1;
			break;
		case SND_SOC_DAIFMT_DSP_A:
			sel = 0x0;
			break;
		default:
			dev_err(codec->dev, "Format isn't supported by codec!\n");
			return -EINVAL;
		}
		ret = snd_soc_update_bits(codec, IF_FMT_SEL, sel_mask, sel);
		if (ret < 0)
			return ret;
	} else {
		switch (fmt & SND_SOC_DAIFMT_FORMAT_MASK) {
		case SND_SOC_DAIFMT_I2S:
			sel = 0x3;
			break;
		case SND_SOC_DAIFMT_MSB:
			sel = 0x2;
			break;
		case SND_SOC_DAIFMT_LFS:
			sel = 0x1;
			break;
		case SND_SOC_DAIFMT_SFS:
			sel = 0x0;
			break;
		default:
			dev_err(codec->dev, "Format isn't supported by codec!\n");
			return -EINVAL;
		}
		ret = -EINVAL;
		if (codec_dai->id == 1)
			ret = snd_soc_update_bits(codec, PCMIF_CON0, sel_mask, sel);
		else if (codec_dai->id == 2)
			ret = snd_soc_update_bits(codec, PCMIF_CON1, sel_mask, sel);
		if (ret < 0)
			return ret;
	}

printk("xxxxxxxxxxxxxxxxx\n");
	if ((fmt & SND_SOC_DAIFMT_FORMAT_MASK) != SND_SOC_DAIFMT_I2S) {
		switch (fmt & SND_SOC_DAIFMT_INV_MASK) {
		case SND_SOC_DAIFMT_NB_NF:
			sel = 0x0;
			break;
		case SND_SOC_DAIFMT_IB_NF:
			sel = 0x1;
			break;
		case SND_SOC_DAIFMT_NB_IF:
			sel = 0x2;
			break;
		case SND_SOC_DAIFMT_IB_IF:
			sel = 0x3;
			break;
		default:
			return -EINVAL;
		}
		ret = -EINVAL;
		if (codec_dai->id == 0)
			ret = snd_soc_update_bits(codec, IF_FMT_SEL, 0x0C, sel << 2);
		else if (codec_dai->id == 1)
			ret = snd_soc_update_bits(codec, PCMIF_CON0, 0x30, sel << 4);
		else if (codec_dai->id == 2)
			ret = snd_soc_update_bits(codec, PCMIF_CON1, 0x30, sel << 4);
		if (ret < 0)
			return ret;
	}

printk("xxxxxxxxxxxxxxxxx\n");
	return 0;
}

static struct {
	unsigned int freq;
	u8 mode;
} sysclk_table[] = {
	{ 11289600, 0x4 },
	{ 12288000, 0x5 },
	{ 12000000, 0x6 },
	{ 24000000, 0x7 },
	{ 19200000, 0x8 },
	{ 13000000, 0xa },
	{ 26000000, 0xb },
	{ 13500000, 0xc },
	{ 27000000, 0xd },
	{ 25000000, 0xe }
};

static int ak4678_set_sysclk(struct snd_soc_dai *dai, int clk_id,
				unsigned int freq, int dir)
{
	struct snd_soc_codec *codec = dai->codec;
	u8 sel = -1;
	int i, ret;

	if (!is_pll_master(codec))
		return 0;

	for (i=0; i<ARRAY_SIZE(sysclk_table); i++) {
		if(sysclk_table[i].freq == freq) {
			sel = sysclk_table[i].mode;
			break;
		}
	}
	if (sel < 0)
		return -EINVAL;

	ret = snd_soc_update_bits(codec, PLL_MODE_SEL0, 0xf, sel);
	if (ret < 0)
		return ret;

	return 0;
}

static struct snd_soc_dai_ops ak4678_dai_ops = {
	.hw_params = ak4678_hw_params,
	.set_fmt = ak4678_set_fmt,
	.set_sysclk = ak4678_set_sysclk,
};

static struct snd_soc_dai_driver ak4678_dai[] = {
	{
		.name = "ak4678-hifi",
		.id = 0,
		.playback = {
			.stream_name = "Playback",
			.channels_min = 1,
			.channels_max = 2,
			.rates = SNDRV_PCM_RATE_8000_48000,
			.formats = (SNDRV_PCM_FMTBIT_S16_LE |
				SNDRV_PCM_FMTBIT_S24_LE),
		},
		.capture = {
			.stream_name = "Capture",
			.channels_min = 1,
			.channels_max = 2,
			.rates = SNDRV_PCM_RATE_8000_48000,
			.formats = (SNDRV_PCM_FMTBIT_S16_LE |
				SNDRV_PCM_FMTBIT_S24_LE),
		},
		.ops = &ak4678_dai_ops,
	}, {
		.name = "ak4678-pcm-a",
		.id = 1,
		.playback = {
			.stream_name = "Playback",
			.channels_min = 1,
			.channels_max = 1,
			.rates = (SNDRV_PCM_RATE_8000 |
				SNDRV_PCM_RATE_16000),
			.formats = SNDRV_PCM_FMTBIT_S16_LE,
		},
		.capture = {
			.stream_name = "Capture",
			.channels_min = 1,
			.channels_max = 1,
			.rates = (SNDRV_PCM_RATE_8000 |
				SNDRV_PCM_RATE_16000),
			.formats = SNDRV_PCM_FMTBIT_S16_LE,
		},
		.ops = &ak4678_dai_ops,
	}, {
		.name = "ak4678-pcm-b",
		.id = 2,
		.playback = {
			.stream_name = "Playback",
			.channels_min = 1,
			.channels_max = 2,
			.rates = SNDRV_PCM_RATE_8000_48000,
			.formats = SNDRV_PCM_FMTBIT_S16_LE,
		},
		.capture = {
			.stream_name = "Capture",
			.channels_min = 1,
			.channels_max = 2,
			.rates = SNDRV_PCM_RATE_8000_48000,
			.formats = SNDRV_PCM_FMTBIT_S16_LE,
		},
		.ops = &ak4678_dai_ops,
	},
};

static void ak4678_warmup_signal(struct snd_soc_codec *codec)
{
	/* Write default values to warm-up codec */
	snd_soc_write(codec, 0x0, 0x00);
	snd_soc_write(codec, 0x3, 0xf4);
	snd_soc_write(codec, 0x4, 0x22);
	snd_soc_write(codec, 0x5, 0x02);
}

static int ak4678_set_bias_level(struct snd_soc_codec *codec,
				enum snd_soc_bias_level level)
{
	switch(level) {
	case SND_SOC_BIAS_ON:
	case SND_SOC_BIAS_PREPARE:
	case SND_SOC_BIAS_STANDBY:
	case SND_SOC_BIAS_OFF:
		break;
	}
	codec->dapm.bias_level = level;
	return 0;
}

static int ak4678_probe(struct snd_soc_codec *codec)
{
	int ret = 0;

	ret = snd_soc_codec_set_cache_io(codec, 8, 8, SND_SOC_I2C);
	if (ret < 0) {
		dev_err(codec->dev, "Fail to set-up codec I/O: %d\n", ret);
		return ret;
	}

	ak4678_warmup_signal(codec);

	ak4678_set_bias_level(codec, SND_SOC_BIAS_STANDBY);

	return 0;
}

static int ak4678_remove(struct snd_soc_codec *codec)
{
	ak4678_set_bias_level(codec, SND_SOC_BIAS_OFF);

	return 0;
}

static u8 ak4678_def_regs[] = {
	0x00, 0x00, 0x00, 0xf6, 0x00, 0x02, 0x00, 0x55, /* 0x07h */
	0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x03, 0x23, /* 0x0Fh */
	0xbb, 0x91, 0xe1, 0x00, 0x00, 0x00, 0x00, 0x02, /* 0x17h */
	0x43, 0x12, 0x00, 0x00, 0x00, 0x0c, 0x0c, 0x00, /* 0x1Fh */
	0x00, 0x00, 0x00, 0x0c, 0x0c, 0x00, 0x00, 0x00, /* 0x27h */
	0x00, 0xa9, 0x1f, 0xad, 0x20, 0x00, 0x00, 0x00, /* 0x2Fh */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x37h */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x3Fh */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x47h */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x4Fh */
	0x3a, 0x00, 0x74, 0x20, 0x1d, 0x00, 0xbb, 0x3f, /* 0x57h */
	0x3a, 0xe0, 0x73, 0x00, 0x76, 0x3e, 0xe6, 0xe0, /* 0x5Fh */
	0x85, 0x10, 0x89, 0x35, 0x0b, 0xe3, 0x2c, 0x11, /* 0x67h */
	0xa9, 0x3d, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00, /* 0x6Fh */
	0x00, 0x00, 0x11, 0x80, 0x80, 0x00, 0x00, 0x00, /* 0x77h */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x7Fh */
	0x00, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x87h */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x8Fh */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x97h */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0x9Fh */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 0xA7h */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  /* 0xAFh */
};

static struct snd_soc_codec_driver soc_codec_dev_ak4678 = {
	.probe = ak4678_probe,
	.remove = ak4678_remove,
	.set_bias_level = ak4678_set_bias_level,
	.reg_cache_size = ARRAY_SIZE(ak4678_def_regs),
	.reg_word_size = sizeof(u8),
	.reg_cache_default = ak4678_def_regs,
	.dapm_widgets = ak4678_dapm_widgets,
	.num_dapm_widgets = ARRAY_SIZE(ak4678_dapm_widgets),
	.dapm_routes = ak4678_route_path,
	.num_dapm_routes = ARRAY_SIZE(ak4678_route_path),
	.controls = ak4678_snd_controls,
	.num_controls = ARRAY_SIZE(ak4678_snd_controls),
};

int ak4678_hookup_probe(struct device *dev)
{
	int ret;

	ret = snd_soc_register_codec(dev, &soc_codec_dev_ak4678,
			ak4678_dai, ARRAY_SIZE(ak4678_dai));
	if (ret < 0) {
		dev_err(dev, "Fail to register codec driver: %d\n", ret);
		return ret;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(ak4678_hookup_probe);

static int ak4678_i2c_probe(struct i2c_client *i2c,
			    const struct i2c_device_id *id)
{
	//struct ak4678_priv *priv;
	int ret;

#if 0
	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->codec_driver = &soc_codec_dev_ak4678;
	i2c_set_clientdata(i2c, priv);
#endif

	ret = snd_soc_register_codec(&i2c->dev, &soc_codec_dev_ak4678,
			ak4678_dai, ARRAY_SIZE(ak4678_dai));
	if (ret < 0) {
		dev_err(&i2c->dev, "Fail to register codec driver: %d\n", ret);
		return ret;
	}

	return 0;
}

static int ak4678_i2c_remove(struct i2c_client *client)
{
	snd_soc_unregister_codec(&client->dev);
	return 0;
}

static const struct i2c_device_id ak4678_i2c_ids[] = {
	{ "ak4678", 0 },
	{ }
};
MODULE_DEVICE_TABLE(i2c, ak4678_i2c_ids);

static struct i2c_driver ak4678_i2c_driver = {
	.driver = {
		.name = "ak4678-codec",
		.owner = THIS_MODULE,
	},
	.probe = ak4678_i2c_probe,
	.remove = ak4678_i2c_remove,
	.id_table = ak4678_i2c_ids,
};

static int __init ak4678_modinit(void)
{
	int ret = 0;

printk("alksdjal;sdjas;lkdj;aslkdj;a\n\n\n\n\n\n\n\n");

	/* Add Codec I2C Channel */
	ret = i2c_add_driver(&ak4678_i2c_driver);
	if (ret != 0)
		pr_err("Failed to register AK4678 I2C driver: %d\n", ret);

	return ret;
}
module_init(ak4678_modinit);

static void __exit ak4678_exit(void)
{
	i2c_del_driver(&ak4678_i2c_driver);
}
module_exit(ak4678_exit);

MODULE_DESCRIPTION("ASoC AK4678 driver");
MODULE_AUTHOR("Claude <claude@insignal.co.kr>");
MODULE_LICENSE("GPL");
