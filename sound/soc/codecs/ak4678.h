/*
 * ak4678.h - ASoC codec driver for AK4678
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

#ifndef __AK4678_H__
#define __AK4678_H__

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/platform_device.h>

#include <sound/core.h>
#include <sound/pcm.h>
#include <sound/pcm_params.h>
#include <sound/soc.h>

#ifndef SND_SOC_DAIFMT_SFS
#	define SND_SOC_DAIFMT_SFS	7
#	define SND_SOC_DAIFMT_LFS	8
#endif

struct ak4678_priv {
	struct snd_soc_codec *codec;
	struct snd_soc_dai *codec_dai;
	int num_of_dai;
	struct snd_soc_codec_driver *codec_driver;
};

int ak4678_hookup_probe(struct device *dev);

#endif
