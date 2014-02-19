/* sound/soc/samsung/audss.h
 *
 * ALSA SoC Audio Layer - Samsung Audio Subsystem driver
 *
 * Copyright (c) 2011 Samsung Electronics Co. Ltd.
 *	Lakkyung Jung <lakkyung.jung@samsung.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __SND_SOC_SAMSUNG_AUDSS_H
#define __SND_SOC_SAMSUNG_AUDSS_H

enum {
	BUSCLK,
	I2SCLK,
};

void audss_clk_enable(bool enable);
bool audss_clken_stat(void);
void audss_suspend(void);
void audss_resume(void);

extern int samsung_audss_init(struct platform_device *pdev);
extern void samsung_audss_exit(void);
#endif /* __SND_SOC_SAMSUNG_AUDSS_H */
