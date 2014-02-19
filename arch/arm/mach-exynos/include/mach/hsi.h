/* arch/arm/mach-exynos/include/mach/hsi.h
 *
 * Copyright 2012 Samsung Electronics Co., Ltd
 *	Donggyun, ko <donggyun.ko@samsung.com>
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
*/
#ifndef __ASM_PLAT_HSI_H
#define __ASM_PLAT_HSI_H __FILE__

struct exynos_hsi_platdata {
	void (*setup_gpio)(int enable, int strength);
};

void exynos_hsi_set_platdata(struct exynos_hsi_platdata *pd);
extern void exynos_hsi_cfg_gpio(int enable, int strength);
#endif /*__ASM_PLAT_HSI_H */
