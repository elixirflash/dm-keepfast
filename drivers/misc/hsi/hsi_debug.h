/* linux/drivers/misc/hsi/hsi_debug.h
 *
 * Copyright 2012 Samsung Electronics Co.Ltd.
 *      Donggyun, ko <donggyun.ko@samsung.com>
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
*/
#ifndef __HSI_DEBUG_HEADER__
#define __HSI_DEBUG_HEADER__

/*#define SECHSI_RELEASE_DEVICE_DRIVER*/

extern int g_sechsi_debug_level;

#ifndef SECHSI_RELEASE_DEVICE_DRIVER

#define SECHSI_ERROR(s, ...) if (g_sechsi_debug_level)\
	printk(KERN_ERR "[ERROR] " s , ##__VA_ARGS__)
#define SECHSI_DEBUG(s, ...) if (g_sechsi_debug_level)\
	printk(KERN_ERR "[DEBUG] " s , ##__VA_ARGS__)
#define SECHSI_OK(s, ...)    if (g_sechsi_debug_level)\
	printk(KERN_ERR "[OK] " s , ##__VA_ARGS__)

#else

#define SECHSI_ERROR(s, ...)
#define SECHSI_DEBUG(s, ...)
#define SECHSI_OK(s, ...)

#endif

void sechsi_set_debug_level(int lev);

#endif
