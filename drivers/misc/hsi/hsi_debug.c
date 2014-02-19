/* linux/drivers/misc/hsi/hsi_debug.c
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

#include "hsi_debug.h"

#ifndef SECHSI_RELEASE_DEVICE_DRIVER
int g_sechsi_debug_level = 1;
#else
int g_sechsi_debug_level;
#endif

void sechsi_set_debug_level(int lev)
{
	g_sechsi_debug_level = lev;
}


