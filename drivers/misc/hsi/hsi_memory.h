/* linux/drivers/misc/hsi/hsi_memory.h
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

#ifndef __HSI_MEMORY_HEADER_FILE__
#define __HSI_MEMORY_HEADER_FILE__

#define ALLOC_BYTES(size)	hsi_alloc_bytes_debug(\
	size, 0, __FILE__, __LINE__)
#define ALLOC_DMA_BYTES(size)	hsi_alloc_bytes_debug(\
	size, 1, __FILE__, __LINE__)
#define FREE_BYTES(p)	hsi_bytes_free(p)

unsigned char *hsi_alloc_bytes_debug(int size, int dma, char *file, int line);
int hsi_bytes_free(unsigned char *p);
void hsi_mem_info(void);
void hsi_memory_init(void);

#endif
