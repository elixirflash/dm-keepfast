/* linux/drivers/misc/hsi/hsi_memory.c
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

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/types.h>

#include "hsi_memory.h"

#define DEFAULT_MEM_INFO_COUNT		1024

#define HSI_MEMINFO_ENTRY(item) do { \
	*(item).filename = '\0'; \
	(item).line = -1; \
	(item).free = 1; \
	(item).ptr = NULL; \
	} while (0);

struct hsi_malloc_info {
	void *ptr;
	char filename[128];
	int line;
	int free;
};

int g_meminfo_num;
int g_alloc_count;
int g_alloc_index;
struct hsi_malloc_info *g_mem_info;

/** for initializing memory */
void hsi_memory_init(void)
{
	int i;
	g_meminfo_num = DEFAULT_MEM_INFO_COUNT;
	g_mem_info = kmalloc(
			sizeof(struct hsi_malloc_info) * g_meminfo_num,
			GFP_ATOMIC);
	g_alloc_index = 0;
	for (i = 0; i < g_meminfo_num; ++i)
		HSI_MEMINFO_ENTRY(g_mem_info[i]);
}

/** for allocating memory */
unsigned char *hsi_alloc_bytes_debug(int size, int dma, char *file, int line)
{
	int i, n;
	struct hsi_malloc_info *temp;
	if (g_alloc_count >= g_meminfo_num) {
		n = g_meminfo_num << 1;
		if (dma)
			temp = kmalloc(
				sizeof(struct hsi_malloc_info) * n, GFP_DMA);
		else
			temp = kmalloc(
				sizeof(struct hsi_malloc_info) * n, GFP_ATOMIC);
		memcpy(temp, g_mem_info,
			sizeof(struct hsi_malloc_info) * g_meminfo_num);
		for (i = g_meminfo_num; i < n; ++i)
			HSI_MEMINFO_ENTRY(temp[i]);
		kfree(g_mem_info);
		g_mem_info = temp;
		g_meminfo_num = n;
	}
	while (!g_mem_info[g_alloc_index].free)
		g_alloc_index = (g_alloc_index+1) % g_meminfo_num;

	strcpy(g_mem_info[g_alloc_index].filename, file);
	g_mem_info[g_alloc_index].line = line;
	g_mem_info[g_alloc_index].free = 0;
	if (dma)
		g_mem_info[g_alloc_index].ptr = kmalloc(size, GFP_DMA);
	else
		g_mem_info[g_alloc_index].ptr = kmalloc(size, GFP_ATOMIC);
	++g_alloc_count;
	return g_mem_info[g_alloc_index].ptr;
}

/** linear search version. This SHOULD BE improved. */
int hsi_mem_find_index(void *p)
{
	int i;
	for (i = 0; i < g_meminfo_num; ++i) {
		if (g_mem_info[i].free == 0 && g_mem_info[i].ptr == p)
			return i;
	}
	return -1;
}

int hsi_bytes_free(unsigned char *p)
{
	int i;
	i = hsi_mem_find_index(p);
	if (i == -1) {
		printk(KERN_ERR "[MIPI-HSI] It's already freed or wroong pointer\n");
		return -1;
	}
	g_mem_info[i].free = 1;
	kfree(p);
	g_alloc_count--;
	return 0;
}

void hsi_mem_info(void)
{
	int i;

	printk(KERN_ERR "[MIPI-HSI] Memory space : %d\n",
		g_meminfo_num);
	printk(KERN_ERR "[MIPI-HSI] Memory allocation count : %d\n",
		g_alloc_count);
	printk(KERN_ERR "[MIPI-HSI] Memory allocation index : %d\n",
		g_alloc_index);
	for (i = 0; i < g_meminfo_num; ++i) {
		if (!g_mem_info[i].free) {
			printk(KERN_ERR "[MIPI-HSI] Memory 0x%08X was not freed - %s(%d)\n",
				(unsigned int)g_mem_info[i].ptr,
				g_mem_info[i].filename,
				g_mem_info[i].line);
		}
	}
}

