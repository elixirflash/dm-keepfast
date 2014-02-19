/* linux/arch/arm/mach-exynos/asv-5250.c
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com/
 *
 * EXYNOS5250 - ASV(Adaptive Supply Voltage) driver
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#include <linux/init.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/clk.h>
#include <linux/io.h>
#include <linux/string.h>

#include <mach/asv.h>
#include <mach/map.h>

#include <plat/cpu.h>

/* ASV function for Fused Chip */
#define IDS_ARM_OFFSET		24
#define IDS_ARM_MASK		0xFF
#define HPM_OFFSET		12
#define HPM_MASK		0x1F

#define FUSED_SG_OFFSET		3
#define ORIG_SG_OFFSET		17
#define ORIG_SG_MASK		0xF
#define MOD_SG_OFFSET		21
#define MOD_SG_MASK		0x7

#define DEFAULT_ASV_GROUP	1

#define CHIP_ID_REG		(S5P_VA_CHIPID + 0x4)
#define LOT_ID_REG		(S5P_VA_CHIPID + 0x14)

/* Original ASV table has 10 level */
struct asv_judge_table exynos5250_limit_orig[] = {
	/* HPM, IDS */
	{ 0, 0},		/* Reserved Group */
	{ 9, 7},
	{ 10, 9},
	{ 12, 11},
	{ 14, 14},
	{ 15, 17},
	{ 16, 20},
	{ 17, 23},
	{ 18, 27},
	{ 19, 30},
	{ 100, 100},
	{ 999, 999},		/* Reserved Group */
};

/* New ASV table has 12 level */
struct asv_judge_table exynos5250_limit[] = {
	/* HPM, IDS */
	{ 6, 7},
	{ 8, 9},
	{ 9, 10},
	{ 10, 11},
	{ 12, 13},
	{ 13, 15},
	{ 14, 17},
	{ 16, 21},
	{ 17, 25},
	{ 19, 32},
	{ 20, 39},
	{ 100, 100},
	{ 999, 999},		/* Reserved Group */
};

struct asv_judge_table exynos5250_mif_limit[] = {
	/* HPM, LOCK */
	{ 0, 0},		/* Reserved Group */
	{ 12, 100},
	{ 15, 112},
	{ 100, 512},
};

static int exynos5250_get_hpm(struct samsung_asv *asv_info)
{
	asv_info->hpm_result = (asv_info->pkg_id >> HPM_OFFSET) & HPM_MASK;

	return 0;
}

static int exynos5250_get_ids(struct samsung_asv *asv_info)
{
	asv_info->ids_result = (asv_info->pkg_id >> IDS_ARM_OFFSET) & IDS_ARM_MASK;

	return 0;
}

char *special_lot_id_list[] = {
	"NZVPU",
	"NZVR7",
};

/*
 * If lot id is "NZVPU", it is need to modify for ARM_IDS value
 */
static int exynos5250_check_lot_id(struct samsung_asv *asv_info)
{
	unsigned int lid_reg = 0;
	unsigned int rev_lid = 0;
	unsigned int i;
	unsigned int tmp;
	unsigned int wno;
	char lot_id[5];

	lid_reg = __raw_readl(LOT_ID_REG);

	for (i = 0; i < 32; i++) {
		tmp = (lid_reg >> i) & 0x1;
		rev_lid += tmp << (31 - i);
	}

	wno = (rev_lid >> 6) & 0x1f;

	lot_id[0] = 'N';
	lid_reg = (rev_lid >> 11) & 0x1FFFFF;

	for (i = 4; i >= 1; i--) {
		tmp = lid_reg % 36;
		lid_reg /= 36;
		lot_id[i] = (tmp < 10) ? (tmp + '0') : ((tmp - 10) + 'A');
	}

	/* NZVPU lot is incorrect ids value  */
	if ((!strncmp(lot_id, "NZVPU", ARRAY_SIZE(lot_id)))) {
		pr_info("Exynos5250 : Lot ID is %s\n", lot_id);
		exynos_lot_is_nzvpu = true;

		if (wno >= 2 && wno <= 6)
			asv_info->ids_result -= 16;

		return 0;
	}

	for (i = 0; i < ARRAY_SIZE(special_lot_id_list); i++) {
		if (!strncmp(lot_id, special_lot_id_list[i], ARRAY_SIZE(lot_id))) {
			pr_info("Exynos5250 : Lot ID is %s\n", lot_id);
			return 0;
		}
	}

	return -EINVAL;
}

static void exynos5250_pre_set_abb(void)
{
	if (!exynos_lot_id) {
		switch (exynos_result_of_asv) {
		case 0:
		case 1:
			exynos4x12_set_abb_member(ABB_ARM, ABB_MODE_080V);
			exynos4x12_set_abb_member(ABB_INT, ABB_MODE_080V);
			exynos4x12_set_abb_member(ABB_G3D, ABB_MODE_080V);
			break;
		default:
			exynos4x12_set_abb_member(ABB_ARM, ABB_MODE_BYPASS);
			exynos4x12_set_abb_member(ABB_INT, ABB_MODE_BYPASS);
			exynos4x12_set_abb_member(ABB_G3D, ABB_MODE_BYPASS);
			break;
		}

		exynos4x12_set_abb_member(ABB_MIF, ABB_MODE_130V);
	} else {
		switch (exynos_result_of_asv) {
		case 0:
		case 1:
		case 2:
			exynos4x12_set_abb(ABB_MODE_080V);
			break;
		case 3:
		case 4:
			exynos4x12_set_abb(ABB_MODE_BYPASS);
			break;
		default:
			exynos4x12_set_abb(ABB_MODE_130V);
			break;
		}
	}
}

static int exynos5250_asv_store_result(struct samsung_asv *asv_info)
{
	unsigned int i;

	if (!exynos5250_check_lot_id(asv_info))
		exynos_lot_id = true;

	if (soc_is_exynos5250()) {
		/* New ASV table */
		if (!exynos_lot_id) {
			for (i = 0; i < ARRAY_SIZE(exynos5250_limit); i++) {
				if ((asv_info->ids_result <= exynos5250_limit[i].ids_limit) ||
				    (asv_info->hpm_result <= exynos5250_limit[i].hpm_limit)) {
					exynos_result_of_asv = i;
					break;
				}
			}
			for (i = 0; i < ARRAY_SIZE(exynos5250_mif_limit); i++) {
				if (asv_info->hpm_result <= exynos5250_mif_limit[i].hpm_limit) {
					exynos_result_mif_asv = i;
					break;
				}
			}
		/* Original ASV table */
		} else {
			for (i = 0; i < ARRAY_SIZE(exynos5250_limit_orig); i++) {
				if ((asv_info->ids_result <= exynos5250_limit_orig[i].ids_limit) ||
				    (asv_info->hpm_result <= exynos5250_limit_orig[i].hpm_limit)) {
					exynos_result_of_asv = i;
					exynos_result_mif_asv = i;
					break;
				}
			}
		}
	}
	/*
	 * If ASV result value is lower than default value
	 * Fix with default value.
	 */
	if (exynos_result_of_asv < DEFAULT_ASV_GROUP)
		exynos_result_of_asv = DEFAULT_ASV_GROUP;

	pr_info("EXYNOS5250(NO SG): IDS : %d HPM : %d RESULT : %d MIF : %d\n",
		asv_info->ids_result, asv_info->hpm_result, exynos_result_of_asv,
		exynos_result_mif_asv);

	exynos5250_pre_set_abb();

	return 0;
}

int exynos5250_asv_init(struct samsung_asv *asv_info)
{
	unsigned int tmp;
	unsigned int exynos_orig_sp;
	unsigned int exynos_mod_sp;
	int exynos_cal_asv;

	exynos_result_of_asv = 0;
	exynos_lot_id = false;
	exynos_lot_is_nzvpu = false;

	pr_info("EXYNOS5250: Adaptive Support Voltage init\n");

	tmp = __raw_readl(CHIP_ID_REG);

	/* Store PKG_ID */
	asv_info->pkg_id = tmp;

	/* If Speed group is fused, get speed group from */
	if ((tmp >> FUSED_SG_OFFSET) & 0x1) {
		exynos_orig_sp = (tmp >> ORIG_SG_OFFSET) & ORIG_SG_MASK;
		exynos_mod_sp = (tmp >> MOD_SG_OFFSET) & MOD_SG_MASK;

		exynos_cal_asv = exynos_orig_sp - exynos_mod_sp;
		/*
		 * If There is no origin speed group,
		 * store 1 asv group into exynos_result_of_asv.
		 */
		if (!exynos_orig_sp) {
			pr_info("EXYNOS5250: No Origin speed Group\n");
			exynos_result_of_asv = DEFAULT_ASV_GROUP;
		} else {
			if (exynos_cal_asv < DEFAULT_ASV_GROUP)
				exynos_result_of_asv = DEFAULT_ASV_GROUP;
			else
				exynos_result_of_asv = exynos_cal_asv;
		}

		pr_info("EXYNOS5250(SG):  ORIG : %d MOD : %d RESULT : %d\n",
			exynos_orig_sp, exynos_mod_sp, exynos_result_of_asv);

		return -EEXIST;
	}

	asv_info->get_ids = exynos5250_get_ids;
	asv_info->get_hpm = exynos5250_get_hpm;
	asv_info->store_result = exynos5250_asv_store_result;

	return 0;
}
