/* s2mps11-pmic.h
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#ifndef __LINUX_MFD_S2MPS11_PMIC_H
#define __LINUX_MFD_S2MPS11_PMIC_H

#include <linux/regulator/machine.h>

/* S2MPS11 regulator ids */
enum s2mps11_regulators {
	S2MPS11_LDO1,
	S2MPS11_LDO2,
	S2MPS11_LDO3,
	S2MPS11_LDO4,
	S2MPS11_LDO5,
	S2MPS11_LDO6,
	S2MPS11_LDO7,
	S2MPS11_LDO8,
	S2MPS11_LDO9,
	S2MPS11_LDO10,
	S2MPS11_LDO11,
	S2MPS11_LDO12,
	S2MPS11_LDO13,
	S2MPS11_LDO14,
	S2MPS11_LDO15,
	S2MPS11_LDO16,
	S2MPS11_LDO17,
	S2MPS11_LDO18,
	S2MPS11_LDO19,
	S2MPS11_LDO20,
	S2MPS11_LDO21,
	S2MPS11_LDO22,
	S2MPS11_LDO23,
	S2MPS11_LDO24,
	S2MPS11_LDO25,
	S2MPS11_LDO26,
	S2MPS11_LDO27,
	S2MPS11_LDO28,
	S2MPS11_LDO29,
	S2MPS11_LDO30,
	S2MPS11_LDO31,
	S2MPS11_LDO32,
	S2MPS11_LDO33,
	S2MPS11_LDO34,
	S2MPS11_LDO35,
	S2MPS11_LDO36,
	S2MPS11_LDO37,
	S2MPS11_LDO38,
	S2MPS11_BUCK1,
	S2MPS11_BUCK2,
	S2MPS11_BUCK3,
	S2MPS11_BUCK4,
	S2MPS11_BUCK5,
	S2MPS11_BUCK6,
	S2MPS11_BUCK7,
	S2MPS11_BUCK8,
	S2MPS11_BUCK9,
	S2MPS11_BUCK10,
	S2MPS11_AP_EN32KHZ,
	S2MPS11_CP_EN32KHZ,
	S2MPS11_BT_EN32KHZ,

	S2MPS11_REG_MAX,
};

#define S2MPS11_PMIC_EN_SHIFT	6

/**
 * s2mps11_regulator_data - regulator data
 * @id: regulator id
 * @initdata: regulator init data (contraints, supplies, ...)
 */
struct s2mps11_regulator_data {
	int				id;
	struct regulator_init_data	*initdata;
};

struct s2mps11_opmode_data {
	int id;
	int mode;
};

enum s2mps11_opmode {
	S2MPS11_OPMODE_NORMAL,
	S2MPS11_OPMODE_LP,
	S2MPS11_OPMODE_STANDBY,
};

#endif /*  __LINUX_MFD_S2MPS11_PMIC_H */
