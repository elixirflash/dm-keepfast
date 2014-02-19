/* linux/arch/arm/mach-exynos/bts.c
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/platform_device.h>
#include <linux/dma-mapping.h>

#include <plat/devs.h>
#include <plat/irqs.h>
#include <plat/cpu.h>
#include <plat/bts.h>

#include <mach/map.h>
#include <mach/irqs.h>
#include <mach/map-exynos5.h>

static struct resource exynos_bts_cpu_resource[] = {
	[0] = {
		.start  = EXYNOS5_PA_BTS_CPU,
		.end    = EXYNOS5_PA_BTS_CPU + SZ_1K,
		.flags = IORESOURCE_MEM,
	},
};

static struct resource exynos_bts_jpeg_resource[] = {
	[0] = {
		.start  = EXYNOS5_PA_BTS_JPEG,
		.end    = EXYNOS5_PA_BTS_JPEG + SZ_1K,
		.flags = IORESOURCE_MEM,
	},
};

static struct resource exynos_bts_mdma1_resource[] = {
	[0] = {
		.start  = EXYNOS5_PA_BTS_MDMA1,
		.end    = EXYNOS5_PA_BTS_MDMA1 + SZ_1K,
		.flags = IORESOURCE_MEM,
	},
};

static struct resource exynos_bts_rotator_resource[] = {
	[0] = {
		.start  = EXYNOS5_PA_BTS_ROTATOR,
		.end    = EXYNOS5_PA_BTS_ROTATOR + SZ_1K,
		.flags = IORESOURCE_MEM,
	},
};

static struct resource exynos_bts_gscl0_resource[] = {
	[0] = {
		.start  = EXYNOS5_PA_BTS_GSCL0,
		.end    = EXYNOS5_PA_BTS_GSCL0 + SZ_1K,
		.flags = IORESOURCE_MEM,
	},
};

static struct resource exynos_bts_gscl1_resource[] = {
	[0] = {
		.start  = EXYNOS5_PA_BTS_GSCL1,
		.end    = EXYNOS5_PA_BTS_GSCL1 + SZ_1K,
		.flags = IORESOURCE_MEM,
	},
};

static struct resource exynos_bts_gscl2_resource[] = {
	[0] = {
		.start  = EXYNOS5_PA_BTS_GSCL2,
		.end    = EXYNOS5_PA_BTS_GSCL2 + SZ_1K,
		.flags = IORESOURCE_MEM,
	},
};

static struct resource exynos_bts_gscl3_resource[] = {
	[0] = {
		.start  = EXYNOS5_PA_BTS_GSCL3,
		.end    = EXYNOS5_PA_BTS_GSCL3 + SZ_1K,
		.flags = IORESOURCE_MEM,
	},
};

static struct resource exynos_bts_mfc_resource[] = {
	[0] = {
		.start  = EXYNOS5_PA_BTS_MFC0,
		.end    = EXYNOS5_PA_BTS_MFC0 + SZ_1K,
		.flags = IORESOURCE_MEM,
	},
	[1] = {
		.start  = EXYNOS5_PA_BTS_MFC1,
		.end    = EXYNOS5_PA_BTS_MFC1 + SZ_1K,
		.flags = IORESOURCE_MEM,
	},
};

static struct resource exynos_bts_g3dacp_resource[] = {
	[0] = {
		.start  = EXYNOS5_PA_BTS_G3D_ACP,
		.end    = EXYNOS5_PA_BTS_G3D_ACP + SZ_1K,
		.flags = IORESOURCE_MEM,
	},
};

#if defined(CONFIG_EXYNOS4_DEV_FIMC_IS)
static struct resource exynos_bts_isp0_resource[] = {
	[0] = {
		.start  = EXYNOS5_PA_BTS_FIMC_ISP,
		.end    = EXYNOS5_PA_BTS_FIMC_ISP + SZ_1K,
		.flags = IORESOURCE_MEM,
	},
	[1] = {
		.start  = EXYNOS5_PA_BTS_FIMC_FD,
		.end    = EXYNOS5_PA_BTS_FIMC_FD + SZ_1K,
		.flags = IORESOURCE_MEM,
	},
	[2] = {
		.start  = EXYNOS5_PA_BTS_FIMC_SCALER_C,
		.end    = EXYNOS5_PA_BTS_FIMC_SCALER_C + SZ_1K,
		.flags = IORESOURCE_MEM,
	},
	[3] = {
		.start  = EXYNOS5_PA_BTS_FIMC_SCALER_P,
		.end    = EXYNOS5_PA_BTS_FIMC_SCALER_P + SZ_1K,
		.flags = IORESOURCE_MEM,
	},
};

static struct resource exynos_bts_isp1_resource[] = {
	[0] = {
		.start  = EXYNOS5_PA_BTS_FIMC_ODC,
		.end    = EXYNOS5_PA_BTS_FIMC_ODC + SZ_1K,
		.flags = IORESOURCE_MEM,
	},
	[1] = {
		.start  = EXYNOS5_PA_BTS_FIMC_DIS0,
		.end    = EXYNOS5_PA_BTS_FIMC_DIS0 + SZ_1K,
		.flags = IORESOURCE_MEM,
	},
	[2] = {
		.start  = EXYNOS5_PA_BTS_FIMC_DIS1,
		.end    = EXYNOS5_PA_BTS_FIMC_DIS1 + SZ_1K,
		.flags = IORESOURCE_MEM,
	},
	[3] = {
		.start  = EXYNOS5_PA_BTS_FIMC_3DNR,
		.end    = EXYNOS5_PA_BTS_FIMC_3DNR + SZ_1K,
		.flags = IORESOURCE_MEM,
	},
};
#endif

static struct resource exynos_bts_disp_resource[] = {
	[0] = {
		.start  = EXYNOS5_PA_BTS_DISP10,
		.end    = EXYNOS5_PA_BTS_DISP10 + SZ_1K,
		.flags = IORESOURCE_MEM,
	},
	[1] = {
		.start  = EXYNOS5_PA_BTS_DISP11,
		.end    = EXYNOS5_PA_BTS_DISP11 + SZ_1K,
		.flags = IORESOURCE_MEM,
	},
};

static struct resource exynos_bts_tv_resource[] = {
	[0] = {
		.start  = EXYNOS5_PA_BTS_TV0,
		.end    = EXYNOS5_PA_BTS_TV0 + SZ_1K,
		.flags = IORESOURCE_MEM,
	},
	[1] = {
		.start  = EXYNOS5_PA_BTS_TV1,
		.end    = EXYNOS5_PA_BTS_TV1 + SZ_1K,
		.flags = IORESOURCE_MEM,
	},
};

#if defined(CONFIG_EXYNOS_C2C)
static struct resource exynos_bts_c2c_resource[] = {
	[0] = {
		.start  = EXYNOS5_PA_BTS_C2C,
		.end    = EXYNOS5_PA_BTS_C2C + SZ_1K,
		.flags = IORESOURCE_MEM,
	},
};
#endif

struct exynos_fbm_resource fbm_res[] = {
	{
		.fbm_group = BTS_FBM_G1_R,
		.priority = BTS_BE,
		.base = EXYNOS5_PA_FBM_DDR_R1,
	}, {
		.fbm_group = BTS_FBM_G1_L,
		.priority = BTS_HARDTIME,
		.base = EXYNOS5_PA_FBM_DDR_R0,
	}
};

struct exynos_fbm_pdata fbm_pdata = {
	.res = fbm_res,
	.res_num = ARRAY_SIZE(fbm_res),
};

#define EXYNOS_BTS_PDATA(_name, _id, _prio, _block, _clkname, _changable, _act)\
static struct exynos_bts_pdata bts_##_name##_res = {			\
		.id = _id,						\
		.def_priority = _prio,					\
		.pd_block = _block,					\
		.clk_name = _clkname,					\
		.fbm = &fbm_pdata,					\
		.res_num = ARRAY_SIZE(exynos_bts_##_name##_resource),	\
		.changable_prior = _changable,	\
		.change_act = _act,	\
}

EXYNOS_BTS_PDATA(cpu, BTS_CPU, BTS_BE, PD_TOP, NULL, 1, BTS_ACT_NONE);
EXYNOS_BTS_PDATA(jpeg, BTS_JPEG, BTS_BE, PD_GSCL, "jpeg", 0, BTS_ACT_NONE);
EXYNOS_BTS_PDATA(mdma1, BTS_MDMA1, BTS_BE, PD_TOP, "pdma", 0, BTS_ACT_NONE);
EXYNOS_BTS_PDATA(rotator, BTS_ROTATOR, BTS_BE, PD_DISP1, "rotator", 1, BTS_ACT_NONE);
EXYNOS_BTS_PDATA(gscl0, BTS_GSCL, BTS_BE, PD_GSCL, "gscl", 0, BTS_ACT_OFF);
EXYNOS_BTS_PDATA(gscl1, BTS_GSCL, BTS_BE, PD_GSCL, "gscl", 0, BTS_ACT_OFF);
EXYNOS_BTS_PDATA(gscl2, BTS_GSCL, BTS_BE, PD_GSCL, "gscl", 0, BTS_ACT_OFF);
EXYNOS_BTS_PDATA(gscl3, BTS_GSCL, BTS_BE, PD_GSCL, "gscl", 0, BTS_ACT_OFF);
EXYNOS_BTS_PDATA(mfc, BTS_MFC, BTS_BE, PD_MFC, "mfc", 0, BTS_ACT_NONE);
EXYNOS_BTS_PDATA(g3dacp, BTS_G3D_ACP, BTS_BE, PD_G3D, "g3d", 1, BTS_ACT_NONE);
#if defined(CONFIG_EXYNOS4_DEV_FIMC_IS)
EXYNOS_BTS_PDATA(isp0, BTS_ISP0, BTS_BE, PD_ISP, "isp0", 0, BTS_ACT_CHANGE_FBM_PRIOR);
EXYNOS_BTS_PDATA(isp1, BTS_ISP1, BTS_BE, PD_ISP, "isp1", 0, BTS_ACT_CHANGE_FBM_PRIOR);
#endif
EXYNOS_BTS_PDATA(disp, BTS_DISP, BTS_HARDTIME, PD_DISP1, "lcd", 0, BTS_ACT_NONE);
EXYNOS_BTS_PDATA(tv, BTS_TV, BTS_HARDTIME, PD_DISP1, "mixer", 0, BTS_ACT_NONE);
#if defined(CONFIG_EXYNOS_C2C)
EXYNOS_BTS_PDATA(c2c, BTS_C2C, BTS_HARDTIME, 0, "c2c", 0, BTS_ACT_NONE);
#endif

/* bts platform device lists */
#define EXYNOS_BTS_DEVICE(_name, _parent)				\
static struct platform_device exynos_device_bts_##_name = {		\
		.name		= "exynos-bts",				\
		.num_resources	= ARRAY_SIZE(exynos_bts_##_name##_resource),\
		.resource	= exynos_bts_##_name##_resource,	\
		.dev		= {					\
			.platform_data = &bts_##_name##_res,		\
			.parent = _parent,				\
		}							\
}

EXYNOS_BTS_DEVICE(disp, &s5p_device_fimd1.dev);
EXYNOS_BTS_DEVICE(tv, &s5p_device_mixer.dev);
#if defined(CONFIG_EXYNOS_C2C)
EXYNOS_BTS_DEVICE(c2c, &exynos_device_c2c.dev);
#endif
EXYNOS_BTS_DEVICE(g3dacp, NULL);
EXYNOS_BTS_DEVICE(rotator, &exynos_device_rotator.dev);
EXYNOS_BTS_DEVICE(jpeg, NULL);
EXYNOS_BTS_DEVICE(mdma1, &exynos_device_mdma.dev);
EXYNOS_BTS_DEVICE(gscl0, &exynos5_device_gsc0.dev);
EXYNOS_BTS_DEVICE(gscl1, &exynos5_device_gsc1.dev);
EXYNOS_BTS_DEVICE(gscl2, &exynos5_device_gsc2.dev);
EXYNOS_BTS_DEVICE(gscl3, &exynos5_device_gsc3.dev);
EXYNOS_BTS_DEVICE(mfc, &s5p_device_mfc.dev);
#if defined(CONFIG_EXYNOS4_DEV_FIMC_IS)
EXYNOS_BTS_DEVICE(isp0, &exynos5_device_fimc_is.dev);
EXYNOS_BTS_DEVICE(isp1, &exynos5_device_fimc_is.dev);
#endif
EXYNOS_BTS_DEVICE(cpu, NULL);

static struct platform_device *exynos_bts[] __initdata = {
	&exynos_device_bts_disp,
	&exynos_device_bts_tv,
#if defined(CONFIG_EXYNOS_C2C)
	&exynos_device_bts_c2c,
#endif
	&exynos_device_bts_cpu,
	&exynos_device_bts_g3dacp,
	&exynos_device_bts_rotator,
	&exynos_device_bts_jpeg,
	&exynos_device_bts_mdma1,
	&exynos_device_bts_gscl0,
	&exynos_device_bts_gscl1,
	&exynos_device_bts_gscl2,
	&exynos_device_bts_gscl3,
	&exynos_device_bts_mfc,
#if defined(CONFIG_EXYNOS4_DEV_FIMC_IS)
	&exynos_device_bts_isp0,
	&exynos_device_bts_isp1,
#endif
};

static int __init exynos_bts_init(void)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(exynos_bts); i++)
		exynos_bts[i]->id = i;

	return platform_add_devices(exynos_bts, ARRAY_SIZE(exynos_bts));
}
arch_initcall(exynos_bts_init);
