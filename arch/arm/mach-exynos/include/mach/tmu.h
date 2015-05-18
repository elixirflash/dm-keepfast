/* linux/arch/arm/mach-exynos/include/mach/tmu.h
 *
 * Copyright 2011 Samsung Electronics Co., Ltd.
 *      http://www.samsung.com/
 *
 * Header file for tmu support
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _S5P_THERMAL_H
#define _S5P_THERMAL_H

#define MUX_ADDR_VALUE 6
#define TMU_SAVE_NUM 10
#define TMU_DC_VALUE 25
#define EFUSE_MIN_VALUE 40
#define EFUSE_MAX_VALUE 100
#define UNUSED_THRESHOLD 0xFF

#if defined(CONFIG_CPU_EXYNOS4212) || defined(CONFIG_CPU_EXYNOS4412) \
					|| defined(CONFIG_CPU_EXYNOS5250)
#define CONFIG_TC_VOLTAGE /* Temperature compensated voltage */
#endif
#if defined(CONFIG_CPU_EXYNOS5250)
#define CONFIG_MIF_VC
#endif

enum tmu_status_t {
	TMU_STATUS_INIT = 0,
	TMU_STATUS_NORMAL,
	TMU_STATUS_THROTTLED,
	TMU_STATUS_WARNING,
	TMU_STATUS_TRIPPED,
	TMU_STATUS_TC,
	TMU_STATUS_MIF_VC,
};

struct temperature_params {
	unsigned int stop_throttle;
	unsigned int start_throttle;
	unsigned int stop_warning;
	unsigned int start_warning;
	unsigned int start_tripping; /* temp to do tripping */
	unsigned int start_hw_tripping;
#if defined(CONFIG_TC_VOLTAGE)
	int stop_tc;	/* temperature compensation for sram */
	int start_tc;
#endif
#if defined(CONFIG_MIF_VC)
	int stop_mif_vc; /* temperture for mif voltage compensation */
	int start_mif_vc;
#endif
};

struct cpufreq_params {
	unsigned int throttle_freq;
	unsigned int warning_freq;
};

#if defined(CONFIG_TC_VOLTAGE)
struct temp_compensate_params {
	 unsigned int arm_volt; /* temperature compensated voltage for ARM */
	 unsigned int bus_volt; /* temperature compensated voltage for BUS */
	 unsigned int g3d_volt; /* temperature compensated voltage for G3D */
};
#endif

struct tmu_data {
	struct temperature_params ts;
	struct cpufreq_params cpulimit;
	unsigned int efuse_value;
	unsigned int slope;
	int mode;
#if defined(CONFIG_TC_VOLTAGE)
	struct temp_compensate_params temp_compensate;
#endif
};

struct tmu_info {
	int id;
	void __iomem	*tmu_base;
	struct device	*dev;
	struct resource *ioarea;
	int irq;

	unsigned int te1; /* triminfo_25 */
	unsigned int te2; /* triminfo_85 */
	int tmu_state;

	unsigned int throttle_freq;
	unsigned int warning_freq;

	/* temperature compensation */
	unsigned int cpulevel_tc;
	unsigned int busfreq_tc;
	unsigned int g3dlevel_tc;

	struct delayed_work polling;
	struct delayed_work monitor;
	unsigned int reg_save[TMU_SAVE_NUM];
#if defined(CONFIG_BUSFREQ_OPP) && defined(CONFIG_TC_VOLTAGE)
	struct device *bus_dev;
#endif
};

void exynos_tmu_set_platdata(struct tmu_data *pd);
struct tmu_info *exynos_tmu_get_platdata(void);
int exynos_tmu_get_irqno(int num);
extern struct platform_device exynos_device_tmu;
extern int mali_dvfs_freq_lock(int level);
extern void mali_dvfs_freq_unlock(void);
#if defined(CONFIG_TC_VOLTAGE)
extern int mali_voltage_lock_init(void);
extern int mali_voltage_lock_push(int lock_vol);
extern int mali_voltage_lock_pop(void);
extern int mali_dvfs_freq_under_lock(int level);
extern void mali_dvfs_freq_under_unlock(void);
#endif
#if defined(CONFIG_BUSFREQ_OPP)
extern void busfreq_set_volt_offset(unsigned int offset);
extern int exynos4x12_find_busfreq_by_volt(unsigned int req_volt,
					   unsigned int *freq);
extern int exynos5250_find_busfreq_by_volt(unsigned int req_volt,
					   unsigned int *freq);
#endif
#endif /* _S5P_THERMAL_H */
