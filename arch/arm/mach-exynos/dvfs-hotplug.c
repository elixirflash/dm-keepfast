/* linux/arch/arm/mach-exynos/dvfs-hotplug.c
 *
 * Copyright (c) 2011 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com/
 *
 * EXYNOS - Integrated DVFS CPU hotplug
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#include <linux/sched.h>
#include <linux/cpufreq.h>
#include <linux/cpu.h>
#include <linux/err.h>
#include <linux/notifier.h>
#include <linux/reboot.h>
#include <linux/suspend.h>
#include <linux/io.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/sysdev.h>

#include <plat/cpu.h>

#include <asm/uaccess.h>

static unsigned int consecutv_highestlevel_cnt;
static unsigned int consecutv_lowestlevel_cnt;

static unsigned int freq_max;
static unsigned int freq_in_trg;
static unsigned int freq_min = -1UL;

static unsigned int can_hotplug;

struct kobject *hotplug_kobject;

static void exynos_integrated_dvfs_hotplug(unsigned int freq_old,
					unsigned int freq_new)
{
	freq_in_trg = 800000;

	if ((freq_old >= freq_in_trg) && (freq_new >= freq_in_trg)) {
		if (soc_is_exynos4412()) {
			if (cpu_online(3) == 0) {
				if (consecutv_highestlevel_cnt >= 5) {
					cpu_up(3);
					consecutv_highestlevel_cnt = 0;
				}
			} else if (cpu_online(2) == 0) {
				if (consecutv_highestlevel_cnt >= 5) {
					cpu_up(2);
					consecutv_highestlevel_cnt = 0;
				}
			} else if (cpu_online(1) == 0) {
				if (consecutv_highestlevel_cnt >= 5) {
					cpu_up(1);
					consecutv_highestlevel_cnt = 0;
				}
			}
			consecutv_highestlevel_cnt++;
		} else {
			if (cpu_online(1) == 0) {
				if (consecutv_highestlevel_cnt >= 5) {
					cpu_up(1);
					consecutv_highestlevel_cnt = 0;
				}
			}
			consecutv_highestlevel_cnt++;
		}
	} else if ((freq_old <= freq_min) && (freq_new <= freq_min)) {
		if (soc_is_exynos4412()) {
			if (cpu_online(1) == 1) {
				if (consecutv_lowestlevel_cnt >= 5) {
					cpu_down(1);
					consecutv_lowestlevel_cnt = 0;
				} else
					consecutv_lowestlevel_cnt++;
			} else if (cpu_online(2) == 1) {
				if (consecutv_lowestlevel_cnt >= 5) {
					cpu_down(2);
					consecutv_lowestlevel_cnt = 0;
				} else
					consecutv_lowestlevel_cnt++;
			} else if (cpu_online(3) == 1) {
				if (consecutv_lowestlevel_cnt >= 5) {
					cpu_down(3);
					consecutv_lowestlevel_cnt = 0;
				} else
					consecutv_lowestlevel_cnt++;
			}
		} else {
			if (cpu_online(1) == 1) {
				if (consecutv_lowestlevel_cnt >= 5) {
					cpu_down(1);
					consecutv_lowestlevel_cnt = 0;
				} else
					consecutv_lowestlevel_cnt++;
			}
		}
	} else {
		consecutv_highestlevel_cnt = 0;
		consecutv_lowestlevel_cnt = 0;
	}
}

/***********************************************************/
/**** sysfs interface to enable/disable dynamic hotplug ****/
/***********************************************************/
static ssize_t show_hotplug_state(struct sys_device *dev,
			struct sysdev_attribute *attr, char *buf)
{
	return sprintf(buf, "Dynamic Hotplug State (on:1  off:0): %u\n",
							can_hotplug);
}

static ssize_t __ref store_hotplug_state(struct sys_device *dev,
		struct sysdev_attribute *attr, const char *buf, size_t count)
{
	ssize_t ret;

	switch (buf[0]) {
	case '0':
		can_hotplug = 0;
		if (soc_is_exynos4412()) {
			if (cpu_online(1) == 0)
				cpu_up(1);
			if (cpu_online(2) == 0)
				cpu_up(2);
			if (cpu_online(3) == 0)
				cpu_up(3);
		} else {
			if (cpu_online(1) == 0)
				cpu_up(1);
		}
		break;
	case '1':
		can_hotplug = 1;
		break;
	default:
		ret = -EINVAL;
	}

	if (ret >= 0)
		ret = count;

	pr_info("Current Dynamic Hotplug State (on:1    off:0): %u\n",
							can_hotplug);

	return ret;
}

static SYSDEV_ATTR(hotplug_state, 0666, show_hotplug_state,
					store_hotplug_state);

static int __init register_hotplug_control(void)
{
	int ret = 0;

	hotplug_kobject = kobject_create_and_add("hotplug_state",
						&cpu_sysdev_class.kset.kobj);
	ret = sysfs_create_file(hotplug_kobject, &attr_hotplug_state.attr);

	return ret;
}
module_init(register_hotplug_control)

/***** end of sysfs interface *****/

static int hotplug_cpufreq_transition(struct notifier_block *nb,
					unsigned long val, void *data)
{
	struct cpufreq_freqs *freqs = (struct cpufreq_freqs *)data;

	if ((val == CPUFREQ_POSTCHANGE) && can_hotplug)
		exynos_integrated_dvfs_hotplug(freqs->old, freqs->new);

	return 0;
}

static struct notifier_block dvfs_hotplug = {
	.notifier_call = hotplug_cpufreq_transition,
};

static int hotplug_pm_transition(struct notifier_block *nb,
					unsigned long val, void *data)
{
	switch (val) {
	case PM_SUSPEND_PREPARE:
		can_hotplug = 0;
		consecutv_highestlevel_cnt = 0;
		consecutv_lowestlevel_cnt = 0;
		break;
	case PM_POST_RESTORE:
	case PM_POST_SUSPEND:
		can_hotplug = 1;
		break;
	}

	return 0;
}

static struct notifier_block pm_hotplug = {
	.notifier_call = hotplug_pm_transition,
};

/*
 * Note : This function should be called after intialization of CPUFreq
 * driver for exynos. The cpufreq_frequency_table for exynos should be
 * established before calling this function.
 */
static int __init exynos_integrated_dvfs_hotplug_init(void)
{
	int i;
	struct cpufreq_frequency_table *table;
	unsigned int freq;

	consecutv_highestlevel_cnt = 0;
	consecutv_lowestlevel_cnt = 0;
	can_hotplug = 1;

	table = cpufreq_frequency_get_table(0);
	if (table == NULL) {
		pr_err("%s: Check loading cpufreq before\n", __func__);
		return -EINVAL;
	}

	for (i = 0; table[i].frequency != CPUFREQ_TABLE_END; i++) {
		freq = table[i].frequency;

		if (freq != CPUFREQ_ENTRY_INVALID && freq > freq_max)
			freq_max = freq;
		else if (freq != CPUFREQ_ENTRY_INVALID && freq_min > freq)
			freq_min = freq;
	}

	pr_info("%s, max(%d),min(%d)\n", __func__, freq_max, freq_min);

	register_pm_notifier(&pm_hotplug);

	return cpufreq_register_notifier(&dvfs_hotplug,
					 CPUFREQ_TRANSITION_NOTIFIER);
}

late_initcall(exynos_integrated_dvfs_hotplug_init);
