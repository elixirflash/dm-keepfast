/* linux/arch/arm/mach-exynos/dynamic-dvfs-nr_running-hotplug.c
 *
 * Copyright (c) 2011 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com/
 *
 * EXYNOS - DYNAMIC DVFS-NR_Running CPU hotplug
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

static unsigned int ctn_freq_in_trg_cnt;
		/* continuous frequency hotplug in trigger count */
static unsigned int ctn_freq_out_trg_cnt;
		/* continuous frequency hotplug out trigger count */
static unsigned int ctn_nr_running_over2;
static unsigned int ctn_nr_running_over3;
static unsigned int ctn_nr_running_over4;
static unsigned int ctn_nr_running_under2;
static unsigned int ctn_nr_running_under3;
static unsigned int ctn_nr_running_under4;
static unsigned int freq_max;
				/* max frequency of the dedicated dvfs table */
static unsigned int freq_min = -1UL;
				/* min frequency of the dedicated dvfs table */
static unsigned int freq_in_trg;
					/* frequency hotplug in trigger */
static unsigned int freq_out_trg;
					/* frequency hotplug out trigger */
static unsigned int can_hotplug;

struct kobject *hotplug_kobject;

static void exynos_integrated_dvfs_hotplug(unsigned int freq_old,
					unsigned int freq_new)
{

	freq_in_trg = 800000;			/* tunnable */
	freq_out_trg = freq_min;		/* tunnable */

	if (nr_running() <= 1) {
		ctn_nr_running_over2 = 0;
		ctn_nr_running_over3 = 0;
		ctn_nr_running_over4 = 0;
		ctn_nr_running_under2++;
		ctn_nr_running_under3++;
		ctn_nr_running_under4++;
	} else if ((nr_running() > 1) && (nr_running() <= 2)) {
		ctn_nr_running_over2++;
		ctn_nr_running_over3 = 0;
		ctn_nr_running_over4 = 0;
		ctn_nr_running_under2 = 0;
		ctn_nr_running_under3++;
		ctn_nr_running_under4++;
	} else if ((nr_running() > 2) && (nr_running() <= 3)) {
		ctn_nr_running_over2++;
		ctn_nr_running_over3++;
		ctn_nr_running_over4 = 0;
		ctn_nr_running_under2 = 0;
		ctn_nr_running_under3 = 0;
		ctn_nr_running_under4++;
	} else if (nr_running() > 3) {
		ctn_nr_running_over2++;
		ctn_nr_running_over3++;
		ctn_nr_running_over4++;
		ctn_nr_running_under2 = 0;
		ctn_nr_running_under3 = 0;
		ctn_nr_running_under4 = 0;
	}

	if ((freq_old >= freq_in_trg) && (freq_new >= freq_in_trg))
		ctn_freq_in_trg_cnt++;
	else
		ctn_freq_in_trg_cnt = 0;
	if ((freq_old <= freq_out_trg) && (freq_new <= freq_out_trg))
		ctn_freq_out_trg_cnt++;
	else
		ctn_freq_out_trg_cnt = 0;

	if (soc_is_exynos4412()) {
		if ((cpu_online(3) == 0) && (nr_running() >= 2) &&
		   ((freq_old >= freq_in_trg) && (freq_new >= freq_in_trg))) {
			if ((ctn_nr_running_over2 >= 4) &&
			   (ctn_freq_in_trg_cnt >= 5)) {
				/* over 400ms for nr_running(), over 500ms for frequency, tunnable */
				cpu_up(3);
				ctn_freq_in_trg_cnt = 0;
			}
		} else if ((cpu_online(2) == 0) && (nr_running() >= 3) &&
			  ((freq_old >= freq_in_trg) && (freq_new >= freq_in_trg))) {
			if ((ctn_nr_running_over3 >= 4) &&
			   (ctn_freq_in_trg_cnt >= 5)) {
				/* over 400ms for nr_running(), over 500ms for frequency, tunnable */
				cpu_up(2);
				ctn_freq_in_trg_cnt = 0;
			}
		} else if ((cpu_online(1) == 0) && (nr_running() >= 4) &&
			  ((freq_old >= freq_in_trg) && (freq_new >= freq_in_trg))) {
			if ((ctn_nr_running_over4 >= 8) &&
			   (ctn_freq_in_trg_cnt >= 5)) {
				/* over 800ms for nr_running(), over 500ms for frequency, tunnable */
				cpu_up(1);
				ctn_freq_in_trg_cnt = 0;
			}
		}
	} else {
		if ((cpu_online(1) == 0) && ((freq_old >= freq_in_trg) &&
		   (freq_new >= freq_in_trg))) {
			if ((ctn_nr_running_over2 >= 8) &&
			   (ctn_freq_in_trg_cnt >= 5)) {
				/* over 800ms  for nr_running(), over 500ms for frequency, tunnable */
				cpu_up(1);
				ctn_nr_running_over2 = 0;
				ctn_freq_in_trg_cnt = 0;
			}
		}
	}

	if (soc_is_exynos4412()) {
		if ((cpu_online(1) == 1) && (nr_running() < 4) &&
		   ((freq_old <= freq_out_trg) && (freq_new <= freq_out_trg))) {
			if ((ctn_nr_running_under4 >= 8) &&
			   (ctn_freq_out_trg_cnt >= 5)) {
				/* over 800ms for nr_running(), over 500ms for frequency, tunnable */
				cpu_down(1);
				ctn_freq_out_trg_cnt = 0;
			}
		} else if ((cpu_online(2) == 1) && (nr_running() < 3) &&
			  ((freq_old <= freq_out_trg) && (freq_new <= freq_out_trg))) {
			if ((ctn_nr_running_under3 >= 8) &&
			   (ctn_freq_out_trg_cnt >= 5)) {
				/* over 800ms for nr_running(), over 500ms for frequency, tunnable */
				cpu_down(2);
				ctn_freq_out_trg_cnt = 0;
			}
		} else if ((cpu_online(3) == 1) && (nr_running() < 2) &&
			  ((freq_old <= freq_out_trg) && (freq_new <= freq_out_trg))) {
			if ((ctn_nr_running_under2 >= 8) &&
			   (ctn_freq_out_trg_cnt >= 5)) {
				/* over 800ms for nr_running(), over 500ms for frequency, tunnable */
				cpu_down(3);
				ctn_freq_out_trg_cnt = 0;
			}
		}
	} else {
		if ((cpu_online(1) == 1) &&
		   ((freq_old <= freq_out_trg) && (freq_new <= freq_out_trg))) {
			if ((ctn_nr_running_under2 >= 8) &&
			   (ctn_freq_out_trg_cnt >= 5)) {
				/* over 800ms for nr_running(), over 500ms for frequency, tunnable */
				cpu_down(1);
				ctn_nr_running_under2 = 0;
				ctn_freq_out_trg_cnt = 0;
			}
		}
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

static SYSDEV_ATTR(hotplug_state, 0666, show_hotplug_state, store_hotplug_state);

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
		ctn_freq_in_trg_cnt = 0;
		ctn_freq_out_trg_cnt = 0;
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

	ctn_freq_in_trg_cnt = 0;
	ctn_freq_out_trg_cnt = 0;
	ctn_nr_running_over2 = 0;
	ctn_nr_running_over3 = 0;
	ctn_nr_running_over4 = 0;
	ctn_nr_running_under2 = 0;
	ctn_nr_running_under3 = 0;
	ctn_nr_running_under4 = 0;

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
