/* linux/arch/arm/mach-exynos/board-smdk5250-input.c
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#include <linux/gpio.h>
#include <linux/gpio_keys.h>
#include <linux/i2c.h>
#include <linux/input.h>
#include <linux/delay.h>

#include <plat/gpio-cfg.h>
#include <plat/devs.h>
#include <plat/iic.h>

#include <mach/irqs.h>
#include <mach/board_rev.h>

#include "board-smdk5250.h"

struct gpio_keys_button smdk5250_button[] = {
#if defined(CONFIG_MACH_ARNDALE)
	{
		.code = KEY_MENU,
		.gpio = EXYNOS5_GPX1(4),
		.active_low = 1,
		.wakeup = 0,
	},
	{
		.code = KEY_HOME,
		.gpio = EXYNOS5_GPX1(5),
		.active_low = 1,
		.wakeup = 0,
	},
	{
		.code = KEY_VOLUMEUP,
		.gpio = EXYNOS5_GPX1(6),
		.active_low = 1,
		.wakeup = 0,
	},
	{
		.code = KEY_VOLUMEDOWN,
		.gpio = EXYNOS5_GPX1(7),
		.active_low = 1,
		.wakeup = 0,
	},
	{
		.code = KEY_BACK,
		.gpio = EXYNOS5_GPX2(0),
		.active_low = 1,
		.wakeup = 0,
	},
	{
		.code = KEY_SEARCH,
		.gpio = EXYNOS5_GPX2(1),
		.active_low = 1,
		.wakeup = 0,
	},
	{
		.code = KEY_POWER,
		.gpio = EXYNOS5_GPX1(3),
		.active_low = 1,
		.wakeup = 1,
	},
#else
	{
		.code = KEY_MENU,
		.gpio = EXYNOS5_GPX1(4),
		.active_low = 1,
		.wakeup = 0,
	},
	{
		.code = KEY_HOME,
		.gpio = EXYNOS5_GPX1(5),
		.active_low = 1,
		.wakeup = 0,
	},
	{
		.code = KEY_VOLUMEUP,
		.gpio = EXYNOS5_GPX1(6),
		.active_low = 1,
		.wakeup = 0,
	},
	{
		.code = KEY_VOLUMEDOWN,
		.gpio = EXYNOS5_GPX1(7),
		.active_low = 1,
		.wakeup = 0,
	},
	{
		.code = KEY_BACK,
		.gpio = EXYNOS5_GPX2(0),
		.active_low = 1,
		.wakeup = 0,
	},
	{
		.code = KEY_SEARCH,
		.gpio = EXYNOS5_GPX2(1),
		.active_low = 1,
		.wakeup = 0,
	},
	{
		.code = KEY_POWER,
		.gpio = EXYNOS5_GPX1(3),
		.active_low = 1,
		.wakeup = 1,
	},
#endif
};

struct gpio_keys_platform_data smdk5250_gpiokeys_platform_data = {
	smdk5250_button,
	ARRAY_SIZE(smdk5250_button),
};

static struct platform_device smdk5250_gpio_keys = {
	.name	= "gpio-keys",
	.dev	= {
		.platform_data = &smdk5250_gpiokeys_platform_data,
	},
};

#ifdef CONFIG_MACH_ARNDALE
static struct i2c_board_info i2c_devs7[] __initdata = {
	{
		I2C_BOARD_INFO("unidisplay_ts", 0x41),
		.irq		= IRQ_EINT(9),
	},
};
#else
struct egalax_i2c_platform_data {
	unsigned int gpio_int;
	unsigned int gpio_en;
	unsigned int gpio_rst;
};

static struct egalax_i2c_platform_data exynos5_egalax_data = {
	.gpio_int	= EXYNOS5_GPX3(1),
};

static struct i2c_board_info i2c_devs7[] __initdata = {
	{
		I2C_BOARD_INFO("egalax_i2c", 0x04),
		.irq		= IRQ_EINT(25),
		.platform_data	= &exynos5_egalax_data,
	},
};
#endif

static struct platform_device *smdk5250_input_devices[] __initdata = {
	&s3c_device_i2c7,
	&smdk5250_gpio_keys,
};

#define TS_RST  samsung_board_rev_is_0_0() ? EXYNOS5_GPX2(4) : EXYNOS5_GPX2(1)

static void exynos5_smdk5250_touch_init(void)
{
#ifdef CONFIG_TOUCHSCREEN_COASIA
	if (gpio_request(TS_RST, "GPX2")) {
		pr_err("%s : TS_RST request port error\n", __func__);
	} else {
		s3c_gpio_cfgpin(TS_RST, S3C_GPIO_OUTPUT);
		gpio_direction_output(TS_RST, 0);
		usleep_range(20000, 21000);
		gpio_direction_output(TS_RST, 1);
		gpio_free(TS_RST);
	}
#endif
}

void __init exynos5_smdk5250_input_init(void)
{
	exynos5_smdk5250_touch_init();
	s3c_i2c7_set_platdata(NULL);
	i2c_register_board_info(7, i2c_devs7, ARRAY_SIZE(i2c_devs7));

	platform_add_devices(smdk5250_input_devices,
			ARRAY_SIZE(smdk5250_input_devices));

	s3c_gpio_setpull(EXYNOS5_GPX1(3), S3C_GPIO_PULL_UP);
}
