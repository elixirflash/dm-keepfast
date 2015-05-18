/* linux/arch/arm/mach-exynos/mach-smdk5250.c
 *
 * Copyright (c) 2011 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#include <linux/platform_device.h>
#include <linux/serial_core.h>
#include <linux/clk.h>
#include <linux/gpio.h>
#include <linux/i2c.h>
#include <linux/regulator/machine.h>
#include <linux/regulator/fixed.h>
#include <linux/mfd/wm8994/pdata.h>
#include <linux/memblock.h>
#include <linux/smsc911x.h>
#include <linux/rfkill-gpio.h>
#include <linux/delay.h>
#include <linux/notifier.h>
#include <linux/reboot.h>

#include <asm/mach/arch.h>
#include <asm/io.h>
#include <asm/mach-types.h>

#include <media/s5k4ba_platform.h>
#include <media/m5mols.h>
#include <media/exynos_gscaler.h>
#include <media/exynos_flite.h>
#include <media/exynos_fimc_is.h>
#include <plat/gpio-cfg.h>
#include <plat/adc.h>
#include <plat/regs-adc.h>
#include <plat/regs-serial.h>
#include <plat/exynos5.h>
#include <plat/cpu.h>
#include <plat/clock.h>
#include <plat/hwmon.h>
#include <plat/devs.h>
#include <plat/regs-srom.h>
#include <plat/iic.h>
#include <plat/pd.h>
#include <plat/s5p-mfc.h>
#include <plat/fimg2d.h>
#include <plat/tv-core.h>

#include <plat/mipi_csis.h>
#include <mach/map.h>
#include <mach/exynos-ion.h>
#include <mach/sysmmu.h>
#include <mach/ppmu.h>
#include <mach/dev.h>
#include <mach/regs-pmu.h>
#include <mach/regs-clock.h>
#include <mach/regs-pmu5.h>
#include <mach/board_rev.h>
#ifdef CONFIG_EXYNOS_CONTENT_PATH_PROTECTION
#include <mach/secmem.h>
#endif
#ifdef CONFIG_VIDEO_JPEG_V2X
#include <plat/jpeg.h>
#endif
#ifdef CONFIG_EXYNOS_C2C
#include <mach/c2c.h>
#endif
#ifdef CONFIG_EXYNOS_HSI
#include <mach/hsi.h>
#endif
#ifdef CONFIG_VIDEO_EXYNOS_TV
#include <plat/tvout.h>
#endif

#ifdef CONFIG_ATH6KL_PLATFORM_DATA
#include <linux/ath6kl.h>
#endif 

#include <plat/media.h>

#include "board-smdk5250.h"

#define REG_INFORM4            (S5P_INFORM4)

/* Following are default values for UCON, ULCON and UFCON UART registers */
#define ARNDALE_UCON_DEFAULT	(S3C2410_UCON_TXILEVEL |	\
				 S3C2410_UCON_RXILEVEL |	\
				 S3C2410_UCON_TXIRQMODE |	\
				 S3C2410_UCON_RXIRQMODE |	\
				 S3C2410_UCON_RXFIFO_TOI |	\
				 S3C2443_UCON_RXERR_IRQEN)

#define ARNDALE_ULCON_DEFAULT	S3C2410_LCON_CS8

#define ARNDALE_UFCON_DEFAULT	(S3C2410_UFCON_FIFOMODE |	\
				 S5PV210_UFCON_TXTRIG4 |	\
				 S5PV210_UFCON_RXTRIG4)

#if CONFIG_INV_SENSORS
#include <linux/mpu.h>
//gyro
static struct mpu_platform_data mpu6050_data = {
	.int_config = 0x10,
	.level_shifter = 0,
	.orientation = { 1, 0, 0, 
					0, 1, 0,
					0, 0, 1 },
};
//compass
static struct ext_slave_platform_data inv_mpu_ak8975_data = {
	.address	= 0x0C,
	.adapt_num	= 5,
	.bus		= EXT_SLAVE_BUS_PRIMARY,
	.orientation = { 1, 0, 0,
					0, -1, 0,
					0, 0, 1 },
};
#endif

static struct s3c2410_uartcfg arndale_uartcfgs[] __initdata = {
	[0] = {
		.hwport		= 0,
		.flags		= 0,
		.ucon		= ARNDALE_UCON_DEFAULT,
		.ulcon		= ARNDALE_ULCON_DEFAULT,
		.ufcon		= ARNDALE_UFCON_DEFAULT,
	},
	[1] = {
		.hwport		= 1,
		.flags		= 0,
		.ucon		= ARNDALE_UCON_DEFAULT,
		.ulcon		= ARNDALE_ULCON_DEFAULT,
		.ufcon		= ARNDALE_UFCON_DEFAULT,
	},
	[2] = {
		.hwport		= 2,
		.flags		= 0,
		.ucon		= ARNDALE_UCON_DEFAULT,
		.ulcon		= ARNDALE_ULCON_DEFAULT,
		.ufcon		= ARNDALE_UFCON_DEFAULT,
	},
	[3] = {
		.hwport		= 3,
		.flags		= 0,
		.ucon		= ARNDALE_UCON_DEFAULT,
		.ulcon		= ARNDALE_ULCON_DEFAULT,
		.ufcon		= ARNDALE_UFCON_DEFAULT,
	},
};

#ifdef CONFIG_EXYNOS_MEDIA_DEVICE
struct platform_device exynos_device_md0 = {
	.name = "exynos-mdev",
	.id = 0,
};

struct platform_device exynos_device_md1 = {
	.name = "exynos-mdev",
	.id = 1,
};

struct platform_device exynos_device_md2 = {
	.name = "exynos-mdev",
	.id = 2,
};
#endif

#if defined CONFIG_VIDEO_EXYNOS5_FIMC_IS
static struct exynos5_platform_fimc_is exynos5_fimc_is_data;

#if defined CONFIG_VIDEO_S5K4E5
static struct exynos5_fimc_is_sensor_info s5k4e5= {
	.sensor_name = "S5K4E5",
	.sensor_id = SENSOR_NAME_S5K4E5,
#if defined CONFIG_S5K4E5_POSITION_FRONT
	.sensor_position = SENSOR_POSITION_FRONT,
#elif  defined CONFIG_S5K4E5_POSITION_REAR
	.sensor_position = SENSOR_POSITION_REAR,
#endif
#if defined CONFIG_S5K4E5_CSI_C
	.csi_id = CSI_ID_A,
	.flite_id = FLITE_ID_A,
	.i2c_channel = SENSOR_CONTROL_I2C0,
#elif  defined CONFIG_S5K4E5_CSI_D
	.csi_id = CSI_ID_B,
	.flite_id = FLITE_ID_B,
	.i2c_channel = SENSOR_CONTROL_I2C1,
#endif

	.max_width = 2560,
	.max_height = 1920,
	.max_frame_rate = 30,

	.mipi_lanes = 2,
	.mipi_settle = 12,
	.mipi_align = 24,
};
#endif

#if defined CONFIG_VIDEO_S5K3H7
static struct exynos5_fimc_is_sensor_info s5k3h7= {
	.sensor_name = "S5K3H7",
	.sensor_id = SENSOR_NAME_S5K3H7,
#if defined CONFIG_S5K3H7_POSITION_FRONT
	.sensor_position = SENSOR_POSITION_FRONT,
#elif  defined CONFIG_S5K3H7_POSITION_REAR
	.sensor_position = SENSOR_POSITION_REAR,
#endif
#if defined CONFIG_S5K3H7_CSI_C
	.csi_id = CSI_ID_A,
	.flite_id = FLITE_ID_A,
	.i2c_channel = SENSOR_CONTROL_I2C0,
#elif  defined CONFIG_S5K3H7_CSI_D
	.csi_id = CSI_ID_B,
	.flite_id = FLITE_ID_B,
	.i2c_channel = SENSOR_CONTROL_I2C1,
#endif

	.max_width = 3248,
	.max_height = 2438,
	.max_frame_rate = 30,

	.mipi_lanes = 4,
	.mipi_settle = 12,
	.mipi_align = 24,
};
#endif

#if defined CONFIG_VIDEO_S5K6A3
static struct exynos5_fimc_is_sensor_info s5k6a3= {
	.sensor_name = "S5K6A3",
	.sensor_id = SENSOR_NAME_S5K6A3,
#if defined CONFIG_S5K6A3_POSITION_FRONT
	.sensor_position = SENSOR_POSITION_FRONT,
#elif  defined CONFIG_S5K6A3_POSITION_REAR
	.sensor_position = SENSOR_POSITION_REAR,
#endif
#if defined CONFIG_S5K6A3_CSI_C
	.csi_id = CSI_ID_A,
	.flite_id = FLITE_ID_A,
	.i2c_channel = SENSOR_CONTROL_I2C0,
#elif  defined CONFIG_S5K6A3_CSI_D
	.csi_id = CSI_ID_B,
	.flite_id = FLITE_ID_B,
	.i2c_channel = SENSOR_CONTROL_I2C1,
#endif

	.max_width = 1280,
	.max_height = 720,
	.max_frame_rate = 30,

	.mipi_lanes = 1,
	.mipi_settle = 12,
	.mipi_align = 24,
};
#endif
#endif

#ifdef CONFIG_EXYNOS_C2C
struct exynos_c2c_platdata smdk5250_c2c_pdata = {
	.setup_gpio	= NULL,
	.shdmem_addr	= C2C_SHAREDMEM_BASE,
	.shdmem_size	= C2C_MEMSIZE_64,
	.ap_sscm_addr	= NULL,
	.cp_sscm_addr	= NULL,
	.rx_width	= C2C_BUSWIDTH_16,
	.tx_width	= C2C_BUSWIDTH_16,
	.clk_opp100	= 400,
	.clk_opp50	= 200,
	.clk_opp25	= 100,
	.default_opp_mode	= C2C_OPP50,
	.get_c2c_state	= NULL,
	.c2c_sysreg	= S5P_VA_CMU + 0x6000,
};
#endif

#ifdef CONFIG_EXYNOS_HSI
struct exynos_hsi_platdata smdk5250_hsi_pdata = {
	.setup_gpio	= NULL,
};
#endif

#ifdef CONFIG_VIDEO_FIMG2D
static struct fimg2d_platdata fimg2d_data __initdata = {
	.hw_ver		= 0x42,
	.gate_clkname	= "fimg2d",
};
#endif

#ifdef CONFIG_VIDEO_EXYNOS_FIMC_LITE
#if defined(CONFIG_ITU_A)
static int smdk5250_cam0_reset(int dummy)
{
#if 0
	int err;
	/* Camera A */
	err = gpio_request(EXYNOS5_GPX1(2), "GPX1");
	if (err)
		printk(KERN_ERR "#### failed to request GPX1_2 ####\n");

	s3c_gpio_setpull(EXYNOS5_GPX1(2), S3C_GPIO_PULL_NONE);
	gpio_direction_output(EXYNOS5_GPX1(2), 0);
	gpio_direction_output(EXYNOS5_GPX1(2), 1);
	gpio_free(EXYNOS5_GPX1(2));
#endif
	return 0;
}
#endif
#if defined(CONFIG_ITU_B)
static int smdk5250_cam1_reset(int dummy)
{
	int err;
	/* Camera A */
	err = gpio_request(EXYNOS5_GPX1(0), "GPX1");
	if (err)
		printk(KERN_ERR "#### failed to request GPX1_2 ####\n");

	s3c_gpio_setpull(EXYNOS5_GPX1(0), S3C_GPIO_PULL_NONE);
	gpio_direction_output(EXYNOS5_GPX1(0), 0);
	gpio_direction_output(EXYNOS5_GPX1(0), 1);
	gpio_free(EXYNOS5_GPX1(0));

	return 0;
}
#endif

#ifdef CONFIG_VIDEO_S5K4BA
static struct s5k4ba_mbus_platform_data s5k4ba_mbus_plat = {
	.id		= 0,
	.fmt = {
		.width	= 1600,
		.height	= 1200,
		/*.code	= V4L2_MBUS_FMT_UYVY8_2X8,*/
		.code	= V4L2_MBUS_FMT_VYUY8_2X8,
	},
	.clk_rate	= 24000000UL,
#ifdef CONFIG_ITU_A
	.set_power	= smdk5250_cam0_reset,
#endif
#ifdef CONFIG_ITU_B
	.set_power	= smdk5250_cam1_reset,
#endif
};

static struct i2c_board_info s5k4ba_info = {
	I2C_BOARD_INFO("S5K4BA", 0x2d),
	.platform_data = &s5k4ba_mbus_plat,
};
#endif

/* 1 MIPI Cameras */
#ifdef CONFIG_VIDEO_M5MOLS
static struct m5mols_platform_data m5mols_platdata = {
#ifdef CONFIG_CSI_C
	.gpio_rst = EXYNOS5_GPX1(2), /* ISP_RESET */
#endif
#ifdef CONFIG_CSI_D
	.gpio_rst = EXYNOS5_GPX1(0), /* ISP_RESET */
#endif
	.enable_rst = true, /* positive reset */
	.irq = IRQ_EINT(22),
};

static struct i2c_board_info m5mols_board_info = {
	I2C_BOARD_INFO("M5MOLS", 0x1F),
	.platform_data = &m5mols_platdata,
};
#endif
#endif /* CONFIG_VIDEO_EXYNOS_FIMC_LITE */

#ifdef CONFIG_VIDEO_EXYNOS_MIPI_CSIS
static struct regulator_consumer_supply mipi_csi_fixed_voltage_supplies[] = {
	REGULATOR_SUPPLY("mipi_csi", "s5p-mipi-csis.0"),
	REGULATOR_SUPPLY("mipi_csi", "s5p-mipi-csis.1"),
};

static struct regulator_init_data mipi_csi_fixed_voltage_init_data = {
	.constraints = {
		.always_on = 1,
	},
	.num_consumer_supplies	= ARRAY_SIZE(mipi_csi_fixed_voltage_supplies),
	.consumer_supplies	= mipi_csi_fixed_voltage_supplies,
};

static struct fixed_voltage_config mipi_csi_fixed_voltage_config = {
	.supply_name	= "DC_5V",
	.microvolts	= 5000000,
	.gpio		= -EINVAL,
	.init_data	= &mipi_csi_fixed_voltage_init_data,
};

static struct platform_device mipi_csi_fixed_voltage = {
	.name		= "reg-fixed-voltage",
	.id		= 3,
	.dev		= {
		.platform_data	= &mipi_csi_fixed_voltage_config,
	},
};
#endif

#ifdef CONFIG_VIDEO_M5MOLS
static struct regulator_consumer_supply m5mols_fixed_voltage_supplies[] = {
	REGULATOR_SUPPLY("core", NULL),
	REGULATOR_SUPPLY("dig_18", NULL),
	REGULATOR_SUPPLY("d_sensor", NULL),
	REGULATOR_SUPPLY("dig_28", NULL),
	REGULATOR_SUPPLY("a_sensor", NULL),
	REGULATOR_SUPPLY("dig_12", NULL),
};

static struct regulator_init_data m5mols_fixed_voltage_init_data = {
	.constraints = {
		.always_on = 1,
	},
	.num_consumer_supplies	= ARRAY_SIZE(m5mols_fixed_voltage_supplies),
	.consumer_supplies	= m5mols_fixed_voltage_supplies,
};

static struct fixed_voltage_config m5mols_fixed_voltage_config = {
	.supply_name	= "CAM_SENSOR",
	.microvolts	= 1800000,
	.gpio		= -EINVAL,
	.init_data	= &m5mols_fixed_voltage_init_data,
};

static struct platform_device m5mols_fixed_voltage = {
	.name		= "reg-fixed-voltage",
	.id		= 4,
	.dev		= {
		.platform_data	= &m5mols_fixed_voltage_config,
	},
};
#endif

/* audio wm8994/wm1811 configurations */
static struct regulator_consumer_supply wm8994_fixed_voltage0_supplies[] = {
	REGULATOR_SUPPLY("AVDD2", "3-001a"),
	REGULATOR_SUPPLY("CPVDD", "3-001a"),
};

static struct regulator_consumer_supply wm8994_fixed_voltage1_supplies[] = {
	REGULATOR_SUPPLY("SPKVDD1", "3-001a"),
	REGULATOR_SUPPLY("SPKVDD2", "3-001a"),
};

static struct regulator_consumer_supply wm8994_fixed_voltage2_supplies =
	REGULATOR_SUPPLY("DBVDD", "3-001a");

static struct regulator_init_data wm8994_fixed_voltage0_init_data = {
	.constraints = {
		.always_on = 1,
	},
	.num_consumer_supplies	= ARRAY_SIZE(wm8994_fixed_voltage0_supplies),
	.consumer_supplies	= wm8994_fixed_voltage0_supplies,
};

static struct regulator_init_data wm8994_fixed_voltage1_init_data = {
	.constraints = {
		.always_on = 1,
	},
	.num_consumer_supplies	= ARRAY_SIZE(wm8994_fixed_voltage1_supplies),
	.consumer_supplies	= wm8994_fixed_voltage1_supplies,
};

static struct regulator_init_data wm8994_fixed_voltage2_init_data = {
	.constraints = {
		.always_on = 1,
	},
	.num_consumer_supplies	= 1,
	.consumer_supplies	= &wm8994_fixed_voltage2_supplies,
};

static struct fixed_voltage_config wm8994_fixed_voltage0_config = {
	.supply_name	= "VDD_1.8V",
	.microvolts	= 1800000,
	.gpio		= -EINVAL,
	.init_data	= &wm8994_fixed_voltage0_init_data,
};

static struct fixed_voltage_config wm8994_fixed_voltage1_config = {
	.supply_name	= "DC_5V",
	.microvolts	= 5000000,
	.gpio		= -EINVAL,
	.init_data	= &wm8994_fixed_voltage1_init_data,
};

static struct fixed_voltage_config wm8994_fixed_voltage2_config = {
	.supply_name	= "VDD_3.3V",
	.microvolts	= 3300000,
	.gpio		= -EINVAL,
	.init_data	= &wm8994_fixed_voltage2_init_data,
};

static struct platform_device wm8994_fixed_voltage0 = {
	.name		= "reg-fixed-voltage",
	.id		= 0,
	.dev		= {
		.platform_data	= &wm8994_fixed_voltage0_config,
	},
};

static struct platform_device wm8994_fixed_voltage1 = {
	.name		= "reg-fixed-voltage",
	.id		= 1,
	.dev		= {
		.platform_data	= &wm8994_fixed_voltage1_config,
	},
};

static struct platform_device wm8994_fixed_voltage2 = {
	.name		= "reg-fixed-voltage",
	.id		= 2,
	.dev		= {
		.platform_data	= &wm8994_fixed_voltage2_config,
	},
};

static struct regulator_consumer_supply wm8994_avdd1_supply =
	REGULATOR_SUPPLY("AVDD1", "3-001a");

static struct regulator_consumer_supply wm8994_dcvdd_supply =
	REGULATOR_SUPPLY("DCVDD", "3-001a");

static struct regulator_init_data wm8994_ldo1_data = {
	.constraints	= {
		.name		= "AVDD1",
	},
	.num_consumer_supplies	= 1,
	.consumer_supplies	= &wm8994_avdd1_supply,
};

static struct regulator_init_data wm8994_ldo2_data = {
	.constraints	= {
		.name		= "DCVDD",
	},
	.num_consumer_supplies	= 1,
	.consumer_supplies	= &wm8994_dcvdd_supply,
};

static struct wm8994_pdata wm8994_platform_data = {
	/* configure gpio1 function: 0x0001(Logic level input/output) */
	.gpio_defaults[0] = 0x0001,
	/* If the i2s0 and i2s2 is enabled simultaneously */
	.gpio_defaults[7] = 0x8100, /* GPIO8  DACDAT3 in */
	.gpio_defaults[8] = 0x0100, /* GPIO9  ADCDAT3 out */
	.gpio_defaults[9] = 0x0100, /* GPIO10 LRCLK3  out */
	.gpio_defaults[10] = 0x0100,/* GPIO11 BCLK3   out */
	.ldo[0] = { 0, NULL, &wm8994_ldo1_data },
	.ldo[1] = { 0, NULL, &wm8994_ldo2_data },
};

//#ifdef CONFIG_RFKILL
/* Bluetooth rfkill gpio platform data */
struct rfkill_gpio_platform_data arndale_bt_pdata = {
	.reset_gpio	= EXYNOS5_GPX2(7),
	.shutdown_gpio	= -1,
	.type		= RFKILL_TYPE_BLUETOOTH,
	.name		= "arndale-bt",
};

/* Bluetooth Platform device */
static struct platform_device arndale_device_bluetooth = {
	.name		= "rfkill_gpio",
	.id		= -1,
	.dev		= {
		.platform_data	= &arndale_bt_pdata,
	},
};

static void __init arndale_bt_setup(void)
{
	gpio_request(EXYNOS5_GPA0(0), "GPIO BT_UART");
	/* 4 UART Pins configuration */
	s3c_gpio_cfgrange_nopull(EXYNOS5_GPA0(0), 4, S3C_GPIO_SFN(2));
	/* Setup BT Reset, this gpio will be requesed by rfkill-gpio */
	s3c_gpio_cfgpin(EXYNOS5_GPX2(7), S3C_GPIO_OUTPUT);
	s3c_gpio_setpull(EXYNOS5_GPX2(7), S3C_GPIO_PULL_NONE);
}
//#endif

static struct i2c_board_info i2c_devs2[] __initdata = {
#ifdef CONFIG_VIDEO_EXYNOS_TV
	{
		I2C_BOARD_INFO("exynos_hdcp", (0x74 >> 1)),
	},
#endif
};

static struct i2c_board_info i2c_devs3[] __initdata = {
	{
		I2C_BOARD_INFO("pixcir_ts", 0x5C),
	},
	{
		I2C_BOARD_INFO("ak4678", 0x12),
	},
#if defined(CONFIG_SND_SOC_ALC5631)
	{
		I2C_BOARD_INFO("alc5631", 0x1a),
	},
#endif
#if defined(CONFIG_SND_SOC_WM8994)
	{
		I2C_BOARD_INFO("wm8994", 0x1a),
		.platform_data	= &wm8994_platform_data,
	},
#endif
};

struct s3c2410_platform_i2c i2c_data3 __initdata = {
	.bus_num	= 3,
	.flags		= 0,
	.slave_addr	= 0x10,
	.frequency	= 200*1000,
	.sda_delay	= 100,
};

#ifdef CONFIG_INV_SENSORS
static struct i2c_board_info i2c_devs5[] __initdata = {
        {
                I2C_BOARD_INFO("mpu6050", 0x68),
                .irq = IRQ_EINT(10),
                .platform_data = &mpu6050_data,
        },
        {
                I2C_BOARD_INFO("ak8975", 0x0C),
                .irq = IRQ_EINT(5),
                .platform_data = &inv_mpu_ak8975_data,
        },
};
#endif

#ifdef CONFIG_S3C_DEV_HWMON
static struct s3c_hwmon_pdata smdk5250_hwmon_pdata __initdata = {
	/* Reference voltage (1.2V) */
	.in[0] = &(struct s3c_hwmon_chcfg) {
		.name		= "smdk:reference-voltage",
		.mult		= 3300,
		.div		= 4096,
	},
};
#endif

#ifdef CONFIG_ATH6KL_PLATFORM_DATA

#define ARNDALE_WLAN_WOW    EXYNOS5_GPX1(0)
#define ARNDALE_WLAN_RESET  EXYNOS5_GPX3(0)

static void a51h_wlan_setup_power(bool val)
{
        int err;
	printk("a51h_wlan_setup_power ~~~~~~~~~~~~~~~~\n");

        if (val) {
                err = gpio_request_one(ARNDALE_WLAN_RESET,
                                GPIOF_OUT_INIT_LOW, "GPX3_0");
                if (err) {
                        pr_warning("ARNDALE: Not obtain WIFI gpios\n");
                        return;
                }
                s3c_gpio_cfgpin(ARNDALE_WLAN_RESET, S3C_GPIO_OUTPUT);
                s3c_gpio_setpull(ARNDALE_WLAN_RESET,
                                                S3C_GPIO_PULL_NONE);
                /* VDD33,I/O Supply must be done */
                gpio_set_value(ARNDALE_WLAN_WOW, 0);
                gpio_set_value(ARNDALE_WLAN_RESET, 0);
                udelay(30);     /*Tb */
                gpio_direction_output(ARNDALE_WLAN_RESET, 1);
        } else {
                gpio_direction_output(ARNDALE_WLAN_RESET, 0);
                gpio_free(ARNDALE_WLAN_RESET);
        }

        mdelay(100);

        return;
}

/*
#define ARNDALE_BT_RESET    EXYNOS5_GPX2(7)
*/

static int a51h_wifi_set_detect(bool val)
{
/*
        if (!wifi_status_cb) {
                pr_warning("ORIGEN: WLAN: No callback \n"
                "ORIGEN: WLAN: MMC should boot earlier than net \n");

                return -EAGAIN;
        }
*/

	printk("a51h_wifi_set_detect ~~~~~~~~~~~~~~~~\n");

        if (true == val) {
                a51h_wlan_setup_power(true);
//                wifi_status_cb(&s3c_device_hsmmc3, 1);
        } else {
                a51h_wlan_setup_power(false);
//                wifi_status_cb(&s3c_device_hsmmc3, 0);
        }

        return 0;
}

struct ath6kl_platform_data a51h_wlan_data  __initdata = {
        .setup_power = a51h_wifi_set_detect,
};
#endif

static int exynos5_notifier_call(struct notifier_block *this,
		unsigned long code, void *_cmd)
{
	int mode = 0;

	if ((code == SYS_RESTART) && _cmd)
		if (!strcmp((char *)_cmd, "recovery"))
			mode = 0xf;

	__raw_writel(mode, REG_INFORM4);

	return NOTIFY_DONE;
}

static struct notifier_block exynos5_reboot_notifier = {
	.notifier_call = exynos5_notifier_call,
};

static struct resource smdk5250_smsc911x_resources[] = {
	[0] = {
		.start	= EXYNOS4_PA_SROM_BANK(1),
		.end	= EXYNOS4_PA_SROM_BANK(1) + SZ_64K - 1,
		.flags	= IORESOURCE_MEM,
	},
	[1] = {
		.start	= IRQ_EINT(25),
		.end	= IRQ_EINT(25),
		.flags	= IORESOURCE_IRQ | IRQF_TRIGGER_LOW,
	},
};

static struct smsc911x_platform_config smsc9215_config = {
	.irq_polarity	= SMSC911X_IRQ_POLARITY_ACTIVE_LOW,
	.irq_type	= SMSC911X_IRQ_TYPE_PUSH_PULL,
	.flags		= SMSC911X_USE_16BIT | SMSC911X_FORCE_INTERNAL_PHY,
	.phy_interface	= PHY_INTERFACE_MODE_MII,
	.mac		= {0x00, 0x80, 0x00, 0x23, 0x45, 0x67},
};

static struct platform_device smdk5250_smsc911x = {
	.name		= "smsc911x",
	.id		= -1,
	.num_resources	= ARRAY_SIZE(smdk5250_smsc911x_resources),
	.resource	= smdk5250_smsc911x_resources,
	.dev		= {
		.platform_data	= &smsc9215_config,
	},
};

static struct platform_device *arndale_devices[] __initdata = {
	&s3c_device_wdt,
	&s3c_device_i2c2,
	&s3c_device_i2c3,
	&s3c_device_i2c4,
	&s3c_device_i2c5,

	&exynos_device_i2s0,
	&wm8994_fixed_voltage0,
	&wm8994_fixed_voltage1,
	&wm8994_fixed_voltage2,
	&samsung_asoc_dma,
	&samsung_asoc_idma,

#if defined(CONFIG_VIDEO_SAMSUNG_S5P_MFC)
	&s5p_device_mfc,
#endif
#ifdef CONFIG_VIDEO_JPEG_V2X
	&s5p_device_jpeg,
#endif
#ifdef CONFIG_ION_EXYNOS
	&exynos_device_ion,
#endif
#ifdef CONFIG_VIDEO_FIMG2D
	&s5p_device_fimg2d,
#endif
#ifdef CONFIG_EXYNOS_MEDIA_DEVICE
	&exynos_device_md0,
	&exynos_device_md1,
	&exynos_device_md2,
#endif
#ifdef CONFIG_VIDEO_EXYNOS5_FIMC_IS
	&exynos5_device_fimc_is,
#endif
#ifdef CONFIG_VIDEO_EXYNOS_GSCALER
	&exynos5_device_gsc0,
	&exynos5_device_gsc1,
	&exynos5_device_gsc2,
	&exynos5_device_gsc3,
#endif
#ifdef CONFIG_VIDEO_EXYNOS_FIMC_LITE
	&exynos_device_flite0,
	&exynos_device_flite1,
	&exynos_device_flite2,
#endif
#ifdef CONFIG_VIDEO_EXYNOS_MIPI_CSIS
	&s5p_device_mipi_csis0,
	&s5p_device_mipi_csis1,
	&mipi_csi_fixed_voltage,
#endif
#ifdef CONFIG_VIDEO_M5MOLS
	&m5mols_fixed_voltage,
#endif
#ifdef CONFIG_VIDEO_EXYNOS_ROTATOR
	&exynos_device_rotator,
#endif
	&s3c_device_rtc,
#ifdef CONFIG_VIDEO_EXYNOS_TV
#ifdef CONFIG_VIDEO_EXYNOS_HDMI
	&s5p_device_hdmi,
#endif
#ifdef CONFIG_VIDEO_EXYNOS_HDMIPHY
	&s5p_device_i2c_hdmiphy,
#endif
#ifdef CONFIG_VIDEO_EXYNOS_MIXER
	&s5p_device_mixer,
#endif
#ifdef CONFIG_VIDEO_EXYNOS_HDMI_CEC
	&s5p_device_cec,
#endif
#endif
#ifdef CONFIG_S5P_DEV_ACE
	&s5p_device_ace,
#endif
#ifdef CONFIG_EXYNOS_C2C
	&exynos_device_c2c,
#endif
#ifdef CONFIG_EXYNOS_HSI
	&exynos_device_hsi,
#endif
	&exynos5_device_ahci,

//#ifdef CONFIG_RFKILL
	&arndale_device_bluetooth,
//#endif
	&smdk5250_smsc911x,
};

#ifdef CONFIG_VIDEO_EXYNOS_HDMI_CEC
static struct s5p_platform_cec hdmi_cec_data __initdata = {

};
#endif

#if defined(CONFIG_CMA)
static void __init exynos_reserve_mem(void)
{
	static struct cma_region regions[] = {
		{
			.name = "ion",
			.size = 30 * SZ_1M,
			.start = 0
		},
#ifdef CONFIG_VIDEO_SAMSUNG_MEMSIZE_GSC0
		{
			.name = "gsc0",
			.size = CONFIG_VIDEO_SAMSUNG_MEMSIZE_GSC0 * SZ_1K,
			.start = 0
		},
#endif
#ifdef CONFIG_VIDEO_SAMSUNG_MEMSIZE_GSC1
		{
			.name = "gsc1",
			.size = CONFIG_VIDEO_SAMSUNG_MEMSIZE_GSC1 * SZ_1K,
			.start = 0
		},
#endif
#ifdef CONFIG_VIDEO_SAMSUNG_MEMSIZE_GSC2
		{
			.name = "gsc2",
			.size = CONFIG_VIDEO_SAMSUNG_MEMSIZE_GSC2 * SZ_1K,
			.start = 0
		},
#endif
#ifdef CONFIG_VIDEO_SAMSUNG_MEMSIZE_GSC3
		{
			.name = "gsc3",
			.size = CONFIG_VIDEO_SAMSUNG_MEMSIZE_GSC3 * SZ_1K,
			.start = 0
		},
#endif
#ifdef CONFIG_VIDEO_SAMSUNG_MEMSIZE_FLITE0
		{
			.name = "flite0",
			.size = CONFIG_VIDEO_SAMSUNG_MEMSIZE_FLITE0 * SZ_1K,
			.start = 0
		},
#endif
#ifdef CONFIG_VIDEO_SAMSUNG_MEMSIZE_FLITE1
		{
			.name = "flite1",
			.size = CONFIG_VIDEO_SAMSUNG_MEMSIZE_FLITE1 * SZ_1K,
			.start = 0
		},
#endif
#ifdef CONFIG_VIDEO_SAMSUNG_MEMSIZE_FIMD
		{
			.name = "fimd",
			.size = CONFIG_VIDEO_SAMSUNG_MEMSIZE_FIMD * SZ_1K,
			.start = 0
		},
#endif
#ifdef CONFIG_AUDIO_SAMSUNG_MEMSIZE_SRP
		{
			.name = "srp",
			.size = CONFIG_AUDIO_SAMSUNG_MEMSIZE_SRP * SZ_1K,
			.start = 0,
		},
#endif
#ifdef CONFIG_VIDEO_SAMSUNG_S5P_MFC
		{
			.name		= "fw",
			.size		= 2 << 20,
			{ .alignment	= 128 << 10 },
			.start		= 0x44000000,
		},
		{
			.name		= "b1",
			.size		= 64 << 20,
			.start		= 0x45000000,
		},
#endif
#ifdef CONFIG_VIDEO_SAMSUNG_MEMSIZE_TV
		{
			.name = "tv",
			.size = CONFIG_VIDEO_SAMSUNG_MEMSIZE_TV * SZ_1K,
			.start = 0
		},
#endif
#ifdef CONFIG_VIDEO_SAMSUNG_MEMSIZE_ROT
		{
			.name = "rot",
			.size = CONFIG_VIDEO_SAMSUNG_MEMSIZE_ROT * SZ_1K,
			.start = 0,
		},
#endif
#ifdef CONFIG_VIDEO_EXYNOS5_FIMC_IS
		{
			.name = "fimc_is",
			.size = CONFIG_VIDEO_EXYNOS_MEMSIZE_FIMC_IS * SZ_1K,
			{
				.alignment = 1 << 26,
			},
			.start = 0
		},
#endif
#ifdef CONFIG_EXYNOS_CONTENT_PATH_PROTECTION
#ifdef CONFIG_ION_EXYNOS_DRM_MFC_SH
		{
			.name = "drm_mfc_sh",
			.size = SZ_1M,
		},
#endif
#endif
		{
			.size = 0
		},
	};
#ifdef CONFIG_EXYNOS_CONTENT_PATH_PROTECTION
	static struct cma_region regions_secure[] = {
#ifdef CONFIG_ION_EXYNOS_DRM_VIDEO
		{
			.name = "drm_video",
			.size = (
#ifdef CONFIG_ION_EXYNOS_DRM_MEMSIZE_FIMD_VIDEO
				CONFIG_ION_EXYNOS_DRM_MEMSIZE_FIMD_VIDEO +
#endif
#ifdef CONFIG_ION_EXYNOS_DRM_MEMSIZE_GSC
				CONFIG_ION_EXYNOS_DRM_MEMSIZE_GSC +
#endif
#ifdef CONFIG_ION_EXYNOS_DRM_MEMSIZE_MFC_SECURE
				CONFIG_ION_EXYNOS_DRM_MEMSIZE_MFC_SECURE +
#endif
				0) * SZ_1K,
		},
#endif
#ifdef CONFIG_ION_EXYNOS_DRM_MFC_FW
		{
			.name = "drm_mfc_fw",
			.size = SZ_1M,
		},
#endif
#ifdef CONFIG_ION_EXYNOS_DRM_SECTBL
		{
			.name = "drm_sectbl",
			.size = SZ_1M,
		},
#endif
		{
			.size = 0
		},
	};
#else /* !CONFIG_EXYNOS_CONTENT_PATH_PROTECTION */
	struct cma_region *regions_secure = NULL;
#endif /* CONFIG_EXYNOS_CONTENT_PATH_PROTECTION */
	static const char map[] __initconst =
#ifdef CONFIG_EXYNOS_C2C
		"samsung-c2c=c2c_shdmem;"
#endif
		"s3cfb.0=fimd;exynos5-fb.1=fimd;"
		"samsung-rp=srp;"
		"exynos-gsc.0=gsc0;exynos-gsc.1=gsc1;exynos-gsc.2=gsc2;exynos-gsc.3=gsc3;"
		"exynos-fimc-lite.0=flite0;exynos-fimc-lite.1=flite1;"
#ifdef CONFIG_EXYNOS_CONTENT_PATH_PROTECTION
		"ion-exynos/mfc_sh=drm_mfc_sh;"
		"ion-exynos/video=drm_video;"
		"ion-exynos/mfc_fw=drm_mfc_fw;"
		"ion-exynos/sectbl=drm_sectbl;"
		"s5p-smem/mfc_sh=drm_mfc_sh;"
		"s5p-smem/video=drm_video;"
		"s5p-smem/mfc_fw=drm_mfc_fw;"
		"s5p-smem/sectbl=drm_sectbl;"
#endif
		"ion-exynos=ion,gsc0,gsc1,gsc2,gsc3,flite0,flite1,fimd,fw,b1,rot;"
		"exynos-rot=rot;"
		"s5p-mfc-v6/f=fw;"
		"s5p-mfc-v6/a=b1;"
		"s5p-mixer=tv;"
		"exynos5-fimc-is=fimc_is;";

	s5p_cma_region_reserve(regions, regions_secure, 0, map);
}
#else /* !CONFIG_CMA*/
static inline void exynos_reserve_mem(void)
{
}
#endif

#ifdef CONFIG_VIDEO_EXYNOS_FIMC_LITE
static void __init smdk5250_camera_gpio_cfg(void)
{
	/* CAM A port(b0010) : PCLK, VSYNC, HREF, CLK_OUT */
	s3c_gpio_cfgrange_nopull(EXYNOS5_GPH0(0), 4, S3C_GPIO_SFN(2));
	/* CAM A port(b0010) : DATA[0-7] */
	s3c_gpio_cfgrange_nopull(EXYNOS5_GPH1(0), 8, S3C_GPIO_SFN(2));
	/* CAM B port(b0010) : PCLK, BAY_RGB[0-6] */
	s3c_gpio_cfgrange_nopull(EXYNOS5_GPG0(0), 8, S3C_GPIO_SFN(2));
	/* CAM B port(b0010) : BAY_Vsync, BAY_RGB[7-13] */
	s3c_gpio_cfgrange_nopull(EXYNOS5_GPG1(0), 8, S3C_GPIO_SFN(2));
	/* CAM B port(b0010) : BAY_Hsync, BAY_MCLK */
	s3c_gpio_cfgrange_nopull(EXYNOS5_GPG2(0), 2, S3C_GPIO_SFN(2));
	/* This is externel interrupt for m5mo */
#ifdef CONFIG_VIDEO_M5MOLS
	s3c_gpio_cfgpin(EXYNOS5_GPX2(6), S3C_GPIO_SFN(0xF));
	s3c_gpio_setpull(EXYNOS5_GPX2(6), S3C_GPIO_PULL_NONE);
#endif
}
#endif

#if defined(CONFIG_VIDEO_EXYNOS_GSCALER) && defined(CONFIG_VIDEO_EXYNOS_FIMC_LITE)
#if defined(CONFIG_VIDEO_S5K4BA)
static struct exynos_isp_info s5k4ba = {
	.board_info	= &s5k4ba_info,
	.cam_srclk_name	= "xxti",
	.clk_frequency  = 24000000UL,
	.bus_type	= CAM_TYPE_ITU,
#ifdef CONFIG_ITU_A
	.cam_clk_name	= "sclk_cam0",
	.i2c_bus_num	= 4,
	.cam_port	= CAM_PORT_A, /* A-Port : 0, B-Port : 1 */
#endif
#ifdef CONFIG_ITU_B
	.cam_clk_name	= "sclk_cam1",
	.i2c_bus_num	= 5,
	.cam_port	= CAM_PORT_B, /* A-Port : 0, B-Port : 1 */
#endif
	.flags		= CAM_CLK_INV_VSYNC,
};
/* This is for platdata of fimc-lite */
static struct s3c_platform_camera flite_s5k4ba = {
	.type		= CAM_TYPE_MIPI,
	.use_isp	= true,
	.inv_pclk	= 1,
	.inv_vsync	= 1,
	.inv_href	= 0,
	.inv_hsync	= 0,
};
#endif
#if defined(CONFIG_VIDEO_M5MOLS)
static struct exynos_isp_info m5mols = {
	.board_info	= &m5mols_board_info,
	.cam_srclk_name	= "xxti",
	.clk_frequency  = 24000000UL,
	.bus_type	= CAM_TYPE_MIPI,
#ifdef CONFIG_CSI_C
	.cam_clk_name	= "sclk_cam0",
	.i2c_bus_num	= 4,
	.cam_port	= CAM_PORT_A, /* A-Port : 0, B-Port : 1 */
#endif
#ifdef CONFIG_CSI_D
	.cam_clk_name	= "sclk_cam1",
	.i2c_bus_num	= 5,
	.cam_port	= CAM_PORT_B, /* A-Port : 0, B-Port : 1 */
#endif
	.flags		= CAM_CLK_INV_PCLK | CAM_CLK_INV_VSYNC,
	.csi_data_align = 32,
};
/* This is for platdata of fimc-lite */
static struct s3c_platform_camera flite_m5mo = {
	.type		= CAM_TYPE_MIPI,
	.use_isp	= true,
	.inv_pclk	= 1,
	.inv_vsync	= 1,
	.inv_href	= 0,
	.inv_hsync	= 0,
};
#endif

static void __set_gsc_camera_config(struct exynos_platform_gscaler *data,
					u32 active_index, u32 preview,
					u32 camcording, u32 max_cam)
{
	data->active_cam_index = active_index;
	data->cam_preview = preview;
	data->cam_camcording = camcording;
	data->num_clients = max_cam;
}

static void __set_flite_camera_config(struct exynos_platform_flite *data,
					u32 active_index, u32 max_cam)
{
	data->active_cam_index = active_index;
	data->num_clients = max_cam;
}

static void __init smdk5250_set_camera_platdata(void)
{
	int gsc_cam_index = 0;
	int flite0_cam_index = 0;
	int flite1_cam_index = 0;
#if defined(CONFIG_VIDEO_M5MOLS)
	exynos_gsc0_default_data.isp_info[gsc_cam_index++] = &m5mols;
#if defined(CONFIG_CSI_C)
	exynos_flite0_default_data.cam[flite0_cam_index] = &flite_m5mo;
	exynos_flite0_default_data.isp_info[flite0_cam_index] = &m5mols;
	flite0_cam_index++;
#endif
#if defined(CONFIG_CSI_D)
	exynos_flite1_default_data.cam[flite1_cam_index] = &flite_m5mo;
	exynos_flite1_default_data.isp_info[flite1_cam_index] = &m5mols;
	flite1_cam_index++;
#endif
#endif
	/* flite platdata register */
	__set_flite_camera_config(&exynos_flite0_default_data, 0, flite0_cam_index);
	__set_flite_camera_config(&exynos_flite1_default_data, 0, flite1_cam_index);

	/* gscaler platdata register */
	/* GSC-0 */
	__set_gsc_camera_config(&exynos_gsc0_default_data, 0, 1, 0, gsc_cam_index);

	/* GSC-1 */
	/* GSC-2 */
	/* GSC-3 */
}
#endif /* CONFIG_VIDEO_EXYNOS_GSCALER */

#if defined(CONFIG_VIDEO_SAMSUNG_S5P_MFC)
static struct s5p_mfc_platdata smdk5250_mfc_pd = {
	.clock_rate = 333000000,
	.lock_thrd_w = 1920,
	.lock_thrd_h = 1080,
	.lock_freq_mem = 100,
	.lock_freq_bus = 160,
};
#endif

static void __init arndale_map_io(void)
{
	clk_xxti.rate = 24000000;
	s5p_init_io(NULL, 0, S5P_VA_CHIPID);
	s3c24xx_init_clocks(24000000);
	s3c24xx_init_uarts(arndale_uartcfgs, ARRAY_SIZE(arndale_uartcfgs));
	exynos_reserve_mem();
}

#ifdef CONFIG_EXYNOS_DEV_SYSMMU
static void __init exynos_sysmmu_init(void)
{
#ifdef CONFIG_VIDEO_JPEG_V2X
	platform_set_sysmmu(&SYSMMU_PLATDEV(jpeg).dev, &s5p_device_jpeg.dev);
#endif
#if defined(CONFIG_VIDEO_SAMSUNG_S5P_MFC)
	platform_set_sysmmu(&SYSMMU_PLATDEV(mfc_lr).dev, &s5p_device_mfc.dev);
#endif
#if defined(CONFIG_VIDEO_EXYNOS_TV)
	platform_set_sysmmu(&SYSMMU_PLATDEV(tv).dev, &s5p_device_mixer.dev);
#endif
#ifdef CONFIG_VIDEO_EXYNOS_GSCALER
	platform_set_sysmmu(&SYSMMU_PLATDEV(gsc0).dev,
						&exynos5_device_gsc0.dev);
	platform_set_sysmmu(&SYSMMU_PLATDEV(gsc1).dev,
						&exynos5_device_gsc1.dev);
	platform_set_sysmmu(&SYSMMU_PLATDEV(gsc2).dev,
						&exynos5_device_gsc2.dev);
	platform_set_sysmmu(&SYSMMU_PLATDEV(gsc3).dev,
						&exynos5_device_gsc3.dev);
#endif
#ifdef CONFIG_VIDEO_EXYNOS_FIMC_LITE
	platform_set_sysmmu(&SYSMMU_PLATDEV(camif0).dev,
						&exynos_device_flite0.dev);
	platform_set_sysmmu(&SYSMMU_PLATDEV(camif1).dev,
						&exynos_device_flite1.dev);
#endif
#ifdef CONFIG_VIDEO_EXYNOS_ROTATOR
	platform_set_sysmmu(&SYSMMU_PLATDEV(rot).dev,
						&exynos_device_rotator.dev);
#endif
#ifdef CONFIG_VIDEO_FIMG2D
	platform_set_sysmmu(&SYSMMU_PLATDEV(2d).dev, &s5p_device_fimg2d.dev);
#endif
#ifdef CONFIG_VIDEO_EXYNOS5_FIMC_IS
	platform_set_sysmmu(&SYSMMU_PLATDEV(isp).dev,
						&exynos5_device_fimc_is.dev);
#endif
}
#else /* !CONFIG_EXYNOS_DEV_SYSMMU */
static inline void exynos_sysmmu_init(void)
{
}
#endif

static int smdk5250_uhostphy_reset(void)
{
	int err;
	err = gpio_request(EXYNOS5_GPX3(5), "GPX3");
	if (!err) {
		gpio_direction_output(EXYNOS5_GPX3(5), 1);
		gpio_set_value(EXYNOS5_GPX3(5), 1);
		s3c_gpio_setpull(EXYNOS5_GPX3(5), S3C_GPIO_PULL_UP);
		gpio_free(EXYNOS5_GPX3(5));
	}
	
	err = gpio_request(EXYNOS5_GPD1(7), "GPD1");
	if (!err) {
		gpio_direction_output(EXYNOS5_GPD1(7), 1);
		gpio_set_value(EXYNOS5_GPD1(7), 1);
		s3c_gpio_setpull(EXYNOS5_GPD1(7), S3C_GPIO_PULL_UP);
		gpio_free(EXYNOS5_GPD1(7));
	}

	return 0;
}

#define SMDK5250_REV_0_0_ADC_VALUE 0
#define SMDK5250_REV_0_2_ADC_VALUE 500

#define PMUREG_ISP_CONFIGURATION	(S5P_VA_PMU  + 0x4020)
#define PMUREG_ISP_STATUS		(S5P_VA_PMU  + 0x4024)

int samsung_board_rev;

static int get_samsung_board_rev(void)
{
	int ret = 0;
	int adc_val = 0;
	void __iomem *adc_regs;
	unsigned int timeout, con;

	writel(0x7, PMUREG_ISP_CONFIGURATION);
	timeout = 1000;
	while ((__raw_readl(PMUREG_ISP_STATUS) & 0x7) != 0x7) {
		if (timeout == 0)
			err("A5 power on failed1\n");
		timeout--;
		udelay(1);
		goto err_power;
	}
	__raw_writel(0x1, EXYNOS5_MTCADC_PHY_CONTROL);

	__raw_writel(0x00000031, EXYNOS5_CLKDIV_ISP0);
	__raw_writel(0x00000031, EXYNOS5_CLKDIV_ISP1);
	__raw_writel(0x00000001, EXYNOS5_CLKDIV_ISP2);

	__raw_writel(0xDFF000FF, EXYNOS5_CLKGATE_ISP0);
	__raw_writel(0x00003007, EXYNOS5_CLKGATE_ISP1);

	adc_regs = ioremap(EXYNOS5_PA_FIMC_IS_ADC, SZ_4K);
	if (unlikely(!adc_regs))
		goto err_power;

	/* SELMUX Channel 3 */
	writel(S5PV210_ADCCON_SELMUX(3), adc_regs + S5P_ADCMUX);

	con = readl(adc_regs + S3C2410_ADCCON);
	con &= ~S3C2410_ADCCON_MUXMASK;
	con &= ~S3C2410_ADCCON_STDBM;
	con &= ~S3C2410_ADCCON_STARTMASK;
	con |=  S3C2410_ADCCON_PRSCEN;

	/* ENABLE START */
	con |= S3C2410_ADCCON_ENABLE_START;
	writel(con, adc_regs + S3C2410_ADCCON);

	udelay (50);

	/* Read Data*/
	adc_val = readl(adc_regs + S3C2410_ADCDAT0) & 0xFFF;
	/* CLRINT */
	writel(0, adc_regs + S3C64XX_ADCCLRINT);

	iounmap(adc_regs);
err_power:
	ret = (adc_val < SMDK5250_REV_0_2_ADC_VALUE/2) ?
			SAMSUNG_BOARD_REV_0_0 : SAMSUNG_BOARD_REV_0_2;

	pr_info ("SMDK MAIN Board Rev 0.%d (ADC value:%d)\n", ret, adc_val);
	return ret;
}

static void __init sromc_setup(void)
{
        s3c_gpio_cfgpin(EXYNOS5_GPY0(1), S3C_GPIO_SFN(2));    // GPY0: control
        s3c_gpio_cfgpin(EXYNOS5_GPY0(4), S3C_GPIO_SFN(2));
        s3c_gpio_cfgpin(EXYNOS5_GPY0(5), S3C_GPIO_SFN(2));
       
        s3c_gpio_cfgall_range(EXYNOS5_GPY1(0), 4, S3C_GPIO_SFN(2), S3C_GPIO_PULL_UP);    // GPY1: control
        s3c_gpio_cfgall_range(EXYNOS5_GPY3(0), 8, S3C_GPIO_SFN(2), S3C_GPIO_PULL_UP);    // GPY3: ADR0~7
        s3c_gpio_cfgall_range(EXYNOS5_GPY4(0), 8, S3C_GPIO_SFN(2), S3C_GPIO_PULL_UP);    // GPY4: ADR7~15
        s3c_gpio_cfgall_range(EXYNOS5_GPY5(0), 8, S3C_GPIO_SFN(2), S3C_GPIO_PULL_UP);    // GPY5: D0~7
        s3c_gpio_cfgall_range(EXYNOS5_GPY6(0), 8, S3C_GPIO_SFN(2), S3C_GPIO_PULL_UP);    // GPY6: D8~15

        // set ethernet CS as Low
        s3c_gpio_cfgpin(EXYNOS5_GPY2(0), S3C_GPIO_OUTPUT);
        s3c_gpio_setpull(EXYNOS5_GPY2(0), S3C_GPIO_PULL_DOWN);
}

static void __init smdk5250_smsc911x_init(void)
{
	u32 cs;
	u32 xxx;

	sromc_setup();

	cs = 0x99;
	xxx = 0x11061C91;    // uboot
	//    xxx = 0x140E1C90;    // 5250 kernel   

	__raw_writel(cs, S5P_SROM_BW);
	__raw_writel(xxx, S5P_SROM_BC1);
        printk("smsc: S5P_SROM_BW set %08X, read %08X\n", cs, __raw_readl(S5P_SROM_BW) );
        printk("smsc: S5P_SROM_BC1 set %08X, read %08X\n", xxx, __raw_readl(S5P_SROM_BC1) );
       
        printk("smsc: S5P_PA_SROMC=%08X\n", S5P_PA_SROMC);
        printk("smsc: S5P_VA_SROMC=%08X\n", (unsigned int)S5P_VA_SROMC);
       
        printk("smsc: pa->va S5P_PA_SROMC=%08X\n", (unsigned int)phys_to_virt(S5P_PA_SROMC));
        printk("smsc: va->pa S5P_VA_SROMC=%08X\n", virt_to_phys(S5P_VA_SROMC));
        printk("smsc: pa->va 0x12250000=%08X\n", (unsigned int)phys_to_virt(0x12250000));
        printk("smsc: va->pa 0x92250000=%08X\n", virt_to_phys((void*)0x92250000));
       
        printk("smsc: S5P_SROM_BW=%08X\n", (unsigned int)S5P_SROM_BW);
        printk("smsc: S5P_SROM_BC1=%08X\n", (unsigned int)S5P_SROM_BC1);
}

static void __init arndale_machine_init(void)
{
	samsung_board_rev = get_samsung_board_rev();

	exynos5_smdk5250_mmc_init();
	exynos5_smdk5250_power_init();
	exynos5_smdk5250_usb_init();
	exynos5_smdk5250_input_init();

	s3c_i2c2_set_platdata(NULL);
	i2c_register_board_info(2, i2c_devs2, ARRAY_SIZE(i2c_devs2));

	s3c_i2c3_set_platdata(&i2c_data3);
	if (samsung_board_rev_is_0_0())
		i2c_devs3[0].irq = IRQ_EINT(21);
	else
		i2c_devs3[0].irq = IRQ_EINT(18);
	i2c_register_board_info(3, i2c_devs3, ARRAY_SIZE(i2c_devs3));

	s3c_i2c4_set_platdata(NULL);
	s3c_i2c5_set_platdata(NULL);
#ifdef CONFIG_INV_SENSORS
	i2c_register_board_info(5, i2c_devs5, ARRAY_SIZE(i2c_devs5));
#endif

#ifdef CONFIG_ION_EXYNOS
	exynos_ion_set_platdata();
#endif

	if (samsung_rev() >= EXYNOS5250_REV_1_0) {
		platform_device_register(&s3c_device_adc);
#ifdef CONFIG_S3C_DEV_HWMON
		platform_device_register(&s3c_device_hwmon);
#endif
	}

#ifdef CONFIG_S3C_DEV_HWMON
	if (samsung_rev() >= EXYNOS5250_REV_1_0)
		s3c_hwmon_set_platdata(&smdk5250_hwmon_pdata);
#endif

#if defined(CONFIG_VIDEO_SAMSUNG_S5P_MFC)
#if defined(CONFIG_EXYNOS_DEV_PD)
	s5p_device_mfc.dev.parent = &exynos5_device_pd[PD_MFC].dev;
#endif
	s5p_mfc_set_platdata(&smdk5250_mfc_pd);

	dev_set_name(&s5p_device_mfc.dev, "s3c-mfc");
	clk_add_alias("mfc", "s5p-mfc-v6", "mfc", &s5p_device_mfc.dev);
	s5p_mfc_setname(&s5p_device_mfc, "s5p-mfc-v6");
#endif

#ifdef CONFIG_VIDEO_FIMG2D
	s5p_fimg2d_set_platdata(&fimg2d_data);
#endif
	exynos_sysmmu_init();

	platform_add_devices(arndale_devices, ARRAY_SIZE(arndale_devices));

	exynos5_smdk5250_display_init();

#ifdef CONFIG_VIDEO_EXYNOS_MIPI_CSIS
#if defined(CONFIG_EXYNOS_DEV_PD)
	s5p_device_mipi_csis0.dev.parent = &exynos5_device_pd[PD_GSCL].dev;
	s5p_device_mipi_csis1.dev.parent = &exynos5_device_pd[PD_GSCL].dev;
#endif
	s3c_set_platdata(&s5p_mipi_csis0_default_data,
			sizeof(s5p_mipi_csis0_default_data), &s5p_device_mipi_csis0);
	s3c_set_platdata(&s5p_mipi_csis1_default_data,
			sizeof(s5p_mipi_csis1_default_data), &s5p_device_mipi_csis1);
#endif
#ifdef CONFIG_VIDEO_EXYNOS_FIMC_LITE
#if defined(CONFIG_EXYNOS_DEV_PD)
	exynos_device_flite0.dev.parent = &exynos5_device_pd[PD_GSCL].dev;
	exynos_device_flite1.dev.parent = &exynos5_device_pd[PD_GSCL].dev;
	exynos_device_flite2.dev.parent = &exynos5_device_pd[PD_GSCL].dev;
#endif
	smdk5250_camera_gpio_cfg();
	smdk5250_set_camera_platdata();
	s3c_set_platdata(&exynos_flite0_default_data,
			sizeof(exynos_flite0_default_data), &exynos_device_flite0);
	s3c_set_platdata(&exynos_flite1_default_data,
			sizeof(exynos_flite1_default_data), &exynos_device_flite1);
	s3c_set_platdata(&exynos_flite2_default_data,
			sizeof(exynos_flite2_default_data), &exynos_device_flite2);
/* In EVT0, for using camclk, gscaler clock should be enabled */
	if (samsung_rev() < EXYNOS5250_REV_1_0) {
		dev_set_name(&exynos_device_flite0.dev, "exynos-gsc.0");
		clk_add_alias("gscl", "exynos-fimc-lite.0", "gscl",
				&exynos_device_flite0.dev);
		dev_set_name(&exynos_device_flite0.dev, "exynos-fimc-lite.0");

		dev_set_name(&exynos_device_flite1.dev, "exynos-gsc.0");
		clk_add_alias("gscl", "exynos-fimc-lite.1", "gscl",
				&exynos_device_flite1.dev);
		dev_set_name(&exynos_device_flite1.dev, "exynos-fimc-lite.1");
	}
#endif
#if defined CONFIG_VIDEO_EXYNOS5_FIMC_IS
	dev_set_name(&exynos5_device_fimc_is.dev, "s5p-mipi-csis.0");
	clk_add_alias("gscl_wrap0", "exynos5-fimc-is", "gscl_wrap0", &exynos5_device_fimc_is.dev);
	clk_add_alias("sclk_gscl_wrap0", "exynos5-fimc-is", "sclk_gscl_wrap0", &exynos5_device_fimc_is.dev);
	dev_set_name(&exynos5_device_fimc_is.dev, "s5p-mipi-csis.1");
	clk_add_alias("gscl_wrap1", "exynos5-fimc-is", "gscl_wrap1", &exynos5_device_fimc_is.dev);
	clk_add_alias("sclk_gscl_wrap1", "exynos5-fimc-is", "sclk_gscl_wrap1", &exynos5_device_fimc_is.dev);
	dev_set_name(&exynos5_device_fimc_is.dev, "exynos-gsc.0");
	clk_add_alias("gscl", "exynos5-fimc-is", "gscl", &exynos5_device_fimc_is.dev);
	dev_set_name(&exynos5_device_fimc_is.dev, "exynos5-fimc-is");

#if defined CONFIG_VIDEO_S5K6A3
	exynos5_fimc_is_data.sensor_info[s5k6a3.sensor_position] = &s5k6a3;
	printk("add s5k6a3 sensor info(pos : %d)\n", s5k6a3.sensor_position);
#endif
#if defined CONFIG_VIDEO_S5K4E5
	exynos5_fimc_is_data.sensor_info[s5k4e5.sensor_position] = &s5k4e5;
	printk("add s5k4e5 sensor info(pos : %d)\n", s5k4e5.sensor_position);
#endif
#if defined CONFIG_VIDEO_S5K3H7
	exynos5_fimc_is_data.sensor_info[s5k3h7.sensor_position] = &s5k3h7;
	printk("add s5k3h7 sensor info(pos : %d)\n", s5k3h7.sensor_position);
#endif

	exynos5_fimc_is_set_platdata(&exynos5_fimc_is_data);
#if defined(CONFIG_EXYNOS_DEV_PD)
	exynos5_device_pd[PD_ISP].dev.parent = &exynos5_device_pd[PD_GSCL].dev;
	exynos5_device_fimc_is.dev.parent = &exynos5_device_pd[PD_ISP].dev;
#endif
#endif
#ifdef CONFIG_VIDEO_EXYNOS_GSCALER
#if defined(CONFIG_EXYNOS_DEV_PD)
	exynos5_device_gsc0.dev.parent = &exynos5_device_pd[PD_GSCL].dev;
	exynos5_device_gsc1.dev.parent = &exynos5_device_pd[PD_GSCL].dev;
	exynos5_device_gsc2.dev.parent = &exynos5_device_pd[PD_GSCL].dev;
	exynos5_device_gsc3.dev.parent = &exynos5_device_pd[PD_GSCL].dev;
#endif
#ifdef CONFIG_EXYNOS_CONTENT_PATH_PROTECTION
	secmem.parent = &exynos5_device_pd[PD_GSCL].dev;
#endif
	if (samsung_rev() >= EXYNOS5250_REV_1_0) {
		exynos5_gsc_set_pdev_name(0, "exynos5250-gsc");
		exynos5_gsc_set_pdev_name(1, "exynos5250-gsc");
		exynos5_gsc_set_pdev_name(2, "exynos5250-gsc");
		exynos5_gsc_set_pdev_name(3, "exynos5250-gsc");
	}

	s3c_set_platdata(&exynos_gsc0_default_data, sizeof(exynos_gsc0_default_data),
			&exynos5_device_gsc0);
	s3c_set_platdata(&exynos_gsc1_default_data, sizeof(exynos_gsc1_default_data),
			&exynos5_device_gsc1);
	s3c_set_platdata(&exynos_gsc2_default_data, sizeof(exynos_gsc2_default_data),
			&exynos5_device_gsc2);
	s3c_set_platdata(&exynos_gsc3_default_data, sizeof(exynos_gsc3_default_data),
			&exynos5_device_gsc3);
#endif
#ifdef CONFIG_EXYNOS_C2C
	exynos_c2c_set_platdata(&smdk5250_c2c_pdata);
#endif

#ifdef CONFIG_EXYNOS_HSI
	exynos_hsi_set_platdata(&smdk5250_hsi_pdata);
#endif

#ifdef CONFIG_VIDEO_JPEG_V2X
	exynos5_jpeg_setup_clock(&s5p_device_jpeg.dev, 150000000);
#endif

#ifdef CONFIG_SND_SAMSUNG_I2S
#if defined(CONFIG_EXYNOS_DEV_PD)
	exynos_device_i2s0.dev.parent = &exynos5_device_pd[PD_MAUDIO].dev;
#endif
#endif

#if defined(CONFIG_VIDEO_EXYNOS_TV) && defined(CONFIG_VIDEO_EXYNOS_HDMI)
	dev_set_name(&s5p_device_hdmi.dev, "exynos5-hdmi");
	clk_add_alias("hdmi", "s5p-hdmi", "hdmi", &s5p_device_hdmi.dev);
	clk_add_alias("hdmiphy", "s5p-hdmi", "hdmiphy", &s5p_device_hdmi.dev);

	s5p_tv_setup();

/* setup dependencies between TV devices */
	/* This will be added after power domain for exynos5 is developed */
	s5p_device_hdmi.dev.parent = &exynos5_device_pd[PD_DISP1].dev;
	s5p_device_mixer.dev.parent = &exynos5_device_pd[PD_DISP1].dev;

	s5p_i2c_hdmiphy_set_platdata(NULL);
#ifdef CONFIG_VIDEO_EXYNOS_HDMI_CEC
	s5p_hdmi_cec_set_platdata(&hdmi_cec_data);
#endif
#endif

#ifdef CONFIG_ATH6KL_PLATFORM_DATA
    ath6kl_set_platform_data(&a51h_wlan_data);
#endif

//#ifdef CONFIG_RFKILL
	arndale_bt_setup();
//#endif

	smdk5250_uhostphy_reset();

	register_reboot_notifier(&exynos5_reboot_notifier);

	smdk5250_smsc911x_init();
}

#ifdef CONFIG_EXYNOS_C2C
static void __init exynos_c2c_reserve(void)
{
	static struct cma_region regions[] = {
		{
			.name = "c2c_shdmem",
			.size = 64 * SZ_1M,
			{ .alignment	= 64 * SZ_1M },
			.start = C2C_SHAREDMEM_BASE
		}, {
			.size = 0,
		}
	};

	s5p_cma_region_reserve(regions, NULL, 0, NULL);
}
#endif

static void __init arndale_fixup(struct machine_desc *desc,
				struct tag *tags, char **cmdline,
				struct meminfo *mi)
{
	mi->bank[0].start = 0x40000000;
	mi->bank[0].size = 1024 * SZ_1M;

	mi->bank[1].start = 0x80000000;
	mi->bank[1].size = 1023 * SZ_1M;

	mi->nr_banks = 2;
}

MACHINE_START(ARNDALE, "ARNDALE")
	.boot_params	= S5P_PA_SDRAM + 0x100,
	.init_irq	= exynos5_init_irq,
	.fixup		= arndale_fixup,
	.map_io		= arndale_map_io,
	.init_machine	= arndale_machine_init,
	.timer		= &exynos4_timer,
#ifdef CONFIG_EXYNOS_C2C
	.reserve	= &exynos_c2c_reserve,
#endif
MACHINE_END
