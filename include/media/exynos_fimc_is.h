/* linux/arch/arm/plat-s5p/include/plat/fimc_is.h
 *
 * Copyright (C) 2011 Samsung Electronics, Co. Ltd
 *
 * Exynos 4 series FIMC-IS slave device support
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef EXYNOS_FIMC_IS_H_
#define EXYNOS_FIMC_IS_H_ __FILE__

#include <linux/videodev2.h>

#define FIMC_IS_MAX_CAMIF_CLIENTS	2
#define FIMC_IS_MAX_SENSOR_NAME_LEN	16
#define EXYNOS4_FIMC_IS_MAX_DIV_CLOCKS		2
#define EXYNOS4_FIMC_IS_MAX_CONTROL_CLOCKS	16

#define UART_ISP_SEL		0
#define UART_ISP_RATIO		1

#define to_fimc_is_plat(d)	(to_platform_device(d)->dev.platform_data)

#if defined(CONFIG_ARCH_EXYNOS5)
enum exynos5_csi_id {
	CSI_ID_A = 0,
	CSI_ID_B
};

enum exynos5_flite_id {
	FLITE_ID_A = 0,
	FLITE_ID_B
};

enum exynos5_sensor_position {
	SENSOR_POSITION_REAR = 0,
	SENSOR_POSITION_FRONT
};
enum exynos5_sensor_id {
	SENSOR_NAME_S5K3H2	= 1,
	SENSOR_NAME_S5K6A3	= 2,
	SENSOR_NAME_S5K4E5	= 3,
	SENSOR_NAME_S5K3H7	= 4,
	SENSOR_NAME_CUSTOM	= 100,
	SENSOR_NAME_END
};

enum actuator_name {
	ACTUATOR_NAME_AD5823	= 1,
	ACTUATOR_NAME_DWXXXX	= 2,
	ACTUATOR_NAME_AK7343	= 3,
	ACTUATOR_NAME_HYBRIDVCA	= 4,
	ACTUATOR_NAME_NOTHING	= 100,
	ACTUATOR_NAME_END
};

enum flash_drv_name {
	FLADRV_NAME_KTD267	= 1,
	FLADRV_NAME_NOTHING	= 100,
	FLADRV_NAME_END
};

enum from_name {
	FROMDRV_NAME_W25Q80BW	= 1,
	FROMDRV_NAME_NOTHING
};

enum sensor_peri_type {
	SE_I2C,
	SE_SPI,
	SE_GPIO,
	SE_MPWM,
	SE_ADC,
	SE_NULL
};

typedef union sensor_peri_format_union {
    struct {
        u32 channel;
        u32 slave_address;
        u32 speed;
    } i2c;

    struct {
        u32 channel;
    } spi;

    struct {
        u32 first_gpio_port_no;
        u32 second_gpio_port_no;
    } gpio;
} sensor_peri_format;

typedef struct {
	u32 product_name;
	enum sensor_peri_type peri_type;
	sensor_peri_format peri_setting;
} sensor_protocol, *psensor_protocol;

enum exynos5_sensor_channel {
	SENSOR_CONTROL_I2C0	= 0,
	SENSOR_CONTROL_I2C1	= 1
};
#endif

struct platform_device;

#if defined(CONFIG_ARCH_EXYNOS5)
/**
 * struct exynos5_fimc_is_sensor_info  - image sensor information required for host
 *			      interace configuration.
*/
struct exynos5_fimc_is_sensor_info {
	char sensor_name[FIMC_IS_MAX_SENSOR_NAME_LEN];
	enum exynos5_sensor_position sensor_position;
	enum exynos5_sensor_id sensor_id;
	enum exynos5_csi_id csi_id;
	enum exynos5_flite_id flite_id;
	enum exynos5_sensor_channel i2c_channel;

	int max_width;
	int max_height;
	int max_frame_rate;


	int mipi_lanes;     /* MIPI data lanes */
	int mipi_settle;    /* MIPI settle */
	int mipi_align;     /* MIPI data align: 24/32 */
};

struct sensor_open_extended {
	sensor_protocol actuator_con;
	sensor_protocol flash_con;
	sensor_protocol from_con;

	u32 mclk;
	u32 mipi_lane_num;
	u32 mipi_speed;
	/* Skip setfile loading when fast_open_sensor is not 0 */
	u32 fast_open_sensor;
	/* Activatiing sensor self calibration mode (6A3) */
	u32 self_calibration_mode;
};

#endif
/**
 * struct exynos4_platform_fimc_is - camera host interface platform data
 *
 * @isp_info: properties of camera sensor required for host interface setup
*/
struct exynos4_platform_fimc_is {
	int	hw_ver;
	struct clk	*div_clock[EXYNOS4_FIMC_IS_MAX_DIV_CLOCKS];
	struct clk	*control_clock[EXYNOS4_FIMC_IS_MAX_CONTROL_CLOCKS];
	void	(*cfg_gpio)(struct platform_device *pdev);
	int	(*clk_get)(struct platform_device *pdev);
	int	(*clk_put)(struct platform_device *pdev);
	int	(*clk_cfg)(struct platform_device *pdev);
	int	(*clk_on)(struct platform_device *pdev);
	int	(*clk_off)(struct platform_device *pdev);
};

#if defined(CONFIG_ARCH_EXYNOS5)
struct exynos5_platform_fimc_is {
	int	hw_ver;
	struct exynos5_fimc_is_sensor_info
		*sensor_info[FIMC_IS_MAX_CAMIF_CLIENTS];
	void	(*cfg_gpio)(struct platform_device *pdev);
	int	(*clk_cfg)(struct platform_device *pdev);
	int	(*clk_on)(struct platform_device *pdev);
	int	(*clk_off)(struct platform_device *pdev);
};
#endif

extern struct exynos4_platform_fimc_is exynos4_fimc_is_default_data;
extern void exynos4_fimc_is_set_platdata(struct exynos4_platform_fimc_is *pd);
#if defined(CONFIG_ARCH_EXYNOS5)
extern void exynos5_fimc_is_set_platdata(struct exynos5_platform_fimc_is *pd);
#endif
/* defined by architecture to configure gpio */
extern void exynos_fimc_is_cfg_gpio(struct platform_device *pdev);

/* platform specific clock functions */
extern int exynos_fimc_is_cfg_clk(struct platform_device *pdev);
extern int exynos_fimc_is_clk_on(struct platform_device *pdev);
extern int exynos_fimc_is_clk_off(struct platform_device *pdev);
extern int exynos_fimc_is_clk_get(struct platform_device *pdev);
extern int exynos_fimc_is_clk_put(struct platform_device *pdev);

#if defined(CONFIG_ARCH_EXYNOS5)
/* defined by architecture to configure gpio */
extern void exynos5_fimc_is_cfg_gpio(struct platform_device *pdev);

/* platform specific clock functions */
extern int exynos5_fimc_is_cfg_clk(struct platform_device *pdev);
extern int exynos5_fimc_is_clk_on(struct platform_device *pdev);
extern int exynos5_fimc_is_clk_off(struct platform_device *pdev);
#endif
#endif /* EXYNOS_FIMC_IS_H_ */
