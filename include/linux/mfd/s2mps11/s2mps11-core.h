/*
 * s2mps11-core.h
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd
 *              http://www.samsung.com
 *
 *  This program is free software; you can redistribute  it and/or modify it
 *  under  the terms of  the GNU General  Public License as published by the
 *  Free Software Foundation;  either version 2 of the  License, or (at your
 *  option) any later version.
 *
 */

#ifndef __LINUX_MFD_S2MPS11_CORE_H
#define __LINUX_MFD_S2MPS11_CORE_H

#define NUM_IRQ_REGS	4

/* S2MPS11 registers */
enum s2mps11_reg {
	S2MPS11_REG_ID,
	S2MPS11_REG_INT1,
	S2MPS11_REG_INT2,
	S2MPS11_REG_INT3,
	S2MPS11_REG_INT1M,
	S2MPS11_REG_INT2M,
	S2MPS11_REG_INT3M,
	S2MPS11_REG_ST1,
	S2MPS11_REG_ST2,
	S2MPS11_REG_OFFSRC,
	S2MPS11_REG_PWRONSRC,
	S2MPS11_REG_RTC_CTRL,
	S2MPS11_REG_CTRL1,
	S2MPS11_REG_ETC_TEST,
	S2MPS11_REG_RSVD3,
	S2MPS11_REG_BU_CHG,
	S2MPS11_REG_RAMP,
	S2MPS11_REG_RAMP_BUCK,
	S2MPS11_REG_LDO1_8,
	S2MPS11_REG_LDO9_16,
	S2MPS11_REG_LDO17_24,
	S2MPS11_REG_LDO25_32,
	S2MPS11_REG_LDO33_38,
	S2MPS11_REG_LDO1_8_1,
	S2MPS11_REG_LDO9_16_1,
	S2MPS11_REG_LDO17_24_1,
	S2MPS11_REG_LDO25_32_1,
	S2MPS11_REG_LDO33_38_1,
	S2MPS11_REG_OTP_ADRL,
	S2MPS11_REG_OTP_ADRH,
	S2MPS11_REG_OTP_DATA,
	S2MPS11_REG_MON1SEL,
	S2MPS11_REG_MON2SEL,
	S2MPS11_REG_LEE,
	S2MPS11_REG_RSVD_NO,
	S2MPS11_REG_UVLO,
	S2MPS11_REG_LEE_NO,
	S2MPS11_REG_B1CTRL1,
	S2MPS11_REG_B1CTRL2,
	S2MPS11_REG_B2CTRL1,
	S2MPS11_REG_B2CTRL2,
	S2MPS11_REG_B3CTRL1,
	S2MPS11_REG_B3CTRL2,
	S2MPS11_REG_B4CTRL1,
	S2MPS11_REG_B4CTRL2,
	S2MPS11_REG_B5CTRL1,
	S2MPS11_REG_BUCK5_SW,
	S2MPS11_REG_B5CTRL2,
	S2MPS11_REG_B5CTRL3,
	S2MPS11_REG_B5CTRL4,
	S2MPS11_REG_B5CTRL5,
	S2MPS11_REG_B6CTRL1,
	S2MPS11_REG_B6CTRL2,
	S2MPS11_REG_B7CTRL1,
	S2MPS11_REG_B7CTRL2,
	S2MPS11_REG_B8CTRL1,
	S2MPS11_REG_B8CTRL2,
	S2MPS11_REG_B9CTRL1,
	S2MPS11_REG_B9CTRL2,
	S2MPS11_REG_B10CTRL1,
	S2MPS11_REG_B10CTRL2,
	S2MPS11_REG_L1CTRL,
	S2MPS11_REG_L2CTRL,
	S2MPS11_REG_L3CTRL,
	S2MPS11_REG_L4CTRL,
	S2MPS11_REG_L5CTRL,
	S2MPS11_REG_L6CTRL,
	S2MPS11_REG_L7CTRL,
	S2MPS11_REG_L8CTRL,
	S2MPS11_REG_L9CTRL,
	S2MPS11_REG_L10CTRL,
	S2MPS11_REG_L11CTRL,
	S2MPS11_REG_L12CTRL,
	S2MPS11_REG_L13CTRL,
	S2MPS11_REG_L14CTRL,
	S2MPS11_REG_L15CTRL,
	S2MPS11_REG_L16CTRL,
	S2MPS11_REG_L17CTRL,
	S2MPS11_REG_L18CTRL,
	S2MPS11_REG_L19CTRL,
	S2MPS11_REG_L20CTRL,
	S2MPS11_REG_L21CTRL,
	S2MPS11_REG_L22CTRL,
	S2MPS11_REG_L23CTRL,
	S2MPS11_REG_L24CTRL,
	S2MPS11_REG_L25CTRL,
	S2MPS11_REG_L26CTRL,
	S2MPS11_REG_L27CTRL,
	S2MPS11_REG_L28CTRL,
	S2MPS11_REG_L29CTRL,
	S2MPS11_REG_L30CTRL,
	S2MPS11_REG_L31CTRL,
	S2MPS11_REG_L32CTRL,
	S2MPS11_REG_L33CTRL,
	S2MPS11_REG_L34CTRL,
	S2MPS11_REG_L35CTRL,
	S2MPS11_REG_L36CTRL,
	S2MPS11_REG_L37CTRL,
	S2MPS11_REG_L38CTRL,
};

enum s2mps11_irq {
	S2MPS11_IRQ_PWRONF,
	S2MPS11_IRQ_PWRONR,
	S2MPS11_IRQ_JIGONBF,
	S2MPS11_IRQ_JIGONBR,
	S2MPS11_IRQ_ACOKBF,
	S2MPS11_IRQ_ACOKBR,
	S2MPS11_IRQ_PWRON1S,
	S2MPS11_IRQ_MRB,

	S2MPS11_IRQ_RTC60S,
	S2MPS11_IRQ_RTCA1,
	S2MPS11_IRQ_RTCA2,
	S2MPS11_IRQ_SMPL,
	S2MPS11_IRQ_RTC1S,
	S2MPS11_IRQ_WTSR,

	S2MPS11_IRQ_INT120C,
	S2MPS11_IRQ_INT140C,

	S2MPS11_IRQ_NR,
};

#define S2MPS11_IRQ_PWRONF_MASK		(1 << 0)
#define S2MPS11_IRQ_PWRONR_MASK		(1 << 1)
#define S2MPS11_IRQ_JIGONBF_MASK	(1 << 2)
#define S2MPS11_IRQ_JIGONBR_MASK		(1 << 3)
#define S2MPS11_IRQ_ACOKBF_MASK		(1 << 4)
#define S2MPS11_IRQ_ACOKBR_MASK	(1 << 5)
#define S2MPS11_IRQ_PWRON1S_MASK	(1 << 6)
#define S2MPS11_IRQ_MRB_MASK	(1 << 7)

#define S2MPS11_IRQ_RTC60S_MASK		(1 << 0)
#define S2MPS11_IRQ_RTCA1_MASK		(1 << 1)
#define S2MPS11_IRQ_RTCA2_MASK		(1 << 2)
#define S2MPS11_IRQ_SMPL_MASK		(1 << 3)
#define S2MPS11_IRQ_RTC1S_MASK		(1 << 4)
#define S2MPS11_IRQ_WTSR_MASK		(1 << 5)

#define S2MPS11_IRQ_INT120C_MASK		(1 << 0)
#define S2MPS11_IRQ_INT140C_MASK		(1 << 1)

/**
 * struct s2mps11_dev - s2mps11 master device for sub-drivers
 * @dev: master device of the chip (can be used to access platform data)
 * @i2c: i2c client private data for regulator
 * @rtc: i2c client private data for rtc
 * @iolock: mutex for serializing io access
 * @irqlock: mutex for buslock
 * @irq_base: base IRQ number for s2mps11, required for IRQs
 * @irq: generic IRQ number for s2mps11
 * @ono: power onoff IRQ number for s2mps11
 * @irq_masks_cur: currently active value
 * @irq_masks_cache: cached hardware value
 * @type: indicate which s2mps11 "variant" is used
 */
struct s2mps11_dev {
	struct device *dev;
	struct i2c_client *i2c;
	struct i2c_client *rtc;
	struct mutex iolock;
	struct mutex irqlock;

	int irq_base;
	int irq;
	int ono;
	u8 irq_masks_cur[NUM_IRQ_REGS];
	u8 irq_masks_cache[NUM_IRQ_REGS];
	int type;
	bool wakeup;
	bool wtsr_smpl;
};



int s2mps11_irq_init(struct s2mps11_dev *s2mps11);
void s2mps11_irq_exit(struct s2mps11_dev *s2mps11);
int s2mps11_irq_resume(struct s2mps11_dev *s2mps11);

extern int s2mps11_reg_read(struct i2c_client *i2c, u8 reg, u8 *dest);
extern int s2mps11_bulk_read(struct i2c_client *i2c,
					u8 reg, int count, u8 *buf);
extern int s2mps11_reg_write(struct i2c_client *i2c, u8 reg, u8 value);
extern int s2mps11_bulk_write(struct i2c_client *i2c,
					u8 reg, int count, u8 *buf);
extern int s2mps11_reg_update(struct i2c_client *i2c, u8 reg, u8 val, u8 mask);

struct s2mps11_platform_data {
	struct s2mps11_regulator_data	*regulators;
	struct s2mps11_opmode_data		*opmode_data;

	int	num_regulators;

	int	irq_base;
	int	(*cfg_pmic_irq)(void);

	int	ono;
	bool	wakeup;

	int	buck2_ramp_delay;
	int	buck34_ramp_delay;
	int	buck5_ramp_delay;
	int	buck16_ramp_delay;
	int	buck7810_ramp_delay;
	int	buck9_ramp_delay;

	bool	buck6_ramp_enable;
	bool	buck2_ramp_enable;
	bool	buck3_ramp_enable;
	bool	buck4_ramp_enable;

	bool	wtsr_smpl;
};

#endif /*  __LINUX_MFD_S2MPS11_CORE_H */
