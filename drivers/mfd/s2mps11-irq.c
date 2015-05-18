/*
 * s2mps11-irq.c
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


#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/mfd/s2mps11/s2mps11-core.h>

struct s2mps11_irq_data {
	int reg;
	int mask;
};

static struct s2mps11_irq_data s2mps11_irqs[] = {
	[S2MPS11_IRQ_PWRONF] = {
		.reg = 1,
		.mask = S2MPS11_IRQ_PWRONF_MASK,
	},
	[S2MPS11_IRQ_PWRONR] = {
		.reg = 1,
		.mask = S2MPS11_IRQ_PWRONR_MASK,
	},
	[S2MPS11_IRQ_JIGONBF] = {
		.reg = 1,
		.mask = S2MPS11_IRQ_JIGONBF_MASK,
	},
	[S2MPS11_IRQ_JIGONBR] = {
		.reg = 1,
		.mask = S2MPS11_IRQ_JIGONBR_MASK,
	},
	[S2MPS11_IRQ_ACOKBF] = {
		.reg = 1,
		.mask = S2MPS11_IRQ_ACOKBF_MASK,
	},
	[S2MPS11_IRQ_ACOKBR] = {
		.reg = 1,
		.mask = S2MPS11_IRQ_ACOKBR_MASK,
	},
	[S2MPS11_IRQ_PWRON1S] = {
		.reg = 1,
		.mask = S2MPS11_IRQ_PWRON1S_MASK,
	},
	[S2MPS11_IRQ_MRB] = {
		.reg = 1,
		.mask = S2MPS11_IRQ_MRB_MASK,
	},
	[S2MPS11_IRQ_RTC60S] = {
		.reg = 2,
		.mask = S2MPS11_IRQ_RTC60S_MASK,
	},
	[S2MPS11_IRQ_RTCA1] = {
		.reg = 2,
		.mask = S2MPS11_IRQ_RTCA1_MASK,
	},
	[S2MPS11_IRQ_RTCA2] = {
		.reg = 2,
		.mask = S2MPS11_IRQ_RTCA2_MASK,
	},
	[S2MPS11_IRQ_SMPL] = {
		.reg = 2,
		.mask = S2MPS11_IRQ_SMPL_MASK,
	},
	[S2MPS11_IRQ_RTC1S] = {
		.reg = 2,
		.mask = S2MPS11_IRQ_RTC1S_MASK,
	},
	[S2MPS11_IRQ_WTSR] = {
		.reg = 2,
		.mask = S2MPS11_IRQ_WTSR_MASK,
	},
	[S2MPS11_IRQ_INT120C] = {
		.reg = 3,
		.mask = S2MPS11_IRQ_INT120C_MASK,
	},
	[S2MPS11_IRQ_INT140C] = {
		.reg = 3,
		.mask = S2MPS11_IRQ_INT140C_MASK,
	},

};

static inline struct s2mps11_irq_data *
irq_to_s2mps11_irq(struct s2mps11_dev *s2mps11, int irq)
{
	return &s2mps11_irqs[irq - s2mps11->irq_base];
}

static void s2mps11_irq_lock(struct irq_data *data)
{
	struct s2mps11_dev *s2mps11 = irq_data_get_irq_chip_data(data);

	mutex_lock(&s2mps11->irqlock);
}

static void s2mps11_irq_sync_unlock(struct irq_data *data)
{
	struct s2mps11_dev *s2mps11 = irq_data_get_irq_chip_data(data);
	int i;

	for (i = 0; i < ARRAY_SIZE(s2mps11->irq_masks_cur); i++) {
		if (s2mps11->irq_masks_cur[i] != s2mps11->irq_masks_cache[i]) {
			s2mps11->irq_masks_cache[i] = s2mps11->irq_masks_cur[i];
			s2mps11_reg_write(s2mps11->i2c, S2MPS11_REG_INT1M + i,
					s2mps11->irq_masks_cur[i]);
		}
	}

	mutex_unlock(&s2mps11->irqlock);
}

static void s2mps11_irq_unmask(struct irq_data *data)
{
	struct s2mps11_dev *s2mps11 = irq_data_get_irq_chip_data(data);
	struct s2mps11_irq_data *irq_data = irq_to_s2mps11_irq(s2mps11,
							       data->irq);

	s2mps11->irq_masks_cur[irq_data->reg - 1] &= ~irq_data->mask;
}

static void s2mps11_irq_mask(struct irq_data *data)
{
	struct s2mps11_dev *s2mps11 = irq_data_get_irq_chip_data(data);
	struct s2mps11_irq_data *irq_data = irq_to_s2mps11_irq(s2mps11,
							       data->irq);

	s2mps11->irq_masks_cur[irq_data->reg - 1] |= irq_data->mask;
}

static struct irq_chip s2mps11_irq_chip = {
	.name = "s2mps11",
	.irq_bus_lock = s2mps11_irq_lock,
	.irq_bus_sync_unlock = s2mps11_irq_sync_unlock,
	.irq_mask = s2mps11_irq_mask,
	.irq_unmask = s2mps11_irq_unmask,
};

static irqreturn_t s2mps11_irq_thread(int irq, void *data)
{
	struct s2mps11_dev *s2mps11 = data;
	u8 irq_reg[NUM_IRQ_REGS-1];
	int ret;
	int i;

	ret = s2mps11_bulk_read(s2mps11->i2c, S2MPS11_REG_INT1,
				NUM_IRQ_REGS - 1, irq_reg);
	if (ret < 0) {
		dev_err(s2mps11->dev, "Failed to read interrupt register: %d\n",
				ret);
		return IRQ_NONE;
	}

	for (i = 0; i < NUM_IRQ_REGS - 1; i++)
		irq_reg[i] &= ~s2mps11->irq_masks_cur[i];

	for (i = 0; i < S2MPS11_IRQ_NR; i++) {
		if (irq_reg[s2mps11_irqs[i].reg - 1] & s2mps11_irqs[i].mask)
			handle_nested_irq(s2mps11->irq_base + i);
	}

	return IRQ_HANDLED;
}

int s2mps11_irq_resume(struct s2mps11_dev *s2mps11)
{
	if (s2mps11->irq && s2mps11->irq_base)
		s2mps11_irq_thread(s2mps11->irq_base, s2mps11);

	return 0;
}

int s2mps11_irq_init(struct s2mps11_dev *s2mps11)
{
	int i;
	int cur_irq;
	int ret = 0;

	if (!s2mps11->irq) {
		dev_warn(s2mps11->dev,
			 "No interrupt specified, no interrupts\n");
		s2mps11->irq_base = 0;
		return 0;
	}

	if (!s2mps11->irq_base) {
		dev_err(s2mps11->dev,
			"No interrupt base specified, no interrupts\n");
		return 0;
	}

	mutex_init(&s2mps11->irqlock);
	for (i = 0; i < NUM_IRQ_REGS - 1; i++) {
		s2mps11->irq_masks_cur[i] = 0xff;
		s2mps11->irq_masks_cache[i] = 0xff;
		s2mps11_reg_write(s2mps11->i2c, S2MPS11_REG_INT1M + i,
					0xff);
	}
	for (i = 0; i < S2MPS11_IRQ_NR; i++) {
		cur_irq = i + s2mps11->irq_base;
		ret = irq_set_chip_data(cur_irq, s2mps11);
		if (ret) {
			dev_err(s2mps11->dev,
				"Failed to irq_set_chip_data %d: %d\n",
				s2mps11->irq, ret);
			return ret;
		}

		irq_set_chip_and_handler(cur_irq, &s2mps11_irq_chip,
					 handle_edge_irq);
		irq_set_nested_thread(cur_irq, 1);
#ifdef CONFIG_ARM
			set_irq_flags(cur_irq, IRQF_VALID);
#else
			irq_set_noprobe(cur_irq);
#endif
	}

	ret = request_threaded_irq(s2mps11->irq, NULL,
				   s2mps11_irq_thread,
				   IRQF_TRIGGER_FALLING | IRQF_ONESHOT,
				   "s2mps11-irq", s2mps11);
	if (ret) {
		dev_err(s2mps11->dev, "Failed to request IRQ %d: %d\n",
			s2mps11->irq, ret);
		return ret;
	}

	if (!s2mps11->ono)
		return 0;



	ret = request_threaded_irq(s2mps11->ono, NULL,
				s2mps11_irq_thread,
				IRQF_TRIGGER_FALLING |
				IRQF_TRIGGER_RISING |
				IRQF_ONESHOT, "s2mps11-ono", s2mps11);

	if (ret)
		dev_err(s2mps11->dev, "Failed to request IRQ %d: %d\n",
			s2mps11->ono, ret);

	return 0;
}

void s2mps11_irq_exit(struct s2mps11_dev *s2mps11)
{
	if (s2mps11->ono)
		free_irq(s2mps11->ono, s2mps11);

	if (s2mps11->irq)
		free_irq(s2mps11->irq, s2mps11);
}
