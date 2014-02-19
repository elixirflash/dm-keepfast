/*
 * s2mps11-core.c
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


#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/i2c.h>
#include <linux/interrupt.h>
#include <linux/pm_runtime.h>
#include <linux/mutex.h>
#include <linux/mfd/core.h>
#include <linux/mfd/s2mps11/s2mps11-core.h>
#include <linux/mfd/s2mps11/s2mps11-pmic.h>

#define RTC_I2C_ADDR		(0x0c>>1)

static struct mfd_cell s2mps11_devs[] = {
	{.name = "s2mps11-pmic"},
};

int s2mps11_reg_read(struct i2c_client *i2c, u8 reg, u8 *dest)
{
	struct s2mps11_dev *s2mps11 = i2c_get_clientdata(i2c);
	int ret;

	mutex_lock(&s2mps11->iolock);
	ret = i2c_smbus_read_byte_data(i2c, reg);
	mutex_unlock(&s2mps11->iolock);
	if (ret < 0)
		return ret;

	ret &= 0xff;
	*dest = ret;
	return 0;
}
EXPORT_SYMBOL(s2mps11_reg_read);

int s2mps11_bulk_read(struct i2c_client *i2c, u8 reg, int count, u8 *buf)
{
	struct s2mps11_dev *s2mps11 = i2c_get_clientdata(i2c);
	int ret;

	mutex_lock(&s2mps11->iolock);
	ret = i2c_smbus_read_i2c_block_data(i2c, reg, count, buf);
	mutex_unlock(&s2mps11->iolock);
	if (ret < 0)
		return ret;

	return 0;
}
EXPORT_SYMBOL(s2mps11_bulk_read);

int s2mps11_reg_write(struct i2c_client *i2c, u8 reg, u8 value)
{
	struct s2mps11_dev *s2mps11 = i2c_get_clientdata(i2c);
	int ret;

	mutex_lock(&s2mps11->iolock);
	ret = i2c_smbus_write_byte_data(i2c, reg, value);
	mutex_unlock(&s2mps11->iolock);
	return ret;
}
EXPORT_SYMBOL(s2mps11_reg_write);

int s2mps11_bulk_write(struct i2c_client *i2c, u8 reg, int count, u8 *buf)
{
	struct s2mps11_dev *s2mps11 = i2c_get_clientdata(i2c);
	int ret;

	mutex_lock(&s2mps11->iolock);
	ret = i2c_smbus_write_i2c_block_data(i2c, reg, count, buf);
	mutex_unlock(&s2mps11->iolock);
	if (ret < 0)
		return ret;

	return 0;
}
EXPORT_SYMBOL(s2mps11_bulk_write);

int s2mps11_reg_update(struct i2c_client *i2c, u8 reg, u8 val, u8 mask)
{
	struct s2mps11_dev *s2mps11 = i2c_get_clientdata(i2c);
	int ret;

	mutex_lock(&s2mps11->iolock);
	ret = i2c_smbus_read_byte_data(i2c, reg);
	if (ret >= 0) {
		u8 old_val = ret & 0xff;
		u8 new_val = (val & mask) | (old_val & (~mask));
		ret = i2c_smbus_write_byte_data(i2c, reg, new_val);
	}
	mutex_unlock(&s2mps11->iolock);
	return ret;
}
EXPORT_SYMBOL(s2mps11_reg_update);

static int s2mps11_i2c_probe(struct i2c_client *i2c,
			    const struct i2c_device_id *id)
{
	struct s2mps11_platform_data *pdata = i2c->dev.platform_data;
	struct s2mps11_dev *s2mps11;
	int ret = 0;

	s2mps11 = kzalloc(sizeof(struct s2mps11_dev), GFP_KERNEL);
	if (s2mps11 == NULL)
		return -ENOMEM;

	i2c_set_clientdata(i2c, s2mps11);
	s2mps11->dev = &i2c->dev;
	s2mps11->i2c = i2c;
	s2mps11->irq = i2c->irq;
	s2mps11->type = id->driver_data;

	if (pdata) {
		s2mps11->ono = pdata->ono;
		s2mps11->irq_base = pdata->irq_base;
		s2mps11->wakeup = pdata->wakeup;
		s2mps11->wtsr_smpl = pdata->wtsr_smpl;
	}

	mutex_init(&s2mps11->iolock);

	s2mps11->rtc = i2c_new_dummy(i2c->adapter, RTC_I2C_ADDR);
	i2c_set_clientdata(s2mps11->rtc, s2mps11);

	if (pdata && pdata->cfg_pmic_irq)
		pdata->cfg_pmic_irq();

	s2mps11_irq_init(s2mps11);

	pm_runtime_set_active(s2mps11->dev);

	ret = mfd_add_devices(s2mps11->dev, -1,
				s2mps11_devs, ARRAY_SIZE(s2mps11_devs),
				NULL, 0);

	if (ret < 0)
		goto err;

	dev_info(s2mps11->dev, "s2mps11 MFD probe done!!!\n");
	return ret;

err:
	mfd_remove_devices(s2mps11->dev);
	s2mps11_irq_exit(s2mps11);
	i2c_unregister_device(s2mps11->rtc);
	kfree(s2mps11);
	return ret;
}

static int s2mps11_i2c_remove(struct i2c_client *i2c)
{
	struct s2mps11_dev *s2mps11 = i2c_get_clientdata(i2c);

	mfd_remove_devices(s2mps11->dev);
	s2mps11_irq_exit(s2mps11);
	i2c_unregister_device(s2mps11->rtc);
	kfree(s2mps11);

	return 0;
}

static const struct i2c_device_id s2mps11_i2c_id[] = {
	{ "s2mps11", 0 },
	{ }
};
MODULE_DEVICE_TABLE(i2c, s2mps11_i2c_id);

#ifdef CONFIG_PM
static int s2mps11_suspend(struct device *dev)
{
	struct i2c_client *i2c = container_of(dev, struct i2c_client, dev);
	struct s2mps11_dev *s2mps11 = i2c_get_clientdata(i2c);

	if (s2mps11->wakeup)
		enable_irq_wake(s2mps11->irq);

	disable_irq(s2mps11->irq);

	return 0;
}

static int s2mps11_resume(struct device *dev)
{
	struct i2c_client *i2c = container_of(dev, struct i2c_client, dev);
	struct s2mps11_dev *s2mps11 = i2c_get_clientdata(i2c);

	if (s2mps11->wakeup)
		disable_irq_wake(s2mps11->irq);

	enable_irq(s2mps11->irq);

	return 0;
}
#else
#define s2mps11_suspend       NULL
#define s2mps11_resume                NULL
#endif /* CONFIG_PM */

const struct dev_pm_ops s2mps11_apm = {
	.suspend = s2mps11_suspend,
	.resume = s2mps11_resume,
};

static struct i2c_driver s2mps11_i2c_driver = {
	.driver = {
		   .name = "s2mps11",
		   .owner = THIS_MODULE,
		   .pm = &s2mps11_apm,
	},
	.probe = s2mps11_i2c_probe,
	.remove = s2mps11_i2c_remove,
	.id_table = s2mps11_i2c_id,
};

static int __init s2mps11_i2c_init(void)
{
	return i2c_add_driver(&s2mps11_i2c_driver);
}

subsys_initcall(s2mps11_i2c_init);

static void __exit s2mps11_i2c_exit(void)
{
	i2c_del_driver(&s2mps11_i2c_driver);
}
module_exit(s2mps11_i2c_exit);

MODULE_AUTHOR("Junhan Bae <junhan84.bae@samsung.com>");
MODULE_DESCRIPTION("Core support for the s2mps11 MFD");
MODULE_LICENSE("GPL");
