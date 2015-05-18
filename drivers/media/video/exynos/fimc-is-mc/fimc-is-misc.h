/*
 * Samsung Exynos5 SoC series FIMC-IS driver
 *
 *
 * Copyright (c) 2011 Samsung Electronics Co., Ltd
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef FIMC_IS_MISC_H
#define FIMC_IS_MISC_H

int enable_mipi(void);
int start_fimc_lite(unsigned long mipi_reg_base, struct flite_frame *f_frame);
int stop_fimc_lite(int channel);
int start_mipi_csi(int channel, struct flite_frame *f_frame);
int stop_mipi_csi(int channel);

/*iky to do here*/
int flite_hw_get_status2(unsigned long flite_reg_base);
void flite_hw_set_status2(unsigned long flite_reg_base, u32 val);
int flite_hw_get_status1(unsigned long flite_reg_base);
void flite_hw_set_status1(unsigned long flite_reg_base, u32 val);
void flite_hw_set_start_addr(unsigned long flite_reg_base,
	u32 number, u32 addr);
void flite_hw_set_use_buffer(unsigned long flite_reg_base, u32 number);
void flite_hw_set_unuse_buffer(unsigned long flite_reg_base, u32 number);
int flite_hw_get_present_frame_buffer(unsigned long flite_reg_base);
void flite_hw_set_output_dma(unsigned long flite_reg_base, bool enable);
int init_fimc_lite(unsigned long mipi_reg_base);
void flite_hw_set_capture_start(unsigned long flite_reg_base);
void flite_hw_set_output_local(unsigned long flite_reg_base, bool enable);
u32 flite_hw_get_buffer_seq(unsigned long flite_reg_base);

int fimc_is_digital_zoom(struct fimc_is_dev *dev, int value);
int fimc_is_v4l2_af_start_stop(struct fimc_is_dev *dev, int value);
int fimc_is_v4l2_touch_af_start_stop(struct fimc_is_dev *dev, int value);
int fimc_is_v4l2_caf_start_stop(struct fimc_is_dev *dev, int value);
int fimc_is_ctrl_odc(struct fimc_is_dev *dev, int value);
int fimc_is_ctrl_dis(struct fimc_is_dev *dev, int value);
int fimc_is_ctrl_3dnr(struct fimc_is_dev *dev, int value);
int fimc_is_v4l2_isp_scene_mode(struct fimc_is_dev *dev, int mode);
int fimc_is_af_face(struct fimc_is_dev *dev);
int fimc_is_v4l2_af_mode(struct fimc_is_dev *dev, int value);
int fimc_is_v4l2_isp_iso(struct fimc_is_dev *dev, int value);
int fimc_is_v4l2_isp_effect(struct fimc_is_dev *dev, int value);
int fimc_is_v4l2_isp_effect_legacy(struct fimc_is_dev *dev, int value);
int fimc_is_v4l2_isp_flash_mode(struct fimc_is_dev *dev, int value);
int fimc_is_v4l2_awb_mode(struct fimc_is_dev *dev, int value);
int fimc_is_v4l2_awb_mode_legacy(struct fimc_is_dev *dev, int value);
int fimc_is_v4l2_isp_contrast(struct fimc_is_dev *dev, int value);
int fimc_is_v4l2_isp_contrast_legacy(struct fimc_is_dev *dev, int value);
int fimc_is_v4l2_isp_saturation(struct fimc_is_dev *dev, int value);
int fimc_is_v4l2_isp_sharpness(struct fimc_is_dev *dev, int value);
int fimc_is_v4l2_isp_exposure(struct fimc_is_dev *dev, int value);
int fimc_is_v4l2_isp_exposure_legacy(struct fimc_is_dev *dev, int value);
int fimc_is_v4l2_isp_brightness(struct fimc_is_dev *dev, int value);
int fimc_is_v4l2_isp_hue(struct fimc_is_dev *dev, int value);
int fimc_is_v4l2_isp_metering(struct fimc_is_dev *dev, int value);
int fimc_is_v4l2_isp_metering_legacy(struct fimc_is_dev *dev, int value);
int fimc_is_v4l2_isp_afc(struct fimc_is_dev *dev, int value);
int fimc_is_v4l2_isp_afc_legacy(struct fimc_is_dev *dev, int value);
int fimc_is_v4l2_fd_angle_mode(struct fimc_is_dev *dev, int value);
int fimc_is_v4l2_frame_rate(struct fimc_is_dev *dev, int value);
int fimc_is_v4l2_ae_awb_lockunlock(struct fimc_is_dev *dev, int value);
int fimc_is_v4l2_set_isp(struct fimc_is_dev *dev, int value);
int fimc_is_v4l2_set_drc(struct fimc_is_dev *dev, int value);
int fimc_is_v4l2_cmd_isp(struct fimc_is_dev *dev, int value);
int fimc_is_v4l2_cmd_drc(struct fimc_is_dev *dev, int value);
int fimc_is_v4l2_cmd_fd(struct fimc_is_dev *dev, int value);
int fimc_is_v4l2_shot_mode(struct fimc_is_dev *dev, int value);
#endif/*FIMC_IS_MISC_H*/
