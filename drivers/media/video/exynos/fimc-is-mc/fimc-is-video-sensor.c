/*
 * Samsung Exynos5 SoC series FIMC-IS driver
 *
 * exynos5 fimc-is video functions
 *
 * Copyright (c) 2011 Samsung Electronics Co., Ltd
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <mach/videonode.h>
#ifdef CONFIG_BUSFREQ_OPP
#ifdef CONFIG_CPU_EXYNOS5250
#include <mach/dev.h>
#endif
#endif
#include <media/exynos_mc.h>
#include <linux/cma.h>
#include <asm/cacheflush.h>
#include <asm/pgtable.h>
#include <linux/firmware.h>
#include <linux/dma-mapping.h>
#include <linux/delay.h>
#include <linux/scatterlist.h>
#include <linux/videodev2.h>
#include <linux/videodev2_exynos_camera.h>
#include <linux/videodev2_exynos_media.h>
#include <linux/v4l2-mediabus.h>

#include "fimc-is-core.h"
#include "fimc-is-helper.h"
#include "fimc-is-param.h"
#include "fimc-is-cmd.h"
#include "fimc-is-regs.h"
#include "fimc-is-err.h"
#include "fimc-is-misc.h"
#include "fimc-is-video.h"

/*************************************************************************/
/* video file opertation						 */
/************************************************************************/

static int fimc_is_bayer_video_open(struct file *file)
{
	struct fimc_is_dev *is = video_drvdata(file);
	struct fimc_is_sensor_dev *sensor;
	struct fimc_is_video_dev *video;

	dbg_sensor("%s\n", __func__);

	sensor = &is->sensor;
	video = &is->video[FIMC_IS_VIDEO_NUM_BAYER];

	file->private_data = video;
	video->num_buf = 0;
	video->buf_ref_cnt = 0;
	sensor->last_capture = false;
	sensor->streaming = false;

	if (!test_bit(FIMC_IS_STATE_FW_DOWNLOADED, &is->pipe_state)) {
		is->sensor_num = 1;

		fimc_is_load_fw(is);

		set_bit(FIMC_IS_STATE_FW_DOWNLOADED, &is->pipe_state);
		clear_bit(FIMC_IS_STATE_SENSOR_INITIALIZED, &is->pipe_state);
		clear_bit(FIMC_IS_STATE_HW_STREAM_ON, &is->pipe_state);
	}

	/*TODO: will fixed*/
	/*
	INIT_LIST_HEAD(&sensor->shot_free_head);
	INIT_LIST_HEAD(&sensor->shot_request_head);
	sensor->shot_free_cnt = 0;
	sensor->shot_request_cnt = 0;

	for (i = 0; i < 20; ++i) {
		shot = kmalloc(sizeof(struct fimc_is_sensor_shot), GFP_KERNEL);
		list_add_tail(&shot->list, &sensor->shot_free_head);
		sensor->shot_free_cnt++;

	}
	*/

	clear_bit(FIMC_IS_STATE_BAYER_STREAM_ON, &is->pipe_state);
	fimc_is_fw_clear_irq1_all(is);
	return 0;
}

static int fimc_is_bayer_video_close(struct file *file)
{
	struct fimc_is_dev *is = video_drvdata(file);
	struct fimc_is_sensor_dev *sensor;
	int sensor_id;
	int flite_ch, csi_ch;
	int ret;

	dbg_sensor("%s\n", __func__);

	sensor = &is->sensor;
	sensor_id = is->sensor.id_position;
	flite_ch = is->pdata->sensor_info[sensor_id]->flite_id;
	csi_ch = is->pdata->sensor_info[sensor_id]->csi_id;

	dbg_sensor("stop flite & mipi (pos:%d) (port:%d)\n",
		sensor_id, flite_ch);

	sensor->last_capture = false;

	stop_fimc_lite(flite_ch);
	stop_mipi_csi(csi_ch);

	dbg_sensor("waiting last capture\n");
	mutex_lock(&is->lock);
	ret = wait_event_timeout(is->irq_queue,
		sensor->last_capture,
		FIMC_IS_SHUTDOWN_TIMEOUT_SENSOR);
	mutex_unlock(&is->lock);
	if (!ret) {
		err("last capture timeout:%s\n", __func__);
		stop_fimc_lite(flite_ch);
		stop_mipi_csi(csi_ch);
		msleep(60);
	}

	dbg_sensor("last capture done\n");

	vb2_queue_release(&is->video[FIMC_IS_VIDEO_NUM_BAYER].vbq);
	clear_bit(FIMC_IS_STATE_BAYER_BUFFER_PREPARED, &is->pipe_state);

	if (!test_bit(FIMC_IS_STATE_SCALERP_STREAM_ON, &is->pipe_state) &&
		!test_bit(FIMC_IS_STATE_SCALERC_STREAM_ON, &is->pipe_state) &&
		!test_bit(FIMC_IS_STATE_3DNR_STREAM_ON, &is->pipe_state) &&
		test_bit(FIMC_IS_STATE_FW_DOWNLOADED, &is->power)) {
		clear_bit(FIMC_IS_STATE_HW_STREAM_ON, &is->pipe_state);
		fimc_is_hw_subip_poweroff(is);

		mutex_lock(&is->lock);
		ret = wait_event_timeout(is->irq_queue,
			!test_bit(FIMC_IS_PWR_ST_POWER_ON_OFF, &is->power),
			FIMC_IS_SHUTDOWN_TIMEOUT_SENSOR);
		mutex_unlock(&is->lock);

		if (!ret) {
			err("wait timeout : %s\n", __func__);
			ret = -EINVAL;
		}

		fimc_is_hw_a5_power(is, 0);
		clear_bit(FIMC_IS_STATE_FW_DOWNLOADED, &is->pipe_state);
	}

	return 0;
}

static unsigned int fimc_is_bayer_video_poll(struct file *file,
				      struct poll_table_struct *wait)
{
	struct fimc_is_dev *isp = video_drvdata(file);

	dbg_sensor("%s\n", __func__);
	return vb2_poll(&isp->video[FIMC_IS_VIDEO_NUM_BAYER].vbq, file, wait);

}

static int fimc_is_bayer_video_mmap(struct file *file,
					struct vm_area_struct *vma)
{
	struct fimc_is_dev *isp = video_drvdata(file);

	dbg_sensor("%s\n", __func__);
	return vb2_mmap(&isp->video[FIMC_IS_VIDEO_NUM_BAYER].vbq, vma);

}

/*************************************************************************/
/* video ioctl operation						*/
/************************************************************************/

static int fimc_is_bayer_video_querycap(struct file *file, void *fh,
					struct v4l2_capability *cap)
{
	struct fimc_is_dev *isp = video_drvdata(file);

	strncpy(cap->driver, isp->pdev->name, sizeof(cap->driver) - 1);

	dbg_sensor("%s(devname : %s)\n", __func__, cap->driver);
	strncpy(cap->card, isp->pdev->name, sizeof(cap->card) - 1);
	cap->bus_info[0] = 0;
	cap->version = KERNEL_VERSION(1, 0, 0);
	cap->capabilities = V4L2_CAP_STREAMING
				| V4L2_CAP_VIDEO_CAPTURE
				| V4L2_CAP_VIDEO_CAPTURE_MPLANE;

	return 0;
}

static int fimc_is_bayer_video_enum_fmt_mplane(struct file *file, void *priv,
				    struct v4l2_fmtdesc *f)
{
	dbg_sensor("%s\n", __func__);
	return 0;
}

static int fimc_is_bayer_video_get_format_mplane(struct file *file, void *fh,
						struct v4l2_format *format)
{
	dbg_sensor("%s\n", __func__);
	return 0;
}

static int fimc_is_bayer_video_set_format_mplane(struct file *file, void *fh,
						struct v4l2_format *format)
{
	struct fimc_is_dev *isp = video_drvdata(file);
	struct fimc_is_video_dev *sensor_video;
	struct v4l2_pix_format_mplane *pix;
	struct fimc_is_fmt *frame;

	dbg_sensor("%s\n", __func__);

	pix = &format->fmt.pix_mp;
	frame = fimc_is_find_format(&pix->pixelformat, NULL, 0);

	if (!frame)
		return -EINVAL;

	sensor_video = &isp->video[FIMC_IS_VIDEO_NUM_BAYER];
	sensor_video->frame.format.pixelformat = frame->pixelformat;
	sensor_video->frame.format.mbus_code = frame->mbus_code;
	sensor_video->frame.format.num_planes = frame->num_planes;
	sensor_video->frame.width = pix->width;
	sensor_video->frame.height = pix->height;
	dbg_sensor("num_planes : %d\n", frame->num_planes);
	dbg_sensor("width : %d\n", pix->width);
	dbg_sensor("height : %d\n", pix->height);

	return 0;
}

static int fimc_is_bayer_video_try_format_mplane(struct file *file, void *fh,
						struct v4l2_format *format)
{
	dbg_sensor("%s\n", __func__);
	return 0;
}

static int fimc_is_bayer_video_cropcap(struct file *file, void *fh,
						struct v4l2_cropcap *cropcap)
{
	dbg_sensor("%s\n", __func__);
	return 0;
}

static int fimc_is_bayer_video_get_crop(struct file *file, void *fh,
						struct v4l2_crop *crop)
{
	dbg_sensor("%s\n", __func__);
	return 0;
}

static int fimc_is_bayer_video_set_crop(struct file *file, void *fh,
						struct v4l2_crop *crop)
{
	dbg_sensor("%s\n", __func__);
	return 0;
}

static int fimc_is_bayer_video_reqbufs(struct file *file, void *priv,
						struct v4l2_requestbuffers *buf)
{
	int ret;
	struct fimc_is_video_dev *video = file->private_data;
	struct fimc_is_dev *isp = video_drvdata(file);

	dbg_sensor("%s\n", __func__);
	ret = vb2_reqbufs(&video->vbq, buf);
	if (!ret)
		isp->video[FIMC_IS_VIDEO_NUM_BAYER].num_buf = buf->count;

	if (buf->count == 0)
		isp->video[FIMC_IS_VIDEO_NUM_BAYER].buf_ref_cnt = 0;

	dbg_sensor("%s(num_buf | %d)\n", __func__,
		isp->video[FIMC_IS_VIDEO_NUM_BAYER].num_buf);

	return ret;
}

static int fimc_is_bayer_video_querybuf(struct file *file, void *priv,
						struct v4l2_buffer *buf)
{
	int ret;
	struct fimc_is_video_dev *video = file->private_data;

	dbg_sensor("%s\n", __func__);
	ret = vb2_querybuf(&video->vbq, buf);

	return ret;
}

static int fimc_is_bayer_video_qbuf(struct file *file, void *priv,
						struct v4l2_buffer *buf)
{
	int vb_ret;
	struct fimc_is_video_dev *video = file->private_data;

	dbg_sensor("%s\n", __func__);
#if 0
	if (test_bit(FIMC_IS_STATE_BAYER_BUFFER_PREPARED, &isp->pipe_state)) {
		video->buf_mask |= (1<<buf->index);
		isp->video[FIMC_IS_VIDEO_NUM_BAYER].buf_mask = video->buf_mask;
		dbg_sensor("%s :: index(%d) mask(0x%08x)\n",
			__func__, buf->index, video->buf_mask);
		IS_ISP_SET_PARAM_DMA_OUTPUT2_CMD(isp,
			DMA_OUTPUT_UPDATE_MASK_BITS);
		IS_ISP_SET_PARAM_DMA_OUTPUT2_MASK(isp,
			video->buf_mask);
		IS_SET_PARAM_BIT(isp, PARAM_ISP_DMA2_OUTPUT);
		IS_INC_PARAM_NUM(isp);

		dbg("%s :: index(%d) mask(0x%08x)\n", __func__,
			buf->index, video->buf_mask);
	} else {
		dbg("%s :: index(%d)\n", __func__, buf->index);
	}
#endif

	vb_ret = vb2_qbuf(&video->vbq, buf);

	return vb_ret;
}

static int fimc_is_bayer_video_dqbuf(struct file *file, void *priv,
						struct v4l2_buffer *buf)
{
	int vb_ret;
	struct fimc_is_video_dev *video = file->private_data;
	struct fimc_is_dev *isp = video_drvdata(file);

	vb_ret = vb2_dqbuf(&video->vbq, buf, file->f_flags & O_NONBLOCK);

	video->buf_mask &= ~(1<<buf->index);
	isp->video[FIMC_IS_VIDEO_NUM_BAYER].buf_mask = video->buf_mask;

	dbg_sensor("%s :: index(%d) mask(0x%08x)\n",
		__func__, buf->index, video->buf_mask);

	/*iky to do here*/
	/*doesn't work well with old masking method*/
#if 0
	IS_ISP_SET_PARAM_DMA_OUTPUT2_CMD(isp,
		DMA_OUTPUT_UPDATE_MASK_BITS);
	IS_ISP_SET_PARAM_DMA_OUTPUT2_MASK(isp,
		video->buf_mask);
	IS_SET_PARAM_BIT(isp, PARAM_ISP_DMA2_OUTPUT);
	IS_INC_PARAM_NUM(isp);

	fimc_is_mem_cache_clean((void *)isp->is_p_region,
		IS_PARAM_SIZE);

	isp->scenario_id = ISS_PREVIEW_STILL;
	set_bit(IS_ST_INIT_PREVIEW_STILL,	&isp->state);
	clear_bit(IS_ST_INIT_CAPTURE_STILL, &isp->state);
	clear_bit(IS_ST_INIT_PREVIEW_VIDEO, &isp->state);
	fimc_is_hw_set_param(isp);
	mutex_lock(&isp->lock);
	ret = wait_event_timeout(isp->irq_queue,
		test_bit(IS_ST_INIT_PREVIEW_VIDEO, &isp->state),
		FIMC_IS_SHUTDOWN_TIMEOUT);
	mutex_unlock(&isp->lock);
	if (!ret) {
		dev_err(&isp->pdev->dev,
			"wait timeout : %s\n", __func__);
		return -EBUSY;
	}
#endif

	return vb_ret;
}

static int fimc_is_bayer_video_streamon(struct file *file, void *priv,
						enum v4l2_buf_type type)
{
	struct fimc_is_dev *isp = video_drvdata(file);

	dbg_sensor("%s\n", __func__);
	return vb2_streamon(&isp->video[FIMC_IS_VIDEO_NUM_BAYER].vbq, type);
}

static int fimc_is_bayer_video_streamoff(struct file *file, void *priv,
						enum v4l2_buf_type type)
{
	struct fimc_is_dev *isp = video_drvdata(file);

	dbg_sensor("%s\n", __func__);
	return vb2_streamoff(&isp->video[FIMC_IS_VIDEO_NUM_BAYER].vbq, type);
}

static int fimc_is_bayer_video_enum_input(struct file *file, void *priv,
						struct v4l2_input *input)
{
	struct fimc_is_dev *isp = video_drvdata(file);
	struct exynos5_fimc_is_sensor_info *sensor_info;

	sensor_info = isp->pdata->sensor_info[input->index];

	dbg_sensor("index(%d) sensor(%s)\n",
		input->index, sensor_info->sensor_name);
	dbg_sensor("pos(%d) sensor_id(%d)\n",
		sensor_info->sensor_position, sensor_info->sensor_id);
	dbg_sensor("csi_id(%d) flite_id(%d)\n",
		sensor_info->csi_id, sensor_info->flite_id);
	dbg_sensor("i2c_ch(%d)\n", sensor_info->i2c_channel);

	if (input->index >= FIMC_IS_MAX_CAMIF_CLIENTS)
		return -EINVAL;

	input->type = V4L2_INPUT_TYPE_CAMERA;

	strncpy(input->name, sensor_info->sensor_name,
					FIMC_IS_MAX_SENSOR_NAME_LEN);
	return 0;
}

static int fimc_is_bayer_video_g_input(struct file *file, void *priv,
						unsigned int *input)
{
	dbg_sensor("%s\n", __func__);
	return 0;
}

static int fimc_is_bayer_video_s_input(struct file *file, void *priv,
						unsigned int input)
{
	struct fimc_is_dev *isp = video_drvdata(file);
	struct fimc_is_sensor_dev *sensor;
	struct exynos5_fimc_is_sensor_info *sensor_info;

	sensor_info = isp->pdata->sensor_info[input];
	isp->sensor.id_position = input;
	isp->sensor.sensor_type = fimc_is_hw_get_sensor_type(
		sensor_info->sensor_id, sensor_info->flite_id);

	fimc_is_hw_set_default_size(isp, sensor_info->sensor_id);

	/*iky to do here*/
	sensor = &isp->sensor;
	sensor->flite_ch = sensor_info->flite_id;
	if (sensor->flite_ch == FLITE_ID_A)
		sensor->regs = (unsigned long)S5P_VA_FIMCLITE0;
	else if (sensor->flite_ch == FLITE_ID_B)
		sensor->regs = (unsigned long)S5P_VA_FIMCLITE1;

	dbg_sensor("%s sensor info : pos(%d) type(%d) 0x%08X\n", \
		__func__, input, isp->sensor.sensor_type, sensor->regs);

	return 0;
}

const struct v4l2_file_operations fimc_is_bayer_video_fops = {
	.owner		= THIS_MODULE,
	.open		= fimc_is_bayer_video_open,
	.release	= fimc_is_bayer_video_close,
	.poll		= fimc_is_bayer_video_poll,
	.unlocked_ioctl	= video_ioctl2,
	.mmap		= fimc_is_bayer_video_mmap,
};

const struct v4l2_ioctl_ops fimc_is_bayer_video_ioctl_ops = {
	.vidioc_querycap		= fimc_is_bayer_video_querycap,
	.vidioc_enum_fmt_vid_cap_mplane	= fimc_is_bayer_video_enum_fmt_mplane,
	.vidioc_g_fmt_vid_cap_mplane	= fimc_is_bayer_video_get_format_mplane,
	.vidioc_s_fmt_vid_cap_mplane	= fimc_is_bayer_video_set_format_mplane,
	.vidioc_try_fmt_vid_cap_mplane	= fimc_is_bayer_video_try_format_mplane,
	.vidioc_cropcap			= fimc_is_bayer_video_cropcap,
	.vidioc_g_crop			= fimc_is_bayer_video_get_crop,
	.vidioc_s_crop			= fimc_is_bayer_video_set_crop,
	.vidioc_reqbufs			= fimc_is_bayer_video_reqbufs,
	.vidioc_querybuf		= fimc_is_bayer_video_querybuf,
	.vidioc_qbuf			= fimc_is_bayer_video_qbuf,
	.vidioc_dqbuf			= fimc_is_bayer_video_dqbuf,
	.vidioc_streamon		= fimc_is_bayer_video_streamon,
	.vidioc_streamoff		= fimc_is_bayer_video_streamoff,
	.vidioc_enum_input		= fimc_is_bayer_video_enum_input,
	.vidioc_g_input			= fimc_is_bayer_video_g_input,
	.vidioc_s_input			= fimc_is_bayer_video_s_input,
};

static int fimc_is_bayer_queue_setup(struct vb2_queue *vq,
			unsigned int *num_buffers, unsigned int *num_planes,
			unsigned long sizes[],
			void *allocators[])
{

	struct fimc_is_video_dev *video = vq->drv_priv;
	struct fimc_is_dev	*isp = video->dev;
	int i;

	*num_planes = video->frame.format.num_planes;
	fimc_is_set_plane_size(&video->frame, sizes);

	for (i = 0; i < *num_planes; i++)
		allocators[i] =  isp->alloc_ctx;

	dbg_sensor("%s(num_planes : %d)(size : %d)\n",
		__func__, (int)*num_planes, (int)sizes[0]);

	return 0;
}

static inline void fimc_is_bayer_lock(struct vb2_queue *vq)
{
	dbg_sensor("-%s\n", __func__);
}

static inline void fimc_is_bayer_unlock(struct vb2_queue *vq)
{
	dbg_sensor("-%s\n", __func__);
}

static int fimc_is_bayer_start_streaming(struct vb2_queue *q)
{
	struct fimc_is_video_dev *sensor_video = q->drv_priv;
	struct fimc_is_dev	*isp = sensor_video->dev;
	struct fimc_is_sensor_dev *sensor = &isp->sensor;
	struct flite_frame f_frame;
	struct isp_param *isp_param;
	struct odc_param *odc_param;
	unsigned int width, height;
	int ret;
	int i;
	int buf_index;

	dbg_sensor("%s(pipe_state : %d)\n", __func__, (int)isp->pipe_state);

	if (test_bit(FIMC_IS_STATE_BAYER_BUFFER_PREPARED,
		&isp->pipe_state) &&
		!test_bit(FIMC_IS_STATE_HW_STREAM_ON, &isp->pipe_state)) {
		dbg_sensor("IS Stream On\n");

		/*iky to do here*/
		set_bit(IS_ST_CHANGE_MODE, &isp->state);

		width = isp->video[FIMC_IS_VIDEO_NUM_SCALERC].frame.width;
		height = isp->video[FIMC_IS_VIDEO_NUM_SCALERC].frame.height;

		isp_param = &isp->is_p_region->parameter.isp;
		isp_param->control.cmd = CONTROL_COMMAND_START;
		isp_param->control.bypass = CONTROL_BYPASS_DISABLE;
		/*isp->is_p_region->parameter.isp.control.run_mode = 0;*/
		isp_param->control.run_mode = 1;

		isp_param->otf_input.cmd = OTF_INPUT_COMMAND_DISABLE;
		isp_param->otf_input.width = width;
		isp_param->otf_input.height = height;
		isp_param->otf_input.format = OTF_INPUT_FORMAT_BAYER;
		isp_param->otf_input.bitwidth = OTF_INPUT_BIT_WIDTH_10BIT;
		isp_param->otf_input.order = OTF_INPUT_ORDER_BAYER_GR_BG;
		isp_param->otf_input.frametime_min = 0;
		isp_param->otf_input.frametime_max = 33333;

		isp_param->dma1_input.cmd = DMA_INPUT_COMMAND_ENABLE;
		isp_param->dma1_input.width = width;
		isp_param->dma1_input.height = height;
		isp_param->dma1_input.format = DMA_INPUT_FORMAT_BAYER;
		isp_param->dma1_input.crop_offset_x = 0;
		isp_param->dma1_input.crop_offset_y = 0;
		isp_param->dma1_input.crop_width = 0;
		isp_param->dma1_input.crop_height = 0;
		isp_param->dma1_input.wide_frame_gap = 1;
		isp_param->dma1_input.frame_gap = 0x1000;
		isp_param->dma1_input.line_gap = 45;
		isp_param->dma1_input.user_min_frame_time = 0;
		isp_param->dma1_input.user_max_frame_time = 33333;
		isp_param->dma1_input.bitwidth = DMA_INPUT_BIT_WIDTH_10BIT;
		isp_param->dma1_input.order = DMA_INPUT_ORDER_GR_BG;
		isp_param->dma1_input.plane = 1;
		isp_param->dma1_input.buffer_number = 1;
		isp_param->dma1_input.buffer_address = \
			(u32)isp->mem.dvaddr_shared + 100*sizeof(u32);
		isp->is_p_region->shared[100] = 0xffffffff;

		IS_SET_PARAM_BIT(isp, PARAM_ISP_DMA1_INPUT);
		IS_SET_PARAM_BIT(isp, PARAM_ISP_OTF_INPUT);
		IS_SET_PARAM_BIT(isp, PARAM_ISP_CONTROL);
		IS_INC_PARAM_NUM(isp);
		IS_INC_PARAM_NUM(isp);
		IS_INC_PARAM_NUM(isp);

		odc_param = &isp->is_p_region->parameter.odc;
		odc_param->control.cmd = CONTROL_COMMAND_START;
		odc_param->control.bypass = CONTROL_BYPASS_ENABLE;

		IS_SET_PARAM_BIT(isp, PARAM_ODC_CONTROL);
		IS_INC_PARAM_NUM(isp);

		fimc_is_mem_cache_clean((void *)isp->is_p_region,
			IS_PARAM_SIZE);

		fimc_is_hw_set_param(isp);

		dbg_sensor("mode change(%dx%d)\n", width, height);
		fimc_is_hw_change_mode(isp, IS_MODE_PREVIEW_STILL);
		mutex_lock(&isp->lock);
		ret = wait_event_timeout(isp->irq_queue,
			test_bit(IS_ST_CHANGE_MODE_DONE,
			&isp->state),
			FIMC_IS_SHUTDOWN_TIMEOUT);
		mutex_unlock(&isp->lock);
		if (!ret) {
			dev_err(&isp->pdev->dev,
				"Mode change timeout:%s\n", __func__);
			return -EBUSY;
		}

		init_fimc_lite(sensor->regs);

		for (i = 0; i < sensor_video->num_buf; i++) {
			buf_index = i*sensor_video->frame.format.num_planes;
			dbg_sensor("(%d)set buf(%d) = 0x%08x\n",
				buf_index, i, sensor_video->buf[i][0]);

			flite_hw_set_use_buffer(sensor->regs, (i+1));
			flite_hw_set_start_addr(sensor->regs, (i+1),
				sensor_video->buf[i][0]);
		}

		/*flite_hw_set_use_buffer(sensor->regs, 1);*/
		flite_hw_set_output_dma(sensor->regs, true);
		flite_hw_set_output_local(sensor->regs, false);

		f_frame.o_width = width + 16;
		f_frame.o_height = height + 10;
		f_frame.offs_h = 0;
		f_frame.offs_v = 0;
		f_frame.width = width + 16;
		f_frame.height = height + 10;

		dbg_sensor("start_fimc(%dx%d)",
			(width + 16),
			(height + 10));

		start_fimc_lite(sensor->regs, &f_frame);

		set_bit(FIMC_IS_STATE_SENSOR_INITIALIZED, &isp->pipe_state);
		set_bit(FIMC_IS_STATE_BAYER_STREAM_ON, &isp->pipe_state);
#if 1
		fimc_is_hw_set_stream(isp, 1);
		mutex_lock(&isp->lock);
		ret = wait_event_timeout(isp->irq_queue,
			test_bit(IS_ST_STREAM_ON, &isp->state),
			FIMC_IS_SHUTDOWN_TIMEOUT);

		mutex_unlock(&isp->lock);
		if (!ret) {
			dev_err(&isp->pdev->dev,
				"wait timeout : %s\n", __func__);
			return -EBUSY;
		}
		clear_bit(IS_ST_STREAM_ON, &isp->state);
		set_bit(FIMC_IS_STATE_HW_STREAM_ON, &isp->pipe_state);
#endif
	}

	return 0;
}

static int fimc_is_bayer_stop_streaming(struct vb2_queue *q)
{
	struct fimc_is_video_dev *sensor_video = q->drv_priv;
	struct fimc_is_dev	*isp = sensor_video->dev;
	int sensor_id, flite_ch;

#if 1
	dbg_sensor("%s\n", __func__);

	sensor_id = isp->sensor.id_position;
	flite_ch = isp->pdata->sensor_info[sensor_id]->flite_id;
	stop_fimc_lite(flite_ch);

	clear_bit(FIMC_IS_STATE_BAYER_BUFFER_PREPARED, &isp->pipe_state);
	clear_bit(FIMC_IS_STATE_BAYER_STREAM_ON, &isp->pipe_state);
#else
	IS_ISP_SET_PARAM_DMA_OUTPUT2_CMD(isp,
			DMA_OUTPUT_COMMAND_DISABLE);
	IS_ISP_SET_PARAM_DMA_OUTPUT2_BUFFER_NUMBER(isp, 0);
	IS_ISP_SET_PARAM_DMA_OUTPUT2_BUFFER_ADDRESS(isp, 0);

	IS_SET_PARAM_BIT(isp, PARAM_ISP_DMA2_OUTPUT);
	IS_INC_PARAM_NUM(isp);

	fimc_is_mem_cache_clean((void *)isp->is_p_region,
		IS_PARAM_SIZE);

	isp->scenario_id = ISS_PREVIEW_STILL;
	set_bit(IS_ST_INIT_PREVIEW_STILL,	&isp->state);
	clear_bit(IS_ST_INIT_PREVIEW_VIDEO, &isp->state);
	fimc_is_hw_set_param(isp);
	mutex_lock(&isp->lock);
	ret = wait_event_timeout(isp->irq_queue,
		test_bit(IS_ST_INIT_PREVIEW_VIDEO, &isp->state),
		FIMC_IS_SHUTDOWN_TIMEOUT);
	mutex_unlock(&isp->lock);
	if (!ret) {
		dev_err(&isp->pdev->dev,
			"wait timeout : %s\n", __func__);
		return -EBUSY;
	}


	if (!test_bit(FIMC_IS_STATE_SCALERC_STREAM_ON, &isp->pipe_state) &&
		!test_bit(FIMC_IS_STATE_SCALERP_STREAM_ON, &isp->pipe_state)) {
		clear_bit(IS_ST_STREAM_OFF, &isp->state);
		fimc_is_hw_set_stream(isp, 0);
		dbg("IS Stream Off");
		mutex_lock(&isp->lock);
		ret = wait_event_timeout(isp->irq_queue,
			test_bit(IS_ST_STREAM_OFF, &isp->state),
			FIMC_IS_SHUTDOWN_TIMEOUT);
		mutex_unlock(&isp->lock);
		if (!ret) {
			dev_err(&isp->pdev->dev,
				"wait timeout : %s\n", __func__);
			return -EBUSY;
		}
		clear_bit(FIMC_IS_STATE_HW_STREAM_ON, &isp->pipe_state);
	}

	clear_bit(IS_ST_RUN, &isp->state);
	clear_bit(IS_ST_STREAM_ON, &isp->state);
	clear_bit(FIMC_IS_STATE_BAYER_BUFFER_PREPARED, &isp->pipe_state);
	clear_bit(FIMC_IS_STATE_BAYER_STREAM_ON, &isp->pipe_state);
#endif

	return 0;
}

static void fimc_is_bayer_buffer_queue(struct vb2_buffer *vb)
{
	struct fimc_is_video_dev *video = vb->vb2_queue->drv_priv;
	struct fimc_is_dev	*isp = video->dev;
	struct fimc_is_video_dev *sensor_video;
	unsigned int i;

	dbg_sensor("%s\n", __func__);

	sensor_video = &isp->video[FIMC_IS_VIDEO_NUM_BAYER];
	sensor_video->frame.format.num_planes = vb->num_planes;

	if (!test_bit(FIMC_IS_STATE_BAYER_BUFFER_PREPARED, &isp->pipe_state)) {
		for (i = 0; i < vb->num_planes; i++) {
			sensor_video->buf[vb->v4l2_buf.index][i]
				= isp->vb2->plane_addr(vb, i);
			dbg("index(%d)(%d) deviceVaddr(0x%08x)\n",
				vb->v4l2_buf.index,
				i, sensor_video->buf[vb->v4l2_buf.index][i]);
		}

		sensor_video->buf_ref_cnt++;

		if (sensor_video->num_buf == sensor_video->buf_ref_cnt)
			set_bit(FIMC_IS_STATE_BAYER_BUFFER_PREPARED,
			&isp->pipe_state);
	}

	if (!test_bit(FIMC_IS_STATE_BAYER_STREAM_ON, &isp->pipe_state))
		fimc_is_bayer_start_streaming(vb->vb2_queue);

	return;
}

const struct vb2_ops fimc_is_bayer_qops = {
	.queue_setup		= fimc_is_bayer_queue_setup,
	.buf_prepare		= vb2_ion_buf_prepare,
	.buf_queue		= fimc_is_bayer_buffer_queue,
	.buf_finish             = vb2_ion_buf_finish,
	.wait_prepare		= fimc_is_bayer_unlock,
	.wait_finish		= fimc_is_bayer_lock,
	.start_streaming	= fimc_is_bayer_start_streaming,
	.stop_streaming	= fimc_is_bayer_stop_streaming,
};
