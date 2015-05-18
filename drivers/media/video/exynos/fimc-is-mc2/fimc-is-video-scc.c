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
#if defined(CONFIG_BUSFREQ_OPP) && defined(CONFIG_CPU_EXYNOS5250)
#include <mach/dev.h>
#endif
#include <plat/bts.h>
#include <media/exynos_mc.h>
#include <linux/cma.h>
#include <asm/cacheflush.h>
#include <asm/pgtable.h>
#include <linux/firmware.h>
#include <linux/dma-mapping.h>
#include <linux/delay.h>
#include <linux/scatterlist.h>
#include <linux/videodev2_exynos_media.h>
#include <linux/videodev2_exynos_camera.h>
#include <linux/v4l2-mediabus.h>

#include "fimc-is-core.h"
#include "fimc-is-param.h"
#include "fimc-is-cmd.h"
#include "fimc-is-regs.h"
#include "fimc-is-err.h"
#include "fimc-is-video.h"
#include "fimc-is-metadata.h"
#include "fimc-is-device-ischain.h"

int fimc_is_scc_video_probe(void *core_data)
{
	int ret = 0;
	struct fimc_is_core *core = (struct fimc_is_core *)core_data;
	struct fimc_is_video_scc *video = &core->video_scc;

	dbg_scc("%s\n", __func__);

	ret = fimc_is_video_probe(&video->common,
		core_data,
		video,
		FIMC_IS_VIDEO_SCALERC_NAME,
		FIMC_IS_VIDEO_NUM_SCALERC,
		V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE,
		&fimc_is_scalerc_video_fops,
		&fimc_is_scalerc_video_ioctl_ops,
		&fimc_is_scalerc_qops);

	return ret;
}

/*************************************************************************/
/* video file opertation */
/************************************************************************/

static int fimc_is_scalerc_video_open(struct file *file)
{
	struct fimc_is_core *core = video_drvdata(file);
	struct fimc_is_video_scc *video = &core->video_scc;
	struct fimc_is_device_ischain *ischain = &core->ischain;
	struct fimc_is_ischain_dev *scc = &ischain->scc;

	dbg_scc("%s\n", __func__);

	file->private_data = video;
	fimc_is_video_open(&video->common, ischain);
	fimc_is_ischain_dev_open(scc, &video->common, NUM_SCC_DMA_BUF);

	return 0;
}

static int fimc_is_scalerc_video_close(struct file *file)
{
	int ret = 0;
	struct fimc_is_video_scc *video = file->private_data;
	struct fimc_is_video_common *common = &video->common;
	struct fimc_is_device_ischain *ischain = common->device;
	struct fimc_is_ischain_dev *scc = &ischain->scc;

	dbg("%s\n", __func__);

	if (test_bit(FIMC_IS_VIDEO_STREAM_ON, &common->state)) {
		clear_bit(FIMC_IS_VIDEO_STREAM_ON, &video->common.state);
		fimc_is_frame_close(&scc->framemgr);
	}

	file->private_data = 0;
	fimc_is_video_close(&video->common);

	return ret;
}

static unsigned int fimc_is_scalerc_video_poll(struct file *file,
				      struct poll_table_struct *wait)
{
	struct fimc_is_video_scc *video = file->private_data;

	dbg("%s\n", __func__);
	return vb2_poll(&video->common.vbq, file, wait);

}

static int fimc_is_scalerc_video_mmap(struct file *file,
					struct vm_area_struct *vma)
{
	struct fimc_is_video_scc *video = file->private_data;

	dbg("%s\n", __func__);
	return vb2_mmap(&video->common.vbq, vma);

}

/*************************************************************************/
/* video ioctl operation						*/
/************************************************************************/

static int fimc_is_scalerc_video_querycap(struct file *file, void *fh,
						struct v4l2_capability *cap)
{
	struct fimc_is_core *isp = video_drvdata(file);

	strncpy(cap->driver, isp->pdev->name, sizeof(cap->driver) - 1);

	dbg("(devname : %s)\n", cap->driver);
	strncpy(cap->card, isp->pdev->name, sizeof(cap->card) - 1);
	cap->bus_info[0] = 0;
	cap->version = KERNEL_VERSION(1, 0, 0);
	cap->capabilities = V4L2_CAP_STREAMING
				| V4L2_CAP_VIDEO_CAPTURE
				| V4L2_CAP_VIDEO_CAPTURE_MPLANE;

	return 0;
}

static int fimc_is_scalerc_video_enum_fmt_mplane(struct file *file, void *priv,
				    struct v4l2_fmtdesc *f)
{
	dbg("%s\n", __func__);
	return 0;
}

static int fimc_is_scalerc_video_get_format_mplane(struct file *file, void *fh,
						struct v4l2_format *format)
{
	dbg("%s\n", __func__);
	return 0;
}

static int fimc_is_scalerc_video_set_format_mplane(struct file *file, void *fh,
						struct v4l2_format *format)
{
	int ret = 0;
	struct fimc_is_video_scc *video = file->private_data;

	dbg_scp("%s\n", __func__);

	ret = fimc_is_video_set_format_mplane(&video->common, format);

	dbg_scc("req w : %d req h : %d\n",
		video->common.frame.width,
		video->common.frame.height);

	return ret;
}

static int fimc_is_scalerc_video_try_format_mplane(struct file *file, void *fh,
						struct v4l2_format *format)
{
	dbg("%s\n", __func__);
	return 0;
}

static int fimc_is_scalerc_video_cropcap(struct file *file, void *fh,
						struct v4l2_cropcap *cropcap)
{
	dbg("%s\n", __func__);
	return 0;
}

static int fimc_is_scalerc_video_get_crop(struct file *file, void *fh,
						struct v4l2_crop *crop)
{
	dbg("%s\n", __func__);
	return 0;
}

static int fimc_is_scalerc_video_set_crop(struct file *file, void *fh,
						struct v4l2_crop *crop)
{
	dbg("%s\n", __func__);
	return 0;
}

static int fimc_is_scalerc_video_reqbufs(struct file *file, void *priv,
					struct v4l2_requestbuffers *buf)
{
	int ret;
	struct fimc_is_video_scc *video = file->private_data;

	dbg_scc("%s\n", __func__);

	ret = fimc_is_video_reqbufs(&video->common, buf);
	if (ret)
		err("fimc_is_video_reqbufs is fail(error %d)", ret);

	return ret;
}

static int fimc_is_scalerc_video_querybuf(struct file *file, void *priv,
						struct v4l2_buffer *buf)
{
	int ret;
	struct fimc_is_video_scc *video = file->private_data;

	dbg("%s\n", __func__);
	ret = vb2_querybuf(&video->common.vbq, buf);

	return ret;
}

static int fimc_is_scalerc_video_qbuf(struct file *file, void *priv,
	struct v4l2_buffer *buf)
{
	int ret = 0;
	struct fimc_is_video_scc *video = file->private_data;

#ifdef DBG_STREAMING
	/*dbg_scc("%s(index : %d)\n", __func__, buf->index);*/
#endif

	ret = fimc_is_video_qbuf(&video->common, buf);

	return ret;
}

static int fimc_is_scalerc_video_dqbuf(struct file *file, void *priv,
	struct v4l2_buffer *buf)
{
	int ret = 0;
	struct fimc_is_video_scc *video = file->private_data;

	ret = fimc_is_video_dqbuf(&video->common, buf,
		file->f_flags & O_NONBLOCK);

#ifdef DBG_STREAMING
	/*dbg_scc("%s(index : %d)\n", __func__, buf->index);*/
#endif

	return ret;
}

static int fimc_is_scalerc_video_streamon(struct file *file, void *priv,
						enum v4l2_buf_type type)
{
	struct fimc_is_video_scc *video = file->private_data;

	dbg("%s\n", __func__);
	return vb2_streamon(&video->common.vbq, type);
}

static int fimc_is_scalerc_video_streamoff(struct file *file, void *priv,
						enum v4l2_buf_type type)
{
	struct fimc_is_video_scc *video = file->private_data;

	dbg("%s\n", __func__);
	return vb2_streamoff(&video->common.vbq, type);
}

static int fimc_is_scalerc_video_enum_input(struct file *file, void *priv,
						struct v4l2_input *input)
{
	struct fimc_is_core *isp = video_drvdata(file);
	struct exynos5_fimc_is_sensor_info *sensor_info
			= isp->pdata->sensor_info[input->index];

	dbg("index(%d) sensor(%s)\n",
		input->index, sensor_info->sensor_name);
	dbg("pos(%d) sensor_id(%d)\n",
		sensor_info->sensor_position, sensor_info->sensor_id);
	dbg("csi_id(%d) flite_id(%d)\n",
		sensor_info->csi_id, sensor_info->flite_id);
	dbg("i2c_ch(%d)\n", sensor_info->i2c_channel);

	if (input->index >= FIMC_IS_MAX_CAMIF_CLIENTS)
		return -EINVAL;

	input->type = V4L2_INPUT_TYPE_CAMERA;

	strncpy(input->name, sensor_info->sensor_name,
					FIMC_IS_MAX_SENSOR_NAME_LEN);
	return 0;
}

static int fimc_is_scalerc_video_g_input(struct file *file, void *priv,
						unsigned int *input)
{
	dbg("%s\n", __func__);
	return 0;
}

static int fimc_is_scalerc_video_s_input(struct file *file, void *priv,
						unsigned int input)
{
	return 0;
}

const struct v4l2_file_operations fimc_is_scalerc_video_fops = {
	.owner		= THIS_MODULE,
	.open		= fimc_is_scalerc_video_open,
	.release	= fimc_is_scalerc_video_close,
	.poll		= fimc_is_scalerc_video_poll,
	.unlocked_ioctl	= video_ioctl2,
	.mmap		= fimc_is_scalerc_video_mmap,
};

const struct v4l2_ioctl_ops fimc_is_scalerc_video_ioctl_ops = {
	.vidioc_querycap		= fimc_is_scalerc_video_querycap,
	.vidioc_enum_fmt_vid_cap_mplane
				= fimc_is_scalerc_video_enum_fmt_mplane,
	.vidioc_g_fmt_vid_cap_mplane
				= fimc_is_scalerc_video_get_format_mplane,
	.vidioc_s_fmt_vid_cap_mplane
				= fimc_is_scalerc_video_set_format_mplane,
	.vidioc_try_fmt_vid_cap_mplane
				= fimc_is_scalerc_video_try_format_mplane,
	.vidioc_cropcap			= fimc_is_scalerc_video_cropcap,
	.vidioc_g_crop			= fimc_is_scalerc_video_get_crop,
	.vidioc_s_crop			= fimc_is_scalerc_video_set_crop,
	.vidioc_reqbufs			= fimc_is_scalerc_video_reqbufs,
	.vidioc_querybuf		= fimc_is_scalerc_video_querybuf,
	.vidioc_qbuf			= fimc_is_scalerc_video_qbuf,
	.vidioc_dqbuf			= fimc_is_scalerc_video_dqbuf,
	.vidioc_streamon		= fimc_is_scalerc_video_streamon,
	.vidioc_streamoff		= fimc_is_scalerc_video_streamoff,
	.vidioc_enum_input		= fimc_is_scalerc_video_enum_input,
	.vidioc_g_input			= fimc_is_scalerc_video_g_input,
	.vidioc_s_input			= fimc_is_scalerc_video_s_input,
};

static int fimc_is_scalerc_queue_setup(struct vb2_queue *vq,
			unsigned int *num_buffers,
			unsigned int *num_planes, unsigned long sizes[],
			void *allocators[])
{
	int ret = 0;
	struct fimc_is_video_scc *video = vq->drv_priv;

	dbg_sensor("%s\n", __func__);

	ret = fimc_is_video_queue_setup(&video->common,
		num_planes,
		sizes,
		allocators);

	dbg_sensor("(num_planes : %d)(size : %d)\n",
		(int)*num_planes, (int)sizes[0]);

	return ret;
}
static int fimc_is_scalerc_buffer_prepare(struct vb2_buffer *vb)
{
	return 0;
}


static inline void fimc_is_scalerc_lock(struct vb2_queue *vq)
{
}

static inline void fimc_is_scalerc_unlock(struct vb2_queue *vq)
{
}

static int fimc_is_scalerc_start_streaming(struct vb2_queue *q)
{
	int ret = 0;
	struct fimc_is_video_scc *video = q->drv_priv;

	dbg_scc("%s\n", __func__);

	if (test_bit(FIMC_IS_VIDEO_BUFFER_PREPARED, &video->common.state))
		set_bit(FIMC_IS_VIDEO_STREAM_ON, &video->common.state);

	return ret;
}

static int fimc_is_scalerc_stop_streaming(struct vb2_queue *q)
{
	int ret = 0;
	struct fimc_is_video_scc *video = q->drv_priv;
	struct fimc_is_device_ischain *ischain = video->common.device;
	struct fimc_is_ischain_dev *scc = &ischain->scc;

	dbg_scc("%s\n", __func__);

	if (test_bit(FIMC_IS_VIDEO_STREAM_ON, &video->common.state)) {
		clear_bit(FIMC_IS_VIDEO_STREAM_ON, &video->common.state);
		clear_bit(FIMC_IS_VIDEO_BUFFER_PREPARED, &video->common.state);
		fimc_is_frame_close(&scc->framemgr);
		fimc_is_frame_open(&scc->framemgr, NUM_SCC_DMA_BUF);
	}

	return ret;
}

static void fimc_is_scalerc_buffer_queue(struct vb2_buffer *vb)
{
	struct fimc_is_video_scc *video = vb->vb2_queue->drv_priv;
	struct fimc_is_device_ischain *ischain = video->common.device;
	struct fimc_is_ischain_dev *scc = &ischain->scc;

#ifdef DBG_STREAMING
	dbg_scc("%s\n", __func__);
#endif

	fimc_is_video_buffer_queue(&video->common, vb, &scc->framemgr);
	fimc_is_ischain_dev_buffer_queue(scc, vb->v4l2_buf.index);

	if (!test_bit(FIMC_IS_VIDEO_STREAM_ON, &video->common.state))
		fimc_is_scalerc_start_streaming(vb->vb2_queue);
}

static int fimc_is_scalerc_buffer_finish(struct vb2_buffer *vb)
{
	int ret = 0;
	struct fimc_is_video_scc *video = vb->vb2_queue->drv_priv;
	struct fimc_is_device_ischain *ischain = video->common.device;
	struct fimc_is_ischain_dev *scc = &ischain->scc;

#ifdef DBG_STREAMING
	dbg_scc("%s(%d)\n", __func__, vb->v4l2_buf.index);
#endif

	ret = fimc_is_ischain_dev_buffer_finish(scc, vb->v4l2_buf.index);

	return ret;
}

const struct vb2_ops fimc_is_scalerc_qops = {
	.queue_setup		= fimc_is_scalerc_queue_setup,
	.buf_prepare		= fimc_is_scalerc_buffer_prepare,
	.buf_queue		= fimc_is_scalerc_buffer_queue,
	.buf_finish		= fimc_is_scalerc_buffer_finish,
	.wait_prepare		= fimc_is_scalerc_unlock,
	.wait_finish		= fimc_is_scalerc_lock,
	.start_streaming	= fimc_is_scalerc_start_streaming,
	.stop_streaming		= fimc_is_scalerc_stop_streaming,
};

