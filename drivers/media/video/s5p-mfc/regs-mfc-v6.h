/*
 * Register definition file for Samsung MFC V5.1 Interface (FIMV) driver
 *
 * Kamil Debski, Copyright (c) 2010 Samsung Electronics
 * http://www.samsung.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#ifndef _REGS_FIMV_V6_H
#define _REGS_FIMV_V6_H

#define S5P_FIMV_REG_SIZE	(S5P_FIMV_END_ADDR - S5P_FIMV_START_ADDR)
#define S5P_FIMV_REG_COUNT	((S5P_FIMV_END_ADDR - S5P_FIMV_START_ADDR) / 4)

/* Number of bits that the buffer address should be shifted for particular
 * MFC buffers.  */
#define S5P_FIMV_MEM_OFFSET		0

#define S5P_FIMV_START_ADDR		0x0000
#define S5P_FIMV_END_ADDR		0xfd80

#define S5P_FIMV_REG_CLEAR_BEGIN	0xf000
#define S5P_FIMV_REG_CLEAR_COUNT	1024

/* Codec Common Registers */
#define S5P_FIMV_RISC_ON			0x0000
#define S5P_FIMV_RISC2HOST_INT			0x003C
#define S5P_FIMV_HOST2RISC_INT			0x0044
#define S5P_FIMV_RISC_BASE_ADDRESS		0x0054

#define S5P_FIMV_MFC_RESET			0x1070

/* FIXME: Need to unify H2R and CH */
#define S5P_FIMV_HOST2RISC_CMD			0x1100
#define S5P_FIMV_H2R_CMD_EMPTY			0
#define S5P_FIMV_H2R_CMD_SYS_INIT		1
#define S5P_FIMV_H2R_CMD_OPEN_INSTANCE		2
#define S5P_FIMV_CH_SEQ_HEADER			3
#define S5P_FIMV_CH_INIT_BUFS			4
#define S5P_FIMV_CH_FRAME_START			5
#define S5P_FIMV_H2R_CMD_CLOSE_INSTANCE		6
#define S5P_FIMV_H2R_CMD_SLEEP			7
#define S5P_FIMV_H2R_CMD_WAKEUP			8
#define S5P_FIMV_CH_LAST_FRAME			9
#define S5P_FIMV_H2R_CMD_FLUSH			10
/* RMVME: REALLOC used? */
#define S5P_FIMV_CH_FRAME_START_REALLOC		5

#define S5P_FIMV_RISC2HOST_CMD			0x1104
#define S5P_FIMV_R2H_CMD_EMPTY			0
#define S5P_FIMV_R2H_CMD_SYS_INIT_RET		1
#define S5P_FIMV_R2H_CMD_OPEN_INSTANCE_RET	2
#define S5P_FIMV_R2H_CMD_SEQ_DONE_RET		3
#define S5P_FIMV_R2H_CMD_INIT_BUFFERS_RET	4

#define S5P_FIMV_R2H_CMD_CLOSE_INSTANCE_RET	6
#define S5P_FIMV_R2H_CMD_SLEEP_RET		7
#define S5P_FIMV_R2H_CMD_WAKEUP_RET		8
#define S5P_FIMV_R2H_CMD_COMPLETE_SEQ_RET	9
#define S5P_FIMV_R2H_CMD_DPB_FLUSH_RET		10
#define S5P_FIMV_R2H_CMD_NAL_ABORT_RET		11
#define S5P_FIMV_R2H_CMD_FW_STATUS_RET		12
#define S5P_FIMV_R2H_CMD_FRAME_DONE_RET		13
#define S5P_FIMV_R2H_CMD_FIELD_DONE_RET		14
#define S5P_FIMV_R2H_CMD_SLICE_DONE_RET		15
#define S5P_FIMV_R2H_CMD_ENC_BUFFER_FUL_RET	16
#define S5P_FIMV_R2H_CMD_ERR_RET		32

#define S5P_FIMV_MFC_BUS_RESET_CTRL		0x7110
#define S5P_FIMV_FW_VERSION			0xF000

#define S5P_FIMV_INSTANCE_ID			0xF008
#define S5P_FIMV_CODEC_TYPE			0xF00C
#define S5P_FIMV_CONTEXT_MEM_ADDR		0xF014
#define S5P_FIMV_CONTEXT_MEM_SIZE		0xF018
#define S5P_FIMV_PIXEL_FORMAT			0xF020

#define S5P_FIMV_METADATA_ENABLE		0xF024
#define S5P_FIMV_MFC_VERSION			0xF028
#define S5P_FIMV_DBG_BUFFER_ADDR		0xF030
#define S5P_FIMV_DBG_BUFFER_SIZE		0xF034
#define S5P_FIMV_RET_INSTANCE_ID		0xF070

#define S5P_FIMV_ERROR_CODE			0xF074
#define S5P_FIMV_ERR_WARNINGS_START		160
#define S5P_FIMV_ERR_DEC_MASK			0xFFFF
#define S5P_FIMV_ERR_DEC_SHIFT			0
#define S5P_FIMV_ERR_DSPL_MASK			0xFFFF0000
#define S5P_FIMV_ERR_DSPL_SHIFT			16

#define S5P_FIMV_DBG_BUFFER_OUTPUT_SIZE		0xF078
#define S5P_FIMV_METADATA_STATUS		0xF07C
#define S5P_FIMV_METADATA_ADDR_MB_INFO		0xF080
#define S5P_FIMV_METADATA_SIZE_MB_INFO		0xF084

/* Decoder Registers */
#define S5P_FIMV_D_CRC_CTRL			0xF0B0
#define S5P_FIMV_D_DEC_OPTIONS			0xF0B4
#define S5P_FIMV_D_OPT_FMO_ASO_CTRL_MASK	4
#define S5P_FIMV_D_OPT_DDELAY_EN_SHIFT		3
#define S5P_FIMV_D_OPT_LF_CTRL_SHIFT		1
#define S5P_FIMV_D_OPT_LF_CTRL_MASK		0x3
#define S5P_FIMV_D_OPT_TILE_MODE_SHIFT		0

#define S5P_FIMV_D_DISPLAY_DELAY		0xF0B8

#define S5P_FIMV_D_SET_FRAME_WIDTH		0xF0BC
#define S5P_FIMV_D_SET_FRAME_HEIGHT		0xF0C0

#define S5P_FIMV_D_SEI_ENABLE			0xF0C4

/* Buffer setting registers */
#define S5P_FIMV_D_MIN_NUM_DPB			0xF0F0
#define S5P_FIMV_D_MIN_LUMA_DPB_SIZE		0xF0F4
#define S5P_FIMV_D_MIN_CHROMA_DPB_SIZE		0xF0F8
#define S5P_FIMV_D_MVC_NUM_VIEWS		0xF0FC
#define S5P_FIMV_D_MIN_NUM_MV			0xF100
#define S5P_FIMV_D_NUM_DPB			0xF130
#define S5P_FIMV_D_LUMA_DPB_SIZE		0xF134
#define S5P_FIMV_D_CHROMA_DPB_SIZE		0xF138
#define S5P_FIMV_D_MV_BUFFER_SIZE		0xF13C

#define S5P_FIMV_D_LUMA_DPB			0xF140
#define S5P_FIMV_D_CHROMA_DPB			0xF240
#define S5P_FIMV_D_MV_BUFFER			0xF340

#define S5P_FIMV_D_SCRATCH_BUFFER_ADDR		0xF440
#define S5P_FIMV_D_SCRATCH_BUFFER_SIZE		0xF444
#define S5P_FIMV_D_METADATA_BUFFER_ADDR		0xF448
#define S5P_FIMV_D_METADATA_BUFFER_SIZE		0xF44C
#define S5P_FIMV_D_NUM_MV			0xF478
#define S5P_FIMV_D_CPB_BUFFER_ADDR		0xF4B0
#define S5P_FIMV_D_CPB_BUFFER_SIZE		0xF4B4

#define S5P_FIMV_D_AVAILABLE_DPB_FLAG_UPPER	0xF4B8
#define S5P_FIMV_D_AVAILABLE_DPB_FLAG_LOWER	0xF4BC
#define S5P_FIMV_D_CPB_BUFFER_OFFSET		0xF4C0
#define S5P_FIMV_D_SLICE_IF_ENABLE		0xF4C4
#define S5P_FIMV_D_PICTURE_TAG			0xF4C8
#define S5P_FIMV_D_STREAM_DATA_SIZE		0xF4D0

/* Display information register */
#define S5P_FIMV_D_DISPLAY_FRAME_WIDTH		0xF500
#define S5P_FIMV_D_DISPLAY_FRAME_HEIGHT		0xF504

/* Display status */
#define S5P_FIMV_D_DISPLAY_STATUS		0xF508
#define S5P_FIMV_DEC_STATUS_DECODING_ONLY		0
#define S5P_FIMV_DEC_STATUS_DECODING_DISPLAY		1
#define S5P_FIMV_DEC_STATUS_DISPLAY_ONLY		2
#define S5P_FIMV_DEC_STATUS_DECODING_EMPTY		3
#define S5P_FIMV_DEC_STATUS_DECODING_STATUS_MASK	7
#define S5P_FIMV_DEC_STATUS_PROGRESSIVE			(0<<3)
#define S5P_FIMV_DEC_STATUS_INTERLACE			(1<<3)
#define S5P_FIMV_DEC_STATUS_INTERLACE_MASK		(1<<3)
#define S5P_FIMV_DEC_STATUS_RESOLUTION_MASK		(3<<4)
#define S5P_FIMV_DEC_STATUS_RESOLUTION_INC		(1<<4)
#define S5P_FIMV_DEC_STATUS_RESOLUTION_DEC		(2<<4)
#define S5P_FIMV_DEC_STATUS_RESOLUTION_SHIFT		4
#define S5P_FIMV_DEC_STATUS_CRC_GENERATED		(1<<5)
#define S5P_FIMV_DEC_STATUS_CRC_NOT_GENERATED		(0<<5)
#define S5P_FIMV_DEC_STATUS_CRC_MASK			(1<<5)

#define S5P_FIMV_D_DISPLAY_LUMA_ADDR		0xF50C
#define S5P_FIMV_D_DISPLAY_CHROMA_ADDR		0xF510

#define S5P_FIMV_D_DISPLAY_FRAME_TYPE		0xF514
#define S5P_FIMV_DISPLAY_FRAME_MASK		7
#define S5P_FIMV_DISPLAY_FRAME_NOT_CODED	0
#define S5P_FIMV_DISPLAY_FRAME_I		1
#define S5P_FIMV_DISPLAY_FRAME_P		2
#define S5P_FIMV_DISPLAY_FRAME_B		3
#define S5P_FIMV_DISPLAY_FRAME_S_VOP		4 /* MPEG4 */
#define S5P_FIMV_SHARED_CROP_INFO_H		0x0020
#define S5P_FIMV_SHARED_CROP_LEFT_MASK		0xFFFF
#define S5P_FIMV_SHARED_CROP_LEFT_SHIFT		0
#define S5P_FIMV_SHARED_CROP_RIGHT_MASK		0xFFFF0000
#define S5P_FIMV_SHARED_CROP_RIGHT_SHIFT	16
#define S5P_FIMV_SHARED_CROP_INFO_V		0x0024
#define S5P_FIMV_SHARED_CROP_TOP_MASK		0xFFFF
#define S5P_FIMV_SHARED_CROP_TOP_SHIFT		0
#define S5P_FIMV_SHARED_CROP_BOTTOM_MASK	0xFFFF0000
#define S5P_FIMV_SHARED_CROP_BOTTOM_SHIFT	16

#define S5P_FIMV_D_DISPLAY_CROP_INFO1		0xF518
#define S5P_FIMV_D_DISPLAY_CROP_INFO2		0xF51C
#define S5P_FIMV_D_DISPLAY_PICTURE_PROFILE	0xF520
#define S5P_FIMV_D_DISPLAY_LUMA_CRC_TOP		0xF524
#define S5P_FIMV_D_DISPLAY_CHROMA_CRC_TOP	0xF528
#define S5P_FIMV_D_DISPLAY_LUMA_CRC_BOT		0xF52C
#define S5P_FIMV_D_DISPLAY_CHROMA_CRC_BOT	0xF530
#define S5P_FIMV_D_DISPLAY_ASPECT_RATIO		0xF534
#define S5P_FIMV_D_DISPLAY_EXTENDED_AR		0xF538

/* Decoded picture information register */
#define S5P_FIMV_D_DECODED_FRAME_WIDTH		0xF53C
#define S5P_FIMV_D_DECODED_FRAME_HEIGHT		0xF540
#define S5P_FIMV_D_DECODED_STATUS		0xF544
#define S5P_FIMV_DEC_CRC_GEN_MASK		0x1
#define S5P_FIMV_DEC_CRC_GEN_SHIFT		6

#define S5P_FIMV_D_DECODED_LUMA_ADDR		0xF548
#define S5P_FIMV_D_DECODED_CHROMA_ADDR		0xF54C

#define S5P_FIMV_D_DECODED_FRAME_TYPE		0xF550
#define S5P_FIMV_DECODED_FRAME_MASK		7
#define S5P_FIMV_DECODED_FRAME_NOT_CODED	0
#define S5P_FIMV_DECODED_FRAME_I		1
#define S5P_FIMV_DECODED_FRAME_P		2
#define S5P_FIMV_DECODED_FRAME_B		3
#define S5P_FIMV_DECODED_FRAME_S_VOP		4 /* MPEG4 */
#define S5P_FIMV_DECODED_FRAME_NON_DISPLAY	5 /* VP8 */

#define S5P_FIMV_D_DECODED_CROP_INFO1		0xF554
#define S5P_FIMV_D_DECODED_CROP_INFO2		0xF558
#define S5P_FIMV_D_DECODED_PICTURE_PROFILE	0xF55C
#define S5P_FIMV_D_DECODED_NAL_SIZE		0xF560
#define S5P_FIMV_D_DECODED_LUMA_CRC_TOP		0xF564
#define S5P_FIMV_D_DECODED_CHROMA_CRC_TOP	0xF568
#define S5P_FIMV_D_DECODED_LUMA_CRC_BOT		0xF56C
#define S5P_FIMV_D_DECODED_CHROMA_CRC_BOT	0xF570

/* Returned value register for specific setting */
#define S5P_FIMV_D_RET_PICTURE_TAG_TOP		0xF574
#define S5P_FIMV_D_RET_PICTURE_TAG_BOT		0xF578
#define S5P_FIMV_D_RET_PICTURE_TIME_TOP		0xF57C
#define S5P_FIMV_D_RET_PICTURE_TIME_BOT		0xF580
#define S5P_FIMV_D_CHROMA_FORMAT		0xF588
#define S5P_FIMV_D_MPEG4_INFO			0xF58C
#define S5P_FIMV_D_H264_INFO			0xF590

#define S5P_FIMV_D_METADATA_ADDR_CONCEALED_MB	0xF594
#define S5P_FIMV_D_METADATA_SIZE_CONCEALED_MB	0xF598
#define S5P_FIMV_D_METADATA_ADDR_VC1_PARAM	0xF59C
#define S5P_FIMV_D_METADATA_SIZE_VC1_PARAM	0xF5A0
#define S5P_FIMV_D_METADATA_ADDR_SEI_NAL	0xF5A4
#define S5P_FIMV_D_METADATA_SIZE_SEI_NAL	0xF5A8
#define S5P_FIMV_D_METADATA_ADDR_VUI		0xF5AC
#define S5P_FIMV_D_METADATA_SIZE_VUI		0xF5B0

#define S5P_FIMV_D_MVC_VIEW_ID			0xF5B4
#define S5P_FIMV_D_MVC_VIEW_ID_DISP_MASK	0xFFFF

/* SEI related information */
#define S5P_FIMV_D_FRAME_PACK_SEI_AVAIL		0xF5F0
#define S5P_FIMV_D_FRAME_PACK_ARRGMENT_ID	0xF5F4
#define S5P_FIMV_D_FRAME_PACK_SEI_INFO		0xF5F8
#define S5P_FIMV_D_FRAME_PACK_GRID_POS		0xF5FC

/* Encoder Registers */
#define S5P_FIMV_E_FRAME_WIDTH			0xF770
#define S5P_FIMV_E_FRAME_HEIGHT			0xF774
#define S5P_FIMV_E_CROPPED_FRAME_WIDTH		0xF778
#define S5P_FIMV_E_CROPPED_FRAME_HEIGHT		0xF77C
#define S5P_FIMV_E_FRAME_CROP_OFFSET		0xF780
#define S5P_FIMV_E_ENC_OPTIONS			0xF784
#define S5P_FIMV_E_PICTURE_PROFILE		0xF788
#define S5P_FIMV_ENC_PROFILE_H264_BASELINE		0
#define S5P_FIMV_ENC_PROFILE_H264_MAIN			1
#define S5P_FIMV_ENC_PROFILE_H264_HIGH			2
#define S5P_FIMV_ENC_PROFILE_H264_CONSTRAINED_BASELINE	3
#define S5P_FIMV_ENC_PROFILE_MPEG4_SIMPLE		0
#define S5P_FIMV_ENC_PROFILE_MPEG4_ADVANCED_SIMPLE	1
#define S5P_FIMV_E_FIXED_PICTURE_QP		0xF790

#define S5P_FIMV_E_RC_CONFIG			0xF794
#define S5P_FIMV_E_RC_QP_BOUND			0xF798
#define S5P_FIMV_E_RC_RPARAM			0xF79C
#define S5P_FIMV_E_MB_RC_CONFIG			0xF7A0
#define S5P_FIMV_E_PADDING_CTRL			0xF7A4
#define S5P_FIMV_E_MV_HOR_RANGE			0xF7AC
#define S5P_FIMV_E_MV_VER_RANGE			0xF7B0

#define S5P_FIMV_E_VBV_BUFFER_SIZE		0xF84C
#define S5P_FIMV_E_VBV_INIT_DELAY		0xF850
#define S5P_FIMV_E_NUM_DPB			0xF890
#define S5P_FIMV_E_LUMA_DPB			0xF8C0
#define S5P_FIMV_E_CHROMA_DPB			0xF904
#define S5P_FIMV_E_ME_BUFFER			0xF948

#define S5P_FIMV_E_SCRATCH_BUFFER_ADDR		0xF98C
#define S5P_FIMV_E_SCRATCH_BUFFER_SIZE		0xF990
#define S5P_FIMV_E_TMV_BUFFER0			0xF994
#define S5P_FIMV_E_TMV_BUFFER1			0xF998
#define S5P_FIMV_E_SOURCE_LUMA_ADDR		0xF9F0
#define S5P_FIMV_E_SOURCE_CHROMA_ADDR		0xF9F4
#define S5P_FIMV_E_STREAM_BUFFER_ADDR		0xF9F8
#define S5P_FIMV_E_STREAM_BUFFER_SIZE		0xF9FC
#define S5P_FIMV_E_ROI_BUFFER_ADDR		0xFA00

#define S5P_FIMV_E_PARAM_CHANGE			0xFA04
#define S5P_FIMV_E_IR_SIZE			0xFA08
#define S5P_FIMV_E_GOP_CONFIG			0xFA0C
#define S5P_FIMV_E_MSLICE_MODE			0xFA10
#define S5P_FIMV_E_MSLICE_SIZE_MB		0xFA14
#define S5P_FIMV_E_MSLICE_SIZE_BITS		0xFA18
#define S5P_FIMV_E_FRAME_INSERTION		0xFA1C

#define S5P_FIMV_E_RC_FRAME_RATE		0xFA20
#define S5P_FIMV_E_RC_BIT_RATE			0xFA24
#define S5P_FIMV_E_RC_QP_OFFSET			0xFA28
#define S5P_FIMV_E_RC_ROI_CTRL			0xFA2C
#define S5P_FIMV_E_PICTURE_TAG			0xFA30
#define S5P_FIMV_E_BIT_COUNT_ENABLE		0xFA34
#define S5P_FIMV_E_MAX_BIT_COUNT		0xFA38
#define S5P_FIMV_E_MIN_BIT_COUNT		0xFA3C

#define S5P_FIMV_E_METADATA_BUFFER_ADDR		0xFA40
#define S5P_FIMV_E_METADATA_BUFFER_SIZE		0xFA44
#define S5P_FIMV_E_STREAM_SIZE			0xFA80
#define S5P_FIMV_E_SLICE_TYPE			0xFA84
#define S5P_FIMV_ENCODED_TYPE_NOT_CODED		0
#define S5P_FIMV_ENCODED_TYPE_I			1
#define S5P_FIMV_ENCODED_TYPE_P			2
#define S5P_FIMV_ENCODED_TYPE_B			3
#define S5P_FIMV_ENCODED_TYPE_SKIPPED		4
#define S5P_FIMV_E_PICTURE_COUNT		0xFA88
#define S5P_FIMV_E_RET_PICTURE_TAG		0xFA8C
#define S5P_FIMV_E_STREAM_BUFFER_WRITE_POINTER	0xFA90

#define S5P_FIMV_E_ENCODED_SOURCE_LUMA_ADDR	0xFA94
#define S5P_FIMV_E_ENCODED_SOURCE_CHROMA_ADDR	0xFA98
#define S5P_FIMV_E_RECON_LUMA_DPB_ADDR		0xFA9C
#define S5P_FIMV_E_RECON_CHROMA_DPB_ADDR	0xFAA0
#define S5P_FIMV_E_METADATA_ADDR_ENC_SLICE	0xFAA4
#define S5P_FIMV_E_METADATA_SIZE_ENC_SLICE	0xFAA8

#define S5P_FIMV_E_MPEG4_OPTIONS		0xFB10
#define S5P_FIMV_E_MPEG4_HEC_PERIOD		0xFB14
#define S5P_FIMV_E_ASPECT_RATIO			0xFB50
#define S5P_FIMV_E_EXTENDED_SAR			0xFB54

#define S5P_FIMV_E_H264_OPTIONS			0xFB58
#define S5P_FIMV_E_H264_LF_ALPHA_OFFSET		0xFB5C
#define S5P_FIMV_E_H264_LF_BETA_OFFSET		0xFB60
#define S5P_FIMV_E_H264_I_PERIOD		0xFB64

#define S5P_FIMV_E_H264_FMO_SLICE_GRP_MAP_TYPE			0xFB68
#define S5P_FIMV_E_H264_FMO_NUM_SLICE_GRP_MINUS1		0xFB6C
#define S5P_FIMV_E_H264_FMO_SLICE_GRP_CHANGE_DIR		0xFB70
#define S5P_FIMV_E_H264_FMO_SLICE_GRP_CHANGE_RATE_MINUS1	0xFB74
#define S5P_FIMV_E_H264_FMO_RUN_LENGTH_MINUS1_0	0xFB78
#define S5P_FIMV_E_H264_FMO_RUN_LENGTH_MINUS1_1	0xFB7C
#define S5P_FIMV_E_H264_FMO_RUN_LENGTH_MINUS1_2	0xFB80
#define S5P_FIMV_E_H264_FMO_RUN_LENGTH_MINUS1_3	0xFB84

#define S5P_FIMV_E_H264_ASO_SLICE_ORDER_0	0xFB88
#define S5P_FIMV_E_H264_ASO_SLICE_ORDER_1	0xFB8C
#define S5P_FIMV_E_H264_ASO_SLICE_ORDER_2	0xFB90
#define S5P_FIMV_E_H264_ASO_SLICE_ORDER_3	0xFB94
#define S5P_FIMV_E_H264_ASO_SLICE_ORDER_4	0xFB98
#define S5P_FIMV_E_H264_ASO_SLICE_ORDER_5	0xFB9C
#define S5P_FIMV_E_H264_ASO_SLICE_ORDER_6	0xFBA0
#define S5P_FIMV_E_H264_ASO_SLICE_ORDER_7	0xFBA4

#define S5P_FIMV_E_H264_CHROMA_QP_OFFSET	0xFBA8
#define S5P_FIMV_E_H264_NUM_T_LAYER		0xFBAC

#define S5P_FIMV_E_H264_HIERARCHICAL_QP_LAYER0	0xFBB0
#define S5P_FIMV_E_H264_HIERARCHICAL_QP_LAYER1	0xFBB4
#define S5P_FIMV_E_H264_HIERARCHICAL_QP_LAYER2	0xFBB8
#define S5P_FIMV_E_H264_HIERARCHICAL_QP_LAYER3	0xFBBC
#define S5P_FIMV_E_H264_HIERARCHICAL_QP_LAYER4	0xFBC0
#define S5P_FIMV_E_H264_HIERARCHICAL_QP_LAYER5	0xFBC4
#define S5P_FIMV_E_H264_HIERARCHICAL_QP_LAYER6	0xFBC8

#define S5P_FIMV_E_H264_FRAME_PACKING_SEI_INFO	0xFC4C

#define S5P_FIMV_E_MVC_FRAME_QP_VIEW1		0xFD40
#define S5P_FIMV_E_MVC_RC_FRAME_RATE_VIEW1	0xFD44
#define S5P_FIMV_E_MVC_RC_BIT_RATE_VIEW1	0xFD48
#define S5P_FIMV_E_MVC_RC_QBOUND_VIEW1		0xFD4C
#define S5P_FIMV_E_MVC_RC_RPARA_VIEW1		0xFD50
#define S5P_FIMV_E_MVC_INTER_VIEW_PREDICTION_ON	0xFD80

/* Codec numbers  */
#define MFC_FORMATS_NO_CODEC		-1

#define S5P_FIMV_CODEC_H264_DEC		0
#define S5P_FIMV_CODEC_H264_MVC_DEC	1

#define S5P_FIMV_CODEC_MPEG4_DEC	3
#define S5P_FIMV_CODEC_FIMV1_DEC	4
#define S5P_FIMV_CODEC_FIMV2_DEC	5
#define S5P_FIMV_CODEC_FIMV3_DEC	6
#define S5P_FIMV_CODEC_FIMV4_DEC	7
#define S5P_FIMV_CODEC_H263_DEC		8
#define S5P_FIMV_CODEC_VC1RCV_DEC	9
#define S5P_FIMV_CODEC_VC1_DEC		10
/* FIXME: Add 11~12 */
#define S5P_FIMV_CODEC_MPEG2_DEC	13
#define S5P_FIMV_CODEC_VP8_DEC		14
/* FIXME: Add 15~16 */
#define S5P_FIMV_CODEC_H264_ENC		20
#define S5P_FIMV_CODEC_H264_MVC_ENC	21

#define S5P_FIMV_CODEC_MPEG4_ENC	23
#define S5P_FIMV_CODEC_H263_ENC		24
/* FIXME: Add 25 */

/***	Definitions for MFCv5 compatibility ***/
#define S5P_FIMV_SI_DISPLAY_Y_ADR		S5P_FIMV_D_DISPLAY_LUMA_ADDR
#define S5P_FIMV_SI_DISPLAY_C_ADR		S5P_FIMV_D_DISPLAY_CHROMA_ADDR

#define S5P_FIMV_CRC_LUMA0			S5P_FIMV_D_DECODED_LUMA_CRC_TOP
#define S5P_FIMV_CRC_CHROMA0			S5P_FIMV_D_DECODED_CHROMA_CRC_TOP
#define S5P_FIMV_CRC_LUMA1			S5P_FIMV_D_DECODED_LUMA_CRC_BOT
#define S5P_FIMV_CRC_CHROMA1			S5P_FIMV_D_DECODED_CHROMA_CRC_BOT
#define S5P_FIMV_CRC_DISP_LUMA0			S5P_FIMV_D_DISPLAY_LUMA_CRC_TOP
#define S5P_FIMV_CRC_DISP_CHROMA0		S5P_FIMV_D_DISPLAY_CHROMA_CRC_TOP

#define S5P_FIMV_SI_DECODED_STATUS		S5P_FIMV_D_DECODED_STATUS
#define S5P_FIMV_SI_DISPLAY_STATUS		S5P_FIMV_D_DISPLAY_STATUS
#define S5P_FIMV_SHARED_SET_FRAME_TAG		S5P_FIMV_D_PICTURE_TAG
#define S5P_FIMV_SHARED_GET_FRAME_TAG_TOP	S5P_FIMV_D_RET_PICTURE_TAG_TOP
#define S5P_FIMV_CRC_DISP_STATUS		S5P_FIMV_D_DISPLAY_STATUS

/* SEI related information */
#define S5P_FIMV_FRAME_PACK_SEI_AVAIL		S5P_FIMV_D_FRAME_PACK_SEI_AVAIL
#define S5P_FIMV_FRAME_PACK_ARRGMENT_ID		S5P_FIMV_D_FRAME_PACK_ARRGMENT_ID
#define S5P_FIMV_FRAME_PACK_SEI_INFO		S5P_FIMV_D_FRAME_PACK_SEI_INFO
#define S5P_FIMV_FRAME_PACK_GRID_POS		S5P_FIMV_D_FRAME_PACK_GRID_POS

#define S5P_FIMV_SHARED_SET_E_FRAME_TAG		S5P_FIMV_E_PICTURE_TAG
#define S5P_FIMV_SHARED_GET_E_FRAME_TAG		S5P_FIMV_E_RET_PICTURE_TAG
#define S5P_FIMV_ENCODED_LUMA_ADDR		S5P_FIMV_E_ENCODED_SOURCE_LUMA_ADDR
#define S5P_FIMV_ENCODED_CHROMA_ADDR		S5P_FIMV_E_ENCODED_SOURCE_CHROMA_ADDR
#define	S5P_FIMV_FRAME_INSERTION		S5P_FIMV_E_FRAME_INSERTION

#define S5P_FIMV_PARAM_CHANGE_FLAG		S5P_FIMV_E_PARAM_CHANGE /* flag */
#define S5P_FIMV_NEW_I_PERIOD			S5P_FIMV_E_GOP_CONFIG
#define S5P_FIMV_NEW_RC_FRAME_RATE		S5P_FIMV_E_RC_FRAME_RATE
#define S5P_FIMV_NEW_RC_BIT_RATE		S5P_FIMV_E_RC_BIT_RATE

#define S5P_FIMV_ERR_FRAME_CONCEAL		150
/*** End of MFCv5 compatibility definitions ***/

/***      old definitions     ***/
#if 1

#define S5P_FIMV_SW_RESET		0x0000
#define S5P_FIMV_RISC_HOST_INT		0x0008

/* Command from HOST to RISC */
#define S5P_FIMV_HOST2RISC_ARG1		0x0034
#define S5P_FIMV_HOST2RISC_ARG2		0x0038
#define S5P_FIMV_HOST2RISC_ARG3		0x003c
#define S5P_FIMV_HOST2RISC_ARG4		0x0040

/* Command from RISC to HOST */
#define S5P_FIMV_RISC2HOST_CMD_MASK	0x1FFFF
#define S5P_FIMV_RISC2HOST_ARG1		0x0048
#define S5P_FIMV_RISC2HOST_ARG2		0x004c
#define S5P_FIMV_RISC2HOST_ARG3		0x0050
#define S5P_FIMV_RISC2HOST_ARG4		0x0054

#define S5P_FIMV_SYS_MEM_SZ		0x005c
#define S5P_FIMV_FW_STATUS		0x0080

/* Memory controller register */
#define S5P_FIMV_MC_DRAMBASE_ADR_A	0x0508
#define S5P_FIMV_MC_DRAMBASE_ADR_B	0x050c
#define S5P_FIMV_MC_STATUS		0x0510

/* Common register */
#define S5P_FIMV_COMMON_BASE_A		0x0600
#define S5P_FIMV_COMMON_BASE_B		0x0700

/* Decoder */
#define S5P_FIMV_DEC_CHROMA_ADR		(S5P_FIMV_COMMON_BASE_A)
#define S5P_FIMV_DEC_LUMA_ADR		(S5P_FIMV_COMMON_BASE_B)

/* H.264 decoding */
#define S5P_FIMV_H264_VERT_NB_MV_ADR	(S5P_FIMV_COMMON_BASE_A + 0x8c)	/* vertical neighbor motion vector */
#define S5P_FIMV_H264_NB_IP_ADR		(S5P_FIMV_COMMON_BASE_A + 0x90)	/* neighbor pixels for intra pred */
#define S5P_FIMV_H264_MV_ADR		(S5P_FIMV_COMMON_BASE_B + 0x80)	/* H264 motion vector */

/* MPEG4 decoding */
#define S5P_FIMV_MPEG4_NB_DCAC_ADR	(S5P_FIMV_COMMON_BASE_A + 0x8c)	/* neighbor AC/DC coeff. */
#define S5P_FIMV_MPEG4_UP_NB_MV_ADR	(S5P_FIMV_COMMON_BASE_A + 0x90)	/* upper neighbor motion vector */
#define S5P_FIMV_MPEG4_SA_MV_ADR	(S5P_FIMV_COMMON_BASE_A + 0x94)	/* subseq. anchor motion vector */
#define S5P_FIMV_MPEG4_OT_LINE_ADR	(S5P_FIMV_COMMON_BASE_A + 0x98)	/* overlap transform line */
#define S5P_FIMV_MPEG4_SP_ADR		(S5P_FIMV_COMMON_BASE_A + 0xa8)	/* syntax parser */

/* H.263 decoding */
#define S5P_FIMV_H263_NB_DCAC_ADR	(S5P_FIMV_COMMON_BASE_A + 0x8c)
#define S5P_FIMV_H263_UP_NB_MV_ADR	(S5P_FIMV_COMMON_BASE_A + 0x90)
#define S5P_FIMV_H263_SA_MV_ADR		(S5P_FIMV_COMMON_BASE_A + 0x94)
#define S5P_FIMV_H263_OT_LINE_ADR	(S5P_FIMV_COMMON_BASE_A + 0x98)

/* VC-1 decoding */
#define S5P_FIMV_VC1_NB_DCAC_ADR	(S5P_FIMV_COMMON_BASE_A + 0x8c)
#define S5P_FIMV_VC1_UP_NB_MV_ADR	(S5P_FIMV_COMMON_BASE_A + 0x90)
#define S5P_FIMV_VC1_SA_MV_ADR		(S5P_FIMV_COMMON_BASE_A + 0x94)
#define S5P_FIMV_VC1_OT_LINE_ADR	(S5P_FIMV_COMMON_BASE_A + 0x98)
#define S5P_FIMV_VC1_BITPLANE3_ADR	(S5P_FIMV_COMMON_BASE_A + 0x9c)	/* bitplane3 */
#define S5P_FIMV_VC1_BITPLANE2_ADR	(S5P_FIMV_COMMON_BASE_A + 0xa0)	/* bitplane2 */
#define S5P_FIMV_VC1_BITPLANE1_ADR	(S5P_FIMV_COMMON_BASE_A + 0xa4)	/* bitplane1 */

/* Encoder */
#define S5P_FIMV_ENC_REF0_LUMA_ADR	(S5P_FIMV_COMMON_BASE_A + 0x1c)	/* reconstructed luma */
#define S5P_FIMV_ENC_REF1_LUMA_ADR	(S5P_FIMV_COMMON_BASE_A + 0x20)
#define S5P_FIMV_ENC_REF0_CHROMA_ADR	(S5P_FIMV_COMMON_BASE_B)	/* reconstructed chroma */
#define S5P_FIMV_ENC_REF1_CHROMA_ADR	(S5P_FIMV_COMMON_BASE_B + 0x04)
#define S5P_FIMV_ENC_REF2_LUMA_ADR	(S5P_FIMV_COMMON_BASE_B + 0x10)
#define S5P_FIMV_ENC_REF2_CHROMA_ADR	(S5P_FIMV_COMMON_BASE_B + 0x08)
#define S5P_FIMV_ENC_REF3_LUMA_ADR	(S5P_FIMV_COMMON_BASE_B + 0x14)
#define S5P_FIMV_ENC_REF3_CHROMA_ADR	(S5P_FIMV_COMMON_BASE_B + 0x0c)

/* H.264 encoding */
#define S5P_FIMV_H264_UP_MV_ADR		(S5P_FIMV_COMMON_BASE_A)	/* upper motion vector */
#define S5P_FIMV_H264_NBOR_INFO_ADR	(S5P_FIMV_COMMON_BASE_A + 0x04)	/* entropy engine's neighbor info. */
#define S5P_FIMV_H264_UP_INTRA_MD_ADR	(S5P_FIMV_COMMON_BASE_A + 0x08)	/* upper intra MD */
#define S5P_FIMV_H264_COZERO_FLAG_ADR	(S5P_FIMV_COMMON_BASE_A + 0x10)	/* direct cozero flag */
#define S5P_FIMV_H264_UP_INTRA_PRED_ADR	(S5P_FIMV_COMMON_BASE_B + 0x40)	/* upper intra PRED */

/* H.263 encoding */
#define S5P_FIMV_H263_UP_MV_ADR		(S5P_FIMV_COMMON_BASE_A)	/* upper motion vector */
#define S5P_FIMV_H263_ACDC_COEF_ADR	(S5P_FIMV_COMMON_BASE_A + 0x04)	/* upper Q coeff. */

/* MPEG4 encoding */
#define S5P_FIMV_MPEG4_UP_MV_ADR	(S5P_FIMV_COMMON_BASE_A)	/* upper motion vector */
#define S5P_FIMV_MPEG4_ACDC_COEF_ADR	(S5P_FIMV_COMMON_BASE_A + 0x04)	/* upper Q coeff. */
#define S5P_FIMV_MPEG4_COZERO_FLAG_ADR	(S5P_FIMV_COMMON_BASE_A + 0x10)	/* direct cozero flag */

#define S5P_FIMV_ENC_REF_B_LUMA_ADR     0x062c /* ref B Luma addr */
#define S5P_FIMV_ENC_REF_B_CHROMA_ADR   0x0630 /* ref B Chroma addr */

#define S5P_FIMV_ENC_CUR_LUMA_ADR	0x0718 /* current Luma addr */
#define S5P_FIMV_ENC_CUR_CHROMA_ADR	0x071C /* current Chroma addr */

/* Codec common register */
#define S5P_FIMV_ENC_HSIZE_PX		0x0818 /* frame width at encoder */
#define S5P_FIMV_ENC_VSIZE_PX		0x081c /* frame height at encoder */
#define S5P_FIMV_ENC_PROFILE		0x0830 /* profile register */
#define S5P_FIMV_ENC_PIC_STRUCT		0x083c /* picture field/frame flag */
#define S5P_FIMV_ENC_LF_CTRL		0x0848 /* loop filter control */
#define S5P_FIMV_ENC_ALPHA_OFF		0x084c /* loop filter alpha offset */
#define S5P_FIMV_ENC_BETA_OFF		0x0850 /* loop filter beta offset */
#define S5P_FIMV_MR_BUSIF_CTRL		0x0854 /* hidden, bus interface ctrl */
#define S5P_FIMV_ENC_PXL_CACHE_CTRL	0x0a00 /* pixel cache control */

/* Channel & stream interface register */
#define S5P_FIMV_SI_RTN_CHID		0x2000 /* Return CH instance ID register */
#define S5P_FIMV_SI_CH0_INST_ID		0x2040 /* codec instance ID */
#define S5P_FIMV_SI_CH1_INST_ID		0x2080 /* codec instance ID */
/* Decoder */
#define S5P_FIMV_SI_VRESOL		0x2004 /* vertical resolution of decoder */
#define S5P_FIMV_SI_HRESOL		0x2008 /* horizontal resolution of decoder */
#define S5P_FIMV_SI_BUF_NUMBER		0x200c /* number of frames in the decoded pic */
#define S5P_FIMV_SI_CONSUMED_BYTES	0x2018 /* Consumed number of bytes to decode
								a frame */
#define S5P_FIMV_SI_FRAME_TYPE		0x2020 /* frame type such as skip/I/P/B */

#define S5P_FIMV_SI_CH0_SB_ST_ADR	0x2044 /* start addr of stream buf */
#define S5P_FIMV_SI_CH0_SB_FRM_SIZE	0x2048 /* size of stream buf */
#define S5P_FIMV_SI_CH0_DESC_ADR	0x204c /* addr of descriptor buf */
#define S5P_FIMV_SI_CH0_CPB_SIZE	0x2058 /* max size of coded pic. buf */
#define S5P_FIMV_SI_CH0_DESC_SIZE	0x205c /* max size of descriptor buf */

#define S5P_FIMV_SI_CH1_SB_ST_ADR	0x2084 /* start addr of stream buf */
#define S5P_FIMV_SI_CH1_SB_FRM_SIZE	0x2088 /* size of stream buf */
#define S5P_FIMV_SI_CH1_DESC_ADR	0x208c /* addr of descriptor buf */
#define S5P_FIMV_SI_CH1_CPB_SIZE	0x2098 /* max size of coded pic. buf */
#define S5P_FIMV_SI_CH1_DESC_SIZE	0x209c /* max size of descriptor buf */

#define S5P_FIMV_SI_FIMV1_HRESOL	0x2054 /* horizontal resolution */
#define S5P_FIMV_SI_FIMV1_VRESOL	0x2050 /* vertical resolution */

/* Decode frame address */
#define S5P_FIMV_DECODE_Y_ADR			0x2024
#define S5P_FIMV_DECODE_C_ADR			0x2028

/* Decoded frame type */
#define S5P_FIMV_DECODED_FRAME_TYPE		0x2020

/* Sizes of buffers required for decoding */
#define S5P_FIMV_DEC_NB_IP_SIZE			(32 * 1024)
#define S5P_FIMV_DEC_VERT_NB_MV_SIZE		(16 * 1024)
#define S5P_FIMV_DEC_NB_DCAC_SIZE		(16 * 1024)
#define S5P_FIMV_DEC_UPNB_MV_SIZE		(68 * 1024)
#define S5P_FIMV_DEC_SUB_ANCHOR_MV_SIZE		(136 * 1024)
#define S5P_FIMV_DEC_OVERLAP_TRANSFORM_SIZE     (32 * 1024)
#define S5P_FIMV_DEC_VC1_BITPLANE_SIZE		(2 * 1024)
#define S5P_FIMV_DEC_STX_PARSER_SIZE		(68 * 1024)

/* FIXME: Should be checked for alignment */
#define S5P_FIMV_DEC_BUF_ALIGN			(8 * 1024)
#define S5P_FIMV_ENC_BUF_ALIGN			(8 * 1024)
#define S5P_FIMV_NV12M_HALIGN			16
#define S5P_FIMV_NV12M_LVALIGN			16
#define S5P_FIMV_NV12M_CVALIGN			8
#define S5P_FIMV_NV12MT_HALIGN			16
#define S5P_FIMV_NV12MT_VALIGN			16
#define S5P_FIMV_NV12M_SALIGN			2048
#define S5P_FIMV_NV12MT_SALIGN			8192

/* Sizes of buffers required for encoding */
#define S5P_FIMV_ENC_UPMV_SIZE			(0x10000)
#define S5P_FIMV_ENC_COLFLG_SIZE		(0x10000)
#define S5P_FIMV_ENC_INTRAMD_SIZE		(0x10000)
#define S5P_FIMV_ENC_INTRAPRED_SIZE		(0x4000)
#define S5P_FIMV_ENC_NBORINFO_SIZE		(0x10000)
#define S5P_FIMV_ENC_ACDCCOEF_SIZE		(0x10000)

/* Encoder */
#define S5P_FIMV_ENC_SI_STRM_SIZE	0x2004 /* stream size */
#define S5P_FIMV_ENC_SI_PIC_CNT		0x2008 /* picture count */
#define S5P_FIMV_ENC_SI_WRITE_PTR	0x200c /* write pointer */
#define S5P_FIMV_ENC_SI_SLICE_TYPE	0x2010 /* slice type(I/P/B/IDR) */
#define S5P_FIMV_ENCODED_Y_ADDR         0x2014 /* the addr of the encoded luma pic */
#define S5P_FIMV_ENCODED_C_ADDR         0x2018 /* the addr of the encoded chroma pic */

#define S5P_FIMV_ENC_SI_CH0_SB_ADR	0x2044 /* addr of stream buf */
#define S5P_FIMV_ENC_SI_CH0_SB_SIZE	0x204c /* size of stream buf */
#define S5P_FIMV_ENC_SI_CH0_CUR_Y_ADR	0x2050 /* current Luma addr */
#define S5P_FIMV_ENC_SI_CH0_CUR_C_ADR	0x2054 /* current Chroma addr */
#define S5P_FIMV_ENC_SI_CH0_FRAME_INS	0x2058 /* frame insertion */

#define S5P_FIMV_ENC_SI_CH1_SB_ADR	0x2084 /* addr of stream buf */
#define S5P_FIMV_ENC_SI_CH1_SB_SIZE	0x208c /* size of stream buf */
#define S5P_FIMV_ENC_SI_CH1_CUR_Y_ADR	0x2090 /* current Luma addr */
#define S5P_FIMV_ENC_SI_CH1_CUR_C_ADR	0x2094 /* current Chroma addr */
#define S5P_FIMV_ENC_SI_CH1_FRAME_INS	0x2098 /* frame insertion */

#define S5P_FIMV_ENC_PIC_TYPE_CTRL	0xc504 /* pic type level control */
#define S5P_FIMV_ENC_B_RECON_WRITE_ON	0xc508 /* B frame recon write ctrl */
#define S5P_FIMV_ENC_MSLICE_CTRL	0xc50c /* multi slice control */
#define S5P_FIMV_ENC_MSLICE_MB		0xc510 /* MB number in the one slice */
#define S5P_FIMV_ENC_MSLICE_BIT		0xc514 /* bit count for one slice */
#define S5P_FIMV_ENC_CIR_CTRL		0xc518 /* number of intra refresh MB */
#define S5P_FIMV_ENC_MAP_FOR_CUR	0xc51c /* linear or 64x32 tiled mode */
#define S5P_FIMV_ENC_PADDING_CTRL	0xc520 /* padding control */

#define S5P_FIMV_ENC_RC_CONFIG		0xc5a0 /* RC config */
#define S5P_FIMV_ENC_RC_BIT_RATE	0xc5a8 /* bit rate */
#define S5P_FIMV_ENC_RC_QBOUND		0xc5ac /* max/min QP */
#define S5P_FIMV_ENC_RC_RPARA		0xc5b0 /* rate control reaction coeff */
#define S5P_FIMV_ENC_RC_MB_CTRL		0xc5b4 /* MB adaptive scaling */

/* Encoder for H264 only */
#define S5P_FIMV_ENC_H264_ENTRP_MODE	0xd004 /* CAVLC or CABAC */
#define S5P_FIMV_ENC_H264_ALPHA_OFF	0xd008 /* loop filter alpha offset */
#define S5P_FIMV_ENC_H264_BETA_OFF	0xd00c /* loop filter beta offset */
#define S5P_FIMV_ENC_H264_NUM_OF_REF	0xd010 /* number of reference for P/B */
#define S5P_FIMV_ENC_H264_TRANS_FLAG	0xd034 /* 8x8 transform flag in PPS & high profile */

#define S5P_FIMV_ENC_RC_FRAME_RATE	0xd0d0 /* frame rate */

/* Encoder for MPEG4 only */
#define S5P_FIMV_ENC_MPEG4_QUART_PXL	0xe008 /* qpel interpolation ctrl */

/* Additional */
#define S5P_FIMV_SI_CH0_DPB_CONF_CTRL   0x2068 /* DPB Config Control Register */
#define S5P_FIMV_DPB_COUNT_MASK		0xffff

#define S5P_FIMV_SI_CH0_RELEASE_BUF     0x2060 /* DPB release buffer register */
#define S5P_FIMV_SI_CH0_HOST_WR_ADR	0x2064 /* address of shared memory */

/* Channel Control Register */
#define S5P_FIMV_CH_FRAME_START_REALLOC	5

#define S5P_FIMV_CH_MASK		7
#define S5P_FIMV_CH_SHIFT		16

/* Host to RISC command */
#define S5P_FIMV_R2H_CMD_RSV_RET		3
#define S5P_FIMV_R2H_CMD_ENC_COMPLETE_RET	7
#define S5P_FIMV_R2H_CMD_FLUSH_RET		12
#define S5P_FIMV_R2H_CMD_EDFU_INIT_RET		16

/* Shared memory registers' offsets */

/* An offset of the start position in the stream when
 * the start position is not aligned */
#define S5P_FIMV_SHARED_GET_FRAME_TAG_BOT	0x000C
#define S5P_FIMV_SHARED_START_BYTE_NUM		0x0018
#define S5P_FIMV_SHARED_RC_VOP_TIMING		0x0030
#define S5P_FIMV_SHARED_LUMA_DPB_SIZE		0x0064
#define S5P_FIMV_SHARED_CHROMA_DPB_SIZE		0x0068
#define S5P_FIMV_SHARED_MV_SIZE			0x006C
#define S5P_FIMV_SHARED_PIC_TIME_TOP		0x0010
#define S5P_FIMV_SHARED_PIC_TIME_BOTTOM		0x0014
#define S5P_FIMV_SHARED_EXT_ENC_CONTROL		0x0028
#define S5P_FIMV_SHARED_P_B_FRAME_QP		0x0070
#define S5P_FIMV_SHARED_ASPECT_RATIO_IDC	0x0074
#define S5P_FIMV_SHARED_EXTENDED_SAR		0x0078
#define S5P_FIMV_SHARED_H264_I_PERIOD		0x009C
#define S5P_FIMV_SHARED_RC_CONTROL_CONFIG	0x00A0

#endif /* End of old definitions */

#endif /* _REGS_FIMV_V6_H */
