#include <linux/workqueue.h>

#include "fimc-is-time.h"
#include "fimc-is-core.h"
#include "fimc-is-cmd.h"
#include "fimc-is-regs.h"
#include "fimc-is-err.h"

#include "fimc-is-interface.h"

static int init_request_barrier(struct fimc_is_interface *interface)
{
	mutex_init(&interface->request_barrier);

	return 0;
}

static int enter_request_barrier(struct fimc_is_interface *interface)
{
	mutex_lock(&interface->request_barrier);

	return 0;
}

static int exit_request_barrier(struct fimc_is_interface *interface)
{
	mutex_unlock(&interface->request_barrier);

	return 0;
}

static int init_process_barrier(struct fimc_is_interface *interface)
{
	spin_lock_init(&interface->process_barrier);

	return 0;
}

static int enter_process_barrier(struct fimc_is_interface *interface)
{
	spin_lock_irq(&interface->process_barrier);

	return 0;
}

static int exit_process_barrier(struct fimc_is_interface *interface)
{
	spin_unlock_irq(&interface->process_barrier);

	return 0;
}

static int init_state_barrier(struct fimc_is_interface *interface)
{
	mutex_init(&interface->state_barrier);

	return 0;
}

static int enter_state_barrier(struct fimc_is_interface *interface)
{
	mutex_lock(&interface->state_barrier);

	return 0;
}

static int exit_state_barrier(struct fimc_is_interface *interface)
{
	mutex_unlock(&interface->state_barrier);

	return 0;
}

int print_fre_work_list(struct fimc_is_work_list *this)
{
	struct list_head *temp;
	struct fimc_is_work *work;

	if (!(this->id & TRACE_WORK_ID_MASK))
		return 0;

	printk(KERN_CONT "[INF] fre(%02X, %02d) :",
		this->id, this->work_free_cnt);

	list_for_each(temp, &this->work_free_head) {
		work = list_entry(temp, struct fimc_is_work, list);
		printk(KERN_CONT "%X(%d)->", work->msg.command, work->fcount);
	}

	printk(KERN_CONT "X\n");

	return 0;
}

static int set_free_work(struct fimc_is_work_list *this,
	struct fimc_is_work *work)
{
	int ret = 0;
	unsigned long flags;

	if (work) {
		spin_lock_irqsave(&this->slock_free, flags);

		list_add_tail(&work->list, &this->work_free_head);
		this->work_free_cnt++;
#ifdef TRACE_WORK
		print_fre_work_list(this);
#endif

		spin_unlock_irqrestore(&this->slock_free, flags);
	} else {
		ret = -EFAULT;
		err("item is null ptr\n");
	}

	return ret;
}

static int set_free_work_irq(struct fimc_is_work_list *this,
	struct fimc_is_work *work)
{
	int ret = 0;

	if (work) {
		spin_lock(&this->slock_free);

		list_add_tail(&work->list, &this->work_free_head);
		this->work_free_cnt++;
#ifdef TRACE_WORK
		print_fre_work_list(this);
#endif

		spin_unlock(&this->slock_free);
	} else {
		ret = -EFAULT;
		err("item is null ptr\n");
	}

	return ret;
}

static int get_free_work(struct fimc_is_work_list *this,
	struct fimc_is_work **work)
{
	int ret = 0;
	unsigned long flags;

	if (work) {
		spin_lock_irqsave(&this->slock_free, flags);

		if (this->work_free_cnt) {
			*work = container_of(this->work_free_head.next,
					struct fimc_is_work, list);
			list_del(&(*work)->list);
			this->work_free_cnt--;
		} else
			*work = NULL;

		spin_unlock_irqrestore(&this->slock_free, flags);
	} else {
		ret = EFAULT;
		err("item is null ptr");
	}

	return ret;
}

static int get_free_work_irq(struct fimc_is_work_list *this,
	struct fimc_is_work **work)
{
	int ret = 0;

	if (work) {
		spin_lock(&this->slock_free);

		if (this->work_free_cnt) {
			*work = container_of(this->work_free_head.next,
					struct fimc_is_work, list);
			list_del(&(*work)->list);
			this->work_free_cnt--;
		} else
			*work = NULL;

		spin_unlock(&this->slock_free);
	} else {
		ret = EFAULT;
		err("item is null ptr");
	}

	return ret;
}

int print_req_work_list(struct fimc_is_work_list *this)
{
	struct list_head *temp;
	struct fimc_is_work *work;

	if (!(this->id & TRACE_WORK_ID_MASK))
		return 0;

	printk(KERN_CONT "[INF] req(%02X, %02d) :",
		this->id, this->work_request_cnt);

	list_for_each(temp, &this->work_request_head) {
		work = list_entry(temp, struct fimc_is_work, list);
		printk(KERN_CONT "%X(%d)->", work->msg.command, work->fcount);
	}

	printk(KERN_CONT "X\n");

	return 0;
}

static int set_req_work(struct fimc_is_work_list *this,
	struct fimc_is_work *work)
{
	int ret = 0;
	unsigned long flags;

	if (work) {
		spin_lock_irqsave(&this->slock_request, flags);

		list_add_tail(&work->list, &this->work_request_head);
		this->work_request_cnt++;
#ifdef TRACE_WORK
		print_req_work_list(this);
#endif

		spin_unlock_irqrestore(&this->slock_request, flags);
	} else {
		ret = EFAULT;
		err("item is null ptr\n");
	}

	return ret;
}

static int set_req_work_irq(struct fimc_is_work_list *this,
	struct fimc_is_work *work)
{
	int ret = 0;

	if (work) {
		spin_lock(&this->slock_request);

		list_add_tail(&work->list, &this->work_request_head);
		this->work_request_cnt++;
#ifdef TRACE_WORK
		print_req_work_list(this);
#endif

		spin_unlock(&this->slock_request);
	} else {
		ret = EFAULT;
		err("item is null ptr\n");
	}

	return ret;
}

static int get_req_work(struct fimc_is_work_list *this,
	struct fimc_is_work **work)
{
	int ret = 0;
	unsigned long flags;

	if (work) {
		spin_lock_irqsave(&this->slock_request, flags);

		if (this->work_request_cnt) {
			*work = container_of(this->work_request_head.next,
					struct fimc_is_work, list);
			list_del(&(*work)->list);
			this->work_request_cnt--;
		} else
			*work = NULL;

		spin_unlock_irqrestore(&this->slock_request, flags);
	} else {
		ret = EFAULT;
		err("item is null ptr\n");
	}

	return ret;
}

static int get_request_work_irq(struct fimc_is_work_list *this,
	struct fimc_is_work **work)
{
	int ret = 0;

	if (work) {
		spin_lock(&this->slock_request);

		if (this->work_request_cnt) {
			*work = container_of(this->work_request_head.next,
					struct fimc_is_work, list);
			list_del(&(*work)->list);
			this->work_request_cnt--;
		} else
			*work = NULL;

		spin_unlock(&this->slock_request);
	} else {
		ret = EFAULT;
		err("item is null ptr\n");
	}

	return ret;
}

static void init_work_list(struct fimc_is_work_list *this, u32 id, u32 count)
{
	u32 i;

	this->id = id;
	this->work_free_cnt	= 0;
	this->work_request_cnt	= 0;
	INIT_LIST_HEAD(&this->work_free_head);
	INIT_LIST_HEAD(&this->work_request_head);
	spin_lock_init(&this->slock_free);
	spin_lock_init(&this->slock_request);
	for (i = 0; i < count; ++i)
		set_free_work(this, &this->work[i]);

	init_waitqueue_head(&this->wait_queue);
}

static void init_wait_queue(struct fimc_is_interface *this)
{
	init_waitqueue_head(&this->wait_queue);
}

static int set_state(struct fimc_is_interface *interface,
	enum fimc_is_interface_state state)
{
	enter_state_barrier(interface);

	interface->state = state;

	exit_state_barrier(interface);

	return 0;
}

static int wait_state(struct fimc_is_interface *this,
	enum fimc_is_interface_state state)
{
	s32 ret = 0;

	if (this->state != state) {
		ret = wait_event_timeout(this->wait_queue,
				(this->state == state),
				FIMC_IS_SHUTDOWN_TIMEOUT);
		if (!ret) {
			err("wait_state timeout(state : %d, %d)\n",
				this->state, state);
			ret = -EBUSY;
		}
	}

	return ret;
}

static int waiting_is_ready(struct fimc_is_interface *interface)
{
	u32 try_count = TRY_RECV_AWARE_COUNT;
	u32 cfg = readl(interface->regs + INTMSR0);
	u32 status = INTMSR0_GET_INTMSD0(cfg);
	while (status) {
		cfg = readl(interface->regs + INTMSR0);
		status = INTMSR0_GET_INTMSD0(cfg);

		try_count--;
		if (try_count <= 0) {
			try_count = TRY_RECV_AWARE_COUNT;
			err("INTMSR0's 0 bit is not cleared.\n");
		}
	}

	return 0;
}

static void send_interrupt(struct fimc_is_interface *interface)
{
	writel(INTGR0_INTGD0, interface->regs + INTGR0);
}

static int fimc_is_set_cmd(struct fimc_is_interface *interface,
	struct fimc_is_msg *msg)
{
	int ret = 0;
	bool block_io, send_cmd;

	dbg_interface("TP#1\n");
	enter_request_barrier(interface);
	dbg_interface("TP#2\n");

	switch (msg->command) {
	case HIC_STREAM_ON:
		if (interface->streaming) {
			send_cmd = false;
		} else {
			send_cmd = true;
			block_io = true;
		}
		break;
	case HIC_STREAM_OFF:
		if (!interface->streaming) {
			send_cmd = false;
		} else {
			send_cmd = true;
			block_io = true;
		}
		break;
	case HIC_OPEN_SENSOR:
	case HIC_GET_SET_FILE_ADDR:
	case HIC_SET_PARAMETER:
	case HIC_PREVIEW_STILL:
	case HIC_PROCESS_START:
	case HIC_PROCESS_STOP:
	case HIC_GET_STATIC_METADATA:
	case HIC_SET_A5_MEM_ACCESS:
	case HIC_POWER_DOWN:
	case HIC_SET_CAM_CONTROL:
		send_cmd = true;
		block_io = true;
		break;
	case HIC_SHOT:
	case ISR_DONE:
		send_cmd = true;
		block_io = false;
		break;
	default:
		send_cmd = true;
		block_io = true;
		break;
	}

	if (send_cmd) {
		enter_process_barrier(interface);

		waiting_is_ready(interface);
		set_state(interface, IS_IF_STATE_BLOCK_IO);
		interface->com_regs->hicmd = msg->command;
		interface->com_regs->hic_sensorid = msg->instance;
		interface->com_regs->hic_param1 = msg->parameter1;
		interface->com_regs->hic_param2 = msg->parameter2;
		interface->com_regs->hic_param3 = msg->parameter3;
		interface->com_regs->hic_param4 = msg->parameter4;
		send_interrupt(interface);

		exit_process_barrier(interface);

		if (block_io) {
			wait_state(interface, IS_IF_STATE_IDLE);
			if (interface->reply.command == ISR_DONE)
				ret = 0;
			else
				ret = 1;
		}

		switch (msg->command) {
		case HIC_STREAM_ON:
			interface->streaming = true;
			break;
		case HIC_STREAM_OFF:
			interface->streaming = false;
			break;
		default:
			break;
		}
	} else
		dbg_interface("skipped\n");

	exit_request_barrier(interface);

	return ret;
}

static int fimc_is_set_cmd_nblk(struct fimc_is_interface *this,
	struct fimc_is_work *work)
{
	int ret = 0;
	struct fimc_is_msg *msg;

	msg = &work->msg;

	switch (msg->command) {
	case HIC_SET_CAM_CONTROL:
		set_req_work(&this->nblk_cam_ctrl, work);
		break;
	case HIC_SHOT:
		set_req_work(&this->nblk_shot, work);
		break;
	default:
		err("unresolved command\n");
		break;
	}

	enter_process_barrier(this);

	waiting_is_ready(this);
	this->com_regs->hicmd = msg->command;
	this->com_regs->hic_sensorid = msg->instance;
	this->com_regs->hic_param1 = msg->parameter1;
	this->com_regs->hic_param2 = msg->parameter2;
	this->com_regs->hic_param3 = msg->parameter3;
	this->com_regs->hic_param4 = msg->parameter4;
	send_interrupt(this);

	exit_process_barrier(this);

	return ret;
}

static int fimc_is_get_cmd(struct fimc_is_interface *interface,
	struct fimc_is_msg *msg, u32 index)
{
	switch (index) {
	case INTR_GENERAL:
		msg->id = 0;
		msg->command = interface->com_regs->ihcmd;
		msg->instance = interface->com_regs->ihc_sensorid;
		msg->parameter1 = interface->com_regs->ihc_param1;
		msg->parameter2 = interface->com_regs->ihc_param2;
		msg->parameter3 = interface->com_regs->ihc_param3;
		msg->parameter4 = interface->com_regs->ihc_param4;
		break;
	case INTR_SCC_FDONE:
		msg->id = 0;
		msg->command = IHC_FRAME_DONE;
		msg->instance = interface->com_regs->scc_sensor_id;
		msg->parameter1 = interface->com_regs->scc_param1;
		msg->parameter2 = interface->com_regs->scc_param2;
		msg->parameter3 = interface->com_regs->scc_param3;
		msg->parameter4 = interface->com_regs->scc_param4;
		break;
	case INTR_SCP_FDONE:
		msg->id = 0;
		msg->command = IHC_FRAME_DONE;
		msg->instance = interface->com_regs->scp_sensor_id;
		msg->parameter1 = interface->com_regs->scp_param1;
		msg->parameter2 = interface->com_regs->scp_param2;
		msg->parameter3 = interface->com_regs->scp_param3;
		msg->parameter4 = interface->com_regs->scp_param4;
		break;
	case INTR_META_DONE:
		msg->id = 0;
		msg->command = IHC_FRAME_DONE;
		msg->instance = interface->com_regs->meta_sensor_id;
		msg->parameter1 = interface->com_regs->meta_parameter1;
		msg->parameter2 = 0;
		msg->parameter3 = 0;
		msg->parameter4 = 0;
		break;
	default:
		msg->id = 0;
		msg->command = IHC_FRAME_DONE;
		msg->instance = 0;
		msg->parameter1 = 0;
		msg->parameter2 = 0;
		msg->parameter3 = 0;
		msg->parameter4 = 0;
		err("unknown command getting\n");
		break;
	}

	return 0;
}

static void wq_func_general(struct work_struct *data)
{
	struct fimc_is_interface *itf;
	struct fimc_is_msg *msg;
	struct fimc_is_work *work;
	struct fimc_is_work *nblk_work;

	itf = container_of(data, struct fimc_is_interface,
		work_queue[INTR_GENERAL]);

	get_req_work(&itf->work_list[INTR_GENERAL], &work);
	while (work) {
		msg = &work->msg;
		switch (msg->command) {
		case IHC_GET_SENSOR_NUMBER:
			dbg_interface("version : %d\n", msg->parameter1);
			fimc_is_hw_enum(itf, 1);
			exit_request_barrier(itf);

			set_state(itf, IS_IF_STATE_IDLE);
			break;
		case ISR_DONE:
			switch (msg->parameter1) {
			case HIC_OPEN_SENSOR:
				dbg_interface("open done\n");
				memcpy(&itf->reply, msg,
					sizeof(struct fimc_is_msg));
				set_state(itf, IS_IF_STATE_IDLE);
				wake_up(&itf->wait_queue);
				break;
			case HIC_GET_SET_FILE_ADDR:
				dbg_interface("saddr(%p) done\n",
					(void *)msg->parameter2);
				memcpy(&itf->reply, msg,
					sizeof(struct fimc_is_msg));
				set_state(itf, IS_IF_STATE_IDLE);
				wake_up(&itf->wait_queue);
				break;
			case HIC_LOAD_SET_FILE:
				dbg_interface("setfile done\n");
				memcpy(&itf->reply, msg,
					sizeof(struct fimc_is_msg));
				set_state(itf, IS_IF_STATE_IDLE);
				wake_up(&itf->wait_queue);
				break;
			case HIC_SET_A5_MEM_ACCESS:
				dbg_interface("cfgmem done\n");
				memcpy(&itf->reply, msg,
					sizeof(struct fimc_is_msg));
				set_state(itf, IS_IF_STATE_IDLE);
				wake_up(&itf->wait_queue);
				break;
			case HIC_PROCESS_START:
				dbg_interface("process_on done\n");
				memcpy(&itf->reply, msg,
					sizeof(struct fimc_is_msg));
				set_state(itf, IS_IF_STATE_IDLE);
				wake_up(&itf->wait_queue);
				break;
			case HIC_PROCESS_STOP:
				dbg_interface("process_off done\n");
				memcpy(&itf->reply, msg,
					sizeof(struct fimc_is_msg));
				set_state(itf, IS_IF_STATE_IDLE);
				wake_up(&itf->wait_queue);
				break;
			case HIC_STREAM_ON:
				dbg_interface("stream_on done\n");
				memcpy(&itf->reply, msg,
					sizeof(struct fimc_is_msg));
				set_state(itf, IS_IF_STATE_IDLE);
				wake_up(&itf->wait_queue);
				break;
			case HIC_STREAM_OFF:
				dbg_interface("stream_off done\n");
				memcpy(&itf->reply, msg,
					sizeof(struct fimc_is_msg));
				set_state(itf, IS_IF_STATE_IDLE);
				wake_up(&itf->wait_queue);
				break;
			case HIC_SET_PARAMETER:
				dbg_interface("s_param done\n");
				memcpy(&itf->reply, msg,
					sizeof(struct fimc_is_msg));
				set_state(itf, IS_IF_STATE_IDLE);
				wake_up(&itf->wait_queue);
				break;
			case HIC_GET_STATIC_METADATA:
				dbg_interface("g_capability done\n");
				memcpy(&itf->reply, msg,
					sizeof(struct fimc_is_msg));
				set_state(itf, IS_IF_STATE_IDLE);
				wake_up(&itf->wait_queue);
				break;
			case HIC_PREVIEW_STILL:
				dbg_interface("a_param(%dx%d) done\n",
					msg->parameter2,
					msg->parameter3);
				memcpy(&itf->reply, msg,
					sizeof(struct fimc_is_msg));
				set_state(itf, IS_IF_STATE_IDLE);
				wake_up(&itf->wait_queue);
				break;
			case HIC_POWER_DOWN:
				dbg_interface("powerdown done\n");
				memcpy(&itf->reply, msg,
					sizeof(struct fimc_is_msg));
				set_state(itf, IS_IF_STATE_IDLE);
				wake_up(&itf->wait_queue);
				break;
			/*non-blocking command*/
			case HIC_SHOT:
				dbg_interface("shot done\n");
				get_req_work(&itf->nblk_shot , &nblk_work);
				if (nblk_work) {
					nblk_work->msg.command = ISR_DONE;
					nblk_work->fcount =
						nblk_work->msg.parameter3;
					set_free_work(&itf->nblk_shot,
						nblk_work);
#ifdef MEASURE_TIME
			{
				struct fimc_is_frame_shot *frame;
				frame = nblk_work->frame;
				do_gettimeofday(&frame->tzone[TM_SHOT_D]);
			}
#endif

				} else {
					err("nblk shot request is empty");
					print_fre_work_list(
						&itf->nblk_shot);
					print_req_work_list(
						&itf->nblk_shot);
				}
				break;
			case HIC_SET_CAM_CONTROL:
				dbg_interface("camctrl done\n");
				get_req_work(&itf->nblk_cam_ctrl , &nblk_work);
				if (nblk_work) {
					nblk_work->msg.command = ISR_DONE;
					set_free_work(&itf->nblk_cam_ctrl,
						nblk_work);
				} else {
					err("nblk camctrl request is empty");
					print_fre_work_list(
						&itf->nblk_cam_ctrl);
					print_req_work_list(
						&itf->nblk_cam_ctrl);
				}
				break;
			default:
				err("unknown done is invokded\n");
				break;
			}
			break;
		case ISR_NDONE:
			switch (msg->parameter1) {
			case HIC_SHOT:
				dbg_interface("shot NOT done\n");
				get_req_work(&itf->nblk_shot , &nblk_work);
				nblk_work->msg.command = ISR_NDONE;
				set_free_work(&itf->nblk_shot, nblk_work);
				break;
			case HIC_SET_CAM_CONTROL:
				dbg_interface("camctrl NOT done\n");
				get_req_work(&itf->nblk_cam_ctrl , &nblk_work);
				nblk_work->msg.command = ISR_NDONE;
				set_free_work(&itf->nblk_cam_ctrl, nblk_work);
				break;
			default:
				err("a command(%d) not done\n",
					msg->parameter1);
				memcpy(&itf->reply, msg,
					sizeof(struct fimc_is_msg));
				set_state(itf, IS_IF_STATE_IDLE);
				wake_up(&itf->wait_queue);
				break;
			}
			break;
		case IHC_SET_FACE_MARK:
			err("FACE_MARK(%d,%d,%d) is not acceptable\n",
				msg->parameter1,
				msg->parameter2,
				msg->parameter3);
			break;
		case IHC_AA_DONE:
			err("AA_DONE(%d,%d,%d) is not acceptable\n",
				msg->parameter1,
				msg->parameter2,
				msg->parameter3);
			break;
		case IHC_FLASH_READY:
			err("IHC_FLASH_READY is not acceptable");
			break;
		default:
			err("func_general unknown(%d) end\n", msg->command);
			break;
		}

		set_free_work(&itf->work_list[INTR_GENERAL], work);
		get_req_work(&itf->work_list[INTR_GENERAL], &work);
	}
}

static void wq_func_scc(struct work_struct *data)
{
	struct fimc_is_interface *itf;
	struct fimc_is_msg *msg;
	struct fimc_is_framemgr *framemgr;
	struct fimc_is_device_ischain *ischain;
	struct fimc_is_ischain_dev *dev;
	struct fimc_is_frame_shot *frame;
	struct fimc_is_video_common *video;
	struct fimc_is_work *work;
	unsigned long flags;
	u32 fnumber;
	u32 index;

	index = FIMC_IS_INVALID_BUF_INDEX;
	itf = container_of(data, struct fimc_is_interface,
		work_queue[INTR_SCC_FDONE]);
	video = itf->video_scc;
	ischain = video->device;
	dev = &ischain->scc;
	framemgr = &dev->framemgr;

	get_req_work(&itf->work_list[INTR_SCC_FDONE], &work);
	while (work) {
		msg = &work->msg;
		fnumber = msg->parameter1;

		framemgr_e_barrier_irqs(framemgr, FMGR_IDX_4, flags);

		fimc_is_frame_process_head(framemgr, &frame);
		if (frame && test_bit(FIMC_IS_REQ, &frame->req_flag)) {
			clear_bit(FIMC_IS_REQ, &frame->req_flag);

			index = frame->index;
			dbg_interface("C%d %d\n", index, fnumber);

			fimc_is_frame_trans_pro_to_com(framemgr, frame);
			buffer_done(video, frame->index);
		} else
			err("done(%p) is occured without request\n", frame);

		framemgr_x_barrier_irqr(framemgr, FMGR_IDX_4, flags);

		set_free_work(&itf->work_list[INTR_SCC_FDONE], work);
		get_req_work(&itf->work_list[INTR_SCC_FDONE], &work);
	}
}

static void wq_func_scp(struct work_struct *data)
{
	struct fimc_is_interface *itf;
	struct fimc_is_msg *msg;
	struct fimc_is_framemgr *framemgr;
	struct fimc_is_device_ischain *ischain;
	struct fimc_is_ischain_dev *dev;
	struct fimc_is_frame_shot *frame;
	struct fimc_is_video_common *video;
	struct fimc_is_work *work;
	unsigned long flags;
	u32 fcount;
	u32 index;

	index = FIMC_IS_INVALID_BUF_INDEX;
	itf = container_of(data, struct fimc_is_interface,
		work_queue[INTR_SCP_FDONE]);
	framemgr = itf->framemgr;
	video = itf->video_scp;
	ischain = video->device;
	dev = &ischain->scp;
	framemgr = &dev->framemgr;

	get_req_work(&itf->work_list[INTR_SCP_FDONE], &work);
	while (work) {
		msg = &work->msg;
		fcount = msg->parameter1;

		framemgr_e_barrier_irqs(framemgr, FMGR_IDX_4, flags);

		fimc_is_frame_process_head(framemgr, &frame);
		if (frame && test_bit(FIMC_IS_REQ, &frame->req_flag)) {
			clear_bit(FIMC_IS_REQ, &frame->req_flag);

			index = frame->index;
#ifdef DBG_STREAMING
			printk(KERN_INFO "P%d %d\n", index, fcount);
#endif

			fimc_is_frame_trans_pro_to_com(framemgr, frame);
			buffer_done(video, frame->index);
		} else
			err("done is occured without request(%p)\n", frame);

		framemgr_x_barrier_irqr(framemgr, FMGR_IDX_4, flags);

		set_free_work(&itf->work_list[INTR_SCP_FDONE], work);
		get_req_work(&itf->work_list[INTR_SCP_FDONE], &work);
	}
}

static void wq_func_meta(struct work_struct *data)
{
	struct fimc_is_interface *itf;
	struct fimc_is_msg *msg;
	struct fimc_is_framemgr *framemgr;
	struct fimc_is_device_ischain *ischain;
	struct fimc_is_frame_shot *frame;
	struct fimc_is_video_common *video;
	struct fimc_is_work_list *work_list;
	struct fimc_is_work *work;
	struct camera2_lens_uctl *isp_lens_uctl;
	struct camera2_lens_uctl *lens_uctl;
	struct camera2_sensor_uctl *isp_sensor_uctl;
	struct camera2_sensor_uctl *sensor_uctl;
	struct camera2_flash_uctl *isp_flash_uctl;
	struct camera2_flash_uctl *flash_uctl;
	unsigned long flags;
	u32 fcount;
	u32 index;
	void *cookie;
	bool req_done = false;

	index = FIMC_IS_INVALID_BUF_INDEX;
	itf = container_of(data, struct fimc_is_interface,
		work_queue[INTR_META_DONE]);
	work_list = &itf->work_list[INTR_META_DONE];
	framemgr = itf->framemgr;
	video = itf->video_isp;
	ischain = video->device;
	isp_lens_uctl = &itf->isp_peri_ctl.lensUd;
	isp_sensor_uctl = &itf->isp_peri_ctl.sensorUd;
	isp_flash_uctl = &itf->isp_peri_ctl.flashUd;

	get_req_work(work_list, &work);
	while (work) {
		msg = &work->msg;
		fcount = msg->parameter1;

		itf->fcount++;
		if (itf->fcount != fcount) {
			err("fcount is not correct(%d, %d)",
				fcount, itf->fcount);

			itf->fcount = fcount;
			goto next;
		}

		framemgr_e_barrier_irqs(framemgr, FMGR_IDX_7, flags);

		fimc_is_frame_process_head(framemgr, &frame);
		if (frame) {
			if (fcount != frame->fcount)
				dbg_warning("frame mismatch(%d != %d)",
					fcount, frame->fcount);

			index = frame->index;
#ifdef DBG_STREAMING
			printk(KERN_INFO "M%d %d\n", index, fcount);
#endif

			/*flush cache*/
			cookie = vb2_plane_cookie(frame->vb, 1);
			vb2_ion_sync_for_device(cookie, 0, frame->shot_size,
				DMA_FROM_DEVICE);

			if (frame->shot->uctl.uUpdateBitMap & CAM_SENSOR_CMD) {
				sensor_uctl = &frame->shot->uctl.sensorUd;
				isp_sensor_uctl->ctl.exposureTime =
					sensor_uctl->ctl.exposureTime;
				isp_sensor_uctl->ctl.frameDuration =
					sensor_uctl->ctl.frameDuration;
				isp_sensor_uctl->ctl.sensitivity =
					sensor_uctl->ctl.sensitivity;

				frame->shot->uctl.uUpdateBitMap &=
					~CAM_SENSOR_CMD;
			}

			if (frame->shot->uctl.uUpdateBitMap & CAM_LENS_CMD) {
				lens_uctl = &frame->shot->uctl.lensUd;
				isp_lens_uctl->ctl.focusDistance =
					lens_uctl->ctl.focusDistance;
				isp_lens_uctl->maxPos =
					lens_uctl->maxPos;
				isp_lens_uctl->slewRate =
					lens_uctl->slewRate;

				frame->shot->uctl.uUpdateBitMap &=
					~CAM_LENS_CMD;
			}

			if (frame->shot->uctl.uUpdateBitMap & CAM_FLASH_CMD) {
				flash_uctl = &frame->shot->uctl.flashUd;
				isp_flash_uctl->ctl.flashMode =
					flash_uctl->ctl.flashMode;
				isp_flash_uctl->ctl.firingPower =
					flash_uctl->ctl.firingPower;
				isp_flash_uctl->ctl.firingTime =
					flash_uctl->ctl.firingTime;

				frame->shot->uctl.uUpdateBitMap &=
					~CAM_FLASH_CMD;
			}

#ifdef MEASURE_TIME
			do_gettimeofday(&frame->tzone[TM_META_D]);
#endif

			if (test_bit(FIMC_IS_REQ, &frame->req_flag)) {
				clear_bit(FIMC_IS_REQ, &frame->req_flag);
#ifdef AUTO_MODE
				fimc_is_frame_trans_pro_to_fre(framemgr, frame);
				buffer_done(itf->video_sensor, index);
#else
				fimc_is_frame_trans_pro_to_com(framemgr, frame);
				buffer_done(itf->video_isp, index);
#endif
				req_done = true;
			}
		} else {
			err("Meta done is occured without request");
			fimc_is_frame_print_all(framemgr);
		}

		framemgr_x_barrier_irqr(framemgr, FMGR_IDX_7, flags);

#if 1
		if (req_done) {
			mutex_lock(&ischain->mutex_state);
			fimc_is_ischain_callback(ischain);
			mutex_unlock(&ischain->mutex_state);
		}
#endif

next:
		set_free_work(work_list, work);
		get_req_work(work_list, &work);
	}
}

static irqreturn_t interface_isr(int irq, void *data)
{
	struct fimc_is_interface *itf;
	struct work_struct *work_queue;
	struct fimc_is_work_list *work_list;
	struct fimc_is_work *work;
	u32 status;

	itf = (struct fimc_is_interface *)data;
	status = readl(itf->regs + INTMSR1);

	if (status & (1<<INTR_GENERAL)) {
		work_queue = &itf->work_queue[INTR_GENERAL];
		work_list = &itf->work_list[INTR_GENERAL];

		get_free_work_irq(&itf->work_list[INTR_GENERAL], &work);
		if (work) {
			fimc_is_get_cmd(itf, &work->msg, INTR_GENERAL);
			set_req_work_irq(work_list, work);

			if (!work_pending(work_queue))
				schedule_work(work_queue);
		} else
			err("free work item is empty1");

		writel((1<<INTR_GENERAL), itf->regs + INTCR1);
	}

	if (status & (1<<INTR_SCC_FDONE)) {
		work_queue = &itf->work_queue[INTR_SCC_FDONE];
		work_list = &itf->work_list[INTR_SCC_FDONE];

		get_free_work_irq(work_list, &work);
		if (work) {
			fimc_is_get_cmd(itf, &work->msg, INTR_SCC_FDONE);
			set_req_work_irq(work_list, work);

			if (!work_pending(work_queue))
				schedule_work(work_queue);
		} else
			err("free work item is empty2");

		writel((1<<INTR_SCC_FDONE), itf->regs + INTCR1);
	}

	if (status & (1<<INTR_SCP_FDONE)) {
		work_queue = &itf->work_queue[INTR_SCP_FDONE];
		work_list = &itf->work_list[INTR_SCP_FDONE];

		get_free_work_irq(work_list, &work);
		if (work) {
			fimc_is_get_cmd(itf, &work->msg, INTR_SCP_FDONE);
			set_req_work_irq(work_list, work);

			if (!work_pending(work_queue))
				schedule_work(work_queue);
		} else
			err("free work item is empty3");

		writel((1<<INTR_SCP_FDONE), itf->regs + INTCR1);
	}

	if (status & (1<<INTR_META_DONE)) {
		work_queue = &itf->work_queue[INTR_META_DONE];
		work_list = &itf->work_list[INTR_META_DONE];

		get_free_work_irq(work_list, &work);
		if (work) {
			fimc_is_get_cmd(itf, &work->msg, INTR_META_DONE);
			work->fcount = work->msg.parameter1;
			set_req_work_irq(work_list, work);

			if (!work_pending(work_queue))
				schedule_work(work_queue);
		} else
			err("free work item is empty4");

		writel((1<<INTR_META_DONE), itf->regs + INTCR1);
	}

	return IRQ_HANDLED;
}


int fimc_is_interface_probe(struct fimc_is_interface *this,
	struct fimc_is_framemgr *framemgr,
	u32 regs,
	u32 irq,
	void *core_data)
{
	int ret = 0;
	struct fimc_is_core *core = (struct fimc_is_core *)core_data;

	dbg_interface("%s\n", __func__);

	this->streaming = false;
	init_request_barrier(this);
	init_process_barrier(this);
	init_state_barrier(this);
	init_wait_queue(this);

	INIT_WORK(&this->work_queue[INTR_GENERAL], wq_func_general);
	INIT_WORK(&this->work_queue[INTR_SCC_FDONE], wq_func_scc);
	INIT_WORK(&this->work_queue[INTR_SCP_FDONE], wq_func_scp);
	INIT_WORK(&this->work_queue[INTR_META_DONE], wq_func_meta);

	enter_request_barrier(this);

	set_state(this, IS_IF_STATE_IDLE);

	this->regs = (void *)regs;
	this->com_regs = (struct is_common_reg *)(regs + ISSR0);

	ret = request_irq(irq, interface_isr, 0, "MCUCTL", this);
	if (ret)
		err("request_irq failed\n");

	this->framemgr			= framemgr;
	this->core			= (void *)core;
	this->video_isp			= &core->video_isp.common;
	this->video_sensor		= &core->video_sensor.common;
	this->video_scp			= &core->video_scp.common;
	this->video_scc			= &core->video_scc.common;

	init_work_list(&this->nblk_cam_ctrl, TRACE_WORK_ID_CAMCTRL,
		MAX_NBLOCKING_COUNT);
	init_work_list(&this->nblk_shot, TRACE_WORK_ID_SHOT,
		MAX_NBLOCKING_COUNT);
	init_work_list(&this->work_list[INTR_GENERAL],
		TRACE_WORK_ID_GENERAL, MAX_WORK_COUNT);
	init_work_list(&this->work_list[INTR_SCC_FDONE],
		TRACE_WORK_ID_SCC, MAX_WORK_COUNT);
	init_work_list(&this->work_list[INTR_SCP_FDONE],
		TRACE_WORK_ID_SCP, MAX_WORK_COUNT);
	init_work_list(&this->work_list[INTR_META_DONE],
		TRACE_WORK_ID_META, MAX_WORK_COUNT);

	return ret;
}

int fimc_is_interface_open(struct fimc_is_interface *this)
{
	int ret = 0;

	dbg_interface("%s\n", __func__);

	this->streaming = false;
	init_request_barrier(this);
	init_process_barrier(this);
	init_state_barrier(this);
	init_wait_queue(this);

	enter_request_barrier(this);

	this->fcount = 0;
	set_state(this, IS_IF_STATE_IDLE);

	return ret;
}

int fimc_is_interface_close(struct fimc_is_interface *this)
{
	int ret = 0;

	dbg_interface("%s\n", __func__);

	return ret;
}

int fimc_is_hw_enum(struct fimc_is_interface *this,
	u32 instances)
{
	struct fimc_is_msg msg;

	dbg_interface("enum(%d)\n", instances);

	msg.id = 0;
	msg.command = ISR_DONE;
	msg.instance = 0;
	msg.parameter1 = IHC_GET_SENSOR_NUMBER;
	msg.parameter2 = instances;
	msg.parameter3 = 0;
	msg.parameter4 = 0;

	waiting_is_ready(this);
	set_state(this, IS_IF_STATE_BLOCK_IO);
	this->com_regs->hicmd = msg.command;
	this->com_regs->hic_sensorid = msg.instance;
	this->com_regs->hic_param1 = msg.parameter1;
	this->com_regs->hic_param2 = msg.parameter2;
	this->com_regs->hic_param3 = msg.parameter3;
	this->com_regs->hic_param4 = msg.parameter4;
	send_interrupt(this);

	return 0;
}

int fimc_is_hw_saddr(struct fimc_is_interface *this,
	u32 instance, u32 *setfile_addr)
{
	struct fimc_is_msg msg;

	dbg_interface("saddr(%d)\n", instance);

	msg.id = 0;
	msg.command = HIC_GET_SET_FILE_ADDR;
	msg.instance = instance;
	msg.parameter1 = 0;
	msg.parameter2 = 0;
	msg.parameter3 = 0;
	msg.parameter4 = 0;

	fimc_is_set_cmd(this, &msg);
	*setfile_addr = this->reply.parameter2;

	return 0;
}

int fimc_is_hw_setfile(struct fimc_is_interface *this,
	u32 instance)
{
	struct fimc_is_msg msg;

	dbg_interface("setfile(%d)\n", instance);

	msg.id = 0;
	msg.command = HIC_LOAD_SET_FILE;
	msg.instance = instance;
	msg.parameter1 = 0;
	msg.parameter2 = 0;
	msg.parameter3 = 0;
	msg.parameter4 = 0;

	fimc_is_set_cmd(this, &msg);

	return 0;
}

int fimc_is_hw_open(struct fimc_is_interface *this,
	u32 instance, u32 sensor, u32 channel, u32 ext,
	u32 *mwidth, u32 *mheight)
{
	int ret;
	struct fimc_is_msg msg;

	dbg_interface("open(%d)\n", sensor);

	wait_state(this, IS_IF_STATE_IDLE);

	msg.id = 0;
	msg.command = HIC_OPEN_SENSOR;
	msg.instance = instance;
	msg.parameter1 = sensor;
	msg.parameter2 = channel;
	msg.parameter3 = ext;
	msg.parameter4 = 0;

	ret = fimc_is_set_cmd(this, &msg);

	*mwidth = this->reply.parameter2;
	*mheight = this->reply.parameter3;

	return ret;
}

int fimc_is_hw_stream_on(struct fimc_is_interface *this,
	u32 instance)
{
	int ret;
	struct fimc_is_msg msg;

	dbg_interface("stream_on(%d)\n", instance);

	msg.id = 0;
	msg.command = HIC_STREAM_ON;
	msg.instance = instance;
	msg.parameter1 = 0;
	msg.parameter2 = 0;
	msg.parameter3 = 0;
	msg.parameter4 = 0;

	ret = fimc_is_set_cmd(this, &msg);

	return ret;
}

int fimc_is_hw_stream_off(struct fimc_is_interface *this,
	u32 instance)
{
	int ret;
	struct fimc_is_msg msg;

	dbg_interface("stream_off(%d)\n", instance);

	msg.id = 0;
	msg.command = HIC_STREAM_OFF;
	msg.instance = instance;
	msg.parameter1 = 0;
	msg.parameter2 = 0;
	msg.parameter3 = 0;
	msg.parameter4 = 0;

	ret = fimc_is_set_cmd(this, &msg);

	return ret;
}

int fimc_is_hw_process_on(struct fimc_is_interface *this,
	u32 instance)
{
	int ret;
	struct fimc_is_msg msg;

	dbg_interface("process_on(%d)\n", instance);

	msg.id = 0;
	msg.command = HIC_PROCESS_START;
	msg.instance = instance;
	msg.parameter1 = 0;
	msg.parameter2 = 0;
	msg.parameter3 = 0;
	msg.parameter4 = 0;

	ret = fimc_is_set_cmd(this, &msg);

	return ret;
}

int fimc_is_hw_process_off(struct fimc_is_interface *this,
	u32 instance)
{
	int ret;
	struct fimc_is_msg msg;

	dbg_interface("process_off(%d)\n", instance);

	msg.id = 0;
	msg.command = HIC_PROCESS_STOP;
	msg.instance = instance;
	msg.parameter1 = 0;
	msg.parameter2 = 0;
	msg.parameter3 = 0;
	msg.parameter4 = 0;

	ret = fimc_is_set_cmd(this, &msg);

	return ret;
}

int fimc_is_hw_s_param(struct fimc_is_interface *this,
	u32 instance, u32 indexes, u32 lindex, u32 hindex)
{
	int ret;
	struct fimc_is_msg msg;

	dbg_interface("s_param(%d)\n", instance);

	msg.id = 0;
	msg.command = HIC_SET_PARAMETER;
	msg.instance = instance;
	msg.parameter1 = ISS_PREVIEW_STILL;
	msg.parameter2 = indexes;
	msg.parameter3 = lindex;
	msg.parameter4 = hindex;

	ret = fimc_is_set_cmd(this, &msg);

	return ret;
}

int fimc_is_hw_a_param(struct fimc_is_interface *this,
	u32 instance, u32 mode, u32 sub_mode)
{
	int ret = 0;
	struct fimc_is_msg msg;

	dbg_interface("a_param(%d)\n", instance);

	msg.id = 0;
	msg.command = mode;
	msg.instance = instance;
	msg.parameter1 = sub_mode;
	msg.parameter2 = 0;
	msg.parameter3 = 0;
	msg.parameter4 = 0;

	ret = fimc_is_set_cmd(this, &msg);

	return ret;
}

int fimc_is_hw_f_param(struct fimc_is_interface *this,
	u32 instance)
{
	int ret;
	struct fimc_is_msg msg;

	dbg_interface("f_param(%d)\n", instance);

	msg.id = 0;
	msg.command = HIC_PREVIEW_STILL;
	msg.instance = instance;
	msg.parameter1 = 0;
	msg.parameter2 = 0;
	msg.parameter3 = 0;
	msg.parameter4 = 0;

	ret = fimc_is_set_cmd(this, &msg);

	return ret;
}

int fimc_is_hw_g_capability(struct fimc_is_interface *this,
	u32 instance, u32 address)
{
	int ret;
	struct fimc_is_msg msg;

	dbg_interface("g_capability(%d)\n", instance);

	msg.id = 0;
	msg.command = HIC_GET_STATIC_METADATA;
	msg.instance = instance;
	msg.parameter1 = address;
	msg.parameter2 = 0;
	msg.parameter3 = 0;
	msg.parameter4 = 0;

	ret = fimc_is_set_cmd(this, &msg);

	return ret;
}

int fimc_is_hw_cfg_mem(struct fimc_is_interface *this,
	u32 instance, u32 address, u32 size)
{
	int ret;
	struct fimc_is_msg msg;

	dbg_interface("cfg_mem(%d)\n", instance);

	msg.id = 0;
	msg.command = HIC_SET_A5_MEM_ACCESS;
	msg.instance = instance;
	msg.parameter1 = address;
	msg.parameter2 = size;
	msg.parameter3 = 0;
	msg.parameter4 = 0;

	ret = fimc_is_set_cmd(this, &msg);

	return ret;
}

int fimc_is_hw_power_down(struct fimc_is_interface *this,
	u32 instance)
{
	int ret = 0;
	struct fimc_is_msg msg;

	dbg_interface("pwr_down(%d)\n", instance);

	msg.id = 0;
	msg.command = HIC_POWER_DOWN;
	msg.instance = instance;
	msg.parameter1 = 0;
	msg.parameter2 = 0;
	msg.parameter3 = 0;
	msg.parameter4 = 0;

	ret = fimc_is_set_cmd(this, &msg);

	return ret;
}

int fimc_is_hw_shot_nblk(struct fimc_is_interface *this,
	u32 instance, u32 bayer, u32 shot, u32 fcount,
	struct fimc_is_frame_shot *frame)
{
	int ret = 0;
	struct fimc_is_work *work;
	struct fimc_is_msg *msg;

	dbg_interface("shot_nblk(%d, %d)\n", instance, fcount);

	get_free_work(&this->nblk_shot, &work);
	if (work) {
		work->fcount = fcount;
		work->frame = frame;
		msg = &work->msg;
		msg->id = 0;
		msg->command = HIC_SHOT;
		msg->instance = instance;
		msg->parameter1 = bayer;
		msg->parameter2 = shot;
		msg->parameter3 = fcount;
		msg->parameter4 = 0;

		ret = fimc_is_set_cmd_nblk(this, work);
	} else {
		err("g_free_nblk return NULL");
		print_fre_work_list(&this->nblk_shot);
		print_req_work_list(&this->nblk_shot);
		ret = 1;
	}

	return ret;
}

int fimc_is_hw_s_camctrl_nblk(struct fimc_is_interface *this,
	u32 instance, u32 address, u32 fcount)
{
	int ret = 0;
	struct fimc_is_work *work;
	struct fimc_is_msg *msg;

	dbg_interface("cam_ctrl_nblk(%d)\n", instance);

	get_free_work(&this->nblk_cam_ctrl, &work);
	/*printk("%d %d\n", fnumber, this->nblk_cam_ctrl.work_free_cnt);*/
	if (work) {
		work->fcount = fcount;
		msg = &work->msg;
		msg->id = 0;
		msg->command = HIC_SET_CAM_CONTROL;
		msg->instance = instance;
		msg->parameter1 = address;
		msg->parameter2 = fcount;
		msg->parameter3 = 0;
		msg->parameter4 = 0;

		ret = fimc_is_set_cmd_nblk(this, work);
	} else {
		err("g_free_nblk return NULL");
		print_fre_work_list(&this->nblk_cam_ctrl);
		print_req_work_list(&this->nblk_cam_ctrl);
		ret = 1;
	}

	return ret;
}

