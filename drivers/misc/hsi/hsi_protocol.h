/* linux/drivers/misc/hsi/hsi_protocol.h
 *
 * Copyright 2012 Samsung Electronics Co.Ltd.
 *      Donggyun, ko <donggyun.ko@samsung.com>
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
*/

#ifndef __HSI_PROTOCOL_HEADER__
#define __HSI_PROTOCOL_HEADER__

/* The begin of the sechsi command */
enum {
	CMD_BREAK = 0,
	CMD_ECHO,
	CMD_INFO_REQ,
	CMD_INFO,
	CMD_CONFIGURE,
	CMD_ALLOC_CH,
	CMD_RELEASE_CH,
	CMD_OPEN_CONN,
	CMD_CONN_READY,
	CMD_CONN_CLOSED,
	CMD_CANCEL_CONN,
	CMD_ACK,
	CMD_NAK
};

enum {
	HSI_CHANNEL0,
	HSI_CHANNEL1,
	HSI_CHANNEL2,
	HSI_CHANNEL3,
	HSI_CHANNEL4,
	HSI_CHANNEL5,
	HSI_CHANNEL6,
	HSI_CHANNEL7,
	HSI_CHANNEL_INVALID
};
/* The end of the sechsi command */

int send_break(void);
int send_echo(void);

#endif
