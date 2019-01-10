/*
 * Copyright (C) 2006 Voice Sistem SRL
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 * History:
 * ---------
 *  2006-09-25  first version (bogdan)
 */


#ifndef _MI_FIFO_H_
#define _MI_FIFO_H_

#define DEFAULT_MI_REPLY_DIR "/tmp/"

#define MI_CMD_SEPARATOR       ':'

/* size of the fifo read buffer */
#define MAX_MI_FIFO_BUFFER    4096

/* how patient is ser with FIFO clients not awaiting a reply?
	4 x 80ms = 0.32 sec */
#define FIFO_REPLY_RETRIES  4

/* maximum size for the composed fifo reply name */
#define MAX_MI_FILENAME 128

/* we are waiting for a while between fifo file checks */
#define FIFO_CHECK_WAIT 30

#endif /* _MI_FIFO */
