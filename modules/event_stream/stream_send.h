/*
 * Copyright (C) 2018 OpenSIPS Solutions
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
 */

#ifndef _STREAM_SEND_H_
#define _STREAM_SEND_H_

#define STREAM_SEND_RETRY 3

#include <sys/time.h>

typedef struct _stream_send {
	union sockaddr_union addr;
	struct timeval time;
	int process_idx;
	str message;
	int id;
} stream_send_t;

void stream_process(int rank);
int stream_init_process(void);
void stream_destroy_pipe(void);
int stream_init_writer(void);
int stream_init_buffers(void);
int stream_send(stream_send_t * streams);
void stream_destroy(evi_reply_sock *sock);
int stream_build_buffer(str *,
		evi_reply_sock*, evi_params_t *, stream_send_t **);

#define STREAM_DEFAULT_TIMEOUT 1000
#define STREAM_BUFFER_SIZE 8192
#define JSONRPC_VERSION "2.0"

extern int stream_timeout;
extern unsigned stream_sync_mode;
extern char *stream_event_param;

#endif
