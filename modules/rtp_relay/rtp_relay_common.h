/*
 * Copyright (C) 2021 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 
 */

#ifndef _RTP_RELAY_COMMON_H_
#define _RTP_RELAY_COMMON_H_

#define RTP_RELAY_CALLER 0
#define RTP_RELAY_CALLEE 1

#define RTP_COPY_MODE_SIPREC (1<<0)
#define RTP_COPY_MODE_DISABLE (1<<1)

#define RTP_COPY_LEG_CALLER (1<<2)
#define RTP_COPY_LEG_CALLEE (1<<3)
#define RTP_COPY_LEG_BOTH \
	(RTP_COPY_LEG_CALLER|RTP_COPY_LEG_CALLEE)
#define RTP_COPY_MAX_STREAMS 32

struct rtp_relay_stream {
	int leg;
	int medianum;
	int label;
};

struct rtp_relay_streams {
	int count;
	struct rtp_relay_stream streams[RTP_COPY_MAX_STREAMS];
};

#endif /* _RTP_RELAY_COMMON_H_ */
