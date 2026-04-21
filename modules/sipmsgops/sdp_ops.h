/*
 * Copyright (C) 2025 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef SIPMSGOPS_SDP
#define SIPMSGOPS_SDP

#include "../../parser/sdp/sdp.h"
#include "../../parser/msg_parser.h"

#define AUDIO_STR "audio"
#define AUDIO_STR_LEN 5

static inline int is_audio_on_hold(struct sip_msg *msg)
{
	int sdp_session_num = 0, sdp_stream_num;
	sdp_session_cell_t* sdp_session;
	sdp_stream_cell_t* sdp_stream;
	sdp_info_t* sdp;

	if ( (sdp=parse_sdp(msg))!=NULL ) {
		for(;;) {
			sdp_session = get_sdp_session(sdp, sdp_session_num);
			if(!sdp_session) break;
			sdp_stream_num = 0;
			for(;;) {
				sdp_stream = get_sdp_stream(sdp, sdp_session_num,
					sdp_stream_num);
				if(!sdp_stream) break;
				if(sdp_stream->media.len==AUDIO_STR_LEN &&
						!strncmp(sdp_stream->media.s,AUDIO_STR,AUDIO_STR_LEN) &&
						sdp_stream->is_on_hold)
					return sdp_stream->is_on_hold;
				sdp_stream_num++;
			}
			sdp_session_num++;
		}
	}
	return 0;
}

#endif /* SIPMSGOPS_SDP */
