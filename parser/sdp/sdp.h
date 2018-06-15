/*
 * SDP parser interface
 *
 * Copyright (C) 2008 SOMA Networks, INC.
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
 *
 *
 * HISTORY:
 * --------
 * 2007-09-09 osas: ported and enhanced sdp parsing functions from nathelper module
 * 2008-04-22 osas: integrated RFC4975 attributes - patch provided by Denis Bilenko (denik)
 *
 */


#ifndef SDP_H
#define SDP_H

#include "../msg_parser.h"
#include "../../mem/mem.h"

#define      NO_HOLD 0
#define RFC2543_HOLD 1
#define RFC3264_HOLD 2

typedef struct sdp_attr {
	struct sdp_attr *next;
	str attribute;
	str value;
} sdp_attr_t;

typedef struct sdp_payload_attr {
	struct sdp_payload_attr *next;
	/**< payload index inside stream */
	int payload_num;
	str rtp_payload;
	str rtp_enc;
	str rtp_clock;
	str rtp_params;
	str fmtp_string;
} sdp_payload_attr_t;

typedef struct sdp_stream_cell {
	struct sdp_stream_cell *next;
	/**< body of the entire stream */
	str body;
	/* c=<network type> <address type> <connection address> */
	/**< connection address family: AF_INET/AF_INET6 */
	int pf;
	/**< connection address */
	str ip_addr;
	/**< stream index inside a session */
	int stream_num;
	/**< flag indicating if this is an RTP stream */
	int is_rtp;
	/**< flag indicating if this stream is on hold */
	int is_on_hold;
	/* m=<media> <port> <transport> <payloads> */
	str media;
	str port;
	str transport;
	str sendrecv_mode;
	str ptime;
	str payloads;
	/**< number of payloads inside a stream */
	int payloads_num;
	/* b=<bwtype>:<bandwidth> */
	/**< alphanumeric modifier giving the meaning of the <bandwidth> figure:
		CT - conference total;
		AS - application specific */
	str bw_type;
	/**< The <bandwidth> is interpreted as kilobits per second by default */
	str bw_width;
	/* RFC3605: Real Time Control Protocol (RTCP) attribute in
	 * Session Description Protocol (SDP) */
	/* a=rtcp: port  [nettype space addrtype space connection-address] CRLF */
	/**< RFC3605: rtcp attribute */
	str rtcp_port;
	/**< RFC4975: path attribute */
	str path;
	/**< RFC4975: max-size attribute */
	str max_size;
	/**< RFC4975: accept-types attribute */
	str accept_types;
	/**< RFC4975: accept-wrapped-types attribute */
	str accept_wrapped_types;
	/**< fast access pointers to payloads */
	struct sdp_payload_attr **p_payload_attr;
	struct sdp_payload_attr *payload_attr;
	struct sdp_attr *attr;
} sdp_stream_cell_t;

typedef struct sdp_session_cell {
	struct sdp_session_cell *next;
	/**< body of the entire session */
	str body;
	/**< session index inside sdp */
	int session_num;
	/**< the Content-Disposition header (for Content-Type:multipart/mixed) */
	str cnt_disp;
	/* c=<network type> <address type> <connection address> */
	/**< connection address family: AF_INET/AF_INET6 */
	int pf;
	/**< connection address */
	str ip_addr;
	/* o=<username> <session id> <version> <network type> <addr type> <addr> */
	/**< origin address family: AF_INET/AF_INET6 */
	int o_pf;
	/**< origin address */
	str o_ip_addr;
	/* b=<bwtype>:<bandwidth> */
	/**< alphanumeric modifier giving the meaning of the <bandwidth> figure:
		CT - conference total;
		AS - application specific */
	str bw_type;
	/**< The <bandwidth> is interpreted as kilobits per second by default */
	str bw_width;
	/**< number of streams inside a session */
	int streams_num;
	struct sdp_stream_cell*  streams;
	struct sdp_attr *attr;
} sdp_session_cell_t;

/**
 * Here we hold the head of the parsed sdp structure
 */
typedef struct sdp_info {
	int sessions_num;	/**< number of SDP sessions */
	int streams_num;  /**< total number of streams for all SDP sessions */
	struct sdp_session_cell *sessions;
} sdp_info_t;


/*
 * Parse SDP.
 */
sdp_info_t* parse_sdp(struct sip_msg* _m);
int parse_sdp_session(str *sdp_body, int session_num, str *cnt_disp,
                      sdp_info_t* _sdp);

/**
 * Get a session for the given sdp based on position inside SDP.
 */
sdp_session_cell_t* get_sdp_session(sdp_info_t* sdp, int session_num);

/**
 * Get a stream for the given sdp based on positions inside SDP.
 */
sdp_stream_cell_t* get_sdp_stream(sdp_info_t* sdp, int session_num,
		int stream_num);

/**
 * Get a payload from a stream based on payload.
 */
sdp_payload_attr_t* get_sdp_payload4payload(sdp_stream_cell_t *stream, str *rtp_payload);

/**
 * Get a payload from a stream based on position.
 */
sdp_payload_attr_t* get_sdp_payload4index(sdp_stream_cell_t *stream, int index);

/**
 * Free all memory associated with parsed structure.
 */
void free_sdp_content(sdp_info_t* sdp);
/**
 * Free all memory associated with parsed structure.
 *
 * Note: this will also pkg_free() the given pointer
 */
static inline void free_sdp(sdp_info_t* sdp)
{
	free_sdp_content(sdp);
	pkg_free(sdp);
}

/**
 * Print the content of the given sdp_info structure.
 *
 * Note: only for debug purposes.
 */
void print_sdp(sdp_info_t* sdp, int log_level);
/**
 * Print the content of the given sdp_session structure.
 *
 * Note: only for debug purposes.
 */
void print_sdp_session(sdp_session_cell_t* sdp_session, int log_level);
/**
 * Print the content of the given sdp_stream structure.
 *
 * Note: only for debug purposes.
 */
void print_sdp_stream(sdp_stream_cell_t *stream, int log_level);

/**
 * Get the first SDP from the body
 */
static inline sdp_info_t* get_sdp(struct sip_msg* _m)
{
	struct body_part *p;
	if (_m->body) {
		for( p=&_m->body->first ; p ; p=p->next)
			if (p->mime==((TYPE_APPLICATION<<16)+SUBTYPE_SDP)
			&& p->parsed )
				return (sdp_info_t*)p->parsed;
	}
	return NULL;
}

#endif /* SDP_H */
