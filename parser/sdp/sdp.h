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
} sdp_stream_cell_t;

typedef struct sdp_session_cell {
	struct sdp_session_cell *next;
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
int parse_sdp(struct sip_msg* _m);
int parse_sdp_session(str *sdp_body, int session_num, str *cnt_disp,
                      sdp_info_t* _sdp);

/**
 * Get number of sessions in existing SDP.
 */
int get_sdp_session_num(struct sip_msg* _m);
/**
 * Get number of streams in existing SDP.
 */
int get_sdp_stream_num(struct sip_msg* _m);
/**
 * Get a session for the current sip msg based on position inside SDP.
 */
sdp_session_cell_t* get_sdp_session(struct sip_msg* _m, int session_num);
/**
 * Get a session for the given sdp based on position inside SDP.
 */
sdp_session_cell_t* get_sdp_session_sdp(struct sdp_info* sdp, int session_num);

/**
 * Get a stream for the current sip msg based on positions inside SDP.
 */
sdp_stream_cell_t* get_sdp_stream(struct sip_msg* _m, int session_num, int stream_num);
/**
 * Get a stream for the given sdp based on positions inside SDP.
 */
sdp_stream_cell_t* get_sdp_stream_sdp(struct sdp_info* sdp, int session_num, int stream_num);

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
 *
 * Note: this will free up the parsed sdp structure (form PKG_MEM).
 */
void free_sdp(sdp_info_t** sdp);
void __free_sdp(sdp_info_t* sdp);


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


#endif /* SDP_H */
