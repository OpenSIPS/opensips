/**
 * Copyright (C) 2013 OpenSIPS Solutions
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
 * History
 * -------
 * 2013-06-05  created (liviu)
 *
 */

#ifndef __SNGTC_H__
#define __SNGTC_H__

#include <sng_tc/sngtc_node.h>
#include "../../locking.h"

#define SDP_CONTENT_TYPE_LEN (sizeof("Content-Type: application/sdp\r\n") - 1)
#define A_LINE_PREFIX_LEN    (sizeof("a=rtpmap:") - 1)
#define C_LINE_LEN           (sizeof("c=IN IP4 xxx.xxx.xxx.xxx\r\n") - 1)
#define SDP_BUFFER_SIZE      4096
#define MAX_STREAMS          30
#define CONTENT_LEN_DIGITS   5

#define PROCESSED_FLAG       (1 << 0)

#define READ_END  0
#define WRITE_END 1

#define is_processed(_info) (_info->flags & PROCESSED_FLAG)

/**
 * @_level:    OpenSIPS debug level
 * @_l:        struct sngtc_codec_request_leg
 * @_start:    string identifier of the leg
 */
#define sngtc_print_request_leg(_level, _l, _start) \
	do { \
		LM_GEN1(_level, "%s: [Codec: %d][ms: %d][ip: %d][nm: %d][port: %d]\n", \
		        _start, _l.codec_id, _l.ms, _l.host_ip, _l.host_netmask, \
		        _l.host_udp_port); \
	} while (0)

/**
 * @_level:    OpenSIPS debug level
 * @_l:        struct sngtc_codec_reply_leg
 * @_start:    string identifier of the leg
 */
#define sngtc_print_reply_leg(_level, _l, _start) \
	do { \
		LM_GEN1(_level, "%s: [IP: %d][nm: %d][port: %d]\n", \
		        _start, _l.codec_ip, _l.codec_netmask, _l.codec_udp_port); \
		LM_GEN1(_level, "%s: [Host IP: %d][nm: %d][port: %d][iana: %d]\n", \
		        _start, _l.host_ip, _l.host_netmask, _l.host_udp_port, \
		        _l.iana_code); \
	} while (0)

/**
 * @_level: OpenSIPS debug level
 * @_r:     struct sngtc_codec_request
 */
#define sngtc_print_request(_level, _r) \
	do { \
		LM_GEN1(_level, "sngtc_codec_request with rtcp: %d\n", _r.rtcp_enable); \
		sngtc_print_request_leg(_level, (_r).a, "A"); \
		sngtc_print_request_leg(_level, (_r).b, "B"); \
	} while (0)

/**
 * @_level: OpenSIPS debug level
 * @_r:     struct sngtc_codec_reply *
 */
#define sngtc_print_reply(_level, _r) \
	do { \
		LM_GEN1(_level, "sngtc_codec_reply with [mod_session: %d]" \
		        "[rtp_session: %d]\n", (_r)->codec_module_session_idx, \
		        (_r)->codec_rtp_session_idx); \
		sngtc_print_reply_leg(_level, (_r)->a, "A"); \
		sngtc_print_reply_leg(_level, (_r)->b, "B"); \
	} while (0)

#define SNGTC_SDP_ERR -1
#define SNGTC_TC_ERR  -2
#define SNGTC_ERR     -3

enum sng_module_status {
	SNGTC_UNSUP_CODECS = -2,
	SNGTC_BAD_SDP,
	SNGTC_OFF,
	SNGTC_ON,
};

struct sngtc_session_list {
	struct sngtc_codec_reply *reply;
	struct sngtc_session_list *next;
};

struct sngtc_info {
	str caller_sdp;
	str modified_caller_sdp;

	gen_lock_t lock;

	/* various session-related flags */
	int flags;

	/* optional, used if transcoding is needed */
	struct sngtc_session_list *sessions;
	struct sngtc_session_list *last_session;
};

struct codec_pair {
	struct sdp_payload_attr *att1;
	struct sdp_payload_attr *att2;

	enum sngtc_codec_definition tc1;
	enum sngtc_codec_definition tc2;

	enum sng_module_status status;

	struct sngtc_codec_reply *reply;
};

struct codec_mapping {
	str name;
	int bitrate;

	int mode;

	int sng_codec;
};

#endif /* __SNGTC_H__ */

