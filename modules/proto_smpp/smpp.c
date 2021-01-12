/*
 * Copyright (C) 2019 - OpenSIPS Project
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
 */

#include <poll.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/tcp.h>

#include "../../timer.h"
#include "../../sr_module.h"
#include "../../net/api_proto.h"
#include "../../net/api_proto_net.h"
#include "../../net/net_tcp.h"
#include "../../socket_info.h"
#include "../../tsend.h"
#include "../../net/proto_tcp/tcp_common_defs.h"
#include "../../pt.h"
#include "../../ut.h"
#include "../../resolve.h"
#include "../../forward.h"
#include "../../receive.h"
#include "../../strcommon.h"
#include "../tm/tm_load.h"
#include "../../parser/parse_from.h"

#include "proto_smpp.h"
#include "utils.h"
#include "smpp.h"
#include "db.h"

str smpp_outbound_uri;
int smpp_send_timeout = DEFAULT_SMPP_SEND_TIMEOUT;

int bind_session(smpp_session_t *session);
static int recv_smpp_msg(smpp_header_t *header, smpp_deliver_sm_t *body,
		smpp_session_t *session, struct receive_info *rcv);
static void send_enquire_link_request(smpp_session_t *session);

static uint32_t increment_sequence_number(smpp_session_t *session);

#define free_smpp_msg(_msg) \
	do { \
		pkg_free((_msg)->header); \
		pkg_free((_msg)->body); \
		if ((_msg)->payload.s) \
			pkg_free((_msg)->payload.s); \
		pkg_free((_msg)); \
	} while (0)


/** TM bind */
struct tm_binds tmb;

//static smpp_session_t **g_sessions = NULL;
struct list_head *g_sessions;
rw_lock_t *smpp_lock;       /* reader-writers lock for reloading the data */

static uint32_t get_payload_from_header(char *payload, smpp_header_t *header)
{
	if (!payload || !header) {
		LM_ERR("NULL params\n");
		return 0;
	}

	char *p = payload;
	p += copy_u32(p, header->command_length);
	p += copy_u32(p, header->command_id);
	p += copy_u32(p, header->command_status);
	p += copy_u32(p, header->sequence_number);

	return p - payload;
}

static uint32_t get_payload_from_bind_transceiver_body(char *body, smpp_bind_transceiver_t *transceiver)
{
	if (!body || !transceiver) {
		LM_ERR("NULL params\n");
		return 0;
	}

	char *p = body;
	p += copy_var_str(p, transceiver->system_id, MAX_SYSTEM_ID_LEN);
	p += copy_var_str(p, transceiver->password, MAX_PASSWORD_LEN);
	p += copy_var_str(p, transceiver->system_type, MAX_SYSTEM_TYPE_LEN);
	p += copy_u8(p, transceiver->interface_version);
	p += copy_u8(p, transceiver->addr_ton);
	p += copy_u8(p, transceiver->addr_npi);
	p += copy_var_str(p, transceiver->address_range, MAX_ADDRESS_RANGE_LEN);

	return p - body;
}

static uint32_t get_payload_from_bind_transceiver_resp_body(char *body, smpp_bind_transceiver_resp_t *transceiver_resp)
{
	if (!body || !transceiver_resp) {
		LM_ERR("NULL params\n");
		return 0;
	}

	char *p = body;
	p += copy_var_str(p, transceiver_resp->system_id, MAX_SYSTEM_ID_LEN);

	return p - body;
}

uint32_t get_payload_from_submit_sm_body(char *body, smpp_submit_sm_t *submit_sm)
{
	if (!body || !submit_sm) {
		LM_ERR("NULL params\n");
		return 0;
	}

	char *p = body;
	p += copy_var_str(p, submit_sm->service_type, MAX_SERVICE_TYPE_LEN);
	p += copy_u8(p, submit_sm->source_addr_ton);
	p += copy_u8(p, submit_sm->source_addr_npi);
	p += copy_var_str(p, submit_sm->source_addr, MAX_ADDRESS_LEN);
	p += copy_u8(p, submit_sm->dest_addr_ton);
	p += copy_u8(p, submit_sm->dest_addr_npi);
	p += copy_var_str(p, submit_sm->destination_addr, MAX_ADDRESS_LEN);
	p += copy_u8(p, submit_sm->esm_class);
	p += copy_u8(p, submit_sm->protocol_id);
	p += copy_u8(p, submit_sm->protocol_flag);
	p += copy_var_str(p, submit_sm->schedule_delivery_time, MAX_SCHEDULE_DELIVERY_LEN);
	p += copy_var_str(p, submit_sm->validity_period, MAX_VALIDITY_PERIOD);
	p += copy_u8(p, submit_sm->registered_delivery);
	p += copy_u8(p, submit_sm->replace_if_present_flag);
	p += copy_u8(p, submit_sm->data_coding);
	p += copy_u8(p, submit_sm->sm_default_msg_id);
	p += copy_u8(p, submit_sm->sm_length);
	p += copy_fixed_str(p, submit_sm->short_message, submit_sm->sm_length);

	return p - body;
}

uint32_t get_payload_from_deliver_sm_resp_body(char *body, smpp_deliver_sm_resp_t *deliver_sm_resp)
{
	if (!body || !deliver_sm_resp) {
		LM_ERR("NULL params\n");
		return 0;
	}

	body[0] = deliver_sm_resp->message_id[0];
	return 1;
}

uint32_t get_payload_from_submit_sm_resp_body(char *body, smpp_submit_sm_resp_t *submit_sm_resp)
{
	if (!body || !submit_sm_resp) {
		LM_ERR("NULL params\n");
		return 0;
	}

	body[0] = submit_sm_resp->message_id[0];
	return 1;
}

static int build_bind_transceiver_request(smpp_bind_transceiver_req_t **preq, smpp_session_t *session)
{
	if (!preq || !session) {
		LM_ERR("NULL params\n");
		goto err;
	}

	/* request allocations */
	smpp_bind_transceiver_req_t *req = pkg_malloc(sizeof(*req));
	*preq = req;
	if (!req) {
		LM_ERR("malloc error for request\n");
		goto err;
	}

	smpp_header_t *header = pkg_malloc(sizeof(*header));
	if (!header) {
		LM_ERR("malloc error for header\n");
		goto header_err;
	}

	smpp_bind_transceiver_t *body = pkg_malloc(sizeof(*body));
	if (!body) {
		LM_ERR("malloc error for body\n");
		goto body_err;
	}

	req->payload.s = pkg_malloc(REQ_MAX_SZ(BIND_RECEIVER));
	if (!req->payload.s) {
		LM_ERR("malloc error for payload\n");
		goto payload_err;
	}

	req->header = header;
	req->body = body;

	/* copy body fields */
	smpp_bind_transceiver_t *transceiver = &session->bind.transceiver;
	copy_var_str(body->system_id, transceiver->system_id, MAX_SYSTEM_ID_LEN);
	copy_var_str(body->password, transceiver->password, MAX_PASSWORD_LEN);
	copy_var_str(body->system_type, transceiver->system_type, MAX_SYSTEM_TYPE_LEN);
	body->interface_version = transceiver->interface_version;
	body->addr_ton = transceiver->addr_ton;
	body->addr_npi = transceiver->addr_npi;
	copy_var_str(body->address_range, transceiver->address_range, MAX_ADDRESS_RANGE_LEN);

	uint32_t body_len = get_payload_from_bind_transceiver_body(req->payload.s + HEADER_SZ, transceiver);
	header->command_length = HEADER_SZ + body_len;
	header->command_id = BIND_TRANSCEIVER_CID;
	header->command_status = 0;
	header->sequence_number = increment_sequence_number(session);

	get_payload_from_header(req->payload.s, header);

	req->payload.len = header->command_length;

	return 0;

payload_err:
	pkg_free(body);
body_err:
	pkg_free(header);
header_err:
	pkg_free(req);
err:
	return -1;
}

static int build_bind_resp_request(smpp_bind_transceiver_resp_req_t **preq, uint32_t command_id,
		uint32_t command_status, uint32_t seq_no, char *system_id)
{
	if (!preq) {
		LM_ERR("NULL params\n");
		goto err;
	}

	/* request allocations */
	smpp_bind_transceiver_resp_req_t *req = pkg_malloc(sizeof(*req));
	*preq = req;
	if (!req) {
		LM_ERR("malloc error for request\n");
		goto err;
	}

	smpp_header_t *header = pkg_malloc(sizeof(*header));
	if (!header) {
		LM_ERR("malloc error for header\n");
		goto header_err;
	}

	smpp_bind_transceiver_resp_t *body = pkg_malloc(sizeof(*body));
	if (!body) {
		LM_ERR("malloc error for body\n");
		goto body_err;
	}

	req->payload.s = pkg_malloc(REQ_MAX_SZ(BIND_TRANSCEIVER_RESP));
	if (!req->payload.s) {
		LM_ERR("malloc error for payload\n");
		goto payload_err;
	}

	req->header = header;
	req->body = body;

	/* copy body fields */
	smpp_bind_transceiver_resp_t transceiver_resp;
	copy_var_str(transceiver_resp.system_id, system_id, MAX_SYSTEM_ID_LEN);

	uint32_t body_len = get_payload_from_bind_transceiver_resp_body(req->payload.s + HEADER_SZ, &transceiver_resp);
	header->command_length = HEADER_SZ + body_len;
	header->command_id = command_id;
	header->command_status = command_status;
	header->sequence_number = seq_no;

	get_payload_from_header(req->payload.s, header);

	req->payload.len = header->command_length;

	return 0;

payload_err:
	pkg_free(body);
body_err:
	pkg_free(header);
header_err:
	pkg_free(req);
err:
	return -1;
}

static int build_enquire_link_request(smpp_enquire_link_req_t **preq, smpp_session_t *session)
{
	if (!preq || !session) {
		LM_ERR("NULL param\n");
		goto err;
	}

	/* request allocations */
	smpp_enquire_link_req_t *req = pkg_malloc(sizeof(*req));
	*preq = req;
	if (!req) {
		LM_ERR("malloc error for request\n");
		goto err;
	}

	smpp_header_t *header = pkg_malloc(sizeof(*header));
	if (!header) {
		LM_ERR("malloc error for header\n");
		goto header_err;
	}

	req->payload.s = pkg_malloc(REQ_MAX_SZ(ENQUIRE_LINK));
	if (!req->payload.s) {
		LM_ERR("malloc error for payload\n");
		goto payload_err;
	}

	req->header = header;

	header->command_length = HEADER_SZ;
	header->command_id = ENQUIRE_LINK_CID;
	header->command_status = 0;
	header->sequence_number = increment_sequence_number(session);

	get_payload_from_header(req->payload.s, header);

	req->payload.len = header->command_length;

	return 0;

payload_err:
	pkg_free(header);
header_err:
	pkg_free(req);
err:
	return -1;
}

static int convert_utf16_to_ucs2(str *input, char *output)
{
	int i,hex_4grp,hex_val;
	char *p;

	hex_val = 0;
	p = output;
	for (i = 0; i < input->len;i++) {
		hex_4grp = hex2int(input->s[i]);
		if (i % 2 == 0) {
			hex_val = hex_4grp << 4;
		} else {
			hex_val |= hex_4grp;
			*p++ = hex_val;
		}
	}
	return input->len / 2;
}

static int convert_utf8_to_gsm7(str *input, char *output)
{
#define CASE_OUT_REPR(_c, _v) \
	case (_c): *o++ = (_v); break;
#define CASE_OUT_REPR_EN(_c, _v) \
	case (_c): *o++ = 0x1B; *o++ = (_v); break;

	int i;
	unsigned char c, c1, c2, *o;
	unsigned int t;
	o = (unsigned char *)output;
	/* GSM7 is definitely smaller than UTF8 */
	for (i = 0; i < input->len; i++) {
		c = input->s[i];
		if ((c & 0xF8) == 0xF0) {
			/* four bytes - no representation in GSM */
			*o++ = '?';
			i += 3; /* skip a total of 4 bytes */
			continue;
		}
		if ((c & 0xF0) == 0xE0) {
			/* three bytes */
			if (i + 2 >= input->len) {
				*o++ = '?';
				i += 2; /* terminate */
				continue;
			}
			c1 = input->s[++i];
			c2 = input->s[++i];
			t = ((c & 0x0F) << 12) | ((c1 & 0x3F) << 6) | (c2 & 0x3F);
			/* we only support the euro sign */
			if (t == 0x20AC) {
				*o++ = 0x1B;
				*o++ = 0x65;
			} else {
				*o++ = '?';
			}
			continue;
		}
		if ((c & 0xE0) == 0xC0) {
			/* two bytes */
			if (i + 1 >= input->len) {
				*o++ = '?';
				i++; /* terminate */
				continue;
			}
			c1 = input->s[++i];
			t = ((c & 0x1F) << 6) | (c1 & 0x3F);
		} else {
			t = c;
		}
		if ((t >= 0x20 /* ' ' */ && t <= 0x5A /* 'Z' */ &&
				t != 0x24 && t != 0x40) ||
			(t >= 0x61 /* 'z' */ && t <= 0x7A /* 'z' */)) {
			*o++ = t;
		} else {
			/* handle exceptions */
			switch (t) {
				/* newline */
				CASE_OUT_REPR(0x0A, 0x0A);
				CASE_OUT_REPR(0x0D, 0x0D);
				/* skipped characters */
				CASE_OUT_REPR(0x24, 0x02);
				CASE_OUT_REPR(0x40, 0x00);
				/* escaped */
				CASE_OUT_REPR_EN('^', 0x14);
				CASE_OUT_REPR_EN('{', 0x28);
				CASE_OUT_REPR_EN('}', 0x29);
				CASE_OUT_REPR_EN('\\', 0x2F);
				CASE_OUT_REPR_EN('[', 0x3C);
				CASE_OUT_REPR_EN('~', 0x3D);
				CASE_OUT_REPR_EN(']', 0x3E);
				CASE_OUT_REPR_EN('|', 0x40);
				CASE_OUT_REPR('_', 0x11);
				/* special */
				CASE_OUT_REPR(0xA1, 0x40);
				CASE_OUT_REPR(0xA3, 0x01);
				CASE_OUT_REPR(0xA4, 0x24);
				CASE_OUT_REPR(0xA5, 0x03);
				CASE_OUT_REPR(0xA7, 0x5F);
				CASE_OUT_REPR(0xBF, 0x60);
				CASE_OUT_REPR(0xC4, 0x5B);
				CASE_OUT_REPR(0xC5, 0x0E);
				CASE_OUT_REPR(0xC6, 0x1C);
				CASE_OUT_REPR(0xC7, 0x09);
				CASE_OUT_REPR(0xC9, 0x1F);
				CASE_OUT_REPR(0xD1, 0x5D);
				CASE_OUT_REPR(0xD6, 0x5C);
				CASE_OUT_REPR(0xD8, 0x0B);
				CASE_OUT_REPR(0xDC, 0x5E);
				CASE_OUT_REPR(0xDF, 0x1E);
				CASE_OUT_REPR(0xE0, 0x7F);
				CASE_OUT_REPR(0xE4, 0x7B);
				CASE_OUT_REPR(0xE5, 0x0F);
				CASE_OUT_REPR(0xE6, 0x1D);
				CASE_OUT_REPR(0xE7, 0x09);
				CASE_OUT_REPR(0xE8, 0x04);
				CASE_OUT_REPR(0xE9, 0x05);
				CASE_OUT_REPR(0xEC, 0x07);
				CASE_OUT_REPR(0xF1, 0x7D);
				CASE_OUT_REPR(0xF2, 0x08);
				CASE_OUT_REPR(0xF6, 0x7C);
				CASE_OUT_REPR(0xF8, 0x0C);
				CASE_OUT_REPR(0xF9, 0x06);
				CASE_OUT_REPR(0xFC, 0x7E);
				/* large */
				CASE_OUT_REPR(0x394, 0x10);
				CASE_OUT_REPR(0x3A6, 0x12);
				CASE_OUT_REPR(0x393, 0x13);
				CASE_OUT_REPR(0x39B, 0x14);
				CASE_OUT_REPR(0x3A9, 0x15);
				CASE_OUT_REPR(0x3A0, 0x16);
				CASE_OUT_REPR(0x3A8, 0x17);
				CASE_OUT_REPR(0x3A3, 0x18);
				CASE_OUT_REPR(0x398, 0x19);
				CASE_OUT_REPR(0x39E, 0x1A);
				default:
					/* unknown representation */
					*o++ = '?';
					break;
			}
		}
	}
	return (char *)o - output;
#undef CASE_OUT_REPR
#undef CASE_OUT_REPR_EN
}

static int convert_gsm7_to_utf8(unsigned char *input, int input_len, char *output)
{
	static unsigned int table_gsm7_to_utf8[] = {\
		  '@',  0xA3,   '$',  0xA5,  0xE8,  0xE9,  0xF9,  0xEC,
		 0xF2,  0xC7,  0x10,  0xd8,  0xF8,  0x13,  0xC5,  0xE5,
		0x394,   '_', 0x3A6, 0x393, 0x39B, 0x3A9, 0x3A0, 0x3A8,
		0x3A3, 0x398, 0x39E,   '?',  0xC6,  0xE6,  0xDF,  0xC9,
		  ' ',   '!',   '"',   '#',  0xA4,   '%',   '&',  '\'',
		  '(',   ')',   '*',   '+',   ',',   '-',   '.',   '/',
		  '0',   '1',   '2',   '3',   '4',   '5',   '6',   '7',
		  '8',   '9',   ':',   ';',   '<',   '=',   '>',   '?',
		  0xA1,  'A',   'B',   'C',   'D',   'E',   'F',   'G',
		  'H',   'I',   'J',   'K',   'L',   'M',   'N',   'O',
		  'P',   'Q',   'R',   'S',   'T',   'U',   'V',   'W',
		  'X',   'Y',   'Z',  0xC4,  0xD6,  0xD1,  0xDC,  0xA7,
		 0xBF,   'a',   'b',   'c',   'd',   'e',   'f',   'g',
		  'h',   'i',   'j',   'k',   'l',   'm',   'n',   'o',
		  'p',   'q',   'r',   's',   't',   'u',   'v',   'w',
		  'x',   'y',   'z',  0xE4,  0xF6,  0xF1,  0xFC,  0xE0,
	};
	char *p = output;
	int i, t;
	unsigned char c;
	for (i = 0; i < input_len; i++) {
		c = input[i];
		if (c == 0x1B) {
			/* escaped character - check the next char */
			switch (input[++i]) {
			case 0x0A:
				t = 0x0A; /* FF is a Page Break control, treated like LF */
				break;
			case 0x14:
				t = '^';
				break;
			case 0x28:
				t = '{';
				break;
			case 0x29:
				t = '}';
				break;
			case 0x2F:
				t = '\\';
				break;
			case 0x3C:
				t = '[';
				break;
			case 0x3D:
				t = '~';
				break;
			case 0x3E:
				t = ']';
				break;
			case 0x40:
				t = '|';
				break;
			case 0x65:
				t = 0x20AC;
				break;
			default:
				--i; /* consider the previous character */
			case 0x0D: /* CR2 - control character */
			case 0x1B: /* SS2 - Single shift Escape */
				t = '?'; /* unknown extended char */
				break;
			}
		} else if (c < 0x80)
			t = table_gsm7_to_utf8[c];
		else
			t = c;
		if (t > 0x7F) {
			if (t > 0x10000) {
				/* four bytes */
				*p++ = 0xF0 | ((t >> 18) & 0x07); /* 11110xxx */
				*p++ = 0x80 | ((t >> 12) & 0x3F); /* 10xxxxxx */
				*p++ = 0x80 | ((t >> 6) & 0x3F);  /* 10xxxxxx */
				*p++ = 0x80 | (t & 0x3F);         /* 10xxxxxx */
			} else if (t > 0x800) {
				/* three bytes */
				*p++ = 0xE0 | ((t >> 12) & 0x0F); /* 1110xxxx */
				*p++ = 0x80 | ((t >> 6) & 0x3F);  /* 10xxxxxx */
				*p++ = 0x80 | (t & 0x3F);         /* 10xxxxxx */
			} else {
				/* two bytes */
				*p++ = 0xC0 | ((t >> 6) & 0x1F);  /* 110xxxxx */
				*p++ = 0x80 | (t & 0x3F);         /* 10xxxxxx */
			}
		} else
			*p++ = (unsigned char )t;             /* 0xxxxxxx */
	}
	return p - output;
}

static int build_submit_or_deliver_request(smpp_submit_sm_req_t **preq,
	str *src, str *dst, str *message, int message_type,
	smpp_session_t *session,int *delivery_confirmation,
	int chunk_id, int total_chunks,uint8_t chunk_group_id)
{
	char *start;

	if (!preq || !src || !dst || !message) {
		LM_ERR("NULL params\n");
		goto err;
	}

	/* request allocations */
	smpp_submit_sm_req_t *req = pkg_malloc(sizeof(*req));
	*preq = req;
	if (!req) {
		LM_ERR("malloc error for request\n");
		goto err;
	}

	smpp_header_t *header = pkg_malloc(sizeof(*header));
	if (!header) {
		LM_ERR("malloc error for header\n");
		goto header_err;
	}

	smpp_submit_sm_t *body = pkg_malloc(sizeof(*body));
	if (!body) {
		LM_ERR("malloc error for body\n");
		goto body_err;
	}

	req->payload.s = pkg_malloc(REQ_MAX_SZ(SUBMIT_SM));
	if (!req->payload.s) {
		LM_ERR("malloc error for payload\n");
		goto payload_err;
	}

	req->header = header;
	req->body = body;

	memset(body, 0, sizeof(*body));
	body->source_addr_ton = session->source_addr_ton;
	body->source_addr_npi = session->source_addr_npi;
	strncpy(body->source_addr, src->s, src->len);
	body->dest_addr_ton = session->dest_addr_ton;
	body->dest_addr_npi = session->dest_addr_npi;
	strncpy(body->destination_addr, dst->s, dst->len);

	if (total_chunks > 1) {
		body->esm_class = 0x40;
		start = body->short_message;

		/* length of UDH = 5 bytes */
		*start++ = 5;
		/* concatenated chunks indicator */
		*start++ = 0;
		/* data length */
		*start++ = 3;
		/* chunk group identifier */
		*start++ = chunk_group_id;
		/* number of total chunks */
		*start++ = total_chunks;
		/* current chunk */
		*start++ = chunk_id;

		body->sm_length = 6;
	} else {
		start = body->short_message;
	}

	if (message_type == SMPP_CODING_DEFAULT) {
		body->data_coding = SMPP_CODING_DEFAULT;
		body->sm_length += convert_utf8_to_gsm7(message, start);
	} else {
		/* UTF-16 */
		body->data_coding = SMPP_CODING_UCS2;
		body->sm_length += convert_utf16_to_ucs2(message, start);
	}

	if (delivery_confirmation && *delivery_confirmation > 0)
		body->registered_delivery = 1;

	uint32_t body_len = get_payload_from_submit_sm_body(req->payload.s + HEADER_SZ, body);

	header->command_length = HEADER_SZ + body_len;
	if (session->session_type == SMPP_OUTBIND) // we are a SMSC
	    header->command_id = DELIVER_SM_CID;
	else // we are an ESME
	    header->command_id = SUBMIT_SM_CID;
	header->command_status = ESME_ROK;
	header->sequence_number = increment_sequence_number(session);

	get_payload_from_header(req->payload.s, header);

	req->payload.len = header->command_length;

	return 0;

payload_err:
	pkg_free(body);
body_err:
	pkg_free(header);
header_err:
	pkg_free(req);
err:
	return -1;
}

static int build_submit_or_deliver_resp_request(smpp_submit_sm_resp_req_t **preq, uint32_t command_id, uint32_t command_status, uint32_t sequence_number)
{
	if (!preq) {
		LM_ERR("NULL param\n");
		goto err;
	}

	/* request allocations */
	smpp_submit_sm_resp_req_t *req = pkg_malloc(sizeof(*req));
	*preq = req;
	if (!req) {
		LM_ERR("malloc error for request\n");
		goto err;
	}

	smpp_header_t *header = pkg_malloc(sizeof(*header));
	if (!header) {
		LM_ERR("malloc error for header\n");
		goto header_err;
	}

	smpp_submit_sm_resp_t *body = pkg_malloc(sizeof(*body));
	if (!body) {
		LM_ERR("malloc error for body\n");
		goto body_err;
	}

	req->payload.s = pkg_malloc(REQ_MAX_SZ(SUBMIT_SM_RESP));
	if (!req->payload.s) {
		LM_ERR("malloc error for payload\n");
		goto payload_err;
	}

	req->header = header;
	req->body = body;

	memset(body, 0, sizeof(*body));

	uint32_t body_len = get_payload_from_submit_sm_resp_body(req->payload.s + HEADER_SZ, body);
	header->command_length = HEADER_SZ + body_len;
	header->command_id = command_id;
	header->command_status = command_status;
	header->sequence_number = sequence_number;

	get_payload_from_header(req->payload.s, header);

	req->payload.len = header->command_length;

	return 0;

payload_err:
	pkg_free(body);
body_err:
	pkg_free(header);
header_err:
	pkg_free(req);
err:
	return -1;
}


static uint32_t increment_sequence_number(smpp_session_t *session)
{
	uint32_t seq_no;
	lock_get(&session->sequence_number_lock);
	seq_no = session->sequence_number++;
	lock_release(&session->sequence_number_lock);
	return seq_no;
}

static uint8_t increment_chunk_identifier(smpp_session_t *session)
{
	uint8_t seq_no;

	lock_get(&session->sequence_number_lock);
	seq_no = session->chunk_identifier++;
	lock_release(&session->sequence_number_lock);

	return seq_no;
}

int send_outbind(smpp_session_t *session)
{
	LM_INFO("sending outbind to esme \"%s\"\n", session->bind.outbind.system_id);
	return -1;
}

static struct tcp_connection *smpp_connect(smpp_session_t *session, int *fd)
{
	union sockaddr_union to;
	union sockaddr_union server;
	struct socket_info *send_socket;

	if (init_su(&to, &session->ip, session->port)) {
		LM_ERR("error creating su from ipaddr and port\n");
		return NULL;
	}
	if (init_su(&server, &session->ip, session->port)) {
		LM_ERR("error creating su from ipaddr and port\n");
		return NULL;
	}
	send_socket = get_send_socket(NULL, &to, PROTO_SMPP);
	if (!send_socket) {
		LM_ERR("error getting send socket\n");
		return NULL;
	}
	return smpp_sync_connect(send_socket, &server, fd);
}

static int smpp_send_msg(smpp_session_t *smsc, str *buffer)
{
	int ret, fd;
	struct tcp_connection *conn;
	int retry = 1;
	/* first try to acquire the connection */

	/* TBD - handle conn not found here = reconnect ? */
retry:
	ret = tcp_conn_get(smsc->conn_id, &smsc->ip, smsc->port, PROTO_SMPP,
		NULL, &conn, &fd);
	if (ret <= 0) {
		if (retry == 0) {
			LM_ERR("cannot fetch connection for %.*s (%d)\n",
					smsc->name.len, smsc->name.s, ret);
			return -1;
		}
		if (bind_session(smsc) < 0) {
			LM_ERR("could not re-bind connectionfor %.*s\n",
					smsc->name.len, smsc->name.s);
			return -1;
		}
		retry = 0;
		goto retry;
	}
	/* update connection in case it has changed */
	ret = tsend_stream(fd, buffer->s, buffer->len, smpp_send_timeout);
	tcp_conn_set_lifetime(conn, tcp_con_lifetime);
	if (ret < 0) {
		LM_ERR("failed to send data!\n");
		conn->state=S_CONN_BAD;
	}
	if (conn->proc_id != process_no)
		close(fd);
	tcp_conn_release(conn, 0);
	return ret;
}


static int send_bind(smpp_session_t *session)
{
	int fd, n = -1;
	struct tcp_connection *conn;
	smpp_bind_transceiver_req_t *req = NULL;

	if (!session) {
		LM_ERR("NULL param\n");
		return -1;
	}

	LM_INFO("binding session with system_id \"%s\"\n", session->bind.transceiver.system_id);

	if (build_bind_transceiver_request(&req, session)) {
		LM_ERR("error creating request\n");
		return -1;
	}
	conn = smpp_connect(session, &fd);
	if (!conn) {
		LM_ERR("cannot create a TCP connection!\n");
		goto free_req;
	}

	session->conn_id = conn->id;
	conn->proto_data = session;
	n = tsend_stream(fd, req->payload.s, req->payload.len, smpp_send_timeout);
	LM_DBG("sent %d bytes on smpp connection %p\n", n, conn);
free_req:
	free_smpp_msg(req);
	return n;
}

int bind_session(smpp_session_t *session)
{
	int ret = (session->session_type == SMPP_OUTBIND)?
		send_outbind(session):
		send_bind(session);
	if (ret < 0) {
		LM_ERR("failed to bind session %.*s\n",
				session->name.len, session->name.s);
		return ret;
	}
	LM_DBG("succsessfully bound %.*s\n",
			session->name.len, session->name.s);
	return 0;
}

void smpp_bind_sessions(struct list_head *list)
{
	struct list_head *l;
	smpp_session_t *session;

	list_for_each(l, list) {
		session = list_entry(l, smpp_session_t, list);
		bind_session(session);
	}
}

void rpc_bind_sessions(int sender_id, void *param)
{
	if (load_smpp_sessions_from_db(g_sessions) < 0) {
		LM_INFO("cannot load smpp sessions!\n");
		return;
	}
	smpp_bind_sessions(g_sessions);
}


void enquire_link(unsigned int ticks, void *params)
{
	struct list_head *l;
	smpp_session_t *session;

	lock_start_read(smpp_lock);

	list_for_each(l, g_sessions) {
		session = list_entry(l, smpp_session_t, list);
	    send_enquire_link_request(session);
	}
	lock_stop_read(smpp_lock);
}


static int smpp_parse_header(smpp_header_t *header, char *buffer)
{
	if (!header || !buffer) {
		LM_ERR("NULL params");
		return -1;
	}

	uint32_t *p = (uint32_t*)buffer;

	header->command_length = ntohl(*p++);
	header->command_id = ntohl(*p++);
	header->command_status = ntohl(*p++);
	header->sequence_number = ntohl(*p++);
	return 0;
}

static void parse_submit_or_deliver_body(smpp_submit_sm_t *body, smpp_header_t *header, char *buffer)
{
	if (!body || !header || !buffer) {
		LM_ERR("NULL params\n");
		return;
	}

	char *p = buffer;
	p += copy_var_str(body->service_type, p, MAX_SERVICE_TYPE_LEN);
	body->source_addr_ton = *p++;
	body->source_addr_npi = *p++;
	p += copy_var_str(body->source_addr, p, MAX_ADDRESS_LEN);
	body->dest_addr_ton = *p++;
	body->dest_addr_npi = *p++;
	p += copy_var_str(body->destination_addr, p, MAX_ADDRESS_LEN);
	body->esm_class = *p++;
	body->protocol_id = *p++;
	body->protocol_flag = *p++;
	p += copy_var_str(body->schedule_delivery_time, p, MAX_SCHEDULE_DELIVERY_LEN);
	p += copy_var_str(body->validity_period, p, MAX_VALIDITY_PERIOD);
	body->registered_delivery = *p++;
	body->replace_if_present_flag = *p++;
	body->data_coding = *p++;
	body->sm_default_msg_id = *p++;
	body->sm_length = *p++;
	copy_fixed_str(body->short_message, p, body->sm_length);
}

void parse_bind_receiver_body(smpp_bind_receiver_t *body, smpp_header_t *header, char *buffer)
{
	if (!body || !header || !buffer) {
		LM_ERR("NULL params\n");
		return;
	}

	char *p = buffer;
	p += copy_var_str(body->system_id, p, MAX_SYSTEM_ID_LEN);
	p += copy_var_str(body->password, p, MAX_PASSWORD_LEN);
	p += copy_var_str(body->system_type, p, MAX_SYSTEM_TYPE_LEN);
	body->interface_version = *p++;
	body->addr_ton = *p++;
	body->addr_npi = *p++;
	p += copy_var_str(body->address_range, p, MAX_ADDRESS_RANGE_LEN);
}

void parse_bind_receiver_resp_body(smpp_bind_receiver_resp_t *body, smpp_header_t *header, char *buffer)
{
	if (!body || !header || !buffer) {
		LM_ERR("NULL params\n");
		return;
	}

	copy_var_str(body->system_id, buffer, MAX_SYSTEM_ID_LEN);
}

void parse_bind_transmitter_body(smpp_bind_transmitter_t *body, smpp_header_t *header, char *buffer)
{
	parse_bind_receiver_body((smpp_bind_receiver_t*)body, header, buffer);
}

void parse_bind_transmitter_resp_body(smpp_bind_transmitter_resp_t *body, smpp_header_t *header, char *buffer)
{
	parse_bind_receiver_resp_body((smpp_bind_receiver_resp_t*)body, header, buffer);
}

void parse_bind_transceiver_body(smpp_bind_transceiver_t *body, smpp_header_t *header, char *buffer)
{
	parse_bind_receiver_body((smpp_bind_receiver_t*)body, header, buffer);
}

void parse_bind_transceiver_resp_body(smpp_bind_transceiver_resp_t *body, smpp_header_t *header, char *buffer)
{
	parse_bind_receiver_resp_body((smpp_bind_receiver_resp_t*)body, header, buffer);
}

void parse_submit_or_deliver_resp_body(smpp_submit_sm_resp_t *body, smpp_header_t *header, char *buffer)
{
	if (!body || !header || !buffer) {
		LM_ERR("NULL params\n");
		return;
	}

	copy_var_str(body->message_id, buffer, MAX_MESSAGE_ID);
}

void send_submit_or_deliver_resp(smpp_submit_sm_req_t *req, smpp_session_t *session)
{
	if (!req || !session) {
		LM_ERR("NULL params\n");
		return;
	}

	smpp_submit_sm_resp_req_t *resp;
	uint32_t command_status = ESME_ROK;
	uint32_t seq_no = req->header->sequence_number;
	uint32_t command_id = req->header->command_id + 0x80000000; // transform command to resp command
	if (build_submit_or_deliver_resp_request(&resp, command_id, command_status, seq_no)) {
		LM_ERR("error creating request\n");
		return;
	}

	smpp_send_msg(session, &resp->payload);
	free_smpp_msg(resp);
}

uint32_t check_bind_session(smpp_bind_transceiver_t *body, smpp_session_t *session)
{
	if (memcmp(session->bind.transceiver.system_id, body->system_id, MAX_SYSTEM_ID_LEN) != 0) {
		LM_WARN("wrong system id when trying to bind \"%.*s\"\n", MAX_SYSTEM_ID_LEN, body->system_id);
		return ESME_RBINDFAIL;
	}

	if (memcmp(session->bind.transceiver.password, body->password, MAX_PASSWORD_LEN) != 0) {
		LM_WARN("wrong password when trying to bind \"%.*s\"\n", MAX_SYSTEM_ID_LEN, body->system_id);
		return ESME_RBINDFAIL;
	}
	if (session->session_type != SMPP_OUTBIND) {
		LM_WARN("cannot receive bind command on ESME type interface for \"%.*s\"\n",
				MAX_SYSTEM_ID_LEN, body->system_id);
		return ESME_RBINDFAIL;
	}
	LM_INFO("successfully found \"%.*s\"\n", MAX_SYSTEM_ID_LEN, body->system_id);
	return ESME_ROK;
}

void send_bind_resp(smpp_header_t *header, smpp_bind_transceiver_t *body, uint32_t command_status,
		smpp_session_t *session)
{
	if (!header || !body || !session) {
		LM_ERR("NULL params\n");
		return;
	}

	smpp_bind_transceiver_resp_req_t *req;
	uint32_t seq_no = header->sequence_number;
	uint32_t command_id = header->command_id + 0x80000000; // transform command to resp command
	if (build_bind_resp_request(&req, command_id, command_status, seq_no, body->system_id)) {
		LM_ERR("error creating request\n");
		return;
	}

	smpp_send_msg(session, &req->payload);
	free_smpp_msg(req);
}

void handle_generic_nack_cmd(smpp_header_t *header, char *buffer, smpp_session_t *session)
{
	LM_DBG("Received generic_nack command\n");
}

void handle_bind_receiver_cmd(smpp_header_t *header, char *buffer, smpp_session_t *session)
{
	LM_DBG("Received bind_receiver command\n");
	if (!header || !buffer || !session) {
		LM_ERR("NULL params\n");
		return;
	}

	smpp_bind_receiver_t body;
	memset(&body, 0, sizeof(body));
	parse_bind_receiver_body(&body, header, buffer);
	uint32_t command_status = check_bind_session(&body, session);
	send_bind_resp(header, &body, command_status, session);
}

void handle_bind_receiver_resp_cmd(smpp_header_t *header, char *buffer, smpp_session_t *session)
{
	LM_DBG("Received bind_receiver_resp command\n");
	if (!header || !buffer || !session) {
		LM_ERR("NULL params\n");
		return;
	}
}

void handle_bind_transmitter_cmd(smpp_header_t *header, char *buffer, smpp_session_t *session)
{
	LM_DBG("Received bind_transmitter command\n");
	if (!header || !buffer || !session) {
		LM_ERR("NULL params\n");
		return;
	}

	smpp_bind_transmitter_t body;
	memset(&body, 0, sizeof(body));
	parse_bind_transmitter_body(&body, header, buffer);
	uint32_t command_status = check_bind_session(&body, session);
	send_bind_resp(header, &body, command_status, session);
}

void handle_bind_transmitter_resp_cmd(smpp_header_t *header, char *buffer, smpp_session_t *session)
{
	LM_DBG("Received bind_transmitter_resp command\n");
	if (!header || !buffer || !session) {
		LM_ERR("NULL params\n");
		return;
	}
}

void handle_submit_or_deliver_cmd(smpp_header_t *header, char *buffer,
		smpp_session_t *session, struct receive_info *rcv)
{
	if (header->command_status) {
		LM_ERR("Error in submit_sm %08x\n", header->command_status);
		return;
	}

	smpp_submit_sm_t body;
	memset(&body, 0, sizeof(body));
	parse_submit_or_deliver_body(&body, header, buffer);
	LM_DBG("Received SMPP message\n"
			"FROM:\t%02x %02x %s\n"
			"TO:\t%02x %02x %s\nLEN:\t%d\n%.*s\n",
			body.source_addr_ton, body.source_addr_npi, body.source_addr,
			body.dest_addr_ton, body.dest_addr_npi, body.destination_addr,
			body.sm_length,
			body.sm_length, body.short_message);
	smpp_submit_sm_req_t req;
	req.header = header;
	req.body = &body;
	req.optionals = NULL;
	send_submit_or_deliver_resp(&req, session);
	recv_smpp_msg(header, &body, session, rcv);
}

void handle_submit_or_deliver_resp_cmd(smpp_header_t *header, char *buffer,
		smpp_session_t *session, struct receive_info *rcv)
{
	if (header->command_status) {
		LM_ERR("Error in submit_sm_resp %08x\n", header->command_status);
		return;
	}

	smpp_submit_sm_resp_t body;
	memset(&body, 0, sizeof(body));
	parse_submit_or_deliver_resp_body(&body, header, buffer);
	LM_INFO("Successfully sent message \"%s\"\n", body.message_id);
}

void handle_submit_sm_cmd(smpp_header_t *header, char *buffer,
		smpp_session_t *session, struct receive_info *rcv)
{
	LM_DBG("Received submit_sm command\n");
	if (!header || !buffer || !session) {
		LM_ERR("NULL params\n");
		return;
	}

	handle_submit_or_deliver_cmd(header, buffer, session, rcv);
}

static void handle_submit_sm_resp_cmd(smpp_header_t *header, char *buffer,
		smpp_session_t *session, struct receive_info *rcv)
{
	LM_DBG("Received submit_sm_resp command\n");
	if (!header || !buffer || !session) {
		LM_ERR("NULL params\n");
		return;
	}
	handle_submit_or_deliver_resp_cmd(header, buffer, session, rcv);
}

static void handle_deliver_sm_cmd(smpp_header_t *header, char *buffer,
		smpp_session_t *session, struct receive_info *rcv)
{
	LM_DBG("Received deliver_sm command\n");
	if (!header || !buffer || !session) {
		LM_ERR("NULL params\n");
		return;
	}

	handle_submit_or_deliver_cmd(header, buffer, session, rcv);
}

static void handle_deliver_sm_resp_cmd(smpp_header_t *header, char *buffer,
		smpp_session_t *session, struct receive_info *rcv)
{
	LM_DBG("Received deliver_sm_resp command\n");
	if (!header || !buffer || !session) {
		LM_ERR("NULL params\n");
		return;
	}
	handle_submit_or_deliver_resp_cmd(header, buffer, session, rcv);
}

static void handle_unbind_resp_cmd(smpp_header_t *header, char *buffer,
		smpp_session_t *session)
{
	LM_DBG("Received unbind_resp command\n");
}

static void handle_unbind_cmd(smpp_header_t *header, char *buffer,
		smpp_session_t *session)
{
	LM_DBG("Received unbind command\n");
}

static void handle_bind_transceiver_cmd(smpp_header_t *header, char *buffer,
		smpp_session_t *session)
{
	LM_DBG("Received bind_transceiver command\n");
	if (!header || !buffer || !session) {
		LM_ERR("NULL params\n");
		return;
	}
	smpp_bind_transceiver_t body;
	memset(&body, 0, sizeof(body));
	parse_bind_transceiver_body(&body, header, buffer);
	uint32_t command_status = check_bind_session(&body, session);
	send_bind_resp(header, &body, command_status, session);
}

static void handle_bind_transceiver_resp_cmd(smpp_header_t *header,
		char *buffer, smpp_session_t *session)
{
	if (!header || !buffer || !session) {
		LM_ERR("NULL params\n");
		return;
	}
	LM_DBG("Received bind_transceiver_resp command\n");
	if (header->command_status) {
		LM_ERR("Error in bind_transceiver_resp %08x\n", header->command_status);
		return;
	}
	smpp_bind_transceiver_resp_t body;
	memset(&body, 0, sizeof(body));
	parse_bind_transceiver_resp_body(&body, header, buffer);
	LM_INFO("Successfully bound transceiver \"%s\"\n", body.system_id);
}

static void handle_data_sm_cmd(smpp_header_t *header,
		char *buffer, smpp_session_t *session)
{
	LM_DBG("Received data_sm command\n");
}

static void handle_data_sm_resp_cmd(smpp_header_t *header,
		char *buffer, smpp_session_t *session)
{
	LM_DBG("Received data_sm_resp command\n");
}

static void handle_enquire_link_cmd(smpp_header_t *header,
		char *buffer, smpp_session_t *session)
{
	LM_DBG("Received enquire_link command\n");
}

static void handle_enquire_link_resp_cmd(smpp_header_t *header,
		char *buffer, smpp_session_t *session)
{
	LM_DBG("Received enquire_link_resp command\n");
}

void handle_smpp_msg(char *buffer, smpp_session_t *session, struct receive_info *rcv)
{
	smpp_header_t header;
	if (smpp_parse_header(&header, buffer) < 0) {
		LM_ERR("could not parse SMPP header!\n");
		return;
	}
	buffer += HEADER_SZ;

	LM_DBG("Received SMPP command %08x\n", header.command_id);

	switch (header.command_id) {
		case GENERIC_NACK_CID:
			handle_generic_nack_cmd(&header, buffer, session);
			break;
		case BIND_RECEIVER_CID:
			handle_bind_receiver_cmd(&header, buffer, session);
			break;
		case BIND_RECEIVER_RESP_CID:
			handle_bind_receiver_resp_cmd(&header, buffer, session);
			break;
		case BIND_TRANSMITTER_RESP_CID:
			handle_bind_transmitter_resp_cmd(&header, buffer, session);
			break;
		case BIND_TRANSMITTER_CID:
			handle_bind_transmitter_cmd(&header, buffer, session);
			break;
		case SUBMIT_SM_CID:
			handle_submit_sm_cmd(&header, buffer, session, rcv);
			break;
		case SUBMIT_SM_RESP_CID:
			handle_submit_sm_resp_cmd(&header, buffer, session, rcv);
			break;
		case DELIVER_SM_CID:
			handle_deliver_sm_cmd(&header, buffer, session, rcv);
			break;
		case DELIVER_SM_RESP_CID:
			handle_deliver_sm_resp_cmd(&header, buffer, session, rcv);
			break;
		case UNBIND_CID:
			handle_unbind_cmd(&header, buffer, session);
			break;
		case UNBIND_RESP_CID:
			handle_unbind_resp_cmd(&header, buffer, session);
			break;
		case BIND_TRANSCEIVER_CID:
			handle_bind_transceiver_cmd(&header, buffer, session);
			break;
		case BIND_TRANSCEIVER_RESP_CID:
			handle_bind_transceiver_resp_cmd(&header, buffer, session);
			break;
		case DATA_SM_CID:
			handle_data_sm_cmd(&header, buffer, session);
			break;
		case DATA_SM_RESP_CID:
			handle_data_sm_resp_cmd(&header, buffer, session);
			break;
		case ENQUIRE_LINK_CID:
			handle_enquire_link_cmd(&header, buffer, session);
			break;
		case ENQUIRE_LINK_RESP_CID:
			handle_enquire_link_resp_cmd(&header, buffer, session);
			break;
		default:
			LM_WARN("Unknown or unsupported command received %08X\n", header.command_id);
	}
}


int send_submit_or_deliver_request(str *msg, int msg_type, str *src, str *dst,
		smpp_session_t *session, int *delivery_confirmation)
{
	smpp_submit_sm_req_t *req;
	int ret = 0,chunks_no = 0,i,max_chunk_bytes;
	uint8_t chunk_group_id;
	str chunked_msg;

	LM_DBG("sending submit_sm\n");
	LM_DBG("FROM: %.*s\n", src->len, src->s);
	LM_DBG("TO: %.*s\n", dst->len, dst->s);
	LM_DBG("MESSAGE: %.*s type = %d\n", msg->len, msg->s,msg_type);

	if ( (msg_type == SMPP_CODING_DEFAULT && msg->len > MAX_SMS_CHARACTERS) ||
	(msg_type == SMPP_CODING_UCS2 && msg->len > MAX_SMS_CHARACTERS * 2) ) {
		/* need to split into multiple chunks */

		/* for DEFAULT, we have 140 limit,
		for UCS2, we have a 70 limit, but with HEX encoding
		we get to 70 * 4 characters */

		/* for both, since again UCS2 is HEX encoded */
		if (msg_type == SMPP_CODING_DEFAULT)
			max_chunk_bytes = 134;
		else
			/* 67 UTF-16 characters times 4 for the HEX encoding */
			max_chunk_bytes = 67 * 4;

		if (msg->len % max_chunk_bytes > 0)
			chunks_no = msg->len / max_chunk_bytes + 1;
		else
			chunks_no = msg->len / max_chunk_bytes;

		LM_DBG("We need %d chunks to send %d characters of type %d\n",chunks_no,msg->len,msg_type);

		chunk_group_id = increment_chunk_identifier(session);
		for (i=0; i<chunks_no;i++) {
			chunked_msg.s = msg->s + i * max_chunk_bytes;

			if (msg->len % max_chunk_bytes == 0)
				chunked_msg.len = max_chunk_bytes;
			else {
				if (i == chunks_no - 1)
					chunked_msg.len = msg->len % max_chunk_bytes;
				else
					chunked_msg.len = max_chunk_bytes;
			}

			LM_DBG("sending type %d [%.*s] with len %d \n",
			msg_type,chunked_msg.len,chunked_msg.s,chunked_msg.len);

			if (build_submit_or_deliver_request(&req, src, dst,
			&chunked_msg, msg_type, session,delivery_confirmation,
			i+1,chunks_no,chunk_group_id)) {
				LM_ERR("error creating submit_sm request\n");
				return -1;
			}

			ret = smpp_send_msg(session, &req->payload);
			if (ret <= 0) {
				LM_ERR("Failed to send chunk %d \n",i+1);
				goto free_req;
			}

			free_smpp_msg(req);
		}
		return ret;
	} else {
		if (build_submit_or_deliver_request(&req, src, dst, msg, msg_type,
		session,delivery_confirmation,1,1,0)) {
			LM_ERR("error creating submit_sm request\n");
			return -1;
		}

		ret = smpp_send_msg(session, &req->payload);
	}

free_req:
	free_smpp_msg(req);
	return ret;
}

static void send_enquire_link_request(smpp_session_t *session)
{
	smpp_enquire_link_req_t *req;
	if (build_enquire_link_request(&req, session)) {
		LM_ERR("error creating enquire_link_sm request\n");
		return;
	}

	/* TODO: fix this */
	if (!session)
		session = list_entry(g_sessions->next, smpp_session_t, list);

	smpp_send_msg(session, &req->payload);
	pkg_free(req->header);
	pkg_free(req->payload.s);
	pkg_free(req);
}

static int smpp_build_uri(char *user, struct ip_addr *ip, int port, str *uri)
{
	str sip;
	str sport;
	str suser;
	str euser;
	int len;
	char *p;

	init_str(&suser, user);
	sip.s = ip_addr2a(ip);
	sip.len = strlen(sip.s);
	sport.s = int2str(port, &sport.len);

	len = 4 /* 'sip:' */ + suser.len * 3 + 1 /* user encoded */ + 1 /* '@' */ +
		sip.len + /* ':' */ + sport.len;
	p = pkg_malloc(len);
	if (!p) {
		LM_ERR("cannot allocate %d bytes for URI sip:%s@%s:%d bytes\n",
				len, user, sip.s, port);
		return -1;
	}
	uri->s = p;
	memcpy(p, "sip:", 4);
	p += 4;

	euser.s = p;
	euser.len = len - 4;
	escape_user(&suser, &euser);
	p += euser.len;

	memcpy(p, "@", 1);
	p += 1;

	memcpy(p, sip.s, sip.len);
	p += sip.len;

	memcpy(p, ":", 1);
	p += 1;

	memcpy(p, sport.s, sport.len);
	p += sport.len;

	uri->len = p - uri->s;

	return 0;
}

static int recv_smpp_msg(smpp_header_t *header, smpp_deliver_sm_t *body,
		smpp_session_t *session, struct receive_info *rcv)
{
	static str msg_type = str_init("MESSAGE");
	static char sms_body[2*MAX_SMS_CHARACTERS];

	str hdr;
	str src;
	str dst;
	str body_str;

	if (smpp_build_uri(body->source_addr, &rcv->src_ip, rcv->src_port, &src) < 0) {
		LM_ERR("could not build received info for sip!\n");
		return -1;
	}

	if (smpp_build_uri(body->destination_addr, &rcv->dst_ip, rcv->dst_port, &dst) < 0) {
		LM_ERR("could not build destination info for sip!\n");
		pkg_free(src.s);
		return -1;
	}

	if (body->data_coding == SMPP_CODING_UCS2)
		init_str(&hdr, "Content-Type:text/plain; charset=UTF-16\r\n");
	else
		init_str(&hdr, "Content-Type:text/plain\r\n");

	if (body->data_coding == SMPP_CODING_UCS2) {
		memset(sms_body,0,2*MAX_SMS_CHARACTERS);
		body_str.len = string2hex((unsigned char *)body->short_message,
		body->sm_length,sms_body);

		body_str.s = sms_body;
	} else {
		body_str.len = convert_gsm7_to_utf8((unsigned char *)body->short_message,
				body->sm_length,sms_body);
		body_str.s = sms_body;
	}

	tmb.t_request(&msg_type, /* Type of the message */
		      &dst,          /* Request-URI */
		      &dst,          /* To */
		      &src,          /* From */
		      &hdr,          /* Optional headers including CRLF */
		      &body_str,     /* Message body */
		      &smpp_outbound_uri,
		      /* outbound uri */
		      NULL,
		      NULL,
		      NULL
		     );
	pkg_free(src.s);
	pkg_free(dst.s);
	return 0;
}

int smpp_sessions_init(void)
{
	g_sessions = shm_malloc(sizeof(*g_sessions));
	if (!g_sessions) {
		LM_CRIT("failed to allocate shared memory for sessions pointer\n");
		return -1;
	}
	smpp_lock = lock_init_rw();
	if (!smpp_lock) {
		LM_CRIT("cannot allocate shared memory fir smpp_lock\n");
		return -1;
	}
	return 0;
}

smpp_session_t *smpp_session_new(str *name, struct ip_addr *ip, int port,
		str *system_id, str *password, str *system_type, int src_addr_ton,
		int src_addr_npi, int dst_addr_ton, int dst_addr_npi, int stype)
{
	smpp_session_t *session;

	session = shm_malloc(sizeof(smpp_session_t) + name->len);
	if (!session) {
		LM_ERR("no more shm memory!\n");
		return NULL;
	}

	memset(session, 0, sizeof(smpp_session_t));
	session->name.s = (char *)session + sizeof(smpp_session_t);

	session->bind.transceiver.interface_version = SMPP_VERSION;
	lock_init(&session->sequence_number_lock);
	session->session_status = SMPP_UNKNOWN;
	session->sequence_number = 0;

	if (system_id->len > MAX_SYSTEM_ID_LEN) {
		LM_INFO("[%.*s] system id %.*s is too long, trimming it to %d\n",
				name->len, name->s, system_id->len, system_id->s,
				MAX_SYSTEM_ID_LEN);
		system_id->len = MAX_SYSTEM_ID_LEN;
	}
	if (password->len > MAX_PASSWORD_LEN) {
		LM_INFO("[%.*s] password for %.*s is too long, trimming it to %d\n",
				name->len, name->s, system_id->len, system_id->s,
				MAX_PASSWORD_LEN);
		password->len = MAX_PASSWORD_LEN;
	}
	if (system_type->len > MAX_SYSTEM_TYPE_LEN) {
		LM_INFO("[%.*s] system type %.*s of %.*s is too long, trimming it to %d\n",
				name->len, name->s, system_type->len, system_type->s,
				system_id->len, system_id->s, MAX_SYSTEM_TYPE_LEN);
		system_type->len = MAX_SYSTEM_TYPE_LEN;
	}

	session->name.len = name->len;
	memcpy(session->name.s, name->s, name->len);
	memcpy(&session->ip, ip, sizeof(struct ip_addr));
	memcpy(session->bind.transceiver.system_id, system_id->s, system_id->len);
	memcpy(session->bind.transceiver.password, password->s, password->len);
	memcpy(session->bind.transceiver.system_type, system_type->s, system_type->len);

	session->port = port;
	session->bind.transceiver.addr_ton = src_addr_ton;
	session->bind.transceiver.addr_npi = src_addr_npi;
	session->source_addr_ton = src_addr_ton;
	session->source_addr_npi = src_addr_npi;
	session->dest_addr_ton = dst_addr_ton;
	session->dest_addr_npi = dst_addr_npi;
	session->session_type = stype;

	LM_DBG("Added %.*s SMSC %p\n", name->len, name->s, session);

	return session;
}


smpp_session_t *smpp_session_get(str *name)
{
	struct list_head *l;
	smpp_session_t *session = NULL;

	lock_start_read(smpp_lock);

	list_for_each(l, g_sessions) {
		session = list_entry(l, smpp_session_t, list);
		if (session->name.len == name->len &&
				memcmp(session->name.s, name->s, name->len) == 0)
			goto found;
	}
	session = NULL;
found:
	lock_stop_read(smpp_lock);
	return session;
}
