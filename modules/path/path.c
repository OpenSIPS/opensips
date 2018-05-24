/*
 * Path handling for intermediate proxies.
 *
 * Copyright (C) 2006 Inode GmbH (Andreas Granig <andreas.granig@inode.info>)
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


#include <string.h>
#include <stdio.h>

#include "../../mem/mem.h"
#include "../../data_lump.h"
#include "../../parser/parse_param.h"
#include "../../strcommon.h"
#include "../../ut.h"

#include "path.h"
#include "path_mod.h"

#define PATH_PREFIX		"Path: <sip:"
#define PATH_PREFIX_LEN		(sizeof(PATH_PREFIX)-1)

#define PATH_LR_PARAM		";lr"
#define PATH_LR_PARAM_LEN	(sizeof(PATH_LR_PARAM)-1)

#define PATH_RC_PARAM		";received="
#define PATH_RC_PARAM_LEN	(sizeof(PATH_RC_PARAM)-1)

#define PATH_TRANS_PARAM	";transport="
#define PATH_TRANS_PARAM_LEN	(sizeof(PATH_TRANS_PARAM)-1)

#define PATH_ESC_TRANS_PARAM	"\%3btransport\%3d"
#define PATH_ESC_TRANS_PARAM_LEN	(sizeof(PATH_ESC_TRANS_PARAM)-1)

#define	PATH_CRLF		">\r\n"
#define PATH_CRLF_LEN		(sizeof(PATH_CRLF)-1)

#define PATH_R2 ";r2=on"
#define PATH_R2_LEN (sizeof(PATH_R2)-1)

#define INBOUND  1  /* Insert inbound Path */
#define OUTBOUND 0  /* Insert outbound Path */

static int build_path(struct sip_msg* _m, struct lump* l, struct lump* l2,
					str* user, int recv, int _inbound)
{
	char *prefix, *suffix, *crlf, *r2;
	int prefix_len, suffix_len;
	str rcv_addr = {0, 0};
	char *src_ip;

	prefix = suffix = crlf = r2 = 0;

	prefix_len = PATH_PREFIX_LEN + (user->len ? (user->len+1) : 0);
	prefix = pkg_malloc(prefix_len);
	if (!prefix) {
		LM_ERR("no pkg memory left for prefix\n");
		goto out1;
	}
	memcpy(prefix, PATH_PREFIX, PATH_PREFIX_LEN);
	if (user->len) {
		memcpy(prefix + PATH_PREFIX_LEN, user->s, user->len);
		memcpy(prefix + prefix_len - 1, "@", 1);
	}

	suffix_len = PATH_LR_PARAM_LEN + (recv ? PATH_RC_PARAM_LEN : 0);
	suffix = pkg_malloc(suffix_len);
	if (!suffix) {
		LM_ERR("no pkg memory left for suffix\n");
		goto out1;
	}
	memcpy(suffix, PATH_LR_PARAM, PATH_LR_PARAM_LEN);
	if(recv)
		memcpy(suffix+PATH_LR_PARAM_LEN, PATH_RC_PARAM, PATH_RC_PARAM_LEN);

	crlf = pkg_malloc(PATH_CRLF_LEN);
	if (!crlf) {
		LM_ERR("no pkg memory left for crlf\n");
		goto out1;
	}
	memcpy(crlf, PATH_CRLF, PATH_CRLF_LEN);

	r2 = pkg_malloc(PATH_R2_LEN);
	if (!r2) {
		LM_ERR("no pkg memory left for r2\n");
		goto out1;
	}
	memcpy(r2, PATH_R2, PATH_R2_LEN);

	l = insert_new_lump_after(l, prefix, prefix_len, 0);
	if (!l) goto out1;
	l = insert_subst_lump_after(l, _inbound?SUBST_RCV_ALL:SUBST_SND_ALL, 0);
	if (!l) goto out2;
	if (enable_double_path) {
		if (!(l = insert_cond_lump_after(l, COND_IF_DIFF_REALMS, 0)))
			goto out2;
		if (!(l = insert_new_lump_after(l, r2, PATH_R2_LEN, 0)))
			goto out2;
                r2 = 0;
	} else {
		pkg_free(r2);
		r2 = 0;
	}
	l2 = insert_new_lump_before(l2, suffix, suffix_len, 0);
	if (!l2) goto out3;
	if (recv) {
		/* TODO: agranig: optimize this one! */
		src_ip = ip_addr2a(&_m->rcv.src_ip);
		rcv_addr.s = pkg_malloc(4 + IP_ADDR_MAX_STR_SIZE + 7 +
			PATH_TRANS_PARAM_LEN + 4); /* sip:<ip>:<port>[;transport=xxxx]\0 */
		if(!rcv_addr.s) {
			LM_ERR("no pkg memory left for receive-address\n");
			goto out4;
		}
		rcv_addr.len = snprintf(rcv_addr.s, 4 + IP_ADDR_MAX_STR_SIZE + 6, "sip:%s:%u", src_ip, _m->rcv.src_port);
		switch (_m->rcv.proto) {
			case PROTO_TCP:
				memcpy(rcv_addr.s+rcv_addr.len, PATH_ESC_TRANS_PARAM "tcp",PATH_ESC_TRANS_PARAM_LEN+3);
				rcv_addr.len += PATH_ESC_TRANS_PARAM_LEN + 3;
				break;
			case PROTO_TLS:
				memcpy(rcv_addr.s+rcv_addr.len, PATH_ESC_TRANS_PARAM "tls",PATH_ESC_TRANS_PARAM_LEN+3);
				rcv_addr.len += PATH_ESC_TRANS_PARAM_LEN + 3;
				break;
			case PROTO_SCTP:
				memcpy(rcv_addr.s+rcv_addr.len, PATH_ESC_TRANS_PARAM "sctp",PATH_ESC_TRANS_PARAM_LEN+4);
				rcv_addr.len += PATH_ESC_TRANS_PARAM_LEN + 4;
				break;
		}
		l2 = insert_new_lump_before(l2, rcv_addr.s, rcv_addr.len, 0);
		if (!l2) goto out4;
	}
	l2 = insert_new_lump_before(l2, crlf, CRLF_LEN+1, 0);
	if (!l2) goto out5;

	return 1;

out1:
	if (prefix) pkg_free(prefix);
out2:
	if (r2)	pkg_free(r2);
out3:
	if (suffix) pkg_free(suffix);
out4:
	if (rcv_addr.s) pkg_free(rcv_addr.s);
out5:
	if (crlf) pkg_free(crlf);

	LM_ERR("failed to insert prefix lump\n");

	return -1;
}

static int prepend_path(struct sip_msg* _m, str *user, int recv)
{
	struct lump* l, *l2;
	struct hdr_field *hf;

	if (parse_headers(_m, HDR_PATH_F, 0) < 0) {
		LM_ERR("failed to parse message for Path header\n");
		return -1;
	}

	for (hf = _m->headers; hf; hf = hf->next) {
		if (hf->type == HDR_PATH_T) {
			break;
		}
	}

	if (hf) {
		/* path found, add ours in front of that */
		l = anchor_lump(_m, hf->name.s - _m->buf, 0);
		l2 = anchor_lump(_m, hf->name.s - _m->buf, 0);
	} else {
		/* no path, append to message */
		l = anchor_lump(_m, _m->unparsed - _m->buf, 0);
		l2 = anchor_lump(_m, _m->unparsed - _m->buf, 0);
	}

	if (!l || !l2) {
		LM_ERR("failed to get anchor\n");
		return -2;
	}

	if (build_path(_m, l, l2, user, recv, OUTBOUND) < 0) {
		LM_ERR("failed to insert outbound Path");
		return -3;
	}

	if (enable_double_path) {
		if (hf) {
			/* path found, add ours in front of that */
			l = anchor_lump(_m, hf->name.s - _m->buf, 0);
			l2 = anchor_lump(_m, hf->name.s - _m->buf, 0);
		} else {
			/* no path, append to message */
			l = anchor_lump(_m, _m->unparsed - _m->buf, 0);
			l2 = anchor_lump(_m, _m->unparsed - _m->buf, 0);
		}

		if (!l || !l2) {
			LM_ERR("failed to get anchor\n");
			return -4;
		}

		l = insert_cond_lump_after(l, COND_IF_DIFF_REALMS, 0);
		l2 = insert_cond_lump_before(l2, COND_IF_DIFF_REALMS, 0);

		if (!l || !l2) {
			LM_ERR("failed to insert conditional lump\n");
			return -5;
		}
		if (build_path(_m, l, l2, user, 0, INBOUND) < 0) {
			LM_ERR("failed to insert inbound Path");
			return -6;
		}
	}

	return 1;
}

/*
 * Prepend own uri to Path header
 */
int add_path(struct sip_msg* _msg, char* _a, char* _b)
{
	str user = {0,0};
	return prepend_path(_msg, &user, 0);
}

/*
 * Prepend own uri to Path header and take care of given
 * user.
 */
int add_path_usr(struct sip_msg* _msg, char* _usr, char* _b)
{
	return prepend_path(_msg, (str*)_usr, 0);
}

/*
 * Prepend own uri to Path header and append received address as
 * "received"-param to that uri.
 */
int add_path_received(struct sip_msg* _msg, char* _a, char* _b)
{
	str user = {0,0};
	return prepend_path(_msg, &user, 1);
}

/*
 * Prepend own uri to Path header and append received address as
 * "received"-param to that uri and take care of given user.
 */
int add_path_received_usr(struct sip_msg* _msg, char* _usr, char* _b)
{
	return prepend_path(_msg, (str*)_usr, 1);
}

/*
 * rr callback
 */
void path_rr_callback(struct sip_msg *_m, str *r_param, void *cb_param)
{
	static char _unescape_buf[MAX_PATH_SIZE];

	param_hooks_t hooks;
	param_t *params;
	param_t *first_param;
	str received = {0, 0};
	str transport = {0, 0};
	str dst_uri = {0, 0};
	str unescape_buf = {_unescape_buf, MAX_PATH_SIZE};
	char *p;

	if (parse_params(r_param, CLASS_ANY, &hooks, &params) != 0) {
		LM_ERR("failed to parse route parameters\n");
		return;
	}

	first_param = params;

	while(params)
	{
		if (params->name.len == 8 &&
		    !strncasecmp(params->name.s, "received", params->name.len)) {

			received = params->body;
			unescape_buf.len = MAX_PATH_SIZE;
			if (unescape_param(&received, &unescape_buf) != 0) {
				LM_ERR("failed to unescape received=%.*s\n",
				       received.len, received.s);
				goto out1;
			}

			/* if there's a param here, it has to be ;transport= */
			if ((p = q_memchr(unescape_buf.s, ';', unescape_buf.len))) {
				received.len = p - unescape_buf.s;

				if ((p = q_memchr(p, '=', unescape_buf.len))) {
					transport.s = p + 1;
					transport.len = unescape_buf.s + unescape_buf.len - transport.s;
				}
			}

			break;
		}

		params = params->next;
	}

	LM_DBG("extracted received=%.*s, transport=%.*s\n",
	       received.len, received.s, transport.len, transport.s);

	if (received.len > 0) {
		if (transport.len > 0) {
			dst_uri.len = received.len + PATH_TRANS_PARAM_LEN + 1 + transport.len;
			dst_uri.s = pkg_malloc(dst_uri.len);
			if(!dst_uri.s) {
				LM_ERR("no pkg memory left for receive-address\n");
				goto out1;
			}
			dst_uri.len = snprintf(dst_uri.s, dst_uri.len,
				"%.*s" PATH_TRANS_PARAM "%.*s", received.len, received.s, transport.len, transport.s);
		}
		else
		{
			dst_uri = received;
		}

		if (set_dst_uri(_m, &dst_uri) != 0)
			LM_ERR("failed to set dst-uri\n");

		if (transport.len > 0)
			pkg_free(dst_uri.s);
	}

out1:
	free_params(first_param);
	return;
}
