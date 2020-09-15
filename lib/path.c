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

#include "../mem/mem.h"
#include "../data_lump.h"
#include "../parser/parse_param.h"
#include "../net/trans.h"

#include "path.h"

#define INBOUND  1  /* Insert inbound Path */
#define OUTBOUND 0  /* Insert outbound Path */

static int build_path(struct sip_msg* _m, struct lump* l, struct lump* l2,
					str* user, int recv, int _inbound, int double_path)
{
	char *prefix, *lr, *crlf, *r2, *received;
	int prefix_len, is_6;
	str rcv_addr = {0, 0};
	char *src_ip;

	prefix = crlf = r2 = lr = received = NULL;

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

	lr = pkg_malloc(PATH_LR_PARAM_LEN);
	if (!lr) {
		LM_ERR("no pkg memory left for lr\n");
		goto out1;
	}
	memcpy(lr, PATH_LR_PARAM, PATH_LR_PARAM_LEN);

	crlf = pkg_malloc(PATH_CRLF_LEN);
	if (!crlf) {
		LM_ERR("no pkg memory left for crlf\n");
		goto out1;
	}
	memcpy(crlf, PATH_CRLF, PATH_CRLF_LEN);

	l = insert_new_lump_after(l, prefix, prefix_len, 0);
	if (!l) goto out1;

	l = insert_subst_lump_after(l, _inbound?SUBST_RCV_ALL:SUBST_SND_ALL, 0);
	if (!l) goto out2;

	if (double_path) {
		r2 = pkg_malloc(PATH_R2_LEN);
		if (!r2) {
			LM_ERR("no pkg memory left for r2\n");
			goto out2;
		}
		memcpy(r2, PATH_R2, PATH_R2_LEN);

		if (_inbound == OUTBOUND &&
		        !(l = insert_cond_lump_after(l, COND_IF_DIFF_REALMS, 0))) {
			goto out2;
		}

		if (!(l = insert_new_lump_after(l, r2, PATH_R2_LEN, 0)))
			goto out2;
	}

	if (!(l = insert_new_lump_before(l2, lr, PATH_LR_PARAM_LEN, 0)))
		goto out3;

	if (!recv)
		goto end_path;

	/* include ";received=" in Path #1 if 1 header or Path #2 if 2 headers */
	if (double_path && _inbound == OUTBOUND &&
	        !(l = insert_cond_lump_before(l, COND_IF_SAME_REALMS, 0)))
		goto out4;

	received = pkg_malloc(PATH_RC_PARAM_LEN);
	if (!received) {
		LM_ERR("oom\n");
		goto out4;
	}
	memcpy(received, PATH_RC_PARAM, PATH_RC_PARAM_LEN);

	if (!(l = insert_new_lump_before(l, received, PATH_RC_PARAM_LEN, 0)))
		goto out4;

	src_ip = ip_addr2a(&_m->rcv.src_ip);
	is_6 =  ((&_m->rcv.src_ip)->af == AF_INET6) ? 1 : 0;
	rcv_addr.len = 4 + 2*is_6 + IP_ADDR_MAX_STR_SIZE + 7 +
		PATH_ESC_TRANS_PARAM_LEN + 4; /* sip:<ip>:<port>(\0|[%3btransport%3dxxxx]) */
	rcv_addr.s = pkg_malloc( rcv_addr.len );
	if (!rcv_addr.s) {
		LM_ERR("no pkg memory left for receive-address\n");
		goto out5;
	}

	if (_m->rcv.proto==PROTO_UDP) {
		rcv_addr.len = snprintf(rcv_addr.s, rcv_addr.len,
			"sip:%s%s%s:%u",
			is_6?"[":"", src_ip, is_6?"]":"", _m->rcv.src_port);
	} else {
		rcv_addr.len = snprintf(rcv_addr.s, rcv_addr.len,
			"sip:%s%s%s:%u" PATH_ESC_TRANS_PARAM "%s",
			is_6?"[":"", src_ip, is_6?"]":"", _m->rcv.src_port,
			get_proto_name(_m->rcv.proto));
	}

	if (!(l = insert_new_lump_before(l, rcv_addr.s, rcv_addr.len, 0)))
		goto out5;

end_path:
	if (_inbound == OUTBOUND) {
		if (!insert_new_lump_after(l2, crlf, CRLF_LEN+1, 0))
			goto out6;
	} else {
		if (!insert_new_lump_before(l, crlf, CRLF_LEN+1, 0))
			goto out6;
	}

	return 1;

out1:
	if (prefix) pkg_free(prefix);
out2:
	if (r2) pkg_free(r2);
out3:
	if (lr) pkg_free(lr);
out4:
	if (received) pkg_free(received);
out5:
	if (rcv_addr.s) pkg_free(rcv_addr.s);
out6:
	if (crlf) pkg_free(crlf);

	LM_ERR("failed to build Path header lumps\n");
	return -1;
}

int prepend_path(struct sip_msg* _m, str *user, int recv, int double_path)
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

	if (build_path(_m, l, l2, user, recv, OUTBOUND, double_path) < 0) {
		LM_ERR("failed to insert outbound Path");
		return -3;
	}

	if (double_path) {
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
		if (build_path(_m, l, l2, user, recv, INBOUND, double_path) < 0) {
			LM_ERR("failed to insert inbound Path");
			return -6;
		}
	}

	return 0;
}
