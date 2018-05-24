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
#include "../../lib/path.h"
#include "../../strcommon.h"
#include "../../ut.h"

#include "path_mod.h"

/*
 * Prepend own uri to Path header
 */
int add_path(struct sip_msg* _msg, char* _a, char* _b)
{
	str user = {0,0};
	int rc;

	rc = prepend_path(_msg, &user, 0, enable_double_path);

	return rc == 0 ? 1 : rc;
}

/*
 * Prepend own uri to Path header and take care of given
 * user.
 */
int add_path_usr(struct sip_msg* _msg, char* _usr, char* _b)
{
	int rc;

	rc = prepend_path(_msg, (str*)_usr, 0, enable_double_path);
	return rc == 0 ? 1 : rc;
}

/*
 * Prepend own uri to Path header and append received address as
 * "received"-param to that uri.
 */
int add_path_received(struct sip_msg* _msg, char* _a, char* _b)
{
	str user = {0,0};
	int rc;

	rc = prepend_path(_msg, &user, 1, enable_double_path);
	return rc == 0 ? 1 : rc;
}

/*
 * Prepend own uri to Path header and append received address as
 * "received"-param to that uri and take care of given user.
 */
int add_path_received_usr(struct sip_msg* _msg, char* _usr, char* _b)
{
	int rc;

	rc = prepend_path(_msg, (str*)_usr, 1, enable_double_path);
	return rc == 0 ? 1 : rc;
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
