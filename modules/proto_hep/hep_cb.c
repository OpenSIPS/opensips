/*
 * Copyright (C) 2015 - OpenSIPS Solutions
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 * History:
 * -------
 *  2015-09-03  first version (Ionut Ionita)
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
#include "../../context.h"
#include "hep.h"
#include "hep_cb.h"

extern int hep_ctx_idx;
extern int homer5_on;

struct hep_cb_list {
	hep_cb_t cb;
	struct hep_cb_list *next;
};

struct hep_cb_list *cb_list=0;

int get_hep_ctx_id(void)
{
	return hep_ctx_idx;
}

int register_hep_cb(hep_cb_t cb)
{
	struct hep_cb_list *cb_el;

	cb_el = shm_malloc(sizeof(struct hep_cb_list));
	if (cb_el == NULL) {
		LM_ERR("no more shm\n");
		return -1;
	}

	/* set cb_el->next to 0 */
	memset(cb_el, 0, sizeof(struct hep_cb_list));
	cb_el->cb = cb;


	if (cb_list == NULL) {
		cb_list = cb_el;
	} else {
		/* add in front; no need to iterate whole list */
		cb_el->next = cb_list;
		cb_list = cb_el;
	}

	return 0;
}

int run_hep_cbs(void)
{
	int ret, fret=-1;
	struct hep_cb_list *cb_el;

	for (cb_el=cb_list; cb_el; cb_el=cb_el->next) {
		ret=cb_el->cb();
		if (ret < 0) {
			LM_ERR("hep callback failed! Continuing with the other ones!\n");
		} else if (ret == HEP_SCRIPT_SKIP) {
			fret = HEP_SCRIPT_SKIP;
		} else if (fret == -1) {
			/* if at least one succeeds then it's ok */
			fret = 0;
		}
	}

	return fret;
}

void free_hep_cbs(void)
{
	struct hep_cb_list *curr, *next;

	curr = cb_list;
	while (curr) {
		next = curr->next;
		shm_free(curr);
		curr = next;
	}

}

static inline int get_homer_version(void) {
	return homer5_on ? HOMER5 : HOMER6;
}

int bind_proto_hep(proto_hep_api_t *api)
{
	if (!api) {
		LM_ERR("invalid parameter value!\n");
		return -1;
	}

	api->register_hep_cb    = register_hep_cb;
	api->get_hep_ctx_id     = get_hep_ctx_id;
	api->get_homer_version  = get_homer_version;

	return 0;
}



