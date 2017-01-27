/*
 * Dedicated process for handling events on multiple FS ESL connections
 *
 * Copyright (C) 2017 OpenSIPS Solutions
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
 * History:
 * --------
 *  2017-01-26 initial version (liviu)
 */

#include <stdlib.h>

#include "../../mem/mem.h"
#include "../../reactor.h"
#include "../../timer.h"

#include "esl/src/include/esl.h"

#include "fs_api.h"

inline static int handle_io(struct fd_map *fm, int idx, int event_type)
{
	fs_evs *box = (fs_evs *)fm->data;
	esl_status_t rc;

	LM_DBG("FS data is available!\n");

	switch (fm->type) {
		case F_FS_STATS:
			rc = esl_recv_event(box->handle, 0, &box->handle->last_sr_event);
			if (rc != ESL_SUCCESS) {
				LM_ERR("read error %d on FS box %.*s:%d. Reconnecting...\n",
				       rc, box->host.len, box->host.s, box->port);

				if (reactor_del_reader(box->handle->sock, idx,
				                       IO_WATCH_READ) != 0) {
					LM_ERR("del failed for sock %d\n", box->handle->sock);
					return 0;
				}

				rc = esl_disconnect(box->handle);
				if (rc != ESL_SUCCESS) {
					LM_ERR("disconnect error %d on FS box %.*s:%d\n",
					       rc, box->host.len, box->host.s, box->port);
					box->handle->connected = 0;
					return 0;
				}

				return 0;
			}

			/* TODO: push stats to subscribers */
			LM_INFO("FS stats:\n%s\n", box->handle->last_sr_event->body);
			break;
		default:
			LM_CRIT("unknown fd type %d in FreeSWITCH worker\n", fm->type);
			return -1;
	}

	return 0;
}

static int handle_reconnects(int first_run)
{
	struct list_head *ele;
	fs_evs *box;
	int ret = 0;
	esl_status_t rc;

	if (!first_run && get_ticks() % 10 != 9) {
		return 0;
	}

	LM_DBG("handling FS reconnects\n");

	list_for_each(ele, fs_boxes) {
		box = list_entry(ele, fs_evs, list);

		if (box->handle) {
			if (box->handle->connected && box->handle->sock != ESL_SOCK_INVALID) {
				LM_DBG("FS box '%.*s:%d' is OK\n", box->host.len,
				       box->host.s, box->port);
				continue;
			} else {
				rc = esl_disconnect(box->handle);
				if (rc != ESL_SUCCESS) {
					LM_ERR("disconnect error %d on FS box %.*s:%d\n",
					       rc, box->host.len, box->host.s, box->port);
				}
			}
		} else {
			box->handle = pkg_malloc(sizeof *box->handle);
			if (!box->handle) {
				LM_ERR("failed to create FS handle!\n");
				ret++;
				continue;
			}
		}

		memset(box->handle, 0, sizeof *box->handle);
		LM_DBG("reconnecting to FS box '%s:%d'\n", box->host.s, box->port);

		if (esl_connect_timeout(box->handle, box->host.s, box->port, NULL,
			                    "opensips", 5000U) != ESL_SUCCESS) {
			LM_ERR("failed to connect to FS box '%.*s:%d'\n",
			       box->host.len, box->host.s, box->port);
			ret++;
			continue;
		}

		LM_DBG("sucessfully connected to FS!\n");

		if (!box->handle->connected) {
			LM_BUG("FS connect");
			abort();
		}

		LM_DBG("registering for HEARTBEAT events...\n");
		if (esl_send_recv(box->handle, "event json HEARTBEAT\n\n")
		    != ESL_SUCCESS) {
			LM_ERR("failed to register HEARTBEAT event on FS box '%.*s:%d'\n",
			       box->host.len, box->host.s, box->port);
			ret++;
			continue;
		}

		LM_DBG("answer: %s\n", box->handle->last_sr_reply);
		LM_DBG("sucessfully enabled HEARTBEAT events!\n");

		if (reactor_add_reader(box->handle->sock, F_FS_STATS,
		                       RCT_PRIO_TIMER, box) < 0) {
			LM_ERR("failed to add FS socket to reactor (box '%.*s:%d')\n",
			       box->host.len, box->host.s, box->port);
			ret++;
			continue;
		}
	}

	return ret;
}

void fs_stats_loop(int proc_no)
{
	int rc;

	LM_DBG("size: %d, method: %d\n", reactor_size, io_poll_method);

	if (init_worker_reactor("FS Stats", RCT_PRIO_MAX) != 0) {
		LM_BUG("failed to init reactor");
		abort();
	}

	rc = handle_reconnects(1);
	if (rc != 0) {
		LM_ERR("failed to reconnect to %d FS boxes!\n", rc);
	}

	reactor_main_loop(1, out_err, handle_reconnects(0));

out_err:
	destroy_io_wait(&_worker_io);
	abort();
}
