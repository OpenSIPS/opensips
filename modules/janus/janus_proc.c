/*
 * Janus Module
 *
 * Copyright (C) 2024 OpenSIPS Project
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * History:
 * --------
 * 2024-12-03 initial release (vlad)
 */

#include <ctype.h>

#include "../../dprint.h"
#include "../../ut.h"
#include "../../net/trans_trace.h"
#include "../../net/tcp_common.h"

#include "../../reactor.h"
#include "../../timer.h"
#include "../../ipc.h"

#include "janus_common.h"
#include "janus_ws.h"
#include "ws_common_defs.h"
#include "janus_proc.h"
#include "ws_common_defs.h"

#include "../../lib/cJSON.h"

static ipc_handler_type ipc_hdl_run_janus;

inline static int handle_io(struct fd_map *fm, int idx, int event_type)
{
	janus_connection *conn;

	switch (fm->type) {
		case F_GEN_PROC:
			conn = (janus_connection *)fm->data;
			if (janus_handle_data(conn) < 0) {
				LM_ERR("Failed to read from janus on %d\n",conn->fd);

				if (reactor_del_reader(
				conn->fd, 
				idx,
				IO_WATCH_READ) != 0)
					LM_ERR("del failed for sock %d\n",conn->fd);

				close(conn->fd);
				lock_start_write(sockets_down_lock);
				list_add_tail(&conn->reconnect_list, janus_sockets_down);
				lock_stop_write(sockets_down_lock);
			}
			break;
		case F_IPC:
			LM_DBG("received JANUS IPC job!\n");
			ipc_handle_job(fm->fd);
			break;
		default:
			LM_CRIT("unknown fd type %d in JANUS worker\n", fm->type);
			return 0;

	}	

	return 0;
}

void janus_run_command(int sender, void *_cmd)
{
	janus_ipc_cmd *cmd = (janus_ipc_cmd *)_cmd;

	LM_DBG("We need to run command %.*s on %.*s sock %d \n",cmd->janus_cmd.len,cmd->janus_cmd.s,cmd->sock->full_url.len,cmd->sock->full_url.s,cmd->sock->fd);

	if (janusws_write_req(cmd->sock,cmd->janus_cmd.s,cmd->janus_cmd.len) < 0) {
		LM_ERR("Failed to run command %.*s on janus %.*s sock %d\n",
		cmd->janus_cmd.len,cmd->janus_cmd.s,
		cmd->sock->janus_id.len,cmd->sock->janus_id.s,
		cmd->sock->fd);

		/* reader will timeout */
		goto out;
	}

out:
	shm_free(cmd->janus_cmd.s);
	shm_free(cmd);

	return;
}

int janus_ipc_init(void)
{
	LM_DBG("registering IPC handler\n");

	ipc_hdl_run_janus = ipc_register_handler(janus_run_command, "Run JANUS command");
	if (ipc_bad_handler_type(ipc_hdl_run_janus)) {
		LM_ERR("failed to register 'Run JANUS command' IPC handler\n");
		return -1;
	}

	return 0;
}

int janus_mgr_init(void)
{
	janus_sockets = shm_malloc(2 * sizeof *janus_sockets);
	if (!janus_sockets) {
		LM_ERR("No more shm\n");
		return -1;
	}
	INIT_LIST_HEAD(janus_sockets);

	janus_sockets_down = janus_sockets + 1;
	INIT_LIST_HEAD(janus_sockets_down);

	sockets_lock = lock_init_rw();
	sockets_down_lock = lock_init_rw();
	if (!sockets_lock || !sockets_down_lock) {
		LM_ERR("No more shm\n");
		return -1;
	}

	janus_mgr_process_no = shm_malloc(sizeof *janus_mgr_process_no);
	if (!janus_mgr_process_no) {
		LM_ERR("oom\n");
		return -1;
	}

	return 0;
}

int janus_set_mgr_proc_no(void)
{
	*janus_mgr_process_no = process_no;
	return 0;
}

/* TODO: rework this specific "PID advertising" hack
 * as part of a more reusable OpenSIPS mechanism */
int janus_mgr_wait_init(void)
{
	int i;

	/* time out startup after 10 sec */
	for (i = 0; i < 2000000; i++) {
		if (*janus_mgr_process_no != 0)
			return 0;

		usleep(5);
	}

	LM_ERR("JANUS Manager is not ready for use after 10 sec, aborting\n");
	return -1;
}

#define JANUS_REACTOR_TIMEOUT 1

int janus_reconnect(janus_connection *sock) 
{
	if (janus_ws_connect(sock) < 0) {
		LM_ERR("Failed to connect \n");
		return -1;
	}

	if (janus_init_connection(sock) < 0) {
		LM_ERR("Failed to init connection \n");
		return -1;
	}

	if (sock->fd && sock->janus_handler_id > 0) {
		return 1; 
	}

	LM_ERR("Unhandled error in reconnect \n");
	return -1;
}

void janus_reconnects(void) 
{
	struct list_head *_, *__;
	janus_connection *sock;

	lock_start_write(sockets_lock);
	lock_start_write(sockets_down_lock);

	list_for_each_safe(_, __, janus_sockets_down) {
		sock = list_entry(_, janus_connection, reconnect_list);

		LM_DBG("need to reconnect sock %.*s : %.*s\n", 
		sock->janus_id.len, sock->janus_id.s,
		sock->full_url.len,sock->full_url.s);

		if (janus_reconnect(sock) < 0) {
			LM_ERR("Failed to connect JANUS \n");
			continue;
		}

		if (reactor_add_reader(sock->fd, F_GEN_PROC,
		                       RCT_PRIO_TIMER, sock) < 0) {
			LM_ERR("failed to add JANUS socket %.*s to reactor\n",
			sock->janus_id.len, sock->janus_id.s);

			close(sock->fd);
			continue;
		}

		list_del(&sock->reconnect_list);
		INIT_LIST_HEAD(&sock->reconnect_list);
	}

	lock_stop_write(sockets_down_lock);
	lock_stop_write(sockets_lock);
}

void janus_worker_loop(int proc_no)
{
	janus_set_mgr_proc_no();

	if (init_worker_reactor("JANUS Manager", RCT_PRIO_MAX) != 0) {
		LM_BUG("failed to init JANUS reactor");
		abort();
	}

	if (reactor_add_reader(IPC_FD_READ_SELF, F_IPC, RCT_PRIO_ASYNC, NULL)<0){
		LM_CRIT("failed to add IPC pipe to FS reactor\n");
		abort();
	}

	/* connect to all JANUS servers now */
	janus_reconnects();

	reactor_main_loop(JANUS_REACTOR_TIMEOUT, out_err, janus_reconnects());

out_err:
	destroy_io_wait(&_worker_io);
	abort();
}

uint64_t janus_ipc_send_request(janus_connection *sock, cJSON *janus_cmd)
{
	janus_ipc_cmd *cmd;
	uint64_t janus_transaction_id;
	str full_cmd;
	int len;

	cmd = shm_malloc(sizeof *cmd);
	if (!cmd) {
		LM_ERR("oom\n");
		return 0;
	}
	memset(cmd, 0, sizeof *cmd);

	cmd->sock = sock;

	lock_start_write(sock->lists_lk);

	sock->janus_transaction_id = sock->janus_transaction_id+1;
	cmd->janus_transaction_id = sock->janus_transaction_id;

	cJSON_AddStringToObject(janus_cmd,"transaction",
			int2str(cmd->janus_transaction_id,&len));
	cJSON_AddNumberToObject(janus_cmd,"session_id",
			sock->janus_handler_id);

	lock_stop_write(sock->lists_lk);

	full_cmd.s = cJSON_Print(janus_cmd);
	full_cmd.len = strlen(full_cmd.s);

	if (shm_nt_str_dup(&cmd->janus_cmd, &full_cmd) != 0) {
		shm_free(cmd);
		LM_ERR("oom\n");
		return 0;
	}

	janus_transaction_id = cmd->janus_transaction_id;

	if (ipc_send_job(*janus_mgr_process_no, ipc_hdl_run_janus, cmd) != 0) {
		LM_ERR("IPC send failed\n");
		shm_free(cmd->janus_cmd.s);
		shm_free(cmd);
		return 0;
	}

	return janus_transaction_id;
}


void janus_pinger_routine(unsigned int ticks , void * attr)
{
	struct list_head *_;
	janus_connection *sock = NULL;
	str janus_keepalive = str_init("{\"janus\":\"keepalive\"}");
	cJSON *j_request;
	uint64_t reply_id;

	j_request = cJSON_Parse(janus_keepalive.s);
	if (j_request == NULL) {
		LM_ERR("refusing to run invalid JSON keepalive %.*s!\n",
		janus_keepalive.len,janus_keepalive.s);
		return;
	}

	list_for_each(_, janus_sockets) {
		sock = list_entry(_, janus_connection, list);
		LM_DBG("Ping routing on JANUS %.*s\n",sock->janus_id.len,sock->janus_id.s);

		reply_id = janus_ipc_send_request(sock,j_request);
		if (reply_id == 0) {
			LM_ERR("Failed to send keepalive request towards %.*s\n",
			sock->janus_id.len,sock->janus_id.s);
		}

		/* keepalives end in ACK, right now we're not saving those, so we don't wait for them either */
	}

	cJSON_Delete(j_request);
}
