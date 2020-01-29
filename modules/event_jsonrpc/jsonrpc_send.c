/*
 * Copyright (C) 2018 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
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
 */

#include "../../evi/evi_transport.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../ut.h"
#include "../../pt.h"
#include "../../lib/osips_malloc.h"
#include "../../lib/cJSON.h"
#include "../../reactor.h"
#include "jsonrpc_send.h"
#include "event_jsonrpc.h"
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>
#include "../../lib/list.h"


#define JSONRPC_REQ_NEW		0
#define JSONRPC_REQ_SENT	1
#define JSONRPC_REACTOR_TIMEOUT  1 /* sec */
#define JSONRPC_SEND_SUCCESS 0
#define JSONRPC_SEND_FAIL -1
#define JSONRPC_MAX_PENDING_READS 4
#define IS_ERR(_err) (errno == _err)
#define JSONRPC_ADDR(con) \
	inet_ntoa(con->addr.sin.sin_addr), ntohs(con->addr.sin.sin_port)

int jsonrpc_timeout = JSONRPC_DEFAULT_TIMEOUT;
char *jsonrpc_event_param;
unsigned jsonrpc_sync_mode = 0;
static int jrpc_id_index = 0;

/* used to communicate with the sending process */
static int jsonrpc_pipe[2];

struct jsonrpc_con {
	union sockaddr_union addr;
	int id;
	int fd;
	str pending_buffer;
	int pending_writes;
	int pending_reads;
	struct list_head list;
	struct list_head cmds;
};

struct jsonrpc_cmd {
	int state;
	jsonrpc_send_t *job;
	struct list_head list;
};

struct list_head jsonrpc_conns;

/* creates communication pipe */
static int jsonrpc_create_pipe(void)
{
	int rc;

	jsonrpc_pipe[0] = jsonrpc_pipe[1] = -1;
	/* create pipe */
	do {
		rc = pipe(jsonrpc_pipe);
	} while (rc < 0 && IS_ERR(EINTR));

	if (rc < 0) {
		LM_ERR("cannot create status pipe [%d:%s]\n", errno, strerror(errno));
		return -1;
	}

	return 0;
}

int jsonrpc_init_process(void)
{
	INIT_LIST_HEAD(&jsonrpc_conns);

	return jsonrpc_create_pipe();
}

void jsonrpc_destroy_pipe(void)
{
	if (jsonrpc_pipe[0] != -1)
		close(jsonrpc_pipe[0]);
	if (jsonrpc_pipe[1] != -1)
		close(jsonrpc_pipe[1]);
}

int jsonrpc_send(jsonrpc_send_t* jsonrpcs)
{
	int rc, retries = JSONRPC_SEND_RETRY;
	long send_status;

	jsonrpcs->process_idx = process_no;

	do {
		rc = write(jsonrpc_pipe[1], &jsonrpcs, sizeof(jsonrpc_send_t *));
	} while (rc < 0 && (IS_ERR(EINTR) || retries-- > 0));

	if (rc < 0) {
		LM_ERR("unable to send jsonrpc send struct to worker\n");
		shm_free(jsonrpcs);
		return JSONRPC_SEND_FAIL;
	}
	/* give a chance to the writer :) */
	sched_yield();

	if (jsonrpc_sync_mode) {
		if (ipc_recv_sync_reply((void **)(long *)&send_status) < 0) {
			LM_ERR("cannot receive send status\n");
			send_status = JSONRPC_SEND_FAIL;
		}

		return (int)send_status;
	} else
		return JSONRPC_SEND_SUCCESS;
}

static jsonrpc_send_t * jsonrpc_receive(void)
{
	static jsonrpc_send_t * recv;
	int rc;
	int retries = JSONRPC_SEND_RETRY;

	if (jsonrpc_pipe[0] == -1)
		return NULL;

	do {
		rc = read(jsonrpc_pipe[0], &recv, sizeof(jsonrpc_send_t*));
	} while (rc < 0 && (IS_ERR(EINTR) || retries-- > 0));

	if (rc < 0) {
		LM_ERR("cannot receive send param\n");
		return NULL;
	}
	return recv;
}

int jsonrpc_init_writer(void)
{
	int flags;

	if (jsonrpc_pipe[0] != -1) {
		close(jsonrpc_pipe[0]);
		jsonrpc_pipe[0] = -1;
	}

	if (jsonrpc_sync_mode) {
		/* initilize indexes */
		jrpc_id_index = my_pid() & USHRT_MAX;
		jrpc_id_index |= rand() << sizeof(unsigned short);
	}

	/* Turn non-blocking mode on for sending*/
	flags = fcntl(jsonrpc_pipe[1], F_GETFL);
	if (flags == -1) {
		LM_ERR("fcntl failed: %s\n", strerror(errno));
		goto error;
	}
	if (fcntl(jsonrpc_pipe[1], F_SETFL, flags | O_NONBLOCK) == -1) {
		LM_ERR("fcntl: set non-blocking failed: %s\n", strerror(errno));
		goto error;
	}

	return 0;
error:
	close(jsonrpc_pipe[1]);
	jsonrpc_pipe[1] = -1;
	return -1;
}

static void jsonrpc_init_reader(void)
{
	if (jsonrpc_pipe[1] != -1) {
		close(jsonrpc_pipe[1]);
		jsonrpc_pipe[1] = -1;
	}
}


static inline int jsonrpc_unique_id(void)
{
	if (!jsonrpc_sync_mode)
		return 0;
	/*
	 * the format is 'rand | my_pid'
	 * rand is (int) - (unsigned short) long
	 * my_pid is (short) long
	 */
	jrpc_id_index += (1 << sizeof(unsigned short));
	/* make sure we always return something positive */
	return jrpc_id_index < 0 ? -jrpc_id_index : jrpc_id_index;
}

static jsonrpc_send_t *jsonrpc_build_send_t(evi_reply_sock *sock,
		char *json, int id)
{
	int jlen = strlen(json);
	int len = sizeof(jsonrpc_send_t) + jlen;

	jsonrpc_send_t *msg = shm_malloc(len);
	if (!msg) {
		LM_ERR("no more shm mem\n");
		return NULL;
	}
	memset(msg, 0, len);

	/* first is body */
	msg->message.s = (char*)(msg + 1);
	memcpy(msg->message.s, json, jlen);
	msg->message.len = jlen;
	msg->id = id;

	msg->process_idx = process_no;
	gettimeofday(&msg->time, NULL);

	/* finally add the socket info */
	memcpy(&msg->addr, &sock->src_addr.udp_addr, sizeof(union sockaddr_union));
	return msg;
}

/* function to build jsonrpc buffer */
int jsonrpc_build_buffer(str *event_name, evi_reply_sock *sock,
		evi_params_t *params, jsonrpc_send_t ** msg)
{
	char *s;
	int ret = -1;
	evi_param_p param;
	cJSON *param_obj = NULL, *tmp;
	int id = jsonrpc_unique_id();
	str *method = (sock->flags & EVI_PARAMS ? (str *)sock->params: event_name);
	cJSON *ret_obj = cJSON_CreateObject();
	if (jsonrpc_sync_mode)
		cJSON_AddNumberToObject(ret_obj, "id", id);
	else
		cJSON_AddNullToObject(ret_obj, "id");
	cJSON_AddItemToObject(ret_obj, "jsonrpc",
			cJSON_CreateString(JSONRPC_VERSION));
	cJSON_AddItemToObject(ret_obj, "method",
			cJSON_CreateStr(method->s, method->len));

	if (params->first && !params->first->name.s)
		param_obj = cJSON_CreateArray();
	else
		param_obj = cJSON_CreateObject();

	if (jsonrpc_event_param) {
		tmp = cJSON_CreateStr(event_name->s, event_name->len);
		if (params->first && !params->first->name.s)
			cJSON_AddItemToArray(param_obj, tmp);
		else
			cJSON_AddItemToObject(param_obj, jsonrpc_event_param, tmp);
	}

	cJSON_AddItemToObject(ret_obj, "params", param_obj);
	for (param = params->first; param; param = param->next) {
		if (param->flags & EVI_INT_VAL)
			tmp = cJSON_CreateNumber(param->val.n);
		else
			tmp = cJSON_CreateStr(param->val.s.s, param->val.s.len);
		if (param->name.s) {
			s = pkg_malloc(param->name.len + 1);
			if (!s) {
				LM_ERR("cannot allocate %d for param's name!\n",
						param->name.len);
				goto error;
			}
			memcpy(s, param->name.s, param->name.len);
			s[param->name.len] = 0;
			cJSON_AddItemToObject(param_obj, s, tmp);
			pkg_free(s);
		} else
			cJSON_AddItemToArray(param_obj, tmp);
	}

	s = cJSON_PrintUnformatted(ret_obj);
	if (!s) {
		LM_ERR("cannot print json object!\n");
		goto error;
	}

	*msg = jsonrpc_build_send_t(sock, s, id);
	if (!*msg) {
		LM_ERR("cannot build send msg\n");
		cJSON_PurgeString(s);
		goto error;
	}
	cJSON_PurgeString(s);
	ret = 0;
error:
	cJSON_Delete(ret_obj);

	return ret;
}

static struct jsonrpc_con *jsonrpc_get_con(union sockaddr_union *addr)
{
	struct jsonrpc_con *con;
	struct list_head *it;

	list_for_each(it, &jsonrpc_conns) {
		con = list_entry(it, struct jsonrpc_con, list);
		if (memcmp(&con->addr, addr, sizeof(*addr)) == 0)
			return con;
	}
	return NULL;
}


/**
 * this process uses it's own types of sockets, so we don't need to
 * declare them in the reactor defs - just go negative to prevent
 * overlapping
 */
#define F_EV_JSONRPC_CMD -1
#define F_EV_JSONRPC_RPL -2

static struct jsonrpc_con *jsonrpc_new_con(union sockaddr_union *addr)
{
	struct jsonrpc_con *con;
	int fd;
	int flags;

	/* writing the iov on the network */
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		LM_ERR("cannot create socket\n");
		return NULL;
	}

	if (connect(fd, &addr->s, sizeof(struct sockaddr_in)) < 0) {
		LM_ERR("cannot connect to %s[%d:%s]\n",
				inet_ntoa(addr->sin.sin_addr),
				errno, strerror(errno));
		goto close;
	}

	/* mark the socket as non-blocking after connect :) */
	flags = fcntl(fd, F_GETFL);
	if (flags == -1) {
		LM_ERR("fcntl failed: %s\n", strerror(errno));
		goto close;
	}
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		LM_ERR("fcntl: set non-blocking failed: %s\n", strerror(errno));
		goto close;
	}

	con = pkg_malloc(sizeof(*con));
	if (!con) {
		LM_ERR("cannot create new JSON-RPC connection\n");
		goto close;
	}
	con->id = -1;
	con->fd = fd;
	con->addr = *addr;
	con->pending_writes = 0;
	INIT_LIST_HEAD(&con->cmds);

	con->pending_buffer.len = 0;
	con->pending_buffer.s = NULL;
	con->pending_reads = 0;

	/* also add the file descripor to the reactor */
	if (reactor_add_reader(fd, F_EV_JSONRPC_RPL, RCT_PRIO_ASYNC, con)<0){
		LM_CRIT("failed to add read jsonrpc connection to reactor\n");
		pkg_free(con);
		goto close;
	}

	list_add(&con->list, &jsonrpc_conns);
	return con;
close:
	shutdown(fd, SHUT_RDWR);
	close(fd);
	return NULL;
}

static void jsonrpc_cmd_free(struct jsonrpc_cmd *cmd)
{
	shm_free(cmd->job);
	pkg_free(cmd);
}

static void jsonrpc_cmd_write(int process_idx, int send_status)
{
	if (ipc_send_sync_reply(process_idx, (void *)(long)send_status) < 0)
		LM_ERR("cannot send status back to requesting process\n");
}

static void jsonrpc_cmd_reply(struct jsonrpc_cmd *cmd, int send_status)
{

	if (!jsonrpc_sync_mode)
		return;

	jsonrpc_cmd_write(cmd->job->process_idx, send_status);
}

static void jsonrpc_con_free(struct jsonrpc_con *con)
{
	struct list_head *it, *tmp;
	struct jsonrpc_cmd *cmd;

	if (con->pending_writes != 0)
		reactor_del_all(con->fd, con->id, 0);
	else
		reactor_del_reader(con->fd, con->id, 0);
	if (con->pending_buffer.len)
		pkg_free(con->pending_buffer.s);

	if (jsonrpc_sync_mode) {
		/* in sync mode, we need to send back error */
		list_for_each_safe(it, tmp, &con->cmds) {
			cmd = list_entry(it, struct jsonrpc_cmd, list);
			jsonrpc_cmd_reply(cmd, JSONRPC_SEND_FAIL);
			list_del(&cmd->list);
			jsonrpc_cmd_free(cmd);
		}
	}
	shutdown(con->fd, SHUT_RDWR);
	close(con->fd);
	/* remove from the list */
	list_del(&con->list);
	pkg_free(con);
}


static void handle_new_jsonrpc(jsonrpc_send_t *jsonrpc)
{
	struct jsonrpc_con *con;
	struct jsonrpc_cmd *cmd;

	/* reuse ongoing connections */
	con = jsonrpc_get_con(&jsonrpc->addr);
	if (!con) {
		con = jsonrpc_new_con(&jsonrpc->addr);
		if (!con) {
			LM_ERR("cannot create new connection!\n");
			goto error;
		}
	}

	/* send the message */
	cmd = pkg_malloc(sizeof *cmd);
	if (!cmd) {
		LM_ERR("cannot create new JSON-RPC command to %s:%hu!\n", JSONRPC_ADDR(con));
		goto error;
	}
	con->pending_writes++;
	cmd->state = JSONRPC_REQ_NEW;
	cmd->job = jsonrpc;
	list_add_tail(&cmd->list, &con->cmds);

	if (con->pending_writes == 1 /* first write pending */) {
		if (reactor_add_writer(con->fd, F_EV_JSONRPC_RPL, RCT_PRIO_ASYNC, con)<0){
			LM_CRIT("failed to add write jsonrpc connection to reactor\n");
			jsonrpc_con_free(con);
			return;
		}
	}

error:
	if (jsonrpc_sync_mode) {
		/* we need to notify the process that the connection failed! */
		jsonrpc_cmd_write(jsonrpc->process_idx, JSONRPC_SEND_FAIL);
	}
}

static int handle_cmd_reply(struct jsonrpc_con *con, cJSON *reply)
{
	struct jsonrpc_cmd *cmd;
	struct list_head *it, *tmp;
	cJSON *aux;
	int id;
	int ret;

	/* check if it has a proper id */
	aux = cJSON_GetObjectItem(reply, "id");
	if (!aux) {
		LM_ERR("reply does not have an ID!\n");
		return -1;
	}
	if (aux->type != cJSON_Number) {
		LM_ERR("json does not have an integer id!\n");
		return -1;
	}
	id = aux->valueint;

	/* now check if there is an error */
	aux = cJSON_GetObjectItem(reply, "error");
	ret = (aux ? JSONRPC_SEND_FAIL : JSONRPC_SEND_SUCCESS);

	/* XXX: should we check the version too?! */

	/* in sync mode, we need to send back error */
	list_for_each_safe(it, tmp, &con->cmds) {
		cmd = list_entry(it, struct jsonrpc_cmd, list);
		if (id != cmd->job->id)
			continue;
		jsonrpc_cmd_reply(cmd, ret);
		list_del(&cmd->list);
		jsonrpc_cmd_free(cmd);
		/* all good */
		return 0;
	}

	LM_INFO("no pending queries with id %d found!\n", id);
	return 0;
}

static void handle_reply_jsonrpc(struct jsonrpc_con *con)
{
	/* got a reply on the connection */
	str buf;
	cJSON *reply;
	int bytes_read;
	const char *end;
	char buffer[JSONRPC_BUFFER_SIZE + 1];

	do {
		bytes_read = read(con->fd, buffer, JSONRPC_BUFFER_SIZE);
	} while (bytes_read == -1 && errno == EINTR);
	if (bytes_read < 0) {
		LM_ERR("error while reading reply from %s:%hu\n", JSONRPC_ADDR(con));
		goto error;
	} else if (bytes_read == 0) {
			LM_INFO("connection to %s:%hu closed!\n", JSONRPC_ADDR(con));
		goto error;
	}

	/* if not in sync mode, no one listens for the reply */
	if (jsonrpc_sync_mode == 0)
		return;

	/* got a reply - parse it and match a command */
	/* TODO: proper parse a reply */
	LM_INFO("Received reply %.*s\n", bytes_read, buffer);

	/* if there was something else in the buffer, merge with what we had */
	if (con->pending_buffer.len) {
		/* XXX: this wasn't tested */
		con->pending_buffer.s = pkg_realloc(con->pending_buffer.s,
				con->pending_buffer.len + bytes_read + 1);
		if (!con->pending_buffer.s) {
			LM_ERR("No more pkg memory to keep replies!\n");
			goto error;
		}
		memcpy(con->pending_buffer.s + con->pending_buffer.len, buffer, bytes_read);
		con->pending_buffer.len += bytes_read;
		con->pending_buffer.s[con->pending_buffer.len] = 0;
		buf = con->pending_buffer;
	} else {
		buf.s = buffer;
		buf.len = bytes_read;
	}

	do {
		reply = cJSON_ParseWithOpts(buf.s, &end, 0);
		if (!reply && buf.s == end) {
			LM_ERR("cannot parse reply [%.*s]\n", buf.len, buf.s);
			goto error;
		}

		if (reply) {
			if (handle_cmd_reply(con, reply) < 0) {
				cJSON_Delete(reply);
				goto error;
			}
			cJSON_Delete(reply);
			reply = (cJSON *)0x1; /* make sure we continue to process */
		}

		/* advance the buffer */
		bytes_read = end - buf.s;
		buf.len -= bytes_read;
		buf.s += bytes_read;

		if (buf.len) {
			/* XXX: this was not tested! */
			/* still have stuff to parse - move it in the connection */
			if (con->pending_buffer.s) {
				con->pending_reads++;
				if (con->pending_reads > JSONRPC_MAX_PENDING_READS) {
					LM_ERR("too many reads retries: %d\n", con->pending_reads);
					goto error;
				}
				if (buf.s != con->pending_buffer.s) {
					memmove(con->pending_buffer.s, buf.s, buf.len);
					con->pending_buffer.len = buf.len;
					buf = con->pending_buffer;
				}
			} else {
				/* move it in the buffer! */
				con->pending_buffer.s = pkg_malloc(buf.len);
				if (!con->pending_buffer.s) {
					LM_ERR("cannot move buffer to pkg for reply!\n");
					goto error;
				}
				memcpy(con->pending_buffer.s, buf.s, buf.len);
				con->pending_buffer.len = buf.len;
				con->pending_reads++;
			}
		} else if (con->pending_buffer.len) {
			pkg_free(con->pending_buffer.s);
			con->pending_buffer.len = 0;
			con->pending_reads = 0;
		}
	} while (reply && buf.len);

	return;
error:
	jsonrpc_con_free(con);
}

static void handle_write_jsonrpc(struct jsonrpc_con *con)
{
	struct list_head *it, *tmp;
	struct jsonrpc_cmd *cmd;
	int bytes_written;
	int bytes_written_total = 0;

	/* the buffer is free to write - write as much as possible */
	list_for_each_safe(it, tmp, &con->cmds) {
		cmd = list_entry(it, struct jsonrpc_cmd, list);

		if (cmd->state != JSONRPC_REQ_NEW)
			continue;

		/* try to write */
		do {
			bytes_written = send(con->fd,
				cmd->job->message.s, cmd->job->message.len, 0);
		} while (bytes_written < -1 && errno == EINTR);
		if (bytes_written < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				LM_ERR("error while writing on connection to %s:%hu\n",
						JSONRPC_ADDR(con));
				goto error_free;
			} else
				break; /* check to see if there was anything written */
		} else if (bytes_written == 0) {
			LM_ERR("remote connection closed while trying to write to %s:%hu!\n",
						JSONRPC_ADDR(con));
		}
		/* there was a success */
		bytes_written_total += bytes_written;
		cmd->job->message.s += bytes_written;
		cmd->job->message.len -= bytes_written;

		/* if there's more to write from this command, return now */
		if (cmd->job->message.len)
			return;

		/* otherwise, reply to this command and try a different command */
		cmd->state = JSONRPC_REQ_SENT;
		con->pending_writes--;

		/* if sync mode was not used, we don't really care about the reply,
		 * so we simply discard the job right here */
		if (!jsonrpc_sync_mode) {
			list_del(&cmd->list);
			jsonrpc_cmd_free(cmd);
		}
	}

	if (bytes_written_total == 0) {
		LM_ERR("con fd %d in reactor but nothing was written to %s:%hu!\n",
				con->fd, JSONRPC_ADDR(con));
		goto error_free;
	}

	/* if there were no writes pending, remove from reactor and don't do
	 * anything else */
	if (con->pending_writes == 0) {
		if (reactor_del_writer(con->fd, con->id, 0) < 0)
			LM_ERR("cannot remove %d fd from writer reactor!\n", con->fd);
	}
	/* all done ! */
	return;

error_free:
	jsonrpc_con_free(con);
}

static int handle_io(struct fd_map *fm, int idx, int event_type)
{
	jsonrpc_send_t *jsonrpcs;
	struct jsonrpc_con *con;

	switch (fm->type) {
		case F_EV_JSONRPC_CMD:
			jsonrpcs = jsonrpc_receive();
			if (!jsonrpcs) {
				LM_ERR("invalid receive jsonrpc command\n");
				return -1;
			}

			handle_new_jsonrpc(jsonrpcs);
			break;
		case F_EV_JSONRPC_RPL:
			con = (struct jsonrpc_con *)fm->data;
			if (event_type == IO_WATCH_READ)
				handle_reply_jsonrpc(con);
			else
				handle_write_jsonrpc(con);
			break;
		default:
			LM_CRIT("unknown fd type %d in JSON-RPC handler\n", fm->type);
			return 0;
	}
	return 0;
}

static void jsonrpc_cleanup_old(void)
{
	struct list_head *it_con, *it_cmd, *tmp;
	struct jsonrpc_cmd *cmd;
	struct jsonrpc_con *con;

	/* goes through each command and times it out */
	list_for_each(it_con, &jsonrpc_conns) {
		con = list_entry(it_con, struct jsonrpc_con, list);
		list_for_each_safe(it_cmd, tmp, &con->cmds) {
			cmd = list_entry(it_cmd, struct jsonrpc_cmd, list);
			if (get_time_diff(&cmd->job->time) > jsonrpc_timeout * 1000) {
				if (jsonrpc_sync_mode)
					jsonrpc_cmd_reply(cmd, JSONRPC_SEND_FAIL);
				list_del(&cmd->list);
				LM_INFO("Handling JSON-RPC command [%.*s] timed out!\n",
						cmd->job->message.len, cmd->job->message.s);
				jsonrpc_cmd_free(cmd);
			}
		}
	}
}


void jsonrpc_process(int rank)
{

	if (init_worker_reactor("JSON-RPC Sender", RCT_PRIO_MAX) != 0) {
		LM_BUG("failed to init JSON-RPC reactor");
		abort();
	}
	jsonrpc_init_reader();

	if (reactor_add_reader(jsonrpc_pipe[0], F_EV_JSONRPC_CMD, RCT_PRIO_ASYNC, NULL)<0){
		LM_CRIT("failed to add jsonrpc pipe to reactor\n");
		abort();
	}

	reactor_main_loop(JSONRPC_REACTOR_TIMEOUT, out_err, jsonrpc_cleanup_old());

out_err:
	destroy_io_wait(&_worker_io);
	abort();
}
