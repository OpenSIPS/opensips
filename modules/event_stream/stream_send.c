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
#include "stream_send.h"
#include "event_stream.h"
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>
#include "../../lib/list.h"


#define JSONRPC_REQ_NEW		0
#define JSONRPC_REQ_SENT	1
#define STREAM_REACTOR_TIMEOUT  1 /* sec */
#define STREAM_SEND_SUCCESS 0
#define STREAM_SEND_FAIL -1
#define STREAM_MAX_PENDING_READS 4
#define IS_ERR(_err) (errno == _err)
#define STREAM_ADDR(con) \
	inet_ntoa(con->addr.sin.sin_addr), ntohs(con->addr.sin.sin_port)

int stream_timeout = STREAM_DEFAULT_TIMEOUT;
char *stream_event_param;
unsigned stream_sync_mode = 0;
static int jrpc_id_index = 0;

/* used to communicate with the sending process */
static int stream_pipe[2];

struct stream_con {
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
	stream_send_t *job;
	struct list_head list;
};

struct list_head stream_conns;

/* creates communication pipe */
static int stream_create_pipe(void)
{
	int rc;

	stream_pipe[0] = stream_pipe[1] = -1;
	/* create pipe */
	do {
		rc = pipe(stream_pipe);
	} while (rc < 0 && IS_ERR(EINTR));

	if (rc < 0) {
		LM_ERR("cannot create status pipe [%d:%s]\n", errno, strerror(errno));
		return -1;
	}

	return 0;
}

int stream_init_process(void)
{
	INIT_LIST_HEAD(&stream_conns);

	return stream_create_pipe();
}

void stream_destroy_pipe(void)
{
	if (stream_pipe[0] != -1)
		close(stream_pipe[0]);
	if (stream_pipe[1] != -1)
		close(stream_pipe[1]);
}

int stream_send(stream_send_t* streams)
{
	int rc, retries = STREAM_SEND_RETRY;
	long send_status;

	streams->process_idx = process_no;

	do {
		rc = write(stream_pipe[1], &streams, sizeof(stream_send_t *));
	} while (rc < 0 && (IS_ERR(EINTR) || retries-- > 0));

	if (rc < 0) {
		LM_ERR("unable to send jsonrpc send struct to worker\n");
		shm_free(streams);
		return STREAM_SEND_FAIL;
	}
	/* give a chance to the writer :) */
	sched_yield();

	if (stream_sync_mode) {
		if (ipc_recv_sync_reply((void **)(long *)&send_status) < 0) {
			LM_ERR("cannot receive send status\n");
			send_status = STREAM_SEND_FAIL;
		}

		return (int)send_status;
	} else
		return STREAM_SEND_SUCCESS;
}

static stream_send_t * stream_receive(void)
{
	static stream_send_t * recv;
	int rc;
	int retries = STREAM_SEND_RETRY;

	if (stream_pipe[0] == -1)
		return NULL;

	do {
		rc = read(stream_pipe[0], &recv, sizeof(stream_send_t*));
	} while (rc < 0 && (IS_ERR(EINTR) || retries-- > 0));

	if (rc < 0) {
		LM_ERR("cannot receive send param\n");
		return NULL;
	}
	return recv;
}

int stream_init_writer(void)
{
	int flags;

	if (stream_pipe[0] != -1) {
		close(stream_pipe[0]);
		stream_pipe[0] = -1;
	}

	if (stream_sync_mode) {
		/* initilize indexes */
		jrpc_id_index = my_pid() & USHRT_MAX;
		jrpc_id_index |= rand() << sizeof(unsigned short);
	}

	/* Turn non-blocking mode on for sending*/
	flags = fcntl(stream_pipe[1], F_GETFL);
	if (flags == -1) {
		LM_ERR("fcntl failed: %s\n", strerror(errno));
		goto error;
	}
	if (fcntl(stream_pipe[1], F_SETFL, flags | O_NONBLOCK) == -1) {
		LM_ERR("fcntl: set non-blocking failed: %s\n", strerror(errno));
		goto error;
	}

	return 0;
error:
	close(stream_pipe[1]);
	stream_pipe[1] = -1;
	return -1;
}

static void jsonrpc_init_reader(void)
{
	if (stream_pipe[1] != -1) {
		close(stream_pipe[1]);
		stream_pipe[1] = -1;
	}
}


static inline int jsonrpc_unique_id(void)
{
	if (!stream_sync_mode)
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

static stream_send_t *stream_build_send_t(evi_reply_sock *sock,
		char *json, int id)
{
	int jlen = strlen(json);
	int len = sizeof(stream_send_t) + jlen;

	stream_send_t *msg = shm_malloc(len);
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
int stream_build_buffer(str *event_name, evi_reply_sock *sock,
		evi_params_t *params, stream_send_t ** msg)
{
	char *s;
	int id = jsonrpc_unique_id();
	str *method = (sock->flags & EVI_PARAMS ? (str *)sock->params: event_name);
	str extra_param = {0,0};

	if (stream_event_param)
		init_str(&extra_param, stream_event_param);

	s = evi_build_payload(params, method, stream_sync_mode ? id : 0,
		extra_param.s ? &extra_param : NULL, extra_param.s ? event_name : NULL);
	if (!s) {
		LM_ERR("Failed to build event payload %.*s\n", event_name->len, event_name->s);
		return -1;
	}

	*msg = stream_build_send_t(sock, s, id);
	if (!*msg) {
		LM_ERR("cannot build send msg\n");
		evi_free_payload(s);
		return -1;
	}

	evi_free_payload(s);

	return 0;
}

static struct stream_con *stream_get_con(union sockaddr_union *addr)
{
	struct stream_con *con;
	struct list_head *it;

	list_for_each(it, &stream_conns) {
		con = list_entry(it, struct stream_con, list);
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

static struct stream_con *stream_new_con(union sockaddr_union *addr)
{
	struct stream_con *con;
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

	list_add(&con->list, &stream_conns);
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

	if (!stream_sync_mode)
		return;

	jsonrpc_cmd_write(cmd->job->process_idx, send_status);
}

static void stream_con_free(struct stream_con *con)
{
	struct list_head *it, *tmp;
	struct jsonrpc_cmd *cmd;

	if (con->pending_writes != 0)
		reactor_del_all(con->fd, con->id, 0);
	else
		reactor_del_reader(con->fd, con->id, 0);
	if (con->pending_buffer.len)
		pkg_free(con->pending_buffer.s);

	if (stream_sync_mode) {
		/* in sync mode, we need to send back error */
		list_for_each_safe(it, tmp, &con->cmds) {
			cmd = list_entry(it, struct jsonrpc_cmd, list);
			jsonrpc_cmd_reply(cmd, STREAM_SEND_FAIL);
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


static void handle_new_stream(stream_send_t *stream)
{
	struct stream_con *con;
	struct jsonrpc_cmd *cmd;

	/* reuse ongoing connections */
	con = stream_get_con(&stream->addr);
	if (!con) {
		con = stream_new_con(&stream->addr);
		if (!con) {
			LM_ERR("cannot create new connection!\n");
			goto error;
		}
	}

	/* send the message */
	cmd = pkg_malloc(sizeof *cmd);
	if (!cmd) {
		LM_ERR("cannot create new JSON-RPC command to %s:%hu!\n", STREAM_ADDR(con));
		goto error;
	}
	con->pending_writes++;
	cmd->state = JSONRPC_REQ_NEW;
	cmd->job = stream;
	list_add_tail(&cmd->list, &con->cmds);

	if (con->pending_writes == 1 /* first write pending */) {
		if (reactor_add_writer(con->fd, F_EV_JSONRPC_RPL, RCT_PRIO_ASYNC, con)<0){
			LM_CRIT("failed to add write event_stream connection to reactor\n");
			stream_con_free(con);
			return;
		}
	}

error:
	if (stream_sync_mode) {
		/* we need to notify the process that the connection failed! */
		jsonrpc_cmd_write(stream->process_idx, STREAM_SEND_FAIL);
	}
}

static int handle_cmd_reply(struct stream_con *con, cJSON *reply)
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
	ret = (aux ? STREAM_SEND_FAIL : STREAM_SEND_SUCCESS);

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

static void handle_reply_jsonrpc(struct stream_con *con)
{
	/* got a reply on the connection */
	str buf;
	cJSON *reply;
	int bytes_read;
	const char *end;
	char buffer[STREAM_BUFFER_SIZE + 1];

	do {
		bytes_read = read(con->fd, buffer, STREAM_BUFFER_SIZE);
	} while (bytes_read == -1 && errno == EINTR);
	if (bytes_read < 0) {
		LM_ERR("error while reading reply from %s:%hu\n", STREAM_ADDR(con));
		goto error;
	} else if (bytes_read == 0) {
			LM_INFO("connection to %s:%hu closed!\n", STREAM_ADDR(con));
		goto error;
	}

	/* if not in sync mode, no one listens for the reply */
	if (stream_sync_mode == 0)
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
				if (con->pending_reads > STREAM_MAX_PENDING_READS) {
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
	stream_con_free(con);
}

static void handle_write_jsonrpc(struct stream_con *con)
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
						STREAM_ADDR(con));
				goto error_free;
			} else
				break; /* check to see if there was anything written */
		} else if (bytes_written == 0) {
			LM_ERR("remote connection closed while trying to write to %s:%hu!\n",
						STREAM_ADDR(con));
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
		if (!stream_sync_mode) {
			list_del(&cmd->list);
			jsonrpc_cmd_free(cmd);
		}
	}

	if (bytes_written_total == 0) {
		LM_ERR("con fd %d in reactor but nothing was written to %s:%hu!\n",
				con->fd, STREAM_ADDR(con));
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
	stream_con_free(con);
}

static int handle_io(struct fd_map *fm, int idx, int event_type)
{
	stream_send_t *jsonrpcs;
	struct stream_con *con;

	switch (fm->type) {
		case F_EV_JSONRPC_CMD:
			jsonrpcs = stream_receive();
			if (!jsonrpcs) {
				LM_ERR("invalid receive jsonrpc command\n");
				return -1;
			}

			handle_new_stream(jsonrpcs);
			break;
		case F_EV_JSONRPC_RPL:
			con = (struct stream_con *)fm->data;
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

static void stream_cleanup_old(void)
{
	struct list_head *it_con, *it_cmd, *tmp;
	struct jsonrpc_cmd *cmd;
	struct stream_con *con;

	/* goes through each command and times it out */
	list_for_each(it_con, &stream_conns) {
		con = list_entry(it_con, struct stream_con, list);
		list_for_each_safe(it_cmd, tmp, &con->cmds) {
			cmd = list_entry(it_cmd, struct jsonrpc_cmd, list);
			if (get_time_diff(&cmd->job->time) > stream_timeout * 1000) {
				if (stream_sync_mode)
					jsonrpc_cmd_reply(cmd, STREAM_SEND_FAIL);
				list_del(&cmd->list);
				LM_INFO("Handling JSON-RPC command [%.*s] timed out!\n",
						cmd->job->message.len, cmd->job->message.s);
				jsonrpc_cmd_free(cmd);
			}
		}
	}
}


void stream_process(int rank)
{

	if (init_worker_reactor("event_stream Sender", RCT_PRIO_MAX) != 0) {
		LM_BUG("failed to init event_stream reactor");
		abort();
	}
	jsonrpc_init_reader();

	if (reactor_add_reader(stream_pipe[0], F_EV_JSONRPC_CMD, RCT_PRIO_ASYNC, NULL)<0){
		LM_CRIT("failed to add event_stream pipe to reactor\n");
		abort();
	}

	reactor_main_loop(STREAM_REACTOR_TIMEOUT, out_err, stream_cleanup_old());

out_err:
	destroy_io_wait(&_worker_io);
	abort();
}
