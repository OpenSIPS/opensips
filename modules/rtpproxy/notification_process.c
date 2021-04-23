/*
 * Copyright (C) 2010 Voice System
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
 * ---------
 *  Initial version 02-04-2010 (Anca Vamanu)
*/
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include "../../dprint.h"
#include "../../ut.h"
#include "../../trim.h"
#include "../../resolve.h"
#include "../../pt.h"
#include "../../sr_module.h"
#include "../../reactor_defs.h"
#include "../../reactor_proc.h"
#include "../../io_wait.h"
#include "../../lib/list.h"

#include "rtpproxy.h"

#if !defined(AF_LOCAL)
#define AF_LOCAL AF_UNIX
#endif

#define BUF_LEN				255

int *rtpp_notify_process_no;

#define IS_DIGIT(_c) ((_c) >= '0' && (_c) <= '9')

struct rtpp_notify {
	int fd;
	char *remaining;
	int remaining_len;
	union sockaddr_union addr;
	struct list_head list;
};
OSIPS_LIST_HEAD(rtpp_notify_fds);

static int notification_handler(str *command)
{
	char cmd, *p;
	str param, token;
	unsigned int h_entry, h_id, is_callid = 0;
	struct rtpp_dtmf_event dtmf;
	str terminate_reason = str_init("RTPProxy Timeout");

	if (command->len < 1) {
		LM_ERR("no command received from RTPProxy!\n");
		return -1;
	}
	cmd = command->s[0];
	param.s = command->s + 1;
	param.len = command->len - 1;
	LM_DBG("Handling RTPProxy command %c %.*s\n", cmd, param.len, param.s);
	switch (cmd) {
		case 'I':
			/* we are not listening for timeout notifications */
			return 0;
		case 'T':
			LM_INFO("Timeout notification for %.*s\n", param.len, param.s);
			if (parse_dlg_did(&param, &h_entry, &h_id) < 0)
				return -1;
			if(dlg_api.terminate_dlg(NULL, h_entry, h_id, &terminate_reason)< 0)
				LM_ERR("Failed to terminate dialog h_entry=[%u], h_id=[%u]\n", h_entry, h_id);
			return 0;
		case 'D':
			p = q_memchr(param.s, ' ' ,param.len);
			if (!p) {
				LM_ERR("could not determine the notification id in %.*s!\n",
						param.len, param.s);
				return -1;
			}
			token.s = param.s + 1;
			token.len = p - token.s;
			if (*param.s == 'c')
				is_callid = 1;

			param.s = p + 1;
			param.len -= token.len + 2;

			if (param.len < 0) {
				LM_ERR("could not get digit in param %.*s!\n", param.len, param.s);
				return -1;
			}

			memset(&dtmf, 0, sizeof dtmf);
			dtmf.is_callid = is_callid;
			dtmf.id = token;

			dtmf.digit = *param.s;

			param.s += 2;
			param.len -= 2;

			if (param.len > 0) {
				p = q_memchr(param.s, ' ', param.len);
				if (p) {
					token.s = param.s;
					token.len = p - param.s;
					if (str2int(&token, &dtmf.volume) < 0)
						dtmf.volume = 0;

					param.s = p + 1;
					param.len -= token.len + 1;
					if (param.len >= 0) {
						p = q_memchr(param.s, ' ', param.len);
						if (p) {
							/* we got both duration and stream */
							token.s = p + 1;
							token.len = param.len - (token.s - param.s);

							param.len -= token.len + 1;
							if (param.len >= 0 && str2int(&token, &dtmf.stream) < 0)
								dtmf.stream = 0;
						}
						if (str2int(&param, &dtmf.duration) < 0)
							dtmf.duration = 0;
					}
				}
			}
			LM_INFO("got event %c volume=%u duration=%u stream=%u for %.*s\n",
					dtmf.digit, dtmf.volume, dtmf.duration, dtmf.stream,
					dtmf.id.len, dtmf.id.s);
			rtpproxy_raise_dtmf_event(&dtmf);

			return 0;
		default:
			LM_WARN("Unhandled command %c param=%.*s\n", cmd, param.len, param.s);
			return 0;
	}
}

static int compare_sa(struct sockaddr *s1, struct sockaddr *s2)
{
	if (s1->sa_family != s2->sa_family)
		return 1;
	if (s1->sa_family == AF_INET &&
			memcmp(&((struct sockaddr_in *)s1)->sin_addr,
				&((struct sockaddr_in *)s2)->sin_addr, 4) != 0)
		return 2;
	if (s1->sa_family == AF_INET6 &&
			memcmp(&((struct sockaddr_in6 *)s1)->sin6_addr,
				&((struct sockaddr_in6 *)s2)->sin6_addr, 16) != 0)
		return 3;
	return 0;
}

static struct rtpp_node *rtpproxy_get_node(union sockaddr_union *rtpp_info)
{
	struct rtpp_set * rtpp_list;
	struct rtpp_node *crt_rtpp;

	if (!rtpp_set_list || !(*rtpp_set_list))
		return NULL;

	if (nh_lock)
		lock_start_read( nh_lock );
	for (rtpp_list = (*rtpp_set_list)->rset_first; rtpp_list != NULL;
			rtpp_list = rtpp_list->rset_next) {
		for(crt_rtpp = rtpp_list->rn_first; crt_rtpp != NULL;
						crt_rtpp = crt_rtpp->rn_next) {
			if (crt_rtpp->rn_umode == CM_UNIX)
				continue;
			if (compare_sa(&crt_rtpp->addr.s, &rtpp_info->s) == 0) {
				if (nh_lock)
					lock_stop_read( nh_lock );
				return crt_rtpp;
			}
		}
	}
	if (nh_lock)
		lock_stop_read( nh_lock );
	return NULL;
}

static int rtpproxy_io_callback(int fd, void *fs, int was_timeout)
{
	struct rtpp_notify *notify = (struct rtpp_notify *)fs;
	char buffer[BUF_LEN];
	int len, left, offset;
	str command;
	char *p, *start, *sp, *end;

	if (notify && notify->remaining) {
		memcpy(buffer, notify->remaining, notify->remaining_len);
		offset = notify->remaining_len;
		pkg_free(notify->remaining);
		notify->remaining_len = 0;
		notify->remaining = NULL;
	} else {
		offset = 0;
	}

	do
		len = read(fd, buffer + offset, BUF_LEN - offset);
	while (len == -1 && errno == EINTR);

	if (len < 0) {
		LM_ERR("reading from socket failed: %s\n",strerror(errno));
		return -1;
	}
	if (len == 0) {
		LM_DBG("closing rtpproxy notify socket\n");
		reactor_del_reader(fd, -1, IO_FD_CLOSING);
		if (notify) {
			list_del(&notify->list);
			pkg_free(notify);
		}
		shutdown(fd, SHUT_RDWR);
		close(fd);
		return 0;
	}

	LM_DBG("Notification(s) received: [%.*s]\n", len, buffer);
	p = buffer;
	left = len + offset;
	end = buffer + left;

	do {
		start = p;

		sp = q_memchr(p, '\n', left);
		if (sp == NULL)
			break;
		command.s = p;
		command.len = sp - p;
		/* skip the command */
		p = sp + 1;
		left -= (sp - start) + 1;

		if (notification_handler(&command) < 0)
			return -1;

		LM_DBG("Left to process: %d\n[%.*s]\n", left, left, p);

	} while (p < end);

	if (end - p) {
		LM_DBG("%d remaining data in buffer!\n", (int)(end - start));
		if (notify && (notify->remaining = pkg_malloc(end - start)) != NULL) {
			notify->remaining_len = (int)(end - start);
			memcpy(notify->remaining, p, notify->remaining_len);
		} else {
			LM_WARN("dropping remaining data [%.*s]\n", (int)(end - start), start);
		}
	}
	return 0;
}

static int rtpproxy_io_new_callback(int fd, void *fs, int was_timeout)
{
	int size;
	struct sockaddr_storage rtpp_info;
	struct rtpp_node *node;
	struct rtpp_notify *notify;

	size = sizeof(rtpp_info);
	memset(&rtpp_info, 0, size);
	fd = accept(fd, (struct sockaddr *)&rtpp_info, (socklen_t *)&size);
	if(fd < 0) {
		LM_ERR("socket accept failed: %s(%d)\n", strerror(errno), errno);
		return -1;
	}

	if (rtpp_notify_socket_un) {
		LM_DBG("trusting unix socket connection\n");
		if (reactor_proc_add_fd(fd, rtpproxy_io_callback, NULL)<0) {
			LM_CRIT("failed to add RTPProxy new connection to reactor\n");
			return -1;
		}
		return 0;
	}
	node = rtpproxy_get_node((union sockaddr_union *)&rtpp_info);
	if (!node) {
		LM_WARN("connection from unknown RTPProxy node");
		return -1;
	}

	notify = pkg_malloc(sizeof *notify);
	if (!notify) {
		LM_ERR("could not allocate notify node\n");
		return -1;
	}
	memset(notify, 0, sizeof *notify);
	notify->fd = fd;
	memcpy(&notify->addr, &node->addr, sizeof(union sockaddr_union));
	if (reactor_proc_add_fd(fd, rtpproxy_io_callback, notify) < 0) {
		LM_CRIT("failed to add RTPProxy listen socket to reactor\n");
		pkg_free(notify);
		return -1;
	}
	list_add(&notify->list, &rtpp_notify_fds);
	return 0;
}

int init_rtpp_notify(void)
{
	rtpp_notify_process_no = shm_malloc(sizeof *rtpp_notify_process_no);
	if (!rtpp_notify_process_no) {
		LM_ERR("cannot allocate space for rtpp notify process number\n");
		return -1;
	}
	return 0;
}

void notification_listener_process(int rank)
{
	struct sockaddr_un saddr_un;
	struct sockaddr_in saddr_in;
	char *p;
	str id;
	unsigned short port;
	struct sockaddr* saddr;
	int len, n;
	int optval = 1;
	int socket_fd;

	*rtpp_notify_process_no = process_no;

	if (!rtpp_notify_socket_un) {
		p = strrchr(rtpp_notify_socket.s, ':');
		if (!p) {
			LM_ERR("invalid udp address <%.*s>\n", rtpp_notify_socket.len, rtpp_notify_socket.s);
			return;
		}
		n = p- rtpp_notify_socket.s;
		rtpp_notify_socket.s[n] = 0;

		id.s = p+1;
		id.len = rtpp_notify_socket.len - n -1;
		port= str2s(id.s, id.len, &n);
		if(n) {
			LM_ERR("Bad format for socket name. Expected ip:port\n");
			return;
		}
		/* skip here tcp part */
		rtpp_notify_socket.s += 4;
		memset(&saddr_in, 0, sizeof(saddr_in));
		saddr_in.sin_addr.s_addr = inet_addr(rtpp_notify_socket.s);
		saddr_in.sin_family = AF_INET;
		saddr_in.sin_port = htons(port);

		socket_fd = socket(AF_INET, SOCK_STREAM, 0);
		if (socket_fd == -1) {
			LM_ERR("can't create timeout socket\n");
			return;
		}
		saddr = (struct sockaddr*)&saddr_in;
		len = sizeof(saddr_in);
		LM_DBG("binding socket %d to %s:%d\n", socket_fd, rtpp_notify_socket.s, port);
	} else {
		/* create socket */
		socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (socket_fd == -1) {
			LM_ERR("Failed to create unix socket\n");
			return;
		}

		memset(&saddr_un, 0, sizeof(struct sockaddr_un));
		saddr_un.sun_family = AF_LOCAL;
		strncpy(saddr_un.sun_path, rtpp_notify_socket.s,
				sizeof(saddr_un.sun_path) - 1);
		saddr = (struct sockaddr*)&saddr_un;
		len = sizeof(saddr_un);
		LM_DBG("binding unix socket %s\n", rtpp_notify_socket.s);
	}

	if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, (void*)&optval,
				sizeof(optval)) == -1) {
		LM_ERR("setsockopt failed %s\n", strerror(errno));
		return;
	}

	if (bind(socket_fd, saddr, len) == -1) {
		LM_ERR("failed to bind to socket: %s\n", strerror(errno));
		return;
	}

	/* open socket for listening */
	if(listen(socket_fd, 10) == -1) {
		LM_ERR("socket listen failed: %s(%d)\n", strerror(errno), errno);
		close(socket_fd);
		return;
	}

	if (reactor_proc_init("RTPProxy events") < 0) {
		LM_ERR("failed to init the RTPProxy events\n");
		return;
	}

	if (reactor_proc_add_fd( socket_fd, rtpproxy_io_new_callback, NULL) < 0) {
		LM_CRIT("failed to add RTPProxy listen socket to reactor\n");
		return;
	}

	reactor_proc_loop();
}

static void ipc_update_rtpp_notify(int sender, void *param)
{
	struct list_head *it, *safe;
	struct rtpp_notify *notify;

	LM_INFO("updating RTPProxy notify handlers!\n");
	/* go through each handler and see if there's a corresponding rtpp node */
	list_for_each_safe(it, safe, &rtpp_notify_fds) {
		notify = list_entry(it, struct rtpp_notify, list);
		if (rtpproxy_get_node(&notify->addr) == NULL) {
			reactor_del_reader(notify->fd, -1, IO_FD_CLOSING);
			list_del(&notify->list);
			shutdown(notify->fd, SHUT_RDWR);
			close(notify->fd);
			if (notify->remaining)
				pkg_free(notify->remaining);
			pkg_free(notify);
		}
	}
}

void update_rtpp_notify(void)
{
	if (!rtpp_notify_process_no) {
		LM_WARN("RTPProxy process not initialized\n");
		return;
	}
	if (ipc_send_rpc(*rtpp_notify_process_no, ipc_update_rtpp_notify, NULL) != 0)
		LM_ERR("could not send RTPProxy update to notify process!\n");
}
