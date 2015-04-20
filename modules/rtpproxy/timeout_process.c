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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

#include "rtpproxy.h"

#if !defined(AF_LOCAL)
#define AF_LOCAL AF_UNIX
#endif

#define BUF_LEN				255
#define POLL_DEFAULT_SIZE	8

void update_rtpproxy_list(void);

int socket_fd;
int nfds = 0;
int nr_events;
int pfds_size = POLL_DEFAULT_SIZE;
struct pollfd* pfds;

#define IS_DIGIT(_c) ((_c) >= '0' && (_c) <= '9')

void timeout_listener_process(int rank)
{
	struct sockaddr_un saddr_un;
	struct sockaddr_un *s_un;
	struct sockaddr_in saddr_in;
	struct sockaddr_in *s_in;
	struct sockaddr_in6 *s_in6;
	int connect_fd;
	char buffer[BUF_LEN];
	char *p, *sp, *end, *start;
	unsigned int h_entry, h_id;
	str id;
	unsigned short port;
	struct sockaddr* saddr;
	int len, i,n, left;
	int optval = 1;
	struct sockaddr rtpp_info;
	struct rtpp_notify_node *rtpp_lst;
	str terminate_reason = str_init("RTPProxy Timeout");
	int offset = 0;

	if (init_child(PROC_MODULE) != 0) {
		LM_ERR("cannot init child process");
		return;
	}

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

	pfds = (struct pollfd *)pkg_malloc(pfds_size*sizeof(struct pollfd));
	if (!pfds) {
		LM_ERR("no more pkg memory\n");
		return;
	}
	pfds[0].fd = socket_fd;
	pfds[nfds++].events = POLLIN;

	for(;;) {
		nr_events = poll(pfds, nfds, -1);
		if (nr_events < 0)
			continue;

		/* check if the rtpproxy list needs updates */
		lock_get(rtpp_notify_h->lock);
		if (rtpp_notify_h->changed) {
			/* update list */
			update_rtpproxy_list();
			rtpp_notify_h->changed = 0;
		}
		lock_release(rtpp_notify_h->lock);

		rtpp_lst = NULL;
		/* there is a new connection */
		if (pfds[0].revents & POLLIN) {
			i = sizeof(rtpp_info);
			memset(&rtpp_info, 0, i);
			connect_fd = accept(socket_fd, &rtpp_info, (socklen_t *)&i);
			if(connect_fd < 0) {
				LM_ERR("socket accept failed: %s(%d)\n", strerror(errno), errno);
				continue;
			}

			/* if it is a unix socket, try to authenticate it */
			if (rtpp_info.sa_family == AF_UNIX) {
				s_un = (struct sockaddr_un*)&rtpp_info;
				/* check if the socket is already opened */
				lock_get(rtpp_notify_h->lock);
				for (rtpp_lst = rtpp_notify_h->rtpp_list; rtpp_lst; rtpp_lst = rtpp_lst->next)
					if ( rtpp_lst->mode == 0 && !strcmp(rtpp_lst->addr, s_un->sun_path))
						break;

				/* if not found add a new one */
				if (!rtpp_lst) {
					/* leave the lock for a moment */
					lock_release(rtpp_notify_h->lock);
					rtpp_lst = (struct rtpp_notify_node*)
						shm_malloc(sizeof(struct rtpp_notify_node));
					if (!rtpp_lst) {
						LM_ERR("no shm more memory\n");
						return;
					}
					rtpp_lst->index = 0;
					rtpp_lst->mode = 0;
					rtpp_lst->addr = 0;

					/* copy the socket name */
					len = strlen(s_un->sun_path);
					rtpp_lst->addr = (char *)shm_malloc(len + 1);
					if (!rtpp_lst->addr) {
						LM_ERR("no more shm memory\n");
						return;
					}
					memcpy(rtpp_lst->addr, s_un->sun_path, len + 1);

					lock_get(rtpp_notify_h->lock);
					rtpp_lst->next = rtpp_notify_h->rtpp_list;
					rtpp_notify_h->rtpp_list = rtpp_lst;
				}
			} else {
				/* search if I can find this connection */
				if (rtpp_info.sa_family == AF_INET) {
					s_in = (struct sockaddr_in*)&rtpp_info;
					lock_get(rtpp_notify_h->lock);
					for (rtpp_lst = rtpp_notify_h->rtpp_list; rtpp_lst; rtpp_lst = rtpp_lst->next)
						if (rtpp_lst->mode == 1 &&
							memcmp(rtpp_lst->addr, &s_in->sin_addr.s_addr, 4) == 0)
							break;
				} else if (rtpp_info.sa_family == AF_INET6) {
					s_in6 = (struct sockaddr_in6*)&rtpp_info;
					lock_get(rtpp_notify_h->lock);
					for (rtpp_lst = rtpp_notify_h->rtpp_list; rtpp_lst; rtpp_lst = rtpp_lst->next)
						if (rtpp_lst->mode == 6 &&
							memcmp(rtpp_lst->addr, s_in6->sin6_addr.s6_addr, 16) == 0)
							break;
				} else {
					LM_ERR("cannot accept this type of connection\n");
				}
			}

			if (!rtpp_lst) {
				lock_release(rtpp_notify_h->lock);
				LM_DBG("unknown rtpproxy -- ignoring\n");
				shutdown(connect_fd, SHUT_RDWR);
				close(connect_fd);
			} else {
				/* valid connection - checking if already connected */
				if (rtpp_lst->index) {
					LM_DBG("rtpproxy restarted - update connection status\n");
					shutdown(rtpp_lst->fd, SHUT_RDWR);
					close(rtpp_lst->fd);
				} else {
					rtpp_lst->index = nfds++;
					if (nfds > pfds_size) {
						pfds_size *= 2;
						pfds = (struct pollfd*)pkg_realloc(pfds,
								pfds_size*sizeof(struct pollfd));
					}
				}

				LM_DBG("rtpproxy accepted\n");
				pfds[rtpp_lst->index].fd = connect_fd;
				pfds[rtpp_lst->index].events = POLLIN;
				rtpp_lst->fd = connect_fd;
				lock_release(rtpp_notify_h->lock);
			}
			nr_events--;
		}

		for (i=1; (nr_events && i<nfds); i++)
		{
			if (!(pfds[i].revents & POLLIN))
				continue;
			nr_events--;

			do
				len = read(pfds[i].fd, buffer + offset, BUF_LEN - offset);
			while (len == -1 && errno == EINTR);

			if (len < 0) {
				LM_ERR("reading from socket failed: %s\n",strerror(errno));
				continue;
			}

			if (!len) {
				LM_DBG("closing rtpproxy\n");
				lock_get(rtpp_notify_h->lock);
				for (rtpp_lst=rtpp_notify_h->rtpp_list;
						rtpp_lst;rtpp_lst=rtpp_lst->next)
					if (rtpp_lst->index == i)
						break;
				if (!rtpp_lst) {
					LM_ERR("BUG - rtpproxy not found\n");
					lock_release(rtpp_notify_h->lock);
					continue;
				}
				rtpp_lst->index = 0;
				lock_release(rtpp_notify_h->lock);
				nfds--;
				shutdown(pfds[i].fd, SHUT_RDWR);
				close(pfds[i].fd);

				if (nfds == i)
					continue;

				pfds[i].fd = pfds[nfds].fd;
				lock_get(rtpp_notify_h->lock);
				for (rtpp_lst=rtpp_notify_h->rtpp_list; rtpp_lst; rtpp_lst=rtpp_lst->next)
					if (rtpp_lst->index == nfds)
						break;
				if (!rtpp_lst) {
					LM_ERR("BUG - rtpproxy index mismatch\n");
					lock_release(rtpp_notify_h->lock);
					continue;
				}
				rtpp_lst->index = i;
				lock_release(rtpp_notify_h->lock);
				continue;
			}
			LM_INFO("Timeout detected on the following calls [%.*s]\n", len, buffer);
			p = buffer;
			left = len + offset;
			offset = 0;
			end = buffer + left;

			do {
				start = p;
				/* the message is: h_entry.h_id\n */
				sp = memchr(p, '.', left);
				if (sp == NULL)
					break;

				id.s = p;
				id.len = sp - p;

				if (sp >= end)
					break;

				p = sp + 1;
				left -= id.len + 1;

				if(str2int(&id, &h_entry)< 0) {
					LM_ERR("Wrong formated message received from rtpproxy - invalid"
							" dialog entry [%.*s]\n", id.len, id.s);
					break;
				}

				sp = memchr(p, '\n', left);
				if (sp == NULL)
					break;

				id.s = p;
				id.len = sp - p;

				if (sp >= end)
					break;

				p = sp + 1;
				left -= id.len + 1;

				if(str2int(&id, &h_id)< 0) {
					LM_ERR("Wrong formated message received from rtpproxy - invalid"
							" dialog id [%.*s]\n", id.len, id.s);
					break;
				}
				LM_DBG("hentry = %u, h_id = %u\n", h_entry, h_id);

				if(dlg_api.terminate_dlg(h_entry, h_id,&terminate_reason)< 0)
					LM_ERR("Failed to terminate dialog h_entry=[%u], h_id=[%u]\n", h_entry, h_id);

				LM_DBG("Left to process: %d\n[%.*s]\n", left, left, p);

			} while (p < end);

			offset = end - start;
			memmove(buffer, start, end - start);
		}
	}
}


struct rtpp_notify_node *new_rtpp_notify_node(struct rtpp_node *crt_rtpp)
{
	char buffer[BUF_LEN];
	char *p;
	struct hostent *rtpp_server;
	struct rtpp_notify_node *rtpp_lst;

	rtpp_lst = (struct rtpp_notify_node*)
		shm_malloc(sizeof(struct rtpp_notify_node));
	if (!rtpp_lst) {
		LM_ERR("no shm more memory\n");
		return NULL;
	}

	rtpp_lst->mode = crt_rtpp->rn_umode;
	rtpp_lst->index = 0;
	rtpp_lst->next = NULL;
	memcpy(buffer,crt_rtpp->rn_address,strlen(crt_rtpp->rn_address) + 1);
	p = strrchr(buffer, ':');
	if (!p) {
		LM_ERR("invalid address %s\n", crt_rtpp->rn_address);
		goto error;
	}
	*p = 0;

	rtpp_server = resolvehost(buffer, 0);
	if (!rtpp_server || !rtpp_server->h_addr) {
		LM_ERR("cannot resolve hostname %s\n", crt_rtpp->rn_address);
		goto error;
	}

	rtpp_lst->addr = (char*)shm_malloc(rtpp_server->h_length);
	if (!rtpp_lst->addr) {
		LM_ERR("no more shm memory\n");
		goto error;
	}
	memcpy(rtpp_lst->addr,rtpp_server->h_addr,rtpp_server->h_length);
	return rtpp_lst;

error:
	shm_free(rtpp_lst);
	return NULL;

}


int init_rtpp_notify_list(void)
{
	struct rtpp_set * rtpp_list;
	struct rtpp_node * crt_rtpp;
	struct rtpp_notify_node *rtpp_lst=NULL;

	if (!(*rtpp_set_list) || !(*rtpp_set_list)->rset_first) {
		LM_DBG("null rtpproxy set list\n");
		return 0;
	}

	for(rtpp_list = (*rtpp_set_list)->rset_first; rtpp_list != NULL;
			rtpp_list = rtpp_list->rset_next) {
		for(crt_rtpp = rtpp_list->rn_first; crt_rtpp != NULL;
				crt_rtpp = crt_rtpp->rn_next) {
			/* if it is an unix sock - don't put it in the list */
			if (!crt_rtpp->rn_umode)
				continue;

			rtpp_lst = new_rtpp_notify_node(crt_rtpp);
			if (!rtpp_lst) {
				LM_ERR("cannot add rtpproxy to list\n");
				return -1;
			}

			rtpp_lst->next = rtpp_notify_h->rtpp_list;
			rtpp_notify_h->rtpp_list = rtpp_lst;

		}
	}

	return 0;
}

int compare_rtpp(struct rtpp_node *r_node, struct rtpp_notify_node *n_node)
{
	char buffer[BUF_LEN];
	char *p;
	struct hostent *rtpp_server;

	if (r_node->rn_umode != n_node->mode)
		return 0;

	memcpy(buffer,r_node->rn_address,strlen(r_node->rn_address));
	p = strrchr(buffer, ':');
	if (!p) {
		LM_ERR("invalid address %s\n", r_node->rn_address);
		return 0;
	}
	*p = 0;

	rtpp_server = resolvehost(buffer, 0);
	if (!rtpp_server || !rtpp_server->h_addr) {
		LM_ERR("cannot resolve hostname %s\n", r_node->rn_address);
		return 0;
	}

	if (memcmp(n_node->addr, rtpp_server->h_addr, rtpp_server->h_length)!= 0)
		return 0;
	return 1;
}

void update_rtpproxy_list(void)
{
	struct rtpp_set * rtpp_list;
	struct rtpp_node * crt_rtpp;
	struct rtpp_notify_node *rtpp_lst, *r_prev, *rl;

	if (!rtpp_set_list || !(*rtpp_set_list)) {
		LM_DBG("no rtpproxy set\n");
		return;
	}
	LM_DBG("updating rtppproxy list\n");

	/* add new rtppproxies */
	for(rtpp_list = (*rtpp_set_list)->rset_first; rtpp_list != NULL;
			rtpp_list = rtpp_list->rset_next) {
		for(crt_rtpp = rtpp_list->rn_first; crt_rtpp != NULL;
				crt_rtpp = crt_rtpp->rn_next) {
			/* if it is an unix sock - don't do anything */
			if (!crt_rtpp->rn_umode)
				continue;

			/* search if it already exists */
			for (rtpp_lst=rtpp_notify_h->rtpp_list;
					rtpp_lst; rtpp_lst=rtpp_lst->next)
				if (compare_rtpp(crt_rtpp, rtpp_lst))
					break;

			if (!rtpp_lst) {
				/* if it doesn't exist add a new one */
				rtpp_lst = new_rtpp_notify_node(crt_rtpp);
				if (!rtpp_lst) {
					LM_ERR("cannot add rtpproxy to list\n");
					return;
				}
				rtpp_lst->next = rtpp_notify_h->rtpp_list;
				rtpp_notify_h->rtpp_list = rtpp_lst;
			}
		}
	}

	/* search for deleted rtpproxies */
	r_prev = NULL;
	rtpp_lst=rtpp_notify_h->rtpp_list;
	while (rtpp_lst) {
		/* don't update for unix sockets */
		if (rtpp_lst->mode == 0)
			goto loop;
		for(rtpp_list = (*rtpp_set_list)->rset_first; rtpp_list != NULL;
				rtpp_list = rtpp_list->rset_next) {
			for(crt_rtpp = rtpp_list->rn_first; crt_rtpp != NULL;
						crt_rtpp = crt_rtpp->rn_next) {
				/* if not the same type */
				if (crt_rtpp->rn_umode != rtpp_lst->mode)
					continue;

				if (compare_rtpp(crt_rtpp, rtpp_lst))
					goto loop;
			}
		}

		/* if it gets here it means we couldn't find the old rtpproxy */
		LM_DBG("removing rtpproxy %s\n",
				inet_ntoa(*(struct in_addr*)rtpp_lst->addr));
		/* remove fd from poll vector */
		if (rtpp_lst->index) {
			if (pfds[rtpp_lst->index].revents & POLLIN)
				nr_events--;
			nfds--;
			if (nfds != rtpp_lst->index) {
				pfds[rtpp_lst->index].fd = pfds[nfds].fd;
				pfds[rtpp_lst->index].revents = pfds[nfds].revents;
				for (rl=rtpp_notify_h->rtpp_list; rl; rl=rl->next)
					if (rl->index == nfds)
						break;
				if (!rtpp_lst) {
					LM_ERR("BUG - rtpproxy index mismatch\n");
					return;
				}
				rl->index = rtpp_lst->index;
			}
			/* close connection */
			shutdown(rtpp_lst->fd, SHUT_RDWR);
			close(rtpp_lst->fd);
		}

		/* remove it from the list */
		if (!r_prev)
			rtpp_notify_h->rtpp_list = rtpp_lst->next;
		else
			r_prev->next = rtpp_lst->next;
		shm_free(rtpp_lst);
		/* r_prev remains the same */
		rtpp_lst = r_prev ? r_prev->next : rtpp_notify_h->rtpp_list;
		continue;

loop:
		r_prev = rtpp_lst;
		rtpp_lst = rtpp_lst->next;
	}

}
