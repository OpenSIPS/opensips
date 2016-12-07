/*
 * Copyright (C) 2016 Razvan Crainea <razvan@opensips.org>
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

#include "cgrates_common.h"
#include "cgrates_engine.h"
#include "../../reactor_defs.h"
#include "../../net/net_tcp.h"
#include "../../resolve.h"
#include "../../async.h"

struct cgr_conn *cgr_get_free_conn(struct cgr_engine *e)
{
	struct list_head *l;
	struct cgr_conn *c;

	list_for_each(l, &e->conns) {
		c = list_entry(l, struct cgr_conn, list);
		if (c->state == CGRC_FREE)
			return c;
	}
	LM_DBG("no free connection - create a new one!\n");
	/* no free connection - try to create a new one */
	if (e->conns_no < cgrc_max_conns) {
		if ((c = cgrc_new(e)) && cgrc_conn(c) >= 0) {
			e->conns_no++;
			list_add(&c->list, &e->conns);
			return c;
		} else
			LM_ERR("cannot create a new connection!\n");
	} else {
		LM_DBG("maximum async connections per process reached!\n");
	}
	/* use the default connection */
	if (e->default_con && e->default_con->state == CGRC_FREE) {
		LM_DBG("using default connection - running in sync mode!\n");
		return e->default_con;
	}
	return NULL;
}

struct cgr_conn *cgrc_new(struct cgr_engine *e)
{
	struct cgr_conn *c;

	if (!(c = pkg_malloc(sizeof(struct cgr_conn)))) {
		LM_ERR("no more mem for nuew connection\n");
		return NULL;
	}
	memset(c, 0, sizeof(struct cgr_conn));

	c->jtok = json_tokener_new();
	if (!c->jtok) {
		LM_ERR("cannot create json token\n");
		goto error;
	}
	c->engine = e;

	return c;
error:
	pkg_free(c);
	return NULL;
}


void cgrc_close(struct cgr_conn *c, int release)
{
	c->state = CGRC_CLOSED;
	/* clean whatever was left in the buffer */
	json_tokener_reset(c->jtok);
	if (release) {
		reactor_del_reader(c->fd, -1, IO_FD_CLOSING);
		close(c->fd);
	}

	LM_INFO("closing connection %.*s:%hu\n", c->engine->host.len,
			c->engine->host.s, c->engine->port);
	/* TODO: how should we re-enable connections? */
}

int cgrc_conn(struct cgr_conn *c)
{
	int s = -1;
	union sockaddr_union my_name;
	int my_name_len;
	struct ip_addr *ip;

	s=socket(AF_INET, SOCK_STREAM, 0);
	if (s==-1){
		LM_ERR("socket: (%d) %s\n", errno, strerror(errno));
		return -1;
	}
	if (tcp_init_sock_opt(s)<0){
		LM_ERR("tcp_init_sock_opt failed\n");
		goto error;
	}

	if (cgre_bind_ip.s) {
		my_name_len = sizeof(struct sockaddr_in);
		if ((ip = str2ip(&cgre_bind_ip)) == NULL) {
			LM_ERR("invalid ip in bind_ip: %s\n", cgre_bind_ip.s);
			goto error;
		}
		init_su(&my_name, ip, 0);
		if (bind(s, &my_name.s, my_name_len )!=0) {
			LM_ERR("bind failed (%d) %s\n", errno,strerror(errno));
			goto error;
		}
	}

	if (tcp_connect_blocking(s, &c->engine->su.s, sockaddru_len(c->engine->su))<0){
		LM_ERR("cannot connect to %.*s:%d\n", c->engine->host.len,
				c->engine->host.s, c->engine->port);
		goto error;
	}

	/* all good - set the fd */
	c->fd = s;

	c->state = CGRC_FREE;

	return 0;
error:
	if (s!=-1) close(s);
	return -1;
}


/* sends a message to the cgrates engine */
int cgrc_send(struct cgr_conn *c, str *buf)
{
	int ret, written = 0;

	do {
		ret = write(c->fd, buf->s + written, buf->len - written);
		if (ret <= 0) {
			if (errno != EINTR) {
				cgrc_close(c, CGRC_IS_LISTEN(c));
				return -1;
			}
		} else {
			written += ret;
		}
	} while (written < buf->len);
	LM_DBG("Successfully sent %d bytes\n", written);

	return written;
}


int cgrc_start_listen(struct cgr_conn *c)
{
	c->state = CGRC_FREE;
	CGRC_SET_LISTEN(c);
	/* add the fd to the reactor */
	return register_async_fd(c->fd, cgrates_async_resume_req, c);
}

/* disables the cgrates engine */
static inline int cgre_disable(struct cgr_engine *e)
{
	struct list_head *l;
	struct cgr_conn *c;

	LM_INFO("Disabling CGRateS engine %.*s:%d\n",
			e->host.len, e->host.s, e->port);

	list_for_each(l, &e->conns) {
		c = list_entry(l, struct cgr_conn, list);
		cgrc_close(c, CGRC_IS_LISTEN(c));
	}

	return 0;
}
