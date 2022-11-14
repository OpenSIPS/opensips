/*
 * Copyright (C) 2017 Răzvan Crainea <razvan@opensips.org>
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
#include "../../net/tcp_common.h"
#include "../../resolve.h"
#include "../../async.h"

#include "../../lib/timerfd.h"

static int cgrc_conn(struct cgr_conn *c);
static void cgrc_reconn_rpc(int sender, void *p);

static int cgrc_reconn(struct cgr_conn *c)
{
	int ret = cgrc_conn(c);
	if (ret >= 0 && c == c->engine->default_con)
		return cgrc_start_listen(c);
	return ret;
}

#ifdef HAVE_TIMER_FD
static void cgr_conn_schedule(struct cgr_conn *c);

static int cgrc_conn_sched(int fd, void *p)
{
	struct cgr_conn *c = (struct cgr_conn *)p;
	/* if connect not succeeded, re-schedule */
	LM_INFO("re-connecting to %.*s:%d\n", c->engine->host.len,
			c->engine->host.s, c->engine->port);
	if (cgrc_reconn(c) < 0)
		cgr_conn_schedule(c);
	return 1;
}

static void cgr_conn_schedule(struct cgr_conn *c)
{
	int fd;
	struct itimerspec its;

	if (c->disable_time + cgre_retry_tout <= time(NULL)) {
		/* no need for timer schedule - we should re-connect immediately */
		if (ipc_send_rpc(process_no, cgrc_reconn_rpc, c) < 0)
			LM_ERR("could not send re-connect job!\n");
		return;
	}

	if ((fd = timerfd_create(CLOCK_REALTIME, 0)) < 0) {
		LM_ERR("failed to create new timer FD (%d) <%s>\n",
			errno, strerror(errno));
		return;
	}
	memset(&its, 0, sizeof(its));

	/* set the time */
	its.it_value.tv_sec = cgre_retry_tout;
	its.it_value.tv_nsec = 0;
	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = 0;
	if (timerfd_settime(fd, 0, &its, NULL) < 0) {
		LM_ERR("failed to set timer FD (%d) <%s>\n",
			errno, strerror(errno));
		return;
	}

	/* schedule re-connect */
	if (register_async_fd(fd, cgrc_conn_sched, c) < 0)
		LM_ERR("could not schedule conn reconnect\n");
}

#else /* HAVE_TIMER_FD */
#warning Your GLIB is too old, disabling cgrates async re-connect!!!
#define cgr_conn_schedule()
#endif /* HAVE_TIMER_FD */

void cgrc_conn_rpc(int sender, void *p)
{
	struct cgr_conn *c = (struct cgr_conn *)p;
	cgrc_reconn(c);
}

static void cgrc_reconn_rpc(int sender, void *p)
{
	struct cgr_conn *c = (struct cgr_conn *)p;
	if (cgrc_reconn(c) < 0)
		cgr_conn_schedule(c);
}


struct cgr_conn *cgr_get_free_conn(struct cgr_engine *e)
{
	struct list_head *l;
	struct cgr_conn *c;
	time_t now = time(NULL);
	int disabled_no = 0;

	if (e->disable_time && e->disable_time + cgre_retry_tout > now)
		return NULL;

	list_for_each(l, &e->conns) {
		c = list_entry(l, struct cgr_conn, list);
		if (c->state == CGRC_CLOSED) {
			if (c->disable_time + cgre_retry_tout < now) {
				if (tcp_connect_blocking_timeout(c->fd, &c->engine->su.s,
				        sockaddru_len(c->engine->su), c->connect_timeout)<0){
					LM_INFO("cannot connect to %.*s:%d\n", c->engine->host.len,
							c->engine->host.s, c->engine->port);
					c->disable_time = now;
					cgr_conn_schedule(c);
				} else {
					c->state = CGRC_FREE;
					e->disable_time = 0;
					return c;
				}
			}
			disabled_no++;
		}
		if (c->state == CGRC_FREE)
			return c;
	}
	LM_DBG("no free connection - create a new one!\n");
	/* no free connection - try to create a new one */
	if (e->conns_no < cgrc_max_conns) {
		if ((c = cgrc_new(e)) && cgrc_conn(c) >= 0) {
			e->conns_no++;
			e->disable_time = 0;
			list_add(&c->list, &e->conns);
			return c;
		}
		LM_ERR("cannot create a new connection!\n");
	} else {
		LM_DBG("maximum async connections per process reached!\n");
	}
	if (disabled_no > 0) {
		LM_INFO("Disabling CGRateS engine %.*s:%d for %ds\n",
				e->host.len, e->host.s, e->port, cgre_retry_tout);
		e->disable_time = now;
		return NULL;
	}
	return cgr_get_default_conn(e);
}

struct cgr_conn *cgr_get_default_conn(struct cgr_engine *e)
{
	time_t now = time(NULL);

	if (e->disable_time && e->disable_time + cgre_retry_tout > now) {
		LM_DBG("engine=%p down now=%lu until=%lu\n", e, now,
				e->disable_time + cgre_retry_tout);
		return NULL;
	}

	/* use the default connection */
	if (!e->default_con)
		return NULL;
	if (e->default_con->state == CGRC_FREE) {
		LM_DBG("using default connection - running in sync mode!\n");
		return e->default_con;
	} else if (e->default_con->disable_time + cgre_retry_tout < now) {
		if (cgrc_conn(e->default_con)<0){
			LM_INFO("cannot connect to %.*s:%d\n", e->host.len,
					e->host.s, e->port);
			e->default_con->disable_time = now;
			cgr_conn_schedule(e->default_con);
		} else {
			LM_INFO("re-connected to %.*s:%d\n", e->host.len,
					e->host.s, e->port);
			e->disable_time = 0;
			cgrc_start_listen(e->default_con);
			return e->default_con;
		}
	} else {
		LM_DBG("conn=%p state=%x now=%lu until=%lu\n", e->default_con,
				e->default_con->state, now, e->default_con->disable_time + cgre_retry_tout);
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
	c->state = CGRC_CLOSED;

	return c;
error:
	pkg_free(c);
	return NULL;
}


void cgrc_close(struct cgr_conn *c, int release)
{
	c->state = CGRC_CLOSED;
	c->disable_time = time(NULL);
	/* clean whatever was left in the buffer */
	json_tokener_reset(c->jtok);

	/* we need to schedule the re-connect before closing the socket, otherwise
	 * there is a high chance that the schedule take the same FD, thus it will
	 * be later on removed from the reactor again */
	cgr_conn_schedule(c);
	if (release) {
		reactor_del_reader(c->fd, -1, IO_FD_CLOSING);
		close(c->fd);
	}

	LM_INFO("closing connection %.*s:%hu\n", c->engine->host.len,
			c->engine->host.s, c->engine->port);
}

static int cgrc_conn(struct cgr_conn *c)
{
	int s = -1;
	union sockaddr_union *src_su = NULL, _src_su;
	struct tcp_conn_profile prof;
	struct ip_addr *ip;
	struct hostent *he;

	if (c->engine->is_fqdn) {
		he = resolvehost(c->engine->host.s, 1);
		if (!he || hostent2su(&c->engine->su, he, 0, c->engine->port) < 0) {
			LM_ERR("cannot resolve %.*s:%d\n", c->engine->host.len,
					c->engine->host.s, c->engine->port);
			return -1;
		}
	}

	if (cgre_bind_ip.s) {
		if ((ip = str2ip(&cgre_bind_ip)) == NULL) {
			LM_ERR("invalid ip in bind_ip: %s\n", cgre_bind_ip.s);
			goto error;
		}
		init_su(&_src_su, ip, 0);
		src_su = &_src_su;
	}

	tcp_con_get_profile(&c->engine->su, src_su, PROTO_TCP, &prof);

	s = tcp_sync_connect_fd(src_su, &c->engine->su, PROTO_TCP, &prof);
	if (s < 0) {
		LM_ERR("cannot connect to %.*s:%d\n", c->engine->host.len,
				c->engine->host.s, c->engine->port);
		goto error;
	}

	/* all good - set the fd */
	c->fd = s;

	c->connect_timeout = prof.connect_timeout;
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
static inline int ALLOW_UNUSED cgre_disable(struct cgr_engine *e)
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
