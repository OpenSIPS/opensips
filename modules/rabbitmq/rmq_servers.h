/*
 * Copyright (C) 2017 OpenSIPS Project
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
 *
 * History:
 * ---------
 *  2017-01-24  created (razvanc)
 */

#ifndef _RMQ_SERVERS_H_
#define _RMQ_SERVERS_H_

enum rmq_server_state { RMQS_NONE, RMQS_INIT, RMQS_ENABLED };

struct rmq_server {
	enum rmq_server_state state;
	str cid; /* connection id */
	struct db_id *id;
	struct list_head list;
};

int rmq_server_add(modparam_t type, void * val);
int rmq_reconnect(struct rmq_server *srv);
int fixup_rmq_server(void **param);
struct rmq_server *rmq_get_server(str *cid);
struct rmq_server *rmq_resolve_server(struct sip_msg *msg, char *param);
void rmq_connect_servers(void);

#endif /* _RMQ_SERVERS_H_ */
