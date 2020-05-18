/*
 * Copyright (C) 2011 OpenSIPS Solutions
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
 * history:
 * ---------
 *  2011-05-xx  created (razvancrainea)
 */


#ifndef _EV_RMQ_H_
#define _EV_RMQ_H_

#include <amqp.h>
#include <amqp_framing.h>
#if defined AMQP_VERSION && AMQP_VERSION >= 0x00040000
  #define AMQP_VERSION_v04
#include <amqp_tcp_socket.h>
#endif


/* transport protocols name */
#define RMQ_NAME	"rabbitmq"
#define RMQ_STR		{ RMQ_NAME, sizeof(RMQ_NAME) - 1}
/* module flag */
#define RMQ_FLAG		(1 << 28 )

#define RMQ_DEFAULT_CONNECT_TIMEOUT 500 /* ms */

#define RMQ_DEFAULT_UP		"guest"
#define RMQ_DEFAULT_UP_LEN	(sizeof(RMQ_DEFAULT_UP))
#define RMQ_DEFAULT_MAX		131072
#define RMQ_DEFAULT_VHOST	"/"
#define RMQ_DEFAULT_PORT	5672

#define RMQ_PARAM_RKEY	(1 << 1)
#define RMQ_PARAM_CONN	(1 << 2)
#define RMQ_PARAM_CHAN	(1 << 3)
#define RMQ_PARAM_USER	(1 << 4)
#define RMQ_PARAM_PASS	(1 << 5)
#define RMQ_PARAM_EKEY	(1 << 6)

typedef struct _rmq_params {
	str routing_key;
	str exchange;
	str user;
	str pass;
	amqp_connection_state_t conn;
	int channel;
	int flags;
	int heartbeat;
} rmq_params_t;

#endif

