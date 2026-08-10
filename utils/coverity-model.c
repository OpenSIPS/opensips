/*
 * Copyright (C) 2020 OpenSIPS Solutions
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
 */


struct ip_addr;
struct tcp_connection;
struct socket_info;
struct _kafka_job;
typedef struct _kafka_job kafka_job_t;
enum sip_protos { PROTO_NONE };

int tcp_conn_get(unsigned int id, struct ip_addr *ip, int port,
		enum sip_protos proto, void *proto_extra_id,
		struct tcp_connection **conn, const struct socket_info *send_sock)
{
	__coverity_tainted_data_sink__(conn);
}

static kafka_job_t *kafka_receive_job(void)
{
	kafka_job_t *recv = (void *)0;
	__coverity_tainted_data_sink__(recv);
	return recv;
}

void xmlFree(void *mem)
{
	__coverity_free__(mem);
}
