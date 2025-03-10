/*
 * Copyright (C) 2022 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "tcp_path.h"
#include "tcp_db.h"
#include "../../socket_info.h"
#include "../../lib/csv.h"

struct tcp_path *tcp_paths;
int *tcp_paths_sz;
rw_lock_t *tcp_paths_lk;


int tcp_path_init(void)
{
	tcp_paths_lk = lock_init_rw();
	if (!tcp_paths_lk) {
		LM_ERR("failed to create rw lock\n");
		return -1;
	}

	tcp_paths_sz = shm_malloc(sizeof *tcp_paths_sz);
	if (!tcp_paths_sz) {
		LM_ERR("oom\n");
		return -1;
	}
	*tcp_paths_sz = 0;

	return 0;
}


int tcp_mgm_get_profile(const union sockaddr_union *remote,
         const union sockaddr_union *local, enum sip_protos proto,
         struct tcp_conn_profile *out_profile)
{
	struct tcp_path *path, *lim;
	struct ip_addr remote_ip, local_ip;
	unsigned short remote_port, local_port;

	sockaddr2ip_addr(&remote_ip, &remote->s);
	sockaddr2ip_addr(&local_ip, &local->s);
	remote_port = su_getport(remote);
	local_port = su_getport(local);

	lock_start_read(tcp_paths_lk);

	for (path = tcp_paths, lim = tcp_paths+*tcp_paths_sz; path < lim; path++) {
		if (path->proto != PROTO_NONE && proto != PROTO_NONE
		        && path->proto != proto)
			continue;

		if ((!path->remote_port || path->remote_port == remote_port)
		        && (!path->local_port || path->local_port == local_port)
		        && (path->remote_any || matchnet(&remote_ip, &path->remote_addr) == 1)
		        && (path->local_any || matchnet(&local_ip, &path->local_addr) == 1)) {
			*out_profile = path->prof;
			break;
		}
	}

	lock_stop_read(tcp_paths_lk);

	/* was a matching TCP path found? */
	if (path < lim) {
		LM_DBG("matched a TCP path, id: %d (%d/%d/%d/%d/%d/%d/%d/%d)\n",
		       out_profile->id, out_profile->connect_timeout,
		       out_profile->con_lifetime, out_profile->msg_read_timeout,
		       out_profile->send_threshold, out_profile->no_new_conn,
		       out_profile->alias_mode, out_profile->parallel_read,
		       out_profile->keepalive);
		return 1;
	}

	/* nope, then just return the default profile */
	*out_profile = tcp_con_df_profile;
	LM_DBG("failed to match a TCP path, using the default TCP profile\n");
	return 0;
}


int tcp_store_path(int *int_vals, char **str_vals, struct tcp_path *path)
{
	const struct socket_info *sock;
	str st;
	int _proto;

	init_str(&st, str_vals[TCPCOL_PROTO]);
	if (!strcasecmp(st.s, "any")) {
		_proto = PROTO_NONE;
	} else if (parse_proto((unsigned char *)st.s, st.len, &_proto) != 0) {
		LM_ERR("invalid protocol: %s\n", st.s);
		return -1;
	}

	if (_proto == PROTO_UDP || _proto == PROTO_SCTP || _proto == PROTO_HEP_UDP) {
		LM_ERR("unacceptable TCP-based protocol: %d, id: %d\n",
		       _proto, int_vals[TCPCOL_ID]);
		return -1;
	}
	path->proto = _proto;

	if (!str_vals[TCPCOL_REMOTE_ADDR]) {
		path->remote_any = 1;
		memset(&path->remote_addr, 0, sizeof path->remote_addr);
	} else {
		init_str(&st, str_vals[TCPCOL_REMOTE_ADDR]);
		if (!strcasecmp(st.s, "any")) {
			path->remote_any = 1;
			memset(&path->remote_addr, 0, sizeof path->remote_addr);
		} else {
			path->remote_any = 0;
			if (mk_net_cidr(&st, &path->remote_addr) != 0) {
				LM_ERR("failed to parse and/or validate remote address '%s', id: %d\n",
				       st.s, int_vals[TCPCOL_ID]);
				return -1;
			}
		}
	}

	path->remote_port = int_vals[TCPCOL_REMOTE_PORT];
	if (path->remote_port > 65535) {
		LM_ERR("invalid remote_port: %d\n", path->remote_port);
		return -1;
	}

	path->local_port = int_vals[TCPCOL_LOCAL_PORT];
	if (path->local_port > 65535) {
		LM_ERR("invalid local_port: %d\n", path->local_port);
		return -1;
	}

	if (!str_vals[TCPCOL_LOCAL_ADDR]) {
		path->local_any = 1;
		memset(&path->local_addr, 0, sizeof path->local_addr);
	} else {
		init_str(&st, str_vals[TCPCOL_LOCAL_ADDR]);
		if (!strcasecmp(st.s, "any")) {
			path->local_any = 1;
			memset(&path->local_addr, 0, sizeof path->local_addr);
		} else {
			struct net *tmp_net;

			path->local_any = 0;
			sock = grep_internal_sock_info(&st, path->local_port, path->proto);
			if (!sock) {
				LM_ERR("failed to match local addr '%s' against an OpenSIPS "
				       "listener socket, id: %d\n", st.s, int_vals[TCPCOL_ID]);
				return -1;
			}

			tmp_net = mk_net_bitlen(&sock->address,
			               sock->address.af == AF_INET6 ? 128 : 32);
			if (!tmp_net) {
				LM_ERR("oom\n");
				return -1;
			}

			path->local_addr = *tmp_net;
			pkg_free(tmp_net);
		}
	}

	if (!path->remote_any && !path->local_any
	       && path->remote_addr.ip.af != path->local_addr.ip.af) {
		LM_ERR("IP family mismatch for '%s' and '%s' (%d vs. %d), id: %d\n",
			str_vals[TCPCOL_REMOTE_ADDR], st.s, path->remote_addr.ip.af,
			path->local_addr.ip.af, int_vals[TCPCOL_ID]);
		return -1;
	}

	path->priority = int_vals[TCPCOL_PRIORITY];

	tcp_init_attrs(path->prof.attrs);
	if (str_vals[TCPCOL_ATTRS]) {
		csv_record *params, *it;
		init_str(&st, str_vals[TCPCOL_ATTRS]);

		params = __parse_csv_record(&st, 0, ';');
		for (it = params; it; it = it->next) {
			char *eq = q_memchr(it->s.s, '=', it->s.len);
			str key;
			int val;

			if (!eq) {
				key = st;
				val = 0;
			} else {
				key.s = st.s;
				key.len = eq - st.s;

				st.s = eq + 1;
				st.len -= key.len + 1;
				if (str2sint(&st, &val) < 0) {
					LM_ERR("non-integer TCP conn value: '%.*s', id: %d\n",
					       st.len, st.s, int_vals[TCPCOL_ID]);
					return -1;
				}
			}

			enum tcp_conn_attr attr;
			if (!tcp_con_attr_lookup(&it->s, &attr)) {
				LM_ERR("unknown TCP conn attribute: '%.*s', id: %d\n",
				       key.len, key.s, int_vals[TCPCOL_ID]);
				return -1;
			}

			path->prof.attrs[attr] = val;
		}

		free_csv_record(params);
	}

	path->prof.alias_mode = int_vals[TCPCOL_ALIAS_MODE];
	if (path->prof.alias_mode > TCP_ALIAS_ALWAYS) {
		LM_ERR("invalid alias_mode: %d, id: %d\n",
		       path->prof.alias_mode, int_vals[TCPCOL_ID]);
		return -1;
	}

	path->prof.parallel_read = int_vals[TCPCOL_PARALLEL_READ];
	if (path->prof.parallel_read > 2) {
		LM_ERR("invalid parallel_read mode: %d, id: %d\n",
		       path->prof.parallel_read, int_vals[TCPCOL_ID]);
		return -1;
	}

	path->prof.id = int_vals[TCPCOL_ID];
	path->prof.connect_timeout = int_vals[TCPCOL_CONNECT_TIMEOUT];
	path->prof.con_lifetime = int_vals[TCPCOL_CON_LIFETIME];
	path->prof.msg_read_timeout = int_vals[TCPCOL_MSG_READ_TIMEOUT];
	path->prof.send_threshold = int_vals[TCPCOL_SEND_THRESHOLD];
	path->prof.no_new_conn = !!int_vals[TCPCOL_NO_NEW_CONN];
	path->prof.keepalive = !!int_vals[TCPCOL_KEEPALIVE];
	path->prof.keepcount = int_vals[TCPCOL_KEEPCOUNT];
	path->prof.keepidle = int_vals[TCPCOL_KEEPIDLE];
	path->prof.keepinterval = int_vals[TCPCOL_KEEPINTERVAL];

#ifdef EXTRA_DEBUG
	LM_INFO("----------- TCP Path [%d] -------------\n", int_vals[TCPCOL_ID]);
	LM_INFO("priority: %d\n", path->priority);
	LM_INFO("proto: %d\n", path->proto);
	LM_INFO("remote: %s:%u | ANY: %d\n",
	        path->remote_any ? "NULL" : ip_addr2a(&path->remote_addr.ip),
	        path->remote_port, path->remote_any);
	LM_INFO("remote_prefix: %s\n",
	        path->remote_any ? "NULL" : ip_addr2a(&path->remote_addr.mask));
	LM_INFO("local: %s:%u | ANY: %d\n",
	        path->local_any ? "NULL" : ip_addr2a(&path->local_addr.ip),
	        path->local_port, path->local_any);
	LM_INFO("local_prefix: %s\n",
	        path->local_any ? "NULL" : ip_addr2a(&path->local_addr.mask));
	LM_INFO("  %d %d %d\n", path->prof.connect_timeout,
	          path->prof.con_lifetime, path->prof.msg_read_timeout);
	LM_INFO("  %d %d %d %d\n", path->prof.send_threshold,
	          path->prof.no_new_conn, path->prof.alias_mode,
	          path->prof.parallel_read);
	LM_INFO("  %d %d %d %d\n", path->prof.keepalive,
	          path->prof.keepcount, path->prof.keepidle, path->prof.keepinterval);
#endif

	return 0;
}


void tcp_path_destroy(void)
{
	lock_destroy_rw(tcp_paths_lk);
	shm_free(tcp_paths);
	shm_free(tcp_paths_sz);
}
