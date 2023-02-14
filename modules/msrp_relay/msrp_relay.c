/*
 * Copyright (C) 2022 - OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../error.h"
#include "../../lib/hash.h"
#include "../../timer.h"
#include "../../net/trans.h"

#include "../auth/api.h"
#include "../proto_msrp/msrp_api.h"

#include "msrp_relay.h"
#include "auth.h"

#define DFEAULT_AUTH_ROUTE_NAME "msrp_auth"

#define UNKNOWN_METHOD_S "Unknown method"

#define REPORT_NO_STR  "no"
#define REPORT_YES_STR "yes"

#define STATUS_TIMEOUT_STR "000 408"
#define STATUS_NOT_ALLOWED_STR "000 403"
#define STATUS_SESS_NOT_EXISTS_STR "000 481"
#define STATUS_BAD_REQUEST_STR "000 400"

static int mod_init(void);
static int child_init(int _rank);
static void destroy(void);

auth_api_t auth_api;

/* proto_msrp binds */
struct msrp_binds msrp_api;

/* proto_msrp registration handler */
void *msrp_hdl = NULL;

int msrp_sessions_hsize = 10;
gen_hash_t *msrp_sessions;
int cleanup_interval = 60;

static char *msrp_auth_route  = DFEAULT_AUTH_ROUTE_NAME;
int auth_routeid;

static char *msrp_sock_route  = NULL;
int sock_routeid = -1;

struct msrp_url *my_url_list;

str user_spec_param = str_init("$var(username)");
str realm_spec_param = str_init("$var(realm)");
str passwd_spec_param = str_init("$var(password)");

str dschema_spec_param = str_init("$var(dst_schema)");
str dhost_spec_param = str_init("$var(dst_host)");
pv_spec_t dschema_spec;
pv_spec_t dhost_spec;

static int parse_my_uri_param(unsigned int type, void *val);

static const param_export_t params[] = {
	{"hash_size", INT_PARAM, &msrp_sessions_hsize},
	{"cleanup_interval", INT_PARAM, &cleanup_interval},
	{"auth_route", STR_PARAM, &msrp_auth_route},
	{"username_var", STR_PARAM, &user_spec_param.s},
	{"realm_var", STR_PARAM, &realm_spec_param.s},
	{"password_var", STR_PARAM, &passwd_spec_param.s},
	{"calculate_ha1", INT_PARAM, &auth_calc_ha1},
	{"socket_route", STR_PARAM, &msrp_sock_route},
	{"dst_schema_var", STR_PARAM, &dschema_spec_param.s},
	{"dst_host_var", STR_PARAM, &dhost_spec_param.s},
	{"auth_realm", STR_PARAM, &default_auth_realm.s},
	{"auth_expires", INT_PARAM, &auth_expires},
	{"auth_min_expires", INT_PARAM, &auth_min_expires},
	{"auth_max_expires", INT_PARAM, &auth_max_expires},
	{"nonce_expire", INT_PARAM, &nonce_expire},
	{"my_uri", STR_PARAM|USE_FUNC_PARAM, (void *)&parse_my_uri_param},
	{0, 0, 0}
};

struct module_exports exports = {
	"msrp_relay",  /* module name*/
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,               /* load function */
	0,          /* OpenSIPS module dependencies */
	0,          /* exported functions */
	0,          /* exported async functions */
	params,     /* module parameters */
	0,          /* exported statistics */
	0,          /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,          /* exported transformations */
	0,          /* extra processes */
	0,          /* module pre-initialization function */
	mod_init,   /* module initialization function */
	0,          /* response function */
	destroy,    /* destroy function */
	child_init, /* per-child init function */
	0           /* reload confirm function */
};

int handle_msrp_request(struct msrp_msg *req, void *param);
int handle_msrp_reply(struct msrp_msg *rpl, struct msrp_cell *tran,
		void *trans_param, void *hdl_param);

void clean_msrp_sessions(unsigned int ticks,void *param);

static int parse_my_uri_param(unsigned int type, void *val)
{
	str val_str;
	struct msrp_url *url;
	char *p, *end;

	val_str.s = (char *)val;
	val_str.len = strlen(val_str.s);

	url = shm_malloc(sizeof *url + val_str.len);
	if (!url) {
		LM_ERR("no more shm memory\n");
		return -1;
	}
	memset(url, 0, sizeof *url);

	p = (char*)(url+1);
	memcpy(p, val_str.s, val_str.len);

	end = p + val_str.len;
	p = parse_msrp_url(p, end, url);
	if (!p) {
		LM_ERR("Failed to parse MSRP URI in 'my_uri'\n");
		goto error;
	}

	if (url->port_no == 0) {
		LM_INFO("Explicit port number not provided in 'my_uri', using 2855\n");
		url->port_no = 2855;
	}

	url->next = my_url_list;
	my_url_list = url;

	return 0;

error:
	shm_free(url);
	return -1;
}

static int mod_init(void)
{
	bind_auth_t bind_auth;

	LM_INFO("initializing...\n");

	/* bind to auth module and import the API */
	bind_auth = (bind_auth_t)find_export("bind_auth", 0);
	if (!bind_auth) {
		LM_ERR("unable to find bind_auth function."
			" Check if you loaded the auth module.\n");
		return -1;
	}

	if (bind_auth(&auth_api) < 0) {
		LM_ERR("unable to bind auth module\n");
		return -1;
	}

	/* load MSRP API */
	if(load_msrp_api(&msrp_api)< 0){
		LM_ERR("can't load MSRP functions\n");
		return -1;
	}

	msrp_hdl = msrp_api.register_msrp_handler((str*)_str("*"), 0, 0,
		handle_msrp_request, handle_msrp_reply, NULL);
	if (!msrp_hdl) {
		LM_ERR("Failed to register MSRP handler\n");
		return -1;
	}

	if (init_digest_auth() < 0)
		return -1;

	auth_routeid = get_script_route_ID_by_name(msrp_auth_route,
		sroutes->request, RT_NO);
	if (auth_routeid < 1) {
		LM_ERR("AUTH route <%s> does not exist\n", msrp_auth_route);
		return -1;
	}

	user_spec_param.len = strlen(user_spec_param.s);
	realm_spec_param.len = strlen(realm_spec_param.s);
	passwd_spec_param.len = strlen(passwd_spec_param.s);

	if (!my_url_list) {
		LM_ERR("'my_uri' parameter must be set at least once\n");
		return -1;
	}

	if (default_auth_realm.s)
		default_auth_realm.len = strlen(default_auth_realm.s);

	if (!pv_parse_spec(&user_spec_param, &user_spec)) {
		LM_ERR("failed to parse username spec\n");
		return -1;
	}
	if (!pv_parse_spec(&realm_spec_param, &realm_spec)) {
		LM_ERR("failed to parse realm spec\n");
		return -1;
	}
	if (!pv_parse_spec(&passwd_spec_param, &passwd_spec)) {
		LM_ERR("failed to parse password spec\n");
		return -1;
	}

	if (msrp_sock_route==NULL) {
		sock_routeid = -1;
	} else {
		sock_routeid = get_script_route_ID_by_name(msrp_sock_route,
			sroutes->request, RT_NO);
		if (sock_routeid < 1) {
			LM_ERR("SOCKet route <%s> does not exist\n", msrp_sock_route);
			return -1;
		}

		dschema_spec_param.len = strlen(dschema_spec_param.s);
		dhost_spec_param.len = strlen(dhost_spec_param.s);

		if (!pv_parse_spec(&dschema_spec_param, &dschema_spec)) {
			LM_ERR("failed to parse dst schema spec\n");
			return -1;
		}
		if (!pv_parse_spec(&dhost_spec_param, &dhost_spec)) {
			LM_ERR("failed to parse dst host spec\n");
			return -1;
		}
	}

	if (msrp_sessions_hsize < 1 || msrp_sessions_hsize > 20) {
		LM_ERR("hash size should be between 1 and 20\n");
		return -1;
	}
	msrp_sessions_hsize = 1 << msrp_sessions_hsize;

	msrp_sessions = hash_init(msrp_sessions_hsize);
	if (!msrp_sessions) {
		LM_ERR("Failed to init MSRP sessions table\n");
		return -1;
	}

	register_timer("msrprelay-expire", clean_msrp_sessions, NULL,
		cleanup_interval, TIMER_FLAG_DELAY_ON_DELAY);

	return 0;
}

static int child_init(int _rank)
{
	return init_digest_auth_child();
}

void free_msrp_session(void *val)
{
	shm_free(val);
}

static void destroy(void)
{
	struct msrp_url *url, *tmp;

	destroy_digest_auth();

	hash_destroy(msrp_sessions, free_msrp_session);

	url = my_url_list;
	while (url) {
		tmp = url;
		url = url->next;
		shm_free(tmp);
	}
}

static inline int msrp_uri_cmp(struct msrp_url *a, struct msrp_url *b)
{
	struct ip_addr *pip_a, *pip_b;
	struct ip_addr ip_a;

	if (a->secured != b->secured)
		return 0;

	pip_a = str2ip(&a->host);
	if (!pip_a)
		pip_a = str2ip6(&a->host);
	if (pip_a)
		ip_a = *pip_a;

	pip_b = str2ip(&b->host);
	if (!pip_b)
		pip_b = str2ip6(&b->host);

	if (!pip_a != !pip_b) {
		return 0;
	} else if (pip_a) { /* compare as IPs */
		if (!ip_addr_cmp(&ip_a, pip_b))
			return 0;
	} else { /* compare as FQDNs */
		if (str_strcasecmp(&a->host, &b->host))
			return 0;
	}

	/* If the port exists explicitly in either URI, then it MUST match
     * exactly */
	if (!a->port_no != !b->port_no)
		return 0;
	else if (a->port_no && a->port_no != b->port_no)
		return 0;

	/* transport parameters must match */
	if (str_strcasecmp(&a->params, &b->params))
		return 0;

	return 1;
}


static int run_msrp_socket_route(struct receive_info *rcv, char *d_schema_s,
		str *d_host, struct socket_info **si)
{
	pv_value_t pval;
	struct sip_msg *dummy_msg;

	/* prepare a fake/dummy request */
	dummy_msg = get_dummy_sip_msg();
	if(dummy_msg == NULL) {
		LM_ERR("cannot create new dummy sip request\n");
		return -1;
	}
	dummy_msg->rcv = *rcv;

	pval.flags = PV_VAL_STR;
	pval.rs.s = d_schema_s;
	pval.rs.len = strlen(d_schema_s);
	if (pv_set_value(dummy_msg, &dschema_spec, 0, &pval) < 0) {
		LM_ERR("Failed to set destination schema var\n");
		goto error;
	}

	pval.flags = PV_VAL_STR;
	pval.rs = *d_host;
	if (pv_set_value(dummy_msg, &dhost_spec, 0, &pval) < 0) {
		LM_ERR("Failed to set destination schema var\n");
		goto error;
	}

	set_route_type(REQUEST_ROUTE);

	run_top_route(sroutes->request[sock_routeid], dummy_msg);

	*si = dummy_msg->force_send_socket;

	release_dummy_sip_msg(dummy_msg);
	reset_avps();

	return 0;
error:
	release_dummy_sip_msg(dummy_msg);
	return -1;
}


int handle_msrp_request(struct msrp_msg *req, void *param)
{
	int rc;
	struct msrp_url *to, *from;
	unsigned int hentry;
	struct msrp_session *session;
	void **val;
	union sockaddr_union *to_su = NULL;
	int mark_peer_conn = 0;
	int from_peer = 0;
	struct msrp_url *my_url;
	int report = 0;
	struct socket_info *si;

	LM_DBG("Received MSRP request [%.*s]\n", req->fl.u.request.method.len,
		req->fl.u.request.method.s);

	to = (struct msrp_url *)req->to_path->parsed;

	if (to->port_no == 0) {
		/* AUTH requests might not have the explicit port number in To-Path
		 * but we should still be able to match one of our URIs */
		if (req->fl.u.request.method_id == MSRP_METHOD_AUTH) {
			to->port_no = req->rcv.dst_port;
		} else {
			LM_ERR("No port in To-Path header for non-AUTH request\n");
			return -1;
		}
	}

	/* match one of my URIs */
	for (my_url = my_url_list; my_url && !msrp_uri_cmp(to, my_url);
		my_url = my_url->next) ;
	if (!my_url) {
		LM_ERR("Request is not addressed to this relay\n");
		return -1;
	}

	if (req->fl.u.request.method_id == MSRP_METHOD_AUTH) {
		if (to->next) {
			if(msrp_api.forward_request(msrp_hdl,req,NULL,0,NULL,NULL,NULL)<0){
				LM_ERR("Failed to forward AUTH request\n");

				if (msrp_api.send_reply(msrp_hdl, req, 403, NULL, NULL, 0)<0) {
					LM_ERR("Failed to send reply\n");
					return 0;
				}		
			}
		} else {
			if (handle_msrp_auth_req(req, my_url) < 0)
				LM_ERR("Failed to processes AUTH request\n");
		}
	} else if (req->fl.u.request.method_id != MSRP_METHOD_OTHER) {
		if (req->fl.u.request.method_id == MSRP_METHOD_SEND &&
			(!req->failure_report || str_strcmp((&str_init(REPORT_NO_STR)),
			&req->failure_report->body))) {
			report = 1;

			if (msrp_api.send_reply(msrp_hdl, req, 200,
				&str_init(REASON_OK_STR), NULL, 0) < 0) {
				LM_ERR("Failed to send reply\n");
				return 0;
			}
		}

		hentry = hash_entry(msrp_sessions, to->session);
		hash_lock(msrp_sessions, hentry);

		val = hash_find(msrp_sessions, hentry, to->session);
		if (!val) {
			hash_unlock(msrp_sessions, hentry);
			LM_ERR("Invalid URI, session does not exist\n");

			if (report && msrp_api.send_report(msrp_hdl,
				&str_init(STATUS_SESS_NOT_EXISTS_STR), req, NULL) < 0)
				LM_ERR("Failed to send REPORT\n");
			return 0;
		}
		session = *val;

		if (session->expires < get_ticks()) {
			hash_remove_key(msrp_sessions, to->session);
			free_msrp_session(session);

			hash_unlock(msrp_sessions, hentry);
			LM_ERR("Invalid URI, session does not exist\n");

			if (report && msrp_api.send_report(msrp_hdl,
				&str_init(STATUS_SESS_NOT_EXISTS_STR), req, NULL) < 0)
				LM_ERR("Failed to send REPORT\n");
			return 0;
		}

		if (req->from_path->parsed == NULL) {
			req->from_path->parsed = parse_msrp_path(&req->from_path->body);
			if (req->from_path->parsed == NULL) {
				hash_unlock(msrp_sessions, hentry);
				LM_ERR("Failed to parse From-Path\n");

				if (report && msrp_api.send_report(msrp_hdl,
					&str_init(STATUS_BAD_REQUEST_STR), req, NULL) < 0)
					LM_ERR("Failed to send REPORT\n");
				return 0;
			}
		}
		from = (struct msrp_url *)req->from_path->parsed;

		if (str_strcmp(&from->whole, &session->top_from))
			/* request from the peer of our authenticated endpoint */
			from_peer = 1;
		else if (session->flags & SESS_ACCEPTED_PEER_CONN)
			/* forward to the source address, from the connection opened
			 * by peer to us; otherwise, forward according to To-Path */
			to_su = &session->peer_src_su;

		if (req->fl.u.request.method_id == MSRP_METHOD_SEND) {
			if (!(session->flags & SESS_HAVE_PEER_CONN)) {
				mark_peer_conn = 1;

				if (from_peer) {
					/* peer connected to us first */
					session->flags |= SESS_ACCEPTED_PEER_CONN;
					session->peer_src_su = req->rcv.src_su;
				}
			}

			hash_unlock(msrp_sessions, hentry);
		} else {
			hash_unlock(msrp_sessions, hentry);
		}

		if (sock_routeid<=0 ||
		run_msrp_socket_route( &req->rcv,
			protos[to->next->secured?PROTO_MSRPS:PROTO_MSRP].name,
			&to->next->host, &si)!=0
		)
			si = NULL;

		rc = msrp_api.forward_request(msrp_hdl, req, NULL, 0, si, to_su, NULL);
		if (rc == 0) {
			if (mark_peer_conn) {
				hash_lock(msrp_sessions, hentry);
				session->flags |= SESS_HAVE_PEER_CONN;
				hash_unlock(msrp_sessions, hentry);
			}
		} else {
			LM_ERR("Failed to forward request\n");

			if (report && msrp_api.send_report(msrp_hdl,
				&str_init(STATUS_NOT_ALLOWED_STR), req, NULL) < 0) {
				LM_ERR("Failed to send REPORT\n");
				return 0;
			}
		}
	} else {
		if (msrp_api.send_reply(msrp_hdl, req, 501,
			&str_init(UNKNOWN_METHOD_S), NULL, 0) < 0)
			LM_ERR("Failed to send reply\n");
	}

	return 0;
}

int handle_msrp_reply(struct msrp_msg *rpl, struct msrp_cell *tran,
		void *trans_param, void *hdl_param)
{
	struct msrp_url *my_url, *to;
	static char buf[7] = "000 ";
	str status = {buf, 7};

	if (rpl) {
		LM_DBG("Received MSRP reply [%d %.*s]\n", rpl->fl.u.reply.status_no,
			rpl->fl.u.reply.reason.len, rpl->fl.u.reply.reason.s);

		to = (struct msrp_url *)rpl->to_path->parsed;

		/* match one of my URIs */
		for (my_url = my_url_list; my_url && !msrp_uri_cmp(to, my_url);
			my_url = my_url->next) ;
		if (!my_url) {
			LM_ERR("Request is not addressed to this relay\n");
			return -1;
		}

		if (rpl->fl.u.reply.status_no == 200)
			return 0;

		if (to->next) {
			if (msrp_api.forward_reply(msrp_hdl, rpl, tran) < 0) {
				LM_ERR("Failed to forward reply\n");
				return 0;
			}
		} else {
			if (!tran->failure_report.len || str_strcmp(&tran->failure_report,
				(&str_init(REPORT_NO_STR)))) {
				rctostr(buf+4, rpl->fl.u.reply.status_no);
				if (msrp_api.send_report(msrp_hdl, &status, NULL, tran) < 0)
					LM_ERR("Failed to send REPORT for failure response\n");
			}
		}
	} else {
		LM_DBG("Timeout for ident=%.*s\n", tran->ident.len, tran->ident.s);

		if (tran->method_id != MSRP_METHOD_AUTH) {
			if ((tran->failure_report.len && !str_strcmp(&tran->failure_report,
				(&str_init(REPORT_YES_STR)))) &&
				msrp_api.send_report(msrp_hdl, &str_init(STATUS_TIMEOUT_STR),
				NULL, tran) < 0)
				LM_ERR("Failed to send REPORT on timeout\n");
		} else {
			if (msrp_api.send_reply_on_cell(msrp_hdl, tran, 408,
				NULL, NULL, 0) < 0)
				LM_ERR("Failed to send reply on timeout for AUTH request\n");
		}
	}

	return 0;
}

static int timer_clean_session(void *param, str key, void *value)
{
	struct msrp_session *session = (struct msrp_session *)value;

	if (session->expires < get_ticks()) {
		hash_remove_key(msrp_sessions, key);
		free_msrp_session(session);
	}

	return 0;
}

void clean_msrp_sessions(unsigned int ticks,void *param)
{
	hash_for_each_locked(msrp_sessions, timer_clean_session, NULL);
}
