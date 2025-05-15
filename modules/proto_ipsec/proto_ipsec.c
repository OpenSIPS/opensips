/*
 * Copyright (C) 2024 - OpenSIPS Solutions
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

#include <errno.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <fcntl.h>

#include "../../pt.h"
#include "../../timer.h"
#include "../../socket_info.h"
#include "../../receive.h"
#include "../../net/api_proto.h"
#include "../../net/api_proto_net.h"
#include "../../net/net_udp.h"
#include "../../net/net_tcp.h"
#include "../../net/tcp_common.h"
#include "../../parser/parse_authenticate.h"
#include "../../parser/parse_fline.h"
#include "../../data_lump.h"
#include "../../parser/digest/digest.h"
#include "../../lib/aka.h"
#include "../tm/tm_load.h"
#include "../usrloc/usrloc.h"
#include "ipsec_algo.h"
#include "ipsec.h"
#include "ipsec_user.h"

#define IPSEC_CTX_TM_GET(t) ((struct ipsec_ctx *) tm_ipsec.t_ctx_get_ptr(t, ipsec_ctx_tm_idx))
#define IPSEC_CTX_TM_PUT(t, ctx) tm_ipsec.t_ctx_put_ptr(t, ipsec_ctx_tm_idx, ctx)


static int ipsec_default_client_port = 0;
static int ipsec_default_server_port = 0;
static str ipsec_allowed_algorithms;
static struct tm_binds tm_ipsec;
static usrloc_api_t ul_ipsec;
static int ipsec_ctx_tm_idx = -1;

static int ipsec_port = IPSEC_DEFAULT_PORT;
static int mod_init(void);
static void mod_destroy(void);
static int proto_ipsec_init(struct proto_info *pi);
static int proto_ipsec_init_listener(struct socket_info *si);
static int proto_ipsec_bind_listener(struct socket_info *si);
static int proto_ipsec_send(const struct socket_info* source,
		char* buf, unsigned int len, const union sockaddr_union* to,
		unsigned int id);
static int ipsec_pre_script_handler( struct sip_msg *msg, void *param);
static void ipsec_usrloc_handler(void *binding, ul_cb_type type, ul_cb_extra *_);

int ipsec_tmp_timeout = IPSEC_DEFAULT_TMP_TOUT;

static int ipsec_aka_auth_match_f(const struct authenticate_body *auth,
    const struct match_auth_hf_desc *md);
static struct match_auth_hf_desc ipsec_aka_auth_match =
	MATCH_AUTH_HF(ipsec_aka_auth_match_f, NULL);

static int w_ipsec_create(struct sip_msg *msg, int *port_ps, int *port_pc,
		struct ipsec_allowed_algo *algos);
static int fixup_ipsec_create_algos(void **param);
static int fixup_ipsec_create_algos_free(void **param);

static const cmd_export_t cmds[] = {
	{"ipsec_create", (cmd_function)w_ipsec_create, {
		{CMD_PARAM_INT|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_INT|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,
			fixup_ipsec_create_algos, fixup_ipsec_create_algos_free},
		{0,0,0}},
		ONREPLY_ROUTE},
	{"proto_init", (cmd_function)proto_ipsec_init, {{0,0,0}}, 0},
	{0,0,{{0,0,0}},0}
};


static const param_export_t params[] = {
	{ "port",							INT_PARAM, &ipsec_port },
	{ "min_spi",						INT_PARAM, &ipsec_min_spi },
	{ "max_spi",						INT_PARAM, &ipsec_max_spi },
	/* TODO: this should be reg-await-auth timer */
	{ "temporary_timeout",				INT_PARAM, &ipsec_tmp_timeout },
	{ "default_client_port",			INT_PARAM, &ipsec_default_client_port },
	{ "default_server_port",			INT_PARAM, &ipsec_default_server_port },
	{ "allowed_algorithms",				STR_PARAM, &ipsec_allowed_algorithms.s },
	{ "disable_deprecated_algorithms",	INT_PARAM, &ipsec_disable_deprecated_algorithms },
	{0, 0, 0}
};

static int pv_get_ipsec_ctx_me(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *val);
static int pv_get_ipsec_ctx_ue(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *val);
static int pv_parse_ipsec_ctx(pv_spec_p sp, const str *in);

static const pv_export_t pvars[] = {
	{ str_const_init("ipsec"), 2001, pv_get_ipsec_ctx_me, NULL,
		pv_parse_ipsec_ctx, NULL, 0, 0},
	{ str_const_init("ipsec_ue"), 2002, pv_get_ipsec_ctx_ue, NULL,
		pv_parse_ipsec_ctx, NULL, 0, 1},
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};

static const dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "tm", DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "usrloc", DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "proto_udp", DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "proto_tcp", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};



struct module_exports exports = {
	PROTO_PREFIX "ipsec",  /* module name*/
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,               /* load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds,       /* exported functions */
	0,          /* exported async functions */
	params,     /* module parameters */
	0,          /* exported statistics */
	0,          /* exported MI functions */
	pvars,      /* exported pseudo-variables */
	0,          /* exported transformations */
	0,          /* extra processes */
	0,          /* module pre-initialization function */
	mod_init,   /* module initialization function */
	0,          /* response function */
	mod_destroy,/* destroy function */
	0,          /* per-child init function */
	0           /* reload confirm function */
};

static struct socket_info *find_ipsec_socket_info(struct ip_addr *ip, unsigned int port,
		unsigned int no_port1, unsigned int no_port2)
{
	struct socket_info_full *it;
	for (it = protos[PROTO_IPSEC].listeners; it; it = it->next) {
		LM_DBG("searching port %d vs %d (no %d, %d)\n", port, it->socket_info.port_no, no_port1, no_port2);
		if (port && it->socket_info.port_no != port)
			continue;
		if (no_port1 && it->socket_info.port_no == no_port1)
			continue;
		if (no_port2 && it->socket_info.port_no == no_port2)
			continue;
		if (ip && !ip_addr_cmp(ip, &it->socket_info.address))
			continue;
		return &it->socket_info;
	}
	return NULL;
}

static int ipsec_sockets_init(void)
{
	struct socket_info_full *it, *it2;
	int count = 0;

	if (ipsec_default_client_port) {
		if (ipsec_default_client_port == ipsec_default_server_port) {
			LM_ERR("cannot use the same default ports (%d) for both client and server\n",
					ipsec_default_client_port);
		}
		if (!find_ipsec_socket_info(NULL, ipsec_default_client_port, 0, 0))
			LM_ERR("cannot find any socket listening on default client port %d\n",
					ipsec_default_client_port);
	}
	if (ipsec_default_server_port &&
			!find_ipsec_socket_info(NULL, ipsec_default_server_port, 0, 0))
		LM_WARN("cannot find any socket listening on default server port %d\n",
				ipsec_default_server_port);

	for (it = protos[PROTO_IPSEC].listeners; it; it = it->next) {
		for (it2 = protos[PROTO_IPSEC].listeners; it2; it2 = it2->next) {
			if (it == it2)
				continue;
			if (str_match(&it->socket_info.name, &it2->socket_info.name))
				break; /* we've got same IP */
		}
		if (!it2) {
			LM_ERR("only one port for IPSEC IP %.*s\n",
					it->socket_info.name.len, it->socket_info.name.s);
			return -1;
		}
		count++;
	}
	LM_DBG("found %d IPSEC sockets\n", count);
	return 0;
}

static void ipsec_handle_register_req(struct cell* t, int type, struct tmcb_params *param)
{
	struct ipsec_ctx *ctx = ipsec_ctx_get();

	if (!ctx) {
		LM_DBG("no IPSec context\n");
		return;
	}

	IPSEC_CTX_REF(ctx);
	IPSEC_CTX_TM_PUT(t, ctx);
	LM_DBG("saved IPSec context %p in t=%p\n", ctx, t);
}

static int mod_init(void)
{
	LM_INFO("initializing IPSec protocols\n");
	if (ipsec_tmp_timeout <= 0) {
		LM_ERR("invalid temporary timeout value %d - positive value required\n",
				ipsec_tmp_timeout);
		return -1;
	}

	if (ipsec_sockets_init() < 0)
		return -1;

	if (load_tm_api(&tm_ipsec)!=0) {
		LM_ERR("can't load TM API\n");
		return -1;
	}

	ipsec_ctx_tm_idx = tm_ipsec.t_ctx_register_ptr((context_destroy_f)ipsec_ctx_release);

	if (load_ul_api(&ul_ipsec) != 0) {
		LM_ERR("can't load usrloc API\n");
		return -1;
	}

	if (ul_ipsec.register_ulcb(UL_CONTACT_INSERT|UL_CONTACT_UPDATE|
			UL_CONTACT_DELETE|UL_CONTACT_EXPIRE, ipsec_usrloc_handler) < 0) {
		LM_ERR("can not register callback for usrloc\n");
		return -1;
	}

	if (ipsec_allowed_algorithms.s) {
		ipsec_allowed_algorithms.len = strlen(ipsec_allowed_algorithms.s);
		if (ipsec_add_allowed_algorithms(&ipsec_allowed_algorithms) < 0) {
			LM_ERR("could not parse preferred_algorithms_pairs\n");
			return -1;
		}
	}

	if (ipsec_init() < 0) {
		LM_ERR("could not initiate IPSec engine\n");
		return -1;
	}

	if (ipsec_map_init() < 0) {
		LM_ERR("could not initiate IPSec map\n");
		return -1;
	}
	if (register_script_cb(ipsec_pre_script_handler,
			REQ_TYPE_CB|RPL_TYPE_CB|PRE_SCRIPT_CB, NULL) != 0) {
			LM_ERR("failed to register script callbacks\n");
			return -1;
	}

	/* all good now - register for transaction creation */
	if (tm_ipsec.register_tmcb(0, 0, TMCB_REQUEST_IN, ipsec_handle_register_req,
			NULL, 0) <= 0) {
		LM_ERR("cannot register TMCB_REQUEST_IN callback\n");
	}

	return 0;
}

static void mod_destroy(void)
{
	ipsec_destroy();
	ipsec_map_destroy();
}

struct socket_info_pair {
	struct socket_info *udp, *tcp;
};

static int proto_ipsec_add_listeners(void)
{
	struct socket_id *si;
	struct socket_info_full *it, *udp, *tcp;
	struct socket_info_pair *pair;

	for (it = protos[PROTO_IPSEC].listeners; it; it = it->next) {
		/* extract si and duplicate information as internal */
		si = socket_info2id(&it->socket_info);
		si->proto = PROTO_UDP;
		si->flags |= SI_INTERNAL;
		udp = new_sock_info(si);
		if (!udp) {
			LM_ERR("could not add UDP listening sucket for %s:%d\n",
					si->name, si->port);
			return -1;
		}
		udp->socket_info.internal_proto = PROTO_IPSEC;
		si->proto = PROTO_TCP;
		si->workers = 0;
		si->flags |= SI_REUSEPORT;
		tcp = new_sock_info(si);
		if (!tcp) {
			LM_ERR("could not add TCP listening sucket for %s:%d\n",
					si->name, si->port);
			return -1;
		}
		tcp->socket_info.internal_proto = PROTO_IPSEC;
		pair = pkg_malloc(sizeof *pair);
		if (!pair) {
			LM_ERR("could not add new socket info pair!\n");
			return -1;
		}
		push_sock2list(udp);
		push_sock2list(tcp);
		pair->udp = &udp->socket_info;
		pair->tcp = &tcp->socket_info;
		it->socket_info.extra_data = pair;

	}
	return 0;
}

static int proto_ipsec_init(struct proto_info *pi)
{
	pi->id					= PROTO_IPSEC;
	pi->name				= "ipsec";
	pi->default_port		= ipsec_port;

	pi->tran.init_listener	= proto_ipsec_init_listener;
	pi->tran.bind_listener	= proto_ipsec_bind_listener;
	pi->tran.dst_attr		= tcp_conn_fcntl;
	pi->tran.send			= proto_ipsec_send;

	pi->net.flags			= 0;

	/* we also need to "convert" the IPSec listeners to UDP and TCP ones */
	if (proto_ipsec_add_listeners() < 0)
		return -1;

	return 0;
}


static int proto_ipsec_init_listener(struct socket_info *si)
{
	return 0;
	int ret;
	/* force reuse port for all connections */
	si->flags |= SI_REUSEPORT;
	ret = tcp_init_listener(si);
	if (ret < 0) {
		LM_ERR("cannot initialize IPSec TCP listener\n");
		return ret;
	}
	si->extra_data = (void *)(long)si->socket;
	si->socket = -1;
	/* re-initialize as UDP now */
	return udp_init_listener(si, O_NONBLOCK);
}

static int proto_ipsec_bind_listener(struct socket_info *si)
{
	/* we only need to bind the UDP listener */
	return udp_bind_listener(si);
}

static int proto_ipsec_send(const struct socket_info* source,
		char* buf, unsigned int len, const union sockaddr_union* to,
		unsigned int id)
{
	struct ip_addr ip;
	unsigned short port;
	int ret;
	struct socket_info *ipsec_si;
	struct ipsec_ctx *ctx = NULL;
	struct cell *t;
	struct msg_start fl;
	union sockaddr_union ue_to;

	sockaddr2ip_addr(&ip, &to->s);
	port = su_getport(to);

	parse_first_line(buf, len, &fl);
	if (fl.type == SIP_INVALID) {
		LM_DBG("invalid SIP message to be sent!\n");
		return 0;
	}

	ipsec_si = find_ipsec_socket_info((struct ip_addr *)&source->address, source->port_no, 0, 0);
	if (!ipsec_si) {
		LM_BUG("trying to send through IPSec coming from a non-IPSec socket\n");
		return -1;
	}
	/* check to see if we need to change the socket info */
	if (fl.type == SIP_REQUEST || source->proto == PROTO_UDP) {
		/* we need to send from the client port */
		t = tm_ipsec.t_gett();
		if (t && t != T_UNDEFINED)
			ctx = IPSEC_CTX_TM_GET(t);
		if (!ctx)
			ctx = ipsec_get_ctx_ip_port(&ip, port);
		if (ctx) {
			ipsec_si = ctx->client;
			if (source->proto == PROTO_UDP)
				source = ((struct socket_info_pair *)ipsec_si->extra_data)->udp;
			else
				source = ((struct socket_info_pair *)ipsec_si->extra_data)->tcp;
			/* destination should be ue's server port */
			if (ctx->ue.port_s != port) {
				memcpy(&ue_to, to, sizeof *to);
				su_setport(&ue_to, ctx->ue.port_s);
				to = &ue_to;
			}
			IPSEC_CTX_UNREF(ctx);
		} else {
			LM_WARN("could not find ctx for %s:%hu\n", ip_addr2a(&ip), port);
		}
	} else {
		/* this should be a TCP reply - preserve the socket */
		LM_DBG("keeping same socket for reply!\n");
	}
	LM_DBG("sending SIP %s over %s from %.*s:%hu -> %s:%hu\n",
			(fl.type == SIP_REQUEST?"request":"reply"), proto2a(source->proto),
			source->address_str.len, source->address_str.s, source->port_no,
			ip_addr2a(&ip), port);
	ret = protos[source->proto].tran.send(source, buf, len, to, id);
	if (ret >= 0)
		return ret;
	/* TODO: handle protocol fallback! - need to update via? */
	/* grab the new pair */
	ipsec_si = find_ipsec_socket_info((struct ip_addr *)&source->address, source->port_no, 0, 0);
	if (!ipsec_si) {
		LM_BUG("trying to send through IPSec coming from a non-IPSec socket\n");
		return -1;
	}
	if (source->proto == PROTO_UDP)
		source = ((struct socket_info_pair *)ipsec_si->extra_data)->tcp;
	else
		source = ((struct socket_info_pair *)ipsec_si->extra_data)->udp;
	LM_DBG("fallback SIP %s over %s from %.*s:%hu -> %s:%hu\n",
			(fl.type == SIP_REQUEST?"request":"reply"), proto2a(source->proto),
			source->address_str.len, source->address_str.s, source->port_no,
			ip_addr2a(&ip), port);
	return protos[source->proto].tran.send(source, buf, len, to, id);
}

static int ipsec_aka_auth_match_f(const struct authenticate_body *auth,
    const struct match_auth_hf_desc *md)
{
	return ALG_IS_AKAv1(auth->algorithm);
}

static int ipsec_aka_auth_remove_param(struct sip_msg *msg, struct hdr_field *hdr, str *param)
{
	char *c, *p;

	if (!param->len) {
		LM_ERR("no parameter to remove\n");
		return -2;
	}

	/* first, search previous param, or start of header */
	for (c = param->s; c > hdr->body.s; c--)
		if (*c == ',') {
			c++; /* do not eat the comma */
			break;
		}
	p = c;
	/* now go to the end of param, or EOF */
	for (c = param->s + param->len; c < hdr->body.s + hdr->body.len; c++)
		if (*c == ',') {
			c++; /* eat the comma, if present */
			break;
		}

	if (!del_lump(msg, p - msg->buf, c - p, HDR_WWW_AUTHENTICATE_T)) {
		LM_ERR("could not delelete parameter [%.*s]\n", (int)(c - p), p);
		return -1;
	}
	return 0;
}

static int ipsec_aka_auth_remove(struct sip_msg *msg, struct authenticate_body *auth)
{
	struct hdr_field *hdr;
	for (hdr = msg->www_authenticate; hdr; hdr = hdr->sibling)
		if (hdr->parsed == auth)
			break;
	if (!hdr) {
		LM_BUG("could not find chosen AKA WWW-Authenticate header\n");
		return -1;
	}
	if (ipsec_aka_auth_remove_param(msg, hdr, &auth->ik) < 0) {
		LM_BUG("could not remove AKA IK WWW-Authenticate parameter\n");
		return -1;
	}
	if (ipsec_aka_auth_remove_param(msg, hdr, &auth->ck) < 0) {
		LM_BUG("could not remove AKA CK WWW-Authenticate parameter\n");
		return -1;
	}
	return 0;
}

static int ipsec_add_security_server(struct sip_msg *msg, struct ipsec_ctx *ctx)
{
	struct lump* anchor;
	char *h, *p;
	str tmp;
	str hdr1 = str_init("Supported: sec-agree\r\nSecurity-Server: ipsec-3gpp;q=0.1;prot=esp;mod=trans;spi-s=");
	str hdr2 = str_init(";spi-c=");
	str hdr3 = str_init(";port-s=");
	str hdr4 = str_init(";port-c=");
	str hdr5 = str_init(";alg=");
	str hdr6 = str_init(";ealg=");
	str hdr7 = str_init("\r\n");
	int alg_len, ealg_len;

	alg_len = strlen(ctx->alg->name);
	ealg_len = strlen(ctx->ealg->name);

	h = pkg_malloc(hdr1.len + 5 /* max port */ + hdr2.len + 5 +
			hdr3.len + INT2STR_MAX_LEN /* spi */ + hdr4.len + INT2STR_MAX_LEN +
			hdr5.len + alg_len + hdr6.len + strlen(ctx->ealg->name) + ealg_len);
	if (!h) {
		LM_ERR("oom for Security-Server header\n");
		return -1;
	}
	p = h;
	memcpy(p, hdr1.s, hdr1.len);
	p += hdr1.len;
	tmp.s = int2str(ctx->me.spi_s, &tmp.len);
	memcpy(p, tmp.s, tmp.len);
	p += tmp.len;
	memcpy(p, hdr2.s, hdr2.len);
	p += hdr2.len;
	tmp.s = int2str(ctx->me.spi_c, &tmp.len);
	memcpy(p, tmp.s, tmp.len);
	p += tmp.len;
	memcpy(p, hdr3.s, hdr3.len);
	p += hdr3.len;
	tmp.s = int2str(ctx->me.port_s, &tmp.len);
	memcpy(p, tmp.s, tmp.len);
	p += tmp.len;
	memcpy(p, hdr4.s, hdr4.len);
	p += hdr4.len;
	tmp.s = int2str(ctx->me.port_c, &tmp.len);
	memcpy(p, tmp.s, tmp.len);
	p += tmp.len;
	memcpy(p, hdr5.s, hdr5.len);
	p += hdr5.len;
	memcpy(p, ctx->alg->name, alg_len);
	p += alg_len;
	memcpy(p, hdr6.s, hdr6.len);
	p += hdr6.len;
	memcpy(p, ctx->ealg->name, ealg_len);
	p += ealg_len;
	memcpy(p, hdr7.s, hdr7.len);
	p += hdr7.len;

	anchor = anchor_lump(msg, msg->unparsed - msg->buf, 0);
	if (!anchor) {
		LM_ERR("could not add an anchor for Security-Server header\n");
		return -1;
	}
	if (insert_new_lump_before(anchor, h, p - h, 0) == 0) {
		LM_ERR("can't insert Security-Server header lump\n");
		pkg_free(h);
		return -1;
	}
	return 0;
}

static auth_body_t *ipsec_get_auth(struct sip_msg *msg)
{
	struct hdr_field *ptr, *prev = NULL;
	auth_body_t *auth;
	dig_cred_t *d;

	if (parse_headers(msg, HDR_AUTHORIZATION_F, 0) == -1) {
		LM_ERR("could not find Authorization header!\n");
		return NULL;
	}

	do {
		ptr = (prev?msg->last_header:msg->authorization);
		prev = ptr;
		if (parse_credentials(ptr) == 0) {
			auth = ptr->parsed;
			d = &auth->digest;
			if (ALG_IS_AKAv1(d->alg.alg_parsed)) {
				auth->authorized = ptr;
				return auth;
			}
		} else {
			LM_ERR("could not parse Authorization header!\n");
		}
	} while (parse_headers(msg, HDR_AUTHORIZATION_F, 1) != -1 &&
		msg->last_header != prev && msg->last_header->type == HDR_AUTHORIZATION_F);
	return NULL;
}

/* check if it was received on one of our listening interfaces */
static struct socket_info *ipsec_get_socket_info(const struct socket_info *bind_address)
{
	struct socket_info_full *si;
	struct socket_info_pair *pair;
	if (!bind_address || !(bind_address->flags & SI_INTERNAL))
		return NULL;
	for (si = protos[PROTO_IPSEC].listeners; si; si = si->next) {
		pair = si->socket_info.extra_data;
		if (pair->udp == bind_address || pair->tcp == bind_address)
			return &si->socket_info;
	}
	return NULL;
}



static int w_ipsec_create(struct sip_msg *msg, int *_port_ps, int *_port_pc,
		struct ipsec_allowed_algo *algos)
{
	struct cell *t;
	int port_ps, port_pc;
	struct socket_info *ss, *sc, *si;
	struct sip_msg *req;
	struct authenticate_body *auth = NULL;
	sec_agree_body_t *sa;
	struct ipsec_socket *sock;
	struct ipsec_ctx *ctx;
	struct ipsec_user *user;
	auth_body_t *a = NULL;
	str *impu, *impi;
	int ret = -1;
	unsigned short prev_port_pc = 0;

	if (msg->first_line.type != SIP_REPLY || msg->REPLY_STATUS != 401) {
		LM_ERR("can only be called on 401 Reply\n");
		return -1;
	}

	if (_port_ps)
		port_ps = *_port_ps;
	else
		port_ps = ipsec_default_server_port;
	if (_port_pc)
		port_pc = *_port_pc;
	else
		port_pc = ipsec_default_client_port;

	/* parse cseq header */
	if (parse_headers(msg, HDR_CSEQ_F, 0) < 0) {
		LM_ERR("cannot parse cseq header\n");
		return -1;
	}

	if (!msg->cseq || !msg->cseq->body.s) {
		LM_ERR("cseq header empty\n");
		return -1;
	}

	if (get_cseq(msg)->method_id != METHOD_REGISTER) {
		LM_ERR("REGISTER required to create ipsec tunnel)\n");
		return -1;
	}

	/* search for our AKA credentials */
	if (parse_www_authenticate_header(msg, &ipsec_aka_auth_match, &auth) < 0) {
		LM_ERR("could not find any valid AKA WWW-Authenticate header\n");
		return -3;
	}

	/* this is a reply - search for the request */
	t = tm_ipsec.t_gett();
	if (!t || t == T_UNDEFINED) {
		LM_ERR("could not find a transaction for this REGISTER (reply)\n");
		return -1;
	}
	req = t->uas.request;
	if (!req) {
		LM_ERR("could not find a REGISTER request for this transaction\n");
		return -1;
	}

	a = ipsec_get_auth(req);
	if (!auth) {
		LM_DBG("could not find any auth header!\n");
		return -1;
	}
	impu = aka_get_public_identity(msg, HDR_AUTHORIZATION_T);
	if (!impu) {
		LM_DBG("could not get public identity!\n");
		return -1;
	}
	impi = aka_get_private_identity(msg, a, HDR_AUTHORIZATION_T);
	if (!impi) {
		LM_DBG("could not get private identity!\n");
		return -1;
	}

	user = ipsec_get_user(&req->rcv.src_ip, impi, impu);
	if (!user) {
		LM_ERR("could not get a new IPSec user\n");
		return -1;
	}

	/* fetch the identity of the user */
	/* remove ik and ck parameters from the authenticate header
	 * Note:  this also ensures that they exist! */
	if (ipsec_aka_auth_remove(msg, auth) < 0) {
		LM_ERR("could not remove AKA parameters\n");
		ret = -3;
		goto release_user;
	}
	/* TODO: double check for sec-agree in Required/Supported */

	/* check if the request was secured */
	si = ipsec_get_socket_info(req->rcv.bind_address);
	if (si) {
		/*
		 * the request came secure, this means that there is an already
		 * existing SA/ctx for this USER - try to locate it
		 */
		ctx = IPSEC_CTX_TM_GET(t);
		if (ctx)
			prev_port_pc = ctx->me.port_c;
		else
			prev_port_pc = 0;
	} else {
		prev_port_pc = 0;
		/* message was received unprotected - remove all temporary SAs */
		ipsec_ctx_release_tmp_user(user);
	}

	/* locate the received IP */
	ret = -2;
	ss = find_ipsec_socket_info(&req->rcv.dst_ip, port_ps, port_pc, prev_port_pc);
	if (!ss) {
			LM_INFO("could not find a server listener on %s:%d!\n",
				ip_addr2a(&req->rcv.dst_ip), port_ps);
		goto release_user;
	}
	sc = find_ipsec_socket_info(&req->rcv.dst_ip, port_pc, ss->port_no, prev_port_pc);
	if (!sc) {
		LM_INFO("could not find a client listener on %s:%d!\n",
				ip_addr2a(&req->rcv.dst_ip), port_pc);
		goto release_user;
	}

	sa = ipsec_get_security_client(req, algos);
	if (!sa) {
		LM_ERR("could not find a matching Secrity-Client header\n");
		ret = -2;
		goto release_user;
	}

	ret = -5;
	ctx = ipsec_ctx_new(sa, &req->rcv.src_ip, ss, sc, &auth->ck, &auth->ik, 0, 0);
	if (!ctx) {
		LM_ERR("could not allocate new IPSec ctx\n");
		goto release_user;
	}
	ipsec_ctx_push(ctx);

	sock = ipsec_sock_new();
	if (!sock) {
		LM_ERR("could not create IPSec socket\n");
		goto release_user;
	}
	/*
	 * Flows according to 3GPP TS 33.203
	 */
	if (ipsec_sa_add_all(sock, ctx) < 0)
		goto close;

	/* all good now - add Security-Server */
	if (ipsec_add_security_server(msg, ctx) < 0) {
		LM_ERR("could not add Security-Server header\n");
		ipsec_sa_rm_all(sock, ctx);
		goto close;
	}
	/* add the context as temporarily */
	ipsec_ctx_push_user(user, ctx, IPSEC_STATE_TMP);
	ipsec_sock_close(sock);

	ipsec_release_user(user);

	return 1;
close:
	ipsec_sock_close(sock);
release_user:
	ipsec_release_user(user);
	return ret;
}

static int fixup_ipsec_create_algos(void **param)
{
	*param = ipsec_parse_allowed_algorithms((str *)*param);
	return 0;
}

static int fixup_ipsec_create_algos_free(void **param)
{
	ipsec_free_allowed_algorithms(*param);
	return 0;
}

str pv_ipsec_ctx_type[] = {
	str_init("alg"),     /* 0 */
	str_init("ealg"),    /* 1 */
	str_init("ip"),      /* 2 */
	str_init("spi-c"),   /* 3 */
	str_init("spi-s"),   /* 4 */
	str_init("port-c"),  /* 5 */
	str_init("port-s"),  /* 6 */
	str_init("ik"),      /* 7 */
	str_init("ck"),      /* 8 */
};

static int pv_parse_ipsec_ctx_flag(str *name)
{
	int i;
	for (i = 0; i < (sizeof(pv_ipsec_ctx_type)/sizeof(pv_ipsec_ctx_type[0])); i++) {
		if (str_match(name, &pv_ipsec_ctx_type[i]))
			return i;
	}
	return -1;
}

static int pv_parse_ipsec_ctx(pv_spec_p sp, const str *in)
{
	pv_elem_t *format;

	LM_DBG("name %p with name <%.*s>\n", &sp->pvp.pvn, in->len, in->s);
	if (pv_parse_format( in, &format)!=0) {
		LM_ERR("failed to ipsec variable name format <%.*s> \n",
			in->len,in->s);
		return -1;
	}

	if (format->next==NULL && format->spec.type==PVT_NONE) {
		sp->pvp.pvn.type = PV_NAME_INTSTR;
		sp->pvp.pvn.u.isname.name.n = pv_parse_ipsec_ctx_flag(&format->text);
		if (sp->pvp.pvn.u.isname.name.n < 0) {
			LM_ERR("unknown flag [%.*s]\n", format->text.len, format->text.s);
			return -1;
		}
	} else {
		sp->pvp.pvn.type = PV_NAME_PVAR;
		sp->pvp.pvn.u.dname = (void*)format;
	}

	return 0;
}

static int pv_get_ipsec_ctx(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res, int ue)
{
	int name;
	str tmp;
	struct ipsec_endpoint *e;
	struct ipsec_ctx *ctx;

	if (!msg || !res)
		return -1;
	res->rs.s = NULL;
	if (param->pvn.type == PV_NAME_PVAR) {
		if (pv_printf_s(msg, (pv_elem_t *)param->pvn.u.dname, &tmp)) {
			LM_ERR("could not get variable's name\n");
			return -1;
		}
		name = pv_parse_ipsec_ctx_flag(&tmp);
		if (name < 0)
			return -1;
	} else {
		name = param->pvn.u.isname.name.n;
	}
	ctx = ipsec_ctx_get();
	if (!ctx)
		return pv_get_null(msg, param, res);

	e = (ue?&ctx->ue:&ctx->me);

	switch (name) {
	case 0: /* alg */
		if (!ctx->alg)
			return pv_get_null(msg, param, res);
		res->rs.s = (char *)ctx->alg->name;
		res->rs.len = strlen(res->rs.s);
		break;
	case 1: /* ealg */
		if (!ctx->ealg)
			return pv_get_null(msg, param, res);
		res->rs.s = (char *)ctx->ealg->name;
		res->rs.len = strlen(res->rs.s);
		break;
	case 2: /* ip */
		res->rs.s = ip_addr2a(&e->ip);
		res->rs.len = strlen(res->rs.s);
		break;
	case 3: /* spi-c */
		res->ri = e->spi_c;
		break;
	case 4: /* spi-s */
		res->ri = e->spi_s;
		break;
	case 5: /* port-c */
		res->ri = e->port_c;
		break;
	case 6: /* port-s */
		res->ri = e->port_s;
		break;
	case 7: /* ik */
		res->rs = ctx->ik;
		break;
	case 8: /* ck */
		res->rs = ctx->ck;
		break;
	default:
		LM_BUG("invalid name %d\n", name);
		return -1;
	}
	if (!res->rs.s) {
		res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;
		res->rs.s = int2str(res->ri, &res->rs.len);
	} else {
		res->flags = PV_VAL_STR;
	}

	return 0;
}

static int pv_get_ipsec_ctx_me(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	return pv_get_ipsec_ctx(msg, param, res, 0);
}

static int pv_get_ipsec_ctx_ue(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	return pv_get_ipsec_ctx(msg, param, res, 1);
}

static int ipsec_handle_register(struct sip_msg *msg, struct socket_info *si)
{
	struct ip_addr *ip;
	struct via_body *via;
	struct ipsec_ctx *ctx;
	struct ipsec_user *user;
	struct sec_agree_body *sa;
	auth_body_t *auth = NULL;
	int is_secure = 1, extend_tmp = 0;
	struct lump* anchor;
	str integrity_protected = str_init(",integrity-protected=");
	char *is_protected;
	str *impu, *impi;

	if (parse_headers(msg, HDR_VIA1_F|HDR_VIA2_F, 0) < 0 || !msg->via1) {
		LM_ERR("could not parse VIA headers!\n");
		goto drop;
	}
	if (msg->via2) {
		LM_ERR("message has a second via!\n");
		goto drop;
	}
	via = msg->via1;
	ip = str2ip(&via->host);
	if (!ip) {
		ip = str2ip6(&via->host);
		if (!ip)
			LM_WARN("TODO: resolve host %.*s\n", via->host.len, via->host.s);
	}
	auth = ipsec_get_auth(msg);
	if (!auth) {
		LM_DBG("could not find any auth header!\n");
		return SCB_RUN_ALL;
	}
	impu = aka_get_public_identity(msg, HDR_AUTHORIZATION_T);
	if (!impu) {
		LM_DBG("could not get public identity!\n");
		return SCB_RUN_ALL;
	}
	impi = aka_get_private_identity(msg, auth, HDR_AUTHORIZATION_T);
	if (!impi) {
		LM_DBG("could not get private identity!\n");
		return SCB_RUN_ALL;
	}

	user = ipsec_find_user(&msg->rcv.src_ip, impi, impu);
	if (!user) {
		LM_WARN("received unprotected message from %s:%hu on IPSec listener %s:%s:%hu (%.*s/%.*s)!\n",
			ip_addr2a(&msg->rcv.src_ip), msg->rcv.src_port,
			(msg->rcv.bind_address->proto==PROTO_UDP?"UDP":"TCP"),
			ip_addr2a(&msg->rcv.dst_ip), msg->rcv.dst_port,
			impi->len, impi->s, impu->len, impu->s);
		return SCB_RUN_ALL;
	}

	if (ip && !ip_addr_cmp(&user->ip, ip)) {
		LM_ERR("Via host %.*s is different than User's %s\n",
				via->host.len, via->host.s, ip_addr2a(&user->ip));
		goto drop_user;
	}

	ctx = ipsec_get_ctx_user(user, &msg->rcv);
	if (!ctx) {
		LM_ERR("could not find any IPSec context!\n");
		goto drop_user;
	}
	lock_get(&ctx->lock);
	switch (ctx->state) {
	case IPSEC_STATE_TMP:
		/* we've got a temporary association, check the Security-Client/Verify */
		if (parse_headers(msg, HDR_SECURITY_CLIENT_F|HDR_SECURITY_VERIFY_F, 0) < 0) {
			LM_ERR("could not parse security headers!\n");
			goto drop_release;
		}
		if (!msg->security_client) {
			LM_ERR("no Security-Client header for temporary association!\n");
			goto drop_release;
		}
		if (!msg->security_verify) {
			LM_ERR("no Security-Verify header for temporary association!\n");
			goto drop_release;
		}
		if (parse_sec_agree(msg->security_verify) < 0) {
			LM_ERR("could not parse Security-Verify header for temporary association!\n");
			goto drop_release;
		}
		sa = msg->security_verify->parsed;
		if (!sa || sa->invalid) {
			LM_ERR("invalid Security-Verify header for temporary association!\n");
			goto drop_release;
		}
		if (sa->mechanism != SEC_AGREE_MECHANISM_IPSEC_3GPP) {
			LM_ERR("invalid Security-Verify mechanism for temporary association!\n");
			goto drop_release;
		}
		if (!ipsec_spi_match(ctx->spi_c, sa->ts3gpp.spi_c)) {
			LM_ERR("invalid Security-Verify spi_c for temporary association!\n");
			goto drop_release;
		}
		if (!ipsec_spi_match(ctx->spi_s, sa->ts3gpp.spi_s)) {
			LM_ERR("invalid Security-Verify spi_s for temporary association!\n");
			goto drop_release;
		}
		if (!str_match(_str(ctx->alg->name), &sa->ts3gpp.alg_str)) {
			LM_ERR("invalid Security-Verify alg for temporary association!\n");
			goto drop_release;
		}
		if (!str_match(_str(ctx->ealg->name), &sa->ts3gpp.ealg_str)) {
			LM_ERR("invalid Security-Verify ealg for temporary association!\n");
			goto drop_release;
		}

		/* TODO: check Security-Client */

		/* remove Security-Client and Security-Verify */
		if (del_lump(msg, msg->security_client->name.s - msg->buf,
				msg->security_client->len, HDR_SECURITY_CLIENT_T) == 0)
			LM_ERR("could not delete Security-Client header\n");
		if (del_lump(msg, msg->security_verify->name.s - msg->buf,
				msg->security_verify->len, HDR_SECURITY_VERIFY_T) == 0)
			LM_ERR("could not delete Security-Verify header\n");

		/* all good - mark the context as stable */
		extend_tmp = 1;

		is_secure = 0;

		break;
	case IPSEC_STATE_OK:
		break;
	case IPSEC_STATE_INVALID:
		LM_WARN("received message on an expired association!\n");
		goto drop_release;
	case IPSEC_STATE_NEW:
		LM_WARN("received message on new/un-initialized association!\n");
		goto drop_release;
	}
	/*
	 * TS 133.203 7.2 TODO: check if there are 6 SAs
3. The SIP application at the P-CSCF shall check upon receipt of an initial REGISTER message or a re-REGISTER
message that the pair (UE_IP_address, UE_protected_client_port), where the UE_IP_address is the source IP
address in the packet header and the protected client port is sent as part of the security mode set-up procedure
(cf. clause 7.2), has not yet been associated with entries in the "SA_table". Furthermore, the P-CSCF shall check
that, for any one IMPI, no more than six SAs per direction are stored at any one time. If these checks are
unsuccessful the registration is aborted and a suitable error message is sent to the UE.
NOTE 13: According to clause 7.4 on SA handling, at most six SAs per direction per registered contact may exist at
a P-CSCF for one IMPI at any one time.
*/

	/* pushing in global context */
	IPSEC_CTX_REF_UNSAFE(ctx);
	ipsec_ctx_push(ctx);
	lock_release(&ctx->lock);

	if (extend_tmp)
		ipsec_ctx_extend_tmp(ctx);

	/* we need to add the integrity-protected - search for Authorization header */
	if (!is_secure) {
		if (auth->digest.response.s && auth->digest.response.len)
			is_secure = 1;
	}
	is_protected = pkg_malloc(integrity_protected.len + (is_secure?3:2));
	if (!is_protected) {
		LM_ERR("oom for integrity-protected parameter\n");
		return SCB_RUN_ALL;
	}
	memcpy(is_protected, integrity_protected.s, integrity_protected.len);
	if (is_protected) {
		memcpy(is_protected + integrity_protected.len, "yes", 3);
		integrity_protected.len += 3;
	} else {
		memcpy(is_protected + integrity_protected.len, "no", 2);
		integrity_protected.len += 2;
	}
	anchor = anchor_lump(msg, auth->authorized->body.s +
			auth->authorized->body.len - msg->buf, 0);
	if (!anchor || insert_new_lump_before(anchor, is_protected, integrity_protected.len, 0) == 0) {
		LM_ERR("could not add an anchor for integrity-protected parameter\n");
		pkg_free(is_protected);
	}

	return SCB_RUN_ALL;
drop_release:
	lock_release(&ctx->lock);
	IPSEC_CTX_UNREF(ctx);
drop_user:
	ipsec_release_user(user);
drop:
	return SCB_DROP_MSG;
}

static int ipsec_pre_script_handler(struct sip_msg *msg, void *param)
{
	int ret = SCB_RUN_ALL;
	struct socket_info *si;

	if (!msg || msg == FAKED_REPLY || !(si = ipsec_get_socket_info(msg->rcv.bind_address)))
		return SCB_RUN_ALL;
	LM_DBG("message received over IPSec %s tunnel %s:%hu -> %s:%hu\n",
			(msg->rcv.bind_address->proto==PROTO_UDP?"UDP":"TCP"),
			ip_addr2a(&msg->rcv.src_ip), msg->rcv.src_port,
			ip_addr2a(&msg->rcv.dst_ip), msg->rcv.dst_port);

	/* parse cseq header */
	if (parse_headers(msg, HDR_CSEQ_F, 0) < 0) {
		LM_ERR("cannot parse cseq header\n");
		return -1;
	}

	if (!msg->cseq || !msg->cseq->body.s) {
		LM_ERR("cseq header empty\n");
		return -1;
	}

	if (msg->first_line.type == SIP_REQUEST) {
		if (get_cseq(msg)->method_id == METHOD_REGISTER)
			ret = ipsec_handle_register(msg, si);
	}

	return ret;
}

static str ipsec_usrloc_ck = str_init("ipsec.ck");
static str ipsec_usrloc_ik = str_init("ipsec.ik");
static str ipsec_usrloc_alg = str_init("ipsec.alg");
static str ipsec_usrloc_ealg = str_init("ipsec.ealg");
static str ipsec_usrloc_impi = str_init("ipsec.impi");
static str ipsec_usrloc_impu = str_init("ipsec.impu");
static str ipsec_usrloc_spi_pc = str_init("ipsec.spi_pc");
static str ipsec_usrloc_spi_ps = str_init("ipsec.spi_ps");
static str ipsec_usrloc_spi_uc = str_init("ipsec.spi_uc");
static str ipsec_usrloc_spi_us = str_init("ipsec.spi_us");
static str ipsec_usrloc_port_pc = str_init("ipsec.port_pc");
static str ipsec_usrloc_port_uc = str_init("ipsec.port_uc");
static str ipsec_usrloc_port_us = str_init("ipsec.port_us");

#define UL_GET_S_RET(_c, _s, _d, _e) \
	({ \
		int_str_t *ret = ul_ipsec.get_ucontact_key(_c, &(_s)); \
		if (!ret || !ret->is_str) { \
			LM_ERR("%s%s!\n", _d, (ret?"has invalid type":"not found")); \
			_e; \
		} \
		(ret->s); \
	})
#define UL_GET_S(_c, _s, _d) UL_GET_S_RET(_c, _s, _d, return)

#define UL_GET_I_RET(_c, _s, _d, _e) \
	({ \
		int_str_t *ret = ul_ipsec.get_ucontact_key(_c, &(_s)); \
		if (!ret || ret->is_str) { \
			LM_ERR("%s%s!\n", _d, (ret?"has invalid type":"not found")); \
			_e; \
		} \
		(ret->i); \
	})
#define UL_GET_I(_c, _s, _d) UL_GET_I_RET(_c, _s, _d, return)

#define INT_STR_S(_s) ({\
		static int_str_t _is; \
		_is.s = *(_s); \
		_is.is_str = 1; \
		(&_is); \
	})

#define INT_STR_I(_i) ({\
		static int_str_t _is; \
		_is.i = (_i); \
		_is.is_str = 0; \
		(&_is); \
	})

static struct ipsec_user *ipsec_usrloc_get_user(ucontact_t *contact)
{
	str impi, impu;
	str *uris;
	struct ip_addr *ip;
	struct sip_uri uri;

	if (contact->received.s)
		uris = &contact->received;
	else
		uris = &contact->c;

	if (parse_uri(uris->s, uris->len, &uri) < 0) {
		LM_ERR("could not parse contact uri %.*s\n", uris->len, uris->s);
		return NULL;
	}

	ip = str2ip(&uri.host);
	if (!ip) {
		ip = str2ip6(&uri.host);
		if (!ip) {
			LM_WARN("TODO: resolve host %.*s\n", uri.host.len, uri.host.s);
			return NULL;
		}
	}
	impi = UL_GET_S_RET(contact, ipsec_usrloc_impi, "IMPI", return NULL);
	impu = UL_GET_S_RET(contact, ipsec_usrloc_impu, "IMPU", return NULL);
	return ipsec_get_user(ip, &impi, &impu);
}

static void ipsec_usrloc_restore(ucontact_t *contact)
{
	str ck, ik;
	int spi_pc, spi_ps, port_pc;
	sec_agree_body_t sa;
	struct socket_info *sc, *ss;
	struct ipsec_user *user;
	struct ipsec_socket *sock;
	struct ipsec_ctx *ctx;
	LM_DBG("restoring IPSec context for %.*s (%.*s)\n",
			contact->aor->len, contact->aor->s,
			contact->c.len, contact->c.s);

	/* simulate a sec_agree_body */
	memset(&sa, 0, sizeof sa);
	sa.mechanism = SEC_AGREE_MECHANISM_IPSEC_3GPP;
	sa.mechanism_str = str_init("ipsec-3gpp");
	sa.ts3gpp.pref = 1000;
	sa.ts3gpp.pref_str = str_init("1000");
	ck = UL_GET_S(contact, ipsec_usrloc_ck, "CK");
	ik = UL_GET_S(contact, ipsec_usrloc_ik, "IK");
	sa.ts3gpp.alg_str = UL_GET_S(contact, ipsec_usrloc_alg, "ALG");
	sa.ts3gpp.prot_str = str_init("esp");
	sa.ts3gpp.mod_str = str_init("trans");
	sa.ts3gpp.ealg_str = UL_GET_S(contact, ipsec_usrloc_ealg, "EALG");
	spi_pc = UL_GET_I(contact, ipsec_usrloc_spi_pc, "SPI-PC");
	spi_ps = UL_GET_I(contact, ipsec_usrloc_spi_ps, "SPI-PS");
	sa.ts3gpp.spi_c = UL_GET_I(contact, ipsec_usrloc_spi_uc, "SPI-UC");
	sa.ts3gpp.spi_s = UL_GET_I(contact, ipsec_usrloc_spi_us, "SPI-US");
	port_pc = UL_GET_I(contact, ipsec_usrloc_port_pc, "port_pc");
	sa.ts3gpp.port_c = UL_GET_I(contact, ipsec_usrloc_port_uc, "port_uc");
	sa.ts3gpp.port_s = UL_GET_I(contact, ipsec_usrloc_port_us, "port_us");

	ss = (struct socket_info *)contact->sock;
	sc = find_ipsec_socket_info(&ss->address, port_pc, 0, 0);
	if (!sc) {
		LM_INFO("could not find a client listener on %.*s:%d!\n",
				ss->name.len, ss->name.s, port_pc);
		return;
	}

	user = ipsec_usrloc_get_user(contact);
	if (!user) {
		LM_ERR("could not get new user\n");
		return;
	}

	ctx = ipsec_ctx_new(&sa, &user->ip, ss, sc, &ck, &ik, spi_pc, spi_ps);
	if (!ctx) {
		LM_ERR("could not allocate new IPSec ctx\n");
		goto release_user;
	}

	sock = ipsec_sock_new();
	if (!sock) {
		LM_ERR("could not create IPSec socket\n");
		goto release_ctx;
	}
	/*
	 * Flows according to 3GPP TS 33.203
	 */
	if (ipsec_sa_add_all(sock, ctx) < 0)
		goto close;

	/* add the context as temporarily */
	ipsec_ctx_push_user(user, ctx, IPSEC_STATE_OK);
	ipsec_sock_close(sock);

	ipsec_release_user(user);
	return;
close:
	ipsec_sock_close(sock);
release_ctx:
	ipsec_ctx_release(ctx);
release_user:
	ipsec_release_user(user);
}

static void ipsec_usrloc_insert(ucontact_t *contact)
{
	struct cell *t;
	struct ipsec_ctx *ctx;
	int remove_tmp = 0;

	/* if we have a transaction, we need to have a context as well */
	t = tm_ipsec.t_gett();
	if (!t || t == T_UNDEFINED) {
		/* this is an insert after a load */
		ipsec_usrloc_restore(contact);
		return;
	}
	ctx = IPSEC_CTX_TM_GET(t);
	LM_DBG("searched IPSec context %p in t=%p\n", ctx, t);
	if (!ctx) {
		LM_DBG("no IPSec context for %.*s (%.*s)\n",
				contact->aor->len, contact->aor->s,
				contact->c.len, contact->c.s);
		return;
	}
	LM_DBG("saving IPSec context for %.*s (%.*s)\n",
			contact->aor->len, contact->aor->s,
			contact->c.len, contact->c.s);
	ul_ipsec.put_ucontact_key(contact, &ipsec_usrloc_ck, INT_STR_S(&ctx->ck));
	ul_ipsec.put_ucontact_key(contact, &ipsec_usrloc_ik, INT_STR_S(&ctx->ik));
	ul_ipsec.put_ucontact_key(contact, &ipsec_usrloc_impi, INT_STR_S(&ctx->user->impi));
	ul_ipsec.put_ucontact_key(contact, &ipsec_usrloc_impu, INT_STR_S(&ctx->user->impu));
	ul_ipsec.put_ucontact_key(contact, &ipsec_usrloc_alg, INT_STR_S(_str(ctx->alg->name)));
	ul_ipsec.put_ucontact_key(contact, &ipsec_usrloc_ealg, INT_STR_S(_str(ctx->ealg->name)));
	ul_ipsec.put_ucontact_key(contact, &ipsec_usrloc_spi_pc, INT_STR_I(ctx->me.spi_c));
	ul_ipsec.put_ucontact_key(contact, &ipsec_usrloc_spi_ps, INT_STR_I(ctx->me.spi_s));
	ul_ipsec.put_ucontact_key(contact, &ipsec_usrloc_spi_uc, INT_STR_I(ctx->ue.spi_c));
	ul_ipsec.put_ucontact_key(contact, &ipsec_usrloc_spi_us, INT_STR_I(ctx->ue.spi_s));
	ul_ipsec.put_ucontact_key(contact, &ipsec_usrloc_port_pc, INT_STR_I(ctx->me.port_c));
	ul_ipsec.put_ucontact_key(contact, &ipsec_usrloc_port_uc, INT_STR_I(ctx->ue.port_c));
	ul_ipsec.put_ucontact_key(contact, &ipsec_usrloc_port_us, INT_STR_I(ctx->ue.port_s));
	
	/* all good mark the SA as OK */
	lock_get(&ctx->lock);
	remove_tmp = (ctx->state == IPSEC_STATE_TMP);
	ctx->state = IPSEC_STATE_OK;
	lock_release(&ctx->lock);
	if (remove_tmp)
		ipsec_ctx_remove_tmp(ctx);
}

static void ipsec_usrloc_update(ucontact_t *contact,
		str *prev_host, unsigned short prev_port)
{
	struct ipsec_user *user;
	struct ipsec_ctx *ctx;

	LM_DBG("updating IPSec context for %.*s (%.*s)\n",
			contact->aor->len, contact->aor->s,
			contact->c.len, contact->c.s);
	user = ipsec_usrloc_get_user(contact);
	if (!user) {
		LM_ERR("could not find an IPSec user for this contact!\n");
		return;
	}
	ctx = ipsec_ctx_find(user, prev_port);
	if (ctx)
		ipsec_ctx_release(ctx);
	else
		LM_ERR("could not find SA on port %hu\n", prev_port);
	ipsec_release_user(user);
	/* now overwrite the information with the new SA */
	ipsec_usrloc_insert(contact);
}

static void ipsec_usrloc_delete(ucontact_t *contact)
{
	struct ipsec_user *user;
	struct ipsec_ctx *ctx;
	unsigned short port_uc;

	LM_DBG("removing IPSec context for %.*s (%.*s)\n",
			contact->aor->len, contact->aor->s,
			contact->c.len, contact->c.s);
	user = ipsec_usrloc_get_user(contact);
	if (!user) {
		LM_ERR("could not find an IPSec user for this contact!\n");
		return;
	}
	port_uc = UL_GET_I(contact, ipsec_usrloc_port_uc, "port_uc");
	ctx = ipsec_ctx_find(user, port_uc);
	if (ctx)
		ipsec_ctx_release(ctx);
	else
		LM_ERR("could not find SA on port %hu\n", port_uc);
	ipsec_release_user(user);
}
#undef INT_STR_I
#undef INT_STR_S
#undef UL_GET_S
#undef UL_GET_I
#undef UL_GET_S_RET
#undef UL_GET_I_RET

void ipsec_usrloc_handler(void *binding, ul_cb_type type, ul_cb_extra *extra)
{
	ucontact_t *contact = (ucontact_t*)binding;
	switch (type) {
		case UL_CONTACT_INSERT:
			ipsec_usrloc_insert(contact);
			break;
		case UL_CONTACT_UPDATE:
			if (extra)
				ipsec_usrloc_update(contact, &extra->contact_update.prev_name,
						extra->contact_update.prev_port);
			else
				ipsec_usrloc_update(contact, NULL, 0);
			break;
		case UL_CONTACT_DELETE:
		case UL_CONTACT_EXPIRE:
			ipsec_usrloc_delete(contact);
			break;
		default:
			break;
	}
}
