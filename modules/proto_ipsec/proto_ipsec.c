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
#include "../../data_lump.h"
#include "../tm/tm_load.h"
#include "ipsec_algo.h"
#include "ipsec.h"


static int ipsec_default_client_port = 0;
static int ipsec_default_server_port = 0;
static str ipsec_allowed_algorithms;
static struct tm_binds tm_ipsec;

static int ipsec_port = 5062;
static int mod_init(void);
static void mod_destroy(void);
static int proto_ipsec_init(struct proto_info *pi);
static int proto_ipsec_init_listener(struct socket_info *si);
static int ipsec_pre_script_handler( struct sip_msg *msg, void *param);

static int ipsec_aka_auth_match_f(const struct authenticate_body *auth,
    const struct match_auth_hf_desc *md);
static struct match_auth_hf_desc ipsec_aka_auth_match =
	MATCH_AUTH_HF(ipsec_aka_auth_match_f, NULL);

static int w_ipsec_create(struct sip_msg *msg, int *port_ps, int *port_pc);

static const cmd_export_t cmds[] = {
	{"ipsec_create", (cmd_function)w_ipsec_create, {
		{CMD_PARAM_INT|CMD_PARAM_OPT, 0, 0},
		{CMD_PARAM_INT|CMD_PARAM_OPT, 0, 0},
		{0,0,0}},
		ONREPLY_ROUTE},
	{"proto_init", (cmd_function)proto_ipsec_init, {{0,0,0}}, 0},
	{0,0,{{0,0,0}},0}
};


static const param_export_t params[] = {
	{ "port",							INT_PARAM, &ipsec_port },
	{ "min_spi",						INT_PARAM, &ipsec_min_spi },
	{ "max_spi",						INT_PARAM, &ipsec_max_spi },
	{ "default_client_port",			INT_PARAM, &ipsec_default_client_port },
	{ "default_server_port",			INT_PARAM, &ipsec_default_server_port },
	{ "allowed_algorithms",				STR_PARAM, &ipsec_allowed_algorithms },
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

static struct socket_info *find_ipsec_socket_info(struct ip_addr *ip, unsigned int port, unsigned int no_port)
{
	struct socket_info_full *it;
	for (it = protos[PROTO_IPSEC].listeners; it; it = it->next) {
		LM_DBG("searching port %d vs %d (no %d)\n", port, it->socket_info.port_no, no_port);
		if (port && it->socket_info.port_no != port)
			continue;
		if (no_port && it->socket_info.port_no == no_port)
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
		if (!find_ipsec_socket_info(NULL, ipsec_default_client_port, 0))
			LM_ERR("cannot find any socket listening on default client port %d\n",
					ipsec_default_client_port);
	}
	if (ipsec_default_server_port &&
			!find_ipsec_socket_info(NULL, ipsec_default_server_port, 0))
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

static int mod_init(void)
{
	LM_INFO("initializing IPSec protocols\n");
	/* we must have at least two listeners/ports for each IP */

	if (ipsec_sockets_init() < 0)
		return -1;

	if (load_tm_api(&tm_ipsec)!=0) {
		LM_ERR("can't load TM API\n");
		return -1;
	}

	if (ipsec_add_allowed_algorithms(&ipsec_allowed_algorithms) < 0) {
		LM_ERR("could not parse preferred_algorithms_pairs\n");
		return -1;
	}
	if (ipsec_init() < 0) {
		LM_ERR("could not initiate IPSec engine\n");
		return -1;
	}
	if (register_script_cb(ipsec_pre_script_handler,
			REQ_TYPE_CB|RPL_TYPE_CB|PRE_SCRIPT_CB, NULL) != 0) {
			LM_ERR("failed to register script callbacks\n");
			return -1;
	}

	return 0;
}

static void mod_destroy(void)
{
	ipsec_destroy();
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
			LM_ERR("could not add UDP listening sucket for %s:%hu\n",
					si->name, si->port);
			return -1;
		}
		si->proto = PROTO_TCP;
		si->workers = 0;
		si->flags |= SI_REUSEPORT;
		tcp = new_sock_info(si);
		if (!tcp) {
			LM_ERR("could not add TCP listening sucket for %s:%hu\n",
					si->name, si->port);
			return -1;
		}
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
	pi->tran.dst_attr		= tcp_conn_fcntl;

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
	str hdr1 = str_init("Security-Server: ipsec-3gpp;q=0.1;prot=esp;mod=trans;spi-s=");
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

static int w_ipsec_create(struct sip_msg *msg, int *_port_ps, int *_port_pc)
{
	struct cell *t;
	int port_ps, port_pc;
	struct socket_info *ss, *sc;
	struct sip_msg *req;
	struct authenticate_body *auth = NULL;
	sec_agree_body_t *sa;
	struct ipsec_socket *sock;
	struct ipsec_ctx *ctx;

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
	/* remove ik and ck parameters from the authenticate header
	 * Note:  this also ensures that they exist! */
	if (ipsec_aka_auth_remove(msg, auth) < 0) {
		LM_ERR("could not remove AKA parameters\n");
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
	/* TODO: double check for sec-agree in Required/Supported */

	/* locate the received IP */
	ss = find_ipsec_socket_info(&req->rcv.dst_ip, port_ps, port_pc);
	if (!ss) {
		LM_INFO("could not find a server listener on %s:%d!\n",
				ip_addr2a(&req->rcv.dst_ip), port_ps);
		return -2;
	}
	sc = find_ipsec_socket_info(&req->rcv.dst_ip, port_pc, ss->port_no);
	if (!sc) {
		LM_INFO("could not find a client listener on %s:%d!\n",
				ip_addr2a(&req->rcv.dst_ip), port_pc);
		return -2;
	}

	sa = ipsec_get_security_client(req);
	if (!sa) {
		LM_ERR("could not find a matching Secrity-Client header\n");
		return -4;
	}

	ctx = ipsec_ctx_new(sa, &req->rcv.src_ip, ss, sc);
	if (!ctx) {
		LM_ERR("could not allocate new IPSec ctx\n");
		return -5;
	}
	ipsec_ctx_push(ctx);

	sock = ipsec_new();
	if (!sock) {
		LM_ERR("could not create IPSec socket\n");
		return -5;
	}
	/*
	 * Flows according to 3GPP TS 33.203
	 */
	if (ipsec_add_flow(sock, ctx, &auth->ck, &auth->ik, IPSEC_POLICY_IN, 0) < 0) {
		LM_ERR("could not add UE(uc)->P(ps) SA\n");
		goto close;
	}
	if (ipsec_add_flow(sock, ctx, &auth->ck, &auth->ik, IPSEC_POLICY_OUT, 0) < 0) {
		LM_ERR("could not add P(ps)->UE(uc) SA\n");
		goto release_sa1;
	}
	if (ipsec_add_flow(sock, ctx, &auth->ck, &auth->ik, IPSEC_POLICY_IN, 1) < 0) {
		LM_ERR("could not add UE(us)->P(pc) SA\n");
		goto release_sa2;
	}
	if (ipsec_add_flow(sock, ctx, &auth->ck, &auth->ik, IPSEC_POLICY_OUT, 1) < 0) {
		LM_ERR("could not add P(pc)->UE(us) SA\n");
		goto release_sa3;
	}

	/* all good now - add Security-Server */
	if (ipsec_add_security_server(msg, ctx) < 0) {
		LM_ERR("could not add Security-Server header\n");
		goto release_sa4;
	}
	/* TODO: add to hash instead of raw reffing */
	ctx->ref++;
	ipsec_close(sock);

	return 1;
release_sa4:
	ipsec_rm_flow(sock, ctx, IPSEC_POLICY_OUT, 1);
release_sa3:
	ipsec_rm_flow(sock, ctx, IPSEC_POLICY_IN, 1);
release_sa2:
	ipsec_rm_flow(sock, ctx, IPSEC_POLICY_OUT, 0);
release_sa1:
	ipsec_rm_flow(sock, ctx, IPSEC_POLICY_IN, 0);
close:
	ipsec_close(sock);
	return -5;
}

str pv_ipsec_ctx_type[] = {
	str_init("alg"),     /* 0 */
	str_init("ealg"),    /* 1 */
	str_init("ip"),      /* 2 */
	str_init("spi-c"),   /* 3 */
	str_init("spi-s"),   /* 4 */
	str_init("port-c"),  /* 5 */
	str_init("port-s"),  /* 6 */
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

/* check if it was received on one of our listening interfaces */
static struct socket_info *ipsec_get_socket_info(const struct socket_info *bind_address)
{
	struct socket_info_full *si;
	struct socket_info_pair *pair;
	if (!bind_address)
		return NULL;
	for (si = protos[PROTO_IPSEC].listeners; si; si = si->next) {
		pair = si->socket_info.extra_data;
		if (pair->udp == bind_address || pair->tcp == bind_address)
			return &si->socket_info;
	}
	return NULL;
}

static int ipsec_pre_script_handler(struct sip_msg *msg, void *param)
{
	struct socket_info *si;
	if (!msg || msg == FAKED_REPLY || !(si = ipsec_get_socket_info(msg->rcv.bind_address)))
		return SCB_RUN_ALL;
	LM_DBG("message received over IPSec %s tunnel %s:%hu -> %s:%hu\n",
			(msg->rcv.bind_address->proto==PROTO_UDP?"UDP":"TCP"),
			ip_addr2a(&msg->rcv.src_ip), msg->rcv.src_port,
			ip_addr2a(&msg->rcv.dst_ip), msg->rcv.dst_port);

	/* TODO: handle message */
	return SCB_RUN_ALL;
}
