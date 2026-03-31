/*
 * TLS module - select interface
 *
 * Copyright (C)  2001-2003 FhG FOKUS
 * Copyright (C)  2004,2005 Free Software Foundation, Inc.
 * Copyright (C)  2005 iptelorg GmbH
 * Copyright (C)  2006 enum.at
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
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

#include "../../globals.h"
#include "../../ipc.h"
#include "../../mem/shm_mem.h"
#include "../../net/tcp_conn.h"
#include "../../net/net_tcp.h"

#include "../tls_openssl/openssl_api.h"
#include "../tls_wolfssl/wolfssl_api.h"

#include "tls_select.h"
#include "tls_config.h"
#include "api.h"

extern struct openssl_binds openssl_api;
extern struct wolfssl_binds wolfssl_api;
extern int is_tcp_main;

#define TLS_QUERY_STR_BUF_SIZE 4096

enum tls_query_type {
	TLS_QUERY_CIPHER = 1,
	TLS_QUERY_BITS,
	TLS_QUERY_VERSION,
	TLS_QUERY_DESC,
	TLS_QUERY_CERT_VERSION,
	TLS_QUERY_CHECK_CERT,
	TLS_QUERY_VALIDITY,
	TLS_QUERY_SN,
	TLS_QUERY_COMP,
	TLS_QUERY_ALT,
	TLS_QUERY_IS_PEER_VERIFIED
};

#define TLS_QUERY_RES_STR (1 << 0)
#define TLS_QUERY_RES_INT (1 << 1)

struct tls_query_req {
	unsigned int conn_id;
	int sender;
	int type;
	int arg;
	int rc;
	int flags;
	int int_res;
	int str_len;
	char str[TLS_QUERY_STR_BUF_SIZE];
};

static char tls_query_res_buf[TLS_QUERY_STR_BUF_SIZE];

static void *get_ssl(struct sip_msg *msg, struct tcp_connection **c)
{
	if (msg->rcv.proto != PROTO_TLS && msg->rcv.proto != PROTO_WSS) {
		LM_ERR("transport protocol is not TLS (bug in config)\n");
		goto err;
	}

	/* get conn by ID */
	tcp_conn_get(msg->rcv.proto_reserved1, 0, 0, PROTO_NONE, NULL,
		c, NULL);
	if (*c && (*c)->type != PROTO_TLS && (*c)->type != PROTO_WSS) {
		LM_ERR("connection found but is not TLS (bug in config)\n");
		goto err;
	}

	if (!*c) {
		LM_INFO("TLS connection not found\n");
		goto err;
	}

	if (!is_tcp_main) {
		LM_ERR("TLS runtime state is private to TCP main\n");
		goto err;
	}

	if (!(*c)->extra_data) {
		LM_ERR("failed to extract SSL data from TLS connection\n");
		goto err;
	}

	return (*c)->extra_data;
err:
	if (*c) {
		tcpconn_put(*c);
		*c = NULL;
	}
	return 0;
}

static int tls_query_set_str(struct tls_query_req *req, const str *res)
{
	if (res->len >= TLS_QUERY_STR_BUF_SIZE) {
		LM_ERR("TLS query string too long: %d\n", res->len);
		return -1;
	}

	if (res->len > 0)
		memcpy(req->str, res->s, res->len);
	req->str_len = res->len;
	req->flags |= TLS_QUERY_RES_STR;
	return 0;
}

static int tls_query_fill(void *ssl, struct tls_query_req *req)
{
	str str_res;
	int rc;

	req->flags = 0;
	req->int_res = 0;
	req->str_len = 0;

	switch (req->type) {
	case TLS_QUERY_CIPHER:
		if (tls_library == TLS_LIB_OPENSSL)
			rc = openssl_api.get_tls_var_cipher(ssl, &str_res);
		else if (tls_library == TLS_LIB_WOLFSSL)
			rc = wolfssl_api.get_tls_var_cipher(ssl, &str_res);
		else
			return -1;
		return rc < 0 ? -1 : tls_query_set_str(req, &str_res);
	case TLS_QUERY_BITS:
		if (tls_library == TLS_LIB_OPENSSL)
			rc = openssl_api.get_tls_var_bits(ssl, &str_res, &req->int_res);
		else if (tls_library == TLS_LIB_WOLFSSL)
			rc = wolfssl_api.get_tls_var_bits(ssl, &str_res, &req->int_res);
		else
			return -1;
		if (rc < 0 || tls_query_set_str(req, &str_res) < 0)
			return -1;
		req->flags |= TLS_QUERY_RES_INT;
		return 0;
	case TLS_QUERY_VERSION:
		if (tls_library == TLS_LIB_OPENSSL)
			rc = openssl_api.get_tls_var_version(ssl, &str_res);
		else if (tls_library == TLS_LIB_WOLFSSL)
			rc = wolfssl_api.get_tls_var_version(ssl, &str_res);
		else
			return -1;
		return rc < 0 ? -1 : tls_query_set_str(req, &str_res);
	case TLS_QUERY_DESC:
		if (tls_library == TLS_LIB_OPENSSL)
			rc = openssl_api.get_tls_var_desc(ssl, &str_res);
		else if (tls_library == TLS_LIB_WOLFSSL)
			rc = wolfssl_api.get_tls_var_desc(ssl, &str_res);
		else
			return -1;
		return rc < 0 ? -1 : tls_query_set_str(req, &str_res);
	case TLS_QUERY_CERT_VERSION:
		if (tls_library == TLS_LIB_OPENSSL)
			rc = openssl_api.get_tls_var_cert_vers(req->arg, ssl, &str_res);
		else if (tls_library == TLS_LIB_WOLFSSL)
			rc = wolfssl_api.get_tls_var_cert_vers(req->arg, ssl, &str_res);
		else
			return -1;
		return rc < 0 ? -1 : tls_query_set_str(req, &str_res);
	case TLS_QUERY_CHECK_CERT:
		if (tls_library == TLS_LIB_OPENSSL)
			rc = openssl_api.get_tls_var_check_cert(req->arg, ssl, &str_res,
				&req->int_res);
		else if (tls_library == TLS_LIB_WOLFSSL)
			rc = wolfssl_api.get_tls_var_check_cert(req->arg, ssl, &str_res,
				&req->int_res);
		else
			return -1;
		if (rc < 0 || tls_query_set_str(req, &str_res) < 0)
			return -1;
		req->flags |= TLS_QUERY_RES_INT;
		return 0;
	case TLS_QUERY_VALIDITY:
		if (tls_library == TLS_LIB_OPENSSL)
			rc = openssl_api.get_tls_var_validity(req->arg, ssl, &str_res);
		else if (tls_library == TLS_LIB_WOLFSSL)
			rc = wolfssl_api.get_tls_var_validity(req->arg, ssl, &str_res);
		else
			return -1;
		return rc < 0 ? -1 : tls_query_set_str(req, &str_res);
	case TLS_QUERY_SN:
		if (tls_library == TLS_LIB_OPENSSL)
			rc = openssl_api.get_tls_var_sn(req->arg, ssl, &str_res,
				&req->int_res);
		else if (tls_library == TLS_LIB_WOLFSSL)
			rc = wolfssl_api.get_tls_var_sn(req->arg, ssl, &str_res,
				&req->int_res);
		else
			return -1;
		if (rc < 0 || tls_query_set_str(req, &str_res) < 0)
			return -1;
		req->flags |= TLS_QUERY_RES_INT;
		return 0;
	case TLS_QUERY_COMP:
		if (tls_library == TLS_LIB_OPENSSL)
			rc = openssl_api.get_tls_var_comp(req->arg, ssl, &str_res);
		else if (tls_library == TLS_LIB_WOLFSSL)
			rc = wolfssl_api.get_tls_var_comp(req->arg, ssl, &str_res);
		else
			return -1;
		return rc < 0 ? -1 : tls_query_set_str(req, &str_res);
	case TLS_QUERY_ALT:
		if (tls_library == TLS_LIB_OPENSSL)
			rc = openssl_api.get_tls_var_alt(req->arg, ssl, &str_res);
		else if (tls_library == TLS_LIB_WOLFSSL)
			rc = wolfssl_api.get_tls_var_alt(req->arg, ssl, &str_res);
		else
			return -1;
		return rc < 0 ? -1 : tls_query_set_str(req, &str_res);
	case TLS_QUERY_IS_PEER_VERIFIED:
		if (tls_library == TLS_LIB_OPENSSL)
			req->int_res = openssl_api.is_peer_verified(ssl);
		else if (tls_library == TLS_LIB_WOLFSSL)
			req->int_res = wolfssl_api.is_peer_verified(ssl);
		else
			return -1;
		req->flags |= TLS_QUERY_RES_INT;
		return 0;
	default:
		LM_BUG("unknown TLS query type %d\n", req->type);
		return -1;
	}
}

static int tls_query_local(struct sip_msg *msg, struct tls_query_req *req)
{
	struct tcp_connection *c = NULL;
	void *ssl;

	ssl = get_ssl(msg, &c);
	if (!ssl)
		return -1;

	req->rc = tls_query_fill(ssl, req);
	tcpconn_put(c);
	return req->rc;
}

static int tls_query_run(void *data)
{
	struct tls_query_req *req = data;
	struct tcp_connection *c = NULL;
	int ret = -1;

	if (!req)
		return -1;

	if (tcp_conn_get(req->conn_id, 0, 0, PROTO_NONE, NULL, &c, NULL) <= 0 ||
			!c)
		goto done;

	if (c->type != PROTO_TLS && c->type != PROTO_WSS)
		goto release;

	if (!c->extra_data)
		goto release;

	req->rc = tls_query_fill(c->extra_data, req);
	ret = req->rc;
	tcpconn_put(c);
	goto done;

release:
	tcpconn_put(c);
done:
	if (ret < 0)
		req->rc = -1;
	if (ipc_send_sync_reply(req->sender, req) < 0)
		LM_ERR("failed to reply to TLS query\n");
	return ret;
}

static void tls_query_main_rpc(int sender, void *param)
{
	struct tls_query_req *req = param;

	if (!req)
		return;

	req->sender = sender;
	if (tcp_run_task(tls_query_run, req) < 0) {
		req->rc = -1;
		if (ipc_send_sync_reply(sender, req) < 0)
			LM_ERR("failed to reply to TLS query\n");
	}
}

static int tls_query_remote(struct tls_query_req *req)
{
	struct tls_query_req *shm_req;
	void *reply;
	int tcp_main_proc;

	tcp_main_proc = tcp_get_main_proc_no();
	if (tcp_main_proc < 0) {
		LM_ERR("TCP main process not found for TLS query\n");
		return -1;
	}

	shm_req = shm_malloc(sizeof(*shm_req));
	if (!shm_req) {
		LM_ERR("oom while allocating TLS query payload\n");
		return -1;
	}

	memcpy(shm_req, req, sizeof(*shm_req));
	if (ipc_send_rpc(tcp_main_proc, tls_query_main_rpc, shm_req) < 0) {
		LM_ERR("failed sending TLS query to TCP main\n");
		shm_free(shm_req);
		return -1;
	}

	if (ipc_recv_sync_reply(&reply) < 0) {
		LM_ERR("failed receiving TLS query reply from TCP main\n");
		shm_free(shm_req);
		return -1;
	}
	if (reply != shm_req) {
		LM_ERR("unexpected TLS query reply payload %p (expected %p)\n",
			reply, shm_req);
		shm_free(shm_req);
		return -1;
	}

	memcpy(req, shm_req, sizeof(*req));
	shm_free(shm_req);
	return req->rc;
}

static int tls_query_msg(struct sip_msg *msg, int type, int arg,
		struct tls_query_req *req)
{
	memset(req, 0, sizeof(*req));
	req->conn_id = msg->rcv.proto_reserved1;
	req->type = type;
	req->arg = arg;
	req->rc = -1;

	if (is_tcp_main)
		return tls_query_local(msg, req);

	if (msg->rcv.proto != PROTO_TLS && msg->rcv.proto != PROTO_WSS) {
		LM_ERR("transport protocol is not TLS (bug in config)\n");
		return -1;
	}

	return tls_query_remote(req);
}

static int tls_query_apply_pv(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res, int type, int arg)
{
	struct tls_query_req req;

	if (tls_query_msg(msg, type, arg, &req) < 0)
		return pv_get_null(msg, param, res);

	res->flags = 0;
	if (req.flags & TLS_QUERY_RES_STR) {
		if (req.str_len > 0)
			memcpy(tls_query_res_buf, req.str, req.str_len);
		res->rs.s = tls_query_res_buf;
		res->rs.len = req.str_len;
		res->flags |= PV_VAL_STR;
	}
	if (req.flags & TLS_QUERY_RES_INT) {
		res->ri = req.int_res;
		res->flags |= PV_VAL_INT;
	}

	return 0;
}
int tlsops_cipher(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	return tls_query_apply_pv(msg, param, res, TLS_QUERY_CIPHER, 0);
}


int tlsops_bits(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	return tls_query_apply_pv(msg, param, res, TLS_QUERY_BITS, 0);
}


int tlsops_version(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	return tls_query_apply_pv(msg, param, res, TLS_QUERY_VERSION, 0);
}


int tlsops_desc(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	return tls_query_apply_pv(msg, param, res, TLS_QUERY_DESC, 0);
}


int tlsops_cert_version(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	return tls_query_apply_pv(msg, param, res, TLS_QUERY_CERT_VERSION,
		param->pvn.u.isname.name.n);
}


/*
 * Check whether peer certificate exists and verify the result
 * of certificate verification
 */
int tlsops_check_cert(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	return tls_query_apply_pv(msg, param, res, TLS_QUERY_CHECK_CERT,
		param->pvn.u.isname.name.n);
}


int tlsops_validity(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	return tls_query_apply_pv(msg, param, res, TLS_QUERY_VALIDITY,
		param->pvn.u.isname.name.n);
}


int tlsops_sn(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	return tls_query_apply_pv(msg, param, res, TLS_QUERY_SN,
		param->pvn.u.isname.name.n);
}

int tlsops_comp(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	return tls_query_apply_pv(msg, param, res, TLS_QUERY_COMP,
		param->pvn.u.isname.name.n);
}

int tlsops_alt(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	return tls_query_apply_pv(msg, param, res, TLS_QUERY_ALT,
		param->pvn.u.isname.name.n);
}

int tls_is_peer_verified(struct sip_msg* msg)
{
	struct tls_query_req req;

	if (tls_query_msg(msg, TLS_QUERY_IS_PEER_VERIFIED, 0, &req) < 0)
		return -1;

	if (!(req.flags & TLS_QUERY_RES_INT) || req.int_res < 0)
		return -1;

	LM_DBG("peer is successfully verified... done\n");
	return 1;
}
