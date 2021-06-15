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
#include "../../net/net_tcp.h"

#include "../tls_openssl/openssl_api.h"
#include "../tls_wolfssl/wolfssl_api.h"

#include "tls_select.h"
#include "tls_config.h"
#include "api.h"

extern struct openssl_binds openssl_api;
extern struct wolfssl_binds wolfssl_api;

static void *get_ssl(struct sip_msg *msg, struct tcp_connection **c)
{
	if (msg->rcv.proto != PROTO_TLS && msg->rcv.proto != PROTO_WSS) {
		LM_ERR("transport protocol is not TLS (bug in config)\n");
		goto err;
	}

	/* get conn by ID */
	tcp_conn_get(msg->rcv.proto_reserved1, 0, 0, PROTO_NONE, NULL,
		c, NULL/*fd*/, NULL);
	if (*c && (*c)->type != PROTO_TLS && (*c)->type != PROTO_WSS) {
		LM_ERR("connection found but is not TLS (bug in config)\n");
		goto err;
	}

	if (!*c) {
		LM_INFO("TLS connection not found\n");
		goto err;
	}

	if (!(*c)->extra_data) {
		LM_ERR("failed to extract SSL data from TLS connection\n");
		goto err;
	}

	return (*c)->extra_data;
err:
	if (*c) {
		tcp_conn_release(*c, 0);
		*c = NULL;
	}
	return 0;
}


int tlsops_cipher(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	struct tcp_connection *c = NULL;
	void *ssl;
	int rc;

	ssl = get_ssl(msg, &c);
	if (!ssl) goto err;

	if (tls_library == TLS_LIB_OPENSSL) {
		rc = openssl_api.get_tls_var_cipher(ssl, &res->rs);
	} else if (tls_library == TLS_LIB_WOLFSSL) {
		rc = wolfssl_api.get_tls_var_cipher(ssl, &res->rs);
	} else {
		LM_CRIT("No TLS library module loaded\n");
		goto err;
	}

	if (rc < 0)
		goto err;

	res->flags = PV_VAL_STR;

	tcp_conn_release(c,0);

	return 0;
err:
	if (c) tcp_conn_release(c,0);
	return pv_get_null(msg, param, res);
}


int tlsops_bits(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	struct tcp_connection *c = NULL;
	void *ssl;
	int rc;

	ssl = get_ssl(msg, &c);
	if (!ssl) goto err;

	if (tls_library == TLS_LIB_OPENSSL) {
		rc = openssl_api.get_tls_var_bits(ssl, &res->rs, &res->ri);
	} else if (tls_library == TLS_LIB_WOLFSSL) {
		rc = wolfssl_api.get_tls_var_bits(ssl, &res->rs, &res->ri);
	} else {
		LM_CRIT("No TLS library module loaded\n");
		goto err;
	}

	if (rc < 0)
		goto err;

	res->flags = PV_VAL_STR | PV_VAL_INT;

	tcp_conn_release(c,0);

	return 0;
err:
	if (c) tcp_conn_release(c,0);
	return pv_get_null(msg, param, res);
}


int tlsops_version(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	struct tcp_connection *c = NULL;
	void *ssl;
	int rc;

	ssl = get_ssl(msg, &c);
	if (!ssl) goto err;

	if (tls_library == TLS_LIB_OPENSSL) {
		rc = openssl_api.get_tls_var_version(ssl, &res->rs);
	} else if (tls_library == TLS_LIB_WOLFSSL) {
		rc = wolfssl_api.get_tls_var_version(ssl, &res->rs);
	} else {
		LM_CRIT("No TLS library module loaded\n");
		goto err;
	}

	if (rc < 0)
		goto err;

	res->flags = PV_VAL_STR;

	tcp_conn_release(c,0);

	return 0;
err:
	if (c) tcp_conn_release(c,0);
	return pv_get_null(msg, param, res);
}


int tlsops_desc(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	struct tcp_connection *c = NULL;
	void *ssl;
	int rc;

	ssl = get_ssl(msg, &c);
	if (!ssl) goto err;

	if (tls_library == TLS_LIB_OPENSSL) {
		rc = openssl_api.get_tls_var_desc(ssl, &res->rs);
	} else if (tls_library == TLS_LIB_WOLFSSL) {
		rc = wolfssl_api.get_tls_var_desc(ssl, &res->rs);
	} else {
		LM_CRIT("No TLS library module loaded\n");
		goto err;
	}

	if (rc < 0)
		goto err;

	res->flags = PV_VAL_STR;

	tcp_conn_release(c,0);

	return 0;
err:
	if (c) tcp_conn_release(c,0);
	return pv_get_null(msg, param, res);
}


int tlsops_cert_version(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	struct tcp_connection *c = NULL;
	void *ssl;
	int rc;

	ssl = get_ssl(msg, &c);
	if (!ssl)
		goto err;

	if (tls_library == TLS_LIB_OPENSSL) {
		rc = openssl_api.get_tls_var_cert_vers(param->pvn.u.isname.name.n,
		ssl, &res->rs);
	} else if (tls_library == TLS_LIB_WOLFSSL) {
		rc = wolfssl_api.get_tls_var_cert_vers(param->pvn.u.isname.name.n,
		ssl, &res->rs);
	} else {
		LM_CRIT("No TLS library module loaded\n");
		goto err;
	}

	if (rc < 0)
		goto err;

	res->flags = PV_VAL_STR;

	tcp_conn_release(c,0);

	return 0;
err:
	if (c) tcp_conn_release(c,0);
	return pv_get_null(msg, param, res);
}


/*
 * Check whether peer certificate exists and verify the result
 * of certificate verification
 */
int tlsops_check_cert(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	struct tcp_connection *c = NULL;
	void *ssl;
	int rc;

	ssl = get_ssl(msg, &c);
	if (!ssl) goto err;

	if (tls_library == TLS_LIB_OPENSSL) {
		rc = openssl_api.get_tls_var_check_cert(param->pvn.u.isname.name.n,
		ssl, &res->rs, &res->ri);
	} else if (tls_library == TLS_LIB_WOLFSSL) {
		rc = wolfssl_api.get_tls_var_check_cert(param->pvn.u.isname.name.n,
		ssl, &res->rs, &res->ri);
	} else {
		LM_CRIT("No TLS library module loaded\n");
		goto err;
	}

	if (rc < 0)
		goto err;

	res->flags = PV_VAL_STR | PV_VAL_INT;

	tcp_conn_release(c,0);

	return 0;
err:
	if (c) tcp_conn_release(c,0);
	return pv_get_null(msg, param, res);
}


int tlsops_validity(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	struct tcp_connection *c = NULL;
	void *ssl;
	int rc;

	ssl = get_ssl(msg, &c);
	if (!ssl)
		goto err;

	if (tls_library == TLS_LIB_OPENSSL) {
		rc = openssl_api.get_tls_var_validity(param->pvn.u.isname.name.n,
		ssl, &res->rs);
	} else if (tls_library == TLS_LIB_WOLFSSL) {
		rc = wolfssl_api.get_tls_var_validity(param->pvn.u.isname.name.n,
		ssl, &res->rs);
	} else {
		LM_CRIT("No TLS library module loaded\n");
		goto err;
	}

	if (rc < 0)
		goto err;

	res->flags = PV_VAL_STR;

	tcp_conn_release(c,0);

	return 0;
err:
	if (c) tcp_conn_release(c,0);
	return pv_get_null(msg, param, res);
}


int tlsops_sn(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	struct tcp_connection *c = NULL;
	void *ssl;
	int rc;

	ssl = get_ssl(msg, &c);
	if (!ssl)
		goto err;

	if (tls_library == TLS_LIB_OPENSSL) {
		rc = openssl_api.get_tls_var_sn(param->pvn.u.isname.name.n,
		ssl, &res->rs, &res->ri);
	} else if (tls_library == TLS_LIB_WOLFSSL) {
		rc = wolfssl_api.get_tls_var_sn(param->pvn.u.isname.name.n,
		ssl, &res->rs, &res->ri);
	} else {
		LM_CRIT("No TLS library module loaded\n");
		goto err;
	}

	if (rc < 0)
		goto err;

	res->flags = PV_VAL_STR | PV_VAL_INT;

	tcp_conn_release(c,0);

	return 0;
 err:
	if (c) tcp_conn_release(c,0);
	return pv_get_null(msg, param, res);
}

int tlsops_comp(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	struct tcp_connection *c = NULL;
	void *ssl;
	int rc;

	ssl = get_ssl(msg, &c);
	if (!ssl)
		goto err;

	if (tls_library == TLS_LIB_OPENSSL) {
		rc = openssl_api.get_tls_var_comp(param->pvn.u.isname.name.n,
		ssl, &res->rs);
	} else if (tls_library == TLS_LIB_WOLFSSL) {
		rc = wolfssl_api.get_tls_var_comp(param->pvn.u.isname.name.n,
		ssl, &res->rs);
	} else {
		LM_CRIT("No TLS library module loaded\n");
		goto err;
	}

	if (rc < 0)
		goto err;

	res->flags = PV_VAL_STR;

	tcp_conn_release(c,0);

	return 0;
 err:
	if (c) tcp_conn_release(c,0);
	return pv_get_null(msg, param, res);
}

int tlsops_alt(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	struct tcp_connection *c = NULL;
	void *ssl;
	int rc;

	ssl = get_ssl(msg, &c);
	if (!ssl)
		goto err;

	if (tls_library == TLS_LIB_OPENSSL) {
		rc = openssl_api.get_tls_var_alt(param->pvn.u.isname.name.n,
		ssl, &res->rs);
	} else if (tls_library == TLS_LIB_WOLFSSL) {
		rc = wolfssl_api.get_tls_var_alt(param->pvn.u.isname.name.n,
		ssl, &res->rs);
	} else {
		LM_CRIT("No TLS library module loaded\n");
		goto err;
	}

	if (rc < 0)
		goto err;

	res->flags = PV_VAL_STR;

	tcp_conn_release(c,0);

	return 0;
 err:
	if (c) tcp_conn_release(c,0);
	return pv_get_null(msg, param, res);
}

int tls_is_peer_verified(struct sip_msg* msg)
{
	struct tcp_connection *c = NULL;
	void *ssl;
	int rc;

	ssl = get_ssl(msg, &c);
	if (!ssl)
		goto err;

	if (tls_library == TLS_LIB_OPENSSL) {
		rc = openssl_api.is_peer_verified(c->extra_data);
	} else if (tls_library == TLS_LIB_WOLFSSL) {
		rc = wolfssl_api.is_peer_verified(c->extra_data);
	} else {
		LM_CRIT("No TLS library module loaded\n");
		goto err;
	}

	if (rc < 0)
		goto err;

	tcp_conn_release(c, 0);

	LM_DBG("peer is successfully verified... done\n");
	return 1;
err:
	if (c) tcp_conn_release(c, 0);
	return -1;
}
