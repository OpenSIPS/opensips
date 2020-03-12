/*
 * OpenSIPS LDAP Module
 *
 * Copyright (C) 2007 University of North Carolina
 *
 * Original author: Christian Schlatter, cs@unc.edu
 *
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
 * History:
 * --------
 * 2007-02-18: Initial version
 */


#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include <ldap.h>
#include <stdlib.h>

#include "ldap_connect.h"
#include "ld_session.h"
#include "../../mem/mem.h"
#include "../../ut.h"

#define W_SET_OPTION(handle, opt, str, name) \
	do { \
		if (ldap_set_option( handle, opt, str) \
			!= LDAP_OPT_SUCCESS) { \
			LM_ERR("[%s]: could not set " # opt " [%s]\n" \
					, name, str); \
			return -1; \
		} \
	} while (0);


static inline int ldap_word2upper(char* input)
{
	int index=0;

	while (input[index] == ' ')
		input++;

	while (input[index] != '\0') {
		if (input[index] >= 'a' && input[index] <= 'z') {
			input[index++] -= 32;
			continue;
		}

		if (input[index] < 'A' || input[index] > 'Z') {
			LM_ERR("invalid req_cert parameter!"
					" must contain only letters\n");
			return -1;
		}

		index++;
	}

	return 0;
}

static inline int get_req_cert_param(char* req_cert)
{
	#define DWORD(s) ( *s + (*(s+1) << 8) + (*(s+2) << 16) + (*(s+3) << 24))

	switch (DWORD(req_cert)) {
		case NEVE:
			if (*(req_cert+4) != 'R' || *(req_cert+5) != '\0')
				goto error;
			return LDAP_OPT_X_TLS_NEVER;
		case DEMA:
			if (*(req_cert+4) != 'N' || *(req_cert+5) != 'D' ||
					*(req_cert+6) != '\0')
				goto error;
			return LDAP_OPT_X_TLS_DEMAND;
		case ALLO:
			if (*(req_cert+4) != 'W' || *(req_cert+5) != '\0')
				goto error;
			return LDAP_OPT_X_TLS_ALLOW;
		case HARD:
			if (*(req_cert+4) != '\0')
				goto error;
			return LDAP_OPT_X_TLS_HARD;
		case  TRY:
			return LDAP_OPT_X_TLS_TRY;
		default	 :
			goto error;

	}

error:
	LM_ERR("invalid req_cert parameter [%s]!"
		"OPTIONS: NEVER|DEMAND|ALLOW|HARD|TRY\n", req_cert);
	return -1;
	#undef DWORD
}


int ldap_connect(char* _ld_name, struct ld_conn* conn)
{
	int rc;
	int ldap_proto_version;
	int req_cert_value;
	char *errmsg;
	struct ld_session* lds;
	struct berval ldap_cred;
	struct berval* ldap_credp;

	struct ld_conn* ldap_conn;

	LDAP* handle = NULL;

	/*
	struct berval* serv_cred = (struct berval*)pkg_malloc(sizeof(struct berval));
	if(!serv_cred){
	    LM_ERR("Out of mem\n");
	    return -1;
	}
	 */

	/*
	* get ld session and session config parameters
	*/

	if ((lds = get_ld_session(_ld_name)) == NULL)
	{
		LM_ERR("ld_session [%s] not found\n", _ld_name);
		return -1;
	}

	/*
	 * ldap_initialize
	 */

	rc = ldap_initialize(&handle, lds->host_name);
	if (rc != LDAP_SUCCESS)
	{
		LM_ERR(	"[%s]: ldap_initialize (%s) failed: %s\n",
			_ld_name,
			lds->host_name,
			ldap_err2string(rc));
		return -1;
	}

	/*
	 * set LDAP OPTIONS
	 */

	/* LDAP_OPT_PROTOCOL_VERSION */
	switch (lds->version) {
	case 2:
		ldap_proto_version = LDAP_VERSION2;
		break;
	case 3:
		ldap_proto_version = LDAP_VERSION3;
		break;
	default:
		LM_ERR(	"[%s]: Invalid LDAP protocol version [%d]\n",
			_ld_name,
			lds->version);
		return -1;
	}
	if (ldap_set_option(handle,
				LDAP_OPT_PROTOCOL_VERSION,
				&ldap_proto_version)
			!= LDAP_OPT_SUCCESS)
	{
		LM_ERR(	"[%s]: Could not set LDAP_OPT_PROTOCOL_VERSION [%d]\n",
			_ld_name,
			ldap_proto_version);
		return -1;
	}

	/* LDAP_OPT_RESTART */
	if (ldap_set_option(handle,
				LDAP_OPT_RESTART,
				LDAP_OPT_ON)
			!= LDAP_OPT_SUCCESS) {
		LM_ERR("[%s]: Could not set LDAP_OPT_RESTART to ON\n", _ld_name);
		return -1;
	}

	/* LDAP_OPT_TIMELIMIT */
	/*
	if (lds->server_search_timeout > 0) {
		if (ldap_set_option(lds->handle,
				LDAP_OPT_TIMELIMIT,
				&lds->server_search_timeout)
			!= LDAP_OPT_SUCCESS) {
			LM_ERR("[%s]: Could not set LDAP_OPT_TIMELIMIT to [%d]\n",
			_ld_name, lds->server_search_timeout);
			return -1;
		}
	}
	*/

	/* LDAP_OPT_NETWORK_TIMEOUT */
	if ((lds->network_timeout.tv_sec > 0) || (lds->network_timeout.tv_usec > 0))
	{
		if (ldap_set_option(handle,
					LDAP_OPT_NETWORK_TIMEOUT,
					(const void *)&lds->network_timeout)
				!= LDAP_OPT_SUCCESS)
		{
			LM_ERR(	"[%s]: Could not set"
				" LDAP_NETWORK_TIMEOUT to [%d.%d]\n",
				_ld_name,
				(int)lds->network_timeout.tv_sec,
				(int)lds->network_timeout.tv_usec);
		}
	}


	/* if timeout == 0 then use default */
	if ((lds->client_bind_timeout.tv_sec == 0)
			&& (lds->client_bind_timeout.tv_usec == 0))
	{
	    lds->client_bind_timeout.tv_sec =
		    CFG_DEF_LDAP_CLIENT_BIND_TIMEOUT / 1000;
	    lds->client_bind_timeout.tv_usec =
		    (CFG_DEF_LDAP_CLIENT_BIND_TIMEOUT % 1000) * 1000;
	}

	rc = ldap_set_option(handle, LDAP_OPT_TIMEOUT, &lds->client_bind_timeout);
	if(rc != LDAP_SUCCESS){
	    LM_ERR("[%s]: ldap set option LDAP_OPT_TIMEOUT failed\n", _ld_name);
	    return -1;
	}

	/* if no "ldap_bind_password" then anonymous */
	ldap_cred.bv_val = lds->bind_pwd;
	ldap_cred.bv_len = strlen(lds->bind_pwd);

	if(ldap_cred.bv_len == 0 || ldap_cred.bv_val[0]==0){
	    ldap_credp = NULL;
	}else{
	    ldap_credp = &ldap_cred;
	}

	/* configure tls */
	if (*lds->cacertfile && *lds->certfile && *lds->keyfile) {

		W_SET_OPTION(handle, LDAP_OPT_X_TLS_CACERTFILE,
				lds->cacertfile, _ld_name);

		W_SET_OPTION(handle, LDAP_OPT_X_TLS_CERTFILE,
				lds->certfile, _ld_name);

		W_SET_OPTION(handle, LDAP_OPT_X_TLS_KEYFILE,
				lds->keyfile, _ld_name);

		if (ldap_word2upper(lds->req_cert) != 0)
			return -1;

		if ((req_cert_value = get_req_cert_param(lds->req_cert)) < 0)
			return -1;

		if (ldap_set_option( handle, LDAP_OPT_X_TLS_REQUIRE_CERT,
					&req_cert_value) != LDAP_OPT_SUCCESS) {
				LM_ERR("[%s]: could not set LDAP_OPT_X_TLS_REQUIRE_CERT [%s]\n"
						, _ld_name, lds->req_cert);
				return -1;
		}

		int ret = ldap_start_tls_s(handle, NULL, NULL);

		switch (ret) {
		case LDAP_SUCCESS:
			LM_INFO("Using StartTLS for session [%s]\n", _ld_name);

			break;

		case LDAP_CONNECT_ERROR:
			ldap_get_option(handle,
						LDAP_OPT_DIAGNOSTIC_MESSAGE, (void *)&errmsg);
			LM_ERR("ldap_Start_tls_s(): %s\n", errmsg);
			ldap_memfree(errmsg);
			ldap_unbind_ext(handle, NULL, NULL);

			return -1;

		default:
			LM_ERR("ldap_start_tls_s(): %s\n", ldap_err2string(ret));
			ldap_unbind_ext(handle, NULL,NULL);
			return -1;
		}

	} else if (*lds->cacertfile || *lds->certfile || *lds->keyfile) {
		LM_WARN("ldap_ca_certfile, ldap_cert_file and ldap_key_file"
				" must be set in order to use StartTLS. "
				"No StartTLS configured!\n");
	}

	/*
	* ldap_sasl_bind (LDAP_SASL_SIMPLE)
	*/

	rc = ldap_sasl_bind_s (
		handle,
		lds->bind_dn,
		LDAP_SASL_SIMPLE,
		ldap_credp,
		NULL,
		NULL,
		NULL   /*&serv_cred */
		);
	if (rc != LDAP_SUCCESS)
	{
		LM_ERR(	"[%s]: ldap bind failed: %s\n",
			_ld_name,
			ldap_err2string(rc));
		return -1;
	}

	LM_DBG(	"[%s]: LDAP bind successful (ldap_host [%s])\n",
		_ld_name,
		lds->host_name);

	/* it's an already defined connection; just set the new handle */
	if (conn) {
		conn->handle = handle;
	} else {
		ldap_conn = pkg_malloc(sizeof(struct ld_conn));
		if (ldap_conn == NULL) {
			LM_ERR("no more pkg mem!\n");
			return -1;
		}

		memset(ldap_conn, 0, sizeof(struct ld_conn));
		ldap_conn->handle = handle;

		if (lds->conn_pool == NULL) {
			lds->conn_pool = ldap_conn;
		} else {
			ldap_conn->next = lds->conn_pool;
			lds->conn_pool = ldap_conn;
		}
		lds->pool_size++;
	}


	return 0;
}

int ldap_disconnect(char* _ld_name, struct ld_conn* conn)
{
	struct ld_session* lds;
	struct ld_conn *foo=NULL, *it;

	/*
		* get ld session
		*/

	/* disconnect all and free */
	if (!conn) {
		if ((lds = get_ld_session(_ld_name)) == NULL)
		{
			LM_ERR("ld_session [%s] not found\n", _ld_name);
			return -1;
		}

		if (lds->conn_pool == NULL) {
			return 0;
		}


		for (it=lds->conn_pool; it; foo=it, it=it->next) {
			ldap_unbind_ext_s(it->handle, NULL, NULL);
			if (foo)
				pkg_free(foo);
		}

		/* check for last element in list */
		if (foo)
			pkg_free(foo);

		lds->conn_pool = NULL;
	} else {
		ldap_unbind_ext_s(conn->handle, NULL, NULL);
		conn->handle = NULL;
		conn->is_used = 0;
	}

	return 0;
}

int ldap_reconnect(char* _ld_name, struct ld_conn* conn)
{
	int rc;

	if (conn->handle && ldap_disconnect(_ld_name, conn) != 0)
	{
		LM_ERR("[%s]: disconnect failed\n", _ld_name);
		return -1;
	}

	if ((rc = ldap_connect(_ld_name, conn)) != 0)
	{
		LM_ERR("[%s]: reconnect failed\n",
				_ld_name);
	}
	else
	{
		LM_DBG("[%s]: LDAP reconnect successful\n",
				_ld_name);
	}

	return rc;
}

int ldap_get_vendor_version(char** _version)
{
	static char version[128];
	LDAPAPIInfo api;
	int rc;

#ifdef LDAP_API_INFO_VERSION
	api.ldapai_info_version = LDAP_API_INFO_VERSION;
#else
	api.ldapai_info_version = 1;
#endif

	if (ldap_get_option(NULL, LDAP_OPT_API_INFO, &api) != LDAP_SUCCESS)
	{
		LM_ERR("ldap_get_option(API_INFO) failed\n");
		return -1;
	}

	rc = snprintf(version, 128, "%s - %d", api.ldapai_vendor_name,
			api.ldapai_vendor_version);
	if ((rc >= 128) || (rc < 0))
	{
		LM_ERR("snprintf failed\n");
		return -1;
	}

	*_version = version;
	return 0;
}

#undef W_SET_OPTION
