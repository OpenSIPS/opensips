/*
 * $Id$
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

int ldap_connect(char* _ld_name)
{
	int rc;
	int ldap_proto_version;
	struct ld_session* lds;
	struct berval ldap_cred;
	struct berval* ldap_credp;

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

	rc = ldap_initialize(&lds->handle, lds->host_name);
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
	if (ldap_set_option(lds->handle,
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
	if (ldap_set_option(lds->handle,
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
		if (ldap_set_option(lds->handle,
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

	rc = ldap_set_option(lds->handle, LDAP_OPT_TIMEOUT, &lds->client_bind_timeout);
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

	/*
	* ldap_sasl_bind (LDAP_SASL_SIMPLE)
	*/

	rc = ldap_sasl_bind_s(
		lds->handle,
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

	return 0;
}

int ldap_disconnect(char* _ld_name)
{
	struct ld_session* lds;

	/*
		* get ld session
		*/

	if ((lds = get_ld_session(_ld_name)) == NULL)
	{
		LM_ERR("ld_session [%s] not found\n", _ld_name);
		return -1;
	}

	if (lds->handle == NULL) {
		return 0;
	}

	ldap_unbind_ext(lds->handle, NULL, NULL);
	lds->handle = NULL;

	return 0;
}

int ldap_reconnect(char* _ld_name)
{
	int rc;
	
	if (ldap_disconnect(_ld_name) != 0)
	{
		LM_ERR("[%s]: disconnect failed\n", _ld_name);
		return -1;
	}

	if ((rc = ldap_connect(_ld_name)) != 0)
	{
		LM_ERR("[%s]: reconnect failed\n",
				_ld_name);
	}
	else
	{
		LM_ERR("[%s]: LDAP reconnect successful\n",
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
