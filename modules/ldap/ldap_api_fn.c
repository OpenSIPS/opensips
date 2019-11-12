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


#include <unistd.h>
#include <stdarg.h>

#include "../../ut.h"

#include <ldap.h>

#include "ldap_api_fn.h"
#include "api.h"
#include "ldap_connect.h"
#include "ldap_escape.h"

extern int max_async_connections;

static LDAP* last_ldap_handle = NULL;
static LDAPMessage* last_ldap_result = NULL;

int get_connected_ldap_session(
	char* _lds_name,
	struct ld_session** _lds);
int lds_search(char* _lds_name,
	char* _dn,
	int _scope,
	char* _filter,
	char** _attrs,
	struct timeval* _search_timeout,
	int* _ld_result_count,
	int* _ld_error);
int lds_search_async(
	char* _lds_name,
	char* _dn,
	int _scope,
	char* _filter,
	char** _attrs,
	struct timeval* _search_timeout,
	int* _msgidp,
	struct ld_conn** conn);


int load_ldap(ldap_api_t *api)
{
	if (api == NULL)
	{
		return -1;
	}

	api->ldap_params_search    = ldap_params_search;
	api->ldap_url_search       = ldap_url_search;
	api->ldap_result_attr_vals = ldap_get_attr_vals;
	api->ldap_value_free_len   = ldap_value_free_len;
	api->ldap_result_next      = ldap_inc_result_pointer;
	api->ldap_str2scope        = ldap_str2scope;
	api->ldap_rfc4515_escape   = ldap_rfc4515_escape;
	api->get_ldap_handle       = get_ldap_handle;
	api->get_last_ldap_result  = get_last_ldap_result;

	return 1;
}


struct ld_conn* get_ldap_connection(struct ld_session* lds)
{
	struct ld_conn* it;


	for (it=lds->conn_pool; it; it=it->next) {
		if (it->handle == NULL) {

			if (ldap_reconnect(lds->name, it)) {
				LM_ERR("ldap failed to reconnect!\n");
				return NULL;
			}

			it->is_used = 1;
			return it;
		}

		if (it->is_used == 0) {
			it->is_used = 1;
			return it;
		}
	}

	/* if we're out of connections create a new one
	 * only if we are allowed to; if limit reached return NULL  */
	if (max_async_connections <= lds->pool_size) {
		LM_DBG("async connection pool size limit reached!\n");
		return NULL;
	}

	if (ldap_connect(lds->name, NULL) < 0) {
			LM_ERR("failed to create new ldap connection!\n");
			return NULL;
	}

	/* newly created connection will be first in list */
	lds->conn_pool->is_used = 1;

	return lds->conn_pool;
}

void release_ldap_connection(struct ld_conn* conn)
{
	conn->is_used = 0;
}


int get_ldap_handle(char* _lds_name, LDAP** _ldap_handle)
{
	int rc;
	struct ld_session* lds;

	rc = get_connected_ldap_session(_lds_name, &lds);

	*_ldap_handle = NULL;
	if (rc == 0)
	{
		*_ldap_handle = lds->conn_s.handle;
	}

	return rc;
}

int get_connected_ldap_session(char* _lds_name, struct ld_session** _lds)
{
	/*
	* get ld session
	*/
	if ((*_lds = get_ld_session(_lds_name)) == NULL)
	{
		LM_ERR("[%s]: ldap_session not found\n", _lds_name);
		return -1;
	}

	return 0;
}

/**
 * reconnect if a session is disconnected
 */
static inline int check_reconnect(char* _lds_name, struct ld_conn* conn)
{
	if ( conn == NULL ) {
		LM_ERR("no session to reconect!\n");
		return -1;
	}

	if (conn->handle == NULL) {
		if ( ldap_reconnect(_lds_name, conn) != 0) {
			if ( last_ldap_result != NULL ) {
				ldap_msgfree(last_ldap_result);
				last_ldap_result = NULL;
			}

			ldap_disconnect( _lds_name, conn);
			LM_ERR("[%s]: reconnect failed for synchronous connection!\n", _lds_name);
			return -1;
		}
	}

	return 0;
}

void get_last_ldap_result(LDAP** _last_ldap_handle, LDAPMessage** _last_ldap_result)
{
	*_last_ldap_handle = last_ldap_handle;
	*_last_ldap_result = last_ldap_result;
}

int ldap_params_search_async(
	int* _msgidp,
	char* _lds_name,
	char* _dn,
	int _scope,
	char** _attrs,
	struct ld_conn** conn,
	char* _filter,
	...)
{
	int rc;
	static char filter_str[LDAP_MAX_FILTER_LEN];
	va_list filter_vars;

	/*
	* check _scope
	*/
	switch (_scope)
	{
	case LDAP_SCOPE_ONELEVEL:
	case LDAP_SCOPE_BASE:
	case LDAP_SCOPE_SUBTREE:
		break;
	default:
		LM_ERR("[%s]: invalid scope argument [%d]\n", _lds_name, _scope);
		return -1;
	}

	/*
	* vsnprintf
	*/
	va_start(filter_vars, _filter);
	rc = vsnprintf(filter_str, (size_t)LDAP_MAX_FILTER_LEN, _filter,
			filter_vars);
	va_end(filter_vars);
	if (rc >= LDAP_MAX_FILTER_LEN)
	{
		LM_ERR(	"[%s]: filter string too long (len [%d], max len [%d])\n",
			_lds_name,
			rc,
			LDAP_MAX_FILTER_LEN);
		return -1;
	}
	else if (rc < 0)
	{
		LM_ERR("vsnprintf failed\n");
		return -1;
	}

	/*
	* ldap search
	*/
	if ((rc=lds_search_async(_lds_name,
			_dn,
			_scope,
			filter_str,
			_attrs,
			NULL,
			_msgidp,
			conn)
		) != 0)
	{
		/* try again if LDAP API ERROR */
		if (LDAP_API_ERROR(rc) &&
			lds_search_async(_lds_name,
						_dn,
						_scope,
						filter_str,
						_attrs,
						NULL,
						_msgidp,
						conn) != 0) {
				LM_ERR("[%s]: LDAP search (dn [%s], scope [%d],"
					" filter [%s]) failed: %s\n",
					_lds_name,
					_dn,
					_scope,
					filter_str,
					ldap_err2string(rc));
				return -1;
		}
	}

	return rc;
}



int ldap_params_search(
	int* _ld_result_count,
	char* _lds_name,
	char* _dn,
	int _scope,
	char** _attrs,
	char* _filter,
	...)
{
	int rc;
	static char filter_str[LDAP_MAX_FILTER_LEN];
	va_list filter_vars;

	/*
	* check _scope
	*/
	switch (_scope)
	{
	case LDAP_SCOPE_ONELEVEL:
	case LDAP_SCOPE_BASE:
	case LDAP_SCOPE_SUBTREE:
		break;
	default:
		LM_ERR("[%s]: invalid scope argument [%d]\n", _lds_name, _scope);
		return -1;
	}

	/*
	* vsnprintf
	*/
	va_start(filter_vars, _filter);
	rc = vsnprintf(filter_str, (size_t)LDAP_MAX_FILTER_LEN, _filter,
			filter_vars);
	va_end(filter_vars);
	if (rc >= LDAP_MAX_FILTER_LEN)
	{
		LM_ERR(	"[%s]: filter string too long (len [%d], max len [%d])\n",
			_lds_name,
			rc,
			LDAP_MAX_FILTER_LEN);
		return -1;
	}
	else if (rc < 0)
	{
		LM_ERR("vsnprintf failed\n");
		return -1;
	}

	/*
	* ldap search
	*/
	if (lds_search(_lds_name,
			_dn,
			_scope,
			filter_str,
			_attrs,
			NULL,
			_ld_result_count,
			&rc)
		!= 0)
	{
		/* try again if LDAP API ERROR */
		if (LDAP_API_ERROR(rc) &&
				(lds_search(_lds_name,
						_dn,
						_scope,
						filter_str,
						_attrs,
						NULL,
						_ld_result_count,
						&rc) != 0))
		{
			LM_ERR(	"[%s]: LDAP search (dn [%s], scope [%d],"
				" filter [%s]) failed: %s\n",
				_lds_name,
				_dn,
				_scope,
				filter_str,
				ldap_err2string(rc));
			return -1;
		}
	}

	LM_DBG(	"[%s]: [%d] LDAP entries found\n",
		_lds_name,
		*_ld_result_count);

	return 0;
}


int ldap_url_search_async(
	str* _ldap_url,
	int* _msgidp,
	struct ld_session **ldsp,
	struct ld_conn** conn,
	int* ld_result_count)
{
	LDAPURLDesc *ludp;
	int rc;
	str ldap_url_nt;

	if (pkg_nt_str_dup(&ldap_url_nt, _ldap_url) < 0) {
		LM_ERR("no more pkg memory\n");
		return -2;
	}

	if (ldap_url_parse(ldap_url_nt.s, &ludp) != 0) {
		LM_ERR("invalid LDAP URL [%s]\n", ldap_url_nt.s);
		if (ludp != NULL) {
			ldap_free_urldesc(ludp);
		}
		goto error;
	}
	if (ludp->lud_host == NULL)
	{
		LM_ERR(	"no ldap session name found in ldap URL [%s]\n",
			ldap_url_nt.s);
		goto error;
	}


	LM_DBG(	"LDAP URL parsed into session_name"
		" [%s], base [%s], scope [%d], filter [%s]\n",
		ZSW(ludp->lud_host),
		ZSW(ludp->lud_dn),
		ludp->lud_scope,
		ZSW(ludp->lud_filter));

	rc = ldap_params_search_async(_msgidp,
		ludp->lud_host,
		ludp->lud_dn,
		ludp->lud_scope,
		ludp->lud_attrs,
		conn,
		ludp->lud_filter);
	if ((rc == 0 && *_msgidp >= 0) || rc == 1) {
		if (get_connected_ldap_session(ludp->lud_host, ldsp)) {
			LM_ERR("[%s]: couldn't get ldap session\n", ludp->lud_host);
			pkg_free(ldap_url_nt.s);		
			return -1;
		}
	}

	/* sync mode; get the number of results */
	if (rc == 1) {
		*ld_result_count = ldap_count_entries((*ldsp)->conn_s.handle, last_ldap_result);
		if (*ld_result_count < 0) {
			LM_ERR("[%s]: ldap_count_entries for sync call failed\n", (*ldsp)->name);
			pkg_free(ldap_url_nt.s);
			return -1;
		}
	}


	ldap_free_urldesc(ludp);
	pkg_free(ldap_url_nt.s);
	return rc;
error:
	pkg_free(ldap_url_nt.s);
	return -2;
}



int ldap_url_search(
	char* _ldap_url,
	int* _ld_result_count)
{
	LDAPURLDesc *ludp;
	int rc;

	if (ldap_url_parse(_ldap_url, &ludp) != 0) {
		LM_ERR("invalid LDAP URL [%s]\n", _ldap_url);
		if (ludp != NULL) {
			ldap_free_urldesc(ludp);
		}
		return -2;
	}
	if (ludp->lud_host == NULL)
	{
		LM_ERR(	"no ldap session name found in ldap URL [%s]\n",
			_ldap_url);
		return -2;
	}


	LM_DBG(	"LDAP URL parsed into session_name"
		" [%s], base [%s], scope [%d], filter [%s]\n",
		ZSW(ludp->lud_host),
		ZSW(ludp->lud_dn),
		ludp->lud_scope,
		ZSW(ludp->lud_filter));

	rc = ldap_params_search(_ld_result_count,
		ludp->lud_host,
		ludp->lud_dn,
		ludp->lud_scope,
		ludp->lud_attrs,
		ludp->lud_filter);
	ldap_free_urldesc(ludp);
	return rc;
}


int ldap_inc_result_pointer(void)
{
	LDAPMessage *next_result = NULL;

	/*
	* check for last_ldap_result
	*/
	if (last_ldap_result == NULL) {
		LM_ERR("last_ldap_result == NULL\n");
		return -1;
	}
	if (last_ldap_handle == NULL)
	{
		LM_ERR("last_ldap_handle == NULL\n");
		return -1;
	}

	/*
	* get next LDAP result pointer
	*/
	if ((next_result = ldap_next_entry(last_ldap_handle, last_ldap_result))
			== NULL)
	{
		/* no more LDAP entries */
		return 1;
	}
	last_ldap_result = next_result;
	return 0;
}


int ldap_get_attr_vals(str *_attr_name, struct berval ***_vals)
{
	BerElement *ber;
	char *a;

	/*
	* check for last_ldap_result
	*/
	if (last_ldap_result == NULL) {
		LM_ERR("last_ldap_result == NULL\n");
		return -1;
	}

	if (last_ldap_handle == NULL)
	{
		LM_ERR("last_ldap_handle == NULL\n");
		return -1;
	}

	/*
	* search for attribute named _attr_name
	*/
	*_vals = NULL;
	for (a = ldap_first_attribute(last_ldap_handle,
			last_ldap_result,
			&ber);
		a != NULL;
		a = ldap_next_attribute(last_ldap_handle,
			last_ldap_result,
			ber))
	{
		if (strlen(a) == _attr_name->len &&
				strncmp(a, _attr_name->s, _attr_name->len) == 0) {
			*_vals = ldap_get_values_len(
				last_ldap_handle,
				last_ldap_result,
				a);
			ldap_memfree(a);
			break;
		}
		ldap_memfree(a);
	}

	if (ber != NULL) {
		ber_free(ber, 0);
	}

	if (*_vals != NULL)
	{
		return 0;
	} else {
		return 1;
	}
}

int ldap_str2scope(char* scope_str)
{
	if ( strcasecmp( scope_str, "one" ) == 0 ) {
		return LDAP_SCOPE_ONELEVEL;

	} else if ( strcasecmp( scope_str, "onelevel" ) == 0 ) {
		return LDAP_SCOPE_ONELEVEL;

	} else if ( strcasecmp( scope_str, "base" ) == 0 ) {
		return LDAP_SCOPE_BASE;

	} else if ( strcasecmp( scope_str, "sub" ) == 0 ) {
		return LDAP_SCOPE_SUBTREE;

	} else if ( strcasecmp( scope_str, "subtree" ) == 0 ) {
		return LDAP_SCOPE_SUBTREE;
	};

	return( -1 );
}

/*
 * sets last_ldap_result and last_ldap_handle only if async receive succeeds;
 * if successful
 * 3 return possibilities:
 * a) message received - @return 0; @_msgidp -1
 * b) failed to receive; reactor needed - @return 0; @_msgidp >=0
 * c) other type of failure - @return < 0
 */
int lds_resume(
	struct ldap_async_params* asp,
	int *ld_result_count)
{

	int rc, rc_new;
	struct timeval zerotime;

	zerotime.tv_sec = zerotime.tv_usec = 0L;

	rc = ldap_result(asp->conn->handle, asp->msgid, LDAP_MSG_ALL,
			&zerotime, &last_ldap_result);

	switch (rc) {
		case 0:
			/* receive did not succeed; reactor needed */
			LM_DBG("Timeout exceeded! Async operation not complete!\n");
			return 0;
		default:
			if (LDAP_API_ERROR(rc)) {
				ldap_disconnect( asp->lds->name, asp->conn);

				/**
				 * FIXME FIXME we should continue asynchronously here
				 */
				/* this time try synchronously */
				/* execute the query again; we might have a failover server */
				if ((rc_new = ldap_url_search( asp->ldap_url.s, ld_result_count)) < 0) {
					/* LDAP search error; abort */
					rc = -2;
					goto error;
				}

				if ( *ld_result_count < 1) {
					LM_DBG("no LDAP entry found!\n");
				}

				return 1;
			}

			/* receive successful */
			LM_DBG("Successfully received response from ldap server!\n");
			/* FIXME we release the connection now; calling another async
			 * operation before calling ldap_result will break this mechanism,
			 * since the connection is released and the handle is being kept
			 * in last_ldap_handle global parameter
			 *
			 */
			release_ldap_connection(asp->conn);
			break;
	}

	last_ldap_handle = asp->conn->handle;
	*ld_result_count = ldap_count_entries(asp->conn->handle, last_ldap_result);

	if (*ld_result_count < 0)
	{
		LM_DBG("[%s]: ldap_count_entries failed\n", asp->lds->name);
		return -1;
	}

	return 1;
error:
	release_ldap_connection(asp->conn);
	return rc;
}


int lds_search_async(
	char* _lds_name,
	char* _dn,
	int _scope,
	char* _filter,
	char** _attrs,
	struct timeval* _search_timeout,
	int* _msgidp,
	struct ld_conn** conn)
{
	int ld_error, rc;
	struct ld_session* lds;

#ifdef LDAP_PERF
	struct timeval before_search = { 0, 0 }, after_search = { 0, 0 };
#endif

	/*
	 * get ld_handle
	 */
	if (get_connected_ldap_session(_lds_name, &lds) != 0)
	{
		LM_ERR("[%s]: couldn't get ldap session\n", _lds_name);
		return -1;
	}


	if ((*conn=get_ldap_connection(lds)) == NULL) {
		LM_DBG("No more connections available! will do synchronous query\n");
	}

	LM_DBG(	"[%s]: performing LDAP search: dn [%s],"
		" scope [%d], filter [%s], client_timeout [%d] usecs\n",
		_lds_name,
		_dn,
		_scope,
		_filter,
		(int)(lds->client_search_timeout.tv_sec * 1000000
			+ lds->client_search_timeout.tv_usec));

#ifdef LDAP_PERF
	gettimeofday(&before_search, NULL);
#endif

	/*
	 * perform ldap search
	 */

	if (*conn) {
		if ( check_reconnect( _lds_name, *conn) < 0 ) {
			LM_ERR("Reconnect failed!\n");
			return -1;
		}

		ld_error = ldap_search_ext(
			(*conn)->handle,
			_dn,
			_scope,
			_filter,
			_attrs,
			0,
			NULL,
			NULL,
			&lds->client_search_timeout,
			0,
			_msgidp);

		rc = 0;
	} else {
		/* falling back to sync */
		if ( check_reconnect( _lds_name, &lds->conn_s) < 0 ) {
			LM_ERR("Reconnect failed!\n");
			return -1;
		}

		ld_error = ldap_search_ext_s(
			lds->conn_s.handle,
			_dn,
			_scope,
			_filter,
			_attrs,
			0,
			NULL,
			NULL,
			&lds->client_search_timeout,
			0,
			&last_ldap_result);

		/* signal that the operation is sync to upper layers */
		rc = 1;
	}

#ifdef LDAP_PERF
	gettimeofday(&after_search, NULL);

	LM_INFO("[%s]: LDAP search took [%d] usecs\n",
		_lds_name,
		(int)((after_search.tv_sec * 1000000 + after_search.tv_usec)
		- (before_search.tv_sec * 1000000 + before_search.tv_usec)));
#endif

	if (ld_error != LDAP_SUCCESS)
	{
		if (LDAP_API_ERROR(ld_error))
		{
			ldap_disconnect(_lds_name, *conn);
		}

		LM_ERR(	"[%s]: LDAP search (dn [%s], scope [%d],"
				" filter [%s]) failed: %s\n",
				_lds_name,
				_dn,
				_scope,
				_filter,
				ldap_err2string(ld_error));

		return -1;
	}

	return rc;
}


/*
 * sets last_ldap_result and last_ldap_handle
 */
int lds_search(
	char* _lds_name,
	char* _dn,
	int _scope,
	char* _filter,
	char** _attrs,
	struct timeval* _search_timeout,
	int* _ld_result_count,
	int* _ld_error)
{
	struct ld_session* lds;
	struct ld_conn* conn;
#ifdef LDAP_PERF
	struct timeval before_search = { 0, 0 }, after_search = { 0, 0 };
#endif

	/*
	 * get ld_handle
	 */
	if (get_connected_ldap_session(_lds_name, &lds) != 0)
	{
		LM_ERR("[%s]: couldn't get ldap session\n", _lds_name);
		return -1;
	}

	conn = &lds->conn_s;
	/*
	 * free last_ldap_result
	 */
	if ( check_reconnect( _lds_name, conn) < 0 ) {
		LM_ERR("Reconnect failed!\n");
		return -1;
	}

	if (last_ldap_result != NULL) {
		ldap_msgfree(last_ldap_result);
		last_ldap_result = NULL;
	}


	LM_DBG(	"[%s]: performing LDAP search: dn [%s],"
		" scope [%d], filter [%s], client_timeout [%d] usecs\n",
		_lds_name,
		_dn,
		_scope,
		_filter,
		(int)(lds->client_search_timeout.tv_sec * 1000000
			+ lds->client_search_timeout.tv_usec));

#ifdef LDAP_PERF
	gettimeofday(&before_search, NULL);
#endif

	/*
	 * perform ldap search
	 */
	*_ld_error = ldap_search_ext_s(
		conn->handle,
		_dn,
		_scope,
		_filter,
		_attrs,
		0,
		NULL,
		NULL,
		&lds->client_search_timeout,
		0,
		&last_ldap_result);

#ifdef LDAP_PERF
	gettimeofday(&after_search, NULL);

	LM_INFO("[%s]: LDAP search took [%d] usecs\n",
		_lds_name,
		(int)((after_search.tv_sec * 1000000 + after_search.tv_usec)
		- (before_search.tv_sec * 1000000 + before_search.tv_usec)));
#endif

	if (*_ld_error != LDAP_SUCCESS)
	{
		if (last_ldap_result != NULL)
		{
			ldap_msgfree(last_ldap_result);
			last_ldap_result = NULL;
		}

		if (LDAP_API_ERROR(*_ld_error))
		{
			ldap_disconnect(_lds_name, conn);
		}

		LM_DBG( "[%s]: ldap_search_ext_st failed: %s\n",
			_lds_name,
			ldap_err2string(*_ld_error));
		return -1;
	}

	last_ldap_handle = conn->handle;
	*_ld_result_count = ldap_count_entries(conn->handle, last_ldap_result);
	if (*_ld_result_count < 0)
	{
		LM_DBG("[%s]: ldap_count_entries failed\n", _lds_name);
		return -1;
	}

	return 0;
}

