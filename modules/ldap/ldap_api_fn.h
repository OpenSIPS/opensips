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


#ifndef LDAP_API_FN_H
#define LDAP_API_FN_H

#include <ldap.h>

#include "../../str.h"
#include "../../sr_module.h"
#include "ld_session.h"
#include "ldap_exp_fn.h"

#define LDAP_MAX_FILTER_LEN 1024

/*
* LDAP API functions
*/
int lds_resume(
	struct ldap_async_params* asp,
	int *ld_result_count);

int ldap_params_search_async(
	int* _msgidp,
	char* _lds_name,
	char* _dn,
	int _scope,
	char** _attrs,
	struct ld_conn** conn,
	char* _filter,
	...);


int ldap_params_search(
	int* _ld_result_count,
	char* _lds_name,
	char* _dn,
	int _scope,
	char** _attrs,
	char* _filter,
	...);

int ldap_url_search_async(
	str* _ldap_url,
	int* _msgidp,
	struct ld_session **ldsp,
	struct ld_conn** conn,
	int* ld_result_count);

int ldap_url_search(
	char* _ldap_url,
	int* _ld_result_count);

int ldap_get_attr_vals(
	str *_attr_name,
	struct berval ***_vals);

int ldap_inc_result_pointer();

int ldap_str2scope(char* scope_str);

int get_ldap_handle(char* _lds_name, LDAP** _ldap_handle);

void get_last_ldap_result(LDAP** _last_ldap_handle,
		LDAPMessage** _last_ldap_result);

void release_ldap_connection(struct ld_conn* conn);
#endif /* LDAP_API_FN_H */
