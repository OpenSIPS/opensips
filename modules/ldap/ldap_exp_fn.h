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


#ifndef LDAP_EXP_FN_H
#define LDAP_EXP_FN_H


#include "../../str.h"
#include "../../pvar.h"
#include "../../parser/msg_parser.h"
#include "../../re.h"
#include "ld_session.h"

struct ldap_async_params {
	int msgid;
	str ldap_url;
	struct ld_session *lds;
	struct ld_conn *conn;
};

int ldap_search_impl_async(
	struct sip_msg* _msg,
	async_ctx *ctx,
	str* _ldap_url);

int ldap_search_impl(
	struct sip_msg* _msg,
	str* _ldap_url);

int ldap_write_result( struct sip_msg* _msg, str *attr_name, pv_spec_t *dst_avp,
				int avp_type, struct subst_expr* _se);

int ldap_result_next();

int ldap_filter_url_encode(struct sip_msg* _msg, str *filter_component,
					pv_spec_t* _dst_avp_spec);

int rfc2254_escape(
	struct sip_msg* _msg,
	char* _value,
	char* _avp_name);

int ldap_result_check(struct sip_msg* _msg, str* attr_name, str *check_str,
				struct subst_expr *_se);

#endif /* LDAP_EXP_FN_H */
