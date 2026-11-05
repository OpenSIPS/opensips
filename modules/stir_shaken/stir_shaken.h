/*
 * Copyright (C) 2019 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 *
 */

#ifndef STIR_SHAKEN_H
#define STIR_SHAKEN_H

#include "../../pvar.h"
#include "passport.h"

#define DEFAULT_AUTH_FRESHNESS 60
#define DEFAULT_VERIFY_FRESHNESS 60

#define DATE_FORMAT "%a, %d %b %Y %H:%M:%S GMT"
#define DATE_MAX_LEN 64

#define BADREQ_CODE 400
#define BADREQ_ORIG_REASON "Bad Request (PAI/From Number)"
#define BADREQ_DEST_REASON "Bad Request (To Number)"
#define BADREQ_NODATE_REASON "Bad Request (Missing Date)"
#define STALE_DATE_CODE 403
#define STALE_DATE_REASON "Stale Date"
#define USE_IDENTITY_CODE 428
#define USE_IDENTITY_REASON "Use Identity Header"
#define UNSUPPORTED_CRED_CODE 437
#define UNSUPPORTED_CRED_REASON "Unsupported Credential"
#define INVALID_IDENTITY_CODE 438
#define INVALID_IDENTITY_REASON "Invalid Identity Header"
#define IERROR_CODE 500
#define IERROR_REASON "Internal Server Error"
#define IERROR_REASON_PARSE_HEADERS "Failed to parse headers"
#define IERROR_REASON_PARSE_IDENTITY "Failed to parse identity header"
#define IERROR_REASON_GET_CURRENT_TIME "Failed to get current time"
#define IERROR_REASON_GET_TIME_FROM_DATE_HEADER "Failed to get UNIX time from Date header"
#define IERROR_REASON_LOAD_CERTIFICATE "Failed to load certificate"
#define IERROR_REASON_VALIDATE_CERTIFICATE "Error validating certificate"
#define IERROR_REASON_VERIFY_SIGNATURE "Error while verifying signature"

#define TN_AUTH_LIST_OID "1.3.6.1.5.5.7.1.26"
#define TN_AUTH_LIST_LN "TNAuthorizationList"
#define TN_AUTH_LIST_SN "TNAuthList"

#define AUTH_OUT_REQ_STR "req"
#define AUTH_OUT_RPL_STR "rpl"

enum auth_out_type {
	AUTH_APPEND_TO_REQ,
	AUTH_APPEND_TO_RPL,
	AUTH_OUT_VAR
};

struct auth_out_param {
	enum auth_out_type type;
	pv_spec_t var;
};

#endif /* STIR_SHAKEN_H */
