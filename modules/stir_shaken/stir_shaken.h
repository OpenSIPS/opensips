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

#define FULL_ATTEST_STR    "A"
#define PARTIAL_ATTEST_STR "B"
#define GATEWAY_ATTEST_STR "C"

#define DEFAULT_AUTH_FRESHNESS 60
#define DEFAULT_VERIFY_FRESHNESS 60

#define DATE_FORMAT "%a, %d %b %Y %H:%M:%S GMT"
#define DATE_MAX_LEN 64

#define CRLF "\r\n"
#define CRLF_LEN (sizeof(CRLF) - 1)

#define PPORT_HDR_ALG 	  "alg"
#define PPORT_HDR_ALG_VAL "ES256"
#define PPORT_HDR_PPT     "ppt"
#define PPORT_HDR_PPT_VAL "shaken"
#define PPORT_HDR_TYP     "typ"
#define PPORT_HDR_TYP_VAL "passport"
#define PPORT_HDR_X5U "x5u"
#define PPORT_PAYLOAD_ATTEST "attest"
#define PPORT_PAYLOAD_DEST "dest"
#define PPORT_PAYLOAD_TN "tn"
#define PPORT_PAYLOAD_IAT "iat"
#define PPORT_PAYLOAD_ORIG "orig"
#define PPORT_PAYLOAD_ORIGID "origid"
#define PPORT_SEPARATOR '.'

#define HDR_PARAM_SEPARATOR ';'

#define BASE64_PAD_CHAR '='

#define IDENTITY_HDR_S "Identity: "
#define IDENTITY_HDR_LEN (sizeof(IDENTITY_HDR_S)-1)
#define HDR_INFO_PARAM_S "info="
#define HDR_INFO_PARAM_LEN (sizeof(HDR_INFO_PARAM_S)-1)
#define HDR_PPT_PARAM_S "ppt=\"shaken\""
#define HDR_PPT_PARAM_LEN (sizeof(HDR_PPT_PARAM_S)-1)

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

#define TN_AUTH_LIST_OID "1.3.6.1.5.5.7.1.26"
#define TN_AUTH_LIST_LN "TNAuthorizationList"
#define TN_AUTH_LIST_SN "TNAuthList"

#define R_S_INT_LEN 32
#define RAW_SIG_LEN 64

struct parsed_identity {
	cJSON *header;
	cJSON *x5u;

	cJSON *payload;
	cJSON *attest;
	cJSON *dest_tn;
	cJSON *iat;
	cJSON *orig_tn;
	cJSON *origid;

	str dec_header;
	str dec_payload;
	str dec_signature;

	str ppt_hdr_param;
	str alg_hdr_param;
};

enum pv_identity_field {
	PV_HEADER,
	PV_HEADER_X5U,
	PV_PAYLOAD,
	PV_PAYLOAD_ATTEST,
	PV_PAYLOAD_DEST,
	PV_PAYLOAD_IAT,
	PV_PAYLOAD_ORIG,
	PV_PAYLOAD_ORIGID
};
