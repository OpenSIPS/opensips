/*
 * Copyright (C) 2006 enum.at
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
 */

#ifndef _TLS_SELECT_H_
#define _TLS_SELECT_H_

#include <openssl/ssl.h>

#include "../../parser/msg_parser.h"
#include "../../pvar.h"

enum {
	CERT_LOCAL      = 1<<0,   /* Select local certificate */
	CERT_PEER       = 1<<1,   /* Select peer certificate */
	CERT_SUBJECT    = 1<<2,   /* Select subject part of certificate */
	CERT_ISSUER     = 1<<3,   /* Select issuer part of certificate */

	CERT_VERIFIED   = 1<<4,   /* Test for verified certificate */
	CERT_REVOKED    = 1<<5,   /* Test for revoked certificate */
	CERT_EXPIRED    = 1<<6,   /* Expiration certificate test */
	CERT_SELFSIGNED = 1<<7,   /* self-signed certificate test */
	CERT_NOTBEFORE  = 1<<8,   /* Select validity end from certificate */
	CERT_NOTAFTER   = 1<<9,   /* Select validity start from certificate */

	COMP_CN = 1<<10,          /* Common name */
	COMP_O  = 1<<11,          /* Organization name */
	COMP_OU = 1<<12,          /* Organization unit */
	COMP_C  = 1<<13,          /* Country name */
	COMP_ST = 1<<14,          /* State */
	COMP_L  = 1<<15,          /* Locality/town */

	COMP_HOST = 1<<16,        /* hostname from subject/alternative */
	COMP_URI  = 1<<17,        /* URI from subject/alternative */
	COMP_E    = 1<<18,        /* Email address */
	COMP_IP   = 1<<19,        /* IP from subject/alternative */
	COMP_SUBJECT_SERIAL = 1<<20    /*Serial name from Subject*/
};


typedef int select_t;

int tlsops_cipher(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);

int tlsops_bits(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);

int tlsops_version(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);

int tlsops_desc(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);

int tlsops_cert_version(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);

/*
 * Check whether peer certificate exists and verify the result
 * of certificate verification
 */
int tlsops_check_cert(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);

int tlsops_validity(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);

int tlsops_sn(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);

int tlsops_comp(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);

int tlsops_alt(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);

#endif
