/*
 * Copyright (C) 2001-2003 FhG Fokus
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
 */


#ifndef PARSE_URI_H
#define PARSE_URI_H

/*
 * SIP URI parser
 */


#include "../str.h"
#include "../net/trans.h"
#include "../parser/msg_parser.h"

#define SIP_SCH			0x3a706973
#define SIPS_SCH		0x73706973
#define TEL_SCH			0x3a6c6574
#define URN_SERVICE_SCH		0x3a6e7275
#define URN_SERVICE_STR 	":service:"
#define URN_SERVICE_STR_LEN	(sizeof(URN_SERVICE_STR) - 1)

/* buf= pointer to beginning of uri (sip:x@foo.bar:5060;a=b?h=i)
 * len= len of uri
 * returns: fills uri & returns <0 on error or 0 if ok
 */
int parse_uri(char *buf, int len, struct sip_uri* uri);

/*
 * Fully prints a given "struct sip_uri" into a given buffer
 *
 * The following "struct sip_uri" fields can be disabled by setting to NULL:
 *   - passwd / host / port
 *   - transport / ttl / user_param / maddr / method / lr / r2 / gr
 *   - any of the unknown param names
 *
 * Returns 0 on success, -1 on failure
 */
int print_uri(struct sip_uri *uri, str *out_buf);

/* headers  : the list of headers to parse (taken from uri structure)
 * h_name[] : array of header names
 * h_val[]  : array of header values
 * h_size   : size of header array */
int parse_uri_headers(str headers, str h_name[], str h_val[], int h_size);
int parse_sip_msg_uri(struct sip_msg* msg);
int parse_orig_ruri(struct sip_msg* msg);
int compare_uris(str *raw_uri_a,struct sip_uri* parsed_uri_a,
					str *raw_uri_b,struct sip_uri *parsed_uri_b);
char * uri_type2str(const uri_type type, char *result);
int uri_typestrlen(const uri_type type);
uri_type str2uri_type(char * buf);

/* Gets (in a SIP wise manner) the SIP port from a SIP URI ; if the port
   is not explicitly set in the URI, it returns the default port corresponding
   to the used transport protocol (if protocol misses, we assume the default
   protos according to the URI schema) */
static inline unsigned short get_uri_port(struct sip_uri* _uri,
													unsigned short *_proto)
{
	unsigned short port;
	unsigned short proto;

	/* known protocol? */
	if ((proto=_uri->proto)==PROTO_NONE) {
		/* use UDP as default proto, but TLS for secure schemas */
		proto = (_uri->type==SIPS_URI_T || _uri->type==TELS_URI_T)?
			PROTO_TLS : PROTO_UDP ;
	}

	/* known port? */
	if ((port=_uri->port_no)==0)
		port = protos[proto].default_rfc_port;

	if (_proto) *_proto = proto;

	return port;
}

#endif /* PARSE_URI_H */
