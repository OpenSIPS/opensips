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


#include "../ut.h"
#include "../str.h"
#include "../net/trans.h"
#include "../parser/msg_parser.h"

#define SIP_SCH			0x3a706973
#define SIPS_SCH		0x73706973
#define TEL_SCH			0x3a6c6574
#define URN_SERVICE_SCH		0x3a6e7275
#define URN_SERVICE_STR 	":service:"
#define URN_SERVICE_STR_LEN	(sizeof(URN_SERVICE_STR) - 1)
#define URN_NENA_SERVICE_STR 	":nena:service:"
#define URN_NENA_SERVICE_STR_LEN	(sizeof(URN_NENA_SERVICE_STR) - 1)

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
static inline int get_uri_param_val(const struct sip_uri *uri,
                                    const str *param, str *val);
static inline int get_uri_param_idx(const str *param,
                                    const struct sip_uri *parsed_uri);

/**
 * Test a given char or an entire string against the allowed characters
 * of a SIP URI 'username' field.
 *
 * Return 1 (success), 0 (failure)
 */
static inline int is_username_char(char c);
static inline int is_username_str(const str *username);

/**
 * Test a given char or an entire string against the allowed characters
 * of a SIP URI 'uri-parameter' field.  Works for both 'pname'
 * and 'pvalue'.
 *
 * Return 1 (success), 0 (failure)
 */
static inline int is_uri_parameter_char(char c);
static inline int is_uri_parameter_str(const str *uri_param);

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


/**
 * get_uri_param_val() - Fetch the value of a given URI parameter
 * @uri - parsed SIP URI
 * @param - URI param name to search for
 * @val - output value
 *
 * Return:
 *   0 on RFC-recognized parameters (even if they are missing!)
 *       or successful search of unknown ones
 *  -1 otherwise
 */
static inline int get_uri_param_val(const struct sip_uri *uri,
                                    const str *param, str *val)
{
	int i;

	if (ZSTR(*param))
		return -1;

	switch (param->s[0]) {
	case 'p':
	case 'P':
		if (str_casematch(param, _str("pn-provider"))) {
			*val = uri->pn_provider_val;
			return 0;
		}

		if (str_casematch(param, _str("pn-prid"))) {
			*val = uri->pn_prid_val;
			return 0;
		}

		if (str_casematch(param, _str("pn-param"))) {
			*val = uri->pn_param_val;
			return 0;
		}

		if (str_casematch(param, _str("pn-purr"))) {
			*val = uri->pn_purr_val;
			return 0;
		}
		break;

	case 't':
	case 'T':
		if (str_casematch(param, _str("transport"))) {
			*val = uri->transport_val;
			return 0;
		}

		if (str_casematch(param, _str("ttl"))) {
			*val = uri->ttl_val;
			return 0;
		}
		break;

	case 'u':
	case 'U':
		if (str_casematch(param, _str("user"))) {
			*val = uri->user_param_val;
			return 0;
		}
		break;

	case 'm':
	case 'M':
		if (str_casematch(param, _str("maddr"))) {
			*val = uri->maddr_val;
			return 0;
		}

		if (str_casematch(param, _str("method"))) {
			*val = uri->method_val;
			return 0;
		}
		break;

	case 'l':
	case 'L':
		if (str_casematch(param, _str("lr"))) {
			*val = uri->lr_val;
			return 0;
		}
		break;

	case 'r':
	case 'R':
		if (str_casematch(param, _str("r2"))) {
			*val = uri->r2_val;
			return 0;
		}
		break;

	case 'g':
	case 'G':
		if (str_casematch(param, _str("gr"))) {
			*val = uri->gr_val;
			return 0;
		}
		break;
	}

	for (i = 0; i < uri->u_params_no; i++)
		if (str_match(param, &uri->u_name[i])) {
			*val = uri->u_val[i];
			return 0;
		}

	return -1;
}


/* Unknown URI param index.
 *
 * Returns >= 0 on success, -1 on failure.
 */
static inline int get_uri_param_idx(const str *param,
                                    const struct sip_uri *parsed_uri)
{
	int i;

	for (i = 0; i < parsed_uri->u_params_no; i++)
		if (str_match(&parsed_uri->u_name[i], param))
			return i;

	return -1;
}

static inline int is_username_char(char c)
{
	return (int[]){
		0 /* 0 NUL */,
		0 /* 1 SOH */,
		0 /* 2 STX */,
		0 /* 3 ETX */,
		0 /* 4 EOT */,
		0 /* 5 ENQ */,
		0 /* 6 ACK */,
		0 /* 7 BEL */,
		0 /* 8 BS */,
		0 /* 9 HT */,
		0 /* 10 LF */,
		0 /* 11 VT */,
		0 /* 12 FF */,
		0 /* 13 CR */,
		0 /* 14 SO */,
		0 /* 15 SI */,
		0 /* 16 DLE */,
		0 /* 17 DC1 */,
		0 /* 18 DC2 */,
		0 /* 19 DC3 */,
		0 /* 20 DC4 */,
		0 /* 21 NAK */,
		0 /* 22 SYN */,
		0 /* 23 ETB */,
		0 /* 24 CAN */,
		0 /* 25 EM */,
		0 /* 26 SUB */,
		0 /* 27 ESC */,
		0 /* 28 FS */,
		0 /* 29 GS */,
		0 /* 30 RS */,
		0 /* 31 US */,
		0 /* 32   */,
		1 /* 33 ! */,
		0 /* 34 " */,
		0 /* 35 # */,
		1 /* 36 $ */,
		0 /* 37 % */,
		1 /* 38 & */,
		1 /* 39 ' */,
		1 /* 40 ( */,
		1 /* 41 ) */,
		1 /* 42 * */,
		1 /* 43 + */,
		1 /* 44 , */,
		1 /* 45 - */,
		1 /* 46 . */,
		1 /* 47 / */,
		1 /* 48 0 */,
		1 /* 49 1 */,
		1 /* 50 2 */,
		1 /* 51 3 */,
		1 /* 52 4 */,
		1 /* 53 5 */,
		1 /* 54 6 */,
		1 /* 55 7 */,
		1 /* 56 8 */,
		1 /* 57 9 */,
		0 /* 58 : */,
		1 /* 59 ; */,
		0 /* 60 < */,
		1 /* 61 = */,
		0 /* 62 > */,
		1 /* 63 ? */,
		0 /* 64 @ */,
		1 /* 65 A */,
		1 /* 66 B */,
		1 /* 67 C */,
		1 /* 68 D */,
		1 /* 69 E */,
		1 /* 70 F */,
		1 /* 71 G */,
		1 /* 72 H */,
		1 /* 73 I */,
		1 /* 74 J */,
		1 /* 75 K */,
		1 /* 76 L */,
		1 /* 77 M */,
		1 /* 78 N */,
		1 /* 79 O */,
		1 /* 80 P */,
		1 /* 81 Q */,
		1 /* 82 R */,
		1 /* 83 S */,
		1 /* 84 T */,
		1 /* 85 U */,
		1 /* 86 V */,
		1 /* 87 W */,
		1 /* 88 X */,
		1 /* 89 Y */,
		1 /* 90 Z */,
		0 /* 91 [ */,
		0 /* 92 \ */,
		0 /* 93 ] */,
		0 /* 94 ^ */,
		1 /* 95 _ */,
		0 /* 96 ` */,
		1 /* 97 a */,
		1 /* 98 b */,
		1 /* 99 c */,
		1 /* 100 d */,
		1 /* 101 e */,
		1 /* 102 f */,
		1 /* 103 g */,
		1 /* 104 h */,
		1 /* 105 i */,
		1 /* 106 j */,
		1 /* 107 k */,
		1 /* 108 l */,
		1 /* 109 m */,
		1 /* 110 n */,
		1 /* 111 o */,
		1 /* 112 p */,
		1 /* 113 q */,
		1 /* 114 r */,
		1 /* 115 s */,
		1 /* 116 t */,
		1 /* 117 u */,
		1 /* 118 v */,
		1 /* 119 w */,
		1 /* 120 x */,
		1 /* 121 y */,
		1 /* 122 z */,
		0 /* 123 { */,
		0 /* 124 | */,
		0 /* 125 } */,
		1 /* 126 ~ */,
		0 /* 127 DEL */
	}[(int)c];
}


static inline int is_username_str(const str *username)
{
	char *p, *end, c;

	for (p = username->s, end = p + username->len; p < end; p++) {
		c = *p;

		if (c < 0)
			goto err;

		if (c == '%') {
			if ((p + 3) > end || !_isxdigit(*(p + 1)) || !_isxdigit(*(p + 2)))
				goto err;
			p += 2;
		} else if (!is_username_char(c)) {
			goto err;
		}
	}

	return 1;

err:
	LM_DBG("invalid character %c[%d] in username <%.*s> on index %d\n",
	       c, c, username->len, username->s, (int)(p - username->s));
	return 0;
}


static inline int is_uri_parameter_char(char c)
{
	return (int[]){
		0 /* 0 NUL */,
		0 /* 1 SOH */,
		0 /* 2 STX */,
		0 /* 3 ETX */,
		0 /* 4 EOT */,
		0 /* 5 ENQ */,
		0 /* 6 ACK */,
		0 /* 7 BEL */,
		0 /* 8 BS */,
		0 /* 9 HT */,
		0 /* 10 LF */,
		0 /* 11 VT */,
		0 /* 12 FF */,
		0 /* 13 CR */,
		0 /* 14 SO */,
		0 /* 15 SI */,
		0 /* 16 DLE */,
		0 /* 17 DC1 */,
		0 /* 18 DC2 */,
		0 /* 19 DC3 */,
		0 /* 20 DC4 */,
		0 /* 21 NAK */,
		0 /* 22 SYN */,
		0 /* 23 ETB */,
		0 /* 24 CAN */,
		0 /* 25 EM */,
		0 /* 26 SUB */,
		0 /* 27 ESC */,
		0 /* 28 FS */,
		0 /* 29 GS */,
		0 /* 30 RS */,
		0 /* 31 US */,
		0 /* 32   */,
		1 /* 33 ! */,
		0 /* 34 " */,
		0 /* 35 # */,
		1 /* 36 $ */,
		0 /* 37 % */,
		1 /* 38 & */,
		1 /* 39 ' */,
		1 /* 40 ( */,
		1 /* 41 ) */,
		1 /* 42 * */,
		1 /* 43 + */,
		0 /* 44 , */,
		1 /* 45 - */,
		1 /* 46 . */,
		1 /* 47 / */,
		1 /* 48 0 */,
		1 /* 49 1 */,
		1 /* 50 2 */,
		1 /* 51 3 */,
		1 /* 52 4 */,
		1 /* 53 5 */,
		1 /* 54 6 */,
		1 /* 55 7 */,
		1 /* 56 8 */,
		1 /* 57 9 */,
		1 /* 58 : */,
		0 /* 59 ; */,
		0 /* 60 < */,
		0 /* 61 = */,
		0 /* 62 > */,
		0 /* 63 ? */,
		0 /* 64 @ */,
		1 /* 65 A */,
		1 /* 66 B */,
		1 /* 67 C */,
		1 /* 68 D */,
		1 /* 69 E */,
		1 /* 70 F */,
		1 /* 71 G */,
		1 /* 72 H */,
		1 /* 73 I */,
		1 /* 74 J */,
		1 /* 75 K */,
		1 /* 76 L */,
		1 /* 77 M */,
		1 /* 78 N */,
		1 /* 79 O */,
		1 /* 80 P */,
		1 /* 81 Q */,
		1 /* 82 R */,
		1 /* 83 S */,
		1 /* 84 T */,
		1 /* 85 U */,
		1 /* 86 V */,
		1 /* 87 W */,
		1 /* 88 X */,
		1 /* 89 Y */,
		1 /* 90 Z */,
		1 /* 91 [ */,
		0 /* 92 \ */,
		1 /* 93 ] */,
		0 /* 94 ^ */,
		1 /* 95 _ */,
		0 /* 96 ` */,
		1 /* 97 a */,
		1 /* 98 b */,
		1 /* 99 c */,
		1 /* 100 d */,
		1 /* 101 e */,
		1 /* 102 f */,
		1 /* 103 g */,
		1 /* 104 h */,
		1 /* 105 i */,
		1 /* 106 j */,
		1 /* 107 k */,
		1 /* 108 l */,
		1 /* 109 m */,
		1 /* 110 n */,
		1 /* 111 o */,
		1 /* 112 p */,
		1 /* 113 q */,
		1 /* 114 r */,
		1 /* 115 s */,
		1 /* 116 t */,
		1 /* 117 u */,
		1 /* 118 v */,
		1 /* 119 w */,
		1 /* 120 x */,
		1 /* 121 y */,
		1 /* 122 z */,
		0 /* 123 { */,
		0 /* 124 | */,
		0 /* 125 } */,
		1 /* 126 ~ */,
		0 /* 127 DEL */
	}[(int)c];
}


static inline int is_uri_parameter_str(const str *uri_param)
{
	char *p, *end, c;

	for (p = uri_param->s, end = p + uri_param->len; p < end; p++) {
		c = *p;

		if (c < 0)
			goto err;

		if (c == '%') {
			if ((p + 3) > end || !_isxdigit(*(p + 1)) || !_isxdigit(*(p + 2)))
				goto err;
			p += 2;
		} else if (!is_uri_parameter_char(c)) {
			goto err;
		}
	}

	return 1;

err:
	LM_DBG("invalid character %c[%d] in uri-parameter <%.*s> on index %d\n",
	       c, c, uri_param->len, uri_param->s, (int)(p - uri_param->s));
	return 0;
}

#endif /* PARSE_URI_H */
