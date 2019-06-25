/*
 * Copyright (C) 2007 voice-system.ro
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

/*! \file
 * \brief Transformations support
 */

#ifndef _TRANSFORMATIONS_H_
#define _TRANSFORMATIONS_H_

#include "usr_avp.h"
#include "pvar.h"

#define TR_LBRACKET_STR		"{"
#define TR_LBRACKET		'{'
#define TR_RBRACKET_STR		"}"
#define TR_RBRACKET		'}'
#define TR_CLASS_MARKER		'.'
#define TR_PARAM_MARKER		','

enum _tr_s_subtype {
	TR_S_NONE=0, TR_S_LEN, TR_S_INT, TR_S_MD5, TR_S_SUBSTR,
	TR_S_SELECT, TR_S_ENCODEHEXA, TR_S_DECODEHEXA, TR_S_HEX2DEC, TR_S_DEC2HEX,
	TR_S_ESCAPECOMMON, TR_S_UNESCAPECOMMON, TR_S_ESCAPEUSER, TR_S_UNESCAPEUSER,
	TR_S_ESCAPEPARAM, TR_S_UNESCAPEPARAM, TR_S_TOLOWER, TR_S_TOUPPER, TR_S_CRC32,
	TR_S_INDEX, TR_S_RINDEX, TR_S_FILL_LEFT, TR_S_FILL_RIGHT, TR_S_WIDTH,
        TR_S_B64ENCODE, TR_S_B64DECODE, TR_S_XOR, TR_S_TRIM, TR_S_TRIMR, TR_S_TRIML,
        TR_S_REVERSE
};
enum _tr_uri_subtype {
	TR_URI_NONE=0, TR_URI_USER, TR_URI_HOST, TR_URI_PASSWD, TR_URI_PORT,
	TR_URI_PARAMS, TR_URI_PARAM, TR_URI_HEADERS, TR_URI_TRANSPORT, TR_URI_TTL,
	TR_URI_UPARAM, TR_URI_MADDR, TR_URI_METHOD, TR_URI_LR,
	TR_URI_R2, TR_URI_SCHEMA
};
enum _tr_via_subtype {
        TR_VIA_NONE=0, TR_VIA_NAME, TR_VIA_VERSION, TR_VIA_TRANSPORT,
	TR_VIA_HOST, TR_VIA_PORT, TR_VIA_PARAMS, TR_VIA_PARAM,
	TR_VIA_COMMENT, TR_VIA_BRANCH, TR_VIA_RECEIVED, TR_VIA_RPORT
};
enum _tr_param_subtype {
	TR_PL_NONE=0, TR_PL_VALUE, TR_PL_VALUEAT, TR_PL_NAME, TR_PL_COUNT,
	TR_PL_EXIST
};
enum _tr_nameaddr_subtype {
	TR_NA_NONE=0, TR_NA_NAME, TR_NA_URI, TR_NA_LEN, TR_NA_PARAM,
	TR_NA_PARAMS
};
enum _tr_param_type { TR_PARAM_NONE=0, TR_PARAM_STRING, TR_PARAM_NUMBER,
	TR_PARAM_SPEC };
enum _tr_csv_subtype {TR_CSV_NONE=0, TR_CSV_COUNT,TR_CSV_VALUEAT};
enum _tr_sdp_subtype {TR_SDP_NONE=0, TR_SDP_LINEAT, TR_SDP_STREAM_DEL,
	TR_SDP_STREAM};
enum _tr_ip_subtype  {TR_IP_NONE=0,TR_IP_FAMILY,TR_IP_NTOP,TR_IP_RESOLVE,
	TR_IP_ISIP, TR_IP_ISIP4, TR_IP_ISIP6, TR_IP_PTON, TR_IP_MATCHES, TR_IP_ISPRIVATE};
enum _tr_re_subtype  {TR_RE_NONE=0,TR_RE_SUBST};

typedef struct tr_param_ {
	int type;
	union {
		int n;
		str s;
		void *data;
	} v;
	struct tr_param_ *next;
} tr_param_t, *tr_param_p;

typedef int (*tr_eval_f) (struct sip_msg *, tr_param_t*, int, pv_value_t*);

typedef struct trans_ {
	str name;
	int subtype;
	tr_eval_f trf;
	tr_param_t *params;
	struct trans_ *next;
} trans_t, *trans_p;

typedef int (*tr_parse_f)(str *in, trans_t *t);

typedef struct trans_export_ {
	str name;
	tr_parse_f parse_func;
	tr_eval_f eval_func;
} trans_export_t;

typedef struct trans_extra_ {
	trans_export_t tre;
	struct trans_extra_ *next;
} trans_extra_t;

int register_trans_mod(char *mod_name, trans_export_t *tr_exports);
void tr_free_extra_list(void);

int run_transformations(struct sip_msg *msg, trans_t *tr, pv_value_t *val);
char* parse_transformation(str *in, trans_t **tr);
void destroy_transformation(trans_t *t);
void free_transformation(trans_t *t);
void free_tr_param(tr_param_t *tp);

/* transformation parameter parsing helper functions */
char *tr_parse_nparam(char *p, str *in, tr_param_t **tp);
char *tr_parse_sparam(char *p, str *in, tr_param_t **tp, int skip_param_ws);

/* core transformations */
int tr_parse_string(str* in, trans_t *t);
int tr_eval_string(struct sip_msg *msg, tr_param_t *tp, int subtype,
		pv_value_t *val);

int tr_parse_uri(str* in, trans_t *t);
int tr_eval_uri(struct sip_msg *msg, tr_param_t *tp, int subtype,
		pv_value_t *val);

int tr_parse_via(str* in, trans_t *t);
int tr_eval_via(struct sip_msg *msg, tr_param_t *tp, int subtype,
		pv_value_t *val);

int tr_parse_paramlist(str* in, trans_t *t);
int tr_eval_paramlist(struct sip_msg *msg, tr_param_t *tp, int subtype,
		pv_value_t *val);

int tr_parse_nameaddr(str* in, trans_t *t);
int tr_eval_nameaddr(struct sip_msg *msg, tr_param_t *tp, int subtype,
		pv_value_t *val);

int tr_parse_csv(str *in,trans_t *t);
int tr_eval_csv(struct sip_msg *msg, tr_param_t *tp, int subtype,
		pv_value_t *val);

int tr_parse_sdp(str *in,trans_t *t);
int tr_eval_sdp(struct sip_msg *msg, tr_param_t *tp, int subtype,
		pv_value_t *val);

int tr_parse_ip(str *in,trans_t *t);
int tr_eval_ip(struct sip_msg *msg, tr_param_t *tp, int subtype,
		pv_value_t *val);

int tr_parse_re(str *in,trans_t *t);
int tr_eval_re(struct sip_msg *msg, tr_param_t *tp, int subtype,
		pv_value_t *val);

#endif

