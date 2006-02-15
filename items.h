/*
 * $Id$
 *
 * Copyright (C) 2001-2003 FhG Fokus
 *
 * This file is part of openser, a free SIP server.
 *
 * openser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * openser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _ITEMS_H_
#define _ITEMS_H_

#include "parser/msg_parser.h"
#include "usr_avp.h"

#define ITEM_MARKER_STR	"$"
#define ITEM_MARKER	'$'

#define ITEM_LNBRACKET_STR	"("
#define ITEM_LNBRACKET		'('
#define ITEM_RNBRACKET_STR	")"
#define ITEM_RNBRACKET		')'

#define ITEM_LIBRACKET_STR	"["
#define ITEM_LIBRACKET		'['
#define ITEM_RIBRACKET_STR	"]"
#define ITEM_RIBRACKET		']'

#define XL_DISABLE_NONE		0
#define XL_THROW_ERROR		1
#define XL_DISABLE_MULTI	2
#define XL_DISABLE_COLORS	4
#define XL_DISABLE_PVARS	8
#define XL_DPARAM			16
#define XL_LEVEL2			32

#define XL_VAL_NONE			0
#define XL_VAL_NULL			1
#define XL_VAL_EMPTY		2
#define XL_VAL_STR			4
#define XL_VAL_INT			8
#define XL_TYPE_INT			16

enum _xl_type { 
	XL_NONE=0,           XL_EMPTY,             XL_NULL, 
	XL_MARKER,           XL_AVP,               XL_HDR,
	XL_PID,              XL_RETURN_CODE,       XL_TIMES,
	XL_TIMEF,            XL_MSGID,             XL_METHOD,
	XL_STATUS,           XL_REASON,            XL_RURI,
	XL_RURI_USERNAME,    XL_RURI_DOMAIN,       XL_RURI_PORT,
	XL_FROM,             XL_FROM_USERNAME,     XL_FROM_DOMAIN,
	XL_FROM_TAG,         XL_TO,                XL_TO_USERNAME,
	XL_TO_DOMAIN,        XL_TO_TAG,            XL_CSEQ,
	XL_CONTACT,          XL_CALLID,            XL_USERAGENT,
	XL_MSG_BUF,          XL_MSG_LEN,           XL_FLAGS,
	XL_HEXFLAGS,         XL_SRCIP,             XL_SRCPORT,
	XL_RCVIP,            XL_RCVPORT,           XL_REFER_TO,
	XL_DSET,             XL_DSTURI,            XL_COLOR,
	XL_BRANCH,           XL_BRANCHES,          XL_CONTENT_TYPE,
	XL_CONTENT_LENGTH,   XL_MSG_BODY,          XL_AUTH_USERNAME,
	XL_AUTH_REALM,       XL_RURI_PROTOCOL,     XL_DSTURI_DOMAIN,
	XL_DSTURI_PORT,      XL_DSTURI_PROTOCOL,   XL_FROM_DISPLAYNAME,
	XL_TO_DISPLAYNAME,   XL_OURI,              XL_OURI_USERNAME,
	XL_OURI_DOMAIN,      XL_OURI_PORT,         XL_OURI_PROTOCOL,
	XL_FORCE_SOCK
};
typedef enum _xl_type xl_type_t;


typedef struct _xl_value
{
	str rs;
	int ri;
	int flags;
} xl_value_t, *xl_value_p;

typedef struct _xl_param
{
	str val;
	int ind;
} xl_param_t, *xl_param_p;

typedef int (*item_func_t) (struct sip_msg*, xl_value_t*,  xl_param_t*, int);

typedef int xl_flags_t;

typedef struct _xl_dparam
{
	item_func_t itf;
	int ind;
} xl_dparam_t, *xl_dparam_p;

typedef struct _xl_spec {
	xl_type_t   type;
	xl_flags_t  flags;
	item_func_t itf;
	xl_param_t  p;
	xl_dparam_t dp;
} xl_spec_t, *xl_spec_p;

typedef struct _xl_elem
{
	str text;
	xl_spec_t spec;
	struct _xl_elem *next;
} xl_elem_t, *xl_elem_p;

int xl_elem_free_all(xl_elem_p list);
char* xl_parse_spec(char *s, xl_spec_p sp, int flags);
int xl_parse_format(char *s, xl_elem_p *el, int flags);
int xl_get_spec_value(struct sip_msg* msg, xl_spec_p sp, xl_value_t *value,
		int flags);
int xl_get_spec_name(struct sip_msg* msg, xl_spec_p sp, xl_value_t *value,
		int flags);
int xl_get_avp_name(struct sip_msg* msg, xl_spec_p sp, int_str *avp_name,
		unsigned short *name_type);
int xl_print_spec(struct sip_msg* msg, xl_spec_p sp, char *buf, int *len);
int xl_printf(struct sip_msg* msg, xl_elem_p list, char *buf, int *len);

#endif

