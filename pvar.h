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
 */

/*!
 * \file
 * \brief Definitions for Pseudo-variable support
 */


#ifndef _PVAR_H_
#define _PVAR_H_

#include "str.h"
#include "usr_avp.h"
#include "parser/msg_parser.h"

#define PV_MARKER_STR	"$"
#define PV_MARKER		'$'

#define PV_LNBRACKET_STR	"("
#define PV_LNBRACKET		'('
#define PV_RNBRACKET_STR	")"
#define PV_RNBRACKET		')'

#define PV_LIBRACKET_STR	"["
#define PV_LIBRACKET		'['
#define PV_RIBRACKET_STR	"]"
#define PV_RIBRACKET		']'

#define PV_LCBRACKET		'<'
#define PV_LCBRACKET_STR	"<"
#define PV_RCBRACKET		'>'
#define PV_RCBRACKET_STR	">"


#define PV_VAL_NONE			0
#define PV_VAL_NULL			1
#define PV_VAL_EMPTY		2
#define PV_VAL_STR			4
#define PV_VAL_INT			8
#define PV_TYPE_INT			16
#define PV_VAL_PKG			32
#define PV_VAL_SHM			64

/* @v: a (pv_value_t *) */
#define pvv_is_int(v) \
	((v)->flags & (PV_VAL_INT|PV_TYPE_INT) && \
		((v)->flags & PV_TYPE_INT || !((v)->flags & PV_VAL_STR)))
#define pvv_is_str(v) \
	((v)->flags & PV_VAL_STR && !((v)->flags & PV_TYPE_INT))

#define fix_val_str_flags(_pvv) \
	do { \
		if (_pvv.flags & PV_VAL_STR) { \
			if (!_pvv.rs.s && _pvv.rs.len == 0) \
				_pvv.flags |= PV_VAL_NULL; \
			else if (_pvv.rs.s && _pvv.rs.len == 0) \
				_pvv.flags |= PV_VAL_EMPTY; \
		} \
	} while (0)

#define PV_NAME_INTSTR	0
#define PV_NAME_PVAR	1

#define PV_IDX_PVAR    1
#define PV_IDX_ALL     2
#define PV_IDX_INT     3
#define PV_IDX_APPEND  4

/*! if PV name is dynamic, integer, or str */
#define pv_has_dname(pv) ((pv)->pvp.pvn.type==PV_NAME_PVAR)
#define pv_has_iname(pv) ((pv)->pvp.pvn.type==PV_NAME_INTSTR \
							&& !((pv)->pvp.pvn.u.isname.type&AVP_NAME_STR))
#define pv_has_sname(pv) ((pv)->pvp.pvn.type==PV_NAME_INTSTR \
							&& (pv)->pvp.pvn.u.isname.type&AVP_NAME_STR)
#define pv_is_w(pv)   ((pv)->setf)
#define pv_type(type) (type < PVT_EXTRA ? type : type - PVT_EXTRA)

enum _pv_type {
	PVT_NONE=0,           PVT_EMPTY,             PVT_NULL,
	PVT_MARKER,           PVT_AVP,               PVT_HDR,
	PVT_PID,              PVT_RETURN_CODE,       PVT_TIMES,
	PVT_TIMEF,            PVT_MSGID,             PVT_METHOD,
	PVT_STATUS,           PVT_REASON,            PVT_RURI,
	PVT_RURI_USERNAME,    PVT_RURI_DOMAIN,       PVT_RURI_PORT,
	PVT_FROM,             PVT_FROM_USERNAME,     PVT_FROM_DOMAIN,
	PVT_FROM_TAG,         PVT_TO,                PVT_TO_USERNAME,
	PVT_TO_DOMAIN,        PVT_TO_TAG,            PVT_CSEQ,
	PVT_CONTACT,          PVT_CALLID,            PVT_USERAGENT,
	PVT_MSG_BUF,          PVT_MSG_LEN,           PVT_FLAGS,
	PVT_HEXFLAGS,         PVT_SRCIP,             PVT_SRCPORT,
	PVT_RCVIP,            PVT_RCVPORT,           PVT_REFER_TO,
	PVT_DSET,             PVT_DSTURI,            PVT_COLOR,
	PVT_BRANCH,           PVT_BRANCHES,          PVT_CONTENT_TYPE,
	PVT_CONTENT_LENGTH,   PVT_MSG_BODY,          PVT_AUTH_USERNAME,
	PVT_AUTH_REALM,       PVT_RURI_PROTOCOL,     PVT_DSTURI_DOMAIN,
	PVT_DSTURI_PORT,      PVT_DSTURI_PROTOCOL,   PVT_FROM_DISPLAYNAME,
	PVT_TO_DISPLAYNAME,   PVT_OURI,              PVT_OURI_USERNAME,
	PVT_OURI_DOMAIN,      PVT_OURI_PORT,         PVT_OURI_PROTOCOL,
	PVT_FORCE_SOCK,       PVT_RPID_URI,          PVT_DIVERSION_URI,
	PVT_ACC_USERNAME,     PVT_PPI,               PVT_PPI_DISPLAYNAME,
	PVT_PPI_DOMAIN,       PVT_PPI_USERNAME,      PVT_PAI_URI,
	PVT_BFLAGS,           PVT_HEXBFLAGS,         PVT_SFLAGS,
	PVT_HEXSFLAGS,        PVT_ERR_CLASS,         PVT_ERR_LEVEL,
	PVT_ERR_INFO,         PVT_ERR_RCODE,         PVT_ERR_RREASON,
	PVT_SCRIPTVAR,        PVT_PROTO,             PVT_AUTH_USERNAME_WHOLE,
	PVT_AUTH_DURI,        PVT_DIV_REASON,        PVT_DIV_PRIVACY,
	PVT_AUTH_DOMAIN,      PVT_AUTH_NONCE,        PVT_AUTH_RESPONSE,
	PVT_TIME,             PVT_PATH,              PVT_ARGV,
	PVT_HDRCNT,           PVT_AUTH_NONCE_COUNT,  PVT_AUTH_QOP,
	PVT_AUTH_ALGORITHM,   PVT_AUTH_OPAQUE,       PVT_AUTH_CNONCE,
	PVT_RU_Q,             PVT_ROUTE_PARAM,       PVT_ROUTE_TYPE,
	PVT_LINE_NUMBER,      PVT_CFG_FILE_NAME,     PVT_LOG_LEVEL,
	PVT_XLOG_LEVEL,       PVT_AF,                PVT_HDR_NAME,
	PVT_SOCKET_IN,        PVT_SOCKET_OUT,        PVT_BRANCH_FLAG,
	PVT_MSG_FLAG,
	/* registered by json module */
	PVT_JSON,
	/* registered by xml module */
	PVT_XML,

	PVT_EXTRA /* keep it last */
};

typedef enum _pv_type pv_type_t;
typedef int pv_flags_t;


typedef struct _pv_value
{
	str rs;    /*!< string value */
	int ri;    /*!< integer value */
	int flags; /*!< flags about the type of value */
} pv_value_t, *pv_value_p;

typedef struct _pv_name
{
	int type;             /*!< type of name */
	union {
		struct {
			int type;     /*!< type of int_str name - compatibility with AVPs */
			int_str name; /*!< the value of the name */
		} isname;
		void *dname;      /*!< PV value - dynamic name */
	} u;
} pv_name_t, *pv_name_p;

typedef struct _pv_index
{
	int type; /*!< type of PV index */
	union {
		int ival;   /*!< integer value */
		void *dval; /*!< PV value - dynamic index */
	} u;
} pv_index_t, *pv_index_p;

typedef struct _pv_param
{
	pv_name_t    pvn; /*!< PV name */
	pv_index_t   pvi; /*!< PV index */
	str          pvv; /*!< PV value buffer */
} pv_param_t, *pv_param_p;

typedef int (*pv_getf_t) (struct sip_msg*,  pv_param_t*, pv_value_t*);
typedef int (*pv_setf_t) (struct sip_msg*,  pv_param_t*, int, pv_value_t*);
typedef struct sip_msg* (*pv_contextf_t) (struct sip_msg*);

typedef struct pv_context
{
	str name;
	pv_contextf_t contextf;
	struct pv_context* next;
}pv_context_t;


typedef struct _pv_spec {
	pv_type_t        type;   /*!< type of PV */
	pv_getf_t        getf;   /*!< get PV value function */
	pv_setf_t        setf;   /*!< set PV value function */
	pv_param_t       pvp;    /*!< parameter to be given to get/set functions */
	pv_context_t*    pvc;    /*< get pv context function */
	void            *trans; /*!< transformations */
} pv_spec_t, *pv_spec_p;

typedef int (*pv_parse_name_f)(pv_spec_p sp, str *in);
typedef int (*pv_parse_index_f)(pv_spec_p sp, str *in);
typedef int (*pv_init_param_f)(pv_spec_p sp, int param);

/*! \brief
 * PV spec format:
 * - $class_name
 * - $class_name(inner_name)
 * - $(class_name[index])
 * - $(class_name(inner_name)[index])
 * - $(class_name{transformation})
 * - $(class_name(inner_name){transformation})
 * - $(class_name[index]{transformation})
 * - $(class_name(inner_name)[index]{transformation})
 */
typedef struct _pv_export {
	str name;                      /*!< class name of PV */
	pv_type_t type;                /*!< type of PV */
	pv_getf_t  getf;               /*!< function to get the value */
	pv_setf_t  setf;               /*!< function to set the value */
	pv_parse_name_f parse_name;    /*!< function to parse the inner name */
	pv_parse_index_f parse_index;  /*!< function to parse the index of PV */
	pv_init_param_f init_param;    /*!< function to init the PV spec */
	int iparam;                    /*!< parameter for the init function */
} pv_export_t;

typedef struct _pv_elem
{
	str text;
	pv_spec_t spec;
	struct _pv_elem *next;
} pv_elem_t, *pv_elem_p;

extern int pv_print_buf_size;
int init_pvar_support(void);

char* pv_parse_spec(str *in, pv_spec_p sp);
int pv_get_spec_value(struct sip_msg* msg, pv_spec_p sp, pv_value_t *value);
int pv_print_spec(struct sip_msg* msg, pv_spec_p sp, char *buf, int *len);
int pv_printf(struct sip_msg* msg, pv_elem_p list, char *buf, int *len);
int pv_elem_free_all(pv_elem_p log);

/* always obtain a printable version of the given (pv_value_t *) */
str pv_value_print(pv_value_t *val);
void pv_value_destroy(pv_value_t *val);

void pv_spec_free(pv_spec_t *spec);
int pv_spec_dbg(pv_spec_p sp);
int pv_get_spec_index(struct sip_msg* msg, pv_param_p ip, int *idx, int *flags);
int pv_get_avp_name(struct sip_msg* msg, pv_param_p ip, int *avp_name,
		unsigned short *name_type);
int pv_get_spec_name(struct sip_msg* msg, pv_param_p ip, pv_value_t *name);
int pv_parse_format(str *in, pv_elem_p *el);
int pv_init_iname(pv_spec_p sp, int param);
int pv_printf_s(struct sip_msg* msg, pv_elem_p list, str *s);

int pv_set_value(struct sip_msg* msg, pv_spec_p sp,
		int op, pv_value_t *val);

typedef struct _pvname_list {
	pv_spec_t sname;
	struct _pvname_list *next;
} pvname_list_t, *pvname_list_p;

typedef struct pv_spec_list {
	pv_spec_p spec;
	struct pv_spec_list *next;
} pv_spec_list_t, *pv_spec_list_p;

pvname_list_t* parse_pvname_list(str *in, unsigned int type);

int register_pvars_mod(char *mod_name, pv_export_t *items);
int pv_free_extra_list(void);

/*! \brief PV helper functions */
int pv_parse_index(pv_spec_p sp, str *in);
int pv_parse_avp_name(pv_spec_p sp, str *in);

int pv_get_null(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);

int pv_get_uintval(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res, unsigned int uival);
int pv_get_sintval(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res, int sival);
int pv_get_strval(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res, str *sval);
int pv_get_strintval(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res, str *sval, int ival);
int pv_get_intstrval(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res, int ival, str *sval);

int register_pv_context(char* name, pv_contextf_t get_context);
int pv_contextlist_check(void);

/* command line arguments specified with '-o' */
typedef struct argv {
	str name;
	str value;
	struct argv *next;
} argv_t, *argv_p;

int add_arg_var(char *opt);
int pv_parse_argv_name(pv_spec_p sp, str *in);
int pv_get_argv(struct sip_msg *msg,  pv_param_t *param, pv_value_t *res);
void destroy_argv_list(void);

#endif

