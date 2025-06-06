/**
 * Copyright (C) 2010-2020 OpenSIPS Solutions
 * Copyright (C) 2005-2009 Voice Sistem SRL
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
 * History:
 * --------
 * 2004-10-20 - added header name specifier (ramona)
 * 2005-06-14 - added avp name specifier (ramona)
 * 2005-06-18 - added color printing support via escape sequesnces
 *              contributed by Ingo Flaschberger (daniel)
 * 2005-06-22 - created this file from modules/xlog/pv_lib.c (daniel)
 * 2009-04-28 - $ct and $ct.fields() PVs added (bogdan)
 * 2009-05-02 - $branch() added, $br, $bR, $bf, $bF removed (bogdan)
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>

#include "dprint.h"
#include "mem/mem.h"
#include "mem/shm_mem.h"
#include "ut.h"
#include "trim.h"
#include "dset.h"
#include "action.h"
#include "socket_info.h"
#include "route_struct.h"
#include "usr_avp.h"
#include "errinfo.h"
#include "transformations.h"
#include "script_var.h"
#include "pvar.h"
#include "sdp_ops.h"
#include "flags.h"
#include "xlog.h"

#include "parser/parse_from.h"
#include "parser/parse_uri.h"
#include "parser/parse_hname2.h"
#include "parser/parse_content.h"
#include "parser/parse_refer_to.h"
#include "parser/parse_rpid.h"
#include "parser/parse_diversion.h"
#include "parser/parse_ppi.h"
#include "parser/parse_pai.h"
#include "parser/digest/digest.h"
#include "parser/contact/parse_contact.h"
#include "parser/parse_authenticate.h"
#include "lib/digest_auth/digest_auth.h"

#define is_in_str(p, in) (p<in->s+in->len && *p)

extern int curr_action_line;
extern char *curr_action_file;

typedef struct _pv_extra
{
	pv_export_t pve;
	struct _pv_extra *next;
} pv_extra_t, *pv_extra_p;

pv_extra_p  *_pv_extra_list=0;

static str str_marker = { PV_MARKER_STR, 1 };

/* IMPORTANT : the "const" strings returned by the var functions must
   be read-write (as they may be changed by the script interpreter), so
   we need to allocated as array and not as pointing to RO data segment
   */
static char _str_null_hlp[] = "<null>";
static str str_null         = str_init(_str_null_hlp);

static char _str_empty_hlp[] = "";
static str str_empty         = str_init(_str_empty_hlp);

int _pv_pid = 0;

#define PV_FIELD_DELIM ", "
#define PV_FIELD_DELIM_LEN (sizeof(PV_FIELD_DELIM) - 1)

#define PV_LOCAL_BUF_SIZE	511
static char pv_local_buf[PV_LOCAL_BUF_SIZE+1];

/* pv context list */
pv_context_t* pv_context_lst = NULL;

static pv_context_t* pv_get_context(const str* name);
static pv_context_t* add_pv_context(const str* name, pv_contextf_t get_context);

static int pv_parse_argv_name(pv_spec_p sp, const str *in);
static int pv_get_argv(struct sip_msg *msg,  pv_param_t *param, pv_value_t *res);
static int pv_contextlist_check(void);
/* always obtain a printable version of the given (pv_value_t *) */
static str pv_value_print(const pv_value_t *val);

static int pvc_before_check = 1;

int pv_print_buf_size = 20000;
#define PV_PRINT_BUF_NO   7
str *pv_print_buf;

#define is_pv_print_buf(p) (p >= (char *)pv_print_buf && \
			p <= (char *)pv_print_buf + \
				PV_PRINT_BUF_NO * (sizeof(*pv_print_buf) + pv_print_buf_size))

int init_pvar_support(void)
{
	int i;

	/* check pv context list */
	if (pv_contextlist_check() != 0) {
		LM_ERR("used pv context that was not defined\n");
		return -1;
	}

	pv_print_buf = pkg_malloc(PV_PRINT_BUF_NO * (sizeof(str)
	                               + pv_print_buf_size));
	if (!pv_print_buf) {
		LM_ERR("oom\n");
		return -1;
	}

	for (i = 0; i < PV_PRINT_BUF_NO; i++) {
		pv_print_buf[i].s = (char *)(pv_print_buf + PV_PRINT_BUF_NO)
		                              + i * pv_print_buf_size;
		pv_print_buf[i].len = pv_print_buf_size;
	}

	return 0;
}

/* route param variable */
static int pv_get_param(struct sip_msg *msg,  pv_param_t *ip, pv_value_t *res);
static int pv_parse_param_name(pv_spec_p sp, const str *in);
static int pv_parse_return_value(pv_spec_p sp, const str *in);

/********** helper functions ********/
/**
 * convert unsigned int to pv_value_t
 */
int pv_get_uintval(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res, unsigned int uival)
{
	int l = 0;
	char *ch = NULL;

	if(res==NULL)
		return -1;

	ch = int2str(uival, &l);
	res->rs.s = ch;
	res->rs.len = l;

	res->ri = (int)uival;
	res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;
	return 0;
}

/**
 * convert signed int to pv_value_t
 */
int pv_get_sintval(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res, int sival)
{
	int l = 0;
	char *ch = NULL;

	if(res==NULL)
		return -1;

	ch = sint2str(sival, &l);
	res->rs.s = ch;
	res->rs.len = l;

	res->ri = sival;
	res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;
	return 0;
}

/**
 * convert str to pv_value_t
 */
int pv_get_strval(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res, str *sval)
{
	if(res==NULL)
		return -1;

	res->rs = *sval;
	res->flags = PV_VAL_STR;
	return 0;
}

/**
 * convert str-int to pv_value_t (type is str)
 */
static int pv_get_strintval(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res, str *sval, int ival)
{
	if(res==NULL)
		return -1;

	res->rs = *sval;
	res->ri = ival;
	res->flags = PV_VAL_STR|PV_VAL_INT;
	return 0;
}

/**
 * convert int-str to pv_value_t (type is int)
 */
static int pv_get_intstrval(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res, int ival, str *sval)
{
	if(res==NULL)
		return -1;

	res->rs = *sval;
	res->ri = ival;
	res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;
	return 0;
}

/************************************************************/
static int pv_get_marker(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	return pv_get_strintval(msg, param, res, &str_marker, (int)str_marker.s[0]);
}

int pv_get_null(struct sip_msg *msg, pv_param_t *param, pv_value_t *res)
{
	if(res==NULL)
		return -1;

	res->rs = str_empty;
	res->ri = 0;
	res->flags = PV_VAL_NULL;
	return 0;
}

/************************************************************/
static int pv_get_pid(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	if(_pv_pid == 0)
		_pv_pid = (int)getpid();
	return pv_get_sintval(msg, param, res, _pv_pid);
}


extern int return_code;
static int pv_get_return_code(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	return pv_get_sintval(msg, param, res, return_code);
}

static int pv_get_route(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	static str rn_buf;

	str s;
	int i, idx, idx_flags, len, rlen, has_name, route_stack_size_ctx;

	if (pv_get_spec_index(msg, param, &idx, &idx_flags) != 0) {
		LM_ERR("invalid index\n");
		return -1;
	}

	if (idx_flags == PV_IDX_ALL) {
		get_top_route_type(&s, &has_name);
		if (!has_name)
			goto unnamed_route;

		len = strlen(route_stack[route_stack_start]);
		if (pkg_str_extend(&rn_buf, s.len + 2 + len + 1) != 0) {
			LM_ERR("oom\n");
			return pv_get_null(msg, param, res);
		}

		len = sprintf(rn_buf.s, "%.*s[%s]", s.len, s.s, route_stack[route_stack_start]);
		goto print_remaining;

	unnamed_route:
		if (pkg_str_extend(&rn_buf, s.len + 1) != 0) {
			LM_ERR("oom\n");
			return pv_get_null(msg, param, res);
		}

		len = sprintf(rn_buf.s, "%.*s", s.len, s.s);

	print_remaining:
		s = str_route;

		for (i = route_stack_start+1; i < route_stack_size; i++) {
			if (!route_stack[i]) {
				if (pkg_str_extend(&rn_buf, len + 3 + s.len + 1) != 0) {
					LM_ERR("oom\n");
					return pv_get_null(msg, param, res);
				}

				len += sprintf(rn_buf.s + len, " > %.*s", s.len, s.s);
			} else if (route_stack[i][0] != '!') {
				rlen = strlen(route_stack[i]);

				if (pkg_str_extend(&rn_buf, len + s.len + 5 + rlen + 1) != 0) {
					LM_ERR("oom\n");
					return pv_get_null(msg, param, res);
				}

				len += sprintf(rn_buf.s + len, " > %.*s[%s]",
									s.len, s.s, route_stack[i]);
			} else {
				rlen = strlen(route_stack[i]);

				/* the "!" marker tells us to print that route name as-is */
				if (pkg_str_extend(&rn_buf, len + rlen + 3) != 0) {
					LM_ERR("oom\n");
					return pv_get_null(msg, param, res);
				}

				len += sprintf(rn_buf.s + len, " > %s", route_stack[i] + 1);
			}
		}

		s.s = rn_buf.s;
		s.len = len;
		return pv_get_strval(msg, param, res, &s);
	}

	route_stack_size_ctx = route_stack_size - route_stack_start;

	if (idx < 0)
		idx += route_stack_size_ctx;

	/* index out of bounds -- play nice and return NULL */
	if (idx > route_stack_size_ctx - 1 || idx < 0)
		return pv_get_null(msg, param, res);

	/* reverse the index, since we index the route stack backwards */
	idx = route_stack_size_ctx - idx - 1;

	if (idx == 0) {
		get_top_route_type(&s, &has_name);
		if (!has_name)
			goto out_ok;

	} else {
		s = str_route;
		if (!route_stack[route_stack_start + idx])
			goto out_ok;
	}

	len = strlen(route_stack[route_stack_start + idx]);

	if (route_stack[route_stack_start + idx][0] != '!') {
		if (pkg_str_extend(&rn_buf, s.len + 2 + len + 1) != 0) {
			LM_ERR("oom\n");
			return pv_get_null(msg, param, res);
		}

		s.len = sprintf(rn_buf.s, "%.*s[%s]", s.len, s.s, route_stack[route_stack_start + idx]);
		s.s = rn_buf.s;
	} else {
		/* the "!" marker tells us to print that route name as-is */
		if (pkg_str_extend(&rn_buf, len) != 0) {
			LM_ERR("oom\n");
			return pv_get_null(msg, param, res);
		}

		s.len = sprintf(rn_buf.s, "%s", route_stack[route_stack_start + idx] + 1);
		s.s = rn_buf.s;
	}

out_ok:
	return pv_get_strval(msg, param, res, &s);
}


static int pv_get_route_name(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	str rn;
	int idx, idx_flags, route_stack_size_ctx;

	if (pv_get_spec_index(msg, param, &idx, &idx_flags) != 0) {
		LM_ERR("invalid index\n");
		return -1;
	}

	if (idx_flags == PV_IDX_ALL) {
		LM_ERR("unsupported index: [*]\n");
		return -1;
	}

	route_stack_size_ctx = route_stack_size - route_stack_start;

	if (idx < 0)
		idx += route_stack_size_ctx;

	/* index out of bounds -- play nice and return NULL */
	if (idx > route_stack_size_ctx - 1 || idx < 0)
		return pv_get_null(msg, param, res);

	/* reverse the index, since we index the route stack backwards */
	idx = route_stack_size_ctx - idx - 1;

	get_route_name(idx, &rn);
	return pv_get_strval(msg, param, res, &rn);
}


static int pv_get_route_type(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	str rt;
	int idx, idx_flags, route_stack_size_ctx;

	if (pv_get_spec_index(msg, param, &idx, &idx_flags) != 0) {
		LM_ERR("invalid index\n");
		return -1;
	}

	if (idx_flags == PV_IDX_ALL) {
		LM_ERR("unsupported index: [*]\n");
		return -1;
	}

	route_stack_size_ctx = route_stack_size - route_stack_start;

	if (idx < 0)
		idx += route_stack_size_ctx;

	/* index out of bounds -- play nice and return NULL */
	if (idx > route_stack_size_ctx - 1 || idx < 0)
		return pv_get_null(msg, param, res);

	/* reverse the index, since we index the route stack backwards */
	idx = route_stack_size_ctx - idx - 1;

	get_route_type(idx, &rt);
	return pv_get_strval(msg, param, res, &rt);
}


static int pv_get_times(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	if(msg==NULL)
		return -1;

	return pv_get_uintval(msg, param, res, (unsigned int)time(NULL));
}

static int pv_get_timem(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	struct timeval TP;

	if(msg==NULL)
		return -1;

	gettimeofday(&TP, NULL);
	return pv_get_uintval(msg, param, res, (unsigned int)TP.tv_usec);
}

static int pv_get_start_times(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	if(msg==NULL)
		return -1;

	return pv_get_uintval(msg, param, res, (unsigned int)startup_time);
}

static int pv_parse_time_name(pv_spec_p sp, const str *in)
{
	sp->pvp.pvn.type = PV_NAME_INTSTR;
	sp->pvp.pvn.u.isname.type = AVP_NAME_STR;
	sp->pvp.pvn.u.isname.name.s.s = pkg_malloc(in->len + 1);
	if (sp->pvp.pvn.u.isname.name.s.s==NULL) {
		LM_ERR("failed to allocated private mem\n");
		return -1;
	}
	memcpy(sp->pvp.pvn.u.isname.name.s.s, in->s, in->len);
	sp->pvp.pvn.u.isname.name.s.s[in->len] = 0;
	sp->pvp.pvn.u.isname.name.s.len = in->len;
	return 0;
}

static int pv_get_formated_time(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	static char buf[128];
	struct tm ltime;
	time_t t;

	if(msg==NULL)
		return -1;

	time( &t );
	localtime_r(&t, &ltime);
	res->rs.len = strftime( buf, 127, param->pvn.u.isname.name.s.s, &ltime);

	if (res->rs.len<=0)
		return pv_get_null(msg, param, res);

	res->rs.s = buf;
	res->flags = PV_VAL_STR;
	return 0;
}

#define CTIME_BUFFER_NO 5
#define CTIME_BUFFER_SIZE 26

static int pv_get_timef(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	static char ctime_bufs[CTIME_BUFFER_NO][CTIME_BUFFER_SIZE];
	static char *buf;
	static int ctime_buf_no = 0;
	time_t t;
	str s;

	if(msg==NULL)
		return -1;

	t = time(NULL);
	buf = ctime_bufs[ctime_buf_no];
	ctime_buf_no = (ctime_buf_no + 1) % CTIME_BUFFER_NO;
	s.s = ctime_r(&t, buf);
	s.len = strlen(s.s)-1;
	return pv_get_strintval(msg, param, res, &s, (int)t);
}

static int pv_get_msgid(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	if(msg==NULL)
		return -1;
	return pv_get_uintval(msg, param, res, msg->id);
}

static int pv_get_method(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	if(msg==NULL)
		return -1;

	if(msg->first_line.type == SIP_REQUEST)
	{
		return pv_get_strintval(msg, param, res,
				&msg->first_line.u.request.method,
				(int)msg->first_line.u.request.method_value);
	}

	if(msg->cseq==NULL && ((parse_headers(msg, HDR_CSEQ_F, 0)==-1) ||
				(msg->cseq==NULL)))
	{
		LM_ERR("no CSEQ header\n");
		return pv_get_null(msg, param, res);
	}

	return pv_get_strintval(msg, param, res,
			&get_cseq(msg)->method,
			get_cseq(msg)->method_id);
}

static int pv_get_status(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	if(msg==NULL)
		return -1;

	if(msg->first_line.type != SIP_REPLY)
		return pv_get_null(msg, param, res);

	return pv_get_intstrval(msg, param, res,
			(int)msg->first_line.u.reply.statuscode,
			&msg->first_line.u.reply.status);
}

static int pv_get_reason(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	if(msg==NULL)
		return -1;

	if(msg->first_line.type != SIP_REPLY)
		return pv_get_null(msg, param, res);

	return pv_get_strval(msg, param, res, &msg->first_line.u.reply.reason);
}

static int pv_get_ruri(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	if(msg==NULL || res==NULL)
		return -1;

	if(msg->first_line.type == SIP_REPLY)	/* REPLY doesn't have a ruri */
		return pv_get_null(msg, param, res);

	if(msg->parsed_uri_ok==0 /* R-URI not parsed*/ && parse_sip_msg_uri(msg)<0)
	{
		LM_ERR("failed to parse the R-URI\n");
		return pv_get_null(msg, param, res);
	}

	if (msg->new_uri.s!=NULL)
		return pv_get_strval(msg, param, res, &msg->new_uri);
	return pv_get_strval(msg, param, res, &msg->first_line.u.request.uri);
}

static int pv_get_ru_q(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	if(msg==NULL || res==NULL)
		return -1;

	if(msg->first_line.type == SIP_REPLY)
		return pv_get_null(msg, param, res);

	return pv_get_sintval(msg, param, res, get_ruri_q(msg));
}

static int pv_get_ouri(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	if(msg==NULL || res==NULL)
		return -1;

	if(msg->first_line.type == SIP_REPLY)	/* REPLY doesn't have a ruri */
		return pv_get_null(msg, param, res);

	if(msg->parsed_orig_ruri_ok==0
			/* orig R-URI not parsed*/ && parse_orig_ruri(msg)<0)
	{
		LM_ERR("failed to parse the R-URI\n");
		return pv_get_null(msg, param, res);
	}
	return pv_get_strval(msg, param, res, &msg->first_line.u.request.uri);
}

static int pv_get_xuri_attr(struct sip_msg *msg, struct sip_uri *parsed_uri,
		pv_param_t *param, pv_value_t *res)
{
	unsigned short proto;
	str proto_s;

	if(param->pvn.u.isname.name.n==1) /* username */
	{
		if(parsed_uri->user.s==NULL || parsed_uri->user.len<=0)
			return pv_get_null(msg, param, res);
		return pv_get_strval(msg, param, res, &parsed_uri->user);
	} else if(param->pvn.u.isname.name.n==2) /* domain */ {
		if(parsed_uri->host.s==NULL || parsed_uri->host.len<=0)
			return pv_get_null(msg, param, res);
		return pv_get_strval(msg, param, res, &parsed_uri->host);
	} else if(param->pvn.u.isname.name.n==3) /* port */ {
		if(parsed_uri->port.s==NULL)
			return pv_get_uintval(msg, param, res,
				get_uri_port( parsed_uri, &proto));
		return pv_get_strintval(msg, param, res, &parsed_uri->port,
				(int)parsed_uri->port_no);
	} else if(param->pvn.u.isname.name.n==4) /* protocol */ {
		if(parsed_uri->transport_val.s==NULL) {
			get_uri_port(parsed_uri, &proto);
			proto_s.s = protos[proto].name;
			proto_s.len = proto_s.s ? strlen(proto_s.s) : 0;
			return pv_get_strintval(msg, param, res, &proto_s, (int)proto);
		}
		return pv_get_strintval(msg, param, res, &parsed_uri->transport_val,
				(int)parsed_uri->proto);
	}
	LM_ERR("unknown specifier\n");
	return pv_get_null(msg, param, res);
}

static int pv_get_ruri_attr(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	if(msg==NULL)
		return -1;

	if(msg->first_line.type == SIP_REPLY)	/* REPLY doesn't have a ruri */
		return pv_get_null(msg, param, res);

	if(msg->parsed_uri_ok==0 /* R-URI not parsed*/ && parse_sip_msg_uri(msg)<0)
	{
		LM_ERR("failed to parse the R-URI\n");
		return pv_get_null(msg, param, res);
	}
	return pv_get_xuri_attr(msg, &(msg->parsed_uri), param, res);
}

static int pv_get_ouri_attr(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	if(msg==NULL)
		return -1;

	if(msg->first_line.type == SIP_REPLY)	/* REPLY doesn't have a ruri */
		return pv_get_null(msg, param, res);

	if(msg->parsed_orig_ruri_ok==0
			/* orig R-URI not parsed*/ && parse_orig_ruri(msg)<0)
	{
		LM_ERR("failed to parse the R-URI\n");
		return pv_get_null(msg, param, res);
	}
	return pv_get_xuri_attr(msg, &(msg->parsed_orig_ruri), param, res);
}

static int pv_get_path(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	if(msg==NULL)
		return -1;

	if(!msg->path_vec.s)
	{
		return pv_get_null(msg, param, res);
	}
	return pv_get_strval(msg, param, res, &msg->path_vec);
}

#define CT_NAME_S        "name"
#define CT_NAME_LEN      (sizeof(CT_NAME_S)-1)
#define CT_NAME_ID       1
#define CT_URI_S         "uri"
#define CT_URI_LEN       (sizeof(CT_URI_S)-1)
#define CT_URI_ID        2
#define CT_Q_S           "q"
#define CT_Q_LEN         (sizeof(CT_Q_S)-1)
#define CT_Q_ID          3
#define CT_EXPIRES_S     "expires"
#define CT_EXPIRES_LEN   (sizeof(CT_EXPIRES_S)-1)
#define CT_EXPIRES_ID     4
#define CT_METHODS_S     "methods"
#define CT_METHODS_LEN   (sizeof(CT_METHODS_S)-1)
#define CT_METHODS_ID    5
#define CT_RECEIVED_S    "received"
#define CT_RECEIVED_LEN  (sizeof(CT_RECEIVED_S)-1)
#define CT_RECEIVED_ID   6
#define CT_PARAMS_S      "params"
#define CT_PARAMS_LEN    (sizeof(CT_PARAMS_S)-1)
#define CT_PARAMS_ID     7

static int pv_parse_ct_name(pv_spec_p sp, const str *in)
{
	if (sp==NULL)
		return -1;

	sp->pvp.pvn.type = PV_NAME_INTSTR;
	sp->pvp.pvn.u.isname.type = 0;

	if (in==NULL || in->s==NULL || in->len==0) {
		sp->pvp.pvn.u.isname.name.n = 0;
	} else
	if (in->len==CT_NAME_LEN &&
	strncasecmp(in->s, CT_NAME_S, CT_NAME_LEN)==0 ) {
		sp->pvp.pvn.u.isname.name.n = CT_NAME_ID;
	} else
	if (in->len==CT_URI_LEN &&
	strncasecmp(in->s, CT_URI_S, CT_URI_LEN)==0 ) {
		sp->pvp.pvn.u.isname.name.n = CT_URI_ID;
	} else
	if (in->len==CT_Q_LEN &&
	strncasecmp(in->s, CT_Q_S, CT_Q_LEN)==0 ) {
		sp->pvp.pvn.u.isname.name.n = CT_Q_ID;
	} else
	if (in->len==CT_EXPIRES_LEN &&
	strncasecmp(in->s, CT_EXPIRES_S, CT_EXPIRES_LEN)==0 ) {
		sp->pvp.pvn.u.isname.name.n = CT_EXPIRES_ID;
	} else
	if (in->len==CT_METHODS_LEN &&
	strncasecmp(in->s, CT_METHODS_S, CT_METHODS_LEN)==0 ) {
		sp->pvp.pvn.u.isname.name.n = CT_METHODS_ID;
	} else
	if (in->len==CT_RECEIVED_LEN &&
	strncasecmp(in->s, CT_RECEIVED_S, CT_RECEIVED_LEN)==0 ) {
		sp->pvp.pvn.u.isname.name.n = CT_RECEIVED_ID;
	} else
	if (in->len==CT_PARAMS_LEN &&
	strncasecmp(in->s, CT_PARAMS_S, CT_PARAMS_LEN)==0 ) {
		sp->pvp.pvn.u.isname.name.n = CT_PARAMS_ID;
	} else {
		LM_ERR("unsupported CT field <%.*s>\n",in->len,in->s);
		return -1;
	}

	return 0;
}


static inline int get_contact_body_field(pv_value_t *res,struct hdr_field *cth,
										contact_t *ct, pv_name_t *pvn)
{
	param_t *p;

	if (ct==NULL) {
		/* star contact hdr */
		if (pvn->u.isname.name.n==0) {
			res->rs = cth->body;
			res->flags = PV_VAL_STR;
			return 0;
		}
		return pv_get_null(NULL, NULL, res);
	}

	switch (pvn->u.isname.name.n) {
		case 0: /* all body */
			res->rs.s = ct->name.s?ct->name.s:ct->uri.s;
			res->rs.len = ct->len;
			break;
		case CT_NAME_ID: /* name only */
			if (ct->name.s==NULL || ct->name.len==0)
				return pv_get_null(NULL, NULL, res);
			res->rs = ct->name;
			break;
		case CT_URI_ID: /* uri only */
			res->rs = ct->uri;
			break;
		case CT_Q_ID: /* Q param only */
			if ( !ct->q || !ct->q->body.s || !ct->q->body.len)
				return pv_get_null(NULL, NULL, res);
			res->rs = ct->q->body;
			break;
		case CT_EXPIRES_ID: /* EXPIRES param only */
			if (!ct->expires||!ct->expires->body.s||!ct->expires->body.len)
				return pv_get_null(NULL, NULL, res);
			res->rs = ct->expires->body;
			break;
		case CT_METHODS_ID: /* METHODS param only */
			if (!ct->methods||!ct->methods->body.s||!ct->methods->body.len)
				return pv_get_null(NULL, NULL, res);
			res->rs = ct->methods->body;
			break;
		case CT_RECEIVED_ID: /* RECEIVED param only */
			if(!ct->received||!ct->received->body.s||!ct->received->body.len)
				return pv_get_null(NULL, NULL, res);
			res->rs = ct->received->body;
			break;
		case CT_PARAMS_ID: /* all param */
			if (!ct->params)
				return pv_get_null(NULL, NULL, res);
			res->rs.s = ct->params->name.s;
			for( p=ct->params ; p->next ; p=p->next);
			res->rs.len = p->name.s + p->len - res->rs.s;
			break;
		default:
			LM_CRIT("BUG - unsupported ID %d\n",pvn->u.isname.type);
			return pv_get_null(NULL, NULL, res);
	}

	res->flags = PV_VAL_STR;
	return 0;
}


static int pv_get_contact_body(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	struct hdr_field *ct_h;
	contact_body_t *ct_b;
	contact_t *ct;
	int idx;
	int idxf;
	char *p;

	if(msg==NULL)
		return -1;

	/* get all CONTACT headers */
	if(parse_headers(msg, HDR_EOH_F, 0)==-1 || msg->contact==NULL ||
	!msg->contact->body.s || msg->contact->body.len<=0)
	{
		LM_DBG("no contact header!\n");
		return pv_get_null(msg, param, res);
	}

	ct_h = msg->contact;
	if (parse_contact( ct_h )!=0) {
		LM_ERR("failed to parse contact hdr\n");
		return -1;
	}
	ct_b = (contact_body_t*)ct_h->parsed;
	if (ct_b==NULL)
		return pv_get_null(msg, param, res);
	ct = ct_b->contacts;

	/* get the index */
	if(pv_get_spec_index(msg, param, &idx, &idxf)!=0) {
		LM_ERR("invalid index\n");
		return -1;
	}

	if( idxf!=PV_IDX_ALL && idx==0) {
		/* no index specified -> return the first contact body */
		return get_contact_body_field( res , ct_h, ct, &param->pvn);
	}

	if(idxf==PV_IDX_ALL) {
		/* return all contact bodies */
		p = pv_local_buf;
		do {
			if(p!=pv_local_buf) {
				if (p-pv_local_buf+PV_FIELD_DELIM_LEN+1>PV_LOCAL_BUF_SIZE){
					LM_ERR("local buffer length exceeded\n");
					return pv_get_null(msg, param, res);
				}
				memcpy(p, PV_FIELD_DELIM, PV_FIELD_DELIM_LEN);
				p += PV_FIELD_DELIM_LEN;
			}

			get_contact_body_field( res , ct_h, ct, &param->pvn);
			if (p-pv_local_buf+res->rs.len+1>PV_LOCAL_BUF_SIZE) {
				LM_ERR("local buffer length exceeded!\n");
				return pv_get_null(msg, param, res);
			}
			memcpy(p, res->rs.s, res->rs.len);
			p += res->rs.len;

			ct = ct?ct->next:NULL;
			while (ct==NULL && ct_h!=NULL) {
				ct_h = ct_h->sibling;
				if (ct_h) {
					if (parse_contact( ct_h )!=0) {
						LM_ERR("failed to parse contact hdr\n");
						return -1;
					}
					ct_b = (contact_body_t*)ct_h->parsed;
					ct = ct_b->contacts;
				}
			}
		} while (ct_h);

		res->rs.s = pv_local_buf;
		res->rs.len = p - pv_local_buf;
		res->flags = PV_VAL_STR;
		return 0;
	}

	/* numerical index */
	if (idx<0) {
		/* index from the end */
		idxf=0;
		while(ct_h) {
			idxf++;
			ct = ct?ct->next:NULL;
			while (ct==NULL && ct_h!=NULL) {
				ct_h = ct_h->sibling;
				if (ct_h) {
					if (parse_contact( ct_h)!=0) {
						LM_ERR("failed to parse contact hdr\n");
						return -1;
					}
					ct_b = (contact_body_t*)ct_h->parsed;
					ct = ct_b->contacts;
				}
			}
		}
		if (-idx>idxf)
			return pv_get_null(msg, param, res);

		idx = idxf +idx;
		ct_h = msg->contact;
		ct_b = (contact_body_t*)ct_h->parsed;
		ct = ct_b->contacts;
	}

	while (idx!=0 && ct_h) {
		/* get to the next contact body */
		idx--;
		ct = ct?ct->next:NULL;
		while (ct==NULL && ct_h!=NULL) {
			ct_h = ct_h->sibling;
			if (ct_h) {
				if (parse_contact( ct_h )!=0) {
					LM_ERR("failed to parse contact hdr\n");
					return -1;
				}
				ct_b = (contact_body_t*)ct_h->parsed;
				ct = ct_b->contacts;
			}
		}
	}

	/* nothing found ?*/
	if (ct==NULL)
		return pv_get_null(msg, param, res);

	/* take the current body */
	return get_contact_body_field( res , ct_h, ct, &param->pvn);
}

extern err_info_t _oser_err_info;
static int pv_get_errinfo_attr(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	if(msg==NULL)
		return -1;

	if(param->pvn.u.isname.name.n==0) /* class */ {
		return pv_get_sintval(msg, param, res, _oser_err_info.eclass);
	} else if(param->pvn.u.isname.name.n==1) /* level */ {
		return pv_get_sintval(msg, param, res, _oser_err_info.level);
	} else if(param->pvn.u.isname.name.n==2) /* info */ {
		if(_oser_err_info.info.s==NULL)
			pv_get_null(msg, param, res);
		return pv_get_strval(msg, param, res, &_oser_err_info.info);
	} else if(param->pvn.u.isname.name.n==3) /* rcode */ {
		return pv_get_sintval(msg, param, res, _oser_err_info.rcode);
	} else if(param->pvn.u.isname.name.n==4) /* rreason */ {
		if(_oser_err_info.rreason.s==NULL)
			pv_get_null(msg, param, res);
		return pv_get_strval(msg, param, res, &_oser_err_info.rreason);
	} else {
		LM_DBG("invalid attribute!\n");
		return pv_get_null(msg, param, res);
	}
}

static int pv_get_xto_attr(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res, struct to_body *xto, int type)
{
	struct sip_uri *uri;
	if(xto==NULL)
		return -1;

	if(param->pvn.u.isname.name.n==1) /* uri */
		return pv_get_strval(msg, param, res, &xto->uri);

	if(param->pvn.u.isname.name.n==4) /* tag */
	{
		if (xto->tag_value.s==NULL || xto->tag_value.len<=0)
		{
		        LM_DBG("no Tag parameter\n");
		        return pv_get_null(msg, param, res);
		}
		return pv_get_strval(msg, param, res, &xto->tag_value);
	}

	if(param->pvn.u.isname.name.n==5) /* display name */
	{
		if(xto->display.s==NULL || xto->display.len<=0)
		{
			LM_DBG("no Display name\n");
			return pv_get_null(msg, param, res);
		}
		return pv_get_strval(msg, param, res, &xto->display);
	}

	if(type==0)
	{
		if((uri=parse_to_uri(msg))==NULL)
		{
			LM_ERR("cannot parse To URI\n");
			return pv_get_null(msg, param, res);
		}
	} else {
		if((uri=parse_from_uri(msg))==NULL)
		{
			LM_ERR("cannot parse From URI\n");
			return pv_get_null(msg, param, res);
		}
	}

	if(param->pvn.u.isname.name.n==2) /* username */
	{
	    if(uri->user.s==NULL || uri->user.len<=0)
		{
		    LM_DBG("no username\n");
			return pv_get_null(msg, param, res);
		}
		return pv_get_strval(msg, param, res, &uri->user);
	} else if(param->pvn.u.isname.name.n==3) /* domain */ {
	    if(uri->host.s==NULL || uri->host.len<=0)
		{
		    LM_DBG("no domain\n");
			return pv_get_null(msg, param, res);
		}
		return pv_get_strval(msg, param, res, &uri->host);
	}

	LM_ERR("unknown specifier\n");
	return pv_get_null(msg, param, res);
}

static int pv_get_to_attr(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	if(msg==NULL)
		return -1;

	if(msg->to==NULL && parse_headers(msg, HDR_TO_F, 0)==-1)
	{
		LM_ERR("cannot parse To header\n");
		return pv_get_null(msg, param, res);
	}
	if(msg->to==NULL || get_to(msg)==NULL) {
		LM_DBG("no To header\n");
		return pv_get_null(msg, param, res);
	}
	return pv_get_xto_attr(msg, param, res, get_to(msg), 0);
}

static int pv_get_from_attr(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	if(msg==NULL)
		return -1;

	if(parse_from_header(msg)<0)
	{
		LM_ERR("cannot parse From header\n");
		return pv_get_null(msg, param, res);
	}

	if(msg->from==NULL || get_from(msg)==NULL) {
		LM_DBG("no From header\n");
		return pv_get_null(msg, param, res);
	}
	return pv_get_xto_attr(msg, param, res, get_from(msg), 1);
}

static int pv_get_cseq(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	if(msg==NULL)
		return -1;

	if(msg->cseq==NULL && ((parse_headers(msg, HDR_CSEQ_F, 0)==-1)
				|| (msg->cseq==NULL)) )
	{
		LM_ERR("cannot parse CSEQ header\n");
		return pv_get_null(msg, param, res);
	}
	return pv_get_strval(msg, param, res, &(get_cseq(msg)->number));
}

static int pv_get_msg_buf(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	str s;
	if(msg==NULL)
		return -1;

	s.s = msg->buf;
	s.len = msg->len;
	return pv_get_strval(msg, param, res, &s);
}

static int pv_get_msg_len(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	if(msg==NULL)
		return -1;

	return pv_get_uintval(msg, param, res, msg->len);
}

static int pv_get_flags(struct sip_msg *msg, pv_param_t *param,
                         pv_value_t *res)
{
	str buf;

	if (!msg)
		return -1;

	buf = bitmask_to_flag_list(FLAG_TYPE_MSG, msg->flags);

	return pv_get_strval(msg, param, res, &buf);
}

static int pv_get_bflags(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	str buf;

	if (!msg)
		return -1;

	buf = bitmask_to_flag_list(FLAG_TYPE_BRANCH, getb0flags(msg));

	return pv_get_strval(msg, param, res, &buf);
}

static int pv_get_callid(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	if(msg==NULL)
		return -1;

	if(msg->callid==NULL && ((parse_headers(msg, HDR_CALLID_F, 0)==-1) ||
				(msg->callid==NULL)) )
	{
		LM_ERR("cannot parse Call-Id header\n");
		return pv_get_null(msg, param, res);
	}

	return pv_get_strval(msg, param, res, &msg->callid->body);
}

static int pv_get_srcip(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	str s;
	if(msg==NULL)
		return -1;

	if ( (s.s=ip_addr2a(&msg->rcv.src_ip))==NULL)
		return pv_get_null(msg, param, res);
	s.len = strlen(s.s);
	return pv_get_strval(msg, param, res, &s);
}

static int pv_get_srcport(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	if(msg==NULL)
		return -1;
	return pv_get_uintval(msg, param, res, msg->rcv.src_port);
}

static int pv_get_useragent(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	if(msg==NULL)
		return -1;
	if(msg->user_agent==NULL && ((parse_headers(msg, HDR_USERAGENT_F, 0)==-1)
			 || (msg->user_agent==NULL)))
	{
		LM_DBG("no User-Agent header\n");
		return pv_get_null(msg, param, res);
	}

	return pv_get_strval(msg, param, res, &msg->user_agent->body);
}

static int pv_get_refer_to(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	if(msg==NULL)
		return -1;

	if(parse_refer_to_header(msg)==-1)
	{
		LM_DBG("no Refer-To header\n");
		return pv_get_null(msg, param, res);
	}

	if(msg->refer_to==NULL || get_refer_to(msg)==NULL)
		return pv_get_null(msg, param, res);

	return pv_get_strval(msg, param, res, &(get_refer_to(msg)->uri));
}

static int pv_get_diversion(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	str *val;
	str name;

	if(msg == NULL)
		return -1;

	if(parse_diversion_header(msg) == -1)
	{
		LM_DBG("no Diversion header\n");
		return pv_get_null(msg, param, res);
	}

	if(msg->diversion == NULL || get_diversion(msg) == NULL)
	{
		LM_DBG("no Diversion header\n");
		return pv_get_null(msg, param, res);
	}

	if(param->pvn.u.isname.name.n == 1)  { /* uri */
		return pv_get_strval(msg, param, res, &(get_diversion(msg)->uri));
	}

	if(param->pvn.u.isname.name.n == 2)  { /* reason param */
	    name.s = "reason";
	    name.len = 6;
	    val = diversion_param(msg, name);
	    if (val) {
			return pv_get_strval(msg, param, res, val);
	    } else {
			return pv_get_null(msg, param, res);
	    }
	}

	if(param->pvn.u.isname.name.n == 3)  { /* privacy param */
	    name.s = "privacy";
	    name.len = 7;
	    val = diversion_param(msg, name);
	    if (val) {
			return pv_get_strval(msg, param, res, val);
	    } else {
			return pv_get_null(msg, param, res);
	    }
	}

	LM_ERR("unknown diversion specifier\n");
	return pv_get_null(msg, param, res);
}

static int pv_get_rpid(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	if(msg==NULL)
		return -1;

	if(parse_rpid_header(msg)==-1)
	{
		LM_DBG("no RPID header\n");
		return pv_get_null(msg, param, res);
	}

	if(msg->rpid==NULL || get_rpid(msg)==NULL)
		return pv_get_null(msg, param, res);

	return pv_get_strval(msg, param, res, &(get_rpid(msg)->uri));
}

static int pv_get_ppi_attr(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
    struct sip_uri *uri;

    if(msg==NULL)
	return -1;

    if(parse_ppi_header(msg) < 0) {
	LM_DBG("no P-Preferred-Identity header\n");
	return pv_get_null(msg, param, res);
    }

    if(msg->ppi == NULL || get_ppi(msg) == NULL) {
	       LM_DBG("no P-Preferred-Identity header\n");
		return pv_get_null(msg, param, res);
    }

    if(param->pvn.u.isname.name.n == 1) { /* uri */
		return pv_get_strval(msg, param, res, &(get_ppi(msg)->uri));
    }

    if(param->pvn.u.isname.name.n==4) { /* display name */
		if(get_ppi(msg)->display.s == NULL ||
				get_ppi(msg)->display.len <= 0) {
		    LM_DBG("no P-Preferred-Identity display name\n");
			return pv_get_null(msg, param, res);
		}
		return pv_get_strval(msg, param, res, &(get_ppi(msg)->display));
    }

    if((uri=parse_ppi_uri(msg))==NULL) {
		LM_ERR("cannot parse P-Preferred-Identity URI\n");
		return pv_get_null(msg, param, res);
    }

    if(param->pvn.u.isname.name.n==2) { /* username */
		if(uri->user.s==NULL || uri->user.len<=0) {
		    LM_DBG("no P-Preferred-Identity username\n");
		    return pv_get_null(msg, param, res);
		}
		return pv_get_strval(msg, param, res, &uri->user);
    } else if(param->pvn.u.isname.name.n==3) { /* domain */
		if(uri->host.s==NULL || uri->host.len<=0) {
			LM_DBG("no P-Preferred-Identity domain\n");
			return pv_get_null(msg, param, res);
		}
		return pv_get_strval(msg, param, res, &uri->host);
    }

	LM_ERR("unknown specifier\n");
	return pv_get_null(msg, param, res);
}

static int pv_get_pai(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
    if(msg==NULL)
		return -1;

    if(parse_pai_header(msg)==-1)
    {
		LM_DBG("no P-Asserted-Identity header\n");
		return pv_get_null(msg, param, res);
    }

    if(msg->pai==NULL || get_pai(msg)==NULL) {
		LM_DBG("no P-Asserted-Identity header\n");
		return pv_get_null(msg, param, res);
    }

	return pv_get_strval(msg, param, res, &(get_pai(msg)->uri));
}

static int pv_get_dset(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	str s;

	if(msg==NULL)
		return -1;

	s.s = print_dset(msg, &s.len);
	if (s.s == NULL)
		return pv_get_null(msg, param, res);
	s.len -= CRLF_LEN;

	return pv_get_strval(msg, param, res, &s);
}


static int pv_get_dsturi(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	if(msg==NULL)
		return -1;

	if (msg->dst_uri.s == NULL) {
		LM_DBG("no destination URI\n");
		return pv_get_null(msg, param, res);
	}

	return pv_get_strval(msg, param, res, &msg->dst_uri);
}

static int pv_get_dsturi_attr(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	struct sip_uri uri;
	unsigned short proto;
	str proto_s;

	if(msg==NULL)
		return -1;

	if (msg->dst_uri.s == NULL) {
		LM_DBG("no destination URI\n");
		return pv_get_null(msg, param, res);
	}

	if(parse_uri(msg->dst_uri.s, msg->dst_uri.len, &uri)!=0)
	{
		LM_ERR("failed to parse dst uri\n");
		return pv_get_null(msg, param, res);
	}

	if(param->pvn.u.isname.name.n==1) /* domain */
	{
		if(uri.host.s==NULL || uri.host.len<=0)
			return pv_get_null(msg, param, res);
		return pv_get_strval(msg, param, res, &uri.host);
	} else if(param->pvn.u.isname.name.n==2) /* port */ {
		if(uri.port.s==NULL)
			return pv_get_uintval(msg, param, res, get_uri_port(&uri, &proto));
		return pv_get_strintval(msg, param, res, &uri.port, (int)uri.port_no);
	} else if(param->pvn.u.isname.name.n==3) /* proto */ {
		if(uri.transport_val.s==NULL) {
			get_uri_port(&uri, &proto);
			proto_s.s = protos[proto].name;
			proto_s.len = proto_s.s ? strlen(proto_s.s) : 0;
			return pv_get_strintval(msg, param, res, &proto_s, (int)proto);
		}
		return pv_get_strintval(msg, param, res, &uri.transport_val,
				(int)uri.proto);
	}

	LM_ERR("invalid specifier\n");
	return pv_get_null(msg, param, res);
}

static int pv_get_content_type(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
#define BUFLEN 1024

	str s;
	int idx=-1;
	int idxf=-1;
	int distance=0;
	char buf[BUFLEN];
	struct sip_msg_body* sbody;
	struct body_part* body_part;
	struct body_part* neg_index[2];

	if(msg==NULL)
		return -1;

	if (pv_get_spec_index(msg, param, &idx, &idxf)!=0) {
		LM_ERR("invalid index\n");
		return -1;
	}

	/* no index or all contenttypes */
	if (param->pvi.type==0 || idxf == PV_IDX_ALL) {
		if(msg->content_type==NULL
				&& ((parse_headers(msg, HDR_CONTENTTYPE_F, 0)==-1)
				 || (msg->content_type==NULL)))
		{
			LM_DBG("no Content-Type header\n");
			return pv_get_null(msg, param, res);
		}

		/* only the main contenttype requested*/
		if (param->pvi.type==0)
			return pv_get_strval(msg, param, res, &msg->content_type->body);
	}

	if ( parse_sip_body(msg)<0 || (sbody=msg->body)==NULL ) {
		LM_DBG("no body found\n");
		return pv_get_null(msg, param, res);
	}

	/* one contenttype request */
	if (idxf != PV_IDX_ALL) {
		if (idx< 0) {
			neg_index[0] = neg_index[1] = &sbody->first;
			/*distance=last_body_postition-searched_body_position*/
			distance -= idx+1;
			while (neg_index[1]->next) {
				if (distance == 0) {
					neg_index[0] = neg_index[0]->next;
				} else {
					distance--;
				}
				neg_index[1] = neg_index[1]->next;
			}

			if (distance>0) {
				LM_ERR("Index too low [%d]\n", idx);
				return pv_get_null(msg, param, res);
			}

			s.s = convert_mime2string_CT(neg_index[0]->mime);
			s.len = strlen(s.s);
		} else {
			body_part = &sbody->first;
			distance = idx;
			while (distance && body_part->next) {
				distance--;
				body_part=body_part->next;
			}

			if (distance > 0) {
				LM_ERR("Index too big [%d]\n", idx);
				return pv_get_null(msg, param, res);
			}

			s.s = convert_mime2string_CT(body_part->mime);
			s.len = strlen(s.s);
		}
	} else {
		/* copy main content type */
		memcpy(buf, msg->content_type->body.s, msg->content_type->body.len);
		buf[msg->content_type->body.len] = ',';
		s.len = msg->content_type->body.len+1;

		/* copy all the other contenttypes */
		body_part = &sbody->first;
		while (body_part) {
			s.s = convert_mime2string_CT(body_part->mime);
			if (s.len + strlen(s.s) >= BUFLEN) {
				LM_CRIT("buffer overflow! Too many contenttypes!\n");
				return pv_get_null(msg, param, res);
			}

			memcpy( buf+s.len, s.s, strlen(s.s));
			s.len += strlen(s.s);

			/* delimiter only if something follows */
			if(body_part->next)
				buf[s.len++] = ',';

			body_part = body_part->next;
		}
		s.s = buf;
	}

	return pv_get_strval(msg, param, res, &s);

#undef BUFLEN
}

static int pv_get_content_length(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	if(msg==NULL)
		return -1;
	if(msg->content_length==NULL
			&& ((parse_headers(msg, HDR_CONTENTLENGTH_F, 0)==-1)
			 || (msg->content_length==NULL)))
	{
		LM_DBG("no Content-Length header\n");
		return pv_get_null(msg, param, res);
	}

	return pv_get_intstrval(msg, param, res,
			(int)(long)msg->content_length->parsed,
			&msg->content_length->body);
}

static int pv_parse_rb_name(pv_spec_p sp, const str *in)
{
	if(in==NULL || in->s==NULL || sp==NULL)
		return -1;

	if (decode_mime_type( in->s, in->s+in->len ,
	(unsigned int *)&sp->pvp.pvn.u.isname.name.n , NULL) == 0) {
		LM_ERR("unsupported mime <%.*s>\n",in->len,in->s);
		return -1;
	}

	sp->pvp.pvn.type = PV_NAME_INTSTR;  /* INT/STR for var name type */
	sp->pvp.pvn.u.isname.type = 0;      /* name is INT */

	return 0;
}

static int pv_get_msg_body(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	str s;
	int idx=-1;
	int idxf=-1;
	int distance=0;
	struct sip_msg_body* sbody;
	struct body_part* body_part;
	struct body_part* neg_index[2];
	unsigned int mime;

	if(msg==NULL)
		return -1;

	if (pv_get_spec_index(msg, param, &idx, &idxf)!=0) {
		LM_ERR("invalid index\n");
		return -1;
	}

	/* any index specified */
	if (param->pvi.type==0 || idxf==PV_IDX_ALL) {
		if (param->pvn.u.isname.name.n==0) {
			/* no name/mime -> requests all bodies */
			if (get_body( msg, &s)!=0 || s.len==0 ) {
				LM_DBG("no message body\n");
				return pv_get_null(msg, param, res);
			}
			goto end;
		} else {
			/* return first part with the requested mime */
			idx = 0;
		}
	}

	if ( parse_sip_body(msg)<0 || (sbody=msg->body)==NULL ) {
		LM_DBG("no body found\n");
		return pv_get_null(msg, param, res);
	}

	mime = param->pvn.u.isname.name.n;
	LM_DBG("--------mime is <%d>, idx=%d\n",mime, idx);

#define first_part_by_mime( _part_start, _part_end, _mime) \
	do {\
		_part_end = _part_start;\
		while( (_part_end) && \
		!(is_body_part_received(_part_end) && ((_mime)==0 || \
		(_mime)==(_part_end)->mime )) ) { \
			_part_end = (_part_end)->next; \
		} \
	}while(0)

	if (idx<0) {
		first_part_by_mime( &sbody->first, neg_index[1], mime );
		neg_index[0] = neg_index[1];

		if (neg_index[0]==NULL) {
			LM_DBG("Body part not found for <%d>\n", mime);
			return pv_get_null(msg, param, res);
		}

		/*distance=last_body_postition-searched_body_position*/
		distance -= idx+1;
		first_part_by_mime(neg_index[1]->next, neg_index[1], mime);
		while (neg_index[1]) {
			if (distance == 0) {
				first_part_by_mime( neg_index[0]->next, neg_index[0], mime );
			} else {
				distance--;
			}
			first_part_by_mime( neg_index[1]->next, neg_index[1], mime );
		}

		if (distance>0) {
			LM_DBG("Index too low [%d]\n", idx);
			return pv_get_null(msg, param, res);
		}

		s.s = neg_index[0]->body.s;
		s.len = neg_index[0]->body.len;
	} else {
		first_part_by_mime( &sbody->first, body_part, mime );
		distance = idx;
		while (distance && body_part ) {
			distance--;
			first_part_by_mime( body_part->next, body_part, mime );
		}

		if (distance>0 || body_part==NULL) {
			LM_DBG("Index too big [%d], body_part=%p\n", idx,body_part);
			return pv_get_null(msg, param, res);
		}

		s.s = body_part->body.s;
		s.len = body_part->body.len;
	}

end:
	return pv_get_strval(msg, param, res, &s);
}


static int pv_get_sdp(struct sip_msg *msg, pv_param_t *_, pv_value_t *res)
{
	pv_param_t param;

	memset(&param, 0, sizeof param);
	param.pvn.u.isname.name.n = ((TYPE_APPLICATION<<16)+SUBTYPE_SDP);

	return pv_get_msg_body(msg, &param, res);
}


static int pv_get_authattr(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	struct hdr_field *hdr;
	str *s;

	if(msg==NULL)
		return -1;

	if ((msg->REQ_METHOD==METHOD_ACK) || (msg->REQ_METHOD==METHOD_CANCEL)) {
		LM_DBG("no [Proxy-]Authorization header\n");
		return pv_get_null(msg, param, res);
	}

	if ((parse_headers(msg, HDR_PROXYAUTH_F|HDR_AUTHORIZATION_F, 0)==-1)
			|| (msg->proxy_auth==0 && msg->authorization==0))
	{
		LM_DBG("no [Proxy-]Authorization header\n");
		return pv_get_null(msg, param, res);
	}

	hdr = (msg->proxy_auth==0)?msg->authorization:msg->proxy_auth;
	if(parse_credentials(hdr)!=0) {
		LM_ERR("failed to parse credentials\n");
		return pv_get_null(msg, param, res);
	}

	switch(param->pvn.u.isname.name.n)
	{
		case 11:
			s = &((auth_body_t*)(hdr->parsed))->digest.nc;
			break;
		case 10:
			s = &((auth_body_t*)(hdr->parsed))->digest.qop.qop_str;
			break;
		case 9:
			s = &((auth_body_t*)(hdr->parsed))->digest.alg.alg_str;
			break;
		case 8:
			s = &((auth_body_t*)(hdr->parsed))->digest.opaque;
			break;
		case 7:
			s = &((auth_body_t*)(hdr->parsed))->digest.cnonce;
			break;
		case 6:
			s = &((auth_body_t*)(hdr->parsed))->digest.response;
			break;
		case 5:
			s = &((auth_body_t*)(hdr->parsed))->digest.nonce;
			break;
		case 4:
			s = &((auth_body_t*)(hdr->parsed))->digest.username.domain;
			break;
		case 3:
			s = &((auth_body_t*)(hdr->parsed))->digest.uri;
			break;
		case 2:
			s = &((auth_body_t*)(hdr->parsed))->digest.realm;
			break;
		case 1:
			s = &((auth_body_t*)(hdr->parsed))->digest.username.user;
			break;
		default:
			s = &((auth_body_t*)(hdr->parsed))->digest.username.whole;
	}

	if (s->len==0)
		return pv_get_null(msg, param, res);
	return pv_get_strval(msg, param, res, s);
}


static int pv_get_cauthattr(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	struct authenticate_body *auth = NULL;
	str *s;

	if(msg==NULL)
		return -1;

	if (msg->first_line.type!=SIP_REPLY) {
		LM_DBG("{Proxy,WWW}-Authenticate header should be only in replies\n");
		return pv_get_null(msg, param, res);
	}
	switch (msg->REPLY_STATUS) {
		case 401:
			parse_www_authenticate_header(msg, NULL, &auth);
			break;
		case 407:
			parse_proxy_authenticate_header(msg, NULL, &auth);
			break;
		default:
			LM_DBG("bad reply code for a challenge!\n");
			break;
	}
	if (!auth) {
		LM_DBG("no {Proxy,WWW}-Authenticate header\n");
		return pv_get_null(msg, param, res);
	}

	switch (param->pvn.u.isname.name.n) {
		case 1:
			s = (str *)print_digest_algorithm(auth->algorithm);
			break;
		case 2:
			s = &auth->realm;
			break;
		case 3:
			s = &auth->nonce;
			break;
		case 4:
			s = &auth->opaque;
			break;
		case 5:
			s = &auth->qop;
			break;
		case 6:
			s = &auth->ik;
			break;
		case 7:
			s = &auth->ck;
			break;
		default:
			LM_BUG("unhandled mode %d\n", param->pvn.u.isname.name.n);
			return pv_get_null(msg, param, res);
	}

	return pv_get_strval(msg, param, res, s);
}


static inline str *cred_user(struct sip_msg *rq)
{
	struct hdr_field* h;
	auth_body_t* cred;

	get_authorized_cred(rq->proxy_auth, &h);
	if (!h) get_authorized_cred(rq->authorization, &h);
	if (!h) return 0;
	cred=(auth_body_t*)(h->parsed);
	if (!cred || !cred->digest.username.user.len)
			return 0;
	return &cred->digest.username.user;
}


static inline str *cred_realm(struct sip_msg *rq)
{
	str* realm;
	struct hdr_field* h;
	auth_body_t* cred;

	get_authorized_cred(rq->proxy_auth, &h);
	if (!h) get_authorized_cred(rq->authorization, &h);
	if (!h) return 0;
	cred=(auth_body_t*)(h->parsed);
	if (!cred) return 0;
	realm = GET_REALM(&cred->digest);
	if (!realm->len || !realm->s) {
		return 0;
	}
	return realm;
}

static int pv_get_acc_username(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	static char buf[MAX_URI_SIZE];
	str* user;
	str* realm;
	struct sip_uri puri;
	struct to_body* from;
	str s;

	/* try to take it from credentials */
	user = cred_user(msg);
	if (user) {
		realm = cred_realm(msg);
		if (realm) {
			s.len = user->len+1+realm->len;
			if (s.len > MAX_URI_SIZE) {
				LM_ERR("uri too long\n");
				return pv_get_null(msg, param, res);
			}
			s.s = buf;
			memcpy(s.s, user->s, user->len);
			(s.s)[user->len] = '@';
			memcpy(s.s+user->len+1, realm->s, realm->len);
			return pv_get_strval(msg, param, res, &s);
		}
		return pv_get_strval(msg, param, res, user);
	}

	/* from from uri */
	if(parse_from_header(msg)<0)
	{
		LM_ERR("cannot parse FROM header\n");
		return pv_get_null(msg, param, res);
	}
	if (msg->from && (from=get_from(msg)) && from->uri.len) {
		if (parse_uri(from->uri.s, from->uri.len, &puri) < 0 ) {
			LM_ERR("bad From URI\n");
			return pv_get_null(msg, param, res);
		}
		s.len = puri.user.len + 1 + puri.host.len;
		if (s.len > MAX_URI_SIZE) {
			LM_ERR("from URI too long\n");
			return pv_get_null(msg, param, res);
		}
		s.s = buf;
		memcpy(s.s, puri.user.s, puri.user.len);
		(s.s)[puri.user.len] = '@';
		memcpy(s.s + puri.user.len + 1, puri.host.s, puri.host.len);
	} else {
		s.len = 0;
		s.s = 0;
	}
	return pv_get_strval(msg, param, res, &s);
}


#define BR_URI_S         "uri"
#define BR_URI_LEN       (sizeof(BR_URI_S)-1)
#define BR_URI_ID        1
#define BR_DURI_S        "duri"
#define BR_DURI_LEN      (sizeof(BR_DURI_S)-1)
#define BR_DURI_ID       2
#define BR_Q_S           "q"
#define BR_Q_LEN         (sizeof(BR_Q_S)-1)
#define BR_Q_ID          3
#define BR_PATH_S        "path"
#define BR_PATH_LEN      (sizeof(BR_PATH_S)-1)
#define BR_PATH_ID       4
#define BR_FLAGS_S       "flags"
#define BR_FLAGS_LEN     (sizeof(BR_FLAGS_S)-1)
#define BR_FLAGS_ID       5
#define BR_SOCKET_S       "socket"
#define BR_SOCKET_LEN     (sizeof(BR_SOCKET_S)-1)
#define BR_SOCKET_ID      6

static int pv_parse_branch_name(pv_spec_p sp, const str *in)
{
	if (sp==NULL || in==NULL || in->s==NULL || in->len==0)
		return -1;

	sp->pvp.pvn.type = PV_NAME_INTSTR;
	sp->pvp.pvn.u.isname.type = 0;

	if (in->len==BR_URI_LEN &&
	strncasecmp(in->s, BR_URI_S, BR_URI_LEN)==0 ) {
		sp->pvp.pvn.u.isname.name.n = BR_URI_ID;
	} else
	if (in->len==BR_DURI_LEN &&
	strncasecmp(in->s, BR_DURI_S, BR_DURI_LEN)==0 ) {
		sp->pvp.pvn.u.isname.name.n = BR_DURI_ID;
	} else
	if (in->len==BR_Q_LEN &&
	strncasecmp(in->s, BR_Q_S, BR_Q_LEN)==0 ) {
		sp->pvp.pvn.u.isname.name.n = BR_Q_ID;
	} else
	if (in->len==BR_PATH_LEN &&
	strncasecmp(in->s, BR_PATH_S, BR_PATH_LEN)==0 ) {
		sp->pvp.pvn.u.isname.name.n = BR_PATH_ID;
	} else
	if (in->len==BR_FLAGS_LEN &&
	strncasecmp(in->s, BR_FLAGS_S, BR_FLAGS_LEN)==0 ) {
		sp->pvp.pvn.u.isname.name.n = BR_FLAGS_ID;
	} else
	if (in->len==BR_SOCKET_LEN &&
	strncasecmp(in->s, BR_SOCKET_S, BR_SOCKET_LEN)==0 ) {
		sp->pvp.pvn.u.isname.name.n = BR_SOCKET_ID;
	} else {
		LM_ERR("unsupported MSG BRANCH field <%.*s>\n",in->len,in->s);
		return -1;
	}

	return 0;
}

static inline int get_branch_field( int idx, int field_id, pv_value_t *res)
{
	struct msg_branch *branch;

	branch = get_msg_branch(idx);
	if (branch==NULL)
		return pv_get_null( NULL, NULL, res);

	/* got a valid branch, return the field */
	switch (field_id) {
		case 0:
		case BR_URI_ID: /* return URI */
			res->rs = branch->uri;
			res->flags = PV_VAL_STR;
			break;
		case BR_Q_ID: /* return Q */
			res->rs.s = q2str(branch->q, (unsigned int*)&res->rs.len);
			res->flags = PV_VAL_STR;
			break;
		case BR_DURI_ID: /* return DURI */
			if ( ZSTR(branch->dst_uri) )
				return pv_get_null(NULL, NULL, res);
			res->rs = branch->dst_uri;
			res->flags = PV_VAL_STR;
			break;
		case BR_PATH_ID: /* return PATH */
			if ( ZSTR(branch->path) )
				return pv_get_null(NULL, NULL, res);
			res->rs = branch->path;
			res->flags = PV_VAL_STR;
			break;
		case BR_FLAGS_ID: /* return FLAGS */
			res->rs = bitmask_to_flag_list(FLAG_TYPE_BRANCH, branch->bflags);
			res->flags = PV_VAL_STR;
			break;
		case BR_SOCKET_ID: /* return SOCKET */
			if ( branch->force_send_socket==NULL )
				return pv_get_null(NULL, NULL, res);
			res->rs = branch->force_send_socket->sock_str;
			res->flags = PV_VAL_STR;
			break;
		default:
			LM_CRIT("BUG - unsupported ID %d\n",field_id);
			return pv_get_null(NULL, NULL, res);
	}
	return 0;
}


static int pv_get_branch_fields(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	int size;
	int idx;
	int idxf;
	char *p;

	if(msg==NULL || res==NULL)
		return -1;

	if ( (size=get_dset_size()) == 0)
		return pv_get_null(msg, param, res);

	/* get the index */
	if(pv_get_spec_index(msg, param, &idx, &idxf)!=0) {
		LM_ERR("invalid index\n");
		return -1;
	}

	if (idxf!=PV_IDX_ALL && idx==0) {
		/* no index specified -> return the first branch */
		return get_branch_field( 0, param->pvn.u.isname.name.n, res);
	}

	if(idxf==PV_IDX_ALL) {
		/* return all branches */
		p = pv_local_buf;
		idx = 0;

		while ( idx<size ) {

			get_branch_field( idx, param->pvn.u.isname.name.n, res);

			if ( pv_local_buf + PV_LOCAL_BUF_SIZE <=
			p + res->rs.len + PV_FIELD_DELIM_LEN ) {
				LM_ERR("local buffer length exceeded\n");
				return pv_get_null(msg, param, res);
			}

			if (idx) {
				memcpy(p, PV_FIELD_DELIM, PV_FIELD_DELIM_LEN);
				p += PV_FIELD_DELIM_LEN;
			}

			memcpy(p, res->rs.s, res->rs.len);
			p += res->rs.len;
			idx++;
		}

		res->rs.s = pv_local_buf;
		res->rs.len = p - pv_local_buf;
		res->flags = PV_VAL_STR;
		return 0;
	}

	/* numerical index */
	if (idx<0) {
		/* index from the end */
		if (-idx > size)
			return pv_get_null(msg, param, res);
		idx = size + idx;
	}

	/* return the request branch info */
	return get_branch_field( idx, param->pvn.u.isname.name.n, res);
}


/******* MSG Branch stuff *******/

static inline int get_msg_branch_field( struct sip_msg *msg, int idx,
												int field_id, pv_value_t *res)
{
	if (idx==0) {
		/* this is the RURI branch */
		switch (field_id) {
			case 0:
			case BR_URI_ID: /* return URI */
				res->rs = *GET_RURI(msg);
				res->flags = PV_VAL_STR;
				break;
			case BR_Q_ID: /* return Q */
				res->rs.s = q2str(msg->ruri_q, (unsigned int*)&res->rs.len);
				res->flags = PV_VAL_STR;
				break;
			case BR_DURI_ID: /* return DURI */
				if ( ZSTR(msg->dst_uri) )
					return pv_get_null(NULL, NULL, res);
				res->rs = msg->dst_uri;
				res->flags = PV_VAL_STR;
				break;
			case BR_PATH_ID: /* return PATH */
				if ( ZSTR(msg->path_vec) )
					return pv_get_null(NULL, NULL, res);
				res->rs = msg->path_vec;
				res->flags = PV_VAL_STR;
				break;
			case BR_FLAGS_ID: /* return FLAGS */
				res->rs = bitmask_to_flag_list(FLAG_TYPE_BRANCH,
					msg->ruri_bflags);
				res->flags = PV_VAL_STR;
				break;
			case BR_SOCKET_ID: /* return SOCKET */
				if ( msg->force_send_socket==NULL )
					return pv_get_null(NULL, NULL, res);
				res->rs = msg->force_send_socket->sock_str;
				res->flags = PV_VAL_STR;
				break;
			default:
				LM_CRIT("BUG - unsupported ID %d\n",field_id);
				return pv_get_null(NULL, NULL, res);
		}
		return 0;
	} else {
		/* translate this to idx into the additional msg branches */
		return get_branch_field( idx-1, field_id, res);
	}
}

static int pv_get_msg_branch_fields(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res, int field)
{
	int size;
	int idx;
	int idxf;
	char *p;

	if(msg==NULL || res==NULL)
		return -1;

	size = get_dset_size() + 1;

	/* get the index */
	if(pv_get_spec_index(msg, param, &idx, &idxf)!=0) {
		LM_ERR("invalid index\n");
		return -1;
	}

	if (idxf==0 && idx==0) {
		/* no index specified -> operate with the last branch */
		return get_msg_branch_field( msg, size-1 , field, res);
	}

	if(idxf==PV_IDX_ALL) {
		/* return all branches */
		p = pv_local_buf;
		idx = 0;

		while ( idx<size ) {

			get_msg_branch_field( msg, idx, field, res);

			if ( pv_local_buf + PV_LOCAL_BUF_SIZE <=
			p + res->rs.len + PV_FIELD_DELIM_LEN ) {
				LM_ERR("local buffer length exceeded\n");
				return pv_get_null(msg, param, res);
			}

			if (idx) {
				memcpy(p, PV_FIELD_DELIM, PV_FIELD_DELIM_LEN);
				p += PV_FIELD_DELIM_LEN;
			}

			memcpy(p, res->rs.s, res->rs.len);
			p += res->rs.len;
			idx++;
		}

		res->rs.s = pv_local_buf;
		res->rs.len = p - pv_local_buf;
		res->flags = PV_VAL_STR;
		return 0;
	}

	/* numerical index */
	if (idx<0) {
		/* index from the end */
		if (-idx > size)
			return pv_get_null(msg, param, res);
		idx = size + idx;
	}

	/* return the request branch info */
	return get_msg_branch_field( msg, idx, field, res);
}

static int pv_get_msg_branch_uri(struct sip_msg *msg, pv_param_t *param,
															pv_value_t *res)
{
	return pv_get_msg_branch_fields( msg, param, res, BR_URI_ID);
}

static int pv_get_msg_branch_duri(struct sip_msg *msg, pv_param_t *param,
															pv_value_t *res)
{
	return pv_get_msg_branch_fields( msg, param, res, BR_DURI_ID);
}

static int pv_get_msg_branch_q(struct sip_msg *msg, pv_param_t *param,
															pv_value_t *res)
{
	return pv_get_msg_branch_fields( msg, param, res, BR_Q_ID);
}

static int pv_get_msg_branch_path(struct sip_msg *msg, pv_param_t *param,
															pv_value_t *res)
{
	return pv_get_msg_branch_fields( msg, param, res, BR_PATH_ID);
}

static int pv_get_msg_branch_flags(struct sip_msg *msg, pv_param_t *param,
															pv_value_t *res)
{
	return pv_get_msg_branch_fields( msg, param, res, BR_FLAGS_ID);
}

static int pv_get_msg_branch_sock(struct sip_msg *msg, pv_param_t *param,
															pv_value_t *res)
{
	return pv_get_msg_branch_fields( msg, param, res, BR_SOCKET_ID);
}

static int pv_get_msg_branch_attr(struct sip_msg *msg,  pv_param_t *param,
															pv_value_t *res)
{
	int idx, idxf;
	int size, n, attr_name;
	unsigned short attr_flags;
	int_str val;

	if(msg==NULL || res==NULL || param==NULL)
		return -1;

	if (pv_get_avp_name(msg, param, &attr_name, &attr_flags)!=0) {
		LM_ALERT("BUG in getting dst AVP name\n");
		return -1;
	}

	/* get the index */
	if (pv_get_spec_index(msg, param, &idx, &idxf)!=0) {
		LM_ERR("invalid index\n");
		return -1;
	}

	if (idxf==PV_IDX_ALL) {
		/* ALL - not supported */
		LM_ERR("ALL index not supported for attrs\n");
		return -1;
	}

	size = get_dset_size() + 1 /* ruri branch*/;
	/* if no branch set, consider the last one */
	if (idxf==0 && idx==0)
		idx = size - 1;

	/* numerical index */
	if (idx<0) {
		/* index from the end */
		if (-idx > size)
			return -1;
		idx = size + idx;
	}

	n = get_msg_branch_attr( idx, attr_name, &attr_flags, &val);
	if ( n<0 || attr_flags&AVP_VAL_NULL)
		return pv_get_null(msg, param, res);

	res->flags = PV_VAL_STR;

	if (attr_flags & AVP_VAL_STR) {
		res->rs = val.s;
	} else {
		res->rs.s = sint2str(val.n, &res->rs.len);
		res->ri = val.n;
		res->flags |= PV_VAL_INT|PV_TYPE_INT;
	}

	return 0;
}

static int pv_get_msg_branch_lastidx(struct sip_msg *msg,  pv_param_t *param,
															pv_value_t *res)
{
	int idx;

	/* the last index is the size -1, counting all branches, as RURI as 
	 * branch 0 followed by the added branches in dset */
	idx = get_dset_size();
	res->flags = PV_VAL_STR;
	res->rs.s = sint2str( idx, &res->rs.len);
	res->ri = idx;
	res->flags |= PV_VAL_INT|PV_TYPE_INT;
	return 0;
}


/******** LISTENING SOCKETS related vars & functions **********/

#define SOCK_IP_S             "ip"
#define SOCK_IP_LEN           (sizeof(SOCK_IP_S)-1)
#define SOCK_IP_ID            1
#define SOCK_PORT_S           "port"
#define SOCK_PORT_LEN         (sizeof(SOCK_PORT_S)-1)
#define SOCK_PORT_ID          2
#define SOCK_PROTO_S          "proto"
#define SOCK_PROTO_LEN        (sizeof(SOCK_PROTO_S)-1)
#define SOCK_PROTO_ID         3
#define SOCK_ADV_IP_S         "advertised_ip"
#define SOCK_ADV_IP_LEN       (sizeof(SOCK_ADV_IP_S)-1)
#define SOCK_ADV_IP_ID        4
#define SOCK_ADV_PORT_S       "advertised_port"
#define SOCK_ADV_PORT_LEN     (sizeof(SOCK_ADV_PORT_S)-1)
#define SOCK_ADV_PORT_ID      5
#define SOCK_TAG_S            "tag"
#define SOCK_TAG_LEN          (sizeof(SOCK_TAG_S)-1)
#define SOCK_TAG_ID           6
#define SOCK_ANYCAST_S        "anycast"
#define SOCK_ANYCAST_LEN      (sizeof(SOCK_ANYCAST_S)-1)
#define SOCK_ANYCAST_ID       7
#define SOCK_AF_S             "af"
#define SOCK_AF_LEN           (sizeof(SOCK_AF_S)-1)
#define SOCK_AF_ID            8
#define SOCK_FORCED_S         "forced"
#define SOCK_FORCED_LEN       (sizeof(SOCK_FORCED_S)-1)
#define SOCK_FORCED_ID        9

static int pv_parse_socket_name(pv_spec_p sp, const str *in)
{
	if (sp==NULL || in==NULL || in->s==NULL || in->len==0)
		return -1;

	sp->pvp.pvn.type = PV_NAME_INTSTR;
	sp->pvp.pvn.u.isname.type = 0;

	if (in->len==SOCK_IP_LEN &&
	strncasecmp(in->s, SOCK_IP_S, SOCK_IP_LEN)==0 ) {
		sp->pvp.pvn.u.isname.name.n = SOCK_IP_ID;
	} else
	if (in->len==SOCK_PORT_LEN &&
	strncasecmp(in->s, SOCK_PORT_S, SOCK_PORT_LEN)==0 ) {
		sp->pvp.pvn.u.isname.name.n = SOCK_PORT_ID;
	} else
	if (in->len==SOCK_PROTO_LEN &&
	strncasecmp(in->s, SOCK_PROTO_S, SOCK_PROTO_LEN)==0 ) {
		sp->pvp.pvn.u.isname.name.n = SOCK_PROTO_ID;
	} else
	if (in->len==SOCK_ADV_IP_LEN &&
	strncasecmp(in->s, SOCK_ADV_IP_S, SOCK_ADV_IP_LEN)==0 ) {
		sp->pvp.pvn.u.isname.name.n = SOCK_ADV_IP_ID;
	} else
	if (in->len==SOCK_ADV_PORT_LEN &&
	strncasecmp(in->s, SOCK_ADV_PORT_S, SOCK_ADV_PORT_LEN)==0 ) {
		sp->pvp.pvn.u.isname.name.n = SOCK_ADV_PORT_ID;
	} else
	if (in->len==SOCK_TAG_LEN &&
	strncasecmp(in->s, SOCK_TAG_S, SOCK_TAG_LEN)==0 ) {
		sp->pvp.pvn.u.isname.name.n = SOCK_TAG_ID;
	} else
	if (in->len==SOCK_ANYCAST_LEN &&
	strncasecmp(in->s, SOCK_ANYCAST_S, SOCK_ANYCAST_LEN)==0 ) {
		sp->pvp.pvn.u.isname.name.n = SOCK_ANYCAST_ID;
	} else
	if (in->len==SOCK_AF_LEN &&
	strncasecmp(in->s, SOCK_AF_S, SOCK_AF_LEN)==0 ) {
		sp->pvp.pvn.u.isname.name.n = SOCK_AF_ID;
	} else {
		LM_ERR("unsupported SOCKET_IN/OUT field <%.*s>\n",in->len,in->s);
		return -1;
	}

	return 0;
}

static int pv_parse_socket_out_name(pv_spec_p sp, const str *in)
{
	if (sp==NULL || in==NULL || in->s==NULL || in->len==0)
		return -1;

	sp->pvp.pvn.type = PV_NAME_INTSTR;
	sp->pvp.pvn.u.isname.type = 0;

	if (in->len==SOCK_FORCED_LEN &&
	strncasecmp(in->s, SOCK_FORCED_S, SOCK_FORCED_LEN)==0 ) {
		sp->pvp.pvn.u.isname.name.n = SOCK_FORCED_ID;
		return 0;
	} else {
		return pv_parse_socket_name(sp, in);
	}
}


static inline int get_socket_field( const struct socket_info *si,
											pv_name_t *pvn, pv_value_t *res)
{
	if (si==NULL)
		return pv_get_null( NULL, NULL, res);

	/* return the field */
	switch (pvn->u.isname.name.n) {
		case 0: /* return full socket description */
		case SOCK_FORCED_ID: /* return forced socket description */
			res->rs = si->sock_str;
			res->flags = PV_VAL_STR;
			break;
		case SOCK_IP_ID: /* return IP address */
			res->rs = si->address_str;
			res->flags = PV_VAL_STR;
			break;
		case SOCK_PORT_ID: /* return PORT */
			res->rs = si->port_no_str;
			res->ri = si->port_no;
			res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;
			break;
		case SOCK_PROTO_ID: /* return PROTOCOL */
			if ( si->proto>=PROTO_FIRST && si->proto<PROTO_LAST &&
			protos[si->proto].id ) {
				res->rs.s = protos[si->proto].name;
				res->rs.len = strlen(res->rs.s);
				res->flags = PV_VAL_STR;
			} else {
				return pv_get_null( NULL, NULL, res);
			}
			break;
		case SOCK_ADV_IP_ID: /* return advertised IP address */
			if (si->adv_name_str.s) {
				res->rs = si->adv_name_str;
				res->flags = PV_VAL_STR;
			} else {
				return pv_get_null( NULL, NULL, res);
			}
			break;
		case SOCK_ADV_PORT_ID: /* return advertised PORT */
			if (si->adv_port_str.s) {
				res->rs = si->adv_port_str;
				res->ri = si->adv_port;
				res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;
			} else {
				return pv_get_null( NULL, NULL, res);
			}
			break;
		case SOCK_TAG_ID: /* return internal TAG */
			if (si->tag.s) {
				res->rs = si->tag;
				res->flags = PV_VAL_STR;
			} else {
				return pv_get_null( NULL, NULL, res);
			}
			break;
		case SOCK_ANYCAST_ID: /* return ANYCAST */
			if (si->flags&SI_IS_ANYCAST)
				res->ri = 1;
			else
				res->ri = 0;
			res->flags = PV_VAL_INT|PV_TYPE_INT;
			break;
		case SOCK_AF_ID:  /* returns Address Family */
			if (si->address.af == AF_INET) {
				res->rs.s = "INET";
				res->rs.len = 4;
			} else if (si->address.af == AF_INET6) {
				res->rs.s = "INET6";
				res->rs.len = 5;
			} else
				return pv_get_null( NULL, NULL, res);
			res->flags = PV_VAL_STR;
			break;
		default:
			LM_CRIT("BUG - unsupported ID %d\n",pvn->u.isname.name.n);
			return pv_get_null(NULL, NULL, res);
	}
	return 0;
}


static int pv_get_socket_in_fields(struct sip_msg *msg, pv_param_t *param,
															pv_value_t *res)
{

	if(msg==NULL || res==NULL)
		return -1;

	return get_socket_field( msg->rcv.bind_address, &param->pvn, res);
}


static int pv_get_socket_out_fields(struct sip_msg *msg, pv_param_t *param,
															pv_value_t *res)
{
	const struct socket_info *si;

	if(msg==NULL || res==NULL)
		return -1;

	if (param->pvn.u.isname.name.n == SOCK_FORCED_ID && !msg->force_send_socket)
		return pv_get_null(msg, NULL, res);

	si = (msg->force_send_socket) ?
		msg->force_send_socket : msg->rcv.bind_address;

	return get_socket_field( si, &param->pvn, res);
}




/************************************************************/

/**
 *
 */
static int pv_get_avp(struct sip_msg *msg,  pv_param_t *param, pv_value_t *res)
{
	unsigned short name_type;
	int avp_name;
	int_str avp_value;
	struct usr_avp *avp;
	int_str avp_value0;
	struct usr_avp *avp0;
	int idx;
	int idxf;
	char *p;
	int n=0;

	if(msg==NULL || res==NULL || param==NULL)
		return -1;

	/* get the name */
	if(pv_get_avp_name(msg, param, &avp_name, &name_type)!=0)
	{
		LM_ERR("invalid name\n");
		return -1;
	}
	/* get the index */
	if(pv_get_spec_index(msg, param, &idx, &idxf)!=0)
	{
		LM_ERR("invalid index\n");
		return -1;
	}
	if (idxf==PV_IDX_APPEND)
		return pv_get_null(msg, param, res);

	if ((avp=search_first_avp(name_type, avp_name, &avp_value, 0))==0)
		return pv_get_null(msg, param, res);
	res->flags = PV_VAL_STR;

	if (idxf!=PV_IDX_ALL && idx==0)
	{
		if(avp->flags & AVP_VAL_STR) {
			res->rs = avp_value.s;
		} else if(avp->flags & AVP_VAL_NULL) {
			res->flags |= PV_VAL_NULL;
		} else {
			res->rs.s = sint2str(avp_value.n, &res->rs.len);
			res->ri = avp_value.n;
			res->flags |= PV_VAL_INT|PV_TYPE_INT;
		}
		return 0;
	}

	/* print the entire AVP array */
	if(idxf==PV_IDX_ALL)
	{
		p = pv_local_buf;

		/* separately handle the first AVP */
		if(avp->flags & AVP_VAL_STR) {
			res->rs = avp_value.s;
		} else if(avp->flags & AVP_VAL_NULL) {
			memset(&res->rs, 0, sizeof res->rs);
		} else {
			res->rs.s = sint2str(avp_value.n, &res->rs.len);
		}

		if(p-pv_local_buf+res->rs.len+1>PV_LOCAL_BUF_SIZE)
		{
			LM_ERR("local buffer length exceeded!\n");
			return pv_get_null(msg, param, res);
		}
		memcpy(p, res->rs.s, res->rs.len);
		p += res->rs.len;

		/* print subsequent AVPs as [DELIM AVP]* */
		while ((avp = search_first_avp(name_type, avp_name, &avp_value, avp)))
		{
			if(avp->flags & AVP_VAL_STR) {
				res->rs = avp_value.s;
			} else if(avp->flags & AVP_VAL_NULL) {
				memset(&res->rs, 0, sizeof res->rs);
			} else {
				res->rs.s = sint2str(avp_value.n, &res->rs.len);
			}

			if(p-pv_local_buf+PV_FIELD_DELIM_LEN+1>PV_LOCAL_BUF_SIZE)
			{
				LM_ERR("local buffer length exceeded\n");
				return pv_get_null(msg, param, res);
			}
			memcpy(p, PV_FIELD_DELIM, PV_FIELD_DELIM_LEN);
			p += PV_FIELD_DELIM_LEN;

			if(p-pv_local_buf+res->rs.len+1>PV_LOCAL_BUF_SIZE)
			{
				LM_ERR("local buffer length exceeded!\n");
				return pv_get_null(msg, param, res);
			}
			memcpy(p, res->rs.s, res->rs.len);
			p += res->rs.len;
		}

		*p = 0;
		res->rs.s = pv_local_buf;
		res->rs.len = p - pv_local_buf;
		return 0;
	}

	/* we have a numeric index */
	if(idx<0)
	{
		n = 1;
		avp0 = avp;
		while ((avp0=search_first_avp(name_type, avp_name,
						&avp_value0, avp0))!=0) n++;
		idx = -idx;
		if(idx>n)
		{
			LM_DBG("index out of range\n");
			return pv_get_null(msg, param, res);
		}
		idx = n - idx;
		if(idx==0)
		{
			if(avp->flags & AVP_VAL_STR) {
				res->rs = avp_value.s;
			} else if(avp->flags & AVP_VAL_NULL) {
				res->flags |= PV_VAL_NULL;
			} else {
				res->rs.s = sint2str(avp_value.n, &res->rs.len);
				res->ri = avp_value.n;
				res->flags |= PV_VAL_INT|PV_TYPE_INT;
			}
			return 0;
		}
	}
	n=0;
	while(n<idx
			&& (avp=search_first_avp(name_type, avp_name, &avp_value, avp))!=0)
		n++;

	if(avp!=0)
	{
		if(avp->flags & AVP_VAL_STR) {
			res->rs = avp_value.s;
		} else if(avp->flags & AVP_VAL_NULL) {
			res->flags |= PV_VAL_NULL;
		} else {
			res->rs.s = sint2str(avp_value.n, &res->rs.len);
			res->ri = avp_value.n;
			res->flags |= PV_VAL_INT|PV_TYPE_INT;
		}
		return 0;
	}

	LM_DBG("index out of range\n");
	return pv_get_null(msg, param, res);
}


static int pv_resolve_hdr_name(const str *in, pv_value_t *tv)
{
	struct hdr_field hdr;
	str s;
	if(in->len>=PV_LOCAL_BUF_SIZE-1)
	{
		LM_ERR("name too long\n");
		return -1;
	}
	memcpy(pv_local_buf, in->s, in->len);
	pv_local_buf[in->len] = ':';
	s.s = pv_local_buf;
	s.len = in->len+1;

	if (parse_hname2(s.s, s.s + ((s.len<4)?4:s.len), &hdr)==0)
	{
		LM_ERR("error parsing header name [%.*s]\n", s.len, s.s);
		return -1;
	}
	if (hdr.type!=HDR_OTHER_T && hdr.type!=HDR_ERROR_T)
	{
		LM_DBG("using hdr type (%d) instead of <%.*s>\n",
			hdr.type, in->len, in->s);
		tv->flags = 0;
		tv->ri = hdr.type;
	} else {
		tv->flags = PV_VAL_STR;
		tv->rs = *in;
	}
	return 0;
}

static int pv_get_hdr_prolog(struct sip_msg *msg,  pv_param_t *param, pv_value_t *res, pv_value_t* tv)
{
	if(msg==NULL || res==NULL || param==NULL)
		return -1;

	/* get the name */
	if(param->pvn.type == PV_NAME_PVAR)
	{
		if(pv_get_spec_name(msg, param, tv)!=0 || (!(tv->flags&PV_VAL_STR)))
		{
			LM_ERR("invalid name\n");
			return -1;
		}
		if (pv_resolve_hdr_name(&tv->rs, tv) < 0)
			return -1;
	} else {
		if(param->pvn.u.isname.type == AVP_NAME_STR)
		{
			tv->flags = PV_VAL_STR;
			tv->rs = param->pvn.u.isname.name.s;
		} else {
			tv->flags = 0;
			tv->ri = param->pvn.u.isname.name.n;
		}
	}
	/* we need to be sure we have parsed all headers */
	if(parse_headers(msg, HDR_EOH_F, 0)<0)
	{
		LM_ERR("error parsing headers\n");
		return pv_get_null(msg, param, res);
	}
	return 1;
}

static int pv_get_hdrcnt(struct sip_msg *msg,  pv_param_t *param, pv_value_t *res)
{
	pv_value_t tv;
	struct hdr_field *hf;
	unsigned int n;
	int ret;

	if ( (ret=pv_get_hdr_prolog(msg,  param, res, &tv)) <= 0 )
	    	return ret;

	n = 0;
	if (tv.flags==0) {
		/* it is a known header -> use type to find it */
		for (hf=msg->headers; hf; hf=hf->next) {
			if (tv.ri==hf->type)
			        ++n;
		}
	} else {
		/* it is an un-known header -> use name to find it */
		for (hf=msg->headers; hf; hf=hf->next) {
			if (hf->type==HDR_OTHER_T && hf->name.len==tv.rs.len
			&& strncasecmp(hf->name.s, tv.rs.s, hf->name.len)==0)
				++n;
		}
	}
	return pv_get_uintval(msg, param, res, n);
}

static int pv_get_hdr(struct sip_msg *msg,  pv_param_t *param, pv_value_t *res)
{
	int idx;
	int idxf;
	pv_value_t tv;
	struct hdr_field *hf;
	struct hdr_field *hf0;
	char *p;
	int n;
	int ret;

	if ( (ret=pv_get_hdr_prolog(msg,  param, res, &tv)) <= 0 )
	    	return ret;

	if (tv.flags==0) {
		/* it is a known header -> use type to find it */
		for (hf=msg->headers; hf; hf=hf->next) {
			if (tv.ri==hf->type)
				break;
		}
	} else {
		/* it is an un-known header -> use name to find it */
		for (hf=msg->headers; hf; hf=hf->next) {
			if (hf->type==HDR_OTHER_T && hf->name.len==tv.rs.len
			&& strncasecmp(hf->name.s, tv.rs.s, hf->name.len)==0)
				break;
		}
	}

	if(hf==NULL)
		return pv_get_null(msg, param, res);
	/* get the index */
	if(pv_get_spec_index(msg, param, &idx, &idxf)!=0)
	{
		LM_ERR("invalid index\n");
		return -1;
	}

	/* get the value */
	res->flags = PV_VAL_STR;
	if(idxf!=PV_IDX_ALL && idx==0)
	{
		res->rs  = hf->body;
		return 0;
	}
	if(idxf==PV_IDX_ALL)
	{
		p = pv_local_buf;
		do {
			if(p!=pv_local_buf)
			{
				if(p-pv_local_buf+PV_FIELD_DELIM_LEN+1>PV_LOCAL_BUF_SIZE)
				{
					LM_ERR("local buffer length exceeded\n");
					return pv_get_null(msg, param, res);
				}
				memcpy(p, PV_FIELD_DELIM, PV_FIELD_DELIM_LEN);
				p += PV_FIELD_DELIM_LEN;
			}

			if(p-pv_local_buf+hf->body.len+1>PV_LOCAL_BUF_SIZE)
			{
				LM_ERR("local buffer length exceeded!\n");
				return pv_get_null(msg, param, res);
			}
			memcpy(p, hf->body.s, hf->body.len);
			p += hf->body.len;
			/* next hf */
			if (tv.flags==0) {
				/* it is a known header -> use type to find it */
				for (hf=hf->next ; hf; hf=hf->next) {
					if (tv.ri==hf->type)
						break;
				}
			} else {
				/* it is an un-known header -> use name to find it */
				for (hf=hf->next ; hf; hf=hf->next) {
					if (hf->type==HDR_OTHER_T && hf->name.len==tv.rs.len
					&& strncasecmp(hf->name.s, tv.rs.s, hf->name.len)==0)
						break;
				}
			}
		} while (hf);
		*p = 0;
		res->rs.s = pv_local_buf;
		res->rs.len = p - pv_local_buf;
		return 0;
	}

	/* we have a numeric index */
	hf0 = 0;
	if(idx<0)
	{
		n = 1;
		/* count headers */
		if (tv.flags==0 ) {
			/* it is a known header -> use type to find it */
			for (hf0=hf->next; hf0; hf0=hf0->next) {
				if (tv.ri==hf0->type)
					n++;
			}
		} else {
			/* it is an un-known header -> use name to find it */
			for (hf0=hf->next; hf0; hf0=hf0->next) {
				if (hf0->type==HDR_OTHER_T && hf0->name.len==tv.rs.len
				&& strncasecmp(hf0->name.s, tv.rs.s, hf0->name.len)==0)
					n++;
			}
		}

		idx = -idx;
		if(idx>n)
		{
			LM_DBG("index out of range\n");
			return pv_get_null(msg, param, res);
		}
		idx = n - idx;
		if(idx==0)
		{
			res->rs  = hf->body;
			return 0;
		}
	}
	n=0;
	while(n<idx)
	{
		if (tv.flags==0) {
			/* it is a known header -> use type to find it */
			for (hf0=hf->next; hf0; hf0=hf0->next) {
				if (tv.ri==hf0->type) {
					n++;
					if(n==idx) break;
				}
			}
		} else {
			/* it is an un-known header -> use name to find it */
			for (hf0=hf->next; hf0; hf0=hf0->next) {
				if (hf0->type==HDR_OTHER_T && hf0->name.len==tv.rs.len
				&& strncasecmp(hf0->name.s, tv.rs.s, hf0->name.len)==0) {
					n++;
					if(n==idx) break;
				}
			}
		}
		if(hf0==NULL)
			break;
	}

	if(hf0!=0)
	{
		res->rs  = hf0->body;
		return 0;
	}

	LM_DBG("index out of range\n");
	return pv_get_null(msg, param, res);

}

static int pv_get_hdr_name(struct sip_msg *msg,  pv_param_t *param, pv_value_t *res)
{
	int idx, idx_f;
	struct hdr_field *hf;
	char *p;
	int n;

	if(msg==NULL || res==NULL || param==NULL)
		return -1;

	/* get the index */
	if (pv_get_spec_index(msg, param, &idx, &idx_f) != 0) {
		LM_ERR("invalid index\n");
		return -1;
	}

	/* make sure we have parsed all the headers */
	if (parse_headers(msg, HDR_EOH_F, 0) <0 ) {
		LM_ERR("error parsing headers\n");
		return pv_get_null(msg, param, res);
	}

	res->flags = PV_VAL_STR;

	if (idx_f == PV_IDX_ALL) {
		/* return all header names, separated by ',' */

		p = pv_local_buf;
		hf = msg->headers;
		do {
			if (p != pv_local_buf) {
				if (p - pv_local_buf + PV_FIELD_DELIM_LEN + 1 > PV_LOCAL_BUF_SIZE) {
					LM_ERR("local buffer length exceeded\n");
					return pv_get_null(msg, param, res);
				}
				memcpy(p, PV_FIELD_DELIM, PV_FIELD_DELIM_LEN);
				p += PV_FIELD_DELIM_LEN;
			}

			if (p - pv_local_buf + hf->name.len + 1 > PV_LOCAL_BUF_SIZE) {
				LM_ERR("local buffer length exceeded!\n");
				return pv_get_null(msg, param, res);
			}
			memcpy(p, hf->name.s, hf->name.len);
			p += hf->name.len;

			hf = hf->next;
		} while (hf);

		*p = 0;
		res->rs.s = pv_local_buf;
		res->rs.len = p - pv_local_buf;
		return 0;
	}

	if (idx < 0) {
		/* negative index, translate it to a positive one */

		n = 0;
		for (hf = msg->headers; hf; hf = hf->next, n++) ;
		idx = -idx;
		if(idx > n) {
			LM_DBG("index [%d] out of range\n", -idx);
			return pv_get_null(msg, param, res);
		}
		idx = n - idx;
	}

	for (hf = msg->headers, n = 0; hf && n != idx; hf = hf->next, n++) ;

	if (!hf) {
		LM_DBG("index [%d] out of range\n", idx);
		return pv_get_null(msg, param, res);
	}

	res->rs = hf->name;
	return 0;
}

static int pv_get_scriptvar(struct sip_msg *msg,  pv_param_t *param,
		pv_value_t *res)
{
	int ival = 0;
	char *sval = NULL;
	script_var_t *sv=NULL;

	if(msg==NULL || res==NULL)
		return -1;

	if(param==NULL || param->pvn.u.dname==0)
		return pv_get_null(msg, param, res);

	sv= (script_var_t*)param->pvn.u.dname;

	if (sv->v.flags&VAR_VAL_NULL)
		return pv_get_null(msg, param, res);

	if(sv->v.flags&VAR_VAL_STR)
	{
		res->rs = sv->v.value.s;
		res->flags = PV_VAL_STR;
	} else {
		sval = sint2str(sv->v.value.n, &ival);

		res->rs.s = sval;
		res->rs.len = ival;

		res->ri = sv->v.value.n;
		res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;
	}
	return 0;
}

/********* end PV get functions *********/

/********* start PV set functions *********/
static int pv_set_avp(struct sip_msg* msg, pv_param_t *param,
		int op, pv_value_t *val)
{
	int avp_name;
	int_str avp_val;
	int flags;
	unsigned short name_type;
	int idx, idxf;

	if(param==NULL)
	{
		LM_ERR("bad parameters\n");
		return -1;
	}

	if(pv_get_avp_name(msg, param, &avp_name, &name_type)!=0)
	{
		LM_ALERT("BUG in getting dst AVP name\n");
		goto error;
	}

	/* get the index */
	if(pv_get_spec_index(msg, param, &idx, &idxf)!=0)
	{
		LM_ERR("invalid index\n");
		return -1;
	}

	if(val == NULL)
	{
		if(op == COLONEQ_T || idxf == PV_IDX_ALL)
			destroy_avps(name_type, avp_name, 1);
		else
		{
			destroy_index_avp(name_type, avp_name, idx);
		}
		return 0;
	}

	if(op == COLONEQ_T || idxf == PV_IDX_ALL)
		destroy_avps(name_type, avp_name, 1);

	flags = name_type;
	if(val->flags&PV_TYPE_INT)
	{
		avp_val.n = val->ri;
	} else {
		avp_val.s = val->rs;
		flags |= AVP_VAL_STR;
	}

	if(idxf == PV_IDX_INT || idxf == PV_IDX_PVAR) /* if the avp is indexed */
	{
		if(replace_avp(flags, avp_name, avp_val, idx)< 0)
		{
			LM_ERR("Failed to replace avp\n");
			goto error;
		}
	}
	else if (idxf == PV_IDX_APPEND) /* add AVP at the end */
	{
		if (add_avp_last(flags, avp_name, avp_val)<0)
		{
			LM_ERR("error - cannot add AVP\n");
			goto error;
		}
	}
	else {
		if (add_avp(flags, avp_name, avp_val)<0)
		{
			LM_ERR("error - cannot add AVP\n");
			goto error;
		}
	}

	return 0;
error:
	return -1;
}

static int pv_set_scriptvar(struct sip_msg* msg, pv_param_t *param,
		int op, pv_value_t *val)
{
	int_str avp_val;
	int flags;

	if(param==NULL)
	{
		LM_ERR("bad parameters\n");
		return -1;
	}

	if(param->pvn.u.dname==0)
	{
		LM_ERR("error - cannot find svar\n");
		goto error;
	}
	if(val == NULL)
	{
		set_var_value((script_var_t*)param->pvn.u.dname, NULL, VAR_VAL_NULL);
		return 0;
	}
	if(val->flags&PV_TYPE_INT)
	{
		avp_val.n = val->ri;
		flags = 0;
	} else {
		avp_val.s = val->rs;
		flags = VAR_VAL_STR;
	}
	if(set_var_value((script_var_t*)param->pvn.u.dname, &avp_val, flags)==NULL)
	{
		LM_ERR("error - cannot set svar [%.*s] \n",
				((script_var_t*)param->pvn.u.dname)->name.len,
				((script_var_t*)param->pvn.u.dname)->name.s);
		goto error;
	}
	return 0;
error:
	return -1;
}

static int pv_set_dsturi(struct sip_msg* msg, pv_param_t *param,
		int op, pv_value_t *val)
{
	if(msg==NULL || param==NULL)
	{
		LM_ERR("bad parameters\n");
		return -1;
	}

	if(val == NULL)
	{
		reset_dst_uri(msg);

		return 1;
	}
	if(!(val->flags&PV_VAL_STR))
	{
		LM_ERR("error - str value required to set dst uri\n");
		goto error;
	}

	if(set_dst_uri(msg, &val->rs)!=0)
		goto error;

	return 0;
error:
	return -1;
}

static int pv_set_ruri(struct sip_msg* msg, pv_param_t *param,
		int op, pv_value_t *val)
{
	if(msg==NULL || param==NULL || val==NULL)
	{
		LM_ERR("bad parameters\n");
		return -1;
	}

	if(!(val->flags&PV_VAL_STR))
	{
		LM_ERR("str value required to set R-URI\n");
		goto error;
	}

	if (set_ruri( msg, &val->rs)!=0) {
		LM_ERR("failed to set RURI\n");
		goto error;
	}

	return 0;
error:
	return -1;
}

static int pv_set_ru_q(struct sip_msg* msg, pv_param_t *param,
		int op, pv_value_t *val)
{
	if(msg==NULL || param==NULL || val==NULL)
	{
		LM_ERR("bad parameters\n");
		return -1;
	}

	if(!(val->flags&PV_VAL_INT))
	{
		LM_ERR("int value required to set r-uri queue value\n");
		return -1;
	}

	if (val->ri > 1000) {
		LM_WARN("queue value too big %d - setting queue to "
				"maximum value (1000)\n", val->ri);
		set_ruri_q(msg, 1000);
	} else
		set_ruri_q(msg, val->ri);

	return 0;
}

static int pv_set_ruri_user(struct sip_msg* msg, pv_param_t *param,
		int op, pv_value_t *val)
{
	str sval;

	if(msg==NULL || param==NULL)
	{
		LM_ERR("bad parameters\n");
		return -1;
	}

	if(val == NULL)
		sval = str_empty;
	else if(!(val->flags&PV_VAL_STR)) {
		LM_ERR("str value required to set R-URI user\n");
		return -1;
	} else
		sval = val->rs;

	if (rewrite_ruri(msg, &sval, 0, RW_RURI_USER) < 0) {
		LM_ERR("Failed to set R-URI user\n");
		return -1;
	}

	return 0;
}

static int pv_set_ruri_host(struct sip_msg* msg, pv_param_t *param,
		int op, pv_value_t *val)
{
	if(msg==NULL || param==NULL || val==NULL)
	{
		LM_ERR("bad parameters\n");
		return -1;
	}

	if(!(val->flags&PV_VAL_STR))
	{
		LM_ERR("str value required to set R-URI hostname\n");
		return -1;
	}

	if (rewrite_ruri(msg, &val->rs, 0, RW_RURI_HOST) < 0) {
		LM_ERR("Failed to set R-URI hostname\n");
		return -1;
	}

	return 0;
}

static int pv_set_dsturi_host(struct sip_msg* msg, pv_param_t *param,
		int op, pv_value_t *val)
{
	if(msg==NULL || param==NULL || val==NULL)
	{
		LM_ERR("bad parameters\n");
		return -1;
	}

	if(!(val->flags&PV_VAL_STR))
	{
		LM_ERR("str value required to set DST-URI hostname\n");
		return -1;
	}

	if (set_dst_host_port(msg, &val->rs, NULL) < 0) {
		LM_ERR("Failed to set DST-URI host\n");
		return -1;
	}

	return 0;
}

static int pv_set_dsturi_port(struct sip_msg* msg, pv_param_t *param,
		int op, pv_value_t *val)
{
	str sval;

	if(msg==NULL || param==NULL)
	{
		LM_ERR("bad parameters\n");
		return -1;
	}

	if(val == NULL)
		sval = str_empty;
	else if(!(val->flags&PV_VAL_STR))
		sval.s = int2str(val->ri, &sval.len);
	else
		sval = val->rs;

	if (set_dst_host_port(msg, NULL, &sval) < 0) {
		LM_ERR("Failed to set DST-URI port\n");
		return -1;
	}

	return 0;
}




static int pv_set_ruri_port(struct sip_msg* msg, pv_param_t *param,
		int op, pv_value_t *val)
{
	str sval;

	if(msg==NULL || param==NULL)
	{
		LM_ERR("bad parameters\n");
		return -1;
	}

	if(val == NULL)
		sval = str_empty;
	else if(!(val->flags&PV_VAL_STR))
		sval.s = int2str(val->ri, &sval.len);
	else
		sval = val->rs;

	if (rewrite_ruri(msg, &sval, 0, RW_RURI_PORT) < 0) {
		LM_ERR("Failed to set R-URI hostname\n");
		return -1;
	}

	return 0;
}


static int pv_set_msg_branch(struct sip_msg* msg, pv_param_t *param,
		int op, pv_value_t *val)
{
	struct msg_branch branch;

	if (msg==NULL || param==NULL) {
		LM_ERR("bad parameters\n");
		return -1;
	}

	if (!val || !(val->flags&PV_VAL_STR) || val->flags&(PV_VAL_NULL) ||
	val->rs.len==0 ) {
		LM_ERR("str value required to create a new branch\n");
		return -1;
	}

	memset( &branch, 0, sizeof branch);
	branch.uri = val->rs;
	branch.q = Q_UNSPECIFIED;
	if (append_msg_branch( &branch )!=1){
		LM_ERR("failed to append new branch\n");
		return -1;
	}

	return 0;
}


static int _int_pv_set_branch_fields(struct sip_msg* msg, pv_param_t *param,
		int op, pv_value_t *val, int field, int has_ruri_branch)
{
	int size, is_ruri_branch = 0;
	int idx;
	int idxf;
	str *s;
	qvalue_t q;
	unsigned int flags;
	const struct socket_info *si;

	if (msg==NULL || param==NULL) {
		LM_ERR("bad parameters\n");
		return -1;
	}

	if (msg->first_line.type == SIP_REPLY)
		return -1;

	/* get the index */
	if (pv_get_spec_index(msg, param, &idx, &idxf)!=0) {
		LM_ERR("invalid index\n");
		return -1;
	}

	if (idxf==PV_IDX_ALL) {
		LM_ERR("SCRIPT BUG - * not allowed in branch assignment\n");
		return -1;
	}

	if (has_ruri_branch) {
		size = get_dset_size() + 1 ;
		/* no branch set, consider the last one */
		if (idxf==0 && idx==0)
			idx = size - 1;
		else
		/* if negative, count from the end */
		if (idx<0)
			idx = size + idx;
		/* now evaluate and ajust the idx to dset only */
		if (idx==0) {
			is_ruri_branch = 1;
		} else {
			/* offset with -1 */
			idx--;
		}
	} else {
		size = get_dset_size();
		/* if negative, count from the end */
		if (idx<0)
			idx = size + idx;
	}

	if (!is_ruri_branch) {
		/* if not RURI branch, it is a msg branch, so check the idx*/
		if (idx<0 || idx>=get_dset_size()) {
			LM_ERR("inexisting branch assignment [%d/%d]\n", size, idx);
			return -1;
		}
	}

	switch (field) {
		case BR_URI_ID: /* set URI */
			if (!val || !(val->flags&PV_VAL_STR) || val->flags&(PV_VAL_NULL) ||
			val->rs.len==0 ) {
				LM_ERR("str value required to set the branch URI\n");
				return -1;
			}
			s = &val->rs;
			return is_ruri_branch ?
				set_ruri( msg, s) :
				update_msg_branch_uri( idx, s);
		case BR_Q_ID: /* set Q */
			if ( val && !(val->flags&PV_VAL_INT) ) {
				LM_ERR("INT value required to set the branch Q\n");
				return -1;
			}
			q = (!val||val->flags&PV_VAL_NULL)? Q_UNSPECIFIED : val->ri;
			if (is_ruri_branch )
				set_ruri_q( msg, q);
			else
				update_msg_branch_q( idx, q);
			return 0;
		case BR_DURI_ID: /* set DURI */
			if ( val && !(val->flags&PV_VAL_STR) ) {
				LM_ERR("STR value required to set the branch DURI\n");
				return -1;
			}
			s = (!val||val->flags&PV_VAL_NULL)? NULL : &val->rs;
			return is_ruri_branch ?
				set_dst_uri( msg, s) :
				update_msg_branch_dst_uri( idx, s);
		case BR_PATH_ID: /* set PATH */
			if ( val && !(val->flags&PV_VAL_STR) ) {
				LM_ERR("STR value required to set the branch PATH\n");
				return -1;
			}
			s = (!val||val->flags&PV_VAL_NULL)? NULL : &val->rs;
			return is_ruri_branch ?
				set_path_vector( msg, s) :
				update_msg_branch_path( idx, s);
		case BR_FLAGS_ID: /* set FLAGS */
			if ( val && !(val->flags&PV_VAL_STR) ) {
				LM_ERR("string value required to set the branch FLAGS\n");
				return -1;
			}
			flags = (!val||val->flags&PV_VAL_NULL)?
				0 : flag_list_to_bitmask(str2const(&val->rs), FLAG_TYPE_BRANCH, FLAG_DELIM, 0);
			if ( is_ruri_branch )
				msg->ruri_bflags = flags;
			else
				update_msg_branch_bflags( idx, flags);
			return 0;
		case BR_SOCKET_ID: /* set SOCKET */
			if ( val && !(val->flags&PV_VAL_STR) ) {
				LM_ERR("STR value required to set the branch SOCKET\n");
				return -1;
			}
			if (!val || val->flags&PV_VAL_NULL) {
				si = NULL;
			} else {
				si = parse_sock_info(&val->rs);
				if (si==NULL)
					return -1;
			}
			if ( is_ruri_branch )
				msg->force_send_socket = si;
			else
				update_msg_branch_socket( idx, si);
			return 0;
		default:
			LM_CRIT("BUG - unsupported ID %d\n", field);
			return -1;
	}
}

static int pv_set_branch_fields(struct sip_msg* msg, pv_param_t *param,
		int op, pv_value_t *val)
{
	/* named branch fields,
	 * so the type is in the name, no RURI branch support*/
	return _int_pv_set_branch_fields( msg, param, op, val,
		param->pvn.u.isname.name.n, 0);
}

static int pv_set_msg_branch_uri(struct sip_msg* msg, pv_param_t *param,
		int op, pv_value_t *val)
{
	return _int_pv_set_branch_fields( msg, param, op, val, BR_URI_ID, 1);
}

static int pv_set_msg_branch_duri(struct sip_msg* msg, pv_param_t *param,
		int op, pv_value_t *val)
{
	return _int_pv_set_branch_fields( msg, param, op, val, BR_DURI_ID, 1);
}

static int pv_set_msg_branch_q(struct sip_msg* msg, pv_param_t *param,
		int op, pv_value_t *val)
{
	return _int_pv_set_branch_fields( msg, param, op, val, BR_Q_ID, 1);
}

static int pv_set_msg_branch_path(struct sip_msg* msg, pv_param_t *param,
		int op, pv_value_t *val)
{
	return _int_pv_set_branch_fields( msg, param, op, val, BR_PATH_ID, 1);
}

static int pv_set_msg_branch_flags(struct sip_msg* msg, pv_param_t *param,
		int op, pv_value_t *val)
{
	return _int_pv_set_branch_fields( msg, param, op, val, BR_FLAGS_ID, 1);
}

static int pv_set_msg_branch_sock(struct sip_msg* msg, pv_param_t *param,
		int op, pv_value_t *val)
{
	return _int_pv_set_branch_fields( msg, param, op, val, BR_SOCKET_ID, 1);
}

static int pv_set_msg_branch_attr(struct sip_msg* msg, pv_param_t *param,
		int op, pv_value_t *val)
{
	int idx, idxf;
	int size, n, attr_name;
	unsigned short attr_flags;
	int_str attr_val;

	if (msg==NULL || param==NULL) {
		LM_ERR("bad parameters\n");
		return -1;
	}

	if (msg->first_line.type == SIP_REPLY)
		return -1;

	if(pv_get_avp_name(msg, param, &attr_name, &attr_flags)!=0) {
		LM_ALERT("BUG in getting dst AVP name\n");
		return -1;
	}

	/* get the index */
	if (pv_get_spec_index(msg, param, &idx, &idxf)!=0) {
		LM_ERR("invalid index\n");
		return -1;
	}

	if(idxf==PV_IDX_ALL) {
		LM_ERR("SCRIPT BUG - * not allowed in branch assignment\n");
		return -1;
	}

	size = get_dset_size() + 1 /* ruri branch*/;
	/* if no branch set, consider the last one */
	if (idxf==0 && idx==0)
		idx = size - 1;

	/* numerical index */
	if (idx<0) {
		/* index from the end */
		if (-idx > size)
			return -1;
		idx = size + idx;
	}

	if (!val || val->flags&PV_VAL_NULL) {
		attr_val.n = 0; //useless, makes compiler happy
		attr_flags |= AVP_VAL_NULL;
	} else
	if(val->flags&PV_TYPE_INT) {
		attr_val.n = val->ri;
	} else {
		attr_val.s = val->rs;
		attr_flags |= AVP_VAL_STR;
	}

	n = set_msg_branch_attr(idx, attr_name, attr_flags, attr_val);

	return (n>=0) ? 0 : -1 ;
}


static int pv_set_force_sock(struct sip_msg* msg, pv_param_t *param,
		int op, pv_value_t *val)
{
	const struct socket_info *si;

	if(msg==NULL || param==NULL)
	{
		LM_ERR("bad parameters\n");
		return -1;
	}

	if(val==NULL)
	{
		msg->force_send_socket = NULL;
		return 0;
	}

	if(!(val->flags&PV_VAL_STR) || val->rs.len<=0)
	{
		LM_ERR("str value required to set the force send sock\n");
		goto error;
	}

	si = parse_sock_info(&val->rs);
	if (si!=NULL)
	{
		msg->force_send_socket = si;
	} else {
		LM_WARN("no socket found to match [%.*s]\n",
				val->rs.len, val->rs.s);
	}

	return 0;
error:
	return -1;
}


/********* end PV set functions *********/

static int pv_parse_scriptvar_name(pv_spec_p sp, const str *in)
{
	if(in==NULL || in->s==NULL || sp==NULL)
		return -1;

	sp->pvp.pvn.type = PV_NAME_PVAR;
	sp->pvp.pvn.u.dname = (void*)add_var(in);
	if(sp->pvp.pvn.u.dname==NULL)
	{
		LM_ERR("cannot register var [%.*s]\n", in->len, in->s);
		return -1;
	}
	return 0;
}

static int pv_parse_hdr_name(pv_spec_p sp, const str *in)
{
	char *p;
	pv_spec_p nsp = 0;
	pv_value_t tv;

	if(in==NULL || in->s==NULL || sp==NULL)
		return -1;

	p = in->s;
	if(*p==PV_MARKER)
	{
		nsp = (pv_spec_p)pkg_malloc(sizeof(pv_spec_t));
		if(nsp==NULL)
		{
			LM_ERR("no more memory\n");
			return -1;
		}
		p = pv_parse_spec(in, nsp);
		if(p==NULL)
		{
			LM_ERR("invalid name [%.*s]\n", in->len, in->s);
			pv_spec_free(nsp);
			return -1;
		}
		//LM_ERR("dynamic name [%.*s]\n", in->len, in->s);
		//pv_print_spec(nsp);
		sp->pvp.pvn.type = PV_NAME_PVAR;
		sp->pvp.pvn.u.dname = (void*)nsp;
		return 0;
	}

	if (pv_resolve_hdr_name(in, &tv) < 0)
		return -1;

	sp->pvp.pvn.type = PV_NAME_INTSTR;
	if (!tv.flags)
	{
		LM_DBG("using hdr type (%d) instead of <%.*s>\n",
			tv.ri, in->len, in->s);
		sp->pvp.pvn.u.isname.type = 0;
		sp->pvp.pvn.u.isname.name.n = tv.ri;
	} else {
		sp->pvp.pvn.u.isname.type = AVP_NAME_STR;
		sp->pvp.pvn.u.isname.name.s = *in;
	}
	return 0;
}

int pv_parse_avp_name(pv_spec_p sp, const str *in)
{
	char *p;
	char *s;
	pv_spec_p nsp = 0;

	if(in==NULL || in->s==NULL || sp==NULL)
		return -1;
	p = in->s;
	if(*p==PV_MARKER)
	{
		nsp = (pv_spec_p)pkg_malloc(sizeof(pv_spec_t));
		if(nsp==NULL)
		{
			LM_ERR("no more memory\n");
			return -1;
		}
		s = pv_parse_spec(in, nsp);
		if(s==NULL)
		{
			LM_ERR("invalid name [%.*s]\n", in->len, in->s);
			pv_spec_free(nsp);
			return -1;
		}
		//LM_ERR("dynamic name [%.*s]\n", in->len, in->s);
		//pv_print_spec(nsp);
		sp->pvp.pvn.type = PV_NAME_PVAR;
		sp->pvp.pvn.u.dname = (void*)nsp;
		return 0;
	}
	/*LM_DBG("static name [%.*s]\n", in->len, in->s);*/
	/* always an int type from now */
	sp->pvp.pvn.u.isname.type = 0;
	if(parse_avp_spec(in, &sp->pvp.pvn.u.isname.name.n)!=0)
	{
		LM_ERR("bad avp name [%.*s]\n", in->len, in->s);
		return -1;
	}
	sp->pvp.pvn.type = PV_NAME_INTSTR;
	return 0;
}

static int pv_parse_avp_index(pv_spec_p sp, const str *in)
{
	#define AVP_APPEND_IDX "append"

	if(in==NULL || in->s==NULL || sp==NULL)
		return -1;

	if ( (in->len==(sizeof(AVP_APPEND_IDX)-1)) &&
	strncasecmp(in->s,AVP_APPEND_IDX,in->len)==0) {
		sp->pvp.pvi.type = PV_IDX_APPEND;
		return 0;
	}
	return pv_parse_index(sp,in);
}

int pv_parse_index(pv_spec_p sp, const str *in)
{
	char *p;
	char *s;
	int sign;
	pv_spec_p nsp = 0;

	if(in==NULL || in->s==NULL || sp==NULL)
		return -1;
	p = in->s;
	if(*p==PV_MARKER)
	{
		nsp = (pv_spec_p)pkg_malloc(sizeof(pv_spec_t));
		if(nsp==NULL)
		{
			LM_ERR("no more memory\n");
			return -1;
		}
		memset(nsp, 0, sizeof(pv_spec_t));
		s = pv_parse_spec(in, nsp);
		if(s==NULL)
		{
			LM_ERR("invalid index [%.*s]\n", in->len, in->s);
			pv_spec_free(nsp);
			return -1;
		}
		sp->pvp.pvi.type = PV_IDX_PVAR;
		sp->pvp.pvi.u.dval = (void*)nsp;
		return 0;
	}
	if(*p=='*' && in->len==1)
	{
		sp->pvp.pvi.type = PV_IDX_ALL;
		return 0;
	}
	sign = 1;
	if(*p=='-')
	{
		sign = -1;
		p++;
	}
	sp->pvp.pvi.u.ival = 0;
	while(p<in->s+in->len && *p>='0' && *p<='9')
	{
		sp->pvp.pvi.u.ival = sp->pvp.pvi.u.ival * 10 + *p - '0';
		p++;
	}
	if(p!=in->s+in->len)
	{
		LM_ERR("invalid index [%.*s]\n", in->len, in->s);
		return -1;
	}
	sp->pvp.pvi.u.ival *= sign;
	sp->pvp.pvi.type = PV_IDX_INT;

	return 0;
}

int pv_init_iname(pv_spec_p sp, int param)
{
	if(sp==NULL)
		return -1;
	sp->pvp.pvn.type = PV_NAME_INTSTR;
	sp->pvp.pvn.u.isname.name.n = param;
	return 0;
}

static int pv_get_line_number(struct sip_msg *msg,  pv_param_t *param, pv_value_t *res){
	int l;
	char *ch;

	if (param==NULL) {
		LM_CRIT("BUG - bad parameters\n");
		return -1;
	}

	if(res == NULL) {
		return -1;
	}

	res->ri = curr_action_line;
	ch = int2str( (unsigned long)res->ri, &l);

	res->rs.s = ch;
	res->rs.len = l;

	res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;

	return 0;
}

static int pv_get_cfg_file_name(struct sip_msg *msg,  pv_param_t *param, pv_value_t *res){

	if (param==NULL) {
		LM_CRIT("BUG - bad parameters\n");
		return -1;
	}

	if(res == NULL) {
		return -1;
	}

	res->rs.s = curr_action_file;
	res->rs.len = (res->rs.s)?(strlen(res->rs.s)):(0);

	res->flags = PV_VAL_STR;

	return 0;
}


static int pv_set_log_level(struct sip_msg* msg, pv_param_t *param, int op,
															pv_value_t *val)
{
	if(param==NULL)
	{
		LM_ERR("bad parameters\n");
		return -1;
	}

	if(val==NULL || (val->flags&(PV_VAL_NULL|PV_VAL_NONE))!=0) {
		/* reset the value to default */
		reset_proc_log_level();
	} else {
		if ((val->flags&PV_TYPE_INT)==0) {
			LM_ERR("input for $log_level found not to be an integer\n");
			return -1;
		}
		set_proc_log_level(val->ri);
	}

	return 0;
}

static int pv_get_log_level(struct sip_msg *msg,  pv_param_t *param, pv_value_t *res)
{
	int l;

	if (param==NULL) {
		LM_CRIT("BUG - bad parameters\n");
		return -1;
	}

	if(res == NULL) {
		return -1;
	}

	res->ri = *log_level;
	res->rs.s = sint2str( (long)res->ri, &l);
	res->rs.len = l;

	res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;

	return 0;
}

static int pv_set_xlog_level(struct sip_msg* msg, pv_param_t *param, int op,
															pv_value_t *val)
{
	if(param==NULL)
	{
		LM_ERR("bad parameters\n");
		return -1;
	}

	if(val==NULL || (val->flags&(PV_VAL_NULL|PV_VAL_NONE))!=0) {
		/* reset the value to default */
		reset_xlog_level();
	} else {
		if ((val->flags&PV_TYPE_INT)==0) {
			LM_ERR("input for $xlog_level found not to be an integer\n");
			return -1;
		}
		set_local_xlog_level( val->ri );
	}

	return 0;
}

static int pv_get_xlog_level(struct sip_msg *msg,  pv_param_t *param, pv_value_t *res)
{
	int l;

	if (param==NULL) {
		LM_CRIT("BUG - bad parameters\n");
		return -1;
	}

	if(res == NULL) {
		return -1;
	}

	res->ri = *xlog_level;
	res->rs.s = sint2str( (long)res->ri, &l);
	res->rs.len = l;

	res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;

	return 0;
}

static int pv_get_return_value(struct sip_msg *msg,  pv_param_t *param, pv_value_t *res)
{
	int index;
	pv_value_t tv;

	if (param==NULL) {
		LM_CRIT("BUG - bad parameters\n");
		return -1;
	}

	if(res == NULL)
		return -1;

	if (param->pvn.type == PV_NAME_INTSTR) {
		if (param->pvn.u.isname.type != 0) {
			LM_ERR("route $return variable accepts only integer indexes\n");
			return -1;
		}
		index = param->pvn.u.isname.name.n;
	} else {
		/* pvar -> it might be another $param variable! */
		if(pv_get_spec_value(msg, (pv_spec_p)(param->pvn.u.dname), &tv)!=0) {
			LM_ERR("cannot get spec value\n");
			return -1;
		}

		if(tv.flags&PV_VAL_NULL || tv.flags&PV_VAL_EMPTY) {
			LM_ERR("null or empty name\n");
			return -1;
		}
		if (!(tv.flags&PV_VAL_INT) || str2int(&tv.rs,(unsigned int*)&index) < 0) {
			LM_ERR("invalid index <%.*s>\n", tv.rs.len, tv.rs.s);
			return -1;
		}
	}

	if (script_return_get(res, index) < 0) {
		LM_ERR("could not get return %d\n", index);
		return -1;
	}

	/* "normalize" integer */
	if ((res->flags & PV_VAL_INT) && !(res->flags & PV_VAL_STR)) {
		res->rs.s = int2str(res->ri, &res->rs.len);
		res->flags |= PV_VAL_STR;
	}

	return 0;
}

/************** Boolean consts *****************/

const pv_value_t pv_true = {
	.ri = 1,
	.rs = str_init("true"),
	.flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT,
};


const pv_value_t pv_false = {
	.ri = 0,
	.rs = str_init("false"),
	.flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT,
};


/************** MSG FLAGS function *****************/

static int msg_flag_parse_name(pv_spec_p sp, const str *in)
{
	unsigned int idx;
	if (sp==NULL || in==NULL || in->s==NULL || in->len==0)
		return -1;

	if ( (idx=fixup_flag(FLAG_TYPE_MSG, in))==NAMED_FLAG_ERROR) {
		LM_ERR("failed to fix the flag <%.*s>\n",in->len,in->s);
		return -1;
	}

	sp->pvp.pvn.type = PV_NAME_INTSTR;
	sp->pvp.pvn.u.isname.type = 0;

	sp->pvp.pvn.u.isname.name.n = idx;

	return 0;
}


static int msg_flag_set(struct sip_msg* msg, pv_param_t *param, int op,
															pv_value_t *val)
{
	if(param==NULL) {
		LM_ERR("bad parameters\n");
		return -1;
	}

	if (val==NULL || (val->flags&(PV_VAL_NULL|PV_VAL_NONE))!=0 ||
	(val->flags&PV_TYPE_INT)==0 ) {
		LM_ERR("input for $msg.flag() found not to be an integer\n");
		return -1;
	}

	if (val->ri==0)
		resetflag (msg, (unsigned int)param->pvn.u.isname.name.n);
	else
		setflag( msg, (unsigned int)param->pvn.u.isname.name.n);

	return 0;
}


static int msg_flag_get(struct sip_msg *msg,  pv_param_t *param, pv_value_t *res)
{
	if (param==NULL||res==NULL) {
		LM_CRIT("BUG - bad parameters\n");
		return -1;
	}

	if ( isflagset( msg, (unsigned int)param->pvn.u.isname.name.n)==1 ) {
		*res = pv_true;
	} else {
		*res = pv_false;
	}
	return 0;
}


/************** MSG TYPE function *****************/

static int msg_is_request_get(struct sip_msg *msg, pv_param_t *param, pv_value_t *res)
{
	if (param==NULL||res==NULL) {
		LM_CRIT("BUG - bad parameters\n");
		return -1;
	}

	if ( msg->first_line.type==SIP_REQUEST ) {
		*res = pv_true;
	} else {
		*res = pv_false;
	}
	return 0;
}


static int msg_type_get(struct sip_msg *msg, pv_param_t *param, pv_value_t *res)
{
	if (param==NULL||res==NULL) {
		LM_CRIT("BUG - bad parameters\n");
		return -1;
	}

	if ( msg->first_line.type==SIP_REQUEST ) {
		res->rs.s = "request";
		res->rs.len = 7;
	} else {
		res->rs.s = "reply";
		res->rs.len = 5;
	}

	res->flags = PV_VAL_STR;

	return 0;
}



/************** BRANCH FLAGS function *****************/

static int msg_branch_flag_parse_name(pv_spec_p sp, const str *in)
{
	unsigned int idx;
	if (sp==NULL || in==NULL || in->s==NULL || in->len==0)
		return -1;

	if ( (idx=fixup_flag(FLAG_TYPE_BRANCH, in))==NAMED_FLAG_ERROR) {
		LM_ERR("failed to fix the flag <%.*s>\n",in->len,in->s);
		return -1;
	}

	sp->pvp.pvn.type = PV_NAME_INTSTR;
	sp->pvp.pvn.u.isname.type = 0;

	sp->pvp.pvn.u.isname.name.n = idx;

	return 0;
}


static int msg_branch_flag_set(struct sip_msg* msg, pv_param_t *param, int op,
															pv_value_t *val)
{
	int size;
	int idx;
	int idxf;

	if(param==NULL) {
		LM_ERR("bad parameters\n");
		return -1;
	}

	if (val==NULL || (val->flags&(PV_VAL_NULL|PV_VAL_NONE))!=0 ||
	(val->flags&PV_TYPE_INT)==0 ) {
		LM_ERR("input for $branch.flag() found not to be an integer\n");
		return -1;
	}

	/* get the index */
	if (pv_get_spec_index(msg, param, &idx, &idxf)!=0) {
		LM_ERR("invalid index\n");
		return -1;
	}

	if(idxf==PV_IDX_ALL) {
		LM_ERR("SCRIPT BUG - * not allowed in branch flag assignment\n");
		return -1;
	}

	size = get_dset_size() + 1;

	/* if no idx, work with the last branch */
	if (idxf==0 && idx==0)
		idx = size - 1;

	if (idx<0) {
		idx = size + idx;
	}

	if (idx<0 || idx>=size) {
		LM_DBG("inexisting branch flag assignment [%d/%d]\n", size, idx);
		return -1;
	}

	if (val->ri==0)
		resetbflag (msg, idx, param->pvn.u.isname.name.n);
	else
		setbflag( msg, idx, param->pvn.u.isname.name.n);

	return 0;
}


static int msg_branch_flag_get(struct sip_msg *msg,  pv_param_t *param,
															pv_value_t *res)
{
	int size;
	int idx;
	int idxf;

	if (param==NULL||res==NULL) {
		LM_CRIT("BUG - bad parameters\n");
		return -1;
	}

	/* get the index */
	if (pv_get_spec_index(msg, param, &idx, &idxf)!=0) {
		LM_ERR("invalid index\n");
		return -1;
	}

	if(idxf==PV_IDX_ALL) {
		LM_ERR("SCRIPT BUG - * not allowed in branch flag reading\n");
		return -1;
	}

	size = get_dset_size();

	if (idx<0) {
		idx = size + idx;
	}

	if (idx<0 || idx>=size) {
		LM_DBG("inexisting branch flag reading [%d/%d]\n", size, idx);
		return -1;
	}

	if ( isbflagset( msg, idx, param->pvn.u.isname.name.n)==1 ) {
		*res = pv_true;
	} else {
		*res = pv_false;
	}
	return 0;
}


/********** generic helper functions ***************/

/**
 * the table with core pseudo-variables
 */
#ifndef FUZZ_BUILD
static
#endif
const pv_export_t _pv_names_table[] = {
	{str_const_init("avp"), PVT_AVP, pv_get_avp, pv_set_avp,
		pv_parse_avp_name, pv_parse_avp_index, 0, 0},
	{str_const_init("hdr"), PVT_HDR, pv_get_hdr, 0, pv_parse_hdr_name,
		pv_parse_index, 0, 0},
	{str_const_init("hdr_name"), PVT_HDR_NAME, pv_get_hdr_name, 0, 0,
		pv_parse_index, 0, 0},
	{str_const_init("hdrcnt"), PVT_HDRCNT, pv_get_hdrcnt, 0, pv_parse_hdr_name, 0, 0, 0},
	{str_const_init("var"), PVT_SCRIPTVAR, pv_get_scriptvar,
		pv_set_scriptvar, pv_parse_scriptvar_name, 0, 0, 0},
	{str_const_init("ai"), /* */
		PVT_PAI_URI, pv_get_pai, 0,
		0, 0, 0, 0},
	{str_const_init("au"), /* */
		PVT_AUTH_USERNAME, pv_get_authattr, 0,
		0, 0, pv_init_iname, 1},
	{str_const_init("ar"), /* auth realm */
		PVT_AUTH_REALM, pv_get_authattr, 0,
		0, 0, pv_init_iname, 2},
	{str_const_init("adu"), /* auth digest uri */
		PVT_AUTH_DURI, pv_get_authattr, 0,
		0, 0, pv_init_iname, 3},
	{str_const_init("ad"), /* */
		PVT_AUTH_DOMAIN, pv_get_authattr, 0,
		0, 0, pv_init_iname, 4},
	{str_const_init("an"), /* */
		PVT_AUTH_NONCE, pv_get_authattr, 0,
		0, 0, pv_init_iname, 5},
	{str_const_init("auth.nonce"), /* */
		PVT_AUTH_NONCE, pv_get_authattr, 0,
		0, 0, pv_init_iname, 5},
	{str_const_init("auth.resp"), /* */
		PVT_AUTH_RESPONSE, pv_get_authattr, 0,
		0, 0, pv_init_iname, 6},
	{str_const_init("auth.cnonce"), /* */
		PVT_AUTH_CNONCE, pv_get_authattr, 0,
		0, 0, pv_init_iname, 7},
	{str_const_init("auth.opaque"), /* */
		PVT_AUTH_OPAQUE, pv_get_authattr, 0,
		0, 0, pv_init_iname, 8},
	{str_const_init("auth.alg"), /* */
		PVT_AUTH_ALGORITHM, pv_get_authattr, 0,
		0, 0, pv_init_iname, 9},
	{str_const_init("auth.qop"), /* */
		PVT_AUTH_QOP, pv_get_authattr, 0,
		0, 0, pv_init_iname, 10},
	{str_const_init("auth.nc"), /* */
		PVT_AUTH_NONCE_COUNT, pv_get_authattr, 0,
		0, 0, pv_init_iname, 11},
	{str_const_init("aU"), /* */
		PVT_AUTH_USERNAME_WHOLE, pv_get_authattr, 0,
		0, 0, pv_init_iname, 99},
	{str_const_init("challenge.algorithm"), /* */
		PVT_AUTH_USERNAME, pv_get_cauthattr, 0,
		0, 0, pv_init_iname, 1},
	{str_const_init("challenge.realm"),
		PVT_AUTH_REALM, pv_get_cauthattr, 0,
		0, 0, pv_init_iname, 2},
	{str_const_init("challenge.nonce"),
		PVT_AUTH_DURI, pv_get_cauthattr, 0,
		0, 0, pv_init_iname, 3},
	{str_const_init("challenge.opaque"),
		PVT_AUTH_DOMAIN, pv_get_cauthattr, 0,
		0, 0, pv_init_iname, 4},
	{str_const_init("challenge.qop"),
		PVT_AUTH_NONCE, pv_get_cauthattr, 0,
		0, 0, pv_init_iname, 5},
	{str_const_init("challenge.ik"), /* */
		PVT_AUTH_NONCE, pv_get_cauthattr, 0,
		0, 0, pv_init_iname, 6},
	{str_const_init("challenge.ck"), /* */
		PVT_AUTH_RESPONSE, pv_get_cauthattr, 0,
		0, 0, pv_init_iname, 7},
	{str_const_init("Au"), /* */
		PVT_ACC_USERNAME, pv_get_acc_username, 0,
		0, 0, pv_init_iname, 1},
	{str_const_init("bf"), /* */
		PVT_BFLAGS, pv_get_bflags, 0,
		0, 0, 0, 0},
	{str_const_init("branch"), /* to be obsolete */
		PVT_BRANCH, pv_get_branch_fields, pv_set_msg_branch,
		0, 0, 0, 0},
	{str_const_init("branch"), /* to be obsolete */
		PVT_BRANCH, pv_get_branch_fields, pv_set_branch_fields,
		pv_parse_branch_name, pv_parse_index, 0, 0},
	{str_const_init("branch.flag"), /* to be obsolete  */
		PVT_BRANCH_FLAG, msg_branch_flag_get, msg_branch_flag_set,
		msg_branch_flag_parse_name, pv_parse_index, 0, 0},
	{str_const_init("ci"), /* */
		PVT_CALLID, pv_get_callid, 0,
		0, 0, 0, 0},
	{str_const_init("cl"), /* */
		PVT_CONTENT_LENGTH, pv_get_content_length, 0,
		0, 0, 0, 0},
	{str_const_init("cs"), /* */
		PVT_CSEQ, pv_get_cseq, 0,
		0, 0, 0, 0},
	{str_const_init("ct"), /* */
		PVT_CONTACT, pv_get_contact_body, 0,
		0, pv_parse_index, 0, 0},
	{str_const_init("ct.fields"), /* */
		PVT_CONTACT, pv_get_contact_body, 0,
		pv_parse_ct_name, pv_parse_index, 0, 0},
	{str_const_init("cT"), /* */
		PVT_CONTENT_TYPE, pv_get_content_type, 0,
		0, pv_parse_index, 0, 0},
	{str_const_init("dd"), /* */
		PVT_DSTURI_DOMAIN, pv_get_dsturi_attr, pv_set_dsturi_host,
		0, 0, pv_init_iname, 1},
	{str_const_init("di"), /* */
		PVT_DIVERSION_URI, pv_get_diversion, 0,
		0, 0, pv_init_iname, 1},
	{str_const_init("dir"), /* */
		PVT_DIV_REASON, pv_get_diversion, 0,
		0, 0, pv_init_iname, 2},
	{str_const_init("dip"), /* */
		PVT_DIV_PRIVACY, pv_get_diversion, 0,
		0, 0, pv_init_iname, 3},
	{str_const_init("dp"), /* */
		PVT_DSTURI_PORT, pv_get_dsturi_attr, pv_set_dsturi_port,
		0, 0, pv_init_iname, 2},
	{str_const_init("dP"), /* */
		PVT_DSTURI_PROTOCOL, pv_get_dsturi_attr, 0,
		0, 0, pv_init_iname, 3},
	{str_const_init("ds"), /* */
		PVT_DSET, pv_get_dset, 0,
		0, 0, 0, 0},
	{str_const_init("du"), /* */
		PVT_DSTURI, pv_get_dsturi, pv_set_dsturi,
		0, 0, 0, 0},
	{str_const_init("duri"), /* */
		PVT_DSTURI, pv_get_dsturi, pv_set_dsturi,
		0, 0, 0, 0},
	{str_const_init("err.class"), /* */
		PVT_ERR_CLASS, pv_get_errinfo_attr, 0,
		0, 0, 0, 0},
	{str_const_init("err.level"), /* */
		PVT_ERR_LEVEL, pv_get_errinfo_attr, 0,
		0, 0, pv_init_iname, 1},
	{str_const_init("err.info"), /* */
		PVT_ERR_INFO, pv_get_errinfo_attr, 0,
		0, 0, pv_init_iname, 2},
	{str_const_init("err.rcode"), /* */
		PVT_ERR_RCODE, pv_get_errinfo_attr, 0,
		0, 0, pv_init_iname, 3},
	{str_const_init("err.rreason"), /* */
		PVT_ERR_RREASON, pv_get_errinfo_attr, 0,
		0, 0, pv_init_iname, 4},
	{str_const_init("fd"), /* */
		PVT_FROM_DOMAIN, pv_get_from_attr, 0,
		0, 0, pv_init_iname, 3},
	{str_const_init("from.domain"), /* */
		PVT_FROM_DOMAIN, pv_get_from_attr, 0,
		0, 0, pv_init_iname, 3},
	{str_const_init("fn"), /* */
		PVT_FROM_DISPLAYNAME, pv_get_from_attr, 0,
		0, 0, pv_init_iname, 5},
	{str_const_init("ft"), /* */
		PVT_FROM_TAG, pv_get_from_attr, 0,
		0, 0, pv_init_iname, 4},
	{str_const_init("fu"), /* */
		PVT_FROM, pv_get_from_attr, 0,
		0, 0, pv_init_iname, 1},
	{str_const_init("from"), /* */
		PVT_FROM, pv_get_from_attr, 0,
		0, 0, pv_init_iname, 1},
	{str_const_init("fU"), /* */
		PVT_FROM_USERNAME, pv_get_from_attr, 0,
		0, 0, pv_init_iname, 2},
	{str_const_init("from.user"), /* */
		PVT_FROM_USERNAME, pv_get_from_attr, 0,
		0, 0, pv_init_iname, 2},
	{str_const_init("log_level"), /* per process log level*/
		PVT_LOG_LEVEL, pv_get_log_level, pv_set_log_level,
		0, 0, 0, 0},
	{str_const_init("mb"), /* */
		PVT_MSG_BUF, pv_get_msg_buf, 0,
		0, 0, 0, 0},
	{str_const_init("mf"), /* */
		PVT_FLAGS, pv_get_flags, 0,
		0, 0, 0, 0},
	{str_const_init("msg.flag"), /* */
		PVT_MSG_FLAG, msg_flag_get, msg_flag_set,
		msg_flag_parse_name, 0, 0, 0},
	{str_const_init("msg.is_request"), /* */
		PVT_MSG_FLAG, msg_is_request_get, 0,
		0, 0, 0, 0},
	{str_const_init("msg.type"), /* */
		PVT_MSG_FLAG, msg_type_get, 0,
		0, 0, 0, 0},

	{str_const_init("msg.branch"), /* */
		PVT_BRANCH, pv_get_branch_fields, pv_set_msg_branch,
		0, 0, 0, 0},
	{str_const_init("msg.branch.uri"), /* */
		PVT_BRANCH, pv_get_msg_branch_uri, pv_set_msg_branch_uri,
		0, pv_parse_index, 0, 0},
	{str_const_init("msg.branch.duri"), /* */
		PVT_BRANCH, pv_get_msg_branch_duri, pv_set_msg_branch_duri,
		0, pv_parse_index, 0, 0},
	{str_const_init("msg.branch.path"), /* */
		PVT_BRANCH, pv_get_msg_branch_path, pv_set_msg_branch_path,
		0, pv_parse_index, 0, 0},
	{str_const_init("msg.branch.q"), /* */
		PVT_BRANCH, pv_get_msg_branch_q, pv_set_msg_branch_q,
		0, pv_parse_index, 0, 0},
	{str_const_init("msg.branch.flags"), /* */
		PVT_BRANCH, pv_get_msg_branch_flags, pv_set_msg_branch_flags,
		0, pv_parse_index, 0, 0},
	{str_const_init("msg.branch.socket"), /* */
		PVT_BRANCH, pv_get_msg_branch_sock, pv_set_msg_branch_sock,
		0, pv_parse_index, 0, 0},
	{str_const_init("msg.branch.flag"), /* */
		PVT_BRANCH_FLAG, msg_branch_flag_get, msg_branch_flag_set,
		msg_branch_flag_parse_name, pv_parse_index, 0, 0},
	{str_const_init("msg.branch.attr"), /* */
		PVT_BRANCH, pv_get_msg_branch_attr, pv_set_msg_branch_attr,
		pv_parse_avp_name, pv_parse_index, 0, 0},
	{str_const_init("msg.branch.last_idx"), /* */
		PVT_BRANCH, pv_get_msg_branch_lastidx, NULL,
		NULL, NULL, 0, 0},
	{str_const_init("mi"), /* */
		PVT_MSGID, pv_get_msgid, 0,
		0, 0, 0, 0},
	{str_const_init("ml"), /* */
		PVT_MSG_LEN, pv_get_msg_len, 0,
		0, 0, 0, 0},
	{str_const_init("od"), /* */
		PVT_OURI_DOMAIN, pv_get_ouri_attr, 0,
		0, 0, pv_init_iname, 2},
	{str_const_init("op"), /* */
		PVT_OURI_PORT, pv_get_ouri_attr, 0,
		0, 0, pv_init_iname, 3},
	{str_const_init("oP"), /* */
		PVT_OURI_PROTOCOL, pv_get_ouri_attr, 0,
		0, 0, pv_init_iname, 4},
	{str_const_init("ou"), /* */
		PVT_OURI, pv_get_ouri, 0,
		0, 0, 0, 0},
	{str_const_init("ouri"), /* */
		PVT_OURI, pv_get_ouri, 0,
		0, 0, 0, 0},
	{str_const_init("oU"), /* */
		PVT_OURI_USERNAME, pv_get_ouri_attr, 0,
		0, 0, pv_init_iname, 1},
	{str_const_init("path"), /* */
		PVT_PATH, pv_get_path, 0,
		0, 0, 0, 0},
	{str_const_init("pd"), /* */
		PVT_PPI_DOMAIN, pv_get_ppi_attr, 0,
		0, 0, pv_init_iname, 3},
	{str_const_init("pn"), /* */
		PVT_PPI_DISPLAYNAME, pv_get_ppi_attr, 0,
		0, 0, pv_init_iname, 4},
	{str_const_init("pp"), /* */
		PVT_PID, pv_get_pid, 0,
		0, 0, 0, 0},
	{str_const_init("pu"), /* */
		PVT_PPI, pv_get_ppi_attr, 0,
		0, 0, pv_init_iname, 1},
	{str_const_init("pU"), /* */
		PVT_PPI_USERNAME, pv_get_ppi_attr, 0,
		0, 0, pv_init_iname, 2},
	{str_const_init("rb"), /* */
		PVT_MSG_BODY, pv_get_msg_body, 0,
		0, pv_parse_index, 0, 0},
	{str_const_init("rb"), /* */
		PVT_MSG_BODY, pv_get_msg_body, 0,
		pv_parse_rb_name, pv_parse_index, 0, 0},
	{str_const_init("rc"), /* */
		PVT_RETURN_CODE, pv_get_return_code, 0,
		0, 0, 0, 0},
	{str_const_init("retcode"), /* */
		PVT_RETURN_CODE, pv_get_return_code, 0,
		0, 0, 0, 0},
	{str_const_init("rd"), /* */
		PVT_RURI_DOMAIN, pv_get_ruri_attr, pv_set_ruri_host,
		0, 0, pv_init_iname, 2},
	{str_const_init("ruri.domain"), /* */
		PVT_RURI_DOMAIN, pv_get_ruri_attr, pv_set_ruri_host,
		0, 0, pv_init_iname, 2},
	{str_const_init("re"), /* */
		PVT_RPID_URI, pv_get_rpid, 0,
		0, 0, 0, 0},
	{str_const_init("rm"), /* */
		PVT_METHOD, pv_get_method, 0,
		0, 0, 0, 0},
	{str_const_init("route"), /* */
		PVT_ROUTE, pv_get_route, 0,
		0, pv_parse_index, 0, 0},
	{str_const_init("route.name"), /* */
		PVT_ROUTE_NAME, pv_get_route_name, 0,
		0, pv_parse_index, 0, 0},
	{str_const_init("route.type"), /* */
		PVT_ROUTE_TYPE, pv_get_route_type, 0,
		0, pv_parse_index, 0, 0},
	{str_const_init("rp"), /* */
		PVT_RURI_PORT, pv_get_ruri_attr, pv_set_ruri_port,
		0, 0, pv_init_iname, 3},
	{str_const_init("rP"), /* */
		PVT_RURI_PROTOCOL, pv_get_ruri_attr, 0,
		0, 0, pv_init_iname, 4},
	{str_const_init("rr"), /* */
		PVT_REASON, pv_get_reason, 0,
		0, 0, 0, 0},
	{str_const_init("rs"), /* */
		PVT_STATUS, pv_get_status, 0,
		0, 0, 0, 0},
	{str_const_init("rt"), /* */
		PVT_REFER_TO, pv_get_refer_to, 0,
		0, 0, 0, 0},
	{str_const_init("ru"), /* */
		PVT_RURI, pv_get_ruri, pv_set_ruri,
		0, 0, 0, 0},
	{str_const_init("ruri"), /* */
		PVT_RURI, pv_get_ruri, pv_set_ruri,
		0, 0, 0, 0},
	{str_const_init("ru_q"), /* */
		PVT_RU_Q, pv_get_ru_q, pv_set_ru_q,
		0, 0, 0, 0},
	{str_const_init("rU"), /* */
		PVT_RURI_USERNAME, pv_get_ruri_attr, pv_set_ruri_user,
		0, 0, pv_init_iname, 1},
	{str_const_init("ruri.user"), /* */
		PVT_RURI_USERNAME, pv_get_ruri_attr, pv_set_ruri_user,
		0, 0, pv_init_iname, 1},
	{str_const_init("sdp"), /* */
		PVT_SDP, pv_get_sdp, pv_set_sdp,
		0, 0, pv_init_iname, 1},
	{str_const_init("sdp"), /* */
		PVT_SDP, pv_get_sdp, pv_set_sdp,
		pv_parse_sdp_name, 0, pv_init_iname, 1},
	{str_const_init("sdp.line"), /* */
		PVT_SDP_LINE, pv_get_sdp_line, pv_set_sdp_line,
		pv_parse_sdp_line_name, pv_parse_sdp_line_index, 0, 0},
	{str_const_init("sdp.stream"), /* */
		PVT_SDP_STREAM, pv_get_sdp_stream, pv_set_sdp_stream,
		pv_parse_sdp_stream_name, pv_parse_sdp_line_index, 0, 0},
	{str_const_init("sdp.stream.idx"), /* */
		PVT_SDP_LINE, pv_get_sdp_stream_idx, 0,
		pv_parse_sdp_stream_name, 0, 0, 0},
	{str_const_init("sdp.session"), /* */
		PVT_SDP_SESSION, pv_get_sdp_session, pv_set_sdp_session,
		pv_parse_sdp_line_name, pv_parse_sdp_line_index, 0, 0},
	{str_const_init("src_ip"), /* */
		PVT_SRCIP, pv_get_srcip, 0,
		0, 0, 0, 0},
	{str_const_init("socket_in"), /* */
		PVT_SOCKET_IN, pv_get_socket_in_fields, NULL,
		0, 0, 0, 0},
	{str_const_init("socket_in"), /* */
		PVT_SOCKET_IN, pv_get_socket_in_fields, NULL,
		pv_parse_socket_name, 0, 0, 0},
	{str_const_init("socket_out"), /* */
		PVT_SOCKET_OUT, pv_get_socket_out_fields, pv_set_force_sock,
		0, 0, 0, 0},
	{str_const_init("socket_out"), /* */
		PVT_SOCKET_OUT, pv_get_socket_out_fields, NULL,
		pv_parse_socket_out_name, 0, 0, 0},
	{str_const_init("si"), /* */
		PVT_SRCIP, pv_get_srcip, 0,
		0, 0, 0, 0},
	{str_const_init("sp"), /* */
		PVT_SRCPORT, pv_get_srcport, 0,
		0, 0, 0, 0},
	{str_const_init("td"), /* */
		PVT_TO_DOMAIN, pv_get_to_attr, 0,
		0, 0, pv_init_iname, 3},
	{str_const_init("to.domain"), /* */
		PVT_TO_DOMAIN, pv_get_to_attr, 0,
		0, 0, pv_init_iname, 3},
	{str_const_init("time"), /* */
		PVT_TIME, pv_get_formated_time, 0,
		pv_parse_time_name, 0, 0, 0},
	{str_const_init("tn"), /* */
		PVT_TO_DISPLAYNAME, pv_get_to_attr, 0,
		0, 0, pv_init_iname, 5},
	{str_const_init("tt"), /* */
		PVT_TO_TAG, pv_get_to_attr, 0,
		0, 0, pv_init_iname, 4},
	{str_const_init("tu"), /* */
		PVT_TO, pv_get_to_attr, 0,
		0, 0, pv_init_iname, 1},
	{str_const_init("to"), /* */
		PVT_TO, pv_get_to_attr, 0,
		0, 0, pv_init_iname, 1},
	{str_const_init("tU"), /* */
		PVT_TO_USERNAME, pv_get_to_attr, 0,
		0, 0, pv_init_iname, 2},
	{str_const_init("to.user"), /* */
		PVT_TO_USERNAME, pv_get_to_attr, 0,
		0, 0, pv_init_iname, 2},
	{str_const_init("Tf"), /* */
		PVT_TIMEF, pv_get_timef, 0,
		0, 0, 0, 0},
	{str_const_init("Ts"), /* */
		PVT_TIMES, pv_get_times, 0,
		0, 0, 0, 0},
	{str_const_init("Tsm"), /* */
		PVT_TIMES, pv_get_timem, 0,
		0, 0, 0, 0},
	{str_const_init("TS"), /* */
		PVT_TIMES, pv_get_start_times, 0,
		0, 0, 0, 0},
	{str_const_init("ua"), /* */
		PVT_USERAGENT, pv_get_useragent, 0,
		0, 0, 0, 0},
	{str_const_init("C"), PVT_COLOR, pv_get_color, 0,
		pv_parse_color_name, 0, 0, 0 },
	{str_const_init("argv"), PVT_ARGV, pv_get_argv, 0,
		pv_parse_argv_name, 0, 0, 0 },
	{str_const_init("param"), PVT_ROUTE_PARAM, pv_get_param, 0,
		pv_parse_param_name, 0, 0, 0 },
	{str_const_init("cfg_line"), PVT_LINE_NUMBER, pv_get_line_number, 0,
		0, 0, 0, 0 },
	{str_const_init("cfg_file"), PVT_CFG_FILE_NAME, pv_get_cfg_file_name, 0,
	0, 0, 0, 0 },
	{str_const_init("xlog_level"), PVT_XLOG_LEVEL, pv_get_xlog_level,
		pv_set_xlog_level, 0, 0, 0, 0 },
	{str_const_init("return"), PVT_EXTRA, pv_get_return_value, 0,
		pv_parse_return_value, 0, 0, 0 },
	{{0,0}, 0, 0, 0, 0, 0, 0, 0}
};

static const pv_export_t* pv_lookup_spec_name(str *pvname, pv_spec_p e, int has_name)
{
	int i;
	pv_extra_p pvi;
	int found;

	if(pvname==0 || e==0)
	{
		LM_ERR("bad parameters\n");
		return NULL;
	}
	/* search in main table */
	for(i=0; _pv_names_table[i].name.s!=0; i++)
	{
		if(_pv_names_table[i].name.len==pvname->len
			&& !((has_name?1:0) ^ (_pv_names_table[i].parse_name?1:0))
			&& memcmp(_pv_names_table[i].name.s, pvname->s, pvname->len)==0)
		{
			/*LM_DBG("found [%.*s] [%d]\n", pvname->len, pvname->s,
					_pv_names_table[i].type);*/
			/* copy data from table to spec */
			e->type = _pv_names_table[i].type;
			e->getf = _pv_names_table[i].getf;
			e->setf = _pv_names_table[i].setf;
			return &_pv_names_table[i];
		}
	}
	/* search in extra list */
	if(_pv_extra_list==0)
	{
		LM_DBG("extra items list is empty\n");
		return NULL;
	}
	pvi = *_pv_extra_list;
	while(pvi)
	{
		if(pvi->pve.name.len>pvname->len)
			break;
		if(pvi->pve.name.len==pvname->len)
		{
			found = strncmp(pvi->pve.name.s, pvname->s, pvname->len);
			if(found>0)
				break;
			if(found==0)
			{
				LM_DBG("found in extra list [%.*s]\n", pvname->len, pvname->s);
				/* copy data from export to spec */
				e->type = pvi->pve.type;
				e->getf = pvi->pve.getf;
				e->setf = pvi->pve.setf;
				return &(pvi->pve);
			}
		}
		pvi = pvi->next;
	}

	return NULL;
}

static int is_pv_valid_char(char c)
{
	if((c>='0' && c<='9') || (c>='a' && c<='z') || (c>='A' && c<='Z')
			|| (c=='_') || (c=='.'))
		return 1;
	return 0;
}

char* pv_parse_spec(const str *in, const pv_spec_p e)
{
	char *p;
	str s;
	str pvname;
	str pvcontext;
	int pvstate;
	int has_inner_name;
	trans_t *tr = NULL;
	const pv_export_t *pte = NULL;
	int n=0;

	if(in==NULL || in->s==NULL || e==NULL || *in->s!=PV_MARKER)
	{
		LM_ERR("bad parameters\n");
		return NULL;
	}

//	LM_DBG("***** input [%.*s] (%d)\n", in->len, in->s, in->len);
	tr = 0;
	pvstate = 0;
	memset(e, 0, sizeof(pv_spec_t));
	p = in->s;
	p++;
	if(*p==PV_LNBRACKET)
	{
		p++;
		pvstate = 1;
	}
	pvname.s = p;
	if(*p == PV_MARKER) {
		p++;
		if(pvstate==1)
		{
			if(*p!=PV_RNBRACKET)
				goto error;
			p++;
		}
		e->getf = pv_get_marker;
		e->type = PVT_MARKER;
		pvname.len = 1;
		goto done_all;
	}

	if (*p==PV_LCBRACKET)
	{ /* context definition*/
		p++;
		pvcontext.s = p;

		while(is_in_str(p,in) && is_pv_valid_char(*p))
			p++;

		if(*p != PV_RCBRACKET)
		{
			LM_ERR("Expected to find the end of the context\n");
			return 0;
		}
		pvcontext.len = p - pvcontext.s;
		LM_DBG("Context name is %.*s\n", pvcontext.len, pvcontext.s);
		p++;
		e->pvc = pv_get_context(&pvcontext);
		if(e->pvc == NULL)
		{
			if(!pvc_before_check)
			{
				LM_ERR("Requested a non existing pv context\n");
				return 0;
			}
			LM_DBG("No context definition found for [%.*s]\n", pvcontext.len, pvcontext.s);
			/* create a dummy context strcuture to be filled by the register functions */
			e->pvc = add_pv_context(&pvcontext, 0);
			if(e->pvc == NULL )
			{
				LM_ERR("Failed to new context\n");
				return 0;
			}
		}
	}

	pvname.s = p;
	while(is_in_str(p,in) && is_pv_valid_char(*p))
		p++;
	pvname.len = p - pvname.s;

	if(pvstate==1)
	{
		if(*p==PV_RNBRACKET)
		{ /* full pv name ended here*/
			goto done_inm;
		} else if(*p==PV_LNBRACKET) {
			p++;
			pvstate = 2;
		} else if(*p==PV_LIBRACKET) {
			p++;
			pvstate = 3;
		} else if(*p==TR_LBRACKET) {
			p++;
			pvstate = 4;
		}
		else {
			LM_ERR("invalid char '%c' in [%.*s] (%d)\n", *p, in->len, in->s,
					pvstate);
			goto error;
		}
	} else {
		if(!is_in_str(p, in)) {
			p--;
			goto done_inm;
		} else if(*p==PV_LNBRACKET) {
			p++;
			pvstate = 5;
		} else {
			/* still in input str, but end of PV */
			/* p is increased at the end, so decrement here */
			p--;
			goto done_inm;
		}
	}

done_inm:
	has_inner_name = (pvstate==2||pvstate==5)?1:0;
	if((pte = pv_lookup_spec_name(&pvname, e, has_inner_name))==NULL)
	{
		LM_ERR("unknown script var $%.*s%s, maybe a 'loadmodule' statement "
		       "is missing?\n", pvname.len, pvname.s,has_inner_name ? "()":"");
		goto error;
	}
	if(pvstate==2 || pvstate==5)
	{
		s.s = p;
		n = 0;
		while(is_in_str(p, in))
		{
			if(*p==PV_RNBRACKET)
			{
				if(n==0)
					break;
				n--;
			}
			if(*p == PV_LNBRACKET)
				n++;
			p++;
		}

		if(!is_in_str(p, in))
			goto error;

		if(p==s.s)
		{
			LM_ERR("pvar \"%.*s\" does not get empty name param\n",
					pvname.len, pvname.s);
			goto error;
		}
		s.len = p - s.s;
		if(pte->parse_name == NULL || pte->parse_name(e, &s)!=0)
		{
			LM_ERR("pvar \"%.*s\" has an invalid name param [%.*s]\n",
					pvname.len, pvname.s, s.len, s.s);
			goto error;
		}
		if(pvstate==2)
		{
			p++;
			if(*p==PV_RNBRACKET)
			{ /* full pv name ended here*/
				goto done_vnm;
			} else if(*p==PV_LIBRACKET) {
				p++;
				pvstate = 3;
			} else if(*p==TR_LBRACKET) {
				p++;
				pvstate = 4;
			} else {
				LM_ERR("invalid char '%c' in [%.*s] (%d)\n", *p, in->len, in->s,
					pvstate);
				goto error;
			}
		} else {
			if(*p==PV_RNBRACKET)
			{ /* full pv name ended here*/
				p++;
				goto done_all;
			} else {
				LM_ERR("invalid char '%c' in [%.*s] (%d)\n", *p, in->len, in->s,
					pvstate);
				goto error;
			}
		}
	}
done_vnm:
	if(pvstate==3)
	{
		if(pte->parse_index==NULL)
		{
			LM_ERR("pvar \"%.*s\" does not get index param\n",
					pvname.len, pvname.s);
			goto error;
		}
		s.s = p;
		n = 0;
		while(is_in_str(p, in))
		{
			if(*p==PV_RIBRACKET)
			{
				if(n==0)
					break;
				n--;
			}
			if(*p == PV_LIBRACKET)
				n++;
			p++;
		}
		if(!is_in_str(p, in))
			goto error;

		if(p==s.s)
		{
			LM_ERR("pvar \"%.*s\" does not get empty index param\n",
					pvname.len, pvname.s);
			goto error;
		}
		s.len = p - s.s;
		if(pte->parse_index(e, &s)!=0)
		{
			LM_ERR("pvar \"%.*s\" has an invalid index param [%.*s]\n",
					pvname.len, pvname.s, s.len, s.s);
			goto error;
		}
		p++;
		if(*p==PV_RNBRACKET)
		{ /* full pv name ended here*/
			goto done_idx;
		} else if(*p==TR_LBRACKET) {
			p++;
			pvstate = 4;
		} else {
			LM_ERR("invalid char '%c' in [%.*s] (%d)\n", *p, in->len, in->s,
					pvstate);
			goto error;
		}
	}
done_idx:
	if(pvstate==4)
	{
		s.s = p-1;
		n = 0;
		while(is_in_str(p, in))
		{
			if(*p==TR_RBRACKET)
			{
				if(n==0)
				{
					/* yet another transformation */
					p++;
					while(is_in_str(p, in) && (*p==' ' || *p=='\t')) p++;

					if(!is_in_str(p, in) || *p != TR_LBRACKET)
					{
						p--;
						break;
					}
				}
				n--;
			}
			if(*p == TR_LBRACKET)
				n++;
			p++;
		}
		if(!is_in_str(p, in))
			goto error;

		if(p==s.s)
		{
			LM_ERR("pvar \"%.*s\" does not get empty index param\n",
					pvname.len, pvname.s);
			goto error;
		}
		s.len = p - s.s + 1;

		p = parse_transformation(&s, &tr);
		if(p==NULL)
		{
			LM_ERR("ERROR:bad tr in pvar name \"%.*s\"\n",
					pvname.len, pvname.s);
			goto error;
		}
		if(*p!=PV_RNBRACKET)
		{
			LM_ERR("bad pvar name \"%.*s\" (%c)!\n", in->len, in->s, *p);
			goto error;
		}
		e->trans = (void*)tr;
	}
	p++;

done_all:
	if(pte!=NULL && pte->init_param)
		pte->init_param(e, pte->iparam);
	return p;

error:
	if(p!=NULL)
		LM_ERR("wrong char [%c/%d] in [%.*s] at [%d (%d)]\n", *p, (int)*p,
			in->len, in->s, (int)(p-in->s), pvstate);
	else
		LM_ERR("invalid parsing in [%.*s] at (%d)\n", in->len, in->s, pvstate);
	return NULL;

} /* end: pv_parse_spec */

/**
 *
 */
int pv_parse_format(const str *in, pv_elem_p *el)
{
	char *p, *p0;
	/*int n = 0;*/
	pv_elem_p e, e0;
	str s;

	if(in==NULL || in->s==NULL || el==NULL)
		return -1;

	/*LM_DBG("parsing [%.*s]\n", in->len, in->s);*/

	if(in->len == 0)
	{
		*el = pkg_malloc(sizeof(pv_elem_t));
		if(*el == NULL) {
			LM_ERR("not enough pkg memory for PV element (1)\n");
			goto error;
		}
		memset(*el, 0, sizeof(pv_elem_t));
		(*el)->text = *in;
		return 0;
	}

	p = in->s;
	*el = NULL;
	e = e0 = NULL;

	while(is_in_str(p,in))
	{
		e0 = e;
		e = pkg_malloc(sizeof(pv_elem_t));
		if(!e) {
			LM_ERR("not enough pkg memory for PV element (2)\n");
			goto error;
		}
		memset(e, 0, sizeof(pv_elem_t));
		/*n++;*/
		if(*el == NULL)
			*el = e;
		if(e0)
			e0->next = e;

		e->text.s = p;
		while(is_in_str(p,in) && *p!=PV_MARKER)
			p++;
		e->text.len = p - e->text.s;

		if(!is_in_str(p,in))
			break;
		s.s = p;
		s.len = in->s+in->len-p;
		p0 = pv_parse_spec(&s, &e->spec);

		if(p0==NULL) {
			LM_ERR("parsing PV spec failed\n");
			goto error;
		}
		if(!is_in_str(p0,in))
			break;
		p = p0;
	}
	/*LM_DBG("format parsed OK: [%d] items\n", n);*/

	if(*el == NULL)
		return -1;

	return 0;

error:
	pv_elem_free_all(*el);
	*el = NULL;
	return -1;
}

int pv_get_spec_name(struct sip_msg* msg, pv_param_p ip, pv_value_t *name)
{
	if(msg==NULL || ip==NULL || name==NULL)
		return -1;
	memset(name, 0, sizeof(pv_value_t));

	if(ip->pvn.type==PV_NAME_INTSTR)
	{
		if(ip->pvn.u.isname.type&AVP_NAME_STR)
		{
			name->rs = ip->pvn.u.isname.name.s;
			name->flags = PV_VAL_STR;
		} else {
			name->ri = ip->pvn.u.isname.name.n;
			name->flags = PV_VAL_INT|PV_TYPE_INT;
		}
		return 0;
	}
	/* pvar */
	if(pv_get_spec_value(msg, (const pv_spec_p)(ip->pvn.u.dname), name)!=0)
	{
		LM_ERR("cannot get name value\n");
		return -1;
	}
	if(name->flags&PV_VAL_NULL || name->flags&PV_VAL_EMPTY)
	{
		LM_ERR("null or empty name\n");
		return -1;
	}
	return 0;
}

int pv_get_avp_name(struct sip_msg* msg, pv_param_p ip, int *avp_name,
		unsigned short *name_type)
{
	pv_value_t tv;
	if(ip==NULL || avp_name==NULL || name_type==NULL)
		return -1;
	*avp_name = 0;
	*name_type = 0;

	if(ip->pvn.type==PV_NAME_INTSTR)
	{
		*name_type = ip->pvn.u.isname.type;
		*avp_name = ip->pvn.u.isname.name.n;
		*name_type &= AVP_SCRIPT_MASK;
		return 0;
	}
	/* pvar */
	if(pv_get_spec_value(msg, (const pv_spec_p)(ip->pvn.u.dname), &tv)!=0)
	{
		LM_ERR("cannot get avp value\n");
		return -1;
	}
	if(tv.flags&PV_VAL_NULL || tv.flags&PV_VAL_EMPTY)
	{
		LM_ERR("null or empty name\n");
		return -1;
	}

	if(!(tv.flags&PV_VAL_STR))
		tv.rs.s = int2str(tv.ri, &tv.rs.len);

	/* search the name here */
	*avp_name = get_avp_id(&tv.rs);
	if (*avp_name == 0) {
		LM_ERR("cannot find avp %.*s\n", tv.rs.len, tv.rs.s);
		return -1;
	}
	return 0;
}


int pv_get_spec_index(struct sip_msg* msg, pv_param_p ip, int *idx, int *flags)
{
	pv_value_t tv;
	if(ip==NULL || idx==NULL || flags==NULL)
		return -1;

	*idx = 0;
	*flags = ip->pvi.type;

	if(ip->pvi.type == 0)
		return 0;

	if(ip->pvi.type == PV_IDX_ALL || ip->pvi.type == PV_IDX_APPEND) {
		return 0;
	}

	if(ip->pvi.type == PV_IDX_INT)
	{
		*idx = ip->pvi.u.ival;
		return 0;
	}

	/* pvar */
	if(pv_get_spec_value(msg, (const pv_spec_p)ip->pvi.u.dval, &tv)!=0)
	{
		LM_ERR("cannot get index value\n");
		return -1;
	}
	if(!(tv.flags & PV_VAL_INT))
	{
		LM_ERR("invalid index value\n");
		return -1;
	}
	*idx = tv.ri;
	return 0;
}

/* function to set pv value */
int pv_set_value(struct sip_msg* msg, pv_spec_p sp,
		int op, pv_value_t *value)
{
	struct sip_msg* pv_msg;

	if(msg==NULL || sp==NULL || sp->setf==NULL || sp->type==PVT_NONE)
	{
		LM_ERR("bad parameters\n");
		return -1;
	}

	if(sp->pvc && sp->pvc->contextf)
	{
		pv_msg = sp->pvc->contextf(msg);
		if(pv_msg == NULL || pv_msg==FAKED_REPLY)
		{
			LM_DBG("Invalid %p pv context message\n",pv_msg);
			return -1;
		}
	}
	else
		pv_msg = msg;

	return (*sp->setf)(pv_msg, &(sp->pvp), op, value);
}

int pv_get_spec_value(struct sip_msg* msg, const pv_spec_p sp, pv_value_t *value)
{
	struct sip_msg* pv_msg;

	if(msg==NULL || sp==NULL || sp->getf==NULL || value==NULL
			|| sp->type==PVT_NONE)
	{
		LM_ERR("bad parameters\n");
		return -1;
	}

	memset(value, 0, sizeof(pv_value_t));

	if(sp->pvc && sp->pvc->contextf)
	{
		LM_DBG("Found context function %p\n", sp->pvc->contextf);
		pv_msg = sp->pvc->contextf(msg);
		if(pv_msg == NULL || pv_msg==FAKED_REPLY)
		{
			LM_DBG("Invalid %p pv context message\n",pv_msg);
			return pv_get_null( NULL, NULL, value);
		}
	} else {
		pv_msg = msg;
	}
	if((*sp->getf)(pv_msg, &(sp->pvp), value)!=0)
		return pv_get_null( NULL, NULL, value);
	if(sp->trans)
		if (run_transformations(pv_msg, (trans_t*)sp->trans, value)!=0)
			return pv_get_null( NULL, NULL, value);
	return 0;
}

int pv_print_spec(struct sip_msg* msg, const pv_spec_p sp, char *buf, int *len)
{
	pv_value_t tok;
	if(msg==NULL || sp==NULL || buf==NULL || len==NULL)
		return -1;

	if(*len <= 0)
		return -1;

	memset(&tok, 0, sizeof(pv_value_t));

	/* put the value of the specifier */
	if(pv_get_spec_value(msg, sp, &tok)==0)
	{
		if(tok.flags&PV_VAL_NULL)
			tok.rs = str_null;
		if(tok.rs.len < *len)
			memcpy(buf, tok.rs.s, tok.rs.len);
		else
			goto overflow;
	}

	*len = tok.rs.len;
	buf[tok.rs.len] = '\0';
	return 0;

overflow:
	LM_ERR("buffer overflow -- increase the buffer size...\n");
	return -1;
}


int pv_printf(struct sip_msg* msg, pv_elem_p list, char *buf, int *len)
{
	int n;
	pv_value_t tok;
	str print;
	pv_elem_p it;
	char *cur;

	if(msg==NULL || list==NULL || buf==NULL || len==NULL)
		return -1;

	if(*len <= 0)
		return -1;

	*buf = '\0';
	cur = buf;

	n = 0;
	for (it=list; it; it=it->next)
	{
		/* put the text */
		if(it->text.s && it->text.len>0)
		{
			if(n+it->text.len < *len)
			{
				memcpy(cur, it->text.s, it->text.len);
				n += it->text.len;
				cur += it->text.len;
			} else {
				LM_ERR("no more space for text [%d][%d]\n", n, it->text.len);
				goto overflow;
			}
		}
		/* put the value of the specifier */
		if(it->spec.type!=PVT_NONE
				&& pv_get_spec_value(msg, &(it->spec), &tok)==0)
		{
			print = pv_value_print(&tok);
			if (n + print.len >= *len) {
				LM_ERR("no more space for spec value [%d][%d]\n",
				       n, print.len);
				goto overflow;
			}

			memcpy(cur, print.s, print.len);
			n += print.len;
			cur += print.len;
		}
	}

	goto done;

overflow:
	if (is_pv_print_buf(buf))
		LM_ERR("buffer too small -- increase 'pv_print_buf_size' from [%d]\n",
				*len);
	else
		LM_ERR("buffer too small -- increase the buffer size "
				"from [%d]...\n", *len);
	return -1;

done:
#ifdef EXTRA_DEBUG
	LM_DBG("final buffer length %d\n", n);
#endif
	*cur = '\0';
	*len = n;
	return 0;
}



pvname_list_t* parse_pvname_list(str *in, unsigned int type)
{
	pvname_list_t* head = NULL;
	pvname_list_t* al = NULL;
	pvname_list_t* last = NULL;
	char *p;
	pv_spec_t spec;
	str s;

	if(in==NULL || in->s==NULL)
	{
		LM_ERR("bad parameters\n");
		return NULL;
	}

	p = in->s;
	while(is_in_str(p, in))
	{
		while(is_in_str(p, in) && (is_ws(*p)||*p==','||*p==';'))
			p++;
		if(!is_in_str(p, in))
		{
			if(head==NULL)
				LM_ERR("wrong item name list [%.*s]\n", in->len, in->s);
			return head;
		}
		s.s=p;
		s.len = in->s+in->len-p;
		p = pv_parse_spec(&s, &spec);
		if(p==NULL || (type && spec.type!=type))
		{
			LM_ERR("wrong item name list [%.*s]!\n", in->len, in->s);
			goto error;
		}
		al = (pvname_list_t*)pkg_malloc(sizeof(pvname_list_t));
		if(al==NULL)
		{
			LM_ERR("no more memory!\n");
			goto error;
		}
		memset(al, 0, sizeof(pvname_list_t));
		memcpy(&al->sname, &spec, sizeof(pv_spec_t));

		if(last==NULL)
		{
			head = al;
			last = al;
		} else {
			last->next = al;
			last = al;
		}
	}

	return head;

error:
	while(head)
	{
		al = head;
		head=head->next;
		pkg_free(al);
	}
	return NULL;
}

int pv_elem_free_all(pv_elem_p log)
{
	pv_elem_p t;
	while(log)
	{
		t = log;
		log = log->next;

		if (t->spec.trans)
			free_transformation((trans_t *)t->spec.trans);
		pkg_free(t);
	}
	return 0;
}

static str pv_value_print(const pv_value_t *val)
{
	str printed = str_init(NULL);

	if (val->flags & PV_VAL_NULL)
		return str_null;

	if (val->flags & PV_VAL_STR)
		return val->rs;

	if (val->flags & (PV_VAL_INT|PV_TYPE_INT)) {
		printed.s = int2str(val->ri, &printed.len);
		return printed;
	}

	LM_ERR("unknown type %x\n", val->flags);
	return str_empty;
}

void pv_value_destroy(pv_value_t *val)
{
	if(val==0) return;
	if(val->flags&PV_VAL_PKG) pkg_free(val->rs.s);
	if(val->flags&PV_VAL_SHM) shm_free(val->rs.s);
	memset(val, 0, sizeof(pv_value_t));
}

/* IMPORTANT NOTE - even if the function prints and returns a static buffer, it
 * has built-in support for PV_PRINTF_BUF_NO levels of nesting
 * (or concurrent usage).  If you think it's not enough for you, either use
 * pv_printf() directly, either increase PV_PRINT_BUF_NO   --bogdan */
int pv_printf_s(struct sip_msg* msg, pv_elem_p list, str *s)
{
	static int buf_itr = 0;

	if (list->next==0 && list->spec.getf==0) {
		*s = list->text;
		return 0;
	} else {
		*s = pv_print_buf[buf_itr];
		buf_itr = (buf_itr + 1) % PV_PRINT_BUF_NO;
		return pv_printf(msg, list, s->s, &s->len);
	}
}

void pv_spec_free(pv_spec_t *spec)
{
	if(spec==0) return;
	/* TODO: free name if it is PV */
	if(spec->trans)
		free_transformation((trans_t*)spec->trans);
	pkg_free(spec);
}

int pv_spec_dbg(const pv_spec_p sp)
{
	if(sp==NULL)
	{
		LM_DBG("spec: <<NULL>>\n");
		return 0;
	}
	LM_DBG("<spec>\n");
	LM_DBG("type: %d\n", sp->type);
	LM_DBG("getf: %p\n", sp->getf);
	LM_DBG("setf: %p\n", sp->setf);
	LM_DBG("tran: %p\n", sp->trans);
	LM_DBG("<param>\n");
	LM_DBG("<name>\n");
	LM_DBG("type: %d\n", sp->pvp.pvn.type);
	if(sp->pvp.pvn.type==PV_NAME_INTSTR)
	{
		LM_DBG("sub-type: %d\n", sp->pvp.pvn.u.isname.type);
		if (sp->pvp.pvn.u.isname.type&AVP_NAME_STR)
		{
			LM_DBG("name str: %.*s\n",
					sp->pvp.pvn.u.isname.name.s.len,
					sp->pvp.pvn.u.isname.name.s.s);
		} else {
			LM_DBG("name in: %d\n",
					sp->pvp.pvn.u.isname.name.n);
		}

	} else if(sp->pvp.pvn.type==PV_NAME_PVAR) {
		pv_spec_dbg((pv_spec_p)sp->pvp.pvn.u.dname);
	} else {
		LM_DBG("name: unknown\n");
	}
	LM_DBG("</name>\n");
	LM_DBG("<index>\n");
	LM_DBG("type: %d\n", sp->pvp.pvi.type);
	if(sp->pvp.pvi.type==PV_IDX_INT)
	{
		LM_DBG("index: %d\n", sp->pvp.pvi.u.ival);
	} else if(sp->pvp.pvi.type==PV_IDX_PVAR) {
		pv_spec_dbg((pv_spec_p)sp->pvp.pvi.u.dval);
	} else if(sp->pvp.pvi.type==PV_IDX_ALL){
		LM_DBG("index: *\n");
	} else {
		LM_DBG("index: unknown\n");
	}
	LM_DBG("</index>\n");
	LM_DBG("</param>\n");
	LM_DBG("</spec\n");
	return 0;
}


/**
 *
 */
static int pv_init_extra_list(void)
{
	_pv_extra_list = (pv_extra_p*)pkg_malloc(sizeof(pv_extra_p));
	if(_pv_extra_list==0)
	{
		LM_ERR("cannot alloc extra items list\n");
		return -1;
	}
	*_pv_extra_list=0;
	return 0;
}

static int pv_add_extra(const pv_export_t *e)
{
	const char *p;
	const str_const *in;
	pv_extra_t *pvi = NULL;
	pv_extra_t *pvj = NULL;
	pv_extra_t *pvn = NULL;
	int found;

	if(e==NULL || e->name.s==NULL || e->getf==NULL || e->type==PVT_NONE)
	{
		LM_ERR("invalid parameters\n");
		return -1;
	}

	if(_pv_extra_list==0)
	{
		LM_DBG("extra items list is not initialized\n");
		if(pv_init_extra_list()!=0)
		{
			LM_ERR("cannot intit extra list\n");
			return -1;
		}
	}
	in = &(e->name);
	p = in->s;
	while(is_in_str(p,in) && is_pv_valid_char(*p))
		p++;
	if(is_in_str(p,in))
	{
		LM_ERR("invalid char [%c] in [%.*s]\n", *p, in->len, in->s);
		return -1;
	}
	found = 0;
	pvi = *_pv_extra_list;
	while(pvi)
	{
		if(pvi->pve.name.len > in->len)
			break;
		if(pvi->pve.name.len==in->len)
		{
			found = strncmp(pvi->pve.name.s, in->s, in->len);
			if(found>0)
				break;
			if(found==0)
			{
				LM_ERR("pvar [%.*s] already exists\n", in->len, in->s);
				return -1;
			}
		}
		pvj = pvi;
		pvi = pvi->next;
	}

	pvn = (pv_extra_t*)pkg_malloc(sizeof(pv_extra_t));
	if(pvn==0)
	{
		LM_ERR("no more memory\n");
		return -1;
	}
	memcpy(&pvn->pve, e, sizeof(*e));
	pvn->pve.type += PVT_EXTRA;

	if(pvj==0)
	{
		pvn->next = *_pv_extra_list;
		*_pv_extra_list = pvn;
		goto done;
	}
	pvn->next = pvj->next;
	pvj->next = pvn;

done:
	return 0;
}

int register_pvars_mod(const char *mod_name, const pv_export_t *items)
{
	int ret;
	int i;

	if (items==0)
		return 0;

	for ( i=0 ; items[i].name.s ; i++ ) {
		ret = pv_add_extra(&items[i]);
		if (ret!=0) {
			LM_ERR("failed to register pseudo-variable <%.*s> for module %s\n",
					items[i].name.len, items[i].name.s, mod_name);
		}
	}
	return 0;
}

/**
 *
 */
int pv_free_extra_list(void)
{
	pv_extra_p xe;
	pv_extra_p xe1;
	if(_pv_extra_list!=0)
	{
		xe = *_pv_extra_list;
		while(xe!=0)
		{
			xe1 = xe;
			xe = xe->next;
			pkg_free(xe1);
		}
		pkg_free(_pv_extra_list);
		_pv_extra_list = 0;
	}

	return 0;
}

static pv_context_t* new_pv_context(const str* name, pv_contextf_t get_context)
{
	pv_context_t* pvc_new = NULL;
	int size;
/*
	if(get_context == NULL)
	{
		LM_ERR("NULL pointer to function\n");
		return 0;
	}
*/
	size = sizeof(pv_context_t) + name->len;
	pvc_new = (pv_context_t*)pkg_malloc(size);
	if(pvc_new == NULL)
	{
		LM_ERR("No more memory\n");
		return 0;
	}
	memset(pvc_new, 0, size);

	pvc_new->name.s = (char*)pvc_new + sizeof(pv_context_t);
	memcpy(pvc_new->name.s, name->s, name->len);
	pvc_new->name.len = name->len;

	pvc_new->contextf = get_context;

	return pvc_new;
}

int register_pv_context(char* cname, pv_contextf_t get_context)
{
	pv_context_t* pvc = pv_context_lst;
	str name;

	if(cname == NULL)
	{
		LM_DBG("NULL parameter\n");
		return -1;
	}

	name.s = cname;
	name.len = strlen(cname);

	LM_DBG("Registered new context: %.*s / %p\n", name.len, name.s, get_context);
	pvc = pv_get_context(&name);
	if(pvc == NULL)
	{
		LM_DBG("Context not found\n");
		if(add_pv_context(&name, get_context) == NULL)
		{
			LM_ERR("Failed to add context\n");
			return -1;
		}
		return 1;
	}

	if(pvc->contextf!=NULL)
	{
		LM_ERR("Context already registered [%s]\n", cname);
		return -1;
	}
	if(get_context == NULL)
	{
		LM_ERR("NULL context getter function\n");
		return -1;
	}
	pvc->contextf= get_context;
	return 1;
}


/* function to register a pv context getter */
static pv_context_t* add_pv_context(const str* name, pv_contextf_t get_context)
{
	pv_context_t* pvc = pv_context_lst;
	pv_context_t* pvc_new, *pvc_prev;

	if(pvc == NULL)
	{
		pvc_new = new_pv_context(name, get_context);
		if(pvc_new == NULL)
		{
			LM_ERR("Failed to allocate context\n");
			return 0;
		}
		pv_context_lst = pvc_new;
		return pvc_new;
	}

	while(pvc)
	{
		if(pvc->name.len == name->len && strncmp(pvc->name.s, name->s, name->len)==0)
		{
			LM_ERR("PV Context already registered [%.*s]\n", name->len, name->s);
			return 0;
		}
		pvc_prev = pvc;
		pvc = pvc->next;
	}

	pvc_new = new_pv_context(name, get_context);
	if(pvc_new == NULL)
	{
		LM_ERR("Failed to allocate context\n");
		return 0;
	}

	LM_DBG("Registered new context: %.*s\n", name->len, name->s);

	pvc_prev->next = pvc_new;

	return pvc_new;
}

static pv_context_t* pv_get_context(const str* name)
{
	pv_context_t* pvc = pv_context_lst;

	while(pvc)
	{
		if(pvc->name.len == name->len &&
				strncmp(pvc->name.s, name->s, name->len) == 0)
		{
			return pvc;
		}
		pvc = pvc->next;
	}
	return 0;
}

static int pv_contextlist_check(void)
{
	pv_context_t* pvc = pv_context_lst;

	while(pvc)
	{
		if(pvc->contextf == NULL)
			return -1;

		pvc = pvc->next;
	}
	pvc_before_check = 0;
	return 0;
}

/* argument options '-o' */
argv_p argv_vars = NULL;

static argv_p search_argv(const str *name)
{
	argv_p it;

	for (it = argv_vars; it; it = it->next) {
		if (it->name.len == name->len &&
				!strncmp(it->name.s, name->s, name->len))
			return it;
	}
	return 0;
}

int add_arg_var(char *opt)
{
	char *eq;
	str name;
	argv_p new = NULL;

	if (!opt) {
		LM_ERR("cannot receive null option\n");
		return -1;
	}

	eq = strchr(opt, '=');
	if (!eq) {
		LM_ERR("invalid option format - '=' char cannot be found\n");
		return -1;
	}
	if (eq <= opt) {
		LM_ERR("no option name specified\n");
		return -1;
	}

	name.s = opt;
	name.len = eq - name.s;

	/* check for duplicate option name */
	if (search_argv(&name)) {
		LM_ERR("duplicate option name <%.*s>\n", name.len, name.s);
		return -1;
	}

	new = (argv_p)pkg_malloc(sizeof(argv_t));
	if (!new) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}
	memset(new, 0, sizeof(argv_t));

	new->name.s = name.s;
	new->name.len = name.len;

	new->value.s = eq+1;
	new->value.len = strlen(opt) + opt - new->value.s;

	if (!new->value.len)
		new->value.s = 0;

	new->next = argv_vars;
	argv_vars = new;

	LM_DBG("added argument name <%.*s> = <%.*s>\n",
			name.len, name.s, new->value.len, new->value.s);
	return 0;

}

static int pv_parse_argv_name(pv_spec_p sp, const str *in)
{
	argv_p v_arg;

	if(in==NULL || in->s==NULL || sp==NULL)
		return -1;

	v_arg = search_argv(in);
	if (!v_arg) {
		LM_DBG("$argv(%.*s) not found\n", in->len, in->s);
		sp->pvp.pvv.len = 0;
		sp->pvp.pvv.s = 0;
	} else {
		sp->pvp.pvv = v_arg->value;
		sp->pvp.pvn.u.isname.name.s = v_arg->name;
	}

	sp->pvp.pvn.type = PV_NAME_PVAR;

	return 0;
}

static int pv_get_argv(struct sip_msg *msg,  pv_param_t *param, pv_value_t *res)
{
	if (!param) {
		LM_ERR("null parameter received\n");
		return -1;
	}

	if (param->pvv.len == 0 || !param->pvv.s)
		return pv_get_null(msg, param, res);

	return pv_get_strval(msg, param, res, &param->pvv);
}

static int pv_parse_param_name(pv_spec_p sp, const str *in)
{
	char *p;
	char *s;
	pv_spec_p nsp = 0;

	if(in==NULL || in->s==NULL || sp==NULL)
		return -1;
	p = in->s;
	if(*p==PV_MARKER)
	{
		nsp = (pv_spec_p)pkg_malloc(sizeof(pv_spec_t));
		if(nsp==NULL)
		{
			LM_ERR("no more memory\n");
			return -1;
		}
		s = pv_parse_spec(in, nsp);
		if(s==NULL)
		{
			LM_ERR("invalid name [%.*s]\n", in->len, in->s);
			pv_spec_free(nsp);
			return -1;
		}
		sp->pvp.pvn.type = PV_NAME_PVAR;
		sp->pvp.pvn.u.dname = (void*)nsp;
		return 0;
	}
	/*LM_DBG("static name [%.*s]\n", in->len, in->s);*/
	/* always an int type from now */
	sp->pvp.pvn.u.isname.type = 0;
	sp->pvp.pvn.type = PV_NAME_INTSTR;
	/* do our best to convert it to an index */
	if (str2int(in, (unsigned int *)&sp->pvp.pvn.u.isname.name.n) < 0)
	{
		/* remember it was a string, so we can retrieve it later */
		sp->pvp.pvn.u.isname.name.s = *in;
		sp->pvp.pvn.u.isname.type = AVP_NAME_STR;
	}
	return 0;

}

static int pv_parse_return_value(pv_spec_p sp, const str *in)
{
	char *p;
	char *s;
	pv_spec_p nsp = 0;

	if(in==NULL || in->s==NULL || sp==NULL)
		return -1;
	p = in->s;
	if(*p==PV_MARKER)
	{
		nsp = (pv_spec_p)pkg_malloc(sizeof(pv_spec_t));
		if(nsp==NULL)
		{
			LM_ERR("no more memory\n");
			return -1;
		}
		s = pv_parse_spec(in, nsp);
		if(s==NULL)
		{
			LM_ERR("invalid name [%.*s]\n", in->len, in->s);
			pv_spec_free(nsp);
			return -1;
		}
		sp->pvp.pvn.type = PV_NAME_PVAR;
		sp->pvp.pvn.u.dname = (void*)nsp;
		return 0;
	}
	sp->pvp.pvn.u.isname.type = 0;
	sp->pvp.pvn.type = PV_NAME_INTSTR;
	/* do our best to convert it to an index */
	if (str2int(in, (unsigned int *)&sp->pvp.pvn.u.isname.name.n) < 0) {
		LM_ERR("could not convert index to int!\n");
		return -1;
	}
	return 0;

}

static int pv_get_param(struct sip_msg *msg,  pv_param_t *ip, pv_value_t *res)
{
	if (!ip)
	{
		LM_ERR("null parameter received\n");
		return -1;
	}
	return route_params_run(msg, ip, res);
}

void destroy_argv_list(void)
{
	argv_p arg;

	while (argv_vars) {
		arg = argv_vars;
		argv_vars = argv_vars->next;
		pkg_free(arg);
	}
}
