/**
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <ctype.h>

#include "sr_module.h"
#include "dprint.h"
#include "error.h"
#include "mem/mem.h"
#include "xlog.h"

#include "pvar.h"
#include "trace_api.h"

#define XLOG_TRACE_API_MODULE "proto_hep"
#define XLOG_CORRELATION_MAGIC "XLOGCORR"



char *log_buf = NULL;

int xlog_buf_size = 4096;
int xlog_force_color = 0;
int xlog_default_level = L_ERR;

/* this variable is used by the xlog_level to print (inside an xlog)
 * the current logging level of that xlog() ; it has no meaning outside
 * the scope of an xlog() ! */
int xlog_level = INT_MAX;

/* id with which xlog will be identified by siptrace module
 * and will identify an xlog tracing packet */
int xlog_proto_id;
/* tracing module api */
static trace_proto_t tprot;


/* xlog string identifier */
static const char* xlog_id_s="xlog";

static int buf_init(void)
{
	LM_DBG("initializing...\n");
	log_buf = (char*)pkg_malloc((xlog_buf_size+1)*sizeof(char));
	if(log_buf==NULL)
	{
		LM_ERR("no pkg memory left\n");
		return -1;
	}
	return 0;
}

int init_xlog(void)
{
	if (log_buf == NULL) {
		if (buf_init()) {
			LM_ERR("Cannot print message!\n");
			return -1;
		}
	}

	if (register_trace_type)
		xlog_proto_id = register_trace_type((char *)xlog_id_s);

	memset(&tprot, 0, sizeof(trace_proto_t));
	if (global_trace_api) {
		memcpy(&tprot, global_trace_api, sizeof(trace_proto_t));
	} else {
		if (trace_prot_bind(XLOG_TRACE_API_MODULE, &tprot)) {
			LM_DBG("failed to load trace protocol!\n");
		}
	}


	return 0;
}


static inline void add_xlog_data(trace_message message, void* param)
{
	str str_level;
	xl_trace_t* xtrace_param = param;


	/* FIXME FIXME */
	switch (xlog_level) {
		case L_ALERT:
			str_level.s = DP_ALERT_TEXT; break;
		case L_CRIT:
			str_level.s = DP_CRIT_TEXT; break;
		case L_ERR:
			str_level.s = DP_ERR_TEXT; break;
		case L_WARN:
			str_level.s = DP_WARN_TEXT; break;
		case L_NOTICE:
			str_level.s = DP_NOTICE_TEXT; break;
		case L_INFO:
			str_level.s = DP_INFO_TEXT; break;
		case L_DBG:
			str_level.s = DP_DBG_TEXT;
			str_level.len = sizeof(DP_DBG_TEXT) - 2;
			break;
		default:
			LM_BUG("Unexpected log level [%d]\n", xlog_level);
			return;
	}

	/* remove ':' after each level */
	str_level.len = strlen(str_level.s) - 1;

	tprot.add_payload_part( message, "level", &str_level);

	if ( !xtrace_param )
		return;

	tprot.add_payload_part( message, "text", &xtrace_param->buf);

	tprot.add_extra_correlation( message, "sip", &xtrace_param->msg->callid->body );
}

static inline int trace_xlog(struct sip_msg* msg, char* buf, int len)
{
	struct modify_trace mod_p;

	xl_trace_t xtrace_param;

	const int proto = IPPROTO_TCP;

	if (msg == NULL || buf == NULL) {
		LM_ERR("bad input!\n");
		return -1;
	}

	/* xlog not traced; exit... */
	if (!check_is_traced || check_is_traced(xlog_proto_id) == 0)
		return 0;

	mod_p.mod_f = add_xlog_data;
	xtrace_param.msg = msg;

	xtrace_param.buf.s = buf;
	xtrace_param.buf.len = len;

	mod_p.param = &xtrace_param;

	if (sip_context_trace(xlog_proto_id, 0, 0,
				0, proto, &msg->callid->body, &mod_p) < 0) {
		LM_ERR("failed to trace xlog message!\n");
		return -1;
	}

	return 0;
}

int xl_print_log(struct sip_msg* msg, pv_elem_p list, int *len)
{
	if (pv_printf(msg, list, log_buf, len) < 0) {
		LM_ERR("failed to resolve xlog variables!\n");
		return -1;
	}

	if (trace_xlog(msg, log_buf, *len) < 0) {
		LM_ERR("failed to trace xlog message!\n");
		return -1;
	}

	return 0;
}


int xlog_2(struct sip_msg* msg, char* lev, char* frm)
{
	int log_len;
	long level;
	xl_level_p xlp;
	pv_value_t value;

	xlp = (xl_level_p)lev;
	if(xlp->type==1)
	{
		if(pv_get_spec_value(msg, &xlp->v.sp, &value)!=0
			|| value.flags&PV_VAL_NULL || !(value.flags&PV_VAL_INT))
		{
			LM_ERR("invalid log level value [%d]\n", value.flags);
			return -1;
		}
		level = (long)value.ri;
	} else {
		level = xlp->v.level;
	}

	if(!is_printable((int)level))
		return 1;

	log_len = xlog_buf_size;

	xlog_level = level;
	if(xl_print_log(msg, (pv_elem_t*)frm, &log_len)<0) {
		xlog_level = INT_MAX;
		return -1;
	}
	xlog_level = INT_MAX;

	/* log_buf[log_len] = '\0'; */
	LM_GEN1((int)level, "%.*s", log_len, log_buf);

	return 1;
}


int xlog_1(struct sip_msg* msg, char* frm, char* str2)
{
	int log_len;

	if(!is_printable(L_ERR))
		return 1;

	log_len = xlog_buf_size;

	xlog_level = xlog_default_level;
	if(xl_print_log(msg, (pv_elem_t*)frm, &log_len)<0) {
		xlog_level = INT_MAX;
		return -1;
	}
	xlog_level = INT_MAX;

	/* log_buf[log_len] = '\0'; */
	LM_GEN1(xlog_default_level, "%.*s", log_len, log_buf);

	return 1;
}

/**
 */
int xdbg(struct sip_msg* msg, char* frm, char* str2)
{
	int log_len;

	if(!is_printable(L_DBG))
		return 1;

	log_len = xlog_buf_size;

	xlog_level = L_DBG;
	if(xl_print_log(msg, (pv_elem_t*)frm, &log_len)<0) {
		xlog_level = INT_MAX;
		return -1;
	}
	xlog_level = INT_MAX;

	/* log_buf[log_len] = '\0'; */
	LM_GEN1(L_DBG, "%.*s", log_len, log_buf);

	return 1;
}

int pv_parse_color_name(pv_spec_p sp, str *in)
{

	if(in==NULL || in->s==NULL || sp==NULL)
		return -1;

	if(in->len != 2)
	{
		LM_ERR("color name must have two chars\n");
		return -1;
	}

	/* foreground */
	switch(in->s[0])
	{
		case 'x':
		case 's': case 'r': case 'g':
		case 'y': case 'b': case 'p':
		case 'c': case 'w': case 'S':
		case 'R': case 'G': case 'Y':
		case 'B': case 'P': case 'C':
		case 'W':
		break;
		default:
			goto error;
	}

	/* background */
	switch(in->s[1])
	{
		case 'x':
		case 's': case 'r': case 'g':
		case 'y': case 'b': case 'p':
		case 'c': case 'w':
		break;
		default:
			goto error;
	}

	sp->pvp.pvn.type = PV_NAME_INTSTR;
	sp->pvp.pvn.u.isname.type = AVP_NAME_STR;
	sp->pvp.pvn.u.isname.name.s = *in;

	sp->getf = pv_get_color;

	/* force the color PV type */
	sp->type = PVT_COLOR;
	return 0;
error:
	LM_ERR("invalid color name\n");
	return -1;
}

#define COL_BUF 10

#define append_sstring(p, end, s) \
        do{\
                if ((p)+(sizeof(s)-1)<=(end)){\
                        memcpy((p), s, sizeof(s)-1); \
                        (p)+=sizeof(s)-1; \
                }else{ \
                        /* overflow */ \
                        LM_ERR("append_sstring overflow\n"); \
                        goto error;\
                } \
        } while(0)


int pv_get_color(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res)
{
	static char color[COL_BUF];
	char* p;
	char* end;
	str s;

	if(log_stderr==0 && xlog_force_color==0)
	{
		s.s = "";
		s.len = 0;
		return pv_get_strval(msg, param, res, &s);
	}

	p = color;
	end = p + COL_BUF;

	/* excape sequenz */
	append_sstring(p, end, "\033[");

	if(param->pvn.u.isname.name.s.s[0]!='_')
	{
		if (islower((int)param->pvn.u.isname.name.s.s[0]))
		{
			/* normal font */
			append_sstring(p, end, "0;");
		} else {
			/* bold font */
			append_sstring(p, end, "1;");
			param->pvn.u.isname.name.s.s[0] += 32;
		}
	}

	/* foreground */
	switch(param->pvn.u.isname.name.s.s[0])
	{
		case 'x':
			append_sstring(p, end, "39;");
		break;
		case 's':
			append_sstring(p, end, "30;");
		break;
		case 'r':
			append_sstring(p, end, "31;");
		break;
		case 'g':
			append_sstring(p, end, "32;");
		break;
		case 'y':
			append_sstring(p, end, "33;");
		break;
		case 'b':
			append_sstring(p, end, "34;");
		break;
		case 'p':
			append_sstring(p, end, "35;");
		break;
		case 'c':
			append_sstring(p, end, "36;");
		break;
		case 'w':
			append_sstring(p, end, "37;");
		break;
		default:
			LM_ERR("invalid foreground\n");
			return pv_get_null(msg, param, res);
	}

	/* background */
	switch(param->pvn.u.isname.name.s.s[1])
	{
		case 'x':
			append_sstring(p, end, "49");
		break;
		case 's':
			append_sstring(p, end, "40");
		break;
		case 'r':
			append_sstring(p, end, "41");
		break;
		case 'g':
			append_sstring(p, end, "42");
		break;
		case 'y':
			append_sstring(p, end, "43");
		break;
		case 'b':
			append_sstring(p, end, "44");
		break;
		case 'p':
			append_sstring(p, end, "45");
		break;
		case 'c':
			append_sstring(p, end, "46");
		break;
		case 'w':
			append_sstring(p, end, "47");
		break;
		default:
			LM_ERR("invalid background\n");
			return pv_get_null(msg, param, res);
	}

	/* end */
	append_sstring(p, end, "m");

	s.s = color;
	s.len = p-color;
	return pv_get_strval(msg, param, res, &s);

error:
	return -1;
}

