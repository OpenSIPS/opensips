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
 *
 * History:
 * -------
 *  2003-02-28  scratchpad compatibility abandoned (jiri)
 *  2003-01-29: - rewriting actions (replace, search_append) now begin
 *                at the second line -- previously, they could affect
 *                first line too, which resulted in wrong calculation of
 *                forwarded requests and an error consequently
 *              - replace_all introduced
 *  2003-01-28  scratchpad removed (jiri)
 *  2003-01-18  append_urihf introduced (jiri)
 *  2003-03-10  module export interface updated to the new format (andrei)
 *  2003-03-16  flags export parameter added (janakj)
 *  2003-03-19  replaced all mallocs/frees w/ pkg_malloc/pkg_free (andrei)
 *  2003-04-97  actions permitted to be used from failure/reply routes (jiri)
 *  2003-04-21  remove_hf and is_present_hf introduced (jiri)
 *  2003-08-19  subst added (support for sed like res:s/re/repl/flags) (andrei)
 *  2003-08-20  subst_uri added (like above for uris) (andrei)
 *  2003-09-11  updated to new build_lump_rpl() interface (bogdan)
 *  2003-11-11: build_lump_rpl() removed, add_lump_rpl() has flags (bogdan)
 *  2004-05-09: append_time introduced (jiri)
 *  2004-07-06  subst_user added (like subst_uri but only for user) (sobomax)
 *  2004-11-12  subst_user changes (old serdev mails) (andrei)
 *  2005-07-05  is_method("name") to check method using id (ramona)
 *  2006-03-17  applied patch from Marc Haisenko <haisenko@comdasys.com>
 *              for adding has_body() function (bogdan)
 *  2009-07-23  added methods for sdp codec manipulation(andreidragus)
 *  2012-02-21  add change_reply_status (idea from kamailio/textopsx) (rpedraza)
 *
 */


#include "../../sr_module.h"
#include "../../action.h"
#include "../../dprint.h"
#include "../../data_lump.h"
#include "../../data_lump_rpl.h"
#include "../../error.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../str.h"
#include "../../re.h"
#include "../../ut.h"
#include "../../mod_fix.h"
#include "../../parser/parse_uri.h"
#include "../../parser/parse_allow.h"
#include "../../parser/parse_expires.h"
#include "../../parser/parse_event.h"
#include "../../parser/parse_hname2.h"
#include "../../parser/parse_methods.h"
#include "../../parser/parse_content.h"
#include "../../parser/parse_privacy.h"
#include "../../parser/parse_authenticate.h"
#include "../../parser/parse_supported.h"
#include "../../parser/parse_disposition.h"
#include "../../parser/parse_call_info.h"
#include "../../parser/parse_sst.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_rr.h"
#include "../../parser/sdp/sdp.h"
#include "../../parser/contact/parse_contact.h"
#include "../../parser/digest/digest.h"
#include "../../mod_fix.h"
#include "../../trim.h"

#include"codecs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h> /* for regex */
#include <regex.h>
#include <time.h>
#include <sys/time.h>
#include <fnmatch.h>


static str header_body = {0, 0};

/* RFC822-conforming dates format:

   %a -- abbreviated week of day name (locale), %d day of month
   as decimal number, %b abbreviated month name (locale), %Y
   year with century, %T time in 24h notation
   */
#define TIME_FORMAT "Date: %a, %d %b %Y %H:%M:%S GMT"
#define MAX_TIME 64

#define AUDIO_STR "audio"
#define AUDIO_STR_LEN 5

static int remove_hf_f(struct sip_msg* msg, char* str_hf, char* foo);
static int remove_hf_match_f(struct sip_msg* msg, char* pattern, char* foo);
static int is_present_hf_f(struct sip_msg* msg, char* str_hf, char* foo);
static int append_to_reply_f(struct sip_msg* msg, char* key, char* str);
static int append_hf_1(struct sip_msg* msg, char* str1, char* str2);
static int append_hf_2(struct sip_msg* msg, char* str1, char* str2);
static int insert_hf_1(struct sip_msg* msg, char* str1, char* str2);
static int insert_hf_2(struct sip_msg* msg, char* str1, char* str2);
static int append_urihf(struct sip_msg* msg, char* str1, char* str2);
static int append_time_f(struct sip_msg* msg, char* , char *);
static int is_method_f(struct sip_msg* msg, char* , char *);
static int has_body_f(struct sip_msg *msg, char *type, char *str2 );
static int is_privacy_f(struct sip_msg *msg, char *privacy, char *str2 );
static int remove_body_part_f(struct sip_msg *msg, char *str1, char *str2 );
static int add_body_part_f(struct sip_msg *msg, char *str1, char *str2 );
static int is_audio_on_hold_f(struct sip_msg *msg, char *str1, char *str2 );
static int w_sip_validate(struct sip_msg *msg, char *flags_s, char* pv_result);

static int hname_fixup(void** param, int param_no);
static int free_hname_fixup(void** param, int param_no);
static int hname_match_fixup(void** param, int param_no);
static int free_hname_match_fixup(void** param, int param_no);

static int fixup_method(void** param, int param_no);
static int add_header_fixup(void** param, int param_no);
static int fixup_body_type(void** param, int param_no);
static int fixup_privacy(void** param, int param_no);
static int fixup_sip_validate(void** param, int param_no);

static int change_reply_status_f(struct sip_msg*, char*, char *);
static int change_reply_status_fixup(void** param, int param_no);

static int mod_init(void);


static cmd_export_t cmds[]={
	{"append_to_reply",  (cmd_function)append_to_reply_f, 1,
		fixup_spve_null, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ERROR_ROUTE},
	{"append_hf",        (cmd_function)append_hf_1,       1,
		add_header_fixup, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"append_hf",        (cmd_function)append_hf_2,       2,
		add_header_fixup, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"insert_hf",        (cmd_function)insert_hf_1,       1,
		add_header_fixup, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"insert_hf",        (cmd_function)insert_hf_2,       2,
		add_header_fixup, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"append_urihf",     (cmd_function)append_urihf,      2,
		fixup_str_str, fixup_free_str_str,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE},
	{"remove_hf",        (cmd_function)remove_hf_f,       1,
		hname_fixup, free_hname_fixup,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"remove_hf",        (cmd_function)remove_hf_match_f,  2,
		hname_match_fixup, free_hname_match_fixup,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"is_present_hf",    (cmd_function)is_present_hf_f,   1,
		hname_fixup, free_hname_fixup,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"append_time",      (cmd_function)append_time_f,     0,
		0, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE },
	{"is_method",        (cmd_function)is_method_f,       1,
		fixup_method, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"has_body",         (cmd_function)has_body_f,        0,
		0, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"has_body_part",    (cmd_function)has_body_f,        0,
		0, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"has_body",         (cmd_function)has_body_f,        1,
		fixup_body_type, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"has_body_part",    (cmd_function)has_body_f,        1,
		fixup_body_type, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"is_privacy",       (cmd_function)is_privacy_f,      1,
		fixup_privacy, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"remove_body_part", (cmd_function)remove_body_part_f,0,
		0, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE },
	{"remove_body_part", (cmd_function)remove_body_part_f,1,
		fixup_body_type, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE },
	{"remove_body_part", (cmd_function)remove_body_part_f,2,
		fixup_body_type, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE },
	{"add_body_part",    (cmd_function)add_body_part_f,   2,
		add_header_fixup, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"codec_exists",	(cmd_function)codec_find,	1,
		fixup_codec,0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"codec_exists_re",	(cmd_function)codec_find_re,	1,
		fixup_codec_regexp, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"codec_exists",	(cmd_function)codec_find_clock,	2,
		fixup_codec,0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"codec_delete",	(cmd_function)codec_delete,	1,
		fixup_codec,0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"codec_delete_re",	(cmd_function)codec_delete_re,	1,
		fixup_codec_regexp, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"codec_delete_except_re",	(cmd_function)codec_delete_except_re,	1,
		fixup_codec_regexp, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"codec_delete",	(cmd_function)codec_delete_clock, 2,
		fixup_codec,0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"codec_move_up",	(cmd_function)codec_move_up, 1,
		fixup_codec,0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"codec_move_up_re",	(cmd_function)codec_move_up_re, 1,
		fixup_codec_regexp,0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"codec_move_up",	(cmd_function)codec_move_up_clock, 2,
		fixup_codec,0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"codec_move_down",	(cmd_function)codec_move_down,	1,
		fixup_codec,0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"codec_move_down_re",	(cmd_function)codec_move_down_re,	1,
		fixup_codec_regexp,0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"codec_move_down",	(cmd_function)codec_move_down_clock,	2,
		fixup_codec,0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"is_audio_on_hold",    (cmd_function)is_audio_on_hold_f,       0,
		0, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"sipmsg_validate",     (cmd_function)w_sip_validate,       0,
		0, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE},
	{"sipmsg_validate",     (cmd_function)w_sip_validate,       1,
		fixup_sip_validate, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE},
	{"sipmsg_validate",     (cmd_function)w_sip_validate,       2,
		fixup_sip_validate, 0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE},
	{"change_reply_status", (cmd_function)change_reply_status_f, 2,
		change_reply_status_fixup, 0, ONREPLY_ROUTE },
	{"stream_exists",	(cmd_function)stream_find,               1,
		fixup_regexp_dynamic_null,0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"stream_delete",	(cmd_function)stream_delete,             1,
		fixup_regexp_dynamic_null,0,
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{0,0,0,0,0,0}
};


struct module_exports exports= {
	"sipmsgops",  /* module name*/
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	NULL,            /* OpenSIPS module dependencies */
	cmds,       /* exported functions */
	0,          /* exported async functions */
	0,          /* module parameters */
	0,          /* exported statistics */
	0,          /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,			/* exported transformations */
	0,          /* extra processes */
	mod_init,   /* module initialization function */
	0,          /* response function */
	0,          /* destroy function */
	0,          /* per-child init function */
};


static int mod_init(void)
{
	LM_INFO("initializing...\n");
	return 0;
}


int get_pvs_header_value(struct sip_msg *msg, gparam_p gp, pv_value_p ret)
{
	struct hdr_field hdr;
	int hdr_len;

	if (fixup_get_svalue(msg, gp, &ret->rs) != 0) {
		LM_ERR("failed to get the string value\n");
		return -1;
	}

	hdr_len = ret->rs.len + 1;
	if (header_body.len < hdr_len)
	{
		header_body.s = pkg_realloc(header_body.s, hdr_len);
		if (!header_body.s)
		{
			LM_ERR("PKG MEMORY depleted!\n");
			return E_OUT_OF_MEM;
		}

		header_body.len = hdr_len;
	}

	memcpy(header_body.s, ret->rs.s, ret->rs.len);
	header_body.s[ret->rs.len] = ':';

	LM_DBG("Parsing %.*s\n", hdr_len, header_body.s);
	if (parse_hname2(header_body.s, header_body.s + hdr_len, &hdr) == 0)
	{
		LM_ERR("error parsing header name '%.*s'\n", ret->rs.len, ret->rs.s);
		return E_UNSPEC;
	}

	if (hdr.type != HDR_OTHER_T && hdr.type != HDR_ERROR_T)
	{
		LM_DBG("using hdr type (%d) instead of <%.*s>\n",
				hdr.type, ret->rs.len, ret->rs.s);
		ret->flags = PV_VAL_INT;
		ret->ri = hdr.type;
	}

	return 0;
}

static int hf_already_removed(struct sip_msg* msg, unsigned int offset,
		unsigned int len, enum _hdr_types_t type)
{
	struct lump *it;
	/* parse only the msg headers, not the body */
	for (it = msg->add_rm; it; it = it->next) {
		if (it->op == LUMP_DEL && it->type == type &&
				it->u.offset == offset && it->len == len)
			return 1;
	}
	return 0;
}

static int remove_hf_f(struct sip_msg* msg, char* str_hf, char* foo)
{
	struct hdr_field *hf;
	struct lump* l;
	int cnt;
	pv_value_t pval;

	cnt=0;

	pval.flags = PV_VAL_NONE;

	if (((gparam_p)str_hf)->type == GPARAM_TYPE_INT) {
		pval.flags = PV_VAL_INT;
		pval.ri = ((gparam_p)str_hf)->v.ival;
	} else if (get_pvs_header_value(msg, (gparam_p)str_hf, &pval) != 0) {
		LM_ERR("failed to get header value\n");
		return -1;
	}

	/* we need to be sure we have seen all HFs */
	if (parse_headers(msg, HDR_EOH_F, 0) < 0) {
		LM_ERR("cannot parse message!\n");
		return -1;
	}

	for (hf=msg->headers; hf; hf=hf->next) {
		/* for well known header names str_hf->s will be set to NULL
		   during parsing of opensips.cfg and str_hf->len contains
		   the header type */
		if (pval.flags & PV_VAL_INT)
		{
			if (pval.ri != hf->type)
				continue;
		} else {
			if (hf->type != HDR_OTHER_T)
				continue;
			if (hf->name.len != pval.rs.len)
				continue;
			if (strncasecmp(hf->name.s, pval.rs.s, hf->name.len) != 0)
				continue;
		}
		/* check to see if the header was already removed */
		if (hf_already_removed(msg, hf->name.s-msg->buf, hf->len,
					hf->type))
			continue;
		l=del_lump(msg, hf->name.s-msg->buf, hf->len, hf->type);
		if (l==0) {
			LM_ERR("no memory\n");
			return -1;
		}
		cnt++;
	}
	return cnt==0 ? -1 : 1;
}


static int remove_hf_match_f(struct sip_msg* msg, char* pattern, char* regex_or_glob)
{
	struct hdr_field *hf;
	struct lump* l;
	int cnt;
	str* pat = (str*)pattern;
	regex_t* re = (regex_t*)pattern;
	char matchtype = *regex_or_glob;
	regmatch_t pmatch;
	char tmp;

	cnt=0;

	/* we need to be sure we have seen all HFs */
	if (parse_headers(msg, HDR_EOH_F, 0)!=0) {
		LM_ERR("failed to parse SIP message\n");
		return -1;
	}
	for (hf=msg->headers; hf; hf=hf->next) {
		tmp = *(hf->name.s+hf->name.len);
		*(hf->name.s+hf->name.len) = 0;
		if( matchtype == 'g' ) { /* GLOB */
			if(fnmatch(pat->s, hf->name.s, 0) !=0 ){
				*(hf->name.s+hf->name.len) = tmp;
				continue;
			}
		} else if( matchtype == 'r' ){ /* REGEX */
			if(regexec(re, hf->name.s, 1, &pmatch, 0)!=0){
				*(hf->name.s+hf->name.len) = tmp;
				continue;
			}
		} else {
			LM_ERR("Unknown match type. Supported types are r (regex) and g (glob)");
			return -1;
		}
		*(hf->name.s+hf->name.len) = tmp;

		/* check to see if the header was already removed */
		if (hf_already_removed(msg, hf->name.s-msg->buf, hf->len,
					hf->type))
			continue;
		l=del_lump(msg, hf->name.s-msg->buf, hf->len, hf->type);
		if (l==0) {
			LM_ERR("no memory\n");
			return -1;
		}
		cnt++;
	}
	return cnt==0 ? -1 : 1;
}


static int is_present_hf_f(struct sip_msg* msg, char* str_hf, char* foo)
{
	struct hdr_field *hf;
	pv_value_t pval;

	memset(&pval, '\0', sizeof pval);

	if (((gparam_p)str_hf)->type == GPARAM_TYPE_INT) {
		pval.flags = PV_VAL_INT;
		pval.ri = ((gparam_p)str_hf)->v.ival;
	} else if (get_pvs_header_value(msg, (gparam_p)str_hf, &pval) != 0) {
		LM_ERR("failed to get header value\n");
		return -1;
	}

	/* we need to be sure we have seen all HFs */
	if (parse_headers(msg, HDR_EOH_F, 0) < 0) {
		LM_ERR("cannot parse message!\n");
		return -1;
	}

	if (pval.flags & PV_VAL_INT) {
		for (hf=msg->headers; hf; hf=hf->next)
			if (pval.ri == hf->type)
				return 1;
	} else {
		for (hf=msg->headers; hf; hf=hf->next)
			if (hf->type == HDR_OTHER_T &&
				hf->name.len == pval.rs.len &&
				strncasecmp(hf->name.s, pval.rs.s, hf->name.len) == 0)
				return 1;
	}

	LM_DBG("header '%.*s'(%d) not found\n", pval.rs.len, pval.rs.s, pval.ri);

	return -1;
}


static int append_time_f(struct sip_msg* msg, char* p1, char *p2)
{


	size_t len;
	char time_str[MAX_TIME];
	time_t now;
	struct tm *bd_time;

	now=time(0);

	bd_time=gmtime(&now);
	if (bd_time==NULL) {
		LM_ERR("gmtime failed\n");
		return -1;
	}

	len=strftime(time_str, MAX_TIME, TIME_FORMAT, bd_time);
	if (len>MAX_TIME-2 || len==0) {
		LM_ERR("unexpected time length\n");
		return -1;
	}

	time_str[len]='\r';
	time_str[len+1]='\n';


	if (add_lump_rpl(msg, time_str, len+2, LUMP_RPL_HDR)==0)
	{
		LM_ERR("unable to add lump\n");
		return -1;
	}

	return 1;
}


static int append_to_reply_f(struct sip_msg* msg, char* key, char* str0)
{
	str s0;

	if(key==NULL)
	{
		LM_ERR("bad parameters\n");
		return -1;
	}

	if(fixup_get_svalue(msg, (gparam_p)key, &s0)!=0)
	{
		LM_ERR("cannot print the format\n");
		return -1;
	}

	if ( add_lump_rpl( msg, s0.s, s0.len, LUMP_RPL_HDR)==0 )
	{
		LM_ERR("unable to add lump_rl\n");
		return -1;
	}

	return 1;
}


/* add str1 to end of header or str1.r-uri.str2 */

static int add_hf_helper(struct sip_msg* msg, str *str1, str *str2,
		gparam_p hfval, int mode, gparam_p hfanc)
{
	struct lump* anchor;
	struct hdr_field *hf;
	char *s;
	int len;
	str s0;

	if (parse_headers(msg, HDR_EOH_F, 0) == -1) {
		LM_ERR("error while parsing message\n");
		return -1;
	}

	hf = 0;
	if(hfanc!=NULL) {
		for (hf=msg->headers; hf; hf=hf->next) {
			if(hfanc->type==GPARAM_TYPE_INT)
			{
				if (hfanc->v.ival!=hf->type)
					continue;
			} else {
				if (hf->type!=HDR_OTHER_T)
					continue;
				if (hf->name.len!=hfanc->v.sval.len)
					continue;
				if (strncasecmp(hf->name.s,hfanc->v.sval.s,hf->name.len)!=0)
					continue;
			}
			break;
		}
	}

	if(mode == 0) { /* append */
		if(hf==0) { /* after last header */
			anchor = anchor_lump(msg, msg->unparsed - msg->buf, 0);
		} else { /* after hf */
			anchor = anchor_lump(msg, hf->name.s + hf->len - msg->buf, 0);
		}
	} else { /* insert */
		if(hf==0) { /* before first header */
			anchor = anchor_lump(msg, msg->headers->name.s - msg->buf, 0);
		} else { /* before hf */
			anchor = anchor_lump(msg, hf->name.s - msg->buf, 0);
		}
	}

	if(anchor == 0) {
		LM_ERR("can't get anchor\n");
		return -1;
	}

	if(str1) {
		s0 = *str1;
	} else {
		if(hfval) {
			if(fixup_get_svalue(msg, hfval, &s0)!=0)
			{
				LM_ERR("cannot print the format\n");
				return -1;
			}
		} else {
			s0.len = 0;
			s0.s   = 0;
		}
	}

	len=s0.len;
	if (str2) len+= str2->len + REQ_LINE(msg).uri.len;

	s = (char*)pkg_malloc(len);
	if (!s) {
		LM_ERR("no pkg memory left\n");
		return -1;
	}

	memcpy(s, s0.s, s0.len);
	if (str2) {
		memcpy(s+s0.len, REQ_LINE(msg).uri.s, REQ_LINE(msg).uri.len);
		memcpy(s+s0.len+REQ_LINE(msg).uri.len, str2->s, str2->len );
	}

	if (insert_new_lump_before(anchor, s, len, 0) == 0) {
		LM_ERR("can't insert lump\n");
		pkg_free(s);
		return -1;
	}
	return 1;
}

static int append_hf_1(struct sip_msg *msg, char *str1, char *str2 )
{
	return add_hf_helper(msg, 0, 0, (gparam_p)str1, 0, 0);
}

static int append_hf_2(struct sip_msg *msg, char *str1, char *str2 )
{
	return add_hf_helper(msg, 0, 0, (gparam_p)str1, 0,
			(gparam_p)str2);
}

static int insert_hf_1(struct sip_msg *msg, char *str1, char *str2 )
{
	return add_hf_helper(msg, 0, 0, (gparam_p)str1, 1, 0);
}

static int insert_hf_2(struct sip_msg *msg, char *str1, char *str2 )
{
	return add_hf_helper(msg, 0, 0, (gparam_p)str1, 1,
			(gparam_p)str2);
}

static int append_urihf(struct sip_msg *msg, char *str1, char *str2)
{
	return add_hf_helper(msg, (str*)str1, (str*)str2, 0, 0, 0);
}

static int is_method_f(struct sip_msg *msg, char *meth, char *str2 )
{
	str *m;

	m = (str*)meth;
	if(msg->first_line.type==SIP_REQUEST)
	{
		if(m->s==0)
			return (msg->first_line.u.request.method_value&m->len)?1:-1;
		else
			return (msg->first_line.u.request.method_value==METHOD_OTHER
					&& msg->first_line.u.request.method.len==m->len
					&& (strncasecmp(msg->first_line.u.request.method.s, m->s,
							m->len)==0))?1:-1;
	}
	if(parse_headers(msg, HDR_CSEQ_F, 0)!=0 || msg->cseq==NULL)
	{
		LM_ERR("cannot parse cseq header\n");
		return -1; /* should it be 0 ?!?! */
	}
	if(m->s==0)
		return (get_cseq(msg)->method_id&m->len)?1:-1;
	else
		return (get_cseq(msg)->method_id==METHOD_OTHER
				&& get_cseq(msg)->method.len==m->len
				&& (strncasecmp(get_cseq(msg)->method.s, m->s,
						m->len)==0))?1:-1;
}


/*
 * Convert char* header_name to str* parameter
 */
static int hname_fixup(void** param, int param_no)
{
	char *c;
	int len;
	struct hdr_field hdr;
	gparam_p gp = NULL;

	if (fixup_sgp(param) != 0)
	{
		LM_ERR("Fixup failed!\n");
		return E_UNSPEC;
	}

	gp = (gparam_p)*param;

	if (gp->type == GPARAM_TYPE_STR)
	{
		/* parse_hname2() accepts a minimum 4 bytes len buffer
		 * for parsing, so whatever is the len of the header name,
		 * fill it up to 4 */
		len = (gp->v.sval.len<3) ? (4) : (gp->v.sval.len+1) ;
		c = pkg_malloc( len );
		if (!c)
			return E_OUT_OF_MEM;

		memcpy(c, gp->v.sval.s, gp->v.sval.len);
		c[gp->v.sval.len] = ':';

		if (parse_hname2(c, c + len, &hdr) == 0)
		{
			LM_ERR("error parsing header name\n");
			return E_UNSPEC;
		}

		pkg_free(c);

		if (hdr.type != HDR_OTHER_T && hdr.type != HDR_ERROR_T)
		{
			LM_DBG("using hdr type (%d) instead of <%.*s>\n",
					hdr.type, gp->v.sval.len, gp->v.sval.s);

			gp->type = GPARAM_TYPE_INT;
			gp->v.ival = hdr.type;
		}
	}

	return 0;
}

static int free_hname_fixup(void** param, int param_no)
{
	if(*param)
	{
		if(((gparam_p)(*param))->type==GPARAM_TYPE_STR)
			pkg_free(((gparam_p)(*param))->v.sval.s);
		pkg_free(*param);
		*param = 0;
	}
	return 0;
}

static int hname_match_fixup(void** param, int param_no)
{
	char * type_param = NULL;
	char * type_str = NULL;
	char type = 0;
	char * matchstr = *(char**)param;

	if(param_no == 1){
		if(strlen(matchstr)==0){
			LM_ERR("Empty match string parameter.\n");
			return E_UNSPEC;
		}
		type_param = ((char*)param)+sizeof(action_elem_t);
		if(!type_param){
			LM_ERR("Unable to fetch the 2nd parameter\n");
			return E_UNSPEC;
		}

		type_str = *((char**)type_param);
		if(!type_str){
			LM_ERR("Unable to access 2nd parameter value\n");
			return E_UNSPEC;
		}
		type = *type_str;
		if(type == 'r'){
			/* regex fixup code here */
			LM_DBG("processing param1: %s as regex\n", *(char**)param);
			fixup_regexp_null(param, param_no);
		}else if(type == 'g'){
			/* glob fixup code here */
			LM_DBG("processing param1: %s as glob\n", *(char**)param);
			fixup_str(param);
		}else{
			LM_ERR("unknown match type '%c'\n", type);
			return E_UNSPEC;
		}
	}
	return 0;
}


static int free_hname_match_fixup(void** param, int param_no)
{
	char * type_param = NULL;
	char * type_str = NULL;
	char type = 0;

	if(param_no == 1){
		type_param = ((char*)param)+sizeof(action_elem_t);
		if(!type_param){
			LM_ERR("Unable to fetch the 2nd parameter\n");
			return E_UNSPEC;
		}
		type_str = *((char**)type_param);
		if(!type_str){
			LM_ERR("Unable to access 2nd parameter value\n");
			return E_UNSPEC;
		}
		type = *type_str;
		if(type == 'r'){
			/* regex fixup code here */
			LM_DBG("Freeing regexp\n");
			fixup_free_regexp_null(param, param_no);
		}else if(type == 'g'){
			/* glob fixup code here */
			LM_DBG("Freeing glob\n");
			fixup_free_str_str(param, param_no);
		}else{
			LM_ERR("unknown match type in free_hname_match_fixup. Please notify a developer.\n");
		}
	}

	return 0;
}

/*
 * Convert char* method to str* parameter
 */
static int fixup_method(void** param, int param_no)
{
	str* s;
	char *p;
	int m;
	unsigned int method;

	s = (str*)pkg_malloc(sizeof(str));
	if (!s) {
		LM_ERR("no pkg memory left\n");
		return E_UNSPEC;
	}

	s->s = (char*)*param;
	s->len = strlen(s->s);
	if(s->len==0)
	{
		LM_ERR("empty method name\n");
		pkg_free(s);
		return E_UNSPEC;
	}
	m=0;
	p=s->s;
	while(*p)
	{
		if(*p=='|')
		{
			*p = ',';
			m=1;
		}
		p++;
	}
	if(parse_methods(s, &method)!=0)
	{
		LM_ERR("bad method names\n");
		pkg_free(s);
		return E_UNSPEC;
	}

	if(m==1)
	{
		if(method==METHOD_UNDEF || method&METHOD_OTHER)
		{
			LM_ERR("unknown method in list [%.*s/%d] - must be only defined methods\n",
					s->len, s->s, method);
			return E_UNSPEC;
		}
		LM_DBG("using id for methods [%.*s/%d]\n",
				s->len, s->s, method);
		s->s = 0;
		s->len = method;
	} else {
		if(method!=METHOD_UNDEF && method!=METHOD_OTHER)
		{
			LM_DBG("using id for method [%.*s/%d]\n",
					s->len, s->s, method);
			s->s = 0;
			s->len = method;
		} else
			LM_DBG("name for method [%.*s/%d]\n",
					s->len, s->s, method);
	}

	*param = (void*)s;
	return 0;
}

/*
 * Convert char* privacy value to corresponding bit value
 */
static int fixup_privacy(void** param, int param_no)
{
	str p;
	unsigned int val;

	p.s = (char*)*param;
	p.len = strlen(p.s);

	if (p.len == 0) {
		LM_ERR("empty privacy value\n");
		return E_UNSPEC;
	}

	if (parse_priv_value(p.s, p.len, &val) != p.len) {
		LM_ERR("invalid privacy value\n");
		return E_UNSPEC;
	}

	*param = (void *)(long)val;
	return 0;
}

static int add_header_fixup(void** param, int param_no)
{
	if(param_no==1)
	{
		return fixup_spve_null(param, param_no);
	} else if(param_no==2) {
		return hname_fixup(param, param_no);
	} else {
		LM_ERR("wrong number of parameters\n");
		return E_UNSPEC;
	}
}


static int fixup_body_type(void** param, int param_no)
{
	char *p;
	char *r;
	unsigned int type;

	if(param_no==1) {
		p = (char*)*param;
		if (p==0 || p[0]==0) {
			type = 0;
		} else {
			r = decode_mime_type( p, p+strlen(p) , &type , NULL);
			if (r==0) {
				LM_ERR("unsupported mime <%s>\n",p);
				return E_CFG;
			}
			if ( r!=p+strlen(p) ) {
				LM_ERR("multiple mimes not supported!\n");
				return E_CFG;
			}
		}
		pkg_free(*param);
		*param = (void*)(long)type;
	} else if(param_no==2) {
		/* only by remove_body_part() */
		p = (char*)*param;
		if (p && strcmp(p,"revert")==0) {
			pkg_free(*param);
			*param = (void*)(long)1;
		} else {
			pkg_free(*param);
			*param = (void*)(long)0;
		}
	}
	return 0;

}


static int has_body_f(struct sip_msg *msg, char *type, char *str2 )
{
	struct body_part * p;

	if ( msg->content_length==NULL &&
	(parse_headers(msg,HDR_CONTENTLENGTH_F, 0)==-1||msg->content_length==NULL))
		return -1;

	if (get_content_length (msg)==0) {
		LM_DBG("content length is zero\n");
		/* Nothing to see here, please move on. */
		return -1;
	}

	if( ( ((int)(long)type )>>16) == TYPE_MULTIPART )
	{
		int mime = parse_content_type_hdr(msg);

		if( mime == ((int)(long)type ) )
			return 1;

		return -1;
	}

	/* check type also? */
	if (type==0)
		return 1;

	if (parse_sip_body(msg)<0 || msg->body==NULL) {
		LM_DBG("no body found\n");
		return -1;
	}

	p = &msg->body->first;
	while (p)
	{
		if( p->mime == ((int)(long)type ) )
			return 1;
		p = p->next;
	}

	return -1;
}


static int is_privacy_f(struct sip_msg *msg, char *_privacy, char *str2 )
{
	if (parse_privacy(msg) == -1)
		return -1;

	return get_privacy_values(msg) & ((unsigned int)(long)_privacy) ? 1 : -1;

}


static int remove_body_part_f(struct sip_msg *msg, char *type, char *revert )
{
	struct sip_msg_body * b;
	struct body_part * p;
	int deleted = 0;

	if (parse_sip_body(msg)<0 || (b=msg->body)==NULL) {
		LM_DBG("no body found\n");
		return -1;
	}

	p = &b->first;
	deleted = -1;

	for ( p=&b->first ; p ; p=p->next) {

		if ( (type==NULL) || ( !revert && (p->mime==((int)(long)type)) )
		|| ( revert && (p->mime!=((int)(long)type)) ) ) {
			delete_body_part( msg, p);
			deleted =  1;
		}

	}

	return deleted;
}

/*
 *	Function to add a new body
 * */
static int add_body_part_f(struct sip_msg *msg, char *nbody, char *ctype )
{
	str body;
	str mime;

	if(fixup_get_svalue(msg, (gparam_p)nbody, &body)!=0) {
		LM_ERR("cannot print the format\n");
		return -1;
	}

	if(body.s== NULL || body.len == 0) {
		LM_ERR("null body parameter\n");
		return -1;
	}

	if(fixup_get_svalue(msg, (gparam_p)ctype, &mime)!=0) {
		LM_ERR("cannot print the mime string\n");
		return -1;
	}

	if(mime.s== NULL || mime.len == 0) {
		LM_ERR("empty mime value\n");
		return -1;
	}

	if (add_body_part(msg, &mime, &body)==NULL) {
		LM_ERR("failed to add new body part <%.*s>\n",
			mime.len, mime.s);
		return -1;
	}

	return 1;
}


static int is_audio_on_hold_f(struct sip_msg *msg, char *str1, char *str2 )
{
	int sdp_session_num = 0, sdp_stream_num;
	sdp_session_cell_t* sdp_session;
	sdp_stream_cell_t* sdp_stream;
	sdp_info_t* sdp;

	if ( (sdp=parse_sdp(msg))!=NULL ) {
		for(;;) {
			sdp_session = get_sdp_session(sdp, sdp_session_num);
			if(!sdp_session) break;
			sdp_stream_num = 0;
			for(;;) {
				sdp_stream = get_sdp_stream(sdp, sdp_session_num,
					sdp_stream_num);
				if(!sdp_stream) break;
				if(sdp_stream->media.len==AUDIO_STR_LEN &&
						strncmp(sdp_stream->media.s,AUDIO_STR,AUDIO_STR_LEN)==0 &&
						sdp_stream->is_on_hold)
					return 1;
				sdp_stream_num++;
			}
			sdp_session_num++;
		}
	}
	return -1;
}


#define SIP_PARSE_SDP	0x1
#define SIP_PARSE_HDR	0x2
#define SIP_PARSE_NOMF	0x4
#define SIP_PARSE_RURI	0x8
#define SIP_PARSE_TO 0x10
#define SIP_PARSE_FROM 0x20
#define SIP_PARSE_CONTACT 0x40

static int fixup_sip_validate(void** param, int param_no)
{
	char *flags_s, *end;
	unsigned long flags = 0;
	pv_elem_t *pvar;
	str s;

	if (param_no==1) {
		if (!param)
			return -1;
		flags_s = (char*)*param;
		end = flags_s + strlen(flags_s);

		for ( ; flags_s < end; flags_s++) {
			switch (*flags_s) {
				case 's':
				case 'S':
					flags |= SIP_PARSE_SDP;
					break;

				case 'h':
				case 'H':
					flags |= SIP_PARSE_HDR;
					break;

				case 'm':
				case 'M':
					flags |= SIP_PARSE_NOMF;
					break;

				case 'r':
				case 'R':
					flags |= SIP_PARSE_RURI;
					break;

				case 't':
				case 'T':
					flags |= SIP_PARSE_TO;
					break;

				case 'f':
				case 'F':
					flags |= SIP_PARSE_FROM;
					break;

				case 'c':
				case 'C':
					flags |= SIP_PARSE_CONTACT;
					break;

				default:
					LM_DBG("unknown option \'%c\'\n", *flags_s);
					break;
			}
		}
		*param = (void *)(unsigned long)flags;
		return 0;
	} else if (param_no==2) {
		s.s = (char*)(*param);
		s.len = strlen(s.s);
		if (pv_parse_format(&s, &pvar)<0)
		{
			LM_ERR( "wrong format[%s]\n",(char*)(*param));
			return E_UNSPEC;
		}
		*param = (void*)pvar;
		return 0;
	} else {
		LM_ERR("invalid parameter number %d\n", param_no);
		return E_UNSPEC;
	}
}

static int sip_validate_hdrs(struct sip_msg *msg)
{
	struct disposition *disp;
	struct hdr_field* hf;
	struct to_body *to;
	content_t * cont;
	struct via_body *via_b;
	str str_aux;
	char *s_aux, *e_aux;
	unsigned u_aux;
	int i_aux;

#define CHECK_HDR_EMPTY() \
	do { \
		str_aux = hf->body; \
		trim_len( str_aux.len , str_aux.s , hf->body ); \
		if (str_aux.len <= 0) { \
			LM_DBG("header '%.*s' has invalid value %d\n", \
					hf->name.len, hf->name.s, str_aux.len); \
			goto failed; \
		} \
	} while (0)

#define CHECK_HDR_FUNC(_f, _o) \
	do { \
		if (_f(_o) < 0) { \
			LM_DBG("cannot parse '%.*s' header\n", \
					hf->name.len, hf->name.s); \
			goto failed; \
		} \
	} while (0)

	/* skip via, cseq, to and content length
	 * = we can be sure that they have been properly parsed =
	 * = because otherwise the code wouldn't reach here =
	 * = but in 'parse_msg'*/

	for (hf = msg->headers; hf; hf = hf->next) {
		/* try to eliminate errors fast */
		if (hf->type == HDR_ERROR_T) {
			LM_DBG("header %.*s could not be properly parsed\n",
					hf->name.len, hf->name.s);
			goto failed;
		}
		/* was successfully parsed previously */
		if (hf->parsed)
			continue;

		/* try to manually parse them */
		switch (hf->type) {
			case HDR_CONTENTTYPE_T:
				if (!(cont = pkg_malloc(sizeof (content_t)))) {
					LM_ERR("Unable to allocate memory\n");
					goto failed;
				}
				memset(cont, 0, sizeof (content_t));

				/* it seams we have to parse it! :-( */
				e_aux = hf->body.s + hf->body.len;
				if ((s_aux = decode_mime_type(hf->body.s, e_aux ,
								&u_aux, cont)) == 0) {
					pkg_free(cont);
					goto failed;
				}
				if (e_aux != s_aux) {
					LM_DBG("the header CONTENT_TYPE contains "
							"more than one mime type :-(!\n");
					pkg_free(cont);
					goto failed;
				}
				if ((u_aux&0x00ff)==SUBTYPE_ALL || (u_aux>>16)==TYPE_ALL) {
					LM_DBG("invalid mime with wildcard '*'"
							" in Content-Type hdr!\n");
					pkg_free(cont);
					goto failed;
				}
				cont->type = u_aux;
				hf->parsed = cont;
				break;

			case HDR_VIA2_T:
				via_b=pkg_malloc(sizeof(struct via_body));
				if (!via_b) {
					LM_ERR("out of pkg memory\n");
					goto failed;
				}
				memset(via_b, 0, sizeof(struct via_body));
				e_aux = parse_via(hf->body.s,
						hf->body.s + hf->body.len, via_b);
				if (via_b->error==PARSE_ERROR){
					LM_DBG("bad via header\n");
					free_via_list(via_b);
					goto failed;
				}
				via_b->hdr.s = hf->name.s;
				via_b->hdr.len = hf->name.len;
				hf->parsed = via_b;
				break;

			case HDR_CONTENTDISPOSITION_T:
				if (!(disp = (struct disposition*)
							pkg_malloc(sizeof(struct disposition)))) {
					LM_ERR("no more pkg memory\n");
					goto failed;
				}
				memset(disp, 0, sizeof(struct disposition));

				if (parse_disposition(&(hf->body), disp)<0) {
					free_disposition(&disp);
					LM_DBG("cannot parse disposition\n");
					goto failed;
				}
				/* even if success, we need to free the parsed disposition
				   hdr as it is not linked anywhere */
				free_disposition(&disp);
				break;

				/* to-style headers */
			case HDR_FROM_T:
			case HDR_PPI_T:
			case HDR_PAI_T:
			case HDR_RPID_T:
			case HDR_REFER_TO_T:
			case HDR_DIVERSION_T:
				/* these are similar */
				if (!(to = pkg_malloc(sizeof(struct to_body)))) {
					LM_ERR("out of pkg_memory\n");
					goto failed;
				}
				parse_to(hf->body.s,  hf->body.s + hf->body.len + 1, to);
				if (to->error == PARSE_ERROR) {
					LM_DBG("bad '%.*s' header\n",
							hf->name.len, hf->name.s);
					pkg_free(to);
					goto failed;
				}
				hf->parsed = to;
				break;

			case HDR_MAXFORWARDS_T:
				CHECK_HDR_EMPTY();
				/* should be a number */
				u_aux = str2s(str_aux.s, str_aux.len, &i_aux);
				if (i_aux) {
					LM_DBG("invalid body number in '%.*s'\n",
							hf->name.len, hf->name.s);
					goto failed;
				}
				hf->parsed = (void*)(unsigned long)u_aux;
				break;

			case HDR_SUPPORTED_T:
				CHECK_HDR_FUNC(parse_supported, msg);
				break;

			case HDR_ACCEPT_T:
				CHECK_HDR_FUNC(parse_accept_hdr, msg);
				break;

			case HDR_PRIVACY_T:
				CHECK_HDR_FUNC(parse_privacy, msg);
				break;

			case HDR_CONTACT_T:
				CHECK_HDR_FUNC(parse_contact, hf);
				break;

			case HDR_PATH_T:
			case HDR_ROUTE_T:
			case HDR_RECORDROUTE_T:
				CHECK_HDR_FUNC(parse_rr, hf);
				break;

			case HDR_AUTHORIZATION_T:
			case HDR_PROXYAUTH_T:
				CHECK_HDR_FUNC(parse_credentials, hf);
				break;

			case HDR_EXPIRES_T:
				CHECK_HDR_FUNC(parse_expires, hf);
				break;

			case HDR_ALLOW_T:
				CHECK_HDR_FUNC(parse_allow, msg);
				break;

			case HDR_EVENT_T:
				CHECK_HDR_FUNC(parse_event, hf);
				break;

			case HDR_SESSION_EXPIRES_T:
				CHECK_HDR_FUNC(parse_session_expires_body, hf);
				break;

			case HDR_CALL_INFO_T:
				CHECK_HDR_FUNC(parse_call_info_header, msg);
				break;

			case HDR_MIN_SE_T:
			case HDR_MIN_EXPIRES_T:
				CHECK_HDR_FUNC(parse_min_se_body, hf);
				break;

			case HDR_PROXY_AUTHENTICATE_T:
			case HDR_WWW_AUTHENTICATE_T:
				CHECK_HDR_FUNC(parse_authenticate_header, hf);
				break;

			case HDR_CALLID_T:
			case HDR_PROXYREQUIRE_T:
			case HDR_UNSUPPORTED_T:
			case HDR_ACCEPTLANGUAGE_T:
			case HDR_ORGANIZATION_T:
			case HDR_PRIORITY_T:
			case HDR_SUBJECT_T:
			case HDR_USERAGENT_T:
			case HDR_ACCEPTDISPOSITION_T:
			case HDR_RETRY_AFTER_T:
				/* headers that must have body */
				CHECK_HDR_EMPTY();
				break;

			case HDR_ERROR_T:
				LM_DBG("[BUG] this can't be possible\n");
				goto failed;

			case HDR_VIA1_T:
			case HDR_TO_T:
			case HDR_CSEQ_T:
			case HDR_CONTENTLENGTH_T:
			case HDR_EOH_T:
				LM_DBG("duplicate header \'%.*s\'\n",
						hf->name.len, hf->name.s);
			case HDR_OTHER_T:
			default:
				/* unknown or already parsed */
				break;
		}
	}

	return 0;
failed:
	return -1;
}

#define IS_ALPHANUM(_c) ( \
		((_c) >= 'a' && (_c) <= 'z') || \
		((_c) >= 'A' && (_c) <= 'Z') || \
		((_c) >= '0' && (_c) <= '9') )

static int check_hostname(str *domain)
{
	char *p, *end;

	if (!domain || domain->len < 0) {
		LM_DBG("inexistent domain\n");
		return -1;
	}

	/* always starts with a ALPHANUM */
	if (!IS_ALPHANUM(domain->s[0])) {
		LM_DBG("invalid starting character in domain: %c[%d]\n", domain->s[0], domain->s[0]);
		return -1;
	}

	/* check the last character separately, as it cannot contain '-' */
	end = domain->s + domain->len - 1;

	for (p = domain->s + 1; p < end; p++) {
		if (!IS_ALPHANUM(*p) && (*p != '-')) {
			if (*p != '.') {
				LM_DBG("invalid character in hostname: %c[%d]\n", *p, *p);
				return -1;
			} else if (*(p - 1) == '.') {
				LM_DBG("two consecutive '.' are not allowed in hostname\n");
				return -1;
			}
		}
	}

	/* check if the last character is a '-' */
	if (!IS_ALPHANUM(*end) && (*end != '.')) {
		LM_DBG("invalid character at the end of the domain: %c[%d]\n", *end, *end);
		return -1;
	}
	return 0;

}

#undef IS_ALPHANUM

#define CHECK_HEADER(_m, _h) \
	do { \
		if (!msg->_h) { \
			LM_DBG( _m " doesn't have " #_h " header\n"); \
			goto failed; \
		} \
	} while (0)

#define MAX_REASON 256

enum sip_validation_failures {
	SV_NO_MSG=-1,
	SV_HDR_PARSE_ERROR=-2,
	SV_NO_CALLID=-3,
	SV_NO_CONTENT_LENGTH=-4,
	SV_INVALID_CONTENT_LENGTH=-5,
	SV_PARSE_SDP=-6,
	SV_NO_CSEQ=-7,
	SV_NO_FROM=-8,
	SV_NO_TO=-9,
	SV_NO_VIA1=-10,
	SV_RURI_PARSE_ERROR=-11,
	SV_BAD_HOSTNAME=-12,
	SV_NO_MF=-13,
	SV_NO_CONTACT=-14,
	SV_PATH_NONREGISTER=-15,
	SV_NOALLOW_405=-16,
	SV_NOMINEXP_423=-17,
	SV_NO_PROXY_AUTH=-18,
	SV_NO_UNSUPPORTED=-19,
	SV_NO_WWW_AUTH=-20,
	SV_NO_CONTENT_TYPE=-21,
	SV_TO_PARSE_ERROR=-22,
	SV_TO_DOMAIN_ERROR=-23,
	SV_FROM_PARSE_ERROR=-24,
	SV_FROM_DOMAIN_ERROR=-25,
	SV_CONTACT_PARSE_ERROR=-26,
	SV_GENERIC_FAILURE=-255
};

static int w_sip_validate(struct sip_msg *msg, char *flags_s, char* pv_result)
{
	unsigned int hdrs_len;
	int method;
	str body;
	struct hdr_field * ptr;
	contact_t * contacts;
	struct sip_uri test_contacts;
	struct cseq_body * cbody;
	struct to_body *from, *to;
	unsigned long flags;
	pv_elem_t* pv_res = (pv_elem_t*)pv_result;
	pv_value_t pv_val;
	char reason[MAX_REASON];
	int ret = -SV_GENERIC_FAILURE;

	if (!msg) {
		strcpy(reason, "no message object");
		ret = SV_NO_MSG;
		goto failed;
	}

	/* try to check the whole SIP msg */
	if (parse_headers(msg, HDR_EOH_F, 0) < 0) {
		strcpy(reason, "message parsing failed");
		ret = SV_HDR_PARSE_ERROR;
		goto failed;
	}

	/* any message has to have a call-id */
	if (!msg->callid) {
		strcpy(reason, "message doesn't have callid");
		ret = SV_NO_CALLID;
		goto failed;
	}

	/* content length should be present if protocol is not UDP */
	if (msg->rcv.proto != PROTO_UDP && !msg->content_length) {
		snprintf(reason, MAX_REASON-1, "message doesn't have Content Length header for proto %d",
				msg->rcv.proto);
		ret = SV_NO_CONTENT_LENGTH;
		goto failed;
	}

	body.s = NULL;
	body.len = 0;

	flags = flags_s ? (unsigned long)(void*)flags_s : 0;

	/* if not CANCEL, check if it has body */
	if (msg->first_line.type!=SIP_REQUEST || msg->REQ_METHOD!=METHOD_CANCEL) {

		if (get_body( msg, &body)!=0) {
			strcpy(reason, "invalid parsing");
			ret = SV_HDR_PARSE_ERROR;
			goto failed;
		}

		if (get_content_length(msg) != body.len) {
			snprintf(reason, MAX_REASON-1, "invalid body - content length %ld different than actual body %d",
					get_content_length(msg), body.len);
			ret = SV_INVALID_CONTENT_LENGTH;
			goto failed;
		}

		/* if has body, check for SDP */
		if (body.s && body.len && (flags & SIP_PARSE_SDP) &&
				parse_content_type_hdr(msg)==(TYPE_APPLICATION<<16 | SUBTYPE_SDP) ) {
			if (!parse_sdp(msg)) {
				strcpy(reason, "failed to parse SDP message");
				ret = SV_PARSE_SDP;
				goto failed;
			}
		}
	}

	/* set reason to empty (covers cases where we
	 * exit via CHECK_HEADER) */
	reason[0] = 0;

	/* Cseq */
	ret = SV_NO_CSEQ;
	CHECK_HEADER("", cseq);

	/* From */
	ret = SV_NO_FROM;
	CHECK_HEADER("", from);

	/* To */
	ret = SV_NO_TO;
	CHECK_HEADER("", to);

	/* check only if Via1 is present */
	ret = SV_NO_VIA1;
	CHECK_HEADER("", via1);

	/* test to header uri */
	if(flags & SIP_PARSE_TO) {
		if(!msg->to->parsed) {
			if(parse_to_header(msg) < 0) {
				strcpy(reason, "failed to parse 'To' header");
				ret = SV_TO_PARSE_ERROR;
				goto failed;
			}
		}

		to = (struct to_body*)msg->to->parsed;

		if(parse_uri(to->uri.s, to->uri.len, &to->parsed_uri) < 0) {
			strcpy(reason, "failed to parse 'To' header");
			ret = SV_TO_PARSE_ERROR;
			goto failed;
		}

		/* check for valid domain format */
		if(check_hostname(&to->parsed_uri.host) < 0) {
			strcpy(reason, "invalid domain for 'To' header");
			ret = SV_TO_DOMAIN_ERROR;
			goto failed;
		}
	}

	/* test from header uri */
	if(flags & SIP_PARSE_FROM) {
		if(!msg->from->parsed) {
			if(parse_from_header(msg) < 0) {
				strcpy(reason, "failed to parse 'From' header");
				ret = SV_FROM_PARSE_ERROR;
				goto failed;
			}
		}

		from = (struct to_body*)msg->from->parsed;

		if(parse_uri(from->uri.s, from->uri.len, &from->parsed_uri) < 0) {
			strcpy(reason, "failed to parse 'From' header");
			ret = SV_FROM_PARSE_ERROR;
			goto failed;
		}

		/* check for valid domain format */
		if(check_hostname(&from->parsed_uri.host) < 0) {
			strcpy(reason, "invalid domain for 'From' header");
			ret = SV_FROM_DOMAIN_ERROR;
			goto failed;
		}
	}

	/* request or reply */
	switch (msg->first_line.type) {
		case SIP_REQUEST:

			/* check R-URI */
			if (flags & SIP_PARSE_RURI) {
				if(msg->parsed_uri_ok==0 && parse_sip_msg_uri(msg) < 0) {
					strcpy(reason, "failed to parse R-URI");
					ret = SV_RURI_PARSE_ERROR;
					goto failed;
				}
				if (check_hostname(&msg->parsed_uri.host) < 0) {
					strcpy(reason, "invalid domain for R-URI");
					ret = SV_BAD_HOSTNAME;
					goto failed;
				}
			}
			/* Max-Forwards */
			if (!(flags & SIP_PARSE_NOMF)) {
				ret = SV_NO_MF;
				CHECK_HEADER("", maxforwards);
			}

			if (msg->REQ_METHOD == METHOD_INVITE) {
				ret = SV_NO_CONTACT;
				CHECK_HEADER("INVITE", contact);
				if(flags & SIP_PARSE_CONTACT) {
					/* iterate through Contact headers */
					for(ptr = msg->contact; ptr; ptr = ptr->sibling) {
						/* parse Contact header */
						if(!ptr->parsed && (parse_contact(ptr) < 0
									|| !ptr->parsed)) {
							strcpy(reason, "failed to parse 'Contact' header");
							ret = SV_CONTACT_PARSE_ERROR;
							goto failed;
						}
						contacts = ((contact_body_t*)ptr->parsed)->contacts;
						/* empty contacts header - something must be wrong */
						if(contacts == NULL) {
							strcpy(reason, "empty body for 'Contact' header");
							ret = SV_CONTACT_PARSE_ERROR;
							goto failed;
						}
						/* iterate through URIs and check validty */
						for(; contacts; contacts = contacts->next) {
							if(parse_uri(contacts->uri.s, contacts->uri.len,
										&test_contacts) < 0
									|| test_contacts.host.len < 0) {
								strcpy(reason, "failed to parse 'Contact' header");
								ret = SV_CONTACT_PARSE_ERROR;
								goto failed;
							}
						}
					}

				}
			}

			if (msg->REQ_METHOD != METHOD_REGISTER && msg->path) {
				strcpy(reason, "PATH header supported only for REGISTERs");
				ret = SV_PATH_NONREGISTER;
				goto failed;
			}

			method = msg->REQ_METHOD;

			break;

		case SIP_REPLY:
			/* checking the reply's message type */
			cbody = (struct cseq_body *)msg->cseq->parsed;
			if (!cbody) {
				strcpy(reason, "cseq not parsed properly");
				ret = SV_NO_CSEQ;
				goto failed;
			}
			method = cbody->method_id;
			if (method != METHOD_CANCEL) {
				switch (msg->first_line.u.reply.statuscode) {
					case 405:
						ret = SV_NOALLOW_405;
						CHECK_HEADER("", allow);
						break;

					case 423:
						if (method == METHOD_REGISTER) {
							ret = SV_NOMINEXP_423;
							CHECK_HEADER("REGISTER", min_expires);
						}
						break;

					case 407:
						ret = SV_NO_PROXY_AUTH;
						CHECK_HEADER("", proxy_authenticate);
						break;

					case 420:
						ret = SV_NO_UNSUPPORTED;
						CHECK_HEADER("", unsupported);
						break;

					case 401:
						ret = SV_NO_WWW_AUTH;
						CHECK_HEADER("", www_authenticate);
						break;
				}
			}

			break;

		default:
			strcpy(reason, "invalid message type");
			ret = SV_GENERIC_FAILURE;
			goto failed;
	}
	/* check for body */
	if (method != METHOD_CANCEL) {
		if (!msg->unparsed) {
			strcpy(reason, "invalid parsing");
			ret = SV_HDR_PARSE_ERROR;
			goto failed;
		}
		hdrs_len=(unsigned int)(msg->unparsed-msg->buf);

		if ((hdrs_len+2<=msg->len) && (strncmp(CRLF,msg->unparsed,CRLF_LEN)==0) )
			body.s = msg->unparsed + CRLF_LEN;
		else if ( (hdrs_len+1<=msg->len) &&
				(*(msg->unparsed)=='\n' || *(msg->unparsed)=='\r' ) )
			body.s = msg->unparsed + 1;
		else {
			/* no body */
			body.s = NULL;
			body.len = 0;
		}

		/* determine the length of the body */
		body.len = msg->buf + msg->len - body.s;

		if (get_content_length(msg) != body.len) {
			snprintf(reason, MAX_REASON-1, "invalid body - content length %ld different than "
					"actual body %d\n", get_content_length(msg), body.len);
			ret = SV_INVALID_CONTENT_LENGTH;
			goto failed;
		}

		if (body.len && body.s) {
			/* if it really has body, check for content type */
			ret = SV_NO_CONTENT_TYPE;
			CHECK_HEADER("", content_type);
		}
	}

	if ((flags & SIP_PARSE_HDR) && sip_validate_hdrs(msg) < 0) {
		strcpy(reason, "failed to parse headers");
		ret = SV_HDR_PARSE_ERROR;
		goto failed;
	}

	return 1;
failed:
	LM_DBG("message does not comply with SIP RFC3261 : (%s)\n", reason);

	if (pv_result != NULL)
	{
		pv_val.rs.len = strlen(reason);
		pv_val.rs.s = reason;
		pv_val.flags = PV_VAL_STR;
		if (pv_set_value(msg, &pv_res->spec, 0, &pv_val) != 0)
		{
			LM_ERR("cannot populate parameter\n");
			return SV_GENERIC_FAILURE;
		}
	}
	return ret;
}

#undef CHECK_HEADER



/* Change_reply_status config parsing function (supports AVPs) */
static int change_reply_status_fixup(void** param, int param_no)
{
	if(param_no == 1)
		return fixup_igp(param);

	if(param_no == 2)
		return fixup_spve(param);

	return 0;
}

/* Function to change  the reply status in reply route */
static int change_reply_status_f(struct sip_msg* msg, char* str1, char* str2)
{
	int code_i;
	str code_s;
	struct lump *l;
	char *ch;

	if(fixup_get_ivalue(msg, (gparam_p)str1, &code_i) < 0) {
		LM_ERR("Wrong param 1, expected integer\n");
		return -1;
	}

	if ( fixup_get_svalue(msg, (gparam_p) str2, &code_s) < 0) {
		LM_ERR("Wrong param 2, expected string\n");
		return -1;
	}

	if ((code_i < 100) || (code_i > 699)) {
		LM_ERR("wrong status code: %d\n", code_i);
		return -1;
	}

	if (((code_i < 300) || (msg->REPLY_STATUS < 300))
			&& (code_i/100 != msg->REPLY_STATUS/100)) {
		LM_ERR("the class of provisional or positive final replies"
				" cannot be changed\n");
		return -1;
	}

	/* rewrite the status code directly in the message buffer */
	msg->first_line.u.reply.statuscode = code_i;
	msg->first_line.u.reply.status.s[2] = code_i % 10 + '0'; code_i /= 10;
	msg->first_line.u.reply.status.s[1] = code_i % 10 + '0'; code_i /= 10;
	msg->first_line.u.reply.status.s[0] = code_i + '0';

	l = del_lump(msg,
			msg->first_line.u.reply.reason.s - msg->buf,
			msg->first_line.u.reply.reason.len,
			0);
	if (!l) {
		LM_ERR("Failed to add del lump\n");
		return -1;
	}
	/* clone the reason phrase, the lumps need to be pkg allocated */
	ch = (char *)pkg_malloc(code_s.len);
	if (!ch) {
		LM_ERR("Not enough memory\n");
		return -1;
	}

	memcpy(ch, code_s.s, code_s.len);
	if (insert_new_lump_after(l, ch, code_s.len, 0)==0){
		LM_ERR("failed to add new lump: %.*s\n", code_s.len, ch);
		pkg_free(ch);
		return -1;
	}

	return 1;
}

