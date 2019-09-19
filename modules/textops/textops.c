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
 *  2003-03-10  module export interface updated to the new format (andrei)
 *  2003-03-16  flags export parameter added (janakj)
 *  2003-03-19  replaced all mallocs/frees w/ pkg_malloc/pkg_free (andrei)
 *  2003-04-97  actions permitted to be used from failure/reply routes (jiri)
 *  2003-04-21  remove_hf introduced (jiri)
 *  2003-08-19  subst added (support for sed like res:s/re/repl/flags) (andrei)
 *  2003-08-20  subst_uri added (like above for uris) (andrei)
 *  2003-09-11  updated to new build_lump_rpl() interface (bogdan)
 *  2004-07-06  subst_user added (like subst_uri but only for user) (sobomax)
 *  2004-11-12  subst_user changes (old serdev mails) (andrei)
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
#include "../../mod_fix.h"
#include "../../parser/parse_uri.h"
#include "../../mod_fix.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h> /* for regex */
#include <regex.h>
#include <time.h>
#include <sys/time.h>



static int search_f(struct sip_msg*, regex_t*);
static int search_body_f(struct sip_msg* msg, regex_t* key);
static int replace_f(struct sip_msg* msg, regex_t* key, str* str2);
static int replace_body_f(struct sip_msg* msg, regex_t* key, str* str2);
static int replace_all_f(struct sip_msg* msg, regex_t* key, str* str2);
static int replace_body_all_f(struct sip_msg* msg, regex_t* key, str* str2);
static int replace_body_atonce_f(struct sip_msg*, regex_t* key, str* str2);
static int subst_f(struct sip_msg* msg, struct subst_expr *se);
static int subst_uri_f(struct sip_msg*, struct subst_expr *se);
static int subst_user_f(struct sip_msg*, struct subst_expr *se);
static int subst_body_f(struct sip_msg*, struct subst_expr *se);
static int search_append_f(struct sip_msg* msg, regex_t* key, str* str2);
static int search_append_body_f(struct sip_msg* msg, regex_t* key, str* str2);

static int fixup_substre(void**);
static int fixup_free_substre(void** param);


static int mod_init(void);

static cmd_export_t cmds[]={
	{"search", (cmd_function)search_f, {
		{CMD_PARAM_REGEX, 0, 0}, {0,0,0}},
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"search_body", (cmd_function)search_body_f, {
		{CMD_PARAM_REGEX, 0, 0}, {0,0,0}},
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"search_append", (cmd_function)search_append_f, {
		{CMD_PARAM_REGEX, 0, 0},
		{CMD_PARAM_STR, 0, 0}, {0,0,0}},
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"search_append_body", (cmd_function)search_append_body_f, {
		{CMD_PARAM_REGEX, 0, 0},
		{CMD_PARAM_STR, 0, 0}, {0,0,0}},
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"replace", (cmd_function)replace_f, {
		{CMD_PARAM_REGEX, 0, 0},
		{CMD_PARAM_STR, 0, 0}, {0,0,0}},
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"replace_body",     (cmd_function)replace_body_f, {
		{CMD_PARAM_REGEX, 0, 0},
		{CMD_PARAM_STR, 0, 0}, {0,0,0}},
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"replace_all",      (cmd_function)replace_all_f, {
		{CMD_PARAM_REGEX, 0, 0},
		{CMD_PARAM_STR, 0, 0}, {0,0,0}},
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"replace_body_all", (cmd_function)replace_body_all_f, {
		{CMD_PARAM_REGEX, 0, 0},
		{CMD_PARAM_STR, 0, 0}, {0,0,0}},
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"replace_body_atonce", (cmd_function)replace_body_atonce_f, {
		{CMD_PARAM_REGEX, 0, 0},
		{CMD_PARAM_STR, 0, 0}, {0,0,0}},
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"subst", (cmd_function)subst_f, {
		{CMD_PARAM_STR|CMD_PARAM_NO_EXPAND, fixup_substre, fixup_free_substre}, {0,0,0}},
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"subst_uri", (cmd_function)subst_uri_f, {
		{CMD_PARAM_STR|CMD_PARAM_NO_EXPAND, fixup_substre, fixup_free_substre}, {0,0,0}},
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE},
	{"subst_user", (cmd_function)subst_user_f, {
		{CMD_PARAM_STR|CMD_PARAM_NO_EXPAND, fixup_substre, fixup_free_substre}, {0,0,0}},
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE},
	{"subst_body", (cmd_function)subst_body_f, {
		{CMD_PARAM_STR|CMD_PARAM_NO_EXPAND, fixup_substre, fixup_free_substre}, {0,0,0}},
		REQUEST_ROUTE|ONREPLY_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{0,0,{{0,0,0}},0}
};

struct module_exports exports= {
	"textops",  /* module name*/
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	NULL,            /* OpenSIPS module dependencies */
	cmds,       /* exported functions */
	NULL,       /* exported async functions */
	0,          /* module parameters */
	0,          /* exported statistics */
	0,          /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,			/* exported transformations */
	0,          /* extra processes */
	0,          /* module pre-initialization function */
	mod_init,   /* module initialization function */
	0,          /* response function */
	0,          /* destroy function */
	0,          /* per-child init function */
	0           /* reload confirm function */
};


static int mod_init(void)
{
	LM_INFO("initializing...\n");
	return 0;
}

static char *get_header(struct sip_msg *msg)
{
	return msg->buf+msg->first_line.len;
}



static int search_f(struct sip_msg* msg, regex_t* key)
{
	/*we registered only 1 param, so we ignore str2*/
	regmatch_t pmatch;

	if (regexec(key, msg->buf, 1, &pmatch, 0)!=0) return -1;
	return 1;
}


static int search_body_f(struct sip_msg* msg, regex_t* key)
{
	str body;
	/*we registered only 1 param, so we ignore str2*/
	regmatch_t pmatch;

	if ( get_body(msg,&body)!=0 || body.len==0) {
		LM_DBG("message body has zero length\n");
		return -1;
	}

	if (regexec(key, body.s, 1, &pmatch, 0)!=0) return -1;
	return 1;
}


static int search_append_f(struct sip_msg* msg, regex_t* key, str* str2)
{
	struct lump* l;
	regmatch_t pmatch;
	char* s;
	char *begin;
	int off;

	begin=get_header(msg); /* msg->orig/buf previously .. uri problems */
	off=begin-msg->buf;

	if (regexec(key, begin, 1, &pmatch, 0)!=0) return -1;
	if (pmatch.rm_so!=-1){
		if ((l=anchor_lump(msg, off+pmatch.rm_eo, 0))==0)
			return -1;
		s=pkg_malloc(str2->len);
		if (s==0){
			LM_ERR("memory allocation failure\n");
			return -1;
		}
		memcpy(s, str2->s, str2->len);
		if (insert_new_lump_after(l, s, str2->len, 0)==0){
			LM_ERR("could not insert new lump\n");
			pkg_free(s);
			return -1;
		}
		return 1;
	}
	return -1;
}

static int search_append_body_f(struct sip_msg* msg, regex_t* key, str* str2)
{
	struct lump* l;
	regmatch_t pmatch;
	char* s;
	int off;
	str body;

	if ( get_body(msg,&body)!=0 || body.len==0) {
		LM_DBG("message body has zero length\n");
		return -1;
	}

	off=body.s-msg->buf;

	if (regexec(key, body.s, 1, &pmatch, 0)!=0) return -1;
	if (pmatch.rm_so!=-1){
		if ((l=anchor_lump(msg, off+pmatch.rm_eo, 0))==0)
			return -1;
		s=pkg_malloc(str2->len);
		if (s==0){
			LM_ERR("memory allocation failure\n");
			return -1;
		}
		memcpy(s, str2->s, str2->len);
		if (insert_new_lump_after(l, s, str2->len, 0)==0){
			LM_ERR("could not insert new lump\n");
			pkg_free(s);
			return -1;
		}
		return 1;
	}
	return -1;
}


static int replace_all_f(struct sip_msg* msg, regex_t* key, str* str2)
{
	struct lump* l;
	regmatch_t pmatch;
	char* s;
	char* begin;
	int off;
	int ret;
	int eflags;

	begin = get_header(msg);
	ret=-1; /* pessimist: we will not find any */
	eflags=0; /* match ^ at the beginning of the string*/

	while (begin<msg->buf+msg->len
				&& regexec(key, begin, 1, &pmatch, eflags)==0) {
		off=begin-msg->buf;
		if (pmatch.rm_so==-1){
			LM_ERR("offset unknown\n");
			return -1;
		}
		if (pmatch.rm_so==pmatch.rm_eo){
			LM_ERR("matched string is empty... invalid regexp?\n");
			return -1;
		}
		if ((l=del_lump(msg, pmatch.rm_so+off,
						pmatch.rm_eo-pmatch.rm_so, 0))==0) {
			LM_ERR("del_lump failed\n");
			return -1;
		}
		s=pkg_malloc(str2->len);
		if (s==0){
			LM_ERR("memory allocation failure\n");
			return -1;
		}
		memcpy(s, str2->s, str2->len);
		if (insert_new_lump_after(l, s, str2->len, 0)==0){
			LM_ERR("could not insert new lump\n");
			pkg_free(s);
			return -1;
		}
		/* new cycle */
		begin=begin+pmatch.rm_eo;
		/* is it still a string start */
		if (*(begin-1)=='\n' || *(begin-1)=='\r')
			eflags&=~REG_NOTBOL;
		else
			eflags|=REG_NOTBOL;
		ret=1;
	} /* while found ... */
	return ret;
}

static int do_replace_body_f(struct sip_msg* msg, regex_t *key, str* str2, int nobol)
{
	struct lump* l;
	regmatch_t pmatch;
	char* s;
	char* begin;
	int off;
	int ret;
	int eflags;
	str body;

	if ( get_body(msg,&body)!=0 || body.len==0) {
		LM_DBG("message body has zero length\n");
		return -1;
	}

	begin=body.s;
	ret=-1; /* pessimist: we will not find any */
	eflags=0; /* match ^ at the beginning of the string*/

	while (begin<msg->buf+msg->len
				&& regexec(key, begin, 1, &pmatch, eflags)==0) {
		off=begin-msg->buf;
		if (pmatch.rm_so==-1){
			LM_ERR("offset unknown\n");
			return -1;
		}
		if (pmatch.rm_so==pmatch.rm_eo){
			LM_ERR("matched string is empty... invalid regexp?\n");
			return -1;
		}
		if ((l=del_lump(msg, pmatch.rm_so+off,
						pmatch.rm_eo-pmatch.rm_so, 0))==0) {
			LM_ERR("del_lump failed\n");
			return -1;
		}
		s=pkg_malloc(str2->len);
		if (s==0){
			LM_ERR("memory allocation failure\n");
			return -1;
		}
		memcpy(s, str2->s, str2->len);
		if (insert_new_lump_after(l, s, str2->len, 0)==0){
			LM_ERR("could not insert new lump\n");
			pkg_free(s);
			return -1;
		}
		/* new cycle */
		begin=begin+pmatch.rm_eo;
		/* is it still a string start */
		if (nobol && (*(begin-1)=='\n' || *(begin-1)=='\r'))
			eflags&=~REG_NOTBOL;
		else
			eflags|=REG_NOTBOL;
		ret=1;
	} /* while found ... */
	return ret;
}

static int replace_body_all_f(struct sip_msg* msg, regex_t* key, str* str2)
{
	return do_replace_body_f(msg, key, str2, 1);
}

static int replace_body_atonce_f(struct sip_msg* msg, regex_t* key, str* str2)
{
	return do_replace_body_f(msg, key, str2, 0);
}

static int replace_f(struct sip_msg* msg, regex_t* key, str* str2)
{
	struct lump* l;
	regmatch_t pmatch;
	char* s;
	char* begin;
	int off;

	begin=get_header(msg); /* msg->orig previously .. uri problems */

	if (regexec((regex_t*) key, begin, 1, &pmatch, 0)!=0) return -1;
	off=begin-msg->buf;

	if (pmatch.rm_so!=-1){
		if ((l=del_lump(msg, pmatch.rm_so+off,
						pmatch.rm_eo-pmatch.rm_so, 0))==0)
			return -1;
		s=pkg_malloc(str2->len);
		if (s==0){
			LM_ERR("memory allocation failure\n");
			return -1;
		}
		memcpy(s, str2->s, str2->len);
		if (insert_new_lump_after(l, s, str2->len, 0)==0){
			LM_ERR("could not insert new lump\n");
			pkg_free(s);
			return -1;
		}

		return 1;
	}
	return -1;
}

static int replace_body_f(struct sip_msg* msg, regex_t* key, str* str2)
{
	struct lump* l;
	regmatch_t pmatch;
	char* s;
	char* begin;
	int off;
	str body;

	if ( get_body(msg,&body)!=0 || body.len==0) {
		LM_DBG("message body has zero length\n");
		return -1;
	}

	begin=body.s; /* msg->orig previously .. uri problems */

	if (regexec(key, begin, 1, &pmatch, 0)!=0) return -1;
	off=begin-msg->buf;

	if (pmatch.rm_so!=-1){
		if ((l=del_lump(msg, pmatch.rm_so+off,
						pmatch.rm_eo-pmatch.rm_so, 0))==0)
			return -1;
		s=pkg_malloc(str2->len);
		if (s==0){
			LM_ERR("memory allocation failure\n");
			return -1;
		}
		memcpy(s, str2->s, str2->len);
		if (insert_new_lump_after(l, s, str2->len, 0)==0){
			LM_ERR("could not insert new lump\n");
			pkg_free(s);
			return -1;
		}

		return 1;
	}
	return -1;
}


/* sed-perl style re: s/regular expression/replacement/flags */
static int subst_f(struct sip_msg* msg, struct subst_expr *se)
{
	struct lump* l;
	struct replace_lst* lst;
	struct replace_lst* rpl;
	char* begin;
	int off;
	int ret;
	int nmatches;

	begin=get_header(msg);  /* start after first line to avoid replacing
							   the uri */
	off=begin-msg->buf;
	ret=-1;
	if ((lst=subst_run(se, begin, msg, &nmatches))==0)
		goto error; /* not found */
	for (rpl=lst; rpl; rpl=rpl->next){
		LM_DBG("%s: replacing at offset %d [%.*s] with [%.*s]\n",
				exports.name, rpl->offset+off,
				rpl->size, rpl->offset+off+msg->buf,
				rpl->rpl.len, rpl->rpl.s);
		if ((l=del_lump(msg, rpl->offset+off, rpl->size, 0))==0)
			goto error;
		/* hack to avoid re-copying rpl, possible because both
		 * replace_lst & lumps use pkg_malloc */
		if (insert_new_lump_after(l, rpl->rpl.s, rpl->rpl.len, 0)==0){
			LM_ERR("ERROR: %s: subst_f: could not insert new lump\n",
					exports.name);
			goto error;
		}
		/* hack continued: set rpl.s to 0 so that replace_lst_free will
		 * not free it */
		rpl->rpl.s=0;
		rpl->rpl.len=0;
	}
	ret=1;
error:
	LM_DBG("lst was %p\n", lst);
	if (lst) replace_lst_free(lst);
	if (nmatches<0)
		LM_ERR("ERROR: %s: subst_run failed\n", exports.name);
	return ret;
}


/* sed-perl style re: s/regular expression/replacement/flags, like
 *  subst but works on the message uri */
static int subst_uri_f(struct sip_msg* msg, struct subst_expr *se)
{
	char* tmp;
	int len;
	char c;
	str* result;

	if (msg->new_uri.s){
		len=msg->new_uri.len;
		tmp=msg->new_uri.s;
	}else{
		tmp=msg->first_line.u.request.uri.s;
		len	=msg->first_line.u.request.uri.len;
	};
	/* ugly hack: 0 s[len], and restore it afterward
	 * (our re functions require 0 term strings), we can do this
	 * because we always alloc len+1 (new_uri) and for first_line, the
	 * message will always be > uri.len */
	c=tmp[len];
	tmp[len]=0;
	result=subst_str(tmp, msg, se, 0); /* pkg malloc'ed result */
	tmp[len]=c;
	if (result){
		LM_DBG("%s match - old uri= [%.*s], new uri= [%.*s]\n",
				exports.name, len, tmp,
				(result->len)?result->len:0,(result->s)?result->s:"");
		if (msg->new_uri.s) pkg_free(msg->new_uri.s);
		msg->new_uri=*result;
		msg->parsed_uri_ok=0; /* reset "use cached parsed uri" flag */
		pkg_free(result); /* free str* pointer */
		return 1; /* success */
	}
	return -1; /* false, no subst. made */
}



/* sed-perl style re: s/regular expression/replacement/flags, like
 *  subst but works on the user part of the uri */
static int subst_user_f(struct sip_msg* msg, struct subst_expr *se)
{
	str* result;
	str user;
	char c;
	int nmatches;

	c=0;
	if (parse_sip_msg_uri(msg)<0){
		return -1; /* error, bad uri */
	}
	if (msg->parsed_uri.user.s==0){
		/* no user in uri */
		user.s="";
		user.len=0;
	}else{
		user=msg->parsed_uri.user;
		c=user.s[user.len];
		user.s[user.len]=0;
	}
	result=subst_str(user.s, msg, se, &nmatches);/* pkg malloc'ed result */
	if (c)	user.s[user.len]=c;
	if (result == NULL) {
		if (nmatches<0)
			LM_ERR("subst_user(): subst_str() failed\n");
		return -1;
	}
	/* result->s[result->len] = '\0';  --subst_str returns 0-term strings */
	if (rewrite_ruri(msg, result, 0, RW_RURI_USER) < 0) {
		LM_ERR("Failed to set R-URI user\n");
		return -1;
	}
	pkg_free(result->s);
	pkg_free(result);
	return 1;
}


/* sed-perl style re: s/regular expression/replacement/flags */
static int subst_body_f(struct sip_msg* msg, struct subst_expr *se)
{
	struct lump* l;
	struct replace_lst* lst;
	struct replace_lst* rpl;
	char* begin;
	int off;
	int ret;
	int nmatches;
	str body;

	if ( get_body(msg,&body)!=0 || body.len==0) {
		LM_DBG("message body has zero length\n");
		return -1;
	}

	begin=body.s;

	off=begin-msg->buf;
	ret=-1;
	if ((lst=subst_run(se, begin, msg, &nmatches))==0)
		goto error; /* not found */
	for (rpl=lst; rpl; rpl=rpl->next){
		LM_DBG("%s replacing at offset %d [%.*s] with [%.*s]\n",
				exports.name, rpl->offset+off,
				rpl->size, rpl->offset+off+msg->buf,
				rpl->rpl.len, rpl->rpl.s);
		if ((l=del_lump(msg, rpl->offset+off, rpl->size, 0))==0)
			goto error;
		/* hack to avoid re-copying rpl, possible because both
		 * replace_lst & lumps use pkg_malloc */
		if (insert_new_lump_after(l, rpl->rpl.s, rpl->rpl.len, 0)==0){
			LM_ERR("%s could not insert new lump\n",
					exports.name);
			goto error;
		}
		/* hack continued: set rpl.s to 0 so that replace_lst_free will
		 * not free it */
		rpl->rpl.s=0;
		rpl->rpl.len=0;
	}
	ret=1;
error:
	LM_DBG("lst was %p\n", lst);
	if (lst) replace_lst_free(lst);
	if (nmatches<0)
		LM_ERR("%s subst_run failed\n", exports.name);
	return ret;
}

static int fixup_substre(void** param)
{
	struct subst_expr* se;

	se=subst_parser((str*)*param);
	if (se==0){
		LM_ERR("%s: bad subst. re %.*s\n", exports.name,
				((str*)*param)->len, ((str*)*param)->s);
		return E_BAD_RE;
	}

	*param=se;
	return 0;
}

static int fixup_free_substre(void** param)
{
	subst_expr_free(*param);
	return 0;
}
