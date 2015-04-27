/*
 * Copyright (C) 2005 Voice Sistem SRL
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *
 * History:
 * ---------
 *  2005-06-22  first version (bogdan)
 */

#include <sys/types.h> /* for regex */
#include <regex.h>

#include "../../sr_module.h"
#include "../../str.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../tm/tm_load.h"
#include "rd_funcs.h"
#include "rd_filter.h"



/* internal global variables */
struct tm_binds rd_tmb;           /*imported functions from tm */
cmd_function    rd_acc_fct = 0;   /*imported function from acc */

/* global parameter variables */
char *acc_db_table = "acc";
char *acc_fct_s    = "acc_log_request";

/* private parameter variables */
char *deny_filter_s = 0;
char *accept_filter_s = 0;
char *def_filter_s = 0;


#define ACCEPT_RULE_STR "accept"
#define DENY_RULE_STR   "deny"



static int redirect_init(void);
static int w_set_deny(struct sip_msg* msg, char *dir, char *foo);
static int w_set_accept(struct sip_msg* msg, char *dir, char *foo);
static int w_get_redirect1(struct sip_msg* msg, char *max_c);
static int w_get_redirect2(struct sip_msg* msg, char *max_c, pv_elem_t *reason);
static int regexp_compile(char *re_s, regex_t **re);
static int get_redirect_fixup(void** param, int param_no);
static int setf_fixup(void** param, int param_no);


static cmd_export_t cmds[] = {
	{"set_deny_filter",   (cmd_function)w_set_deny,      2,  setf_fixup, 0,
			FAILURE_ROUTE },
	{"set_accept_filter", (cmd_function)w_set_accept,    2,  setf_fixup, 0,
			FAILURE_ROUTE },
	{"get_redirects",     (cmd_function)w_get_redirect2,  2,  get_redirect_fixup, 0,
			FAILURE_ROUTE },
	{"get_redirects",     (cmd_function)w_get_redirect1,  1,  get_redirect_fixup, 0,
			FAILURE_ROUTE },
	{0, 0, 0, 0, 0, 0}
};

static param_export_t params[] = {
	{"deny_filter",     STR_PARAM,  &deny_filter_s    },
	{"accept_filter",   STR_PARAM,  &accept_filter_s  },
	{"default_filter",  STR_PARAM,  &def_filter_s     },
	{"acc_function",    STR_PARAM,  &acc_fct_s        },
	{"acc_db_table",    STR_PARAM,  &acc_db_table     },
	{0, 0, 0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "tm",  DEP_ABORT   },
		{ MOD_TYPE_DEFAULT, "acc", DEP_SILENT  },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

struct module_exports exports = {
	"uac_redirect",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	&deps,           /* OpenSIPS module dependencies */
	cmds,     /* Exported functions */
	0,        /* Exported async functions */
	params,   /* Exported parameters */
	0,        /* exported statistics */
	0,        /* exported MI functions */
	0,        /* exported pseudo-variables */
	0,        /* extra processes */
	redirect_init, /* Module initialization function */
	(response_function) 0,
	(destroy_function) 0,
	(child_init_function) 0 /* per-child init function */
};



int get_nr_max(char *s, unsigned char *max)
{
	unsigned short nr;
	int err;

	if ( s[0]=='*' && s[1]==0 ) {
		/* is '*' -> infinit ;-) */
		*max = 0;
		return 0;
	} else {
		/* must be a positive number less than 255 */
		nr = str2s(s, strlen(s), &err);
		if (err==0){
			if (nr>255){
				LM_ERR("number too big <%d> (max=255)\n",nr);
				return -1;
			}
			*max = (unsigned char)nr;
			return 0;
		}else{
			LM_ERR("bad number <%s>\n",s);
			return -1;
		}
	}
}


static int get_redirect_fixup(void** param, int param_no)
{
	unsigned char maxb,maxt;
	pv_elem_t *reason;
	cmd_function fct;
	char *p;
	str s;

	s.s = (char*)*param;
	if (param_no == 1) {
		if ( (p = strchr(s.s, ':')) != 0 ) {
			/* have max branch also */
			*p = 0;
			if (get_nr_max(p + 1, &maxb) != 0)
				return E_UNSPEC;
		} else {
			maxb = 0; /* infinit */
		}

		/* get max total */
		if (get_nr_max(s.s, &maxt) != 0)
			return E_UNSPEC;

		pkg_free(*param);
		*param = (void*)(long)( (((unsigned short)maxt) << 8) | maxb);

	} else if (param_no == 2) {
		/* acc function loaded? */
		if (rd_acc_fct != 0)
			return 0;
		/* must import the acc stuff */
		if (acc_fct_s == 0 || acc_fct_s[0] == 0) {
			LM_ERR("acc support enabled, but no acc function defined\n");
			return E_UNSPEC;
		}
		fct = find_export(acc_fct_s, 2, REQUEST_ROUTE);
		if (fct == 0)
			fct = find_export(acc_fct_s, 1, REQUEST_ROUTE);
		if (fct == 0) {
			LM_ERR("cannot import %s function; is acc loaded and proper "
				"compiled?\n", acc_fct_s);
			return E_UNSPEC;
		}
		rd_acc_fct = fct;
		/* Convert reason into pv_elem_t */
		if (s.s == 0 || s.s[0] == 0) {
			s.s = "n/a";
			s.len = 3;
		} else {
			s.len = strlen(s.s);
		}
		if (pv_parse_format(&s, &reason) < 0) {
			LM_ERR("pv_parse_format failed\n");
			return E_OUT_OF_MEM;
		}
		*param = (void*)reason;
	}

	return 0;
}


static int setf_fixup(void** param, int param_no)
{
	unsigned short nr;
	regex_t *filter;
	char *s;

	s = (char*)*param;
	if (param_no==1) {
		/* compile the filter */
		if (regexp_compile( s, &filter)<0) {
			LM_ERR("cannot init filter <%s>\n", s);
			return E_BAD_RE;
		}
		pkg_free(*param);
		*param = (void*)filter;
	} else if (param_no==2) {
		if (s==0 || s[0]==0) {
			nr = 0;
		} else if (strcasecmp(s,"reset_all")==0) {
			nr = RESET_ADDED|RESET_DEFAULT;
		} else if (strcasecmp(s,"reset_default")==0) {
			nr = RESET_DEFAULT;
		} else if (strcasecmp(s,"reset_added")==0) {
			nr = RESET_ADDED;
		} else {
			LM_ERR("unknown reset type <%s>\n",s);
			return E_UNSPEC;
		}
		pkg_free(*param);
		*param = (void*)(long)nr;
	}

	return 0;
}



static int regexp_compile(char *re_s, regex_t **re)
{
	*re = 0;
	if (re_s==0 || strlen(re_s)==0 ) {
		return 0;
	} else {
		if ((*re=pkg_malloc(sizeof(regex_t)))==0)
			return E_OUT_OF_MEM;
		if (regcomp(*re, re_s, REG_EXTENDED|REG_ICASE|REG_NEWLINE) ){
			pkg_free(*re);
			*re = 0;
			LM_ERR("regexp_compile:bad regexp <%s>\n", re_s);
			return E_BAD_RE;
		}
	}
	return 0;
}



static int redirect_init(void)
{
	regex_t *filter;

	/* load the TM API */
	if (load_tm_api(&rd_tmb)!=0) {
		LM_ERR("failed to load TM API\n");
		goto error;
	}

	/* init filter */
	init_filters();

	/* what's the default rule? */
	if (def_filter_s) {
		if ( !strcasecmp(def_filter_s,ACCEPT_RULE_STR) ) {
			set_default_rule( ACCEPT_RULE );
		} else if ( !strcasecmp(def_filter_s,DENY_RULE_STR) ) {
			set_default_rule( DENY_RULE );
		} else {
			LM_ERR("unknown default filter <%s>\n",def_filter_s);
		}
	}

	/* if accept filter specify, compile it */
	if (regexp_compile(accept_filter_s, &filter)<0) {
		LM_ERR("failed to init accept filter\n");
		goto error;
	}
	add_default_filter( ACCEPT_FILTER, filter);

	/* if deny filter specify, compile it */
	if (regexp_compile(deny_filter_s, &filter)<0) {
		LM_ERR("failed to init deny filter\n");
		goto error;
	}
	add_default_filter( DENY_FILTER, filter);

	return 0;
error:
	return -1;
}


static inline void msg_tracer(struct sip_msg* msg, int reset)
{
	static unsigned int id  = 0;
	static unsigned int set = 0;

	if (reset) {
		set = 0;
	} else {
		if (set) {
			if (id!=msg->id) {
				LM_WARN("filters set but not used -> reseting to default\n");
				reset_filters();
				id = msg->id;
			}
		} else {
			id = msg->id;
			set = 1;
		}
	}
}


static int w_set_deny(struct sip_msg* msg, char *re, char *flags)
{
	msg_tracer( msg, 0);
	return (add_filter( DENY_FILTER, (regex_t*)re, (int)(long)flags)==0)?1:-1;
}


static int w_set_accept(struct sip_msg* msg, char *re, char *flags)
{
	msg_tracer( msg, 0);
	return (add_filter( ACCEPT_FILTER, (regex_t*)re, (int)(long)flags)==0)?1:-1;
}


static int w_get_redirect2(struct sip_msg* msg, char *max_c, pv_elem_t *reason)
{
	int n;
	unsigned short max;

	msg_tracer( msg, 0);
	/* get the contacts */
	max = (unsigned short)(long)max_c;
	n = get_redirect(msg , (max>>8)&0xff, max&0xff, reason);
	reset_filters();
	/* reset the tracer */
	msg_tracer( msg, 1);

	return n;
}


static int w_get_redirect1(struct sip_msg* msg, char *max_c)
{
	return w_get_redirect2(msg, max_c, 0);
}

