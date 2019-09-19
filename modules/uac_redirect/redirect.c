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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
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

/* private parameter variables */
char *deny_filter_s = 0;
char *accept_filter_s = 0;
char *def_filter_s = 0;


#define ACCEPT_RULE_STR "accept"
#define DENY_RULE_STR   "deny"



static int redirect_init(void);
static int w_set_deny(struct sip_msg* msg, regex_t *re, void *flags);
static int w_set_accept(struct sip_msg* msg, regex_t *re, void *flags);
static int w_get_redirect(struct sip_msg* msg, int *max_t, int *max_b);
static int regexp_compile(char *re_s, regex_t **re);
//static int setf_fixup(void** param, int param_no);
static int fix_reset_flags(void **pflags);
static int fix_contact_count(void** param);


static cmd_export_t cmds[] = {
	{"set_deny_filter",   (cmd_function)w_set_deny,
		{ {CMD_PARAM_REGEX, NULL, NULL},
		  {CMD_PARAM_STR, fix_reset_flags, NULL},
		  {0 , 0, 0}
		},
		FAILURE_ROUTE },
	{"set_accept_filter",   (cmd_function)w_set_accept,
		{ {CMD_PARAM_REGEX, NULL, NULL},
		  {CMD_PARAM_STR, fix_reset_flags, NULL},
		  {0 , 0, 0}
		},
		FAILURE_ROUTE },
	{"get_redirects",   (cmd_function)w_get_redirect,
		{ {CMD_PARAM_INT|CMD_PARAM_OPT, fix_contact_count, NULL},
		  {CMD_PARAM_INT|CMD_PARAM_OPT, fix_contact_count, NULL},
		  {0 , 0, 0}
		},
		FAILURE_ROUTE },
	{0, 0, {{0, 0, 0}}, 0}
};

static param_export_t params[] = {
	{"deny_filter",     STR_PARAM,  &deny_filter_s    },
	{"accept_filter",   STR_PARAM,  &accept_filter_s  },
	{"default_filter",  STR_PARAM,  &def_filter_s     },
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
	0,				 /* load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds,     /* Exported functions */
	0,        /* Exported async functions */
	params,   /* Exported parameters */
	0,        /* exported statistics */
	0,        /* exported MI functions */
	0,        /* exported pseudo-variables */
	0,		  /* exported transformations */
	0,        /* extra processes */
	0,             /* Module pre-initialization function */
	redirect_init, /* Module initialization function */
	(response_function) 0,
	(destroy_function) 0,
	(child_init_function) 0, /* per-child init function */
	0                        /* reload confirm function */
};


static int fix_contact_count(void **count)
{
	int ct_count = **(int **)count;

	if (ct_count > 255) {
		LM_ERR("get_redirects() param too big (%d), max 255\n", ct_count);
		return -1;
	}

	return 0;
}


static int fix_reset_flags(void **pflags)
{
	str *flags = (str *)*pflags;
	str f_reset_all = str_init("reset_all"),
		f_reset_def = str_init("reset_default"), f_reset_added = str_init("reset_added");

	if (!flags) {
		*pflags = 0;
		return 0;
	}

	if (!flags->s || *flags->s == '\0')
		*(int *)pflags = 0;
	else if (!str_strcmp(flags, &f_reset_all))
		*(int *)pflags = RESET_ADDED|RESET_DEFAULT;
	else if (!str_strcmp(flags, &f_reset_def))
		*(int *)pflags = RESET_DEFAULT;
	else if (!str_strcmp(flags, &f_reset_added))
		*(int *)pflags = RESET_ADDED;
	else {
		LM_ERR("unknown reset type <%.*s>\n", flags->len, flags->s);
		return E_UNSPEC;
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
				LM_WARN("filters set but not used -> resetting to default\n");
				reset_filters();
				id = msg->id;
			}
		} else {
			id = msg->id;
			set = 1;
		}
	}
}


static int w_set_deny(struct sip_msg* msg, regex_t *re, void *flags)
{
	msg_tracer( msg, 0);
	return (add_filter( DENY_FILTER, re, (int)(long)flags)==0)?1:-1;
}


static int w_set_accept(struct sip_msg* msg, regex_t *re, void *flags)
{
	msg_tracer( msg, 0);
	return (add_filter( ACCEPT_FILTER, re, (int)(long)flags)==0)?1:-1;
}


static int w_get_redirect(struct sip_msg* msg, int *max_t, int *max_b)
{
	int n;

	msg_tracer( msg, 0);
	/* get the contacts */
	n = get_redirect(msg , max_t ? *max_t : 0, max_b ? *max_b : 0);
	reset_filters();
	/* reset the tracer */
	msg_tracer( msg, 1);

	return n;
}
