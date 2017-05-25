/*
 * Copyright (C) 2004-2006 Voice Sistem SRL
 *
 * This file is part of Open SIP Server (opensips).
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
 * History:
 * ---------
 *  2004-10-04  first version (ramona)
 *  2004-11-15  added support for db schemes for avp_db_load (ramona)
 *  2004-11-17  aligned to new AVP core global aliases (ramona)
 *  2005-01-30  "fm" (fast match) operator added (ramona)
 *  2005-01-30  avp_copy (copy/move operation) added (ramona)
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h> /* for regex */
#include <regex.h>

#include "../../sr_module.h"
#include "../../mem/shm_mem.h"
#include "../../mem/mem.h"
#include "../../parser/parse_hname2.h"
#include "../../str.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../ut.h"
#include "../../mod_fix.h"
#include "avpops_parse.h"
#include "avpops_impl.h"
#include "avpops_db.h"

#define AVPDB "avp_db"

typedef enum {GPARAM=0, URL} db_id_type;

struct db_url_container {
	db_id_type type;
	union {
		struct db_url *url;
		gparam_p gp;
	} u;
};


char *printbuf = NULL;

/* modules param variables */
static str db_table        = str_init("usr_preferences");  /* table */
static int use_domain      = 0;  /* if domain should be use for avp matching */
static str uuid_col        = str_init("uuid");
static str attribute_col   = str_init("attribute");
static str value_col       = str_init("value");
static str type_col        = str_init("type");
static str username_col    = str_init("username");
static str domain_col      = str_init("domain");
static str* db_columns[6] = {&uuid_col, &attribute_col, &value_col,
                             &type_col, &username_col, &domain_col};
static int need_db=0;

unsigned buf_size=1024;

static int avpops_init(void);
static int avpops_child_init(int rank);

static int fixup_db_load_avp(void** param, int param_no);
static int fixup_db_delete_avp(void** param, int param_no);
static int fixup_db_store_avp(void** param, int param_no);
static int fixup_db_query_avp(void** param, int param_no);
static int fixup_async_db_query_avp(void** param, int param_no);
static int fixup_delete_avp(void** param, int param_no);
static int fixup_copy_avp(void** param, int param_no);
static int fixup_pushto_avp(void** param, int param_no);
static int fixup_check_avp(void** param, int param_no);
static int fixup_op_avp(void** param, int param_no);
static int fixup_subst(void** param, int param_no);
static int fixup_is_avp_set(void** param, int param_no);
static int fixup_insert_avp(void** param, int param_no);

static int w_print_avps(struct sip_msg* msg, char* foo, char *bar);
static int w_dbload_avps(struct sip_msg* msg, char* source,
		char* param, char *url, char *prefix);
static int w_dbdelete_avps(struct sip_msg* msg, char* source,
		char* param, char* url);
static int w_dbstore_avps(struct sip_msg* msg, char* source,
		char* param, char* url);
static int w_dbquery_avps(struct sip_msg* msg, char* query,
		char* dest, char* url);
static int w_async_dbquery_avps(struct sip_msg* msg, async_ctx *ctx,
		char* query, char* dest, char* url);
static int w_delete_avps(struct sip_msg* msg, char* param, char *foo);
static int w_copy_avps(struct sip_msg* msg, char* param, char *check);
static int w_pushto_avps(struct sip_msg* msg, char* destination, char *param);
static int w_check_avps(struct sip_msg* msg, char* param, char *check);
static int w_op_avps(struct sip_msg* msg, char* param, char *op);
static int w_subst(struct sip_msg* msg, char* src, char *subst);
static int w_is_avp_set(struct sip_msg* msg, char* param, char *foo);

static acmd_export_t acmds[] = {
	{ "avp_db_query", (acmd_function)w_async_dbquery_avps, 1,
		fixup_async_db_query_avp },
	{ "avp_db_query", (acmd_function)w_async_dbquery_avps, 2,
	  fixup_async_db_query_avp },
	{ "avp_db_query", (acmd_function)w_async_dbquery_avps, 3,
	  fixup_async_db_query_avp },
	{ 0, 0, 0, 0 }
};

/*! \brief
 * Exported functions
 */
static cmd_export_t cmds[] = {
	{"avp_print", (cmd_function)w_print_avps, 0, 0, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"avp_db_load", (cmd_function)w_dbload_avps,  2, fixup_db_load_avp, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"avp_db_load", (cmd_function)w_dbload_avps,  3, fixup_db_load_avp, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"avp_db_load", (cmd_function)w_dbload_avps,  4, fixup_db_load_avp, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"avp_db_delete", (cmd_function)w_dbdelete_avps, 2, fixup_db_delete_avp, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"avp_db_delete", (cmd_function)w_dbdelete_avps, 3, fixup_db_delete_avp, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"avp_db_store", (cmd_function)w_dbstore_avps,  2, fixup_db_store_avp, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"avp_db_store", (cmd_function)w_dbstore_avps,  3, fixup_db_store_avp, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"avp_db_query", (cmd_function)w_dbquery_avps, 1, fixup_db_query_avp, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"avp_db_query", (cmd_function)w_dbquery_avps, 2, fixup_db_query_avp, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"avp_db_query", (cmd_function)w_dbquery_avps, 3, fixup_db_query_avp, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"avp_delete", (cmd_function)w_delete_avps, 1, fixup_delete_avp, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"avp_copy",   (cmd_function)w_copy_avps,  2,  fixup_copy_avp, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"avp_pushto", (cmd_function)w_pushto_avps, 2, fixup_pushto_avp, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"avp_check",  (cmd_function)w_check_avps, 2, fixup_check_avp, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"avp_op",     (cmd_function)w_op_avps, 2, fixup_op_avp, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"avp_subst",  (cmd_function)w_subst,   2, fixup_subst, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"is_avp_set", (cmd_function)w_is_avp_set, 1, fixup_is_avp_set, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"avp_insert", (cmd_function)w_insert_avp, 3, fixup_insert_avp, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{0, 0, 0, 0, 0, 0}
};


/*! \brief
 * Exported parameters
 */
static param_export_t params[] = {
	{"db_url",            STR_PARAM|USE_FUNC_PARAM, (void*)add_db_url },
	{"avp_table",         STR_PARAM, &db_table.s      },
	{"use_domain",        INT_PARAM, &use_domain      },
	{"uuid_column",       STR_PARAM, &uuid_col.s      },
	{"attribute_column",  STR_PARAM, &attribute_col.s },
	{"value_column",      STR_PARAM, &value_col.s     },
	{"type_column",       STR_PARAM, &type_col.s      },
	{"username_column",   STR_PARAM, &username_col.s  },
	{"domain_column",     STR_PARAM, &domain_col.s    },
	{"db_scheme",         STR_PARAM|USE_FUNC_PARAM, (void*)avp_add_db_scheme },
	{"buf_size",          INT_PARAM, &buf_size},
	{0, 0, 0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "db_url", get_deps_sqldb_url },
		{ NULL, NULL },
	},
};

struct module_exports exports = {
	"avpops",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,  /* module version */
	DEFAULT_DLFLAGS, /* dlopen flags */
	&deps,           /* OpenSIPS module dependencies */
	cmds,       /* Exported functions */
	acmds,      /* Exported async functions */
	params,     /* Exported parameters */
	0,          /* exported statistics */
	0,          /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,			/* exported transformations */
	0,          /* extra processes */
	avpops_init,/* Module initialization function */
	(response_function) 0,
	(destroy_function) 0,
	(child_init_function) avpops_child_init /* per-child init function */
};



static int avpops_init(void)
{
	int i;

	LM_INFO("initializing...\n");

	if (db_table.s)
		db_table.len = strlen(db_table.s);
	uuid_col.len = strlen(uuid_col.s);
	attribute_col.len = strlen(attribute_col.s);
	value_col.len = strlen(value_col.s);
	type_col.len = strlen(type_col.s);
	username_col.len = strlen(username_col.s);
	domain_col.len = strlen(domain_col.s);

	/* search if any avp_db_* function is used */
	for (i=0; cmds[i].name != NULL; i++) {
		if (strncasecmp(cmds[i].name, AVPDB, sizeof(AVPDB)-1) == 0 &&
				(is_script_func_used(cmds[i].name, cmds[i].param_no))) {
			need_db=1;
		}
	}

	for (i=0; acmds[i].name != NULL; i++) {
		if (strncasecmp(acmds[i].name, AVPDB, sizeof(AVPDB)-1) == 0 &&
				(is_script_async_func_used(acmds[i].name, acmds[i].param_no))) {
			need_db=1;
		}
	}

	if (need_db) {
		default_db_url = get_default_db_url();
		if (default_db_url==NULL) {
			if (db_default_url==NULL) {
				LM_ERR("no DB URL provision into the module!\n");
				return -1;
			}
			/* if nothing explicitly set as DB URL, add automatically
			 * the default DB URL */
			if (add_db_url(STR_PARAM, db_default_url)!=0) {
				LM_ERR("failed to use the default DB URL!\n");
				return -1;
			}
			default_db_url = get_default_db_url();
			if (default_db_url==NULL) {
				LM_BUG("Really ?!\n");
				return -1;
			}
		}

		/* bind to the DB module */
		if (avpops_db_bind()<0)
			goto error;

		init_store_avps(db_columns);
	}

	printbuf = (char*)pkg_malloc((buf_size+1)*sizeof(char));
	if(printbuf==NULL) {
		LM_ERR("no pkg memory left\n");
		return -1;
	}

	return 0;
error:
	return -1;
}


static int avpops_child_init(int rank)
{
	/* skip main process and TCP manager process */
	if (!need_db || rank==PROC_MAIN || rank==PROC_TCP_MAIN)
		return 0;
	/* init DB connection */
	return avpops_db_init(&db_table, db_columns);
}


static int fixup_db_url(void ** param, int require_raw_query, int is_async)
{
	struct db_url* url;
	unsigned int ui;
	str s;

	s.s = (char*)*param;
	s.len = strlen(s.s);

	if(str2int(&s, &ui)!=0) {
		LM_ERR("bad db_url number <%s>\n", (char *)(*param));
		return E_CFG;
	}

	url = get_db_url(ui);
	if (url==NULL) {
		LM_ERR("no db_url with id <%s>\n", (char *)(*param));
		return E_CFG;
	}

	/*
	 * Since mod_init() is run before function fixups, all DB structs
	 * are initialized and all DB capabilities are populated
	 */
	if (require_raw_query && !DB_CAPABILITY(url->dbf, DB_CAP_RAW_QUERY)) {
		LM_ERR("driver for DB URL [%u] does not support raw queries\n", ui);
		return -1;
	}

	if (is_async && !DB_CAPABILITY(url->dbf, DB_CAP_ASYNC_RAW_QUERY))
		LM_WARN("async() calls for DB URL [%u] will work "
		        "in normal mode due to driver limitations\n", ui);

	pkg_free(*param);
	*param=(void *)url;
	return 0;
}

static int id2db_url(int id, int require_raw_query, int is_async,
		struct db_url** url)
{

	*url = get_db_url((unsigned int)id);
	if (*url==NULL) {
		LM_ERR("no db_url with id <%d>\n", id);
		return E_CFG;
	}

	/*
	 * Since mod_init() is run before function fixups, all DB structs
	 * are initialized and all DB capabilities are populated
	 */
	if (require_raw_query && !DB_CAPABILITY((*url)->dbf, DB_CAP_RAW_QUERY)) {
		LM_ERR("driver for DB URL [%u] does not support raw queries\n",
				(unsigned int)id);
		return -1;
	}

	if (is_async && !DB_CAPABILITY((*url)->dbf, DB_CAP_ASYNC_RAW_QUERY))
		LM_WARN("async() calls for DB URL [%u] will work "
		        "in normal mode due to driver limitations\n",
				(unsigned int)id);

	return 0;
}

/* parse the name avp again when adding an avp name prefix (param 4) */
struct db_param *dbp_fixup;

static int fixup_avp_prefix(void **param)
{
	str st, *name, *prefix;
	char *p;

	prefix = pkg_malloc(sizeof(*prefix));
	if (!prefix) {
		LM_ERR("No more pkg\n");
		return -1;
	}

	prefix->s = (char *)*param;
	prefix->len = strlen(prefix->s);

	name = get_avp_name_id(dbp_fixup->a.u.sval.pvp.pvn.u.isname.name.n);

	if (name && dbp_fixup->a.type == AVPOPS_VAL_PVAR) {

		p = pkg_malloc(name->len + prefix->len + 7);
		if (!p) {
			LM_ERR("No more pkg mem!\n");
			return -1;
		}

		memcpy(p, "$avp(", 5);
		memcpy(p + 5, prefix->s, prefix->len);
		memcpy(p + 5 + prefix->len, name->s, name->len);
		p[name->len + prefix->len + 5] = ')';
		p[name->len + prefix->len + 6] = '\0';

		st.s = p;
		st.len = prefix->len + name->len + 6;

		pv_parse_spec(&st, &dbp_fixup->a.u.sval);
	}

	*param = prefix;

	return 0;
}

static int fixup_db_avp(void** param, int param_no, int allow_scheme)
{
	struct fis_param *sp;
	struct db_param  *dbp;
	int flags;
	str s;
	char *p;

	if (default_db_url==NULL) {
		LM_ERR("no db url defined to be used by this function\n");
		return E_CFG;
	}

	flags=0;

	s.s = (char*)*param;
	if (param_no==1)
	{
		/* prepare the fis_param structure */
		sp = (struct fis_param*)pkg_malloc(sizeof(struct fis_param));
		if (sp==0) {
			LM_ERR("no more pkg mem!\n");
			return E_OUT_OF_MEM;
		}
		memset( sp, 0, sizeof(struct fis_param));

		if ( (p=strchr(s.s,'/'))!=0)
		{
			*(p++) = 0;
			/* check for extra flags/params */
			if (!strcasecmp("domain",p)) {
				flags|=AVPOPS_FLAG_DOMAIN0;
			} else if (!strcasecmp("username",p)) {
				flags|=AVPOPS_FLAG_USER0;
			} else if (!strcasecmp("uri",p)) {
				flags|=AVPOPS_FLAG_URI0;
			} else if (!strcasecmp("uuid",p)) {
				flags|=AVPOPS_FLAG_UUID0;
			} else {
				LM_ERR("unknown flag "
					"<%s>\n",p);
				return E_UNSPEC;
			}
		}
		if (*s.s!='$')
		{
			/* is a constant string -> use it as uuid*/
			sp->opd = ((flags==0)?AVPOPS_FLAG_UUID0:flags)|AVPOPS_VAL_STR;
			sp->u.s.s = (char*)pkg_malloc(strlen(s.s)+1);
			if (sp->u.s.s==0) {
				LM_ERR("no more pkg mem!!\n");
				return E_OUT_OF_MEM;
			}
			sp->u.s.len = strlen(s.s);
			strcpy(sp->u.s.s, s.s);
		} else {
			/* is a variable $xxxxx */
			s.len = strlen(s.s);
			p = pv_parse_spec(&s, &sp->u.sval);
			if (p==0 || sp->u.sval.type==PVT_NULL || sp->u.sval.type==PVT_EMPTY)
			{
				LM_ERR("bad param 1; "
					"expected : $pseudo-variable or int/str value\n");
				return E_UNSPEC;
			}

			if(sp->u.sval.type==PVT_RURI || sp->u.sval.type==PVT_FROM
					|| sp->u.sval.type==PVT_TO || sp->u.sval.type==PVT_OURI)
			{
				sp->opd = ((flags==0)?AVPOPS_FLAG_URI0:flags)|AVPOPS_VAL_PVAR;
			} else {
				sp->opd = ((flags==0)?AVPOPS_FLAG_UUID0:flags)|AVPOPS_VAL_PVAR;
			}
		}
		*param=(void*)sp;
	} else if (param_no==2) {
		/* compose the db_param structure */
		dbp = (struct db_param*)pkg_malloc(sizeof(struct db_param));
		if (dbp==0)
		{
			LM_ERR("no more pkg mem!!!\n");
			return E_OUT_OF_MEM;
		}
		memset( dbp, 0, sizeof(struct db_param));
		if ( parse_avp_db( s.s, dbp, allow_scheme)!=0 )
		{
			LM_ERR("parse failed\n");
			return E_UNSPEC;
		}

		dbp_fixup = dbp;
		*param=(void*)dbp;
	} else if (param_no==3) {
		return fixup_db_url(param, 0, 0);
	} else if (param_no==4) {
		return fixup_avp_prefix(param);
	}

	return 0;
}


static int fixup_db_load_avp(void** param, int param_no)
{
	return fixup_db_avp( param, param_no, 1/*allow scheme*/);
}

static int fixup_db_delete_avp(void** param, int param_no)
{
	return fixup_db_avp( param, param_no, 0/*no scheme*/);
}


static int fixup_db_store_avp(void** param, int param_no)
{
	return fixup_db_avp( param, param_no, 0/*no scheme*/);
}

/**
 * @is_async - if set, a warning will be thrown if the underlying
 *	driver does not support async operations, and will run queries in sync mode
 */
static int __fixup_db_query_avp(void** param, int param_no, int is_async)
{
	int type;

	pv_elem_t *model = NULL;
	pvname_list_t *anlist = NULL;
	str s;

	if (default_db_url==NULL) {
		LM_ERR("no db url defined to be used by this function\n");
		return E_CFG;
	}

	s.s = (char*)(*param);
	if (param_no==1)
	{
		if(s.s==NULL)
		{
			LM_ERR("null format in P%d\n",
					param_no);
			return E_UNSPEC;
		}
		s.len = strlen(s.s);
		if(pv_parse_format(&s, &model)<0)
		{
			LM_ERR("wrong format[%s]\n", s.s);
			return E_UNSPEC;
		}

		*param = (void*)model;
		return 0;
	} else if(param_no==2) {
		if(s.s==NULL || s.s[0]==0) {
			*param = NULL;
			return 0;
		}
		s.len = strlen(s.s);

		anlist = parse_pvname_list(&s, PVT_AVP);
		if(anlist==NULL)
		{
			LM_ERR("bad format in P%d [%s]\n", param_no, s.s);
			return E_UNSPEC;
		}
		*param = (void*)anlist;
		return 0;
	} else if (param_no==3) {
		struct db_url_container *db_id;

		if (*param==NULL)
			return 0;

		if (fixup_igp(param) < 0) {
			LM_ERR("fixup failed for param #3!\n");
			return -1;
		}

		db_id=pkg_malloc(sizeof(struct db_url_container));
		if (db_id==NULL) {
			LM_ERR("no more pkg!\n");
			return -1;
		}

		if ((type=((gparam_p)*param)->type) == GPARAM_TYPE_INT) {
			db_id->type   = URL;

			if (id2db_url(((gparam_p)*param)->v.ival,
							1, is_async, &db_id->u.url) < 0) {
				LM_ERR("failed to get db url!\n");

				return E_CFG;
			}
		} else if (type == GPARAM_TYPE_STR) {
			unsigned int int_id;
			if (str2int(&((gparam_p)*param)->v.sval, &int_id) < 0) {
				LM_ERR("failed to get db id!\n");
				return -1;
			}

			db_id->type   = URL;

			if (id2db_url(int_id, 1, is_async, &db_id->u.url) < 0) {
				LM_ERR("failed to get db url!\n");
				return E_CFG;
			}
		}
		else if(type==GPARAM_TYPE_PVS||type==GPARAM_TYPE_PVE){
			db_id->type   = GPARAM;
			db_id->u.gp = (gparam_p)*param;
		} else {
			LM_ERR("invalid value for param #3!\n");
			return E_CFG;
		}

		*param = db_id;
	}

	return 0;
}

static int fixup_db_query_avp(void** param, int param_no)
{
	return __fixup_db_query_avp(param, param_no, 0);
}

static int fixup_async_db_query_avp(void** param, int param_no)
{
	return __fixup_db_query_avp(param, param_no, 1);
}

static int fixup_delete_avp(void** param, int param_no)
{
	struct fis_param *ap=NULL;
	char *p;
	char *s;
	unsigned int flags;
	str s0;

	s = (char*)(*param);
	if (param_no==1) {
		/* attribute name / alias */
		if ( (p=strchr(s,'/'))!=0 )
			*(p++)=0;

		if(*s=='$')
		{
			/* is variable */
			ap = avpops_parse_pvar(s);
			if (ap==0)
			{
				LM_ERR("unable to get"
					" pseudo-variable in param \n");
				return E_UNSPEC;
			}
			if (ap->u.sval.type!=PVT_AVP)
			{
				LM_ERR("bad param; expected : $avp(name)\n");
				return E_UNSPEC;
			}
			ap->opd|=AVPOPS_VAL_PVAR;
			ap->type = AVPOPS_VAL_PVAR;
		} else {
			if(strlen(s)<1)
			{
				LM_ERR("bad param - expected : $avp(name), *, s or i value\n");
				return E_UNSPEC;
			}
			ap = (struct fis_param*)pkg_malloc(sizeof(struct fis_param));
			if (ap==0)
			{
				LM_ERR(" no more pkg mem\n");
				return E_OUT_OF_MEM;
			}
			memset(ap, 0, sizeof(struct fis_param));
			ap->opd|=AVPOPS_VAL_NONE;
			switch(*s) {
				case 's': case 'S':
					ap->opd = AVPOPS_VAL_NONE|AVPOPS_VAL_STR;
				break;
				case 'i': case 'I':
					ap->opd = AVPOPS_VAL_NONE|AVPOPS_VAL_INT;
				break;
				case '*': case 'a': case 'A':
					ap->opd = AVPOPS_VAL_NONE;
				break;
				default:
					LM_ERR(" bad param - expected : *, s or i AVP flag\n");
					pkg_free(ap);
					return E_UNSPEC;
			}
			/* flags */
			flags = 0;
			if(*(s+1)!='\0')
			{
				s0.s = s+1;
				s0.len = strlen(s0.s);
				if(str2int(&s0, &flags)!=0)
				{
					LM_ERR("bad avp flags\n");
					pkg_free(ap);
					return E_UNSPEC;
				}
			}
			ap->type = AVPOPS_VAL_INT;
			ap->u.n = flags<<8;
		}

		/* flags */
		for( ; p&&*p ; p++ )
		{
			switch (*p)
			{
				case 'g':
				case 'G':
					ap->ops|=AVPOPS_FLAG_ALL;
					break;
				default:
					LM_ERR(" bad flag <%c>\n",*p);
					if(ap!=NULL)
						pkg_free(ap);
					return E_UNSPEC;
			}
		}
		/* force some flags: if no avp name is given, force "all" flag */
		if (ap->opd&AVPOPS_VAL_NONE)
			ap->ops |= AVPOPS_FLAG_ALL;

		*param=(void*)ap;
	}

	return 0;
}

static int fixup_copy_avp(void** param, int param_no)
{
	struct fis_param *ap;
	char *s;
	char *p;

	s = (char*)*param;
	ap = 0;
	p = 0;

	if (param_no==2)
	{
		/* avp / flags */
		if ( (p=strchr(s,'/'))!=0 )
			*(p++)=0;
	}

	ap = avpops_parse_pvar(s);
	if (ap==0)
	{
		LM_ERR("unable to get pseudo-variable in P%d\n", param_no);
		return E_OUT_OF_MEM;
	}

	/* attr name is mandatory */
	if (ap->u.sval.type!=PVT_AVP)
	{
		LM_ERR("you must specify only AVP as parameter\n");
		return E_UNSPEC;
	}

	if (param_no==2)
	{
		/* flags */
		for( ; p&&*p ; p++ )
		{
			switch (*p) {
				case 'g':
				case 'G':
					ap->ops|=AVPOPS_FLAG_ALL;
					break;
				case 'd':
				case 'D':
					ap->ops|=AVPOPS_FLAG_DELETE;
					break;
				case 'n':
				case 'N':
					ap->ops|=AVPOPS_FLAG_CASTN;
					break;
				case 's':
				case 'S':
					ap->ops|=AVPOPS_FLAG_CASTS;
					break;
				default:
					LM_ERR("bad flag <%c>\n",*p);
					return E_UNSPEC;
			}
		}
	}

	*param=(void*)ap;
	return 0;
}

static int fixup_pushto_avp(void** param, int param_no)
{
	struct fis_param *ap;
	char *s;
	char *p;

	s = (char*)*param;
	ap = 0;

	if (param_no==1)
	{
		if ( *s!='$')
		{
			LM_ERR("bad param 1; expected : $ru $du ...\n");
			return E_UNSPEC;
		}
		/* compose the param structure */

		if ( (p=strchr(s,'/'))!=0 )
			*(p++)=0;
		ap = avpops_parse_pvar(s);
		if (ap==0)
		{
			LM_ERR("unable to get pseudo-variable in param 1\n");
			return E_OUT_OF_MEM;
		}

		switch(ap->u.sval.type) {
			case PVT_RURI:
				ap->opd = AVPOPS_VAL_NONE|AVPOPS_USE_RURI;
				if ( p && !(
					(!strcasecmp("username",p)
							&& (ap->opd|=AVPOPS_FLAG_USER0)) ||
					(!strcasecmp("domain",p)
							&& (ap->opd|=AVPOPS_FLAG_DOMAIN0)) ))
				{
					LM_ERR("unknown ruri flag \"%s\"!\n",p);
					return E_UNSPEC;
				}
			break;
			case PVT_DSTURI:
				if ( p!=0 )
				{
					LM_ERR("unknown duri flag \"%s\"!\n",p);
					return E_UNSPEC;
				}
				ap->opd = AVPOPS_VAL_NONE|AVPOPS_USE_DURI;
			break;
			case PVT_HDR:
				/* what's the hdr destination ? request or reply? */
				LM_ERR("push to header is obsolete - use append_hf() "
						"or append_to_reply() from textops module!\n");
				return E_UNSPEC;
			break;
			case PVT_BRANCH:
				if ( p!=0 )
				{
					LM_ERR("unknown branch flag \"%s\"!\n",p);
					return E_UNSPEC;
				}
				ap->opd = AVPOPS_VAL_NONE|AVPOPS_USE_BRANCH;
			break;
			default:
				LM_ERR("unsupported destination \"%s\"; "
						"expected $ru,$du,$br\n",s);
				return E_UNSPEC;
		}
	} else if (param_no==2) {
		/* attribute name*/
		if ( *s!='$')
		{
			LM_ERR("bad param 1; expected :$pseudo-variable ...\n");
			return E_UNSPEC;
		}
		/* compose the param structure */

		if ( (p=strchr(s,'/'))!=0 )
			*(p++)=0;
		ap = avpops_parse_pvar(s);
		if (ap==0)
		{
			LM_ERR("unable to get pseudo-variable in param 2\n");
			return E_OUT_OF_MEM;
		}
		if (ap->u.sval.type==PVT_NULL)
		{
			LM_ERR("bad param 2; expected : $pseudo-variable ...\n");
			pkg_free(ap);
			return E_UNSPEC;
		}
		ap->opd |= AVPOPS_VAL_PVAR;

		/* flags */
		for( ; p&&*p ; p++ )
		{
			switch (*p) {
				case 'g':
				case 'G':
					ap->ops|=AVPOPS_FLAG_ALL;
					break;
				default:
					LM_ERR("bad flag <%c>\n",*p);
					pkg_free(ap);
					return E_UNSPEC;
			}
		}
	}

	*param=(void*)ap;
	return 0;
}

static int fixup_check_avp(void** param, int param_no)
{
	struct fis_param *ap;
	regex_t* re;
	char *s;

	s = (char*)*param;
	ap = 0;

	if (param_no==1)
	{
		ap = avpops_parse_pvar(s);
		if (ap==0)
		{
			LM_ERR(" unable to get pseudo-variable in P1\n");
			return E_OUT_OF_MEM;
		}
		/* attr name is mandatory */
		if (ap->u.sval.type==PVT_NULL)
		{
			LM_ERR("null pseudo-variable in P1\n");
			return E_UNSPEC;
		}
	} else if (param_no==2) {
		if ( (ap=parse_check_value(s))==0 )
		{
			LM_ERR(" failed to parse checked value \n");
			return E_UNSPEC;
		}
		/* if REGEXP op -> compile the expression */
		if (ap->ops&AVPOPS_OP_RE)
		{
			if ( (ap->opd&AVPOPS_VAL_STR)==0 )
			{
				LM_ERR(" regexp operation requires string value\n");
				return E_UNSPEC;
			}
			re = pkg_malloc(sizeof(regex_t));
			if (re==0)
			{
				LM_ERR(" no more pkg mem\n");
				return E_OUT_OF_MEM;
			}
			LM_DBG("compiling regexp <%.*s>\n", ap->u.s.len, ap->u.s.s);
			if (regcomp(re, ap->u.s.s,
						REG_EXTENDED|REG_ICASE|REG_NEWLINE))
			{
				pkg_free(re);
				LM_ERR("bad re <%.*s>\n", ap->u.s.len, ap->u.s.s);
				return E_BAD_RE;
			}
			/* free the string and link the regexp */
			// pkg_free(ap->sval.p.s);
			ap->u.s.s = (char*)re;
		} else if (ap->ops&AVPOPS_OP_FM) {
			if ( !( ap->opd&AVPOPS_VAL_PVAR ||
			(!(ap->opd&AVPOPS_VAL_PVAR) && ap->opd&AVPOPS_VAL_STR) ) )
			{
				LM_ERR(" fast_match operation requires string value or "
						"avp name/alias (%d/%d)\n",	ap->opd, ap->ops);
				return E_UNSPEC;
			}
		}
	}

	*param=(void*)ap;
	return 0;
}

static int fixup_subst(void** param, int param_no)
{
	struct subst_expr* se;
	str subst;
	struct fis_param *ap;
	struct fis_param **av;
	char *s;
	char *p;

	if (param_no==1) {
		s = (char*)*param;
		ap = 0;
		p = 0;
		av = (struct fis_param**)pkg_malloc(2*sizeof(struct fis_param*));
		if(av==NULL)
		{
			LM_ERR("no more pkg memory\n");
			return E_UNSPEC;
		}
		memset(av, 0, 2*sizeof(struct fis_param*));

		/* avp src / avp dst /flags */
		if ( (p=strchr(s,'/'))!=0 )
			*(p++)=0;
		ap = avpops_parse_pvar(s);
		if (ap==0)
		{
			LM_ERR("unable to get pseudo-variable in param 2 [%s]\n", s);
			return E_OUT_OF_MEM;
		}
		if (ap->u.sval.type!=PVT_AVP)
		{
			LM_ERR("bad attribute name <%s>\n", (char*)*param);
			pkg_free(av);
			return E_UNSPEC;
		}
		/* attr name is mandatory */
		if (ap->opd&AVPOPS_VAL_NONE)
		{
			LM_ERR("you must specify a name for the AVP\n");
			return E_UNSPEC;
		}
		av[0] = ap;
		if(p==0 || *p=='\0')
		{
			*param=(void*)av;
			return 0;
		}

		/* dst || flags */
		s = p;
		if(*s==PV_MARKER)
		{
			if ( (p=strchr(s,'/'))!=0 )
				*(p++)=0;
			if(p==0 || (p!=0 && p-s>1))
			{
				ap = avpops_parse_pvar(s);
				if (ap==0)
				{
					LM_ERR("unable to get pseudo-variable in param 2 [%s]\n",s);
					return E_OUT_OF_MEM;
				}

				if (ap->u.sval.type!=PVT_AVP)
				{
					LM_ERR("bad attribute name <%s>!\n", s);
					pkg_free(av);
					return E_UNSPEC;
				}
				/* attr name is mandatory */
				if (ap->opd&AVPOPS_VAL_NONE)
				{
					LM_ERR("you must specify a name for the AVP!\n");
					return E_UNSPEC;
				}
				av[1] = ap;
			}
			if(p==0 || *p=='\0')
			{
				*param=(void*)av;
				return 0;
			}
		}

		/* flags */
		for( ; p&&*p ; p++ )
		{
			switch (*p) {
				case 'g':
				case 'G':
					av[0]->ops|=AVPOPS_FLAG_ALL;
					break;
				case 'd':
				case 'D':
					av[0]->ops|=AVPOPS_FLAG_DELETE;
					break;
				default:
					LM_ERR("bad flag <%c>\n",*p);
					return E_UNSPEC;
			}
		}
		*param=(void*)av;
	} else if (param_no==2) {
		LM_DBG("%s fixing %s\n", exports.name, (char*)(*param));
		subst.s=*param;
		subst.len=strlen(*param);
		se=subst_parser(&subst);
		if (se==0){
			LM_ERR("%s: bad subst re %s\n",exports.name, (char*)*param);
			return E_BAD_RE;
		}
		/* don't free string -- needed for specifiers */
		/* pkg_free(*param); */
		/* replace it with the compiled subst. re */
		*param=se;
	}

	return 0;
}

static int fixup_op_avp(void** param, int param_no)
{
	struct fis_param *ap;
	struct fis_param **av;
	char *s;
	char *p;

	s = (char*)*param;
	ap = 0;

	if (param_no==1)
	{
		av = (struct fis_param**)pkg_malloc(2*sizeof(struct fis_param*));
		if(av==NULL)
		{
			LM_ERR("no more pkg memory\n");
			return E_UNSPEC;
		}
		memset(av, 0, 2*sizeof(struct fis_param*));
		/* avp src / avp dst */
		if ( (p=strchr(s,'/'))!=0 )
			*(p++)=0;

		av[0] = avpops_parse_pvar(s);
		if (av[0]==0)
		{
			LM_ERR("unable to get pseudo-variable in param 1\n");
			return E_OUT_OF_MEM;
		}
		if (av[0]->u.sval.type!=PVT_AVP)
		{
			LM_ERR("bad attribute name <%s>\n", (char*)*param);
			pkg_free(av);
			return E_UNSPEC;
		}
		if(p==0 || *p=='\0')
		{
			*param=(void*)av;
			return 0;
		}

		s = p;
		ap = avpops_parse_pvar(s);
		if (ap==0)
		{
			LM_ERR("unable to get pseudo-variable in param 1 (2)\n");
			return E_OUT_OF_MEM;
		}
		if (ap->u.sval.type!=PVT_AVP)
		{
			LM_ERR("bad attribute name/alias <%s>!\n", s);
			pkg_free(av);
			return E_UNSPEC;
		}
		av[1] = ap;
		*param=(void*)av;
		return 0;
	} else if (param_no==2) {
		if ( (ap=parse_op_value(s))==0 )
		{
			LM_ERR("failed to parse the value \n");
			return E_UNSPEC;
		}
		/* only integer values or avps */
		if ( (ap->opd&AVPOPS_VAL_STR)!=0 && (ap->opd&AVPOPS_VAL_PVAR)==0)
		{
			LM_ERR("operations requires integer values\n");
			return E_UNSPEC;
		}
		*param=(void*)ap;
		return 0;
	}
	return -1;
}

static int fixup_is_avp_set(void** param, int param_no)
{
	struct fis_param *ap;
	char *p;
	char *s;

	s = (char*)(*param);
	if (param_no==1) {
		/* attribute name | alias / flags */
		if ( (p=strchr(s,'/'))!=0 )
			*(p++)=0;

		ap = avpops_parse_pvar(s);
		if (ap==0)
		{
			LM_ERR("unable to get pseudo-variable in param\n");
			return E_OUT_OF_MEM;
		}

		if (ap->u.sval.type!=PVT_AVP)
		{
			LM_ERR("bad attribute name <%s>\n", (char*)*param);
			return E_UNSPEC;
		}
		if(p==0 || *p=='\0')
			ap->ops|=AVPOPS_FLAG_ALL;

		/* flags */
		for( ; p&&*p ; p++ )
		{
			switch (*p) {
				case 'e':
				case 'E':
					ap->ops|=AVPOPS_FLAG_EMPTY;
					break;
				case 'n':
				case 'N':
					if(ap->ops&AVPOPS_FLAG_CASTS)
					{
						LM_ERR("invalid flag combination <%c> and 's|S'\n",*p);
						return E_UNSPEC;
					}
					ap->ops|=AVPOPS_FLAG_CASTN;
					break;
				case 's':
				case 'S':
					if(ap->ops&AVPOPS_FLAG_CASTN)
					{
						LM_ERR("invalid flag combination <%c> and 'n|N'\n",*p);
						return E_UNSPEC;
					}
					ap->ops|=AVPOPS_FLAG_CASTS;
					break;
				default:
					LM_ERR("bad flag <%c>\n",*p);
					return E_UNSPEC;
			}
		}

		*param=(void*)ap;
	}

	return 0;
}

static int fixup_insert_avp(void** param, int param_no)
{
	pv_elem_t* pv_elem;
	str s;

	if(param_no== 0)
		return 0;

	if(!param)
	{
		LM_ERR( "null format\n");
		return E_UNSPEC;
	}

	s.s = (char*)(*param); s.len = strlen(s.s);

	if(param_no == 3) /* the third argumet in an integer */
	{
		unsigned int* index;

		index = (unsigned int*)pkg_malloc(sizeof(unsigned int));
		if(index == NULL)
		{
			LM_ERR("No more memory\n");
			return E_OUT_OF_MEM;
		}

		if(str2int(&s, index) < 0)
		{
			LM_ERR("Bad format for the third argument - must be a positive integer\n");
			return E_UNSPEC;
		}
		*param = (void*)index;
		return 0;
	}

	if(pv_parse_format(&s, &pv_elem)<0)
	{
		LM_ERR( "wrong format[%s]\n",(char*)(*param));
		return E_UNSPEC;
	}
	*param = (void*)pv_elem;

	/* attr name is mandatory */
	if (param_no == 1 && pv_elem->spec.type!=PVT_AVP)
	{
		LM_ERR("The first parameter must be an AVP name\n");
		return E_UNSPEC;
	}

	*param = (void*)pv_elem;

	return 0;
}


static int w_dbload_avps(struct sip_msg* msg, char* source,
										char* param, char *url, char *prefix)
{
	return ops_dbload_avps ( msg, (struct fis_param*)source,
		(struct db_param*)param,
		url?(struct db_url*)url:default_db_url,
		use_domain, (str *)prefix);
}

static int w_dbdelete_avps(struct sip_msg* msg, char* source,
										char* param, char *url)
{
	return ops_dbdelete_avps ( msg, (struct fis_param*)source,
		(struct db_param*)param,
		url?(struct db_url*)url:default_db_url,
		use_domain);
}

static int w_dbstore_avps(struct sip_msg* msg, char* source,
													char* param, char *url)
{
	return ops_dbstore_avps ( msg, (struct fis_param*)source,
		(struct db_param*)param,
		url?(struct db_url*)url:default_db_url,
		use_domain);
}


static inline int get_url(struct sip_msg* msg, struct db_url_container* _url_struc,
								struct db_url** parsed_url, int is_async)
{
	int id=0;
	unsigned int gp_flags;

	str sid;
	gparam_p gp;

	if (_url_struc) {
		if (_url_struc->type == GPARAM) {
			gp = _url_struc->u.gp;
			if (fixup_get_isvalue(msg, gp, &id, &sid, &gp_flags) < 0
					|| !(gp_flags&GPARAM_INT_VALUE_FLAG)) {
				LM_ERR("Failed to fetch PVAR str value!\n");
				return -1;
			}

			if (id2db_url(id,1, is_async, parsed_url)) {
				LM_ERR("failed to get db url!\n");
				return -1;
			}
		} else {
			*parsed_url = _url_struc->u.url;
		}
	} else {
		*parsed_url = default_db_url;
	}

	return 0;
}

static int w_dbquery_avps(struct sip_msg* msg, char* query,
													char* dest, char *url)
{
	struct db_url *parsed_url;

	if (get_url(msg, (struct db_url_container*)url, &parsed_url, 0) < 0) {
		LM_ERR("failed to get db url\n");
		return -1;
	}

	return ops_dbquery_avps ( msg, (pv_elem_t*)query,
		parsed_url, (pvname_list_t*)dest);
}

static int w_async_dbquery_avps(struct sip_msg* msg, async_ctx *ctx,
		char* query, char* dest, char* url)
{
	struct db_url *parsed_url;

	if (get_url(msg, (struct db_url_container*)url, &parsed_url, 1) < 0) {
		LM_ERR("failed to get db url\n");
		return -1;
	}

	return ops_async_dbquery(msg, ctx, (pv_elem_t *)query,
			parsed_url, (pvname_list_t *)dest);
}

static int w_delete_avps(struct sip_msg* msg, char* param, char* foo)
{
	return ops_delete_avp ( msg, (struct fis_param*)param);
}

static int w_copy_avps(struct sip_msg* msg, char* name1, char *name2)
{
	return ops_copy_avp ( msg, (struct fis_param*)name1,
								(struct fis_param*)name2);
}

static int w_pushto_avps(struct sip_msg* msg, char* destination, char *param)
{
	return ops_pushto_avp ( msg, (struct fis_param*)destination,
								(struct fis_param*)param);
}

static int w_check_avps(struct sip_msg* msg, char* param, char *check)
{
	return ops_check_avp ( msg, (struct fis_param*)param,
								(struct fis_param*)check);
}

static int w_op_avps(struct sip_msg* msg, char* param, char *op)
{
	return ops_op_avp ( msg, (struct fis_param**)param,
								(struct fis_param*)op);
}

static int w_subst(struct sip_msg* msg, char* src, char *subst)
{
	return ops_subst(msg, (struct fis_param**)src, (struct subst_expr*)subst);
}

static int w_is_avp_set(struct sip_msg* msg, char* param, char *op)
{
	return ops_is_avp_set(msg, (struct fis_param*)param);
}

static int w_print_avps(struct sip_msg* msg, char* foo, char *bar)
{
	return ops_print_avp();
}

