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

static int avpops_init(void);
static int avpops_child_init(int rank);
static int avpops_cfg_validate(void);

static int fixup_db_avp_source(void** param);
static int fixup_db_avp_dbparam_scheme(void** param);
static int fixup_db_avp_dbparam(void** param);
static int fixup_db_url(void ** param);
static int fixup_avp_prefix(void **param);

static int fixup_copy_avp(void** param, int param_no);
static int fixup_avp_copy_p1(void** param);
static int fixup_avp_copy_p2(void** param);
static int fixup_pushto_avp_p1(void** param);
static int fixup_pushto_avp_p2(void** param);
static int fixup_check_avp_p1(void** param);
static int fixup_check_avp_p2(void** param);
static int fixup_op_avp_p1(void** param);
static int fixup_op_avp_p2(void** param);
static int fixup_avp_subst_p1(void** param);
static int fixup_avp_subst_p2(void** param);
static int fixup_subst(void **param, int param_no);
static int fixup_is_avp_set_p1(void** param);
static int fixup_db_id_sync(void** param);
static int fixup_db_id_async(void** param);
static int fixup_pvname_list(void** param);

static int fixup_avp_del_name(void** param);
static int fixup_free_check_avp_p2(void** param);
static int fixup_free_avp_subst_p1(void** param);
static int fixup_free_avp_subst_p2(void** param);
static int fixup_free_pvname_list(void** param);
static int fixup_free_avp_dbparam(void** param);

static int w_print_avps(struct sip_msg* msg, char* foo, char *bar);
static int w_dbload_avps(struct sip_msg* msg, void* source,
                         void* param, void *url, str *prefix);
static int w_dbdelete_avps(struct sip_msg* msg, void* source,
                           void* param, void *url);
static int w_dbstore_avps(struct sip_msg* msg, void* source,
                          void* param, void *url);
static int w_dbquery_avps(struct sip_msg* msg, str* query,
                          void* dest, void *url);
static int w_async_dbquery_avps(struct sip_msg* msg, async_ctx *ctx,
                                str* query, void* dest, void* url);
static int w_delete_avps(struct sip_msg* msg, void* param);
static int w_copy_avps(struct sip_msg* msg, void* name1, void *name2);
static int w_pushto_avps(struct sip_msg* msg, void* destination, void *param);
static int w_check_avps(struct sip_msg* msg, void* param, void *check);
static int w_op_avps(struct sip_msg* msg, char* param, char *op);
static int w_subst(struct sip_msg* msg, char* src, char *subst);
static int w_is_avp_set(struct sip_msg* msg, char* param, char *foo);

static acmd_export_t acmds[] = {
	{"avp_db_query", (acmd_function)w_async_dbquery_avps, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_NO_EXPAND, fixup_pvname_list, fixup_free_pvname_list},
		{CMD_PARAM_INT|CMD_PARAM_OPT, fixup_db_id_async, fixup_free_pkg}, {0, 0, 0}}},
	{0, 0, {{0, 0, 0}}}
};

/*! \brief
 * Exported functions
 */
static cmd_export_t cmds[] = {
	{"avp_print", (cmd_function)w_print_avps, {{0, 0, 0}},
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},

	{"avp_db_load", (cmd_function)w_dbload_avps, {
		{CMD_PARAM_STR|CMD_PARAM_NO_EXPAND, fixup_db_avp_source, fixup_free_pkg},
		{CMD_PARAM_STR|CMD_PARAM_NO_EXPAND, fixup_db_avp_dbparam_scheme, fixup_free_avp_dbparam},
		{CMD_PARAM_INT|CMD_PARAM_OPT, fixup_db_url, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, fixup_avp_prefix, fixup_free_pkg}, {0, 0, 0}},
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},

	{"avp_db_delete", (cmd_function)w_dbdelete_avps, {
		{CMD_PARAM_STR|CMD_PARAM_NO_EXPAND, fixup_db_avp_source, fixup_free_pkg},
		{CMD_PARAM_STR|CMD_PARAM_NO_EXPAND, fixup_db_avp_dbparam, fixup_free_avp_dbparam},
		{CMD_PARAM_INT|CMD_PARAM_OPT, fixup_db_url, 0}, {0, 0, 0}},
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},

	{"avp_db_store", (cmd_function)w_dbstore_avps, {
		{CMD_PARAM_STR|CMD_PARAM_NO_EXPAND, fixup_db_avp_source, fixup_free_pkg},
		{CMD_PARAM_STR|CMD_PARAM_NO_EXPAND, fixup_db_avp_dbparam, fixup_free_avp_dbparam},
		{CMD_PARAM_INT|CMD_PARAM_OPT, fixup_db_url, 0}, {0, 0, 0}},
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},

	{"avp_db_query", (cmd_function)w_dbquery_avps, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_NO_EXPAND, fixup_pvname_list, fixup_free_pvname_list},
		{CMD_PARAM_INT|CMD_PARAM_OPT, fixup_db_id_sync, fixup_free_pkg}, {0, 0, 0}},
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},

	{"avp_delete", (cmd_function)w_delete_avps, {
		{CMD_PARAM_STR|CMD_PARAM_NO_EXPAND, fixup_avp_del_name, fixup_free_pkg}, {0, 0, 0}},
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},

	{"avp_copy",   (cmd_function)w_copy_avps,  {
		{CMD_PARAM_STR|CMD_PARAM_NO_EXPAND, fixup_avp_copy_p1, fixup_free_pkg},
		{CMD_PARAM_STR|CMD_PARAM_NO_EXPAND, fixup_avp_copy_p2, fixup_free_pkg}, {0, 0, 0}},
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},

	{"avp_pushto", (cmd_function)w_pushto_avps, {
		{CMD_PARAM_STR|CMD_PARAM_NO_EXPAND, fixup_pushto_avp_p1, fixup_free_pkg},
		{CMD_PARAM_STR|CMD_PARAM_NO_EXPAND, fixup_pushto_avp_p2, fixup_free_pkg}, {0, 0, 0}},
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},

	{"avp_check",  (cmd_function)w_check_avps, {
		{CMD_PARAM_STR|CMD_PARAM_NO_EXPAND, fixup_check_avp_p1, fixup_free_pkg},
		{CMD_PARAM_STR|CMD_PARAM_NO_EXPAND, fixup_check_avp_p2, fixup_free_check_avp_p2}, {0, 0, 0}},
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},

	{"avp_op",     (cmd_function)w_op_avps, {
		{CMD_PARAM_STR|CMD_PARAM_NO_EXPAND, fixup_op_avp_p1, fixup_free_avp_subst_p1},
		{CMD_PARAM_STR|CMD_PARAM_NO_EXPAND, fixup_op_avp_p2, fixup_free_pkg}, {0, 0, 0}},
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},

	{"avp_subst",  (cmd_function)w_subst,   {
		{CMD_PARAM_STR|CMD_PARAM_NO_EXPAND, fixup_avp_subst_p1, fixup_free_avp_subst_p1},
		{CMD_PARAM_STR, fixup_avp_subst_p2, fixup_free_avp_subst_p2}, {0, 0, 0}},
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},

	{"is_avp_set", (cmd_function)w_is_avp_set, {
		{CMD_PARAM_STR|CMD_PARAM_NO_EXPAND, fixup_is_avp_set_p1, fixup_free_pkg}, {0, 0, 0}},
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},

	{0, 0, {{0, 0, 0}}, 0}
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
	0,				 /* load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds,       /* Exported functions */
	acmds,      /* Exported async functions */
	params,     /* Exported parameters */
	0,          /* exported statistics */
	0,          /* exported MI functions */
	0,          /* exported pseudo-variables */
	0,			/* exported transformations */
	0,          /* extra processes */
	0,          /* Module pre-initialization function */
	avpops_init,/* Module initialization function */
	(response_function) 0,
	(destroy_function) 0,
	(child_init_function) avpops_child_init, /* per-child init function */
	avpops_cfg_validate /* reload confirm function */
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
				(is_script_func_used(cmds[i].name, -1))) {
			need_db=1;
		}
	}

	for (i=0; acmds[i].name != NULL; i++) {
		if (strncasecmp(acmds[i].name, AVPDB, sizeof(AVPDB)-1) == 0 &&
				(is_script_async_func_used(acmds[i].name, -1))) {
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

	return 0;
error:
	return -1;
}


static int avpops_cfg_validate(void)
{
	int i;

	/* if DB already on, everything is ok */
	if (need_db==1)
		return 1;

	/* search if any avp_db_* function is used */
	for (i=0; cmds[i].name != NULL; i++) {
		if (strncasecmp(cmds[i].name, AVPDB, sizeof(AVPDB)-1) == 0 &&
				(is_script_func_used(cmds[i].name, -1))) {
			LM_ERR("%s() was found, but module started without DB support,"
				" better restart\n",cmds[i].name);
			return 0;
		}
	}

	for (i=0; acmds[i].name != NULL; i++) {
		if (strncasecmp(acmds[i].name, AVPDB, sizeof(AVPDB)-1) == 0 &&
				(is_script_async_func_used(acmds[i].name, -1))){
			LM_ERR("%s() was found, but module started without DB support,"
				" better restart\n",acmds[i].name);
			return 0;
		}
	}

	return 1;
}


static int avpops_child_init(int rank)
{
	if (!need_db)
		return 0;
	/* init DB connection */
	return avpops_db_init(&db_table, db_columns);
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

static int fixup_db_url(void ** param)
{
	struct db_url* url;

	if (id2db_url(*(unsigned int*)*param, 0, 0, &url) < 0) {
		LM_ERR("failed to get DB URL\n");
		return E_CFG;
	}

	*param=(void *)url;
	return 0;
}


/* parse the name avp again when adding an avp name prefix (param 4) */
struct db_param *dbp_fixup;

static int fixup_avp_prefix(void **param)
{
	str st, *name, *prefix = (str *)*param;
	char *p;

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

	return 0;
}

static int fixup_db_avp(void** param, int param_no, int allow_scheme)
{
	struct fis_param *sp = NULL;
	struct db_param  *dbp;
	int flags;
	str s, cpy;
	char *p;

	if (default_db_url==NULL) {
		LM_ERR("no db url defined to be used by this function\n");
		return E_CFG;
	}

	flags=0;

	if (pkg_nt_str_dup(&cpy, (str *)*param) < 0) {
		LM_ERR("oom\n");
		return -1;
	}
	s = cpy;

	if (param_no==1)
	{
		/* prepare the fis_param structure */
		sp = (struct fis_param*)pkg_malloc(sizeof(struct fis_param));
		if (sp==0) {
			LM_ERR("no more pkg mem!\n");
			goto err_free;
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
				goto err_free;
			}
		}
		if (*s.s!='$')
		{
			/* is a constant string -> use it as uuid*/
			sp->opd = ((flags==0)?AVPOPS_FLAG_UUID0:flags)|AVPOPS_VAL_STR;
			sp->u.s.s = (char*)pkg_malloc(s.len + 1);
			if (sp->u.s.s==0) {
				LM_ERR("no more pkg mem!!\n");
				goto err_free;
			}
			sp->u.s.len = s.len;
			strcpy(sp->u.s.s, s.s);
		} else {
			/* is a variable $xxxxx */
			p = pv_parse_spec(&s, &sp->u.sval);
			if (p==0 || sp->u.sval.type==PVT_NULL || sp->u.sval.type==PVT_EMPTY)
			{
				LM_ERR("bad param 1; "
					"expected : $pseudo-variable or int/str value\n");
				goto err_free;
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
			pkg_free(dbp);
			return E_UNSPEC;
		}

		dbp_fixup = dbp;
		*param=(void*)dbp;
	}

	pkg_free(cpy.s);
	return 0;

err_free:
	pkg_free(cpy.s);
	pkg_free(sp);
	return E_UNSPEC;
}

static int fixup_db_avp_source(void** param)
{
	return fixup_db_avp(param, 1, 0);
}

static int fixup_db_avp_dbparam_scheme(void** param)
{
	return fixup_db_avp(param, 2, 1);
}

static int fixup_db_avp_dbparam(void** param)
{
	return fixup_db_avp(param, 2, 0);
}

static int fixup_free_avp_dbparam(void** param)
{
	struct db_param *dbp = (struct db_param *)*param;

	pkg_free(dbp->table.s);
	pkg_free(dbp);
	return 0;
}

static int fixup_pvname_list(void** param)
{
	pvname_list_t *anlist = NULL;
	str s = *(str *)*param;

	if(s.s==NULL || s.s[0]==0) {
		*param = NULL;
		return 0;
	}

	anlist = parse_pvname_list(&s, PVT_AVP);
	if(anlist==NULL)
	{
		LM_ERR("bad format in [%.*s]\n", s.len, s.s);
		return E_UNSPEC;
	}
	*param = (void*)anlist;
	return 0;
}

static int fixup_free_pvname_list(void** param)
{
	pvname_list_t *l = (pvname_list_t *)*param, *next;

	while (l) {
		next = l->next;
		pkg_free(l);
		l = next;
	}

	return 0;
}

static inline int fixup_db_id(void** param, int is_async)
{
	struct db_url_container *db_id;

	if (!default_db_url) {
		LM_ERR("no db url defined to be used by this function\n");
		return E_CFG;
	}

	if (*param == NULL)
		return 0;

	db_id=pkg_malloc(sizeof(struct db_url_container));
	if (db_id==NULL) {
		LM_ERR("no more pkg!\n");
		return -1;
	}

	if (id2db_url(*(int *)*param, 1, is_async, &db_id->u.url) < 0) {
		LM_ERR("failed to get db url!\n");
		pkg_free(db_id);
		return -1;
	}

	*param = db_id;
	return 0;
}

static int fixup_db_id_sync(void** param)
{
	return fixup_db_id(param, 0);
}

static int fixup_db_id_async(void** param)
{
	return fixup_db_id(param, 1);
}

static int fixup_avp_del_name(void** param)
{
	struct fis_param *ap=NULL;
	char *p;
	char *s;
	unsigned int flags;
	str s0, cpy;

	if (pkg_nt_str_dup(&cpy, (str *)*param) < 0) {
		LM_ERR("oom\n");
		return -1;
	}
	s = cpy.s;

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
			goto err_free;
		}
		if (ap->u.sval.type!=PVT_AVP)
		{
			LM_ERR("bad param; expected : $avp(name)\n");
			goto err_free;
		}
		ap->opd|=AVPOPS_VAL_PVAR;
		ap->type = AVPOPS_VAL_PVAR;
	} else {
		if(cpy.len < 1)
		{
			LM_ERR("bad param - expected : $avp(name), *, s or i value\n");
			goto err_free;
		}
		ap = (struct fis_param*)pkg_malloc(sizeof(struct fis_param));
		if (ap==0)
		{
			LM_ERR(" no more pkg mem\n");
			goto err_free;
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
				goto err_free;
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
				goto err_free;
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
				goto err_free;
		}
	}

	/* force some flags: if no avp name is given, force "all" flag */
	if (ap->opd&AVPOPS_VAL_NONE)
		ap->ops |= AVPOPS_FLAG_ALL;

	*param=(void*)ap;
	pkg_free(cpy.s);

	return 0;

err_free:
	pkg_free(cpy.s);
	pkg_free(ap);
	return E_UNSPEC;
}

static int fixup_avp_copy_p1(void** param)
{
	return fixup_copy_avp(param, 1);
}

static int fixup_avp_copy_p2(void** param)
{
	return fixup_copy_avp(param, 2);
}

static int fixup_copy_avp(void** param, int param_no)
{
	struct fis_param *ap;
	char *s;
	char *p;
	str cpy;

	if (pkg_nt_str_dup(&cpy, (str *)*param) < 0) {
		LM_ERR("oom\n");
		return -1;
	}
	s = cpy.s;

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
		goto err_free;
	}

	/* attr name is mandatory */
	if (ap->u.sval.type!=PVT_AVP)
	{
		LM_ERR("you must specify only AVP as parameter\n");
		goto err_free;
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
					goto err_free;
			}
		}
	}

	*param=(void*)ap;
	pkg_free(cpy.s);
	return 0;

err_free:
	pkg_free(cpy.s);
	return E_UNSPEC;
}

static int fixup_pushto_avp(void** param, int param_no)
{
	struct fis_param *ap = NULL;
	char *s;
	char *p;
	str cpy;

	if (pkg_nt_str_dup(&cpy, (str *)*param) < 0) {
		LM_ERR("oom\n");
		return -1;
	}
	s = cpy.s;

	if (param_no==1)
	{
		if ( *s!='$')
		{
			LM_ERR("bad param 1; expected : $ru $du ...\n");
			goto err_free;
		}
		/* compose the param structure */

		if ( (p=strchr(s,'/'))!=0 )
			*(p++)=0;
		ap = avpops_parse_pvar(s);
		if (ap==0)
		{
			LM_ERR("unable to get pseudo-variable in param 1\n");
			goto err_free;
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
					goto err_free;
				}
			break;
			case PVT_DSTURI:
				if ( p!=0 )
				{
					LM_ERR("unknown duri flag \"%s\"!\n",p);
					goto err_free;
				}
				ap->opd = AVPOPS_VAL_NONE|AVPOPS_USE_DURI;
			break;
			case PVT_HDR:
				/* what's the hdr destination ? request or reply? */
				LM_ERR("push to header is obsolete - use append_hf() "
						"or append_to_reply() from textops module!\n");
				goto err_free;
			break;
			case PVT_BRANCH:
				if ( p!=0 )
				{
					LM_ERR("unknown branch flag \"%s\"!\n",p);
					goto err_free;
				}
				ap->opd = AVPOPS_VAL_NONE|AVPOPS_USE_BRANCH;
			break;
			default:
				LM_ERR("unsupported destination \"%s\"; "
						"expected $ru,$du,$br\n",s);
				goto err_free;
		}
	} else if (param_no==2) {
		/* attribute name*/
		if ( *s!='$')
		{
			LM_ERR("bad param 1; expected :$pseudo-variable ...\n");
			goto err_free;
		}
		/* compose the param structure */

		if ( (p=strchr(s,'/'))!=0 )
			*(p++)=0;
		ap = avpops_parse_pvar(s);
		if (ap==0)
		{
			LM_ERR("unable to get pseudo-variable in param 2\n");
			goto err_free;
		}
		if (ap->u.sval.type==PVT_NULL)
		{
			LM_ERR("bad param 2; expected : $pseudo-variable ...\n");
			goto err_free;
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
					goto err_free;
			}
		}
	}

	*param=(void*)ap;
	pkg_free(cpy.s);
	return 0;

err_free:
	pkg_free(cpy.s);
	pkg_free(ap);
	return E_UNSPEC;
}

static int fixup_pushto_avp_p1(void** param)
{
	return fixup_pushto_avp(param, 1);
}

static int fixup_pushto_avp_p2(void** param)
{
	return fixup_pushto_avp(param, 2);
}

static int fixup_check_avp(void** param, int param_no)
{
	struct fis_param *ap = NULL;
	regex_t* re = NULL;
	char *s;
	str cpy;

	if (pkg_nt_str_dup(&cpy, (str *)*param) < 0) {
		LM_ERR("oom\n");
		return -1;
	}
	s = cpy.s;

	if (param_no==1)
	{
		ap = avpops_parse_pvar(s);
		if (ap==0)
		{
			LM_ERR(" unable to get pseudo-variable in P1\n");
			goto err_free;
		}
		/* attr name is mandatory */
		if (ap->u.sval.type==PVT_NULL)
		{
			LM_ERR("null pseudo-variable in P1\n");
			goto err_free;
		}
	} else if (param_no==2) {
		if ( (ap=parse_check_value(s))==0 )
		{
			LM_ERR(" failed to parse checked value \n");
			goto err_free;
		}
		/* if REGEXP op -> compile the expression */
		if (ap->ops&AVPOPS_OP_RE)
		{
			if ( (ap->opd&AVPOPS_VAL_STR)==0 )
			{
				LM_ERR(" regexp operation requires string value\n");
				goto err_free;
			}
			re = pkg_malloc(sizeof(regex_t));
			if (re==0)
			{
				LM_ERR(" no more pkg mem\n");
				goto err_free;
			}
			LM_DBG("compiling regexp <%.*s>\n", ap->u.s.len, ap->u.s.s);
			if (regcomp(re, ap->u.s.s,
						REG_EXTENDED|REG_ICASE|REG_NEWLINE))
			{
				pkg_free(re);
				LM_ERR("bad re <%.*s>\n", ap->u.s.len, ap->u.s.s);
				goto err_free;
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
				goto err_free;
			}
		}
	}

	*param=(void*)ap;
	pkg_free(cpy.s);
	return 0;

err_free:
	pkg_free(cpy.s);
	pkg_free(ap);
	pkg_free(re);
	return E_UNSPEC;
}

static int fixup_check_avp_p1(void** param)
{
	return fixup_check_avp(param, 1);
}

static int fixup_check_avp_p2(void** param)
{
	return fixup_check_avp(param, 2);
}

static int fixup_free_check_avp_p2(void** param)
{
	struct fis_param *ap = (struct fis_param *)*param;

	if (ap->ops & AVPOPS_OP_RE)
		pkg_free(ap->u.s.s);

	pkg_free(ap);
	return 0;
}

static int fixup_subst(void **param, int param_no)
{
	struct subst_expr* se = NULL;
	struct fis_param *ap = NULL;
	struct fis_param **av = NULL;
	str cpy = STR_NULL, *_param = (str *)*param;
	char *s;
	char *p;

	if (param_no==1) {
		if (pkg_nt_str_dup(&cpy, _param) < 0) {
			LM_ERR("oom\n");
			return -1;
		}
		s = cpy.s;

		ap = 0;
		p = 0;
		av = (struct fis_param**)pkg_malloc(2*sizeof(struct fis_param*));
		if(av==NULL)
		{
			LM_ERR("no more pkg memory\n");
			goto err_free;
		}
		memset(av, 0, 2*sizeof(struct fis_param*));

		/* avp src / avp dst /flags */
		if ( (p=strchr(s,'/'))!=0 )
			*(p++)=0;
		ap = avpops_parse_pvar(s);
		if (ap==0)
		{
			LM_ERR("unable to get pseudo-variable in param 2 [%s]\n", s);
			goto err_free;
		}
		if (ap->u.sval.type!=PVT_AVP)
		{
			LM_ERR("bad attribute name <%.*s>\n", _param->len, _param->s);
			pkg_free(ap);
			goto err_free;
		}
		/* attr name is mandatory */
		if (ap->opd&AVPOPS_VAL_NONE)
		{
			LM_ERR("you must specify a name for the AVP\n");
			pkg_free(ap);
			goto err_free;
		}
		av[0] = ap;
		if(p==0 || *p=='\0')
		{
			*param=(void*)av;
			goto out;
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
					goto err_free;
				}

				if (ap->u.sval.type!=PVT_AVP)
				{
					LM_ERR("bad attribute name <%s>!\n", s);
					pkg_free(ap);
					goto err_free;
				}
				/* attr name is mandatory */
				if (ap->opd&AVPOPS_VAL_NONE)
				{
					LM_ERR("you must specify a name for the AVP!\n");
					pkg_free(ap);
					goto err_free;
				}
				av[1] = ap;
			}
			if(p==0 || *p=='\0')
			{
				*param=(void*)av;
				goto out;
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
					goto err_free;
			}
		}
		*param=(void*)av;
	} else if (param_no==2) {
		LM_DBG("%s fixing %.*s\n", exports.name, _param->len, _param->s);
		se=subst_parser(_param);
		if (se==0){
			LM_ERR("%s: bad subst re: %.*s\n",exports.name, _param->len, _param->s);
			return E_BAD_RE;
		}

		/* replace it with the compiled subst. re */
		*param = se;
	}

out:
	pkg_free(cpy.s);
	return 0;

err_free:
	if (av) {
		pkg_free(av[0]);
		pkg_free(av[1]);
	}
	pkg_free(cpy.s);
	return E_UNSPEC;
}

static int fixup_avp_subst_p1(void** param)
{
	return fixup_subst(param, 1);
}

static int fixup_avp_subst_p2(void** param)
{
	return fixup_subst(param, 2);
}

static int fixup_free_avp_subst_p1(void** param)
{
	struct fis_param **av = (struct fis_param **)*param;

	if (av) {
		pkg_free(av[0]);
		pkg_free(av[1]);
	}

	return 0;
}

static int fixup_free_avp_subst_p2(void** param)
{
	if (*param)
		subst_expr_free((struct subst_expr *)*param);

	return 0;
}

static int fixup_op_avp(void** param, int param_no)
{
	struct fis_param *ap;
	struct fis_param **av = NULL;
	char *s;
	str cpy, *_param = (str *)*param;
	char *p;

	if (pkg_nt_str_dup(&cpy, _param) < 0) {
		LM_ERR("oom\n");
		return -1;
	}
	s = cpy.s;

	ap = 0;

	if (param_no==1)
	{
		av = (struct fis_param**)pkg_malloc(2*sizeof(struct fis_param*));
		if(av==NULL)
		{
			LM_ERR("no more pkg memory\n");
			goto err_free;
		}
		memset(av, 0, 2*sizeof(struct fis_param*));
		/* avp src / avp dst */
		if ( (p=strchr(s,'/'))!=0 )
			*(p++)=0;

		av[0] = avpops_parse_pvar(s);
		if (av[0]==0)
		{
			LM_ERR("unable to get pseudo-variable in param 1\n");
			goto err_free;
		}
		if (av[0]->u.sval.type!=PVT_AVP)
		{
			LM_ERR("bad attribute name <%s>\n", (char*)*param);
			goto err_free;
		}
		if(p==0 || *p=='\0')
		{
			*param=(void*)av;
			goto out;
		}

		s = p;
		ap = avpops_parse_pvar(s);
		if (ap==0)
		{
			LM_ERR("unable to get pseudo-variable in param 1 (2)\n");
			goto err_free;
		}
		if (ap->u.sval.type!=PVT_AVP)
		{
			LM_ERR("bad attribute name/alias <%s>!\n", s);
			goto err_free;
		}
		av[1] = ap;
		*param=(void*)av;
	} else if (param_no==2) {
		if ( (ap=parse_op_value(s))==0 )
		{
			LM_ERR("failed to parse the value \n");
			goto err_free;
		}
		/* only integer values or avps */
		if ( (ap->opd&AVPOPS_VAL_STR)!=0 && (ap->opd&AVPOPS_VAL_PVAR)==0)
		{
			LM_ERR("operations requires integer values\n");
			pkg_free(ap);
			goto err_free;
		}
		*param=(void*)ap;
	}

out:
	pkg_free(cpy.s);
	return 0;

err_free:
	pkg_free(cpy.s);
	if (av) {
		pkg_free(av[0]);
		pkg_free(av[1]);
	}
	return E_UNSPEC;
}

static int fixup_op_avp_p1(void** param)
{
	return fixup_op_avp(param, 1);
}

static int fixup_op_avp_p2(void** param)
{
	return fixup_op_avp(param, 2);
}

static int fixup_is_avp_set(void** param, int param_no)
{
	struct fis_param *ap = NULL;
	char *p;
	char *s;
	str cpy, *_param = (str *)*param;

	if (pkg_nt_str_dup(&cpy, _param) < 0) {
		LM_ERR("oom\n");
		return -1;
	}
	s = cpy.s;

	if (param_no==1) {
		/* attribute name | alias / flags */
		if ( (p=strchr(s,'/'))!=0 )
			*(p++)=0;

		ap = avpops_parse_pvar(s);
		if (ap==0)
		{
			LM_ERR("unable to get pseudo-variable in param\n");
			goto err_free;
		}

		if (ap->u.sval.type!=PVT_AVP)
		{
			LM_ERR("bad attribute name <%s>\n", (char*)*param);
			goto err_free;
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
						goto err_free;
					}
					ap->ops|=AVPOPS_FLAG_CASTS;
					break;
				default:
					LM_ERR("bad flag <%c>\n",*p);
					goto err_free;
			}
		}

		*param=(void*)ap;
	}

	pkg_free(cpy.s);
	return 0;

err_free:
	pkg_free(cpy.s);
	pkg_free(ap);
	return E_UNSPEC;
}

static int fixup_is_avp_set_p1(void** param)
{
	return fixup_is_avp_set(param, 1);
}


static int w_dbload_avps(struct sip_msg* msg, void* source,
                         void* param, void *url, str *prefix)
{
	return ops_dbload_avps ( msg, (struct fis_param*)source,
		(struct db_param*)param,
		url?(struct db_url*)url:default_db_url, use_domain, prefix);
}

static int w_dbdelete_avps(struct sip_msg* msg, void* source,
                           void* param, void *url)
{
	return ops_dbdelete_avps ( msg, (struct fis_param*)source,
		(struct db_param*)param,
		url?(struct db_url*)url:default_db_url,
		use_domain);
}

static int w_dbstore_avps(struct sip_msg* msg, void* source,
                          void* param, void *url)
{
	return ops_dbstore_avps ( msg, (struct fis_param*)source,
		(struct db_param*)param,
		url?(struct db_url*)url:default_db_url,
		use_domain);
}


static int w_dbquery_avps(struct sip_msg* msg, str* query,
                          void* dest, void *url)
{
	struct db_url *parsed_url;

	if (url)
		parsed_url = ((struct db_url_container *)url)->u.url;
	else
		parsed_url = default_db_url;

	return ops_dbquery_avps(msg, query, parsed_url, (pvname_list_t*)dest);
}

static int w_async_dbquery_avps(struct sip_msg* msg, async_ctx *ctx,
                                str* query, void* dest, void* url)
{
	struct db_url *parsed_url;

	if (url)
		parsed_url = ((struct db_url_container *)url)->u.url;
	else
		parsed_url = default_db_url;

	return ops_async_dbquery(msg, ctx, query, parsed_url, (pvname_list_t *)dest);
}

static int w_delete_avps(struct sip_msg* msg, void* param)
{
	return ops_delete_avp ( msg, (struct fis_param*)param);
}

static int w_copy_avps(struct sip_msg* msg, void* name1, void *name2)
{
	return ops_copy_avp ( msg, (struct fis_param*)name1,
								(struct fis_param*)name2);
}

static int w_pushto_avps(struct sip_msg* msg, void* destination, void *param)
{
	return ops_pushto_avp ( msg, (struct fis_param*)destination,
								(struct fis_param*)param);
}

static int w_check_avps(struct sip_msg* msg, void* param, void *check)
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

