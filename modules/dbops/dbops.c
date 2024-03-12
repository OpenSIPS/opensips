/*
 * Copyright (C) 2008-2024 OpenSIPS Solutions
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
#include "dbops_parse.h"
#include "dbops_impl.h"
#include "dbops_db.h"

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

static int dbops_init(void);
static int dbops_child_init(int rank);

static int fixup_db_avp_source(void** param);
static int fixup_db_avp_dbparam_scheme(void** param);
static int fixup_db_avp_dbparam(void** param);
static int fixup_db_url(void ** param);
static int fixup_avp_prefix(void **param);

static int fixup_db_id_sync(void** param);
static int fixup_db_id_async(void** param);
static int fixup_pvname_list(void** param);
static int fixup_avpname_list(void** param);

static int fixup_free_pvname_list(void** param);
static int fixup_free_avp_dbparam(void** param);

static int w_db_avp_load(struct sip_msg* msg, void* source,
		void* param, void *url, str *prefix);
static int w_db_avp_delete(struct sip_msg* msg, void* source,
		void* param, void *url);
static int w_db_avp_store(struct sip_msg* msg, void* source,
		void* param, void *url);
static int w_db_query(struct sip_msg* msg, str* query,
		void* dest, void *url);
static int w_db_query_one(struct sip_msg* msg, str* query,
		void* dest, void *url);
static int w_async_db_query(struct sip_msg* msg, async_ctx *ctx,
		str* query, void* dest, void* url);
static int w_async_db_query_one(struct sip_msg* msg, async_ctx *ctx,
		str* query, void* dest, void* url);

static int w_db_select(struct sip_msg* msg, str* cols, str *table,
		str *filter, str *order, void* dest, void *url);
static int w_db_select_one(struct sip_msg* msg, str* cols, str *table,
		str *filter, str *order, void* dest, void *url);
static int w_db_update(struct sip_msg* msg, str* cols, str *table,
		str *filter, void *url);
static int w_db_insert(struct sip_msg* msg, str* table, str *cols,
		void *url);
static int w_db_delete(struct sip_msg* msg, str *table, str *filter,
		void *url);
static int w_db_replace(struct sip_msg* msg, str* table, str *cols,
		void *url);


static const acmd_export_t acmds[] = {
	{"db_query", (acmd_function)w_async_db_query, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_NO_EXPAND,
			fixup_avpname_list, fixup_free_pvname_list},
		{CMD_PARAM_INT|CMD_PARAM_OPT,
			fixup_db_id_async, fixup_free_pkg},
		{0, 0, 0}}},
	{"db_query_one", (acmd_function)w_async_db_query_one, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_NO_EXPAND,
			fixup_pvname_list, fixup_free_pvname_list},
		{CMD_PARAM_INT|CMD_PARAM_OPT,
			fixup_db_id_async, fixup_free_pkg},
		{0, 0, 0}}},

	{0, 0, {{0, 0, 0}}}
};

/*! \brief
 * Exported functions
 */
static const cmd_export_t cmds[] = {

	{"db_avp_load", (cmd_function)w_db_avp_load, {
		{CMD_PARAM_STR|CMD_PARAM_NO_EXPAND,
			fixup_db_avp_source, fixup_free_pkg},
		{CMD_PARAM_STR|CMD_PARAM_NO_EXPAND,
			fixup_db_avp_dbparam_scheme, fixup_free_avp_dbparam},
		{CMD_PARAM_INT|CMD_PARAM_OPT, fixup_db_url, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, fixup_avp_prefix, fixup_free_pkg},
		{0, 0, 0}},
		ALL_ROUTES},

	{"db_avp_delete", (cmd_function)w_db_avp_delete, {
		{CMD_PARAM_STR|CMD_PARAM_NO_EXPAND,
			fixup_db_avp_source, fixup_free_pkg},
		{CMD_PARAM_STR|CMD_PARAM_NO_EXPAND,
			fixup_db_avp_dbparam, fixup_free_avp_dbparam},
		{CMD_PARAM_INT|CMD_PARAM_OPT, fixup_db_url, 0},
		{0, 0, 0}},
		ALL_ROUTES},

	{"db_avp_store", (cmd_function)w_db_avp_store, {
		{CMD_PARAM_STR|CMD_PARAM_NO_EXPAND,
			fixup_db_avp_source, fixup_free_pkg},
		{CMD_PARAM_STR|CMD_PARAM_NO_EXPAND,
			fixup_db_avp_dbparam, fixup_free_avp_dbparam},
		{CMD_PARAM_INT|CMD_PARAM_OPT, fixup_db_url, 0},
		{0, 0, 0}},
		ALL_ROUTES},

	{"db_query", (cmd_function)w_db_query, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_NO_EXPAND,
			fixup_avpname_list, fixup_free_pvname_list},
		{CMD_PARAM_INT|CMD_PARAM_OPT,
			fixup_db_id_sync, fixup_free_pkg},
		{0, 0, 0}},
		ALL_ROUTES},

	{"db_query_one", (cmd_function)w_db_query_one, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_NO_EXPAND,
			fixup_pvname_list, fixup_free_pvname_list},
		{CMD_PARAM_INT|CMD_PARAM_OPT,
			fixup_db_id_sync, fixup_free_pkg},
		{0, 0, 0}},
		ALL_ROUTES},

	{"db_select", (cmd_function)w_db_select, {
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0}, /* columns */
		{CMD_PARAM_STR, 0, 0}, /* table */
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0}, /* filter */
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0}, /* order */
		{CMD_PARAM_STR|CMD_PARAM_OPT|CMD_PARAM_NO_EXPAND,
			fixup_avpname_list, fixup_free_pvname_list},
		{CMD_PARAM_INT|CMD_PARAM_OPT,
			fixup_db_id_sync, fixup_free_pkg},
		{0, 0, 0}},
		ALL_ROUTES},

	{"db_selec_one", (cmd_function)w_db_select_one, {
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0}, /* columns */
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0}, /* table */
		{CMD_PARAM_STR, 0, 0}, /* filter */
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0}, /* order */
		{CMD_PARAM_STR|CMD_PARAM_NO_EXPAND,
			fixup_pvname_list, fixup_free_pvname_list},
		{CMD_PARAM_INT|CMD_PARAM_OPT,
			fixup_db_id_sync, fixup_free_pkg},
		{0, 0, 0}},
		ALL_ROUTES},

	{"db_update", (cmd_function)w_db_update, {
		{CMD_PARAM_STR, 0, 0}, /* columns */
		{CMD_PARAM_STR, 0, 0}, /* table */
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0}, /* filter */
		{CMD_PARAM_INT|CMD_PARAM_OPT,
			fixup_db_id_sync, fixup_free_pkg},
		{0, 0, 0}},
		ALL_ROUTES},

	{"db_insert", (cmd_function)w_db_insert, {
		{CMD_PARAM_STR, 0, 0}, /* table */
		{CMD_PARAM_STR, 0, 0}, /* columns */
		{CMD_PARAM_INT|CMD_PARAM_OPT,
			fixup_db_id_sync, fixup_free_pkg},
		{0, 0, 0}},
		ALL_ROUTES},

	{"db_delete", (cmd_function)w_db_delete, {
		{CMD_PARAM_STR, 0, 0}, /* table */
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0}, /* filter */
		{CMD_PARAM_INT|CMD_PARAM_OPT,
			fixup_db_id_sync, fixup_free_pkg},
		{0, 0, 0}},
		ALL_ROUTES},

	{"db_replace", (cmd_function)w_db_replace, {
		{CMD_PARAM_STR, 0, 0}, /* table */
		{CMD_PARAM_STR, 0, 0}, /* columns */
		{CMD_PARAM_INT|CMD_PARAM_OPT,
			fixup_db_id_sync, fixup_free_pkg},
		{0, 0, 0}},
		ALL_ROUTES},

	{0, 0, {{0, 0, 0}}, 0}
};


/*! \brief
 * Exported parameters
 */
static const param_export_t params[] = {
	{"db_url",            STR_PARAM|USE_FUNC_PARAM, (void*)add_db_url },
	{"usr_table",         STR_PARAM, &db_table.s      },
	{"use_domain",        INT_PARAM, &use_domain      },
	{"uuid_column",       STR_PARAM, &uuid_col.s      },
	{"attribute_column",  STR_PARAM, &attribute_col.s },
	{"value_column",      STR_PARAM, &value_col.s     },
	{"type_column",       STR_PARAM, &type_col.s      },
	{"username_column",   STR_PARAM, &username_col.s  },
	{"domain_column",     STR_PARAM, &domain_col.s    },
	{"db_scheme",         STR_PARAM|USE_FUNC_PARAM, (void*)add_avp_db_scheme },
	{0, 0, 0}
};

static const dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "db_url", get_deps_sqldb_url },
		{ NULL, NULL },
	},
};

struct module_exports exports = {
	"dbops",
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
	dbops_init,/* Module initialization function */
	(response_function) 0,
	(destroy_function) 0,
	(child_init_function) dbops_child_init, /* per-child init function */
	NULL        /* reload confirm function */
};



static int dbops_init(void)
{
	LM_INFO("initializing...\n");

	db_table.len = strlen(db_table.s);
	uuid_col.len = strlen(uuid_col.s);
	attribute_col.len = strlen(attribute_col.s);
	value_col.len = strlen(value_col.s);
	type_col.len = strlen(type_col.s);
	username_col.len = strlen(username_col.s);
	domain_col.len = strlen(domain_col.s);

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
	if (dbops_db_bind()<0)
		goto error;

	init_store_avps(db_columns);

	return 0;
error:
	return -1;
}


static int dbops_child_init(int rank)
{
	/* init DB connection */
	return dbops_db_init(&db_table, db_columns);
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

static int fixup_avpname_list(void** param)
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
		LM_ERR("bad list of AVPs in [%.*s]\n", s.len, s.s);
		return E_UNSPEC;
	}
	*param = (void*)anlist;
	return 0;
}

static int fixup_pvname_list(void** param)
{
	pvname_list_t *anlist = NULL, *it;
	str s = *(str *)*param;

	if(s.s==NULL || s.s[0]==0) {
		*param = NULL;
		return 0;
	}

	anlist = parse_pvname_list(&s, 0/*type*/);
	if(anlist==NULL)
	{
		LM_ERR("bad list of vars in [%.*s]\n", s.len, s.s);
		return E_UNSPEC;
	}

	/* check if all vars are writeble */
	for( it=anlist ; it ; it=it->next ) {
		if (!pv_is_w( (&it->sname) )) {
			LM_ERR("non-writeable var (type %d) found in [%.*s]\n",
				it->sname.type, s.len, s.s);
			return E_CFG;
		}
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


static int w_db_avp_load(struct sip_msg* msg, void* source,
                         void* param, void *url, str *prefix)
{
	return ops_db_avp_load ( msg, (struct fis_param*)source,
		(struct db_param*)param,
		url?(struct db_url*)url:default_db_url, use_domain, prefix);
}

static int w_db_avp_delete(struct sip_msg* msg, void* source,
                           void* param, void *url)
{
	return ops_db_avp_delete ( msg, (struct fis_param*)source,
		(struct db_param*)param,
		url?(struct db_url*)url:default_db_url,
		use_domain);
}

static int w_db_avp_store(struct sip_msg* msg, void* source,
                          void* param, void *url)
{
	return ops_db_avp_store ( msg, (struct fis_param*)source,
		(struct db_param*)param,
		url?(struct db_url*)url:default_db_url,
		use_domain);
}


static int w_db_query(struct sip_msg* msg, str* query,
                          void* dest, void *url)
{
	struct db_url *parsed_url;

	if (url)
		parsed_url = ((struct db_url_container *)url)->u.url;
	else
		parsed_url = default_db_url;

	return ops_db_query(msg, query, parsed_url, (pvname_list_t*)dest, 0);
}


static int w_db_query_one(struct sip_msg* msg, str* query,
														void* dest, void *url)
{
	struct db_url *parsed_url;

	if (url)
		parsed_url = ((struct db_url_container *)url)->u.url;
	else
		parsed_url = default_db_url;

	return ops_db_query(msg, query, parsed_url, (pvname_list_t*)dest, 1);
}


static int w_db_select(struct sip_msg* msg, str* cols, str *table,
		str *filter, str *order, void* dest, void *url)
{
	struct db_url *parsed_url;

	if (url)
		parsed_url = ((struct db_url_container *)url)->u.url;
	else
		parsed_url = default_db_url;

	return ops_db_api_select(parsed_url, msg, cols, table, filter, order, 
		(pvname_list_t*)dest, 0);
}


static int w_db_select_one(struct sip_msg* msg, str* cols, str *table,
		str *filter, str *order, void* dest, void *url)
{
	struct db_url *parsed_url;

	if (url)
		parsed_url = ((struct db_url_container *)url)->u.url;
	else
		parsed_url = default_db_url;

	return ops_db_api_select(parsed_url, msg, cols, table, filter, order, 
		(pvname_list_t*)dest, 1);
}


static int w_db_update(struct sip_msg* msg, str* cols, str *table,
		str *filter, void *url)
{
	struct db_url *parsed_url;

	if (url)
		parsed_url = ((struct db_url_container *)url)->u.url;
	else
		parsed_url = default_db_url;

	return ops_db_api_update(parsed_url, msg, cols, table, filter);
}


static int w_db_insert(struct sip_msg* msg, str* table, str *cols,
		void *url)
{
	struct db_url *parsed_url;

	if (url)
		parsed_url = ((struct db_url_container *)url)->u.url;
	else
		parsed_url = default_db_url;

	return ops_db_api_insert(parsed_url, msg, table, cols);
}


static int w_db_delete(struct sip_msg* msg, str *table, str *filter,
		void *url)
{
	struct db_url *parsed_url;

	if (url)
		parsed_url = ((struct db_url_container *)url)->u.url;
	else
		parsed_url = default_db_url;

	return ops_db_api_delete(parsed_url, msg, table, filter);
}


static int w_db_replace(struct sip_msg* msg, str* table, str *cols,
		void *url)
{
	struct db_url *parsed_url;

	if (url)
		parsed_url = ((struct db_url_container *)url)->u.url;
	else
		parsed_url = default_db_url;

	return ops_db_api_replace(parsed_url, msg, table, cols);
}


static int w_async_db_query(struct sip_msg* msg, async_ctx *ctx,
											str* query, void* dest, void* url)
{
	struct db_url *parsed_url;

	if (url)
		parsed_url = ((struct db_url_container *)url)->u.url;
	else
		parsed_url = default_db_url;

	return ops_async_db_query(msg, ctx, query, parsed_url,
		(pvname_list_t *)dest, 0);
}

static int w_async_db_query_one(struct sip_msg* msg, async_ctx *ctx,
											str* query, void* dest, void* url)
{
	struct db_url *parsed_url;

	if (url)
		parsed_url = ((struct db_url_container *)url)->u.url;
	else
		parsed_url = default_db_url;

	return ops_async_db_query(msg, ctx, query, parsed_url,
		(pvname_list_t *)dest, 1);
}
