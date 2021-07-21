/*
 * statistics module - script interface to internal statistics manager
 *
 * Copyright (C) 2006 Voice Sistem S.R.L.
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
 *  2006-03-14  initial version (bogdan)
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../ut.h"
#include "../../mod_fix.h"
#include "../../statistics.h"
#include "../../mem/mem.h"
#include "../../trim.h"
#include "../../lib/list.h"
#include "../../lib/hash.h"
#include "stats_funcs.h"


#define STAT_PARAM_TYPE_STAT  1
#define STAT_PARAM_TYPE_NAME  2
struct stat_param {
	unsigned int type;
	union {
		stat_var   *stat;
		str        *name;
	} u;
};

struct stat_iter {
	str name;
	stat_var *cur;
	struct list_head list;
};

enum stat_alg {
	STAT_ALG_ACC,
	STAT_ALG_AVG,
	STAT_ALG_PERC,
};

#define DEFAULT_STAT_SERIES_ALG STAT_ALG_ACC
#define DEFAULT_STAT_SERIES_HASH_SIZE 8
#define DEFAULT_STAT_SERIES_WINDOW 60
#define DEFAULT_STAT_SERIES_PERC_FACTOR 100

struct {
	str name;
	enum stat_alg alg;
} stat_alg_map[] = {
	{str_init("accumulate"), STAT_ALG_ACC},
	{str_init("average"), STAT_ALG_AVG},
	{str_init("percentage"), STAT_ALG_PERC},
};

struct stat_series_profile {
	str name;
	gen_hash_t *hash;
	unsigned int slot_size;
	struct list_head list;

	/* these can be customized */
	unsigned int hash_size;
	unsigned int window;
	unsigned int slots;
	unsigned int factor;
	enum stat_alg algorithm;
	str group;
};

union stat_series_slot {
	struct {
		long sum;
		unsigned int nr;
	} avg;
	struct {
		unsigned long true;
		unsigned long false;
	} perc;
	long acc;
};

struct stat_series {
	char *name;
	gen_lock_t lock;
	unsigned int last_slot;
	unsigned long long last_ts;
	union stat_series_slot cache;
	union stat_series_slot *slots;
	struct stat_series_profile *profile;
};

static int reg_param_stat( modparam_t type, void* val);
static int reg_stat_group( modparam_t type, void* val);
static int reg_stat_series_profile( modparam_t type, void* val);
static int mod_init(void);
static void mod_destroy(void);
static int w_update_stat(struct sip_msg *msg, struct stat_param *sp, int *n);
static int w_reset_stat(struct sip_msg* msg, struct stat_param *sp);
static int fixup_stat(void** param);
static int fixup_free_stat(void** param);
static int fixup_update_stat_series(void** param);
static int fixup_iter_param(void **param);
static int fixup_check_stat_group(void **param);
static int w_update_stat_series(struct sip_msg *msg,
		struct stat_series_profile *profile, str *name, int *val);

int pv_parse_name(pv_spec_p sp, const str *in);
int pv_set_stat(struct sip_msg* msg, pv_param_t *param, int op,
													pv_value_t *val);
int pv_get_stat(struct sip_msg *msg,  pv_param_t *param, pv_value_t *res);
static int w_stat_iter_init(struct sip_msg *msg, str *group, struct stat_iter *iter);
static int w_stat_iter_next(struct sip_msg *msg, pv_spec_t *key, pv_spec_t *val,
						struct stat_iter *iter);

struct list_head script_iters;
static OSIPS_LIST_HEAD(series_profiles);

static cmd_export_t cmds[]={
	{"update_stat", (cmd_function)w_update_stat, {
		{CMD_PARAM_STR, fixup_stat, fixup_free_stat},
		{CMD_PARAM_INT, 0, 0}, {0,0,0}},
		REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|
		LOCAL_ROUTE|STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"reset_stat", (cmd_function)w_reset_stat, {
		{CMD_PARAM_STR, fixup_stat, fixup_free_stat}, {0,0,0}},
		REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|
		LOCAL_ROUTE|STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"stat_iter_init", (cmd_function)w_stat_iter_init, {
		{CMD_PARAM_STR, fixup_check_stat_group, 0},
		{CMD_PARAM_STR, fixup_iter_param, 0}, {0,0,0}},
		REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|
		LOCAL_ROUTE|STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"stat_iter_next",  (cmd_function)w_stat_iter_next, {
		{CMD_PARAM_VAR, 0, 0},
		{CMD_PARAM_VAR, 0, 0},
		{CMD_PARAM_STR, fixup_iter_param, 0}, {0,0,0}},
		REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|
		LOCAL_ROUTE|STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"update_stat_series",  (cmd_function)w_update_stat_series, {
		{CMD_PARAM_STR, fixup_update_stat_series, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_INT, 0, 0}, {0,0,0}},
		ALL_ROUTES},
	{0,0,{{0,0,0}},0}
};

static param_export_t mod_params[]={
	{ "variable",  STR_PARAM|USE_FUNC_PARAM, (void*)reg_param_stat },
	{ "stat_groups",  STR_PARAM|USE_FUNC_PARAM, (void*)reg_stat_group },
	{ "stat_series_profile",  STR_PARAM|USE_FUNC_PARAM, (void*)reg_stat_series_profile },
	{ 0,0,0 }
};


static pv_export_t mod_items[] = {
	{ {"stat",     sizeof("stat")-1},      1100, pv_get_stat,
		pv_set_stat,    pv_parse_name, 0, 0, 0},
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};



struct module_exports exports= {
	"statistics",		/* module's name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,	/* dlopen flags */
	0,					/* load function */
	NULL,				/* OpenSIPS module dependencies */
	cmds,				/* exported functions */
	0,					/* exported async functions */
	mod_params,			/* param exports */
	0,					/* exported statistics */
	0,					/* exported MI functions */
	mod_items,			/* exported pseudo-variables */
	0,					/* exported transformations */
	0,					/* extra processes */
	0,					/* module pre-initialization function */
	mod_init,			/* module initialization function */
	0,					/* reply processing function */
	mod_destroy,		/* module destroy function */
	0,					/* per-child init function */
	0					/* reload confirm function */
};



static int reg_param_stat( modparam_t type, void* val)
{
	return reg_statistic( (char*)val);
}

static int reg_stat_group(modparam_t type, void *val)
{
	char *it, *p, save;
	str group;
	int len;

	len = strlen(val);
	it = val;
	do {
		p = strchr(it, ',');

		group.s = it;
		group.len = p ? (p - it) : ((char *)val + len - it);
		trim(&group);

		if (!group.s || group.len <= 0) {
			goto next;
		}

		save = group.s[group.len];
		group.s[group.len] = '\0';

		LM_DBG("creating stat group '%s' ...\n", group.s);
		if (!add_stat_module(group.s)) {
			LM_ERR("failed to add stat group '%s'!\n", group.s);
			return -1;
		}

		group.s[group.len] = save;
next:
		it = p + 1;
	} while (p);

	return 0;
}

static struct stat_series_profile *get_stat_series_profile(str *name)
{
	struct list_head *iter;
	struct stat_series_profile *sp;

	list_for_each(iter, &series_profiles) {
		sp = list_entry(iter, struct stat_series_profile, list);
		if (!str_strcasecmp(&sp->name, name))
			return sp;
	}
	return NULL;
}

static char *stat_series_alg_name(enum stat_alg alg)
{
	int i;
	for (i = 0; i < sizeof(stat_alg_map)/sizeof(stat_alg_map[0]); i++)
		if (stat_alg_map[i].alg == alg)
			return stat_alg_map[i].name.s;
	return "unknown";
}

static int reg_stat_series_profile( modparam_t type, void* val)
{
	str param_hash_size = str_init("hash_size");
	str param_algorithm = str_init("algorithm");
	str param_group = str_init("group");
	str param_window = str_init("window");
	str param_slots = str_init("slots");
	str param_factor = str_init("percentage_factor");
	struct stat_series_profile *sp;
	str params, name, k, v;
	char *p;
	unsigned int tmp, factor;
	int alg;

	init_str(&params, val);

	p = q_memchr(params.s, ':', params.len);
	if (p) {
		name.s = params.s;
		name.len = p - params.s;
		params.s = p + 1;
		params.len -= name.len + 1;
	} else {
		name = params;
		params.len = 0;
	}
	trim(&name);

	if (get_stat_series_profile(&name)) {
		LM_ERR("profile %s already defined!\n", name.s);
		return -1;
	}

	sp = pkg_malloc(sizeof *sp + name.len + 1);
	if (!sp) {
		LM_ERR("no more pkg memory to store profile!\n");
		return -1;
	}
	memset(sp, 0, sizeof(*sp));

	sp->name.s = (char *)(sp + 1);
	sp->name.len = name.len;
	memcpy(sp->name.s, name.s, name.len);
	sp->name.s[sp->name.len] = 0;

	sp->hash_size = DEFAULT_STAT_SERIES_HASH_SIZE;
	sp->window = DEFAULT_STAT_SERIES_WINDOW;
	sp->algorithm = DEFAULT_STAT_SERIES_ALG;
	sp->factor = DEFAULT_STAT_SERIES_PERC_FACTOR;

	while (params.len > 0) {
		trim_leading(&params);
		if (params.len == 0)
			break;
		for (p = params.s; p < params.s + params.len && !is_ws(*p); p++);

		k.s = params.s;
		for (p = params.s; p < params.s + params.len && !is_ws(*p) && *p != '='; p++);
		if (p == params.s + params.len) {
			LM_ERR("malformed key=value pair: [%.*s]! skipping...\n", params.len, params.s);
			break;
		}
		k.len = p - k.s;
		for (; p < params.s + params.len && (is_ws(*p) || *p == '='); p++);
		v.s = p;
		for (; p < params.s + params.len && !is_ws(*p); p++);
		v.len = p - v.s;
		params.len -= p + 1 - params.s;
		params.s = p + 1;
		if (!str_strcasecmp(&k, &param_hash_size)) {
			if (str2int(&v, &tmp) < 0) {
				LM_ERR("stat series hash size not integer %.*s for %.*s! using previous/default: %d\n",
						v.len, v.s, name.len, name.s, sp->hash_size);
			} else {
				sp->hash_size = tmp;
			}
		} else if (!str_strcasecmp(&k, &param_group)) {
			sp->group = v;
		} else if (!str_strcasecmp(&k, &param_algorithm)) {
			for (alg = sizeof(stat_alg_map)/sizeof(stat_alg_map[0]) - 1; alg >= 0; alg--)
				if (!str_strcasecmp(&stat_alg_map[alg].name, &v))
					break;
			if (alg < 0) {
				LM_ERR("stat series unknown algorithm %.*s for %.*s! using previous/default: %s\n",
						v.len, v.s, name.len, name.s, stat_series_alg_name(sp->algorithm));
			} else {
				sp->algorithm = stat_alg_map[alg].alg;
			}
		} else if (!str_strcasecmp(&k, &param_window)) {
			if (str2int(&v, &tmp) < 0) {
				LM_ERR("stat series window not integer %.*s for %.*s! using previous/default: %d\n",
						v.len, v.s, name.len, name.s, sp->window);
			} else {
				sp->window = tmp;
			}
		} else if (!str_strcasecmp(&k, &param_slots)) {
			if (str2int(&v, &tmp) < 0) {
				LM_ERR("stat series slots not integer %.*s for %.*s! using previous/default: %d\n",
						v.len, v.s, name.len, name.s, sp->window);
			} else {
				sp->slots = tmp;
			}
		} else if (!str_strcasecmp(&k, &param_factor)) {
			if (str2int(&v, &tmp) < 0) {
				LM_ERR("stat series percentage_factor not integer %.*s for %.*s! using previous/default: %d\n",
						v.len, v.s, name.len, name.s, sp->factor);
			} else {
				factor = tmp;
				/* check if multiple of 10 */
				while (tmp > 9 && tmp % 10 == 0)
					tmp /= 10;
				if (tmp != 1) {
					LM_ERR("stat series percentage_factor %d not multiple of 10 for %.*s!"
							" using previous/default: %d\n",
							factor, name.len, name.s, sp->factor);
				} else {
					sp->factor = factor;
				}
			}
		} else {
			LM_WARN("unknown parameter %.*s with value %.*s for %.*s! skipping...\n",
					k.len, k.s, v.len, v.s, name.len, name.s);
		}
	}
	if (!sp->slots) {
		LM_DBG("inherit number of slots from window for %.*s=%d\n",
				name.len, name.s, sp->window);
		sp->slots = sp->window;
	}
	if (!sp->group.len)
		sp->group = sp->name;
	sp->slot_size = sp->window * 1000 / sp->slots;
	LM_DBG("stat series profile %.*s has a window of %us of %u slots of %ums algorithm(%s)\n",
			name.len, name.s, sp->window, sp->slots, sp->slot_size, stat_series_alg_name(sp->algorithm));

	list_add(&sp->list, &series_profiles);

	return 0;
}


static int mod_init(void)
{
	module_stats *mod;
	struct list_head *it;
	struct stat_series_profile *profile;
	LM_INFO("initializing\n");

	INIT_LIST_HEAD(&script_iters);

	/* initialize all lists */
	list_for_each(it, &series_profiles) {
		profile = list_entry(it, struct stat_series_profile, list);
		profile->hash = hash_init(profile->hash_size);
		if (!profile->hash) {
			LM_ERR("could not create profile hash for %s!\n", profile->name.s);
			return -1;
		}
		/* register the module now, so we can make it dynamic */
		mod = get_stat_module(&profile->group);
		if (!mod) {
			mod = add_stat_module(profile->group.s);
			if (!mod) {
				LM_ERR("could not register dynamic module %s for %s\n",
						(profile->group.len?profile->group.s:profile->name.s),
						profile->name.s);
				return -1;
			}
			mod->is_dyn = 1;
		} else if (!mod->is_dyn) {
			LM_WARN("profile %s is does not support dynamic statistics! using %s group!\n",
					profile->group.s, DYNAMIC_MODULE_NAME);
			init_str(&profile->group, DYNAMIC_MODULE_NAME);
		}
	}


	if (register_all_mod_stats()!=0) {
		LM_ERR("failed to register statistic variables\n");
		return E_UNSPEC;
	}
	return 0;
}

static void stat_series_free(void *value)
{
	struct stat_series *ss = (struct stat_series *)value;
	lock_destroy(ss->lock);
	shm_free(ss);
}

static void mod_destroy(void)
{
	struct list_head *ele, *next;
	struct stat_iter *iter;
	struct stat_series_profile *sp;

	list_for_each_safe(ele, next, &script_iters) {
		iter = list_entry(ele, struct stat_iter, list);
		list_del(&iter->list);
		pkg_free(iter);
	}

	list_for_each_safe(ele, next, &series_profiles) {
		sp = list_entry(ele, struct stat_series_profile, list);
		list_del(&sp->list);
		hash_destroy(sp->hash, stat_series_free);
		pkg_free(sp);
	}
}

static int resolve_stat(str *in, str *out_group, str *out_name, int *out_grp_idx)
{
	module_stats *ms;

	parse_groupname(in, out_group, out_name);
	if (out_group->s) {
		ms = get_stat_module(out_group);
		if (!ms) {
			LM_ERR("stat group '%.*s' must be explicitly defined "
			       "using the 'stat_groups' module parameter!\n",
			       out_group->len, out_group->s);
			*out_grp_idx = -1;
			return -1;
		}
		*out_grp_idx = ms->idx;
	} else {
		*out_grp_idx = -1;
	}

	return 0;
}

static int fixup_stat(void** param)
{
	struct stat_param *sp;
	str sname, group;
	int grp_idx __attribute__((unused));

	sp = (struct stat_param *)pkg_malloc(sizeof(struct stat_param));
	if (sp==NULL) {
		LM_ERR("no more pkg mem (%d)\n", (int)sizeof(struct stat_param));
		return E_OUT_OF_MEM;
	}
	memset( sp, 0 , sizeof(struct stat_param) );

	if (resolve_stat((str*)*param, &group, &sname, &grp_idx) != 0) {
		return E_CFG;
	}
	/* text token */
	sp->u.stat = __get_stat(&sname, grp_idx);
	if (sp->u.stat) {
		/* statistic found */
		sp->type = STAT_PARAM_TYPE_STAT;
	} else {
		/* stat not found, keep the name for later */
		sp->type = STAT_PARAM_TYPE_NAME;
		sp->u.name = *param;
	}

	*param = sp;

	return 0;
}

static int fixup_free_stat(void** param)
{
	pkg_free(*param);
	return 0;
}

static int fixup_iter_param(void **param)
{
	struct list_head *ele;
	struct stat_iter *iter;

	list_for_each(ele, &script_iters) {
		iter = list_entry(ele, struct stat_iter, list);

		if (str_match((str *)*param, &iter->name)) {
			*param = iter;
			return 0;
		}
	}

	iter = pkg_malloc(sizeof *iter);
	if (!iter) {
		LM_ERR("oom!\n");
		return E_OUT_OF_MEM;
	}
	memset(iter, 0, sizeof *iter);

	if (pkg_str_dup(&iter->name, (str*)*param) < 0) {
		LM_ERR("oom!\n");
		return E_OUT_OF_MEM;
	}

	list_add(&iter->list, &script_iters);

	*param = iter;
	return 0;
}

static int fixup_check_stat_group(void **param)
{
	if (!get_stat_module((str*)*param)) {
		LM_ERR("stat group '%.*s' must be explicitly defined using the "
		    "'stat_groups' module parameter!\n",
		    ((str*)*param)->len, ((str*)*param)->s);
		return E_UNSPEC;
	}
	return 0;
}

static int w_update_stat(struct sip_msg *msg, struct stat_param *sp, int *n)
{
	stat_var *stat;
	str name, group;
	int grp_idx __attribute__((unused));

	/* update with 0 value makes no sense */
	if (*n==0)
		return 1;

	if (sp->type==STAT_PARAM_TYPE_STAT) {
		/* we have the statistic */
		update_stat( sp->u.stat, (long)*n);
		return 1;
	}

	LM_DBG("needed statistic is <%.*s>\n", sp->u.name->len, sp->u.name->s);

	if (resolve_stat(sp->u.name, &group, &name, &grp_idx) != 0) {
		return E_CFG;
	}

	stat = __get_stat(&name, grp_idx);
	if ( stat==NULL ) {
		/* stats not found -> create it */
		LM_DBG("creating statistic <%.*s>\n", sp->u.name->len, sp->u.name->s);

		if (grp_idx > 0) {
			if (__register_dynamic_stat(&group, &name, &stat) != 0) {
				LM_ERR("failed to create statistic <%.*s:%.*s>\n",
				       group.len, group.s, name.len, name.s);
				return -1;
			}
		} else {
			if (register_dynamic_stat(&name, &stat)!=0) {
				LM_ERR("failed to create statistic <%.*s>\n",
				       name.len, name.s);
				return -1;
			}
		}
	}

	/* statistic exists ! */
	update_stat( stat, (long)*n);
	return 1;
}

static int fixup_update_stat_series(void** param)
{
	str profile;

	profile = *(str *)*param;
	*param = get_stat_series_profile(&profile);
	if (*param == NULL) {
		LM_ERR("unknown profile %.*s\n", profile.len, profile.s);
		return E_UNSPEC;
	}
	return 0;
}



static int w_reset_stat(struct sip_msg *msg, struct stat_param* sp)
{
	stat_var *stat;
	str group, name;
	int grp_idx __attribute__((unused));

	if (sp->type==STAT_PARAM_TYPE_STAT) {
		/* we have the statistic */
		reset_stat( sp->u.stat);
		return 1;
	}

	LM_DBG("needed statistic is <%.*s>\n", sp->u.name->len, sp->u.name->s);

	if (resolve_stat(sp->u.name, &group, &name, &grp_idx) != 0) {
		return E_CFG;
	}

	stat = __get_stat(&name, grp_idx);
	if ( stat==NULL ) {
		/* stats not found -> create it */
		LM_DBG("creating statistic <%.*s>\n", sp->u.name->len, sp->u.name->s);

		if (grp_idx > 0) {
			if (__register_dynamic_stat(&group, &name, &stat) != 0) {
				LM_ERR("failed to create statistic <%.*s:%.*s>\n",
				       group.len, group.s, name.len, name.s);
				return -1;
			}
		} else {
			if (register_dynamic_stat( &name, &stat )!=0) {
				LM_ERR("failed to create statistic <%.*s>\n",
				       name.len, name.s);
				return -1;
			}
		}
	}

	/* statistic exists ! */
	reset_stat( stat );
	return 1;
}


int pv_parse_name(pv_spec_p sp, const str *in)
{
	stat_var *stat;
	pv_elem_t *format;

	if(in==NULL || in->s==NULL || sp==NULL)
		return -1;

	LM_DBG("name %p with name <%.*s>\n", &sp->pvp.pvn, in->len, in->s);
	if (pv_parse_format( in, &format)!=0) {
		LM_ERR("failed to parse statistic name format <%.*s> \n",
			in->len,in->s);
		return -1;
	}

	/* text only ? */
	if (format->next==NULL && format->spec.type==PVT_NONE) {

		/* search for the statistic */
		stat = get_stat( &format->text );

		if (stat==NULL) {
			/* statistic does not exist (yet) -> fill in the string name */
			sp->pvp.pvn.type = PV_NAME_INTSTR;
			sp->pvp.pvn.u.isname.type = AVP_NAME_STR;
			if (clone_pv_stat_name( in, &sp->pvp.pvn.u.isname.name.s )!=0) {
				LM_ERR("failed to clone name of statistic \n");
				return -1;
			}
			LM_DBG("name %p, name cloned (in=%p, out=%p)\n",
				&sp->pvp.pvn, in->s, sp->pvp.pvn.u.isname.name.s.s);
		} else {
			/* link the stat pointer directly as dynamic name */
			sp->pvp.pvn.type = PV_NAME_PVAR;
			sp->pvp.pvn.u.dname = (void*)stat;
			LM_DBG("name %p, stat found\n", &sp->pvp.pvn);
		}

	} else {

			sp->pvp.pvn.type = PV_NAME_INTSTR;
			sp->pvp.pvn.u.isname.type = 0; /* not string */
			sp->pvp.pvn.u.isname.name.s.s = (char*)(void*)format;
			sp->pvp.pvn.u.isname.name.s.len = 0;
			LM_DBG("name %p, stat name is FMT\n", &sp->pvp.pvn);

	}

	return 0;
}


static inline int get_stat_name(struct sip_msg* msg, pv_name_t *name,
												int create, stat_var **stat)
{
	pv_value_t pv_val;
	str sname, group;
	int grp_idx __attribute__((unused));

	/* is the statistic found ? */
	if (name->type==PV_NAME_INTSTR) {
		LM_DBG("stat with name %p still not found\n", name);
		/* not yet :( */
		/* do we have at least the name ?? */
		if (name->u.isname.type==0) {
			/* name is FMT */
			if (pv_printf_s( msg, (pv_elem_t *)name->u.isname.name.s.s,
			&(pv_val.rs) )!=0) {
				LM_ERR("failed to get format string value\n");
				return -1;
			}
		} else {
			/* name is string */
			pv_val.rs = name->u.isname.name.s;
		}

		if (resolve_stat(&pv_val.rs, &group, &sname, &grp_idx) != 0) {
			return E_CFG;
		}

		/* lookup for the statistic */
		*stat = __get_stat(&sname, grp_idx);
		LM_DBG("stat name %p (%.*s) after lookup is %p\n",
		       name, pv_val.rs.len, pv_val.rs.s, *stat);
		if (*stat==NULL) {
			if (!create)
				return 0;
			LM_DBG("creating statistic <%.*s>\n", pv_val.rs.len, pv_val.rs.s);
			if (grp_idx > 0) {
				if (__register_dynamic_stat(&group, &sname, stat) != 0) {
					LM_ERR("failed to create statistic <%.*s>\n",
					       pv_val.rs.len, pv_val.rs.s);
					return -1;
				}
			} else {
				if (register_dynamic_stat(&sname, stat)!=0) {
					LM_ERR("failed to create statistic <%.*s>\n",
					       pv_val.rs.len, pv_val.rs.s);
					return -1;
				}
			}
		}
		/* if name is static string, better link the stat directly
		 * and discard name */
		if (name->u.isname.type==AVP_NAME_STR) {
			LM_DBG("name %p freeing %p\n",name,name->u.isname.name.s.s);
			/* it is totally unsafe to free this shm block here, as it is
			 * referred by the spec from all the processess. Even if we create
			 * here a small leak (one time only), we do not have a better fix
			 * until a final review of the specs in pkg and shm mem - bogdan */
			//shm_free(name->u.isname.name.s.s);
			name->u.isname.name.s.s = NULL;
			name->u.isname.name.s.len = 0;
			name->type = PV_NAME_PVAR;
			name->u.dname = (void*)*stat;
		}
	} else {
		/* stat already found ! */
		*stat = (stat_var*)name->u.dname;
		LM_DBG("found stat name %p\n",name);
	}

	return 0;
}

static int w_stat_iter_init(struct sip_msg *msg, str *group, struct stat_iter *iter)
{
	module_stats *ms;

	ms = get_stat_module(group);
	if (!ms) {
		LM_ERR("unknown group %.*s\n", group->len, group->s);
		return -1;
	}
	iter->cur = ms->head;

	return 1;
}

static int w_stat_iter_next(struct sip_msg *msg, pv_spec_t *key, pv_spec_t *val,
						struct stat_iter *iter)
{
	pv_value_t pval;
	stat_var *stat = iter->cur;

	if (!stat) {
		LM_DBG("no more stats to iterate\n");
		return -1;
	}

	pval.flags = PV_VAL_STR;
	pval.rs = stat->name;
	if (pv_set_value(msg, key, 0, &pval) != 0) {
		LM_ERR("failed to set pv value for stat key '%.*s'\n",
		       stat->name.len, stat->name.s);
		return -1;
	}

	pval.flags = PV_VAL_INT|PV_TYPE_INT;
	pval.ri = get_stat_val(stat);
	if (pv_set_value(msg, val, 0, &pval) != 0) {
		LM_ERR("failed to set pv value for stat val '%d'\n",
		       pval.ri);
		return -1;
	}

	iter->cur = stat->lnext;

	return 1;
}

int pv_set_stat(struct sip_msg* msg, pv_param_t *param, int op,
													pv_value_t *val)
{
	stat_var *stat;

	if (get_stat_name( msg, &(param->pvn), 1, &stat)!=0) {
		LM_ERR("failed to generate/get statistic name\n");
		return -1;
	}

	if (val->ri != 0)
		LM_WARN("non-zero value - setting value to 0\n");

	reset_stat( stat );

	return 0;
}


int pv_get_stat(struct sip_msg *msg,  pv_param_t *param, pv_value_t *res)
{
	stat_var *stat;

	if(msg==NULL || res==NULL)
		return -1;

	if (get_stat_name( msg, &(param->pvn), 0, &stat)!=0) {
		LM_ERR("failed to generate/get statistic name\n");
		return -1;
	}

	if (stat==NULL)
		return pv_get_null(msg, param, res);

	res->ri = (int)get_stat_val( stat );
	res->rs.s = sint2str(res->ri, &res->rs.len);
	res->flags = PV_VAL_INT|PV_VAL_STR|PV_TYPE_INT;

	return 0;
}

#define get_stat_series_slot(_ss, _ts) \
	(((_ts) % ((_ss)->profile->window * 1000)) / (_ss)->profile->slot_size)

inline static void reset_stat_series_slot(struct stat_series *ss, union stat_series_slot *slot)
{
	switch (ss->profile->algorithm) {
		case STAT_ALG_AVG:
			ss->cache.avg.sum -= slot->avg.sum;
			ss->cache.avg.nr -= slot->avg.nr;
			break;
		case STAT_ALG_ACC:
			ss->cache.acc -= slot->acc;
			break;
		case STAT_ALG_PERC:
			ss->cache.perc.true -= slot->perc.true;
			ss->cache.perc.false -= slot->perc.false;
			break;
		default:
			LM_ERR("unknown profile algorithm %d\n", ss->profile->algorithm);
			return;
	}
	memset(slot, 0, sizeof *slot);
}

/* returns the new index where we shall start and cleans up stale data */
static int reset_stat_series(struct stat_series *ss, unsigned long long t)
{
	int new_slot, slot;

	new_slot = get_stat_series_slot(ss, t);
	if (t - ss->last_ts >= ss->profile->window * 1000) {
		memset(ss->slots, 0, ss->profile->slots * sizeof *ss->slots);
		memset(&ss->cache, 0, sizeof ss->cache);
		return new_slot;
	}
	if (new_slot == ss->last_slot)
		return ss->last_slot;

	for (slot = (ss->last_slot + 1) % ss->profile->slots;
			slot != new_slot; slot = (slot + 1) % ss->profile->slots)
		reset_stat_series_slot(ss, &ss->slots[slot]);
	reset_stat_series_slot(ss, &ss->slots[new_slot]);
	memset(&ss->slots[new_slot], 0, sizeof *ss->slots);
	return new_slot;
}

inline static unsigned long long get_stat_now(void)
{
	struct timeval now;
	gettimeofday(&now, NULL);
	return now.tv_sec * 1000 + now.tv_usec / 1000;
}

static unsigned long get_stat_series(struct stat_series *ss)
{
	unsigned long ret = 0;
	unsigned long total = 0;
	int new_slot;
	unsigned long long now;

	lock_get(&ss->lock);

	if (ss->last_ts == 0)
		goto end;

	now = get_stat_now();
	if (now - ss->last_ts >= ss->profile->window *1000)
		goto end;
	new_slot = reset_stat_series(ss, now);

	switch (ss->profile->algorithm) {
		case STAT_ALG_AVG:
			if (ss->cache.avg.nr)
				ret = ss->cache.avg.sum / ss->cache.avg.nr;
			break;
		case STAT_ALG_ACC:
			ret = ss->cache.acc;
			break;
		case STAT_ALG_PERC:
			total = ss->cache.perc.true + ss->cache.perc.false;
			if (total != 0)
				ret = ss->cache.perc.true * ss->profile->factor / total;
			break;
		default:
			LM_ERR("unknown profile algorithm %d\n", ss->profile->algorithm);
			return 0;
	}
	ss->last_ts = now;
	ss->last_slot = new_slot;
end:
	lock_release(&ss->lock);
	return ret;

}

static struct stat_series *new_stat_series(struct stat_series_profile *profile, str *name)
{
	struct stat_series *ss = shm_malloc(sizeof *ss + name->len + 1 +
			profile->slots * sizeof (*ss->slots));
	if (!ss) {
		LM_ERR("could not allocate new stat series!\n");
		return NULL;
	}
	memset(ss, 0, sizeof (*ss));
	lock_init(&ss->lock);
	ss->profile = profile;
	ss->name = (char *)(ss + 1);
	memcpy(ss->name, name->s, name->len);
	ss->name[name->len] = 0;
	ss->slots = (union stat_series_slot *)(ss->name + name->len + 1);
	memset(ss->slots, 0, profile->slots * sizeof (*ss->slots));

	/* all good - register the stat now */
	if (register_stat2(profile->group.s, ss->name, (stat_var **)get_stat_series,
			STAT_NO_RESET|STAT_IS_FUNC, ss, 0) != 0) {
		LM_ERR("could not add dynamic statistic\n");
		stat_series_free(ss);
		return NULL;
	}
	return ss;
}

static int update_stat_series(struct stat_series *ss, int value)
{
	int ret = 0;
	union stat_series_slot *s;
	unsigned long long now = get_stat_now();
	int slot_index;

	lock_get(&ss->lock);

	if (ss->last_ts == 0) {
		/* first run */
		slot_index = get_stat_series_slot(ss, now);
		memset(&ss->cache, 0, sizeof ss->cache);
	} else {
		/* we've skipped some slots - reset them */
		slot_index = reset_stat_series(ss, now);
	}

	s = &ss->slots[slot_index];
	ss->last_ts = now;
	ss->last_slot = slot_index;

	switch (ss->profile->algorithm) {
		case STAT_ALG_AVG:
			s->avg.sum += value;
			s->avg.nr++;
			ss->cache.avg.sum += value;
			ss->cache.avg.nr++;
			break;
		case STAT_ALG_ACC:
			s->acc += value;
			ss->cache.acc += value;
			break;
		case STAT_ALG_PERC:
			if (value > 0) {
				s->perc.true += value;
				ss->cache.perc.true += value;
			} else {
				s->perc.false -= value;
				ss->cache.perc.false -= value;
			}
			break;
		default:
			LM_ERR("unknown profile algorithm %d\n", ss->profile->algorithm);
			ret = -1;
	}
	lock_release(&ss->lock);
	return ret;
}

static int w_update_stat_series(struct sip_msg *msg, struct stat_series_profile *profile, str *name, int *value)
{
	unsigned int hentry;
	struct stat_series **ss;

	if (!profile) {
		LM_ERR("profile does not exist!\n");
		return -1;
	}

	hentry = hash_entry(profile->hash, *name);
	hash_lock(profile->hash, hentry);
	ss = (struct stat_series **)hash_get(profile->hash, hentry, *name);
	if (!ss) {
		LM_ERR("could not allocate new entry!\n");
		goto release_hash;
	}
	if (*ss == NULL) {
		*ss = new_stat_series(profile, name);
		if (*ss == NULL) {
			LM_ERR("could not create new stat series!\n");
			goto release_hash;
		}
	}
	hash_unlock(profile->hash, hentry);

	return update_stat_series(*ss, *value)?-1:1;

release_hash:
	hash_unlock(profile->hash, hentry);
	return -1;
}
