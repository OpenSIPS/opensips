/*
 * Copyright (C) 2006 Voice Sistem SRL
 * Copyright (C) 2010-2012 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
 *  2006-01-16  first version (bogdan)
 *  2006-11-28  added get_stat_var_from_num_code() (Jeffrey Magder -
 *              SOMA Networks)
 *  2009-04-23  function var accepts a context parameter (bogdan)
 *  2012-09-21  support for dynamic statistics (created of demand at runtime)
 *              (bogdan)
 */

/*!
 * \file
 * \brief Statistics support
 */


#include <string.h>

#include "mem/shm_mem.h"
#include "mem/rpm_mem.h"
#include "mi/mi.h"
#include "ut.h"
#include "dprint.h"
#include "locking.h"
#include "core_stats.h"
#include "statistics.h"
#include "pt.h"
#include "atomic.h"
#include "globals.h"
#include "rw_locking.h"

#ifdef STATISTICS

static stats_collector *collector = NULL;
static int stats_ready;

static mi_response_t *mi_get_stats(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *w_mi_list_stats(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *w_mi_list_stats_1(const mi_params_t *params,
								struct mi_handler *async_hdl);
static mi_response_t *mi_reset_stats(const mi_params_t *params,
								struct mi_handler *async_hdl);

static mi_export_t mi_stat_cmds[] = {
	{ "get_statistics",
		"prints the statistics (all, group or one) realtime values.", 0, 0, {
		{mi_get_stats, {"statistics", 0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{ "list_statistics",
		"lists all the registered statistics and their types", 0, 0, {
		{w_mi_list_stats, {0}},
		{w_mi_list_stats_1, {"statistics", 0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{ "reset_statistics", "resets the value of a statistic variable", 0, 0, {
		{mi_reset_stats, {"statistics", 0}},
		{EMPTY_MI_RECIPE}
		}
	},
	{EMPTY_MI_EXPORT}
};


#ifdef NO_ATOMIC_OPS
#warning STATISTICS: Architecture with no support for atomic operations. \
         Using Locks!!
gen_lock_t *stat_lock = 0;
#endif

#define stat_hash(_s) core_hash( _s, 0, STATS_HASH_SIZE)

#define stat_is_hidden(_s)  ((_s)->flags&STAT_HIDDEN)


/*! \brief
 * Returns the statistic associated with 'numerical_code' and 'out_codes'.
 * Specifically:
 *
 *  - if out_codes is nonzero, then the stat_var for the number of messages
 *    _sent out_ with the 'numerical_code' will be returned if it exists.
 *  - otherwise, the stat_var for the number of messages _received_ with the
 *    'numerical_code' will be returned, if the stat exists.
 */
stat_var *get_stat_var_from_num_code(unsigned int numerical_code, int out_codes)
{
	static char msg_code[INT2STR_MAX_LEN+4];
	str stat_name;

	stat_name.s = int2bstr( (unsigned long)numerical_code, msg_code,
		&stat_name.len);
	stat_name.s[stat_name.len++] = '_';

	if (out_codes) {
		stat_name.s[stat_name.len++] = 'o';
		stat_name.s[stat_name.len++] = 'u';
		stat_name.s[stat_name.len++] = 't';
	} else {
		stat_name.s[stat_name.len++] = 'i';
		stat_name.s[stat_name.len++] = 'n';
	}

	return get_stat(&stat_name);
}


char *build_stat_name( str* prefix, char *var_name)
{
	int n;
	char *s;
	char *p;

	n = prefix->len + 1 + strlen(var_name) + 1;
	s = (char*)shm_malloc( n );
	if (s==0) {
		LM_ERR("no more shm mem\n");
		return 0;
	}
	memcpy( s, prefix->s, prefix->len);
	p = s + prefix->len;
	*(p++) = '-';
	memcpy( p , var_name, strlen(var_name));
	p += strlen(var_name);
	*(p++) = 0;
	return s;
}


/************* Functions for handling MODULEs(groups) of stats ***************/

module_stats* get_stat_module( str *module)
{
	int i;

	if ( (module==0) || module->s==0 || module->len==0 )
		return 0;

	for( i=0 ; i<collector->mod_no ; i++ ) {
		if ( (collector->amodules[i].name.len == module->len) &&
		(strncasecmp(collector->amodules[i].name.s,module->s,module->len)==0) )
			return &collector->amodules[i];
	}

	return 0;
}

static inline module_stats* __add_stat_module( char *module, int unsafe)
{
	module_stats *amods;
	module_stats *mods;
	int len;

	if ( (module==0) || ((len = strlen(module))==0 ) )
		return NULL;

	amods = unsafe ?
		(module_stats*)shm_realloc_unsafe( collector->amodules,
		(collector->mod_no+1)*sizeof(module_stats))
		:
		(module_stats*)shm_realloc( collector->amodules,
		(collector->mod_no+1)*sizeof(module_stats));

	if (amods==0) {
		LM_ERR("no more shm memory\n");
		return NULL;
	}

	collector->amodules = amods;
	collector->mod_no++;

	mods = &amods[collector->mod_no-1];
	memset( mods, 0, sizeof(module_stats) );

	mods->name.s = unsafe ? shm_malloc_unsafe(len) : shm_malloc(len);
	if (!mods->name.s) {
	    LM_ERR("oom\n");
	    return NULL;
	}
	memcpy(mods->name.s, module, len);
	mods->name.len = len;

	mods->idx = collector->mod_no-1;

	return mods;
}

module_stats *add_stat_module(char *module)
{
	return __add_stat_module(module, 0);
}


/***************** Init / Destroy STATS support functions *******************/


int clone_pv_stat_name(str *name, str *clone)
{
	clone->s = (char*)shm_malloc(name->len);
	if (clone->s==NULL) {
		LM_ERR("failed to allocated more shm mem (%d)\n",name->len);
		return -1;
	}
	clone->len = name->len;
	memcpy(clone->s,name->s,name->len);

	return 0;
}


int init_stats_collector(void)
{
	module_stats *dy_mod;

	/* init the collector */
	collector = (stats_collector*)shm_malloc_unsafe(sizeof(stats_collector));
	if (collector==0) {
		LM_ERR("no more shm mem\n");
		goto error;
	}
	memset( collector, 0 , sizeof(stats_collector));

	/*
	 * register shm statistics in an unsafe manner, as some allocators
	 * would actually attempt to update these statistics
	 * during their "safe" allocations -- Liviu
	 */
	if (__register_module_stats( "shmem", shm_stats, 1) != 0) {
		LM_ERR("failed to register sh_mem statistics\n");
		goto error;
	}

	if (__register_module_stats( "rpmem", rpm_stats, 1) != 0) {
		LM_ERR("failed to register rp_mem statistics\n");
		goto error;
	}

	stats_ready = 1;

#ifdef NO_ATOMIC_OPS
	/* init BIG (really BIG) lock */
	stat_lock = lock_alloc();
	if (stat_lock==0 || lock_init( stat_lock )==0 ) {
		LM_ERR("failed to init the really BIG lock\n");
		goto error;
	}
#endif

	collector->rwl = (void*)lock_init_rw();
	if (collector->rwl==NULL) {
		LM_ERR("failed to create RW lock dynamic stats\n");
		goto error;
	}

	/* register MI commands */
	if (register_mi_mod( "statistics", mi_stat_cmds)<0) {
		LM_ERR("unable to register MI cmds\n");
		goto error;
	}

	/* register core statistics */
	if (register_module_stats( "core", core_stats)!=0 ) {
		LM_ERR("failed to register core statistics\n");
		goto error;
	}

	/* register network-level statistics */
	if (register_module_stats( "net", net_stats)!=0 ) {
		LM_ERR("failed to register network statistics\n");
		goto error;
	}

	/* create the module for "dynamic" statistics */
	dy_mod = add_stat_module( DYNAMIC_MODULE_NAME );
	if (dy_mod==NULL) {
		LM_ERR("failed to create <%s> module\n",DYNAMIC_MODULE_NAME);
		goto error;
	}
	/* mark it as dynamic, so it will require locking */
	dy_mod->is_dyn = 1 ;

	LM_DBG("statistics manager successfully initialized\n");

	return 0;
error:
	return -1;
}


void destroy_stats_collector(void)
{
	stat_var *stat;
	stat_var *tmp_stat;
	int i, idx;

#ifdef NO_ATOMIC_OPS
	/* destroy big lock */
	if (stat_lock)
		lock_destroy( stat_lock );
#endif

	if (collector) {
		/* destroy hash tables */
		for( i=0 ; i<STATS_HASH_SIZE ; i++ ) {
			/* static stats */
			for( stat=collector->hstats[i] ; stat ; ) {
				tmp_stat = stat;
				stat = stat->hnext;
				if ((tmp_stat->flags&STAT_IS_FUNC)==0 && tmp_stat->u.val && !(tmp_stat->flags&STAT_NOT_ALLOCATED))
					shm_free(tmp_stat->u.val);
				if ( (tmp_stat->flags&STAT_SHM_NAME) && tmp_stat->name.s)
					shm_free(tmp_stat->name.s);
				if (!(tmp_stat->flags&STAT_NOT_ALLOCATED))
					shm_free(tmp_stat);
			}
			/* dynamic stats*/
			for( stat=collector->dy_hstats[i] ; stat ; ) {
				tmp_stat = stat;
				stat = stat->hnext;
				if ((tmp_stat->flags&STAT_IS_FUNC)==0 && tmp_stat->u.val && !(tmp_stat->flags&STAT_NOT_ALLOCATED))
					shm_free(tmp_stat->u.val);
				if ( (tmp_stat->flags&STAT_SHM_NAME) && tmp_stat->name.s)
					shm_free(tmp_stat->name.s);
				if (!(tmp_stat->flags&STAT_NOT_ALLOCATED))
					shm_free(tmp_stat);
			}
		}

		for (idx = 0; idx < collector->mod_no; idx++) {
			shm_free(collector->amodules[idx].name.s);
		}

		/* destroy sts_module array */
		if (collector->amodules)
			shm_free(collector->amodules);

		/* destroy the RW lock */
		if (collector->rwl)
			lock_destroy_rw( (rw_lock_t *)collector->rwl);

		/* destroy the collector */
		shm_free(collector);
	}

	return;
}

int stats_are_ready(void)
{
	return stats_ready;
}

/********************* Create/Register STATS functions ***********************/

/**
 * Note: certain statistics (e.g. shm statistics) require different handling,
 * hence the <unsafe> parameter
 */
int register_stat2( char *module, char *name, stat_var **pvar,
					unsigned short flags, void *ctx, int unsafe)
{
	module_stats* mods;
	stat_var **shash;
	stat_var *stat;
	stat_var *it;
	str smodule;
	int hash;
	int name_len;

	if (module==0 || name==0 || pvar==0) {
		LM_ERR("invalid parameters module=%p, name=%p, pvar=%p \n",
				module, name, pvar);
		goto error;
	}

	name_len = strlen(name);

	if(flags&STAT_NOT_ALLOCATED){
		stat = *pvar;
		goto do_register;
	}
	stat = unsafe ?
			(stat_var*)shm_malloc_unsafe(sizeof(stat_var) +
			(((flags&STAT_SHM_NAME)==0)?name_len:0))
			:
			(stat_var*)shm_malloc(sizeof(stat_var) +
			(((flags&STAT_SHM_NAME)==0)?name_len:0));

	if (stat==0) {
		LM_ERR("no more shm memory\n");
		goto error;
	}
	memset( stat, 0, sizeof(stat_var) );

	if ( (flags&STAT_IS_FUNC)==0 ) {
		stat->u.val = unsafe ?
			(stat_val*)shm_malloc_unsafe(sizeof(stat_val)) :
			(stat_val*)shm_malloc(sizeof(stat_val));
		if (stat->u.val==0) {
			LM_ERR("no more shm memory\n");
			goto error1;
		}
#ifdef NO_ATOMIC_OPS
		*(stat->u.val) = 0;
#else
		atomic_set(stat->u.val,0);
#endif
		*pvar = stat;
	} else {
		stat->u.f = (stat_function)(pvar);
	}

	/* is the module already recorded? */
do_register:
	smodule.s = module;
	smodule.len = strlen(module);
	mods = get_stat_module(&smodule);
	if (mods==0) {
		mods = __add_stat_module(module, unsafe);
		if (mods==0) {
			LM_ERR("failed to add new module\n");
			goto error2;
		}
	}

	/* fill the stat record */
	stat->mod_idx = mods->idx;

	stat->name.len = name_len;
	if ( (flags&STAT_SHM_NAME)==0 ) {
		if(flags&STAT_NOT_ALLOCATED)
			stat->name.s = shm_malloc_unsafe(name_len);
		else
			stat->name.s = (char*)(stat+1);
			
		memcpy(stat->name.s, name, name_len);
	} else {
		stat->name.s = name;
	}
	stat->flags = flags;
	stat->context = ctx;

	/* compute the hash by name */
	hash = stat_hash( &stat->name );

	/* link it into appropriate hash table , with or without locking */
	if (mods->is_dyn) {
		lock_start_write((rw_lock_t *)collector->rwl);
		shash = collector->dy_hstats;
		/* double check for duplicates (due race conditions) */
		for( it=shash[hash] ; it ; it=stat->hnext ) {
			if ( (it->name.len==stat->name.len) &&
			(strncasecmp( it->name.s, stat->name.s, stat->name.len)==0) ) {
				/* duplicate found -> drop current stat and return the
				 * found one */
				lock_stop_write((rw_lock_t *)collector->rwl);

				if (unsafe) {
					if (flags&STAT_SHM_NAME)
						shm_free_unsafe(stat->name.s);

					if ((flags&STAT_IS_FUNC)==0)
						shm_free_unsafe(stat->u.val);

					shm_free_unsafe(stat);
				
				} else {
					if (flags&STAT_SHM_NAME)
						shm_free(stat->name.s);

					if ((flags&STAT_IS_FUNC)==0)
						shm_free(stat->u.val);

					shm_free(stat);
				}

				*pvar = it;
				return 0;
			}
		}
		/* new genuin stat-> continue */
	} else {
		shash = collector->hstats;
	}

	if (shash[hash]==0) {
		shash[hash] = stat;
	} else {
		it = shash[hash];
		while(it->hnext)
			it = it->hnext;
		it->hnext = stat;
	}
	collector->stats_no++;

	/* add the statistic also to the module statistic list */
	if (mods->tail) {
		mods->tail->lnext = stat;
	} else {
		mods->head = stat;
	}
	mods->tail = stat;
	mods->no++;

	if (mods->is_dyn)
		lock_stop_write((rw_lock_t *)collector->rwl);

	return 0;

error2:
	if ( (flags&STAT_IS_FUNC)==0 ) {
		if (unsafe)
			shm_free_unsafe(*pvar);
		else
			shm_free(*pvar);
		*pvar = 0;
	}
error1:
		if (unsafe)
			shm_free_unsafe(stat);
		else
			shm_free(stat);
error:
	if ( (flags&STAT_IS_FUNC)==0 && pvar!=NULL)
		*pvar = 0;

	return -1;
}


int __register_dynamic_stat(str *group, str *name, stat_var **pvar)
{
	char *p;
	int ret;
	str nullgrp = {NULL, 0};

	if (!group)
		group = &nullgrp;

	/*FIXME - what we do here can be avoided - convert from str to
	 * char and next function does the other way around - from char to
	 * str - this is temporary, before fixing the register_stat2 function
	 * prototype to accept str rather than char */
	if ( (p=pkg_malloc(group->len + 1 + name->len + 1))==NULL ) {
		LM_ERR("no more pkg mem (%d)\n",name->len + 1);
		return -1;
	}
	memcpy(p, group->s, group->len);
	p[group->len] = '\0';

	memcpy(p + group->len + 1, name->s, name->len);
	p[group->len + 1 + name->len] = '\0';

	ret = register_stat(!*p ? DYNAMIC_MODULE_NAME : p, p + group->len + 1,
	                    pvar, 0/*flags*/);

	pkg_free(p);

	return ret;
}

int register_dynamic_stat( str *name, stat_var **pvar)
{
	return __register_dynamic_stat (NULL, name, pvar);
}

int __register_module_stats(char *module, stat_export_t *stats, int unsafe)
{
	int ret;

	if (module==0 || module[0]==0 || !stats || !stats[0].name)
		return 0;

	for( ; stats->name ; stats++) {
		ret = register_stat2( module, stats->name, stats->stat_pointer,
			stats->flags, NULL, unsafe);
		if (ret!=0) {
			LM_CRIT("failed to add statistic\n");
			return -1;
		}
	}

	return 0;
}


stat_var* __get_stat( str *name, int mod_idx )
{
	stat_var *stat;
	int hash;

	if (collector==NULL || name==0 || name->s==0 || name->len==0)
		return 0;

	/* compute the hash by name */
	hash = stat_hash( name );

	/* and look for it , first in the hash for static stats */
	for( stat=collector->hstats[hash] ; stat ; stat=stat->hnext ) {
		if ( !stat_is_hidden(stat) && (stat->name.len==name->len) &&
		(strncasecmp( stat->name.s, name->s, name->len)==0) &&
		(mod_idx < 0 || stat->mod_idx == mod_idx))
			return stat;
	}
	/* and then in the hash for dynamic stats */
	lock_start_read((rw_lock_t *)collector->rwl);
	for( stat=collector->dy_hstats[hash] ; stat ; stat=stat->hnext ) {
		if ( !stat_is_hidden(stat) && (stat->name.len==name->len) &&
		(strncasecmp( stat->name.s, name->s, name->len)==0) &&
		(mod_idx < 0 || stat->mod_idx == mod_idx)) {
			lock_stop_read((rw_lock_t *)collector->rwl);
			return stat;
		}
	}
	lock_stop_read((rw_lock_t *)collector->rwl);

	return 0;
}

stat_var* get_stat( str *name )
{
	return __get_stat(name, -1);
}

int mi_stat_name(str *mod, str *stat, str *out)
{
	static str tmp_buf = {0, 0};
	char *tmp;

	if (mod) {
		tmp = pkg_realloc(tmp_buf.s, mod->len + stat->len + 1);
		if (!tmp) {
			LM_ERR("no more pkg memory\n");
			return -1;
		}
		tmp_buf.s = tmp;

		memcpy(tmp_buf.s, mod->s, mod->len);
		tmp_buf.len = mod->len;
		tmp_buf.s[tmp_buf.len++] = ':';

		memcpy(tmp_buf.s + tmp_buf.len, stat->s, stat->len);
		tmp_buf.len += stat->len;

		out->len = tmp_buf.len;
		out->s = tmp_buf.s;
	} else {
		out->len = stat->len;
		out->s = stat->s;
	}
	return 0;
}

int mi_print_stat(mi_item_t *resp_obj, str *mod, str *stat, unsigned long val)
{
	str tmp_buf;

	if (mi_stat_name(mod, stat, &tmp_buf) < 0) {
		LM_ERR("cannot get stat name\n");
		return -1;
	}

	if (add_mi_number(resp_obj, tmp_buf.s, tmp_buf.len, val) < 0) {
		LM_ERR("cannot add stat\n");
		return -1;
	}
	return 0;
}



/***************************** MI STUFF ********************************/

inline static int mi_add_stat(mi_item_t *resp_obj, stat_var *stat)
{
	return mi_print_stat(resp_obj, &collector->amodules[stat->mod_idx].name,
					&stat->name, get_stat_val(stat));
}

inline static int mi_list_stat(mi_item_t *resp_obj, str *mod, stat_var *stat)
{
	str tmp_buf;
	char *buf;

	if (mi_stat_name(mod, &stat->name, &tmp_buf) < 0) {
		LM_ERR("cannot get stat name\n");
		return -1;
	}

	if (stat->flags & (STAT_IS_FUNC|STAT_NO_RESET))
		buf = "non-incremental";
	else
		buf = "incremental";

	if (add_mi_string_fmt(resp_obj, tmp_buf.s, tmp_buf.len, "%s", buf)<0) {
		LM_ERR("cannot add stat\n");
		return -1;
	}
	return 0;
}

inline static int mi_add_module_stats(mi_item_t *resp_obj, module_stats *mods)
{
	stat_var *stat;
	int ret = 0;

	if (mods->is_dyn)
		lock_start_read((rw_lock_t *)collector->rwl);

	for( stat=mods->head ; stat ; stat=stat->lnext) {
		if (stat_is_hidden(stat))
			continue;
		ret = mi_print_stat(resp_obj, &mods->name, &stat->name,
				get_stat_val(stat));
		if (ret < 0)
			break;
	}

	if (mods->is_dyn)
		lock_stop_read((rw_lock_t *)collector->rwl);

	return ret;
}

inline static int mi_list_module_stats(mi_item_t *resp_obj, module_stats *mods)
{
	stat_var *stat;
	int ret = 0;

	if (mods->is_dyn)
		lock_start_read((rw_lock_t *)collector->rwl);

	for( stat=mods->head ; stat ; stat=stat->lnext) {
		if (stat_is_hidden(stat))
			continue;
		ret = mi_list_stat(resp_obj, &mods->name, stat);
		if (ret < 0)
			break;
	}

	if (mods->is_dyn)
		lock_stop_read((rw_lock_t *)collector->rwl);

	return ret;
}


static mi_response_t *mi_get_stats(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	mi_item_t *params_arr;
	int i, j, no_params;
	int found;
	module_stats *mods;
	stat_var *stat;
	str val;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (get_mi_array_param(params, "statistics", &params_arr, &no_params) < 0) {
		free_mi_response(resp);
		return init_mi_param_error();
	}

	for (i = 0; i < no_params; i++) {
		if (get_mi_arr_param_string(params_arr, i, &val.s, &val.len) < 0) {
			free_mi_response(resp);
			return init_mi_param_error();
		}

		if ( val.len==3 && memcmp(val.s,"all",3)==0) {
			/* add all statistic variables */
			for( j=0 ; j<collector->mod_no ;j++ ) {
				if (mi_add_module_stats(resp_obj, &collector->amodules[j] )!=0)
					goto error;
			}

			found = 1;
		} else if ( val.len>1 && val.s[val.len-1]==':') {
			/* add module statistics */
			val.len--;
			mods = get_stat_module( &val );
			if (mods==0)
				continue;
			if (mi_add_module_stats(resp_obj, mods)!=0)
				goto error;

			found = 1;
		} else {
			/* add only one statistic */
			stat = get_stat( &val );
			if (stat==0)
				continue;
			if (mi_add_stat(resp_obj, stat)!=0)
				goto error;

			found = 1;
		}
	}

	if (!found) {
		free_mi_response(resp);
		return init_mi_error(404, MI_SSTR("Statistics Not Found"));
	}

	return resp;

error:
	free_mi_response(resp);
	return 0;
}

static mi_response_t *w_mi_list_stats(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	int i;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	for( i=0 ; i<collector->mod_no ;i++ ) {
		if (mi_list_module_stats(resp_obj, &collector->amodules[i] )!=0) {
			free_mi_response(resp);
			return 0;
		}
	}

	return resp;
}

static mi_response_t *w_mi_list_stats_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	mi_item_t *params_arr;
	int i, no_params;
	int found;
	module_stats   *mods;
	stat_var       *stat;
	str val;

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (get_mi_array_param(params, "statistics", &params_arr, &no_params) < 0) {
		free_mi_response(resp);
		return init_mi_param_error();
	}

	for (i = 0; i < no_params; i++) {
		if (get_mi_arr_param_string(params_arr, i, &val.s, &val.len) < 0) {
			free_mi_response(resp);
			return init_mi_param_error();
		}

		if ( val.len>1 && val.s[val.len-1]==':') {
			/* add module statistics */
			val.len--;
			mods = get_stat_module( &val );
			if (mods==0)
				continue;
			if (mi_list_module_stats(resp_obj, mods)!=0)
				goto error;

			found = 1;
		} else {
			/* add only one statistic */
			stat = get_stat( &val );
			if (stat==0)
				continue;
			if (mi_list_stat(resp_obj,NULL, stat)!=0)
				goto error;

			found = 1;
		}
	}

	if (!found) {
		free_mi_response(resp);
		return init_mi_error(404, MI_SSTR("Statistics Not Found"));
	}

	return resp;

error:
	free_mi_response(resp);
	return 0;
}

static mi_response_t *mi_reset_stats(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_item_t *params_arr;
	int i, no_params;
	str val;
	stat_var *stat;
	int found = 0;

	if (get_mi_array_param(params, "statistics", &params_arr, &no_params) < 0)
		return init_mi_param_error();

	for (i = 0; i < no_params; i++) {
		if (get_mi_arr_param_string(params_arr, i, &val.s, &val.len) < 0)
			return init_mi_param_error();

		stat = get_stat(&val);
		if (stat==0)
			continue;

		reset_stat( stat );
		found = 1;
	}

	if (!found)
		return init_mi_error(404, MI_SSTR("Statistics Not Found"));

	return init_mi_result_ok();
}


#endif /*STATISTICS*/

