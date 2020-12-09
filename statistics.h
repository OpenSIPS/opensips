/*
 * Copyright (C) 2006 Voice Sistem SRL
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
 * History:
 * ---------
 *  2006-01-16  first version (bogdan)
 *  2006-11-28  added get_stat_var_from_num_code() (Jeffrey Magder -
 *              SOMA Networks)
 *  2009-04-23  function var accepts a context parameter (bogdan)
 */

/*!
 * \file
 * \brief OpenSIPS statistics handling
 */


#ifndef _STATISTICS_H_
#define _STATISTICS_H_

#include "hash_func.h"
#include "atomic.h"

#define STATS_HASH_POWER   8
#define STATS_HASH_SIZE    (1<<(STATS_HASH_POWER))

#define DYNAMIC_MODULE_NAME  "dynamic"

#define STAT_NO_RESET  (1<<0)
#define STAT_NO_SYNC   (1<<1)
#define STAT_SHM_NAME  (1<<2)
#define STAT_IS_FUNC   (1<<3)
#define STAT_NOT_ALLOCATED  (1<<4)
#define STAT_HIDDEN    (1<<5)

#ifdef NO_ATOMIC_OPS
typedef unsigned int stat_val;
#else
typedef atomic_t stat_val;
#endif

typedef unsigned long (*stat_function)(void *);

struct module_stats_;

typedef struct stat_var_{
	unsigned int mod_idx; /* backreference */
	str name;
	unsigned short flags;
	void * context;
	union{
		stat_val *val;
		stat_function f;
	}u;
	struct stat_var_ *hnext;
	struct stat_var_ *lnext;
} stat_var;

typedef struct module_stats_ {
	str name;
	unsigned int no;
	unsigned short is_dyn;
	unsigned short idx;
	stat_var *head;
	stat_var *tail;
} module_stats;

typedef struct stats_collector_ {
	int stats_no;
	int mod_no;
	stat_var* hstats[STATS_HASH_SIZE];      /* hash with static statistics */
	stat_var* dy_hstats[STATS_HASH_SIZE];   /* hash with dynamic statistics */
	void *rwl;      /* lock for protecting dynamic stats/modules */
	module_stats *amodules;
}stats_collector;

typedef struct stat_export_ {
	char* name;                /* null terminated statistic name */
	unsigned short flags;      /* flags */
	stat_var** stat_pointer;   /* pointer to the variable's mem location *
	                            * NOTE - it's in shm mem */
} stat_export_t;


#ifdef STATISTICS

char *build_stat_name( str* prefix, char *var_name);

int init_stats_collector();
int stats_are_ready(); /* for code which is statistics-dependent */

int register_udp_load_stat(str *name, stat_var **ctx, int children);
int register_tcp_load_stat(stat_var **ctx);

void destroy_stats_collector();

#define register_stat(_mod,_name,_pvar,_flags) \
		register_stat2(_mod,_name,_pvar,_flags, NULL, 0)

int register_stat2( char *module, char *name, stat_var **pvar,
		unsigned  short flags, void* context, int unsafe);

int register_dynamic_stat( str *name, stat_var **pvar);
int __register_dynamic_stat( str *group, str *name, stat_var **pvar);

#define register_module_stats(mod, stats) \
	__register_module_stats(mod, stats, 0)

int __register_module_stats(char *module, stat_export_t *stats, int unsafe);

int clone_pv_stat_name(str *name, str *clone);

/* returns the first matching statistic (regardless of module index) */
stat_var* get_stat( str *name );
/*
 * same as above, but only at stat module level
 * mod_idx == -1 makes __get_stat() behave like get_stat()
 */
stat_var* __get_stat( str *name, int mod_idx );

module_stats *add_stat_module(char *module);
module_stats *get_stat_module( str *module);

unsigned int get_stat_val( stat_var *var );

/*! \brief
 * Returns the statistic associated with 'numerical_code' and 'is_a_reply'.
 * Specifically:
 *
 *  - if in_codes is nonzero, then the stat_var for the number of messages
 *    _received_ with the 'numerical_code' will be returned if it exists.
 *  - otherwise, the stat_var for the number of messages _sent_ with the
 *    'numerical_code' will be returned, if the stat exists.
 */
stat_var *get_stat_var_from_num_code(unsigned int numerical_code, int in_codes);


#ifdef NO_ATOMIC_OPS
#include "locking.h"
extern gen_lock_t *stat_lock;
#endif

#else
	#define init_stats_collector()  0
	#define destroy_stats_collector()
	#define register_module_stats(_mod,_stats) 0
	#define __register_module_stats(_mod,_stats, unsafe) 0
	#define register_stat( _mod, _name, _pvar, _flags) 0
	#define register_dynamic_stat( _name, _pvar) 0
	#define __register_dynamic_stat( _group, _name, _pvar) 0
	#define get_stat( _name )  0
	#define __get_stat( _name, _idx)  0
	#define add_stat_module(_module) 0
	#define get_stat_module(_module) 0
	#define get_stat_val( _var ) 0
	#define get_stat_var_from_num_code( _n_code, _in_code) NULL
	#define register_udp_load_stat( _a, _b, _c) 0
	#define register_tcp_load_stat( _a)     0
	#define stats_are_ready() 0
	#define clone_pv_stat_name( _name, _clone) 0
#endif


#ifdef STATISTICS
	#ifdef NO_ATOMIC_OPS
		#define update_stat( _var, _n) \
			do { \
				if ( !((_var)->flags&STAT_IS_FUNC) ) {\
					if ((_var)->flags&STAT_NO_SYNC) {\
						*((_var)->u.val) += _n;\
					} else {\
						lock_get(stat_lock);\
						*((_var)->u.val) += _n;\
						lock_release(stat_lock);\
					}\
				}\
			}while(0)
		#define reset_stat( _var) \
			do { \
				if ( ((_var)->flags&(STAT_NO_RESET|STAT_IS_FUNC))==0 ) {\
					if ((_var)->flags&STAT_NO_SYNC) {\
						*((_var)->u.val) = 0;\
					} else {\
						lock_get(stat_lock);\
						*((_var)->u.val) = 0;\
						lock_release(stat_lock);\
					}\
				}\
			}while(0)
		#define get_stat_val( _var ) ((unsigned long)\
			((_var)->flags&STAT_IS_FUNC)?(_var)->u.f((_var)->context):*((_var)->u.val))
	#else
		#define update_stat( _var, _n) \
			do { \
				if ( !((_var)->flags&STAT_IS_FUNC) ) {\
					if ((long)(_n) >= 0L) \
						atomic_add( _n, (_var)->u.val);\
					else \
						atomic_sub( -(_n), (_var)->u.val);\
				}\
			}while(0)
		#define reset_stat( _var) \
			do { \
				if ( ((_var)->flags&(STAT_NO_RESET|STAT_IS_FUNC))==0 ) {\
					atomic_set( (_var)->u.val, 0);\
				}\
			}while(0)
		#define get_stat_val( _var ) ((unsigned long)\
			((_var)->flags&STAT_IS_FUNC)?(_var)->u.f((_var)->context):(_var)->u.val->counter)
	#endif /* NO_ATOMIC_OPS */

	#define if_update_stat(_c, _var, _n) \
		do { \
			if (_c) update_stat( _var, _n); \
		}while(0)
	#define if_reset_stat(_c, _var) \
		do { \
			if (_c) reset_stat( _var); \
		}while(0)
#else
	#define update_stat( _var, _n)
	#define reset_stat( _var)
	#define if_update_stat( _c, _var, _n)
	#define if_reset_stat( _c, _var)
#endif /*STATISTICS*/

#define inc_stat(_var) update_stat(_var, 1)

#endif
