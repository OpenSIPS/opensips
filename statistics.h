/*
 * $Id$
 *
 * Copyright (C) 2006 Voice Sistem SRL
 *
 * This file is part of openser, a free SIP server.
 *
 * openser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * openser is distributed in the hope that it will be useful,
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
 *  2006-01-16  first version (bogdan)
 */


#ifndef _STATISTICS_H_
#define _STATISTICS_H_

#include "hash_func.h"
#include "atomic.h"
#ifdef NO_ATOMIC_OPS
#include "locking.h"
#endif

#define STATS_HASH_POWER   8
#define STATS_HASH_SIZE    (1<<(STATS_HASH_POWER))


#define STAT_NO_RESET  (1<<0)
#define STAT_NO_SYNC   (1<<1)
#define STAT_SHM_NAME  (1<<2)

#ifdef NO_ATOMIC_OPS
typedef unsigned int stat_val;
#else
typedef atomic_t stat_val;
#endif

struct module_stats_;

typedef struct stat_var_{
	struct module_stats_ *module;
	str name;
	int flags;
	stat_val *val;
	struct stat_var_ *hnext;
	struct stat_var_ *lnext;
} stat_var;

typedef struct module_stats_ {
	str name;
	int no;
	stat_var *head;
	stat_var *tail;
} module_stats;

typedef struct stats_collector_ {
	int stats_no;
	int mod_no;
	stat_var* hstats[STATS_HASH_SIZE];
	module_stats *amodules;
}stats_collector;

typedef struct stat_export_ {
	char* name;                /* null terminated statistic name */
	int flags;                 /* flags */
	stat_var** stat_pointer;   /* pointer to the variable's mem location *
	                            * NOTE - it;s in shm mem */
} stat_export_t;


#ifdef STATISTICS
int init_stats_collector();

void destroy_stats_collector();

int register_stat( char *module, char *name, stat_var **pvar, int flags);

int register_module_stats(char *module, stat_export_t *stats);

stat_var* get_stat( str *name );

unsigned int get_stat_val( stat_var *var );

#ifdef NO_ATOMIC_OPS
extern gen_lock_t *stat_lock;
#endif

#else
	#define init_stats_collector()  0
	#define destroy_stats_collector()
	#define register_module_stats(_mod,_stats)
	#define register_stat( _mod, _name, _pvar, _flags)
	#define get_stat( _name )  0
	#define get_stat_val( _var ) 0
#endif


#ifdef STATISTICS
	#ifdef NO_ATOMIC_OPS
		#define update_stat( _var, _n) \
			do { \
				if ((_var)->flags&STAT_NO_SYNC) {\
					*((_var)->val) += _n;\
				} else {\
					lock_get(stat_lock);\
					*((_var)->val) += _n;\
					lock_release(stat_lock);\
				}\
			}while(0)
		#define reset_stat( _var) \
			do { \
				if ( ((_var)->flags&STAT_NO_RESET)==0 ) {\
					if ((_var)->flags&STAT_NO_SYNC) {\
						*((_var)->val) = 0;\
					} else {\
						lock_get(stat_lock);\
						*((_var)->val) = 0;\
						lock_release(stat_lock);\
					}\
				}\
			}while(0)
		#define get_stat_val( _var ) \
			(*((_var)->val))
	#else
		#define update_stat( _var, _n) \
			do { \
				if (_n>=0) \
					atomic_add( _n, _var->val);\
				else \
					atomic_sub( -(_n), _var->val);\
			}while(0)
		#define reset_stat( _var) \
			do { \
				if ( ((_var)->flags&STAT_NO_RESET)==0 ) {\
					atomic_set( _var->val, 0);\
				}\
			}while(0)
		#define get_stat_val( _var ) \
			((_var)->val->counter)
	#endif /* NO_ATOMIC_OPS */

	#define if_update_stat(_c, _var, _n) \
		do { \
			if (_c) update_stat( _var, _n); \
		}while(0)
	#define if_reset_stat(_c, _var, _n) \
		do { \
			if (_c) reset_stat( _var, _n); \
		}while(0)
#else
	#define update_stat( _var, _n)
	#define reset_stat( _var)
	#define if_update_stat( _c, _var, _n)
	#define if_reset_stat( _c, _var)
#endif /*STATISTICS*/


#endif
