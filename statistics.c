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


#include <string.h>

#include "dprint.h"
#include "mem/shm_mem.h"
#include "fifo_server.h"
#include "locking.h"
#include "core_stats.h"
#include "statistics.h"

#ifdef STATISTICS

static stats_collector *collector;

static int fifo_get_stats( FILE *fifo, char *response_file );
static int fifo_reset_stats( FILE *fifo, char *response_file );

#ifdef NO_ATOMIC_OPS
#warning "STATISTICS: Architecture with no support for atomic operations."
         "Using Locks!!\n"
gen_lock_t *stat_lock = 0;
#endif

#define stat_hash(_s) core_hash( _s, 0, STATS_HASH_SIZE)

int init_stats_collector()
{
	/* init the collector */
	collector = (stats_collector*)shm_malloc(sizeof(stats_collector));
	if (collector==0) {
		LOG(L_ERR,"ERROR:init_stats_collector: no more shm mem\n");
		goto error;
	}
	memset( collector, 0 , sizeof(stats_collector));

#ifdef NO_ATOMIC_OPS
	/* init BIG (really BIG) lock */
	stat_lock = lock_alloc();
	if (stat_lock==0 || lock_init( stat_lock )==0 ) {
		LOG(L_ERR,"ERROR:init_stats_collector: failed to init the really "
			"BIG lock\n");
		goto error;
	}
#endif

	/* register FIFO commands */
	if (register_fifo_cmd( fifo_get_stats, "get_statistics", 0)!=1) {
		LOG(L_ERR,"ERROR:init_stats_collector: failed to register fifo "
			"command\n");
		goto error;
	}

	/* register FIFO commands */
	if (register_fifo_cmd( fifo_reset_stats, "reset_statistics", 0)!=1) {
		LOG(L_ERR,"ERROR:init_stats_collector: failed to register fifo "
			"command\n");
		goto error;
		return -1;
	}

	/* register core statistics */
	if (register_module_stats( "core", core_stats)!=0 ) {
		LOG(L_ERR,"ERROR:init_stats_collector: failed to register core "
			"statistics\n");
		goto error;
	}
	/* register sh_mem statistics */
	if (register_module_stats( "shmem", shm_stats)!=0 ) {
		LOG(L_ERR,"ERROR:init_stats_collector: failed to register sh_mem "
			"statistics\n");
		goto error;
	}
	LOG(L_INFO,"INFO: statistics manager successfully initialized\n");

	return 0;
error:
	return -1;
}


void destroy_stats_collector()
{
	stat_var *stat;
	stat_var *tmp_stat;
	int i;

#ifdef NO_ATOMIC_OPS
	/* destroy big lock */
	if (stat_lock)
		lock_destroy( stat_lock );
#endif

	if (collector) {
		/* destroy hash table */
		for( i=0 ; i<STATS_HASH_SIZE ; i++ ) {
			for( stat=collector->hstats[i] ; stat ; ) {
				tmp_stat = stat;
				stat = stat->hnext;
				if ((tmp_stat->flags&STAT_IS_FUNC)==0 && tmp_stat->u.val)
					shm_free(tmp_stat->u.val);
				if ( (tmp_stat->flags&STAT_SHM_NAME) && tmp_stat->name.s)
					shm_free(tmp_stat->name.s);
				shm_free(tmp_stat);
			}
		}

		/* destroy sts_module array */
		if (collector->amodules)
			shm_free(collector->amodules);

		/* destroy the collector */
		shm_free(collector);
	}

	return;
}


static inline module_stats* get_stat_module( str *module)
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


static inline module_stats* add_stat_module( char *module)
{
	module_stats *amods;
	module_stats *mods;
	int len;

	if ( (module==0) || ((len = strlen(module))==0 ) )
		return 0;

	amods = (module_stats*)shm_realloc( collector->amodules,
			(collector->mod_no+1)*sizeof(module_stats) );
	if (amods==0) {
		LOG(L_ERR,"ERROR:add_stat_module: no more shm memory\n");
		return 0;
	}

	collector->amodules = amods;
	collector->mod_no++;

	mods = &amods[collector->mod_no-1];
	memset( mods, 0, sizeof(module_stats) );

	mods->name.s = module;
	mods->name.len = len;

	return mods;
}


int register_stat( char *module, char *name, stat_var **pvar, int flags)
{
	module_stats* mods;
	stat_var *stat;
	stat_var *it;
	str smodule;
	int hash;

	if (module==0 || name==0 || pvar==0) {
		LOG(L_ERR,"ERROR:register_stat: invalid parameters module=%p, "
			"name=%p, pvar=%p \n", module, name, pvar);
		goto error;
	}

	stat = (stat_var*)shm_malloc(sizeof(stat_var));
	if (stat==0) {
		LOG(L_ERR,"ERROR:register_stat: no more shm memory\n");
		goto error;
	}
	memset( stat, 0, sizeof(stat_var));

	if ( (flags&STAT_IS_FUNC)==0 ) {
		stat->u.val = (stat_val*)shm_malloc(sizeof(stat_val));
		if (stat->u.val==0) {
			LOG(L_ERR,"ERROR:register_stat: no more shm memory\n");
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
	smodule.s = module;
	smodule.len = strlen(module);
	mods = get_stat_module(&smodule);
	if (mods==0) {
		mods = add_stat_module(module);
		if (mods==0) {
			LOG(L_ERR,"ERROR:register_stat: failed to add new module\n");
			goto error2;
		}
	}

	/* fill the stat record */
	stat->module = mods;

	stat->name.s = name;
	stat->name.len = strlen(name);
	stat->flags = flags;


	/* compute the hash by name */
	hash = stat_hash( &stat->name );

	/* link it */
	if (collector->hstats[hash]==0) {
		collector->hstats[hash] = stat;
	} else {
		it = collector->hstats[hash];
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

	return 0;
error2:
	if ( (flags&STAT_IS_FUNC)==0 ) {
		shm_free(*pvar);
		*pvar = 0;
	}
error1:
	shm_free(stat);
error:
	*pvar = 0;
	return -1;
}



int register_module_stats(char *module, stat_export_t *stats)
{
	int ret;

	if (module==0 || module[0]==0 || !stats || !stats[0].name)
		return 0;

	for( ; stats->name ; stats++) {
		ret = register_stat( module, stats->name, stats->stat_pointer,
			stats->flags);
		if (ret!=0) {
			LOG(L_CRIT,"CRIT:register_module_stats: failed to add "
				"statistic\n");
			return -1;
		}
	}

	return 0;
}



stat_var* get_stat( str *name )
{
	stat_var *stat;
	int hash;

	if (name==0 || name->s==0 || name->len==0)
		return 0;

	/* compute the hash by name */
	hash = stat_hash( name );

	/* and look for it */
	for( stat=collector->hstats[hash] ; stat ; stat=stat->hnext ) {
		if ( (stat->name.len==name->len) &&
		(strncasecmp( stat->name.s, name->s, name->len)==0) )
			return stat;
	}

	return 0;
}




/***************************** FIFO STUFF ********************************/

static void inline fifo_print_stat(FILE *rf, str *name)
{
	stat_var *stat;

	stat = get_stat( name );
	if (stat==0) {
		fprintf(rf,"404 Statistic not found\n");
		return;
	}

	fprintf(rf,"200 OK\n");
	fprintf(rf,"%.*s:%.*s = %lu\n",
		stat->module->name.len, stat->module->name.s,
		stat->name.len, stat->name.s,
		get_stat_val(stat) );
}



static void inline fifo_print_module_stats(FILE *rf, module_stats *mods)
{
	stat_var *stat;
	
	fprintf(rf,"Module name = %.*s; statistics=%d\n",
		mods->name.len, mods->name.s, mods->no);
	for( stat=mods->head ; stat ; stat=stat->lnext) {
		fprintf(rf,"%.*s:%.*s = %lu\n",
			mods->name.len, mods->name.s,
			stat->name.len, stat->name.s,
			get_stat_val(stat) );
	}
}


static void fifo_all_stats(FILE *rf)
{
	int i;

	fprintf(rf,"200 OK\n");
	fprintf(rf,"Total statistics = %d\n",collector->stats_no);
	fprintf(rf,"Total modules = %d\n",collector->mod_no);

	for( i=0 ; i<collector->mod_no ;i++ )
		fifo_print_module_stats( rf, &collector->amodules[i] );
}


static void fifo_module_stats( FILE *rf, str *mod)
{
	module_stats *mods;

	mods = get_stat_module( mod );
	if (mods==0) {
		fprintf(rf,"404 Module not found\n");
		return;
	}

	fprintf(rf,"200 OK\n");
	fifo_print_module_stats( rf, mods );
}


static int fifo_get_stats( FILE *fifo, char *reply_file )
{
#define MAX_FS_BUF 512
	static char buf[MAX_FS_BUF];
	FILE *rfifo;
	str arg = {0, 0};
	int n;
	int is_mod;

	if (read_line( buf, MAX_FS_BUF, fifo, &n)!=1) {
		LOG(L_ERR,"ERROR:fifo_get_stats: failed to read argument from fifo\n");
		fifo_reply( reply_file, "500 Read error\n");
		goto error;
	}

	if (n==0 || (n==3 && strncasecmp(buf,"all",3)==0 ) ) {
		is_mod = 0;
		arg.s = 0;
		arg.len = 0;
	} else {
		/* parse argument */
		if ( buf[n-1]!=':' ) {
			/* whole argument is just statistic's name */
			is_mod = 0;
		} else {
			/* arg is a module name */
			buf[--n]=0;
			is_mod = 1;
		}
		arg.s = buf;
		arg.len = n;
	}

	/* open reply fifo */
	rfifo = open_reply_pipe( reply_file );
	if (rfifo==0) {
		LOG(L_ERR,"ERROR:fifo_get_stats: failed to open reply fifo\n");
		goto error;
	}

	if (arg.len==0) {
		/* write all statistics */
		fifo_all_stats( rfifo );
	} else if (is_mod) {
		/* write module statistics */
		fifo_module_stats( rfifo, &arg);
	} else {
		/* write statistic */
		fifo_print_stat( rfifo, &arg);
	}

	fclose(rfifo);

	return 0;
error:
	return -1;
}



static int fifo_reset_stats( FILE *fifo, char *reply_file )
{
#define MAX_FS_BUF 512
	static char buf[MAX_FS_BUF];
	stat_var *stat;
	str name;

	if (read_line( buf, MAX_FS_BUF, fifo, &name.len)!=1) {
		LOG(L_ERR,"ERROR:fifo_reset_stats: failed to read arg. from fifo\n");
		fifo_reply( reply_file, "500 Read error\n");
		goto error;
	}

	if (name.len==0) {
		LOG(L_ERR,"ERROR:fifo_reset_stats: no arg found\n");
		fifo_reply( reply_file, "400 Statistic name expected\n");
		goto error;
	}
	name.s = buf;

	stat = get_stat( &name );
	if (stat==0) {
		fifo_reply( reply_file,"404 Statistic not found\n");
		goto error;
	}

	reset_stat( stat );
	fifo_reply( reply_file,"200 OK\n");
	return 0;
error:
	return -1;
}


#endif /*STATISTICS*/

