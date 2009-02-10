/*
 * $Id: dialog.c 5217 2009-01-26 20:41:27Z bogdan_iancu $
 *
 * load balancer module - complex call load balancing
 *
 * Copyright (C) 2009 Voice Sistem SRL
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 *  2009-02-01 initial version (bogdan)
 */

#include "../../sr_module.h"
#include "../../db/db.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../ut.h"
#include "../../mod_fix.h"
#include "../../locking.h"
#include "../dialog/dlg_load.h"
#include "lb_parser.h"
#include "lb_db.h"
#include "lb_data.h"

MODULE_VERSION


/* db stuff */
static str db_url = str_init(DEFAULT_DB_URL);
static char *table_name = NULL;

/* dialog stuff */
struct dlg_binds lb_dlg_binds;

/* lock, ref counter and flag used for reloading the date */
static gen_lock_t *ref_lock = 0;
static volatile int data_refcnt = 0;
static volatile int reload_flag = 0;
static struct lb_data **curr_data = NULL;


static int mod_init(void);
static int child_init(int rank);
static void mod_destroy(void);
static int mi_child_init();

static struct mi_root* mi_lb_reload(struct mi_root *cmd_tree, void *param);

static int fixup_resources(void** param, int param_no);

static int w_load_balance(struct sip_msg *req, char *grp,  char *rl);




static cmd_export_t cmds[]={
	{"load_balance", (cmd_function)w_load_balance,      2, fixup_resources,
			0, REQUEST_ROUTE|BRANCH_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{0,0,0,0,0,0}
	};


static param_export_t mod_params[]={
	{ "db_url",                STR_PARAM, &db_url.s                 },
	{ "db_table",              STR_PARAM, &table_name               },
	{ 0,0,0 }
};


static mi_export_t mi_cmds[] = {
	{ "lb_reload",   mi_lb_reload,   MI_NO_INPUT_FLAG,   0,  mi_child_init},
	{ 0, 0, 0, 0, 0}
};



struct module_exports exports= {
	"load_balancer",  /* module's name */
	DEFAULT_DLFLAGS, /* dlopen flags */
	cmds,            /* exported functions */
	mod_params,      /* param exports */
	0,               /* exported statistics */
	mi_cmds,         /* exported MI functions */
	0,               /* exported pseudo-variables */
	0,               /* extra processes */
	mod_init,        /* module initialization function */
	0,               /* reply processing function */
	mod_destroy,
	child_init       /* per-child init function */
};



static int fixup_resources(void** param, int param_no)
{
	struct lb_res_str_list *lb_rl;

	if (param_no==1) {

		fixup_uint(param);

	} else if (param_no==2) {

		/* parameter is string (semi-colon separated list) 
		 * of needed resources */
		lb_rl = parse_resorces_list( (char *)(*param), 0);
		if (lb_rl==NULL) {
			LM_ERR("invalid paramter %s\n",(char *)(*param));
			return E_CFG;
		}
		pkg_free(*param);
		*param = (void*)lb_rl;
	}

	return 0;
}


static inline int lb_reload_data( void )
{
	struct lb_data *new_data;
	struct lb_data *old_data;

	new_data = load_lb_data();
	if ( new_data==0 ) {
		LM_CRIT("failed to load load-balancing info\n");
		return -1;
	}

	/* block access to data for all readers */
	lock_get( ref_lock );
	reload_flag = 1;
	lock_release( ref_lock );

	/* wait for all readers to finish - it's a kind of busy waitting but
	 * it's not critical;
	 * at this point, data_refcnt can only be decremented */
	while (data_refcnt) {
		usleep(10);
	}

	/* no more activ readers -> do the swapping */
	old_data = *curr_data;
	*curr_data = new_data;

	/* release the readers */
	reload_flag = 0;

	/* destroy old data */
	if (old_data)
		free_lb_data( old_data );

	return 0;
}




static int mod_init(void)
{
	LM_INFO("Load-Balancer module - initializing\n");

	db_url.len = strlen(db_url.s);

	/* Load dialog API */
	if (load_dlg_api(&lb_dlg_binds) != 0) {
		LM_ERR("Can't load dialog hooks");
		return -1;
	}

	/* data pointer in shm */
	curr_data = (struct lb_data**)shm_malloc( sizeof(struct lb_data*) );
	if (curr_data==0) {
		LM_CRIT("failed to get shm mem for data ptr\n");
		return -1;
	}
	*curr_data = 0;

	/* create & init lock */
	if ( (ref_lock=lock_alloc())==0) {
		LM_CRIT("failed to alloc ref_lock\n");
		return -1;
	}
	if (lock_init(ref_lock)==0 ) {
		LM_CRIT("failed to init ref_lock\n");
		return -1;
	}

	/* init and open DB connection */
	if (init_lb_db(&db_url, table_name)!=0) {
		LM_ERR("failed to initialize the DB support\n");
		return -1;
	}

	/* load data */
	if ( lb_reload_data()!=0 ) {
		LM_CRIT("failed to load load-balancing data\n");
		return -1;
	}

	/* close DB connection */
	lb_close_db();

	return 0;
}


static int child_init(int rank)
{
	return 0;
}


static int mi_child_init( void )
{
	/* init DB connection */
	if ( (&db_url)==0 ) {
		LM_CRIT("cannot initialize database connection\n");
		return -1;
	}
	return 0;
}



static void mod_destroy(void)
{
	/* destroy data */
	if ( curr_data) {
		if (*curr_data)
			free_lb_data( *curr_data );
		shm_free( curr_data );
		curr_data = 0;
	}

	/* destroy lock */
	if (ref_lock) {
		lock_destroy( ref_lock );
		lock_dealloc( ref_lock );
		ref_lock = 0;
	}
}


static int w_load_balance(struct sip_msg *req, char *grp, char *rl)
{
	int ret;

	/* ref the data for reading */
again:
	lock_get( ref_lock );
	/* if reload must be done, do un ugly busy waiting 
	 * until reload is finished */
	if (reload_flag) {
		lock_release( ref_lock );
		usleep(5);
		goto again;
	}
	data_refcnt++;
	lock_release( ref_lock );

	/* do lb */
	ret = do_load_balance(req, (int)(long)grp, (struct lb_res_str_list*)rl,
				*curr_data);

	/* we are done reading -> unref the data */
	lock_get( ref_lock );
	data_refcnt--;
	lock_release( ref_lock );

	if (ret<0)
		return ret;
	return 1;
}




static struct mi_root* mi_lb_reload(struct mi_root *cmd_tree, void *param)
{
	LM_INFO("\"lb_reload\" MI command received!\n");

	if ( lb_reload_data()!=0 ) {
		LM_CRIT("failed to load load balancing data\n");
		goto error;
	}

	return init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
error:
	return init_mi_tree( 500, "Failed to reload",16);
}


