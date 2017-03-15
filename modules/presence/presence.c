/*
 * presence module - presence server implementation
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
 *  2006-08-15  initial version (Anca Vamanu)
 *  2010-10-19  support for extra headers (osas)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#include "../../sr_module.h"
#include "../../db/db.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../ut.h"
#include "../../parser/parse_to.h"
#include "../../parser/parse_uri.h"
#include "../../parser/parse_content.h"
#include "../../parser/parse_from.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../usr_avp.h"
#include "../tm/tm_load.h"
#include "../signaling/signaling.h"
#include "../../pt.h"
#include "../../mi/mi.h"
#include "../pua/hash.h"
#include "publish.h"
#include "subscribe.h"
#include "event_list.h"
#include "bind_presence.h"
#include "notify.h"
#include "../../evi/evi_modules.h"


#define S_TABLE_VERSION  4
#define P_TABLE_VERSION  5
#define ACTWATCH_TABLE_VERSION 11

char *log_buf = NULL;
static int clean_period=100;
static int watchers_clean_period=3600;
static int db_update_period=100;

/* database connection */
db_con_t *pa_db = NULL;
db_func_t pa_dbf;
str presentity_table= str_init("presentity");
str active_watchers_table = str_init("active_watchers");
str watchers_table= str_init("watchers");

int library_mode= 0;
str server_address= {0, 0};
evlist_t* EvList= NULL;

/* TM bind */
struct tm_binds tmb;
/* SIGNALING bind */
struct sig_binds sigb;

/** module functions */

static int mod_init(void);
static int child_init(int);
static void destroy(void);
int stored_pres_info(struct sip_msg* msg, char* pres_uri, char* s);
static int fixup_presence(void** param, int param_no);
static int fixup_subscribe(void** param, int param_no);
static struct mi_root* mi_refreshWatchers(struct mi_root* cmd, void* param);
static struct mi_root* mi_cleanup(struct mi_root* cmd, void* param);
static struct mi_root* mi_list_phtable(struct mi_root* cmd, void* param);
static struct mi_root* mi_list_shtable(struct mi_root* cmd, void* param);
static struct mi_root* mi_pres_expose(struct mi_root* cmd, void* param);
static int update_pw_dialogs(subs_t* subs, unsigned int hash_code, subs_t** subs_array);
int update_watchers_status(str pres_uri, pres_ev_t* ev, str* rules_doc);
int refresh_send_winfo_notify(watcher_t* watcher, str pres_uri,
		struct pres_ev* ev);

int counter =0;
int pid = 0;
char prefix='a';
str db_url = {0, 0};
int expires_offset = 0;
int max_expires_subscribe= 3600;
int max_expires_publish= 3600;
int shtable_size= 9;
shtable_t subs_htable= NULL;
int fallback2db= 0;
int sphere_enable= 0;
int mix_dialog_presence= 0;
int notify_offline_body= 0;
/* if subscription should be automatically ended on SIP timeout 408 */
int end_sub_on_timeout= 1;
/* holder for the pointer to presence event */
pres_ev_t** pres_event_p= NULL;
pres_ev_t** dialog_event_p= NULL;

int phtable_size= 9;
phtable_t* pres_htable = NULL;
unsigned int waiting_subs_daysno = 0;
unsigned long waiting_subs_time = 3*24*3600;
str bla_presentity_spec_param = {0, 0};
pv_spec_t bla_presentity_spec;
int fix_remote_target=1;

/* event id */
static str presence_publish_event = str_init("E_PRESENCE_PUBLISH");
static str presence_exposed_event = str_init("E_PRESENCE_EXPOSED");
event_id_t presence_event_id = EVI_ERROR;
event_id_t exposed_event_id = EVI_ERROR;

static cmd_export_t cmds[]=
{
	{"handle_publish",  (cmd_function)handle_publish,  0,fixup_presence,0, REQUEST_ROUTE},
	{"handle_publish",  (cmd_function)handle_publish,  1,fixup_presence, 0, REQUEST_ROUTE},
	{"handle_subscribe",(cmd_function)handle_subscribe,0,fixup_subscribe,0, REQUEST_ROUTE},
	{"handle_subscribe",(cmd_function)handle_subscribe,1,fixup_subscribe,0, REQUEST_ROUTE},
	{"bind_presence",   (cmd_function)bind_presence,   1,     0,         0,  0},
	{ 0,                    0,                         0,     0,         0,  0}
};

static param_export_t params[]={
	{ "db_url",                 STR_PARAM, &db_url.s},
	{ "presentity_table",       STR_PARAM, &presentity_table.s},
	{ "active_watchers_table",  STR_PARAM, &active_watchers_table.s},
	{ "watchers_table",         STR_PARAM, &watchers_table.s},
	{ "clean_period",           INT_PARAM, &clean_period },
	{ "db_update_period",       INT_PARAM, &db_update_period },
	{ "expires_offset",         INT_PARAM, &expires_offset },
	{ "max_expires_subscribe",  INT_PARAM, &max_expires_subscribe },
	{ "max_expires_publish",    INT_PARAM, &max_expires_publish },
	{ "server_address",         STR_PARAM, &server_address.s},
	{ "subs_htable_size",       INT_PARAM, &shtable_size},
	{ "pres_htable_size",       INT_PARAM, &phtable_size},
	{ "fallback2db",            INT_PARAM, &fallback2db},
	{ "enable_sphere_check",    INT_PARAM, &sphere_enable},
	{ "waiting_subs_daysno",    INT_PARAM, &waiting_subs_daysno},
	{ "mix_dialog_presence",    INT_PARAM, &mix_dialog_presence},
	{ "bla_presentity_spec",    STR_PARAM, &bla_presentity_spec_param},
	{ "bla_fix_remote_target",  INT_PARAM, &fix_remote_target},
	{ "notify_offline_body",    INT_PARAM, &notify_offline_body},
	{ "end_sub_on_timeout",     INT_PARAM, &end_sub_on_timeout},
	{0,0,0}
};

static mi_export_t mi_cmds[] = {
	{ "refreshWatchers",   0, mi_refreshWatchers,    0,  0,  0},
	{ "cleanup",           0, mi_cleanup,            0,  0,  0},
	{ "pres_expose",       0, mi_pres_expose,        0,  0,  0},
	{ "pres_phtable_list", 0, mi_list_phtable,       0,  0,  0},
	{ "subs_phtable_list", 0, mi_list_shtable,       0,  0,  0},
	{  0,                  0, 0,                     0,  0,  0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "tm",        DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "signaling", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "db_url", get_deps_sqldb_url },
		{ NULL, NULL },
	},
};

/** module exports */
struct module_exports exports= {
	"presence",					/* module name */
	MOD_TYPE_DEFAULT,           /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,			/* dlopen flags */
	&deps,                      /* OpenSIPS module dependencies */
	cmds,						/* exported functions */
	0,							/* exported async functions */
	params,						/* exported parameters */
	0,							/* exported statistics */
	mi_cmds,					/* exported MI functions */
	0,							/* exported pseudo-variables */
	0,							/* extra processes */
	mod_init,					/* module initialization function */
	(response_function) 0,      /* response handling function */
	(destroy_function) destroy, /* destroy function */
	child_init                  /* per-child init function */
};

/**
 * init module function
 */
static int mod_init(void)
{
	/* register event E_PRESENCE_NOTIFY */ 
	if( (presence_event_id=evi_publish_event(presence_publish_event)) == EVI_ERROR )
		LM_ERR("Cannot register E_PRESENCE_PUBLISH event\n");
	if( (exposed_event_id=evi_publish_event(presence_exposed_event)) == EVI_ERROR )
		LM_ERR("Cannot register E_PRESENCE_EXPOSED event\n");
	db_url.len = db_url.s ? strlen(db_url.s) : 0;
	LM_DBG("db_url=%s/%d/%p\n", ZSW(db_url.s), db_url.len,db_url.s);
	presentity_table.len = strlen(presentity_table.s);
	active_watchers_table.len = strlen(active_watchers_table.s);
	watchers_table.len = strlen(watchers_table.s);

	LM_NOTICE("initializing module ...\n");

	EvList= init_evlist();
	if(!EvList)
	{
		LM_ERR("initializing event list\n");
		return -1;
	}

	pres_event_p = (pres_ev_t**)shm_malloc(sizeof(pres_ev_t*));
	dialog_event_p = (pres_ev_t**)shm_malloc(sizeof(pres_ev_t*));
	if(pres_event_p == NULL || dialog_event_p == NULL)
	{
		LM_ERR("No more shared memory\n");
		return -1;
	}
	*dialog_event_p = *pres_event_p = NULL;

	if(db_url.s== NULL) {
		library_mode= 1;
		LM_DBG("presence module used for library purpose only\n");
		/* disable all MI commands (loading MI cmds is done after init) */
		exports.mi_cmds = NULL;
		return 0;
	}

	if(expires_offset<0)
		expires_offset = 0;

	if(max_expires_subscribe<= 0)
		max_expires_subscribe = 3600;

	if(max_expires_publish<= 0)
		max_expires_publish = 3600;

	if(server_address.s== NULL)
		LM_DBG("server_address parameter not set in configuration file\n");

	if(server_address.s)
		server_address.len= strlen(server_address.s);
	else
		server_address.len= 0;

	/* load SIGNALING API */
	if(load_sig_api(&sigb)< 0)
	{
		LM_ERR("can't load signaling functions\n");
		return -1;
	}

	/* load all TM stuff */
	if(load_tm_api(&tmb)==-1)
	{
		LM_ERR("can't load tm functions\n");
		return -1;
	}

	if(db_url.s== NULL)
	{
		LM_ERR("database url not set!\n");
		return -1;
	}

	/* binding to database module  */
	if (db_bind_mod(&db_url, &pa_dbf))
	{
		LM_ERR("Database module not found\n");
		return -1;
	}

	if (!DB_CAPABILITY(pa_dbf, DB_CAP_ALL))
	{
		LM_ERR("Database module does not implement all functions"
				" needed by presence module\n");
		return -1;
	}

	pa_db = pa_dbf.init(&db_url);
	if (!pa_db)
	{
		LM_ERR("connecting to database failed\n");
		return -1;
	}

	/*verify table versions */
	if((db_check_table_version(&pa_dbf, pa_db, &presentity_table, P_TABLE_VERSION) < 0) ||
		(db_check_table_version(&pa_dbf, pa_db, &active_watchers_table, ACTWATCH_TABLE_VERSION) < 0) ||
		(db_check_table_version(&pa_dbf, pa_db, &watchers_table, S_TABLE_VERSION) < 0)) {
			LM_ERR("error during table version check\n");
			return -1;
	}

	if(shtable_size< 1)
		shtable_size= 512;
	else
		shtable_size= 1<< shtable_size;

	subs_htable= new_shtable(shtable_size);
	if(subs_htable== NULL)
	{
		LM_ERR(" initializing subscribe hash table\n");
		return -1;
	}

	if(restore_db_subs()< 0)
	{
		LM_ERR("restoring subscribe info from database\n");
		return -1;
	}

	if(phtable_size< 1)
		phtable_size= 256;
	else
		phtable_size= 1<< phtable_size;

	pres_htable= new_phtable();
	if(pres_htable== NULL)
	{
		LM_ERR("initializing presentity hash table\n");
		return -1;
	}

	if(pres_htable_restore()< 0)
	{
		LM_ERR("filling in presentity hash table from database\n");
		return -1;
	}

	if(clean_period>0)
	{
		register_timer("presence-pclean", msg_presentity_clean, 0,
			clean_period, TIMER_FLAG_DELAY_ON_DELAY);
		register_timer("presence-wclean", msg_watchers_clean, 0,
			watchers_clean_period, TIMER_FLAG_DELAY_ON_DELAY);
	}

	if(db_update_period>0)
		register_timer("presence-dbupdate", timer_db_update, 0,
			db_update_period, TIMER_FLAG_SKIP_ON_DELAY);

	if (pa_dbf.use_table(pa_db, &watchers_table) < 0)
	{
		LM_ERR("unsuccessful use table sql operation\n");
		return -1;
	}

	if(pa_dbf.delete(pa_db, 0,0,0,0)< 0)
	{
		LM_ERR("deleting all records from database table\n");
		return -1;
	}

	if(pa_db)
		pa_dbf.close(pa_db);
	pa_db = NULL;

	if(waiting_subs_daysno > 30)
	{
		LM_INFO("Too greater value for waiting_subs_daysno parameter."
				" 30 days, the maximum accepted value will be used instead\n");
		waiting_subs_daysno = 30;
	}
	if(waiting_subs_daysno > 0)
		waiting_subs_time = waiting_subs_daysno*24*3600;

	if(bla_presentity_spec_param.s)
	{
		bla_presentity_spec_param.len = strlen(bla_presentity_spec_param.s);
		if(pv_parse_spec(&bla_presentity_spec_param, &bla_presentity_spec)==NULL)
		{
			LM_ERR("failed to parse bla_presentity spec\n");
			return -2;
		}
		switch(bla_presentity_spec.type) {
			case PVT_NONE:
			case PVT_EMPTY:
			case PVT_NULL:
			case PVT_MARKER:
			case PVT_COLOR:
				LM_ERR("invalid bla_presentity spec\n");
				return -3;
			default: ;
		}
	}

	return 0;
}

/**
 * Initialize children
 */
static int child_init(int rank)
{
	LM_NOTICE("init_child [%d]  pid [%d]\n", rank, getpid());

	pid = my_pid();

	if(library_mode)
		return 0;

	if (pa_dbf.init==0)
	{
		LM_CRIT("child_init: database not bound\n");
		return -1;
	}
	pa_db = pa_dbf.init(&db_url);
	if (!pa_db)
	{
		LM_ERR("child %d: unsuccessful connecting to database\n", rank);
		return -1;
	}
	LM_DBG("child %d: Database connection opened successfully\n", rank);

	return 0;
}



/*
 * destroy function
 */
static void destroy(void)
{
	LM_NOTICE("destroy module ...\n");

	if(subs_htable && pa_db)
		timer_db_update(0, 0);

	if(subs_htable)
		destroy_shtable(subs_htable, shtable_size);

	if(pres_htable)
		destroy_phtable();

	if(pa_db && pa_dbf.close)
		pa_dbf.close(pa_db);

	if(pres_event_p)
		shm_free(pres_event_p);
	if(dialog_event_p)
		shm_free(dialog_event_p);

	destroy_evlist();
}

static int fixup_presence(void** param, int param_no)
{
 	pv_elem_t *model;
	str s;

	if(library_mode)
	{
		LM_ERR("Bad config - you can not call 'handle_publish' function"
				" (db_url not set)\n");
		return -1;
	}
	if(param_no== 0)
		return 0;

	if(*param)
 	{
		s.s = (char*)(*param); s.len = strlen(s.s);
 		if(pv_parse_format(&s, &model)<0)
 		{
 			LM_ERR( "wrong format[%s]\n",(char*)(*param));
 			return E_UNSPEC;
 		}

 		*param = (void*)model;
 		return 0;
 	}
 	LM_ERR( "null format\n");
 	return E_UNSPEC;
}

static int fixup_subscribe(void** param, int param_no)
{
	if(library_mode)
	{
		LM_ERR("Bad config - you can not call 'handle_subscribe' function"
				" (db_url not set)\n");
		return -1;
	}
	return 0;
}

/*
 *  mi cmd: refreshWatchers
 *			<presentity_uri>
 *			<event>
 *          <refresh_type> // can be:  = 0 -> watchers autentification type or
 *									  != 0 -> publish type //
 *		* */

static struct mi_root* mi_refreshWatchers(struct mi_root* cmd, void* param)
{
	struct mi_node* node= NULL;
	str pres_uri, event;
	struct sip_uri uri;
	pres_ev_t* ev;
	str* rules_doc= NULL;
	int result;
	unsigned int refresh_type;

	LM_DBG("start\n");

	node = cmd->node.kids;
	if(node == NULL)
		return init_mi_tree(404, "No parameters", 13);

	/* Get presentity URI */
	pres_uri = node->value;
	if(pres_uri.s == NULL || pres_uri.len== 0)
	{
		LM_ERR( "empty uri\n");
		return init_mi_tree(404, "Empty presentity URI", 20);
	}

	node = node->next;
	if(node == NULL)
		return 0;
	event= node->value;
	if(event.s== NULL || event.len== 0)
	{
		LM_ERR( "empty event parameter\n");
		return init_mi_tree(400, "Empty event parameter", 21);
	}
	LM_DBG("event '%.*s'\n",  event.len, event.s);

	node = node->next;
	if(node == NULL)
		return 0;
	if(node->value.s== NULL || node->value.len== 0)
	{
		LM_ERR( "empty event parameter\n");
		return init_mi_tree(400, "Empty event parameter", 21);
	}
	if(str2int(&node->value, &refresh_type)< 0)
	{
		LM_ERR("converting string to int\n");
		goto error;
	}

	if(node->next!= NULL)
	{
		LM_ERR( "Too many parameters\n");
		return init_mi_tree(400, "Too many parameters", 19);
	}

	ev= contains_event(&event, NULL);
	if(ev== NULL)
	{
		LM_ERR( "wrong event parameter\n");
		return 0;
	}

	if(refresh_type== 0) /* if a request to refresh watchers authorization*/
	{
		if(ev->get_rules_doc== NULL)
		{
			LM_ERR("wrong request for a refresh watchers authorization status"
					"for an event that does not require authorization\n");
			goto error;
		}

		if(parse_uri(pres_uri.s, pres_uri.len, &uri)< 0)
		{
			LM_ERR( "parsing uri\n");
			goto error;
		}

		result= ev->get_rules_doc(&uri.user,&uri.host,&rules_doc);
		if(result< 0 || rules_doc==NULL || rules_doc->s== NULL)
		{
			LM_ERR( "no rules doc found for the user\n");
			goto error;
		}

		if(update_watchers_status(pres_uri, ev, rules_doc)< 0)
		{
			LM_ERR("failed to update watchers\n");
			goto error;
		}

		pkg_free(rules_doc->s);
		pkg_free(rules_doc);
		rules_doc = NULL;

	}
	else     /* if a request to refresh Notified info */
	{
		if(query_db_notify(&pres_uri, ev, NULL)< 0)
		{
			LM_ERR("sending Notify requests\n");
			goto error;
		}

	}

	return init_mi_tree( 200, MI_OK_S, MI_OK_LEN);

error:
	if(rules_doc)
	{
		if(rules_doc->s)
			pkg_free(rules_doc->s);
		pkg_free(rules_doc);
	}
	return 0;
}

/*
 *  mi cmd: cleanup
 *		* */

static struct mi_root* mi_cleanup(struct mi_root* cmd, void* param)
{
	LM_DBG("mi_cleanup:start\n");

	(void)msg_watchers_clean(0,0);
	(void)msg_presentity_clean(0,0);

	return init_mi_tree(200, MI_OK_S, MI_OK_LEN);
}


static inline int mi_print_phtable_record(struct mi_node *rpl, pres_entry_t* pres)
{
	struct mi_node* node;
	struct mi_attr* attr;
	char* p;
	int len;

	node = add_mi_node_child(rpl, 0, "pres_uri", 8, pres->pres_uri.s, pres->pres_uri.len);
	if(node == NULL) goto error;
	p= int2str((unsigned long)pres->event, &len);
	attr = add_mi_attr(node, MI_DUP_VALUE, "event", 5, p, len);
	if(attr == NULL) goto error;
	p= int2str((unsigned long)pres->etag_count, &len);
	attr = add_mi_attr(node, MI_DUP_VALUE, "etag_count", 10, p, len);
	if(attr == NULL) goto error;
	if (pres->sphere)
	{
		attr = add_mi_attr(node, MI_DUP_VALUE, "sphere", 6,
						pres->sphere, strlen(pres->sphere));
		if(attr == NULL) goto error;
	}
	attr = add_mi_attr(node, MI_DUP_VALUE, "etag", 4, pres->etag, pres->etag_len);
	if(attr == NULL) goto error;

	return 0;
error:
	LM_ERR("failed to add node\n");
	return -1;
}

static struct mi_root* mi_list_phtable(struct mi_root* cmd, void* param)
{

	struct mi_root *rpl_tree;
	struct mi_node* rpl;
	pres_entry_t* p;
	unsigned int i;

	rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree==NULL) return NULL;
	rpl = &rpl_tree->node;
	rpl->flags |= MI_IS_ARRAY;

	for(i= 0; i<phtable_size; i++)
	{
		lock_get(&pres_htable[i].lock);
		p = pres_htable[i].entries->next;
		while(p)
		{
			if(mi_print_phtable_record(rpl, p)<0) goto error;
			p= p->next;;
		}
		lock_release(&pres_htable[i].lock);
	}
	return rpl_tree;
error:
	lock_release(&pres_htable[i].lock);
	LM_ERR("Unable to create reply\n");
	free_mi_tree(rpl_tree);
	return NULL;
}


static inline int mi_print_shtable_record(struct mi_node *rpl, subs_t* s)
{
	struct mi_node *node, *node1;
	struct mi_attr *attr;
	time_t _ts;
	char date_buf[MI_DATE_BUF_LEN];
	int date_buf_len;
	char *p;
	int len;

	node = add_mi_node_child(rpl, 0, "pres_uri", 8, s->pres_uri.s, s->pres_uri.len);
	if (node==NULL) goto error;
	attr = add_mi_attr(node, MI_DUP_VALUE, "event", 5, s->event->name.s, s->event->name.len);
	if (attr==NULL) goto error;
	/*
	attr = add_mi_attr(node, MI_DUP_VALUE, "event_id", 8, s->event_id.s, s->event_id.len);
	if (attr==NULL) goto error;
	*/
	_ts = (time_t)s->expires;
	date_buf_len = strftime(date_buf, MI_DATE_BUF_LEN - 1,
						"%Y-%m-%d %H:%M:%S", localtime(&_ts));
	if (date_buf_len != 0) {
		attr = add_mi_attr(node, MI_DUP_VALUE, "expires", 7, date_buf, date_buf_len);
	} else {
		p= int2str((unsigned long)s->expires, &len);
		attr = add_mi_attr(node, MI_DUP_VALUE, "expires", 7, p, len);
	}
	if (attr==NULL) goto error;
	p= int2str((unsigned long)s->db_flag, &len);
	attr = add_mi_attr(node, MI_DUP_VALUE, "db_flag", 7, p, len);
	if (attr==NULL) goto error;
	p= int2str((unsigned long)s->version, &len);
	attr = add_mi_attr(node, MI_DUP_VALUE, "version", 7, p, len);
	if (attr==NULL) goto error;

	node1 = add_mi_node_child(node, 0, "to_user", 7, s->to_user.s, s->to_user.len);
	if (node1==NULL) goto error;
	attr = add_mi_attr(node1, MI_DUP_VALUE, "to_domain", 9, s->to_domain.s, s->to_domain.len);
	if (attr==NULL) goto error;
	attr = add_mi_attr(node1, MI_DUP_VALUE, "to_tag", 6, s->to_tag.s, s->to_tag.len);
	if (attr==NULL) goto error;

	node1 = add_mi_node_child(node, 0, "from_user", 9, s->from_user.s, s->from_user.len);
	if (node1==NULL) goto error;
	attr = add_mi_attr(node1, MI_DUP_VALUE, "from_domain", 11,
				s->from_domain.s, s->from_domain.len);
	if (attr==NULL) goto error;
	attr = add_mi_attr(node1, MI_DUP_VALUE, "from_tag", 8, s->from_tag.s, s->from_tag.len);
	if (attr==NULL) goto error;

	node1 = add_mi_node_child(node, 0, "callid", 6, s->callid.s, s->callid.len);
	if (node1==NULL) goto error;
	p= int2str((unsigned long)s->local_cseq, &len);
	attr = add_mi_attr(node1, MI_DUP_VALUE, "local_cseq", 10, p, len);
	if (attr==NULL) goto error;
	p= int2str((unsigned long)s->remote_cseq, &len);
	attr = add_mi_attr(node1, MI_DUP_VALUE, "remote_cseq", 11, p, len);
	if (attr==NULL) goto error;

	return 0;
error:
	LM_ERR("failed to add node\n");
	return -1;
}


static struct mi_root* mi_list_shtable(struct mi_root* cmd, void* param)
{
	struct mi_root *rpl_tree;
	struct mi_node* rpl;
	subs_t *s;
	unsigned int i,j;

	rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
	if (rpl_tree==NULL) return NULL;
	rpl = &rpl_tree->node;
	rpl->flags |= MI_IS_ARRAY;

	for(i=0,j=0; i< shtable_size; i++)
	{
		lock_get(&subs_htable[i].lock);
		s = subs_htable[i].entries->next;
		while(s)
		{
			if(mi_print_shtable_record(rpl, s)<0) goto error;
			s= s->next;
			j++;
		}
		lock_release(&subs_htable[i].lock);

		if ((j % 50) == 0)
			flush_mi_tree(rpl_tree);
	}
	return rpl_tree;
error:
	lock_release(&subs_htable[i].lock);
	LM_ERR("Unable to create reply\n");
	free_mi_tree(rpl_tree);
	return NULL;
}


int pres_update_status(subs_t subs, str reason, db_key_t* query_cols,
        db_val_t* query_vals, int n_query_cols, subs_t** subs_array)
{
	static db_ps_t my_del_ps = NULL;
	static db_ps_t my_upd_ps = NULL;
	db_key_t update_cols[5];
	db_val_t update_vals[5];
	int n_update_cols= 0;
	int u_status_col, u_reason_col, q_wuser_col, q_wdomain_col;
	int status;
	query_cols[q_wuser_col=n_query_cols]= &str_watcher_username_col;
	query_vals[n_query_cols].nul= 0;
	query_vals[n_query_cols].type= DB_STR;
	n_query_cols++;

	query_cols[q_wdomain_col=n_query_cols]= &str_watcher_domain_col;
	query_vals[n_query_cols].nul= 0;
	query_vals[n_query_cols].type= DB_STR;
	n_query_cols++;

	update_cols[u_status_col= n_update_cols]= &str_status_col;
	update_vals[u_status_col].nul= 0;
	update_vals[u_status_col].type= DB_INT;
	n_update_cols++;

	update_cols[u_reason_col= n_update_cols]= &str_reason_col;
	update_vals[u_reason_col].nul= 0;
	update_vals[u_reason_col].type= DB_STR;
	n_update_cols++;

	status= subs.status;
	if(subs.event->get_auth_status(&subs)< 0)
	{
		LM_ERR( "getting status from rules document\n");
		return -1;
	}
	LM_DBG("subs.status= %d\n", subs.status);
	if(get_status_str(subs.status)== NULL)
	{
		LM_ERR("wrong status: %d\n", subs.status);
		return -1;
	}

	if(subs.status!= status || reason.len!= subs.reason.len ||
		(reason.s && subs.reason.s && strncmp(reason.s, subs.reason.s,
											reason.len)))
	{
		/* update in watchers_table */
		query_vals[q_wuser_col].val.str_val= subs.from_user;
		query_vals[q_wdomain_col].val.str_val= subs.from_domain;

		update_vals[u_status_col].val.int_val= subs.status;
		update_vals[u_reason_col].val.str_val= subs.reason;

		if (pa_dbf.use_table(pa_db, &watchers_table) < 0)
		{
			LM_ERR( "in use_table\n");
			return -1;
		}

		/* if status is terminated and reason="deactivated",
		 * delete the record from table */
		if(subs.status == TERMINATED_STATUS && subs.reason.len==11 &&
				strncmp(subs.reason.s, "deactivated", 11)==0)
		{
			CON_PS_REFERENCE(pa_db) = &my_del_ps;
			if(pa_dbf.delete(pa_db, query_cols, 0, query_vals, n_query_cols)<0)
			{
				LM_ERR( "in sql delete\n");
				return -1;
			}
		}
		else
		{
			CON_PS_REFERENCE(pa_db) = &my_upd_ps;
			if(pa_dbf.update(pa_db, query_cols, 0, query_vals, update_cols,
						update_vals, n_query_cols, n_update_cols)< 0)
			{
				LM_ERR( "in sql update\n");
				return -1;
			}
		}

		/* save in the list all affected dialogs */
		/* if status switches to terminated -> delete dialog */
		if(update_pw_dialogs(&subs, subs.db_flag, subs_array)< 0)
		{
			LM_ERR( "extracting dialogs from [watcher]=%.*s@%.*s to"
				" [presentity]=%.*s\n",	subs.from_user.len, subs.from_user.s,
				subs.from_domain.len, subs.from_domain.s, subs.pres_uri.len,
				subs.pres_uri.s);
			return -1;
		}
	}
    return 0;
}

int pres_db_delete_status(subs_t* s)
{
	static db_ps_t my_ps = NULL;
	int n_query_cols= 0;
	db_key_t query_cols[5];
	db_val_t query_vals[5];

	if (pa_dbf.use_table(pa_db, &active_watchers_table) < 0)
	{
		LM_ERR("sql use table failed\n");
		return -1;
	}

	query_cols[n_query_cols]= &str_event_col;
	query_vals[n_query_cols].nul= 0;
	query_vals[n_query_cols].type= DB_STR;
	query_vals[n_query_cols].val.str_val= s->event->name ;
	n_query_cols++;

	query_cols[n_query_cols]= &str_presentity_uri_col;
	query_vals[n_query_cols].nul= 0;
	query_vals[n_query_cols].type= DB_STR;
	query_vals[n_query_cols].val.str_val= s->pres_uri;
	n_query_cols++;

	query_cols[n_query_cols]= &str_watcher_username_col;
	query_vals[n_query_cols].nul= 0;
	query_vals[n_query_cols].type= DB_STR;
	query_vals[n_query_cols].val.str_val= s->from_user;
	n_query_cols++;

	query_cols[n_query_cols]= &str_watcher_domain_col;
	query_vals[n_query_cols].nul= 0;
	query_vals[n_query_cols].type= DB_STR;
	query_vals[n_query_cols].val.str_val= s->from_domain;
	n_query_cols++;

	CON_PS_REFERENCE(pa_db) = &my_ps;

	if(pa_dbf.delete(pa_db, query_cols, 0, query_vals, n_query_cols)< 0)
	{
		LM_ERR("sql delete failed\n");
		return -1;
	}
	return 0;
}


int terminate_watchers(str *pres_uri, pres_ev_t* ev)
{
	subs_t *all_s;
	subs_t *s;
	subs_t *tmp;

	/* get all watchers for the presentity */
	all_s = get_subs_dialog( pres_uri, ev, NULL);
	if ( all_s==NULL ) {
		LM_DBG("No subscription dialogs found for <%.*s>\n",
			pres_uri->len, pres_uri->s);
		return 0;
	}
	/* set expire on 0 for all watchers */
	for( s=all_s ; s ; ) {
		s->expires = 0;
		tmp = s;
		s = s->next;
		/* update subscription */
		update_subscription( NULL, tmp, 0);
	}

	free_subs_list( all_s, PKG_MEM_TYPE, 0);

	return 0;
}


int update_watchers_status(str pres_uri, pres_ev_t* ev, str* rules_doc)
{
//	static db_ps_t my_ps = NULL;
	subs_t subs;
	db_key_t query_cols[6], result_cols[5];
	db_val_t query_vals[6];
	int n_result_cols= 0, n_query_cols = 0;
	db_res_t* result= NULL;
	db_row_t *row;
	db_val_t *row_vals ;
	int i;
	str w_user, w_domain, reason= {0, 0};
	unsigned int status;
	int status_col, w_user_col, w_domain_col, reason_col;
	subs_t* subs_array= NULL,* s;
	unsigned int hash_code;
	int err_ret= -1;
	int n= 0;
	watcher_t *watchers = NULL;

	typedef struct ws
	{
		int status;
		str reason;
		str w_user;
		str w_domain;
	}ws_t;
	ws_t* ws_list= NULL;

    LM_DBG("start\n");

	if(ev->content_type.s== NULL)
	{
		ev= contains_event(&ev->name, NULL);
		if(ev== NULL)
		{
			LM_ERR("wrong event parameter\n");
			return 0;
		}
	}

	subs.pres_uri= pres_uri;
	subs.event= ev;
	subs.auth_rules_doc= rules_doc;

	/* update in watchers_table */
	query_cols[n_query_cols]= &str_presentity_uri_col;
	query_vals[n_query_cols].nul= 0;
	query_vals[n_query_cols].type= DB_STR;
	query_vals[n_query_cols].val.str_val= pres_uri;
	n_query_cols++;

	query_cols[n_query_cols]= &str_event_col;
	query_vals[n_query_cols].nul= 0;
	query_vals[n_query_cols].type= DB_STR;
	query_vals[n_query_cols].val.str_val= ev->name;
	n_query_cols++;

	result_cols[status_col= n_result_cols++]= &str_status_col;
	result_cols[reason_col= n_result_cols++]= &str_reason_col;
	result_cols[w_user_col= n_result_cols++]= &str_watcher_username_col;
	result_cols[w_domain_col= n_result_cols++]= &str_watcher_domain_col;

	if (pa_dbf.use_table(pa_db, &watchers_table) < 0)
	{
		LM_ERR( "in use_table\n");
		goto done;
	}

//	CON_PS_REFERENCE(pa_db) = &my_ps;
	if(pa_dbf.query(pa_db, query_cols, 0, query_vals, result_cols,n_query_cols,
				n_result_cols, 0, &result)< 0)
	{
		LM_ERR( "in sql query\n");
		goto done;
	}
	if(result== NULL)
		return 0;

	if(result->n<= 0)
	{
		err_ret= 0;
		goto done;
	}

    LM_DBG("found %d record-uri in watchers_table\n", result->n);
	hash_code= core_hash(&pres_uri, &ev->name, shtable_size);
	subs.db_flag= hash_code;

    /*must do a copy as sphere_check requires database queries */
	if(sphere_enable)
	{
        n= result->n;
		ws_list= (ws_t*)pkg_malloc(n * sizeof(ws_t));
		if(ws_list== NULL)
		{
			LM_ERR("No more private memory\n");
			goto done;
		}
		memset(ws_list, 0, n * sizeof(ws_t));

		for(i= 0; i< result->n ; i++)
		{
			row= &result->rows[i];
			row_vals = ROW_VALUES(row);

			status= row_vals[status_col].val.int_val;

			reason.s= (char*)row_vals[reason_col].val.string_val;
			reason.len= reason.s?strlen(reason.s):0;

			w_user.s= (char*)row_vals[w_user_col].val.string_val;
			w_user.len= strlen(w_user.s);

			w_domain.s= (char*)row_vals[w_domain_col].val.string_val;
			w_domain.len= strlen(w_domain.s);

			if(reason.len)
			{
				ws_list[i].reason.s = (char*)pkg_malloc(reason.len);
				if(ws_list[i].reason.s== NULL)
				{
					LM_ERR("No more private memory\n");
					goto done;
				}
				memcpy(ws_list[i].reason.s, reason.s, reason.len);
				ws_list[i].reason.len= reason.len;
			}
			else
				ws_list[i].reason.s= NULL;

			ws_list[i].w_user.s = (char*)pkg_malloc(w_user.len);
			if(ws_list[i].w_user.s== NULL)
			{
				LM_ERR("No more private memory\n");
				goto done;

			}
			memcpy(ws_list[i].w_user.s, w_user.s, w_user.len);
			ws_list[i].w_user.len= w_user.len;

			 ws_list[i].w_domain.s = (char*)pkg_malloc(w_domain.len);
			if(ws_list[i].w_domain.s== NULL)
			{
				LM_ERR("No more private memory\n");
				goto done;
			}
			memcpy(ws_list[i].w_domain.s, w_domain.s, w_domain.len);
			ws_list[i].w_domain.len= w_domain.len;

			ws_list[i].status= status;
		}

		pa_dbf.free_result(pa_db, result);
		result= NULL;

		for(i=0; i< n; i++)
		{
			subs.from_user = ws_list[i].w_user;
			subs.from_domain = ws_list[i].w_domain;
			subs.status = ws_list[i].status;
			memset(&subs.reason, 0, sizeof(str));

			if( pres_update_status(subs, reason, query_cols, query_vals,
					n_query_cols, &subs_array)< 0)
			{
				LM_ERR("failed to update watcher status\n");
				goto done;
			}

		}

		for(i=0; i< n; i++)
		{
			pkg_free(ws_list[i].w_user.s);
			pkg_free(ws_list[i].w_domain.s);
			if(ws_list[i].reason.s)
				pkg_free(ws_list[i].reason.s);
		}
		ws_list= NULL;

		goto send_notify;

	}

	for(i = 0; i< result->n; i++)
	{
		row= &result->rows[i];
		row_vals = ROW_VALUES(row);

		status= row_vals[status_col].val.int_val;

		reason.s= (char*)row_vals[reason_col].val.string_val;
		reason.len= reason.s?strlen(reason.s):0;

		w_user.s= (char*)row_vals[w_user_col].val.string_val;
		w_user.len= strlen(w_user.s);

		w_domain.s= (char*)row_vals[w_domain_col].val.string_val;
		w_domain.len= strlen(w_domain.s);

		subs.from_user= w_user;
		subs.from_domain= w_domain;
		subs.status= status;
		memset(&subs.reason, 0, sizeof(str));

 		if( pres_update_status(subs,reason, query_cols, query_vals,
					n_query_cols, &subs_array)< 0)
		{
			LM_ERR("failed to update watcher status\n");
			goto done;
		}
    }

	pa_dbf.free_result(pa_db, result);
	result= NULL;

send_notify:

	s= subs_array;

	watchers= (watcher_t*)pkg_malloc(sizeof(watcher_t));
	if(watchers== NULL)
	{
		LM_ERR("no more pkg memory\n");
		goto done;
	}
	memset(watchers, 0, sizeof(watcher_t));


	while(s)
	{

		if(notify(s, NULL, NULL, 0, NULL, 0)< 0)
		{
			LM_ERR( "sending Notify request\n");
			goto done;
		}

		/* delete from database also */
		if(s->status== TERMINATED_STATUS)
		{
			if(pres_db_delete_status(s)<0)
			{
				err_ret= -1;
				LM_ERR("failed to delete terminated dialog from database\n");
				goto done;
			}
		}
		if(add_watcher_list(s, watchers)< 0)
		{
			LM_ERR("failed to add watcher to list\n");
			continue;
		}
        s= s->next;
	}

	if( refresh_send_winfo_notify(watchers, pres_uri, ev->wipeer) < 0)
	{
		LM_ERR("failed to send Notify for winfo\n");
		goto done;
	}
	free_watcher_list(watchers);
	free_subs_list(subs_array, PKG_MEM_TYPE, 0);
	return 0;

done:
	if(result)
		pa_dbf.free_result(pa_db, result);
	free_subs_list(subs_array, PKG_MEM_TYPE, 0);
	if(ws_list)
	{
		for(i= 0; i< n; i++)
		{
			if(ws_list[i].w_user.s)
				pkg_free(ws_list[i].w_user.s);
			else
				break;
			if(ws_list[i].w_domain.s)
				pkg_free(ws_list[i].w_domain.s);
			if(ws_list[i].reason.s)
				pkg_free(ws_list[i].reason.s);
		}
	}

	free_watcher_list(watchers);

	return err_ret;
}


int refresh_send_winfo_notify(watcher_t* watchers, str pres_uri,
		struct pres_ev* ev)
{
	subs_t* subs_array= NULL, *s;
	str* winfo_nbody= NULL;
	char version[12];

	/* send Notify for watcher info */
	if(watchers->next== NULL)
		return 0;

	subs_array= get_subs_dialog(&pres_uri, ev, NULL);
	if(subs_array == NULL)
	{
		LM_DBG("Could not get subscription dialog\n");
		return 0;
	}

	s= subs_array;

	while(s)
	{
		/* extract notify body */
		sprintf(version, "%d", s->version);
		winfo_nbody =  create_winfo_xml(watchers, version, pres_uri,
			ev->wipeer->name, PARTIAL_STATE_FLAG);
		if(winfo_nbody== NULL)
		{
			LM_ERR("failed to create winfo Notify body\n");
			goto error;
		}

		if(notify(s, NULL, winfo_nbody, 0, NULL, 0)< 0 )
		{
			LM_ERR("Could not send notify for [event]=%.*s\n",
				s->event->name.len, s->event->name.s);
			goto error;
		}

		s = s->next;
	}
	xmlFree(winfo_nbody->s);
	pkg_free(winfo_nbody);

	return 0;

error:
	if(winfo_nbody)
	{
		if(winfo_nbody->s)
			xmlFree(winfo_nbody->s);
		pkg_free(winfo_nbody);
	}
	return -1;
}

static int update_pw_dialogs(subs_t* subs, unsigned int hash_code, subs_t** subs_array)
{
	subs_t* s, *ps, *cs;
	int i= 0;

    LM_DBG("start\n");
	lock_get(&subs_htable[hash_code].lock);

    ps= subs_htable[hash_code].entries;

	while(ps && ps->next)
	{
		s= ps->next;

		if(s->event== subs->event && s->pres_uri.len== subs->pres_uri.len &&
			s->from_user.len== subs->from_user.len &&
			s->from_domain.len==subs->from_domain.len &&
			strncmp(s->pres_uri.s, subs->pres_uri.s, subs->pres_uri.len)== 0 &&
			strncmp(s->from_user.s, subs->from_user.s, s->from_user.len)== 0 &&
			strncmp(s->from_domain.s,subs->from_domain.s,s->from_domain.len)==0)
		{
			i++;
			s->status= subs->status;
			s->reason= subs->reason;
			s->db_flag= UPDATEDB_FLAG;

			cs= mem_copy_subs(s, PKG_MEM_TYPE);
			if(cs== NULL)
			{
				LM_ERR( "copying subs_t structure\n");
                lock_release(&subs_htable[hash_code].lock);
                return -1;
			}
			cs->expires-= (int)time(NULL);
			cs->next= (*subs_array);
			(*subs_array)= cs;
			if(subs->status== TERMINATED_STATUS)
			{
				ps->next= s->next;
				shm_free(s->contact.s);
				shm_free(s);
				LM_DBG(" deleted terminated dialog from hash table\n");
				/* delete from database also */
				if( delete_db_subs(cs->pres_uri,
							cs->event->name, cs->to_tag)< 0)
				{
					LM_ERR("deleting subscription record from database\n");
					lock_release(&subs_htable[hash_code].lock);
					pkg_free(cs);
					return -1;
				}

			}
			else
				ps= s;


			printf_subs(cs);
		}
		else
			ps= s;
	}

    LM_DBG("found %d matching dialogs\n", i);
    lock_release(&subs_htable[hash_code].lock);

    return 0;
}

static struct mi_root* mi_pres_expose(struct mi_root* cmd, void* param)
{
	struct mi_node* node= NULL;
	str event, *pres_fn;
	pres_ev_t* ev;

	node = cmd->node.kids;
	if(node == NULL)
		return init_mi_tree(404, "No parameters", 13);

	event = node->value;
	if (event.s == NULL || event.len == 0)
		return init_mi_tree(404, "Invalid event", 13);

	ev = contains_event(&event, NULL);
	if (!ev)
		return init_mi_tree(404, "unknown event", 13);

	if (node->next && node->next->value.s != NULL && node->next->value.len)
		pres_fn = &node->next->value;
	else
		pres_fn = NULL;

	if (pres_expose_evi(ev, pres_fn) < 0)
		return NULL;

	return init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
}
