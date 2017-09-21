/*
 * Usrloc module interface
 *
 * Copyright (C) 2001-2003 FhG Fokus
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
 * ---------
 * 2003-01-27 timer activity printing #ifdef-ed to EXTRA_DEBUG (jiri)
 * 2003-03-11 New module interface (janakj)
 * 2003-03-12 added replication and state columns (nils)
 * 2003-03-16 flags export parameter added (janakj)
 * 2003-04-05: default_uri #define used (jiri)
 * 2003-04-21 failed fifo init stops init process (jiri)
 * 2004-03-17 generic callbacks added (bogdan)
 * 2004-06-07 updated to the new DB api (andrei)
 */

/*! \file
 *  \brief USRLOC - Usrloc module interface
 *  \ingroup usrloc
 */

/*! \defgroup usrloc User location module
	\brief The module keeps a user location table
   	and provides access to the table to other modules. The module
   	exports no functions that could be used directly from scripts.
 */

#include <stdio.h>
#include "../../sr_module.h"
#include "ul_mod.h"
#include "../../rw_locking.h"
#include "../../dprint.h"
#include "../../timer.h"     /* register_timer */
#include "../../globals.h"   /* is_main */
#include "../../ut.h"        /* str_init */
#include "dlist.h"           /* register_udomain */
#include "udomain.h"         /* {insert,delete,get,release}_urecord */
#include "urecord.h"         /* {insert,delete,get}_ucontact */
#include "ucontact.h"        /* update_ucontact */
#include "ureplication.h"
#include "ul_mi.h"
#include "ul_callback.h"
#include "usrloc.h"


#define USER_COL       "username"
#define DOMAIN_COL     "domain"
#define CONTACT_COL    "contact"
#define EXPIRES_COL    "expires"
#define Q_COL          "q"
#define CALLID_COL     "callid"
#define CSEQ_COL       "cseq"
#define FLAGS_COL      "flags"
#define CFLAGS_COL     "cflags"
#define USER_AGENT_COL "user_agent"
#define RECEIVED_COL   "received"
#define PATH_COL       "path"
#define SOCK_COL       "socket"
#define METHODS_COL    "methods"
#define ATTR_COL       "attr"
#define LAST_MOD_COL   "last_modified"
#define SIP_INSTANCE_COL   "sip_instance"
#define CONTACTID_COL  "contact_id"

static int mod_init(void);                          /*!< Module initialization function */
static void destroy(void);                          /*!< Module destroy function */
static void timer(unsigned int ticks, void* param); /*!< Timer handler */
static int child_init(int rank);                    /*!< Per-child init function */
static int mi_child_init(void);

//static int add_replication_dest(modparam_t type, void *val);

extern int bind_usrloc(usrloc_api_t* api);
extern int ul_locks_no;
extern rw_lock_t *sync_lock;
extern int skip_replicated_db_ops;

int max_contact_delete=10;
db_key_t *cid_keys=NULL;
db_val_t *cid_vals=NULL;

int cid_regen=0;



/*
 * Module parameters and their default values
 */

str user_col        = str_init(USER_COL); 		/*!< Name of column containing usernames */
str domain_col      = str_init(DOMAIN_COL); 		/*!< Name of column containing domains */
str contact_col     = str_init(CONTACT_COL);		/*!< Name of column containing contact addresses */
str expires_col     = str_init(EXPIRES_COL);		/*!< Name of column containing expires values */
str q_col           = str_init(Q_COL);			/*!< Name of column containing q values */
str callid_col      = str_init(CALLID_COL);		/*!< Name of column containing callid string */
str cseq_col        = str_init(CSEQ_COL);		/*!< Name of column containing cseq values */
str flags_col       = str_init(FLAGS_COL);		/*!< Name of column containing internal flags */
str cflags_col      = str_init(CFLAGS_COL);		/*!< Name of column containing contact flags */
str user_agent_col  = str_init(USER_AGENT_COL);		/*!< Name of column containing user agent string */
str received_col    = str_init(RECEIVED_COL);		/*!< Name of column containing transport info of REGISTER */
str path_col        = str_init(PATH_COL);		/*!< Name of column containing the Path header */
str sock_col        = str_init(SOCK_COL);		/*!< Name of column containing the received socket */
str methods_col     = str_init(METHODS_COL);		/*!< Name of column containing the supported methods */
str last_mod_col    = str_init(LAST_MOD_COL);		/*!< Name of column containing the last modified date */
str attr_col        = str_init(ATTR_COL);		/*!< Name of column containing additional info */
str sip_instance_col = str_init(SIP_INSTANCE_COL);
str contactid_col   = str_init(CONTACTID_COL);
str db_url          = {NULL, 0};					/*!< Database URL */
int timer_interval  = 60;				/*!< Timer interval in seconds */
enum usrloc_modes db_mode = NO_DB;		/*!< Database sync scheme */
int use_domain      = 0;				/*!< Whether usrloc should use domain part of aor */
int desc_time_order = 0;				/*!< By default do not enable timestamp ordering */

int ul_hash_size = 9;

/* flag */
unsigned int nat_bflag = (unsigned int)-1;
static char *nat_bflag_str = 0;
unsigned int init_flag = 0;

/* usrloc data replication using the bin interface */
int accept_replicated_udata = 0;
int ul_replicate_cluster = 0;
int ul_repl_auth_check = 0;

db_con_t* ul_dbh = 0; /* Database connection handle */
db_func_t ul_dbf;


/*! \brief
 * Exported functions
 */
static cmd_export_t cmds[] = {
	{"ul_bind_usrloc",        (cmd_function)bind_usrloc,        1, 0, 0, 0},
	{0, 0, 0, 0, 0, 0}
};


/*! \brief
 * Exported parameters
 */
static param_export_t params[] = {
	{"contactid_column",   STR_PARAM, &contactid_col.s   },
	{"user_column",        STR_PARAM, &user_col.s        },
	{"domain_column",      STR_PARAM, &domain_col.s      },
	{"contact_column",     STR_PARAM, &contact_col.s     },
	{"expires_column",     STR_PARAM, &expires_col.s     },
	{"q_column",           STR_PARAM, &q_col.s           },
	{"callid_column",      STR_PARAM, &callid_col.s      },
	{"cseq_column",        STR_PARAM, &cseq_col.s        },
	{"flags_column",       STR_PARAM, &flags_col.s       },
	{"cflags_column",      STR_PARAM, &cflags_col.s      },
	{"db_url",             STR_PARAM, &db_url.s          },
	{"timer_interval",     INT_PARAM, &timer_interval    },
	{"db_mode",            INT_PARAM, &db_mode           },
	{"use_domain",         INT_PARAM, &use_domain        },
	{"desc_time_order",    INT_PARAM, &desc_time_order   },
	{"user_agent_column",  STR_PARAM, &user_agent_col.s  },
	{"received_column",    STR_PARAM, &received_col.s    },
	{"path_column",        STR_PARAM, &path_col.s        },
	{"socket_column",      STR_PARAM, &sock_col.s        },
	{"methods_column",     STR_PARAM, &methods_col.s     },
	{"sip_instance_column",STR_PARAM, &sip_instance_col.s},
	{"attr_column",        STR_PARAM, &attr_col.s        },
	{"matching_mode",      INT_PARAM, &matching_mode     },
	{"cseq_delay",         INT_PARAM, &cseq_delay        },
	{"hash_size",          INT_PARAM, &ul_hash_size      },
	{"nat_bflag",          STR_PARAM, &nat_bflag_str     },
	{"nat_bflag",          INT_PARAM, &nat_bflag         },
    /* data replication through clusterer using TCP binary packets */
	{ "accept_replicated_contacts",INT_PARAM, &accept_replicated_udata },
	{ "replicate_contacts_to",	INT_PARAM, &ul_replicate_cluster   },
	{ "repl_auth_check",		INT_PARAM, &ul_repl_auth_check	   },
	{ "skip_replicated_db_ops", INT_PARAM, &skip_replicated_db_ops     },
	{ "max_contact_delete", INT_PARAM, &max_contact_delete },
	{ "regen_broken_contactid", INT_PARAM, &cid_regen},
	{0, 0, 0}
};


static stat_export_t mod_stats[] = {
	{"registered_users" ,  STAT_IS_FUNC, (stat_var**)get_number_of_users  },
	{0,0,0}
};


static mi_export_t mi_cmds[] = {
	{ MI_USRLOC_RM,           0, mi_usrloc_rm_aor,       0,                 0,
				mi_child_init },
	{ MI_USRLOC_RM_CONTACT,   0, mi_usrloc_rm_contact,   0,                 0,
				mi_child_init },
	{ MI_USRLOC_DUMP,         0, mi_usrloc_dump,         0,                 0,
				0             },
	{ MI_USRLOC_FLUSH,        0, mi_usrloc_flush,        MI_NO_INPUT_FLAG,  0,
				mi_child_init },
	{ MI_USRLOC_ADD,          0, mi_usrloc_add,          0,                 0,
				mi_child_init },
	{ MI_USRLOC_SHOW_CONTACT, 0, mi_usrloc_show_contact, 0,                 0,
				mi_child_init },
	{ MI_USRLOC_SYNC,         0, mi_usrloc_sync,         0,                 0,
				mi_child_init },
	{ 0, 0, 0, 0, 0, 0}
};

static module_dependency_t *get_deps_db_mode(param_export_t *param)
{
	if (*(int *)param->param_pointer == NO_DB)
		return NULL;

	return alloc_module_dep(MOD_TYPE_SQLDB, NULL, DEP_ABORT);
}

static module_dependency_t *get_deps_clusterer(param_export_t *param)
{
	int cluster_id = *(int *)param->param_pointer;

	if (cluster_id <= 0)
		return NULL;

	return alloc_module_dep(MOD_TYPE_DEFAULT, "clusterer", DEP_ABORT);
}

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ "db_mode",			get_deps_db_mode	},
		{ "accept_replicated_contacts",	get_deps_clusterer	},
		{ "replicate_contacts_to",	get_deps_clusterer	},
		{ NULL, NULL },
	},
};

struct module_exports exports = {
	"usrloc",
	MOD_TYPE_DEFAULT,/*!< class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /*!< dlopen flags */
	&deps,           /*!< OpenSIPS module dependencies */
	cmds,       /*!< Exported functions */
	0,          /*!< Exported async functions */
	params,     /*!< Export parameters */
	mod_stats,  /*!< exported statistics */
	mi_cmds,    /*!< exported MI functions */
	0,          /*!< exported pseudo-variables */
	0,          /*!< exported transformations */
	0,          /*!< extra processes */
	mod_init,   /*!< Module initialization function */
	0,          /*!< Response function */
	destroy,    /*!< Destroy function */
	child_init  /*!< Child initialization function */
};


/*! \brief
 * Module initialization function
 */
static int mod_init(void)
{
	int idx;

	LM_DBG("initializing\n");

	/* Compute the lengths of string parameters */
	init_db_url( db_url , 1 /*can be null*/);
	contactid_col.len = strlen(contactid_col.s);
	user_col.len = strlen(user_col.s);
	domain_col.len = strlen(domain_col.s);
	contact_col.len = strlen(contact_col.s);
	expires_col.len = strlen(expires_col.s);
	q_col.len = strlen(q_col.s);
	callid_col.len = strlen(callid_col.s);
	cseq_col.len = strlen(cseq_col.s);
	flags_col.len = strlen(flags_col.s);
	cflags_col.len = strlen(cflags_col.s);
	user_agent_col.len = strlen(user_agent_col.s);
	received_col.len = strlen(received_col.s);
	path_col.len = strlen(path_col.s);
	sock_col.len = strlen(sock_col.s);
	methods_col.len = strlen(methods_col.s);
	sip_instance_col.len = strlen(sip_instance_col.s);
	attr_col.len = strlen(attr_col.s);
	last_mod_col.len = strlen(last_mod_col.s);

	if (ul_hash_size > 16) {
		LM_WARN("hash too big! max 2 ^ 16\n");
		return -1;
	}

	if(ul_hash_size<=1)
		ul_hash_size = 512;
	else
		ul_hash_size = 1<<ul_hash_size;
	ul_locks_no = ul_hash_size;

	if (db_mode != NO_DB) {
		cid_keys = pkg_malloc(max_contact_delete *
				(sizeof(db_key_t) * sizeof(db_val_t)));
		if (cid_keys == NULL) {
			LM_ERR("no more pkg memory\n");
			return -1;
		}

		cid_vals = (db_val_t *)(cid_keys + max_contact_delete);
		for (idx=0; idx < max_contact_delete; idx++) {
			VAL_TYPE(cid_vals+idx) = DB_BIGINT;
			VAL_NULL(cid_vals+idx) = 0;
			cid_keys[idx] = &contactid_col;
		}
	}

	/* check matching mode */
	switch (matching_mode) {
		case CONTACT_ONLY:
		case CONTACT_CALLID:
			break;
		default:
			LM_ERR("invalid matching mode %d\n", matching_mode);
	}

	if(ul_init_locks()!=0)
	{
		LM_ERR("locks array initialization failed\n");
		return -1;
	}

	/* Register cache timer */
	register_timer( "ul-timer", timer, 0, timer_interval,
		TIMER_FLAG_DELAY_ON_DELAY);

	/* init the callbacks list */
	if ( init_ulcb_list() < 0) {
		LM_ERR("usrloc/callbacks initialization failed\n");
		return -1;
	}

	/* Shall we use database ? */
	if (db_mode != NO_DB) { /* Yes */
		if (db_url.s==NULL || db_url.len==0) {
			LM_ERR("selected db_mode requires a db connection -> db_url \n");
			return -1;
		}
		if (db_bind_mod(&db_url, &ul_dbf) < 0) { /* Find database module */
			LM_ERR("failed to bind database module\n");
			return -1;
		}
		if (!DB_CAPABILITY(ul_dbf, DB_CAP_ALL)) {
			LM_ERR("database module does not implement all functions"
					" needed by the module\n");
			return -1;
		}
		if (db_mode != DB_ONLY && (sync_lock = lock_init_rw()) == NULL) {
			LM_ERR("cannot init rw lock\n");
			return -1;
		}
	}

	fix_flag_name(nat_bflag_str, nat_bflag);

	nat_bflag = get_flag_id_by_name(FLAG_TYPE_BRANCH, nat_bflag_str);

	if (nat_bflag==(unsigned int)-1) {
		nat_bflag = 0;
	} else if ( nat_bflag>=8*sizeof(nat_bflag) ) {
		LM_ERR("bflag index (%d) too big!\n", nat_bflag);
		return -1;
	} else {
		nat_bflag = 1<<nat_bflag;
	}

	if (ul_event_init() < 0) {
		LM_ERR("cannot initialize USRLOC events\n");
		return -1;
	}

	if (ul_replicate_cluster < 0) {
		LM_ERR("Invalid ul_replicate_cluster, must be 0 or "
			"a positive cluster id\n");
		return -1;
	}

	if( (ul_replicate_cluster > 0 || accept_replicated_udata > 0)
		&& load_clusterer_api(&clusterer_api)!=0){
		LM_DBG("failed to find clusterer API - is clusterer module loaded?\n");
		return -1;
	}

	if (ul_repl_auth_check < 0) {
		LM_ERR("Invalid value for ul_repl_auth_check, must be 0 or 1\n");
		return -1;	
	}

	/* register handler for processing usrloc packets to the clusterer module */
	if (accept_replicated_udata > 0 && clusterer_api.register_module(repl_module_name.s,
		receive_binary_packet, ul_repl_auth_check, &accept_replicated_udata, 1) < 0) {
		LM_ERR("cannot register binary packet callback to clusterer module!\n");
		return -1;
	}

	init_flag = 1;

	return 0;
}


static int child_init(int _rank)
{
	dlist_t* ptr;

	/* connecting to DB ? */
	switch (db_mode) {
		case NO_DB:
			return 0;
		case DB_ONLY:
		case WRITE_THROUGH:
		case WRITE_BACK:
			/* we need connection from SIP workers, BIN and MAIN procs */
			if (_rank < PROC_MAIN && _rank != PROC_BIN )
				return 0;
			break;
	}

	ul_dbh = ul_dbf.init(&db_url); /* Get a new database connection */
	if (!ul_dbh) {
		LM_ERR("child(%d): failed to connect to database\n", _rank);
		return -1;
	}
	/* _rank==1 is used even when fork is disabled */
	if (_rank==1 && db_mode!= DB_ONLY) {
		/* if cache is used, populate domains from DB */
		for( ptr=root ; ptr ; ptr=ptr->next) {
			if (preload_udomain(ul_dbh, ptr->d) < 0) {
				LM_ERR("child(%d): failed to preload domain '%.*s'\n",
						_rank, ptr->name.len, ZSW(ptr->name.s));
				return -1;
			}
		}
	}

	return 0;
}


/* */
static int mi_child_init(void)
{
	static int done = 0;

	if (done)
		return 0;

	if (db_mode != NO_DB) {
		ul_dbh = ul_dbf.init(&db_url);
		if (!ul_dbh) {
			LM_ERR("failed to connect to database\n");
			return -1;
		}
	}
	done = 1;

	return 0;
}


/*! \brief
 * Module destroy function
 */
static void destroy(void)
{
	/* we need to sync DB in order to flush the cache */
	if (ul_dbh) {
		ul_unlock_locks();
		if (sync_lock)
			lock_start_read(sync_lock);
		if (synchronize_all_udomains() != 0) {
			LM_ERR("flushing cache failed\n");
		}
		if (sync_lock) {
			lock_stop_read(sync_lock);
			lock_destroy_rw(sync_lock);
			sync_lock = 0;
		}
		ul_dbf.close(ul_dbh);
	}

	free_all_udomains();
	ul_destroy_locks();

	/* free callbacks list */
	destroy_ulcb_list();
}


/*! \brief
 * Timer handler
 */
static void timer(unsigned int ticks, void* param)
{
	if (sync_lock)
		lock_start_read(sync_lock);
	if (synchronize_all_udomains() != 0) {
		LM_ERR("synchronizing cache failed\n");
	}
	if (sync_lock)
		lock_stop_read(sync_lock);
}
