/*
 * $Id$
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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
#include "../../socket_info.h" /* udp_listen and friends */
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

static int mod_init(void);                          /*!< Module initialization function */
static void destroy(void);                          /*!< Module destroy function */
static void timer(unsigned int ticks, void* param); /*!< Timer handler */
static int child_init(int rank);                    /*!< Per-child init function */
static int mi_child_init(void);

static int add_replication_dest(modparam_t type, void *val);

static void init_sockaddr_list_str(void);
static void free_sockaddr_list_str(void);

extern int bind_usrloc(usrloc_api_t* api);
extern int ul_locks_no;
extern rw_lock_t *sync_lock;
extern int skip_replicated_db_ops; 

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
str db_url          = {NULL, 0};					/*!< Database URL */
str sockaddr_list_str = {NULL, 0};
int timer_interval  = 60;				/*!< Timer interval in seconds */
int db_mode         = 0;				/*!< Database sync scheme: 0-no db, 1-write through, 2-write back, 3-only db */
int use_domain      = 0;				/*!< Whether usrloc should use domain part of aor */
int desc_time_order = 0;				/*!< By default do not enable timestamp ordering */

int ul_hash_size = 9;

/* flag */
unsigned int nat_bflag = (unsigned int)-1;
static char *nat_bflag_str = 0;
unsigned int init_flag = 0;

/* usrloc data replication using the bin interface */
int accept_replicated_udata;
struct replication_dest *replication_dests;

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
    /* data replication through UDP binary packets */
	{ "accept_replicated_contacts",INT_PARAM, &accept_replicated_udata },
	{ "replicate_contacts_to",     STR_PARAM|USE_FUNC_PARAM,
	                            (void *)add_replication_dest           },
	{ "skip_replicated_db_ops", INT_PARAM, &skip_replicated_db_ops     },
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


struct module_exports exports = {
	"usrloc",
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /*!< dlopen flags */
	cmds,       /*!< Exported functions */
	params,     /*!< Export parameters */
	mod_stats,  /*!< exported statistics */
	mi_cmds,    /*!< exported MI functions */
	0,          /*!< exported pseudo-variables */
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
	LM_DBG("initializing\n");

	/* Compute the lengths of string parameters */
	init_db_url( db_url , 1 /*can be null*/);
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

	if(ul_hash_size<=1)
		ul_hash_size = 512;
	else
		ul_hash_size = 1<<ul_hash_size;
	ul_locks_no = ul_hash_size;

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
	register_timer( "ul-timer", timer, 0, timer_interval);

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

	init_sockaddr_list_str();

	fix_flag_name(&nat_bflag_str, nat_bflag);
	
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

	/* register handler for processing usrloc packets from the bin interface */
	if (accept_replicated_udata &&
		bin_register_cb(repl_module_name.s, receive_binary_packet) < 0) {
		LM_ERR("cannot register binary packet callback!\n");
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
			/* we need connection from working SIP, BIN, TIMER and MAIN procs */
			if (_rank <= 0 && _rank != PROC_BIN &&
			    _rank != PROC_TIMER && _rank != PROC_MAIN)
				return 0;
			break;
		case WRITE_BACK:
			/* connect only from TIMER (for flush), from MAIN (for
			 * final flush() and from child 1 for preload */
			if (_rank!=PROC_TIMER && _rank!=PROC_MAIN && _rank!=1)
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
	free_sockaddr_list_str();

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

static int add_replication_dest(modparam_t type, void *val)
{
	struct replication_dest *rd;
	char *host;
	int hlen, port;
	int proto;
	struct hostent *he;
	str st;

	rd = pkg_malloc(sizeof *rd);
	memset(rd, 0, sizeof *rd);

	if (parse_phostport(val, strlen(val), &host, &hlen, &port, &proto) < 0) {
		LM_ERR("bad replication destination IP: '%s'!\n", (char *)val);
		return -1;
	}

	if (proto == PROTO_NONE)
		proto = PROTO_UDP;

	if (proto != PROTO_UDP) {
		LM_ERR("usrloc replication only supports UDP packets!\n");
		return -1;
	}

	st.s = host;
	st.len = hlen;
	he = sip_resolvehost(&st, (unsigned short *)&port,
	                          (unsigned short *)&proto, 0, 0);
	if (!he) {
		LM_ERR("cannot resolve host: %.*s\n", hlen, host);
		return -1;
	}

	hostent2su(&rd->to, he, 0, port);

	rd->next = replication_dests;
	replication_dests = rd;

	return 1;
}

/*! \brief
 * Initialize a list of listen addresses for use by the natping query
 */
static void init_sockaddr_list_str(void)
{
	struct socket_info *si;
	struct socket_info *lists[5];
	int lists_len = 0;
	int i;

	int addresses = 0;
	int buflen = 0;
	char *p;

	if (udp_listen)
		lists[lists_len++] = udp_listen;
#ifdef USE_TCP
	if (tcp_listen)
		lists[lists_len++] = tcp_listen;
#endif
#ifdef USE_TLS
	if (tls_listen)
		lists[lists_len++] = tls_listen;
#endif
#ifdef USE_SCTP
	if (sctp_listen)
		lists[lists_len++] = sctp_listen;
#endif

	for (i = 0; i < lists_len; ++i) {
		for (si = lists[i]; si; si = si->next) {
			buflen += si->sock_str.len;
			addresses++;
		}
	}
	buflen += 1 /*'*/ + 3 * (addresses - 1) /*','*/ + 2 /*'NUL*/;

	/* No addresses? */
	if (!addresses) {
		sockaddr_list_str.s = NULL;
		sockaddr_list_str.len = 0;
		return;
	}

	p = sockaddr_list_str.s = shm_malloc(buflen);
	if (!p) {
		LM_ERR("No memory for sockaddr_list_str.s\n");
		sockaddr_list_str.s = NULL;
		sockaddr_list_str.len = 0;
		return;
	}

	for (i = 0; i < lists_len; ++i) {
		for (si = lists[i]; si; si = si->next) {
			*p++ = '\'';
			memcpy(p, si->sock_str.s, si->sock_str.len);
			p += si->sock_str.len;
			*p++ = '\'';
			*p++ = ',';
		}
	}
	*--p = '\0';
	sockaddr_list_str.len = p - sockaddr_list_str.s;
}

static void free_sockaddr_list_str(void)
{
	shm_free(sockaddr_list_str.s);
	sockaddr_list_str.s = NULL;
	sockaddr_list_str.len = 0;
}
