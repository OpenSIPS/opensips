/**
 * dispatcher module
 *
 * Copyright (C) 2004-2006 FhG Fokus
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
 * History
 * -------
 * 2004-07-31  first version, by daniel
 * 2007-01-11  Added a function to check if a specific gateway is in
 *              a group (carsten)
 * 2007-02-09  Added active probing of failed destinations and automatic
 *              re-enabling of destinations
 * 2007-05-08  Ported the changes to SVN-Trunk and renamed ds_is_domain
 *              to ds_is_from_list.
 * 2009-05-18  Added support for weights for the destinations;
 *              added support for custom "attrs" (opaque string) (bogdan)
 * 2013-12-02  Added support state persistency (restart and reload) (bogdan)
 * 2013-12-05  Added a safer reload mechanism based on locking read/writter (bogdan)
 */

#ifndef _DISPATCH_H_
#define _DISPATCH_H_

#include <stdio.h>
#include "../../pvar.h"
#include "../../mod_fix.h"
#include "../../parser/msg_parser.h"
#include "../tm/tm_load.h"
#include "../freeswitch/fs_api.h"
#include "../../db/db.h"
#include "../../rw_locking.h"

#define DS_HASH_USER_ONLY	1  /* use only the uri user part for hashing */
#define DS_FAILOVER_ON		2  /* store the other dest in avps */
#define DS_USE_DEFAULT		4  /* use last address in destination set as last option */
#define DS_FORCE_DST		8  /* if not set it will force overwriting the destination address
					if already set */

#define DS_INACTIVE_DST		1  /* inactive destination */
#define DS_PROBING_DST		2  /* checking destination */
#define DS_RESET_FAIL_DST	4  /* Reset-Failure-Counter */
#define DS_STATE_DIRTY_DST	8  /* STATE is dirty */

#define DS_PV_ALGO_MARKER	"%u"	/* Marker to indicate where the URI should
									   be inserted in the pvar */
#define DS_PV_ALGO_MARKER_LEN (sizeof(DS_PV_ALGO_MARKER) - 1)

#define DS_MAX_IPS  32

#define DS_COUNT_ACTIVE     1
#define DS_COUNT_INACTIVE   2
#define DS_COUNT_PROBING    4

#define DS_PARTITION_DELIM ':'
#define DS_DEFAULT_PARTITION_NAME "default"

#define MI_FULL_LISTING (1<<0)


extern int ds_persistent_state;

typedef struct _ds_dest
{
	str uri;
	str dst_uri;    /* Actual uri used in ds_select_dst ds_select_domain */
	str attrs;
	str description;
	int flags;
	unsigned short weight;    /* dynamic weight - may change at runtime */
	unsigned short rr_count; /* times it was chosen in a row for weighted round-robin */
	unsigned short running_weight;
	unsigned short active_running_weight;
	unsigned short priority;
	struct socket_info *sock;
	struct ip_addr ips[DS_MAX_IPS]; /* IP-Address of the entry */
	unsigned short int ports[DS_MAX_IPS]; /* Port of the request URI */
	unsigned short int protos[DS_MAX_IPS]; /* Protocol of the request URI */
	unsigned short ips_cnt;
	unsigned short failure_count;
	unsigned short chosen_count;
	void *param;
	fs_evs *fs_sock;
	struct _ds_dest *next;
} ds_dest_t, *ds_dest_p;

typedef struct _ds_set
{
	int id;				/* id of dst set */
	int nr;				/* number of items in dst set */
	int active_nr;		/* number of active items in dst set */
	int last;			/* last used item in dst set */
	int redo_weights;   /* whether at least one item has dynamic weight */
	ds_dest_p dlist;
	struct _ds_set *next;
} ds_set_t, *ds_set_p;

typedef struct _ds_data
{
	ds_set_t *sets;
	unsigned int sets_no;
} ds_data_t;

typedef struct _ds_pvar_param
{
	pv_spec_t pvar;
	int value;
} ds_pvar_param_t, *ds_pvar_param_p;


typedef struct _ds_partition
{
	str name;              /* Partition name */
	str table_name;        /* Table name */
	str db_url;            /* DB url */

	db_con_t **db_handle;
	db_func_t dbf;
	ds_data_t **data;      /* dispatching data holder */
	rw_lock_t *lock;       /* reader-writers lock for reloading the data */

	int dst_avp_name;
	unsigned short dst_avp_type;

	int grp_avp_name;
	unsigned short grp_avp_type;

	int cnt_avp_name;
	unsigned short cnt_avp_type;

	int sock_avp_name;
	unsigned short sock_avp_type;

	int attrs_avp_name;
	unsigned short attrs_avp_type;

	struct _ds_partition *next;
} ds_partition_t;


typedef struct _ds_select_ctl
{
	int set;					/* set id to process */
	ds_partition_t *partition;  /* partition of set_id */
	int alg;					/* algorith to aply */
	int mode;					/* set destination uri */
	int max_results;			/* max destinaitons to process */
	int reset_AVP;				/* reset AVPs flag */
	int set_destination;		/* set destination flag */
	int ds_flags;
} ds_select_ctl_t, *ds_select_ctl_p;

typedef struct
{
	ds_partition_t *partition;
	int set_id;
} ds_options_callback_param_t;

typedef struct _ds_selected_dst
{
	str uri;
	struct socket_info *socket;
} ds_selected_dst, *ds_selected_dst_p;

extern str ds_set_id_col;
extern str ds_dest_uri_col;
extern str ds_dest_sock_col;
extern str ds_dest_comsock_col;
extern str ds_dest_state_col;
extern str ds_dest_weight_col;
extern str ds_dest_prio_col;
extern str ds_dest_attrs_col;
extern str ds_dest_description_col;

extern pv_elem_t * hash_param_model;

extern str ds_setid_pvname;
extern pv_spec_t ds_setid_pv;

/* Structure containing pointers to TM-functions */
struct tm_binds tmb;

extern struct fs_binds fs_api;
extern str ds_ping_method;
extern str ds_ping_from;
extern int ds_ping_maxfwd;
extern int probing_threshhold; /* number of failed requests,
						before a destination is taken into probing */
extern int ds_probing_mode;

extern int fetch_freeswitch_stats;
extern int max_freeswitch_weight;

int init_ds_db(ds_partition_t *partition);
int ds_connect_db(ds_partition_t *partition);
void ds_disconnect_db(ds_partition_t *partition);
int ds_reload_db(ds_partition_t *partition);

int init_ds_data(ds_partition_t *partition);
void ds_destroy_data(ds_partition_t *partition);

int ds_update_dst(struct sip_msg *msg, str *uri, struct socket_info *sock, int mode);
int ds_select_dst(struct sip_msg *msg, ds_select_ctl_p ds_select_ctl, ds_selected_dst_p selected_dst, int ds_flags);
int ds_next_dst(struct sip_msg *msg, int mode, ds_partition_t *partition);
int ds_set_state(int group, str *address, int state, int type,
		ds_partition_t *partition);
int ds_mark_dst(struct sip_msg *msg, int mode, ds_partition_t *partition);
int ds_print_mi_list(struct mi_node* rpl, ds_partition_t *partition, int flags);
int ds_count(struct sip_msg *msg, int set_id, const char *cmp, pv_spec_p ret,
				ds_partition_t *partition);

int ds_is_in_list(struct sip_msg *_m, gparam_t *addr, gparam_t *port,
		int set, int active_only, ds_partition_t *partition);
/*
 * Timer for checking inactive destinations
 */
void ds_check_timer(unsigned int ticks, void* param);
void ds_flusher_routine(unsigned int ticks, void* param);

void ds_update_weights(unsigned int ticks, void *param);

int check_options_rplcode(int code);

/* pvar algorithm pattern parser */
void ds_pvar_parse_pattern(str);

#endif

