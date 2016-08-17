/*
 * $Id$
 *
 * Copyright (C) 2005-2009 Voice Sistem SRL
 *
 * This file is part of Open SIP Server (OpenSIPS).
 *
 * DROUTING OpenSIPS-module is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * DROUTING OpenSIPS-module is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * For any questions about this software and its license, please contact
 * Voice Sistem at following e-mail address:
 *         office@voice-system.ro
 *
 * History:
 * ---------
 *  2005-02-20  first version (cristian)
 *  2005-02-27  ported to 0.9.0 (bogdan)
 */

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>

#include "../../sr_module.h"
#include "../../str.h"
#include "../../dprint.h"
#include "../../usr_avp.h"
#include "../../db/db.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../rw_locking.h"
#include "../../action.h"
#include "../../error.h"
#include "../../ut.h"
#include "../../resolve.h"
#include "../../mod_fix.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_uri.h"
#include "../../mi/mi.h"
#include "../tm/tm_load.h"

#include "dr_load.h"
#include "prefix_tree.h"
#include "routing.h"
#include "dr_bl.h"
#include "dr_db_def.h"


#define DR_PARAM_USE_WEIGTH         (1<<0)
#define DR_PARAM_RULE_FALLBACK      (1<<1)
#define DR_PARAM_STRICT_LEN         (1<<2)
#define DR_PARAM_ONLY_CHECK         (1<<3)
#define DR_PARAM_INTERNAL_TRIGGERED (1<<30)


/* probing related stuff */
static unsigned int dr_prob_interval = 30;
static str dr_probe_replies = {NULL,0};
struct tm_binds dr_tmb;
str dr_probe_method = str_init("OPTIONS");
str dr_probe_from = str_init("sip:prober@localhost");
static int* probing_reply_codes = NULL;
static int probing_codes_no = 0;

static int dr_disable(struct sip_msg *req);


/*** DB relatede stuff ***/
/* parameters  */
static str db_url = {NULL,0};
static int dr_persistent_state = 1;
/* DRG use domain */
static int use_domain = 1;
int dr_default_grp = -1;
int dr_force_dns = 1;

/* variables */
static db_con_t  *db_hdl=0;     /* DB handler */
static db_func_t dr_dbf;        /* DB functions */

/* current dr data - pointer to a pointer in shm */
static rt_data_t **rdata = 0;
static unsigned int* ongoing_reload = 0;


/* internal AVP used to store serial RURIs */
static int ruri_avp = -1;
static str ruri_avp_spec = str_init("$avp(___dr_ruri__)");

/* internal AVP used to store GW IDs */
static int gw_id_avp = -1;
static str gw_id_avp_spec = str_init("$avp(___dr_gw_id__)");

/* internal AVP used to store GW socket */
static int gw_sock_avp = -1;
static str gw_sock_avp_spec = str_init("$avp(___dr_sock__)");

/* internal AVP used to store GW ATTRs */
static int gw_attrs_avp = -1;
static str gw_attrs_avp_spec = str_init("$avp(___dr_gw_att__)");

/* AVP used to store GW Pri Prefix */
static int gw_priprefix_avp = -1;
static str gw_priprefix_avp_spec = { NULL, 0};

/* AVP used to store RULE IDs */
static int rule_id_avp = -1;
static str rule_id_avp_spec = {NULL, 0};

/* internal AVP used to store RULE ATTRs */
static int rule_attrs_avp = -1;
static str rule_attrs_avp_spec = str_init("$avp(___dr_ru_att__)");

/* AVP used to store RULE prefix */
static int rule_prefix_avp = -1;
static str rule_prefix_avp_spec = {NULL, 0};

/* AVP used to store CARRIER ID */
static int carrier_id_avp = -1;
static str carrier_id_avp_spec = {NULL, 0};

/* internal AVP used to store CARRIER ATTRs */
static int carrier_attrs_avp = -1;
static str carrier_attrs_avp_spec = str_init("$avp(___dr_cr_att__)");

/*
 * global pointers for faster parameter passing between functions
 * meaning: current script pvar to dump attrs in (NULL to ignore)
 */
static pv_spec_p rule_attrs_spec;
static pv_spec_p gw_attrs_spec;
static pv_spec_p carrier_attrs_spec;

/*
 * if the attributes are not used at all in the script,
 * do not store them in their internal AVPs at all --liviu
 */
static int populate_rule_attrs;
static int populate_gw_attrs;
static int populate_carrier_attrs;

/* internal AVPs used for fallback */
static int avpID_store_ruri;
static int avpID_store_prefix;
static int avpID_store_index;
static int avpID_store_whitelist;
static int avpID_store_group;
static int avpID_store_flags;

/* statistic data */
int tree_size = 0;
int inode = 0;
int unode = 0;
static str attrs_empty = str_init("");
static int no_concurrent_reload = 0;

/* reader-writers lock for reloading the data */
static rw_lock_t *ref_lock = NULL;

static int dr_init(void);
static int dr_child_init(int rank);
static int dr_exit(void);

static int fixup_do_routing(void** param, int param_no);
static int fixup_next_gw(void** param, int param_no);
static int fixup_from_gw(void** param, int param_no);
static int fixup_is_gw(void** param, int param_no);
static int fixup_route2_carrier( void** param, int param_no);
static int fixup_route2_gw( void** param, int param_no);

static int do_routing(struct sip_msg* msg, dr_group_t *drg, int sort, gparam_t* wl);
static int do_routing_0(struct sip_msg* msg);
static int do_routing_1(struct sip_msg* msg, char* id, char* fl, char* wl,
					char* rule_att, char* gw_att, char* carr_att);
static int use_next_gw(struct sip_msg* msg,
					char* rule_att, char* gw_att, char* carr_att);
static int is_from_gw_0(struct sip_msg* msg);
static int is_from_gw_1(struct sip_msg* msg, char* str1);
static int is_from_gw_2(struct sip_msg* msg, char* str1, char* str2, char* str3);
static int goes_to_gw_0(struct sip_msg* msg);
static int goes_to_gw_1(struct sip_msg* msg, char* f1, char* f2, char* f3);
static int dr_is_gw(struct sip_msg* msg, char* str1, char* str2, char* str3,
					char* str4);
static int route2_carrier(struct sip_msg* msg, char* cr_str,
                          char* gw_att_pv, char* carr_att_pv);
static int route2_gw(struct sip_msg* msg, char* gw, char* gw_att_pv);

static struct mi_root* dr_reload_cmd(struct mi_root *cmd_tree, void *param);
static struct mi_root* mi_dr_gw_status(struct mi_root *cmd, void *param);
static struct mi_root* mi_dr_cr_status(struct mi_root *cmd, void *param);


/*
 * Exported functions
 */
static cmd_export_t cmds[] = {
	{"do_routing",  (cmd_function)do_routing_0,   0,  0, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"do_routing",  (cmd_function)do_routing_1, 1,  fixup_do_routing, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"do_routing",  (cmd_function)do_routing_1, 2,  fixup_do_routing, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"do_routing",  (cmd_function)do_routing_1, 3,  fixup_do_routing, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"do_routing",  (cmd_function)do_routing_1, 4,  fixup_do_routing, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"do_routing",  (cmd_function)do_routing_1, 5,  fixup_do_routing, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"do_routing",  (cmd_function)do_routing_1, 6,  fixup_do_routing, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"use_next_gw",  (cmd_function)use_next_gw,   0,  0, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"use_next_gw",  (cmd_function)use_next_gw,   1,  fixup_next_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"use_next_gw",  (cmd_function)use_next_gw,   2,  fixup_next_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"use_next_gw",  (cmd_function)use_next_gw,   3,  fixup_next_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"next_routing",  (cmd_function)use_next_gw,  0,  0, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"next_routing",  (cmd_function)use_next_gw,  1,  fixup_next_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"next_routing",  (cmd_function)use_next_gw,  2,  fixup_next_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"next_routing",  (cmd_function)use_next_gw,  3,  fixup_next_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"is_from_gw",  (cmd_function)is_from_gw_0,   0,  0, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE},
	{"is_from_gw",  (cmd_function)is_from_gw_1,   1,  fixup_from_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE},
	{"is_from_gw",  (cmd_function)is_from_gw_2,   2,  fixup_from_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE},
	{"is_from_gw",  (cmd_function)is_from_gw_2,   3,  fixup_from_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE},
	{"goes_to_gw",  (cmd_function)goes_to_gw_0,   0,  0, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"goes_to_gw",  (cmd_function)goes_to_gw_1,   1,  fixup_from_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"goes_to_gw",  (cmd_function)goes_to_gw_1,   2,  fixup_from_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"goes_to_gw",  (cmd_function)goes_to_gw_1,   3,  fixup_from_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE},
	{"dr_is_gw",  (cmd_function)dr_is_gw,         1,  fixup_is_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"dr_is_gw",  (cmd_function)dr_is_gw,         2,  fixup_is_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"dr_is_gw",  (cmd_function)dr_is_gw,         3,  fixup_is_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"dr_is_gw",  (cmd_function)dr_is_gw,         4,  fixup_is_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|BRANCH_ROUTE|LOCAL_ROUTE|
		STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE},
	{"dr_disable", (cmd_function)dr_disable,      0,  0, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE},
	{"route_to_carrier",(cmd_function)route2_carrier,1,fixup_route2_carrier, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"route_to_carrier",(cmd_function)route2_carrier,2,fixup_route2_carrier, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"route_to_carrier",(cmd_function)route2_carrier,3,fixup_route2_carrier, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"route_to_gw",     (cmd_function)route2_gw,     1,fixup_route2_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{"route_to_gw",     (cmd_function)route2_gw,     2,fixup_route2_gw, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{0, 0, 0, 0, 0, 0}
};


/*
 * Exported parameters
 */
static param_export_t params[] = {
	{"db_url",           STR_PARAM, &db_url.s         },
	{"drd_table",        STR_PARAM, &drd_table.s      },
	{"drr_table",        STR_PARAM, &drr_table.s      },
	{"drg_table",        STR_PARAM, &drg_table.s      },
	{"drc_table",        STR_PARAM, &drc_table.s      },
	{"use_domain",       INT_PARAM, &use_domain       },
	{"drg_user_col",     STR_PARAM, &drg_user_col.s   },
	{"drg_domain_col",   STR_PARAM, &drg_domain_col.s },
	{"drg_grpid_col",    STR_PARAM, &drg_grpid_col.s  },
	{"ruri_avp",         STR_PARAM, &ruri_avp_spec.s  },
	{"gw_id_avp",        STR_PARAM, &gw_id_avp_spec.s         },
	{"gw_priprefix_avp", STR_PARAM, &gw_priprefix_avp_spec.s  },
	{"gw_sock_avp",      STR_PARAM, &gw_sock_avp_spec.s       },
	{"rule_id_avp",      STR_PARAM, &rule_id_avp_spec.s       },
	{"rule_prefix_avp",  STR_PARAM, &rule_prefix_avp_spec.s   },
	{"carrier_id_avp",   STR_PARAM, &carrier_id_avp_spec.s    },
	{"force_dns",        INT_PARAM, &dr_force_dns             },
	{"default_group",    INT_PARAM, &dr_default_grp           },
	{"define_blacklist", STR_PARAM|USE_FUNC_PARAM, (void*)set_dr_bl },
	{"probing_interval", INT_PARAM, &dr_prob_interval         },
	{"probing_method",   STR_PARAM, &dr_probe_method.s        },
	{"probing_from",     STR_PARAM, &dr_probe_from.s          },
	{"probing_reply_codes", STR_PARAM, &dr_probe_replies.s       },
	{"persistent_state",    INT_PARAM, &dr_persistent_state      },
	{"no_concurrent_reload",INT_PARAM, &no_concurrent_reload     },
	{0, 0, 0}
};


/*
 * Exported MI functions
 */
#define HLP1 "Params: none ; Forces drouting module to reload data from DB "\
	"into memory; A return string is returned only in case of error."
#define HLP2 "Params: [ gw_id [ status ]] ; Sets/gets the status of a GW; "\
	"If no gw_id is given, all gws will be listed; if a new status is give, "\
	"it will be pushed to the given GW."
#define HLP3 "Params: [ carrier_id [ status ]] ; Sets/gets the status of a " \
	"carrier; If no carrier_id is given, all carrier will be listed; if a " \
	"new status is give, it will be pushed to the given carrier."
static mi_export_t mi_cmds[] = {
	{ "dr_reload",         HLP1, dr_reload_cmd,    MI_NO_INPUT_FLAG, 0,  0},
	{ "dr_gw_status",      HLP2, mi_dr_gw_status,  0,                0,  0},
	{ "dr_carrier_status", HLP3, mi_dr_cr_status,  0,                0,  0},
	{ 0, 0, 0, 0, 0, 0}
};



struct module_exports exports = {
	"drouting",
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	cmds,            /* Exported functions */
	params,          /* Exported parameters */
	0,               /* exported statistics */
	mi_cmds,         /* exported MI functions */
	0,               /* exported pseudo-variables */
	0,               /* additional processes */
	dr_init,         /* Module initialization function */
	(response_function) 0,
	(destroy_function) dr_exit,
	(child_init_function) dr_child_init /* per-child init function */
};


/** Probing Section **/

static int check_options_rplcode(int code)
{
	int i;

	for (i =0; i< probing_codes_no; i++) {
		if(probing_reply_codes[i] == code)
			return 1;
	}

	return 0;
}


static int dr_disable(struct sip_msg *req)
{
	struct usr_avp *avp;
	int_str id_val;
	pgw_t *gw;

	lock_start_read( ref_lock );

	avp = search_first_avp( AVP_VAL_STR, gw_id_avp, &id_val,0);
	if (avp==NULL) {
		LM_DBG(" no AVP ID ->nothing to disable\n");
		lock_stop_read( ref_lock );
		return -1;
	}

	gw = get_gw_by_id( (*rdata)->pgw_l, &id_val.s );
	if (gw!=NULL && (gw->flags&DR_DST_STAT_DSBL_FLAG)==0)
		gw->flags |= DR_DST_STAT_DSBL_FLAG|DR_DST_STAT_DIRT_FLAG;

	lock_stop_read( ref_lock );

	return 1;
}


static void dr_probing_callback( struct cell *t, int type,
		struct tmcb_params *ps )
{
	int code = ps->code;
	pgw_t *gw;

	if (!*ps->param) {
		LM_CRIT("BUG - reply to a DR probe with no ID (code=%d)\n", ps->code);
		return;
	}

	lock_start_read( ref_lock );

	gw = get_gw_by_internal_id( (*rdata)->pgw_l, (int)(long)(*ps->param) );
	if (gw==NULL)
		goto end;

	if ((code == 200) || check_options_rplcode(code)) {
		/* re-enable to DST  (if allowed) */
		if ( (gw->flags&DR_DST_STAT_NOEN_FLAG)!=0 ||  /* permanently disabled */
		(gw->flags&DR_DST_STAT_DSBL_FLAG)==0)         /* not disabled at all */
			goto end;
		gw->flags &= ~DR_DST_STAT_DSBL_FLAG;
		gw->flags |= DR_DST_STAT_DIRT_FLAG;
		goto end;
	}

	if (code>=400 && (gw->flags&DR_DST_STAT_DSBL_FLAG)==0) {
		gw->flags |= DR_DST_STAT_DSBL_FLAG|DR_DST_STAT_DIRT_FLAG;
	}


end:
	lock_stop_read( ref_lock );

	return;
}


static void dr_prob_handler(unsigned int ticks, void* param)
{
	static char buff[1000] = {"sip:"};
	dlg_t *dlg;
	str uri;

	if (rdata==NULL || *rdata==NULL)
		return;

	lock_start_read( ref_lock );

	/* do probing */
	pgw_t *dst;

	/* go through all destinations */
	for( dst = (*rdata)->pgw_l ; dst ; dst=dst->next ) {
		/* dst requires probing ? */
		if ( dst->flags&DR_DST_STAT_NOEN_FLAG
			|| !( (dst->flags&DR_DST_PING_PERM_FLAG)  ||  /*permanent probing*/
					( dst->flags&DR_DST_PING_DSBL_FLAG
					&& dst->flags&DR_DST_STAT_DSBL_FLAG  /*probing on disable*/
					)
				)
			)
			continue;

		memcpy(buff + 4, dst->ip_str.s, dst->ip_str.len);
		uri.s = buff;
		uri.len = dst->ip_str.len + 4;

		/* Execute the Dialog using the "request"-Method of the
		 * TM-Module.*/
		if (dr_tmb.new_auto_dlg_uac(&dr_probe_from, &uri, dst->sock, &dlg)!=0) {
			LM_ERR("failed to create new TM dlg\n");
			continue;
		}
		dlg->state = DLG_CONFIRMED;
		if (dr_tmb.t_request_within(&dr_probe_method, NULL, NULL, dlg,
		dr_probing_callback, (void*)(long)dst->_id, NULL) < 0) {
			LM_ERR("unable to execute dialog\n");
		}
		dr_tmb.free_dlg(dlg);

	}


	lock_stop_read( ref_lock );
}


static void dr_state_flusher(void)
{
	static db_ps_t cr_ps=NULL, gw_ps=NULL;
	pgw_t *gw;
	pcr_t *cr;
	db_key_t key_cmp;
	db_val_t val_cmp;
	db_key_t key_set;
	db_val_t val_set;

	/* is data avaialable? */
	if (!rdata || !(*rdata))
		return;

	val_cmp.type = DB_STR;
	val_cmp.nul  = 0;

	val_set.type = DB_INT;
	val_set.nul  = 0;

	/* update the gateways */
	if (dr_dbf.use_table( db_hdl, &drd_table) < 0) {
		LM_ERR("cannot select table \"%.*s\"\n", drd_table.len, drd_table.s);
		return;
	}
	key_cmp = &gwid_drd_col;
	key_set = &state_drd_col;

	/* iterate the gateways */
	for( gw=(*rdata)->pgw_l ; gw ; gw=gw->next ) {
		if ( (gw->flags & DR_DST_STAT_DIRT_FLAG)==0 )
			/* nothing to do for this gateway */
			continue;

		/* populate the update */
		val_cmp.val.str_val = gw->id;
		val_set.val.int_val = (gw->flags&DR_DST_STAT_DSBL_FLAG) ? ((gw->flags&DR_DST_STAT_NOEN_FLAG)?1:2) : (0);

		/* update the state of this gateway */
		LM_DBG("updating the state of gw <%.*s> to %d\n",
			gw->id.len, gw->id.s, val_set.val.int_val);

		CON_PS_REFERENCE(db_hdl) = gw_ps;
		if ( dr_dbf.update(db_hdl,&key_cmp,0,&val_cmp,&key_set,&val_set,1,1)<0 ) {
			LM_ERR("DB update failed\n");
		} else {
			gw->flags &= ~DR_DST_STAT_DIRT_FLAG;
		}
	}

	/* update the carriers */
	if (dr_dbf.use_table( db_hdl, &drc_table) < 0) {
		LM_ERR("cannot select table \"%.*s\"\n", drc_table.len, drc_table.s);
		return;
	}
	key_cmp = &cid_drc_col;
	key_set = &state_drc_col;

	/* iterate the carriers */
	for( cr=(*rdata)->carriers ; cr ; cr=cr->next ) {
		if ( (cr->flags & DR_CR_FLAG_DIRTY)==0 )
			/* nothing to do for this carrier */
			continue;

		/* populate the update */
		val_cmp.val.str_val = cr->id;
		val_set.val.int_val = (cr->flags&DR_CR_FLAG_IS_OFF) ? 1 : 0;

		/* update the state of this carrier */
		LM_DBG("updating the state of cr <%.*s> to %d\n",
			cr->id.len, cr->id.s, val_set.val.int_val);

		CON_PS_REFERENCE(db_hdl) = cr_ps;
		if ( dr_dbf.update(db_hdl,&key_cmp,0,&val_cmp,&key_set,&val_set,1,1)<0 ) {
			LM_ERR("DB update failed\n");
		} else {
			cr->flags &= ~DR_CR_FLAG_DIRTY;
		}
	}

	return;
}

/* Flushes to DB the state of carriers and gateways (if modified)
 * Locking is done to protect the data consistency */
static void dr_state_timer(unsigned int ticks, void* param)
{
	lock_start_read( ref_lock );

	dr_state_flusher();

	lock_stop_read( ref_lock );
}


static inline int dr_reload_data( void )
{
	rt_data_t *new_data;
	rt_data_t *old_data;
	pgw_t *gw, *old_gw;
	pcr_t *cr, *old_cr;

	if (no_concurrent_reload) {
		lock_get( ref_lock->lock );
		if (*ongoing_reload) {
			lock_release( ref_lock->lock );
			LM_WARN("Reload already in progress, discarding this one\n");
			return -2;
		}
		*ongoing_reload = 1;
		lock_release( ref_lock->lock );
	}

	new_data = dr_load_routing_info( &dr_dbf, db_hdl,
		&drd_table, &drc_table, &drr_table, dr_persistent_state);
	if ( new_data==0 ) {
		LM_CRIT("failed to load routing info\n");
		goto error;
	}

	lock_start_write( ref_lock );

	/* no more activ readers -> do the swapping */
	old_data = *rdata;
	*rdata = new_data;

	lock_stop_write( ref_lock );

	/* destroy old data */
	if (old_data) {
		/* copy the state of gw/cr from old data */
		/* interate new gws and search them into old data */
		for( gw=new_data->pgw_l ; gw ; gw=gw->next ) {
			old_gw = get_gw_by_id( old_data->pgw_l, &gw->id);
			if (old_gw) {
				gw->flags &= ~DR_DST_STAT_MASK;
				gw->flags |= old_gw->flags&DR_DST_STAT_MASK;
			}
		}
		/* interate new crs and search them into old data */
		for( cr=new_data->carriers ; cr ; cr=cr->next ) {
			old_cr = get_carrier_by_id( old_data->carriers, &cr->id);
			if (old_cr) {
				cr->flags &= ~DR_CR_FLAG_IS_OFF;
				cr->flags |= old_cr->flags&DR_CR_FLAG_IS_OFF;
			}
		}

		/* free old data */
		free_rt_data( old_data, 1 );
	}

	/* generate new blacklist from the routing info */
	populate_dr_bls((*rdata)->pgw_l);

	if (no_concurrent_reload)
		*ongoing_reload = 0;
	return 0;

error:
	if (no_concurrent_reload)
		*ongoing_reload = 0;
	return -1;
}


#define dr_fix_avp_definition( _pv_spec, _avp_id, _name) \
	do { \
		_pv_spec.len = strlen(_pv_spec.s); \
		if (pv_parse_spec( &_pv_spec, &avp_spec)==0 \
		|| avp_spec.type!=PVT_AVP) { \
			LM_ERR("malformed or non AVP [%.*s] for %s AVP definition\n",\
				_pv_spec.len, _pv_spec.s, _name); \
			return E_CFG; \
		} \
		if( pv_get_avp_name(0, &(avp_spec.pvp), &_avp_id, &dummy )!=0) { \
			LM_ERR("[%.*s]- invalid AVP definition for %s AVP\n", \
				_pv_spec.len, _pv_spec.s, _name); \
			return E_CFG; \
		} \
	} while(0)


static int dr_init(void)
{
	pv_spec_t avp_spec;
	unsigned short dummy;
	str name;

	LM_INFO("Dynamic-Routing - initializing\n");

	/* check the module params */
	init_db_url( db_url , 0 /*cannot be null*/);

	drd_table.len = strlen(drd_table.s);
	if (drd_table.s[0]==0) {
		LM_CRIT("mandatory parameter \"DRD_TABLE\" found empty\n");
		goto error;
	}

	drr_table.len = strlen(drr_table.s);
	if (drr_table.s[0]==0) {
		LM_CRIT("mandatory parameter \"DRR_TABLE\" found empty\n");
		goto error;
	}

	drg_table.len = strlen(drg_table.s);
	if (drg_table.s[0]==0) {
		LM_CRIT("mandatory parameter \"DRG_TABLE\" found empty\n");
		goto error;
	}

	drc_table.len = strlen(drc_table.s);
	if (drc_table.s[0]==0) {
		LM_CRIT("mandatory parameter \"DRC_TABLE\" found empty\n");
		goto error;
	}

	drg_user_col.len = strlen(drg_user_col.s);
	drg_domain_col.len = strlen(drg_domain_col.s);
	drg_grpid_col.len = strlen(drg_grpid_col.s);

	/* fix specs for internal AVP (used for fallback) */
	name.s = "_dr_fb_ruri"; name.len=11;
	if ( parse_avp_spec( &name, &avpID_store_ruri)!=0 ) {
		LM_ERR("failed to init internal AVP for ruri\n");
		return E_UNSPEC;
	}
	name.s = "_dr_fb_prefix"; name.len=13;
	if ( parse_avp_spec( &name, &avpID_store_prefix)!=0 ) {
		LM_ERR("failed to init internal AVP for prefix\n");
		return E_UNSPEC;
	}
	name.s = "_dr_fb_index"; name.len=12;
	if ( parse_avp_spec( &name, &avpID_store_index)!=0 ) {
		LM_ERR("failed to init internal AVP for index\n");
		return E_UNSPEC;
	}
	name.s = "_dr_fb_whitelist"; name.len=16;
	if ( parse_avp_spec( &name, &avpID_store_whitelist)!=0 ) {
		LM_ERR("failed to init internal AVP for whitelist\n");
		return E_UNSPEC;
	}
	name.s = "_dr_fb_group"; name.len=12;
	if ( parse_avp_spec( &name, &avpID_store_group)!=0 ) {
		LM_ERR("failed to init internal AVP for group\n");
		return E_UNSPEC;
	}
	name.s = "_dr_fb_flags"; name.len=12;
	if ( parse_avp_spec( &name, &avpID_store_flags)!=0 ) {
		LM_ERR("failed to init internal AVP for flags\n");
		return E_UNSPEC;
	}

	/* fix AVP specs for parameters */

	dr_fix_avp_definition( ruri_avp_spec, ruri_avp, "RURI");

	dr_fix_avp_definition( gw_id_avp_spec, gw_id_avp, "GW ID");

	dr_fix_avp_definition( gw_sock_avp_spec, gw_sock_avp, "GW SOCKET");

	dr_fix_avp_definition( gw_attrs_avp_spec, gw_attrs_avp, "GW ATTRS");

	dr_fix_avp_definition( rule_attrs_avp_spec, rule_attrs_avp, "RULE ATTRS");

	dr_fix_avp_definition( carrier_attrs_avp_spec, carrier_attrs_avp,
	                      "CARRIER ATTRS");

	if (gw_priprefix_avp_spec.s)
		dr_fix_avp_definition( gw_priprefix_avp_spec, gw_priprefix_avp,
			"GW PRI PREFIX");

	if (rule_id_avp_spec.s)
		dr_fix_avp_definition( rule_id_avp_spec, rule_id_avp, "RULE ID");

	if (rule_prefix_avp_spec.s)
		dr_fix_avp_definition( rule_prefix_avp_spec, rule_prefix_avp, "RULE PREFIX");

	if (carrier_id_avp_spec.s)
		dr_fix_avp_definition( carrier_id_avp_spec, carrier_id_avp, "CARRIER ID");

	if (init_dr_bls()!=0) {
		LM_ERR("failed to init DR blacklists\n");
		return E_CFG;
	}

	if (no_concurrent_reload) {
		ongoing_reload = (unsigned int *)shm_malloc( sizeof(unsigned int) );
		if (ongoing_reload==NULL) {
			LM_CRIT("failed to get shm mem for reload tracker\n");
			goto error;
		}
		*ongoing_reload = 0;
	}

	/* data pointer in shm */
	rdata = (rt_data_t**)shm_malloc( sizeof(rt_data_t*) );
	if (rdata==0) {
		LM_CRIT("failed to get shm mem for data ptr\n");
		goto error;
	}
	*rdata = 0;

	/* create & init lock */
	if ((ref_lock = lock_init_rw()) == NULL) {
		LM_CRIT("failed to init lock\n");
		goto error;
	}

	/* bind to the mysql module */
	if (db_bind_mod( &db_url, &dr_dbf  )) {
		LM_CRIT("cannot bind to database module! "
			"Did you forget to load a database module ?\n");
		goto error;
	}

	if (!DB_CAPABILITY( dr_dbf, DB_CAP_QUERY)) {
		LM_CRIT( "database modules does not "
			"provide QUERY functions needed by DRounting module\n");
		return -1;
	}


	/* arm a function for probing */
	if (dr_prob_interval) {
		/* load TM API */
		if (load_tm_api(&dr_tmb)!=0) {
			LM_ERR("can't load TM API\n");
			return -1;
		}

		/* probing method */
		dr_probe_method.len = strlen(dr_probe_method.s);
		dr_probe_from.len = strlen(dr_probe_from.s);
		if (dr_probe_replies.s)
			dr_probe_replies.len = strlen(dr_probe_replies.s);

		/* register pinger function */
		if (register_timer( "dr-pinger", dr_prob_handler, NULL,
		dr_prob_interval)<0) {
			LM_ERR("failed to register probing handler\n");
			return -1;
		}

		if (dr_probe_replies.s) {
			dr_probe_replies.len = strlen(dr_probe_replies.s);
			if(parse_reply_codes( &dr_probe_replies, &probing_reply_codes,
			&probing_codes_no )< 0) {
				LM_ERR("Bad format for options_reply_code parameter"
					" - Need a code list separated by commas\n");
				return -1;
			}
		}

	}

	if (dr_persistent_state) {
		/* register function to flush changes in state */
		if (register_timer("dr-flush", dr_state_timer, NULL, 30)<0) {
			LM_ERR("failed to register state flush handler\n");
			return -1;
		}
	}

	return 0;
error:
	if (ongoing_reload) {
		shm_free(ongoing_reload);
		ongoing_reload = 0;
	}
	if (ref_lock) {
		lock_destroy_rw( ref_lock );
		ref_lock = 0;
	}
	if (db_hdl) {
		dr_dbf.close(db_hdl);
		db_hdl = 0;
	}
	if (rdata) {
		shm_free(rdata);
		rdata = 0;
	}
	return -1;
}



static int dr_child_init(int rank)
{
	/* We need DB connection from:
	 * 	 - attendant - for shutdown, flushing state
     *   - timer - may trigger routes with dr group
     *   - workers - execute routes with dr group
     *   - module's proc - ??? */
	if (rank==PROC_TCP_MAIN || rank==PROC_BIN)
		return 0;

	/* init DB connection */
	if ( (db_hdl=dr_dbf.init(&db_url))==0 ) {
		LM_CRIT("cannot initialize database connection\n");
		return -1;
	}

	/* child 1 load the routing info */
	if ( (rank==1) && dr_reload_data()!=0 ) {
		LM_CRIT("failed to load routing data\n");
		return -1;
	}

	/* set GROUP table for workers */
	if (dr_dbf.use_table( db_hdl, &drg_table) < 0) {
		LM_ERR("cannot select table \"%.*s\"\n", drg_table.len, drg_table.s);
		return -1;
	}
	srand(getpid()+time(0)+rank);
	return 0;
}


static int dr_exit(void)
{
	if (dr_persistent_state && db_hdl)
		dr_state_flusher();

	/* close DB connection */
	if (db_hdl) {
		dr_dbf.close(db_hdl);
		db_hdl = 0;
	}

	/* destroy data */
	if ( rdata) {
		if (*rdata)
			free_rt_data( *rdata, 1 );
		shm_free( rdata );
		rdata = 0;
	}

	/* destroy lock */
	if (ref_lock) {
		lock_destroy_rw( ref_lock );
		ref_lock = 0;
	}

	/* destroy tracker for reloads */
	if (ongoing_reload) {
		shm_free(ongoing_reload);
		ongoing_reload = 0;
	}

	/* destroy blacklists */
	destroy_dr_bls();

	return 0;
}



static struct mi_root* dr_reload_cmd(struct mi_root *cmd_tree, void *param)
{
	int n;

	LM_INFO("dr_reload MI command received!\n");

	if ( (n=dr_reload_data())<0 ) {
		if (n==-2)
			return init_mi_tree(500, MI_SSTR("Reload already in progress") );
		LM_CRIT("failed to load routing data\n");
		return init_mi_tree( 500, MI_SSTR("Failed to reload"));
	}

	return init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
}



static inline int get_group_id(struct sip_uri *uri)
{
	db_key_t keys_ret[1];
	db_key_t keys_cmp[2];
	db_val_t vals_cmp[2];
	db_res_t* res;
	int n;

	/* user */
	keys_cmp[0] = &drg_user_col;
	vals_cmp[0].type = DB_STR;
	vals_cmp[0].nul  = 0;
	vals_cmp[0].val.str_val = uri->user;
	n = 1;

	if (use_domain) {
		keys_cmp[1] = &drg_domain_col;
		vals_cmp[1].type = DB_STR;
		vals_cmp[1].nul  = 0;
		vals_cmp[1].val.str_val = uri->host;
		n++;
	}

	keys_ret[0] = &drg_grpid_col;
	res = 0;

	if ( dr_dbf.query(db_hdl,keys_cmp,0,vals_cmp,keys_ret,n,1,0,&res)<0 ) {
		LM_ERR("DB query failed\n");
		goto error;
	}

	if (RES_ROW_N(res) == 0) {
		if (dr_default_grp!=-1)
			return dr_default_grp;
		LM_ERR("no group for user "
			"\"%.*s\"@\"%.*s\"\n", uri->user.len, uri->user.s,
			uri->host.len, uri->host.s);
		goto error;
	}
	if (res->rows[0].values[0].nul || res->rows[0].values[0].type!=DB_INT) {
		LM_ERR("null or non-integer group_id\n");
		goto error;
	}
	n = res->rows[0].values[0].val.int_val;

	dr_dbf.free_result(db_hdl, res);
	return n;
error:
	if (res)
		dr_dbf.free_result(db_hdl, res);
	return -1;
}



static inline str* build_ruri(struct sip_uri *uri, int strip, str *pri,
																str *hostport)
{
	static str uri_str;
	char *p;

	if (uri->user.len<=strip) {
		LM_ERR("stripping %d makes "
			"username <%.*s> null\n",strip,uri->user.len,uri->user.s);
		return 0;
	}

	uri_str.len = 4 /*sip:*/ + uri->user.len - strip +pri->len +
		(uri->passwd.s?(uri->passwd.len+1):0) + 1/*@*/ + hostport->len +
		(uri->params.s?(uri->params.len+1):0) +
		(uri->headers.s?(uri->headers.len+1):0);

	if ( (uri_str.s=(char*)pkg_malloc( uri_str.len + 1))==0) {
		LM_ERR("no more pkg mem\n");
		return 0;
	}

	p = uri_str.s;
	*(p++)='s';
	*(p++)='i';
	*(p++)='p';
	*(p++)=':';
	if (pri->len) {
		memcpy(p, pri->s, pri->len);
		p += pri->len;
	}
	memcpy(p, uri->user.s+strip, uri->user.len-strip);
	p += uri->user.len-strip;
	if (uri->passwd.s && uri->passwd.len) {
		*(p++)=':';
		memcpy(p, uri->passwd.s, uri->passwd.len);
		p += uri->passwd.len;
	}
	*(p++)='@';
	memcpy(p, hostport->s, hostport->len);
	p += hostport->len;
	if (uri->params.s && uri->params.len) {
		*(p++)=';';
		memcpy(p, uri->params.s, uri->params.len);
		p += uri->params.len;
	}
	if (uri->headers.s && uri->headers.len) {
		*(p++)='?';
		memcpy(p, uri->headers.s, uri->headers.len);
		p += uri->headers.len;
	}
	*p = 0;

	if (p-uri_str.s!=uri_str.len) {
		LM_CRIT("difference between allocated(%d)"
			" and written(%d)\n",uri_str.len,(int)(long)(p-uri_str.s));
		return 0;
	}
	return &uri_str;
}


static int do_routing_0(struct sip_msg* msg)
{
	rule_attrs_spec = gw_attrs_spec = carrier_attrs_spec = NULL;

	return do_routing(msg, NULL, 0, NULL);
}

static int do_routing_1(struct sip_msg* msg, char* grp, char* _flags, char* wlst,
                        char* rule_att, char* gw_att, char* carr_att)
{
	str res = {0,0};
	int flags=0;
	char *p;

	if (_flags) {
		if (fixup_get_svalue(msg, (gparam_p)_flags, &res) != 0) {
			LM_ERR("failed to extract flags\n");
			return -1;
		}

		for (p=res.s;p<res.s+res.len;p++)
		{
			switch (*p)
			{
				case 'W':
					flags |= DR_PARAM_USE_WEIGTH;
					LM_DBG("using weights in GW selection\n");
					break;
				case 'F':
					flags |= DR_PARAM_RULE_FALLBACK;
					LM_DBG("enabling rule fallback\n");
					break;
				case 'L':
					flags |= DR_PARAM_STRICT_LEN;
					LM_DBG("matching prefix with strict len\n");
					break;
				case 'C':
					flags |= DR_PARAM_ONLY_CHECK;
					LM_DBG("only check the prefix\n");
					break;
				default:
					LM_DBG("unknown flag : [%c] . Skipping\n",*p);
			}
		}
	}

	rule_attrs_spec = (pv_spec_p)rule_att;
	gw_attrs_spec = (pv_spec_p)gw_att;
	carrier_attrs_spec = (pv_spec_p)carr_att;

	return do_routing(msg, (dr_group_t*)grp, flags, (gparam_t*)wlst);
}


static int use_next_gw(struct sip_msg* msg,
                       char* rule_att, char* gw_att, char* carr_att)
{
	struct usr_avp *avp, *avp_ru, *avp_sk;
	unsigned int flags;
	gparam_t wl_list;
	dr_group_t grp;
	int_str val;
	pv_value_t pv_val;
	str ruri;
	int ok=0;
	pgw_t * dst;
	struct socket_info *sock;

	rule_attrs_spec = (pv_spec_p)rule_att;
	gw_attrs_spec = (pv_spec_p)gw_att;
	carrier_attrs_spec = (pv_spec_p)carr_att;

	/*
	 * pop a value from each AVP
	 * (also remove all bogus non-STR top-most values)
	 */
	while(1)
	{
		if (rule_attrs_spec) {
			avp = search_first_avp(0, rule_attrs_avp, &val, NULL);
			if (avp) {
				pv_val.flags = PV_VAL_STR;
				pv_val.rs = val.s;
				if (pv_set_value(msg, rule_attrs_spec, 0, &pv_val) != 0)
					LM_ERR("failed to set value for rule attrs pvar\n");
			}
		}

		/* remove the old attrs */
		if (gw_attrs_spec) {
			avp = NULL;
			do {
				if (avp) destroy_avp(avp);
				avp = search_first_avp( 0, gw_attrs_avp, NULL, NULL);
			}while (avp && (avp->flags&AVP_VAL_STR)==0 );
			if (avp) destroy_avp(avp);

			avp = search_first_avp(0, gw_attrs_avp, &val, NULL);
			if (avp) {
				pv_val.flags = PV_VAL_STR;
				pv_val.rs = val.s;
				if (pv_set_value(msg, gw_attrs_spec, 0, &pv_val) != 0)
					LM_ERR("failed to set value for gateway attrs pvar\n");
			}
		}

		/* remove the old carrier attrs */
		if (carrier_attrs_spec) {
			avp = NULL;
			do {
				if (avp) destroy_avp(avp);
				avp = search_first_avp( 0, carrier_attrs_avp, NULL, NULL);
			}while (avp && (avp->flags&AVP_VAL_STR)==0 );
			if (avp) destroy_avp(avp);

			avp = search_first_avp(0, carrier_attrs_avp, &val, NULL);
			if (avp) {
				pv_val.flags = PV_VAL_STR;
				pv_val.rs = val.s;
				if (pv_set_value(msg, carrier_attrs_spec, 0, &pv_val) != 0)
					LM_ERR("failed to set value for carrier attrs pvar\n");
			}
		}

		/* remove the old priprefix */
		if (gw_priprefix_avp!=-1) {
			avp = NULL;
			do {
				if (avp) destroy_avp(avp);
				avp = search_first_avp( 0, gw_priprefix_avp, NULL, NULL);
			}while (avp && (avp->flags&AVP_VAL_STR)==0 );
			if (avp) destroy_avp(avp);
		}

		/* remove the old carrier ID */
		if (carrier_id_avp!=-1) {
			avp = NULL;
			do {
				if (avp) destroy_avp(avp);
				avp = search_first_avp( 0, carrier_id_avp, NULL, NULL);
			}while (avp && (avp->flags&AVP_VAL_STR)==0 );
			if (avp) destroy_avp(avp);
		}

		/* remove old gw ID and search next one */
		avp = NULL;
		do {
			if (avp) destroy_avp(avp);
			avp = search_first_avp( 0, gw_id_avp, NULL, NULL);
		}while (avp && (avp->flags&AVP_VAL_STR)==0 );
		if (!avp) {
			LM_WARN("no GWs found at all -> have you done do_routing in script ?? \n");
			return -1;
		}
		do {
			if (avp) destroy_avp(avp);
			avp = search_first_avp( 0, gw_id_avp, NULL, NULL);
		}while (avp && (avp->flags&AVP_VAL_STR)==0 );
		/* any GW found ? */
		if (!avp)
			goto rule_fallback;

		/* search for the first RURI AVP containing a string */
		avp_ru = NULL;
		do {
			if (avp_ru) destroy_avp(avp_ru);
			avp_ru = search_first_avp( 0, ruri_avp, &val, NULL);
		}while (avp_ru && (avp_ru->flags&AVP_VAL_STR)==0 );

		if (!avp_ru)
			goto rule_fallback;
		ruri = val.s;

		/* search for the first SOCK AVP containing a string */
		avp_sk = NULL;
		do {
			if (avp_sk) destroy_avp(avp_sk);
			avp_sk = search_first_avp( 0, gw_sock_avp, &val, NULL);
		}while (avp_sk && (avp_sk->flags&AVP_VAL_STR)==0 );
		if (!avp_sk) {
			/* this shuold not happen, it is a bogus state */
			sock = NULL;
		} else {
			if (sscanf( val.s.s, "%p", (void**)&sock ) != 1)
				sock = NULL;
			destroy_avp(avp_sk);
		}

		LM_DBG("new RURI set to <%.*s> via socket <%.*s>\n",
			val.s.len,val.s.s,
			sock?sock->name.len:4, sock?sock->name.s:"none");

		/* get value for next gw ID from avp */
		get_avp_val(avp, &val);

		/* we have an ID, so we can check the GW state */
		lock_start_read( ref_lock );
		dst = get_gw_by_id( (*rdata)->pgw_l, &val.s);
		if (dst && (dst->flags & DR_DST_STAT_DSBL_FLAG) == 0)
			ok = 1;

		lock_stop_read( ref_lock );

		if ( ok )
			break;

		/* search for the next available GW*/
		destroy_avp(avp_ru);
	}

	if (set_ruri( msg, &ruri)==-1) {
		LM_ERR("failed to rewite RURI\n");
		return -1;
	}
	if (sock)
		msg->force_send_socket = sock;

	destroy_avp(avp_ru);

	return 1;


rule_fallback:
	LM_DBG("using rule fallback\n");

	/* check if a "flags" AVP is there and if fallback allowed */
	avp = search_first_avp( 0, avpID_store_flags, &val, NULL);
	if (avp==NULL || !(val.n & DR_PARAM_RULE_FALLBACK) )
		return -1;

	/* fallback allowed, fetch the rest of data from AVPs */
	flags = val.n | DR_PARAM_INTERNAL_TRIGGERED;

	if (!search_first_avp( 0, avpID_store_group, &val, NULL)) {
		LM_ERR("Cannot find group AVP during a fallback\n");
		goto fallback_failed;
	}
	grp.type = 0;
	grp.u.grp_id = val.n;

	if (!search_first_avp( AVP_VAL_STR, avpID_store_whitelist, &val, NULL)) {
		wl_list.type = 0;
	} else {
		wl_list.type = GPARAM_TYPE_STR;
		wl_list.v.sval = val.s;
		wl_list.v.sval.s[--wl_list.v.sval.len] = 0;
	}

	if (do_routing( msg, &grp, flags, wl_list.type?&wl_list:NULL)==1) {
		return 1;
	}

fallback_failed:
	/* prevent any more fallback by removing the flags AVP */
	destroy_avp(avp);
	return -1;
}


#define DR_MAX_GWLIST	64

static int sort_rt_dst(pgw_list_t *pgwl, unsigned short size,
											int weight, unsigned short *idx)
{
	unsigned short running_sum[DR_MAX_GWLIST];
	unsigned int i, first, weight_sum, rand_no;

	/* populate the index array */
	for( i=0 ; i<size ; i++ ) idx[i] = i;
	first = 0;

	if (weight==0)
		return 0;

	while (size-first>1) {
		/* calculate the running sum */
		for( i=first,weight_sum=0 ; i<size ; i++ ) {
			weight_sum += pgwl[ idx[i] ].weight ;
			running_sum[i] = weight_sum;
			LM_DBG("elen %d, weight=%d, sum=%d\n",i,
				pgwl[ idx[i] ].weight, running_sum[i]);
		}
		if (weight_sum) {
			/* randomly select number */
			rand_no = (unsigned int)(weight_sum*((float)rand()/RAND_MAX));
			LM_DBG("random number is %d\n",rand_no);
			/* select the element */
			for( i=first ; i<size ; i++ )
				if (running_sum[i]>rand_no) break;
			if (i==size) {
				LM_CRIT("bug in weight sort\n");
				return -1;
			}
		} else {
			/* randomly select index */
		//	i = (unsigned int)((size-first)*((float)rand()/RAND_MAX));
			i = first;
		}
		LM_DBG("selecting element %d with weight %d\n",
			idx[i], pgwl[ idx[i] ].weight);
		/* "i" is the selected element : swap it with first position and
		   retake alg without first elem */
		rand_no = idx[i];
		idx[i] = idx[first];
		idx[first] = rand_no;
		first ++;
	}

	return 0;
}


inline static int push_gw_for_usage(struct sip_msg *msg, struct sip_uri *uri,
								pgw_t *gw , str *c_id, str *c_attrs, int idx)
{
	char buf[2+16+1]; /* a hexa string */
	str *ruri;
	int_str val;

	/* build uri*/
	ruri = build_ruri( uri, gw->strip, &gw->pri, &gw->ip_str);
	if (ruri==0) {
		LM_ERR("failed to build new ruri\n");
		return -1;
	}

	LM_DBG("adding gw [%.*s] as \"%.*s\" in order %d\n",
			gw->id.len, gw->id.s, ruri->len, ruri->s, idx);

	/* first GW to be added ? */
	if (idx==0) {

		/* add to RURI */
		if (set_ruri( msg, ruri)!= 0 ) {
			LM_ERR("failed to set new RURI\n");
			goto error;
		}
		/* set socket to be used */
		if (gw->sock)
			msg->force_send_socket = gw->sock;

	} else {

		/* add ruri as AVP */
		val.s = *ruri;
		if (add_avp_last( AVP_VAL_STR, ruri_avp, val)!=0 ) {
			LM_ERR("failed to insert ruri avp\n");
			goto error;
		}

		/* add GW sock avp */
		val.s.len = 1 + sprintf( buf, "%p", gw->sock );
		val.s.s = buf;
		LM_DBG("setting GW sock [%.*s] as avp\n",val.s.len, val.s.s);
		if (add_avp_last( AVP_VAL_STR, gw_sock_avp, val)!=0 ) {
			LM_ERR("failed to insert sock avp\n");
			goto error;
		}

	}

	/* add GW id avp */
	val.s = gw->id;
	LM_DBG("setting GW id [%.*s] as avp\n",val.s.len, val.s.s);
	if (add_avp_last( AVP_VAL_STR, gw_id_avp, val)!=0 ) {
		LM_ERR("failed to insert ids avp\n");
		goto error;
	}

	/* add internal GW attrs avp if requested at least once in the script */
	if (populate_gw_attrs) {
		val.s = gw->attrs.s? gw->attrs : attrs_empty;
		LM_DBG("setting GW attr [%.*s] as avp\n", val.s.len, val.s.s);
		if (add_avp_last(AVP_VAL_STR, gw_attrs_avp, val)!=0){
			LM_ERR("failed to insert gw attrs avp\n");
			goto error;
		}
	}

	/* add GW priprefix avp */
	if (gw_priprefix_avp!=-1) {
		val.s = gw->pri.s? gw->pri : attrs_empty;
		LM_DBG("setting GW priprefix [%.*s] as avp\n",val.s.len,val.s.s);
		if (add_avp_last(AVP_VAL_STR, gw_priprefix_avp, val)!=0){
			LM_ERR("failed to insert priprefix avp\n");
			goto error;
		}
	}

	if (carrier_id_avp!=-1) {
		val.s = (c_id && c_id->s)? *c_id : attrs_empty ;
		LM_DBG("setting CR Id [%.*s] as avp\n",val.s.len,val.s.s);
		if (add_avp_last(AVP_VAL_STR, carrier_id_avp, val)!=0){
			LM_ERR("failed to insert attrs avp\n");
			goto error;
		}
	}

	/* add internal carrier attrs avp if requested at least once in the script */
	if (populate_carrier_attrs) {
		val.s = (c_attrs && c_attrs->s)? *c_attrs : attrs_empty;
		LM_DBG("setting CR attr [%.*s] as avp\n", val.s.len, val.s.s);
		if (add_avp_last(AVP_VAL_STR, carrier_attrs_avp, val)!=0) {
			LM_ERR("failed to insert carrier attrs avp\n");
			goto error;
		}
	}

	pkg_free(ruri->s);
	return 0;
error:
	pkg_free(ruri->s);
	return -1;
}


static inline int is_dst_in_list(void* dst, pgw_list_t *list, unsigned short len)
{
	unsigned short i;

	if (list==NULL)
		return 1;
	for( i=0 ; i<len ; i++ ) {
		if (dst==(void*)list[i].dst.gw)
			return 1;
	}
	return 0;
}


static int do_routing(struct sip_msg* msg, dr_group_t *drg, int flags,
														gparam_t* whitelist)
{
	unsigned short dsts_idx[DR_MAX_GWLIST];
	unsigned short carrier_idx[DR_MAX_GWLIST];
	struct to_body  *from;
	struct sip_uri  uri;
	rt_info_t  *rt_info;
	pv_value_t pv_val;
	struct usr_avp *avp, *avp_prefix=NULL, *avp_index=NULL;
	str parsed_whitelist;
	pgw_list_t *dst, *cdst;
	pgw_list_t *wl_list;
	unsigned int prefix_len;
	unsigned int rule_idx;
	unsigned short wl_len;
	str username;
	int grp_id;
	int i, j, n;
	int_str val;
	str ruri;
	str next_carrier_attrs = {NULL, 0};
	str next_gw_attrs = {NULL, 0};
	int ret;
	char tmp;
	char *ruri_buf;

	ret = -1;
	ruri_buf = NULL;
	wl_list = NULL;
	rt_info = NULL;

	/* allow no GWs if we're only trying to use DR for checking purposes */
	if ( (*rdata)==0 || ((flags & DR_PARAM_ONLY_CHECK) == 0 && (*rdata)->pgw_l==0 )) {
		LM_DBG("empty routing table\n");
		goto error1;
	}

	/* do some cleanup first (if without the CHECK_ONLY flag) */
	if ((flags & DR_PARAM_ONLY_CHECK) == 0) {
		destroy_avps( 0, ruri_avp, 1);
		destroy_avps( 0, gw_id_avp, 1);
		destroy_avps( 0, gw_sock_avp, 1);
		destroy_avps( 0, rule_attrs_avp, 1);
		destroy_avps( 0, gw_attrs_avp, 1);
		destroy_avps( 0, carrier_attrs_avp, 1);

		if (gw_priprefix_avp!=-1)
			destroy_avps( 0, gw_priprefix_avp, 1);
		if (rule_id_avp!=-1)
			destroy_avps( 0, rule_id_avp, 1);
		if (rule_prefix_avp!=-1)
			destroy_avps( 0, rule_prefix_avp, 1);
	}

	if ( !(flags & DR_PARAM_INTERNAL_TRIGGERED) ) {
		/* not internally triggered, so get data from SIP msg */

		/* get user's routing group */
		if(drg==NULL)
		{
			/* get the username from FROM_HDR */
			if (parse_from_header(msg)!=0) {
				LM_ERR("unable to parse from hdr\n");
				goto error1;
			}
			from = (struct to_body*)msg->from->parsed;
			/* parse uri */
			if (parse_uri( from->uri.s, from->uri.len, &uri)!=0) {
				LM_ERR("unable to parse from uri\n");
				goto error1;
			}

			grp_id = get_group_id( &uri );
			if (grp_id<0) {
				LM_ERR("failed to get group id\n");
				goto error1;
			}
		} else {
			if(drg->type==0)
				grp_id = (int)drg->u.grp_id;
			else if(drg->type==1) {
				grp_id = 0; /* call get avp here */
				if((avp=search_first_avp( 0, drg->u.avp_name, &val, 0))==NULL ||
				(avp->flags&AVP_VAL_STR) ) {
					LM_ERR( "failed to get group id\n");
					goto error1;
				}
				grp_id = val.n;
			} else
				grp_id = 0;
		}

		/* get the number/RURI and make a copy of it */
		ruri = *GET_RURI(msg);
		ruri_buf = (char*)pkg_malloc(ruri.len);
		if (ruri_buf==NULL) {
			LM_ERR("no more pkg mem (needed %d)\n",ruri.len);
			goto error1;
		}
		memcpy(ruri_buf, ruri.s, ruri.len);
		ruri.s = ruri_buf;
		/* parse ruri */
		if (parse_uri( ruri.s, ruri.len, &uri)!=0) {
			LM_ERR("unable to parse RURI\n");
			goto error1;
		}
		username = uri.user;

		/* search all rules on dr tree (start from beginning) */
		rule_idx = 0;

	} else {

		/* resume index on the rule under same prefix */
		avp_index = search_first_avp( 0, avpID_store_index, &val, 0);
		if (avp_index==NULL) {
			LM_ERR("Cannot find index AVP during a fallback\n");
			goto error1;
		}
		rule_idx = val.n;

		/* prefix to resume with */
		avp_prefix = search_first_avp( AVP_VAL_STR, avpID_store_prefix, &val, 0);
		if (avp_prefix==NULL) {
			LM_ERR("Cannot find prefix AVP during a fallback\n");
			goto error1;
		}
		username = val.s;
		/* still something to look for ? */
		if (username.len==0) return -1;

		/* original RURI to be used when building RURIs for new attempts */
		if (search_first_avp( AVP_VAL_STR, avpID_store_ruri, &val, 0)==NULL) {
			LM_ERR("Cannot find ruri AVP during a fallback\n");
			goto error1;
		}
		if (parse_uri( val.s.s, val.s.len, &uri)!=0) {
			LM_ERR("unable to parse RURI from AVP\n");
			goto error1;
		}

		grp_id = (int)drg->u.grp_id;
		ruri.s = NULL; ruri.len = 0;
	}


	LM_DBG("using dr group %d, rule_idx %d, username %.*s\n",
		grp_id,rule_idx,username.len,username.s);

	/* ref the data for reading */
	lock_start_read( ref_lock );

search_again:

	if (rt_info) {
		/* we are here because of the "search_again", on a
		   sequential retry based on rule FALL BACK */
		/* => force fallback, either on next rule, either on shorter prefix */
		username.len = prefix_len -(rule_idx?0:1);
		LM_DBG("doing internal fallback, prefix_len=%d,rule_idx=%d\n",
			username.len, rule_idx);
		if (username.len==0 && rule_idx==0) {
			/* disable failover as nothing left */
			flags = flags & ~DR_PARAM_RULE_FALLBACK;
			goto error2;
		}
	}

	/* search a prefix */
	rt_info = get_prefix( (*rdata)->pt, &username , (unsigned int)grp_id,
			&prefix_len, &rule_idx);

	if (flags & DR_PARAM_STRICT_LEN) {
		if (rt_info==NULL || prefix_len!=username.len)
			goto error2;
	}

	if (rt_info==0) {
		LM_DBG("no matching for prefix \"%.*s\"\n",
			username.len, username.s);
		/* try prefixless rules */
		rt_info = check_rt( &(*rdata)->noprefix, (unsigned int)grp_id);
		if (rt_info==0) {
			LM_DBG("no prefixless matching for "
				"grp %d\n", grp_id);
			goto error2;
		}
		prefix_len = 0;
	}

	if (rt_info->route_idx>0 && rt_info->route_idx<RT_NO) {
		ret = run_top_route( rlist[rt_info->route_idx].a, msg );
		if (ret&ACT_FL_DROP) {
			/* drop the action */
			LM_DBG("script route %s drops routing "
				"by %d\n", rlist[rt_info->route_idx].name, ret);
			ret = -1;
			goto error2;
		}
	}

	/* if only checking the prefix, we are done here */
	if (flags & DR_PARAM_ONLY_CHECK)
		goto no_gws;

	/* do we have anything left to failover to ? */
	if (prefix_len==0 && rule_idx==0)
		/* disable failover as nothing left */
		flags = flags & ~DR_PARAM_RULE_FALLBACK;

	/* START EVALUATING THE DESTINATIONS FROM LIST ! */
	n = 0;

	if (rt_info->pgwl==NULL) {
		LM_INFO("no destination for dr group %d, rule_idx %d, username %.*s\n",
			grp_id,rule_idx,username.len,username.s);
		if ( flags & DR_PARAM_RULE_FALLBACK )
			goto search_again;
		goto error2;
	}

	/* sort the destination elements in the rule */
	i = sort_rt_dst(rt_info->pgwl, rt_info->pgwa_len,
		flags&DR_PARAM_USE_WEIGTH, dsts_idx);
	if (i!=0) {
		LM_ERR("failed to sort destinations in rule\n");
		goto error2;
	}

	/* evaluate and parse the whitelist of GWs/CARRIERs, if provided and
	   if the first time here */
	if (whitelist && wl_list==NULL) {
		if (fixup_get_svalue(msg, whitelist, &parsed_whitelist)!=0) {
			LM_ERR("failed to evaluate whitelist-> ignoring...\n");
		} else {
			tmp = parsed_whitelist.s[parsed_whitelist.len];
			parsed_whitelist.s[parsed_whitelist.len] = 0;
			if (parse_destination_list( *rdata, parsed_whitelist.s,
			&wl_list, &wl_len, 1)!=0) {
				LM_ERR("invalid format in whitelist-> ignoring...\n");
				wl_list = NULL;
			}
			parsed_whitelist.s[parsed_whitelist.len] = tmp;
		}
	}

	/* iterate through the list, skip the disabled destination */
	for ( i=0 ; i<rt_info->pgwa_len ; i++ ) {

		dst = &rt_info->pgwl[dsts_idx[i]];

		/* is the destination carrier or gateway ? */
		if (dst->is_carrier) {

			/* is carrier turned off ? */
			if( dst->dst.carrier->flags & DR_CR_FLAG_IS_OFF
			|| !is_dst_in_list( (void*)dst, wl_list, wl_len) )
				continue;

			/* any gws for this carrier ? */
			if( dst->dst.carrier->pgwl==NULL )
				continue;

			/* sort the gws of the carrier */
			j = sort_rt_dst(dst->dst.carrier->pgwl, dst->dst.carrier->pgwa_len,
				dst->dst.carrier->flags&DR_CR_FLAG_WEIGHT, carrier_idx);
			if (j!=0) {
				LM_ERR("failed to sort gws for carrier <%.*s>, skipping\n",
					dst->dst.carrier->id.len, dst->dst.carrier->id.s);
				continue;
			}

			/* iterate through the list of GWs provided by carrier */
			for ( j=0 ; j<dst->dst.carrier->pgwa_len ; j++ ) {

				cdst = &dst->dst.carrier->pgwl[carrier_idx[j]];

				/* is gateway disabled ? */
				if (cdst->dst.gw->flags & DR_DST_STAT_DSBL_FLAG ) {
					/*ignore it*/
				} else {
					/* add gateway to usage list */
					if ( push_gw_for_usage(msg, &uri, cdst->dst.gw ,
					&dst->dst.carrier->id, &dst->dst.carrier->attrs, n ) ) {
						LM_ERR("failed to use gw <%.*s>, skipping\n",
							cdst->dst.gw->id.len, cdst->dst.gw->id.s);
					} else {
						n++;

						/* only export the top-most carrier/gw
						 * attributes in the script */
						if (n == 1) {
							next_carrier_attrs = dst->dst.carrier->attrs;
							next_gw_attrs = cdst->dst.gw->attrs;
						}

						/* use only first valid GW */
						if (dst->dst.carrier->flags&DR_CR_FLAG_FIRST)
							break;
					}
				}

			}

		} else {

			/* is gateway disabled ? */
			if (dst->dst.gw->flags & DR_DST_STAT_DSBL_FLAG
			|| !is_dst_in_list( (void*)dst, wl_list, wl_len) )
				continue;

			/* add gateway to usage list */
			if ( push_gw_for_usage(msg, &uri, dst->dst.gw, NULL, NULL, n) ) {
				LM_ERR("failed to use gw <%.*s>, skipping\n",
					dst->dst.gw->id.len, dst->dst.gw->id.s);
			} else {
				n++;
				/* only export the first gw attributes in the script */
				if (n == 1) {
					next_carrier_attrs.s = NULL;
					next_gw_attrs = dst->dst.gw->attrs;
				}
			}

		}

	}

	if( n < 1) {
		LM_INFO("All the gateways are disabled\n");
		if ( flags & DR_PARAM_RULE_FALLBACK )
			goto search_again;
		goto error2;
	}

	pv_val.flags = PV_VAL_STR;

	if (gw_attrs_spec) {
		pv_val.flags = PV_VAL_STR;
		pv_val.rs = !next_gw_attrs.s ? attrs_empty : next_gw_attrs;
		if (pv_set_value(msg, gw_attrs_spec, 0, &pv_val) != 0) {
			LM_ERR("failed to set value for gateway attrs pvar\n");
			goto error2;
		}
	}

	if (carrier_attrs_spec) {
		pv_val.flags = PV_VAL_STR;
		pv_val.rs = !next_carrier_attrs.s ? attrs_empty : next_carrier_attrs;
		if (pv_set_value(msg, carrier_attrs_spec, 0, &pv_val) != 0) {
			LM_ERR("failed to set value for carrier attrs pvar\n");
			goto error2;
		}
	}

no_gws:
	/* add RULE prefix avp */
	if (rule_prefix_avp!=-1) {
		val.s.s = username.s ;
		val.s.len = prefix_len;
		LM_DBG("setting RULE prefix [%.*s] \n",val.s.len,val.s.s);
		if (add_avp( AVP_VAL_STR, rule_prefix_avp, val)!=0 ) {
			LM_ERR("failed to insert rule prefix avp\n");
			goto error2;
		}
	}

	/* add internal RULE attrs avp if requested at least once in the script */
	if (populate_rule_attrs) {
		val.s = !rt_info->attrs.s ? attrs_empty : rt_info->attrs;
		LM_DBG("setting RULE attr [%.*s] \n", val.s.len, val.s.s);
		if (add_avp( AVP_VAL_STR, rule_attrs_avp, val) != 0) {
			LM_ERR("failed to insert rule attrs avp\n");
			goto error2;
		}

		if (rule_attrs_spec) {
			pv_val.flags = PV_VAL_STR;
			pv_val.rs = val.s;
			if (pv_set_value(msg, rule_attrs_spec, 0, &pv_val) != 0) {
				LM_ERR("failed to set value for rule attrs pvar\n");
				goto error2;
			}
		}
	}

	/* add RULE id avp */
	if (rule_id_avp!=-1) {
		val.n = (int) rt_info->id;
		LM_DBG("setting RULE id [%d] as avp\n",val.n);
		if (add_avp( 0, rule_id_avp, val)!=0 ) {
			LM_ERR("failed to insert rule ids avp\n");
			goto error2;
		}
	}

	/* we are done reading -> unref the data */
	lock_stop_read( ref_lock );

	if ( flags & DR_PARAM_RULE_FALLBACK ) {
		if ( !(flags & DR_PARAM_INTERNAL_TRIGGERED) ) {
			/* first time ? we need to save some date, to be able to
			   do the rule fallback later in "next_gw" */
			LM_DBG("saving rule_idx %d, prefix %.*s\n",rule_idx,
				prefix_len - (rule_idx?0:1), username.s);
			val.n = rule_idx;
			if (add_avp( 0 , avpID_store_index, val) ) {
				LM_ERR("failed to insert index avp for fallback\n");
				flags = flags & ~DR_PARAM_RULE_FALLBACK;
			}
			/* if no rules available on current prefix (index is 0), simply
			   reduce the len of the prefix from start, to lookup another
			   prefix in the DR tree */
			val.s.s = username.s ;
			val.s.len = prefix_len - (rule_idx?0:1);
			if (add_avp( AVP_VAL_STR, avpID_store_prefix, val) ) {
				LM_ERR("failed to insert prefix avp for fallback\n");
				flags = flags & ~DR_PARAM_RULE_FALLBACK;
			}
			/* also store current ruri as we will need it */
			val.s = ruri;
			if (add_avp( AVP_VAL_STR, avpID_store_ruri, val) ) {
				LM_ERR("failed to insert ruri avp for fallback\n");
				flags = flags & ~DR_PARAM_RULE_FALLBACK;
			}
			/* we need to save a some date, to be able to do the rule
			   fallback later in "next_gw" (prefix/index already added) */
			if (wl_list) {
				val.s = parsed_whitelist ;
				val.s.len++; /* we need extra space to place \0 when using */
				if (add_avp( AVP_VAL_STR, avpID_store_whitelist, val) ) {
					LM_ERR("failed to insert whitelist avp for fallback\n");
					flags = flags & ~DR_PARAM_RULE_FALLBACK;
				}
			}
			val.n = grp_id ;
			if (add_avp( 0, avpID_store_group, val) ) {
				LM_ERR("failed to insert group avp for fallback\n");
				flags = flags & ~DR_PARAM_RULE_FALLBACK;
			}
			val.n = flags ;
			if (add_avp( 0, avpID_store_flags, val) ) {
				LM_ERR("failed to insert flags avp for fallback\n");
			}
		} else {
			/* update the fallback coordonats for next resume */
			/* using ugly hack by directly accessing the AVP data in order
			   to perform changes - we want to avoid re-creating the AVP -bogdan */
			avp_index->data = (void *)(long)rule_idx;
			if (rule_idx==0) {
				void *data;
				/* all rules under current prefix used -> reduce the prefix */
				data = (void*)&avp_prefix->data;
				((str*)data)->len = prefix_len-1;
			}
			LM_DBG("updating to %d, prefix %.*s \n",rule_idx,
				prefix_len-(rule_idx?1:0),username.s);
		}
	}

	if (ruri_buf) pkg_free(ruri_buf);
	return 1;
error2:
	/* we are done reading -> unref the data */
	lock_stop_read( ref_lock );
error1:
	if (ruri_buf) pkg_free(ruri_buf);
	return ret;
}


static int route2_carrier(struct sip_msg* msg, char* cr_str,
                          char* gw_att_pv, char* carr_att_pv)
{
	unsigned short carrier_idx[DR_MAX_GWLIST];
	struct sip_uri  uri;
	pgw_list_t *cdst;
	pcr_t *cr;
	pv_value_t pv_val;
	str ruri, id;
	str next_carrier_attrs = {NULL, 0};
	str next_gw_attrs = {NULL, 0};
	int j,n;
	char *ruri_buf= NULL;

	if ( (*rdata)==0 || (*rdata)->pgw_l==0 ) {
		LM_DBG("empty routing table\n");
		return -1;
	}

	/* get the carrier ID */
	if (fixup_get_svalue(msg, (gparam_p)cr_str, &id) != 0) {
		LM_ERR("failed to get string value for carrier ID\n");
		return -1;
	}

	gw_attrs_spec = (pv_spec_p) gw_att_pv;
	carrier_attrs_spec = (pv_spec_p) carr_att_pv;

	/* do some cleanup first */
	destroy_avps( 0, ruri_avp, 1);
	destroy_avps( 0, gw_id_avp, 1);
	destroy_avps( 0, gw_sock_avp, 1);
	destroy_avps( 0, gw_attrs_avp, 1);
	destroy_avps( 0, rule_attrs_avp, 1);
	destroy_avps( 0, carrier_attrs_avp, 1);

	if (gw_priprefix_avp!=-1)
		destroy_avps( 0, gw_priprefix_avp, 1);
	if (rule_id_avp!=-1)
		destroy_avps( 0, rule_id_avp, 1);
	if (rule_prefix_avp!=-1)
		destroy_avps( 0, rule_prefix_avp, 1);

	/* get the RURI */
	ruri = *GET_RURI(msg);
	ruri_buf = (char*)pkg_malloc(ruri.len);
	if (ruri_buf==NULL) {
		LM_ERR("no more pkg mem (needed %d)\n",ruri.len);
		return -1;
	}
	memcpy(ruri_buf, ruri.s, ruri.len);
	ruri.s = ruri_buf;

	/* parse ruri */
	if (parse_uri( ruri.s, ruri.len, &uri)!=0) {
		LM_ERR("unable to parse RURI\n");
		goto error_free;
	}

	/* ref the data for reading */
	lock_start_read( ref_lock );

	cr = get_carrier_by_id( (*rdata)->carriers, &id );
	if (cr==NULL) {
		LM_ERR("carrier <%.*s> was not found\n", id.len, id.s );
		goto error;
	}

	/* is carrier turned off ? */
	if( cr->flags & DR_CR_FLAG_IS_OFF ) {
		LM_NOTICE("routing to disabled carrier <%.*s> failed\n",
			cr->id.len, cr->id.s);
		goto error;
	}

	/* any GWs for the carrier? */
	if (cr->pgwl==NULL)
		goto no_gws;

	/* sort the gws of the carrier */
	j = sort_rt_dst( cr->pgwl, cr->pgwa_len, cr->flags&DR_CR_FLAG_WEIGHT,
		carrier_idx);
	if (j!=0) {
		LM_ERR("failed to sort gws for carrier <%.*s>, skipping\n",
			cr->id.len, cr->id.s);
		goto error;
	}

	/* iterate through the list of GWs provided by carrier */
	for ( j=0,n=0 ; j<cr->pgwa_len ; j++ ) {

		cdst = &cr->pgwl[carrier_idx[j]];

		/* is gateway disabled ? */
		if (cdst->dst.gw->flags & DR_DST_STAT_DSBL_FLAG ) {
			/*ignore it*/
		} else {
			/* add gateway to usage list */
			if ( push_gw_for_usage(msg, &uri, cdst->dst.gw,
			&cr->id, &cr->attrs, n ) ) {
				LM_ERR("failed to use gw <%.*s>, skipping\n",
					cdst->dst.gw->id.len, cdst->dst.gw->id.s);
			} else {
				n++;

				/* only export the top-most carrier/gw
				 * attributes in the script */
				if (n == 1) {
					next_carrier_attrs = cr->attrs;
					next_gw_attrs = cdst->dst.gw->attrs;
				}

				/* use only first valid GW */
				if (cr->flags&DR_CR_FLAG_FIRST)
					break;
			}
		}

	}

	if( n < 1) {
		LM_ERR("All the gateways are disabled\n");
		goto error;
	}

	pv_val.flags = PV_VAL_STR;

	if (gw_attrs_spec) {
		pv_val.flags = PV_VAL_STR;
		pv_val.rs = !next_gw_attrs.s ? attrs_empty : next_gw_attrs;
		if (pv_set_value(msg, gw_attrs_spec, 0, &pv_val) != 0) {
			LM_ERR("failed to set value for gateway attrs pvar\n");
			goto error;
		}
	}

	if (carrier_attrs_spec) {
		pv_val.flags = PV_VAL_STR;
		pv_val.rs = !next_carrier_attrs.s ? attrs_empty : next_carrier_attrs;
		if (pv_set_value(msg, carrier_attrs_spec, 0, &pv_val) != 0) {
			LM_ERR("failed to set value for carrier attrs pvar\n");
			goto error;
		}
	}

no_gws:

	/* we are done reading -> unref the data */
	lock_stop_read( ref_lock );

	if (ruri_buf) pkg_free(ruri_buf);
	return 1;
error:
	/* we are done reading -> unref the data */
	lock_stop_read( ref_lock );
error_free:
	if (ruri_buf) pkg_free(ruri_buf);
	return -1;
}


static int route2_gw(struct sip_msg* msg, char* gw_str, char* gw_att_pv)
{
	struct sip_uri  uri;
	pgw_t *gw;
	pv_value_t pv_val;
	str ruri, ids, id;
	str next_gw_attrs = {NULL, 0};
	char *p,*ruri_buf;
	int idx;

	if ( (*rdata)==0 || (*rdata)->pgw_l==0 ) {
		LM_DBG("empty routing table\n");
		return -1;
	}

	gw_attrs_spec = (pv_spec_p)gw_att_pv;

	/* get the gw ID */
	if (fixup_get_svalue(msg, (gparam_p)gw_str, &ids) != 0) {
		LM_ERR("Invalid pseudo variable!\n");
		return -1;
	}
	str_trim_spaces_lr(ids);
	if (ids.s[0] == ',' || ids.s[ids.len-1] == ',') {
		LM_ERR("Empty slot\n");
		return -1;
	}

	/* get the RURI */
	ruri = *GET_RURI(msg);
	ruri_buf = (char*)pkg_malloc(ruri.len);
	if (ruri_buf==NULL) {
		LM_ERR("no more pkg mem (needed %d)\n",ruri.len);
		return -1;
	}
	memcpy(ruri_buf, ruri.s, ruri.len);
	ruri.s = ruri_buf;

	/* parse ruri */
	if (parse_uri( ruri.s, ruri.len, &uri)!=0) {
		LM_ERR("unable to parse RURI\n");
		goto error_free;
	}

	/* ref the data for reading */
	lock_start_read( ref_lock );


	idx = 0;
	do {
		id.s = ids.s;
		p = q_memchr( ids.s , ',' , ids.len);
		id.len = (p==NULL)?ids.len:(p-ids.s);

		ids.len -= id.len + (p?1:0);
		ids.s += id.len + (p?1:0);

		str_trim_spaces_lr(id);
		if (id.len<=0) {
			LM_ERR("empty slot\n");
			lock_stop_read( ref_lock );
			goto error_free;
		} else {
			LM_DBG("found and looking for gw id <%.*s>,len=%d\n",id.len, id.s, id.len);
			gw = get_gw_by_id( (*rdata)->pgw_l, &id );
			if (gw==NULL) {
				LM_ERR("no GW found with ID <%.*s> -> ignorring\n", id.len, id.s);
			} else if ( push_gw_for_usage(msg, &uri, gw, NULL, NULL, idx ) ) {
				LM_ERR("failed to use gw <%.*s>, skipping\n",
					gw->id.len, gw->id.s);
			} else {
				idx++;

				/* only export the top-most gw attributes in the script */
				if (idx == 1)
					next_gw_attrs = gw->attrs;
			}
		}
	} while(ids.len>0);

	/* we are done reading -> unref the data */
	lock_stop_read( ref_lock );

	if ( idx==0 ) {
		LM_ERR("no GW added at all\n");
		goto error_free;
	}

	if (gw_attrs_spec) {
		pv_val.flags = PV_VAL_STR;
		pv_val.rs = !next_gw_attrs.s ? attrs_empty : next_gw_attrs;
		if (pv_set_value(msg, gw_attrs_spec, 0, &pv_val) != 0) {
			LM_ERR("failed to set value for gateway attrs pvar\n");
			goto error_free;
		}
	}

	if (ruri_buf) pkg_free(ruri_buf);
	return 1;
error_free:
	if (ruri_buf) pkg_free(ruri_buf);
	return -1;
}


static int fixup_do_routing(void** param, int param_no)
{
	char *s;
	dr_group_t *drg;
	pv_spec_t avp_spec;
	unsigned short dummy;
	str r;

	s = (char*)*param;

	switch (param_no) {
	/* group ID */
	case 1:
		drg = (dr_group_t*)pkg_malloc(sizeof(dr_group_t));
		if(drg==NULL) {
			LM_ERR( "no more memory\n");
			return E_OUT_OF_MEM;
		}
		memset(drg, 0, sizeof(dr_group_t));

		if ( s==NULL || s[0]==0 ) {
			pkg_free(drg);
			return 0;
		}

		if (s[0]=='$') {
			/* param is a PV (AVP only supported) */
			r.s = s;
			r.len = strlen(s);
			if (pv_parse_spec( &r, &avp_spec)==0
			|| avp_spec.type!=PVT_AVP) {
				LM_ERR("malformed or non AVP %s AVP definition\n", s);
				return E_CFG;
			}

			if( pv_get_avp_name(0, &(avp_spec.pvp), &drg->u.avp_name,
			&dummy )!=0) {
				LM_ERR("[%s]- invalid AVP definition\n", s);
				return E_CFG;
			}
			drg->type = 1;
			/* do not free the param as the AVP spec may point inside
			   this string*/
		} else {
			while(s && *s) {
				if(*s<'0' || *s>'9') {
					LM_ERR( "bad number\n");
					return E_UNSPEC;
				}
				drg->u.grp_id = (drg->u.grp_id)*10+(*s-'0');
				s++;
			}
			pkg_free(*param);
		}
		*param = (void*)drg;
		return 0;

	/* string with flags */
	case 2:
		return fixup_sgp(param);

	/* white list of GWs/Carriers */
	case 3:
		return fixup_spve(param);

	/* rule | gateway | carrier attributes output pvars */
	case 4:
		populate_rule_attrs = 1;
		return fixup_pvar(param);
	case 5:
		populate_gw_attrs = 1;
		return fixup_pvar(param);
	case 6:
		populate_carrier_attrs = 1;
		return fixup_pvar(param);
	}

	return -1;
}

static int fixup_next_gw( void** param, int param_no)
{
	switch (param_no) {
	/* rule attrs pvar */
	case 1:
		populate_rule_attrs = 1;
		return fixup_pvar(param);

	/* gateway attrs pvar */
	case 2:
		populate_gw_attrs = 1;
		return fixup_pvar(param);

	/* carrier attrs pvar */
	case 3:
		populate_carrier_attrs = 1;
		return fixup_pvar(param);
	}

	return -1;
}


static int fixup_from_gw( void** param, int param_no)
{
	switch (param_no) {
	/* GW type*/
	case 1:
		return fixup_sint(param);

	/* GW ops */
	case 2:
		return fixup_spve(param);

	/* ATTRS pseudo-var */
	case 3:
		return fixup_pvar(param);
	}

	return -1;
}


static int fixup_is_gw( void** param, int param_no)
{
	switch (param_no) {
	/* SIP URI pseudo-var */
	case 1:
		return fixup_pvar(param);

	/* GW type*/
	case 2:
		return fixup_sint(param);

	/* GW ops */
	case 3:
		return fixup_spve(param);

	/* ATTRS pseudo-var */
	case 4:
		return fixup_pvar(param);
	}

	return -1;
}


static int fixup_route2_carrier( void** param, int param_no)
{
	switch (param_no) {

	/* carrier name string */
	case 1:
		return fixup_sgp(param);

	/* gateway attrs pvar */
	case 2:
		populate_gw_attrs = 1;
		return fixup_pvar(param);

	/* carrier attrs pvar */
	case 3:
		populate_carrier_attrs = 1;
		return fixup_pvar(param);
	}

	return -1;
}


static int fixup_route2_gw( void** param, int param_no)
{
	switch (param_no) {

	/* gateway / gateways (csv) */
	case 1:
		return fixup_sgp(param);

	/* gateway attrs pvar */
	case 2:
		populate_gw_attrs = 1;
		return fixup_pvar(param);
	}

	return -1;
}

static int strip_username(struct sip_msg* msg, int strip)
{
	struct action act;

	act.type = STRIP_T;
	act.elem[0].type = NUMBER_ST;
	act.elem[0].u.number = strip;
	act.next = 0;

	if (do_action(&act, msg) < 0) {
		LM_ERR( "Error in do_action\n");
		return -1;
	}
	return 0;
}


static int prefix_username(struct sip_msg* msg, str *pri)
{
	struct action act;

	act.type = PREFIX_T;
	act.elem[0].type = STR_ST;
	act.elem[0].u.s = *pri;
	act.next = 0;

	if (do_action(&act, msg) < 0) {
		LM_ERR( "Error in do_action\n");
		return -1;
	}
	return 0;
}


static int gw_matches_ip(pgw_t *pgwa, struct ip_addr *ip, unsigned short port)
{
	unsigned short j;
	for ( j=0 ; j<pgwa->ips_no ; j++)
		if ( (pgwa->ports[j]==0 || port==0 || pgwa->ports[j]==port) &&
		ip_addr_cmp( &pgwa->ips[j], ip) ) return 1;
	return 0;
}


#define DR_IFG_STRIP_FLAG      (1<<0)
#define DR_IFG_PREFIX_FLAG     (1<<1)
#define DR_IFG_IDS_FLAG        (1<<3)
#define DR_IFG_IGNOREPORT_FLAG (1<<4)
#define DR_IFG_CARRIERID_FLAG  (1<<5)


/*
 * Checks if a given IP + PORT is a GW; tests the TYPE too
 * INTERNAL FUNCTION
 */
static int _is_dr_gw(struct sip_msg* msg, char* flags_pv,
							int type, struct ip_addr *ip, unsigned int port)
{
	pgw_t *pgwa = NULL;
	pcr_t *pcr = NULL;
	pv_value_t pv_val;
	int flags = 0;
	str flags_s;
	int_str val;
	int i;

	if(rdata==NULL || *rdata==NULL || msg==NULL)
		return -1;

	if (flags_pv && flags_pv[0]) {
		if (fixup_get_svalue( msg, (gparam_p)flags_pv, &flags_s)!=0) {
			LM_ERR("invalid flags parameter");
			return -1;
		}
		for( i=0 ; i < flags_s.len ; i++ ) {
			switch (flags_s.s[i]) {
				case 's': flags |= DR_IFG_STRIP_FLAG; break;
				case 'p': flags |= DR_IFG_PREFIX_FLAG; break;
				case 'i': flags |= DR_IFG_IDS_FLAG; break;
				case 'n': flags |= DR_IFG_IGNOREPORT_FLAG; break;
				case 'c': flags |= DR_IFG_CARRIERID_FLAG; break;
				default: LM_WARN("unsuported flag %c \n",flags_s.s[i]);
			}
		}
	}

	pgwa = (*rdata)->pgw_l;
	while(pgwa) {
		if( (type<0 || type==pgwa->type) &&
		gw_matches_ip( pgwa, ip, (flags&DR_IFG_IGNOREPORT_FLAG)?0:port ) ) {
			/* strip ? */
			if ( (flags&DR_IFG_STRIP_FLAG) && pgwa->strip>0)
				strip_username(msg, pgwa->strip);
			/* prefix ? */
			if ( (flags&DR_IFG_PREFIX_FLAG) && pgwa->pri.len>0) {
				/* pri prefix ? */
				if (gw_priprefix_avp!=-1) {
					val.s = pgwa->pri.s ? pgwa->pri : attrs_empty ;
					if (add_avp(AVP_VAL_STR, gw_priprefix_avp, val)!=0)
						LM_ERR("failed to insert GW pri prefix avp\n");
				}
				prefix_username(msg, &pgwa->pri);
			}

			/* attrs ? */
			if (gw_attrs_spec) {
				pv_val.flags = PV_VAL_STR;
				pv_val.rs = pgwa->attrs.s ? pgwa->attrs : attrs_empty;
				if (pv_set_value(msg, gw_attrs_spec, 0, &pv_val) != 0)
					LM_ERR("failed to set value for GW attrs pvar\n");
			}

			if ( flags & DR_IFG_IDS_FLAG ) {
				val.s = pgwa->id;
				if (add_avp(AVP_VAL_STR, gw_id_avp, val)!=0)
					LM_ERR("failed to insert GW attrs avp\n");
			}

			if ( flags & DR_IFG_CARRIERID_FLAG ) {
				/* lookup first carrier that contains this gw */
				for (pcr=(*rdata)->carriers;pcr;pcr=pcr->next) {
					for (i=0;i<pcr->pgwa_len;i++) {
						if (pcr->pgwl[i].is_carrier == 0 &&
						pcr->pgwl[i].dst.gw == pgwa ) {
							/* found our carrier */
							if (carrier_id_avp!=-1) {
								val.s = pcr->id;
								if (add_avp_last(AVP_VAL_STR, carrier_id_avp, val)!=0) {
									LM_ERR("failed to add carrier id AVP\n");
								}
							}
							goto end;
						}
					}
				}
			}
end:
			return 1;
		}
		pgwa = pgwa->next;
	}

	return -1;
}


/*
 * Checks if a given src IP and PORT is a GW; no TYPE, no FLAGS
 */
static int is_from_gw_0(struct sip_msg* msg)
{
	return _is_dr_gw( msg, NULL, -1, &msg->rcv.src_ip , msg->rcv.src_port);
}


/*
 * Checks if a given src IP and PORT is a GW; tests the TYPE too, no FLAGS
 */
static int is_from_gw_1(struct sip_msg* msg, char* type_s)
{
	return _is_dr_gw(msg, NULL, (!type_s ? -1 : (int)(long)type_s),
	                 &msg->rcv.src_ip , msg->rcv.src_port);
}


/*
 * Checks if a given src IP and PORT is a GW; tests the TYPE too
 */
static int is_from_gw_2(struct sip_msg* msg, char* type_s, char* flags_pv,
                        char* gw_att)
{
	gw_attrs_spec = (pv_spec_p)gw_att;

	return _is_dr_gw( msg, flags_pv,
			(int)(long)type_s, &msg->rcv.src_ip , msg->rcv.src_port);
}


/*
 * Checks if a given SIP URI is a GW; tests the TYPE too
 * INTERNAL FUNCTION
 */
static int _is_dr_uri_gw(struct sip_msg* msg, char* flags_pv, int type, str *uri)
{
	struct sip_uri puri;
	struct hostent* he;
	struct ip_addr ip;

	memset( &puri, 0, sizeof(struct sip_uri));
	if (parse_uri(uri->s, uri->len, &puri)!=0) {
		LM_ERR("invalid sip uri <%.*s>\n", uri->len, uri->s);
		return -1;
	}

	he = sip_resolvehost(&puri.host, &puri.port_no, &puri.proto,
		(puri.type==SIPS_URI_T), 0);
	if (he==0) {
		LM_DBG("resolve_host(%.*s) failure\n", puri.host.len, puri.host.s);
		return -1;
	}

	/* extract the first ip */
	memset(&ip,0,sizeof(struct ip_addr));
	hostent2ip_addr( &ip, he, 0);

	return _is_dr_gw( msg, flags_pv, type, &ip , puri.port_no);
}


/*
 * Checks if RURI is a GW ; tests the TYPE too
 */
static int goes_to_gw_1(struct sip_msg* msg, char* _type, char* flags_pv,
                        char* gw_att)
{
	gw_attrs_spec = (pv_spec_p)gw_att;

	return _is_dr_uri_gw(msg, flags_pv, (!_type ? -1 : (int)(long)_type),
	                     GET_NEXT_HOP(msg));
}


/*
 * Checks if RURI is a GW; not TYPE check
 */
static int goes_to_gw_0(struct sip_msg* msg)
{
	return goes_to_gw_1(msg, (char *)-1, NULL, NULL);
}


/*
 * Checks if a variable (containing a SIP URI) is a GW; tests the TYPE too
 */
static int dr_is_gw(struct sip_msg* msg, char* src_pv, char* type_s,
                    char* flags_pv, char* gw_att)
{
	pv_value_t src;

	if ( pv_get_spec_value(msg, (pv_spec_p)src_pv, &src)!=0 || (src.flags&PV_VAL_STR)==0 || src.rs.len<=0) {
		LM_ERR("failed to get string value for src\n");
		return -1;
	}

	gw_attrs_spec = (pv_spec_p)gw_att;

	return _is_dr_uri_gw( msg, flags_pv, (int)(long)type_s, &src.rs );
}


static struct mi_root* mi_dr_gw_status(struct mi_root *cmd, void *param)
{
	struct mi_root *rpl_tree;
	struct mi_node *node;
	struct mi_attr *attr;
	unsigned int stat;
	pgw_t *gw;
	str *id;
	int old_flags;

	node = cmd->node.kids;

	lock_start_read( ref_lock );

	if (rdata==NULL || *rdata==NULL) {
		rpl_tree = init_mi_tree( 404, MI_SSTR("No Data available yet"));
		goto done;
	}

	if (node==NULL) {
		/* no GW specified, list all of them */
		rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
		if (rpl_tree==NULL)
			goto error;
		rpl_tree->node.flags |= MI_IS_ARRAY;

		for( gw=(*rdata)->pgw_l ; gw ; gw=gw->next ) {
			node = add_mi_node_child( &rpl_tree->node, MI_DUP_VALUE,
				"ID", 2, gw->id.s, gw->id.len);
			if (node==NULL) goto error;
			attr = add_mi_attr( node, MI_DUP_VALUE, "IP" , 2,
				gw->ip_str.s, gw->ip_str.len);
			if (attr==NULL) goto error;
			attr = add_mi_attr( node, 0, "Enabled", 7,
				(gw->flags&DR_DST_STAT_DSBL_FLAG)?"no ":"yes", 3);
			if (attr==NULL) goto error;
		}

		goto done;
	}

	/* GW ID (param 1) */
	id =  &node->value;

	/* search for the Gw */
	gw = get_gw_by_id( (*rdata)->pgw_l, id);
	if (gw==NULL) {
		rpl_tree = init_mi_tree( 404, MI_SSTR("GW ID not found"));
		goto done;
	}

	/* status (param 2) */
	node = node->next;
	if (node == NULL) {

		/* no status provided -> return the internal one */
		rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
		if (rpl_tree==NULL)
			goto error;
		node = add_mi_node_child( &rpl_tree->node, 0, "Enabled", 7,
			(gw->flags&DR_DST_STAT_DSBL_FLAG)?"no ":"yes", 3);
		if (node==NULL)
			goto error;

		goto done;

	}

	/* set the status */
	if (node->next) {
		rpl_tree = init_mi_tree( 400,
			MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);
		goto done;
	}
	if (str2int( &node->value, &stat) < 0) {
		rpl_tree = init_mi_tree( 400, MI_SSTR(MI_BAD_PARM_S));
		goto done;
	}
	/* set the disable/enable */
	old_flags = gw->flags;
	if (stat) {
		gw->flags &= ~ (DR_DST_STAT_DSBL_FLAG|DR_DST_STAT_NOEN_FLAG);
	} else {
		gw->flags |= DR_DST_STAT_DSBL_FLAG|DR_DST_STAT_NOEN_FLAG;
	}
	if (old_flags!=gw->flags)
		gw->flags |= DR_DST_STAT_DIRT_FLAG;

	rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);

done:
	lock_stop_read( ref_lock );
	return rpl_tree;
error:
	lock_stop_read( ref_lock );
	if(rpl_tree) free_mi_tree(rpl_tree);
	return NULL;
}


static struct mi_root* mi_dr_cr_status(struct mi_root *cmd, void *param)
{
	struct mi_root *rpl_tree;
	struct mi_node *node;
	struct mi_attr *attr;
	unsigned int stat;
	pcr_t *cr;
	str *id;
	int old_flags;

	node = cmd->node.kids;

	lock_start_read( ref_lock );

	if (rdata==NULL || *rdata==NULL) {
		rpl_tree = init_mi_tree( 404, MI_SSTR("No Data available yet"));
		goto done;
	}

	if (node==NULL) {
		/* no carrier specified, list all of them */
		rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
		if (rpl_tree==NULL)
			goto error;
		rpl_tree->node.flags |= MI_IS_ARRAY;

		for( cr=(*rdata)->carriers ; cr ; cr=cr->next ) {
			node = add_mi_node_child( &rpl_tree->node, MI_DUP_VALUE,
				"ID", 2, cr->id.s, cr->id.len);
			if (node==NULL) goto error;
			attr = add_mi_attr( node, 0, "Enabled", 7,
				(cr->flags&DR_CR_FLAG_IS_OFF)?"no ":"yes", 3);
			if (attr==NULL) goto error;
		}

		goto done;
	}

	/* GW ID (param 1) */
	id =  &node->value;

	/* search for the Carrier */
	cr = get_carrier_by_id( (*rdata)->carriers, id);
	if (cr==NULL) {
		rpl_tree = init_mi_tree( 404, MI_SSTR("Carrier ID not found"));
		goto done;
	}

	/* status (param 2) */
	node = node->next;
	if (node == NULL) {

		/* no status provided -> return the internal one */
		rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);
		if (rpl_tree==NULL)
			goto error;
		node = add_mi_node_child( &rpl_tree->node, 0, "Enabled", 7,
			(cr->flags&DR_CR_FLAG_IS_OFF)?"no ":"yes", 3);
		if (node==NULL)
			goto error;

		goto done;

	}

	/* set the status */
	if (node->next) {
		rpl_tree = init_mi_tree( 400,
			MI_MISSING_PARM_S, MI_MISSING_PARM_LEN);
		goto done;
	}
	if (str2int( &node->value, &stat) < 0) {
		rpl_tree = init_mi_tree( 400, MI_SSTR(MI_BAD_PARM_S));
		goto done;
	}
	/* set the disable/enable */
	old_flags = cr->flags;
	if (stat) {
		cr->flags &= ~ (DR_CR_FLAG_IS_OFF);
	} else {
		cr->flags |= DR_CR_FLAG_IS_OFF;
	}
	if (old_flags!=cr->flags)
		cr->flags |= DR_CR_FLAG_DIRTY;

	rpl_tree = init_mi_tree( 200, MI_OK_S, MI_OK_LEN);

done:
	lock_stop_read( ref_lock );
	return rpl_tree;
error:
	lock_stop_read( ref_lock );
	if(rpl_tree) free_mi_tree(rpl_tree);
	return NULL;
}

