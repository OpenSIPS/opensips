/*
 * call center module - call queuing and distribution
 *
 * Copyright (C) 2014 OpenSIPS Solutions
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
 */



#ifndef CC_CC_DB_H_
#define CC_CC_DB_H_

#include "../../str.h"
#include "cc_data.h"


#define CC_FLOW_TABLE_NAME "cc_flows"
#define CC_FLOW_TABLE_VERSION  1
#define CCF_FLOWID_COL "flowid"
#define CCF_PRIORITY_ID_COL "priority"
#define CCF_SKILL_COL "skill"
#define CCF_CID_COL "prependcid"
#define CCF_WELCOME_COL "message_welcome"
#define CCF_M_QUEUE_COL "message_queue"

#define CC_AGENT_TABLE_NAME "cc_agents"
#define CC_AGENT_TABLE_VERSION  1
#define CCA_AGENTID_COL "agentid"
#define CCA_LOCATION_ID_COL "location"
#define CCA_SKILLS_COL "skills"
#define CCA_LOGSTATE_COL "logstate"
#define CCA_LASTCALLEND_COL "last_call_end"

#define CC_GLOBALS_TABLE_NAME "cc_globals"
#define CC_GLOBALS_TABLE_VERSION  1
#define CCG_NAME_COL "name"
#define CCG_VALUE_COL "value"

#define CC_CDRS_TABLE_NAME "cc_cdrs"
#define CCC_CALLER_COL "caller"
#define CCC_RECV_TIME_COL "received_timestamp"
#define CCC_WAIT_TIME_COL "wait_time"
#define CCC_TALK_TIME_COL "talk_time"
#define CCC_PICKUP_TIME_COL "pickup_time"
#define CCC_FLOW_ID_COL "flow_id"
#define CCC_AGENT_ID_COL "agent_id"
#define CCC_CC_ID_COL "callcenter_id"
#define CCC_TYPE_COL "call_type"
#define CCC_REJECTED_COL "rejected"
#define CCC_FSTATS_COL "fstats"
#define CCC_CID_COL "cid"

#define CC_CALLS_TABLE_NAME "cc_calls"
#define CCQ_STATE_COL       "state"
#define CCQ_IGCBACK_COL     "ig_cback"
#define CCQ_NOREJ_COL       "no_rej"
#define CCQ_SETUP_TIME_COL  "setup_time"
#define CCQ_ETA_COL         "eta"
#define CCQ_LAST_START_COL  "last_start"
#define CCQ_RECV_TIME_COL   "recv_time"
#define CCQ_CALLER_DN_COL   "caller_dn"
#define CCQ_CALLER_UN_COL   "caller_un"
#define CCQ_B2BUAID_COL     "b2buaid"
#define CCQ_FLOW_COL        "flow"
#define CCQ_AGENT_COL       "agent"
#define CCQ_QID_COL         "qid"

int init_cc_db(const str *db_url);
int init_cc_acc_db(const str *acc_db_url);

int cc_connect_db(const str *db_url);
int cc_connect_acc_db(const str *acc_db_url);

void cc_close_db(void);

int cc_load_db_data( struct cc_data *data);

int cc_write_cdr( str *un, str *fid, str *aid, int type,
		int rt, int wt, int tt , int pt, int rej, int fst, int cid);

int prepare_cdr(struct cc_call *call, str *un, str *fid , str *aid);

int cc_db_insert_call(struct cc_call *call);
int cc_db_update_call(struct cc_call *call);
int cc_db_delete_call(struct cc_call *call);
int cc_db_restore_calls( struct cc_data *data);
void cc_db_update_agent_end_call(struct cc_agent* agent);
int b2bl_callback_customer(b2bl_cb_params_t *params, unsigned int event);
int b2bl_callback_agent(b2bl_cb_params_t *params, unsigned int event);

#endif
