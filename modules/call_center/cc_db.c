/*
 * call center module - call queuing and distribution
 *
 * Copyright (C) 2014-2020 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */




#include "../../globals.h"
#include "../../db/db.h"
#include "../../timer.h"
#include "../b2b_logic/b2b_load.h"
#include "cc_db.h"


#define CC_FLOW_TABLE_NAME "cc_flows"
#define CC_FLOW_TABLE_VERSION  2
#define CCF_FLOWID_COL "flowid"
#define CCF_PRIORITY_ID_COL "priority"
#define CCF_SKILL_COL "skill"
#define CCF_CID_COL "prependcid"
#define CCF_MAX_WRAPUP_COL "max_wrapup_time"
#define CCF_DISSUADING_HANGUP_COL "dissuading_hangup"
#define CCF_DISSUADING_ONHOLD_TH_COL "dissuading_onhold_th"
#define CCF_DISSUADING_EWT_TH_COL "dissuading_ewt_th"
#define CCF_DISSUADING_QSIZE_TH_COL "dissuading_qsize_th"
#define CCF_WELCOME_COL "message_welcome"
#define CCF_M_QUEUE_COL "message_queue"
#define CCF_M_DISSUADING_COL "message_dissuading"
#define CCF_M_FLOW_ID_COL "message_flow_id"

#define CC_AGENT_TABLE_NAME "cc_agents"
#define CC_AGENT_TABLE_VERSION  2
#define CCA_AGENTID_COL "agentid"
#define CCA_LOCATION_ID_COL "location"
#define CCA_SKILLS_COL "skills"
#define CCA_LOGSTATE_COL "logstate"
#define CCA_WRAPUPEND_COL "wrapup_end_time"
#define CCA_WRAPUPTIME_COL "wrapup_time"

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
#define CCQ_PARAM_COL       "script_param"
#define CCQ_QID_COL         "qid"

str cc_flow_table_name			=	str_init(CC_FLOW_TABLE_NAME);
str ccf_flowid_column			=	str_init(CCF_FLOWID_COL);
str ccf_priority_column			=	str_init(CCF_PRIORITY_ID_COL);
str ccf_skill_column			=	str_init(CCF_SKILL_COL);
str ccf_cid_column				=	str_init(CCF_CID_COL);
str ccf_max_wrapup_column		=	str_init(CCF_MAX_WRAPUP_COL);
str ccf_dissuading_hangup_column=	str_init(CCF_DISSUADING_HANGUP_COL);
str ccf_dissuading_onhold_th_column=str_init(CCF_DISSUADING_ONHOLD_TH_COL);
str ccf_dissuading_ewt_th_column=	str_init(CCF_DISSUADING_EWT_TH_COL);
str ccf_dissuading_qsize_th_column=	str_init(CCF_DISSUADING_QSIZE_TH_COL);
str ccf_m_welcome_column		=	str_init(CCF_WELCOME_COL);
str ccf_m_queue_column			=	str_init(CCF_M_QUEUE_COL);
str ccf_m_dissuading_column		=	str_init(CCF_M_DISSUADING_COL);
str ccf_m_flow_id_column		=	str_init(CCF_M_FLOW_ID_COL);

str cc_agent_table_name			=	str_init(CC_AGENT_TABLE_NAME);
str cca_agentid_column			=	str_init(CCA_AGENTID_COL);
str cca_location_column			=	str_init(CCA_LOCATION_ID_COL);
str cca_skills_column			=	str_init(CCA_SKILLS_COL);
str cca_logstate_column			=	str_init(CCA_LOGSTATE_COL);
str cca_wrapupend_column		=	str_init(CCA_WRAPUPEND_COL);
str cca_wrapuptime_column		=	str_init(CCA_WRAPUPTIME_COL);

str cc_globals_table_name		=	str_init(CC_GLOBALS_TABLE_NAME);
str ccg_name_column				=	str_init(CCG_NAME_COL);
str ccg_value_column			=	str_init(CCG_VALUE_COL);

str cc_cdrs_table_name			=	str_init(CC_CDRS_TABLE_NAME);
str ccc_caller_column			=	str_init(CCC_CALLER_COL);
str ccc_recv_time_column		=	str_init(CCC_RECV_TIME_COL);
str ccc_wait_time_column		=	str_init(CCC_WAIT_TIME_COL);
str ccc_talk_time_column		=	str_init(CCC_TALK_TIME_COL);
str ccc_pickup_time_column		=	str_init(CCC_PICKUP_TIME_COL);
str ccc_flow_id_column			=	str_init(CCC_FLOW_ID_COL);
str ccc_agent_id_column			=	str_init(CCC_AGENT_ID_COL);
str ccc_cc_id_column			=	str_init(CCC_CC_ID_COL);
str ccc_type_column				=	str_init(CCC_TYPE_COL);
str ccc_rejected_column			=	str_init(CCC_REJECTED_COL);
str ccc_fstats_column 			=	str_init(CCC_FSTATS_COL);
str ccc_cid_column				=	str_init(CCC_CID_COL);

str cc_calls_table_name			=	str_init(CC_CALLS_TABLE_NAME);
str ccq_state_column			=	str_init(CCQ_STATE_COL);
str ccq_ig_cback_column			=	str_init(CCQ_IGCBACK_COL);
str ccq_no_rej_column			=	str_init(CCQ_NOREJ_COL);
str ccq_setup_time_column		=	str_init(CCQ_SETUP_TIME_COL);
str ccq_eta_column				=	str_init(CCQ_ETA_COL);
str ccq_last_start_column		=	str_init(CCQ_LAST_START_COL);
str ccq_recv_time_column		=	str_init(CCQ_RECV_TIME_COL);
str ccq_caller_dn_column		=	str_init(CCQ_CALLER_DN_COL);
str ccq_caller_un_column		=	str_init(CCQ_CALLER_UN_COL);
str ccq_b2buaid_column			=	str_init(CCQ_B2BUAID_COL);
str ccq_flow_column				=	str_init(CCQ_FLOW_COL);
str ccq_agent_column			=	str_init(CCQ_AGENT_COL);
str ccq_param_column			=	str_init(CCQ_PARAM_COL);
#define CCQ_COLS_NO  13

#define CC_FETCH_ROWS     100

static db_con_t* cc_db_handle    = 0; /* database connection handle */
static db_con_t* cc_acc_db_handle    = 0; /* database connection handle */
static db_con_t* cc_rt_db_handle    = 0; /* database connection handle */
static db_func_t cc_dbf;
static db_func_t cc_acc_dbf;
static db_func_t cc_rt_dbf;
extern b2bl_api_t b2b_api;


#define check_val( _val, _type, _not_null, _is_empty_str, _c) \
	do{\
		if ((_val)->type!=_type) { \
			LM_ERR("bad column type: %s [%d/%d]\n", _c, (_val)->type, _type);\
			goto error;\
		} \
		if (_not_null && (_val)->nul) { \
			LM_ERR("nul column: %s\n", _c);\
			goto error;\
		} \
		if (_is_empty_str && VAL_STRING(_val)==0) { \
			LM_ERR("empty str column: %s\n", _c);\
			goto error;\
		} \
	}while(0)


int cc_connect_db(const str *db_url)
{
	if (cc_db_handle) {
		LM_CRIT("BUG - db connection found already open\n");
		return -1;
	}
	if ((cc_db_handle = cc_dbf.init(db_url)) == 0)
		return -1;

	return 0;
}

int cc_connect_acc_db(const str *acc_db_url)
{
	if (cc_acc_db_handle) {
		LM_CRIT("BUG - db connection found already open\n");
		return -1;
	}
	if ((cc_acc_db_handle = cc_acc_dbf.init(acc_db_url)) == 0)
		return -1;

	return 0;
}


int cc_connect_rt_db(const str *rt_db_url)
{
	if (cc_rt_db_handle) {
		LM_CRIT("BUG - db connection found already open\n");
		return -1;
	}
	if ((cc_rt_db_handle = cc_rt_dbf.init(rt_db_url)) == 0)
		return -1;

	return 0;
}


void cc_close_db(void)
{
	if (cc_db_handle==NULL)
		return;

	cc_dbf.close(cc_db_handle);
	cc_db_handle = NULL;
}


void cc_close_rt_db(void)
{
	if (cc_rt_db_handle==NULL)
		return;

	cc_rt_dbf.close(cc_rt_db_handle);
	cc_rt_db_handle = NULL;
}


int init_cc_db(const str *db_url)
{
	/* Find a database module */
	if (db_bind_mod(db_url, &cc_dbf) < 0){
		LM_ERR("Unable to bind to a database driver\n");
		return -1;
	}

	if (cc_connect_db(db_url)!=0){
		LM_ERR("unable to connect to the database\n");
		return -1;
	}

	if(db_check_table_version(&cc_dbf, cc_db_handle,
	&cc_flow_table_name, CC_FLOW_TABLE_VERSION) < 0) {
		LM_ERR("error during FLOW table version check.\n");
		return -1;
	}

	if(db_check_table_version(&cc_dbf, cc_db_handle,
	&cc_agent_table_name, CC_AGENT_TABLE_VERSION) < 0) {
		LM_ERR("error during AGENT table version check.\n");
		return -1;
	}

	return 0;
}


int init_cc_acc_db(const str *acc_db_url)
{
	/* Find a database module */
	if (db_bind_mod(acc_db_url, &cc_acc_dbf) < 0){
		LM_ERR("Unable to bind to a database driver\n");
		return -1;
	}
	return 0;
}


int init_cc_rt_db(const str *rt_db_url)
{
	/* Find a database module */
	if (db_bind_mod(rt_db_url, &cc_rt_dbf) < 0){
		LM_ERR("Unable to bind to a database driver\n");
		return -1;
	}

	if (cc_connect_rt_db(rt_db_url)!=0){
		LM_ERR("unable to connect to the database\n");
		return -1;
	}

	return 0;
}


int cc_db_delete_call(struct cc_call *call)
{
	db_key_t qcols[1];
	db_val_t qvals[1];

	if(cc_rt_dbf.use_table( cc_rt_db_handle, &cc_calls_table_name) < 0)
	{
		LM_ERR("SQL use table for %.*s table failed\n",
				cc_calls_table_name.len, cc_calls_table_name.s);
		return -1;
	}

	qcols[0]             = &ccq_b2buaid_column;
	qvals[0].type        = DB_STR;
	qvals[0].nul         = 0;
	qvals[0].val.str_val = call->b2bua_id;

	if(cc_rt_dbf.delete(cc_rt_db_handle, qcols, 0, qvals, 1) < 0) {
		LM_ERR("unsuccessful sql delete operation");
		return -1;
	}
	LM_DBG("Deleted call %.*s\n", call->b2bua_id.len, call->b2bua_id.s);
	return 0;
}

int cc_db_update_call(struct cc_call *call)
{
	db_key_t qcols[1];
	db_key_t ucols[5];
	db_val_t qvals[1];
	db_val_t uvals[5];

	if(cc_rt_dbf.use_table( cc_rt_db_handle, &cc_calls_table_name) < 0) {
		LM_ERR("SQL use table for %.*s table failed\n",
				cc_calls_table_name.len, cc_calls_table_name.s);
		return -1;
	}

	memset(&uvals, 0, 5*sizeof(db_val_t));

	qcols[0] = &ccq_b2buaid_column;
	qvals[0].type        = DB_STR;
	qvals[0].val.str_val = call->b2bua_id;

	ucols[0]             = &ccq_state_column;
	uvals[0].type        = DB_INT;
	uvals[0].val.int_val = call->state;
	ucols[1]             = &ccq_ig_cback_column;
	uvals[1].type        = DB_INT;
	uvals[1].val.int_val = call->ign_cback;
	ucols[2]             = &ccq_no_rej_column;
	uvals[2].type        = DB_INT;
	uvals[2].val.int_val = call->no_rejections;
	ucols[3]             = &ccq_last_start_column;
	uvals[3].type        = DB_INT;
	uvals[3].val.int_val = call->last_start;
	ucols[4]             = &ccq_agent_column;
	uvals[4].type        = DB_STR;
	if(call->agent)
		uvals[4].val.str_val = call->agent->id;

	if( cc_rt_dbf.update(cc_rt_db_handle, qcols, 0, qvals,
			ucols, uvals, 1, 5)<0) 
	{
		LM_ERR("updating call record in database\n");
		return -1;
	}
	LM_DBG("updated call in db\n");
	return 0;
}


int cc_db_insert_call(struct cc_call *call)
{
	db_key_t columns[CCQ_COLS_NO];
	db_val_t vals[CCQ_COLS_NO];

	if(cc_rt_dbf.use_table( cc_rt_db_handle, &cc_calls_table_name) < 0)
	{
		LM_ERR("SQL use table for %.*s table failed\n",
				cc_calls_table_name.len, cc_calls_table_name.s);
		return -1;
	}

	memset(&vals, 0, CCQ_COLS_NO*sizeof(db_val_t));

	columns[0]           = &ccq_state_column;
	vals[0].type         = DB_INT;
	vals[0].val.int_val  = call->state;
	columns[1]           = &ccq_ig_cback_column;
	vals[1].type         = DB_INT;
	vals[1].val.int_val  = call->ign_cback;
	columns[2]           = &ccq_no_rej_column;
	vals[2].type         = DB_INT;
	vals[2].val.int_val  = call->no_rejections;
	columns[3]           = &ccq_setup_time_column;
	vals[3].type         = DB_INT;
	vals[3].val.int_val  = call->setup_time;
	columns[4]           = &ccq_eta_column;
	vals[4].type         = DB_INT;
	vals[4].val.int_val  = call->eta;
	columns[5]           = &ccq_last_start_column;
	vals[5].type         = DB_INT;
	vals[5].val.int_val  = call->last_start;
	columns[6]           = &ccq_recv_time_column;
	vals[6].type         = DB_INT;
	vals[6].val.int_val  = call->recv_time;
	columns[7]           = &ccq_caller_dn_column;
	vals[7].type         = DB_STR;
	vals[7].val.str_val  = call->caller_dn;
	columns[8]           = &ccq_caller_un_column;
	vals[8].type         = DB_STR;
	vals[8].val.str_val  = call->caller_un;
	columns[9]          = &ccq_b2buaid_column;
	vals[9].type        = DB_STR;
	vals[9].val.str_val = call->b2bua_id;
	columns[10]          = &ccq_flow_column;
	vals[10].type        = DB_STR;
	vals[10].val.str_val = call->flow->id;
	columns[11]          = &ccq_agent_column;
	vals[11].type        = DB_STR;
	if(call->agent)
		vals[11].val.str_val = call->agent->id;
	columns[12]          = &ccq_param_column;
	vals[12].type        = DB_STR;
	vals[12].val.str_val = call->script_param;

	if (cc_rt_dbf.insert(cc_rt_db_handle, columns, vals, CCQ_COLS_NO) < 0) {
		LM_ERR("inserting new record in database\n");
		return -1;
	}
	LM_DBG("inserted call in db\n");
	return 0;
}

int cc_db_restore_calls( struct cc_data *data)
{
	db_key_t columns[CCQ_COLS_NO];
	db_res_t* res;
	db_row_t* row;
	str s;
	struct cc_flow *flow;
	struct cc_call *call;
	int i;
	struct cc_agent *agent = NULL;
	struct cc_agent *prev;
	str dn, un, param;
	str id;

	cc_rt_dbf.use_table( cc_rt_db_handle, &cc_calls_table_name);

	columns[0] = &ccq_state_column;
	columns[1] = &ccq_ig_cback_column;
	columns[2] = &ccq_no_rej_column;
	columns[3] = &ccq_setup_time_column;
	columns[4] = &ccq_eta_column;
	columns[5] = &ccq_last_start_column;
	columns[6] = &ccq_recv_time_column;
	columns[7] = &ccq_caller_dn_column;
	columns[8] = &ccq_caller_un_column;
	columns[9] = &ccq_b2buaid_column;
	columns[10] = &ccq_flow_column;
	columns[11] = &ccq_agent_column;
	columns[12] = &ccq_param_column;

	if ( cc_rt_dbf.query( cc_rt_db_handle, 0, 0, 0, columns, 0,
				CCQ_COLS_NO, 0, &res)<0) {
		LM_ERR("DB query failed\n");
		return -1;
	}


	if (RES_ROW_N(res) == 0) {
		LM_DBG("No calls restored\n");
		return 0;
	}

	LM_DBG("%d records found in %.*s\n",
		RES_ROW_N(res), cc_calls_table_name.len,cc_calls_table_name.s );

	for(i= RES_ROW_N(res)-1; i>= 0; i--) {
		row = RES_ROWS(res) + i;

		/* FLOW_COL */
		check_val( ROW_VALUES(row)+10, DB_STRING, 1, 1, "flow");
		s.s = (char*)VAL_STRING(ROW_VALUES(row)+10);
		s.len = strlen(s.s);
		flow = get_flow_by_name(data, &s);
		if (flow==NULL) {
			LM_ERR("flow <%.*s> does not exists\n", s.len, s.s);
			continue;
		}
		LM_DBG("using call flow %p\n", flow);

		/* CALLER_DN_COL */
		check_val( ROW_VALUES(row)+7, DB_STRING, 1, 0, "caller_dn");
		dn.s = (char*)VAL_STRING(ROW_VALUES(row)+7);
		dn.len = (dn.s ? strlen(dn.s) : 0);
		/* CALLER_UN_COL */
		check_val( ROW_VALUES(row)+8, DB_STRING, 1, 0, "caller_un");
		un.s = (char*)VAL_STRING(ROW_VALUES(row)+8);
		un.len = (un.s ? strlen(un.s) : 0);

		/* SCRIPT_PARAM_COL */
		check_val( ROW_VALUES(row)+12, DB_STRING, 1, 0, "script param");
		param.s = (char*)VAL_STRING(ROW_VALUES(row)+12);
		param.len = (param.s ? strlen(param.s) : 0);

		call = new_cc_call(data, flow, &dn, &un, &param);
		if (call==NULL) {
			LM_ERR("failed to create new call\n");
			goto error;
		}

		/* AGENT_COL */
		check_val( ROW_VALUES(row)+11, DB_STRING, 0, 0, "agent");
		s.s = (char*)VAL_STRING(ROW_VALUES(row)+11);
		if(s.s && strlen(s.s)) {
			s.len = strlen(s.s);
			/* name of the agent */
			agent = get_agent_by_name(data, &s, &prev);
			if (agent==NULL) {
				LM_ERR("Agent <%.*s> does not exists\n", s.len, s.s);
				continue;
			}
			call->agent = agent;
			agent->state = CC_AGENT_INCALL;
			agent->ref_cnt++;
		}

		/* STATE_COL */
		check_val( ROW_VALUES(row), DB_INT, 1, 0, "state");
		call->state = VAL_INT(ROW_VALUES(row));
		/* IGCBACK_COL */
		check_val( ROW_VALUES(row)+1, DB_INT, 1, 0, "ig_cback");
		call->ign_cback = VAL_INT(ROW_VALUES(row)+1);
		/* NOREJ_COL */
		check_val( ROW_VALUES(row)+2, DB_INT, 1, 0, "no_rej");
		call->no_rejections = VAL_INT(ROW_VALUES(row)+2);
		/* SETUP_TIME_COL */
		check_val( ROW_VALUES(row)+3, DB_INT, 1, 0, "setup_time");
		call->setup_time = VAL_INT(ROW_VALUES(row)+3);
		/* ETA_COL  */
		check_val( ROW_VALUES(row)+4, DB_INT, 1, 0, "eta");
		call->eta = VAL_INT(ROW_VALUES(row)+4);
		/* LAST_START_COL */
		check_val( ROW_VALUES(row)+5, DB_INT, 1, 0, "last_start");
		call->last_start = VAL_INT(ROW_VALUES(row)+5);
		/* RECV_TIME_COL */
		check_val( ROW_VALUES(row)+6, DB_INT, 1, 0, "recv_time");
		call->recv_time = VAL_INT(ROW_VALUES(row)+6);
		/* B2BUAID_COL */
		check_val( ROW_VALUES(row)+9, DB_STRING, 1, 1, "b2buaid");
		id.s = (char*)VAL_STRING(ROW_VALUES(row)+9);
		if(id.s) {
			id.len = strlen(id.s);
			call->b2bua_id.len = id.len;
			call->b2bua_id.s = (char*)shm_malloc(id.len);
			if(call->b2bua_id.s == NULL) {
				LM_ERR("No more memory\n");
				goto error;
			}
			memcpy(call->b2bua_id.s, id.s, id.len);
			call->ref_cnt++;

			/* restore logic info */
			if(b2b_api.restore_upper_info(&call->b2bua_id, b2bl_callback_customer, call,
					B2B_DESTROY_CB|B2B_REJECT_CB|B2B_BYE_CB)< 0)
			{
				/* delete the call*/
				LM_ERR("Upper info not found for [%.*s]\n", id.len, id.s);
				free_cc_call( data, call);
				continue;
			}
		}

		if(call->state == CC_CALL_QUEUED) {
			cc_queue_push_call( data, call, 0);
			call->ref_cnt++;
		}
	}
	LM_DBG("Restored calls\n");
	return 0;

error:
	return -1;
}


int cc_load_db_data( struct cc_data *data)
{
	db_key_t columns[13];
	db_res_t* res;
	db_row_t* row;
	int i, j, n;
	str id,skill,cid;
	str location;
	unsigned int priority, wrapup, logstate, wrapup_end_time;
	unsigned int diss_hangup, diss_ewt_th, diss_qsize_th, diss_onhold_th;
	str messages[MAX_AUDIO];

	cc_dbf.use_table( cc_db_handle, &cc_flow_table_name);

	columns[0]  = &ccf_flowid_column;
	columns[1]  = &ccf_priority_column;
	columns[2]  = &ccf_skill_column;
	columns[3]  = &ccf_cid_column;
	columns[4]  = &ccf_max_wrapup_column;
	columns[5]  = &ccf_dissuading_hangup_column;
	columns[6]  = &ccf_dissuading_ewt_th_column;
	columns[7]  = &ccf_dissuading_qsize_th_column;
	columns[8]  = &ccf_dissuading_onhold_th_column;
	columns[9]  = &ccf_m_welcome_column;
	columns[10] = &ccf_m_queue_column;
	columns[11] = &ccf_m_dissuading_column;
	columns[12] = &ccf_m_flow_id_column;

	if (0/*DB_CAPABILITY(cc_dbf, DB_CAP_FETCH))*/) {
		if ( cc_dbf.query( cc_db_handle, 0, 0, 0, columns, 0, 13, 0, 0 ) < 0) {
			LM_ERR("DB query failed\n");
			return -1;
		}
		if(cc_dbf.fetch_result( cc_db_handle, &res, CC_FETCH_ROWS)<0) {
			LM_ERR("Error fetching rows\n");
			return -1;
		}
	} else {
		if ( cc_dbf.query( cc_db_handle, 0, 0, 0, columns, 0, 13, 0, &res)<0) {
			LM_ERR("DB query failed\n");
			return -1;
		}
	}

	LM_DBG("%d records found in %.*s\n",
		RES_ROW_N(res), cc_flow_table_name.len,cc_flow_table_name.s );
	n = 0;

	do {
		for(i=0; i < RES_ROW_N(res); i++) {
			row = RES_ROWS(res) + i;
			/* flowID column */
			check_val( ROW_VALUES(row), DB_STRING, 1, 1, "flowid");
			id.s = (char*)VAL_STRING(ROW_VALUES(row));
			id.len = strlen(id.s);
			/* PRIORITY column */
			check_val( ROW_VALUES(row)+1, DB_INT, 1, 0, "priority");
			priority = VAL_INT(ROW_VALUES(row)+1);
			/* SKILL column */
			check_val( ROW_VALUES(row)+2, DB_STRING, 1, 1, "skill");
			skill.s = (char*)VAL_STRING(ROW_VALUES(row)+2);
			skill.len = strlen(skill.s);
			/* CID column */
			check_val( ROW_VALUES(row)+3, DB_STRING, 0, 0, "prependcid");
			if (VAL_NULL(ROW_VALUES(row)+3)) {
				cid.s = NULL; cid.len = 0;
			} else {
				cid.s = (char*)VAL_STRING(ROW_VALUES(row)+3);
				if (cid.s==NULL || (cid.len=strlen(cid.s))==0 ) {
					cid.s = NULL; cid.len = 0;
				}
			}
			/* MAX_WRAPUP_TIME column */
			check_val( ROW_VALUES(row)+4, DB_INT, 1, 0, "max_wrapup_time");
			wrapup = VAL_INT(ROW_VALUES(row)+4);
			/* DISSUADING_HANGUP column */
			check_val( ROW_VALUES(row)+5, DB_INT, 1, 0, "dissuading hangup");
			diss_hangup = VAL_INT(ROW_VALUES(row)+5);
			/* DISSUADING_EWT_TH column */
			check_val( ROW_VALUES(row)+6, DB_INT, 1, 0,
				"dissuading EWT threshold");
			diss_ewt_th = VAL_INT(ROW_VALUES(row)+6);
			/* DISSUADING_QSIZE_TH column */
			check_val( ROW_VALUES(row)+7, DB_INT, 1, 0,
				"dissuading queue size threshold");
			diss_qsize_th = VAL_INT(ROW_VALUES(row)+7);
			/* DISSUADING_ONHOLD_TH column */
			check_val( ROW_VALUES(row)+8, DB_INT, 1, 0,
				"dissuading onhold threshold");
			diss_onhold_th = VAL_INT(ROW_VALUES(row)+8);

			for( j=0 ; j<MAX_AUDIO ; j++ ) {
				/* MESSAGE_XXXX column */
				check_val( ROW_VALUES(row)+9+j, DB_STRING, 0, 0, "message");
				if (VAL_NULL(ROW_VALUES(row)+9+j)) {
					messages[j].s = NULL; messages[j].len = 0;
				} else {
					messages[j].s = (char*)VAL_STRING(ROW_VALUES(row)+9+j);
					if (messages[j].s==NULL ||
					(messages[j].len=strlen(messages[j].s))==0 ) {
						messages[j].s = NULL; messages[j].len = 0;
					}
				}
			}

			/* queue audio cannot be null */
			if ( messages[1].s == NULL) {
				LM_ERR("queue audio cannot be null in flow %.*s -> "
					"skipping\n", id.len,id.s);
				continue;
			}

			/* add flow */
			if (add_cc_flow(data, &id, priority, &skill, &cid, wrapup,
			diss_hangup, diss_ewt_th, diss_qsize_th, diss_onhold_th,
			messages)<0) {
				LM_ERR("failed to add flow %.*s -> skipping\n",
					id.len,id.s);
				continue;
			}
			n++;
		}
		if (DB_CAPABILITY( cc_dbf, DB_CAP_FETCH)) {
			if(cc_dbf.fetch_result(cc_db_handle, &res, CC_FETCH_ROWS)<0) {
				LM_ERR( "fetching rows (1)\n");
				return -1;
			}
		} else {
			break;
		}
	} while(RES_ROW_N(res)>0);

	cc_dbf.free_result(cc_db_handle, res);
	res = 0;


	cc_dbf.use_table( cc_db_handle, &cc_agent_table_name);

	columns[0] = &cca_agentid_column;
	columns[1] = &cca_location_column;
	columns[2] = &cca_skills_column;
	columns[3] = &cca_logstate_column;
	columns[4] = &cca_wrapupend_column;
	columns[5] = &cca_wrapuptime_column;

	if (0/*DB_CAPABILITY(cc_dbf, DB_CAP_FETCH))*/) {
		if ( cc_dbf.query( cc_db_handle, 0, 0, 0, columns, 0, 6, 0, 0 ) < 0) {
			LM_ERR("DB query failed\n");
			return -1;
		}
		if(cc_dbf.fetch_result( cc_db_handle, &res, CC_FETCH_ROWS)<0) {
			LM_ERR("Error fetching rows\n");
			return -1;
		}
	} else {
		if ( cc_dbf.query( cc_db_handle, 0, 0, 0, columns, 0, 6, 0, &res)<0) {
			LM_ERR("DB query failed\n");
			return -1;
		}
	}

	LM_DBG("%d records found in %.*s\n",
		RES_ROW_N(res), cc_agent_table_name.len,cc_agent_table_name.s );
	n = 0;

	do {
		for(i=0; i < RES_ROW_N(res); i++) {
			row = RES_ROWS(res) + i;
			/* agentID column */
			check_val( ROW_VALUES(row), DB_STRING, 1, 1, "agentid");
			id.s = (char*)VAL_STRING(ROW_VALUES(row));
			id.len = strlen(id.s);
			/* LOCATION column */
			check_val( ROW_VALUES(row)+1, DB_STRING, 1, 1, "location");
			location.s = (char*)VAL_STRING(ROW_VALUES(row)+1);
			location.len = strlen(location.s);
			/* SKILLS column */
			check_val( ROW_VALUES(row)+2, DB_STRING, 1, 1, "skills");
			skill.s = (char*)VAL_STRING(ROW_VALUES(row)+2);
			skill.len = strlen(skill.s);
			/* LOGSTATE column */
			check_val( ROW_VALUES(row)+3, DB_INT, 1, 0, "logstate");
			logstate = VAL_INT(ROW_VALUES(row)+3);
			/* WRAPUP_END_TIME column */
			wrapup_end_time = VAL_INT(ROW_VALUES(row)+4);
			/* WRAPUP_TIME column */
			check_val( ROW_VALUES(row)+5, DB_INT, 1, 0, "wrapup time");
			wrapup = VAL_INT(ROW_VALUES(row)+5);

			/* add agent */
			if (add_cc_agent( data, &id, &location, &skill, logstate, wrapup,
			wrapup_end_time)<0){
				LM_ERR("failed to add agent %.*s -> skipping\n",
					id.len,id.s);
				continue;
			}
			n++;
		}
		if (DB_CAPABILITY( cc_dbf, DB_CAP_FETCH)) {
			if(cc_dbf.fetch_result(cc_db_handle, &res, CC_FETCH_ROWS)<0) {
				LM_ERR( "fetching rows (1)\n");
				return -1;
			}
		} else {
			break;
		}
	} while(RES_ROW_N(res)>0);

	cc_dbf.free_result(cc_db_handle, res);
	res = 0;

	return 0;
error:
	if (res)
		cc_dbf.free_result(cc_db_handle, res);
	return -1;
}


int prepare_cdr(struct cc_call *call, str *un, str *fid , str *aid)
{
	#define CDR_BUF_LEN  2048
	#define CDR_ITEM_LEN(_a)  ( (p+_a>buf+CDR_BUF_LEN) ? buf+CDR_BUF_LEN-p : _a )
	static char buf[CDR_BUF_LEN+1];
	char *p = buf;

	un->len = CDR_ITEM_LEN(call->caller_un.len);
	un->s = p;
	if (un->len) {
		memcpy( p, call->caller_un.s, un->len );
		p += un->len;
	}

	fid->len = CDR_ITEM_LEN(call->flow->id.len);
	fid->s = p;
	if (fid->len) {
		memcpy( p, call->flow->id.s, fid->len );
		p += fid->len;
	}

	if (call->agent) {
		aid->len = CDR_ITEM_LEN(call->agent->id.len);
		aid->s = p;
		if (aid->len) {
			memcpy( p, call->agent->id.s, aid->len );
			p += aid->len;
		}
	} else {
		aid->s = NULL;
		aid->len = 0;
	}

	return 0;
}


int cc_write_cdr( str *un, str *fid, str *aid, int type, int rt, int wt, int tt, int pt, int rej, int fst, int cid)
{
	db_key_t columns[11];
	db_val_t vals[11];
	static db_ps_t my_ps = NULL;

	cc_acc_dbf.use_table( cc_acc_db_handle, &cc_cdrs_table_name);

	columns[0] = &ccc_caller_column;
	columns[1] = &ccc_recv_time_column;
	columns[2] = &ccc_wait_time_column;
	columns[3] = &ccc_talk_time_column;
	columns[4] = &ccc_pickup_time_column;
	columns[5] = &ccc_flow_id_column;
	columns[6] = &ccc_agent_id_column;
	columns[7] = &ccc_type_column;
	columns[8] = &ccc_rejected_column;
	columns[9]= &ccc_fstats_column;
	columns[10]= &ccc_cid_column;

	/* caller */
	vals[0].nul = 0;
	vals[0].type = DB_STR;
	vals[0].val.str_val = *un;

	/* received timestamp */
	vals[1].nul = 0;
	vals[1].type = DB_DATETIME;
	vals[1].val.time_val = startup_time + rt;

	/* wait time */
	vals[2].nul = 0;
	vals[2].type = DB_INT;
	vals[2].val.int_val = wt;

	/* talk time */
	vals[3].nul = 0;
	vals[3].type = DB_INT;
	vals[3].val.int_val = tt;

	/* pickup time */
	vals[4].nul = 0;
	vals[4].type = DB_INT;
	vals[4].val.int_val = pt;

	/* flow ID */
	vals[5].nul = 0;
	vals[5].type = DB_STR;
	vals[5].val.str_val = *fid;

	/* agent ID */
	vals[6].type = DB_STR;
	if (aid->len==0) {
		vals[6].nul = 1;
	} else {
		vals[6].nul = 0;
		vals[6].val.str_val = *aid;
	}

	/* type */
	vals[7].nul = 0;
	vals[7].type = DB_INT;
	vals[7].val.int_val = type;

	/* rej */
	vals[8].nul = 0;
	vals[8].type = DB_INT;
	vals[8].val.int_val = rej;

	/* fstat */
	vals[9].nul = 0;
	vals[9].type = DB_INT;
	vals[9].val.int_val = fst;

	/* cid */
	vals[10].nul = 0;
	vals[10].type = DB_INT;
	vals[10].val.int_val = cid;

	CON_PS_REFERENCE(cc_acc_db_handle) = &my_ps;

	if (cc_acc_dbf.insert( cc_acc_db_handle, columns, vals, 11) < 0) {
		LM_ERR("CDR insert failed\n");
		return -1;
	}

	return 0;
}


void cc_db_update_agent_wrapup_end(struct cc_agent* agent)
{
	db_key_t columns[2];
	db_val_t vals[2];

	columns[0] = &cca_agentid_column;
	columns[1] = &cca_wrapupend_column;

	vals[0].nul = 0;
	vals[0].type = DB_STR;
	vals[0].val.str_val = agent->id;

	vals[1].nul = 0;
	vals[1].type = DB_INT;
	/* translate from internal time to timestamp */
	vals[1].val.int_val = (int)time(NULL)-get_ticks()+agent->wrapup_end_time;

	cc_dbf.use_table( cc_db_handle, &cc_agent_table_name);

	if (cc_dbf.update(cc_db_handle,columns,0,vals,columns+1,vals+1,1,1)<0) {
		LM_ERR("Agent update failed\n");
	}
}

