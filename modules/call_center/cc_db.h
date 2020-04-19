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

#ifndef CC_CC_DB_H_
#define CC_CC_DB_H_

#include "../../str.h"
#include "cc_data.h"

extern str cc_agent_table_name;
extern str cca_agentid_column;
extern str cca_location_column;
extern str cca_skills_column;
extern str cca_logstate_column;
extern str cca_wrapupend_column;
extern str cca_wrapuptime_column;

extern str cc_flow_table_name;
extern str ccf_flowid_column;
extern str ccf_priority_column;
extern str ccf_skill_column;
extern str ccf_cid_column;
extern str ccf_max_wrapup_column;
extern str ccf_dissuading_hangup_column;
extern str ccf_dissuading_onhold_th_column;
extern str ccf_dissuading_ewt_th_column;
extern str ccf_dissuading_qsize_th_column;
extern str ccf_m_welcome_column;
extern str ccf_m_queue_column;
extern str ccf_m_dissuading_column;
extern str ccf_m_flow_id_column;

int init_cc_db(const str *db_url);
int init_cc_acc_db(const str *acc_db_url);
int init_cc_rt_db(const str *rt_db_url);

int cc_connect_db(const str *db_url);
int cc_connect_acc_db(const str *acc_db_url);
int cc_connect_rt_db(const str *rt_db_url);

void cc_close_db(void);
void cc_close_rt_db(void);

int cc_load_db_data( struct cc_data *data);

int cc_write_cdr( str *un, str *fid, str *aid, int type,
		int rt, int wt, int tt , int pt, int rej, int fst, int cid);

int prepare_cdr(struct cc_call *call, str *un, str *fid , str *aid);

int cc_db_insert_call(struct cc_call *call);
int cc_db_update_call(struct cc_call *call);
int cc_db_delete_call(struct cc_call *call);
int cc_db_restore_calls( struct cc_data *data);
void cc_db_update_agent_wrapup_end(struct cc_agent* agent);
int b2bl_callback_customer(b2bl_cb_params_t *params, unsigned int event);

#endif
