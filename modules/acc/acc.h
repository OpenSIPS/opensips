/*
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2006 Voice Sistem SRL
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
 * 2003-04-04  grand acc cleanup (jiri)
 * 2003-11-04  multidomain support for mysql introduced (jiri)
 * 2004-06-06  cleanup: acc_db_{bind,init,close} added (andrei)
 * 2006-09-08  flexible multi leg accounting support added,
 *             code cleanup for low level functions (bogdan)
 * 2006-09-19  final stage of a masive re-structuring and cleanup (bogdan)
 */

#ifndef _ACC_ACC_H_
#define _ACC_ACC_H_

#include "../../db/db_insertq.h"

#define ACC_CORE_LEN 6
#define ACC_DLG_LEN 3

/* leading text for a request accounted from a script */
#define ACC "ACC: "
#define ACC_REQUEST ACC"request accounted: "
#define ACC_REQUEST_LEN (sizeof(ACC_REQUEST)-1)
#define ACC_MISSED ACC"call missed: "
#define ACC_MISSED_LEN (sizeof(ACC_MISSED)-1)
#define ACC_ANSWERED ACC"transaction answered: "
#define ACC_ANSWERED_LEN (sizeof(ACC_ANSWERED)-1)
#define ACC_ACKED ACC"request acknowledged: "
#define ACC_ACKED_LEN (sizeof(ACC_ACKED)-1)
#define ACC_ENDED ACC"call ended: "
#define ACC_ENDED_LEN (sizeof(ACC_ENDED)-1)

/* syslog attribute names */
#define A_METHOD "method"
#define A_METHOD_LEN (sizeof(A_METHOD)-1)
#define A_FROMTAG "from_tag"
#define A_FROMTAG_LEN (sizeof(A_FROMTAG)-1)
#define A_TOTAG "to_tag"
#define A_TOTAG_LEN (sizeof(A_TOTAG)-1)
#define A_CALLID "call_id"
#define A_CALLID_LEN (sizeof(A_CALLID)-1)
#define A_CODE "code"
#define A_CODE_LEN (sizeof(A_CODE)-1)
#define A_STATUS "reason"
#define A_STATUS_LEN (sizeof(A_STATUS)-1)
#define A_DURATION "duration"
#define A_DURATION_LEN (sizeof(A_DURATION)-1)
#define A_SETUPTIME "setuptime"
#define A_SETUPTIME_LEN (sizeof(A_SETUPTIME)-1)
#define A_CREATED "created"
#define A_CREATED_LEN (sizeof(A_CREATED)-1)

#define A_SEPARATOR_CHR ';'
#define A_EQ_CHR '='

#define MAX_SYSLOG_SIZE  65536
#define STRING_INIT_SIZE 128

#include "../dialog/dlg_load.h"

extern struct dlg_binds dlg_api;

void acc_log_init();
int  acc_log_request( struct sip_msg *req, struct sip_msg *rpl, int cdr_flag);
int  acc_log_cdrs(struct dlg_cell *dlg, struct sip_msg *msg,
		struct timeval *end);
int  store_log_extra_values(struct dlg_cell *dlg, struct sip_msg *req,
		struct sip_msg *reply);

int  acc_db_init(const str* db_url);
int  acc_db_init_child(const str* db_url);
void acc_db_close();
int  acc_db_request( struct sip_msg *req, struct sip_msg *rpl,
		query_list_t **ins_list, int cdr_flag);
int  acc_db_cdrs(struct dlg_cell *dlg, struct sip_msg *msg,
		struct timeval *end);
int  store_db_extra_values(struct dlg_cell *dlg, struct sip_msg *req,
		struct sip_msg *reply);

int  init_acc_aaa(char* aaa_proto_url, int srv_type);
int  acc_aaa_request( struct sip_msg *req, struct sip_msg *rpl, int cdr_flag);
int  acc_aaa_cdrs_request(struct dlg_cell *dlg);
int  acc_aaa_cdrs(struct dlg_cell *dlg, struct sip_msg *msg,
		struct timeval *end);
int  store_aaa_extra_values(struct dlg_cell *dlg, struct sip_msg *req,
		struct sip_msg *reply);

int  store_core_leg_values(struct dlg_cell *dlg, struct sip_msg *req);
int  store_created_dlg_time(struct dlg_cell *dlg);
int  create_acc_dlg(struct sip_msg* req);

int  init_acc_evi(void);
int  acc_evi_request( struct sip_msg *req, struct sip_msg *rpl, int cdr_flag);
int  acc_evi_cdrs(struct dlg_cell *dlg, struct sip_msg *msg,
		struct timeval *end);
int  store_evi_extra_values(struct dlg_cell *dlg, struct sip_msg *req,
		struct sip_msg *reply);
extern event_id_t acc_cdr_event;
extern event_id_t acc_event;
extern event_id_t acc_missed_event;



#ifdef DIAM_ACC
int  acc_diam_init();
int  acc_diam_request( struct sip_msg *req, struct sip_msg *rpl);
#endif


#endif
