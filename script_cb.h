/*
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
 * --------
 *  2005-02-13  script callbacks devided into request and reply types (bogdan)
 */

/*!
 * \file
 * \brief Script callbacks
 */

#ifndef _SCRIPT_CB_H_
#define _SCRIPT_CB_H_

#include "parser/msg_parser.h"

/**
 * @return:
 * - SCB_DROP_MSG stops the processing (also skips any other callbacks)
 * - a combination of the SCB_ flags or SCB_RUN_ALL for any other cases
 *
 * NB: return values are logically AND'ed
 *   (one module may wish to skip top route, others may skip post callbacks)
 */
typedef int (cb_function)( struct sip_msg *msg, void *param );

#define SCB_DROP_MSG      0
#define SCB_RUN_TOP_ROUTE (1<<0)
#define SCB_RUN_POST_CBS  (1<<1)
#define SCB_RUN_ALL (SCB_RUN_TOP_ROUTE | SCB_RUN_POST_CBS)

#define PRE_SCRIPT_CB    (1<<0)
#define POST_SCRIPT_CB   (1<<1)
#define REQ_TYPE_CB      (1<<2)
#define RPL_TYPE_CB      (1<<3)
#define PARSE_ERR_CB     (1<<4)

/* helper is any type of data that can be used in further processing */
typedef int (*raw_processing_func)(str *data, struct sip_msg* msg);
#define PRE_RAW_PROCESSING  (1<<0)
#define POST_RAW_PROCESSING (1<<1)

struct raw_processing_cb_list {
	raw_processing_func f;
	struct raw_processing_cb_list* next;
	char freeable; /* set this parameter if you want to register your
						callback per message( registration at every message)
						else put it 0, register callback only once and callback
						will be called for every message that reaches msg_send
						*/
};

struct script_cb {
	cb_function *cbf;
	struct script_cb *next;
	unsigned int id;
	void *param;
	int prio; /* allows callback ordering; highest runs first */
};

#define register_script_cb(func, type, param) \
	__register_script_cb(func, type, param, 0)

/* sorted by priority in descending order (highest prio callback runs first) */
int __register_script_cb( cb_function f, int type, void *param, int prio);
void destroy_script_cb();

int exec_pre_req_cb( struct sip_msg *msg);
int exec_post_req_cb( struct sip_msg *msg);

int exec_pre_rpl_cb( struct sip_msg *msg);
int exec_post_rpl_cb( struct sip_msg *msg);

int exec_parse_err_cb( struct sip_msg *msg);

int register_pre_raw_processing_cb(raw_processing_func f, int type, char freeable);
int register_post_raw_processing_cb(raw_processing_func f, int type, char freeable);

int run_pre_raw_processing_cb(int type, str* data, struct sip_msg* msg);
int run_post_raw_processing_cb(int type, str* data, struct sip_msg* msg);

int run_raw_processing_cb(int type,str *data, struct sip_msg* msg, struct raw_processing_cb_list* list);

#endif

