/*
 * Copyright (C) 2022 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#ifndef _STATUS_REPORT_H_
#define _STATUS_REPORT_H_

#include "mi/mi.h"

#define CHAR_INT MI_SSTR
#define CHAR_INT_NULL NULL,0
#define STR2CI(_str) _str.s, _str.len

/* some pre-defined statuses that may be used by modules too */
enum sr_status {
	SR_STATUS_NOT_FOUND		= INT_MIN, /* just for internal usage! */
	SR_STATUS_NO_DATA		=- 2,
	SR_STATUS_LOADING_DATA	= -1,
	SR_STATUS_NOT_READY		= -1,
	SR_STATUS_RESEARVED		=  0,
	SR_STATUS_READY			=  1,
	SR_STATUS_RELOADING_DATA=  2,
	};


/* functions to be used by modules using the status/report framework */

void *sr_register_group( char *name_s, int name_len, int is_public);

void *sr_get_group_by_name( char *name_s, int name_len);

int sr_register_identifier( void *group,
		char *identifier_s, int identifier_len,
		int init_status, char *status_txt_s, int status_txt_len,
		int max_reports);

void* sr_register_group_with_identifier( char *group_s, int group_len,
		int grp_is_public,
		char *identifier_s, int identifier_len,
		int init_status, char *status_txt_s, int status_txt_len,
		int max_reports);

int sr_unregister_identifier( void *group,
		char *identifier_s, int identifier_len);

int sr_set_status(void *group,
		char *identifier_s, int identifier_len,
		int status, char *status_txt_s, int status_txt_len,
		int is_public);

int sr_add_report(void *group,
		char *identifier_s, int identifier_len,
		char *report_s, int report_len,
		int is_public);

int sr_add_report_fmt(void *group,
		char *identifier_s, int identifier_len,
		int is_public,
		char *fmt_val, ...);


/* functions related to status of the OpenSIPS core */

enum sr_core_states { STATE_NONE=-100, STATE_TERMINATING=-2,
		STATE_INITIALIZING=-1, STATE_RUNNING=1 };

int sr_set_core_status(enum sr_core_states status, char *txt_s, int txt_len);

void sr_set_core_status_terminating( void );

enum sr_core_states sr_get_core_status(void);

int sr_add_core_report(char *report_s, int report_len);


/* functions used by the OpenSIPS core */

int init_status_report(void);

int fixup_sr_group(void **param);

int w_sr_check_status(struct sip_msg *msg, void *group, str *identifier);

mi_response_t *mi_sr_get_status(const mi_params_t *params,
		struct mi_handler *async_hdl);

mi_response_t *mi_sr_list_status(const mi_params_t *params,
		struct mi_handler *async_hdl);

mi_response_t *mi_sr_list_reports(const mi_params_t *params,
		struct mi_handler *async_hdl);

mi_response_t *mi_sr_list_identifiers(const mi_params_t *params,
		struct mi_handler *async_hdl);
#endif


