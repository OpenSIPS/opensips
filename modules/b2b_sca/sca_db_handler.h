/*
 * sca_db_handler module
 *
 * Copyright (C) 2011 VoIP Embedded, Inc.
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
 *  2010-11-21  initial version (Ovidiu Sas)
 */

#ifndef SCA_DB_HANDLER
#define SCA_DB_HANDLER

#include <stdio.h>
#include <stdlib.h>

#include "sca_records.h"

#define SHARED_LINE_COL			"shared_line"
#define WATCHERS_COL			"watchers"
#define SHARED_ENTITY_1_COL		"app1_shared_entity"
#define CALL_STATE_1_COL		"app1_call_state"
#define CALL_INFO_URI_1_COL		"app1_call_info_uri"
#define CALL_INFO_APPEARANCE_URI_1_COL	"app1_call_info_appearance_uri"
#define B2BL_KEY_1_COL			"app1_b2bl_key"
#define SHARED_ENTITY_2_COL		"app2_shared_entity"
#define CALL_STATE_2_COL		"app2_call_state"
#define CALL_INFO_URI_2_COL		"app2_call_info_uri"
#define CALL_INFO_APPEARANCE_URI_2_COL	"app2_call_info_appearance_uri"
#define B2BL_KEY_2_COL			"app2_b2bl_key"
#define SHARED_ENTITY_3_COL		"app3_shared_entity"
#define CALL_STATE_3_COL		"app3_call_state"
#define CALL_INFO_URI_3_COL		"app3_call_info_uri"
#define CALL_INFO_APPEARANCE_URI_3_COL	"app3_call_info_appearance_uri"
#define B2BL_KEY_3_COL			"app3_b2bl_key"
#define SHARED_ENTITY_4_COL		"app4_shared_entity"
#define CALL_STATE_4_COL		"app4_call_state"
#define CALL_INFO_URI_4_COL		"app4_call_info_uri"
#define CALL_INFO_APPEARANCE_URI_4_COL	"app4_call_info_appearance_uri"
#define B2BL_KEY_4_COL			"app4_b2bl_key"
#define SHARED_ENTITY_5_COL		"app5_shared_entity"
#define CALL_STATE_5_COL		"app5_call_state"
#define CALL_INFO_URI_5_COL		"app5_call_info_uri"
#define CALL_INFO_APPEARANCE_URI_5_COL	"app5_call_info_appearance_uri"
#define B2BL_KEY_5_COL			"app5_b2bl_key"
#define SHARED_ENTITY_6_COL		"app6_shared_entity"
#define CALL_STATE_6_COL		"app6_call_state"
#define CALL_INFO_URI_6_COL		"app6_call_info_uri"
#define CALL_INFO_APPEARANCE_URI_6_COL	"app6_call_info_appearance_uri"
#define B2BL_KEY_6_COL			"app6_b2bl_key"
#define SHARED_ENTITY_7_COL		"app7_shared_entity"
#define CALL_STATE_7_COL		"app7_call_state"
#define CALL_INFO_URI_7_COL		"app7_call_info_uri"
#define CALL_INFO_APPEARANCE_URI_7_COL	"app7_call_info_appearance_uri"
#define B2BL_KEY_7_COL			"app7_b2bl_key"
#define SHARED_ENTITY_8_COL		"app8_shared_entity"
#define CALL_STATE_8_COL		"app8_call_state"
#define CALL_INFO_URI_8_COL		"app8_call_info_uri"
#define CALL_INFO_APPEARANCE_URI_8_COL	"app8_call_info_appearance_uri"
#define B2BL_KEY_8_COL			"app8_b2bl_key"
#define SHARED_ENTITY_9_COL		"app9_shared_entity"
#define CALL_STATE_9_COL		"app9_call_state"
#define CALL_INFO_URI_9_COL		"app9_call_info_uri"
#define CALL_INFO_APPEARANCE_URI_9_COL	"app9_call_info_appearance_uri"
#define B2BL_KEY_9_COL			"app9_b2bl_key"
#define SHARED_ENTITY_10_COL		"app10_shared_entity"
#define CALL_STATE_10_COL		"app10_call_state"
#define CALL_INFO_URI_10_COL		"app10_call_info_uri"
#define CALL_INFO_APPEARANCE_URI_10_COL	"app10_call_info_appearance_uri"
#define B2BL_KEY_10_COL			"app10_b2bl_key"

#define SCA_TABLE_NAME		"b2b_sca"

#define SCA_TABLE_VERSION	1
#define DB_MODE_NONE		0
#define DB_MODE_REALTIME	1

#define SCA_TABLE_TOTAL_COL_NO	(2+(MAX_APPEARANCE_INDEX*5))

#define SCA_FETCH_SIZE		128

extern str shared_line_column;
extern str watchers_column;
extern str app_shared_entity_column[MAX_APPEARANCE_INDEX];
extern str app_call_state_column[MAX_APPEARANCE_INDEX];
extern str app_call_info_uri_column[MAX_APPEARANCE_INDEX];
extern str app_call_info_appearance_uri_column[MAX_APPEARANCE_INDEX];
extern str app_b2bl_key_column[MAX_APPEARANCE_INDEX];

extern str sca_table_name;
extern int sca_db_mode;

int init_sca_db(const str *db_url, int dlg_hash_size);
int connect_sca_db(const str *db_url);
void destroy_sca_db(void);

int push_sca_info_to_db(b2b_sca_record_t *record, unsigned int appearance_index,
						unsigned int forced_update);

#endif
