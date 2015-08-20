/*
 * emergency module - basic support for emergency calls
 *
 * Copyright (C) 2014-2015 Robison Tesini & Evandro Villaron
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
 *  2014-10-14 initial version (Villaron/Tesini)
 */


#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../mod_fix.h"
#include "../../socket_info.h"
#include "../../route_struct.h"
#include "../../ip_addr.h"
#include "../../parser/msg_parser.h"
#include "../../parser/parse_uri.h"
#include "../../parser/parse_pai.h"
#include "../../parser/parse_ppi.h"
#include "../../parser/parse_rpid.h"
#include "../../parser/parse_from.h"
#include "../../regexp.h"
#include "../../data_lump.h"
#include "../../data_lump_rpl.h" 
#include "../../ut.h"
#include "../../rw_locking.h"
#include "../../timer.h"
#include "../../db/db.h"
#include "../../db/db_insertq.h"
#include "../../forward.h"
#include "../rr/api.h"

#include "report_emergency.h" 

struct node *list_call;
struct node **calls_eme;

char *empty;

int faixa_result(int result); 
int treat_parse_esrResponse(struct sip_msg *msg, ESCT *call_cell , NENA *call_cell_vpc, NENA *call_cell_source, PARSED *parsed, int proxy_hole);
int get_lro_in_contact(char *contact_lro, ESCT *call_cell);
int get_esqk_in_contact(char *contact_lro, ESCT *call_cell);
int get_esgwri_ert_in_contact(char *contact_esgwri, ESCT *call_cell);
void insert_call_cell_in_list(ESCT *call_cell);
void free_call_cell(NODE *info_call);
void free_nena(NENA *nena);
void free_parsed(PARSED *parsed);
