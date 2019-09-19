/*
 * Accounting module
 *
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
 * ---------
 * 2003-04-04  grand acc cleanup (jiri)
 * 2003-11-04  multidomain support for mysql introduced (jiri)
 * 2004-06-06  removed db_url, db_handle (andrei)
 * 2005-06-28  multi leg call support added (bogdan)
 * 2006-09-19  final stage of a masive re-structuring and cleanup (bogdan)
 */


#ifndef _ACC_MOD_H
#define _ACC_MOD_H

/* module parameter declaration */
extern int report_cancels;
extern int early_media;
extern int failed_transaction_flag;
extern int detect_direction;

extern int acc_log_level;
extern int acc_log_flag;
extern int acc_log_missed_flag;

extern int aaa_flag;
extern int aaa_missed_flag;
extern aaa_prot proto;
extern aaa_conn *conn;
extern char* aaa_proto_url;

extern int cdr_flag;

extern int db_flag;
extern int db_missed_flag;

extern str db_table_acc;
extern str db_table_mc;

extern str acc_method_col;
extern str acc_fromuri_col;
extern str acc_fromtag_col;
extern str acc_touri_col;
extern str acc_totag_col;
extern str acc_callid_col;
extern str acc_cseqno_col;
extern str acc_sipcode_col;
extern str acc_sipreason_col;
extern str acc_time_col;
extern str acc_duration_col;
extern str acc_ms_duration_col;
extern str acc_setuptime_col;
extern str acc_created_col;

extern int db_table_name;
extern unsigned short db_table_name_type;


extern int evi_flag;
extern int evi_missed_flag;

extern int is_cdr_enabled;

#endif
