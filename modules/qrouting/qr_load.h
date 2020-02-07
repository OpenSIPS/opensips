/*
 * Copyright (C) 2004-2005 FhG Fokus
 * Copyright (C) 2006-2010 Voice Sistem SRL
 * Copyright (C) 2014 OpenSIPS Foundation
 * Copyright (C) 2020 OpenSIPS Solutions
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "../../db/db.h"
#include "../../rw_locking.h"

/* qr_profiles table */
#define DOUBLE_VALS_WARN_ASR 0
#define DOUBLE_VALS_WARN_CCR 1
#define DOUBLE_VALS_WARN_PDD 2
#define DOUBLE_VALS_WARN_AST 3
#define DOUBLE_VALS_WARN_ACD 4
#define DOUBLE_VALS_CRIT_ASR 5
#define DOUBLE_VALS_CRIT_CCR 6
#define DOUBLE_VALS_CRIT_PDD 7
#define DOUBLE_VALS_CRIT_AST 8
#define DOUBLE_VALS_CRIT_ACD 9
#define INT_VALS_ID 0
#define STR_VALS_PROFILE_NAME 0

#define N_DOUBLE_VALS 10
#define N_STR_VALS 1
#define N_INT_VALS 1

/* column names */
#define ID_QP_COL "id"
#define PROFILE_NAME_QP_COL "profile_name"
#define WARN_ASR_QP_COL "warn_threshold_asr"
#define WARN_CCR_QP_COL "warn_threshold_ccr"
#define WARN_PDD_QP_COL "warn_threshold_pdd"
#define WARN_AST_QP_COL "warn_threshold_ast"
#define WARN_ACD_QP_COL "warn_threshold_acd"
#define CRIT_ASR_QP_COL "crit_threshold_asr"
#define CRIT_CCR_QP_COL "crit_threshold_ccr"
#define CRIT_PDD_QP_COL "crit_threshold_pdd"
#define CRIT_AST_QP_COL "crit_threshold_ast"
#define CRIT_ACD_QP_COL "crit_threshold_acd"

#define QR_NAME_COL_SZ 64

extern str qr_profiles_table;
extern rw_lock_t *qr_profiles_rwl;

extern db_func_t qr_dbf;
extern db_con_t *qr_db_hdl;

int qr_reload(db_func_t *qr_dbf, db_con_t *qr_db_hdl);
