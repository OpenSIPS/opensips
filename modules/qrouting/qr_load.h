/*
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

#ifndef __QR_LOAD_H__
#define __QR_LOAD_H__

#include "../../db/db.h"
#include "../../rw_locking.h"

/* qr_profiles table */
#define INT_VALS_ID 0
#define STR_VALS_PROFILE_NAME 0
#define DBL_VALS_WARN_ASR 0
#define DBL_VALS_WARN_CCR 1
#define DBL_VALS_WARN_PDD 2
#define DBL_VALS_WARN_AST 3
#define DBL_VALS_WARN_ACD 4
#define DBL_VALS_CRIT_ASR 5
#define DBL_VALS_CRIT_CCR 6
#define DBL_VALS_CRIT_PDD 7
#define DBL_VALS_CRIT_AST 8
#define DBL_VALS_CRIT_ACD 9
#define DBL_VALS_WPTY_ASR 10
#define DBL_VALS_WPTY_CCR 11
#define DBL_VALS_WPTY_PDD 12
#define DBL_VALS_WPTY_AST 13
#define DBL_VALS_WPTY_ACD 14
#define DBL_VALS_CPTY_ASR 15
#define DBL_VALS_CPTY_CCR 16
#define DBL_VALS_CPTY_PDD 17
#define DBL_VALS_CPTY_AST 18
#define DBL_VALS_CPTY_ACD 19
#define DBL_VALS_XSTATS   20

#define N_INT_VALS 1
#define N_STR_VALS 1
#define N_DBL_VALS 20

/* column names */
#define QP_ID_COL "id"
#define QP_PROFILE_NAME_COL "profile_name"
#define QP_WARN_ASR_COL "warn_threshold_asr"
#define QP_WARN_CCR_COL "warn_threshold_ccr"
#define QP_WARN_PDD_COL "warn_threshold_pdd"
#define QP_WARN_AST_COL "warn_threshold_ast"
#define QP_WARN_ACD_COL "warn_threshold_acd"
#define QP_CRIT_ASR_COL "crit_threshold_asr"
#define QP_CRIT_CCR_COL "crit_threshold_ccr"
#define QP_CRIT_PDD_COL "crit_threshold_pdd"
#define QP_CRIT_AST_COL "crit_threshold_ast"
#define QP_CRIT_ACD_COL "crit_threshold_acd"
#define QP_WPTY_ASR_COL "warn_penalty_asr"
#define QP_WPTY_CCR_COL "warn_penalty_ccr"
#define QP_WPTY_PDD_COL "warn_penalty_pdd"
#define QP_WPTY_AST_COL "warn_penalty_ast"
#define QP_WPTY_ACD_COL "warn_penalty_acd"
#define QP_CPTY_ASR_COL "crit_penalty_asr"
#define QP_CPTY_CCR_COL "crit_penalty_ccr"
#define QP_CPTY_PDD_COL "crit_penalty_pdd"
#define QP_CPTY_AST_COL "crit_penalty_ast"
#define QP_CPTY_ACD_COL "crit_penalty_acd"

#define QR_NAME_COL_SZ 64
#define QR_MAX_STAT_NAME_LEN (QR_NAME_COL_SZ - strlen("warn_threshold_"))

extern str qr_profiles_table;
extern rw_lock_t *qr_profiles_rwl;

extern db_func_t qr_dbf;
extern db_con_t *qr_db_hdl;

int qr_reload(db_func_t *qr_dbf, db_con_t *qr_db_hdl);

#endif /* __QR_LOAD_H__ */
