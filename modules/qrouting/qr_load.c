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

#include <string.h>
#include <stdlib.h>

#include "../../ut.h"
#include "../../mem/shm_mem.h"

#include "qr_load.h"
#include "qr_stats.h"

#define check_val( _col, _val, _type, _not_null, _is_empty_str) \
	do{\
		if ((_val)->type!=_type) { \
			LM_ERR("column %.*s has a bad type\n", _col.len, _col.s); \
			goto error;\
		} \
		if (_not_null && (_val)->nul) { \
			LM_ERR("column %.*s is null\n", _col.len, _col.s); \
			goto error;\
		} \
		if (_is_empty_str && VAL_STRING(_val)==0) { \
			LM_ERR("column %.*s (str) is empty\n", _col.len, _col.s); \
			goto error;\
		} \
	}while(0)

str qr_profiles_table = str_init("qr_profiles");
str id_qp_col = str_init(ID_QP_COL);
str profile_name_qp_col = str_init(PROFILE_NAME_QP_COL);
str warn_asr_qp_col = str_init(WARN_ASR_QP_COL);
str warn_ccr_qp_col = str_init(WARN_CCR_QP_COL);
str warn_pdd_qp_col = str_init(WARN_PDD_QP_COL);
str warn_ast_qp_col = str_init(WARN_AST_QP_COL);
str warn_acd_qp_col = str_init(WARN_ACD_QP_COL);
str crit_asr_qp_col = str_init(CRIT_ASR_QP_COL);
str crit_ccr_qp_col = str_init(CRIT_CCR_QP_COL);
str crit_pdd_qp_col = str_init(CRIT_PDD_QP_COL);
str crit_ast_qp_col = str_init(CRIT_AST_QP_COL);
str crit_acd_qp_col = str_init(CRIT_ACD_QP_COL);

static inline void add_profile(qr_thresholds_t *prof, int id, const char *name,
		double warn_asr, double warn_ccr, double warn_pdd, double warn_ast,
		double warn_acd, double crit_asr, double crit_ccr, double crit_pdd,
		double crit_ast, double crit_acd)
{
	prof->id = id;
	strncpy(prof->name, name, QR_NAME_COL_SZ + 1);

	prof->asr1 = warn_asr;
	prof->ccr1 = warn_ccr;
	prof->pdd1 = warn_pdd;
	prof->ast1 = warn_ast;
	prof->acd1 = warn_acd;

	prof->asr2 = crit_asr;
	prof->ccr2 = crit_ccr;
	prof->pdd2 = crit_pdd;
	prof->ast2 = crit_ast;
	prof->acd2 = crit_acd;
}

/* refresh a single threshold set (1 row) */
static inline void qr_refresh_threshold_set(qr_thresholds_t *thr,
                                            qr_thresholds_t *new)
{
	qr_rule_t *r;
	qr_partitions_t *parts;
	int i;

	lock_start_write(*rw_lock_qr);
	parts = *qr_main_list;

	/* XXX: is this dead code?  also review qr_rotate_samples() */
	if (!parts) {
		lock_stop_write(*rw_lock_qr);
		return;
	}

	for (i = 0; i < parts->n_parts; i++) /* for every partition */
		for (r = parts->qr_rules_start[i]; r; r = r->next) /* and rule */
			if (r->thresholds == thr)
				r->thresholds = new;

	lock_stop_write(*rw_lock_qr);
}

/* refresh all reloaded threshold sets (rows) */
static inline void qr_refresh_threshold_sets(qr_thresholds_t *old, int old_n,
                                             qr_thresholds_t *new, int new_n)
{
	int i, j, id, found;

	LM_DBG("updating references for %p -> %p qr_profiles reload\n", old, new);

	/* try to match each old qr profile with a new one:
	 *   - if found, just refresh all references to it
	 *   - otherwise, just set the references to NULL */
	for (i = 0; i < old_n; i++) {
		id = old[i].id;
		found = 0;

		for (j = 0; j < new_n; j++) {
			if (id == new[j].id) {
				LM_DBG("matched qr_profile %d with reloaded data\n", id);
				qr_refresh_threshold_set(&old[i], &new[j]);
				found = 1;
				break;
			}
		}

		/* this old threshold id was discarded (replaced?), then reloaded */
		if (!found)
			qr_refresh_threshold_set(&old[i], NULL);
	}
}

int qr_reload(db_func_t *qr_dbf, db_con_t *qr_db_hdl)
{
	int int_vals[N_INT_VALS];
	char *str_vals[N_STR_VALS];
	double double_vals[N_DOUBLE_VALS];

	qr_thresholds_t *profs = NULL, *old_profs;
	db_key_t columns[12];
	db_res_t *res = 0;
	db_row_t *row = 0;
	int i, no_rows = 0, total_rows = 0, old_n;
	int db_cols = 0;

	memset(double_vals, 0, N_DOUBLE_VALS*sizeof(double));
	memset(int_vals, 0, N_INT_VALS*sizeof(int));
	memset(str_vals, 0, N_STR_VALS*sizeof(char*));

	columns[0] = &id_qp_col;
	columns[1] = &profile_name_qp_col;
	columns[2] = &warn_asr_qp_col;
	columns[3] = &warn_ccr_qp_col;
	columns[4] = &warn_pdd_qp_col;
	columns[5] = &warn_ast_qp_col;
	columns[6] = &warn_acd_qp_col;
	columns[7] = &crit_asr_qp_col;
	columns[8] = &crit_ccr_qp_col;
	columns[9] = &crit_pdd_qp_col;
	columns[10] = &crit_ast_qp_col;
	columns[11] = &crit_acd_qp_col;

	db_cols = 12;

	if (qr_dbf->use_table( qr_db_hdl, &qr_profiles_table) < 0) {
		LM_ERR("cannot select table \"%.*s\"\n", qr_profiles_table.len,
				qr_profiles_table.s);
		goto error;
	}

	if (DB_CAPABILITY(*qr_dbf, DB_CAP_FETCH)) {
		if ( qr_dbf->query( qr_db_hdl, 0, 0, 0, columns, 0, db_cols, 0, 0 ) < 0) {
			LM_ERR("DB query failed\n");
			goto error;
		}

		no_rows = estimate_available_rows(4+QR_NAME_COL_SZ+10*sizeof(double),
		                                  db_cols);
		if (no_rows==0) no_rows = 10;
		if(qr_dbf->fetch_result(qr_db_hdl, &res, no_rows )<0) {
			LM_ERR("Error fetching rows\n");
			goto error;
		}
	} else {
		if ( qr_dbf->query(qr_db_hdl,0,0,0,columns,0,db_cols,0,&res) < 0) {
			LM_ERR("DB query failed\n");
			goto error;
		}
	}

	if (RES_ROW_N(res) == 0) {
		LM_INFO("table '%.*s' is empty\n",
		        qr_profiles_table.len, qr_profiles_table.s);
		goto swap_data;
	}

	LM_DBG("%d records found in table %.*s\n",
			RES_ROW_N(res), qr_profiles_table.len,qr_profiles_table.s);

	do {
		profs = shm_realloc(profs, (total_rows + RES_ROW_N(res)) *
		                            sizeof *profs);
		if (!profs) {
			LM_ERR("oom\n");
			return -1;
		}
		memset(&profs[total_rows], 0, RES_ROW_N(res) * sizeof *profs);

		for (i = 0; i < RES_ROW_N(res); i++) {
			row = RES_ROWS(res) + i;

			check_val(id_qp_col, ROW_VALUES(row), DB_INT, 1, 1);
			int_vals[INT_VALS_ID] = VAL_INT(ROW_VALUES(row));

			check_val(profile_name_qp_col, ROW_VALUES(row)+1, DB_STRING, 1, 1);
			str_vals[STR_VALS_PROFILE_NAME] = (char*)VAL_STRING(ROW_VALUES(row)+1);

			check_val(warn_asr_qp_col, ROW_VALUES(row)+2, DB_DOUBLE, 1, 1);
			double_vals[DOUBLE_VALS_WARN_ASR] = VAL_DOUBLE(ROW_VALUES(row)+2);

			check_val(warn_ccr_qp_col, ROW_VALUES(row)+3, DB_DOUBLE, 1, 1);
			double_vals[DOUBLE_VALS_WARN_CCR] = VAL_DOUBLE(ROW_VALUES(row)+3);

			check_val(warn_pdd_qp_col, ROW_VALUES(row)+4, DB_DOUBLE, 1, 1);
			double_vals[DOUBLE_VALS_WARN_PDD] = VAL_DOUBLE(ROW_VALUES(row)+4);

			check_val(warn_ast_qp_col, ROW_VALUES(row)+5, DB_DOUBLE, 1, 1);
			double_vals[DOUBLE_VALS_WARN_AST] = VAL_DOUBLE(ROW_VALUES(row)+5);

			check_val(warn_acd_qp_col, ROW_VALUES(row)+6, DB_DOUBLE, 1, 1);
			double_vals[DOUBLE_VALS_WARN_ACD] = VAL_DOUBLE(ROW_VALUES(row)+6);

			check_val(crit_asr_qp_col, ROW_VALUES(row)+7, DB_DOUBLE, 1, 1);
			double_vals[DOUBLE_VALS_CRIT_ASR] = VAL_DOUBLE(ROW_VALUES(row)+7);

			check_val(crit_ccr_qp_col, ROW_VALUES(row)+8, DB_DOUBLE, 1, 1);
			double_vals[DOUBLE_VALS_CRIT_CCR] = VAL_DOUBLE(ROW_VALUES(row)+8);

			check_val(crit_pdd_qp_col, ROW_VALUES(row)+9, DB_DOUBLE, 1, 1);
			double_vals[DOUBLE_VALS_CRIT_PDD] = VAL_DOUBLE(ROW_VALUES(row)+9);

			check_val(crit_ast_qp_col, ROW_VALUES(row)+10, DB_DOUBLE, 1, 1);
			double_vals[DOUBLE_VALS_CRIT_AST] = VAL_DOUBLE(ROW_VALUES(row)+10);

			check_val(crit_acd_qp_col, ROW_VALUES(row)+11, DB_DOUBLE, 1, 1);
			double_vals[DOUBLE_VALS_CRIT_ACD] = VAL_DOUBLE(ROW_VALUES(row)+11);

			LM_DBG("qr_profile row: %d %s %lf %lf %lf %lf %lf %lf %lf %lf %lf %lf\n",
					int_vals[INT_VALS_ID], str_vals[STR_VALS_PROFILE_NAME],
					double_vals[DOUBLE_VALS_WARN_ASR], double_vals[DOUBLE_VALS_WARN_CCR],
					double_vals[DOUBLE_VALS_WARN_PDD], double_vals[DOUBLE_VALS_WARN_AST],
					double_vals[DOUBLE_VALS_WARN_ACD], double_vals[DOUBLE_VALS_CRIT_ASR],
					double_vals[DOUBLE_VALS_CRIT_CCR], double_vals[DOUBLE_VALS_CRIT_PDD],
					double_vals[DOUBLE_VALS_CRIT_AST], double_vals[DOUBLE_VALS_CRIT_ACD]);

			add_profile(&profs[total_rows], int_vals[INT_VALS_ID],
					str_vals[STR_VALS_PROFILE_NAME],
					double_vals[DOUBLE_VALS_WARN_ASR], double_vals[DOUBLE_VALS_WARN_CCR],
					double_vals[DOUBLE_VALS_WARN_PDD], double_vals[DOUBLE_VALS_WARN_AST],
					double_vals[DOUBLE_VALS_WARN_ACD], double_vals[DOUBLE_VALS_CRIT_ASR],
					double_vals[DOUBLE_VALS_CRIT_CCR], double_vals[DOUBLE_VALS_CRIT_PDD],
					double_vals[DOUBLE_VALS_CRIT_AST], double_vals[DOUBLE_VALS_CRIT_ACD]);

			total_rows++;
		}

		if (DB_CAPABILITY(*qr_dbf, DB_CAP_FETCH)) {
			if (qr_dbf->fetch_result(qr_db_hdl, &res, no_rows) < 0) {
				LM_ERR("fetching rows (1)\n");
				goto error;
			}
		} else {
			break;
		}

	} while (RES_ROW_N(res));

swap_data:
	lock_start_write(qr_profiles_rwl);
	old_profs = *qr_profiles;
	old_n = *qr_profiles_n;

	*qr_profiles = profs;
	*qr_profiles_n = total_rows;

	qr_refresh_threshold_sets(old_profs, old_n, profs, total_rows);
	lock_stop_write(qr_profiles_rwl);

	shm_free(old_profs);

	LM_DBG("reloaded into %d new profiles (%p -> %p)\n",
	       total_rows, old_profs, profs);
	return 0;

error:
	return -1;
}
