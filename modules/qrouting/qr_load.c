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
str dsbl_asr_qp_col = str_init(DSBL_ASR_QP_COL);
str dsbl_ccr_qp_col = str_init(DSBL_CCR_QP_COL);
str dsbl_pdd_qp_col = str_init(DSBL_PDD_QP_COL);
str dsbl_ast_qp_col = str_init(DSBL_AST_QP_COL);
str dsbl_acd_qp_col = str_init(DSBL_ACD_QP_COL);

void add_profile(int id, char *name, double warn_asr, double warn_ccr,
		double warn_pdd, double warn_ast, double warn_acd, double dsbl_asr,
		double dsbl_ccr, double dsbl_pdd, double dsbl_ast, double dsbl_acd) {

	((*qr_profiles)[*n_qr_profiles]).id = id;
	((*qr_profiles)[*n_qr_profiles]).name.s = name;
	((*qr_profiles)[*n_qr_profiles]).name.len = strlen(name);

	(*qr_profiles)[*n_qr_profiles].asr1 = warn_asr;
	(*qr_profiles)[*n_qr_profiles].ccr1 = warn_ccr;
	(*qr_profiles)[*n_qr_profiles].pdd1 = warn_pdd;
	(*qr_profiles)[*n_qr_profiles].ast1 = warn_ast;
	(*qr_profiles)[*n_qr_profiles].acd1 = warn_acd;

	(*qr_profiles)[*n_qr_profiles].asr2 = dsbl_asr;
	(*qr_profiles)[*n_qr_profiles].ccr2 = dsbl_ccr;
	(*qr_profiles)[*n_qr_profiles].pdd2 = dsbl_pdd;
	(*qr_profiles)[*n_qr_profiles].ast2 = dsbl_ast;
	(*qr_profiles)[*n_qr_profiles].acd2 = dsbl_acd;
	(*n_qr_profiles)++;
}

int qr_load(db_func_t *qr_dbf, db_con_t* qr_db_hdl) {
	int int_vals[N_INT_VALS];
	char *str_vals[N_STR_VALS];
	double double_vals[N_DOUBLE_VALS];

	db_key_t columns[12];
	db_res_t *res = 0;
	db_row_t *row = 0;
	int i, n, no_rows = 0;
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
	columns[7] = &dsbl_asr_qp_col;
	columns[8] = &dsbl_ccr_qp_col;
	columns[9] = &dsbl_pdd_qp_col;
	columns[10] = &dsbl_ast_qp_col;
	columns[11] = &dsbl_acd_qp_col;

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

		no_rows = estimate_available_rows( 4+64+10*sizeof(double), db_cols);
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

	LM_DBG("%d records found in table %.*s\n",
			RES_ROW_N(res), qr_profiles_table.len,qr_profiles_table.s);

	n = 0;

	*qr_profiles = (qr_thresholds_t*)shm_malloc(RES_ROW_N(res)*
			sizeof(qr_thresholds_t));

	if(*qr_profiles == NULL) {
		LM_ERR("no more shm memory\n");
		return -1;
	}
	do {
		for(i = 0; i < RES_ROW_N(res); i++) {
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

			check_val(dsbl_asr_qp_col, ROW_VALUES(row)+7, DB_DOUBLE, 1, 1);
			double_vals[DOUBLE_VALS_DSBL_ASR] = VAL_DOUBLE(ROW_VALUES(row)+7);

			check_val(dsbl_ccr_qp_col, ROW_VALUES(row)+8, DB_DOUBLE, 1, 1);
			double_vals[DOUBLE_VALS_DSBL_CCR] = VAL_DOUBLE(ROW_VALUES(row)+8);

			check_val(dsbl_pdd_qp_col, ROW_VALUES(row)+9, DB_DOUBLE, 1, 1);
			double_vals[DOUBLE_VALS_DSBL_PDD] = VAL_DOUBLE(ROW_VALUES(row)+9);

			check_val(dsbl_ast_qp_col, ROW_VALUES(row)+10, DB_DOUBLE, 1, 1);
			double_vals[DOUBLE_VALS_DSBL_AST] = VAL_DOUBLE(ROW_VALUES(row)+10);

			check_val(dsbl_acd_qp_col, ROW_VALUES(row)+11, DB_DOUBLE, 1, 1);
			double_vals[DOUBLE_VALS_DSBL_ACD] = VAL_DOUBLE(ROW_VALUES(row)+11);
			n++;

			LM_DBG("qr_profile row: %d %s %lf %lf %lf %lf %lf %lf %lf %lf %lf %lf\n",
					int_vals[INT_VALS_ID], str_vals[STR_VALS_PROFILE_NAME],
					double_vals[DOUBLE_VALS_WARN_ASR], double_vals[DOUBLE_VALS_WARN_CCR],
					double_vals[DOUBLE_VALS_WARN_PDD], double_vals[DOUBLE_VALS_WARN_AST],
					double_vals[DOUBLE_VALS_WARN_ACD], double_vals[DOUBLE_VALS_DSBL_ASR],
					double_vals[DOUBLE_VALS_DSBL_CCR], double_vals[DOUBLE_VALS_DSBL_PDD],
					double_vals[DOUBLE_VALS_DSBL_AST], double_vals[DOUBLE_VALS_DSBL_ACD]);
			add_profile(
					int_vals[INT_VALS_ID], str_vals[STR_VALS_PROFILE_NAME],
					double_vals[DOUBLE_VALS_WARN_ASR], double_vals[DOUBLE_VALS_WARN_CCR],
					double_vals[DOUBLE_VALS_WARN_PDD], double_vals[DOUBLE_VALS_WARN_AST],
					double_vals[DOUBLE_VALS_WARN_ACD], double_vals[DOUBLE_VALS_DSBL_ASR],
					double_vals[DOUBLE_VALS_DSBL_CCR], double_vals[DOUBLE_VALS_DSBL_PDD],
					double_vals[DOUBLE_VALS_DSBL_AST], double_vals[DOUBLE_VALS_DSBL_ACD]);
		}
		if (DB_CAPABILITY(*qr_dbf, DB_CAP_FETCH)) {
			if(qr_dbf->fetch_result(qr_db_hdl, &res, no_rows)<0) {
				LM_ERR( "fetching rows (1)\n");
				goto error;
			}
		} else {
			break;
		}

	} while(RES_ROW_N(res));

	return 0;
error:
	return -1;

}

