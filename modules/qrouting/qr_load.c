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

#include <string.h>
#include <stdlib.h>

#include "../../ut.h"
#include "../../mem/shm_mem.h"

#include "qrouting.h"
#include "qr_stats.h"
#include "qr_load.h"

#define check_val( _col, _val, _type, _not_null, _is_empty_str) \
	do{\
		if ((_val)->type!=_type) { \
			LM_ERR("column %s has a bad type\n", _col); \
			goto error;\
		} \
		if (_not_null && (_val)->nul) { \
			LM_ERR("column %s is null\n", _col); \
			goto error;\
		} \
		if (_is_empty_str && VAL_STRING(_val)==0) { \
			LM_ERR("column %s (str) is empty\n", _col); \
			goto error;\
		} \
	}while(0)

str qr_profiles_table = str_init("qr_profiles");

static inline void add_profile(qr_profile_t *prof,
		const int *int_vals, char * const *str_vals, const double *double_vals)
{
	int i, len;

	prof->id = int_vals[INT_VALS_ID];

	len = strlen(str_vals[STR_VALS_PROFILE_NAME]);
	if (len > QR_NAME_COL_SZ)
		len = QR_NAME_COL_SZ;
	memcpy(prof->name, str_vals[STR_VALS_PROFILE_NAME], len);
	prof->name[len] = '\0';

	prof->asr1 = double_vals[DBL_VALS_WARN_ASR];
	prof->ccr1 = double_vals[DBL_VALS_WARN_CCR];
	prof->pdd1 = double_vals[DBL_VALS_WARN_PDD];
	prof->ast1 = double_vals[DBL_VALS_WARN_AST];
	prof->acd1 = double_vals[DBL_VALS_WARN_ACD];

	prof->asr2 = double_vals[DBL_VALS_CRIT_ASR];
	prof->ccr2 = double_vals[DBL_VALS_CRIT_CCR];
	prof->pdd2 = double_vals[DBL_VALS_CRIT_PDD];
	prof->ast2 = double_vals[DBL_VALS_CRIT_AST];
	prof->acd2 = double_vals[DBL_VALS_CRIT_ACD];

	prof->asr_pty1 = double_vals[DBL_VALS_WPTY_ASR];
	prof->ccr_pty1 = double_vals[DBL_VALS_WPTY_CCR];
	prof->pdd_pty1 = double_vals[DBL_VALS_WPTY_PDD];
	prof->ast_pty1 = double_vals[DBL_VALS_WPTY_AST];
	prof->acd_pty1 = double_vals[DBL_VALS_WPTY_ACD];

	prof->asr_pty2 = double_vals[DBL_VALS_CPTY_ASR];
	prof->ccr_pty2 = double_vals[DBL_VALS_CPTY_CCR];
	prof->pdd_pty2 = double_vals[DBL_VALS_CPTY_PDD];
	prof->ast_pty2 = double_vals[DBL_VALS_CPTY_AST];
	prof->acd_pty2 = double_vals[DBL_VALS_CPTY_ACD];

	for (i = 0; i < qr_xstats_n; i++) {
		prof->xstats[i].thr1 = double_vals[DBL_VALS_XSTATS + i*4 + 0];
		prof->xstats[i].thr2 = double_vals[DBL_VALS_XSTATS + i*4 + 1];
		prof->xstats[i].pty1 = double_vals[DBL_VALS_XSTATS + i*4 + 2];
		prof->xstats[i].pty2 = double_vals[DBL_VALS_XSTATS + i*4 + 3];
	}
}

/* refresh a single profile (1 row) */
static inline void qr_refresh_profile(qr_profile_t *old, qr_profile_t *new)
{
	qr_rule_t *r;
	qr_partitions_t *parts;
	int i;

	lock_start_write(qr_main_list_rwl);
	parts = *qr_main_list;

	/* XXX: is this dead code?  also review qr_rotate_samples() */
	if (!parts) {
		lock_stop_write(qr_main_list_rwl);
		return;
	}

	for (i = 0; i < parts->n_parts; i++) /* for every partition */
		for (r = parts->qr_rules_start[i]; r; r = r->next) /* and rule */
			if (r->profile == old)
				r->profile = new;

	lock_stop_write(qr_main_list_rwl);
}

/* refresh all reloaded profiles (rows) */
static inline void qr_refresh_profiles(qr_profile_t *old, int old_n,
                                       qr_profile_t *new, int new_n)
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
				qr_refresh_profile(&old[i], &new[j]);
				found = 1;
				break;
			}
		}

		/* this old threshold id was discarded (replaced?), then reloaded */
		if (!found)
			qr_refresh_profile(&old[i], NULL);
	}
}

int qr_reload(db_func_t *qr_dbf, db_con_t *qr_db_hdl)
{
	int int_vals[N_INT_VALS];
	char *str_vals[N_STR_VALS];
	double dbl_vals[N_DBL_VALS + 4 * qr_xstats_n];

	qr_profile_t *profs = NULL, *old_profs;
	db_res_t *res = 0;
	db_row_t *row = 0;
	int i, j, no_rows = 0, total_rows = 0, old_n;
	int n_cols = N_INT_VALS + N_STR_VALS + N_DBL_VALS;
	str _columns[] = {
		str_init(QP_ID_COL),
		str_init(QP_PROFILE_NAME_COL),
		str_init(QP_WARN_ASR_COL),
		str_init(QP_WARN_CCR_COL),
		str_init(QP_WARN_PDD_COL),
		str_init(QP_WARN_AST_COL),
		str_init(QP_WARN_ACD_COL),
		str_init(QP_CRIT_ASR_COL),
		str_init(QP_CRIT_CCR_COL),
		str_init(QP_CRIT_PDD_COL),
		str_init(QP_CRIT_AST_COL),
		str_init(QP_CRIT_ACD_COL),
		str_init(QP_WPTY_ASR_COL),
		str_init(QP_WPTY_CCR_COL),
		str_init(QP_WPTY_PDD_COL),
		str_init(QP_WPTY_AST_COL),
		str_init(QP_WPTY_ACD_COL),
		str_init(QP_CPTY_ASR_COL),
		str_init(QP_CPTY_CCR_COL),
		str_init(QP_CPTY_PDD_COL),
		str_init(QP_CPTY_AST_COL),
		str_init(QP_CPTY_ACD_COL),
	}, *p;
	db_key_t *columns, orderby = &_columns[0];

	memset(int_vals, 0, N_INT_VALS * sizeof *int_vals);
	memset(str_vals, 0, N_STR_VALS * sizeof *str_vals);
	memset(dbl_vals, 0, (N_DBL_VALS + 4 * qr_xstats_n) * sizeof *dbl_vals);

	columns = pkg_malloc((n_cols + 4 * qr_xstats_n) * sizeof *columns);
	if (!columns) {
		LM_ERR("oom\n");
		return -1;
	}
	memset(columns, 0, (n_cols + 4 * qr_xstats_n) * sizeof *columns);

	for (i = 0; i < n_cols; i++)
		columns[i] = &_columns[i];

	if (qr_xstats_n) {
		p = pkg_malloc(qr_xstats_n * (4 * (sizeof(str) + QR_NAME_COL_SZ)));
		if (!p) {
			LM_ERR("oom\n");
			goto error;
		}
	}

	for (i = 0; i < qr_xstats_n; i++) {
		columns[n_cols + i*4] = p;
		p->s = (char *)(p + 1);
		p->len = snprintf(p->s, QR_NAME_COL_SZ, "warn_threshold_%.*s",
		                  qr_xstats[i].name.len, qr_xstats[i].name.s);

		p = (str *)(p->s + p->len);
		columns[n_cols + i*4 + 1] = p;
		p->s = (char *)(p + 1);
		p->len = snprintf(p->s, QR_NAME_COL_SZ, "crit_threshold_%.*s",
		                  qr_xstats[i].name.len, qr_xstats[i].name.s);

		p = (str *)(p->s + p->len);
		columns[n_cols + i*4 + 2] = p;
		p->s = (char *)(p + 1);
		p->len = snprintf(p->s, QR_NAME_COL_SZ, "warn_penalty_%.*s",
		                  qr_xstats[i].name.len, qr_xstats[i].name.s);

		p = (str *)(p->s + p->len);
		columns[n_cols + i*4 + 3] = p;
		p->s = (char *)(p + 1);
		p->len = snprintf(p->s, QR_NAME_COL_SZ, "crit_penalty_%.*s",
		                  qr_xstats[i].name.len, qr_xstats[i].name.s);

		p = (str *)(p->s + p->len);
	}

	if (qr_dbf->use_table( qr_db_hdl, &qr_profiles_table) < 0) {
		LM_ERR("cannot select table \"%.*s\"\n", qr_profiles_table.len,
				qr_profiles_table.s);
		goto error;
	}

	if (DB_CAPABILITY(*qr_dbf, DB_CAP_FETCH)) {
		if (qr_dbf->query(qr_db_hdl, 0, 0, 0, columns, 0,
		                  n_cols + 4 * qr_xstats_n, orderby, 0) < 0) {
			LM_ERR("DB query failed\n");
			goto error;
		}

		no_rows = estimate_available_rows(4 + QR_NAME_COL_SZ +
				(N_DBL_VALS + 4 * qr_xstats_n) * sizeof(double),
		                                  n_cols + 4 * qr_xstats_n);
		if (no_rows==0) no_rows = 10;
		if(qr_dbf->fetch_result(qr_db_hdl, &res, no_rows )<0) {
			LM_ERR("Error fetching rows\n");
			goto error;
		}
	} else {
		if (qr_dbf->query(qr_db_hdl, 0, 0, 0, columns, 0,
		                  n_cols + 4 * qr_xstats_n, orderby, &res) < 0) {
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

			check_val(QP_ID_COL, ROW_VALUES(row), DB_INT, 1, 1);
			int_vals[INT_VALS_ID] = VAL_INT(ROW_VALUES(row));

			check_val(QP_PROFILE_NAME_COL, ROW_VALUES(row)+1, DB_STRING, 1, 1);
			str_vals[STR_VALS_PROFILE_NAME] = (char*)VAL_STRING(ROW_VALUES(row)+1);


			check_val(QP_WARN_ASR_COL, ROW_VALUES(row)+2, DB_DOUBLE, 1, 1);
			dbl_vals[DBL_VALS_WARN_ASR] = VAL_DOUBLE(ROW_VALUES(row)+2);

			check_val(QP_WARN_CCR_COL, ROW_VALUES(row)+3, DB_DOUBLE, 1, 1);
			dbl_vals[DBL_VALS_WARN_CCR] = VAL_DOUBLE(ROW_VALUES(row)+3);

			check_val(QP_WARN_PDD_COL, ROW_VALUES(row)+4, DB_DOUBLE, 1, 1);
			dbl_vals[DBL_VALS_WARN_PDD] = VAL_DOUBLE(ROW_VALUES(row)+4);

			check_val(QP_WARN_AST_COL, ROW_VALUES(row)+5, DB_DOUBLE, 1, 1);
			dbl_vals[DBL_VALS_WARN_AST] = VAL_DOUBLE(ROW_VALUES(row)+5);

			check_val(QP_WARN_ACD_COL, ROW_VALUES(row)+6, DB_DOUBLE, 1, 1);
			dbl_vals[DBL_VALS_WARN_ACD] = VAL_DOUBLE(ROW_VALUES(row)+6);


			check_val(QP_CRIT_ASR_COL, ROW_VALUES(row)+7, DB_DOUBLE, 1, 1);
			dbl_vals[DBL_VALS_CRIT_ASR] = VAL_DOUBLE(ROW_VALUES(row)+7);

			check_val(QP_CRIT_CCR_COL, ROW_VALUES(row)+8, DB_DOUBLE, 1, 1);
			dbl_vals[DBL_VALS_CRIT_CCR] = VAL_DOUBLE(ROW_VALUES(row)+8);

			check_val(QP_CRIT_PDD_COL, ROW_VALUES(row)+9, DB_DOUBLE, 1, 1);
			dbl_vals[DBL_VALS_CRIT_PDD] = VAL_DOUBLE(ROW_VALUES(row)+9);

			check_val(QP_CRIT_AST_COL, ROW_VALUES(row)+10, DB_DOUBLE, 1, 1);
			dbl_vals[DBL_VALS_CRIT_AST] = VAL_DOUBLE(ROW_VALUES(row)+10);

			check_val(QP_CRIT_ACD_COL, ROW_VALUES(row)+11, DB_DOUBLE, 1, 1);
			dbl_vals[DBL_VALS_CRIT_ACD] = VAL_DOUBLE(ROW_VALUES(row)+11);


			check_val(QP_WPTY_ASR_COL, ROW_VALUES(row)+12, DB_DOUBLE, 1, 1);
			dbl_vals[DBL_VALS_WPTY_ASR] = VAL_DOUBLE(ROW_VALUES(row)+12);

			check_val(QP_WPTY_CCR_COL, ROW_VALUES(row)+13, DB_DOUBLE, 1, 1);
			dbl_vals[DBL_VALS_WPTY_CCR] = VAL_DOUBLE(ROW_VALUES(row)+13);

			check_val(QP_WPTY_PDD_COL, ROW_VALUES(row)+14, DB_DOUBLE, 1, 1);
			dbl_vals[DBL_VALS_WPTY_PDD] = VAL_DOUBLE(ROW_VALUES(row)+14);

			check_val(QP_WPTY_AST_COL, ROW_VALUES(row)+15, DB_DOUBLE, 1, 1);
			dbl_vals[DBL_VALS_WPTY_AST] = VAL_DOUBLE(ROW_VALUES(row)+15);

			check_val(QP_WPTY_ACD_COL, ROW_VALUES(row)+16, DB_DOUBLE, 1, 1);
			dbl_vals[DBL_VALS_WPTY_ACD] = VAL_DOUBLE(ROW_VALUES(row)+16);


			check_val(QP_CPTY_ASR_COL, ROW_VALUES(row)+17, DB_DOUBLE, 1, 1);
			dbl_vals[DBL_VALS_CPTY_ASR] = VAL_DOUBLE(ROW_VALUES(row)+17);

			check_val(QP_CPTY_CCR_COL, ROW_VALUES(row)+18, DB_DOUBLE, 1, 1);
			dbl_vals[DBL_VALS_CPTY_CCR] = VAL_DOUBLE(ROW_VALUES(row)+18);

			check_val(QP_CPTY_PDD_COL, ROW_VALUES(row)+19, DB_DOUBLE, 1, 1);
			dbl_vals[DBL_VALS_CPTY_PDD] = VAL_DOUBLE(ROW_VALUES(row)+19);

			check_val(QP_CPTY_AST_COL, ROW_VALUES(row)+20, DB_DOUBLE, 1, 1);
			dbl_vals[DBL_VALS_CPTY_AST] = VAL_DOUBLE(ROW_VALUES(row)+20);

			check_val(QP_CPTY_ACD_COL, ROW_VALUES(row)+21, DB_DOUBLE, 1, 1);
			dbl_vals[DBL_VALS_CPTY_ACD] = VAL_DOUBLE(ROW_VALUES(row)+21);

			LM_DBG("qr_profile (%d, %s) thresholds: [%lf %lf %lf %lf %lf] "
					"[%lf %lf %lf %lf %lf]\n",
					int_vals[INT_VALS_ID], str_vals[STR_VALS_PROFILE_NAME],
					dbl_vals[DBL_VALS_WARN_ASR], dbl_vals[DBL_VALS_WARN_CCR],
					dbl_vals[DBL_VALS_WARN_PDD], dbl_vals[DBL_VALS_WARN_AST],
					dbl_vals[DBL_VALS_WARN_ACD], dbl_vals[DBL_VALS_CRIT_ASR],
					dbl_vals[DBL_VALS_CRIT_CCR], dbl_vals[DBL_VALS_CRIT_PDD],
					dbl_vals[DBL_VALS_CRIT_AST], dbl_vals[DBL_VALS_CRIT_ACD]);

			LM_DBG("qr_profile (%d, %s) penalties: [%lf %lf %lf %lf %lf] "
					"[%lf %lf %lf %lf %lf]\n",
					int_vals[INT_VALS_ID], str_vals[STR_VALS_PROFILE_NAME],
					dbl_vals[DBL_VALS_WPTY_ASR], dbl_vals[DBL_VALS_WPTY_CCR],
					dbl_vals[DBL_VALS_WPTY_PDD], dbl_vals[DBL_VALS_WPTY_AST],
					dbl_vals[DBL_VALS_WPTY_ACD], dbl_vals[DBL_VALS_CPTY_ASR],
					dbl_vals[DBL_VALS_CPTY_CCR], dbl_vals[DBL_VALS_CPTY_PDD],
					dbl_vals[DBL_VALS_CPTY_AST], dbl_vals[DBL_VALS_CPTY_ACD]);

			for (j = 0; j < qr_xstats_n; j++) {
				check_val(columns[n_cols + j*4]->s,
							ROW_VALUES(row)+22 + j*4, DB_DOUBLE, 1, 1);
				dbl_vals[DBL_VALS_XSTATS + j*4] =
							VAL_DOUBLE(ROW_VALUES(row)+22 + j*4);

				check_val(columns[n_cols + j*4 + 1]->s,
							ROW_VALUES(row)+22 + j*4 + 1, DB_DOUBLE, 1, 1);
				dbl_vals[DBL_VALS_XSTATS + j*4 + 1] =
							VAL_DOUBLE(ROW_VALUES(row)+22 + j*4 + 1);

				check_val(columns[n_cols + j*4 + 2]->s,
							ROW_VALUES(row)+22 + j*4 + 2, DB_DOUBLE, 1, 1);
				dbl_vals[DBL_VALS_XSTATS + j*4 + 2] =
							VAL_DOUBLE(ROW_VALUES(row)+22 + j*4 + 2);

				check_val(columns[n_cols + j*4 + 3]->s,
							ROW_VALUES(row)+22 + j*4 + 3, DB_DOUBLE, 1, 1);
				dbl_vals[DBL_VALS_XSTATS + j*4 + 3] =
							VAL_DOUBLE(ROW_VALUES(row)+22 + j*4 + 3);

				LM_DBG("qr_profile (%d, %s) %s: [%lf %lf | %lf %lf]\n",
						int_vals[INT_VALS_ID], str_vals[STR_VALS_PROFILE_NAME],
						qr_xstats[j].name.s, dbl_vals[DBL_VALS_XSTATS + j*4],
						dbl_vals[DBL_VALS_XSTATS + j*4 + 1],
						dbl_vals[DBL_VALS_XSTATS + j*4 + 2],
						dbl_vals[DBL_VALS_XSTATS + j*4 + 3]);
			}

			add_profile(&profs[total_rows], int_vals, str_vals, dbl_vals);
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

	qr_refresh_profiles(old_profs, old_n, profs, total_rows);
	lock_stop_write(qr_profiles_rwl);

	if (qr_xstats_n)
		pkg_free(columns[n_cols]);

	pkg_free(columns);
	shm_free(old_profs);

	LM_DBG("reloaded into %d new profiles (%p -> %p)\n",
	       total_rows, old_profs, profs);
	return 0;

error:
	if (qr_xstats_n)
		pkg_free(columns[n_cols]);

	pkg_free(columns);
	shm_free(profs);
	return -1;
}
