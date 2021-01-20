/**
 * Fraud Detection Module
 *
 * Copyright (C) 2014 OpenSIPS Foundation
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
 * History
 * -------
 *  2014-09-26  initial version (Andrei Datcu)
*/

#include "../../ut.h"
#include "../../db/db.h"
#include "../drouting/dr_api.h"
#include "../../time_rec.h"

#include "frd_stats.h"

#define FRD_TABLE_VERSION             1
#define FRD_TIME_SEP                  ':'

#define FRD_RID_COL                   "ruleid"
#define FRD_PID_COL                   "profileid"
#define FRD_PREFIX_COL                "prefix"
#define FRD_START_H_COL               "start_hour"
#define FRD_END_H_COL                 "end_hour"
#define FRD_DAYS_COL                  "daysoftheweek"
#define FRD_CPM_THRESH_WARN_COL       "cpm_warning"
#define FRD_CPM_THRESH_CRIT_COL       "cpm_critical"
#define FRD_CALLDUR_THRESH_WARN_COL   "call_duration_warning"
#define FRD_CALLDUR_THRESH_CRIT_COL   "call_duration_critical"
#define FRD_TOTALC_THRESH_WARN_COL    "total_calls_warning"
#define FRD_TOTALC_THRESH_CRIT_COL    "total_calls_critical"
#define FRD_CONCALLS_THRESH_WARN_COL  "concurrent_calls_warning"
#define FRD_CONCALLS_THRESH_CRIT_COL  "concurrent_calls_critical"
#define FRD_SEQCALLS_THRESH_WARN_COL  "sequential_calls_warning"
#define FRD_SEQCALLS_THRESH_CRIT_COL  "sequential_calls_critical"


str db_url;
str table_name = str_init("fraud_detection");

str rid_col = str_init(FRD_RID_COL);
str pid_col = str_init(FRD_PID_COL);
str prefix_col = str_init(FRD_PREFIX_COL);
str start_h_col = str_init(FRD_START_H_COL);
str end_h_col = str_init(FRD_END_H_COL);
str days_col = str_init(FRD_DAYS_COL);
str cpm_thresh_warn_col = str_init(FRD_CPM_THRESH_WARN_COL);
str cpm_thresh_crit_col = str_init(FRD_CPM_THRESH_CRIT_COL);
str calldur_thresh_warn_col = str_init(FRD_CALLDUR_THRESH_WARN_COL);
str calldur_thresh_crit_col = str_init(FRD_CALLDUR_THRESH_CRIT_COL);
str totalc_thresh_warn_col = str_init(FRD_TOTALC_THRESH_WARN_COL);
str totalc_thresh_crit_col = str_init(FRD_TOTALC_THRESH_CRIT_COL);
str concalls_thresh_warn_col = str_init(FRD_CONCALLS_THRESH_WARN_COL);
str concalls_thresh_crit_col = str_init(FRD_CONCALLS_THRESH_CRIT_COL);
str seqcalls_thresh_warn_col = str_init(FRD_SEQCALLS_THRESH_WARN_COL);
str seqcalls_thresh_crit_col = str_init(FRD_SEQCALLS_THRESH_CRIT_COL);


static db_con_t *db_handle;
static db_func_t dbf;

extern dr_head_p *dr_head;
extern struct dr_binds drb;
extern rw_lock_t *frd_data_lock;

/* List of data kept in dr's attr and freed here - pkg */

typedef struct _free_list_t{
	tmrec_p trec;
	frd_thresholds_t *thr;
	unsigned int n;
	struct _free_list_t *next;
} free_list_t;

static free_list_t *free_list;


/*
 * Function that parse time string like %H:%M to a tm struct
 * tm struct must be allocated and initialized
*/

static int strtime(const str *time, int *ihrs, int *imin)
{
	char *colon = q_memchr(time->s, FRD_TIME_SEP, time->len);
	if (colon == NULL)
		goto parse_error;

	str hrs = {time->s, colon - time->s};
	str min = {colon + 1, time->len - hrs.len - 1};
	if (hrs.len == 0 || min.len == 0)
		goto parse_error;

	unsigned int uhrs, umin;
	if (str2int(&hrs, &uhrs) || str2int(&min, &umin))
		goto parse_error;

	if (uhrs > 23 || umin >= 60)
		goto parse_error;

	*imin = umin;
	*ihrs = uhrs;

	return 0;
parse_error:
	LM_ERR("cannot parse time-value <%.*s>", time->len, time->s);
	return -1;
}

static int strcmp_case_insensitive(char *s1, char *s2, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		if (tolower(s1[i]) != tolower(s2[i]))
			return -1;

	return 0;
}

static int parse_week_days(const str *week_days, unsigned short *day_set)
{
	static const str str_days[] = {
		str_init("sun"), str_init("mon"), str_init("tue"), str_init("wed"),
		str_init("thu"), str_init("fri"), str_init("sat")
	};

	static const char interval_delim = '-';
	static const char list_delim = ',';

	if (week_days->len == 0)
		return 0;

	char *p = week_days->s, *np, *dash;
	int rem_len = week_days->len, token_len, i, j, n = 0;
	str t1, t2;

	do {
		np = q_memchr(p, list_delim, rem_len);
		token_len = np ? np - p : rem_len;
		rem_len -= token_len + 1;

		if (token_len < 3)
			goto parse_error;

		/* Now we see if it is an interval */
		dash = q_memchr(p, interval_delim, token_len);

		if (dash){
			/* It is an interval */
			t1.s = p;
			t1.len = dash - p;
			trim_spaces_lr(t1);

			t2.s = dash + 1;
			t2.len = token_len - t1.len - 1;
			trim_spaces_lr(t2);

			if (t1.len != 3 || t2.len != 3)
				goto parse_error;

			for (i = 0; i < 7; ++i)
				if (strcmp_case_insensitive(str_days[i].s, t1.s, 3) == 0)
					break;
			if (i == 7)
				goto parse_error;

			for (j = 0; j < 7; ++j)
				if (strcmp_case_insensitive(str_days[j].s, t2.s, 3) == 0)
					break;
			if (j == 7)
				goto parse_error;

			/* We increase the size of the days set */
			n += (j - i + 7) % 7 + 1;

			for (; i != j; i = (i + 1) % 7)
				*day_set |= 1 << i;

			*day_set |= 1 << j;
		}
		else {
			/* Just one value */
			t1.s = p;
			t1.len = token_len;
			trim_spaces_lr(t1);

			if (t1.len != 3)
				goto parse_error;

			for (i = 0; i < 7; ++i)
				if (strcmp_case_insensitive(str_days[i].s, t1.s, 3) == 0)
					break;
			if (i == 7)
				goto parse_error;

			*day_set |= 1 << i;
			++n;
		}

		p = np + 1;
	} while (rem_len > 0);

	return n;

parse_error:
	LM_ERR("Cannot parse week day list <%.*s>", week_days->len, week_days->s);
	return -1;
}

static int create_time_rec(const str *time_start, const str *time_end,
		const str *week_days, tmrec_p trec, tmrec_p *out_rec)
{
	int end_h, end_m;

	memset(trec, 0, sizeof(tmrec_t));

	/* the default, "catch-all" time rec - using NULL is optimal */
	if (str_match(time_start, _str("00:00")) &&
	        str_match(time_end, _str("23:59")) &&
	        str_match(week_days, _str("Mon-Sun"))) {
		*out_rec = NULL;
		return 0;
	} else {
		*out_rec = trec;
	}

	if (strtime(time_start, &trec->ts.tm_hour, &trec->ts.tm_min) != 0
			|| strtime(time_end, &end_h, &end_m) != 0)
		return -1;

	trec->duration = (end_h * 3600 + end_m * 60) -
		(trec->ts.tm_hour * 3600 + trec->ts.tm_min * 60);
	trec->ts.tm_isdst = -1 /*daylight*/;
	trec->dtstart = trec->duration;
	trec->freq = FREQ_DAILY;

	unsigned short day_set = 0;
	int n = parse_week_days(week_days, &day_set);

	if (n == -1)
		return -1;

	if (n) {
		//TODO - byday custom init - no req needed
		trec->byday = tr_byxxx_new(SHM_ALLOC);
		if (trec->byday == NULL)
			return -1;

		if (tr_byxxx_init(trec->byday, n) < 0) {
			tr_byxxx_free(trec->byday);
			return -1;
		}

		short i, j = 0;

		for (i = 0; i < 7; ++i)
			if (day_set & 1 << i)
				trec->byday->xxx[j++] = i;
	}

	return 0;
}

static int frd_load_data(dr_head_p drp, free_list_t **fl)
{
	static const size_t col_count = 16;
	db_res_t *res = NULL;
	unsigned int no_rows = 0, row_count, i;
	db_row_t *rows;
	db_val_t *values;

	db_key_t query_cols[] = {
		&rid_col, &pid_col, &prefix_col, &start_h_col, &end_h_col, &days_col,
		&cpm_thresh_warn_col, &cpm_thresh_crit_col, &calldur_thresh_warn_col,
		&calldur_thresh_crit_col, &totalc_thresh_warn_col, &totalc_thresh_crit_col,
		&concalls_thresh_warn_col, &concalls_thresh_crit_col, &seqcalls_thresh_warn_col,
		&seqcalls_thresh_crit_col
	};

	if (db_handle == NULL) {
		LM_ERR("Invalid db handler\n");
		return -1;
	}

	if (dbf.use_table(db_handle, &table_name) != 0) {
		LM_ERR("Cannot use table\n");
		return -1;
	}

	if (DB_CAPABILITY(dbf, DB_CAP_FETCH)) {
		if (dbf.query(db_handle, 0, 0, 0, query_cols, 0, col_count, 0, 0) != 0) {
			LM_ERR("Error while querying db\n");
			goto error;
		}
		/* estimate rows */
		no_rows = estimate_available_rows(4 + 64 + 5 + 5 + 64 + 5 * 2 * 4, col_count);

		if (no_rows == 0)
			no_rows = 10;

		if (dbf.fetch_result(db_handle, &res, no_rows) != 0) {
			LM_ERR("Error while fetching rows\n");
			goto error;
		}
	} else {
		/* No fetching capability */
		if (dbf.query(db_handle, 0, 0, 0, query_cols, 0, col_count, 0, &res) != 0) {
			LM_ERR("Error while querying db\n");
			goto error;
		}
	}

	/* Process the actual data */

	unsigned int rid, pid, j;
	str prefix, start_time, end_time, days;
	free_list_t *fl_it = NULL;
	*fl = NULL;

	do {
		row_count = RES_ROW_N(res);
		rows = RES_ROWS(res);
		fl_it = pkg_malloc(sizeof(free_list_t));
		if (fl_it == NULL) {
			LM_ERR ("no more pkg memory\n");
			dbf.free_result(db_handle, res);
			return -1;
		}
		fl_it ->next = *fl;
		*fl = fl_it;
		fl_it->trec = shm_malloc(sizeof(tmrec_t) * row_count);
		if (fl_it->trec == NULL)
			goto no_more_shm;
		fl_it->thr = shm_malloc(sizeof(frd_thresholds_t) * row_count);
		if (fl_it->thr == NULL)
			goto no_more_shm;
		fl_it->n = row_count;

		for (i = 0; i < row_count; ++i) {
			tmrec_p trec;

			values = ROW_VALUES(rows + i);
			fl_it->trec[i].byday = NULL;

			/* rule id */
			if (VAL_NULL(values)) {
				LM_ERR("rule id cannot be NULL - skipping rule\n");
				continue;
			}
			rid = VAL_INT(values);

			/* profile id */
			if (VAL_NULL(values + 1)) {
				LM_ERR("profile id cannot be NULL - skipping rule\n");
				continue;
			}
			pid = VAL_INT(values + 1);

			get_str_from_dbval(prefix_col.s, values + 2, 1, 1, prefix, null_val);
			get_str_from_dbval(start_h_col.s, values + 3, 1, 1, start_time, null_val);
			get_str_from_dbval(end_h_col.s, values + 4, 1, 1, end_time, null_val);
			get_str_from_dbval(days_col.s, values + 5, 1, 1, days, null_val);

			if (create_time_rec(&start_time, &end_time, &days, fl_it->trec + i,
			        &trec) != 0)
				goto null_val;

			/* Now load the thresholds */
			for (j = 0; j < 2 * 5; ++j) {
				if (VAL_NULL(values + 6 + j))
					goto null_val;
				memcpy((char*)fl_it->thr + i * sizeof(frd_thresholds_t) +
						j * sizeof(unsigned int), &VAL_INT(values + 6 + j),
						sizeof(unsigned int));
			}

			/* Rule OK, time to put it in DR */
			if (drb.add_rule(drp, rid, &prefix, pid, 0, trec,
						(void*)(&fl_it->thr[i])) != 0) {

				LM_ERR("Cannot add rule in dr <%u>. Skipping...\n", rid);
			}

			null_val:
				continue;
		}

		if (DB_CAPABILITY(dbf, DB_CAP_FETCH)) {
			/* any more rows to fetch ? */
			if(dbf.fetch_result(db_handle, &res, no_rows)<0) {
				LM_ERR("error while fetching rows\n");
				goto error;
			}
			/* success in fetching more rows - continue the loop */
		} else
			break;

	} while (RES_ROW_N(res) > 0);

	dbf.free_result(db_handle, res);
	return 0;

no_more_shm:
	LM_ERR ("no more shm memory\n");
	dbf.free_result(db_handle, res);

error:
	return -1;
}

/* This function assumes no one is using the dr_head anymore */
static void frd_destroy_data_unsafe(dr_head_p dr_head, free_list_t *fl)
{
	if (dr_head == NULL && fl == NULL)
		return;

	drb.free_head(dr_head);
	free_list_t *it = fl, *aux;
	int i;

	while (it) {
		for (i = 0; i < it->n; ++i)
			if (it->trec[i].byday)
				tr_byxxx_free(it->trec[i].byday);
		shm_free(it->trec);
		shm_free(it->thr);
		aux = it;
		it = it->next;
		pkg_free(aux);
	}
}

/* Function to be called in mod_destroy
 * Still unsafe!!!
*/

void frd_destroy_data(void)
{
	frd_destroy_data_unsafe(*dr_head, free_list);
}

int frd_reload_data(void)
{
	dr_head_p new_head, old_head;

	if ((new_head = drb.create_head()) == NULL) {
		LM_ERR ("cannot create dr_head\n");
		return -1;
	}

	free_list_t *new_list = NULL, *old_list;

	if (frd_load_data(new_head, &new_list) != 0) {
		LM_ERR("cannot load fraud data\n");
		return -1;
	}

	old_head = *dr_head;
	old_list = free_list;
	lock_start_write(frd_data_lock);
	*dr_head = new_head;
	free_list = new_list;
	lock_stop_write(frd_data_lock);
	frd_destroy_data_unsafe(old_head, old_list);
	return 0;
}

int frd_connect_db(void)
{
	if (db_url.s == NULL || db_url.len == 0) {
		LM_ERR("invalid db_url\n");
		return -1;
	}

	if (db_handle != NULL) {
		LM_CRIT("[BUG] connection already open\n");
		return -1;
	}

	if ((db_handle = dbf.init(&db_url)) == 0) {
		LM_ERR("unable to connect to the database\n");
		return -1;
	}

	return 0;
}

void frd_disconnect_db(void)
{
	if (db_handle) {
		dbf.close(db_handle);
		db_handle = NULL;
	}
}


int frd_init_db(void)
{
	int table_version;

	if (table_name.s == NULL || table_name.len == 0) {
		LM_ERR("invalid table name\n");
		return -1;
	}

	if (db_bind_mod(&db_url, &dbf) != 0) {
		LM_ERR("unable to bind to a database driver\n");
		return -1;
	}

	if(frd_connect_db() != 0)
		return -1;

	table_version = db_table_version(&dbf, db_handle, &table_name);
	if (table_version < 0) {
		LM_ERR("failed to query table version\n");
		return -1;
	} else if (table_version != FRD_TABLE_VERSION) {
		LM_ERR("invalid table version (found %d , required %d)\n",
			table_version, FRD_TABLE_VERSION );
		return -1;
	}

	return 0;
}
