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

#include <stdio.h>
#include <stdlib.h>
#include "report_emergency.h" 

#define NR_KEYS 				 12

static str id_rep_col=str_init("id");
static str callid_rep_col=str_init("callid");
static str srid_rep_col=str_init("selectiveRoutingID");
static str resn_rep_col=str_init("routingESN");
static str npa_rep_col=str_init("npa");
static str esgwri_rep_col=str_init("esgwri");
static str lro_rep_col=str_init("lro");
static str vpc_name_rep_col=str_init("VPC_organizationName");
static str vpc_host_rep_col=str_init("VPC_hostname");
static str timestamp_rep_col=str_init("VPC_timestamp");
static str result_rep_col=str_init("result");
static str disposition_rep_col=str_init("disposition");

static str id_col=str_init("id");
static str srid_col=str_init("selectiveRoutingID");
static str resn_col=str_init("routingESN");
static str npa_col=str_init("npa");
static str esgwri_col=str_init("esgwri");

/* store data in the table emergency_report
*/
int report(struct emergency_report *report, str db_url, str table_report) {

	static query_list_t *ins_list = NULL;
	static db_ps_t siptrace_ps = NULL;

	LM_DBG("Report emergency call in db\n");


	db_con = db_funcs.init(&db_url);
	if (!db_con) {
		LM_ERR("unable to connect database\n");
		return -1;
	}

	db_funcs.use_table(db_con, &table_report);

	db_key_t db_keys[NR_KEYS];


	db_val_t db_vals[NR_KEYS];

	if (report == NULL) {
		LM_DBG("invalid parameter\n");
		return -1;
	}

	db_keys[0] = &id_rep_col;
	db_vals[0].type = DB_BIGINT;
	db_vals[0].val.bigint_val = 0;


	db_keys[1] = &callid_rep_col;
	db_vals[1].type = DB_STR;
	db_vals[1].val.str_val = report->callid;

	LM_DBG("CALLID_REPORT %.*s \n", report->callid.len, report->callid.s);
	LM_DBG("CALLID_REPORT_LEN %d \n", report->callid.len);

	db_keys[2] = &srid_rep_col;
	db_vals[2].type = DB_STR;
	db_vals[2].val.str_val = report->ert_srid;

	LM_DBG("SRID_REPORT %.*s \n", report->ert_srid.len, report->ert_srid.s);
	LM_DBG("SRID_REPORT_LEN %d \n", report->ert_srid.len);

	db_keys[3] = &resn_rep_col;
	db_vals[3].type = DB_BIGINT;
	db_vals[3].val.bigint_val = report->ert_resn;

	LM_DBG("RESN_REPORT %d \n", report->ert_resn);

	db_keys[4] = &npa_rep_col;
	db_vals[4].type = DB_BIGINT;
	db_vals[4].val.bigint_val = report->ert_npa;

	LM_DBG("NPA_REPORT %d \n", report->ert_npa);

	db_keys[5] = &esgwri_rep_col;
	db_vals[5].type = DB_STR;
	db_vals[5].val.str_val = report->esgwri;

	LM_DBG("ESGWRI_REPORT %.*s \n", report->esgwri.len, report->esgwri.s);
	LM_DBG("ESGWRI_REPORT_LEN %d \n", report->esgwri.len);

	db_keys[6] = &lro_rep_col;
	db_vals[6].type = DB_STR;
	db_vals[6].val.str_val = report->lro;

	LM_DBG("LRO_REPORT %.*s \n", report->lro.len, report->lro.s);
	LM_DBG("LRO_REPORT_LEN %d \n", report->lro.len);

	db_keys[7] = &vpc_name_rep_col;
	db_vals[7].type = DB_STR;
	db_vals[7].val.str_val = report->vpc_name;

	LM_DBG("VPC_NAME_REPORT %.*s \n", report->vpc_name.len, report->vpc_name.s);
	LM_DBG("VPC_NAME_REPORT_LEN %d \n", report->vpc_name.len);

	db_keys[8] = &vpc_host_rep_col;
	db_vals[8].type = DB_STR;
	db_vals[8].val.str_val = report->vpc_host;

	LM_DBG("VPC_HOST_REPORT %.*s \n", report->vpc_host.len, report->vpc_host.s);
	LM_DBG("VPC_HOST_REPORT_LEN %d \n", report->vpc_host.len);

	db_keys[9] = &timestamp_rep_col;
	db_vals[9].type = DB_STR;
	db_vals[9].val.str_val = report->timestamp;

	LM_DBG("VPC_TIMESTAMP_REPORT %.*s \n", report->timestamp.len, report->timestamp.s);
	LM_DBG("VPC_TIMESTAMP_REPORT_LEN %d \n", report->timestamp.len);

	db_keys[10] = &result_rep_col;
	db_vals[10].type = DB_STR;
	db_vals[10].val.str_val = report->result;

	LM_DBG("RESULT_REPORT %.*s \n", report->result.len, report->result.s);
	LM_DBG("RESULT_REPORT_LEN %d \n", report->result.len);

	db_keys[11] = &disposition_rep_col;
	db_vals[11].type = DB_STR;
	db_vals[11].val.str_val = report->disposition;

	LM_DBG("DISPOSITION_REPORT %.*s \n", report->disposition.len, report->disposition.s);
	LM_DBG("DISPOSITION_REPORT_LEN %d \n", report->disposition.len);


	// no field can be null 
	int i = 0;

	for (i = 0; i < NR_KEYS; i++)
		db_vals[i].nul = 0;

	LM_DBG("storing info...\n");

	if (con_set_inslist(&db_funcs, db_con, &ins_list, db_keys, NR_KEYS) < 0)
		CON_RESET_INSLIST(db_con);
	CON_PS_REFERENCE(db_con) = &siptrace_ps;

	if (db_funcs.insert(db_con, db_keys, db_vals, NR_KEYS) < 0) {
		LM_ERR("failed to insert into database\n");
		return -1;;
	}

	db_funcs.close(db_con);
	db_con = 0;
	
	return 1;
}


/* collects data to system debug:
*   - CALLID
*   - ESGWRI
*   - ERT-RESN
*   - ERT-NPA 
*   - ERT-SRID 
*   - LRO 
*   - VPC - NAME 
*   - VPC - HOST 
*   - TIMESTAMP 
*   - RESULT 
*   - DISPOSITION 
*/
int collect_data(struct node *current, str db_url, str table_report) {

	int callid_len, esgwri_len, srid_len, lro_len, vpc_name_len, vpc_host_len, time_len, result_len, disposition_len;
	int size_report;
	struct emergency_report *report_eme; 
	callid_len = strlen(current->esct->callid);
	esgwri_len = strlen(current->esct->esgwri);
	srid_len = strlen(current->esct->ert_srid);
	lro_len = strlen(current->esct->lro);
	time_len = strlen(current->esct->datetimestamp);
	result_len = strlen(current->esct->result);
	disposition_len = strlen(current->esct->disposition);
	vpc_name_len = strlen(current->esct->vpc->organizationname);
	vpc_host_len = strlen(current->esct->vpc->hostname);
	
	size_report = sizeof (struct emergency_report) +callid_len + esgwri_len + srid_len + lro_len + vpc_name_len + vpc_host_len + time_len + result_len + disposition_len;
	report_eme = pkg_malloc(size_report);
	if (report_eme == NULL) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}
 
	memset(report_eme, 0, size_report);

	report_eme->callid.len = callid_len;
	report_eme->callid.s = (char *) (report_eme + 1);
	memcpy(report_eme->callid.s, current->esct->callid, callid_len);

	report_eme->ert_srid.len = srid_len;
	if (srid_len == 0) {
		report_eme->ert_srid.s = " ";
		report_eme->ert_srid.len = 1;
	} else {
		report_eme->ert_srid.s = (char *) (report_eme + 1) + callid_len;
		memcpy(report_eme->ert_srid.s, current->esct->ert_srid, srid_len);
	}

	report_eme->ert_resn = current->esct->ert_resn;
	report_eme->ert_npa = current->esct->ert_npa;
 
	report_eme->esgwri.len = esgwri_len;
	if (esgwri_len == 0) {
		report_eme->esgwri.s = " ";
		report_eme->esgwri.len = 1;
	} else {
		report_eme->esgwri.s = (char *) (report_eme + 1) + callid_len + srid_len;
		memcpy(report_eme->esgwri.s, current->esct->esgwri, esgwri_len);
	}

	report_eme->lro.len = lro_len;
	if (lro_len == 0) {
		report_eme->lro.s = " ";
		report_eme->lro.len = 1;
	} else {
		report_eme->lro.s = (char *) (report_eme + 1) + callid_len + srid_len + esgwri_len;
		memcpy(report_eme->lro.s, current->esct->lro, lro_len);
	}

	report_eme->vpc_name.len = vpc_name_len;
	if (vpc_name_len == 0) {
		report_eme->vpc_name.s = " ";
		report_eme->vpc_name.len = 1;
	} else {
		report_eme->vpc_name.s = (char *) (report_eme + 1) + callid_len + srid_len + esgwri_len + lro_len;
		memcpy(report_eme->vpc_name.s, current->esct->vpc->organizationname, vpc_name_len);
	}

	report_eme->vpc_host.len = vpc_host_len;
	if (vpc_host_len == 0) {
		report_eme->vpc_host.s = " ";
		report_eme->vpc_host.len = 1;
	} else {
		report_eme->vpc_host.s = (char *) (report_eme + 1) + callid_len + srid_len + esgwri_len + lro_len + vpc_name_len;
		memcpy(report_eme->vpc_host.s, current->esct->vpc->hostname, vpc_host_len);
	}
	report_eme->result.len = result_len;
	report_eme->result.s = (char *) (report_eme + 1) + callid_len + srid_len + esgwri_len + lro_len + vpc_name_len + vpc_host_len + time_len;
	memcpy(report_eme->result.s, current->esct->result, result_len);		  
 
	report_eme->timestamp.len = time_len;
	if (time_len == 0) {
		report_eme->timestamp.s = " ";
		report_eme->timestamp.len = 1;
	} else {
		report_eme->timestamp.s = (char *) (report_eme + 1) + callid_len + srid_len + esgwri_len + lro_len + vpc_name_len + vpc_host_len;
		memcpy(report_eme->timestamp.s, current->esct->datetimestamp, time_len);
	}  
	report_eme->disposition.len = disposition_len;
	report_eme->disposition.s = (char *) (report_eme + 1) + callid_len + srid_len + esgwri_len + lro_len + vpc_name_len + vpc_host_len + time_len + result_len;
	memcpy(report_eme->disposition.s, current->esct->disposition, disposition_len);

	LM_INFO(" --- REPORT - CALLID %.*s XXXXXXX\n\n", report_eme->callid.len, report_eme->callid.s);
	LM_INFO(" --- REPORT - ESGWRI %.*s \n\n", report_eme->esgwri.len, report_eme->esgwri.s);
	LM_INFO(" --- REPORT - ERT-RESN %d \n\n", report_eme->ert_resn);
	LM_INFO(" --- REPORT - ERT-NPA %d \n\n", report_eme->ert_npa);
	LM_INFO(" --- REPORT - ERT-SRID %.*s \n\n", report_eme->ert_srid.len, report_eme->ert_srid.s);
	LM_INFO(" --- REPORT - LRO %.*s \n\n", report_eme->lro.len, report_eme->lro.s);
	LM_INFO(" --- REPORT - VPC - NAME %.*s \n\n", report_eme->vpc_name.len, report_eme->vpc_name.s);
	LM_INFO(" --- REPORT - VPC - HOST %.*s \n\n", report_eme->vpc_host.len, report_eme->vpc_host.s);
	LM_INFO(" --- REPORT - TIMESTAMP %.*s \n\n", report_eme->timestamp.len, report_eme->timestamp.s);
	LM_INFO(" --- REPORT - RESULT %.*s \n\n", report_eme->result.len, report_eme->result.s);
	LM_INFO(" --- REPORT - DISPOSITION %.*s \n\n", report_eme->disposition.len, report_eme->disposition.s);

	LM_INFO(" --- TABLE_REPORT %.*s \n\n", table_report.len, table_report.s);   

	if (report(report_eme, db_url, table_report) != 1) {
		LM_DBG("****** INSERT NOK\n");
		pkg_free(report_eme);
		return -1;
	}

	LM_DBG("****** INSERT OK\n");
	pkg_free(report_eme);
	return 1;
}


/* retreives esgwrifrom the list db_esrn_esgwri
* using  srid(selectiveRoutingID), resn(routingESN) and npa. 
*/
int emergency_routing(char *srid, int resn, int npa, char** esgwri, rw_lock_t *ref_lock ) {

	lock_start_read(ref_lock);

	struct esrn_routing* esrn_domain = *db_esrn_esgwri;
	LM_DBG("SRID = %s \n", srid);
	while (esrn_domain != NULL) {
		LM_DBG("CMP SRID= %.*s \n", esrn_domain->srid.len, esrn_domain->srid.s);
		LM_DBG("CMP RESN= %d \n", esrn_domain->resn);
		LM_DBG("CMP NPA = %d \n", esrn_domain->npa);				
		if (strncmp(esrn_domain->srid.s, srid, esrn_domain->srid.len) == 0) {
			if ((esrn_domain->resn == resn)&&(esrn_domain->npa == npa)) {
				char* temp = pkg_malloc(sizeof (char) * esrn_domain->esgwri.len + 1);
				if (!temp) {
					LM_ERR("no more memory\n");
					lock_stop_read(ref_lock);
					return -1;
				}
				memcpy(temp, esrn_domain->esgwri.s, esrn_domain->esgwri.len);
				temp[esrn_domain->esgwri.len] = 0;
				*esgwri = temp;

				lock_stop_read(ref_lock);

				return 1;
			}
		}
		esrn_domain = esrn_domain->next;
	}
	lock_stop_read(ref_lock);

	return -1;
}

int get_db_routing(str table_name, rw_lock_t *ref_lock ){

	db_key_t query_cols[] = {&id_col, &srid_col, &resn_col, &npa_col, &esgwri_col};
	db_res_t * res;
	db_val_t * values;
	db_row_t * rows;
	str esgwri;
	str SRID;
	int RESN;
	int NPA;
	int nr_rows, i, size;
	struct esrn_routing *esrn_cell, *old_list, *it, *aux, *new_list;
	struct esrn_routing *init_esrn = NULL;


	db_funcs.use_table(db_con, &table_name);

	/* select value from routing table
	*  the keys of routing table: selectiveRoutingID, routingESN, npa
	*  the result of routing lookup: esgwri
	*/
	if (db_funcs.query(db_con, 0, 0, 0, query_cols, 0, 5, 0, &res) != 0) {
		LM_ERR("Failure to issue query\n");
		return -1;
	}

	nr_rows = RES_ROW_N(res);
	rows = RES_ROWS(res);

	new_list = NULL;
	LM_DBG("NUMBER OF LINES %d \n", nr_rows);


	for (i = 0; i < nr_rows; i++) {
		values = ROW_VALUES(rows + i);

		if (VAL_NULL(values) ||
				(VAL_TYPE(values) != DB_INT)) {
			LM_ERR("Invalid value returned 1\n");
			goto end;
		}

		if (VAL_NULL(values + 1) ||
				(VAL_TYPE(values + 1) != DB_STR && VAL_TYPE(values + 1) != DB_STRING)) {
			LM_ERR("Invalid translated returned 2\n");
			goto end;
		}

		if (VAL_TYPE(values + 1) == DB_STR) {
			SRID = VAL_STR(values + 1);
		} else {
			SRID.s = (char*) VAL_STRING(values + 1);
			SRID.len = strlen(SRID.s);
		}

		if (VAL_NULL(values + 2) ||
				(VAL_TYPE(values + 2) != DB_INT)) {
			LM_ERR("Invalid translated returned 3\n");
			goto end;
		}

		RESN = VAL_INT(values + 2);

		if (VAL_NULL(values + 3) ||
				(VAL_TYPE(values + 3) != DB_INT)) {
			LM_ERR("Invalid translated returned 4\n");
			goto end;
		}

		NPA = VAL_INT(values + 3);

		if (VAL_NULL(values + 4) ||
				(VAL_TYPE(values + 4) != DB_STR && VAL_TYPE(values + 4) != DB_STRING)) {
			LM_ERR("Invalid translated returned 5\n");
			goto end;
		}

		if (VAL_TYPE(values + 4) == DB_STR) {
			esgwri = VAL_STR(values + 4);
		} else {
			esgwri.s = (char*) VAL_STRING(values + 4);
			esgwri.len = strlen(esgwri.s);
		}


		size = sizeof (struct esrn_routing)+SRID.len + esgwri.len;
		esrn_cell = shm_malloc(size);
		if (!esrn_cell) {
			LM_ERR("no more shm\n");
			goto end;
		}

		memset(esrn_cell, 0, size);

		esrn_cell->srid.len = SRID.len;
		esrn_cell->srid.s = (char *) (esrn_cell + 1);
		memcpy(esrn_cell->srid.s, SRID.s, SRID.len);
		esrn_cell->resn = RESN;
		esrn_cell->npa = NPA;
		esrn_cell->esgwri.len = esgwri.len;
		esrn_cell->esgwri.s = (char *) (esrn_cell + 1) + SRID.len;
		memcpy(esrn_cell->esgwri.s, esgwri.s, esgwri.len);


		if (new_list != NULL) {
			new_list->next = esrn_cell;
			new_list = esrn_cell;
		} else {
			new_list = esrn_cell;
			init_esrn = new_list;
		}

	}

	new_list = init_esrn;


	lock_start_write(ref_lock);
	old_list = *db_esrn_esgwri;
	*db_esrn_esgwri = init_esrn;
	lock_stop_write(ref_lock);

	it = old_list;
	while (it) {
		aux = it;
		it = it->next;

		shm_free(aux);
	}

end:
	db_funcs.free_result(db_con, res);

	return 1;

}
