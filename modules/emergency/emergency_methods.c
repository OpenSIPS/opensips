/*
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 *  2014-10-14 initial version (Villaron/Tesini)
 */


#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>
#include "emergency_methods.h"
#include "xml_parser.h"

#define TABLE_ROUTING_VERSION   1
#define TABLE_REPORT_VERSION   1

/*
 * Module initialization and cleanup
 */
static int mod_init(void);
static int child_init(int);
static void mod_destroy(void);

struct dlg_binds dlgb;

/*
 * Exported functions
 */
static cmd_export_t cmds[] = {
	{"emergency_call", (cmd_function) emergency_call, 0, 0, 0,
		REQUEST_ROUTE | BRANCH_ROUTE },
	{"failure", (cmd_function) failure, 0, 0, 0,
		FAILURE_ROUTE | ONREPLY_ROUTE },
	{ 0, 0, 0, 0, 0, 0}
};


/*
 * Exported parameters
 */

static param_export_t params[] = {
	{ "emergency_codes", STR_PARAM | USE_FUNC_PARAM, (void *) &set_codes},
	{ "timer_interval", INT_PARAM, &timer_interval},
	{ "db_url", STR_PARAM, &db_url.s},
	{ "db_table_routing", STR_PARAM, &table_name},
	{ "db_table_report", STR_PARAM, &table_report},	
	{ "url_vpc", STR_PARAM, &url_vpc},
	{ "vpc_organization_name", STR_PARAM, &vpc_organization_name},
	{ "vpc_hostname", STR_PARAM, &vpc_hostname},
	{ "vpc_nena_id", STR_PARAM, &vpc_nena_id},
	{ "vpc_contact", STR_PARAM, &vpc_contact},
	{ "vpc_cert_uri", STR_PARAM, &vpc_cert_uri},
	{ "source_organization_name", STR_PARAM, &source_organization_name},
	{ "source_hostname", STR_PARAM, &source_hostname},
	{ "source_nena_id", STR_PARAM, &source_nena_id},
	{ "source_contact", STR_PARAM, &source_contact},
	{ "source_cert_uri", STR_PARAM, &source_cert_uri},
	{ "vsp_organization_name", STR_PARAM, &vsp_organization_name},
	{ "vsp_hostname", STR_PARAM, &vsp_hostname},
	{ "vsp_nena_id", STR_PARAM, &vsp_nena_id},
	{ "vsp_contact", STR_PARAM, &vsp_contact},
	{ "vsp_cert_uri", STR_PARAM, &vsp_cert_uri},
	{ "flag_empresa_terceira", INT_PARAM, &flag_empresa_terceira},
	{ "contingency_hostname", STR_PARAM, &contingency_hostname},
	{ "emergency_call_server", STR_PARAM, &call_server_hostname},
	{ "proxy_hole", INT_PARAM, &proxy_hole},
	{ "callorigin", STR_PARAM, &call_origin},   
	{ 0, 0, 0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_SQLDB, NULL, DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

/*
 * Module parameter variables
 */
struct module_exports exports = {
	"emergency",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION, /* module version */
	DEFAULT_DLFLAGS, /* dlopen flags */
	&deps,           /* OpenSIPS module dependencies */
	cmds,      /* Exported functions */
	NULL,      /* Exported async functions */
	params,    /* Exported parameters */
	0, /* exported statistics */
	0, /* exported MI functions */
	0, /* exported pseudo-variables */
	0, /* extra processes */
	mod_init, /* module initialization function */
	0, /* response function*/
	mod_destroy,
	child_init /* per-child init function */
};

/*
 * Polling Inicialization Functions
 */


/* extracts the code and the description of the parameter emergency_code
* And stores these values in new_code linked list
*/

static int set_codes(unsigned int type, void *val) {
	char *code, *description, *p;
	int code_len, description_len, len;
	struct code_number *new_code;

	code = (char *) val;
	len = strlen(code);

	p = memchr(code, CODE_DELIM, len);
	if (!p) {
		LM_ERR("Invalid code - delimiter not found\n");
		return -1;
	}

	/* separa o codigo e a descrição usando o delimitador CODE_DELIM ("-") */

	code_len = p - code;
	description = ++p;

	description_len = len - code_len - 1;
	new_code = pkg_malloc(sizeof (struct code_number));
	if (!new_code) {
		LM_ERR("No more pkg memory\n");
		return -1;
	}
	LM_DBG(" --- CODE  -----> %.*s\n", code_len, code);
	LM_DBG(" --- DESC  -----> %.*s\n", description_len, description);

	new_code->code.s = code;
	new_code->code.len = code_len;
	new_code->description.s = description;
	new_code->description.len = description_len;

	if (!codes)
		codes = new_code;
	else {
		new_code->next = codes;
		codes = new_code;
	}
	return 0;
}

/* 
*   This function is responsible for :
*   - load api from modules dialog and rr
*   - open database connection and test the version of the tables in the database
*   - initialize polling routing timer
*   - initialize the module linked lists db_esrn_domain and calls_eme
*   - initialize lock: ref_lock
*/
static int mod_init(void) {

	LM_DBG("Initializing module\n");
	
	if ( load_dlg_api( &dlgb ) != 0 ) {
		LM_ERR("failed to load DLG api\n");
		return -1;
	}

	empty = shm_malloc(sizeof (char));
	memset(empty, '\0', 1); 
	
	if (db_url.s) {
		db_url.len = strlen(db_url.s);
		LM_DBG("We have db_url = %.*s\n", db_url.len, db_url.s);

		/* Find a database module */
		if (db_bind_mod(&db_url, &db_funcs) < 0) {
			LM_ERR("Unable to bind to a database driver\n");
			return -1;
		}

		/* open a test connection */
		if ((db_con = db_funcs.init(&db_url)) == 0) {
			LM_ERR("cannot init connection to DB\n");
			return -1;
		}


		if (!DB_CAPABILITY(db_funcs, DB_CAP_INSERT)) {
			LM_ERR("database modules does not provide all functions needed by module\n");
			return -1;
		}

		if (db_check_table_version(&db_funcs, db_con, &table_name, TABLE_ROUTING_VERSION) < 0) {
			LM_ERR("error during table version check.\n");
			return -1;
		}

		db_funcs.close(db_con);
		db_con = 0;
	}


	if (register_timer("emer_rout_table", routing_timer, 0,
	timer_interval, 0) < 0) {
		LM_ERR("failed to register timer \n");
		return -1;
	}

	db_esrn_domain = shm_malloc(sizeof (struct esrn_routing *));
	if (!db_esrn_domain) {
		LM_ERR("no more memory");
		return -1;
	}
	*db_esrn_domain = NULL;

	calls_eme = shm_malloc(sizeof (struct node *));
	if (!calls_eme) {
		LM_ERR("no more memory");
		return -1;
	}
	*calls_eme = NULL;

	if ((ref_lock = lock_init_rw()) == NULL) {
		LM_ERR("failed to init lock\n");
		return -1;
	}

	/* data */

	curl_global_init(CURL_GLOBAL_ALL);
	LM_DBG("EMERGENCY Module initialized!\n");

	if (load_rr_api(&rr_api) != 0) {
		LM_ERR("failed to load rr API\n");
		return -1;
	}

	return 0;
}


/* this function is responsible for:
*   - open database connection 
*   - initialize polling routing timer
*/
static int child_init(int rank) {
	LM_DBG("Initializing child\n");
	if (db_url.s && rank == PROC_TIMER) {
		/* open a test connection */
		if ((db_con = db_funcs.init(&db_url)) == 0) {
			LM_ERR("cannot init connection to DB\n");
			return -1;
		}

		routing_timer(0, 0);
	}

	return 0;
}


/*
*  
*  - close database connection 
*  - terminate lock (ref_lock)
*/
static void mod_destroy(void) {
	curl_global_cleanup();

	db_funcs.close(db_con);

	if(ref_lock){
		lock_destroy_rw( ref_lock );
		ref_lock = NULL;
	}
}

/* 
*   - treats the request within the dialog forwarding to the INVITE that first created the dialog
*   - if the request is a BYE treats the call ending functions
*/
void indialog_ua(struct dlg_cell* dlg, int type, struct dlg_cb_params * params){
	struct sip_msg *msg = params->msg;
	int dir = params->direction;
	int resp;

	LM_INFO(" New sequential request received:%d !! \n",dir);
	LM_INFO(" New sequential request method:%.*s \n",msg->first_line.u.request.method.len,msg->first_line.u.request.method.s);

	if (memcmp(msg->first_line.u.request.method.s,"BYE", msg->first_line.u.request.method.len) == 0) { 
		LM_INFO(" --- TRATA BYE  -----  \n \n");  

		resp = bye(msg,dir);
		LM_INFO(" ---TRATAMENTO DIALOG BYE:%d", resp);		
		//return resp;
	}else{
		if (dir == 1){
			LM_INFO(" --- TRATA DOWNSTREAM  -----  \n \n"); 
			resp = routing_ack(msg);
			LM_INFO(" ---TRATAMENTO DIALOG ACK:%d", resp);
			//return resp;
		}
	}

}

/* 
* - verifying the expiration for packet loss ( timing values are diferent for ACK and BYE)
* - if there is an expiration the module sends a POST informing the VPC to exclude the number
*   the key ESQK is retreived from the list calls_eme
*/
static void libera_esqk(void) {

	time_t rawtime;
	struct tm * timeinfo;
	char formated_time[80];
	int resp = 1;
	char* response;
	char* esct_callid;
	char* xml;
	struct node* current = *calls_eme;
	NODE *previous = NULL;
	NODE *free_cell;


	while (current) {

		current->esct->timeout --;

		NODE* next = current->next;

		LM_INFO("TEMPORIZA:%d\n", current->esct->timeout);
		if (current->esct->timeout <= 0 ){
			LM_INFO("timeout\n");
			  
			free_cell = current;

			if (previous == NULL){
				if (next == NULL){				
					*calls_eme = NULL;			  
				}else{
					*calls_eme = next;
				}
			}else{
				current = next;
				previous->next = current;
			} 

			//send esctRequest to the VPC
	
			xml = buildXmlFromModel(free_cell->esct);
	
			if(free_cell->esct->datetimestamp){
				shm_free (free_cell->esct->datetimestamp);
				LM_DBG(" --- FREE_CELL->TIME");								
			}

			time(&rawtime);
			timeinfo = localtime(&rawtime);
			strftime(formated_time, 80, "%Y-%m-%dT%H:%M:%S%Z", timeinfo);

			//free_cell->esct->datetimestamp = shm_malloc(sizeof (char)*80);
			//memset(free_cell->esct->datetimestamp, 0, 80);			
			//strcpy(free_cell->esct->datetimestamp, formated_time);
			free_cell->esct->datetimestamp = formated_time;
			LM_DBG(" --- Begin BYE TREATMENT XML %s \n \n", xml);

			resp = post(url_vpc, xml, &response);
			if (resp == -1) {
				LM_ERR(" --- PROBLEM OF THE BYE POST\n \n");
			}

			esct_callid = parse_xml_esct(response);
			if (esct_callid== NULL) {
				LM_ERR(" --- esctAck invalid format or without mandatory field \n \n");		
			} else {
				if (strcmp(esct_callid, free_cell->esct->callid)){					
					LM_ERR(" --- callid in esctAck different from asctRequest \n \n");			 
				}
				if(esct_callid)
					pkg_free(esct_callid);
			}
			LM_DBG("END EMERGENCY");
			pkg_free(response);


			pkg_free(xml);

			free_call_cell(free_cell);
		}else{
			previous = current;		   
		}  

		current = current->next;
	}

}


/* 
* - copying data from the routing table to the list db_esrn_domain (performance improvement)
*/
void routing_timer(unsigned int ticks, void *attr) {
	db_key_t query_cols[] = {&id_col, &srid_col, &resn_col, &npa_col, &esgwri_col};
	db_res_t * res;
	db_val_t * values;
	db_row_t * rows;
	str esgwri;
	str SRID;
	int RESN;
	int NPA;
	int nr_rows, i, size;

	struct esrn_routing *esrn_cell, *old_list, *it, *aux;
	struct esrn_routing *init_esrn = NULL;
	
	LM_DBG("timer running at %u tick\n", ticks);

	db_funcs.use_table(db_con, &table_name);

	/* select value from routing table
	*  routing table tem as colunas com as chaves: selectiveRoutingID, routingESN, npa
	*  e a coluna com o resultado do roteamento: esgwri
	*/
	if (db_funcs.query(db_con, 0, 0, 0, query_cols, 0, 5, 0, &res) != 0) {
		LM_ERR("Failure to issue query\n");
		return;
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
	old_list = *db_esrn_domain;
	*db_esrn_domain = init_esrn;
	lock_stop_write(ref_lock);

	it = old_list;
	while (it) {
		aux = it;
		it = it->next;

		shm_free(aux);
	}

end:
	db_funcs.free_result(db_con, res);

	libera_esqk();

}


/*
 * Functions that the User can call from the config file
 */


/* 
* - verify if the request is an emergency call
* - is it is an emergency forward the INVITE to the destiny determined by the VPC
*/
static int emergency_call(struct sip_msg *msg) {
	struct dlg_cell *dlg;

	if (memcmp(msg->first_line.u.request.method.s,"INVITE", msg->first_line.u.request.method.len) == 0) {
		
		if (is_emergency_call(msg)) {
			LM_INFO(" --- IT IS AN EMERGECY -----  \n \n"); 
			// It is, forward the INVITE			
			if(send_request_vpc(msg) == 1){

				if (dlgb.create_dlg(msg,0)<1) {
					LM_ERR("failed to create dialog\n");
					return -1;
				}
				dlg = dlgb.get_dlg();
				if (dlg==NULL) {
					LM_CRIT("BUG: found after create dialog\n");
					return -1;
				}
				if(dlgb.register_dlgcb(dlg, DLGCB_REQ_WITHIN|DLGCB_TERMINATED, indialog_ua ,0,0)!=0) {
					LM_ERR("failed to register dialog callback\n");
					return -1;
				}

				return 1;
			}

		} else {
			LM_INFO(" --- IT IS NOT AN EMERGENCY  -----  \n \n");		   
		}
	}

	return -1;
}


/* treat the command FAILURE
* - treat contingency forwarding in the case of failure of the original  
* - Forward the INVITE to a gateway with the contingency number lro from the field R-URI
*/
static int failure(struct sip_msg *msg) {

	LM_INFO(" --- TRATA FALHA\n \n");

	char* callidHeader;
	int resp = 1;

	ESCT* info_call;

	char* new_to;
	char *lro_aux;

	str pattern_lro, replacement_lro, pt_lro;


	LM_DBG(" --- FAILURE  treatment \n \n");

	// comando failure so sera tratado pelo opensips com o paler de Call Proxy no cenario I
	if (proxy_hole == 1) {
		LM_DBG(" ---Hole: proxy routing \n");
		return - 1;
	}

	// verfifica se o parametro contingency_hostname foi definido no script, caso contrario failure não sera tratado
	if ( contingency_hostname == NULL) {
		LM_ERR("contingency_hostname not defined\n");
		return -1;
	}

	// get callid of the message
	resp = get_callid_header(msg, &callidHeader);
	LM_DBG(" --- FAILURE treatment HEADER RESP %d ", resp);
	if (resp == -1)
		return resp;

	LM_DBG(" ---FAILURE treatment  callid=%s", callidHeader);

	// find the cell with the callid from the list calls_cell
	info_call = find_esct(callidHeader);
	if (info_call == NULL) {
		LM_ERR(" ---FAILURE treatment did not find the CALLID");
		goto error;
	}

	// verifica se a chamada tratada teve o numero de contingencia lro fornecido pelo VPC
	// caso não tenha, não trata failure
	if (info_call->lro == NULL) {
		LM_ERR(" ---treat FAILURE not found lro");
		goto error;
	}

	//verify if there was an attempt to forward the INVITE to the contingency number
	if (strstr(info_call->disposition, "lro") == NULL) {

		LM_INFO("EH LRO -- LRO = %s  HOST = %s ", info_call->lro, contingency_hostname);
		int len_lro = strlen(info_call->lro);

		lro_aux = pkg_malloc(sizeof (char)* len_lro + 1);
		if (!lro_aux) {
			LM_ERR("No more pkg memory\n");
			goto error;
		}

		memset(lro_aux, 0, len_lro + 1);

		pt_lro.s = lro_aux;
		pt_lro.len = len_lro + 1;

		pattern_lro.s = "(tel:)*([+]*[-0-9]+)";
		pattern_lro.len = strlen(pattern_lro.s);

		replacement_lro.s = "\\2";
		replacement_lro.len = strlen(replacement_lro.s);

		if (reg_replace(pattern_lro.s, replacement_lro.s, info_call->lro, &pt_lro) != 1) {
			pkg_free(lro_aux);
			LM_ERR("****** PATTERN LRO NAO OK \n");
			goto error;
		}

		int tamanho_new_to = pt_lro.len + strlen(contingency_hostname) + 17;

		new_to = shm_malloc(sizeof (char)* tamanho_new_to);
		sprintf(new_to, "sip:%s@%s;user=phone", pt_lro.s, contingency_hostname);

		LM_INFO(" ---NOVO DESTINO =%s", new_to);

		pkg_free(lro_aux);

		if(new_uri_proxy(msg, new_to) == -1){
			LM_ERR(" ---ERRO EM NEW_URI_PROXY");
			goto error;
		}  

		if(info_call->esgw && strlen(info_call->esgw)>0)
			shm_free(info_call->esgw);

		info_call->esgw = new_to;
		info_call->disposition = "lro";
		info_call->timeout = ACK_TIME;

		if(callidHeader)
			pkg_free(callidHeader);
		
		return 1;
	}
	
	error : 
		  LM_INFO(" ---FAILURE JA TRANSMITIU LRO");  
		if(callidHeader)
			pkg_free(callidHeader);
		return -1;
}

/*
 * Internal functions
 */

/* verify if the call is an emergency call 
*  - ferify if the field uri has a urn standard for emergency call defined by RFC 5031
*  - if it does not, then verify if se user field is one of the emengency_code in the database
*	- if it is a code, the module checks if the host is from the opensips 
		or if there is a field Geolocation_routing = 'yes"
*/
static int is_emergency_call(struct sip_msg *msg) {
	LM_DBG(" --- emergency_call \n \n");

	// verifica se ruri esta com uma urn padrão para chamada de emergencia
	if (strstr(msg->first_line.u.request.uri.s, "urn:service:sos") != NULL) {
		LM_DBG(" --- IT IS EMERGENCY  -----  \n \n");
		return 1;
	} else {
		// não esta com urn padrão, se o campo user da ruri coincide com algum codigo definido no script parametro emergency_code
		LM_DBG(" --- verificando codigos \n \n");
		if ((parse_sip_msg_uri(msg) < 0) ||
				(!msg->parsed_uri.user.s) ||
				(msg->parsed_uri.user.len > MAXNUMBERLEN)) {
			LM_ERR("cannot parse msg URI\n");
			return 0;
		}
		struct code_number* codigo = codes;
		while (codigo != NULL) {

			LM_DBG(" --- verify CODE %.*s\n \n", codigo->code.len, codigo->code.s);
			LM_DBG(" --- verify CODE USER %.*s\n \n", msg->parsed_uri.user.len, msg->parsed_uri.user.s);
			LM_DBG(" --- verify CODE CODE SIZE %d\n \n", codigo->code.len);
			LM_DBG(" --- verify CODE USER SIZE %d\n \n", msg->parsed_uri.user.len);

			if (codigo->code.len == msg->parsed_uri.user.len){
				if (strncmp(codigo->code.s, msg->parsed_uri.user.s , codigo->code.len) == 0) {
				
					LM_DBG(" ---> CODIGO -- OK %.*s\n\n", codigo->code.len, codigo->code.s);
					
					if (check_myself(msg)) {				   
						return 1;
					} else {
						// host IS NOT MANDATORY AT opensips, Geolocation_Routing DETERMINS THE proxy
						// INVITE (RFC 6442)
						int ret = check_geolocation_header(msg);				  
						return ret;
					}
				}
			}
			codigo = codigo->next;
		}
		LM_DBG(" --- IT IS NOT EMERGENCY \n \n");
		return 0;
	}
	LM_DBG(" --- IT IS NOT EMERGENCY \n \n");
	return 0;
}

/* calculate the size of the xml to allocate memory
*/
unsigned long get_xml_size(char* lie, char* formated_time, char* callidHeader, char* cbn) {
	unsigned long resp = 0;
	resp += strlen(MODEL);
	resp += strlen(lie);
	resp += strlen(callidHeader);
	resp += strlen(cbn);   
	resp += strlen(formated_time);
	resp += strlen(vpc_organization_name);
	resp += strlen(vpc_hostname) + strlen(vpc_nena_id);
	resp += strlen(vpc_contact) + strlen(vpc_cert_uri);
	resp += strlen(source_organization_name);
	resp += strlen(source_hostname) + strlen(source_nena_id);
	resp += strlen(source_contact) + strlen(source_cert_uri);
	resp += strlen(vsp_organization_name);
	resp += strlen(vsp_hostname) + strlen(vsp_nena_id);
	resp += strlen(vsp_contact) + strlen(vsp_cert_uri);
	return resp;
}

/* fill with blanck spaces
*/
int preenche_com_espaco_em_branco(void) {
	int resp = 1;
	resp = preenche_um_com_espaco_em_branco(&vpc_organization_name);
	resp = preenche_um_com_espaco_em_branco(&vpc_hostname);
	resp = preenche_um_com_espaco_em_branco(&vpc_nena_id);
	resp = preenche_um_com_espaco_em_branco(&vpc_contact);
	resp = preenche_um_com_espaco_em_branco(&vpc_cert_uri);
	resp = preenche_um_com_espaco_em_branco(&source_organization_name);
	resp = preenche_um_com_espaco_em_branco(&source_nena_id);
	resp = preenche_um_com_espaco_em_branco(&source_cert_uri);
	resp = preenche_um_com_espaco_em_branco(&vsp_organization_name);
	if (flag_empresa_terceira == 0) {
		resp = preenche_um_com_espaco_em_branco(&vsp_hostname);
		resp = preenche_um_com_espaco_em_branco(&vsp_nena_id);
	}
	resp = preenche_um_com_espaco_em_branco(&vsp_contact);
	resp = preenche_um_com_espaco_em_branco(&vsp_cert_uri);
	return resp;
}
/*
*fill with blanck spaces
*/
int preenche_um_com_espaco_em_branco(char** var) {
	if (*var == NULL) {
		*var = pkg_malloc(sizeof (char) * strlen(BLANK_SPACE));
		if (*var == NULL)
			return -1;
		strcpy(*var, BLANK_SPACE);
		return 1;
	}
	return 1;
}

/* find the body with the type Content-Type: application/pidf+xml 
*  in the INVITE that has multi-body
*/
static int find_body_pidf(struct sip_msg *msg, char** pidf_body) {

	struct part* mbody_part;
	struct multi_body *mbody;
	char *body_start, *body_end;
	char *body_aux;

	int size_body = 0;
	LM_DBG(" --- FIND PIDF BODY \n \n");

	mbody = get_all_bodies(msg);
	if (mbody == NULL) {
		LM_ERR("Failed to get bodies\n");
		return -1;
	}


	mbody_part = mbody->first;
	int cont = 0;
	while (mbody_part != NULL) {
		LM_DBG(" --- PIDF BODY %.*s", mbody_part->body.len, mbody_part->body.s);
		LM_DBG(" --- PIDF BODY COUNT %d", ++cont);

		if (strstr(mbody_part->body.s, CONTENT_TYPE_PIDF) != NULL) {
			body_start = strstr(mbody_part->body.s, PRESENCE_START);
			body_end = strstr(mbody_part->body.s, PRESENCE_END);
			size_body = body_end - body_start + 11;
			body_aux = pkg_malloc(size_body);
			if (body_aux == NULL) {
				LM_ERR("no more pkg memory\n");
				return -1;
			}
			memcpy(body_aux, body_start, size_body - 1);
			body_aux[size_body - 1] = 0;
			*pidf_body = body_aux;

			break;
		}
		mbody_part = mbody_part->next;
	}
	if (*pidf_body == NULL) {
 //	   *pidf_body = "NO-CONTENT";
		*pidf_body = "";	   
	}
	LM_DBG(" --- FIND PIDF BODY  %s \n \n", *pidf_body);

	return 1;
}


/* format the xml to send POST -> esrRequest
*/
char* formatted_xml(char* lie, char* formated_time, char* callidHeader, char* cbn) {
	char* xml;
	LM_DBG(" --- FORMATANDO XML \n \n");
	int size_xml = get_xml_size(lie, formated_time, callidHeader, cbn) + 1;
	LM_DBG(" --- TAMANHO XML %d \n \n", size_xml);	
	xml = pkg_malloc(sizeof (char) * size_xml);
	memset(xml, 0, size_xml);
	sprintf(xml, MODEL,\
	 vpc_organization_name, vpc_hostname, vpc_nena_id, vpc_contact, vpc_cert_uri, \
	 source_organization_name, source_hostname, source_nena_id, source_contact, source_cert_uri, \
	 vsp_organization_name, vsp_hostname, vsp_nena_id, vsp_contact, vsp_cert_uri,\
	 callidHeader, cbn, lie,\
	 call_origin, formated_time);
	LM_DBG(" --- INIT  xml %s\n \n", xml);
	return xml;
}


/*  verify the result field of the VPC
*/
static int faixa_result(int result) {

	// OK
	if (result >= 200 && result <= 203)
		return 1;
	// NOT OK USE THE lro
	if (result >= 400 && result <= 404)
		return 2;
	// resposta NOK, mas podendo usar o campo lro
	if (result >= 500 && result <= 501)
		return 2;

	// resposta NOK sem o campo lro
	return -1;
}


/* this function is used to make Opensips play the role of a "Call server"in the scenarios I and II
*  forward the INVITE to the Routing Proxy(scenarios II) or to Redirect(scenarios III)
*/
static int proxy_request(struct sip_msg *msg) {
	char* ack_uri;
	char *ack_aux;
	
	LM_DBG(" ---Hole: proxy routing \n");
	if (call_server_hostname == NULL) {
		LM_ERR("emergency call server not defined\n");
		return -1;
	}
	if ((parse_sip_msg_uri(msg) < 0) ||
			(!msg->parsed_uri.user.s) ||
			(msg->parsed_uri.user.len > MAXNUMBERLEN)) {
		LM_ERR("cannot parse msg URI\n");
		return -1;
	}

	LM_DBG(" ---USER: %.*s \n\n", msg->parsed_uri.user.len, msg->parsed_uri.user.s);
	int server_host_len = strlen(call_server_hostname);
	size_new_uri = server_host_len + msg->parsed_uri.user.len + 6;
	ack_aux = pkg_malloc(size_new_uri);
	if (ack_aux == NULL) {
		LM_ERR("--------------------------------------------------no more pkg memory\n");
		return -1;
	}
	memset(ack_aux, 0, size_new_uri);
	ack_uri = ack_aux;
	memcpy(ack_aux, "sip:", 4);
	ack_aux += 4;
	memcpy(ack_aux, msg->parsed_uri.user.s, msg->parsed_uri.user.len);
	ack_aux += msg->parsed_uri.user.len;
	*ack_aux = '@';
	ack_aux++;
	memcpy(ack_aux, call_server_hostname, server_host_len);
	LM_DBG(" ---NEW_URI: %s \n\n", ack_uri);
	LM_DBG(" ---NEW_URI -TAM : %d \n\n", size_new_uri);
	
	if(new_uri_proxy(msg, ack_uri) == -1){
		LM_ERR(" ---ERRO EM NEW_URI_PROXY");
		return -1;
	}

	pkg_free(ack_aux);
	
	return 1;
}


/* 
*  this function treats the forwarding of the message in the case when the VPC returns esrResponse "NOT OK" but with the field LRO not blanck
*	-Forward the INVITE in a contingency gateway with the altenative numbe lro in the user field of the R-URI
*/
int contingency(PARSED *parsed , struct sip_msg *msg, ESCT *call_cell)
{
	str pattern_lro, replacement_lro, pt_lro;
	char *pt_lro_aux,*new_to;
	NODE *newNode2;
	
	//Trata LRO 
	 // verfifica se o campo lro foi ransmitido pelo VPC, caso contrario chamada tera tratamento NOK 
	if (parsed->lro == NULL) {
		LM_ERR("no received lro\n");
		return -1;
	}

	// verfifica se o parametro contingency_hostname foi definido no script, caso contrario chamada tera tratamento NOK
	if ( contingency_hostname == NULL) {
		LM_ERR("contingency_hostname not defined\n");
		return -1;
	}

	int len_lro = strlen(parsed->lro);

	// monta R-URI para o INVITE considerando o parametro de script contingency_hostname 
	// e o lro fornecido pelo VPC: R-URI = sip:lro@contingency_hostname;user=phone

	pt_lro_aux = pkg_malloc(len_lro + 1);
	if (pt_lro_aux == NULL) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}
	memset(pt_lro_aux, 0, len_lro + 1);

	pt_lro.s = pt_lro_aux;
	pt_lro.len = len_lro + 1;

	pattern_lro.s = "(tel:)*([+]*[-0-9]+)";
	pattern_lro.len = strlen(pattern_lro.s);

	replacement_lro.s = "\\2";
	replacement_lro.len = strlen(replacement_lro.s);

	if (reg_replace(pattern_lro.s, replacement_lro.s, parsed->lro, &pt_lro) != 1) {
		pkg_free(pt_lro_aux);
		LM_ERR("****** PATTERN LRO NAO OK \n");
		return -1;
	}

	int tamanho_new_to = pt_lro.len + strlen(contingency_hostname) + 17;

	new_to = pkg_malloc(sizeof (char)* tamanho_new_to);
	sprintf(new_to, "sip:%s@%s;user=phone", pt_lro.s, contingency_hostname);

	pkg_free(pt_lro_aux);
	
	call_cell->esgw = shm_malloc(sizeof (char)* tamanho_new_to + 1);
	if (call_cell->esgw == NULL) {
		LM_ERR("--------------------------------------------------no more shm memory\n");
		return -1;
	}

	strcpy(call_cell->esgw, new_to);
	call_cell->esgw[tamanho_new_to] = 0;

	call_cell->ert_npa = 0;
	call_cell->ert_resn = 0;
	call_cell->ert_srid = "";

	if(new_uri_proxy(msg, new_to) == -1){
		LM_ERR(" ---ERRO EM NEW_URI_PROXY");
		return -1;
	}
	
	pkg_free(new_to); 
 
	call_cell->disposition = "lro";

	call_cell->timeout = ACK_TIME;

	
	newNode2 = shm_malloc(sizeof (NODE));
	if (newNode2 == NULL) {
		LM_ERR("--------------------------------------------------no more shm memory\n");
	}
	newNode2->esct = call_cell;
	newNode2->next = NULL;
	if (*calls_eme == NULL) {
		LM_DBG("---FIRST IN THE LIST \n");
		list_call = newNode2;
	} else {
		LM_DBG("---UDATE LIST \n");
		list_call = *calls_eme;
		NODE *current2 = list_call;
		while (current2->next != NULL) {
			current2 = current2->next;
		}
		current2->next = newNode2;
	}

	*calls_eme = list_call;

	return 1;
}


/*
*  - source
*	   .organizationname
*	   .hostname
*	   .nenaid
*	   .contact
*	   .certuri
*   - vpc
*	   .organizationname
*	   .hostname
*	   .nenaid
*	   .contact
*	   .certuri
*   - esqk
*   - callid
*   - lro
*   - result
*   - datetimestamp
*/
int initial_treatment(ESCT *call_cell , NENA *call_cell_vpc, NENA *call_cell_source, PARSED *parsed , struct sip_msg *msg,char* callidHeader)
{
	call_cell->vpc = call_cell_vpc;
	call_cell->source = call_cell_source;
	call_cell_source->organizationname = empty;
	call_cell_source->hostname = empty;
	call_cell_source->nenaid = empty;
	call_cell_source->contact = empty;
	call_cell_source->certuri = empty;

	call_cell_vpc->organizationname = empty;
	call_cell_vpc->hostname = empty;
	call_cell_vpc->nenaid = empty;
	call_cell_vpc->contact = empty;
	call_cell_vpc->certuri = empty;

	call_cell->esqk = empty;
	call_cell->lro = empty;
	call_cell->datetimestamp = empty;

	LM_DBG(" --- ANTES DESTINATION...");


	if (parsed->destination->organizationname != NULL) {
		char* field = shm_malloc(sizeof (char)*strlen(parsed->destination->organizationname));
		if (field == NULL) {
			LM_ERR("--------------------------------------------------no more shm memory\n");
			return -1;
		}
		strcpy(field, parsed->destination->organizationname);			
		call_cell_source->organizationname = field;		  
	}

	if (parsed->destination->hostname != NULL ) {
		char* field = shm_malloc(sizeof (char)*strlen(parsed->destination->hostname));
		if (field == NULL) {
			LM_ERR("--------------------------------------------------no more shm memory\n");
			return -1;
		}
		strcpy(field, parsed->destination->hostname);
		call_cell_source->hostname = field;
	}

	if (parsed->destination->nenaid != NULL ) {
		char* field = shm_malloc(sizeof (char)*strlen(parsed->destination->nenaid));
		if (field == NULL) {
			LM_ERR("--------------------------------------------------no more shm memory\n");
			return -1;
		}
		strcpy(field, parsed->destination->nenaid);
		call_cell_source->nenaid = field;
	}

	if (parsed->destination->contact != NULL ) {
		char* field = shm_malloc(sizeof (char)*strlen(parsed->destination->contact));
		if (field == NULL) {
			LM_ERR("--------------------------------------------------no more shm memory\n");
			return -1;
		}
		strcpy(field, parsed->destination->contact);
		call_cell_source->contact = field;
	}

	if (parsed->destination->certuri != NULL ) {
		char* field = shm_malloc(sizeof (char)*strlen(parsed->destination->certuri));
		if (field == NULL) {
			LM_ERR("--------------------------------------------------no more shm memory\n");
			return -1;
		}
		strcpy(field, parsed->destination->certuri);
		call_cell_source->certuri = field;
	}



	if (parsed->vpc->organizationname != NULL ) {
		char* field = shm_malloc(sizeof (char)*strlen(parsed->vpc->organizationname));
		if (field == NULL) {
			LM_ERR("--------------------------------------------------no more shm memory\n");
			return -1;
		}
		strcpy(field, parsed->vpc->organizationname);
		call_cell_vpc->organizationname = field;
	}
	if (parsed->vpc->hostname != NULL ) {
		char* field = shm_malloc(sizeof (char)*strlen(parsed->vpc->hostname));
		if (field == NULL) {
			LM_ERR("--------------------------------------------------no more shm memory\n");
			return -1;
		}
		strcpy(field, parsed->vpc->hostname);
		call_cell_vpc->hostname = field;
	}

	if (parsed->vpc->nenaid != NULL ) {
		char* field = shm_malloc(sizeof (char)*strlen(parsed->vpc->nenaid));
		if (field == NULL) {
			LM_ERR("--------------------------------------------------no more shm memory\n");
			return -1;
		}
		strcpy(field, parsed->vpc->nenaid);
		call_cell_vpc->nenaid = field;
	}

	if (parsed->vpc->contact != NULL ) {
		char* field = shm_malloc(sizeof (char)*strlen(parsed->vpc->contact));
		if (field == NULL) {
			LM_ERR("--------------------------------------------------no more shm memory\n");
			return -1;
		}
		strcpy(field, parsed->vpc->contact);
		call_cell_vpc->contact = field;
	}

	if (parsed->vpc->certuri != NULL ) {
		char* field = shm_malloc(sizeof (char)*strlen(parsed->vpc->certuri));
		if (field == NULL) {
			LM_ERR("--------------------------------------------------no more shm memory\n");
			return -1;
		}
		strcpy(field, parsed->vpc->certuri);
		call_cell_vpc->certuri = field;
	}

	// verifica se o callid enviado ao VPC é o mesmo retornado em esrResponse
	if (strcmp(parsed->callid, callidHeader) != 0) {
		LM_ERR("CALLID DIFFER %s ## %s \n", parsed->callid, callidHeader);
		return -1;
	}

	if (parsed-> esqk!= NULL ) {
		call_cell->esqk = shm_malloc(sizeof (char)*strlen(parsed->esqk));
		if (call_cell->esqk == NULL) {
			LM_ERR("--------------------------------------------------no more shm memory\n");
			return -1;
		}
		strcpy(call_cell->esqk, parsed->esqk);
	}

	call_cell->callid = shm_malloc(sizeof (char)*strlen(parsed->callid));
	if (call_cell->callid == NULL) {
		LM_ERR("--------------------------------------------------no more shm memory\n");
		return -1;
	}
	strcpy(call_cell->callid, parsed->callid);

	if (parsed-> lro!= NULL ) {
		call_cell->lro = shm_malloc(sizeof (char)*strlen(parsed->lro));
		if (call_cell->lro == NULL) {
			LM_ERR("--------------------------------------------------no more shm memory\n");
			return -1;
		}
		strcpy(call_cell->lro, parsed->lro);
	}

	if (parsed->datetimestamp != NULL ) {
		call_cell->datetimestamp = shm_malloc(sizeof (char)*strlen(parsed->datetimestamp));
		if (call_cell->datetimestamp == NULL) {
			LM_ERR("--------------------------------------------------no more shm memory\n");
			return -1;
		}
		strcpy(call_cell->datetimestamp, parsed->datetimestamp);
	}

	call_cell->result = shm_malloc(sizeof (char)*strlen(parsed->result));
	if (call_cell->result == NULL) {
		LM_ERR("--------------------------------------------------no more shm memory\n");
		return -1;
	}
	strcpy(call_cell->result, parsed->result);
	return 1;
}

/*
* this function is responsible for getting the forwarding data to the INVITE from tha stucture given by the VPC
* Stores :
*	   - selectiveRoutingID
*	   - routingESN
*	   - npa
*   - retreives the esgwri based on the data
*   - forward the invite
*/
int treat_parsed_ert(PARSED *parsed, struct sip_msg *msg, ESCT *call_cell) {
	char *esgwri_db;
	if (parsed->ert->selectiveRoutingID != NULL && strlen(parsed->ert->selectiveRoutingID) > 0)
		LM_DBG("selectiveRoutingID %s\n", parsed->ert->selectiveRoutingID);
	if (parsed->ert->routingESN != NULL && strlen(parsed->ert->routingESN) > 0)
		LM_DBG("routingESN %s\n", parsed->ert->routingESN);
	if (parsed->ert->npa != NULL && strlen(parsed->ert->npa) > 0)
		LM_DBG("selectiveRoutingID %s\n", parsed->ert->npa);
	int npa = atoi(parsed->ert->npa);
	int resn = atoi(parsed->ert->routingESN);
	int srid_len = strlen(parsed->ert->selectiveRoutingID);

	call_cell->ert_npa = npa;
	call_cell->ert_resn = resn;
	call_cell->ert_srid = shm_malloc(sizeof (char)* srid_len + 1);
	if (call_cell->ert_srid == NULL) {
		LM_ERR("--------------------------------------------------no more shm memory\n");
		return -1;
	}

	strcpy(call_cell->ert_srid, parsed->ert->selectiveRoutingID);
	call_cell->ert_srid[srid_len] = 0;

	if (emergency_routing(parsed->ert->selectiveRoutingID, resn, npa, &esgwri_db) != -1) {

		int esgwri_db_len = strlen(esgwri_db);

		LM_DBG("NEW_URI - teste %s \n", esgwri_db);
		
		call_cell->esgw = shm_malloc(sizeof (char)* esgwri_db_len + 1);
		if (call_cell->esgw == NULL) {
			LM_ERR("--------------------------------------------------no more shm memory\n");
			return -1;
		}

		strcpy(call_cell->esgw, esgwri_db);
		call_cell->esgw[esgwri_db_len] = 0;

		if(new_uri_proxy(msg, esgwri_db) == -1){
			if (esgwri_db)
				pkg_free(esgwri_db);			   
			LM_ERR(" ---ERRO EM NEW_URI_PROXY");
			return -1;
		}
		pkg_free(esgwri_db);

	} else {
		LM_ERR("Não ACHOU ERT NA BASE\n");
		return -1;
	}
	return 1;
}


/* Includes the headers to the INVITE
*   - puts the header PAI with the data:
*	   - esqk@ip_opensips:phone=call_back_number
*   - adds record_route to the INVIE for the opensips be notified when the call ends
*/
int add_headers(PARSED *parsed,struct sip_msg *msg) {
	char *s, *p, *socket;
	struct socket_info** list;
	struct lump *l;
	int len;
	int s_addr_len;
	char *s_addr = "@vsp.com";
	struct socket_info* si;
	LM_DBG(" --- F (CALLBACK) \n \n");

	// obtem o endereço ip do opensips que atende na portaque recebeu o INVITE 
	list = get_sock_info_list(msg->rcv.proto);
	if (list == NULL) {
		LM_ERR("ERROR in SOCKET\n");
		return -1;
	}

	si = *list;

	s_addr = NULL;

	while (si) {
		if (si->port_no == msg->rcv.dst_port) {

			socket = pkg_malloc(si->address_str.len + si->port_no_str.len + 3);
			if (socket == NULL) {
				LM_ERR("no more pkg memory\n");
				return -1;
			}
			s_addr = socket;
			*socket = '@';
			socket++;
			memcpy(socket, si->address_str.s, si->address_str.len);
			socket = socket + si->address_str.len;
			*socket = ':';
			socket++;
			memcpy(socket, si->port_no_str.s, si->port_no_str.len);
			socket = socket + si->port_no_str.len;
			*socket = 0;

			LM_DBG(" --- SERVER = %s \n \n", s_addr);
			break;

		}
		si = si->next;
	}

	if (s_addr == NULL) {
		LM_ERR("failed in found ip listen\n");
		return -1;
	}

	s_addr_len = strlen(s_addr);

	if (msg->pai) {
		LM_INFO("PAI: [%.*s]\n", msg->pai->body.len, msg->pai->body.s);

		l = del_lump( msg, msg->pai->name.s - msg->buf, msg->pai->len, HDR_PAI_T);
		if (l==NULL) {
			LM_ERR("failed to add del lump\n");
			return -1;
		}

	}

	l = anchor_lump(msg, msg->from->body.s+msg->from->body.len-msg->buf+1,
			HDR_USERAGENT_T);
	if (l == NULL) {
		LM_ERR("failed to create anchor lump\n");
		return -1;
	}

	len = P_ASSERTED_HDR_LEN + strlen(parsed->esqk) + s_addr_len + PAI_SUFFIX_LEN + cbn.len;

	s = pkg_malloc(len + 1);
	if (s == NULL) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}

	LM_DBG(" --- CBN_NUMBER = %.*s \n \n", cbn.len, cbn.s);
	LM_DBG(" --- CBN_NUMBER_LEN = %d \n \n", cbn.len);

	p = s;
	memcpy(p, P_ASSERTED_HDR, P_ASSERTED_HDR_LEN);
	p += P_ASSERTED_HDR_LEN;
	memcpy(p, parsed->esqk, strlen(parsed->esqk));
	p += strlen(parsed->esqk);
	memcpy(p, s_addr, s_addr_len);
	p += s_addr_len;
	memcpy(p, PAI_SUFFIX, PAI_SUFFIX_LEN);
	p += PAI_SUFFIX_LEN;
	memcpy(p, cbn.s, cbn.len);
	p += cbn.len;
	*p = 0;

	l = insert_new_lump_after(l, s, len, HDR_PAI_T);
	if (l == NULL) {
		pkg_free(s);
		LM_ERR("failed to insert new lump\n");
		return -1;
	}

	rr_api.record_route(msg, NULL);

	pkg_free(cbn.s);
	pkg_free(socket);
	return 1;
}


/* treats the esrResponse from VPC
*   - verify if the message has mandatory fields:
*	   - callid
*	   - result
*	   - nenaid
*	   - contact
*   - checks the result field to verify if the msg from VPC was seuccessfull
*   - checks the esgwri code or the data from the emergency area (selectiveRoutingID, routingESN, npa) to translate to esgwri
*   - includes the data ersResponse to a node of the list calls_eme
*/
int treat_parsed(PARSED *parsed,struct sip_msg* msg, char* callidHeader) {
	ESCT *call_cell;
	NENA *call_cell_vpc, *call_cell_source;
	int resp = 1;
	LM_INFO(" ---PARSED ");
	if ((parsed->callid == NULL || parsed->result == NULL || parsed->vpc->nenaid == NULL || parsed->vpc->contact == NULL)) {
		LM_ERR("MANDATORY FIELDS ARE BLANK \n");
		return -1;
	} else {
		LM_INFO(" --- PARSE OK MANDATORY FIELDS \n \n");
		//lock_start_write( ref_lock );
		call_cell = shm_malloc(sizeof (ESCT));
		if (call_cell == NULL) {
			LM_ERR("--------------------------------------------------no more shm memory\n");
			return -1;
		}
		call_cell_vpc = shm_malloc(sizeof (NENA));
		if (call_cell_vpc == NULL) {
			LM_ERR("--------------------------------------------------no more shm memory\n");
			return -1;
		}

		call_cell_source = shm_malloc(sizeof (NENA));
		if (call_cell_source == NULL) {
			LM_ERR("--------------------------------------------------no more shm memory\n");
			return -1;
		}
	   
	   // obtem campos do esrResponse e guarda na celula na lista ligada calls_eme
		if(initial_treatment(call_cell , call_cell_source , call_cell_vpc , parsed , msg, callidHeader) == -1){
			return -1;
		}

		// transforma result em inteiro para ficar mais facil sua analise separando-o em faixas
		int result = atoi(parsed->result);
		int faixa = faixa_result(result);
		LM_DBG(" --- faixa %d", faixa);
		
		if (faixa == -1) {
			// result NOK sem envio de numero de contigencia
			LM_ERR("RESULT INVALIDO -- SAINDO DO EMERGENCY %d \n", result);
			return -1;
		}
		
		if (faixa == 2) {
			// result NOK mas o VPC mandou o numero de contingencia para escoar a chamada
			LM_ERR("RESULT INVALIDO --CONTINGENCY \n");		   
			return contingency(parsed, msg, call_cell);
		}
		

		// result OK
		call_cell->disposition = "esgwri";
		call_cell->timeout = ACK_TIME;


		LM_DBG(" --- WRITE DATA 6");
		if (parsed->esgwri != NULL && strlen(parsed->esgwri) > 0) {

			// VPC enviou o campo esgwri para encaminhar o INVITE
			if (parsed->esqk == NULL){
				LM_ERR(" ---Result 200 but without esqk \n");
				return -1;					 
			}
			call_cell->esgw = shm_malloc(sizeof (char)*strlen(parsed->esgwri));
			if (call_cell->esgw == NULL) {
				LM_ERR("--------------------------------------------------no more shm memory\n");
				return -1;
			}
			strcpy(call_cell->esgw, parsed->esgwri);
			call_cell->ert_npa = 0;
			call_cell->ert_resn = 0;
			call_cell->ert_srid = "";
			LM_INFO(" ---CALL CELL -----------------------------------------------------ENTROU N IF ESQWRI = %s", call_cell->esgw);
			
			if(new_uri_proxy(msg, parsed->esgwri) == -1){
				LM_ERR(" ---ERRO EM NEW_URI_PROXY");
				return -1;
			}	   

		} else {

			if ((parsed->ert->selectiveRoutingID != NULL) && (parsed->ert->routingESN != NULL) && (parsed->ert->npa != NULL)) {
			   
				if (parsed->esqk == NULL){
					LM_ERR(" ---Result 200 but without esqk \n");
					return -1;					 
				}
				if(treat_parsed_ert(parsed, msg, call_cell) == -1){
					return -1;
				}
			}else{

				// VPC não enviou nenhum dado para fazer o encaminhamento		   
				LM_ERR(" ---Result 200 but without ert or esgwri \n");
				return -1;			   
			}
		}

		LM_DBG(" --- WRITE DATA 7");

		
		NODE *newNode = shm_malloc(sizeof (NODE));
		if (newNode == NULL) {
			LM_ERR("--------------------------------------------------no more shm memory\n");
		}
		newNode->esct = call_cell;
		newNode->next = NULL;
		
		if (*calls_eme == NULL){
			LM_DBG("---FIRST IN THE LIST \n");
			list_call = newNode;
			
		} else {
			LM_DBG("---UPDATE LIST \n");
			list_call = *calls_eme;
			NODE *current = list_call;
			while (current->next != NULL) {
				current = current->next;
			}
			current->next = newNode;
		}

		*calls_eme = list_call;
		LM_DBG(" --- WRITE DATA 8");

		LM_DBG(" ---END WRITE DATA\n \n");
		if(add_headers(parsed, msg)==-1){
			return -1;
		}
		LM_DBG(" --- FREE F e V\n \n");
		resp = 1;
	}
	LM_DBG(" ---END  FREE PARSED  ");
	return resp;
}


/* frees the memory from the struct NENA
*/
void free_nena(NENA *nena) {
	if (nena->organizationname && strlen(nena->organizationname)>0)
		pkg_free(nena->organizationname);
	if (nena->hostname && strlen(nena->hostname)>0)
		pkg_free(nena->hostname);
	if (nena->nenaid && strlen(nena->nenaid)>0)
		pkg_free(nena->nenaid);
	if (nena->contact && strlen(nena->contact)>0)
		pkg_free(nena->contact);
	if (nena->certuri && strlen(nena->certuri)>0)
		pkg_free(nena->certuri);

}


/*frees memory from the data received from the VPC
*/
void free_parsed(PARSED *parsed){
	if(parsed){
		if(parsed->ert->routingESN && strlen(parsed->ert->routingESN)>0)
			pkg_free(parsed->ert->routingESN);
		if(parsed->ert->selectiveRoutingID && strlen(parsed->ert->selectiveRoutingID)>0)
			pkg_free(parsed->ert->selectiveRoutingID);
		if(parsed->ert->npa && strlen(parsed->ert->npa)>0)
			pkg_free(parsed->ert->npa);
		free_nena(parsed->vpc);
		free_nena(parsed->destination);
		if(parsed->result && strlen(parsed->result)>0)
			pkg_free(parsed->result);
		if(parsed->esgwri && strlen(parsed->esgwri)>0)
			pkg_free(parsed->esgwri);
		if(parsed->esqk && strlen(parsed->esqk)>0)
			pkg_free(parsed->esqk);
		if(parsed->lro && strlen(parsed->lro)>0)
			pkg_free(parsed->lro);
		if(parsed->callid && strlen(parsed->callid)>0)
			pkg_free(parsed->callid);
		if(parsed->datetimestamp && strlen(parsed->datetimestamp)>0)
			pkg_free(parsed->datetimestamp);
		
		pkg_free(parsed);
	}
}

/* treatment of an emergency call
*   - verify the opensips configuration:
*	   - 0 : Call Server from scenario I or Routing Proxy scenario II
*	   - 1 : Call Server from scenario II
*	   - 2 : callserver from scenario III
*	   - 3 : Redirect proxy no cenario III
*   - checks if the parameters to emergency call treatment were configured
*   - retreives the location from the INVITE
*   - includes the ersResponse in a node of the list calls_eme
*	   - source
*	   - vpc
*	   - esgw
*	   - esqk
*	   - callid
*	   - ert_srid
*	   - ert_resn
*	   - ert_npa
*	   - datetimestamp
*	   - lro
*	   - disposition
*	   - result 
*	   - timeout
*   - extracts CBN from INVITE 
*   - 
*/
static int send_request_vpc(struct sip_msg *msg) {
	char* xml;
	char* pidf_body = NULL;
	char* response;
	char* locationHeader;
	char* callidHeader;
	time_t rawtime;
	struct tm * timeinfo;
	PARSED *parsed=NULL;
	char formated_time[80];
	int resp =1;
	char* cbn_aux;
	char* lie;


	if (proxy_hole == 1) {

		LM_DBG(" ---Hole: proxy routing \n");
		if (proxy_request(msg) == -1) {
			LM_ERR("ERROR IN ROUTING EMERGENCY REQUEST");
			return -1;
		}
		return 1;
	}

	if (proxy_hole == 2) {
		// Call Server no cenario III
		// NOT YET IMPLEMENTED	   
		LM_DBG(" ---Hole: proxy redirect \n");
		return -1;
	}

	if (proxy_hole == 3) {
		// PROXY SCENARIO III
		// NOT YET IMPLEMENTED	   
		LM_DBG(" ---Hole: proxy redirect \n");
		return -1;
	}

	// checks for mandatory fields
	if (source_hostname == NULL || source_contact == NULL) {
		LM_ERR("source_hostname and source_contact are mandatory \n");
		return -1;
	}
	LM_DBG("TEST flag_empresa_terceira <> 0 %d\n", flag_empresa_terceira);
	if (flag_empresa_terceira != 0 &&
			(vsp_hostname == NULL || vsp_nena_id == NULL)) {
		LM_ERR("vsp_hostname and vsp_nena_id are mandatory when flag_empresa_terceira <> 0 %d\n", flag_empresa_terceira);
		return -1;
	}

	LM_DBG(" ---preenche_com_espaco_em_branco \n");
	resp = preenche_com_espaco_em_branco();
	if (resp == -1)
		return resp;
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	strftime(formated_time, 80, "%Y-%m-%dT%H:%M:%S%Z", timeinfo);
	LM_DBG(" --- INIT  send_request_vpc\n \n");
   
	if (find_body_pidf(msg, &pidf_body) == -1) {
		LM_ERR("Failed to get pidf body\n");
		return -1;
	}

	LM_DBG(" --- INIT  get_geolocation_header\n \n");
	resp = get_geolocation_header(msg, &locationHeader);
	if (resp == -1) {;
		return resp;
	}

	LM_DBG(" --- INIT  get_callid_header\n \n");
	resp = get_callid_header(msg, &callidHeader);
	if (resp == -1)
		return resp;

	cbn_aux = pkg_malloc(MAX_URI_SIZE);
	if (cbn_aux == NULL) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}
	memset(cbn_aux, 0, MAX_URI_SIZE);
	cbn.s = cbn_aux;
	cbn.len = MAX_URI_SIZE;

	found_CBN(msg, &cbn);  
	cbn.len = strlen(cbn.s);  

	if(pidf_body && strlen(pidf_body)>1) {	 

		if(locationHeader && strlen(locationHeader)>1){   
			int size_lie =  strlen(pidf_body) + strlen(locationHeader) + 2;
			lie = pkg_malloc(sizeof (char)* size_lie);
			memset(lie, 0, size_lie);
			sprintf(lie, "%s %s", locationHeader, pidf_body);
			pkg_free(pidf_body);  
			pkg_free(locationHeader);
		}else{
			lie = pidf_body;	   
		}
	} else{
		if(locationHeader && strlen(locationHeader)>1){   
			lie = locationHeader;
		}else{
			LM_ERR("INVITE whithout location information\n");
			return -1;	 
		}  
	} 

	LM_DBG(" --- CALLID-HEADER = %s \n \n", callidHeader);
	xml = formatted_xml(lie, formated_time, callidHeader, cbn.s);

	//  HTTP POST to VPC
	resp = post(url_vpc, xml, &response);
	pkg_free(xml);

	LM_DBG(" --- PIDF = %s \n \n", pidf_body);

   
	if (resp == -1) {
		LM_ERR(" --- PROBLEM IN POST \n \n");
		goto error;
	}
	
	parsed = parse_xml(response);
	if (parsed != NULL) {
		if(treat_parsed(parsed, msg, callidHeader)==-1){
			goto error;
		}
		free_parsed(parsed);
	} else {
		LM_ERR("PARSER ERROR\n");
		goto error;
	}

	LM_DBG("END EMERGENCY");
	pkg_free(response);
	
	if(callidHeader)
		pkg_free(callidHeader);
	
	 if(lie)
		pkg_free(lie);   
	
	
	return 1;
	
	error : 
		if(callidHeader)
			pkg_free(callidHeader);

	  if(lie)
		pkg_free(lie);   
		
		free_parsed(parsed);
		return -1;
			
}


int get_callid_header(struct sip_msg *msg, char** callidHeader) {
	char* code;
	char* p;
	int len;
	if (!msg->callid && ((parse_headers(msg, HDR_CALLID_F, 0) == -1) || !msg->callid)) {
		LM_ERR("Message has no Call-ID header\n");
		return -1;
	}
	LM_DBG(" ---------------------------------------------------------- CALL ID HEADER %.*s \n \n", msg->callid->body.len, msg->callid->body.s);
	code = msg->callid->body.s;
	len = msg->callid->body.len;
	p = memchr(code, '@', len);
	if (p) {
		len = p - code;
	}
	LM_DBG(" ---------------------------------------------------------- LEN DA PARTE SEM @ DO HEADER %d \n \n", len);
	*callidHeader = pkg_malloc(sizeof (char) * len + 1);
	memset(*callidHeader, '\0', len + 1);
	strncpy(*callidHeader, msg->callid->body.s, len);
	LM_DBG(" ---------------------------------------------------------- CALL ID SEM @ DO HEADER %s \n \n", *callidHeader);
	return 1;
}


/* verify if the ruri is from the same opensips
*/
int check_myself(struct sip_msg *msg) {
	int ret = 0;
	if ((parse_sip_msg_uri(msg) < 0) ||
			(!msg->parsed_uri.user.s) ||
			(msg->parsed_uri.user.len > MAXNUMBERLEN)) {
		LM_ERR("cannot parse msg URI\n");
		return 0;
	}
	LM_DBG(" --- emergency_call TRADUCAO %.*s \n \n", msg->parsed_uri.host.len, msg->parsed_uri.host.s);
	ret = check_self_op(EQUAL_OP, &msg->parsed_uri.host, 0);
	LM_DBG(" --- emergency_call retorno  check_self_op %d \n \n", ret);
	return ret;
}


/* verify if the INVITE has the header Geolocation-Routing with the value "yes"
*/
int check_geolocation_header(struct sip_msg *msg) {
	LM_DBG(" --- check_geolocation_header\n\n");
	if (parse_headers(msg, HDR_OTHER_F, 0) == -1) {
		LM_ERR("NO HEADER header\n");
		return 0;
	}
	LM_DBG(" --- check_geolocation_header --- OK\n\n");
	struct hdr_field* atual = msg->headers;
	while (atual != NULL) {
		char* name = pkg_malloc(sizeof (char) * atual->name.len);
		char* body = pkg_malloc(sizeof (char) * atual->body.len);
		strncpy(name, atual->name.s, atual->name.len);
		strncpy(body, atual->body.s, atual->body.len);
		char* geo = strstr(name, GEO_LOCATION_ROUTING);
		char* val = strstr(body, GEO_LOCATION_ROUTING_YES);
		if (geo != NULL && val != NULL) {
			pkg_free(name);
			pkg_free(body);
			return 1;
		}
		atual = atual->next;
		pkg_free(name);
		pkg_free(body);
	}
	return 0;
}

/* retreives Geolocation 
*  - extracts the headers Geolocation from the INVITE,this values will be used by the VPC to obtain the location information form the LIS
*/
int get_geolocation_header(struct sip_msg *msg, char** locationHeader) {
	char* locationTotalHeader = "";
	char* name;
	char* body;

	LM_DBG(" --- get_geolocation_header\n\n");
	if (parse_headers(msg, HDR_OTHER_F, 0) == -1) {
		LM_ERR("NO HEADER header\n");
		return -1;
	}

	LM_DBG(" --- get_geolocation_header --- INICIO %s \n\n", locationTotalHeader);
	struct hdr_field* atual = msg->headers;
	while (atual != NULL) {
		
		name = pkg_malloc(sizeof (char) * atual->name.len + 1);
		if (name == NULL) {
			LM_ERR("NO MEMORY\n");
			return -1;
		}
		memcpy( name, atual->name.s, atual->name.len); 
		name[atual->name.len] = 0;
		
		body = pkg_malloc(sizeof (char) * atual->body.len + 1);
		 if (body == NULL) {
			LM_ERR("NO MEMORY\n");
			return -1;
		} 
		memcpy( body, atual->body.s, atual->body.len); 
		body[atual->body.len] = 0;  
		
		char* geo = strstr(name, GEO_LOCATION);
		char* httpBody = strstr(body, "http");
		char* geoRouting = strstr(name, GEO_LOCATION_ROUTING);		
		
		pkg_free(name);
		pkg_free(body);
		
		if (geo != NULL && httpBody != NULL && geoRouting == NULL) {
			int TotalHeader_len = strlen(locationTotalHeader);
					 
			int new_size = atual->body.len + TotalHeader_len + 1;
			new_size += strlen(LOCATION_TAG_BEGIN) + strlen(LOCATION_TAG_END);
			new_size += strlen(NEW_LINE);
			char* aux = pkg_malloc(sizeof (char) * new_size);
			if (aux == NULL) {
				LM_ERR("NO MEMORY\n");
				return -1;
			}
			 
			strcpy(aux, locationTotalHeader);
			strcat(aux, LOCATION_TAG_BEGIN);
			strncat(aux, atual->body.s, atual->body.len);
			strcat(aux, LOCATION_TAG_END);
			strcat(aux, NEW_LINE);
			aux[new_size - 1] = 0;
			if (TotalHeader_len != 0)			   
				pkg_free(locationTotalHeader);
			
			locationTotalHeader = aux;
			LM_DBG(" --- get_geolocation_header ATUAL %s \n\n", locationTotalHeader);
		}
		atual = atual->next;
	}
	
	*locationHeader = locationTotalHeader;
	LM_DBG(" --- get_geolocation_header FINAL %s \n\n", *locationHeader);
	return 1;
}


NODE* find_and_delete_esct(char* callId) {
	int cont = 0;
	struct node* list_eme = *calls_eme;
	NODE *current = list_eme;
	NODE *previous = NULL;
		
	while (current) {	   
		printf("loop %d", cont++);
		if (same_callid(current->esct->callid, callId) == 0) {			
			NODE* node = current;
			NODE* next = current->next;

			if (collect_data(current) == 1) {
				LM_DBG("****** REPORT OK\n");
			} else {
				LM_DBG("****** REPORT NOK\n");
			}
			
			if (previous == NULL){
				if (next == NULL){
					*calls_eme = NULL;
				}else{
					*calls_eme = next;
				}
			}else{
				current = next;
				previous->next = current;
			}
			
			return node;
		}
		previous = current;
		current = current->next;
	}
	
	printf("Nao achou\n");
	return NULL;
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
static int collect_data(struct node *current) {

	int callid_len, esgwri_len, srid_len, lro_len, vpc_name_len, vpc_host_len, time_len, result_len, disposition_len;
	int size_report;
	struct emergency_report *report_eme;

	callid_len = strlen(current->esct->callid);
	esgwri_len = strlen(current->esct->esgw);
	srid_len = strlen(current->esct->ert_srid);
	lro_len = strlen(current->esct->lro);
	vpc_name_len = strlen(current->esct->vpc->organizationname);
	vpc_host_len = strlen(current->esct->vpc->hostname);
	time_len = strlen(current->esct->datetimestamp);
	result_len = strlen(current->esct->result);
	disposition_len = strlen(current->esct->disposition);

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
		memcpy(report_eme->esgwri.s, current->esct->esgw, esgwri_len);
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

	report_eme->timestamp.len = time_len;
	if (time_len == 0) {
		report_eme->timestamp.s = " ";
		report_eme->timestamp.len = 1;
	} else {
		report_eme->timestamp.s = (char *) (report_eme + 1) + callid_len + srid_len + esgwri_len + lro_len + vpc_name_len + vpc_host_len;
		memcpy(report_eme->timestamp.s, current->esct->datetimestamp, time_len);
	}

	report_eme->result.len = result_len;
	report_eme->result.s = (char *) (report_eme + 1) + callid_len + srid_len + esgwri_len + lro_len + vpc_name_len + vpc_host_len + time_len;
	memcpy(report_eme->result.s, current->esct->result, result_len);

	report_eme->disposition.len = disposition_len;
	report_eme->disposition.s = (char *) (report_eme + 1) + callid_len + srid_len + esgwri_len + lro_len + vpc_name_len + vpc_host_len + time_len + result_len;
	memcpy(report_eme->disposition.s, current->esct->disposition, disposition_len);

	LM_DBG(" --- REPORT - CALLID %.*s XXXXXXX\n\n", report_eme->callid.len, report_eme->callid.s);
	LM_DBG(" --- REPORT - ESGWRI %.*s \n\n", report_eme->esgwri.len, report_eme->esgwri.s);
	LM_DBG(" --- REPORT - ERT-RESN %d \n\n", report_eme->ert_resn);
	LM_DBG(" --- REPORT - ERT-NPA %d \n\n", report_eme->ert_npa);
	LM_DBG(" --- REPORT - ERT-SRID %.*s \n\n", report_eme->ert_srid.len, report_eme->ert_srid.s);
	LM_DBG(" --- REPORT - LRO %.*s \n\n", report_eme->lro.len, report_eme->lro.s);
	LM_DBG(" --- REPORT - VPC - NAME %.*s \n\n", report_eme->vpc_name.len, report_eme->vpc_name.s);
	LM_DBG(" --- REPORT - VPC - HOST %.*s \n\n", report_eme->vpc_host.len, report_eme->vpc_host.s);
	LM_DBG(" --- REPORT - TIMESTAMP %.*s \n\n", report_eme->timestamp.len, report_eme->timestamp.s);
	LM_DBG(" --- REPORT - RESULT %.*s \n\n", report_eme->result.len, report_eme->result.s);
	LM_DBG(" --- REPORT - DISPOSITION %.*s \n\n", report_eme->disposition.len, report_eme->disposition.s);

	if (report(report_eme) != 1) {
		LM_DBG("****** INSERT NOK\n");
		return -1;
	}

	LM_DBG("****** INSERT OK\n");
	return 1;
}

/* find node cell from the callID */
ESCT* find_esct(char* callId) {
	LM_DBG(" --- find_esct para calid  = %s ", callId);
	int cont = 0;

	struct node* list_eme = *calls_eme;

	NODE* current = list_eme;
	while (current) {
		printf("loop %d", cont++);


		if (same_callid(current->esct->callid, callId) == 0) {
			LM_DBG(" --- ACHOU ESCT para callId  = %s ", callId);
			ESCT* esct = current->esct;
			LM_DBG(" ---Roteando o pacote LRO %s \n\n", esct->lro);
			return esct;
		}
		current = current->next;
	}
	LM_DBG("Did not find\n");
	return NULL;
}


int same_callid(char* callIdEsct, char* callId) {
	if (callIdEsct == NULL || callId == NULL) {
		return 0;
	} else {
		LM_DBG(" --- Comparing callId  = %s com %s", callId, callIdEsct);
		return strcmp(callIdEsct, callId);
	}
}


static int routing_ack(struct sip_msg *msg) {
	char* callidHeader;
	int resp = 1;
	int esgw_len;

	ESCT* info_call;
	LM_DBG(" --- INICIANDO TRATAMENTO ACK \n \n");


	resp = get_callid_header(msg, &callidHeader);
	LM_DBG(" --- INICIANDO TRATAMENTO ACK  HEADER RESP %d ", resp);
	if (resp == -1)
		return resp;


	if (proxy_hole == 1) {
		if (proxy_request(msg) == -1) {
			LM_ERR("ERROR IN ROUTING EMERGENCY REQUEST");
			return -1;
		}

		return 1;
	}



	LM_DBG(" ---TRATAMENTO ACK  callid=%s", callidHeader);
	
	info_call = find_esct(callidHeader);
	if (info_call == NULL) {
		LM_DBG(" ---TRATAMENTO ACK NAO ENCONTROU CALLID");
		goto error;
	}

	LM_DBG(" ---Roteando o pacote %s \n\n", info_call->esgw);

	esgw_len = strlen(info_call->esgw);

	if (esgw_len) {

		LM_DBG(" ---Alterando URI ACK %d \n\n", esgw_len);
		
		if(new_uri_proxy(msg, info_call->esgw) == -1){
			LM_ERR(" ---ERRO EM NEW_URI_PROXY");
			goto error;
		}

	}

	info_call->timeout = BYE_TIME;

	//lock_stop_read( ref_lock );
	if(callidHeader)
		pkg_free(callidHeader);
	
	return 1;
	error : 
		if(callidHeader)
			pkg_free(callidHeader);
		return -1;
}

void free_call_cell(NODE *info_call){

	if(info_call){	
		if(info_call->esct){
			if (info_call->esct->source){
				if(info_call->esct->source->organizationname){
					if (strlen(info_call->esct->source->organizationname)!= 0){
						shm_free (info_call->esct->source->organizationname);
						LM_DBG(" ---  FREE INFO_CALL->SOURCE->ORG");				
					}				 
				} 
				if(info_call->esct->source->hostname){
					if (strlen(info_call->esct->source->hostname)!= 0){
						shm_free (info_call->esct->source->hostname);
						LM_DBG(" ---  FREE INFO_CALL->SOURCE->HOST");  
					}				 
				}   
				if(info_call->esct->source->nenaid){
					if (strlen(info_call->esct->source->nenaid)!= 0){
						shm_free (info_call->esct->source->nenaid);
						 LM_DBG(" ---  FREE INFO_CALL->SOURCE->NENA");			   
					}				 
				}			 
				if(info_call->esct->source->contact){
					if (strlen(info_call->esct->source->contact)!= 0){
						shm_free (info_call->esct->source->contact);
						 LM_DBG(" ---  FREE INFO_CALL->SOURCE->CONTACT");				
					}				 
				}
				if(info_call->esct->source->certuri){
					if (strlen(info_call->esct->source->certuri)!= 0){
						shm_free (info_call->esct->source->certuri);
						 LM_DBG(" ---  FREE INFO_CALL->SOURCE->CERTURI");				
					}				 
				}  
				shm_free (info_call->esct->source);
			}

			if (info_call->esct->vpc){
				if(info_call->esct->vpc->organizationname){
					if (strlen(info_call->esct->vpc->organizationname)!= 0){
						shm_free (info_call->esct->vpc->organizationname);
						LM_DBG(" ---  FREE INFO_CALL->VPC->ORG");			   
					}				 
				}
				if(info_call->esct->vpc->hostname){
					if (strlen(info_call->esct->vpc->hostname)!= 0){
						shm_free (info_call->esct->vpc->hostname);
						LM_DBG(" ---  FREE INFO_CALL->VPC->HOST");				
					}				 
				} 
				if(info_call->esct->vpc->nenaid){
					if (strlen(info_call->esct->vpc->nenaid)!= 0){
						shm_free (info_call->esct->vpc->nenaid);
						LM_DBG(" ---  FREE INFO_CALL->VPC->NENA");			   
					}				 
				} 
				if(info_call->esct->vpc->contact){
					if (strlen(info_call->esct->vpc->contact)!= 0){
						shm_free (info_call->esct->vpc->contact);
						LM_DBG(" ---  FREE INFO_CALL->VPC->CONTACT");				
					}				 
				}
				if(info_call->esct->vpc->certuri){
					if (strlen(info_call->esct->vpc->certuri)!= 0){
						shm_free (info_call->esct->vpc->certuri);
						LM_DBG(" ---  FREE INFO_CALL->VPC->CERTURI");				
					}				 
				} 
				shm_free (info_call->esct->vpc);
			} 
			if(info_call->esct->esqk){
				shm_free (info_call->esct->esqk);
				LM_DBG(" ---  FREE INFO_CALL->ESQK");								
			} 

			if(info_call->esct->callid){
				shm_free (info_call->esct->callid);
				LM_DBG(" ---  FREE INFO_CALL->CALLID");								
			}  
			if(info_call->esct->lro){
				shm_free (info_call->esct->lro);
				LM_DBG(" ---  FREE INFO_CALL->LRO");								  
			}
			if(info_call->esct->esgw){
				shm_free (info_call->esct->esgw);
				LM_DBG(" ---  FREE INFO_CALL->ESGW");								
			} 
			if(info_call->esct->ert_srid){
				LM_DBG(" ---  FREE INFO_CALL->ERT_SRID");
				if (strlen(info_call->esct->ert_srid)!= 0){				
					shm_free (info_call->esct->ert_srid);
				}													  
			}   
			if(info_call->esct->result){
				shm_free (info_call->esct->result);
				LM_INFO(" ---  FREE INFO_CALL->RESULT");								 
			}
			shm_free (info_call->esct); 
		}
		shm_free (info_call);		
	}

}


static int bye(struct sip_msg *msg, int dir) {
	char* callidHeader;
	int resp = 1;
	int esgw_len;
	char* response;
	char* esct_callid;
	time_t rawtime;
	struct tm * timeinfo;
	char formated_time[80];
	NODE* info_call;
	char* xml=NULL;

	LM_DBG(" --- BYE \n \n");

	if (proxy_hole == 1) {

	   LM_DBG(" ---Hole: proxy routing \n");
		if (proxy_request(msg) == -1) {
			LM_ERR("ERROR IN ROUTING EMERGENCY REQUEST");
			return -1;
		}
		return 1;
	}

	if (proxy_hole == 2) {
		// Call Server scenario III
		//NOT YET IMPLEMENTED	
		LM_DBG(" ---Hole: proxy redirect \n");
		return -1;
	}

	if (proxy_hole == 3) {
		// Redirect proxy scenario III
		//NOT YET IMPLEMENTED	
		LM_DBG(" ---Hole: proxy redirect \n");
		return -1;
	}

	time(&rawtime);
	timeinfo = localtime(&rawtime);
	strftime(formated_time, 80, "%Y-%m-%dT%H:%M:%S%Z", timeinfo);

	resp = get_callid_header(msg, &callidHeader);
	LM_DBG(" ---BYE  HEADER RESP %d ", resp);
	if (resp == -1)
		return resp;

	LM_DBG(" --- BYE  callid=%s", callidHeader);

	info_call = find_and_delete_esct(callidHeader);
	if (info_call == NULL) {
		LM_ERR(" --- BYE DID NOT FIND CALLID");
		goto error;
	}

	LM_DBG(" ---ROUTING BYE %s \n\n", info_call->esct->esgw);
   
	esgw_len = strlen(info_call->esct->esgw);

	if (dir == 1) {
		
		if (esgw_len) {

			LM_DBG(" ---Changing BYE %d \n\n", esgw_len);
			if(new_uri_proxy(msg, info_call->esct->esgw) == -1){
				LM_ERR(" ---NOK NEW_URI_PROXY");
				goto error;
			}   
		}
	}

	xml = buildXmlFromModel(info_call->esct);
	
	if(info_call->esct->datetimestamp){
		shm_free (info_call->esct->datetimestamp);
		LM_DBG(" ---  FREE INFO_CALL->TIME");								
	}
	
	info_call->esct->datetimestamp = formated_time;
	LM_DBG(" --- INICIANDO TRATAMENTO BYE XML %s \n \n", xml);

	// sends HTTP POST esctRequest to VPC
	resp = post(url_vpc, xml, &response);
	if (resp == -1) {
		LM_ERR(" --- PROBLEM IN POST DO BYE\n \n");
		goto error;
	}

	esct_callid = parse_xml_esct(response);
	if (esct_callid== NULL) {
		LM_ERR(" --- esctAck invalid format or without mandatory field \n \n");		
	} else {
		if (strcmp(esct_callid, callidHeader)){
			LM_ERR(" --- callid in esctAck different from asctRequest \n \n");			 
		}
		if(esct_callid)
			pkg_free(esct_callid);
	}
	pkg_free(response);
	

	pkg_free(xml);
	
	if(callidHeader)
		pkg_free(callidHeader);

	free_call_cell(info_call);

	
	return 1;

error : 
		if(callidHeader)
			pkg_free(callidHeader);
	
		if(xml)
			pkg_free(xml);
		return -1;
}


/* this function tries to find callback number (CBN)  in the given INVITE
- first tries to get from the PAI headers , then PPI , then RDID an finally tries the From header
*/
static void found_CBN(struct sip_msg *msg, str* cbn_pt) {


	str pattern, pattern_from, replacement, cbn;

	int found_cbn;

	pattern.s = "tel:([+]*[-0-9]+)";
	pattern.len = strlen(pattern.s);

	pattern_from.s = "sips?:([+]*[-0-9]+)";
	pattern_from.len = strlen(pattern_from.s);

	replacement.s = "\\1";
	replacement.len = strlen(replacement.s);

	found_cbn = 0;

	cbn = *cbn_pt;

	if (parse_pai_header(msg) == 0) {
		LM_DBG("****** PAI: %.*s\n", msg->pai->body.len, msg->pai->body.s);

		if (reg_replace(pattern.s, replacement.s, msg->pai->body.s, &cbn) == 1) {

			found_cbn = 1;
			LM_DBG("****** PATTERN OK\n");
			LM_DBG("****** REG_REPLACE: %.*s\n", cbn.len, cbn.s);		  
		} else {
			memset(cbn.s, 0, MAX_URI_SIZE);
			LM_DBG("****** PATTERN NAO OK \n");
		}

	}


	if (found_cbn == 0) {
		if (parse_ppi_header(msg) == 0) {
			LM_DBG("****** PPI: %.*s\n", msg->ppi->body.len, msg->ppi->body.s);

			if (reg_replace(pattern.s, replacement.s, msg->ppi->body.s, &cbn) == 1) {
				found_cbn = 1;
				LM_DBG("****** PATTERN OK\n");
				LM_DBG("****** REG_REPLACE: %.*s\n", cbn.len, cbn.s);
			} else {
				memset(cbn.s, 0, MAX_URI_SIZE);
				LM_DBG("****** PATTERN NAO OK \n");
			}
		}
	}


	if (found_cbn == 0) {
		if (parse_rpid_header(msg) == 0) {
			LM_DBG("****** RPID: %.*s\n", msg->rpid->body.len, msg->rpid->body.s);

			if (reg_replace(pattern.s, replacement.s, msg->rpid->body.s, &cbn) == 1) {
				found_cbn = 1;
				LM_DBG("****** PATTERN OK\n");
				LM_DBG("****** REG_REPLACE: %.*s\n", cbn.len, cbn.s);
			} else {
				memset(cbn.s, 0, MAX_URI_SIZE);
				LM_DBG("****** PATTERN NAO OK \n");
			}
		}
	}


	if (found_cbn == 0) {

		if (parse_from_header(msg) == 0) {
			LM_DBG("****** FROM: %.*s\n", msg->from->body.len, msg->from->body.s);

			if (reg_replace(pattern.s, replacement.s, msg->from->body.s, &cbn) == 1) {
				found_cbn = 1;
				LM_DBG("****** PATTERN OK\n");
				LM_DBG("****** REG_REPLACE: %.*s\n", cbn.len, cbn.s);
			} else {

				if (reg_replace(pattern_from.s, replacement.s, msg->from->body.s, &cbn) == 1) {
					found_cbn = 1;
					LM_DBG("****** PATTERN OK\n");
					LM_DBG("****** REG_REPLACE: %.*s\n", cbn.len, cbn.s);
				} else {
					memset(cbn.s, 0, MAX_URI_SIZE);
					LM_ERR("****** PATTERN NAO OK \n");
					cbn.len = 0;
				}
			}

		} else {
			LM_ERR("****** FROM: ERRO");
		}

	}
	return;
}

/* store data in the table emergency_report
*/
static int report(struct emergency_report *report) {

	static query_list_t *ins_list = NULL;
	static db_ps_t siptrace_ps = NULL;

	LM_DBG("Report emergency call in db\n");

	db_con = db_funcs.init(&db_url);
	if (!db_con) {
		LM_ERR("unable to connect database\n");
		goto error;
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
		goto error;

	}

	db_funcs.close(db_con);
	db_con = 0;

	pkg_free(report);
	
	return 1;

error:
	if (report)
		pkg_free(report);

	return -1;
}


static int new_uri_proxy(struct sip_msg *req_msg, char* new_uri ){

	int new_uri_len;
	
	LM_DBG("NEW_URI_PROXY...\n");   
	new_uri_len = strlen (new_uri);
	
	req_msg->new_uri.s = (char*)pkg_malloc(new_uri_len+1);
	if (req_msg->new_uri.s==0){
		LM_ERR("no more pkg\n");
		return -1;
	}
	memcpy( req_msg->new_uri.s, new_uri, new_uri_len);
	req_msg->new_uri.s[new_uri_len]=0;
	req_msg->new_uri.len = strlen(new_uri);
	req_msg->parsed_uri_ok = 0;

	return 1;
}


/* retreives esgwrifrom the list db_esrn_domain
* using  srid(selectiveRoutingID), resn(routingESN) and npa. 
*/
static int emergency_routing(char *srid, int resn, int npa, char** esgwri) {

	lock_start_read(ref_lock);

	struct esrn_routing* esrn_domain = *db_esrn_domain;
	LM_DBG("SRID = %s \n", srid);
	while (esrn_domain != NULL) {
		LM_DBG("CMP = %.*s \n", esrn_domain->srid.len, esrn_domain->srid.s);
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

