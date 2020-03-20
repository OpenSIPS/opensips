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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 *  2014-10-14 initial version (Villaron/Tesini)
 *  2015-03-21 implementing subscriber function (Villaron/Tesini)
 *  2015-04-29 implementing notifier function (Villaron/Tesini)
 *  2015-05-20 change callcell identity
 *  2015-06-08 change from list to hash (Villaron/Tesini)
 *  2015-08-05 code review (Villaron/Tesini)
 *  2015-09-07 final test cases (Villaron/Tesini)
 */


#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>
#include "emergency_methods.h"

#define TABLE_ROUTING_VERSION    1
#define TABLE_REPORT_VERSION     1
#define TABLE_PROVIDER_VERSION   1

/*
 * Module initialization and cleanup
 */
static int mod_init(void);
static int child_init(int);
static void mod_destroy(void);

struct dlg_binds dlgb;
struct rr_binds rr_api;

struct tm_binds eme_tm;

str db_url;
str *db_table;
db_func_t db_funcs;
db_con_t *db_con;

struct esrn_routing **db_esrn_esgwri;
struct service_provider **db_service_provider;

str callid_aux;
char* url_vpc;

int emet_size;
int subst_size;

char *empty;
char *mandatory_parm;

struct call_htable *call_htable;
struct subs_htable *subs_htable;

/*
 * Exported functions
 */
static cmd_export_t cmds[] = {
	{"emergency_call", (cmd_function) emergency_call, {{0, 0, 0}},
		REQUEST_ROUTE | BRANCH_ROUTE },
	{"failure", (cmd_function) failure, {{0, 0, 0}},
		FAILURE_ROUTE | ONREPLY_ROUTE },
	{ 0, 0, {{0, 0, 0}}, 0}
};


/*
 * Exported parameters
 */

static param_export_t params[] = {
	{ "emergency_codes", STR_PARAM | USE_FUNC_PARAM, (void *) &set_codes},
	{ "timer_interval", INT_PARAM, &timer_interval},
	{ "db_url", STR_PARAM, &db_url.s},
	{ "db_table_routing", STR_PARAM, &table_name.s},
	{ "db_table_report", STR_PARAM, &table_report.s},
	{ "db_table_provider", STR_PARAM, &table_provider.s},
	{ "url_vpc", STR_PARAM, &url_vpc},
	{ "contingency_hostname", STR_PARAM, &contingency_hostname},
	{ "emergency_call_server", STR_PARAM, &call_server_hostname},
	{ "proxy_role", INT_PARAM, &proxy_role},
	{ "callorigin", STR_PARAM, &call_origin},
	{ "call_htable_size", INT_PARAM, &emetable_size},
	{ "subs_htable_size", INT_PARAM, &substable_size},
	{ 0, 0, 0}
};


/*
 * Module parameter variables
 */
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
	0,				 /* load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds, /* Exported functions */
	NULL,      /* Exported async functions */
	params, /* Exported parameters */
	0, /* exported statistics */
	0, /* exported MI functions */
	0, /* exported pseudo-variables */
	0, /* exported transformations */
	0, /* extra processes */
	0, /* module pre-initialization function */
	mod_init, /* module initialization function */
	0, /* response function*/
	mod_destroy,
	child_init,/* per-child init function */
	0          /* reload confirm function */
};

/*
 * Polling Inicialization Functions
 */


/* extracts the code and the description of the parameter emergency_code
 *  and stores these values in new_code linked list
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

	/* separates the code and the description using the delimiter CODE_DELIM ("-") */

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

void destroy_codes(struct code_number *codes){
	struct code_number *c;

	while(codes){
		c= codes;
		codes= codes->next;
		pkg_free(c);
	}
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

	table_name.len = strlen(table_name.s);
	table_report.len = strlen(table_report.s);
	table_provider.len = strlen(table_provider.s);

	// checks for mandatory fields
	mandatory_parm = shm_malloc(2);
	mandatory_parm[0] = '1';
	mandatory_parm[1] = 0;

	inicialized = shm_malloc(2);
	inicialized[0] = '0';
	inicialized[1] = 0;

	LM_DBG(" ---fill parameters not config with blank_space \n");
	if (fill_blank_space() == -1)
		return -1;

	if ( load_dlg_api( &dlgb ) != 0 ) {
		LM_ERR("failed to load DLG api\n");
		return -1;
	}

	if (load_tm_api(&eme_tm)!=0) {
		LM_ERR( "can't load TM API\n");
		return -1;
	}

	if (load_rr_api(&rr_api) != 0) {
		LM_ERR("failed to load rr API\n");
		return -1;
	}


	empty = shm_malloc(sizeof (char));
	memset(empty, '\0', 1);

	if(call_origin == NULL)
		call_origin = empty;

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


		if (!DB_CAPABILITY(db_funcs, DB_CAP_ALL)) {
			LM_ERR("database modules does not provide all functions needed by module\n");
			return -1;
		}

		if (db_check_table_version(&db_funcs, db_con, &table_name, TABLE_ROUTING_VERSION) < 0) {
			LM_ERR("error during routing table version check.\n");
			return -1;
		}

		if (db_check_table_version(&db_funcs, db_con, &table_report, TABLE_REPORT_VERSION) < 0) {
			LM_ERR("error during report table version check.\n");
			return -1;
		}

		if (db_check_table_version(&db_funcs, db_con, &table_provider, TABLE_PROVIDER_VERSION) < 0) {
			LM_ERR("error during provider table version check.\n");
			return -1;
		}

		db_funcs.close(db_con);
		db_con = 0;
	}

	db_table = (str *)shm_malloc(sizeof (str));
	if (!db_table) {
		LM_ERR("no more memory\n");
		return -1;
	}
	db_table = &table_report;

	db_esrn_esgwri = shm_malloc(sizeof (struct esrn_routing *));
	if (!db_esrn_esgwri) {
		LM_ERR("no more memory\n");
		return -1;
	}
	*db_esrn_esgwri = NULL;

	db_service_provider = shm_malloc(sizeof (struct service_provider *));
	if (!db_service_provider) {
		LM_ERR("no more memory\n");
		return -1;
	}
	*db_service_provider = NULL;

	if (register_timer("emer_rout_table", routing_timer, 0, timer_interval, 0) < 0) {
		LM_ERR("failed to register timer \n");
		return -1;
	}

	if ((ref_lock = lock_init_rw()) == NULL) {
		LM_ERR("failed to init lock\n");
		return -1;
	}

	if(emetable_size< 1)
		emet_size= 512;
	else
		emet_size= 1<< emetable_size;

	call_htable= new_ehtable(emet_size);
	if(call_htable== NULL)
	{
		LM_ERR(" initializing emergency_call hash table\n");
		return -1;
	}

	if(substable_size< 1)
		subst_size= 512;
	else
		subst_size= 1<< substable_size;

	subs_htable= new_shtable(subst_size);
	if(subs_htable== NULL)
	{
		LM_ERR(" initializing emergency_call hash table\n");
		return -1;
	}

	/* data */
	curl_global_init(CURL_GLOBAL_ALL);

	LM_DBG("EMERGENCY Module initialized!\n");
	return 0;
}


/* this function is responsible for:
 *   - open database connection
 *   - initialize polling routing timer
 */
static int child_init(int rank) {
	LM_DBG("Initializing child\n");

	if (db_url.s && rank>=1) {
		/* open a test connection */

		if ((db_con = db_funcs.init(&db_url)) == 0) {
			LM_ERR("cannot init connection to DB\n");
			return -1;
		}

		if (strcmp(inicialized, "0") == 0){
			inicialized[0] = '1';
			inicialized[1] = 0;

			routing_timer(0, 0);
		}

	}
	return 0;
}


/*
 *  - close database connection
 *  - terminate lock (ref_lock)
 */
static void mod_destroy(void) {
	curl_global_cleanup();

	if(ref_lock){
		lock_destroy_rw( ref_lock );
		ref_lock = NULL;
	}

	if(call_htable)
		destroy_ehtable(call_htable, emet_size);

	if(subs_htable)
		destroy_shtable(subs_htable, subst_size);

	shm_free(inicialized);
	shm_free(db_service_provider);
	shm_free(db_esrn_esgwri);
	shm_free(empty);
	destroy_codes(codes);


}


/*
 * - copying data from the routing table to the list db_esrn_domain (performance improvement)
 */
void routing_timer(unsigned int ticks, void *attr) {

	if (get_db_routing(table_name, ref_lock ) != 1)
		LM_ERR("ERROR IN GET ROUTING OF DB \n");

	if (get_db_provider(table_provider, ref_lock ) != 1)
		LM_ERR("ERROR IN GET SERVICE PROVIDER OF DB \n");

	libera_esqk();

	free_subs();
}


/*
 * - verifying the expiration for packet loss ( timing values are different for ACK and BYE)
 * - if there is an expiration the module sends a POST informing the VPC to exclude the number
 *   the key ESQK is retreived from the list calls_eme
 */
static void libera_esqk(void) {

	time_t rawtime;
	struct tm timeinfo;
	int resp = 1;
	char* response;
	char* esct_callid;
	char* xml;
	struct node* current;
	NODE *previous = NULL;
	NODE *free_cell;
	int i;

	for(i= 0; i< emet_size; i++){

		lock_get(&call_htable[i].lock);

		previous= call_htable[i].entries;
		current= previous->next;

		while (current) {

			current->esct->timeout --;
			NODE* next = current->next;
			LM_DBG("TIMEOUT:%d\n", current->esct->timeout);
			if (current->esct->timeout <= 0 ){
				LM_DBG("time fires\n");
				free_cell = current;
				previous->next = next;

				LM_DBG("********************************************CALLID FREE%s\n", free_cell->esct->callid);

				if ((proxy_role == 0) || (proxy_role == 1) ||(proxy_role == 4)){
					//sends ESCT only if VPC provided key ESQK
					if (strlen(free_cell->esct->esqk) > 0){
						LM_DBG(" --- SEND ESQK=%s \n \n",free_cell->esct->esqk);

						//send esctRequest to the VPC
						time(&rawtime);
						localtime_r(&rawtime, &timeinfo);
						strftime(free_cell->esct->datetimestamp, MAX_TIME_SIZE, "%Y-%m-%dT%H:%M:%S%Z", &timeinfo);

						xml = buildXmlFromModel(free_cell->esct);
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
							LM_DBG(" *** esctACK OK\n");
							if(esct_callid)
								pkg_free(esct_callid);
						}
						pkg_free(response);
						pkg_free(xml);
					}
				}

				shm_free(free_cell->esct->esgwri);
				shm_free(current);

			}else{
				previous = current;
			}
			current = next;
		}
		lock_release(&call_htable[i].lock);
	}
}

/*
 * - verifying the expiration for subscribe
 * - free subscriber cell
 */
static void free_subs(void) {

	time_t rawtime;
	struct sm_subscriber* current;
	struct sm_subscriber* previous = NULL;
	struct sm_subscriber* free_cell;
	struct sm_subscriber* next;
	int time_C;
	int i;

	time(&rawtime);
	time_C = (int)rawtime;
	LM_DBG("TIME : %d \n", (int)rawtime );

	for(i= 0; i< subst_size; i++){

		lock_get(&subs_htable[i].lock);

		previous= subs_htable[i].entries;
		current= previous->next;

		while (current) {

			next = current->next;
			LM_DBG("timeout %d\n", current->timeout);
			if (current->timeout <= time_C ){
				LM_DBG("time fires %d\n", current->timeout);
				free_cell = current;
				previous->next = next;

				shm_free(free_cell);

			}else{
				previous = current;
			}
			current = next;
		}
		lock_release(&subs_htable[i].lock);

	}

}


/*
 * Callback Functions
 */

/*
 *   - treats the request within the dialog forwarding to the INVITE that first created the dialog
 *   - if the request is a BYE treats the call ending functions
 */
void indialog_ua(struct dlg_cell* dlg, int type, struct dlg_cb_params * params){
	struct sip_msg *msg = params->msg;
	int dir = params->direction;
	int resp;
	UNUSED(resp);

	LM_DBG(" New sequential request received:%d !! \n",dir);
	LM_DBG(" New sequential request method:%.*s \n",msg->first_line.u.request.method.len,msg->first_line.u.request.method.s);

	if (memcmp(msg->first_line.u.request.method.s,"BYE", msg->first_line.u.request.method.len) == 0) {
		LM_DBG(" --- TREAT BYE  -----  \n \n");

		resp = bye(msg,dir);
		LM_DBG(" ---TREATMENT DIALOG BYE:%d", resp);

	}else{
		if (dir == 1){
			LM_DBG(" --- TREAT DOWNSTREAM  -----  \n \n");
			resp = routing_ack(msg);
			LM_DBG(" ---TREATMENT DIALOG ACK:%d", resp);

		}
	}

}


void reply_in_redirect( struct cell* t, int type, struct tmcb_params *params){

	char *contact_esgwri = NULL;
	char *contact_lro = NULL;
	struct sip_msg *reply = params->rpl;
	struct sip_msg *msg_retran = params->req;
	struct to_body *pfrom = NULL;
	unsigned int hash_code;
	int resp = 0;
	int resp_esqk = 0;

	if (extract_contact_hdrs(reply, &contact_esgwri, &contact_lro) == -1){
		return;
	}

	if (msg_retran->from->parsed == NULL){
		if ( parse_from_header( reply )<0 ){
			LM_ERR("300 response without From header\n");
			goto error_01;
		}
	}

	pfrom = get_from(msg_retran);
	LM_DBG("PFROM_TAG: %.*sxxx \n ", pfrom->tag_value.len, pfrom->tag_value.s );
	if( pfrom->tag_value.s ==NULL || pfrom->tag_value.len == 0){
		LM_ERR("300 response without from_tag value \n");
		goto error_01;
	}

	if( msg_retran->callid==NULL || msg_retran->callid->body.s==NULL){
		LM_ERR("reply without callid header\n");
		goto error_01;
	}

	call_cell = pkg_malloc(sizeof (ESCT));
	if (call_cell == NULL) {
		LM_ERR("--------------------------------------------------no more shm memory\n");
		return;
	}

	call_cell->callid = pkg_malloc(sizeof (char)* reply->callid->body.len + 1);
	if (call_cell->callid == NULL) {
		LM_ERR("--------------------------------------------------no more shm memory\n");
		return;
	}
	memcpy(call_cell->callid, reply->callid->body.s, reply->callid->body.len);
	call_cell->callid[reply->callid->body.len] = 0;

	call_cell->eme_dlg_id = pkg_malloc(sizeof (struct dialog_set));
	if (call_cell->eme_dlg_id == NULL) {
		LM_ERR("--------------------------------------------------no more shm memory\n");
		return;
	}

	call_cell->eme_dlg_id->local_tag = pkg_malloc(sizeof (char)* pfrom->tag_value.len+1);
	if (call_cell->eme_dlg_id->local_tag == NULL) {
		LM_ERR("--------------------------------------------------no more shm memory\n");
		return;
	}
	memcpy(call_cell->eme_dlg_id->local_tag, pfrom->tag_value.s, pfrom->tag_value.len);
	call_cell->eme_dlg_id->local_tag[pfrom->tag_value.len] = 0;

	call_cell->eme_dlg_id->call_id  = pkg_malloc(sizeof (char)*reply->callid->body.len+1);
	if (call_cell->eme_dlg_id->call_id  == NULL) {
		LM_ERR("--------------------------------------------------no more shm memory\n");
		return;
	}
	memcpy(call_cell->eme_dlg_id->call_id, reply->callid->body.s, reply->callid->body.len);
	call_cell->eme_dlg_id->call_id[reply->callid->body.len] = 0;

	call_cell->eme_dlg_id->rem_tag = "";

	call_cell->esqk = empty;
	call_cell->esgw = empty;
	call_cell->lro = empty;
	call_cell->ert_srid = empty;
	call_cell->esgwri = empty;
	call_cell->result = empty;
	call_cell->datetimestamp = empty;
	call_cell->ert_npa = 0;
	call_cell->ert_resn = 0;
	call_cell->disposition = empty;
	call_cell->datetimestamp = empty;
	call_cell->timeout = ACK_TIME;

	call_cell->source = pkg_malloc(sizeof (NENA));
	if (call_cell->source == NULL) {
		LM_ERR("--------------------------------------------------no more shm memory\n");
		return;
	}

	call_cell->source->organizationname = empty;
	call_cell->source->hostname = empty;
	call_cell->source->nenaid = empty;
	call_cell->source->contact = empty;
	call_cell->source->certuri = empty;

	call_cell->vpc = pkg_malloc(sizeof (NENA));
	if (call_cell->vpc == NULL) {
		LM_ERR("--------------------------------------------------no more shm memory\n");
		return;
	}

	call_cell->vpc->organizationname = empty;
	call_cell->vpc->hostname = empty;
	call_cell->vpc->nenaid = empty;
	call_cell->vpc->contact = empty;
	call_cell->vpc->certuri = empty;

	if (contact_lro){
		if(get_lro_in_contact(contact_lro, call_cell) == -1){
			return;
		}
	}

	if (contact_esgwri){
		resp_esqk = get_esqk_in_contact(contact_esgwri, call_cell);
		if(resp_esqk == -1){
			return;
		}else{
			if(resp_esqk == 1){
				resp = get_esgwri_ert_in_contact(contact_esgwri, call_cell);
				if (resp == -1){
					return;
				}else{
					if(resp == 0){
						if(call_cell->lro == empty){
							LM_ERR("don't exits esgwri/ert or lro to routing\n");
							goto end;
						}
					}
				}
			}else{
				LM_DBG("exits lro to routing %d\n", resp);
				if(call_cell->lro == empty){
					LM_ERR("don't exits esgwri/ert or lro to routing\n");
					goto end;
				}
			}
		}
	}

	hash_code= core_hash(&reply->callid->body, 0, emet_size);
	LM_DBG("********************************************HASH_CODE%d\n", hash_code);

	if(insert_ehtable(call_htable,hash_code,call_cell)< 0){
		LM_ERR("inserting new record in subs_htable\n");
	}

end:
	free_call_cell(call_cell);

	return;

error_01:
	pkg_free(contact_esgwri);
	pkg_free(contact_lro);
	return;
}





/*
 * Functions that the User can call from the config file
 */


/*
 * - verify if the request is an emergency call
 * - is it is an emergency forward the INVITE to the destiny determined by the VPC
 */
int emergency_call(struct sip_msg *msg) {
	struct dlg_cell *dlg;

	// verify if mandatory parameters were configurated in script
	if ((proxy_role == 0|| proxy_role == 1|| proxy_role == 4) && (strcmp(mandatory_parm, "1") == 0)){
		LM_ERR("source_hostname and sorce_nena_id are mandatory\n");
		return -1;
	}

	// the emergency call treatment start with INVITE
	if (memcmp(msg->first_line.u.request.method.s,"INVITE", msg->first_line.u.request.method.len) == 0) {
		LM_DBG(" --- TREAT INVITE -----  \n \n");
		if (is_emergency_call(msg)) {
			LM_DBG(" --- IT IS AN EMERGECY -----  \n \n");
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
		}
	}else{

		if (memcmp(msg->first_line.u.request.method.s,"NOTIFY", msg->first_line.u.request.method.len) == 0){

			if (proxy_role == 4) {
				LM_DBG(" --- TREAT NOTIFY -----  \n \n");
				if ( !treat_notify(msg)){
					LM_ERR ("***** ERROR IN NOTIFY TREATMENT \n");
					return -1;
				}
				return -1;
			}
		}

		if (memcmp(msg->first_line.u.request.method.s,"SUBSCRIBE", msg->first_line.u.request.method.len) == 0){

			if (proxy_role == 3) {
				if ( !treat_subscribe(msg)){
					LM_ERR ("***** ERROR IN SUBSCRIBE TREATMENT \n");
					return -1;
				}
				return -1;
			}
		}

	}
	return -1;
}


/* treat the command FAILURE
 * - treat contingency forwarding in the case of failure of the original
 * - Forward the INVITE to a gateway with the contingency number lro from the field R-URI
 */
static int failure(struct sip_msg *msg) {

	char* callidHeader;
	ESCT* info_call;
	char* new_to;
	char* cbn_aux;
	str cbn;
	char* from_tag;
	struct to_body *pfrom = NULL;
	struct node* s;
	unsigned int hash_code;

	LM_DBG(" --- FAILURE  treatment \n \n");

	if (proxy_role == 2) {
		LM_DBG(" ---role: call server scenario II \n");
		return -1;
	}

	// get callid of the message

	if ( parse_headers(msg,HDR_EOH_F, 0) == -1 ){
		LM_ERR("error in parsing headers\n");
		return -1;
	}

	if( msg->callid==NULL || msg->callid->body.s==NULL){
		LM_ERR("msg without callid header\n");
		return -1;
	}
	callidHeader = pkg_malloc(sizeof (char) * msg->callid->body.len + 1);
	if (callidHeader == NULL) {
		LM_ERR("no more pkg memory\n");
		return -1 ;
	}
	memset(callidHeader, '\0', msg->callid->body.len + 1);
	strncpy(callidHeader, msg->callid->body.s, msg->callid->body.len);
	LM_DBG(" ---FAILURE treatment  callid=%s", callidHeader);

	if (msg->from->parsed == NULL){
		if ( parse_from_header( msg )<0 ){
			LM_ERR("subscribe without From header\n");
			pkg_free(callidHeader);
			return -1;
		}
	}
	pfrom = get_from(msg);
	LM_DBG("PFROM_TAG: %.*sxxx \n ", pfrom->tag_value.len, pfrom->tag_value.s );

	if( pfrom->tag_value.s ==NULL || pfrom->tag_value.len == 0){
		LM_ERR("INVITE without from_tag value \n");
		pkg_free(callidHeader);
		return -1;
	}
	from_tag = pkg_malloc(sizeof (char)* pfrom->tag_value.len + 1);
	if (from_tag == NULL) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}
	memset(from_tag, 0, pfrom->tag_value.len + 1);
	strncpy(from_tag, pfrom->tag_value.s, pfrom->tag_value.len);

	hash_code= core_hash(&msg->callid->body, 0, emet_size);
	LM_DBG("********************************************HASH_CODE%d\n", hash_code);

	// find the cell with the callid from the list calls_cell
	s= search_ehtable(call_htable, callidHeader, from_tag, hash_code, 0);
	if (s == NULL) {
		LM_ERR(" ---FAILURE treatment did not find the CALLID\n");
		goto error;
	}

	info_call = s->esct;

	if (proxy_role == 3) {

		if (strstr(info_call->disposition, "processes") != NULL) {

			LM_DBG(" ---role: proxy routing \n");
			cbn_aux = pkg_malloc(sizeof (char)* MAX_URI_SIZE);
			if (cbn_aux == NULL) {
				LM_ERR("no more pkg memory\n");
				return -1 ;
			}
			memset(cbn_aux, 0, MAX_URI_SIZE);
			found_CBN(msg, &cbn_aux);
			cbn.s = cbn_aux;
			cbn.len = strlen(cbn.s);
			LM_DBG(" --- FOUND CBN%.*s \n \n", cbn.len, cbn.s);

			if(strlen(info_call->esgwri) > 1){
				LM_DBG ("FAILURE REPLY ESGWRI %s \n",info_call->esgwri);
				if(new_uri_proxy(msg, info_call->esgwri) == -1){
					LM_ERR(" ERROR IN NEW_URI_PROXY\n");
					pkg_free(cbn_aux);
					goto lro;
				}

			}else{
				if ((strlen(info_call->ert_srid) > 1)&&(info_call->ert_resn != 0)&&(info_call->ert_npa != 0)){
					LM_DBG ("CONTEUDO FAILURE REPLY SRID %s \n",info_call->ert_srid);
					LM_DBG ("CONTEUDO FAILURE REPLY RESN %d \n",info_call->ert_resn);
					LM_DBG ("CONTEUDO FAILURE REPLY NPA %d \n",info_call->ert_npa);
					if(routing_by_ert( msg, info_call, 1) == -1){
						pkg_free(cbn_aux);
						goto lro;
					}

				}else{
					pkg_free(cbn_aux);
					goto lro;
				}
			}

			if(add_headers(info_call->esqk, msg, cbn)==-1){
				goto error;
			}

			info_call->timeout = ACK_TIME;
			memcpy(info_call->disposition, "esgwri", strlen("esgwri"));
			info_call->disposition[strlen("esgwri")] = 0;

			goto end;
		}
	}

lro:
	LM_DBG("treat lro \n");
	// verfifica se o parametro contingency_hostname foi definido no script, caso contrario failure não sera tratado
	if ( contingency_hostname == NULL) {
		LM_ERR("contingency_hostname not defined\n");
		goto error;
	}

	// verifica se a chamada tratada teve o numero de contingencia lro fornecido pelo VPC
	// caso não tenha, não trata failure
	if (info_call->lro == empty) {
		LM_ERR(" ---treat FAILURE not found lro\n");
		goto error;
	}

	//verify if there was an attempt to forward the INVITE to the contingency number
	if (strstr(info_call->disposition, "lro") == NULL) {

		LM_DBG("EH LRO -- LRO = %s  HOST = %s ", info_call->lro, contingency_hostname);
		int tamanho_new_to = strlen(info_call->lro) + strlen(contingency_hostname) + 17;
		new_to = shm_malloc(sizeof (char)* tamanho_new_to);
		sprintf(new_to, "sip:%s@%s;user=phone", info_call->lro, contingency_hostname);

		if((info_call->esgwri)&&(strlen(info_call->esgwri) > 1))
			shm_free (info_call->esgwri);

		info_call->esgwri = new_to;
		info_call->esgw = empty;
		info_call->timeout = ACK_TIME;
		memcpy(info_call->disposition, "lro", strlen("lro"));
		info_call->disposition[strlen("lro")] = 0;

		LM_DBG(" ---NEW DESTIN =%s", new_to);
		if(new_uri_proxy(msg, new_to) == -1){
			LM_ERR(" ---ERRO EM NEW_URI_PROXY\n");
			goto error;
		}
	}else{
		LM_DBG(" ---FAILURE JA TRANSMITIU LRO\n");
		goto error;
	}
end:
	if(callidHeader)
		pkg_free(callidHeader);
	if(from_tag)
		pkg_free(from_tag);

	return 1;


error :
	if(callidHeader)
		pkg_free(callidHeader);
	if(from_tag)
		pkg_free(from_tag);
	return -1;
}


/*
 * Internal functions
 */

/* verify if the call is an emergency call
 *  - verify if the field uri has a urn standard for emergency call defined by RFC 5031
 *  - if it does not, then verify if se user field is one of the emengency_code in the database
 *    - if it is a code, the module checks if the host is from the opensips
 or if there is a field Geolocation_routing = 'yes"
 */
int is_emergency_call(struct sip_msg *msg) {

	char *request_uri;

	// verify if the field uri has a urn standard for emergency call
	CP_STR_CHAR(msg->first_line.u.request.uri, request_uri);
	LM_DBG(" --- emergency_call %s\n \n", request_uri);

	if (memcmp(request_uri, "urn:service:sos", 12) == 0){
		LM_DBG(" --- IT IS EMERGENCY  -----  \n \n");
		pkg_free(request_uri);
		return 1;
	} else {
		// don't have URN standard for emergency call, verify USER field in RURI bind with some code in emergency_code
		LM_DBG(" --- verifying code \n \n");
		pkg_free(request_uri);
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

					LM_DBG(" ---> CODIGO -- OK %.*s\n", codigo->code.len, codigo->code.s);

					if (check_myself(msg)) {
						LM_DBG(" --- IT IS ONWER HOST  \n \n");
						return 1;
					} else {
						// Host isn't same of opensips, Geolocation_Routing determine if routing the INVITE (RFC 6442)
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

error:
	return 0;
}


/* treatment of an emergency call
 *   - verify the opensips configuration:
 *       - 0 : Call Server from scenario I or Routing Proxy scenario II
 *       - 1 : Call Server from scenario II
 *       - 2 : callserver from scenario III
 *       - 3 : Redirect proxy no cenario III
 *   - checks if the parameters to emergency call treatment were configured
 *   - retreives the location from the INVITE
 *   - includes the ersResponse in a node of the list calls_eme
 *       - source
 *       - vpc
 *       - esgw
 *       - esqk
 *       - callid
 *       - ert_srid
 *       - ert_resn
 *       - ert_npa
 *       - datetimestamp
 *       - lro
 *       - disposition
 *       - result
 *       - timeout
 *   - extracts CBN from INVITE
 *   -
 */
int send_request_vpc(struct sip_msg *msg) {
	char* xml;
	char* pidf_body = NULL;
	char* response;
	char* locationHeader;
	char* callidHeader;
	PARSED *parsed=NULL;
	int resp_post =1;
	char* lie;
	str cbn;
	char *cbn_aux;
	struct to_body *pfrom = NULL;
	char *from_tag;
	int resp =1;

	cbn_aux = pkg_malloc(sizeof (char)* MAX_URI_SIZE);
	if (cbn_aux == NULL) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}
	memset(cbn_aux, 0, MAX_URI_SIZE);

	if (found_CBN(msg, &cbn_aux) == -1)
		return -1;
	cbn.s = cbn_aux;
	cbn.len = strlen(cbn.s);

	LM_DBG(" --- FOUND CBN%.*s \n \n", cbn.len, cbn.s);

	if (proxy_role == 2) {
		LM_DBG(" ---role: call server scenario II \n");
		if (add_hdr_PAI(msg, cbn) == -1) {
			LM_ERR("FAILURE IN ADD PAI\n");
		}
		if (proxy_request(msg,call_server_hostname) == -1) {
			LM_ERR("ERROR IN ROUTING EMERGENCY REQUEST\n");
			return -1;
		}
		return 1;
	}

	if (proxy_role == 3) {
		// Call Server SCENARIO III
		LM_DBG(" ---role: proxy redirect \n");
		//if (add_hdr_PAI(msg, cbn) == -1) {
		//    LM_ERR("FAILURE IN ADD PAI\n");
		//}
		pkg_free(cbn.s);
		if (proxy_request(msg,call_server_hostname) == -1) {
			LM_ERR("ERROR IN ROUTING EMERGENCY REQUEST\n");
			return -1;
		}
		eme_tm.register_tmcb(msg,NULL,TMCB_RESPONSE_IN,reply_in_redirect,0,0);
		return 1;
	}

	// proxy
	if (find_body_pidf(msg, &pidf_body) == -1) {
		LM_ERR("Failed to get pidf body\n");
		return -1;
	}
	LM_DBG(" --- INIT  get_geolocation_header\n \n");
	if (get_geolocation_header(msg, &locationHeader) == -1){
		LM_ERR("Failed to get geolocation header\n");
		return -1;
	}
	LM_DBG(" --- INIT  get_callid_header\n \n");

	if ( parse_headers(msg,HDR_EOH_F, 0) == -1 ){
		LM_ERR("error in parsing headers\n");
		return -1;
	}

	if( msg->callid==NULL || msg->callid->body.s==NULL){
		LM_ERR("msg without callid header\n");
		return -1;
	}

	CP_STR_CHAR(msg->callid->body, callidHeader);

	if (msg->from->parsed == NULL){
		if ( parse_from_header( msg )<0 ){
			LM_ERR("subscribe without From header\n");
			return -1;
		}
	}
	pfrom = get_from(msg);
	LM_DBG("PFROM_TAG: %.*sxxx \n ", pfrom->tag_value.len, pfrom->tag_value.s );
	if( pfrom->tag_value.s ==NULL || pfrom->tag_value.len == 0){
		LM_ERR("INVITE without from_tag value \n");
		return -1;
	}

	CP_STR_CHAR(pfrom->tag_value, from_tag);

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
			LM_ERR("INVITE without location information\n");
			return -1;
		}
	}

	xml = formatted_xml(msg, lie, callidHeader, cbn.s);
	if(xml == NULL){
		LM_ERR(" --- PROBLEM IN FORMATTED XML \n \n");
		resp = -1;
		goto end;
	}

	//  HTTP POST to VPC
	resp_post = post(url_vpc, xml, &response);
	pkg_free(xml);
	if (resp_post == -1) {
		LM_ERR(" --- PROBLEM IN POST \n \n");
		resp = -1;
		goto end;
	}

	parsed = parse_xml(response);
	pkg_free(response);
	if (parsed != NULL) {;
		if(create_call_cell(parsed, msg, callidHeader, cbn, from_tag) == -1){
			resp = -1;
			goto end;
		}
	} else {
		LM_ERR("PARSER ERROR\n");
		resp = -1;
		goto end;
	}


	LM_DBG("END EMERGENCY\n");
	resp = 1;

end:
	if(callidHeader)
		pkg_free(callidHeader);

	if(from_tag)
		pkg_free(from_tag);

	if(lie)
		pkg_free(lie);

	return resp;

error :
	return -1;
}

/* handle data receved in esrResponse
 *   - verify if the message has mandatory fields:
 *       - callid
 *       - result
 *       - vpc_nenaid
 *       - vpc_contact
 *   - put parsed data in calls_eme truct.
 *   - insert calls_eme in call_htable hash with key source ip address
 */
int create_call_cell(PARSED *parsed,struct sip_msg* msg, char* callidHeader, str cbn, char* from_tag) {

	unsigned int hash_code;

	LM_DBG(" ---PARSED \n");
	if ((parsed->callid == empty || parsed->result == empty || parsed->vpc->nenaid == empty || parsed->vpc->contact == empty)) {
		LM_ERR("MANDATORY FIELDS ARE BLANK \n");
		free_parsed(parsed);
		pkg_free(cbn.s);
		return -1;
	} else {
		// check if the callid send in esrRequest is the same of esrResponse
		if (strcmp(parsed->callid, callidHeader) != 0) {
			LM_ERR("CALLID DIFFER %s ## %s \n", parsed->callid, callidHeader);
			free_parsed(parsed);
			pkg_free(cbn.s);
			return -1;
		}

		LM_DBG(" --- PARSE OK MANDATORY FIELDS \n \n");

		call_cell = pkg_malloc(sizeof (ESCT));
		if (call_cell == NULL) {
			LM_ERR("--------------------------------------------------no more shm memory\n");
			return -1;
		}

		call_cell->vpc = pkg_malloc(sizeof (NENA));
		if (call_cell->vpc == NULL) {
			LM_ERR("--------------------------------------------------no more shm memory\n");
			return -1;
		}

		call_cell->source = pkg_malloc(sizeof (NENA));
		if (call_cell->source == NULL) {
			LM_ERR("--------------------------------------------------no more shm memory\n");
			return -1;
		}

		call_cell->eme_dlg_id = pkg_malloc(sizeof (struct dialog_set));
		if (call_cell->eme_dlg_id == NULL) {
			LM_ERR("--------------------------------------------------no more shm memory\n");
			return -1;
		}

		call_cell->eme_dlg_id->local_tag = pkg_malloc(sizeof (char)*strlen(from_tag)+1);
		if (call_cell->eme_dlg_id->local_tag == NULL) {
			LM_ERR("--------------------------------------------------no more shm memory\n");
			return -1;
		}
		strcpy(call_cell->eme_dlg_id->local_tag, from_tag);

		call_cell->eme_dlg_id->call_id  = pkg_malloc(sizeof (char)*strlen(callidHeader)+1);
		if (call_cell->eme_dlg_id->call_id  == NULL) {
			LM_ERR("--------------------------------------------------no more shm memory\n");
			return -1;
		}
		strcpy(call_cell->eme_dlg_id->call_id , callidHeader);

		call_cell->eme_dlg_id->rem_tag = "";

		LM_DBG("PFROM_TAGII: %s \n ", call_cell->eme_dlg_id->local_tag );
		LM_DBG("CALL_IDII: %s \n ", call_cell->eme_dlg_id->call_id );

		// get parsed data extract from esrResponse and save in calls_eme struct
		if(treat_parse_esrResponse(msg, call_cell , parsed, proxy_role) == -1){
			return -1;
		}

		// treat INVITE routing
		if (treat_routing(msg, call_cell, callidHeader, cbn) == -1){
			return -1;
		}

		// insert calls_eme in call_htable hash with key source ip address

		hash_code= core_hash(&msg->callid->body, 0, emet_size);
		LM_DBG("********************************************HASH_CODE%d\n", hash_code);

		if(insert_ehtable(call_htable, hash_code,call_cell)< 0){
			LM_ERR("inserting new record in subs_htable\n");
		}

		free_call_cell(call_cell);

		return 1;
	}
}


/* treats INVITE routing
 *   - checks the result field to verify if the msg from VPC was seuccessfull
 *   - checks the esgwri code or the data from the emergency area (selectiveRoutingID, routingESN, npa) to translate to esgwri
 */
int treat_routing(struct sip_msg* msg, struct esct *call_cell, char* callidHeader, str cbn) {
	static str msg300={"Multiple Choices",sizeof("Multiple Choices")-1};

	int result = atoi(call_cell->result);
	int range = range_result(result);
	LM_DBG(" --- range %d", range);

	if (range == 1) {
		// result NOK without contigency number
		LM_ERR("INVALID RESULT -- EMERGENCY EXIT%d \n", result);
		goto error;
	}

	// opensips with call server role in scenario I or with routing proxy hole in scenario II
	if ((proxy_role == 0) || (proxy_role == 1)){

		if (range == 2) {
			// result NOK but the VPC send contingency number to routing the call
			LM_ERR("INVALID RESULT --CONTINGENCY \n");

			if(contingency(msg, call_cell) == -1)
				goto error;

			call_cell->ert_npa = 0;
			call_cell->ert_resn = 0;
			call_cell->ert_srid = "";

			pkg_free(cbn.s);
			return 1;
		}

		// result OK

		call_cell->disposition = "esgwri";
		call_cell->timeout = ACK_TIME;

		if (call_cell->esgwri != empty && strlen(call_cell->esgwri) > 0) {
			// VPC send esgwri to routing INVITE
			if (call_cell->esqk == empty){
				LM_ERR(" ---Result 200 but without esqk \n");
				goto contingency;
			}

			if(new_uri_proxy(msg,call_cell->esgwri) == -1){
				LM_ERR(" ---ERROR IN NEW_URI_PROXY\n");
				goto error;
			}

		} else {
			LM_DBG("ert_srid %s \n", call_cell->ert_srid);
			LM_DBG("ert_resn %d \n", call_cell->ert_resn);

			if ((call_cell->ert_srid != empty) && (call_cell->ert_resn != 0) && (call_cell->ert_npa != 0)) {
				if (call_cell->esqk == empty){
					LM_ERR(" ---Result 200 but without esqk \n");
					goto contingency;
				}
				if(routing_by_ert( msg, call_cell, 0) == -1){
					goto contingency;
				}
			}else{
				// VPC not send routing information
				LM_ERR(" ---Result 200 but without ert or esgwri \n");
				goto contingency;
			}
		}

		if(add_headers(call_cell->esqk, msg, cbn)==-1){
			free_call_cell(call_cell);
			return -1;
		}

	}else{
		// opensips with redirect server role
		if (proxy_role == 4){
			LM_DBG(" ---TRATA REDIRECT\n \n");
			if(add_hdr_rpl(call_cell, msg)==-1)
				goto error;

			if(!eme_tm.t_reply(msg,300,&msg300)){
				LM_DBG("t_reply (300)\n");
				goto error;
			}
			call_cell->disposition = "redirect";
			call_cell->timeout = BYE_TIME;

			int expires = EXPIRES_SUBSCRIBE;
			if( !send_subscriber(msg, callidHeader, expires))
				goto error;

			pkg_free(cbn.s);

		}else{
			LM_ERR("proxy_role invalid\n");
			goto error;
		}
	}
	return 1;

contingency:
	if(contingency(msg, call_cell) == -1)
		goto error;

	pkg_free(cbn.s);
	return 1;

error:
	pkg_free(cbn.s);
	free_call_cell(call_cell);
	return -1;
}


/*
 * this function is responsible for getting the forwarding data to the INVITE from tha stucture given by the VPC
 * Stores :
 *       - selectiveRoutingID
 *       - routingESN
 *       - npa
 *   - retreives the esgwri based on the data
 *   - forward the invite
 */
int routing_by_ert( struct sip_msg *msg, ESCT *call_cell, int failure) {
	char *esgwri_db;
	int  size_esgwri = 0;

	if (emergency_routing(call_cell->ert_srid, call_cell->ert_resn, call_cell->ert_npa, &esgwri_db, ref_lock) != -1) {

		LM_DBG("DB_ESGWRI %s \n", esgwri_db);

		if (failure == 1){
			shm_free(call_cell->esgwri);
			size_esgwri = strlen(esgwri_db);
			call_cell->esgwri= (char*)shm_malloc(size_esgwri + 1);
			if(call_cell->esgwri== NULL){
				LM_ERR("no more pkg memory\n");
				return -1;
			}
			call_cell->esgwri[size_esgwri] = 0;
			memcpy(call_cell->esgwri, esgwri_db, size_esgwri);
			pkg_free(esgwri_db);

		}else{
			call_cell->esgwri = esgwri_db;

			char *r = strstr(call_cell->esgwri, "@");
			r++;
			int tam_esgw = call_cell->esgwri + strlen(call_cell->esgwri) - r;

			call_cell->esgw = pkg_malloc(sizeof (char)*tam_esgw + 1);
			if (call_cell->esgw == NULL) {
				LM_ERR("no more pkg memory\n");
				return -1;
			}
			memcpy(call_cell->esgw, r, tam_esgw);
			call_cell->esgw[tam_esgw] = 0;

			LM_DBG(" --- ESGW:%s \n", call_cell->esgw);

		}

		if(new_uri_proxy(msg, call_cell->esgwri) == -1){
			LM_ERR(" ---ERROR IN NEW_URI_PROXY\n");
			return -1;
		}

	} else {
		LM_ERR("NOT FOUND ERT IN DB\n");
		return -1;
	}
	return 1;
}


/*
 *  this function treats the forwarding of the message in the case when the VPC returns esrResponse "NOT OK" but with the field LRO not blanck
 *   -Forward the INVITE in a contingency gateway with the altenative numbe lro in the user field of the R-URI
 */
int contingency(struct sip_msg *msg, ESCT *call_cell){

	char *lro;

	//Treat LRO
	//checks if the LRO field was forwarded by VPC, otherwise the called will have NOK treatment
	lro = call_cell-> lro;
	if (lro == empty) {
		LM_ERR("no received lro\n");
		return -1;
	}
	int len_lro = strlen(lro);

	//checks if contingency_hostname parameter was defined in config script, otherwise the called will have NOK treatment
	if ( contingency_hostname == NULL) {
		LM_ERR("contingency_hostname not defined\n");
		return -1;
	}

	// set R-URI to foward INVITE considering contingency_hostname parameter
	// and LRO provided by VPC = sip:lro@contingency_hostname;user=phone
	int tamanho_new_to = len_lro + strlen(contingency_hostname) + 17;

	call_cell->esgwri = pkg_malloc(sizeof (char)* tamanho_new_to);
	sprintf(call_cell->esgwri, "sip:%s@%s;user=phone", lro, contingency_hostname);

	if(new_uri_proxy(msg, call_cell->esgwri) == -1){
		LM_ERR(" ---ERRO EM NEW_URI_PROXY\n");
		return -1;
	}

	call_cell->disposition = "lro";
	call_cell->esgw = empty;
	call_cell->timeout = ACK_TIME;

	return 1;
}

/* treat dialog resquest
*/

/* ensures the routing of the dialog requests in downstream direction
 *  to same destination routed to INVITE
 */
int routing_ack(struct sip_msg *msg) {
	char* callidHeader;
	char* from_tag;
	int resp = 1;
	ESCT* info_call;
	struct to_body *pfrom = NULL;
	struct node* s;
	unsigned int hash_code;

	LM_DBG(" --- START TREATMENT ACK \n \n");
	if (proxy_role == 2) {
		// Call Server scenario II
		if (proxy_request(msg,call_server_hostname) == -1) {
			LM_DBG("ERROR IN ROUTING EMERGENCY REQUEST \n");
			return -1;
		}
		return -1;
	}

	if (proxy_role == 4) {
		// Redirect Proxy scenario III
		LM_DBG(" ---role: proxy redirect \n");
		return -1;
	}

	if ( parse_headers(msg,HDR_EOH_F, 0) == -1 ){
		LM_ERR("error in parsing headers\n");
		return -1;
	}

	if( msg->callid==NULL || msg->callid->body.s==NULL){
		LM_ERR("msg without callid header\n");
		return -1;
	}

	callidHeader = pkg_malloc(sizeof (char) * msg->callid->body.len + 1);
	if (callidHeader == NULL) {
		LM_ERR("no more pkg memory\n");
		return -1 ;
	}
	memset(callidHeader, '\0', msg->callid->body.len + 1);
	strncpy(callidHeader, msg->callid->body.s, msg->callid->body.len);



	if (msg->from->parsed == NULL){
		if ( parse_from_header( msg )<0 ){
			LM_ERR("subscribe without From header\n");
			return -1;
		}
	}
	pfrom = get_from(msg);
	LM_DBG("PFROM_TAG: %.*sxxx \n ", pfrom->tag_value.len, pfrom->tag_value.s );

	if( pfrom->tag_value.s ==NULL || pfrom->tag_value.len == 0){
		LM_ERR("INVITE without from_tag value \n");
		return -1;
	}
	from_tag = pkg_malloc(sizeof (char)* pfrom->tag_value.len + 1);
	if (from_tag == NULL) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}
	memset(from_tag, 0, pfrom->tag_value.len + 1);
	strncpy(from_tag, pfrom->tag_value.s, pfrom->tag_value.len);
	LM_DBG("PFROM_TAGIII: %s \n ", from_tag );

	hash_code= core_hash(&msg->callid->body, 0, emet_size);
	LM_DBG("********************************************HASH_CODE%d\n", hash_code);

	LM_DBG(" ---TREATMENT ACK  callid=%s \n", callidHeader);

	s= search_ehtable(call_htable, callidHeader, from_tag, hash_code, 0);
	if (s == NULL) {
		LM_DBG(" ---TREATMENT ACK - NOT FIND CALLID \n");
		resp = -1;
		goto end;
	}

	info_call = s->esct;

	if (strlen(info_call->esgwri) > 0) {
		LM_DBG(" ---Routing ACK %s \n", info_call->esgwri);
		if(new_uri_proxy(msg, info_call->esgwri) == -1){
			LM_ERR(" ---ERROR IN NEW_URI_PROXY\n");
			resp = -1;
			goto end;
		}
	}

	info_call->timeout = BYE_TIME;
	resp = 1;

end :
	if(callidHeader)
		pkg_free(callidHeader);
	if(from_tag)
		pkg_free(from_tag);
	return resp;
}


/* Treat BYE
*/

/* treat BYE received in emergency calls
 *   - ensure de routing of bye belong dialog received in downstream direction
 *     to same destination routed to INVITE
 *   - signals the VPC the call termination
 *   - free call cell in list linked calls_eme
 */
int bye(struct sip_msg *msg, int dir) {
	char* callidHeader;
	int resp = 1;
	char* response;
	char* esct_callid;
	time_t rawtime;
	struct tm timeinfo;
	NODE* info_call;
	char* xml;
	struct sm_subscriber*  cell_notif;
	int time_now;
	char* from_tag;
	struct to_body *pfrom = NULL, *pto= NULL;
	unsigned int hash_code;

	LM_DBG(" --- BYE \n \n");

	time(&rawtime);
	localtime_r(&rawtime, &timeinfo);
	time_now = (int)rawtime;

	if (proxy_role == 2) {
		// Call Server scenario II
		if (dir == 1) {
			LM_DBG(" ---role: proxy routing \n");
			if (proxy_request(msg,call_server_hostname) == -1) {
				LM_ERR("ERROR IN ROUTING EMERGENCY REQUEST\n");
				return -1;
			}
			return 1;
		}
		return -1;
	}

	if (proxy_role == 4) {
		// Redirect Proxy scenario III
		LM_DBG(" ---role: proxy redirect \n");
		return -1;
	}

	// get callid from BYE and put callidHeader var
	if ( parse_headers(msg,HDR_EOH_F, 0) == -1 ){
		LM_ERR("error in parsing headers\n");
		return -1;
	}
	if( msg->callid==NULL || msg->callid->body.s==NULL){
		LM_ERR("msg without callid header\n");
		return -1;
	}
	callidHeader = pkg_malloc(sizeof (char) * msg->callid->body.len + 1);
	if (callidHeader == NULL) {
		LM_ERR("no more pkg memory\n");
		return -1 ;
	}
	memset(callidHeader, '\0', msg->callid->body.len + 1);
	strncpy(callidHeader, msg->callid->body.s, msg->callid->body.len);

	if (proxy_role == 3) {
		// Redirect proxy scenario III
		LM_DBG(" ---role: proxy redirect \n");
		cell_notif = get_subs_cell(msg, msg->callid->body);
		if (cell_notif != NULL){
			cell_notif->call_dlg_id->status = TERMINATED;
			cell_notif->timeout =  TIMER_N + time_now;
			send_notifier_within(msg, cell_notif);
		}
	}

	if (dir == 1) {
		//downstream direction
		// use from_tag and callid for dialog search
		if (msg->from->parsed == NULL){
			if ( parse_from_header( msg )<0 ){
				LM_ERR("subscribe without From header\n");
				if(callidHeader)
					pkg_free(callidHeader);
				return -1;
			}
		}
		pfrom = get_from(msg);
		LM_DBG("PFROM_TAG: %.*sxxx \n ", pfrom->tag_value.len, pfrom->tag_value.s );

		if( pfrom->tag_value.s ==NULL || pfrom->tag_value.len == 0){
			LM_ERR("INVITE without from_tag value \n");
			if(callidHeader)
				pkg_free(callidHeader);
			return -1;
		}
		from_tag = pkg_malloc(sizeof (char)* pfrom->tag_value.len + 1);
		if (from_tag == NULL) {
			LM_ERR("no more pkg memory\n");
			return -1;
		}
		memset(from_tag, 0, pfrom->tag_value.len + 1);
		strncpy(from_tag, pfrom->tag_value.s, pfrom->tag_value.len);

	}else{
		// upstream direction
		// use to_tag and callid for dialog search
		pto = get_to(msg);
		if (pto == NULL || pto->error != PARSE_OK) {
			LM_ERR("failed to parse TO header\n");
			if(callidHeader)
				pkg_free(callidHeader);
			return -1;
		}
		if( pto->tag_value.s ==NULL || pto->tag_value.len == 0){
			LM_ERR("BYE without tag value \n");
			if(callidHeader)
				pkg_free(callidHeader);
			return -1;
		}
		LM_DBG("PTO: %.*s \n ", pto->uri.len, pto->uri.s );
		LM_DBG("PTO_TAG: %.*s \n ", pto->tag_value.len, pto->tag_value.s );
		from_tag = pkg_malloc(sizeof (char)* pto->tag_value.len + 1);
		if (from_tag == NULL) {
			LM_ERR("no more pkg memory\n");
			return -1;
		}
		memset(from_tag, 0, pto->tag_value.len + 1);
		strncpy(from_tag, pto->tag_value.s, pto->tag_value.len);

	}

	hash_code= core_hash(&msg->callid->body, 0, emet_size);
	LM_DBG("********************************************HASH_CODE%d\n", hash_code);

	// search call hash with hash_code, callidHeader and from/to_tag params
	LM_DBG(" --- BYE  callid=%s \n", callidHeader);
	info_call= search_ehtable(call_htable, callidHeader, from_tag, hash_code, 1);

	// report call datas in emergency_table_report
	if (info_call == NULL) {
		LM_ERR(" --- BYE DID NOT FIND CALLID \n");
		resp = -1;
		goto end;
	}else{
		if (collect_data(info_call, db_url, *db_table) == 1) {
			LM_DBG("****** REPORT OK\n");
		} else {
			LM_DBG("****** REPORT NOK\n");
		}

	}



	if (dir == 1) {
		// downstream direction
		// routing BYE to same direction that INVITE

		if (strlen(info_call->esct->esgwri) > 0) {
			LM_DBG(" ---Routing BYE %s \n", info_call->esct->esgwri);
			if(new_uri_proxy(msg, info_call->esct->esgwri) == -1){
				LM_ERR(" ---ERROR IN NEW_URI_PROXY\n");
				shm_free(info_call->esct->esgwri);
				shm_free(info_call);
				resp = -1;
				goto end;
			}
		}
	}


	// sends ESCT to VPC signalling end call
	if ((proxy_role == 0) || (proxy_role == 1)){
		// send ESCT only if VPC provided key ESQK
		if (strlen(info_call->esct->esqk) > 0){

			LM_DBG(" --- SEND ESQK =%s\n \n",info_call->esct->esqk);

			strftime(info_call->esct->datetimestamp, MAX_TIME_SIZE, "%Y-%m-%dT%H:%M:%S%Z", &timeinfo);

			xml = buildXmlFromModel(info_call->esct);
			LM_DBG(" --- TREAT BYE - XML ESCT %s \n \n", xml);
			// sends HTTP POST esctRequest to VPC
			resp = post(url_vpc, xml, &response);
			if (resp == -1) {
				LM_ERR(" --- PROBLEM IN POST DO BYE\n \n");
				shm_free(info_call->esct->esgwri);
				shm_free(info_call);
				pkg_free(xml);
				resp = -1;
				goto end;
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
		}
	}

	shm_free(info_call->esct->esgwri);
	shm_free(info_call);
	resp = 1;

end :
	if(callidHeader)
		pkg_free(callidHeader);
	if(from_tag)
		pkg_free(from_tag);

	return resp;
}


/*
 * Aux functions
 */

#define SUCCESS_OR_EXIT(_f) \
	do {\
		resp = fill_parm_with_BS(&(_f)); \
		if (resp < 0) { \
			LM_ERR("out of pkg mem\n"); \
			return -1; \
		} \
	} while(0)


/* fill with blanck spaces
*/
int fill_blank_space(void) {
	int resp = 1;
	SUCCESS_OR_EXIT(vpc_organization_name);
	SUCCESS_OR_EXIT(vpc_hostname);
	SUCCESS_OR_EXIT(vpc_nena_id);
	SUCCESS_OR_EXIT(vpc_contact);
	SUCCESS_OR_EXIT(vpc_cert_uri);
	SUCCESS_OR_EXIT(source_organization_name);
	SUCCESS_OR_EXIT(source_nena_id);
	SUCCESS_OR_EXIT(source_cert_uri);
	SUCCESS_OR_EXIT(vsp_organization_name);
	if (proxy_role == 0) {
		SUCCESS_OR_EXIT(vsp_hostname);
		SUCCESS_OR_EXIT(vsp_nena_id);
	}
	SUCCESS_OR_EXIT(vsp_contact);
	SUCCESS_OR_EXIT(vsp_cert_uri);
	return resp;
}

#undef SUCCESS_OR_EXIT


/*fill with blanck spaces
*/
int fill_parm_with_BS(char** var) {
	if (*var == NULL) {
		*var = pkg_malloc(sizeof (char) * strlen(BLANK_SPACE));
		if (*var == NULL)
			return -1;
		strcpy(*var, BLANK_SPACE);
		return 1;
	}
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
	LM_DBG(" --- opensips host %.*s \n \n",
		msg->parsed_uri.host.len, msg->parsed_uri.host.s);

	ret=check_self(&msg->parsed_uri.host, 0, 0);
	return ret;
}


/* calculate the size of the xml to allocate memory
*/
unsigned long get_xml_size(char* lie, char* formated_time, char* callidHeader, char* cbn, char* call_origin) {
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
	resp += strlen(call_origin);
	return resp;
}

/* format the xml to send POST -> esrRequest
*/
char* formatted_xml(struct sip_msg *msg, char* lie, char* callidHeader, char* cbn) {
	char* xml;
	char formated_time[80];
	time_t rawtime;
	struct tm timeinfo;
	struct service_provider* source_provider;
	struct service_provider* vpc_provider;
	struct service_provider* vsp_provider;

	source_organization_name = empty;
	source_hostname = empty;
	source_nena_id = empty;
	source_contact = empty;
	source_cert_uri = empty;
	vpc_organization_name = empty;
	vpc_hostname = empty;
	vpc_nena_id = empty;
	vpc_contact = empty;
	vpc_cert_uri = empty;
	vsp_organization_name = empty;
	vsp_hostname = empty;
	vsp_nena_id = empty;
	vsp_contact = empty;
	vsp_cert_uri = empty;

	time(&rawtime);
	localtime_r(&rawtime, &timeinfo);
	strftime(formated_time, 80, "%Y-%m-%dT%H:%M:%S%Z", &timeinfo);
	LM_DBG(" --- INIT  send_request_vpc\n \n");
	LM_DBG(" --- FORMAT XML \n \n");

	source_provider = get_provider(msg, 0, ref_lock);
	if (source_provider != NULL){
		CP_STR_CHAR(source_provider->OrganizationName, source_organization_name);
		CP_STR_CHAR(source_provider->hostId, source_hostname);
		CP_STR_CHAR(source_provider->nenaId, source_nena_id);
		CP_STR_CHAR(source_provider->contact, source_contact);
		CP_STR_CHAR(source_provider->certUri, source_cert_uri);
	}

	vpc_provider = get_provider(msg, 1, ref_lock);
	if (vpc_provider != NULL){
		CP_STR_CHAR(vpc_provider->OrganizationName, vpc_organization_name);
		CP_STR_CHAR(vpc_provider->hostId, vpc_hostname);
		CP_STR_CHAR(vpc_provider->nenaId, vpc_nena_id);
		CP_STR_CHAR(vpc_provider->contact, vpc_contact);
		CP_STR_CHAR(vpc_provider->certUri, vpc_cert_uri);
	}

	vsp_provider = get_provider(msg, 2, ref_lock);
	if (vsp_provider != NULL){
		CP_STR_CHAR(vsp_provider->OrganizationName, vsp_organization_name);
		CP_STR_CHAR(vsp_provider->hostId, vsp_hostname);
		CP_STR_CHAR(vsp_provider->nenaId, vsp_nena_id);
		CP_STR_CHAR(vsp_provider->contact, vsp_contact);
		CP_STR_CHAR(vsp_provider->certUri, vsp_cert_uri);
	}

	if (proxy_role == 1 && ((strlen(vsp_hostname) == 0) || (strlen(vsp_nena_id) == 0))){
		LM_ERR("vsp_hostname and vsp_nena_id are mandatory when opensips role as routing proxy in scenario II\n");
		return NULL;
	}

	int size_xml = get_xml_size(lie, formated_time, callidHeader, cbn, call_origin) + 1;
	LM_DBG(" --- LEN XML %d \n \n", size_xml);
	xml = pkg_malloc(sizeof (char) * size_xml);
	memset(xml, 0, size_xml);

	sprintf(xml, MODEL,\
			vpc_organization_name, vpc_hostname, vpc_nena_id, vpc_contact, vpc_cert_uri, \
			source_organization_name, source_hostname, source_nena_id, source_contact, source_cert_uri, \
			vsp_organization_name, vsp_hostname, vsp_nena_id, vsp_contact, vsp_cert_uri,\
			callidHeader, cbn, lie,\
			call_origin, formated_time);
	LM_DBG(" --- INIT  xml %s\n \n", xml);

	FREE_BUF(vpc_organization_name);
	FREE_BUF(vpc_hostname);
	FREE_BUF(vpc_nena_id);
	FREE_BUF(vpc_contact);
	FREE_BUF(vpc_cert_uri);

	FREE_BUF(source_organization_name);
	FREE_BUF(source_hostname);
	FREE_BUF(source_nena_id);
	FREE_BUF(source_contact);
	FREE_BUF(source_cert_uri);

	FREE_BUF(vsp_organization_name);
	FREE_BUF(vsp_hostname);
	FREE_BUF(vsp_nena_id);
	FREE_BUF(vsp_contact);
	FREE_BUF(vsp_cert_uri);

	return xml;
error:
	return NULL;
}
