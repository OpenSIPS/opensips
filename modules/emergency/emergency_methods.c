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
#include <curl/curl.h>
#include "emergency_methods.h"

#define TABLE_ROUTING_VERSION   1
#define TABLE_REPORT_VERSION   1

/*
 * Module initialization and cleanup
 */
static int mod_init(void);
static int child_init(int);
static void mod_destroy(void);

struct dlg_binds dlgb;
struct tm_binds eme_tm;
struct rr_binds rr_api;

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
    cmds, /* Exported functions */
    NULL,      /* Exported async functions */
    params, /* Exported parameters */
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

    // checks for mandatory fields
    if (source_hostname == NULL || source_contact == NULL) {
        LM_ERR("source_hostname and source_contact are mandatory \n");
        mandatory_parm = 1;
    }
    LM_DBG("TEST flag_empresa_terceira <> 0 %d\n", flag_empresa_terceira);
    if (flag_empresa_terceira != 0 &&
            (vsp_hostname == NULL || vsp_nena_id == NULL)) {
        LM_ERR("vsp_hostname and vsp_nena_id are mandatory when flag_empresa_terceira <> 0 %d\n", flag_empresa_terceira);
        mandatory_parm = 1;
    }

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

    db_esrn_esgwri = shm_malloc(sizeof (struct esrn_routing *));
    if (!db_esrn_esgwri) {
        LM_ERR("no more memory");
        return -1;
    }
    *db_esrn_esgwri = NULL;

    if (register_timer("emer_rout_table", routing_timer, 0,
          timer_interval, 0) < 0) {
        LM_ERR("failed to register timer \n");
        return -1;
    }

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

    LM_INFO("EMERGENCY Module initialized!\n");
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
        LM_INFO(" --- TREAT BYE  -----  \n \n");  

        resp = bye(msg,dir);
        LM_INFO(" ---TREATMENT DIALOG BYE:%d", resp);        
        //return resp;
    }else{
        if (dir == 1){
            LM_INFO(" --- TREAT DOWNSTREAM  -----  \n \n"); 
            resp = routing_ack(msg);
            LM_INFO(" ---TREATMENT DIALOG ACK:%d", resp);
            //return resp;
        }
    }

}


void reply_in_redirect( struct cell* t, int type, struct tmcb_params *params){   

    char *contact_esgwri = NULL;
    char *contact_lro = NULL;
    struct sip_msg *reply = params->rpl;
    struct sip_msg *msg_retran = params->req;
    char* callidHeader;


    if (extract_contact_hdrs(reply, &contact_esgwri, &contact_lro) == -1){
        return;
    }

    if (get_callid_header(msg_retran, &callidHeader) == -1){;
        pkg_free(contact_esgwri);
        pkg_free(contact_lro); 
        return;
    }

    call_cell = shm_malloc(sizeof (ESCT));
    if (call_cell == NULL) {
        LM_ERR("--------------------------------------------------no more shm memory\n");       
        return;
    }

    int len_callid = strlen(callidHeader);
    call_cell->callid = shm_malloc(sizeof (char)* len_callid + 1);
    if (call_cell->callid == NULL) {
        LM_ERR("--------------------------------------------------no more shm memory\n");        
        return;
    }
    memcpy(call_cell->callid, callidHeader, len_callid);
    call_cell->callid[len_callid] = 0;

    call_cell->esqk = empty;
    call_cell->lro = empty;
    call_cell->ert_srid = empty;
    call_cell->esgwri = empty;    
    call_cell->result = empty;
    call_cell->datetimestamp = empty;     
    call_cell->ert_npa = 0;
    call_cell->ert_resn = 0;

    call_cell_vpc = shm_malloc(sizeof (NENA));
    if (call_cell_vpc == NULL) {
        LM_ERR("--------------------------------------------------no more shm memory\n");
        return;
    }
    call_cell->vpc = call_cell_vpc;
    call_cell->vpc->organizationname = empty;
    call_cell->vpc->hostname = empty;

    if (contact_lro){
        if(get_lro_in_contact(contact_lro, call_cell) == -1){
            return;
        }
    }

    if (contact_esgwri){
        if(get_esqk_in_contact(contact_esgwri, call_cell) == -1){
            return;
        }

        if (get_esgwri_ert_in_contact(contact_esgwri, call_cell) == -1){
            return;            
        }
    }
    insert_call_cell_in_list(call_cell);
    return;    
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
    struct node* current;
    NODE *previous = NULL;
    NODE *free_cell;

    current = *calls_eme;
    while (current) {

        current->esct->timeout --;
        NODE* next = current->next;
        LM_INFO("TIMEOUT:%d\n", current->esct->timeout);
        if (current->esct->timeout <= 0 ){
            LM_INFO("time fires\n");              
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


            if ((proxy_hole == 0) || (proxy_hole == 2)){
                //sends ESCT only if VPC provided key ESQK
                if (strlen(free_cell->esct->esqk) > 0){
                    LM_INFO(" --- SEND ESQK=%s \n \n",free_cell->esct->esqk);

                    //send esctRequest to the VPC
                    if(free_cell->esct->datetimestamp){
                        shm_free (free_cell->esct->datetimestamp);
                        LM_DBG(" --- FREE_CELL->TIME");                                
                    }
                    time(&rawtime);
                    timeinfo = localtime(&rawtime);
                    strftime(formated_time, 80, "%Y-%m-%dT%H:%M:%S%Z", timeinfo);
                    free_cell->esct->datetimestamp = formated_time;

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
                        if(esct_callid)
                            pkg_free(esct_callid);
                    }
                    pkg_free(response);
                    pkg_free(xml);
                }
            }

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

    if (get_db_routing(table_name, ref_lock ) != 1)
        LM_ERR("ERROR IN GET ROUTING OF DB \n");

    libera_esqk();

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
    if (mandatory_parm)
        return -1; 

     // the emergency call treatment start with INVITE    
    if (memcmp(msg->first_line.u.request.method.s,"INVITE", msg->first_line.u.request.method.len) == 0) {
        
        if (is_emergency_call(msg)) {
            LM_INFO(" --- IT IS AN EMERGECY -----  \n \n"); 
            // It is, forward the INVITE            
            if(send_request_vpc(msg) == 1){

                //if(proxy_hole == 0){

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
                //}
                //return 1;
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

    char* callidHeader;
    int resp = 1;
    ESCT* info_call;
    char* new_to;
    char* cbn_aux;
    str cbn;

    LM_DBG(" --- FAILURE  treatment \n \n");

    // comando failure so sera tratado pelo opensips com o paler de Call Proxy no cenario I
    if (proxy_hole == 1) {
        LM_DBG(" ---Hole: proxy routing \n");
        return - 1;
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

    if (proxy_hole == 3) {
        if (strstr(info_call->disposition, "processes") != NULL) {

            LM_INFO(" ---Hole: proxy routing \n");
            cbn_aux = pkg_malloc(sizeof (char)* MAX_URI_SIZE);
            if (cbn_aux == NULL) {
                LM_ERR("no more pkg memory\n");
                return -1 ;
            }
            memset(cbn_aux, 0, MAX_URI_SIZE);
            found_CBN(msg, &cbn_aux);  
            cbn.s = cbn_aux;
            cbn.len = strlen(cbn.s);
            LM_INFO(" --- FOUND CBN%.*s \n \n", cbn.len, cbn.s); 

            if(strlen(info_call->esgwri) > 1){
                LM_INFO ("CONTEUDO FAILURE REPLY ESGWRI II %s \n",info_call->esgwri);
                if(new_uri_proxy(msg, info_call->esgwri) == -1){              
                    LM_ERR(" ---ERRO EM NEW_URI_PROXY");
                    return -1;
                }

            }else{
                if ((strlen(info_call->ert_srid) > 1)&&(info_call->ert_resn != 0)&&(info_call->ert_npa != 0)){
                    LM_INFO ("CONTEUDO FAILURE REPLY SRID %s \n",info_call->ert_srid);
                    LM_INFO ("CONTEUDO FAILURE REPLY RESN %d \n",info_call->ert_resn);
                    LM_INFO ("CONTEUDO FAILURE REPLY NPA %d \n",info_call->ert_npa); 
                    if(routing_by_ert( msg, info_call) == -1){
                        return -1;
                    }

                }else{
                    contingency(msg, info_call);
                    return 1;
                }
            }

            if(add_headers(info_call->esqk, msg, cbn)==-1){
                return -1;
            }
            info_call->disposition = "esgwri";
            info_call->timeout = ACK_TIME;

            //if(eme_tm.t_relay(msg,0,0,0,0,0,0))
                      // LM_ERR(" ---ERRO EM NEW_URI_PROXY"); 

            //LM_INFO(" ---Hole: proxy routing \n");
            return 1;
        }
    }  

    LM_INFO("treat lro \n");
    // verfifica se o parametro contingency_hostname foi definido no script, caso contrario failure não sera tratado
    if ( contingency_hostname == NULL) {
        LM_ERR("contingency_hostname not defined\n");
        return -1;
    }

    // verifica se a chamada tratada teve o numero de contingencia lro fornecido pelo VPC
    // caso não tenha, não trata failure
    if (info_call->lro == NULL) {
        LM_ERR(" ---treat FAILURE not found lro");
        goto error;
    }

    //verify if there was an attempt to forward the INVITE to the contingency number
    if (strstr(info_call->disposition, "lro") == NULL) {

        LM_DBG("EH LRO -- LRO = %s  HOST = %s ", info_call->lro, contingency_hostname);
        int tamanho_new_to = strlen(info_call->lro) + strlen(contingency_hostname) + 17;
        new_to = shm_malloc(sizeof (char)* tamanho_new_to);
        sprintf(new_to, "sip:%s@%s;user=phone", info_call->lro, contingency_hostname);

        LM_DBG(" ---NEW DESTIN =%s", new_to);
        if(new_uri_proxy(msg, new_to) == -1){
            LM_ERR(" ---ERRO EM NEW_URI_PROXY");
            goto error;
        }  

        if(info_call->esgwri && strlen(info_call->esgwri)>0)
            shm_free(info_call->esgwri);

        info_call->esgwri = new_to;
        info_call->disposition = "lro";
        info_call->esgw = "";
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
*  - verify if the field uri has a urn standard for emergency call defined by RFC 5031
*  - if it does not, then verify if se user field is one of the emengency_code in the database
*    - if it is a code, the module checks if the host is from the opensips 
        or if there is a field Geolocation_routing = 'yes"
*/
int is_emergency_call(struct sip_msg *msg) {
    LM_DBG(" --- emergency_call \n \n");

    // verify if the field uri has a urn standard for emergency call
    if (strstr(msg->first_line.u.request.uri.s, "urn:service:sos") != NULL) {
        LM_DBG(" --- IT IS EMERGENCY  -----  \n \n");
        return 1;
    } else {
        // don't have URN standard for emergency call, verify USER field in RURI bind with some code in emergency_code
        LM_DBG(" --- verifying code \n \n");
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
    int resp =1;
    char* lie;
    str cbn;
    char *cbn_aux;

    cbn_aux = pkg_malloc(sizeof (char)* MAX_URI_SIZE);
    if (cbn_aux == NULL) {
        LM_ERR("no more pkg memory\n");
        return -1;
    }
    memset(cbn_aux, 0, MAX_URI_SIZE);

    found_CBN(msg, &cbn_aux);  
    cbn.s = cbn_aux;
    cbn.len = strlen(cbn.s);
    LM_INFO(" --- FOUND CBN%.*s \n \n", cbn.len, cbn.s);

    if (proxy_hole == 1) {
        LM_DBG(" ---Hole: proxy routing \n");
        if (add_hdr_PAI(msg, cbn) == -1) {
            LM_ERR("FAILURE IN ADD PAI");
        }
        if (proxy_request(msg,call_server_hostname) == -1) {
            LM_ERR("ERROR IN ROUTING EMERGENCY REQUEST");
            return -1;
        }
        return 1;
    }

    if (proxy_hole == 3) {        
        // Call Server SCENARIO III      
        LM_INFO(" ---Hole: proxy redirect \n");
        //if (add_hdr_PAI(msg) == -1) {
            //LM_ERR("FAILURE IN ADD PAI");
        //}
        if (proxy_request(msg,call_server_hostname) == -1) {
            LM_ERR("ERROR IN ROUTING EMERGENCY REQUEST");
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
    if ( get_callid_header(msg, &callidHeader) == -1){
        LM_ERR("Failed to get callid header\n");
        return -1;     
    }
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
    xml = formatted_xml(lie, callidHeader, cbn.s);

    //  HTTP POST to VPC
    resp = post(url_vpc, xml, &response);
    pkg_free(xml);
    if (resp == -1) {
        LM_ERR(" --- PROBLEM IN POST \n \n");
        goto error;
    }

    
    parsed = parse_xml(response);
    if (parsed != NULL) {
        if(create_call_cell(parsed, msg, callidHeader, cbn) == -1){
            pkg_free(response);
            goto error;
        }       
        //free_parsed(parsed);
    } else {
        LM_ERR("PARSER ERROR\n");
        goto error;
    }


    LM_INFO("END EMERGENCY");
    pkg_free(response);
    
    if(callidHeader)
        pkg_free(callidHeader);
    
     if(lie)
        pkg_free(lie); 

    free_parsed(parsed);          
       
    return 1;
    
error : 
    if(callidHeader)
        pkg_free(callidHeader);

    if(lie)
        pkg_free(lie);   
        
    free_parsed(parsed);
    return -1;            
}


int create_call_cell(PARSED *parsed,struct sip_msg* msg, char* callidHeader, str cbn) {

    LM_DBG(" ---PARSED ");
    if ((parsed->callid == NULL || parsed->result == NULL || parsed->vpc->nenaid == NULL || parsed->vpc->contact == NULL)) {
        LM_ERR("MANDATORY FIELDS ARE BLANK \n");
        return -1;
    } else {
        // verifica se o callid enviado ao VPC é o mesmo retornado em esrResponse
        if (strcmp(parsed->callid, callidHeader) != 0) {
            LM_ERR("CALLID DIFFER %s ## %s \n", parsed->callid, callidHeader);
            return -1;
        }

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
        if(treat_parse_esrResponse(msg, call_cell , call_cell_source , call_cell_vpc , parsed, proxy_hole) == -1){
            return -1;
        }
        
        if (treat_routing(msg, call_cell, cbn) == -1){
            return -1;
        }
        return 1;
    }
}


/* treats the esrResponse from VPC
*   - verify if the message has mandatory fields:
*       - callid
*       - result
*       - nenaid
*       - contact
*   - checks the result field to verify if the msg from VPC was seuccessfull
*   - checks the esgwri code or the data from the emergency area (selectiveRoutingID, routingESN, npa) to translate to esgwri
*   - includes the data ersResponse to a node of the list calls_eme
*/
int treat_routing(struct sip_msg* msg, struct esct *call_cell, str cbn) {
    static str msg300={"Multiple Choices",sizeof("Multiple Choices")-1};

    // transforma result em inteiro para ficar mais facil sua analise separando-o em faixas
    int result = atoi(call_cell->result);
    int faixa = faixa_result(result);
    LM_INFO(" --- faixa %d", faixa);
    
    if (faixa == 1) {
        // result NOK sem envio de numero de contigencia
        LM_ERR("RESULT INVALIDO -- SAINDO DO EMERGENCY %d \n", result);
        goto error;
    }
 
    if (proxy_hole == 0){  

        if (faixa == 2) {
            // result NOK mas o VPC mandou o numero de contingencia para escoar a chamada
            LM_ERR("RESULT INVALIDO --CONTINGENCY \n");  

            contingency(msg, call_cell);

            call_cell->ert_npa = 0;
            call_cell->ert_resn = 0;
            call_cell->ert_srid = "";

            pkg_free(cbn.s);
            return 1;
        }       

        // result OK
        call_cell->disposition = "esgwri";
        call_cell->timeout = ACK_TIME;

        if (call_cell->esgwri != NULL && strlen(call_cell->esgwri) > 0) {
            // VPC enviou o campo esgwri para encaminhar o INVITE
            if (call_cell->esqk == NULL){
                LM_ERR(" ---Result 200 but without esqk \n");
                goto error;                    
            }
            LM_INFO(" ---CALL CELL -----------------------------------------------------ENTROU N IF ESQWRI = %s", call_cell->esgwri);
            
            if(new_uri_proxy(msg,call_cell->esgwri) == -1){
                LM_ERR(" ---ERRO EM NEW_URI_PROXY");
                goto error;
            }      

        } else {
            LM_INFO("ert_srid %s \n", call_cell->ert_srid);
            LM_INFO("ert_resn %d \n", call_cell->ert_resn); 
                   
            if ((call_cell->ert_srid != NULL) && (call_cell->ert_resn != 0) && (call_cell->ert_npa != 0)) {              
                if (call_cell->esqk == NULL){
                    LM_ERR(" ---Result 200 but without esqk \n");
                    goto error;                    
                } 
                if(routing_by_ert( msg, call_cell) == -1){
                    goto error;
                }
            }else{
                // VPC não enviou nenhum dado para fazer o encaminhamento           
                LM_ERR(" ---Result 200 but without ert or esgwri \n");
                goto error;              
            }
        }

        if(add_headers(call_cell->esqk, msg, cbn)==-1){
            return -1;
        }

    }else{
        if (proxy_hole == 2){
            LM_INFO(" ---TRATA REDIRECT\n \n");   
            if(add_hdr_rpl(call_cell, msg)==-1){
                return -1;
            }
            if(!eme_tm.t_reply(msg,300,&msg300)){
                LM_DBG("t_reply (100)\n");
                return -1;                
            } 
            call_cell->disposition = "redirect";
            call_cell->timeout = BYE_TIME; 
            pkg_free(cbn.s); 


        }else{
            LM_ERR("proxy_hole invalid\n");
            goto error;
        }        
    }  
    return 1;

error:
    pkg_free(cbn.s);
    return -1;
}


/*
* this function is responsible for getting the forwarding data to the INVITE from the structure given by the VPC
* Stores :
*       - selectiveRoutingID
*       - routingESN
*       - npa
*   - retreives the esgwri based on the data
*   - forward the invite
*/
int routing_by_ert( struct sip_msg *msg, ESCT *call_cell) {
    char *esgwri_db; 

    if (emergency_routing(call_cell->ert_srid, call_cell->ert_resn, call_cell->ert_npa, &esgwri_db, ref_lock) != -1) {

        int esgwri_db_len = strlen(esgwri_db);

        LM_INFO("DB_ESGWRI %s \n", esgwri_db);               
        call_cell->esgwri = shm_malloc(sizeof (char)* esgwri_db_len + 1);
        if (call_cell->esgwri == NULL) {
            LM_ERR("--------------------------------------------------no more shm memory\n");
            return -1;
        }

        strcpy(call_cell->esgwri, esgwri_db);
        call_cell->esgwri[esgwri_db_len] = 0;

        if(new_uri_proxy(msg, esgwri_db) == -1){
            if (esgwri_db)
                pkg_free(esgwri_db);               
            LM_ERR(" ---ERROR IN NEW_URI_PROXY");
            return -1;
        }
        
        pkg_free(esgwri_db);

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
    
    char *new_to;
    char *lro;
    
    //Treat LRO 
    //checks if the LRO field was forwarded by VPC, otherwise the called will have NOK treatment
    lro = call_cell-> lro;
    if (lro == NULL) {
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

    new_to = pkg_malloc(sizeof (char)* tamanho_new_to);
    sprintf(new_to, "sip:%s@%s;user=phone", lro, contingency_hostname);
    
    call_cell->esgwri = shm_malloc(sizeof (char)* tamanho_new_to + 1);
    if (call_cell->esgwri == NULL) {
        LM_ERR("--------------------------------------------------no more shm memory\n");
        return -1;
    }
    strcpy(call_cell->esgwri, new_to);
    call_cell->esgwri[tamanho_new_to] = 0;

    if(new_uri_proxy(msg, new_to) == -1){
        LM_ERR(" ---ERRO EM NEW_URI_PROXY");
        return -1;
    }
    
    pkg_free(new_to); 
 
    call_cell->disposition = "lro";
    call_cell->esgw = "";
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
    int resp = 1;
    ESCT* info_call;

    LM_DBG(" --- START TREATMENT ACK \n \n");
    if (proxy_hole == 1) {
        // Call Server scenario II        
        if (proxy_request(msg,call_server_hostname) == -1) {
            LM_DBG("ERROR IN ROUTING EMERGENCY REQUEST \n");
            resp = -1;
            goto end;
        }
        return -1;
    }

    if (proxy_hole == 2) {
        // Redirect Proxy scenario III 
        LM_DBG(" ---Hole: proxy redirect \n");
        return -1;
    }

    if (get_callid_header(msg, &callidHeader) == -1)
        return -1;

    LM_DBG(" ---TREATMENT ACK  callid=%s \n", callidHeader);   
    info_call = find_esct(callidHeader);
    if (info_call == NULL) {
        LM_DBG(" ---TREATMENT ACK - NOT FIND CALLID \n");
        resp = -1;
        goto end;
    }

    if (strlen(info_call->esgwri) > 0) {
        LM_DBG(" ---Routing ACK %s \n\n", info_call->esgwri);       
        if(new_uri_proxy(msg, info_call->esgwri) == -1){
            LM_ERR(" ---ERROR IN NEW_URI_PROXY");
            resp = -1;
            goto end;
        }
    }

    info_call->timeout = BYE_TIME;
    resp = 1;

end : 
        if(callidHeader)
            pkg_free(callidHeader);
        return resp;
}


/* Search the cell with callid key in list linked calls_eme, 
*  if found returns the pointer of this cell
*/
ESCT* find_esct(char* callId) {
    LM_DBG(" --- find_esct para calid  = %s ", callId);

    struct node* list_eme = *calls_eme;

    NODE* current = list_eme;
    while (current) {
        LM_INFO(" --- CALL_LIST callId  = %s \n", current->esct->callid);
        if (same_callid(current->esct->callid, callId) == 0) {
            LM_INFO(" --- FOUND ESCT with callId key = %s ", callId);
            ESCT* esct = current->esct;
            return esct;
        }
        current = current->next;
    }
    LM_INFO("Did not find\n");
    return NULL;
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
    struct tm * timeinfo;
    char formated_time[80];
    NODE* info_call;
    char* xml;

    LM_DBG(" --- BYE \n \n");

    if (proxy_hole == 1) {
       // Call Server scenario II 
       LM_DBG(" ---Hole: proxy routing \n");
        if (proxy_request(msg,call_server_hostname) == -1) {
            LM_ERR("ERROR IN ROUTING EMERGENCY REQUEST");
            return -1;
        }
        return 1;
    }

    if (proxy_hole == 2) {
        // Redirect Proxy scenario III 
        LM_DBG(" ---Hole: proxy redirect \n");
        return -1;
    }

/*
    if (proxy_hole == 3) {
        // Redirect proxy scenario III
        // NOT YET IMPLEMENTED    
        LM_DBG(" ---Hole: proxy redirect \n");
        return -1;
    }
*/

    if (get_callid_header(msg, &callidHeader) == -1)
        return -1;

    LM_INFO(" --- BYE  callid=%s \n", callidHeader);
    info_call = find_and_delete_esct(callidHeader);
    if (info_call->esct == NULL) {
        LM_ERR(" --- BYE DID NOT FIND CALLID \n");
        resp = -1;
        goto end;
    }

    if (dir == 1) {
        if (strlen(info_call->esct->esgwri) > 0) {
            LM_DBG(" ---Routing BYE %s \n\n", info_call->esct->esgwri);       
            if(new_uri_proxy(msg, info_call->esct->esgwri) == -1){
                LM_ERR(" ---ERROR IN NEW_URI_PROXY");
                free_call_cell(info_call);
                resp = -1;
                goto end;
            }
        }
    }


    // sends ESCT only if VPC provided key ESQK
    if (proxy_hole == 0) {
        if (strlen(info_call->esct->esqk) > 0){

            LM_INFO(" --- SEND ESQK =%s\n \n",info_call->esct->esqk);

            if(info_call->esct->datetimestamp){
                shm_free (info_call->esct->datetimestamp);
                LM_DBG(" ---  FREE INFO_CALL->TIME");                                
            }
            time(&rawtime);
            timeinfo = localtime(&rawtime);
            strftime(formated_time, 80, "%Y-%m-%dT%H:%M:%S%Z", timeinfo);        
            info_call->esct->datetimestamp = formated_time;

            xml = buildXmlFromModel(info_call->esct);    
            LM_INFO(" --- TREAT BYE - XML ESCT %s \n \n", xml);

            // sends HTTP POST esctRequest to VPC
            resp = post(url_vpc, xml, &response);
            if (resp == -1) {
                LM_ERR(" --- PROBLEM IN POST DO BYE\n \n");
                free_call_cell(info_call);            
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

    free_call_cell(info_call);
    resp = 1;

end : 
    if(callidHeader)
        pkg_free(callidHeader);
    return resp;
}

/* search and delete call cell with callid key
*   - search cell with callid in list linked calls_eme
*   - if found returns the pointer of this cell and free cell 
*   - report call datas in emergency_report table


*/
NODE* find_and_delete_esct(char* callId) {
    struct node* list_eme = *calls_eme;
    NODE *current = list_eme;
    NODE *previous = NULL;
      
    while (current) {       
        if (same_callid(current->esct->callid, callId) == 0) {            
            NODE* node = current;
            NODE* next = current->next;           
            if (collect_data(current, db_url, table_report) == 1) {
                LM_DBG("****** REPORT OK\n");
            } else {
                LM_DBG("****** REPORT NOK\n");
            }                      
            if (previous == NULL){
                if (next == NULL){;        
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
    
    printf("Not found\n");
    return NULL;
}


/*
 * Aux functions
 */

int same_callid(char* callIdEsct, char* callId) {
    if (callIdEsct == NULL || callId == NULL) {
        return 0;
    } else {
        LM_DBG(" --- Comparing callId  = %s com %s", callId, callIdEsct);
        return strcmp(callIdEsct, callId);
    }
}


/* fill with blanck spaces
*/
int fill_blank_space(void) {
    int resp = 1;
    resp = fill_parm_with_BS(&vpc_organization_name);
    resp = fill_parm_with_BS(&vpc_hostname);
    resp = fill_parm_with_BS(&vpc_nena_id);
    resp = fill_parm_with_BS(&vpc_contact);
    resp = fill_parm_with_BS(&vpc_cert_uri);
    resp = fill_parm_with_BS(&source_organization_name);
    resp = fill_parm_with_BS(&source_nena_id);
    resp = fill_parm_with_BS(&source_cert_uri);
    resp = fill_parm_with_BS(&vsp_organization_name);
    if (flag_empresa_terceira == 0) {
        resp = fill_parm_with_BS(&vsp_hostname);
        resp = fill_parm_with_BS(&vsp_nena_id);
    }
    resp = fill_parm_with_BS(&vsp_contact);
    resp = fill_parm_with_BS(&vsp_cert_uri);
    return resp;
}


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
    LM_DBG(" --- emergency_call TRADUCAO %.*s \n \n", msg->parsed_uri.host.len, msg->parsed_uri.host.s);
    ret = check_self(&msg->parsed_uri.host, 0, 0);
    LM_DBG(" --- emergency_call retorno  check_self_op %d \n \n", ret);
    return ret;
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

/* format the xml to send POST -> esrRequest
*/
char* formatted_xml(char* lie, char* callidHeader, char* cbn) {
    char* xml;
    char formated_time[80];
    time_t rawtime;
    struct tm * timeinfo;

    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(formated_time, 80, "%Y-%m-%dT%H:%M:%S%Z", timeinfo);
    LM_DBG(" --- INIT  send_request_vpc\n \n");

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
