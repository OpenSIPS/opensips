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
 *  2015-06-08 change from list to hash (Villaron/Tesini)
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include "notifier_emergency.h"


/* get data from Subscriber and save in list link with notify information:
    . dialog id of emergency call
    . dialog id of subscribe
    . local uri
    . remote uri
    . contact
    . expires
    . time to expire subscriber
    - status
    . cell next
    . cell previus
*/
struct sm_subscriber* build_notify_cell(struct sip_msg *msg, int expires){

    char *subs_callid, *subs_fromtag;
    str callid_event;
    str fromtag_event;
    str callid;
    struct to_body *pto= NULL, *pfrom = NULL;
    int size_notify_cell;
    int vsp_addr_len;
    char *vsp_addr = "@vsp.com";
    int vsp_port = 5060;
    int size_vsp_port = 4;
    char* str_vsp_port;
    struct sm_subscriber *notify_cell = NULL;
    time_t rawtime;
    int time_now;
    char *p;
    unsigned int hash_code;

    // get data from SUBSCRIBE request
    // get callid from Subscribe
    if( msg->callid==NULL || msg->callid->body.s==NULL){
        LM_ERR("subscribe without callid header\n");
        return NULL;
    }
    callid = msg->callid->body;
    LM_DBG("CALLID: %.*s \n ", callid.len, callid.s );

    //get From header from Subscribe
    if (msg->from->parsed == NULL){
        if ( parse_from_header( msg )<0 ){
            LM_ERR("subscribe without From header\n");
            return NULL;
        }
    }
    pfrom = get_from(msg);
    LM_DBG("PFROM: %.*s \n ", pfrom->uri.len, pfrom->uri.s );
    LM_DBG("PFROM_TAG: %.*s \n ", pfrom->tag_value.len, pfrom->tag_value.s );
    if( pfrom->tag_value.s ==NULL || pfrom->tag_value.len == 0){
        LM_ERR("subscribe without from_tag value \n");
        return NULL;
    }
    if( msg->to==NULL || msg->to->body.s==NULL){
        LM_ERR("error in parse TO header\n");
        return NULL;
    }

    // get To header from Subscribe
    pto = get_to(msg);
    if (pto == NULL || pto->error != PARSE_OK) {
        LM_ERR("failed to parse TO header\n");
        return NULL;
    }
    if( pto->tag_value.s ==NULL || pto->tag_value.len == 0){
        LM_ERR("subscribe without to_tag value \n");
        //return 0;
    }
    LM_DBG("PTO: %.*s \n ", pto->uri.len, pto->uri.s );
    LM_DBG("PTO_TAG: %.*s \n ", pto->tag_value.len, pto->tag_value.s );


    /* get in event header: callid and from_tag */
    if(get_event_header(msg, &subs_callid, &subs_fromtag) == 1){
        LM_DBG("SUBS_CALLID: %s\n ", subs_callid);
        LM_DBG("SUBS_FROMTAG: %s\n ", subs_fromtag);
    };
    callid_event.s = subs_callid;
    callid_event.len = strlen(subs_callid);
    fromtag_event.s = subs_fromtag;
    fromtag_event.len = strlen(subs_fromtag);

    time(&rawtime);
    time_now = (int)rawtime;
    LM_DBG("TIME : %d \n", (int)rawtime );

    // get source ip address that send INVITE
    vsp_addr = ip_addr2a(&msg->rcv.src_ip);
    vsp_addr_len = strlen(vsp_addr);
    vsp_port = msg->rcv.src_port;
    str_vsp_port= int2str(vsp_port, &size_vsp_port);
    LM_DBG("SRC_PORT : %s \n", str_vsp_port);

    /* build notifier cell */
    size_notify_cell = sizeof(struct sm_subscriber) + (2 * sizeof(struct dialog_id))
                    + callid.len + pfrom->tag_value.len + pto->tag_value.len + pfrom->uri.len + pto->uri.len
                    + callid_event.len +  fromtag_event.len + vsp_addr_len + size_vsp_port + 11  ;
    notify_cell = shm_malloc(size_notify_cell + 1);
    if (!notify_cell) {
        LM_ERR("no more shm\n");
        return NULL;
    }

    memset(notify_cell, 0, size_notify_cell + 1);
    notify_cell->expires = expires;
    LM_DBG("EXPIRES: %d \n ", notify_cell->expires );
    notify_cell->timeout =  TIMER_N + time_now;
    LM_DBG("SUBS_TIMEOUT: %d \n ", notify_cell->timeout );
    notify_cell->version =  0;
    LM_DBG("SUBS_VERSION: %d \n ", notify_cell->version );

    notify_cell->dlg_id = (struct dialog_id*)(notify_cell + 1);

    notify_cell->dlg_id->callid.len = callid.len;
    notify_cell->dlg_id->callid.s = (char *) (notify_cell->dlg_id + 1);
    memcpy(notify_cell->dlg_id->callid.s, callid.s, callid.len);
    LM_DBG("SUBS_CALLID: %.*s \n ", notify_cell->dlg_id->callid.len, notify_cell->dlg_id->callid.s );

    notify_cell->dlg_id->rem_tag.len = pfrom->tag_value.len;
    notify_cell->dlg_id->rem_tag.s = (char *) (notify_cell->dlg_id + 1) + callid.len;
    memcpy(notify_cell->dlg_id->rem_tag.s, pfrom->tag_value.s, pfrom->tag_value.len);
    LM_DBG("SUBS_FROM_TAG: %.*s \n ", notify_cell->dlg_id->rem_tag.len, notify_cell->dlg_id->rem_tag.s );

    p = (char *)(notify_cell->dlg_id + 1) + callid.len + pfrom->tag_value.len;
    notify_cell->call_dlg_id = (struct dialog_id*)p;

    notify_cell->call_dlg_id->callid.len= callid_event.len;
    notify_cell->call_dlg_id->callid.s = (char *) (notify_cell->call_dlg_id + 1);
    memcpy(notify_cell->call_dlg_id->callid.s, callid_event.s, callid_event.len);
    LM_DBG("SUBS_CALLID_event: %.*s \n ", notify_cell->call_dlg_id->callid.len, notify_cell->call_dlg_id->callid.s );

    notify_cell->call_dlg_id->rem_tag.len= fromtag_event.len;
    notify_cell->call_dlg_id->rem_tag.s = (char *) (notify_cell->call_dlg_id + 1) + callid_event.len;
    memcpy(notify_cell->call_dlg_id->rem_tag.s, fromtag_event.s, fromtag_event.len);
    LM_DBG("SUBS_FROMTAG_event: %.*s \n ", notify_cell->call_dlg_id->rem_tag.len, notify_cell->call_dlg_id->rem_tag.s );

    notify_cell->loc_uri.len = pto->uri.len;
    notify_cell->loc_uri.s = (char *) (notify_cell->call_dlg_id + 1) + callid_event.len + fromtag_event.len;
    memcpy(notify_cell->loc_uri.s,pto->uri.s,pto->uri.len);
    LM_DBG("SUBS_LOC_URI: %.*s \n ", notify_cell->loc_uri.len, notify_cell->loc_uri.s );

    notify_cell->rem_uri.len= pfrom->uri.len;
    notify_cell->rem_uri.s = (char *) (notify_cell->call_dlg_id + 1) + callid_event.len + fromtag_event.len + pto->uri.len;
    memcpy(notify_cell->rem_uri.s, pfrom->uri.s, pfrom->uri.len);
    LM_DBG("SUBS_REM_URI: %.*s \n ", notify_cell->rem_uri.len, notify_cell->rem_uri.s );

    notify_cell->contact.len = vsp_addr_len + size_vsp_port +11;
    notify_cell->contact.s = (char *) (notify_cell->call_dlg_id + 1) +  pfrom->uri.len + pto->uri.len + callid_event.len + fromtag_event.len;

    memcpy(notify_cell->contact.s, "sip:teste@", 10);
    memcpy(notify_cell->contact.s + 10, vsp_addr, vsp_addr_len);
    memcpy(notify_cell->contact.s + 10 + vsp_addr_len, ":", 1);
    memcpy(notify_cell->contact.s + 11 + vsp_addr_len, str_vsp_port, size_vsp_port);
    LM_DBG("SUBS_CONTACT: %.*s \n ", notify_cell->contact.len, notify_cell->contact.s );

    notify_cell->dlg_id->status =  RESP_WAIT;

    hash_code= core_hash(&callid_event, 0, subst_size);
    LM_DBG("********************************************HASH_CODE%d\n", hash_code);
    LM_DBG("********************************************CALLID_STR%.*s\n", callid_event.len, callid_event.s);

    if(insert_shtable(subs_htable, hash_code, notify_cell)< 0){
        LM_ERR("inserting new record in subs_htable\n");
    }

    return notify_cell;

}

/* Treat Notify to Subscriber Dialog in scenario III*/
int treat_subscribe(struct sip_msg *msg) {

    int resp = 1;
    struct cell *t;
    static str msg200={"OK Subscribe",sizeof("OK Subscribe")-1};
    static str msg423={"Interval Too Brief",sizeof("Interval Too Brief")-1};
    static str msg481={"Subscription does not exist",sizeof("Subscription does not exist")-1};
    static str msg489={"Bad Event",sizeof("Bad Event")-1};
    struct sm_subscriber *notify_cell = NULL;
    char  *subs_expires;
    int expires= 0;
    char *subs_callid, *subs_fromtag;
    str callid_event;

    if(!check_event_header(msg)){
        LM_ERR("event header type not allow\n");
        if(!eme_tm.t_reply(msg,489,&msg489)){
            LM_ERR("t_reply (489)\n");
        }
        return 0;
    }

    /* get expires field */
    if(!get_expires_header(msg, &subs_expires)){
        LM_ERR("body's expires header not found\n");
        expires =  TIME_DEFAULT_SUBS;
    }else{
        LM_DBG("SUBS_EXPIRES: %s\n ", subs_expires);
        // if expires body isn't a numerical string, then expires value is zero
        expires = atoi(subs_expires);
        if ((expires != 0) & (expires < TIMER_MIN_SUBS)){
            /* Reply NOK to Notify*/
            if(!eme_tm.t_reply(msg,423,&msg423)){
                LM_DBG("t_reply (423)\n");
            }
            resp = 0;
            goto end;
        }
    }

    if(get_event_header(msg, &subs_callid, &subs_fromtag) == 1){
        callid_event.s = subs_callid;
        callid_event.len = strlen(subs_callid);
    }else{
        LM_ERR("**** error in Evenrt Header od Subscriber");
        return 0;
    }


    if (expires == 0){
        notify_cell = get_subs_cell(msg, callid_event);
        if (notify_cell == NULL){
            LM_ERR("**** notify cell not found");
            if(!eme_tm.t_reply(msg,481,&msg481)){
                LM_ERR("t_reply (481)\n");
            }
            return 0;
        }
        notify_cell->dlg_id->status =  TERMINATED;
        notify_cell->expires =  0;
    }else{
        notify_cell =  build_notify_cell(msg, expires);
        if (notify_cell == NULL){
            LM_ERR("**** error in build notify cell");
            return 0;
        }
    }


    /* Reply OK to Notify*/
    if(!eme_tm.t_reply(msg,200,&msg200)){
        LM_DBG("t_reply (200)\n");
        resp = 0;
        goto end;
    }

    if(notify_cell->dlg_id->status != TERMINATED){

        t = eme_tm.t_gett();

        LM_DBG(" --- TO TAG %.*s \n", t->uas.local_totag.len, t->uas.local_totag.s);

        notify_cell->dlg_id->local_tag.s = shm_malloc(t->uas.local_totag.len);
        if (!notify_cell->dlg_id->local_tag.s) {
            LM_ERR("no more shm\n");
            resp = 0;
            goto end;
        }

        notify_cell->dlg_id->local_tag.len = t->uas.local_totag.len;
        memcpy(notify_cell->dlg_id->local_tag.s, t->uas.local_totag.s, t->uas.local_totag.len);
        LM_DBG("SUBS_FROM_TAG: %.*s \n ", notify_cell->dlg_id->local_tag.len, notify_cell->dlg_id->local_tag.s );

    }

    if( !send_notifier_within(msg, notify_cell)){
        resp = 0;
        goto end;
    }

    resp = 1;
end:
    //shm_free(notify_cell);
    //pkg_free(subs_state);
    //pkg_free(subs_expires);
    return resp;
}



/* send notifier within of dialog, this notifier is a request that confirm subscribe */
int send_notifier_within(struct sip_msg* msg, struct sm_subscriber* notify){

    dlg_t* dialog =NULL;
    str met= {"NOTIFY", 6};
    int sending;
    struct sm_subscriber* params_cb;
    //char* event;

    str* pt_hdr= NULL;
    str* pt_body = NULL;

    dialog = build_dlg(notify);
    if(dialog== NULL){
            LM_DBG(" --- ERROR IN BUILD DIALOG \n");
            return -1;
    }
    LM_DBG(" --- FINAL \n");
    LM_DBG(" --- DIALOG CALLID%.*s \n", dialog->id.call_id.len, dialog->id.call_id.s);
    LM_DBG(" --- DIALOG REMTAG%.*s \n", dialog->id.rem_tag.len, dialog->id.rem_tag.s);
    LM_DBG(" --- DIALOG LOCTAG%.*s \n", dialog->id.loc_tag.len, dialog->id.loc_tag.s);
    LM_DBG(" --- DIALOG REMURI%.*s \n", dialog->rem_uri.len, dialog->rem_uri.s);
    LM_DBG(" --- DIALOG LOCURI%.*s \n", dialog->loc_uri.len, dialog->loc_uri.s);
    LM_DBG(" --- DIALOG CONTACT%.*s \n", dialog->rem_target.len, dialog->rem_target.s);

    params_cb = notify;

    pt_body = add_body_notifier(notify);

    pt_hdr = add_hdr_notifier(notify);

    sending= eme_tm.t_request_within
        (&met,
        pt_hdr,
        pt_body,
        dialog,
        notif_cback_func,
        (void*)params_cb,
        0
    );

    if(sending< 0)
        LM_ERR("while sending request with t_request_within\n");

    pkg_free(pt_hdr->s);
    pkg_free(pt_hdr);
    if(pt_body){
        pkg_free(pt_body->s);
        pkg_free(pt_body);
    }

    return 1;
}


void notif_cback_func(struct cell *t, int cb_type, struct tmcb_params *params){
    int code = params->code;
    struct sm_subscriber* params_notify = (struct sm_subscriber*)(*params->param);
    unsigned int hash_code;

    LM_DBG("TREAT NOTIFY REPLY \n");
    //LM_DBG("REPLY: %.*s \n ", reply->first_line.u.reply.version.len, reply->first_line.u.reply.version.s );
    LM_DBG("CODE: %d \n ", code);

    // verify if response is OK
    if (code < 300){
        // response OK(2XX)
        if (params_notify->expires > 0){
            LM_DBG("REPLY OK timeout %d \n", params_notify->timeout);
            LM_DBG("REPLY OK expires %d \n", params_notify->expires);
            time_t rawtime;

            time(&rawtime);
            int time_now = (int)rawtime;
            LM_DBG("TIME : %d \n", (int)rawtime );

            params_notify->timeout =  params_notify->expires + time_now;
            LM_DBG("TIMEOUT: %d \n ", params_notify->timeout);
            return;
        }
        if (params_notify->dlg_id->status == TERMINATED){

            hash_code= core_hash(&params_notify->call_dlg_id->callid, 0, subst_size);
            LM_DBG("********************************************HASH_CODE%d\n", hash_code);
            LM_DBG("********************************************CALLID_STR%.*s\n", params_notify->call_dlg_id->callid.len, params_notify->call_dlg_id->callid.s);

            shm_free(params_notify->dlg_id->local_tag.s);
            delete_shtable(subs_htable, hash_code, params_notify);

        }

    }else{
        // Response NOK
        LM_ERR("reply to NOTIFY NOK\n");
    }
    return;
}

/* build new headers(Event, Expires) to SUBSCRIBER request */
str* add_body_notifier(struct sm_subscriber* notifier){


    char *aux_body;
    //char* str_expires= NULL;
    char* call_status=NULL;
    int size_status = 0;
    int size_version = 1;
    int size_body;
    str* pt_body= NULL;
    char* version;

    if (notifier->dlg_id->status == TERMINATED ){
        LM_DBG("finesh notify\n");
        return NULL;
    }

    pt_body = (str*) pkg_malloc (sizeof (str));
    if (pt_body == NULL) {
        LM_ERR("--------------------------------------------------no more pkg memory\n");
        return NULL;
    }

    if (notifier->call_dlg_id->status == TERMINATED ){
        call_status = "terminated";
        size_status = 10;
        //version = "\"2\"";
    }else{
        call_status = "active";
        size_status = 6;
        //version = "\"0\"";
    }


    /* convert version in string*/
    version = int2str(notifier->version, &size_version);
    LM_DBG("VERSION -str : %s \n",version );
    if(version == NULL || size_version == 0){
        LM_ERR("while converting version int to str\n");
        return NULL;
    }
    notifier->version++;

    size_body = size_status + size_version + notifier->call_dlg_id->rem_tag.len + notifier->loc_uri.len + notifier->dlg_id->callid.len + notifier->call_dlg_id->callid.len + 197 + 11*CRLF_LEN;

    aux_body= pkg_malloc(sizeof(char)* size_body + 1);
    if(aux_body== NULL){
        LM_ERR("no more memory\n");
        return NULL;
    }
    memset(aux_body, 0, size_body+1);
    pt_body->s = aux_body;
    pt_body->len = size_body;

    memcpy(aux_body, "<?xml version=\"1.0\"?>", 21);
    aux_body+= 21;
    memcpy(aux_body, CRLF, CRLF_LEN);
    aux_body += CRLF_LEN;
    memcpy(aux_body, "<dialog-info xmlns=\"urn:ietf:params:xml:ns:dialog-info\"", 55);
    aux_body+= 55;
    memcpy(aux_body, CRLF, CRLF_LEN);
    aux_body += CRLF_LEN;
    memcpy(aux_body, "version=\"", 9);
    aux_body+= 9;
    memcpy(aux_body, version, size_version);
    aux_body+= size_version;
    *aux_body = '\"';
    aux_body++;
    memcpy(aux_body, CRLF, CRLF_LEN);
    aux_body += CRLF_LEN;
    memcpy(aux_body, "state=\"full\"", 12);
    aux_body+= 12;
    memcpy(aux_body, CRLF, CRLF_LEN);
    aux_body += CRLF_LEN;
    memcpy(aux_body, "entity=", 7);
    aux_body+= 7;
    memcpy(aux_body, notifier->loc_uri.s, notifier->loc_uri.len);
    aux_body += notifier->loc_uri.len;
    *aux_body = '>';
    aux_body++;
    memcpy(aux_body, CRLF, CRLF_LEN);
    aux_body += CRLF_LEN;
    memcpy(aux_body, "<dialog id=", 11);
    aux_body+= 11;
    memcpy(aux_body, notifier->dlg_id->callid.s, notifier->dlg_id->callid.len);
    aux_body += notifier->dlg_id->callid.len;
    memcpy(aux_body, CRLF, CRLF_LEN);
    aux_body += CRLF_LEN;
    memcpy(aux_body, "call-id=", 8);
    aux_body+= 8;
    memcpy(aux_body, notifier->call_dlg_id->callid.s, notifier->call_dlg_id->callid.len);
    aux_body += notifier->call_dlg_id->callid.len;
    memcpy(aux_body, CRLF, CRLF_LEN);
    aux_body += CRLF_LEN;
    memcpy(aux_body, "local-tag=\"", 11);
    aux_body+= 11;
    memcpy(aux_body, notifier->call_dlg_id->rem_tag.s, notifier->call_dlg_id->rem_tag.len);
    aux_body += notifier->call_dlg_id->rem_tag.len;
    memcpy(aux_body, "\" direction=\"initiator\">", 24);
    aux_body+= 24;
    memcpy(aux_body, CRLF, CRLF_LEN);
    aux_body += CRLF_LEN;
    memcpy(aux_body, "<state>", 7);
    aux_body+= 7;
    memcpy(aux_body, call_status, size_status);
    aux_body += size_status;
    memcpy(aux_body, "</state>", 8);
    aux_body+= 8;
    memcpy(aux_body, CRLF, CRLF_LEN);
    aux_body += CRLF_LEN;
    memcpy(aux_body, "</dialog>", 9);
    aux_body+= 9;
    memcpy(aux_body, CRLF, CRLF_LEN);
    aux_body += CRLF_LEN;
    memcpy(aux_body, "</dialog-info>", 14);
    aux_body+= 14;
    memcpy(aux_body, CRLF, CRLF_LEN);
    aux_body += CRLF_LEN;

    aux_body = '\0';

    return pt_body;



}

/* build new headers(Event, Expires) to SUBSCRIBER request */
str* add_hdr_notifier(struct sm_subscriber* notifier){

    char *aux_hdr;
    char* str_expires= NULL;
    char* status=NULL;
    int size_status = 0;
    int size_expires = 1;
    int size_hdr;
    str* pt_hdr= NULL;

    pt_hdr = (str*) pkg_malloc (sizeof (str));
    if (pt_hdr == NULL) {
        LM_ERR("--------------------------------------------------no more pkg memory\n");
        return 0;
    }

    /* convert expires in string*/
    str_expires= int2str(notifier->expires, &size_expires);
    LM_DBG("EXPIRES -str : %s \n",str_expires );
    if(str_expires == NULL || size_expires == 0){
        LM_ERR("while converting int to str\n");
        return NULL;
    }

    if (notifier->dlg_id->status == TERMINATED ){
        status = "terminated";
        size_status = 10;
        size_expires = 0;
        size_hdr = size_status + 58 + 3*CRLF_LEN;
    }else{
        status = "active";
        size_status = 6;
        size_hdr = size_expires + size_status + 67 + 3*CRLF_LEN;
    }

    aux_hdr= pkg_malloc(sizeof(char)* size_hdr + 1);
    if(aux_hdr== NULL){
        LM_ERR("no more memory\n");
        return NULL;
    }
    memset(aux_hdr, 0, size_hdr+1);
    pt_hdr->s = aux_hdr;
    pt_hdr->len = size_hdr;

    memcpy(aux_hdr, "Event: dialog", 13);
    aux_hdr+= 13;
    memcpy(aux_hdr, CRLF, CRLF_LEN);
    aux_hdr += CRLF_LEN;
    memcpy(aux_hdr, "Subscription-State: ", 20);
    aux_hdr+= 20;
    memcpy(aux_hdr, status, size_status);
    aux_hdr+= size_status;
    if ( size_expires != 0){
        memcpy(aux_hdr, ";expires=", 9);
        aux_hdr+= 9;
        memcpy(aux_hdr, str_expires, size_expires);
        aux_hdr += size_expires;
    }
    memcpy(aux_hdr, CRLF, CRLF_LEN);
    aux_hdr += CRLF_LEN;
    memcpy(aux_hdr, "Content-Type: dialog-info", 25);
    aux_hdr+= 25;
    memcpy(aux_hdr, CRLF, CRLF_LEN);
    aux_hdr += CRLF_LEN;

    aux_hdr = '\0';

    LM_DBG("NEW_HDR : %.*s \n", pt_hdr->len, pt_hdr->s);

    return pt_hdr;

}

