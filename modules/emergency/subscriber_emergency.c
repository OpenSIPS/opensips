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
#include "subscriber_emergency.h"

#define INIT                    0
#define NOTIFY_WAIT             1
#define PENDING                 2
#define ACTIVE                  3
#define TERMINATED              4

/*Create cell to control Subscriber Dialog States
  This cell save this information:
  - Dialog Id:
  .Callid
  .rem_tag
  .local_tag
  - expires
  - Local_uri
  - Remote_uri
  - Notifier_uri
  - INVITE's Callid
  - Event body
  - State
  */
int create_subscriber_cell(struct sip_msg* reply, struct parms_cb* params_cb){

	str* callid = NULL;
	int expires= 0;
	struct to_body *pto= NULL, *pfrom = NULL;
	int size_subs_cell;
	int vsp_addr_len;
	char *vsp_addr = "@vsp.com";
	time_t rawtime;
	int time_now;
	struct sm_subscriber *subs_cell = NULL;
	char *p;
	unsigned int hash_code;

	callid= (str*) pkg_malloc (sizeof (str));
	if (callid == NULL) {
		LM_ERR("--------------------------------------------------no more pkg memory\n");
		return 0;
	}
	/*Verify repĺy is OK and get callid and expires from response*/
	if ( !extract_reply_headers(reply, callid, expires)){
		LM_ERR("fail in extract headers\n");
		pkg_free(callid);
		return 0;
	}

	/*get From header fields */
	pfrom = get_from(reply);
	LM_DBG("PFROM: %.*s \n ", pfrom->uri.len, pfrom->uri.s );
	if( pfrom->tag_value.s ==NULL || pfrom->tag_value.len == 0){
		LM_ERR("reply without tag value \n");
		pkg_free(callid);
		return 0;
	}

	/*get To header fields */
	pto = get_to(reply);
	LM_DBG("PTO: %.*s \n ", pto->uri.len, pto->uri.s );
	if (pto == NULL || pto->error != PARSE_OK) {
		LM_ERR("failed to parse TO header\n");
		pkg_free(callid);
		return 0;
	}

	// get source ip address that send INVITE
	vsp_addr = ip_addr2a(&reply->rcv.src_ip);
	vsp_addr_len = strlen(vsp_addr);

	time(&rawtime);
	time_now = (int)rawtime;
	LM_DBG("TIME : %d \n", (int)rawtime );

	/* build subscriber cell */
	size_subs_cell = sizeof (struct sm_subscriber) + (2 * sizeof(struct dialog_id))
		+ callid->len + pfrom->tag_value.len + pto->tag_value.len + pfrom->uri.len + pto->uri.len
		+ params_cb->callid_ori.len +  params_cb->event.len + params_cb->from_tag.len + vsp_addr_len + 9 ;
	subs_cell = pkg_malloc(size_subs_cell + 1);
	if (!subs_cell) {
		LM_ERR("no more shm\n");
		return 0;
	}

	memset(subs_cell, 0, size_subs_cell + 1);
	subs_cell->expires = expires;
	subs_cell->timeout =  TIMER_N + time_now;
	LM_DBG("SUBS_TIMEOUT: %d \n ", subs_cell->timeout );
	subs_cell->version =  -1;

	subs_cell->dlg_id = (struct dialog_id*)(subs_cell + 1);

	subs_cell->dlg_id->callid.len = callid->len;
	subs_cell->dlg_id->callid.s = (char *) (subs_cell->dlg_id + 1);
	memcpy(subs_cell->dlg_id->callid.s, callid->s, callid->len);
	LM_DBG("SUBS_CALLID: %.*s \n ", subs_cell->dlg_id->callid.len, subs_cell->dlg_id->callid.s );

	subs_cell->dlg_id->local_tag.len = pfrom->tag_value.len;
	subs_cell->dlg_id->local_tag.s = (char *) (subs_cell->dlg_id + 1) + callid->len;
	memcpy(subs_cell->dlg_id->local_tag.s, pfrom->tag_value.s, pfrom->tag_value.len);
	LM_DBG("SUBS_FROM_TAG: %.*s \n ", subs_cell->dlg_id->local_tag.len, subs_cell->dlg_id->local_tag.s );

	subs_cell->dlg_id->rem_tag.len = pto->tag_value.len;
	subs_cell->dlg_id->rem_tag.s = (char *) (subs_cell->dlg_id + 1) + callid->len + pfrom->tag_value.len;
	memcpy(subs_cell->dlg_id->rem_tag.s, pto->tag_value.s, pto->tag_value.len);
	LM_DBG("SUBS_TO_TAG: %.*s \n ", subs_cell->dlg_id->rem_tag.len, subs_cell->dlg_id->rem_tag.s );

	p = (char *)(subs_cell->dlg_id + 1) + callid->len + pfrom->tag_value.len + pto->tag_value.len;
	subs_cell->call_dlg_id = (struct dialog_id*)p;

	subs_cell->call_dlg_id->callid.len= params_cb->callid_ori.len;
	subs_cell->call_dlg_id->callid.s = (char *) (subs_cell->call_dlg_id + 1);
	memcpy(subs_cell->call_dlg_id->callid.s, params_cb->callid_ori.s, params_cb->callid_ori.len);
	LM_DBG("SUBS_CALLID_ORI: %.*s \n ", subs_cell->call_dlg_id->callid.len, subs_cell->call_dlg_id->callid.s );

	subs_cell->call_dlg_id->local_tag.len= params_cb->from_tag.len;
	subs_cell->call_dlg_id->local_tag.s = (char *) (subs_cell->call_dlg_id + 1) + params_cb->callid_ori.len;
	memcpy(subs_cell->call_dlg_id->local_tag.s, params_cb->from_tag.s, params_cb->from_tag.len);
	LM_DBG("SUBS_FROMTAG_event: %.*s \n ", subs_cell->call_dlg_id->local_tag.len, subs_cell->call_dlg_id->local_tag.s );

	subs_cell->loc_uri.len = pfrom->uri.len;
	subs_cell->loc_uri.s = (char *) (subs_cell->call_dlg_id + 1) + params_cb->callid_ori.len + params_cb->from_tag.len;
	memcpy(subs_cell->loc_uri.s,pfrom->uri.s,pfrom->uri.len);
	LM_DBG("SUBS_LOC_URI: %.*s \n ", subs_cell->loc_uri.len, subs_cell->loc_uri.s );

	subs_cell->rem_uri.len= pto->uri.len;
	subs_cell->rem_uri.s = (char *) (subs_cell->call_dlg_id + 1) + params_cb->callid_ori.len + params_cb->from_tag.len + pfrom->uri.len;
	memcpy(subs_cell->rem_uri.s, pto->uri.s, pto->uri.len);
	LM_DBG("SUBS_REM_URI: %.*s \n ", subs_cell->rem_uri.len, subs_cell->rem_uri.s );

	subs_cell->event.len= params_cb->event.len;
	subs_cell->event.s = (char *) (subs_cell->call_dlg_id + 1) + params_cb->callid_ori.len + params_cb->from_tag.len + pfrom->uri.len + pto->uri.len;
	memcpy(subs_cell->event.s, params_cb->event.s, params_cb->event.len);
	LM_DBG("SUBS_EVENT: %.*s \n ", subs_cell->event.len, subs_cell->event.s );

	subs_cell->contact.len = vsp_addr_len + 9;
	subs_cell->contact.s = (char *) (subs_cell->call_dlg_id + 1) + params_cb->callid_ori.len + params_cb->from_tag.len + pfrom->uri.len + pto->uri.len + params_cb->event.len;
	memcpy(subs_cell->contact.s, "sip:test@", 9);
	memcpy(subs_cell->contact.s + 9, vsp_addr, vsp_addr_len);
	LM_DBG("SUBS_CONTACT: %.*s \n ", subs_cell->contact.len, subs_cell->contact.s );

	subs_cell->dlg_id->status = NOTIFY_WAIT;

	hash_code= core_hash(&subs_cell->dlg_id->callid, 0, subst_size);
	LM_DBG("********************************************HASH_CODE%d\n", hash_code);


	if(insert_shtable(subs_htable, hash_code,subs_cell) == NULL){
		LM_ERR("inserting new record in subs_htable\n");
	}

	pkg_free(subs_cell);
	pkg_free(callid);

	return 1;

}


/* Verify is reply OK and get callid and expires */
int extract_reply_headers(struct sip_msg* reply, str* callid, int expires){

	/* get dialog information from reply message: callid, to_tag, from_tag */
	if(reply == NULL){
		LM_ERR("no reply message\n ");
		return 0;
	}
	if ( parse_headers(reply,HDR_EOH_F, 0) == -1 ){
		LM_ERR("error in parsing headers\n");
		return 0;
	}
	if( reply->callid==NULL || reply->callid->body.s==NULL){
		LM_ERR("reply without callid header\n");
		return 0;
	}
	*callid = reply->callid->body;

	if (reply->from->parsed == NULL){
		if ( parse_from_header( reply )<0 ){
			LM_ERR("reply without From header\n");
			return 0;
		}
	}

	if( reply->to==NULL || reply->to->body.s==NULL){
		LM_ERR("error in parse TO header\n");
		return 0;
	}

	if(reply->expires == NULL){
		LM_ERR("reply without Expires header\n");
		return 0;
	}
	/* extract the other necessary information for inserting a new record */
	if(reply->expires && reply->expires->body.len > 0){
		expires = atoi(reply->expires->body.s);
		LM_DBG("expires= %d\n", expires);
	}
	if(expires== 0){
		LM_DBG("expires= 0: no not insert\n");
		return 0;
	}

	return 1;
}


/* Treat Subscribe reply callback from Notifier */
void subs_cback_func(struct cell *t, int cb_type, struct tmcb_params *params){

	int code = params->code;
	struct sip_msg *reply = params->rpl;
	struct parms_cb* params_cb = (struct parms_cb*)(*params->param);


	LM_DBG("TREAT SUBSCRIBE REPLY \n");
	LM_DBG("REPLY: %.*s \n ", reply->first_line.u.reply.version.len, reply->first_line.u.reply.version.s );
	LM_DBG("CODE: %d \n ", code);
	LM_DBG("CALLID_INVITE: %.*s \n ",params_cb->callid_ori.len,params_cb->callid_ori.s);
	LM_DBG("FROM_TAG_INVITE: %.*s \n ",params_cb->from_tag.len,params_cb->from_tag.s);

	/* verify if response is OK*/
	if (code < 200){
		LM_ERR("ignore response \n");
		return;
	}

	if (code < 300){
		/* response OK(2XX): create Subscriber Cell*/
		if ( !create_subscriber_cell(reply, params_cb)){
			LM_ERR("fail in create subcriber cell \n");
		}

	}else{
		/* Response NOK send esct to clear esqk in VPC*/
		LM_ERR("reply to SUBSCRIBER NOK - revisa\n");
		if(send_esct(reply, params_cb->callid_ori, params_cb->from_tag) == 0){
			LM_ERR("error in send to esct\n");
		}
	}

	shm_free(params_cb->callid_ori.s);
	shm_free(params_cb->from_tag.s);
	shm_free(params_cb->event.s);
	shm_free(params_cb);
	return;
}


/* build new headers(Event, Expires) to SUBSCRIBER request */
str* add_hdr_subscriber(int expires, str event){

	char *aux_hdr;
	char* str_expires= NULL;
	int size_expires = 1;
	int size_hdr;
	str* pt_hdr= NULL;

	/* convert expires in string*/
	str_expires= int2str(expires, &size_expires);
	LM_DBG("EXPIRES -str : %s \n",str_expires );
	if(str_expires == NULL || size_expires == 0){
		LM_ERR("while converting int to str\n");
		return NULL;
	}

	pt_hdr = (str*) pkg_malloc (sizeof (str));
	if (pt_hdr == NULL) {
		LM_ERR("--------------------------------------------------no more pkg memory\n");
		return 0;
	}

	LM_DBG("EVENT STR %.*s \n", event.len, event.s);
	size_hdr = size_expires + event.len + 16 + 2*CRLF_LEN;

	aux_hdr= pkg_malloc(sizeof(char)* size_hdr + 1);
	if(aux_hdr== NULL){
		LM_ERR("no more memory\n");
		return NULL;
	}
	memset(aux_hdr, 0, size_hdr+1);
	pt_hdr->s = aux_hdr;
	pt_hdr->len = size_hdr;

	memcpy(aux_hdr, "Event: ", 7);
	aux_hdr+= 7;
	memcpy(aux_hdr, event.s, event.len);
	aux_hdr+= event.len;
	memcpy(aux_hdr, CRLF, CRLF_LEN);
	aux_hdr += CRLF_LEN;

	memcpy(aux_hdr, "Expires: ", 9);
	aux_hdr += 9;
	memcpy(aux_hdr, str_expires, size_expires);
	aux_hdr += size_expires;
	memcpy(aux_hdr, CRLF, CRLF_LEN);
	aux_hdr += CRLF_LEN;

	LM_DBG("HDR: %.*s \n", pt_hdr->len, pt_hdr->s);
	return pt_hdr;

}

/* Get some fields necessary to pass in function_cb*/
int build_params_cb(struct sip_msg* msg, char* callidHeader,  struct parms_cb* params_cb ){

	char *dialog_aux;
	str from_tag;
	int size_callid;
	int size_dialog;
	char *dialog;

	if (parse_from_header(msg) != 0) {
		LM_ERR(" REQUEST WITHOUT FROM HEADER\n");
	}

	from_tag = get_from(msg)->tag_value;
	LM_DBG("FROM_TAG: %.*s\n", from_tag.len, from_tag.s);
	LM_DBG("CALLID = %s \n", callidHeader);

	size_callid = strlen(callidHeader);

	size_dialog= size_callid + from_tag.len + 26;
	dialog_aux = shm_malloc (sizeof (char)* size_dialog + 1);
	if (dialog_aux == NULL) {
		LM_ERR("--------------------------------------------------no more pkg memory\n");
		return 0;
	}

	memset(dialog_aux, 0, size_dialog + 1);
	dialog = dialog_aux;
	memcpy(dialog_aux, "dialog; call-id=", 16);
	dialog_aux += 16;
	memcpy(dialog_aux, callidHeader, size_callid);
	dialog_aux += size_callid;
	memcpy(dialog_aux, ";from-tag=", 10);
	dialog_aux += 10;
	memcpy(dialog_aux, from_tag.s, from_tag.len);
	LM_DBG("dialog: %s\n", dialog);


	char *call_aux = shm_malloc (size_callid + 1);
	if (call_aux == NULL) {
		LM_ERR("--------------------------------------------------no more pkg memory\n");
		return 0;
	}
	call_aux[size_callid] = 0;
	memcpy(call_aux, callidHeader, size_callid);

	char *ftag = shm_malloc (from_tag.len + 1);
	if (ftag == NULL) {
		LM_ERR("--------------------------------------------------no more pkg memory\n");
		return 0;
	}
	ftag[from_tag.len] = 0;
	memcpy(ftag, from_tag.s, from_tag.len);

	params_cb->callid_ori.s = call_aux;
	params_cb->callid_ori.len = size_callid;
	params_cb->from_tag.s = ftag;
	params_cb->from_tag.len = from_tag.len;
	params_cb->event.s = dialog;
	params_cb->event.len = size_dialog;

	return 1;

}


/* build some Uri to use in SUBSCRIBER request */
int get_uris_to_subscribe(struct sip_msg* msg, str* contact, str* notifier, str* subscriber ){

	struct sip_uri *furi;
	int size_contact;
	int size_notifier;
	int size_subscriber;
	char *contact_aux;
	char *notifier_aux;
	char *subscriber_aux;
	int vsp_addr_len;
	char *vsp_addr = "@vsp.com";
	int rp_addr_len;
	char *rp_addr = "@rp.com";

	/* build contact uri to use in To header */
	if ((furi = parse_from_uri(msg)) == NULL) {
		LM_ERR("****** ERROR PARSE FROM \n");
		return 0;
	}

	size_contact= furi->user.len + furi->host.len + furi->port.len + 6;
	contact_aux = pkg_malloc (sizeof (char)* size_contact + 1);
	if (contact_aux == NULL) {
		LM_ERR("--------------------------------------------------no more pkg memory\n");
		return 0;
	}
	memset(contact_aux, 0, size_contact + 1);

	contact->s = contact_aux;
	contact->len = size_contact;
	memcpy(contact_aux, "sip:", 4);
	contact_aux += 4;
	memcpy(contact_aux, furi->user.s, furi->user.len);
	contact_aux += furi->user.len;
	*contact_aux = '@';
	contact_aux++;
	memcpy(contact_aux, furi->host.s, furi->host.len);
	contact_aux += furi->host.len;
	*contact_aux = ':';
	contact_aux++;
	memcpy(contact_aux, furi->port.s, furi->port.len);
	LM_DBG("****** contact: %.*s\n", contact->len, contact->s);

	/* build notifier uri to use in R-URI */
	if ((parse_sip_msg_uri(msg) < 0) ||
		(!msg->parsed_uri.user.s) ||
		(msg->parsed_uri.user.len > MAXNUMBERLEN)) {
		LM_ERR("cannot parse msg URI\n");
		pkg_free(contact_aux);
		return 0;
	}
	// get source ip address that send INVITE
	vsp_addr = ip_addr2a(&msg->rcv.src_ip);
	vsp_addr_len = strlen(vsp_addr);

	size_notifier = vsp_addr_len + msg->parsed_uri.user.len + 5;
	notifier_aux = pkg_malloc(size_notifier + 1);
	if (notifier_aux == NULL) {
		LM_ERR("--------------------------------------------------no more pkg memory\n");
		return 0;
	}
	memset(notifier_aux, 0, size_notifier + 1);
	notifier->s = notifier_aux;
	notifier->len = size_notifier;
	memcpy(notifier_aux, "sip:", 4);
	notifier_aux += 4;
	memcpy(notifier_aux, msg->parsed_uri.user.s, msg->parsed_uri.user.len);
	notifier_aux += msg->parsed_uri.user.len;
	*notifier_aux = '@';
	notifier_aux++;
	memcpy(notifier_aux, vsp_addr, vsp_addr_len);
	LM_DBG("****** notifier: %.*s\n", notifier->len, notifier->s);


	/* build subscriber uri to use in From header */
	// get ip address of opensips server in port that receive INVITE
	if (get_ip_socket(msg, &rp_addr) == -1){
		pkg_free(contact_aux);
		pkg_free(notifier_aux);
		return 0;
	}

	rp_addr_len = strlen(rp_addr);

	size_subscriber = rp_addr_len + 21;
	subscriber_aux = pkg_malloc(size_subscriber + 1);
	if (subscriber_aux == NULL) {
		LM_ERR("--------------------------------------------------no more pkg memory\n");
		return 0;
	}
	memset(subscriber_aux, 0, size_subscriber + 1);
	subscriber->s = subscriber_aux;
	subscriber->len = size_subscriber;
	memcpy(subscriber_aux, "sip:opensips_redirect", 21);
	subscriber_aux += 21;
	memcpy(subscriber_aux, rp_addr, rp_addr_len);
	LM_DBG("****** subscriber: %.*s\n", subscriber->len, subscriber->s);

	return 1;

}


/* analise if reply from subscriber terminated is OK*/
void subs_cback_func_II(struct cell *t, int cb_type, struct tmcb_params *params){

	int code = params->code;
	struct sip_msg *reply = params->rpl;
	UNUSED(reply);
	//struct sm_subscriber* params_subs = (struct sm_subscriber*)(*params->param);

	LM_DBG("TREAT SUBSCRIBE TERMINATED REPLY \n");
	LM_DBG("REPLY: %.*s \n ", reply->first_line.u.reply.version.len, reply->first_line.u.reply.version.s );
	LM_DBG("CODE: %d \n ", code);

	if (code < 300){
		time_t rawtime;
		time(&rawtime);
		//int time_now = (int)rawtime;

		//params_subs->timeout =  TIMER_N + time_now;
		//LM_DBG("TIMEOUT REPLY SUBSCRIBE: %d\n ", params_subs->timeout);


	}else{
		LM_ERR("reply to subscribe terminated NOK\n ");
	}

	return;
}

/* build dialog struct */
dlg_t* build_dlg(struct sm_subscriber* subscriber){


	dlg_t* dialog = NULL;
	int size;

	size= sizeof(dlg_t)+ subscriber->dlg_id->callid.len+ subscriber->dlg_id->rem_tag.len+
		subscriber->dlg_id->local_tag.len+ subscriber->loc_uri.len+
		subscriber->rem_uri.len + subscriber->contact.len;;

	dialog = (dlg_t*)pkg_malloc(size);
	if(dialog == NULL){
		LM_ERR("No memory left\n");
		return NULL;
	}
	memset(dialog, 0, size);

	size= sizeof(dlg_t);

	dialog->id.call_id.s = (char*)dialog+ size;
	memcpy(dialog->id.call_id.s, subscriber->dlg_id->callid.s, subscriber->dlg_id->callid.len);
	dialog->id.call_id.len= subscriber->dlg_id->callid.len;
	size+= subscriber->dlg_id->callid.len;

	dialog->id.rem_tag.s = (char*)dialog+ size;
	memcpy(dialog->id.rem_tag.s, subscriber->dlg_id->rem_tag.s, subscriber->dlg_id->rem_tag.len);
	dialog->id.rem_tag.len = subscriber->dlg_id->rem_tag.len;
	size+= subscriber->dlg_id->rem_tag.len;

	dialog->id.loc_tag.s = (char*)dialog+ size;
	memcpy(dialog->id.loc_tag.s, subscriber->dlg_id->local_tag.s, subscriber->dlg_id->local_tag.len);
	dialog->id.loc_tag.len =subscriber->dlg_id->local_tag.len;
	size+= subscriber->dlg_id->local_tag.len;

	dialog->loc_uri.s = (char*)dialog+ size;
	memcpy(dialog->loc_uri.s, subscriber->loc_uri.s, subscriber->loc_uri.len) ;
	dialog->loc_uri.len = subscriber->loc_uri.len;
	size+= dialog->loc_uri.len;

	dialog->rem_uri.s = (char*)dialog+ size;
	memcpy(dialog->rem_uri.s, subscriber->rem_uri.s, subscriber->rem_uri.len) ;
	dialog->rem_uri.len = subscriber->rem_uri.len;
	size+= dialog->rem_uri.len;

	dialog->rem_target.s = (char*)dialog+ size;
	memcpy(dialog->rem_target.s, subscriber->contact.s, subscriber->contact.len);
	dialog->rem_target.len = subscriber->contact.len;
	size+= dialog->rem_target.len;

	dialog->loc_seq.is_set = 1;
	dialog->state= DLG_CONFIRMED ;

	return dialog;
}

/*
 * send SUBSCRIBER to Call Server in scenario III
 * to receive notify about call status event
 */
int send_subscriber(struct sip_msg* msg, char* callidHeader, int expires){

	str* contact_pt = NULL;
	str* notifier_pt = NULL;
	str* subscriber_pt = NULL;
	str met= {"SUBSCRIBE", 9};
	str* pt_hdr= NULL;
	int sending;
	struct parms_cb* params_cb;
	int resp = 0;

	/*get URI of Notifier, Subscriber and Contact to use in Subscribe request */
	contact_pt = (str*) pkg_malloc (sizeof (str));
	if (contact_pt == NULL) {
		LM_ERR("--------------------------------------------------no more pkg memory\n");
		return 0;
	}
	notifier_pt = (str*) pkg_malloc (sizeof (str));
	if (notifier_pt == NULL) {
		LM_ERR("--------------------------------------------------no more pkg memory\n");
		return 0;
	}
	subscriber_pt = (str*) pkg_malloc (sizeof (str));
	if (subscriber_pt == NULL) {
		LM_ERR("--------------------------------------------------no more pkg memory\n");
		return 0;
	}
	if( !get_uris_to_subscribe(msg, contact_pt, notifier_pt, subscriber_pt)){
		LM_ERR("**** fail in build parameters to cb \n");
		resp = 0;
		goto end_02;
	}

	/*build struct (INVITE Callid, Event body) for parameter callback */
	params_cb = (struct parms_cb*) shm_malloc (sizeof (struct parms_cb));
	if (params_cb == NULL) {
		LM_ERR("--------------------------------------------------no more shm memory\n");
		return 0;
	}

	if( !build_params_cb(msg, callidHeader, params_cb )){
		LM_ERR("**** fail in build parameters to cb \n");
		shm_free(params_cb);
		resp = 0;
		goto end_01;
	}

	/* add new header (Event, Expires) in SUBSCRIBE request */
	pt_hdr = add_hdr_subscriber( expires, params_cb->event);

	LM_DBG("****** PARAMS FROM TAG: %.*s\n", params_cb->from_tag.len, params_cb->from_tag.s);

	/* send SUBSCRIBER */
	sending= eme_tm.t_request
		(&met,                       /* Type of the message */
		 notifier_pt,                 /* Request-URI*/
		 contact_pt,                  /* To */
		 subscriber_pt,               /* From */
		 pt_hdr,                      /* Optional headers including CRLF */
		 0,                           /* Message body */
		 notifier_pt,                 /* Outbound_proxy */
		 subs_cback_func,             /* Callback function */
		 (void*)params_cb,            /* Callback parameter */
		 0
		);

	resp = 1;
	if(sending< 0){
		LM_ERR("while sending request with t_request\n");
		shm_free(params_cb->callid_ori.s);
		shm_free(params_cb->from_tag.s);
		shm_free(params_cb->event.s);
		shm_free(params_cb);
		resp = 0;
	}
	if(pt_hdr != NULL){
		pkg_free(pt_hdr->s);
		pkg_free(pt_hdr);
	}
end_01:
	pkg_free(notifier_pt->s);
	pkg_free(contact_pt->s);
	pkg_free(subscriber_pt->s);
end_02:
	pkg_free(notifier_pt);
	pkg_free(contact_pt);
	pkg_free(subscriber_pt);

	return resp;

}


/* send subscriber within of dialog, this subscriber close this dialog with Expires header = 0 */
int send_subscriber_within(struct sip_msg* msg, struct sm_subscriber* subs, int expires){

	dlg_t* dialog =NULL;
	str met= {"SUBSCRIBE", 9};
	int sending;
	str* pt_hdr= NULL;
	struct sm_subscriber* params_cb;

	dialog = build_dlg(subs);
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

	/*
	   event = pkg_malloc(sizeof (char)* subs->event.len +1);
	   if (event == NULL) {
	   LM_ERR("no more pkg memory\n");
	   return -1;
	   }
	   event[subs->event.len] = 0;
	   memcpy(event, subs->event.s, subs->event.len);

	   LM_DBG(" --- EXPIRES = %d \n", expires);
	   LM_DBG(" --- EVENT = %.*s \n", subs->event.len, subs->event.s);
	   */
	params_cb = subs;

	pt_hdr = add_hdr_subscriber(expires, subs->event);

	sending= eme_tm.t_request_within
		(&met,
		 pt_hdr,
		 0,
		 dialog,
		 subs_cback_func_II,
		 (void*)params_cb,
		 0
		);

	if(sending< 0)
		LM_ERR("while sending request with t_request_within\n");

	if(pt_hdr != NULL){
		pkg_free(pt_hdr->s);
		pkg_free(pt_hdr);
	}
	//pkg_free(event);
	pkg_free(dialog);
	return 1;
}

/* look for subscriber cell using callid and to_tag of Notify*/
struct sm_subscriber* get_subs_cell(struct sip_msg *msg, str callid_event) {
	str callid;
	str method;
	struct to_body *pto= NULL, *pfrom = NULL;
	struct sm_subscriber* s;
	unsigned int hash_code;

	method.s = msg->first_line.u.request.method.s;
	method.len = msg->first_line.u.request.method.len;

	if ( parse_headers(msg,HDR_EOH_F, 0) == -1 ){
		LM_ERR("error in parsing headers\n");
		return NULL;
	}

	// get callid from Notify
	if( msg->callid==NULL || msg->callid->body.s==NULL){
		LM_ERR("reply without callid header\n");
		return NULL;
	}
	callid = msg->callid->body;
	LM_DBG("CALLID: %.*s \n ", callid.len, callid.s );

	if (msg->from->parsed == NULL){
		if ( parse_from_header( msg )<0 ){
			LM_ERR("reply without From header\n");
			return NULL;
		}
	}

	//get From header from Notify
	pfrom = get_from(msg);
	LM_DBG("PFROM: %.*s \n ", pfrom->uri.len, pfrom->uri.s );

	if( pfrom->tag_value.s ==NULL || pfrom->tag_value.len == 0){
		LM_ERR("reply without tag value \n");
		return NULL;
	}
	if( msg->to==NULL || msg->to->body.s==NULL){
		LM_ERR("error in parse TO header\n");
		return NULL;
	}

	// get To header from Notify
	pto = get_to(msg);
	if (pto == NULL || pto->error != PARSE_OK) {
		LM_ERR("failed to parse TO header\n");
		return NULL;
	}
	if( pto->tag_value.s ==NULL || pto->tag_value.len == 0){
		LM_ERR("reply without tag value \n");
	}
	LM_DBG("PTO: %.*s \n ", pto->uri.len, pto->uri.s );
	LM_DBG("PTO_TAG: %.*s \n ", pto->tag_value.len, pto->tag_value.s );
	LM_DBG("********************************************CALLID_STR%.*s\n", callid_event.len, callid_event.s);
	hash_code= core_hash(&callid_event, 0, subst_size);
	LM_DBG("********************************************HASH_CODE%d\n", hash_code);



	s= search_shtable(subs_htable, &callid, &pfrom->tag_value, hash_code, &method);
	if (s == NULL) {
		LM_ERR(" ---FAILURE SUB_CELL NOT FOUND IN SHTABLE\n");
	}

	return s;
}


/* Treat Notify to Subscriber Dialog in scenario III*/
int treat_notify(struct sip_msg *msg) {

	int resp = 1;
	struct sm_subscriber*  cell_subs;
	int expires= 0;
	char *subs_state, *subs_expires;
	str callid_orig;
	str from_tag;
	struct notify_body* notify_body = NULL;
	time_t rawtime;
	int time_now;
	int version;
	char *version_init, *version_end, *version_aux;
	int size_version;
	unsigned int hash_code;
	str callid_event;
	static str msg200={"OK Notify",sizeof("OK Notify")-1};
	static str msg481={"Subscription does not exist",sizeof("Subscription does not exist")-1};
	static str msg489={"Bad Event",sizeof("Bad Event")-1};
	static str msg400={"Bad Request",sizeof("Bad Request")-1};

	if(!check_event_header(msg)){
		LM_ERR("event header type not allow\n");
		if(!eme_tm.t_reply(msg,489,&msg489)){
			LM_ERR("t_reply (489)\n");
		}
		return 0;
	}

	if ( parse_headers(msg,HDR_EOH_F, 0) == -1 ){
		LM_ERR("error in parsing headers\n");
		return 0;
	}

	// get callid from Notify
	if( msg->callid==NULL || msg->callid->body.s==NULL){
		LM_ERR("reply without callid header\n");
		return 0;
	}
	callid_event = msg->callid->body;
	LM_DBG("CALLID: %.*s \n ", callid_event.len, callid_event.s );

	/* look for cell in list linked subs_pt with same dialog Id*/
	cell_subs = get_subs_cell(msg, callid_event);
	if(cell_subs == NULL){
		if(!eme_tm.t_reply(msg,481,&msg481)){
			LM_ERR("t_reply (481)\n");
		}
		return 0;
	}

	LM_DBG("STATUS: %d \n ", cell_subs->dlg_id->status);
	LM_DBG("TIMEOUT NOTIFY: %d \n ", cell_subs->timeout);

	/* get in Subscription_state header: state and expire */
	if(!get_subscription_state_header(msg, &subs_state, &subs_expires)){
		LM_ERR("invalid body of Subscription_state header\n");
		if(!eme_tm.t_reply(msg,400,&msg400)){
			LM_ERR("t_reply (400)\n");
		}
		return 0;
	}
	LM_DBG("STATE: %s\n ", subs_state);
	LM_DBG("SUBS_EXPIRES: %s\n ", subs_expires);

	time(&rawtime);
	time_now = (int)rawtime;

	/* analise state value*/
	if (strcmp(subs_state, "active") == 0){
		cell_subs->dlg_id->status = ACTIVE;
		cell_subs->expires = atoi(subs_expires);
		cell_subs->timeout =  cell_subs->expires + time_now;
	}else{
		if (strcmp(subs_state, "pending") == 0){
			cell_subs->dlg_id->status = PENDING ;
			cell_subs->expires = atoi(subs_expires);
			cell_subs->timeout =  TIMER_N + time_now;
		}else{
			if(strcmp(subs_state, "terminated") == 0){

				/* state is terminated indicate that subcriber dialog finish
				   then pull cell of the list linked and send esct to VPC*/
				LM_DBG(" --- CLEAR CELL \n");
				callid_orig = cell_subs->call_dlg_id->callid;
				from_tag = cell_subs->call_dlg_id->local_tag;

				LM_DBG(" --- CALLID_ORIG %.*s \n", callid_orig.len, callid_orig.s);
				LM_DBG(" --- FROM_TAG_ORIG %.*s \n", from_tag.len, from_tag.s);

				if(send_esct(msg, callid_orig, from_tag) == 0){
					LM_ERR("error in send to esct\n");
				}

				hash_code= core_hash(&callid_event, 0, subst_size);
				LM_DBG("********************************************HASH_CODE%d\n", hash_code);

				delete_shtable(subs_htable, hash_code, cell_subs);

				/* Reply OK to Notify*/
				if(!eme_tm.t_reply(msg,200,&msg200)){
					LM_ERR("t_reply (200)\n");
					return 0;
				}
				return 1;

			}else{
				LM_ERR("INCOMPATIBLE RECEIVED STATUS\n");
				if(!eme_tm.t_reply(msg,400,&msg400)){
					LM_ERR("t_reply (400)\n");
				}
				return 0;
			}
		}
	}

	LM_DBG("STATUS: %d \n ", cell_subs->dlg_id->status);
	LM_DBG(" --- NOTIFY BODY %s", msg->eoh);

	notify_body = parse_notify(msg->eoh);
	if( notify_body == NULL){
		LM_ERR("invalid body in Notify request\n");
		if(!eme_tm.t_reply(msg,400,&msg400)){
			LM_ERR("t_reply (400)\n");
		}
		resp = 0;
		goto end;
	}

	version_init = strchr(notify_body->params->version,'\"');
	version_init++;
	version_end = strchr(version_init,'\"');
	size_version = version_end - version_init;
	version_aux = pkg_malloc(size_version + 1);
	if (version_aux == NULL) {
		LM_ERR("no more pkg memory\n");
		return 0;
	}
	memcpy(version_aux, version_init, size_version );
	version_aux[size_version] = '\0';
	version = atoi(version_aux);
	pkg_free(version_aux);
	LM_DBG(" --- STATE %s", notify_body->state);
	LM_DBG(" --- VERSION %d", version);

	/* Reply OK to Notify*/
	if(!eme_tm.t_reply(msg,200,&msg200)){
		LM_DBG("t_reply (200)\n");
		free_parsed_notify(notify_body);
		resp = 0;
		goto end;
	}

	if(cell_subs->version >= version){
		LM_ERR(" --- ERRO IN VERSION PARAMETER IN NOTIFY BODY");
		free_parsed_notify(notify_body);
		resp = 0;
		goto end;
	}else{
		cell_subs->version  = version;
	}


	/* if Notify body state has terminated value, which indicates that emergency call finish,
	   then send subscribe with expire=0 to terminate the subscriber dialog*/
	if(strcmp(notify_body->state, "terminated") == 0){
		expires = 0;
		LM_DBG(" --- STATE %s", notify_body->state);
		if(send_subscriber_within(msg, cell_subs, expires) == -1){
			LM_ERR(" --- Error in send subscriber terminated \n");
		}
	}

	resp = 1;
	free_parsed_notify(notify_body);

end:
	pkg_free(subs_state);
	pkg_free(subs_expires);
	return resp;
}

// free notify_body
void free_parsed_notify(struct notify_body* notify_body){
	if(notify_body){
		if(notify_body->target){
			if(notify_body->target->dlg_id != empty){
				pkg_free(notify_body->target->dlg_id);
			}
			if(notify_body->target->callid != empty){
				pkg_free(notify_body->target->callid);
			}
			if(notify_body->target->local_tag != empty){
				pkg_free(notify_body->target->local_tag);
			}
			if(notify_body->target->direction != empty){
				pkg_free(notify_body->target->direction);
			}
			pkg_free(notify_body->target);
		}
		if(notify_body->params){
			if(notify_body->params->version != empty){
				pkg_free(notify_body->params->version);
			}
			if(notify_body->params->state != empty){
				pkg_free(notify_body->params->state);
			}
			if(notify_body->params->entity != empty){
				pkg_free(notify_body->params->entity);
			}
			pkg_free(notify_body->params);
		}
		pkg_free(notify_body);
	}
	return;
}
