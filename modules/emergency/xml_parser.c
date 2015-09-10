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
 *  2015-08-05 code review (Villaron/Tesini)
 *  2015-09-07 final test cases (Villaron/Tesini)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "xml_parser.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"

const char *XML_MODEL_ESCT= "<esct xmlns=\"urn:nena:xml:ns:es:v2\" \n  \
							 xmlns:xsi=http://www.w3.org/2001/XMLSchema-instance \n  \
							 xsi:schemaLocation=\"urn:nena:xml:ns:es:v2 v2.xsd\">  \n  \
							 <vpc> \n  \
							 <organizationName>%s</organizationName> \n \
							 <hostId>%s</hostId> \n  \
							 </vpc> \n  \
							 <source> \n  \
							 <organizationName>%s</organizationName> \n  \
							 <hostId>%s</hostId> \n  \
							 <nenaId>%s</nenaId> \n  \
							 <contact>%s</contact> \n  \
							 <certUri>%s</certUri> \n  \
							 </source> \n  \
							 <esgw>%s</esgw> \n  \
							 <esqk>%s</esqk> \n  \
							 <callId>%s</callId> \n \
							 <datetimestamp>%s</datetimestamp> \n  \
							 </esct> ";


char* copy_str_between_two_pointers(char* str_begin, char* str_end){
	char *new_begin;

	new_begin = strstr (str_begin,">");
	new_begin +=1;

	return copy_str_between_two_pointers_simple(new_begin, str_end);
}


char* copy_str_between_two_pointers_simple(char* str_begin, char* str_end){
	size_t tamanho =0;
	char *resp;
	tamanho = str_end - str_begin;
	if (tamanho == 0)
		return empty;
	resp = pkg_malloc(sizeof(char)*(tamanho+1));
	if(resp ==NULL)
		return resp;
	memcpy ( resp, str_begin, tamanho );
	resp[tamanho]='\0';
	return resp;
}

//copy string between initial (<tag>) and end (<\tag>) tags
char* copy_str_between_two_tags(char* tag_begin, char* str_total){
	char *ptr1,*ptr2;
	char *complete_tag_begin, *complete_tag_end;
	int size_begin, size_end;

	size_begin =  sizeof(char) * (strlen(tag_begin)+ strlen("<") + strlen(">")) + 1;
	size_end = sizeof(char) * (strlen(tag_begin)+ strlen("</") + strlen(">")) + 1;
	complete_tag_begin =  pkg_malloc(size_begin);
	complete_tag_end =  pkg_malloc(size_end);
	memset(complete_tag_begin, 0, size_begin);
	memset(complete_tag_end, 0, size_end);

	if(complete_tag_begin == NULL || complete_tag_end == NULL)
		return empty;

	strcpy (complete_tag_begin,"<");
	strcat (complete_tag_begin,tag_begin);
	strcat (complete_tag_begin,">");

	strcpy (complete_tag_end,"</");
	strcat (complete_tag_end,tag_begin);
	strcat (complete_tag_end,">");

	ptr1 = strstr(str_total,complete_tag_begin);
	ptr2 = strstr(str_total,complete_tag_end);
	if(ptr1 != NULL && ptr2 != NULL){
		LM_DBG(" --- FOUND TAG %s",str_total);
		pkg_free(complete_tag_begin);
		pkg_free(complete_tag_end);
		return copy_str_between_two_pointers(ptr1,ptr2);
	}else{
		LM_DBG(" --- NOT FOUND TAG %s",str_total);
	}

	pkg_free(complete_tag_begin);
	pkg_free(complete_tag_end);

	return empty;

}
//copy string between initial (<tag) and end (<\tag>) tags, in this case consider parms in initial tag
char* copy_str_between_two_tags_simple(char* tag_begin, char* str_total){
	char *ptr1,*ptr2;
	char *complete_tag_begin, *complete_tag_end;

	complete_tag_begin =  pkg_malloc(sizeof(char) * (strlen(tag_begin)+ strlen("<")));
	complete_tag_end =  pkg_malloc(sizeof(char) * (strlen(tag_begin)+ strlen("</") + strlen(">")));
	if(complete_tag_begin == NULL || complete_tag_end == NULL)
		return empty;

	strcpy (complete_tag_begin,"<");
	strcat (complete_tag_begin,tag_begin);

	strcpy (complete_tag_end,"</");
	strcat (complete_tag_end,tag_begin);
	strcat (complete_tag_end,">");

	ptr1 = strstr(str_total,complete_tag_begin);
	ptr2 = strstr(str_total,complete_tag_end);
	if(ptr1 != NULL && ptr2 != NULL){
		LM_DBG(" --- FOUND TAG %s",str_total);
		pkg_free(complete_tag_begin);
		pkg_free(complete_tag_end);
		return copy_str_between_two_pointers_simple(ptr1 + strlen(tag_begin) + 1,ptr2);
	}else{
		LM_DBG(" --- NOT FOUND TAG %s",str_total);
	}

	pkg_free(complete_tag_begin);
	pkg_free(complete_tag_end);

	return empty;

}

// check main tag in esrResponse
int check_str_between_init_tags( char* str_total){
	char *ptr1,*ptr2;
	char *complete_tag_begin, *complete_tag_end;

	complete_tag_begin = "<esrResponse";
	complete_tag_end = "</esrResponse";

	ptr1 = strstr(str_total,complete_tag_begin);
	ptr2 = strstr(str_total,complete_tag_end);
	if(ptr1 != NULL && ptr2 != NULL)
		return 0;


	LM_ERR(" --- NAO ENCONTROU INICIO \n");
	return 1;
}

// check main tag in esctAck
int check_ectAck_init_tags( char* str_total){
	char *ptr1,*ptr2;
	char *complete_tag_begin, *complete_tag_end;

	complete_tag_begin = "<esctAck";
	complete_tag_end = "</esctAck";

	ptr1 = strstr(str_total,complete_tag_begin);
	ptr2 = strstr(str_total,complete_tag_end);
	if(ptr1 != NULL && ptr2 != NULL)
		return 0;


	LM_ERR(" --- NAO ENCONTROU INICIO \n");
	return 1;
}

/* treats the esctAck xml from VPC
 *   - extract data callid:
 */
char* parse_xml_esct(char* xml){
	char* callid = "callId";
	//char* datetimestamp = "datetimestamp";
	char* vpc = "vpc";

	char *new_vpc;
	char *new_callid;
	//char *new_datetimestamp;


	if (check_ectAck_init_tags(xml))
		return NULL;

	new_callid = copy_str_between_two_tags(callid,xml);
	//new_datetimestamp = copy_str_between_two_tags(datetimestamp,xml);
	new_vpc = copy_str_between_two_tags(vpc,xml);

	if(new_vpc != empty){
		pkg_free(new_vpc);

		if (new_callid != empty){
			return new_callid;
		}
	}

	return NULL;

}

// check tag dialog-info from Notify request
char* check_dialog_init_tags( char* str_total){
	char *ptr1,*ptr2;
	char *complete_tag_begin, *complete_tag_end;

	complete_tag_begin = "<dialog-info xmlns=\"urn:ietf:params:xml:ns:dialog-info\"";
	complete_tag_end = "</dialog-info>";

	LM_DBG(" --- CHECK DIALOG FLAGS \n");


	ptr1 = strstr(str_total,complete_tag_begin);
	ptr2 = strstr(str_total,complete_tag_end);
	if(ptr1 != NULL && ptr2 != NULL){
		ptr1 += strlen(complete_tag_begin);
		return ptr1;

	}

	LM_ERR(" --- INIT FLAGS NOT FOUND \n");
	return NULL;
}


/* get data of Notify body and put in variable with the struct:
   - params:
   .version
   .state
   .entity
   - target:
   .dialog_id
   .callid
   .local_tag
   .direction
   - state
   */
struct notify_body* parse_notify(char* xml){
	char* version = "version=";
	char* dlg_state = "state=";
	char* entity = "entity=";
	char* dialog = "dialog";
	char* dialog_id = "id=";
	char* callid = "call-id";
	char* local_tag = "local-tag";
	char* direction = "direction";
	char* state = "state";

	char* pt_version;
	char* pt_dlg_state;
	char* pt_entity;
	char* pt_end_entity;
	char* pt_dialog_id;
	char* pt_callid;
	char* pt_local_tag;
	char* pt_direction;
	char* pt_end_direction;

	char* target_info;
	char* dialog_body;
	struct notify_body* notify;

	LM_DBG(" --- PARSES NOTYFY BODY \n");

	dialog_body = check_dialog_init_tags(xml);
	if (dialog_body == NULL)
		return NULL;

	notify = pkg_malloc(sizeof(struct notify_body));
	notify->params = pkg_malloc(sizeof(struct dialog_params));
	notify->target = pkg_malloc(sizeof(struct target_info));

	if(notify == NULL || notify->params == NULL || notify->target == NULL)
		return NULL;

	pt_version = strstr(dialog_body,version);
	pt_dlg_state = strstr(dialog_body,dlg_state);
	pt_entity = strstr(dialog_body,entity);
	pt_end_entity = strstr(dialog_body,">");

	if (pt_version == NULL || pt_dlg_state == NULL || pt_entity == NULL || pt_end_entity == NULL)
		goto error_01;

	target_info = copy_str_between_two_tags_simple(dialog,dialog_body);
	if (target_info == empty)
		goto error_01;

	notify->state = copy_str_between_two_tags(state,dialog_body);
	if (notify->state == empty){
		pkg_free(target_info);
		goto error_01;
	}

	pt_dialog_id = strstr(target_info,dialog_id);
	pt_callid = strstr(target_info,callid);
	pt_local_tag = strstr(target_info,local_tag);
	pt_direction = strstr(target_info,direction);
	pt_end_direction = strstr(target_info,">");

	if (pt_dialog_id == NULL || pt_callid == NULL || pt_local_tag == NULL || pt_direction == NULL || pt_end_direction == NULL){
		pkg_free(target_info);
		pkg_free(notify->state);
		goto error_01;
	}

	notify->params->version = copy_str_between_two_pointers_simple(pt_version + strlen(version), pt_dlg_state);
	notify->params->state = copy_str_between_two_pointers_simple(pt_dlg_state + strlen(dlg_state), pt_entity);
	notify->params->entity = copy_str_between_two_pointers_simple(pt_entity + strlen(entity), pt_end_entity);

	notify->target->dlg_id = copy_str_between_two_pointers_simple(pt_dialog_id + strlen(dialog_id), pt_callid);
	notify->target->callid = copy_str_between_two_pointers_simple(pt_callid + strlen(callid), pt_local_tag);
	notify->target->local_tag = copy_str_between_two_pointers_simple(pt_local_tag + strlen(local_tag), pt_direction);
	notify->target->direction = copy_str_between_two_pointers_simple(pt_direction + strlen(direction), pt_end_direction);

	pkg_free(target_info);
	return notify;

error_01:
	pkg_free(notify->target);
	pkg_free(notify->params);
	pkg_free(notify);
	return NULL;
}

/* treats the esrResponse xml from VPC
 *   - extract data between tags and put in parsed struct:
 *       - result
 *       - esgwri
 *       - esqk
 *       - lro
 *       - callid
 *       - datetimestamp
 *       - vpc
 *           .organizationname
 *           .hostname
 *           .nenaid
 *           .contact
 *           .certuri
 *       - destination
 *           .organizationname
 *           .hostname
 *           .nenaid
 *           .contact
 *           .certuri
 *       - ert
 *           .selectiveRoutingID
 *           .routingESN
 *           .npa
 */
PARSED* parse_xml(char* xml){
	char* result = "result";
	char* esgwri = "esgwri";
	char* esqk = "esqk";
	char* lro = "lro";
	char* callid = "callId";
	char* datetimestamp = "datetimestamp";
	char* vpc = "vpc";
	char* destination = "destination";
	char* organizationname = "organizationName";
	char* hostname = "hostId";
	char* nenaid = "nenaId";
	char* contact = "contact";
	char* certuri = "certUri";
	char* ert = "ert";
	char* selectiveRoutingID = "selectiveRoutingID";
	char* routingESN = "routingESN";
	char* npa = "npa";

	char *new_vpc, *new_destination, *new_ert;

	PARSED *parsed = pkg_malloc(sizeof(PARSED));
	parsed->vpc =pkg_malloc(sizeof(NENA));
	parsed->destination =pkg_malloc(sizeof(NENA));
	parsed->ert =pkg_malloc(sizeof(ERT));

	if (check_str_between_init_tags(xml))
		return NULL;

	if(parsed == NULL || parsed->vpc == NULL || parsed->destination == NULL || parsed->ert == NULL)
		return NULL;

	parsed->result = copy_str_between_two_tags(result,xml);
	parsed->esgwri = copy_str_between_two_tags(esgwri,xml);
	parsed->esqk = copy_str_between_two_tags(esqk,xml);
	parsed->lro = copy_str_between_two_tags(lro,xml);
	parsed->callid = copy_str_between_two_tags(callid,xml);
	parsed->datetimestamp = copy_str_between_two_tags(datetimestamp,xml);

	new_vpc = copy_str_between_two_tags(vpc,xml);
	if(new_vpc != empty){
		parsed->vpc->organizationname = copy_str_between_two_tags(organizationname,new_vpc);
		parsed->vpc->hostname = copy_str_between_two_tags(hostname,new_vpc);
		parsed->vpc->nenaid = copy_str_between_two_tags(nenaid,new_vpc);
		parsed->vpc->contact = copy_str_between_two_tags(contact,new_vpc);
		parsed->vpc->certuri = copy_str_between_two_tags(certuri,new_vpc);

		pkg_free(new_vpc);
	}else{
		parsed->vpc->organizationname = empty;
		parsed->vpc->hostname = empty;
		parsed->vpc->nenaid = empty;
		parsed->vpc->contact = empty;
		parsed->vpc->certuri = empty;
	}

	new_destination = copy_str_between_two_tags(destination,xml);
	if(new_destination!= empty){
		parsed->destination->organizationname = copy_str_between_two_tags(organizationname,new_destination);
		parsed->destination->hostname = copy_str_between_two_tags(hostname,new_destination);
		parsed->destination->nenaid = copy_str_between_two_tags(nenaid,new_destination);
		parsed->destination->contact = copy_str_between_two_tags(contact,new_destination);
		parsed->destination->certuri = copy_str_between_two_tags(certuri,new_destination);

		pkg_free(new_destination);
	}else{
		parsed->destination->organizationname = empty;
		parsed->destination->hostname = empty;
		parsed->destination->nenaid = empty;
		parsed->destination->contact = empty;
		parsed->destination->certuri = empty;
	}

	new_ert = copy_str_between_two_tags(ert,xml);
	if(new_ert != empty){
		parsed->ert->selectiveRoutingID = copy_str_between_two_tags(selectiveRoutingID,new_ert);
		parsed->ert->routingESN = copy_str_between_two_tags(routingESN,new_ert);
		parsed->ert->npa = copy_str_between_two_tags(npa,new_ert);

		pkg_free(new_ert);
	}else{
		parsed->ert->selectiveRoutingID = empty;
		parsed->ert->routingESN = empty;
		parsed->ert->npa = empty;
	}

	return parsed;
}

int isNotBlank(char *str){
	if(str == NULL){
		//LM_DBG("STR NULL...\n");
		return -1;
	}
	if (strcmp(str, "") == 0){
		return -1;
	}else{
		return 1;
	}
}

// build xml for esctRequest
char* buildXmlFromModel(ESCT* esct){

	int len_buf = findOutSize(esct);
	char* resp = pkg_malloc(sizeof(char)* len_buf);
	if (resp == NULL) {
		LM_ERR("--------------------------------------------------no more pkg memory\n");
		return NULL;
	}

	sprintf(resp, XML_MODEL_ESCT ,esct->vpc->organizationname, esct->vpc->hostname,
			esct->source->organizationname , esct->source->hostname, esct->source->nenaid ,
			esct->source->contact, esct->source->certuri ,
			esct->esgw , esct->esqk , esct->callid , esct->datetimestamp);
	return resp;
}

unsigned long findOutSize(ESCT* esct){
	unsigned long resp = 0;
	resp = strlen(XML_MODEL_ESCT);
	if(esct != NULL){
		resp += esct->callid != empty ? strlen(esct->callid) : 0;
		resp += esct->esgw != empty ? strlen(esct->esgw) : 0;
		resp += esct->esqk != empty ? strlen(esct->esqk) : 0;
		resp += esct->datetimestamp != empty ? strlen(esct->datetimestamp) : 0;
		resp += findOutNenaSize(esct->vpc);
		resp += findOutNenaSize(esct->source);
	}
	return resp;
}

unsigned long findOutNenaSize(NENA* nena){
	unsigned long resp = 0;
	if(!nena || nena == NULL)
		return resp;
	resp += nena->organizationname != empty ? strlen(nena->organizationname) : 0;
	resp += nena->hostname != empty ? strlen(nena->hostname) : 0;
	resp += nena->nenaid != empty ? strlen(nena->nenaid) : 0;
	resp += nena->contact != empty ? strlen(nena->contact) : 0;
	resp += nena->certuri != empty ? strlen(nena->certuri) : 0;

	return resp;
}
