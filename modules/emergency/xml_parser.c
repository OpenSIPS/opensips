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


char* copy_str_between_tow_pointers(char* str_begin, char* str_end){
	size_t tamanho =0;
	char *resp, *new_begin;
	new_begin = strstr (str_begin,">");
	new_begin +=1;
	tamanho = (str_end) - new_begin;
	if (tamanho == 0)
		return NULL;
	resp = pkg_malloc(sizeof(char)*(tamanho+1));
	if(resp ==NULL)
		return resp;
	memcpy ( resp, new_begin, tamanho );
	resp[tamanho]='\0';
	return resp;
}


char* copy_str_between_tow_tags(char* tag_begin, char* str_total){
	char *ptr1,*ptr2;
	char *complete_tag_begin, *complete_tag_end;
	//char* resp = pkg_malloc(sizeof(char));
	//memset(resp,'\0',1);
	
	complete_tag_begin =  pkg_malloc(sizeof(char) * (strlen(tag_begin)+ strlen("<") + strlen(">")));
	complete_tag_end =  pkg_malloc(sizeof(char) * (strlen(tag_begin)+ strlen("</") + strlen(">")));
	if(complete_tag_begin == NULL || complete_tag_end == NULL)
		//return resp;
		return NULL;

	strcpy (complete_tag_begin,"<");
	strcat (complete_tag_begin,tag_begin);
	strcat (complete_tag_begin,">");
	
	strcpy (complete_tag_end,"</");
	strcat (complete_tag_end,tag_begin);
	strcat (complete_tag_end,">");
	
	ptr1 = strstr(str_total,complete_tag_begin);
	ptr2 = strstr(str_total,complete_tag_end);
	if(ptr1 != NULL && ptr2 != NULL){
		LM_DBG(" --- ENCONTROU A TAG %s",str_total);
		pkg_free(complete_tag_begin);
		pkg_free(complete_tag_end);		
		return copy_str_between_tow_pointers(ptr1,ptr2);
	}else{
		LM_DBG(" --- NAO ENCONTROU A TAG %s",str_total);
	}
	
	pkg_free(complete_tag_begin);
	pkg_free(complete_tag_end);
	
	//return resp;
	return NULL;

}

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

char* parse_xml_esct(char* xml){
	char* callid = "callId";
	//char* datetimestamp = "datetimestamp";
	char* vpc = "vpc";
	
	char *new_vpc;
	char *new_callid;
	//char *new_datetimestamp;


	if (check_ectAck_init_tags(xml))
		return NULL;	   
	
	new_callid = copy_str_between_tow_tags(callid,xml);
	//new_datetimestamp = copy_str_between_tow_tags(datetimestamp,xml);
	new_vpc = copy_str_between_tow_tags(vpc,xml);

	if(new_vpc != NULL){
		pkg_free(new_vpc);  

		if (new_callid != NULL){	  
			return new_callid;  
		}	 
	}

	return NULL;

}

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
	//LM_INFO(" --- STEP 1");
	PARSED *parsed = pkg_malloc(sizeof(PARSED));
	parsed->vpc =pkg_malloc(sizeof(NENA));
	parsed->destination =pkg_malloc(sizeof(NENA));
	parsed->ert =pkg_malloc(sizeof(ERT));
	//LM_INFO(" --- STEP 2");

	if (check_str_between_init_tags(xml))
		return NULL;	   
	
	if(parsed == NULL || parsed->vpc == NULL || parsed->destination == NULL || parsed->ert == NULL)
		return NULL;
	
	parsed->result = copy_str_between_tow_tags(result,xml);
	parsed->esgwri = copy_str_between_tow_tags(esgwri,xml);
	parsed->esqk = copy_str_between_tow_tags(esqk,xml);
	parsed->lro = copy_str_between_tow_tags(lro,xml);
	parsed->callid = copy_str_between_tow_tags(callid,xml);
	parsed->datetimestamp = copy_str_between_tow_tags(datetimestamp,xml);

	new_vpc = copy_str_between_tow_tags(vpc,xml);
	if(new_vpc != NULL){
		parsed->vpc->organizationname = copy_str_between_tow_tags(organizationname,new_vpc);
		parsed->vpc->hostname = copy_str_between_tow_tags(hostname,new_vpc);
		parsed->vpc->nenaid = copy_str_between_tow_tags(nenaid,new_vpc);
		parsed->vpc->contact = copy_str_between_tow_tags(contact,new_vpc);
		parsed->vpc->certuri = copy_str_between_tow_tags(certuri,new_vpc);  
		pkg_free(new_vpc);
	}else{
		parsed->vpc->organizationname = NULL;
		parsed->vpc->hostname = NULL;
		parsed->vpc->nenaid = NULL;
		parsed->vpc->contact = NULL;
		parsed->vpc->certuri = NULL;
	}

	new_destination = copy_str_between_tow_tags(destination,xml);
	if(new_destination!= NULL){
		parsed->destination->organizationname = copy_str_between_tow_tags(organizationname,new_destination);
		parsed->destination->hostname = copy_str_between_tow_tags(hostname,new_destination);
		parsed->destination->nenaid = copy_str_between_tow_tags(nenaid,new_destination);
		parsed->destination->contact = copy_str_between_tow_tags(contact,new_destination);
		parsed->destination->certuri = copy_str_between_tow_tags(certuri,new_destination);
		pkg_free(new_destination);
	}else{
		parsed->destination->organizationname = NULL;
		parsed->destination->hostname = NULL;
		parsed->destination->nenaid = NULL;
		parsed->destination->contact = NULL;
		parsed->destination->certuri = NULL;	   
	}
	
	new_ert = copy_str_between_tow_tags(ert,xml);
	if(new_ert != NULL){  
		parsed->ert->selectiveRoutingID = copy_str_between_tow_tags(selectiveRoutingID,new_ert);
		parsed->ert->routingESN = copy_str_between_tow_tags(routingESN,new_ert);
		parsed->ert->npa = copy_str_between_tow_tags(npa,new_ert);
		pkg_free(new_ert);
	}else{
		parsed->ert->selectiveRoutingID = NULL;
		parsed->ert->routingESN = NULL;
		parsed->ert->npa = NULL;   
	}
	
	return parsed;
}

int isNotBlank(char *str){
	if(str == NULL){
		//LM_INFO("STR NULL...\n");
		return -1;
	}
	if (strcmp(str, "") == 0){
		return -1;
	}else{
		return 1;
	}
}


char* buildXmlFromModel(ESCT* esct){

	int len_buf = findOutSize(esct);
	LM_INFO("AQUI I %d \n", len_buf);
	char* resp = pkg_malloc(sizeof(char)* len_buf);
	LM_INFO("AQUI II \n");	 
	sprintf(resp, XML_MODEL_ESCT ,esct->vpc->organizationname, esct->vpc->hostname,
		esct->source->hostname , esct->source->hostname, esct->source->nenaid ,
		esct->source->contact, esct->source->certuri ,
		esct->esgw , esct->esqk , esct->callid , esct->datetimestamp); 
	LM_INFO("AQUI III \n");
	return resp;
}

unsigned long findOutSize(ESCT* esct){
	unsigned long resp = 0;
	LM_INFO("AQUI X \n");
	resp = strlen(XML_MODEL_ESCT);
	if(esct != NULL){
		LM_INFO("AQUI XI \n");		
		resp += esct->callid != NULL ? strlen(esct->callid) : 0;
		LM_INFO("AQUI I \n");
		resp += esct->esgw != NULL ? strlen(esct->esgw) : 0;
		LM_INFO("AQUI II \n");
		resp += esct->esqk != NULL ? strlen(esct->esqk) : 0;
		LM_INFO("AQUI III \n");	   
		resp += esct->datetimestamp != NULL ? strlen(esct->datetimestamp) : 0;
		LM_INFO("AQUI XII \n");		
		resp += findOutNenaSize(esct->vpc);
		LM_INFO("AQUI XIII \n");		 
		resp += findOutNenaSize(esct->source);
	}
	return resp;
}

unsigned long findOutNenaSize(NENA* nena){
	unsigned long resp = 0;
	if(!nena || nena == NULL)
		return resp;
	resp += nena->organizationname != NULL ? strlen(nena->organizationname) : 0;
	resp += nena->hostname != NULL ? strlen(nena->hostname) : 0;
	resp += nena->nenaid != NULL ? strlen(nena->nenaid) : 0;
	resp += nena->contact != NULL ? strlen(nena->contact) : 0;
	resp += nena->certuri != NULL ? strlen(nena->certuri) : 0;
	
	return resp;
}
