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
#include "http_emergency.h"

/* finish the emergency call frees resources:
   - pull call cell this call from list linked eme_calls
   - send esct to VPC to release ESQK Key*/
int send_esct(struct sip_msg *msg, str callid_ori, str from_tag){

	char* esct_callid;
	NODE* info_call;
	char* xml = NULL;
	time_t rawtime;
	struct tm timeinfo;
	char* response;
	int resp;
	char* callidHeader;
	char* ftag;
	unsigned int hash_code;
	str callid;

	callidHeader = pkg_malloc(callid_ori.len + 1);
	if(callidHeader == NULL){
		LM_ERR("No memory left\n");
		return -1;
	}
	memset(callidHeader, 0, callid_ori.len + 1);
	memcpy(callidHeader, callid_ori.s, callid_ori.len);


	ftag = pkg_malloc(from_tag.len + 1);
	if(ftag == NULL){
		LM_ERR("No memory left\n");
		return -1;
	}
	memset(ftag, 0, from_tag.len + 1);
	memcpy(ftag, from_tag.s, from_tag.len);


	// extract call cell with same callid from list linked eme_calls
	LM_DBG(" --- BYE  callid=%s \n", callidHeader);

	callid.s = callidHeader,
		callid.len = strlen(callidHeader);

	hash_code= core_hash(&callid, 0, emet_size);
	LM_DBG("********************************************HASH_CODE%d\n", hash_code);

	info_call= search_ehtable(call_htable, callidHeader, ftag, hash_code, 1);
	if (info_call == NULL) {
		LM_ERR(" --- BYE DID NOT FIND CALLID \n");
		return -1;
	}else{
		if (collect_data(info_call, db_url, *db_table) == 1) {
			LM_DBG("****** REPORT OK\n");
		} else {
			LM_DBG("****** REPORT NOK\n");
		}
	}

	if (strlen(info_call->esct->esqk) > 0){

		// if VPC provide ESQK then opensips need send esct to free this key
		LM_DBG(" --- SEND ESQK =%s\n \n",info_call->esct->esqk);

		time(&rawtime);
		localtime_r(&rawtime, &timeinfo);

		strftime(info_call->esct->datetimestamp, MAX_TIME_SIZE, "%Y-%m-%dT%H:%M:%S%Z", &timeinfo);

		xml = buildXmlFromModel(info_call->esct);
		LM_DBG(" --- TREAT BYE - XML ESCT %s \n \n", xml);

		// sends HTTP POST esctRequest to VPC
		resp = post(url_vpc, xml, &response);
		if (resp == -1) {
			LM_ERR(" --- PROBLEM IN POST DO BYE\n \n");
			shm_free(info_call);
			pkg_free(xml);
			return -1;
		}

		// verify if esct response came OK
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
	shm_free(info_call->esct->esgwri);
	shm_free(info_call);

	return 1;

}


/*  verify the result field of the VPC
*/
int range_result(int result) {

	// OK
	if (result >= 200 && result <= 203)
		return 0;
	// NOT OK USE THE lro
	if (result >= 400 && result <= 404)
		return 2;
	// response NOK, but with lro field
	if (result >= 500 && result <= 501)
		return 2;

	// response NOK without lro field
	return 1;
}

/*
 * get parsed data extract from esrResponse and save in calls_eme struct:
 *  - source
 *       .organizationname
 *       .hostname
 *       .nenaid
 *       .contact
 *       .certuri
 *   - vpc
 *       .organizationname
 *       .hostname
 *       .nenaid
 *       .contact
 *       .certuri
 *   - esqk
 *   - callid
 *   - lro
 *   - result
 *   - datetimestamp
 */
int treat_parse_esrResponse(struct sip_msg *msg, ESCT *call_cell, PARSED *parsed, int proxy_role){
	char *p;
	int vsp_addr_len;
	char *vsp_addr = "@vsp.com";
	str pattern_lro, replacement_lro;
	str pt_lro;
	char *lro_aux;

	call_cell->esgwri = empty;
	call_cell->ert_srid = empty;
	call_cell->ert_npa = 0;
	call_cell->ert_resn = 0;

	call_cell->esgw = empty;
	call_cell->lro = empty;
	call_cell->disposition = empty;

	LM_DBG(" --- TREAT PARSE ESRRESPONSE...\n");

	call_cell->source->organizationname = parsed->destination->organizationname;
	call_cell->source->hostname = parsed->destination->hostname;
	call_cell->source->nenaid = parsed->destination->nenaid;
	call_cell->source->contact = parsed->destination->contact;
	call_cell->source->certuri = parsed->destination->certuri;
	call_cell->vpc->organizationname = parsed->vpc->organizationname;
	call_cell->vpc->hostname = parsed->vpc->hostname;
	call_cell->vpc->nenaid = parsed->vpc->nenaid;
	call_cell->vpc->contact = parsed->vpc->contact;
	call_cell->vpc->certuri = parsed->vpc->certuri;
	call_cell->esqk = parsed->esqk;
	call_cell->callid = parsed->callid;
	call_cell->datetimestamp = parsed->datetimestamp;
	call_cell->result = parsed->result;

	if (parsed->esgwri != empty && strlen(parsed->esgwri) > 0) {

		call_cell->esgwri = parsed->esgwri;
		call_cell->ert_npa = 0;
		call_cell->ert_resn = 0;
		call_cell->ert_srid = "";

		char *r = strstr(call_cell->esgwri, "@");
		r++;
		int tam_esgw = call_cell->esgwri + strlen(call_cell->esgwri) - r;

		call_cell->esgw = pkg_malloc(sizeof (char)*tam_esgw + 1);
		if (call_cell->esgw == NULL) {
			LM_ERR("--------------------------------------------------no more shm memory\n");
			return -1;
		}
		memcpy(call_cell->esgw, r, tam_esgw);
		call_cell->esgw[tam_esgw] = 0;

		LM_DBG(" --- ESGW:%s \n", call_cell->esgw);


		if (parsed->ert->selectiveRoutingID != empty)
			pkg_free(parsed->ert->selectiveRoutingID);

		if (parsed->ert->routingESN != empty)
			pkg_free(parsed->ert->routingESN);

		if (parsed->ert->npa != empty)
			pkg_free(parsed->ert->npa);

	} else {
		if ((parsed->ert->selectiveRoutingID != empty) && (parsed->ert->routingESN != empty) && (parsed->ert->npa != empty)) {
			int npa = atoi(parsed->ert->npa);
			int resn = atoi(parsed->ert->routingESN);
			call_cell->ert_npa = npa;
			call_cell->ert_resn = resn;

			call_cell->ert_srid = parsed->ert->selectiveRoutingID;

			if (proxy_role == 4){
				// in opensips as redirect role, consider esgwri as joint selectiveRoutingID + routingESN + npa + @vsp_address in contact headers in 300 response
				// get source ip address that send INVITE
				vsp_addr = ip_addr2a(&msg->rcv.src_ip);
				vsp_addr_len = strlen(vsp_addr);

				int esgw_len = strlen(parsed->ert->selectiveRoutingID) + strlen(parsed->ert->routingESN) + strlen(parsed->ert->npa) + vsp_addr_len + 4;
				p = pkg_malloc(sizeof (char)*esgw_len);
				if (p == NULL) {
					LM_ERR("--------------------------------------------------no more shm memory\n");
					return -1;
				}

				call_cell->esgwri = p;

				memcpy(p, parsed->ert->selectiveRoutingID, strlen(parsed->ert->selectiveRoutingID));
				p += strlen(parsed->ert->selectiveRoutingID);
				*p = '.';
				p++;
				memcpy(p, parsed->ert->routingESN, strlen(parsed->ert->routingESN));
				p += strlen(parsed->ert->routingESN);
				*p = '.';
				p++;
				memcpy(p, parsed->ert->npa, strlen(parsed->ert->npa));
				p += strlen(parsed->ert->npa);
				*p = '@';
				p++;
				memcpy(p, vsp_addr, vsp_addr_len);
				p += vsp_addr_len;
				*p = 0;

			}else{
				call_cell->esgwri = "";
			}

			pkg_free(parsed->ert->routingESN);
			pkg_free(parsed->ert->npa);
		}
	}

	if (parsed-> lro!= empty ) {
		// extarct only contigency number in lro
		LM_DBG( "LRO %s \n", parsed-> lro);
		int len_lro = strlen(parsed->lro);

		lro_aux = pkg_malloc(sizeof (char)*len_lro + 1);
		if (lro_aux == NULL) {
			LM_ERR("no more pkg memory\n");
			return -1;
		}
		memset(lro_aux, 0, len_lro + 1);
		pt_lro.s = lro_aux;
		pt_lro.len = len_lro;

		pattern_lro.s = "(tel:)*[+]*([-0-9]+)";
		pattern_lro.len = strlen(pattern_lro.s);
		replacement_lro.s = "\\2";
		replacement_lro.len = strlen(replacement_lro.s);

		if (reg_replace(pattern_lro.s, replacement_lro.s, parsed->lro, &pt_lro) != 1) {
			LM_ERR("****** PATTERN LRO NAO OK \n");
			pkg_free(lro_aux);
			goto end;
		}
		pt_lro.len = strlen(pt_lro.s);
		LM_DBG("****** PATTERN LRO OK II %.*s\n",pt_lro.len,pt_lro.s);
		call_cell->lro = pkg_malloc(sizeof (char)*pt_lro.len+1);
		if (call_cell->lro == NULL) {
			LM_ERR("--------------------------------------------------no more shm memory\n");
			return -1;
		}

		memcpy(call_cell->lro, pt_lro.s, pt_lro.len);
		call_cell->lro[pt_lro.len] = 0;
		pkg_free(lro_aux);
		pkg_free(parsed->lro);
	}

end:
	pkg_free(parsed->ert);
	pkg_free(parsed->vpc);
	pkg_free(parsed->destination);
	pkg_free(parsed);
	return 1;
}


/* get lro information from contact header and save this in call cell
*/
int get_lro_in_contact(char *contact_lro, ESCT *call_cell) {

	char *contact_lro_aux;
	str pattern_contact_lro, replacement_contact_lro;
	str pt_contact_lro;

	int len_contact_lro =  strlen(contact_lro);

	contact_lro_aux = pkg_malloc(sizeof (char)*len_contact_lro + 1);
	if (contact_lro_aux == NULL) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}
	memset(contact_lro_aux, 0,len_contact_lro  + 1);
	pt_contact_lro.s = contact_lro_aux;
	pt_contact_lro.len = len_contact_lro;

	pattern_contact_lro.s = "sips?:[+]*1?-?([0-9]+)@";
	pattern_contact_lro.len = strlen(pattern_contact_lro.s);
	replacement_contact_lro.s = "\\1";
	replacement_contact_lro.len = strlen(replacement_contact_lro.s);

	if (reg_replace(pattern_contact_lro.s, replacement_contact_lro.s, contact_lro, &pt_contact_lro) != 1) {
		LM_ERR("****** PATTERN LRO NAO OK \n");
		pkg_free(contact_lro_aux);
		pkg_free(contact_lro);
		return 1;
	}
	pt_contact_lro.len = strlen(pt_contact_lro.s);

	call_cell->lro = pkg_malloc(sizeof (char)* pt_contact_lro.len + 1);
	if (call_cell->lro == NULL) {
		LM_ERR("--------------------------------------------------no more shm memory\n");
		return -1;
	}
	memcpy(call_cell->lro, pt_contact_lro.s, pt_contact_lro.len);
	call_cell->lro[pt_contact_lro.len] = 0;
	call_cell->disposition = "none";

	LM_DBG ("TRANS REPLY LRO %s \n", call_cell->lro);
	pkg_free(contact_lro_aux);
	pkg_free(contact_lro);

	return 1;
}


/* get esqk information from contact header and save this in call cell
*/
int get_esqk_in_contact(char *contact_esgwri, ESCT *call_cell){
	char *contact_esqk_aux;
	str pattern_contact_esqk, replacement_contact_esqk;
	str pt_contact_esqk;

	int len_contact_esgwri =  strlen(contact_esgwri);

	contact_esqk_aux = pkg_malloc(sizeof (char)*len_contact_esgwri + 1);
	if (contact_esqk_aux == NULL) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}
	memset(contact_esqk_aux, 0,len_contact_esgwri + 1);
	pt_contact_esqk.s = contact_esqk_aux;
	pt_contact_esqk.len = len_contact_esgwri;

	pattern_contact_esqk.s = "Asserted-Identity:=<(sips?:)*[+]*1?-?([0-9]+)@";
	pattern_contact_esqk.len = strlen(pattern_contact_esqk.s);
	replacement_contact_esqk.s = "\\2";
	replacement_contact_esqk.len = strlen(replacement_contact_esqk.s);

	if (reg_replace(pattern_contact_esqk.s, replacement_contact_esqk.s, contact_esgwri, &pt_contact_esqk) != 1) {
		LM_ERR("****** PATTERN ESQK NAO OK \n");
		pkg_free(contact_esqk_aux);
		pkg_free(contact_esgwri);
		return 0;
	}
	pt_contact_esqk.len = strlen(pt_contact_esqk.s);

	call_cell->esqk = pkg_malloc(sizeof (char)* pt_contact_esqk.len + 1);
	if (call_cell->esqk == NULL) {
		LM_ERR("--------------------------------------------------no more shm memory\n");
		return -1;
	}
	memcpy(call_cell->esqk, pt_contact_esqk.s, pt_contact_esqk.len);
	call_cell->esqk[pt_contact_esqk.len] = 0;

	LM_DBG ("TRANS REPLY ESQK %s \n", call_cell->esqk);
	pkg_free(contact_esqk_aux);

	return 1;
}


/* get esgwri or ert information from contact header and save this in call cell
*/
int get_esgwri_ert_in_contact(char *contact_esgwri, ESCT *call_cell){

	char *contact_routing_aux;
	str pattern_contact_routing, replacement_contact_routing;
	str pt_contact_routing;
	int len_contact_routing;
	char *contact_routing;
	char *pt_aux;
	char *p_aux;
	char *srid_aux, *resn_aux, *npa_aux;
	char *pt_a, *pt_b;
	str pattern_contact_ert, replacement_contact_ert;

	char *p = strstr(contact_esgwri, "P-Asserted-Identity");
	len_contact_routing = p - contact_esgwri -1;

	contact_routing = pkg_malloc(sizeof (char)*len_contact_routing);
	if (contact_routing == NULL) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}
	memset(contact_routing, 0, len_contact_routing);
	p_aux = contact_esgwri;
	p_aux++;
	memcpy(contact_routing, p_aux, len_contact_routing-1 );
	pkg_free(contact_esgwri);

	contact_routing_aux = pkg_malloc(sizeof (char)*len_contact_routing);
	if (contact_routing_aux == NULL) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}
	memset(contact_routing_aux, 0,len_contact_routing);
	pt_contact_routing.s = contact_routing_aux;
	pt_contact_routing.len = len_contact_routing - 1;

	pattern_contact_routing.s = "^(sips?):[+]*([-0-9]+)@";
	pattern_contact_routing.len = strlen(pattern_contact_routing.s);
	replacement_contact_routing.s = "\\2";
	replacement_contact_routing.len = strlen(replacement_contact_routing.s);

	if (reg_replace(pattern_contact_routing.s, replacement_contact_routing.s, contact_routing, &pt_contact_routing) == 1) {
		LM_DBG ("TRANS REPLY ESGWRI %s \n",contact_routing);
		call_cell->esgwri = contact_routing;
		call_cell->disposition = "processes";

		pkg_free(contact_routing_aux);

	}else{
		pattern_contact_ert.s = "^(sips?):([A-Z0-9.]*)@";
		pattern_contact_ert.len = strlen(pattern_contact_ert.s);
		replacement_contact_ert.s = "\\2";
		replacement_contact_ert.len = strlen(replacement_contact_ert.s);

		if (reg_replace(pattern_contact_ert.s, replacement_contact_ert.s, contact_routing, &pt_contact_routing) != 1) {
			LM_ERR("****** PATTERN ERT NAO OK \n");
			pkg_free(contact_routing_aux);
			pkg_free(contact_routing);
			return 0;
		}

		LM_DBG ("CONTEUDO TRANS REPLY ERT %.*s \n", pt_contact_routing.len, pt_contact_routing.s);
		pt_aux = pt_contact_routing.s;
		pt_a = strchr(pt_aux,'.');
		int len_srid = pt_a - pt_contact_routing.s;
		srid_aux = pkg_malloc(sizeof (char)*len_srid + 1);
		if (srid_aux == NULL) {
			LM_ERR("no more pkg memory\n");
			return -1;
		}
		memcpy(srid_aux, pt_aux, len_srid);
		srid_aux[len_srid] = 0;
		pt_aux += len_srid + 1;

		pt_b = strchr(pt_aux,'.');
		int len_resn = pt_b - pt_aux ;
		resn_aux = pkg_malloc(sizeof (char)*len_resn + 1);
		if (resn_aux == NULL) {
			LM_ERR("no more pkg memory\n");
			return -1;
		}
		memcpy(resn_aux, pt_aux, len_resn);
		resn_aux[len_resn] = 0;
		pt_aux += len_resn + 1;

		int len_npa = pt_contact_routing.len - len_srid - len_resn;
		npa_aux = pkg_malloc(sizeof (char)*len_npa + 1);
		if (npa_aux == NULL) {
			LM_ERR("no more pkg memory\n");
			return -1;
		}
		npa_aux[len_npa] = 0;
		memcpy(npa_aux, pt_aux, len_npa);

		LM_DBG ("CONTEUDO TRANS REPLY SRID %s \n",srid_aux);
		LM_DBG ("CONTEUDO TRANS REPLY RESN %s \n",resn_aux);
		LM_DBG ("CONTEUDO TRANS REPLY NPA %s \n",npa_aux);
		int npa = atoi(npa_aux);
		int resn = atoi(resn_aux);
		int srid_len = strlen(srid_aux);

		call_cell->ert_npa = npa;
		call_cell->ert_resn = resn;
		call_cell->ert_srid = pkg_malloc(sizeof (char)* srid_len + 1);
		if (call_cell->ert_srid == NULL) {
			LM_ERR("--------------------------------------------------no more shm memory\n");
			return -1;
		}

		strcpy(call_cell->ert_srid, srid_aux);
		call_cell->ert_srid[srid_len] = 0;

		call_cell->disposition = "processes";

		pkg_free(contact_routing_aux);
		pkg_free(contact_routing);
		pkg_free(srid_aux);
		pkg_free(resn_aux);
		pkg_free(npa_aux);
	}
	return 1;
}


void free_call_cell(ESCT *info_call){

	if(info_call){

		if (info_call->source){
			if(info_call->source->organizationname){
				if (strlen(info_call->source->organizationname)!= 0){
					pkg_free (info_call->source->organizationname);
					LM_DBG(" ---  FREE INFO_CALL->SOURCE->ORG\n");
				}
			}
			if(info_call->source->hostname){
				if (strlen(info_call->source->hostname)!= 0){
					pkg_free (info_call->source->hostname);
					LM_DBG(" ---  FREE INFO_CALL->SOURCE->HOST\n");
				}
			}
			if(info_call->source->nenaid){
				if (strlen(info_call->source->nenaid)!= 0){
					pkg_free (info_call->source->nenaid);
					LM_DBG(" ---  FREE INFO_CALL->SOURCE->NENA\n");
				}
			}
			if(info_call->source->contact){
				if (strlen(info_call->source->contact)!= 0){
					pkg_free (info_call->source->contact);
					LM_DBG(" ---  FREE INFO_CALL->SOURCE->CONTACT\n");
				}
			}
			if(info_call->source->certuri){
				if (strlen(info_call->source->certuri)!= 0){
					pkg_free (info_call->source->certuri);
					LM_DBG(" ---  FREE INFO_CALL->SOURCE->CERTURI\n");
				}
			}
			pkg_free (info_call->source);
		}

		if (info_call->vpc){
			if(info_call->vpc->organizationname){
				if (strlen(info_call->vpc->organizationname)!= 0){
					pkg_free (info_call->vpc->organizationname);
					LM_DBG(" ---  FREE INFO_CALL->VPC->ORG\n");
				}
			}
			if(info_call->vpc->hostname){
				if (strlen(info_call->vpc->hostname)!= 0){
					pkg_free (info_call->vpc->hostname);
					LM_DBG(" ---  FREE INFO_CALL->VPC->HOST\n");
				}
			}
			if(info_call->vpc->nenaid){
				if (strlen(info_call->vpc->nenaid)!= 0){
					pkg_free (info_call->vpc->nenaid);
					LM_DBG(" ---  FREE INFO_CALL->VPC->NENA\n");
				}
			}
			if(info_call->vpc->contact){
				if (strlen(info_call->vpc->contact)!= 0){
					pkg_free (info_call->vpc->contact);
					LM_DBG(" ---  FREE INFO_CALL->VPC->CONTACT\n");
				}
			}
			if(info_call->vpc->certuri){
				if (strlen(info_call->vpc->certuri)!= 0){
					pkg_free (info_call->vpc->certuri);
					LM_DBG(" ---  FREE INFO_CALL->VPC->CERTURI\n");
				}
			}
			pkg_free (info_call->vpc);
		}

		if (info_call->eme_dlg_id){
			if(info_call->eme_dlg_id->call_id){
				pkg_free (info_call->eme_dlg_id->call_id);
				LM_DBG(" ---  FREE INFO_CALL->CALLID\n");
			}

			if(info_call->eme_dlg_id->local_tag){
				pkg_free (info_call->eme_dlg_id->local_tag);
				LM_DBG(" ---  FREE INFO_CALL->LOCAL_TAG\n");
			}
			pkg_free (info_call->eme_dlg_id);
		}

		if((info_call->esqk)&&(strlen(info_call->esqk) > 1)){
			pkg_free (info_call->esqk);
			LM_DBG(" ---  FREE INFO_CALL->ESQK\n");
		}

		if(info_call->callid){
			pkg_free (info_call->callid);
			LM_DBG(" ---  FREE INFO_CALL->CALLID\n");
		}


		if((info_call->lro)&&(strlen(info_call->lro) > 1)){
			pkg_free (info_call->lro);
			LM_DBG(" ---  FREE INFO_CALL->LRO\n");
		}


		if((info_call->esgwri)&&(strlen(info_call->esgwri) > 1)){
			pkg_free (info_call->esgwri);
			LM_DBG(" ---  FREE INFO_CALL->ESGWRI\n");
		}

		if((info_call->esgw)&&(strlen(info_call->esgw) > 1)){
			pkg_free (info_call->esgw);
			LM_DBG(" ---  FREE INFO_CALL->ESGW\n");
		}

		if((info_call->ert_srid)&&(strlen(info_call->ert_srid) > 1)){
			LM_DBG(" ---  FREE INFO_CALL->ERT_SRID\n");
			pkg_free (info_call->ert_srid);
		}

		if((info_call->result)&&(strlen(info_call->result) > 1)){
			pkg_free (info_call->result);
			LM_DBG(" ---  FREE INFO_CALL->RESULT\n");
		}

		if((info_call->datetimestamp)&&(strlen(info_call->datetimestamp) > 1)){
			pkg_free (info_call->datetimestamp);
			LM_DBG(" ---  FREE INFO_CALL->DATETIMESTAMP\n");
		}

		pkg_free (info_call);
	}
}

/* frees the memory from the struct NENA
*/
void free_nena(NENA *nena) {
	if (nena->organizationname && strlen(nena->organizationname)>0){
		pkg_free(nena->organizationname);
	}
	if (nena->hostname && strlen(nena->hostname)>0){
		pkg_free(nena->hostname);
	}
	if (nena->nenaid && strlen(nena->nenaid)>0){
		pkg_free(nena->nenaid);
	}
	if (nena->contact && strlen(nena->contact)>0){
		pkg_free(nena->contact);
	}
	if (nena->certuri && strlen(nena->certuri)>0){
		pkg_free(nena->certuri);
	}

}


/*frees memory from the data received from the VPC
*/
void free_parsed(PARSED *parsed){
	if(parsed){
		if(parsed->ert->routingESN && strlen(parsed->ert->routingESN)>0){
			pkg_free(parsed->ert->routingESN);
		}
		if(parsed->ert->selectiveRoutingID && strlen(parsed->ert->selectiveRoutingID)>0){
			pkg_free(parsed->ert->selectiveRoutingID);
		}
		if(parsed->ert->npa && strlen(parsed->ert->npa)>0){
			pkg_free(parsed->ert->npa);
		}

		pkg_free(parsed->ert);
		free_nena(parsed->vpc);
		pkg_free(parsed->vpc);
		free_nena(parsed->destination);
		pkg_free(parsed->destination);

		if(parsed->result && strlen(parsed->result)>0){
			pkg_free(parsed->result);
		}
		if(parsed->esgwri && strlen(parsed->esgwri)>0){
			pkg_free(parsed->esgwri);
		}
		if(parsed->esqk && strlen(parsed->esqk)>0){
			pkg_free(parsed->esqk);
		}
		if(parsed->lro && strlen(parsed->lro)>0){
			pkg_free(parsed->lro);
		}
		if(parsed->callid && strlen(parsed->callid)>0){
			pkg_free(parsed->callid);
		}
		if(parsed->datetimestamp && strlen(parsed->datetimestamp)>0){
			pkg_free(parsed->datetimestamp);
		}
		pkg_free(parsed);
	}
}
