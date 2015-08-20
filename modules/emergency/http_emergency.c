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
#include "http_emergency.h" 



/*  verify the result field of the VPC
*/
int faixa_result(int result) {

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
int treat_parse_esrResponse(struct sip_msg *msg, ESCT *call_cell , NENA *call_cell_vpc, NENA *call_cell_source, PARSED *parsed, int proxy_hole)
{
    char *p;
    int vsp_addr_len;
    char *vsp_addr = "@vsp.com"; 
    str pattern_lro, replacement_lro;    
    str pt_lro; 
    char *lro_aux;

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

    LM_INFO(" --- TREAT PARSE ESRRESPONSE...");
    if (parsed->destination->organizationname != NULL) {
        char* field = shm_malloc(sizeof (char)*strlen(parsed->destination->organizationname)+1);
        if (field == NULL) {
            LM_ERR("--------------------------------------------------no more shm memory\n");
            return -1;
        }
        strcpy(field, parsed->destination->organizationname);            
        call_cell_source->organizationname = field;          
    }
    if (parsed->destination->hostname != NULL ) {
        char* field = shm_malloc(sizeof (char)*strlen(parsed->destination->hostname)+1);
        if (field == NULL) {
            LM_ERR("--------------------------------------------------no more shm memory\n");
            return -1;
        }
        strcpy(field, parsed->destination->hostname);
        call_cell_source->hostname = field;
    }
    if (parsed->destination->nenaid != NULL ) {
        char* field = shm_malloc(sizeof (char)*strlen(parsed->destination->nenaid)+1);
        if (field == NULL) {
            LM_ERR("--------------------------------------------------no more shm memory\n");
            return -1;
        }
        strcpy(field, parsed->destination->nenaid);
        call_cell_source->nenaid = field;
    }
    if (parsed->destination->contact != NULL ) {
        char* field = shm_malloc(sizeof (char)*strlen(parsed->destination->contact)+1);
        if (field == NULL) {
            LM_ERR("--------------------------------------------------no more shm memory\n");
            return -1;
        }
        strcpy(field, parsed->destination->contact);
        call_cell_source->contact = field;
    }

    if (parsed->destination->certuri != NULL ) {
        char* field = shm_malloc(sizeof (char)*strlen(parsed->destination->certuri)+1);
        if (field == NULL) {
            LM_ERR("--------------------------------------------------no more shm memory\n");
            return -1;
        }
        strcpy(field, parsed->destination->certuri);
        call_cell_source->certuri = field;
    }

    if (parsed->vpc->organizationname != NULL ) {
        char* field = shm_malloc(sizeof (char)*strlen(parsed->vpc->organizationname)+1);
        if (field == NULL) {
            LM_ERR("--------------------------------------------------no more shm memory\n");
            return -1;
        }
        strcpy(field, parsed->vpc->organizationname);
        call_cell_vpc->organizationname = field;
    }
    if (parsed->vpc->hostname != NULL ) {
        char* field = shm_malloc(sizeof (char)*strlen(parsed->vpc->hostname)+1);
        if (field == NULL) {
            LM_ERR("--------------------------------------------------no more shm memory\n");
            return -1;
        }
        strcpy(field, parsed->vpc->hostname);
        call_cell_vpc->hostname = field;
    }
    if (parsed->vpc->nenaid != NULL ) {
        char* field = shm_malloc(sizeof (char)*strlen(parsed->vpc->nenaid)+1);
        if (field == NULL) {
            LM_ERR("--------------------------------------------------no more shm memory\n");
            return -1;
        }
        strcpy(field, parsed->vpc->nenaid);
        call_cell_vpc->nenaid = field;
    }
    if (parsed->vpc->contact != NULL ) {
        char* field = shm_malloc(sizeof (char)*strlen(parsed->vpc->contact)+1);
        if (field == NULL) {
            LM_ERR("--------------------------------------------------no more shm memory\n");
            return -1;
        }
        strcpy(field, parsed->vpc->contact);
        call_cell_vpc->contact = field;
    }
    if (parsed->vpc->certuri != NULL ) {
        char* field = shm_malloc(sizeof (char)*strlen(parsed->vpc->certuri)+1);
        if (field == NULL) {
            LM_ERR("--------------------------------------------------no more shm memory\n");
            return -1;
        }
        strcpy(field, parsed->vpc->certuri);
        call_cell_vpc->certuri = field;
    }

    if (parsed-> esqk!= NULL ) {
        call_cell->esqk = shm_malloc(sizeof (char)*strlen(parsed->esqk)+1);
        if (call_cell->esqk == NULL) {
            LM_ERR("--------------------------------------------------no more shm memory\n");
            return -1;
        }
        strcpy(call_cell->esqk, parsed->esqk);
    }

    call_cell->callid = shm_malloc(sizeof (char)*strlen(parsed->callid)+1);
    if (call_cell->callid == NULL) {
        LM_ERR("--------------------------------------------------no more shm memory\n");
        return -1;
    }
    strcpy(call_cell->callid, parsed->callid);

    if (parsed->esgwri != NULL && strlen(parsed->esgwri) > 0) {

        call_cell->esgwri = shm_malloc(sizeof (char)*strlen(parsed->esgwri));
        if (call_cell->esgwri == NULL) {
            LM_ERR("--------------------------------------------------no more shm memory\n");
            return -1;
        }
        strcpy(call_cell->esgwri, parsed->esgwri);
        call_cell->ert_npa = 0;
        call_cell->ert_resn = 0;
        call_cell->ert_srid = "";

        call_cell->esgw = strstr(call_cell->esgwri, "@");
        call_cell->esgw ++;

    } else {
        if ((parsed->ert->selectiveRoutingID != NULL) && (parsed->ert->routingESN != NULL) && (parsed->ert->npa != NULL)) {
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

            if (proxy_hole == 2){

                // get source ip address that send INVITE
                vsp_addr = ip_addr2a(&msg->rcv.src_ip);
                vsp_addr_len = strlen(vsp_addr); 

                int esgw_len = strlen(parsed->ert->selectiveRoutingID) + strlen(parsed->ert->routingESN) + strlen(parsed->ert->npa) + vsp_addr_len + 4;
                p = shm_malloc(sizeof (char)*esgw_len);
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
        }
    }

    if (parsed-> lro!= NULL ) {
        LM_INFO( "LRO %s \n", parsed-> lro);
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
            return -1;
        }
        pt_lro.len = strlen(pt_lro.s);
        LM_INFO("****** PATTERN LRO OK II %.*s\n",pt_lro.len,pt_lro.s);
        call_cell->lro = shm_malloc(sizeof (char)*pt_lro.len+1);

        if (call_cell->lro == NULL) {
            LM_ERR("--------------------------------------------------no more shm memory\n");
            return -1;
        }

        memcpy(call_cell->lro, pt_lro.s, pt_lro.len);      
        pkg_free(lro_aux);

    }

    if (parsed->datetimestamp != NULL ) {
        call_cell->datetimestamp = shm_malloc(sizeof (char)*strlen(parsed->datetimestamp)+1);
        if (call_cell->datetimestamp == NULL) {
            LM_ERR("--------------------------------------------------no more shm memory\n");
            return -1;
        }
        strcpy(call_cell->datetimestamp, parsed->datetimestamp);
    }
    
    call_cell->result = shm_malloc(sizeof (char)*strlen(parsed->result)+1);
    if (call_cell->result == NULL) {
        LM_ERR("--------------------------------------------------no more shm memory\n");
        return -1;
    }
    strcpy(call_cell->result, parsed->result);

    insert_call_cell_in_list(call_cell);

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

    pattern_contact_lro.s = "(sips?:)*+?1?([-0-9]+)@";
    pattern_contact_lro.len = strlen(pattern_contact_lro.s);
    replacement_contact_lro.s = "\\2";
    replacement_contact_lro.len = strlen(replacement_contact_lro.s);

    if (reg_replace(pattern_contact_lro.s, replacement_contact_lro.s, contact_lro, &pt_contact_lro) != 1) {
        LM_ERR("****** PATTERN LRO NAO OK \n");
        pkg_free(contact_lro_aux);
        pkg_free(contact_lro);

        return 1;
    }
    pt_contact_lro.len = strlen(pt_contact_lro.s);

    call_cell->lro = shm_malloc(sizeof (char)* pt_contact_lro.len + 1);
    if (call_cell->lro == NULL) {
        LM_ERR("--------------------------------------------------no more shm memory\n");
        return -1;
    }

    memcpy(call_cell->lro, pt_contact_lro.s, pt_contact_lro.len);
    call_cell->lro[pt_contact_lro.len] = 0;
    call_cell->disposition = "none";

    LM_INFO ("CONTEUDO TRANS REPLY LRO %.*s \n", pt_contact_lro.len, pt_contact_lro.s);  
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

    pattern_contact_esqk.s = "Asserted_Identity:=<(sips?:)*[+]*1?([-0-9]+)@";        
    pattern_contact_esqk.len = strlen(pattern_contact_esqk.s);
    replacement_contact_esqk.s = "\\2";
    replacement_contact_esqk.len = strlen(replacement_contact_esqk.s);

    if (reg_replace(pattern_contact_esqk.s, replacement_contact_esqk.s, contact_esgwri, &pt_contact_esqk) != 1) {
        LM_ERR("****** PATTERN ESQK NAO OK \n");
        pkg_free(contact_esqk_aux);
        pkg_free(contact_esgwri);

        if (strlen(call_cell->lro) <= 1){            
            pkg_free(call_cell->callid);                            
            pkg_free(call_cell);               
        }
        return -1;
    }
    pt_contact_esqk.len = strlen(pt_contact_esqk.s);

    call_cell->esqk = shm_malloc(sizeof (char)* pt_contact_esqk.len + 1);
    if (call_cell->esqk == NULL) {
        LM_ERR("--------------------------------------------------no more shm memory\n");           
        return -1;
    }

    memcpy(call_cell->esqk, pt_contact_esqk.s, pt_contact_esqk.len);
    call_cell->esqk[pt_contact_esqk.len] = 0;

    LM_INFO ("CONTEUDO TRANS REPLY ESQK %.*s \n", pt_contact_esqk.len, pt_contact_esqk.s);
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
    char *srid_aux, *resn_aux, *npa_aux;
    char *pt_a, *pt_b;

    str pattern_contact_ert, replacement_contact_ert; 


    int len_contact_esgwri =  strlen(contact_esgwri);

    char *p = strstr(contact_esgwri, "P-Asserted_Identity");
    len_contact_routing = p - contact_esgwri -1;
    contact_routing = pkg_malloc(sizeof (char)*len_contact_routing);
    char *p_aux = contact_esgwri;
    memcpy(contact_routing, ++p_aux, len_contact_routing-1 );
    pkg_free(contact_esgwri);
    LM_INFO ("CONTEUDO TRANS ESGWRI II %d \n", len_contact_routing); 
    LM_INFO ("CONTEUDO TRANS ESGWRI II %s \n", contact_routing); 

    contact_routing_aux = pkg_malloc(sizeof (char)*len_contact_esgwri);
    if (contact_routing_aux == NULL) {
        LM_ERR("no more pkg memory\n");
        return -1;
    }
    memset(contact_routing_aux, 0,len_contact_esgwri);
    pt_contact_routing.s = contact_routing_aux;
    pt_contact_routing.len = len_contact_esgwri - 1;

    pattern_contact_routing.s = "^(sips?):[+]*([-0-9]+)@";                
    pattern_contact_routing.len = strlen(pattern_contact_routing.s);
    replacement_contact_routing.s = "\\2";
    replacement_contact_routing.len = strlen(replacement_contact_routing.s);

    if (reg_replace(pattern_contact_routing.s, replacement_contact_routing.s, contact_routing, &pt_contact_routing) == 1) { 
        LM_INFO ("CONTEUDO TRANS REPLY ESGWRI %s \n",contact_routing);
        call_cell->esgwri = shm_malloc(sizeof (char)* len_contact_routing + 1);
        if (call_cell->esgwri == NULL) {
            LM_ERR("--------------------------------------------------no more shm memory\n");
            return -1;
        }
        memcpy(call_cell->esgwri, contact_routing, len_contact_routing -1);
        call_cell->esgwri[len_contact_routing -1] = 0; 
        call_cell->disposition = "processes"; 

        pkg_free(contact_routing_aux);
        pkg_free(contact_routing);

    }else{

        pattern_contact_ert.s = "^(sips?):([A-Z0-9.]*)@";                            
        pattern_contact_ert.len = strlen(pattern_contact_ert.s);
        replacement_contact_ert.s = "\\2";
        replacement_contact_ert.len = strlen(replacement_contact_ert.s);

        if (reg_replace(pattern_contact_ert.s, replacement_contact_ert.s, contact_routing, &pt_contact_routing) != 1) {
            LM_ERR("****** PATTERN LRO NAO OK \n");
            pkg_free(contact_routing_aux);
            pkg_free(contact_routing);                

            if (strlen(call_cell->lro) <= 1){
                pkg_free(call_cell->callid);
                pkg_free(call_cell->esqk);                            
                pkg_free(call_cell);               
            }
            return -1;
        }

        LM_INFO ("CONTEUDO TRANS REPLY ERT %.*s \n", pt_contact_routing.len, pt_contact_routing.s);
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

        LM_INFO ("CONTEUDO TRANS REPLY SRID %s \n",srid_aux);
        LM_INFO ("CONTEUDO TRANS REPLY RESN %s \n",resn_aux);
        LM_INFO ("CONTEUDO TRANS REPLY NPA %s \n",npa_aux); 
        int npa = atoi(npa_aux);
        int resn = atoi(resn_aux);
        int srid_len = strlen(srid_aux);

        call_cell->ert_npa = npa;
        call_cell->ert_resn = resn;
        call_cell->ert_srid = shm_malloc(sizeof (char)* srid_len + 1);
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


void insert_call_cell_in_list(ESCT *call_cell){

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

    return;

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
            
            if((info_call->esct->esqk)&&(strlen(info_call->esct->esqk) > 1)){
                shm_free (info_call->esct->esqk);
                LM_DBG(" ---  FREE INFO_CALL->ESQK");                                
            } 
            
            if(info_call->esct->callid){
                shm_free (info_call->esct->callid);
                LM_DBG(" ---  FREE INFO_CALL->CALLID");                                
            }  
            if((info_call->esct->lro)&&(strlen(info_call->esct->lro) > 1)){
                shm_free (info_call->esct->lro);
                LM_DBG(" ---  FREE INFO_CALL->LRO");                                  
            }
           
           
            if((info_call->esct->esgwri)&&(strlen(info_call->esct->esgwri) > 1)){
                shm_free (info_call->esct->esgwri);
                LM_DBG(" ---  FREE INFO_CALL->ESGW"); 
            } 

            
            if((info_call->esct->ert_srid)&&(strlen(info_call->esct->ert_srid) > 1)){
                LM_DBG(" ---  FREE INFO_CALL->ERT_SRID");              
                shm_free (info_call->esct->ert_srid);                                                    
            } 
            

            if((info_call->esct->result)&&(strlen(info_call->esct->result) > 1)){
                shm_free (info_call->esct->result);
                LM_DBG(" ---  FREE INFO_CALL->RESULT");                                 
            }
            
            
            
            shm_free (info_call->esct); 
        }
        shm_free (info_call);        
    }

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
