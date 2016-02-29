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
#include "sip_emergency.h"

const char *GEO_LOCATION_ROUTING = "Geolocation-Routing";
const char *GEO_LOCATION_ROUTING_YES = "yes";
const char *GEO_LOCATION = "Geolocation";
const char *LOCATION_TAG_BEGIN = "<location-key>";
const char *LOCATION_TAG_END = "</location-key>";
const char *NEW_LINE = "\n";

const char *CONTENT_TYPE_PIDF = "Content-Type: application/pidf+xml";
const char *PRESENCE_START = "<presence";
const char *PRESENCE_END = "/presence>";


#define PAI_SUFFIX			   ";user=phone;CBN="
#define PAI_SUFFIX_LEN		   (sizeof(PAI_SUFFIX)-1)
#define PAI_SUFFIX_II			";user=phone>\n"
#define PAI_SUFFIX_LEN_II		(sizeof(PAI_SUFFIX_II)-1) 

#define P_ASSERTED_HDR		   "P-Asserted-Identity: <sip:"
#define P_ASSERTED_HDR_LEN	   (sizeof(P_ASSERTED_HDR)-1)

#define CONTACT_HDR			 "Contact: <sips:"
#define CONTACT_HDR_LEN		 (sizeof(CONTACT_HDR)-1) 
#define CONTACT_MIDLE		   "?P-Asserted-Identity:=<sips:"
#define CONTACT_MIDLE_LEN	   (sizeof(CONTACT_MIDLE)-1) 
#define CONTACT_SUFFIX		  ";user=phone>"
#define CONTACT_SUFFIX_LEN	  (sizeof(CONTACT_SUFFIX)-1) 

#define MAXNUMBERLEN 31


struct lump *l;
struct rr_binds rr_api;

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


/* this function tries to find callback number (CBN)  in the given INVITE
- first tries to get from the PAI headers , then PPI , then RDID an finally tries the From header
*/
int found_CBN(struct sip_msg *msg, char** cbn_aux) {
	str cbn;
	str pattern, pattern_sip, replacement;
	int found_cbn;

	cbn.s = *cbn_aux;
	cbn.len = MAX_URI_SIZE;

	pattern.s = "tel:([+]*[-0-9]+)";
	pattern.len = strlen(pattern.s);

	pattern_sip.s = "sips?:([+]*[-0-9]+)";
	pattern_sip.len = strlen(pattern_sip.s);
	replacement.s = "\\1";
	replacement.len = strlen(replacement.s);

	found_cbn = 0;

	// First lookup CBN in P-Asserted-Identity header
	if (parse_pai_header(msg) == 0) {
		LM_DBG("****** PAI: %.*s\n", msg->pai->body.len, msg->pai->body.s);

		if (reg_replace(pattern.s, replacement.s, msg->pai->body.s, &cbn) == 1) {

			found_cbn = 1;
			LM_DBG("****** PATTERN OK\n");
			LM_DBG("****** REG_REPLACE: %.*s\n", cbn.len, cbn.s);		  
		} else {

			if (reg_replace(pattern_sip.s, replacement.s, msg->pai->body.s, &cbn) == 1) {
					found_cbn = 1;
					LM_DBG("****** PATTERN OK\n");
					LM_DBG("****** REG_REPLACE: %.*s\n", cbn.len, cbn.s);
			} else {
					memset(cbn.s, 0, MAX_URI_SIZE);
					LM_ERR("****** PATTERN NAO OK \n");
			}

		}

	}

	// Second lookup CBN in P-Preferred-Identity header
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

	// After lookup CBN in Remote-Party_ID header
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

	// Finally lookup CBN in From header
	if (found_cbn == 0) {

		if (parse_from_header(msg) == 0) {
			LM_DBG("****** FROM: %.*s\n", msg->from->body.len, msg->from->body.s);

			if (reg_replace(pattern.s, replacement.s, msg->from->body.s, &cbn) == 1) {
				found_cbn = 1;
				LM_DBG("****** PATTERN OK\n");
				LM_DBG("****** REG_REPLACE: %.*s\n", cbn.len, cbn.s);
			} else {

				if (reg_replace(pattern_sip.s, replacement.s, msg->from->body.s, &cbn) == 1) {
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
			return -1;		   
		}

	}

	return 1;
}

/* get CALLID header fro INVITE
*/
int get_callid_header(struct sip_msg *msg, char** callidHeader) {
	char* code;
	char* p;
	int len;

	if (!msg->callid && ((parse_headers(msg, HDR_CALLID_F, 0) == -1) || !msg->callid)) {
		LM_ERR("Message has no Call-ID header\n");
		return -1;
	}
	LM_DBG(" -----------CALL ID HEADER %.*s \n \n", msg->callid->body.len, msg->callid->body.s);
	code = msg->callid->body.s;
	len = msg->callid->body.len;
	p = memchr(code, '@', len);
	if (p) {
		len = p - code;
	}
	LM_DBG(" -----------LEN without after @ in CALLID HEADER %d \n \n", len);
	*callidHeader = pkg_malloc(sizeof (char) * len + 1);
	memset(*callidHeader, '\0', len + 1);
	strncpy(*callidHeader, msg->callid->body.s, len);
	LM_DBG(" -----------CALL ID extract after @ in CALLID HEADER %s \n \n", *callidHeader);
	return 1;
}


// get ip address of opensips server in port that receive INVITE
int get_ip_socket(struct sip_msg *msg, char** saddr){

	char *socket;
	struct socket_info** list;
	struct socket_info* si;

	list = get_sock_info_list(msg->rcv.proto);
	if (list == NULL) {
		LM_ERR("ERROR in SOCKET\n");
		return -1;
	}

	si = *list;
	*saddr = NULL;

	while (si) {
		if (si->port_no == msg->rcv.dst_port) {
			socket = pkg_malloc(si->address_str.len + si->port_no_str.len + 3);
			if (socket == NULL) {
				LM_ERR("no more pkg memory\n");
				return -1;
			}

			*saddr = socket;
			*socket = '@';
			socket++;
			memcpy(socket, si->address_str.s, si->address_str.len);
			socket = socket + si->address_str.len;
			*socket = ':';
			socket++;
			memcpy(socket, si->port_no_str.s, si->port_no_str.len);
			socket = socket + si->port_no_str.len;
			*socket = 0;

			LM_INFO(" --- SERVER = %s \n \n", *saddr);
			break;
		}
		si = si->next;
	}  
	if (*saddr == NULL) {
		LM_ERR("failed in found ip listen\n");
		return -1;
	}

return 1;

}


/* Includes the headers to the INVITE
*   - puts the header PAI with the data:
*	   - esqk@ip_opensips:phone=call_back_number
*   - adds record_route to the INVIE for the opensips be notified when the call ends
*/
int add_hdr_rpl(struct esct *call_cell, struct sip_msg *msg) {
	char *s = "", *p = ""; 
	int len = 0;
	int rp_addr_len;
	char *rp_addr = "@rp.com";  
	LM_DBG(" --- F (CALLBACK) \n \n");
	static str new_header;
	struct lump_rpl *hdr_lump;
	int vsp_addr_len;
	char *vsp_addr = "@vsp.com"; 
	int q = 0;

	// get source ip address that send INVITE
	vsp_addr = ip_addr2a(&msg->rcv.src_ip);
	vsp_addr_len = strlen(vsp_addr); 

	// get ip address of opensips server in port that receive INVITE
	if (get_ip_socket(msg, &rp_addr) == -1)
		return -1;
	rp_addr_len = strlen(rp_addr);

	if (call_cell->esgwri != NULL && strlen(call_cell->esgwri) > 0) {

		len = CONTACT_HDR_LEN + strlen(call_cell->esqk) + strlen(call_cell->esgwri) + rp_addr_len + CONTACT_SUFFIX_LEN + CONTACT_MIDLE_LEN + 9;

		s = pkg_malloc(len + 1);
		if (s == NULL) {
			LM_ERR("no more pkg memory\n");
			pkg_free(rp_addr);
			return -1;
		}

		p = s;
		memcpy(p, CONTACT_HDR, CONTACT_HDR_LEN);
		p += CONTACT_HDR_LEN;
		memcpy(p, call_cell->esgwri, strlen(call_cell->esgwri));
		p += strlen(call_cell->esgwri);
		memcpy(p, CONTACT_MIDLE, CONTACT_MIDLE_LEN);
		p += CONTACT_MIDLE_LEN; 
		*p = '+';
		p++;
		*p = '1';   
		p++; 
		*p = '-';   
		p++;	   
		memcpy(p, call_cell->esqk, strlen(call_cell->esqk));
		p += strlen(call_cell->esqk); 
		memcpy(p, rp_addr, rp_addr_len);
		p += rp_addr_len; 
		memcpy(p, CONTACT_SUFFIX, CONTACT_SUFFIX_LEN);
		p += CONTACT_SUFFIX_LEN;
		*p = '>';
		p++;
		*p = ';';
		p++;
		*p = 'q';
		p++;
		*p = '=';
		p++;
		*p = '1';
		p++; 
		*p = '\n';
		p++;	  
		*p = 0;

		LM_DBG(" --- NEW HEADER = %s \n \n", s);
		LM_DBG(" --- NEW HEADER = %d \n \n", len); 

		new_header.s = s;
		new_header.len = len;

		hdr_lump = add_lump_rpl( msg, new_header.s, new_header.len, LUMP_RPL_HDR );
		if ( !hdr_lump ) {
			LM_ERR("failed to add hdr lump\n");
			return -1;
		}

		q = 1;
		pkg_free(s);

	}

	pkg_free(rp_addr);

	if (call_cell->lro != NULL){

		len = CONTACT_HDR_LEN + strlen(call_cell->lro) + vsp_addr_len + CONTACT_SUFFIX_LEN + 5 + q*4;
		s = pkg_malloc(sizeof (char)*len + 1);
		if (s == NULL) {
			LM_ERR("no more pkg memory\n");
			return -1;
		}

		p = s;
		memcpy(p, CONTACT_HDR, CONTACT_HDR_LEN);
		p += CONTACT_HDR_LEN;
		*p = '+';
		p++;
		*p = '1';   
		p++; 
		*p = '-';   
		p++;
		memcpy(p, call_cell->lro, strlen(call_cell->lro));
		p += strlen(call_cell->lro); 
		*p = '@';
		p++;				   
		memcpy(p, vsp_addr, vsp_addr_len);
		p += vsp_addr_len; 
		memcpy(p, CONTACT_SUFFIX, CONTACT_SUFFIX_LEN);
		p += CONTACT_SUFFIX_LEN;
		if (q == 1){
			*p = ';';
			p++;
			*p = 'q';
			p++;
			*p = '=';
			p++;
			*p = '2';
			p++; 
		}
		*p = '\n';
		p++; 
		*p = 0;


		LM_DBG(" --- NEW HEADER = %s \n \n", s);
		LM_DBG(" --- NEW HEADER = %d \n \n", len); 

		new_header.s = s;
		new_header.len = len;

		hdr_lump = add_lump_rpl( msg, new_header.s, new_header.len, LUMP_RPL_HDR );
		if ( !hdr_lump ) {
			LM_ERR("failed to add hdr lump\n");
			pkg_free(s);
			return -1;
		}

		pkg_free(s);
	}

	return 1;
}

/* Includes the headers to the INVITE
*   - puts the header PAI with the data:
*	   - esqk@ip_opensips:phone=call_back_number
*   - adds record_route to the INVIE for the opensips be notified when the call ends
*/
int add_headers(char *esqk, struct sip_msg *msg, str cbn) {
	char *s, *p;
	int len;
	int s_addr_len;
	char *s_addr = "@vsp.com";
	LM_DBG(" --- F (CALLBACK) \n \n");
	int resp = 1;

	// get ip address of opensips server in port that receive INVITE 
	if (get_ip_socket(msg, &s_addr) == -1){
		pkg_free(cbn.s);
		return -1;
	}

	s_addr_len = strlen(s_addr);

	// if package has already PAI header that delete this header
	if (msg->pai) {
		LM_INFO("PAI: [%.*s]\n", msg->pai->body.len, msg->pai->body.s);
		LM_INFO("PAI: %d \n", msg->pai->len); 


		l = del_lump( msg, msg->pai->name.s - msg->buf, msg->pai->len, HDR_PAI_T);
		 if (l==NULL) {
			LM_ERR("failed to add del lump\n");
			resp = -1;
			goto end;
		}

	}

	l = anchor_lump(msg, msg->from->body.s+msg->from->body.len-msg->buf+1,
						HDR_USERAGENT_T);
	if (l == NULL) {
		LM_ERR("failed to create anchor lump\n");
		resp = -1;
		goto end;
	}

	len = P_ASSERTED_HDR_LEN + strlen(esqk) + s_addr_len + PAI_SUFFIX_LEN + cbn.len + 2;

	s = pkg_malloc(sizeof (char)*len + 1);
	if (s == NULL) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}

	LM_INFO(" --- CBN_NUMBER = %.*s \n \n", cbn.len, cbn.s);
	LM_INFO(" --- CBN_NUMBER_LEN = %d \n \n", cbn.len);

	p = s;
	memcpy(p, P_ASSERTED_HDR, P_ASSERTED_HDR_LEN);
	p += P_ASSERTED_HDR_LEN;
	*p = '+';
	p++;
	*p = '1';   
	p++;
	memcpy(p, esqk, strlen(esqk));
	p += strlen(esqk);
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
		resp = -1;
		goto end;
	}

	rr_api.record_route(msg, NULL);
	resp = 1;
end:
	pkg_free(cbn.s);
	pkg_free(s_addr);
	return resp;
}


/* Includes the headers to the INVITE
*   - puts the header PAI with the data:
*	   - esqk@ip_opensips:phone=call_back_number
*   - adds record_route to the INVIE for the opensips be notified when the call ends
*/
int add_hdr_PAI(struct sip_msg *msg, str cbn) {
	char *s, *p;
	struct lump *l;
	int len;
	int s_addr_len;
	char *s_addr = "@vsp.com";
	LM_DBG(" --- F (CALLBACK) \n \n");
	int resp;

	// obtem o endereço ip do opensips que atende na portaque recebeu o INVITE 
	if (get_ip_socket(msg, &s_addr) == -1){
		pkg_free(cbn.s);
		return -1;
	}
	s_addr_len = strlen(s_addr);

	// if package has already PAI header that delete this header
	if (msg->pai) {
		LM_DBG("PAI: [%.*s]\n", msg->pai->body.len, msg->pai->body.s);

		l = del_lump( msg, msg->pai->name.s - msg->buf, msg->pai->len, HDR_PAI_T);
		if (l==NULL) {
			resp = -1;
			goto end;
		}

	}

	l = anchor_lump(msg, msg->from->body.s+msg->from->body.len-msg->buf+2,
						HDR_USERAGENT_T);
	if (l == NULL) {
		resp = -1;
		goto end;
	}

	len = P_ASSERTED_HDR_LEN + s_addr_len + PAI_SUFFIX_LEN_II + cbn.len;

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
	memcpy(p, cbn.s, cbn.len); 
	p += cbn.len;	   
	memcpy(p, s_addr, s_addr_len);
	p += s_addr_len;
	memcpy(p, PAI_SUFFIX_II, PAI_SUFFIX_LEN_II);
	p += PAI_SUFFIX_LEN_II;
	*p = 0;

	l = insert_new_lump_after(l, s, len, HDR_PAI_T);
	if (l == NULL) {
		pkg_free(s);
		LM_ERR("failed to insert new lump\n");
		resp = -1;
		goto end;
	}

	//rr_api.record_route(msg, NULL);
	resp = 1;
end:
	pkg_free(cbn.s);
	pkg_free(s_addr);
	return resp;
}


/* find the body with the type Content-Type: application/pidf+xml 
*  in the INVITE that has multi-body
*/
int find_body_pidf(struct sip_msg *msg, char** pidf_body) {

	struct part* mbody_part;
	struct multi_body *mbody;
	char *body_start, *body_end;
	char *body_aux;
	int size_body = 0;
	int cont = 0;
	UNUSED(cont);

	LM_DBG(" --- FIND PIDF BODY \n \n");
	mbody = get_all_bodies(msg);
	if (mbody == NULL) {
		LM_ERR("Failed to get bodies\n");
		return -1;
	}


	mbody_part = mbody->first;
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
		*pidf_body = "";	   
	}
	LM_DBG(" --- FIND PIDF BODY  %s \n \n", *pidf_body);

	return 1;
}


/* this function is used to make Opensips play the role of a "Call server"in the scenarios I and II
*  forward the INVITE to the Routing Proxy(scenarios II) or to Redirect(scenarios III)
*/
int proxy_request(struct sip_msg *msg,char *call_server_hostname) {
	char* ack_uri;
	char *ack_aux;
	int   size_new_uri;
	
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
	LM_INFO(" ---NEW_URI: %s \n\n", ack_uri);
	LM_INFO(" ---NEW_URI -TAM : %d \n\n", size_new_uri);
	
	if(new_uri_proxy(msg, ack_uri) == -1){
		LM_ERR(" ---ERRO EM NEW_URI_PROXY");
		return -1;
	}

	pkg_free(ack_aux);
	
	return 1;
}


/* forward request to new_uri
*/
int new_uri_proxy(struct sip_msg *req_msg, char* new_uri ){

	int new_uri_len;
	
	LM_INFO("NEW_URI_PROXY %s\n", new_uri);   
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


/* extract contact headers from reply 300 or 302
*/
int extract_contact_hdrs(struct sip_msg *reply, char **contact_esgwri, char **contact_lro) {

	struct hdr_field *contact_hdr;	
	struct hdr_field *contact_hdr_II;

	LM_INFO ("TRANS REPLY %.*s \n", reply->first_line.u.reply.reason.len, reply->first_line.u.reply.reason.s); 
	LM_INFO ("TRANS REPLY CODE%d \n", reply->first_line.u.reply.statuscode);

	// check if is 300/302 reply
	if ((reply->first_line.u.reply.statuscode != 300)&&(reply->first_line.u.reply.statuscode != 302)){
		LM_ERR("NO redirect response\n");
		return -1;		
	}

	if (parse_headers(reply, HDR_EOH_F, 0) == -1) {
		LM_ERR("NO HEADER header\n");
		return -1;
	}
	// verify if exist contact headers
	if (reply->contact==0) {
		LM_DBG("contact hdr not found in sh_rpl\n");
		return -1;
	}
	contact_hdr = reply->contact;
	LM_INFO ("TRANS REPLY %.*s \n", contact_hdr->body.len, contact_hdr->body.s);   
	// verify if exist another contact header
	if (contact_hdr->sibling != NULL){
		contact_hdr_II =  contact_hdr->sibling;
		LM_INFO ("TRANS REPLY II %.*s \n", contact_hdr_II->body.len, contact_hdr_II->body.s); 
	}else{
		contact_hdr_II = NULL;
	}
	// match de contact headers with information about esgwri and lro
	if (strstr(contact_hdr->body.s, "P-Asserted_Identity") != NULL){
		LM_INFO("CONTACT_HDR %d \n", contact_hdr->body.len);
		*contact_esgwri = pkg_malloc(sizeof (char)*contact_hdr->body.len + 1);
		*contact_esgwri[contact_hdr->body.len] = 0;
		memcpy(*contact_esgwri,contact_hdr->body.s,contact_hdr->body.len);
		if (contact_hdr_II != NULL){
			LM_INFO("CONTACT_HDR %d \n", contact_hdr_II->body.len);			
			*contact_lro = pkg_malloc(sizeof (char)*contact_hdr_II->body.len + 1);
			*contact_lro[contact_hdr_II->body.len] = 0;		  
			memcpy(*contact_lro,contact_hdr_II->body.s,contact_hdr_II->body.len);
		}	 

	}else{
		if (contact_hdr_II != NULL){
			if (strstr(contact_hdr_II->body.s, "P-Asserted_Identity") != NULL){
				*contact_esgwri = pkg_malloc(sizeof (char)*contact_hdr_II->body.len + 1);
				*contact_esgwri[contact_hdr_II->body.len] = 0;
				memcpy(*contact_esgwri,contact_hdr_II->body.s,contact_hdr_II->body.len);

				*contact_lro = pkg_malloc(sizeof (char)*contact_hdr->body.len + 1);
				*contact_lro[contact_hdr->body.len] = 0;
				memcpy(*contact_lro,contact_hdr->body.s,contact_hdr->body.len);  
			}else{  
				return -1;
			}
		}else{
			*contact_lro = pkg_malloc(sizeof (char)*contact_hdr->body.len + 1);
			*contact_lro[contact_hdr->body.len] = 0;
			memcpy(*contact_lro,contact_hdr->body.s,contact_hdr->body.len);		
		}
	}
	LM_INFO ("TRANS LRO %s \n", *contact_lro);
	LM_INFO ("TRANS ESGWRI %s \n", *contact_esgwri); 

	return 1; 

}
