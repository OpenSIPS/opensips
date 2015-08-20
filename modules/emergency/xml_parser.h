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


typedef struct parsed_xml_vpc {
	char* organizationname;
	char* hostname;
	char* nenaid;
	char* contact;
	char* certuri;
}NENA;

typedef struct parsed_xml_ert{
	char* selectiveRoutingID ;
	char* routingESN;
	char* npa;
}ERT;

typedef struct parsed_xml_resp{
	char* result;
	char* esgwri;
	char* esqk;
	char* lro;
	char* callid;
	char* datetimestamp;
	
	NENA *vpc;
	NENA *destination;
	ERT  *ert;
}PARSED;

typedef struct esct{
	NENA *source;
	NENA *vpc;
	char* esgwri;
	char* esgw;
	char* esqk;
	char* callid;
	char* ert_srid;
	int   ert_resn;
	int   ert_npa;
	char* datetimestamp;
	char* lro;
	char* disposition;
	char* result; 
	int   timeout;
}ESCT;

typedef struct node {
	ESCT *esct;
	struct node *next;
}NODE;


char* copy_str_between_tow_pointers(char* str_begin, char* str_end);
char* copy_str_between_tow_tags(char* tag_begin, char* str_total);
int check_str_between_init_tags( char* str_total);
int check_ectAck_init_tags( char* str_total);
PARSED* parse_xml(char* xml);
char* parse_xml_esct(char* xml);
int isNotBlank(char *str);
unsigned long findOutSize(ESCT* esct);
unsigned long findOutNenaSize(NENA* nena);
char* buildXmlFromModel(ESCT* esct);

