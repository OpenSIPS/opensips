/*
 * $Id$
 *
 * rls module - resource list server
 *
 * Copyright (C) 2007 Voice Sistem S.R.L.
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
 *  2007-09-11  initial version (Anca Vamanu)
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "../../ut.h"
#include "../../str.h"
#include "../../dprint.h"
#include "../../data_lump_rpl.h"
#include "../../parser/msg_parser.h"
#include "../../parser/parse_event.h"
#include "../../parser/parse_expires.h"
#include "../../parser/parse_cseq.h"
#include "../../parser/contact/parse_contact.h"
#include "../../parser/parse_rr.h"
#include "../tm/dlg.h"
#include "../presence/utils_func.h"
#include "../presence/hash.h"
#include "rls.h"
#include "notify.h"

typedef struct res_param
{
	xmlNodePtr list_node;
	db_res_t* db_result;
	str* cid_array;
}res_param_t;

int resource_uri_col=0, ctype_col, pres_state_col= 0,
	auth_state_col= 0, reason_col= 0;

str* constr_rlmi_doc(db_res_t* result, str* rl_uri, int version,
		xmlNodePtr rl_node, str** cid_array);
str* constr_multipart_body(db_res_t* result, str* cid_array, str bstr);

dlg_t* rls_notify_dlg(subs_t* subs);

void rls_notify_callback( struct cell *t, int type, struct tmcb_params *ps);


int send_full_notify(subs_t* subs, xmlNodePtr service_node, int version, str* rl_uri,
		unsigned int hash_code)
{
	str* rlmi_body= NULL;
	str* multipart_body= NULL;
	db_key_t query_cols[2], update_cols[2], result_cols[7];
	db_val_t query_vals[2], update_vals[2];
	db_res_t *result= NULL;
	int n_result_cols= 0, i;
	str bstr= {0, 0};
	str* cid_array= NULL;
	str rlsubs_did= {0, 0};

	LM_DBG("start\n");
	if(CONSTR_RLSUBS_DID(subs, &rlsubs_did) < 0)
	{
		LM_ERR("Failed to create did\n");
		return -1;
	}

	/* query in alfabetical order */
	query_cols[0]= &str_rlsubs_did_col;
	query_vals[0].type = DB_STR;
	query_vals[0].nul = 0;
	query_vals[0].val.str_val= rlsubs_did; 

	result_cols[resource_uri_col= n_result_cols++]= &str_resource_uri_col;
	result_cols[ctype_col= n_result_cols++]= &str_content_type_col;
	result_cols[pres_state_col= n_result_cols++]= &str_presence_state_col;
	result_cols[auth_state_col= n_result_cols++]= &str_auth_state_col;
	result_cols[reason_col= n_result_cols++]= &str_reason_col;
	
	if (rls_dbf.use_table(rls_db, &rlpres_table) < 0) 
	{
		LM_ERR("in use_table\n");
		goto error;
	}

	if(rls_dbf.query(rls_db, query_cols, 0, query_vals, result_cols,
					1, n_result_cols, &str_resource_uri_col, &result )< 0)
	{
		LM_ERR("in sql query\n");
		goto error;
	}
	if(result== NULL)
		goto error;

	rlmi_body= constr_rlmi_doc(result, rl_uri, version, service_node, &cid_array);
	if(rlmi_body== NULL)
	{
		LM_ERR("while constructing rlmi doc\n");
		goto error;
	}

	bstr.s= generate_string((int)time(NULL), BOUNDARY_STRING_LEN);
	if(bstr.s == NULL)
	{
		LM_ERR("failed to generate random string\n");
		goto error;
	}
	bstr.len = BOUNDARY_STRING_LEN;

	if(result->n> 0)
	{
		multipart_body= constr_multipart_body(result, cid_array, bstr);
		if(multipart_body== NULL)
		{
			LM_ERR("while constructing multipart body\n");
			goto error;
		}
		for(i = 0; i<result->n; i++)
		{
			if(cid_array[i].s)
				pkg_free(cid_array[i].s);
		}
	}
	pkg_free(cid_array);
	cid_array= NULL;
	rls_dbf.free_result(rls_db, result);
	result= NULL;

	if(agg_body_sendn_update(rl_uri, bstr, rlmi_body,
		multipart_body, subs, hash_code)< 0)
	{
		LM_ERR("in function agg_body_sendn_update\n");
		goto error;
	}

	/* update updated col in rlpres_table*/
	update_cols[0]= &str_updated_col;
	update_vals[0].type = DB_INT;
	update_vals[0].nul = 0;
	update_vals[0].val.int_val= NO_UPDATE_TYPE; 
	
	if (rls_dbf.use_table(rls_db, &rlpres_table) < 0) 
	{
		LM_ERR("in use_table\n");
		goto error;
	}
	if(rls_dbf.update(rls_db, query_cols, 0, query_vals, update_cols,
					update_vals, 1, 1)< 0)
	{
		LM_ERR("in sql update\n");
		goto error;
	}

	pkg_free(bstr.s);
	xmlFree(rlmi_body->s);
	pkg_free(rlmi_body);

	if(multipart_body)			
	{
		pkg_free(multipart_body->s);
		pkg_free(multipart_body);
	}
	pkg_free(rlsubs_did.s);

	return 0;
error:

	if(bstr.s)
		pkg_free(bstr.s);

	if(rlmi_body)
	{
		if(rlmi_body->s)
			xmlFree(rlmi_body->s);
		pkg_free(rlmi_body);
	}
	if(multipart_body)
	{
		if(multipart_body->s)
			pkg_free(multipart_body->s);
		pkg_free(multipart_body);
	}
	
	if(cid_array)
	{
		for(i= 0; i< result->n ; i++)
			if(cid_array[i].s)
				pkg_free(cid_array[i].s);
		pkg_free(cid_array);
	}
	if(result)
		rls_dbf.free_result(rls_db, result);
	if(rlsubs_did.s)
		pkg_free(rlsubs_did.s);
	return -1;
}

int agg_body_sendn_update(str* rl_uri, str bstr, str* rlmi_body,
		str* multipart_body, subs_t* subs, unsigned int hash_code)
{
	str cid;
	int len;
	str body= {0, 0};
	int init_len;
	int body_len;

	cid.s= generate_cid(rl_uri->s, rl_uri->len);
	if(cid.s == NULL)
	{
		LM_ERR("failed to generate cid\n");
		return -1;
	}
	cid.len = strlen(cid.s);

	len= 2*bstr.len+ 4+ 102+ cid.len+ 2+ rlmi_body->len+50+1;
	if(multipart_body)
		len+= multipart_body->len;
	
	init_len= len;

	body.s= (char*)pkg_malloc(len);
	if(body.s== NULL)
	{
		ERR_MEM(PKG_MEM_STR);
	}
	len=  sprintf(body.s, "--%.*s\r\n", bstr.len, bstr.s);
	len+= sprintf(body.s+ len , "Content-Transfer-Encoding: binary\r\n");
	len+= sprintf(body.s+ len , "Content-ID: <%.*s>\r\n", cid.len, cid.s);	
	len+= sprintf(body.s+ len , 
			"Content-Type: application/rlmi+xml;charset=\"UTF-8\"\r\n");
	len+= sprintf(body.s+ len, "\r\n"); /*blank line*/
	body_len = rlmi_body->len;
	if(rlmi_body->s[rlmi_body->len-1]== '\n')
		body_len--;
	if(rlmi_body->s[rlmi_body->len-1]== '\r')
		body_len--;
	memcpy(body.s+ len, rlmi_body->s, body_len);
	len+= body_len;
	len+= sprintf(body.s+ len, "\r\n\r\n"); /*blank line*/

	if(multipart_body)
	{
		memcpy(body.s+ len, multipart_body->s, multipart_body->len);
		len+= multipart_body->len;
	}
	len+= sprintf(body.s+ len, "--%.*s--\r\n", bstr.len, bstr.s);

	if(init_len< len)
	{
		LM_ERR("buffer size overflow init_size= %d\tlen= %d\n",init_len,len);
		goto error;
	}
	body.s[len]= '\0';
	body.len= len;

	/* send Notify */
	if(rls_send_notify(subs, &body, &cid, &bstr)< 0)
	{
		LM_ERR("when sending Notify\n");
		goto error;
	}
	pkg_free(body.s);
	body.s= NULL;
	
	if(subs->expires!= 0 && subs->status != TERMINATED_STATUS)
	{
		if(pres_update_shtable(rls_table, hash_code,subs, LOCAL_TYPE)< 0)
		{
			LM_ERR("updating in hash table\n");
			goto error;
		}
	}

	pkg_free(cid.s);
	return 0;

error:
	if(cid.s)
		pkg_free(cid.s);
	if(body.s)
		pkg_free(body.s);

	return -1;
}


int add_resource_instance(char* uri, xmlNodePtr resource_node,
		db_res_t* result, str* cid_array)
{
	xmlNodePtr instance_node= NULL;
	db_row_t *row;	
	db_val_t *row_vals;
	int i, cmp_code;
	char* auth_state= NULL;
	int contor= 0;
	str cid;
	int auth_state_flag;
	char* str_aux = NULL;

	for(i= 0; i< result->n; i++)
	{
		row = &result->rows[i];
		row_vals = ROW_VALUES(row);
		
		cmp_code= strncmp(row_vals[resource_uri_col].val.string_val, uri,
				strlen(uri));
		if(cmp_code> 0)
			break;

		if(cmp_code== 0)
		{
			contor++;
			instance_node= xmlNewChild(resource_node, NULL, 
					BAD_CAST "instance", NULL);
			if(instance_node== NULL)
			{
				LM_ERR("while adding instance child\n");
				goto error;
			}
		
			str_aux = generate_string(contor, 8);
			if(str_aux == NULL)
			{
				LM_ERR("failed to generate random string\n");
				goto error;
			}
			xmlNewProp(instance_node, BAD_CAST "id",
					BAD_CAST str_aux);
			pkg_free(str_aux);

			auth_state_flag= row_vals[auth_state_col].val.int_val;
			auth_state= get_auth_string(auth_state_flag );
			if(auth_state== NULL)
			{
				LM_ERR("bad authorization status flag\n");
				goto error;
			}
			xmlNewProp(instance_node, BAD_CAST "state", BAD_CAST auth_state);

			if(auth_state_flag & ACTIVE_STATE)
			{
				cid.s= generate_cid(uri, strlen(uri));
				if(cid.s == NULL)
				{
					LM_ERR("failed to generate cid\n");
					goto error;
				}
				cid.len= strlen(cid.s);
				cid_array[i]= cid;

				xmlNewProp(instance_node, BAD_CAST "cid", BAD_CAST cid.s);
			}
			else
			if(auth_state_flag & TERMINATED_STATE)
			{
				xmlNewProp(instance_node, BAD_CAST "reason", 
						BAD_CAST row_vals[reason_col].val.string_val);	
			}
		}
	}

	/* if record not found should not add a instance node */	
	return 0;
error:
	return -1;
}

int add_resource(char* uri, void* param)
{
	str* cid_array= ((res_param_t*)param)->cid_array;
	xmlNodePtr list_node= ((res_param_t*)param)->list_node;
	xmlNodePtr resource_node= NULL;
	db_res_t *result= ((res_param_t*)param)->db_result;

	LM_DBG("uri= %s\n", uri);
	resource_node= xmlNewChild(list_node, NULL, BAD_CAST "resource", NULL);
	if(resource_node== NULL)
	{
		LM_ERR("while adding new rsource_node\n");
		goto error;
	}
	xmlNewProp(resource_node, BAD_CAST "uri", BAD_CAST uri);

	if(add_resource_instance(uri, resource_node, result, cid_array)< 0)
	{
		LM_ERR("while adding resource instance node\n");
		goto error;
	}

	return 0;
error:
	return -1;
}

str* constr_rlmi_doc(db_res_t *result, str* rl_uri, int version,
		xmlNodePtr service_node, str** rlmi_cid_array)
{
	xmlDocPtr doc= NULL;
	xmlNodePtr list_node= NULL;
	str* rlmi_cont= NULL;
	int len; 
	char* uri;
	res_param_t param;
	str* cid_array= NULL;
	int n= result->n;

	LM_DBG("start\n");
	cid_array= (str*)pkg_malloc(n* sizeof(str));
	if(cid_array== NULL)
	{
		ERR_MEM(PKG_MEM_STR);
	}
	memset(cid_array, 0, n* sizeof(str));

	doc= xmlNewDoc(BAD_CAST "1.0");
	if(doc== NULL)
	{
		LM_ERR("while constructing new xml doc\n");
		goto error;
	}
	list_node= xmlNewNode(NULL, BAD_CAST "list");
	if(list_node== NULL)
	{
		LM_ERR("while creating new xml node\n");
		goto error;
	}
	uri= (char*)pkg_malloc(rl_uri->len+ 1);
	if(uri== NULL)
	{
		ERR_MEM(PKG_MEM_STR);
	}
	memcpy(uri, rl_uri->s, rl_uri->len);
	uri[rl_uri->len]= '\0';
	xmlNewProp(list_node, BAD_CAST "uri", BAD_CAST uri);
	pkg_free(uri);

	xmlNewProp(list_node, BAD_CAST "xmlns",
			BAD_CAST "urn:ietf:params:xml:ns:rlmi");
	xmlNewProp(list_node, BAD_CAST "version", BAD_CAST int2str(version-1, &len));
	xmlNewProp(list_node, BAD_CAST "fullState", BAD_CAST "true");

	xmlDocSetRootElement(doc, list_node);
	
	/* go through the list -- and add the appropriate 'resource' nodes*/
	
	param.list_node= list_node;
	param.db_result= result;
	param.cid_array= cid_array;

	if(process_list_and_exec(service_node, add_resource,(void*)(&param), 0)< 0)
	{
		LM_ERR("in process_list_and_exec function\n");
		goto error;
	}
	rlmi_cont= (str*)pkg_malloc(sizeof(str));
	if(rlmi_cont== NULL)
	{
		ERR_MEM(PKG_MEM_STR);
	}
	xmlDocDumpMemory(doc,(xmlChar**)(void*)&rlmi_cont->s,
			&rlmi_cont->len);

	*rlmi_cid_array= cid_array;
	
	xmlFreeDoc(doc);

	return rlmi_cont;

error:
	if(doc)
		xmlFreeDoc(doc);
	return NULL;	
}


str* constr_multipart_body(db_res_t* result, str* cid_array, str bstr)
{
	char* buf= NULL;
	int size= BUF_REALLOC_SIZE;
	int i, buf_len= 0;
	db_row_t *row;	
	db_val_t *row_vals;
	str cid={0, 0};
	str body= {0, 0};
	int add_len;
	str* multi_body= NULL;
	str ctype;
	
	LM_DBG("start\n");
	buf= pkg_malloc(size);
	if(buf== NULL)
	{
		ERR_MEM(PKG_MEM_STR);
	}

	for(i= 0; i< result->n; i++)
	{
		row = &result->rows[i];
		row_vals = ROW_VALUES(row);
	
		if(row_vals[auth_state_col].val.int_val!= ACTIVE_STATE)
			continue;

		ctype.s = (char*)row_vals[ctype_col].val.string_val;
		if(ctype.s == NULL)
		{
			LM_ERR("empty content type column\n");
			goto error;
		}
		ctype.len = strlen(ctype.s);
		body.s= (char*)row_vals[pres_state_col].val.string_val;
		body.len= strlen(body.s);

		cid= cid_array[i];
		if(cid.s== NULL)
		{
			LM_ERR("No cid found in array for uri= %s\n",
					row_vals[resource_uri_col].val.string_val);
			goto error;
		}
		APPEND_MULTIPART_BODY();
	}

	if(buf_len+ bstr.len+ 7> size )
		REALLOC_BUF;
	
	buf[buf_len]= '\0';
	
	multi_body= (str*)pkg_malloc(sizeof(str));
	if(multi_body== NULL)
	{
		ERR_MEM(PKG_MEM_STR);
	}

	multi_body->s= buf;
	multi_body->len= buf_len;

	return multi_body;

error:

	if(buf)
		pkg_free(buf);
	return NULL;
}

int rls_notify_extra_hdr(subs_t* subs, str* start_cid, str* bstr,
		str *hdr)
{
	int len;
	int lexpire_len;
	char* lexpire_s;
	char* p;

	lexpire_s = int2str(subs->expires, &lexpire_len);
	
	len = 14 /*Max-Forwards: */ + 4 /* valoarea */ + CRLF_LEN + 
		7 /*Event: */ + subs->event->name.len +4 /*;id=*/+ subs->event_id.len+
		CRLF_LEN + 10 /*Contact: <*/ + subs->local_contact.len + 1/*>*/ +
		((subs->sockinfo && subs->sockinfo->proto!=PROTO_UDP)?
		 15/*";transport=xxxx"*/:0) + CRLF_LEN +/*Subscription-State:*/ 20 +
		((subs->expires>0)?(15+lexpire_len):25) + CRLF_LEN + /*Require: */ 18
		+ CRLF_LEN + ((start_cid && bstr)?(/*Content-Type*/59 +
		/*start*/12 + start_cid->len + /*boundary*/12 + 
		bstr->len + CRLF_LEN):0);

	hdr->s = (char*)pkg_malloc(len);
	if(hdr->s== NULL)
	{
		LM_ERR("while allocating memory\n");
		return -1;
	}

	p = hdr->s;

	memcpy(p,"Max-Forwards: ", 14);
	p+= 14;
	len= sprintf(p, "%d", MAX_FORWARD);
	if(len<= 0)
	{
		LM_ERR("while printing in string\n");
		pkg_free(hdr->s);
		return -1;
	}
	p+= len;

	memcpy(p, CRLF, CRLF_LEN);
	p += CRLF_LEN;

	memcpy(p ,"Event: ", 7);
	p+= 7;
	memcpy(p, subs->event->name.s, subs->event->name.len);
	p+= subs->event->name.len;
	if(subs->event_id.len && subs->event_id.s) 
	{
 		memcpy(p, ";id=", 4);
 		p += 4;
 		memcpy(p, subs->event_id.s, subs->event_id.len);
 		p += subs->event_id.len;
 	}
	memcpy(p, CRLF, CRLF_LEN);
	p += CRLF_LEN;

	memcpy(p ,"Contact: <", 10);
	p += 10;
	memcpy(p, subs->local_contact.s, subs->local_contact.len);
	p +=  subs->local_contact.len;
	
	if (subs->sockinfo && subs->sockinfo->proto!=PROTO_UDP)
	{
		memcpy(p,";transport=",11);
		p += 11;
		p = proto2str(subs->sockinfo->proto, p);
		if (p == NULL)
		{
			LM_ERR("invalid proto\n");
			pkg_free(hdr->s);
			return -1;
		}
	}
	*(p++) = '>';

	memcpy(p, CRLF, CRLF_LEN);
	p += CRLF_LEN;

	if(subs->expires> 0 )
	{
		memcpy(p, "Subscription-State: active;expires=", 35);
		p += 35;
		memcpy(p, lexpire_s, lexpire_len);
		p+= lexpire_len;
	}
	else
	{
		memcpy(p, "Subscription-State: terminated;reason=timeout", 45);
		p += 45;
	}

	memcpy(p, CRLF, CRLF_LEN);
	p += CRLF_LEN;

	memcpy(p, "Require: eventlist", 18);
	p += 18;
	memcpy(p, CRLF, CRLF_LEN);
	p += CRLF_LEN;

	if(start_cid && bstr)
	{
		memcpy(p,"Content-Type: multipart/related;type=\"application/rlmi+xml\"", 59 );
		p += 59;
		memcpy(p, ";start=\"<", 9);
		p += 10;
		memcpy(p, start_cid->s, start_cid->len);
		p += start_cid->len;
		memcpy(p, ">\";boundary=\"", 13);
		p += 13;
		memcpy(p, bstr->s, bstr->len);
		p += bstr->len;
		*(p++) = '"';
		memcpy(p, CRLF, CRLF_LEN);
		p += CRLF_LEN;
	}
	hdr->len = p - hdr->s;

	return 0;
}

void rls_free_td(dlg_t* td)
{
		pkg_free(td->loc_uri.s);
		pkg_free(td->rem_uri.s);
		pkg_free(td);
}

int rls_send_notify(subs_t* subs, str* body, str* start_cid,
		str* bstr)
{
	dlg_t* td= NULL;
	str met= {"NOTIFY", 6};
	str str_hdr = {0, 0};
	dialog_id_t* cb_param= NULL;
	int size;
	int rt;

	LM_DBG("start\n");
	td= rls_notify_dlg(subs);
	if(td ==NULL)
	{
		LM_ERR("while building dlg_t structure\n");
		goto error;	
	}
	
	LM_DBG("constructed dlg_t struct\n");
	size= sizeof(dialog_id_t)+(subs->to_tag.len+ subs->callid.len+ 
			subs->from_tag.len) *sizeof(char);
	
	cb_param = (dialog_id_t*)shm_malloc(size);
	if(cb_param== NULL)
	{
		ERR_MEM(SHARE_MEM);
	}
	size= sizeof(dialog_id_t);
	
	cb_param->callid.s= (char*)cb_param + size;
	memcpy(cb_param->callid.s, subs->callid.s, subs->callid.len);
	cb_param->callid.len= subs->callid.len;
	size+= subs->callid.len;

	cb_param->to_tag.s= (char*)cb_param + size;
	memcpy(cb_param->to_tag.s, subs->to_tag.s, subs->to_tag.len);
	cb_param->to_tag.len= subs->to_tag.len;
	size+= subs->to_tag.len;

	cb_param->from_tag.s= (char*)cb_param + size;
	memcpy(cb_param->from_tag.s, subs->from_tag.s, subs->from_tag.len);
	cb_param->from_tag.len= subs->from_tag.len;
	
	LM_DBG("constructed cb_param\n");

	if(rls_notify_extra_hdr(subs, start_cid, bstr, &str_hdr) < 0)
	{
		LM_ERR("while building extra headers\n");
		goto error;
	}
	LM_DBG("str_hdr= %.*s\n", str_hdr.len, str_hdr.s);
	rt = tmb.t_request_within
		(&met,
		&str_hdr,
		body,
		td,
		rls_notify_callback,
		(void*)cb_param,
		NULL);

	if(rt < 0)
	{
		LM_ERR("in function tmb.t_request_within\n");
		goto error;	
	}

	pkg_free(str_hdr.s);
	rls_free_td(td);
	return 0;

error:
	if(td)
		rls_free_td(td);
	if(cb_param)
		shm_free(cb_param);
		
	if(str_hdr.s)
		pkg_free(str_hdr.s);
	
	return -1;
}

dlg_t* rls_notify_dlg(subs_t* subs)
{
	dlg_t* td=NULL;

	td= (dlg_t*)pkg_malloc(sizeof(dlg_t));
	if(td== NULL)
	{
		ERR_MEM(PKG_MEM_STR);
	}

	memset(td, 0, sizeof(dlg_t));
	td->loc_seq.value = subs->local_cseq;
	td->loc_seq.is_set = 1;

	td->id.call_id = subs->callid;
	td->id.rem_tag = subs->from_tag;
	td->id.loc_tag =subs->to_tag;
	if(uandd_to_uri(subs->to_user, subs->to_domain, &td->loc_uri)< 0)
	{
		LM_ERR("while constructing uri from user and domain\n");
		goto error;
	}
	
	if(uandd_to_uri(subs->from_user, subs->from_domain, &td->rem_uri)< 0)
	{
		LM_ERR("while constructing uri from user and domain\n");
		goto error;
	}

	if(subs->contact.len ==0 || subs->contact.s == NULL )
	{
		LM_DBG("BAD BAD contact NULL\n");
		td->rem_target = td->rem_uri;
	}
	else
		td->rem_target = subs->contact;

	if(subs->record_route.s && subs->record_route.len)
	{
		if(parse_rr_body(subs->record_route.s, subs->record_route.len,
			&td->route_set)< 0)
		{
			LM_ERR("in function parse_rr_body\n");
			goto error;
		}
	}

	td->state= DLG_CONFIRMED ;
	td->send_sock = subs->sockinfo;

	return td;

error:
	if(td)
	{
		if(td->loc_uri.s)
			pkg_free(td->loc_uri.s);
	
		if(td->rem_uri.s)
			pkg_free(td->rem_uri.s);
		pkg_free(td);
	}	

	return NULL;

}
void rls_notify_callback( struct cell *t, int type, struct tmcb_params *ps)
{
	if(ps->param==NULL || *ps->param==NULL || 
			((dialog_id_t*)(*ps->param)) == NULL)
	{
		LM_DBG("message id not received\n");
		return;
	}
	
	LM_DBG("completed with status %d [to_tag:"
			"%.*s]\n",ps->code,
			((dialog_id_t*)(*ps->param))->to_tag.len, 
			((dialog_id_t*)(*ps->param))->to_tag.s);

	if(ps->code >= 300)
	{
		/* delete from database table */
		db_key_t db_keys[2];
		db_val_t db_vals[2];
		unsigned int hash_code;
		subs_t subs;
		
		memset(&subs, 0, sizeof(subs_t));

		subs.to_tag= ((dialog_id_t*)(*ps->param))->to_tag;
		subs.from_tag= ((dialog_id_t*)(*ps->param))->from_tag;
		subs.callid= ((dialog_id_t*)(*ps->param))->callid;

		if (rls_dbf.use_table(rls_db, &rlsubs_table) < 0) 
		{
			LM_ERR("in use_table\n");
			goto done;
		}
		
		db_keys[0] =&str_to_tag_col;
		db_vals[0].type = DB_STR;
		db_vals[0].nul = 0;
		db_vals[0].val.str_val = subs.to_tag;

		db_keys[1] =&str_callid_col;
		db_vals[1].type = DB_STR;
		db_vals[1].nul = 0;
		db_vals[1].val.str_val = subs.callid;


		if (rls_dbf.delete(rls_db, db_keys, 0, db_vals, 2) < 0) 
			LM_ERR("cleaning expired messages\n");	

		/* delete from cache table */
		hash_code= core_hash(&subs.callid, &subs.to_tag , hash_size);

		if(pres_delete_shtable(rls_table,hash_code, subs.to_tag)< 0)
		{
			LM_ERR("record not found in hash table\n");
		}
	}	

done:	
	if(*ps->param !=NULL  )
		shm_free(*ps->param);
	return ;

}

/* support only for list - ignore resource-list children */
int process_list_and_exec(xmlNodePtr list_node, list_func_t function,
		void* param, int* cont_no)
{
	xmlNodePtr node;
	char* uri;

	LM_DBG("start\n");
	for(node= list_node->children; node; node= node->next)
	{
		if(xmlStrcasecmp(node->name,(unsigned char*)"entry")== 0)
		{
			uri= XMLNodeGetAttrContentByName(node, "uri");
			if(uri== NULL)
			{
				LM_ERR("when extracting entry uri attribute\n");
				return -1;
			}
			LM_DBG("uri= %s\n", uri);
			if(cont_no)
				*cont_no = *cont_no+1;
			if(function(uri, param)< 0)
			{
				LM_ERR(" infunction given as a parameter\n");
				xmlFree(uri);
				return -1;
			}
			xmlFree(uri);
		}
		else
		if(xmlStrcasecmp(node->name,(unsigned char*)"list")== 0)
			process_list_and_exec(node, function, param, cont_no);
	}
	return 0;

}

char* generate_string(int seed, int length)
{
    char* rstr;
	int r,i;

	rstr = (char*) pkg_malloc(length + 1);
	if(rstr == NULL) 
	{
		LM_ERR("no more memory\n");
		return NULL;
	}

	srand(seed);
		
	for(i=0; i<length; i++) 
	{
		r= rand() % ('z'- 'A') + 'A';
	    if(r>'Z' && r< 'a')
			r= '0'+ (r- 'Z');

		rstr[i] = r;
    }
	rstr[length]= '\0';

	return rstr;
}

char* generate_cid(char* uri, int uri_len)
{
	char* cid;
	int len;

	cid = (char*) pkg_malloc(uri_len + 30);
	if(cid == NULL)
	{
		LM_ERR("no more memory\n");
		return NULL;
	}

	len= sprintf(cid, "%d.%.*s.%d", (int)time(NULL), uri_len, uri, rand());
	cid[len]= '\0';

	return cid;
}

char* get_auth_string(int flag)
{
	switch(flag)
	{
		case ACTIVE_STATE:     return "active";
		case PENDING_STATE:    return "pending";
		case TERMINATED_STATE: return "terminated";
	}
	return NULL;
}

