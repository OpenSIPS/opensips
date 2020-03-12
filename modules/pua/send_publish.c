/*
 * pua module - presence user agent module
 *
 * Copyright (C) 2006 Voice Sistem S.R.L.
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
 *  2006-11-29  initial version (Anca Vamanu)
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/parser.h>
#include <time.h>

#include "../../mem/mem.h"
#include "../../dprint.h"
#include "../../parser/parse_expires.h"
#include "../../dprint.h"
#include "../../mem/shm_mem.h"
#include "../../parser/msg_parser.h"
#include "../../str.h"
#include "../tm/tm_load.h"
#include "../presence/hash.h"
#include "pua.h"
#include "hash.h"
#include "send_publish.h"
#include "pua_callback.h"
#include "event_list.h"

/**
 * !! IMPORTANT !!
 *
 * - MUST be called with lock grabbed on "hash_index"
 * - This lock is _guaranteed_ to be released upon return
 * - DO NOT rely on "presentity" anymore after calling this function
 */
int send_publish_int(ua_pres_t *presentity, publ_info_t* publ,
		pua_event_t* ev, int hash_index);

str* publ_build_hdr(int expires, pua_event_t* ev, str* content_type, str* etag,
		str* extra_headers, int is_body)
{
	static char buf[3000];
	str* str_hdr = NULL;
	char* expires_s = NULL;
	int len = 0;
	str ctype;

	str_hdr =(str*)pkg_malloc(sizeof(str));
	if(str_hdr== NULL)
	{
		LM_ERR("no more memory\n");
		return NULL;
	}
	str_hdr->s = buf;
	str_hdr->len= 0;

	memcpy(str_hdr->s+ str_hdr->len ,"Event: ", 7);
	str_hdr->len+= 7;
	memcpy(str_hdr->s+ str_hdr->len, ev->name.s, ev->name.len);
	str_hdr->len+= ev->name.len;
	memcpy(str_hdr->s+str_hdr->len, CRLF, CRLF_LEN);
	str_hdr->len += CRLF_LEN;

	memcpy(str_hdr->s+str_hdr->len ,"Expires: ", 9);
	str_hdr->len += 9;

	if( expires != 0 )
	{
		expires++;
	}
	expires_s = int2str(expires, &len);

	memcpy(str_hdr->s+str_hdr->len, expires_s, len);
	str_hdr->len+= len;
	memcpy(str_hdr->s+str_hdr->len, CRLF, CRLF_LEN);
	str_hdr->len += CRLF_LEN;

	if(etag)
	{
		LM_DBG("UPDATE_TYPE [etag]= %.*s\n", etag->len, etag->s);
		memcpy(str_hdr->s+str_hdr->len,"SIP-If-Match: ", 14);
		str_hdr->len += 14;
		memcpy(str_hdr->s+str_hdr->len, etag->s, etag->len);
		str_hdr->len += etag->len;
		memcpy(str_hdr->s+str_hdr->len, CRLF, CRLF_LEN);
		str_hdr->len += CRLF_LEN;
	}
	if(is_body)
	{
		if(content_type== NULL || content_type->s== NULL || content_type->len== 0)
		{
			ctype= ev->content_type; /* use event default value */
		}
		else
		{
			ctype.s=   content_type->s;
			ctype.len= content_type->len;
		}

		memcpy(str_hdr->s+str_hdr->len,"Content-Type: ", 14);
		str_hdr->len += 14;
		memcpy(str_hdr->s+str_hdr->len, ctype.s, ctype.len);
		str_hdr->len += ctype.len;
		memcpy(str_hdr->s+str_hdr->len, CRLF, CRLF_LEN);
		str_hdr->len += CRLF_LEN;
	}

	if(extra_headers && extra_headers->s && extra_headers->len)
	{
		memcpy(str_hdr->s+str_hdr->len,extra_headers->s , extra_headers->len);
		str_hdr->len += extra_headers->len;
	}
	str_hdr->s[str_hdr->len] = '\0';

	return str_hdr;
}

#define PUA_PARSE_PRES_ID(id, hi, li) do { \
	li = id / HASH_SIZE;\
	hi = id % HASH_SIZE;\
} while(0)

publ_info_t* construct_pending_publ(ua_pres_t* presentity)
{
	publ_info_t* p;
	publ_t* pending_publ;
	int size;

	pending_publ = presentity->pending_publ;

	if(!presentity->pres_uri)
	{
		LM_ERR("Wrong parameter - empty pres_uri or content_type filed\n");
		return 0;
	}
	size = sizeof(publ_info_t) + sizeof(str) + presentity->pres_uri->len+
		pending_publ->content_type.len;
	if(pending_publ->body.s)
		size+= sizeof(str) + pending_publ->body.len;
	if(pending_publ->extra_headers.s)
		size+= sizeof(str) + pending_publ->extra_headers.len;
	if(presentity->outbound_proxy)
		size+= presentity->outbound_proxy->len;

	p = (publ_info_t*)pkg_malloc(size);
	if(p == NULL)
	{
		LM_ERR("No more memory\n");
		return 0;
	}
	memset(p, 0, size);
	size = sizeof(publ_info_t);

	if(pending_publ->body.s)
	{
		p->body = (str*)((char*)p + size);
		size+= sizeof(str);
		p->body->s = (char*)p + size;
		memcpy(p->body->s, pending_publ->body.s, pending_publ->body.len);
		p->body->len = pending_publ->body.len;
		size+= pending_publ->body.len;
	}

	p->content_type.s = (char*)p + size;
	memcpy(p->content_type.s, pending_publ->content_type.s, pending_publ->content_type.len);
	p->content_type.len = pending_publ->content_type.len;
	size+= pending_publ->content_type.len;

	p->pres_uri = (str*)((char*)p + size);
	size+= sizeof(str);
	p->pres_uri->s = (char*)p + size;
	memcpy(p->pres_uri->s, presentity->pres_uri->s, presentity->pres_uri->len);
	p->pres_uri->len = presentity->pres_uri->len;
	size+= presentity->pres_uri->len;

	if(pending_publ->extra_headers.s)
	{
		p->extra_headers = (str*)((char*)p + size);
		size+= sizeof(str);
		p->extra_headers->s = (char*)p + size;
		memcpy(p->extra_headers->s, pending_publ->extra_headers.s, pending_publ->extra_headers.len);
		p->extra_headers->len = pending_publ->extra_headers.len;
		size+= pending_publ->extra_headers.len;
	}

	if(presentity->outbound_proxy)
	{
		p->outbound_proxy.s = (char*)p + size;
		memcpy(p->outbound_proxy.s, presentity->outbound_proxy->s, presentity->outbound_proxy->len);
		p->outbound_proxy.len = presentity->outbound_proxy->len;
		size+= presentity->outbound_proxy->len;
	}

	p->expires = pending_publ->expires;
	p->cb_param = pending_publ->cb_param;

	return p;
}


void publ_expired_cback_func(struct cell *t, int type, struct tmcb_params *ps)
{
	ua_pres_t presentity;
	struct sip_msg* msg;

	if (ps->param==NULL) {
		LM_DBG("NULL callback parameter\n");
		return;
	}
	LM_DBG("cback param = %p\n", *ps->param);

	if ( (msg=ps->rpl)==NULL) {
		LM_ERR("no reply message found\n");
		return;
	}
	if (parse_headers(msg,HDR_EOH_F, 0)==-1 ) {
		LM_ERR("parsing headers\n");
		return;
	}
	if (msg->expires== NULL || msg->expires->body.len<= 0) {
		LM_ERR("No Expires header found\n");
		return;
	}
	if (parse_expires(msg->expires) < 0) {
		LM_ERR("cannot parse Expires header\n");
		return;
	}

	/* use a dummy presentity structure */
	memset( &presentity, 0, sizeof(presentity) );
	/* copy the MI async handler */
	presentity.cb_param = *ps->param;
	presentity.flag = MI_ASYN_PUBLISH;
	run_pua_callbacks( &presentity, ps->rpl);
	/* unlink the MI handler once triggered */
	*ps->param = NULL;

	return;
}


void publ_cback_func(struct cell *t, int type, struct tmcb_params *ps)
{
	struct hdr_field* hdr= NULL;
	struct sip_msg* msg= NULL;
	ua_pres_t* presentity= NULL;
	unsigned int lexpire= 0;
	str etag;
	unsigned int hash_index, local_index;
	unsigned long pres_id;

	if(ps->param == NULL)
	{
		LM_ERR("NULL parameter\n");
		return;
	}

	msg= ps->rpl;
	if(msg == NULL)
	{
		LM_ERR("no reply message found\n");
		return;
	}
	LM_DBG("cback param = %lu\n", (unsigned long)*ps->param);

	pres_id = (unsigned long)*ps->param;
	PUA_PARSE_PRES_ID(pres_id, hash_index, local_index);
	LM_DBG("hash_index= %u, local_index= %u\n", hash_index, local_index);

	if(!find_htable(hash_index, local_index))
	{
		LM_ERR("No record found\n");
		return;
	}

	if(msg== FAKED_REPLY)
	{
		LM_DBG("FAKED_REPLY\n");
		goto done;
	}

	if( ps->code>= 300 )
	{
		delete_htable(hash_index, local_index);
		goto done;
	}

	if( parse_headers(msg,HDR_EOH_F, 0)==-1 )
	{
		LM_ERR("parsing headers\n");
		return;
	}
	if(msg->expires== NULL || msg->expires->body.len<= 0)
	{
		LM_ERR("No Expires header found\n");
		return;
	}
	if (!msg->expires->parsed && (parse_expires(msg->expires) < 0))
	{
		LM_ERR("cannot parse Expires header\n");
		return;
	}
	lexpire = ((exp_body_t*)msg->expires->parsed)->val;
	LM_DBG("lexpire= %u\n", lexpire);

	if(lexpire == 0)
	{
		delete_htable(hash_index, local_index);
		goto done;
	}
	hdr = get_header_by_static_name( msg, "SIP-ETag");
	if( hdr==NULL ) /* must find SIP-Etag header field in 200 OK msg*/
	{
		LM_ERR("no SIP-ETag header field found\n");
		return;
	}
	etag= hdr->body;

	update_htable(hash_index, local_index, lexpire, &etag, 0);

done:
	lock_get(&HashT->p_records[hash_index].lock);
	presentity = get_htable_safe(hash_index, local_index);
	if(!presentity)
	{
		LM_DBG("Record not found\n");
		lock_release(&HashT->p_records[hash_index].lock);
		return;
	}

	if(presentity->ua_flag == REQ_OTHER)
	{
		run_pua_callbacks(presentity, msg);
		presentity->cb_param = NULL;
	}
	presentity->waiting_reply = 0;

	/* attempt to send out a single queued PUBLISH */
	while (presentity->pending_publ)
	{
		publ_t* pending_publ = presentity->pending_publ;
		publ_info_t* publ = construct_pending_publ(presentity);

		/* if unable to construct the info, simply drop this PUBLISH */
		if(publ == NULL)
		{
			LM_ERR("Failed to create publish record\n");
			presentity->pending_publ = pending_publ->next;
			shm_free(pending_publ);
			continue;
		}

		presentity->waiting_reply = 1;
		presentity->pending_publ  = pending_publ->next;

		send_publish_int(presentity, publ, get_event(presentity->event),
				presentity->hash_index);

		shm_free(pending_publ);
		pkg_free(publ);

		return;
	}

	lock_release(&HashT->p_records[hash_index].lock);
}

publ_t* build_pending_publ(publ_info_t* publ)
{
	publ_t* p;
	int size;

	size = sizeof(publ_t) + ((publ->body)?publ->body->len:0) +
		publ->content_type.len +
		((publ->extra_headers)?publ->extra_headers->len:0);
	p = (publ_t*)shm_malloc(size);
	if(p == NULL)
	{
		LM_ERR("No more share memory\n");
		return 0;
	}
	memset(p, 0, size);
	size = sizeof(publ_t);
	if(publ->body && publ->body->s)
	{
		p->body.s = (char*)p + size;
		memcpy(p->body.s, publ->body->s, publ->body->len);
		p->body.len = publ->body->len;
		size+= publ->body->len;
	}
	if(publ->extra_headers && publ->extra_headers->s)
	{
		p->extra_headers.s = (char*)p + size;
		memcpy(p->extra_headers.s, publ->extra_headers->s, publ->extra_headers->len);
		p->extra_headers.len = publ->extra_headers->len;
		size+= publ->extra_headers->len;
		LM_DBG("saved [%.*s]\n", p->extra_headers.len, p->extra_headers.s);
	}
	CONT_COPY(p, p->content_type, publ->content_type);
	p->expires = publ->expires;
	p->cb_param = publ->cb_param;

	return p;
}


int send_publish_int(ua_pres_t* presentity, publ_info_t* publ, pua_event_t* ev,
		int hash_index)
{
	unsigned long pres_id= 0;
	int ret = ERR_PUBLISH_GENERIC;
	char etag_buf[256];
	char tuple_buf[128];
	str tuple_id= {0, 0};
	str etag= {0, 0};
	int ver= 0;
	str* body= NULL;
	str* str_hdr = NULL;
	str met = {"PUBLISH", 7};
	void* mi_hdl = NULL;

	LM_DBG("start\n");

	if(presentity)
	{
		LM_DBG("presentity exists\n");
		pres_id = PRES_HASH_ID(presentity);
		ver= ++presentity->version;

		/* copy etag */
		if(presentity->etag.s)
		{
			etag.s = etag_buf;
			memcpy(etag.s, presentity->etag.s, presentity->etag.len);
			etag.len = presentity->etag.len;
		}
		/* tuple id */
		if(presentity->tuple_id.s)
		{
			tuple_id.s = tuple_buf;
			memcpy(tuple_id.s, presentity->tuple_id.s, presentity->tuple_id.len);
			tuple_id.len = presentity->tuple_id.len;
		}
               presentity->desired_expires= publ->expires + (int)time(NULL);

		presentity->waiting_reply = 1;
		presentity->cb_param = publ->cb_param;

		if(publ->expires== 0)
		{
			LM_DBG("expires= 0- delete from hash table\n");
			if (presentity->flag&MI_ASYN_PUBLISH)
				mi_hdl = presentity->cb_param;
			delete_htable_safe(presentity, hash_index);
		}
	}
	lock_release(&HashT->p_records[hash_index].lock);

	/* handle body */
	if(publ->body && publ->body->s)
	{
		if(ev->process_body)
		{
			if(ev->process_body(publ, &body, ver, &tuple_id)< 0 || body== NULL)
			{
				LM_ERR("while processing body\n");
				goto error;
			}
		}
		else
			body = publ->body;
		LM_DBG("Handled body [%.*s]\n", body->len, body->s);
	}

	if(publ->expires!= 0 && publ->expires< min_expires)
		publ->expires = min_expires;

	if(presentity== NULL)
	{
		if(publ->expires== 0)
		{
			LM_DBG("request for a publish with expires 0 and"
					" no record found\n");
			ret = ERR_PUBLISH_NO_RECORD;
			goto error;
		}
		if(publ->body== NULL)
		{
			if (ev->content_type.s && ev->content_type.len) {
				LM_ERR("New '%.*s' PUBLISH and no body found - invalid request\n",
					ev->name.len, ev->name.s);
				ret = ERR_PUBLISH_NO_BODY;
				goto error;
			}
		}
		pres_id = new_publ_record(publ, ev, &tuple_id);
	}

	str_hdr = publ_build_hdr(((publ->expires< 0)?3600:publ->expires), ev, &publ->content_type,
				(etag.s?&etag:NULL), publ->extra_headers, ((body)?1:0));
	if(str_hdr == NULL)
	{
		LM_ERR("while building extra_headers\n");
		goto error;
	}

	LM_DBG("publ->pres_uri:\n%.*s\n ", publ->pres_uri->len, publ->pres_uri->s);
	LM_DBG("str_hdr:\n%.*s %d\n ", str_hdr->len, str_hdr->s, str_hdr->len);
	if(body && body->len && body->s )
		LM_DBG("body:\n%.*s\n ", body->len, body->s);

	LM_DBG("cback param = %ld\n", pres_id);

	if (tmb.t_request(&met,						/* Type of the message */
			publ->pres_uri,							/* Request-URI */
			publ->pres_uri,							/* To */
			publ->pres_uri,							/* From */
			str_hdr,								/* Optional headers */
			body,									/* Message body */
			/*Outbound proxy*/
			((publ->outbound_proxy.s)?&publ->outbound_proxy:0),
			/* Callback function */
			publ->expires?publ_cback_func:(mi_hdl?publ_expired_cback_func:0),
			/* Callback parameter */
			publ->expires?(void*)pres_id:mi_hdl,
			0
			) < 0 )
	{
		LM_ERR("failed to send PUBLISH\n");
		ret = -1;
		goto error;
	}

	pkg_free(str_hdr);

	if(body && ev->process_body)
	{
		if(body->s)
			xmlFree(body->s);
		pkg_free(body);
	}

	return ERR_PUBLISH_NO_ERROR;

error:
	if(body && ev->process_body)
	{
		if(body->s)
			xmlFree(body->s);
		pkg_free(body);
	}
	if(str_hdr)
		pkg_free(str_hdr);
	return ret;
}

int send_publish( publ_info_t* publ )
{
	ua_pres_t* presentity= NULL;
	ua_pres_t pres;
	unsigned int hash_code;
	pua_event_t* ev= NULL;
	publ_t **last;

	LM_DBG("pres_uri=%.*s\n", publ->pres_uri->len, publ->pres_uri->s );

	/* get event from list */

	ev= get_event(publ->event);
	if(ev== NULL)
	{
		LM_ERR("event not found in list\n");
		return -1;
	}

	memset(&pres, 0, sizeof(ua_pres_t));
	pres.pres_uri= publ->pres_uri;
	pres.flag= publ->source_flag;
	pres.id= publ->id;
	pres.event= publ->event;
	if(publ->etag)
		pres.etag= *publ->etag;

	hash_code= core_hash(publ->pres_uri, NULL, HASH_SIZE);

	LM_DBG("Try to get hash lock [%d]\n", hash_code);
	lock_get(&HashT->p_records[hash_code].lock);
	LM_DBG("Got hash lock %d\n", hash_code);

	if(publ->flag != INSERT_TYPE)
		presentity= search_htable(&pres, hash_code);
	if(publ->etag && presentity== NULL)
	{
		LM_DBG("Etag restriction and no record found\n");
		lock_release(&HashT->p_records[hash_code].lock);
		return 418;
	}
	if(presentity)
	{
		/* handle extra headers */
		if(presentity->extra_headers.s) shm_free(presentity->extra_headers.s);
		presentity->extra_headers.len= 0;
		if(publ->extra_headers && publ->extra_headers->s && publ->extra_headers->len)
		{
			presentity->extra_headers.s= (char*)shm_malloc(publ->extra_headers->len);
			if(presentity->extra_headers.s == NULL)
			{
				LM_ERR("while processing extra_headers\n");
				lock_release(&HashT->p_records[hash_code].lock);
				return -1;
			}
			memcpy(presentity->extra_headers.s, publ->extra_headers->s,
					publ->extra_headers->len);
			presentity->extra_headers.len= publ->extra_headers->len;
		}
		if(presentity->db_flag == NO_UPDATEDB_FLAG)
			presentity->db_flag= UPDATEDB_FLAG;
		if (presentity->waiting_reply)
		{
			LM_DBG("Presentity is waiting for reply, queue this PUBLISH\n");
			last = &presentity->pending_publ;
			while (*last)
				last = &((*last)->next);
			*last = build_pending_publ(publ);
			if(! *last)
			{
				LM_ERR("Failed to create pending publ record\n");
				lock_release(&HashT->p_records[hash_code].lock);
				return -1;
			}
			lock_release(&HashT->p_records[hash_code].lock);
			return 0;
		}
	}

	return send_publish_int(presentity, publ, ev, hash_code);
}

