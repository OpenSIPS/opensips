/*
 * $Id: dlg.c $
 *
 * back-to-back entities modules
 *
 * Copyright (C) 2009 Free Software Fundation
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
 *  2009-08-03  initial version (Anca Vamanu)
 */

#include <stdio.h>
#include <stdlib.h>
#include "../../data_lump_rpl.h"
#include "../../parser/contact/parse_contact.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_methods.h"
#include "../../parser/parse_content.h"
#include "../presence/hash.h"
#include "dlg.h"
#include "b2b_entities.h"

#define B2B_KEY_PREFIX       "B2B"
#define B2B_KEY_PREFIX_LEN   strlen("B2B")
#define B2B_MAX_KEY_SIZE     (B2B_KEY_PREFIX_LEN+ 5*3 + 40)
#define BUF_LEN              256

str* b2b_htable_insert(b2b_table table, b2b_dlg_t* dlg, int hash_index, int src)
{
	b2b_dlg_t * it, *prev_it= NULL;
	unsigned int local_index;
	str* b2b_key;

	lock_get(&table[hash_index].lock);
	
	dlg->prev = dlg->next = NULL;
	it = table[hash_index].first;

	if(it == NULL)
	{
		table[hash_index].first = dlg;
		dlg->id = 0;
	}
	else
	{
		while(it)
		{
			prev_it = it;
			it = it->next;
		}
		prev_it->next = dlg;
		dlg->prev = prev_it;
		dlg->id = prev_it->id +1;
	}
	local_index = dlg->id; 
	/* if an insert in server_htable -> copy the b2b_key in the to_tag */
	b2b_key = b2b_generate_key(hash_index, local_index);
	if(b2b_key == NULL)
	{
		lock_release(&table[hash_index].lock);
		LM_ERR("Failed to generate b2b key\n");
		return 0;
	}

	if(src == B2B_SERVER)
	{
		dlg->tag[CALLEE_LEG].s = (char*)shm_malloc(b2b_key->len);
		if(dlg->tag[CALLEE_LEG].s == NULL)
		{
			LM_ERR("No more shared memory\n");
			lock_release(&table[hash_index].lock);
			return 0;
		}
		memcpy(dlg->tag[CALLEE_LEG].s, b2b_key->s, b2b_key->len);
		dlg->tag[CALLEE_LEG].len = b2b_key->len;
	}
	lock_release(&table[hash_index].lock);

	return b2b_key;
}

/* key format : B2B.hash_index.local_index *
 */

int b2b_parse_key(str* key, unsigned int* hash_index, unsigned int* local_index)
{
	char* p;
	str s;

	if(strncmp(key->s, B2B_KEY_PREFIX, B2B_KEY_PREFIX_LEN) != 0 || 
			key->len<( B2B_KEY_PREFIX_LEN +4) || key->s[B2B_KEY_PREFIX_LEN]!='.')
	{
		LM_DBG("Does not have b2b_entities prefix\n");
		return -1;
	}

	s.s = key->s + B2B_KEY_PREFIX_LEN+1;
	p= strchr(s.s, '.');
	if(p == NULL || ((p-s.s) > key->len) )
	{
		LM_DBG("Wrong format for b2b key\n");
		return -1;
	}

	s.len = p - s.s;
	if(str2int(&s, hash_index) < 0)
	{
		LM_DBG("Could not extract hash_index [%.*s]\n", key->len, key->s);
		return -1;
	}

	p++;
	s.s = p;
	p= strchr(s.s, '.');
	if(p == NULL || ((p - s.s) > (key->len - s.len)))
	{
		LM_DBG("Could not extract local_index [%.*s]\n", s.len, s.s);
		return -1;
	}
	s.len = p - s.s;
	if(str2int(&s, local_index)< 0)
	{
		LM_DBG("Wrong format for b2b key\n");
		return -1;
	}

	LM_DBG("hash_index = [%d]  - local_index= [%d]\n", *hash_index, *local_index);

	return 0;
}

str* b2b_generate_key(unsigned int hash_index, unsigned int local_index)
{
	char buf[B2B_MAX_KEY_SIZE];
	str* b2b_key;
	int len;

	len = sprintf(buf, "%s.%d.%d.%d", B2B_KEY_PREFIX, hash_index, local_index, (int)time(NULL));

	b2b_key = (str*)pkg_malloc(sizeof(str)+ len);
	if(b2b_key== NULL)
	{
		LM_ERR("no more private memory\n");
		return NULL;
	}
	b2b_key->s = (char*)b2b_key + sizeof(str);
	memcpy(b2b_key->s, buf, len);
	b2b_key->len = len;

	return b2b_key;
}

str* b2b_key_copy_shm(str* b2b_key)
{
	str* b2b_key_shm = NULL;

	b2b_key_shm = (str*)shm_malloc(sizeof(str)+ b2b_key->len);
	if(b2b_key_shm== NULL)
	{
		LM_ERR("no more shared memory\n");
		return 0;
	}
	b2b_key_shm->s = (char*)b2b_key_shm + sizeof(str);
	memcpy(b2b_key_shm->s, b2b_key->s, b2b_key->len);
	b2b_key_shm->len = b2b_key->len;

	return b2b_key_shm;
}

b2b_dlg_t* b2b_dlg_copy(b2b_dlg_t* dlg)
{
	b2b_dlg_t* new_dlg;
	int size;

	size = sizeof(b2b_dlg_t) + dlg->callid.len+ dlg->from_uri.len+ dlg->to_uri.len+
		dlg->tag[0].len + dlg->tag[1].len+ dlg->route_set[0].len+ dlg->route_set[1].len+
		dlg->contact[0].len+ dlg->contact[1].len+ dlg->sdp.len;

	new_dlg = (b2b_dlg_t*)shm_malloc(size);
	if(new_dlg == 0)
	{
		LM_ERR("No more shared memory\n");
		return 0;
	}
	memset(new_dlg, 0, size);
	size = sizeof(b2b_dlg_t);

	CONT_COPY(new_dlg, new_dlg->callid, dlg->callid);
	CONT_COPY(new_dlg, new_dlg->from_uri, dlg->from_uri);
	CONT_COPY(new_dlg, new_dlg->to_uri, dlg->to_uri);
	if(dlg->tag[0].len && dlg->tag[0].s)
		CONT_COPY(new_dlg, new_dlg->tag[0], dlg->tag[0]);
	if(dlg->tag[1].len && dlg->tag[1].s)
		CONT_COPY(new_dlg, new_dlg->tag[1], dlg->tag[1]);
	if(dlg->route_set[0].len && dlg->route_set[0].s)
		CONT_COPY(new_dlg, new_dlg->route_set[0], dlg->route_set[0]);
	if(dlg->route_set[1].len && dlg->route_set[1].s)
		CONT_COPY(new_dlg, new_dlg->route_set[1], dlg->route_set[1]);
	if(dlg->contact[0].len && dlg->contact[0].s)
		CONT_COPY(new_dlg, new_dlg->contact[0], dlg->contact[0]);
	if(dlg->contact[1].len && dlg->contact[1].s)
		CONT_COPY(new_dlg, new_dlg->contact[1], dlg->contact[1]);
	if(dlg->sdp.s && dlg->sdp.len)
		CONT_COPY(new_dlg, new_dlg->sdp, dlg->sdp);

	new_dlg->bind_addr[0] = dlg->bind_addr[0];
	new_dlg->bind_addr[1] = dlg->bind_addr[1];

	new_dlg->cseq[0] = dlg->cseq[0];
	new_dlg->cseq[1] = dlg->cseq[1];

	new_dlg->id       = dlg->id;
	new_dlg->state    = dlg->state;

	new_dlg->param     = dlg->param;
	new_dlg->b2b_cback = dlg->b2b_cback;

	return new_dlg;
}

char* DLG_FLAGS_STR(int type)
{
	switch(type){
		case DLGCB_EARLY: return "DLGCB_EARLY";
		case DLGCB_REQ_WITHIN: return "DLGCB_EARLY";
		case DLGCB_RESPONSE_WITHIN: return "DLGCB_RESPONSE_WITHIN";
	}
	return "Flag not known";
}

int b2b_prescript_f(struct sip_msg *msg, void *uparam)
{
	str b2b_key;
	b2b_dlg_t* dlg;
	unsigned int hash_index, local_index;
	b2b_notify_t b2b_cback;
	void* param;
	b2b_table table = NULL;
	int method_value;
	struct to_body TO;
	static	str reason = {"Trying", 6};

	/* check if a b2b request */
	if (parse_headers(msg, HDR_EOH_F, 0) < 0)
	{
		LM_ERR("failed to parse message\n");
		return -1;
	}
	method_value = msg->first_line.u.request.method_value;

	if( msg->callid==NULL || msg->callid->body.s==NULL)
	{
		LM_ERR("failed to parse callid header\n");
		return -1;
	}

	/* if a CANCEL request - search iteratively in the server_htable*/
	if(method_value == METHOD_CANCEL)
	{
		str from_tag;
		str callid;

		callid = msg->callid->body;

		if(b2b_parse_key(&callid, &hash_index, &local_index) >= 0)
		{
			LM_DBG("received a CANCEL message that I sent\n");
			return 1;
		}

		/* examine the from header */
		if (!msg->from || !msg->from->body.s)
		{
			LM_ERR("cannot find 'from' header!\n");
			return -1;
		}
		if (msg->from->parsed == NULL)
		{
			if ( parse_from_header( msg )<0 ) 
			{
				LM_ERR("cannot parse From header\n");
				return -1;
			}
		}
		from_tag = ((struct to_body*)msg->from->parsed)->tag_value;

		hash_index = core_hash(&callid, &from_tag, server_hsize);

		lock_get(&server_htable[hash_index].lock);
		dlg = server_htable[hash_index].first;
		while(dlg)
		{
			if(dlg->callid.len == callid.len &&
					strncmp(dlg->callid.s, callid.s, callid.len)== 0 &&
					dlg->tag[CALLER_LEG].len == from_tag.len &&
					strncmp(dlg->tag[CALLER_LEG].s, from_tag.s, from_tag.len)== 0)
				break;
			dlg = dlg->next;
		}
		if(dlg == NULL)
		{
			lock_release(&server_htable[hash_index].lock);
			LM_DBG("No dialog found\n");
			return 0;
		}
		table = server_htable;

		goto logic_notify;
	}

	/* we are interested only in request inside dialog */
		/* examine the to header */
	if(msg->to->parsed == NULL)
	{
		memset( &TO , 0, sizeof(TO) );
		if( !parse_to(msg->to->body.s,msg->to->body.s + msg->to->body.len + 1, &TO));
		{
			LM_DBG("'To' header NOT parsed\n");
			return 0;
		}
	}

	b2b_key = get_to(msg)->tag_value;
	if(b2b_key.s == NULL && b2b_key.len == 0 && method_value != METHOD_CANCEL)
	{
		LM_DBG("Not an inside dialog request- not interested.\n");
		return 1;
	}
	/* check if the to tag has the b2b key format -> meaning that it is a server request */
	if(b2b_key.s && b2b_parse_key(&b2b_key, &hash_index, &local_index) >= 0)
	{
		LM_DBG("Received a b2b server request\n");
		table = server_htable;
	}
	else
	{
		/* check if the callid is in b2b format -> meaning that this is a client request */
		b2b_key = msg->callid->body;
		if(b2b_parse_key(&b2b_key, &hash_index, &local_index) >= 0)
		{
			LM_DBG("received a b2b client request\n");
			table = client_htable;
		}
		else /* if also not a client request - not for us */
		{
			LM_DBG("Not a b2b request\n");
			return 1;
		}
	}

	lock_get(&table[hash_index].lock);

	dlg = b2b_search_htable(table, hash_index, local_index);
	if(dlg== NULL)
	{
		LM_ERR("No dialog found\n");
		lock_release(&table[hash_index].lock);
		return -1;
	}

	if(method_value == METHOD_ACK)
	{
		if(dlg->last_reply_code > 299)
		{
			lock_release(&table[hash_index].lock);
			return 0;
		}
		dlg->tm_tran = 0;
	}
	else
	{
		tmb.t_newtran(msg);
		dlg->tm_tran = tmb.t_gett();

		if(method_value == METHOD_INVITE) /* send provisional reply 100 Trying */
			tmb.t_reply(msg, 100, &reason);
	}

logic_notify:
	b2b_cback = dlg->b2b_cback;
	param = dlg->param;

	lock_release(&table[hash_index].lock);

	b2b_cback(msg, &b2b_key, B2B_REQUEST, param);

	return 0;
}

int init_b2b_htables(void)
{
	int i;

	server_htable = (b2b_table)shm_malloc(server_hsize* sizeof(b2b_entry_t));
	client_htable = (b2b_table)shm_malloc(client_hsize* sizeof(b2b_entry_t));
	if(!server_htable || !client_htable)
		ERR_MEM(SHARE_MEM);
	
	memset(server_htable, 0, server_hsize* sizeof(b2b_entry_t));
	memset(client_htable, 0, client_hsize* sizeof(b2b_entry_t));
	for(i= 0; i< server_hsize; i++)
	{
		lock_init(&server_htable[i].lock);
	}

	for(i= 0; i< client_hsize; i++)
	{
		lock_init(&client_htable[i].lock);
	}

	return 0;

error:
	return -1;
}

void destroy_b2b_htables(void)
{
	int i;
	b2b_dlg_t* dlg, *aux;

	if(server_htable)
	{
		for(i= 0; i< server_hsize; i++)
		{
			lock_destroy(&server_htable[i].lock);
			dlg = server_htable[i].first;
			while(dlg)
			{
				aux = dlg->next;
				if(dlg->tag[CALLEE_LEG].s)
					shm_free(dlg->tag[CALLEE_LEG].s);
				shm_free(dlg);
				dlg = aux;
			}
		}
	}

	if(client_htable)
	{
		for(i = 0; i< client_hsize; i++)
		{
			lock_destroy(&client_htable[i].lock);
			dlg = client_htable[i].first;
			while(dlg)
			{
				aux = dlg->next;
				shm_free(dlg);
				dlg = aux;
			}
		}
	}
	shm_free(server_htable);
	shm_free(client_htable);
}


b2b_dlg_t* b2b_new_dlg(struct sip_msg* msg, int on_reply)
{
	struct to_body *pto, *pfrom = NULL, TO;
	b2b_dlg_t dlg;
	contact_body_t*  b;
	b2b_dlg_t* shm_dlg = NULL;

	memset(&dlg, 0, sizeof(b2b_dlg_t));

	if (parse_headers(msg, HDR_EOH_F, 0) < 0)
	{
		LM_ERR("failed to parse message\n");
		return 0;
	}

	/* reject CANCEL messages */
	if (msg->first_line.u.request.method_value==METHOD_CANCEL)
		return 0;

	/* examine the to header */
	if(msg->to->parsed != NULL)
	{
		pto = (struct to_body*)msg->to->parsed;
		LM_DBG("'To' header ALREADY PARSED: <%.*s>\n",pto->uri.len,pto->uri.s);
	}
	else
	{
		memset( &TO , 0, sizeof(TO) );
		if( !parse_to(msg->to->body.s,msg->to->body.s + msg->to->body.len + 1, &TO));
		{
			LM_DBG("'To' header NOT parsed\n");
			return 0;
		}
		pto = &TO;
	}
	if(pto->tag_value.s!= 0 && pto->tag_value.len != 0)
	{
		LM_DBG("Not an initial request\n");
		dlg.tag[CALLEE_LEG] = pto->tag_value;
	}
	dlg.to_uri= pto->uri;

	/* examine the from header */
	if (!msg->from || !msg->from->body.s)
	{
		LM_ERR("cannot find 'from' header!\n");
		return 0;
	}
	if (msg->from->parsed == NULL)
	{
		if ( parse_from_header( msg )<0 ) 
		{
			LM_ERR("cannot parse From header\n");
			return 0;
		}
	}
	pfrom = (struct to_body*)msg->from->parsed;
	dlg.from_uri = pfrom->uri;
	if( pfrom->tag_value.s ==NULL || pfrom->tag_value.len == 0)
	{
		LM_ERR("no from tag value present\n");
		return 0;
	}
	dlg.tag[CALLER_LEG] = pfrom->tag_value;

	if( msg->callid==NULL || msg->callid->body.s==NULL)
	{
		LM_ERR("failed to parse callid header\n");
		return 0;
	}
	dlg.callid = msg->callid->body;

	if( msg->cseq==NULL || msg->cseq->body.s==NULL)
	{
		LM_ERR("failed to parse cseq header\n");
		return 0;
	}
	if (str2int( &(get_cseq(msg)->number), &dlg.cseq[CALLER_LEG])!=0 )
	{
		LM_ERR("failed to parse cseq number - not an integer\n");
		return 0;
	}
	dlg.cseq[CALLEE_LEG] = 1;

	if( msg->contact==NULL || msg->contact->body.s==NULL)
	{
		LM_ERR("no Contact header found\n");
		return 0;
	}
	
	if(parse_contact(msg->contact) <0 )
	{
		LM_ERR("failed to parse contact header\n");
		return 0;
	}
	b= (contact_body_t* )msg->contact->parsed;
	if(b == NULL)
	{
		LM_ERR("contact header not parsed\n");
		return 0;
	}
	if(on_reply)
		dlg.contact[CALLEE_LEG] = b->contacts->uri;
	else
		dlg.contact[CALLER_LEG] = b->contacts->uri;

	if(msg->record_route!=NULL && msg->record_route->body.s!= NULL)
	{
		if( print_rr_body(msg->record_route, &dlg.route_set[CALLER_LEG], 0, 0)!= 0)
		{
			LM_ERR("failed to process record route\n");
		}
	}

	dlg.bind_addr[CALLER_LEG]= msg->rcv.bind_address;

	/* extract sdp also */
	if (!msg->content_length) 
	{
		LM_ERR("no Content-Length header found!\n");
		return 0;
	}

	/* process the body */
	if ( get_content_length(msg) != 0 )
	{
		dlg.sdp.s=get_body(msg);
		if (dlg.sdp.s== NULL) 
		{
			LM_ERR("cannot extract body\n");
			return 0;
		}
		dlg.sdp.len= get_content_length( msg );
	}

	shm_dlg = b2b_dlg_copy(&dlg);
	if(shm_dlg == NULL)
	{
		LM_ERR("failed to copy dialog structure in shared memory\n");
		pkg_free(dlg.route_set[CALLER_LEG].s);
		return 0;
	}
	if(dlg.route_set[CALLER_LEG].s)
		pkg_free(dlg.route_set[CALLER_LEG].s);

	return shm_dlg;
}

/*
 *	Function to send a reply inside a b2b dialog
 *	et      : entity type - it can be B2B_SEVER or B2B_CLIENT
 *	b2b_key : the key to identify the dialog
 *	code  : the status code for the reply
 *	text  : the reason phrase for the reply
 *	body    : the body to be included in the request(optional)
 *	extra_headers  : the extra headers to be included in the request(optional)
 * */
int b2b_send_reply(enum b2b_entity_type et, str* b2b_key, int code, str* text,
		str* body, str* extra_headers)
{
	unsigned int hash_index, local_index;
	b2b_dlg_t* dlg;
	str* to_tag = 0;
	struct cell* tm_tran;
	struct sip_msg* msg;
	char buffer[BUF_LEN];
	int len;
	char* p;
	str ehdr;
	b2b_table table;

	if(et == B2B_SERVER)
		table = server_htable;
	else
		table = client_htable;

	/* parse the key and find the position in hash table */
	if(b2b_parse_key(b2b_key, &hash_index, &local_index) < 0)
	{
		LM_ERR("Wrong format for b2b key\n");
		return -1;
	}

	lock_get(&table[hash_index].lock);
	dlg = b2b_search_htable(table, hash_index, local_index);
	if(dlg== NULL)
	{
		LM_ERR("No dialog found\n");
		lock_release(&table[hash_index].lock);
		return -1;
	}

	if(dlg->callid.s == NULL)
	{
		LM_DBG("NULL callid. Dialog Information not completed yet\n");
		lock_release(&table[hash_index].lock);
		return 0;
	}

	tm_tran = dlg->tm_tran;
	if(tm_tran == NULL)
	{
		LM_ERR("Tm transaction not saved!\n");
		lock_release(&table[hash_index].lock);
		return -1;
	}
	if(code >= 200)
		dlg->tm_tran = NULL;

	msg = tm_tran->uas.request;
	if(msg== NULL)
	{
		LM_DBG("Transaction not valid anymore\n");
		lock_release(&table[hash_index].lock);
		return 0;
	}
	
	/* only for the server replies to the initial INVITE */
	to_tag = &get_to(msg)->tag_value;
	if(to_tag->s == NULL && to_tag->len == 0)
	{
		to_tag = b2b_key;
	}

	/* if sent reply for bye, delete the record */
	if((tm_tran->method.len == BYE_LEN && strncmp(tm_tran->method.s, BYE, BYE_LEN) == 0) ||
		code > 299 )
	{
		LM_DBG("I was asked to send reply for BYE-> DELETE\n");
//		b2b_delete_record(dlg, &table, hash_index);
	}
	dlg->last_reply_code = code;
	lock_release(&table[hash_index].lock);
	
	p = buffer;

	if(extra_headers && extra_headers->s && extra_headers->len)
	{
		memcpy(p, extra_headers->s, extra_headers->len);
		p += extra_headers->len;
	}
	len = sprintf(p,"Contact: <%.*s", server_address.len, server_address.s);
	p += len;
	if (msg->rcv.proto!=PROTO_UDP) {
		memcpy(p,";transport=",11);
		p += 11;
		p = proto2str(msg->rcv.proto, p);
		if (p==NULL) {
			LM_ERR("invalid proto\n");
			goto error;
		}
	}
	*(p++) = '>';
	memcpy(p, CRLF, CRLF_LEN);
	p += CRLF_LEN;
	ehdr.len = p -buffer;
	ehdr.s = buffer;

	/* send reply */
	if(tmb.t_reply_with_body(tm_tran, code, text, body, &ehdr, to_tag) < 0)
	{
		LM_ERR("failed to send reply with tm\n");
		goto error;
	}
	if(code >= 200)
	{
		tmb.unref_cell(tm_tran);
	}
	return 0;

error:
	if(code >= 200)
	{
		tmb.unref_cell(tm_tran);
	}
	return -1;
}

void b2b_delete_record(b2b_dlg_t* dlg, b2b_table* htable, unsigned int hash_index)
{
	if(dlg->prev == NULL)
	{
		(*htable)[hash_index].first = dlg->next;
	}
	else
	{
		dlg->prev->next = dlg->next;
	}

	if(dlg->next)
		dlg->next->prev = dlg->prev;

	if(*htable == server_htable && dlg->tag[CALLEE_LEG].s)
		shm_free(dlg->tag[CALLEE_LEG].s);


	shm_free(dlg);
}

void b2b_entity_delete(enum b2b_entity_type et, str* b2b_key)
{
	b2b_table table;
	unsigned int hash_index, local_index;
	b2b_dlg_t* dlg;

	if(et == B2B_SERVER)
		table = server_htable;
	else
		table = client_htable;

	/* parse the key and find the position in hash table */
	if(b2b_parse_key(b2b_key, &hash_index, &local_index) < 0)
	{
		LM_ERR("Wrong format for b2b key\n");
		return;
	}

	lock_get(&table[hash_index].lock);
	dlg = b2b_search_htable(table, hash_index, local_index);
	if(dlg== NULL)
	{
		LM_ERR("No dialog found\n");
		lock_release(&table[hash_index].lock);
		return;
	}

	b2b_delete_record(dlg, &table, hash_index);
	lock_release(&table[hash_index].lock);
}


b2b_dlg_t* b2b_search_htable(b2b_table table, unsigned int hash_index, unsigned int local_index)
{
	b2b_dlg_t* dlg;

	dlg= table[hash_index].first;
	while(dlg && dlg->id < local_index)
		dlg = dlg->next;

	if(dlg == NULL || dlg->id!=local_index)
	{
		LM_DBG("No dialog with hash_index=[%d] and local_index=[%d] found\n",
				hash_index, local_index);
		return NULL;
	}

	return dlg;
}

void shm_free_param(void* param)
{
	shm_free(param);
}

/*
 *	Function to send a request inside a b2b dialog
 *	et      : entity type - it can be B2B_SEVER or B2B_CLIENT
 *	b2b_key : the key to identify the dialog
 *	method  : the method for the request
 *	extra_headers  : the extra headers to be included in the request(optional)
 *	body    : the body to be included in the request(optional)
 * */
int b2b_send_request(enum b2b_entity_type et, str* b2b_key, str* method,
		str* extra_headers, str* body)
{
	unsigned int hash_index, local_index;
	b2b_dlg_t* dlg;
	dlg_t* td = NULL;
	int result = 0;
	char buffer[256];
	str ehdr = {0, 0};
	str* b2b_key_shm= NULL;
	b2b_table table;
	transaction_cb* tm_cback;
	build_dlg_f build_dlg;

	if(et == B2B_SERVER)
	{
		LM_DBG("Send request to a server entity\n");
		table = server_htable;
		build_dlg = b2b_server_build_dlg;
		tm_cback = b2b_server_tm_cback;
	}
	else
	{
		LM_DBG("Send request to a client entity\n");
		table = client_htable;
		build_dlg = b2b_client_build_dlg;
		tm_cback = b2b_client_tm_cback;
	}

	/* parse the key and find the position in hash table */
	if(b2b_parse_key(b2b_key, &hash_index, &local_index) < 0)
	{
		LM_ERR("Wrong format for b2b key\n");
		return -1;
	}

	lock_get(&table[hash_index].lock);
	dlg = b2b_search_htable(table, hash_index, local_index);
	if(dlg== NULL)
	{
		LM_ERR("No dialog found\n");
		lock_release(&table[hash_index].lock);
		return -1;
	}

	parse_method(method->s, method->s+method->len, &dlg->last_method);

	if(dlg->last_method== METHOD_INVITE)
		dlg->state = B2B_MODIFIED;
	else
	if(dlg->last_method == METHOD_ACK)
		dlg->state = B2B_ESTABLISHED;
	else
	if(dlg->last_method == METHOD_BYE)
		dlg->state = B2B_TERMINATED;


	/* send request */
	if(dlg->last_method == METHOD_CANCEL)
	{
		LM_DBG("send cancel request\n");
		if(dlg->tm_tran)
		{
			result = tmb.t_cancel_uac(&ehdr, 0, dlg->tm_tran->hash_index, dlg->tm_tran->label, 0, 0);
		}
		else
		{
			LM_ERR("No transaction saved. Cannot send CANCEL\n");
			lock_release(&table[hash_index].lock);
			return -1;
		}
		lock_release(&table[hash_index].lock);
	}
	else
	{
		/* build strucuture with dialog information */
		td = build_dlg(dlg);
		if(td == NULL)
		{
			LM_ERR("failed to build tm dlg structure\n");
			lock_release(&table[hash_index].lock);
			return -1;
		}
		lock_release(&table[hash_index].lock);

		/* construct extra headers -> add contact */
		if(extra_headers && extra_headers->s && extra_headers->len)
		{
			if(extra_headers->len + 13 + server_address.len > BUF_LEN)
			{
				LM_ERR("Buffer too small\n");
				pkg_free(td);
				return -1;
			}
			memcpy(buffer, extra_headers->s, extra_headers->len);
			ehdr.len = extra_headers->len;
		}
		ehdr.len += sprintf(buffer+ ehdr.len, "Contact: <%.*s>\r\n",
			server_address.len, server_address.s);
		ehdr.s = buffer;

		b2b_key_shm = b2b_key_copy_shm(b2b_key);
		if(b2b_key_shm== NULL)
		{
			LM_ERR("no more shared memory\n");
			pkg_free(td);
			return -1;
		}

		td->T_flags=T_NO_AUTOACK_FLAG|T_PASS_PROVISIONAL_FLAG ;

		if(method->len == INVITE_LEN && strncmp(method->s, INVITE, INVITE_LEN) == 0)
			tmb.setlocalTholder(&dlg->tm_tran);

		result= tmb.t_request_within
			(method,            /* method*/
			&ehdr,              /* extra headers*/
			body,               /* body*/
			td,                 /* dialog structure*/
			tm_cback,           /* callback function*/
			b2b_key_shm,        /* callback parameter*/
			shm_free_param);

		tmb.setlocalTholder(0);
	}

	LM_DBG("Request sent\n");
	if(result < 0)
	{
		LM_ERR("failed to send request\n");
		if(td)
			pkg_free(td);
		if(b2b_key_shm)
			shm_free(b2b_key_shm);
		return -1;
	}

	if(td)
		pkg_free(td);
	return 0;
}

void b2b_tm_cback(b2b_table htable, struct tmcb_params *ps)
{
	struct sip_msg * msg;
	str* b2b_key;
	unsigned int hash_index, local_index;
	b2b_notify_t b2b_cback;
	b2b_dlg_t* dlg;
	void* param = NULL;
	int statuscode = 0;

	if(ps == NULL || ps->rpl == NULL)
	{
		LM_ERR("wrong ps parameter\n");
		return;
	}
	if( ps->param== NULL || *ps->param== NULL )
	{
		LM_ERR("null callback parameter\n");
		return;
	}

	statuscode = ps->code;

	msg = ps->rpl;
	b2b_key = (str*)*ps->param;

	if(b2b_parse_key(b2b_key, &hash_index, &local_index)< 0)
	{
		LM_ERR("Failed to parse b2b logic key [%.*s]\n",b2b_key->len,b2b_key->s);
		return;
	}

	lock_get(&htable[hash_index].lock);

	dlg = b2b_search_htable(htable, hash_index, local_index);
	if(dlg== NULL)
	{
		LM_ERR("No dialog found\n");
		lock_release(&htable[hash_index].lock);
		return;
	}
	b2b_cback = dlg->b2b_cback;
	param = dlg->param;

	/* if a reply for Bye -> delete the record */
	if(dlg->last_method == METHOD_BYE)
	{
		LM_DBG("I received a reply for BYE-> DELETE\n");
//		b2b_delete_record(dlg, &client_htable, hash_index);
		lock_release(&htable[hash_index].lock);
		goto done;
	}

	if(statuscode >= 300)
	{
		LM_DBG("Received a negative reply\n");

		if(dlg->tm_tran)
		{
			tmb.unref_cell(dlg->tm_tran);
			dlg->tm_tran = 0;
		}

		/* delete the record from hash table */
//		b2b_delete_record(dlg, &client_htable, hash_index);
		lock_release(&htable[hash_index].lock);
		if(msg == FAKED_REPLY)
			return;
	}
	else
	{
		/* if provisional or 200OK reply */
		LM_DBG("Received a reply with statuscode = %d\n", statuscode);
		if(msg == FAKED_REPLY)
			return;

		if( dlg->last_method == METHOD_INVITE )
		{
			LM_DBG("DLG state = %d\n", dlg->state);
			if(dlg->state == B2B_NEW && msg->first_line.u.reply.statuscode < 200)
				dlg->state = B2B_EARLY;
			else
			if((dlg->state == B2B_NEW || dlg->state== B2B_MODIFIED || dlg->state == B2B_EARLY)
					&& msg->first_line.u.reply.statuscode == 200)
			{
				LM_DBG("switched the state CONFIRMED\n");
				dlg->state = B2B_CONFIRMED;
			}
			else
			if(dlg->state == B2B_CONFIRMED)
			{
				LM_DBG("Retrasmission\n");
				lock_release(&htable[hash_index].lock);
				return;
			}
		}

		if(dlg->tm_tran && statuscode>= 200 && statuscode< 300)
		{
			tmb.unref_cell(dlg->tm_tran);
			dlg->tm_tran = 0;
		}

		/* update the state of the dialog according to the code of the reply */

		if(dlg->callid.s == NULL && statuscode>= 200 && statuscode< 300 )
		{
			b2b_dlg_t* new_dlg;

			dlg->state = DLG_ESTABLISHED;

			new_dlg = b2b_new_dlg(msg, 1);
			if(new_dlg == NULL)
			{
				LM_ERR("Failed to create b2b dialog structure\n");
				lock_release(&htable[hash_index].lock);
				return;
			}
			new_dlg->id = dlg->id;
			new_dlg->state = dlg->state;
			new_dlg->b2b_cback = dlg->b2b_cback;
			new_dlg->param = dlg->param;
			
			new_dlg->next = dlg->next;
			new_dlg->prev = dlg->prev;

			dlg = b2b_search_htable(htable, hash_index, local_index);
			if(dlg->prev)
				dlg->prev->next = new_dlg;
			else
				htable[hash_index].first = new_dlg;

			if(dlg->next)
				dlg->next->prev = new_dlg;
			
			dlg->next= dlg->prev = NULL;
			shm_free(dlg);
		}
		
		lock_release(&htable[hash_index].lock);
	}

	/* I have to inform the logic that a reply was received */
done:
	b2b_cback(msg, b2b_key, B2B_REPLY, param);

	return;
}


