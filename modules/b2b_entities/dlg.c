/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 *  2009-08-03  initial version (Anca Vamanu)
 *  2011-06-27  added authentication support (Ovidiu Sas)
 */

#include <stdio.h>
#include <stdlib.h>
#include "../../data_lump_rpl.h"
#include "../../parser/parse_rr.h"
#include "../../parser/contact/parse_contact.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_methods.h"
#include "../../parser/parse_content.h"
#include "../../parser/parse_authenticate.h"
#include "../../locking.h"
#include "../../script_cb.h"
#include "../uac_auth/uac_auth.h"
#include "../presence/hash.h"
#include "../../action.h"
#include "../../trim.h"
#include "dlg.h"
#include "b2b_entities.h"
#include "b2be_db.h"

#define BUF_LEN              1024

str ack = str_init(ACK);
str bye = str_init(BYE);

/* used to make WRITE_THROUGH db mode more efficient */
b2b_dlg_t* current_dlg= NULL;

#define UPDATE_DBFLAG(dlg) do{ \
	if(b2be_db_mode == WRITE_BACK && dlg->db_flag==NO_UPDATEDB_FLAG) \
			dlg->db_flag = UPDATEDB_FLAG; \
	} while(0)


void print_b2b_dlg(b2b_dlg_t *dlg)
{
	dlg_leg_t *leg = dlg->legs;

	LM_DBG("dlg[%p][%p][%p]: [%.*s] id=[%d] param=[%.*s] state=[%d] db_flag=[%d]\n",
		dlg, dlg->prev, dlg->next, dlg->ruri.len, dlg->ruri.s,
		dlg->id, dlg->param.len, dlg->param.s, dlg->state, dlg->db_flag);
	LM_DBG("  from=[%.*s] [%.*s]\n",
		dlg->from_dname.len, dlg->from_dname.s, dlg->from_uri.len, dlg->from_uri.s);
	LM_DBG("    to=[%.*s] [%.*s]\n",
		dlg->to_dname.len, dlg->to_dname.s, dlg->to_uri.len, dlg->to_uri.s);
	LM_DBG("callid=[%.*s] tag=[%.*s][%.*s]\n",
		dlg->callid.len, dlg->callid.s,
		dlg->tag[0].len, dlg->tag[0].s, dlg->tag[1].len, dlg->tag[1].s);
	while(leg)
	{
		LM_DBG("leg[%p][%p] id=[%d] tag=[%.*s] cseq=[%d]\n",
			leg, leg->next, leg->id, leg->tag.len, leg->tag.s, leg->cseq);
		leg = leg->next;
	}
	return;
}


b2b_dlg_t* b2b_search_htable_next_dlg(b2b_dlg_t* start_dlg, b2b_table table, unsigned int hash_index,
		unsigned int local_index, str* to_tag, str* from_tag, str* callid)
{
	b2b_dlg_t* dlg;
	str dlg_from_tag={NULL, 0};
	dlg_leg_t* leg;

	LM_DBG("entering with start=%p, table=%p, hash=%d, label=%d \n",
		start_dlg,table,hash_index,local_index);
	if(callid)
		LM_DBG("searching  callid %d[%.*s]\n", callid->len,callid->len, callid->s);
	if(to_tag)
		LM_DBG("searching   totag %d[%.*s]\n", to_tag->len,to_tag->len, to_tag->s);
	if(from_tag)
		LM_DBG("searching fromtag %d[%.*s]\n", from_tag->len,from_tag->len, from_tag->s);
	dlg= start_dlg?start_dlg->next:table[hash_index].first;
	while(dlg)
	{
		if(dlg->id != local_index)
		{
			dlg = dlg->next;
			continue;
		}

		/*check if the dialog information correspond */
		if(table == server_htable)
		{
			if(!from_tag)
				return NULL;
			dlg_from_tag= dlg->tag[CALLER_LEG];
			/* check from tag and callid */
			 if(dlg_from_tag.len==from_tag->len &&
				strncmp(dlg_from_tag.s, from_tag->s, dlg_from_tag.len)==0
				&& dlg->callid.len==callid->len && strncmp(dlg->callid.s, callid->s, callid->len)==0)
			{
				LM_DBG("Match for server dlg [%p] dlg->uas_tran=[%p]\n",
					dlg, dlg->uas_tran);
				return dlg;
			}

		}
		else
		{
			/*
			LM_DBG("dialog totag [%.*s] with state %d\n",
				dlg->tag[CALLER_LEG].len, dlg->tag[CALLER_LEG].s, dlg->state);
			*/
			/* it is an UAC dialog (callid is the key)*/
			if(dlg->tag[CALLER_LEG].len == to_tag->len &&
				strncmp(dlg->tag[CALLER_LEG].s, to_tag->s, to_tag->len)== 0)
			{

				leg = dlg->legs;
				if(dlg->state < B2B_CONFIRMED || dlg->state>=B2B_DESTROYED)
				{
					if(from_tag == NULL || from_tag->len==0 || leg==NULL)
					{
						LM_DBG("Match for client dlg [%p] last_method=%d"
							" dlg->uac_tran=[%p]\n",
							dlg, dlg->last_method, dlg->uac_tran);
						return dlg;
					}
				}
				if(from_tag == NULL || from_tag->s==NULL)
				{
					dlg = dlg->next;
					continue;
				}
				/* if it is an already confirmed dialog match the to_tag also*/
				while(leg)
				{
					if(leg->tag.len == from_tag->len &&
						strncmp(leg->tag.s, from_tag->s, from_tag->len)== 0)
						return dlg;
					leg = leg->next;
				}
				if(dlg->state < B2B_CONFIRMED || dlg->state>=B2B_DESTROYED) /* state not confirmed yet and a new leg */
					return dlg;
			}
		}
		dlg = dlg->next;
	}
	return NULL;
}

b2b_dlg_t* b2b_search_htable_dlg(b2b_table table, unsigned int hash_index,
		unsigned int local_index, str* to_tag, str* from_tag, str* callid)
{
	return b2b_search_htable_next_dlg(NULL, table, hash_index, local_index,
					to_tag, from_tag, callid);
}

b2b_dlg_t* b2b_search_htable_next(b2b_dlg_t* start_dlg, b2b_table table, unsigned int hash_index,
		unsigned int local_index)
{
	b2b_dlg_t* dlg;

	dlg= start_dlg?start_dlg->next:table[hash_index].first;
	while(dlg && dlg->id != local_index)
		dlg = dlg->next;

	if(dlg == NULL || dlg->id!=local_index)
	{
		LM_DBG("No dialog with hash_index=[%d] and local_index=[%d] found\n",
				hash_index, local_index);
		return NULL;
	}

	return dlg;
}

b2b_dlg_t* b2b_search_htable(b2b_table table, unsigned int hash_index,
		unsigned int local_index)
{
	return b2b_search_htable_next(NULL, table, hash_index, local_index);
}

/* this is only called by server new */
str* b2b_htable_insert(b2b_table table, b2b_dlg_t* dlg, int hash_index, int src, int reload)
{
	b2b_dlg_t * it, *prev_it= NULL;
	str* b2b_key;

	if(!reload)
		lock_get(&table[hash_index].lock);

	dlg->prev = dlg->next = NULL;
	it = table[hash_index].first;

	if(it == NULL)
	{
		table[hash_index].first = dlg;
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
	}
	/* if an insert in server_htable -> copy the b2b_key in the to_tag */
	b2b_key = b2b_generate_key(hash_index, dlg->id);
	if(b2b_key == NULL)
	{
		if(!reload)
			lock_release(&table[hash_index].lock);
		LM_ERR("Failed to generate b2b key\n");
		return NULL;
	}

	if(src == B2B_SERVER)
	{
		dlg->tag[CALLEE_LEG].s = (char*)shm_malloc(b2b_key->len);
		if(dlg->tag[CALLEE_LEG].s == NULL)
		{
			LM_ERR("No more shared memory\n");
			if(!reload)
				lock_release(&table[hash_index].lock);
			return 0;
		}
		memcpy(dlg->tag[CALLEE_LEG].s, b2b_key->s, b2b_key->len);
		dlg->tag[CALLEE_LEG].len = b2b_key->len;
		if(!reload && b2be_db_mode == WRITE_THROUGH)
			b2be_db_insert(dlg, src);
	}

	if(!reload)
		lock_release(&table[hash_index].lock);

	return b2b_key;
}

/* key format : B2B.hash_index.local_index.timestamp *
 */

int b2b_parse_key(str* key, unsigned int* hash_index, unsigned int* local_index)
{
	char* p;
	str s;

	if(!key || !key->s)
		return -1;

	if(strncmp(key->s, b2b_key_prefix.s, b2b_key_prefix.len) != 0 ||
			key->len<(b2b_key_prefix.len +4) || key->s[b2b_key_prefix.len]!='.')
	{
		LM_DBG("Does not have b2b_entities prefix\n");
		return -1;
	}

	s.s = key->s + b2b_key_prefix.len+1;
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
	if(p == NULL || ((p-s.s) > key->len) )
	{
		LM_DBG("Wrong format for b2b key\n");
		return -1;
	}

	s.len = p - s.s;
	if(str2int(&s, local_index)< 0)
	{
		LM_DBG("Wrong format for b2b key\n");
		return -1;
	}
	/* we do not really care about the third part of the key */

	LM_DBG("hash_index = [%d]  - local_index= [%d]\n", *hash_index, *local_index);

	return 0;
}

str* b2b_generate_key(unsigned int hash_index, unsigned int local_index)
{
	char buf[B2B_MAX_KEY_SIZE];
	str* b2b_key;
	int len;

	len = sprintf(buf, "%s.%d.%d.%ld",
		b2b_key_prefix.s, hash_index, local_index, startup_time+get_ticks());

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
		dlg->contact[0].len+ dlg->contact[1].len+ dlg->ruri.len+ B2BL_MAX_KEY_LEN+
		dlg->from_dname.len + dlg->to_dname.len;

	new_dlg = (b2b_dlg_t*)shm_malloc(size);
	if(new_dlg == 0)
	{
		LM_ERR("No more shared memory\n");
		return 0;
	}
	memset(new_dlg, 0, size);
	size = sizeof(b2b_dlg_t);

	if(dlg->ruri.s)
		CONT_COPY(new_dlg, new_dlg->ruri, dlg->ruri);
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
	if(dlg->param.s)
	{
		new_dlg->param.s= (char*)new_dlg+ size;
		memcpy(new_dlg->param.s, dlg->param.s, dlg->param.len);
		new_dlg->param.len= dlg->param.len;
		size+= B2BL_MAX_KEY_LEN;
	}

	if(dlg->from_dname.s)
		CONT_COPY(new_dlg, new_dlg->from_dname, dlg->from_dname);
	if(dlg->to_dname.s)
		CONT_COPY(new_dlg, new_dlg->to_dname, dlg->to_dname);

	new_dlg->cseq[0]          = dlg->cseq[0];
	new_dlg->cseq[1]          = dlg->cseq[1];
	new_dlg->id               = dlg->id;
	new_dlg->state            = dlg->state;
	new_dlg->b2b_cback        = dlg->b2b_cback;
	new_dlg->add_dlginfo      = dlg->add_dlginfo;
	new_dlg->last_invite_cseq = dlg->last_invite_cseq;
	new_dlg->db_flag          = dlg->db_flag;
	new_dlg->send_sock        = dlg->send_sock;

	return new_dlg;
}

void b2b_delete_legs(dlg_leg_t** legs)
{
	dlg_leg_t* leg, *aux_leg;

	leg = *legs;
	while(leg)
	{
		aux_leg = leg->next;
		shm_free(leg);
		leg = aux_leg;
	}
	*legs = NULL;
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

void set_dlg_state(b2b_dlg_t* dlg, int meth)
{
	switch(meth)
	{
		case METHOD_INVITE:
			if (dlg->state != B2B_NEW_AUTH)
				dlg->state= B2B_MODIFIED;
			break;
		case METHOD_CANCEL:
		case METHOD_BYE:
			dlg->state= B2B_TERMINATED;
			break;
		case METHOD_ACK:
			dlg->state= B2B_ESTABLISHED;
			break;
		default:
			break;
	}
}

b2b_dlg_t* b2bl_search_iteratively(str* callid, str* from_tag, str* ruri,
		unsigned int hash_index)
{
	b2b_dlg_t* dlg= NULL;

	LM_DBG("Search for record with callid= %.*s, tag= %.*s\n",
			callid->len, callid->s, from_tag->len, from_tag->s);
	/* must search iteratively */

	lock_get(&server_htable[hash_index].lock);
	dlg = server_htable[hash_index].first;
	while(dlg)
	{
		LM_DBG("Found callid= %.*s, tag= %.*s\n", dlg->callid.len, dlg->callid.s,
			dlg->tag[CALLER_LEG].len, dlg->tag[CALLER_LEG].s);
		if(dlg->callid.len == callid->len && strncmp(dlg->callid.s, callid->s, callid->len)== 0 &&
			dlg->tag[CALLER_LEG].len == from_tag->len &&
			strncmp(dlg->tag[CALLER_LEG].s, from_tag->s, from_tag->len)== 0)
		{
			if(!ruri)
				break;
			if(ruri->len == dlg->ruri.len && strncmp(ruri->s, dlg->ruri.s, ruri->len)== 0)
				break;
		}
		dlg = dlg->next;
	}
	return dlg;
}

int b2b_prescript_f(struct sip_msg *msg, void *uparam)
{
	str b2b_key;
	b2b_dlg_t* dlg = 0, *aux_dlg;
	unsigned int hash_index, local_index;
	b2b_notify_t b2b_cback;
	str param= {NULL,0};
	b2b_table table = NULL;
	int method_value;
	str from_tag;
	str to_tag;
	str callid;
	struct cell* tm_tran;
	int ret;
	str host;
	int port;
	int etype= B2B_NONE;
	int dlg_state = 0;
	struct sip_uri puri;
	struct hdr_field *route_hdr;
	rr_t *rt;

	/* check if a b2b request */
	if (parse_headers(msg, HDR_EOH_F, 0) < 0)
	{
		LM_ERR("failed to parse message\n");
		return SCB_RUN_ALL;
	}
	LM_DBG("start - method = %.*s\n", msg->first_line.u.request.method.len,
		 msg->first_line.u.request.method.s);

	if(msg->route)
	{
		LM_DBG("Found route headers\n");
		route_hdr = msg->route;
		/* we accept Route hdrs only if preloaded route with out IPs */
		if (parse_rr(route_hdr) < 0) {
			LM_ERR("failed to parse Route HF\n");
			return SCB_RUN_ALL;
		}
		rt = (rr_t*)route_hdr->parsed;
		/* check if first route is local*/
		if ( parse_uri(rt->nameaddr.uri.s,rt->nameaddr.uri.len,&puri)!=0 ) {
			LM_ERR("Route uri is not valid <%.*s>\n",
				rt->nameaddr.uri.len,rt->nameaddr.uri.s);
			return SCB_RUN_ALL;
		}
		if (check_self( &puri.host, puri.port_no?puri.port_no:SIP_PORT,
		puri.proto?puri.proto:PROTO_UDP)!= 1 ) {
			LM_DBG("First Route uri is not mine\n");
			return SCB_RUN_ALL;  /* not for b2b */
		}
		/* check if second route is local*/
		rt = rt->next;
		if (rt==NULL) {
			if (msg->route->sibling) {
				route_hdr = msg->route->sibling;
				if (parse_rr(route_hdr) < 0) {
					LM_ERR("failed to parse second Route HF\n");
					return SCB_RUN_ALL;
				}
				rt = (rr_t*)route_hdr->parsed;
			}
		}
		if (rt) {
			if ( parse_uri(rt->nameaddr.uri.s,rt->nameaddr.uri.len,&puri)!=0 ) {
				LM_ERR("Second route uri is not valid <%.*s>\n",
					rt->nameaddr.uri.len,rt->nameaddr.uri.s);
				return SCB_RUN_ALL;
			}
			if (check_self( &puri.host, puri.port_no?puri.port_no:SIP_PORT,
			puri.proto?puri.proto:PROTO_UDP)!= 1 ) {
				LM_DBG("Second Route uri is not mine\n");
				return SCB_RUN_ALL;  /* not for b2b */
			}
			/* check the presence of the third route */
			if (rt->next || route_hdr->sibling) {
				LM_DBG("More than 2 route hdr -> not for me\n");
				return SCB_RUN_ALL;  /* not for b2b */
			}
		}
		/* "route" hdr checking is ok, continue */
	}

	method_value = msg->first_line.u.request.method_value;

	if(method_value == METHOD_ACK)
	{
		goto search_dialog;
	}
	if(parse_sip_msg_uri(msg)< 0)
	{
		LM_ERR("Failed to parse uri\n");
		return SCB_RUN_ALL;
	}
	host = msg->parsed_uri.host;
	port = msg->parsed_uri.port_no;

	/* check if RURI points to me */
	if(method_value!= METHOD_CANCEL)
	{
		LM_DBG("<uri> host:port [%.*s][%d]\n", host.len, host.s, port);
		if (!check_self( &host, port ? port : SIP_PORT, msg->rcv.proto))
		{
			LM_DBG("RURI does not point to me\n");
			return SCB_RUN_ALL;
		}
	}

	if(method_value == METHOD_PRACK)
	{
		LM_DBG("Received a PRACK - send 200 reply\n");
		str reason={"OK", 2};
		/* send 200 OK and exit */
		tmb.t_reply(msg, 200, &reason);
		tm_tran = tmb.t_gett();
		if(tm_tran)
			tmb.unref_cell(tm_tran);

		/* No need to apply lumps */
		if(req_routeid > 0)
			run_top_route(rlist[req_routeid].a, msg);

		goto done;
	}

search_dialog:
	if( msg->callid==NULL || msg->callid->body.s==NULL)
	{
		LM_ERR("no callid header found\n");
		return SCB_RUN_ALL;
	}
	/* examine the from header */
	if (!msg->from || !msg->from->body.s)
	{
		LM_ERR("cannot find 'from' header!\n");
		return SCB_RUN_ALL;
	}
	if (msg->from->parsed == NULL)
	{
		if ( parse_from_header( msg )<0 )
		{
			LM_ERR("cannot parse From header\n");
			return SCB_RUN_ALL;
		}
	}

	callid = msg->callid->body;
	from_tag = ((struct to_body*)msg->from->parsed)->tag_value;
	if (from_tag.len==0 || from_tag.s==NULL) {
		LM_ERR("From header has no TAG parameter\n");
		return SCB_RUN_ALL;
	}

	/* if a CANCEL request - search iteratively in the server_htable*/
	if(method_value == METHOD_CANCEL)
	{
		/*str ruri= msg->first_line.u.request.uri;*/
		str reply_text={"canceling", 9};
		/* This makes no sense - why not accepting a CANCEL that was
		   generated by other b2b instance ? or ourselves ? - bogdan
		if(b2b_parse_key(&callid, &hash_index, &local_index) >= 0)
		{
			LM_DBG("received a CANCEL message that I sent\n");
			return SCB_RUN_ALL;
		}
		*/

		hash_index = core_hash(&callid, &from_tag, server_hsize);
		/* As per RFC3261, the RURI must be used when matching the CANCEL
		   against the INVITE, but we should not do it here as B2B learns
		   a RURI that may have been changed in script (before invoking the
		   B2B module), while the CANCEL has the original RURI (as received)
		*/
		dlg = b2bl_search_iteratively(&callid, &from_tag, NULL/*&ruri*/, hash_index);
		if(dlg == NULL)
		{
			lock_release(&server_htable[hash_index].lock);
			LM_DBG("No dialog found for cancel\n");
			return SCB_RUN_ALL;
		}
		table = server_htable;
		/* send 200 canceling */
		ret = tmb.t_newtran(msg);
		if(ret < 1)
		{
			if(ret== 0)
			{
				LM_DBG("It is a retransmission, drop\n");
				tmb.unref_cell(tmb.t_gett());
			}
			else
				LM_DBG("Error when creating tm transaction\n");
			lock_release(&server_htable[hash_index].lock);
			return SCB_DROP_MSG;
		}

		if(tmb.t_reply(msg, 200, &reply_text) < 0)
		{
			LM_ERR("failed to send reply for CANCEL\n");
			lock_release(&server_htable[hash_index].lock);
			return SCB_RUN_ALL;
		}
		tmb.unref_cell(tmb.t_gett());

		b2b_key = dlg->tag[CALLEE_LEG];

		goto logic_notify;
	}

	/* we are interested only in request inside dialog */
	/* examine the to header */
	if (msg->to==NULL || msg->to->parsed == NULL ||
	((struct to_body *)msg->to->parsed)->error != PARSE_OK )
	{
		LM_DBG("'To' header COULD NOT parsed\n");
		return SCB_DROP_MSG;
	}
	to_tag = get_to(msg)->tag_value;
	if(to_tag.s == NULL || to_tag.len == 0)
	{
		LM_DBG("Not an inside dialog request- not interested.\n");
		return SCB_RUN_ALL;
	}

	b2b_key = to_tag;
	/* check if the to tag has the b2b key format -> meaning that it is a server request */
	if(b2b_key.s && b2b_parse_key(&b2b_key, &hash_index, &local_index) >= 0)
	{
		LM_DBG("Received a b2b server request [%.*s]\n",
					msg->first_line.u.request.method.len,
					msg->first_line.u.request.method.s);
		table = server_htable;
	}
	else
	{
		/* check if the callid is in b2b format -> meaning that this is a client request */
		b2b_key = msg->callid->body;
		if(b2b_parse_key(&b2b_key, &hash_index, &local_index) >= 0)
		{
			LM_DBG("received a b2b client request [%.*s]\n",
				msg->first_line.u.request.method.len,
				msg->first_line.u.request.method.s);
			table = client_htable;
		}
		else /* if also not a client request - not for us */
		{
			if(method_value != METHOD_UPDATE)
			{
				LM_DBG("Not a b2b request\n");
				return SCB_RUN_ALL;
			}
			else
			{
				/* for server UPDATE sent before dialog confirmed */
				table = server_htable;
				hash_index = core_hash(&callid, &from_tag, server_hsize);
				dlg = b2bl_search_iteratively(&callid, &from_tag,NULL, hash_index);
				if(dlg == NULL)
				{
					lock_release(&server_htable[hash_index].lock);
					LM_DBG("No dialog found for cancel\n");
					return SCB_RUN_ALL;
				}
			}
		}
	}

	if(!dlg)
	{
		lock_get(&table[hash_index].lock);
		dlg = b2b_search_htable_dlg(table, hash_index, local_index,
			&to_tag, &from_tag, &callid);
		if(dlg== NULL)
		{
			LM_DBG("No dialog found\n");
			if(method_value != METHOD_ACK)
			{
				str ok = str_init("OK");

				if(method_value == METHOD_BYE)
					tmb.t_reply(msg, 200, &ok);
				else
					LM_ERR("No dialog found, callid= [%.*s], method=%.*s\n",
						callid.len, callid.s,msg->first_line.u.request.method.len,
						msg->first_line.u.request.method.s);
			}
			lock_release(&table[hash_index].lock);
			return SCB_RUN_ALL;
		}
	}

	if(dlg->state < B2B_CONFIRMED)
	{
		if(method_value != METHOD_UPDATE)
		{
			LM_DBG("I can not accept requests if the state is not confimed\n");
			lock_release(&table[hash_index].lock);
			return SCB_DROP_MSG;
		}
	}

	LM_DBG("Received request method[%.*s] for dialog[%p]\n",
			msg->first_line.u.request.method.len,
			msg->first_line.u.request.method.s,  dlg);

	if(method_value == METHOD_ACK && dlg->state == B2B_ESTABLISHED)
	{
		LM_DBG("It is a ACK retransmission, drop\n");
		lock_release(&table[hash_index].lock);
		return SCB_DROP_MSG;
	}

logic_notify:
	etype = (table==server_htable?B2B_SERVER:B2B_CLIENT);

	if(req_routeid > 0)
	{
		lock_release(&table[hash_index].lock);
		run_top_route(rlist[req_routeid].a, msg);
		if (b2b_apply_lumps(msg))
		{
			if (parse_from_header(msg) < 0)
			{
				LM_ERR("cannot parse From header\n");
				return SCB_DROP_MSG;
			}
			callid = msg->callid->body;
			from_tag = ((struct to_body*)msg->from->parsed)->tag_value;
			to_tag = get_to(msg)->tag_value;
			if (table == server_htable)
			{
				if (method_value != METHOD_CANCEL)
					b2b_key = to_tag;
			}
			else
			{
				b2b_key = msg->callid->body;
			}
		}
		lock_get(&table[hash_index].lock);
	}

	if(method_value != METHOD_CANCEL)
	{
		ret = tmb.t_newtran(msg);
		if(ret < 1 && method_value != METHOD_ACK)
		{
			if(ret== 0)
			{
				LM_DBG("It is a retransmission, drop\n");
				tmb.unref_cell(tmb.t_gett());
			}
			else
				LM_DBG("Error when creating tm transaction\n");
			lock_release(&table[hash_index].lock);
			return SCB_DROP_MSG;
		}

		tm_tran = tmb.t_gett();
		if(method_value != METHOD_ACK)
		{
			if(method_value == METHOD_UPDATE)
			{
				dlg->update_tran = tm_tran;
			}
			else
			{
				if(method_value == METHOD_INVITE || method_value == METHOD_BYE)
				{
					tmb.t_setkr(REQ_FWDED);
				}

				if(dlg->uas_tran && dlg->uas_tran!=T_UNDEFINED)
				{
					if(dlg->uas_tran->uas.request)
					/* there is another transaction for which no reply
					 * was sent out */
					{
						/* send reply */
						LM_DBG("Received another request when the previous "
							"one was in process\n");
						str text = str_init("Request Pending");
						if(tmb.t_reply_with_body( tm_tran, 491,
						&text, 0, 0, &to_tag) < 0)
						{
							LM_ERR("failed to send reply with tm\n");
						}
						LM_DBG("Sent reply [491] and unreffed the cell %p\n",
							tm_tran);
					}
					tmb.unref_cell(tm_tran); /* for t_newtran() */
					lock_release(&table[hash_index].lock);
					return SCB_DROP_MSG;
				}
				dlg->uas_tran = tm_tran;
				LM_DBG("Saved uas_tran=[%p] for dlg[%p]\n", tm_tran, dlg);
			}
		}
		else
		{
			if(!tm_tran || tm_tran==T_UNDEFINED)
				tm_tran = tmb.t_get_e2eackt();

			if(tm_tran && tm_tran!=T_UNDEFINED)
				tmb.unref_cell(tm_tran);
		}
	}

	b2b_cback = dlg->b2b_cback;
	if(dlg->param.s)
	{
		param.s = (char*)pkg_malloc(dlg->param.len);
		if(param.s == NULL)
		{
			LM_ERR("No more private memory\n");
			lock_release(&table[hash_index].lock);
			return SCB_RUN_ALL;
		}
		memcpy(param.s, dlg->param.s, dlg->param.len);
		param.len = dlg->param.len;
	}

	set_dlg_state( dlg, method_value);

	UPDATE_DBFLAG(dlg);
/*
	if(b2be_db_mode == WRITE_THROUGH && dlg->state>B2B_CONFIRMED)
	{
		if(b2be_db_update(dlg, etype) < 0)
			LM_ERR("Failed to update in database\n");
	}
*/
	current_dlg = dlg;
	dlg_state = dlg->state;
	lock_release(&table[hash_index].lock);

	b2b_cback(msg, &b2b_key, B2B_REQUEST, param.s?&param:0);

	if(param.s)
		pkg_free(param.s);

done:
	current_dlg = 0;
	if(b2be_db_mode == WRITE_THROUGH && etype!=B2B_NONE && dlg_state>B2B_CONFIRMED)
	{
		/* search the dialog */
		lock_get(&table[hash_index].lock);
		for(aux_dlg = table[hash_index].first; aux_dlg; aux_dlg = aux_dlg->next)
		{
			if(aux_dlg == dlg)
				break;
		}
		if(!aux_dlg)
		{
			LM_DBG("Record not found anymore\n");
			lock_release(&table[hash_index].lock);
			return SCB_DROP_MSG;
		}
		if(b2be_db_update(dlg, etype) < 0)
			LM_ERR("Failed to update in database\n");
		lock_release(&table[hash_index].lock);
	}

	return SCB_DROP_MSG;
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
				if(dlg->ack_sdp.s)
					shm_free(dlg->ack_sdp.s);
				shm_free(dlg);
				dlg = aux;
			}
		}
		shm_free(server_htable);
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
				b2b_delete_legs(&dlg->legs);
				if(dlg->ack_sdp.s)
					shm_free(dlg->ack_sdp.s);
				shm_free(dlg);
				dlg = aux;
			}
		}
		shm_free(client_htable);
	}
}


b2b_dlg_t* b2b_new_dlg(struct sip_msg* msg, str* local_contact,
		b2b_dlg_t* init_dlg, str* param)
{
	struct to_body *pto, *pfrom = NULL;
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
	if (msg->first_line.type == SIP_REQUEST)
	{
		if(msg->first_line.u.request.method_value != METHOD_INVITE)
		{
			LM_ERR("Called b2b_init on a Cancel message\n");
			return 0;
		}
		dlg.ruri = msg->first_line.u.request.uri;
	}

	pto = get_to(msg);
	if (pto == NULL || pto->error != PARSE_OK)
	{
		LM_DBG("'To' header COULD NOT parsed\n");
		return 0;
	}

	if(pto->tag_value.s!= 0 && pto->tag_value.len != 0)
	{
		LM_DBG("Not an initial request\n");
		dlg.tag[CALLEE_LEG] = pto->tag_value;
	}

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
	if( pfrom->tag_value.s ==NULL || pfrom->tag_value.len == 0)
	{
		LM_ERR("no from tag value present\n");
		return 0;
	}
	dlg.tag[CALLER_LEG] = pfrom->tag_value;

	/* for ACK TO & FROM headers must be the same as in Invite */
	if(init_dlg) {
		dlg.to_uri = init_dlg->to_uri;
		dlg.to_dname = init_dlg->to_dname;
		dlg.from_uri = init_dlg->from_uri;
		dlg.from_dname = init_dlg->from_dname;
	}
	else
	{
		dlg.to_uri= pto->uri;
		dlg.to_dname= pto->display;
		dlg.from_uri = pfrom->uri;
		dlg.from_dname = pfrom->display;
	}

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
	dlg.last_invite_cseq = dlg.cseq[CALLER_LEG];
	dlg.cseq[CALLEE_LEG] = 1;

	if( msg->contact!=NULL && msg->contact->body.s!=NULL)
	{
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
		if(init_dlg) /* called on reply */
			dlg.contact[CALLEE_LEG] = b->contacts->uri;
		else
			dlg.contact[CALLER_LEG] = b->contacts->uri;
	}

	if(msg->record_route!=NULL && msg->record_route->body.s!= NULL)
	{
		if( print_rr_body(msg->record_route, &dlg.route_set[CALLER_LEG], (init_dlg?1:0), 0)!= 0)
		{
			LM_ERR("failed to process record route\n");
		}
	}

	dlg.send_sock = msg->rcv.bind_address;
	if(init_dlg) /* called on reply */
		dlg.contact[CALLER_LEG]=*local_contact;
	else
		dlg.contact[CALLEE_LEG]=*local_contact;

	if (!msg->content_length)
	{
		LM_ERR("no Content-Length header found!\n");
		return 0;
	}

	if(!init_dlg) /* called from server_new on initial Invite */
	{
		if(msg->via1->branch)
		{
			dlg.id = core_hash(&dlg.ruri, &msg->via1->branch->value, server_hsize);
		} else {
			dlg.id = core_hash(&dlg.ruri, &msg->callid->body, server_hsize);
		}
	}

	if(param)
		dlg.param = *param;
	dlg.db_flag = INSERTDB_FLAG;

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
int b2b_send_reply(b2b_rpl_data_t* rpl_data)
{
	enum b2b_entity_type et = rpl_data->et;
	str* b2b_key = rpl_data->b2b_key;
	int sip_method = rpl_data->method;
	int code = rpl_data->code;
	str* extra_headers = rpl_data->extra_headers;
	b2b_dlginfo_t* dlginfo = rpl_data->dlginfo;

	unsigned int hash_index, local_index;
	b2b_dlg_t* dlg;
	str* to_tag = NULL;
	struct cell* tm_tran;
	struct sip_msg* msg;
	char buffer[BUF_LEN];
	int len;
	char* p;
	str ehdr;
	b2b_table table;
	str totag, fromtag;
	struct to_body *pto;
	unsigned int method_value = METHOD_UPDATE;
	str local_contact;

	if(et == B2B_SERVER)
	{
		LM_DBG("For server entity\n");
		table = server_htable;
		if(dlginfo)
		{
			totag = dlginfo->fromtag;
			fromtag = dlginfo->totag;
		}
	}
	else
	{
		LM_DBG("For client entity\n");
		table = client_htable;
		if(dlginfo)
		{
			totag = dlginfo->fromtag;
			fromtag = dlginfo->totag;
		}
	}

	/* parse the key and find the position in hash table */
	if(b2b_parse_key(b2b_key, &hash_index, &local_index) < 0)
	{
		LM_ERR("Wrong format for b2b key\n");
		return -1;
	}

	lock_get(&table[hash_index].lock);
	if(dlginfo == NULL)
	{
		dlg = b2b_search_htable(table, hash_index, local_index);
	}
	else
	{
		dlg = b2b_search_htable_dlg(table, hash_index, local_index,
		&fromtag, &totag, &dlginfo->callid);
	}
	if(dlg== NULL)
	{
		LM_ERR("No dialog found\n");
		lock_release(&table[hash_index].lock);
		return -1;
	}

/*	if(dlg->callid.s == NULL)
	{
		LM_DBG("NULL callid. Dialog Information not completed yet\n");
		lock_release(&table[hash_index].lock);
		return 0;
	}
*/
	if(et == B2B_CLIENT)
		local_contact = dlg->contact[CALLER_LEG];
	else
		local_contact = dlg->contact[CALLEE_LEG];

	if(sip_method == METHOD_UPDATE)
		tm_tran = dlg->update_tran;
	else
	{
		tm_tran = dlg->uas_tran;
		if(tm_tran)
		{
			if(parse_method(tm_tran->method.s,
					tm_tran->method.s + tm_tran->method.len, &method_value) == 0)
			{
				LM_ERR("Wrong method stored in tm transaction [%.*s]\n",
					tm_tran->method.len, tm_tran->method.s);
				lock_release(&table[hash_index].lock);
				return -1;
			}
			if(sip_method != method_value)
			{
				LM_ERR("Mismatch between the method in tm[%d] and the method to send reply to[%d]\n",
						sip_method, method_value);
				lock_release(&table[hash_index].lock);
				return -1;
			}
		}
	}
	if(tm_tran == NULL)
	{
		LM_DBG("code = %d, last_method= %d\n", code, dlg->last_method);
		if(dlg->last_reply_code == code)
		{
			LM_DBG("it is a retransmission - nothing to do\n");
			lock_release(&table[hash_index].lock);
			return 0;
		}
		LM_ERR("Tm transaction not saved!\n");
		lock_release(&table[hash_index].lock);
		return -1;
	}

	LM_DBG("Send reply %d %.*s, for dlg [%p]->[%.*s]\n", code, tm_tran->method.len,
			tm_tran->method.s, dlg, b2b_key->len, b2b_key->s);

	if(method_value==METHOD_INVITE &&
			(dlg->state==B2B_CONFIRMED || dlg->state==B2B_ESTABLISHED))
	{
		LM_DBG("A retransmission of the reply\n");
		lock_release(&table[hash_index].lock);
		return 0;
	}

	if(code >= 200)
	{
		if(method_value==METHOD_INVITE)
		{
			if(code < 300)
				dlg->state = B2B_CONFIRMED;
			else
				dlg->state= B2B_TERMINATED;
			UPDATE_DBFLAG(dlg);
		}
		LM_DBG("Reseted transaction- send final reply [%p], uas_tran=0\n", dlg);
		if(sip_method == METHOD_UPDATE)
			dlg->update_tran = NULL;
		else
			dlg->uas_tran = NULL;
	}

	msg = tm_tran->uas.request;
	if(msg== NULL)
	{
		LM_DBG("Transaction not valid anymore\n");
		lock_release(&table[hash_index].lock);
		return 0;
	}

	if(parse_headers(msg, HDR_EOH_F, 0) < 0)
	{
		LM_ERR("Failed to parse headers\n");
		return 0;
	}

	pto = get_to(msg);
	if (pto == NULL || pto->error != PARSE_OK)
	{
		LM_ERR("'To' header COULD NOT parsed\n");
		return 0;
	}

	/* only for the server replies to the initial INVITE */
	if(!pto || !pto->tag_value.s || !pto->tag_value.len)
	{
		to_tag = b2b_key;
	}
	else
		to_tag = &pto->tag_value;

	/* if sent reply for bye, delete the record */
	if(method_value == METHOD_BYE)
		dlg->state = B2B_TERMINATED;

	dlg->last_reply_code = code;
	UPDATE_DBFLAG(dlg);

	if(b2be_db_mode==WRITE_THROUGH && current_dlg!=dlg && dlg->state>B2B_CONFIRMED) {
		if(b2be_db_update(dlg, et) < 0)
			LM_ERR("Failed to update in database\n");
	}

	lock_release(&table[hash_index].lock);

	if((extra_headers?extra_headers->len:0) + 14 + local_contact.len
			+ 20 + CRLF_LEN > BUF_LEN)
	{
		LM_ERR("Buffer overflow!\n");
		goto error;
	}
	p = buffer;

	if(extra_headers && extra_headers->s && extra_headers->len)
	{
		memcpy(p, extra_headers->s, extra_headers->len);
		p += extra_headers->len;
	}
	len = sprintf(p,"Contact: <%.*s>", local_contact.len, local_contact.s);
	p += len;
	memcpy(p, CRLF, CRLF_LEN);
	p += CRLF_LEN;
	ehdr.len = p -buffer;
	ehdr.s = buffer;

	/* send reply */
	if(tmb.t_reply_with_body(tm_tran, code, rpl_data->text, rpl_data->body, &ehdr, to_tag) < 0)
	{
		LM_ERR("failed to send reply with tm\n");
		goto error;
	}
	if(code >= 200)
	{
		LM_DBG("Sent reply [%d] and unreffed the cell %p\n", code, tm_tran);
		tmb.unref_cell(tm_tran);
	}
	else
	{
		LM_DBG("code not >= 200\n");
	}
	return 0;

error:
	if(code >= 200)
	{
		tmb.unref_cell(tm_tran);
	}
	return -1;
}

void b2b_delete_record(b2b_dlg_t* dlg, b2b_table htable, unsigned int hash_index)
{
	if(dlg->prev == NULL)
	{
		htable[hash_index].first = dlg->next;
	}
	else
	{
		dlg->prev->next = dlg->next;
	}

	if(dlg->next)
		dlg->next->prev = dlg->prev;

	if(htable == server_htable && dlg->tag[CALLEE_LEG].s)
		shm_free(dlg->tag[CALLEE_LEG].s);

	b2b_delete_legs(&dlg->legs);

	if(dlg->uac_tran)
		tmb.unref_cell(dlg->uac_tran);

	if(dlg->uas_tran)
		tmb.unref_cell(dlg->uas_tran);

	if(dlg->ack_sdp.s)
		shm_free(dlg->ack_sdp.s);

	shm_free(dlg);
}

void b2b_entity_delete(enum b2b_entity_type et, str* b2b_key,
		 b2b_dlginfo_t* dlginfo, int db_del)
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
	if(dlginfo)
		dlg = b2b_search_htable_dlg(table, hash_index, local_index,
		dlginfo->totag.s?&dlginfo->totag:NULL,
		dlginfo->fromtag.s?&dlginfo->fromtag:NULL, &dlginfo->callid);
	else
		dlg = b2b_search_htable(table, hash_index, local_index);

	if(dlg== NULL)
	{
		LM_ERR("No dialog found\n");
		lock_release(&table[hash_index].lock);
		return;
	}
	LM_DBG("Deleted dlg [%p]->[%.*s] with dlginfo [%p]\n",
			dlg, b2b_key->len, b2b_key->s, dlginfo);

	if(db_del)
		b2b_entity_db_delete(et, dlg);

	b2b_delete_record(dlg, table, hash_index);
	lock_release(&table[hash_index].lock);
}

void shm_free_param(void* param)
{
	shm_free(param);
}

dlg_t* b2b_client_dlg(b2b_dlg_t* dlg)
{
	return b2b_client_build_dlg(dlg, dlg->legs);
}

void free_tm_dlg(dlg_t* td)
{
	if(!td)
		return;
	if(td->route_set)
		free_rr(&td->route_set);
	pkg_free(td);
}

int b2b_send_indlg_req(b2b_dlg_t* dlg, enum b2b_entity_type et,
		str* b2b_key, str* method, str* ehdr, str* body, unsigned int no_cb)
{
	str* b2b_key_shm = NULL;
	dlg_t* td = NULL;
	transaction_cb* tm_cback;
	build_dlg_f build_dlg;
	int method_value = dlg->last_method;
	int result;

	if (!no_cb) {
		b2b_key_shm= b2b_key_copy_shm(b2b_key);
		if(b2b_key_shm== NULL)
		{
			LM_ERR("no more shared memory\n");
			return -1;
		}
	}

	if(et == B2B_SERVER)
	{
		build_dlg = b2b_server_build_dlg;
		tm_cback = b2b_server_tm_cback;
	}
	else
	{
		build_dlg = b2b_client_dlg;
		tm_cback = b2b_client_tm_cback;
	}

	/* build structure with dialog information */
	td = build_dlg(dlg);
	if(td == NULL)
	{
		LM_ERR("Failed to build tm dialog structure, was asked to send [%.*s]"
				" request\n", method->len, method->s);
		if (b2b_key_shm)
			shm_free(b2b_key_shm);
		return -1;
	}

	if(method_value == METHOD_ACK)
	{
		td->loc_seq.value = dlg->last_invite_cseq;
		if(et == B2B_SERVER)
			dlg->cseq[CALLEE_LEG]--;
		else
			dlg->cseq[CALLER_LEG]--;

		if(dlg->ack_sdp.s)
		{
			shm_free(dlg->ack_sdp.s);
			dlg->ack_sdp.s=NULL;
			dlg->ack_sdp.len=0;
		}
		if(body && body->s)
		{
			dlg->ack_sdp.s = (char*)shm_malloc(body->len);
			if(dlg->ack_sdp.s == NULL)
			{
				LM_ERR("No more memory\n");
				goto error;
			}
			memcpy(dlg->ack_sdp.s, body->s, body->len);
			dlg->ack_sdp.len = body->len;
		}
	}
	else
	if(method_value == METHOD_INVITE)
	{
		dlg->last_invite_cseq = td->loc_seq.value +1;
		if(dlg->uac_tran)
			tmb.unref_cell(dlg->uac_tran);
		tmb.setlocalTholder(&dlg->uac_tran);
	}


	if (no_cb)
	{
		result= tmb.t_request_within
			(method,            /* method*/
			ehdr,               /* extra headers*/
			body,               /* body*/
			td,                 /* dialog structure*/
			NULL,               /* callback function*/
			NULL,               /* callback parameter*/
			NULL);
	}
	else
	{
		td->T_flags = T_NO_AUTOACK_FLAG|T_PASS_PROVISIONAL_FLAG;
		result= tmb.t_request_within
			(method,            /* method*/
			ehdr,               /* extra headers*/
			body,               /* body*/
			td,                 /* dialog structure*/
			tm_cback,           /* callback function*/
			b2b_key_shm,        /* callback parameter*/
			shm_free_param);
	}

	tmb.setlocalTholder(0);

	if(result < 0)
	{
		LM_ERR("failed to send request [%.*s] for dlg=[%p] uac_tran=[%p]\n",
			method->len, method->s, dlg, dlg->uac_tran);
		goto error;
	}
	free_tm_dlg(td);

	return 0;
error:
	if(td)
		free_tm_dlg(td);
	if(b2b_key_shm)
		shm_free(b2b_key_shm);
	return -1;
}



/*
 *	Function to send a request inside a b2b dialog
 *	et      : entity type - it can be B2B_SEVER or B2B_CLIENT
 *	b2b_key : the key to identify the dialog
 *	method  : the method for the request
 *	extra_headers  : the extra headers to be included in the request(optional)
 *	body    : the body to be included in the request(optional)
 *	dlginfo : extra params for matching the dialog
 *	no_cb   : no callback required
 * */
int b2b_send_request(b2b_req_data_t* req_data)
{
	enum b2b_entity_type et = req_data->et;
	str* b2b_key = req_data->b2b_key;
	str* method = req_data->method;
	b2b_dlginfo_t* dlginfo = req_data->dlginfo;

	unsigned int hash_index, local_index;
	b2b_dlg_t* dlg;
	str ehdr = {NULL, 0};
	b2b_table table;
	str totag={NULL,0}, fromtag={NULL, 0};
	unsigned int method_value;
	int ret;

	if(et == B2B_SERVER)
	{
		table = server_htable;
	}
	else
	{
		table = client_htable;
	}

	if(dlginfo)
	{
		totag = dlginfo->totag;
		fromtag = dlginfo->fromtag;
	}

	/* parse the key and find the position in hash table */
	if(b2b_parse_key(b2b_key, &hash_index, &local_index) < 0)
	{
		LM_ERR("Wrong format for b2b key [%.*s]\n", b2b_key->len, b2b_key->s);
		return -1;
	}

	lock_get(&table[hash_index].lock);
	if(dlginfo == NULL)
	{
		dlg = b2b_search_htable(table, hash_index, local_index);
	}
	else
	{
		dlg = b2b_search_htable_dlg(table, hash_index, local_index,
		totag.s?&totag:NULL, fromtag.s?&fromtag:NULL, &dlginfo->callid);
	}
	if(dlg== NULL)
	{
		LM_ERR("No dialog found for b2b key [%.*s] and dlginfo=[%p]\n",
			b2b_key->len, b2b_key->s, dlginfo);
		goto error;
	}

	parse_method(method->s, method->s+method->len, &method_value);

	if(dlg->state == B2B_TERMINATED)
	{
		LM_ERR("Can not send request [%.*s] for entity type [%d] "
			"for dlg[%p]->[%.*s] in terminated state\n",
			method->len, method->s, et,
			dlg, b2b_key->len, b2b_key->s);
		lock_release(&table[hash_index].lock);
		if(method_value==METHOD_BYE || method_value==METHOD_CANCEL)
			return 0;
		else
			return -1;
	}

	if(b2breq_complete_ehdr(req_data->extra_headers, &ehdr, req_data->body,
			((et==B2B_SERVER)?&dlg->contact[CALLEE_LEG]:&dlg->contact[CALLER_LEG]))< 0)
	{
		LM_ERR("Failed to complete extra headers\n");
		goto error;
	}

	if(dlg->state < B2B_CONFIRMED)
	{
		if(method_value == METHOD_BYE && et==B2B_CLIENT) /* send CANCEL*/
		{
			method_value = METHOD_CANCEL;
		}
		else
		if(method_value!=METHOD_UPDATE && method_value!=METHOD_PRACK &&
			method_value!=METHOD_CANCEL && (method_value!=METHOD_INVITE /**/))
		{
			LM_ERR("State [%d] not established, can not send request %.*s, [%.*s]\n",
				dlg->state, method->len, method->s, b2b_key->len, b2b_key->s);
			lock_release(&table[hash_index].lock);
			return -1;
		}
	}
	else
	if(dlg->state==B2B_CONFIRMED && method_value!=METHOD_ACK &&
			dlg->last_method == METHOD_INVITE)
	{
		/* send it ACK so that you can send the new request */
		b2b_send_indlg_req(dlg, et, b2b_key, &ack, &ehdr, req_data->body, req_data->no_cb);
		dlg->state= B2B_ESTABLISHED;
	}

	dlg->last_method = method_value;
	LM_DBG("Send request [%.*s] for entity type [%d] for dlg[%p]->[%.*s]\n",
			method->len, method->s, et,
			dlg, b2b_key->len, b2b_key->s);
	UPDATE_DBFLAG(dlg);

	/* send request */
	if(method_value == METHOD_CANCEL)
	{
		if(dlg->state < B2B_CONFIRMED)
		{
			if(dlg->uac_tran)
			{
				struct cell *inv_t;
				LM_DBG("send cancel request\n");
				if (tmb.t_lookup_ident( &inv_t, dlg->uac_tran->hash_index,
				dlg->uac_tran->label) != 1) {
					LM_ERR("Invite trasaction not found\n");
					goto error;
				}
				ret = tmb.t_cancel_trans( inv_t, &ehdr);
				tmb.unref_cell(inv_t);
			}
			else
			{
				LM_ERR("No transaction saved. Cannot send CANCEL\n");
				goto error;
			}
		}
		else
		{
			if(dlg->state == B2B_CONFIRMED)
			{
				b2b_send_indlg_req(dlg, et, b2b_key, &ack, &ehdr, 0, req_data->no_cb);
			}
			ret = b2b_send_indlg_req(dlg, et, b2b_key, &bye, &ehdr, req_data->body, req_data->no_cb);
			method_value = METHOD_BYE;
		}
	}
	else
	{
		ret = b2b_send_indlg_req(dlg, et, b2b_key, method, &ehdr, req_data->body, req_data->no_cb);
	}

	if(ret < 0)
	{
		LM_ERR("Failed to send request\n");
		goto error;
	}
	set_dlg_state(dlg, method_value);

	if(b2be_db_mode==WRITE_THROUGH && current_dlg!=dlg && dlg->state>B2B_CONFIRMED) {
		if(b2be_db_update(dlg, et) < 0)
			LM_ERR("Failed to update in database\n");
	}

	lock_release(&table[hash_index].lock);

	return 0;
error:
	lock_release(&table[hash_index].lock);
	return -1;
}

dlg_leg_t* b2b_find_leg(b2b_dlg_t* dlg, str to_tag)
{
	dlg_leg_t* leg = dlg->legs;

	while(leg)
	{
		/* compare the tag */
		if(to_tag.len == leg->tag.len &&
				strncmp(to_tag.s, leg->tag.s, to_tag.len)==0)
		{
			LM_DBG("Found existing leg  - Nothing to update\n");
			return leg;
		}
		leg = leg->next;
	}
	return 0;
}

dlg_leg_t* b2b_new_leg(struct sip_msg* msg, str* to_tag, int mem_type)
{
	str contact = {NULL, 0};
	str route_set= {NULL, 0};
	dlg_leg_t* new_leg;
	contact_body_t* b;
	int size;

	if( msg->contact!=NULL && msg->contact->body.s!=NULL)
	{
		if(parse_contact(msg->contact) <0 )
		{
			LM_ERR("failed to parse contact header\n");
			goto error;
		}
		b= (contact_body_t* )msg->contact->parsed;
		if(b == NULL)
		{
			LM_ERR("contact header not parsed\n");
			goto error;
		}
		contact = b->contacts->uri;
	}

	if(msg->record_route!=NULL && msg->record_route->body.s!= NULL)
	{
		if( print_rr_body(msg->record_route, &route_set, 1, 0)!= 0)
		{
			LM_ERR("failed to process record route\n");
			goto error;
		}
	}
	size = sizeof(dlg_leg_t) + route_set.len + to_tag->len + contact.len;

	if(mem_type == SHM_MEM_TYPE)
		new_leg = (dlg_leg_t*)shm_malloc(size);
	else
		new_leg = (dlg_leg_t*)pkg_malloc(size);

	if(new_leg == NULL)
	{
		LM_ERR("No more shared memory");
		if(route_set.s)
			pkg_free(route_set.s);
		goto error;
	}
	memset(new_leg, 0, size);
	size = sizeof(dlg_leg_t);

	if(contact.s && contact.len)
	{
		new_leg->contact.s = (char*)new_leg + size;
		memcpy(new_leg->contact.s, contact.s, contact.len);
		new_leg->contact.len = contact.len;
		size+= contact.len;
	}

	if(route_set.s)
	{
		new_leg->route_set.s = (char*)new_leg + size;
		memcpy(new_leg->route_set.s, route_set.s, route_set.len);
		new_leg->route_set.len = route_set.len;
		size+= route_set.len;
		pkg_free(route_set.s);
	}

	new_leg->tag.s = (char*)new_leg + size;
	memcpy(new_leg->tag.s, to_tag->s, to_tag->len);
	new_leg->tag.len = to_tag->len;
	size += to_tag->len;

	if( msg->cseq==NULL || msg->cseq->body.s==NULL)
	{
		LM_ERR("failed to parse cseq header\n");
		goto error;
	}
	if (str2int( &(get_cseq(msg)->number), &new_leg->cseq)!=0 )
	{
		LM_ERR("failed to parse cseq number - not an integer\n");
		goto error;
	}

	return new_leg;

error:
	return 0;
}

dlg_leg_t* b2b_add_leg(b2b_dlg_t* dlg, struct sip_msg* msg, str* to_tag)
{
	dlg_leg_t* new_leg;

	new_leg = b2b_new_leg(msg, to_tag, SHM_MEM_TYPE);
	if(new_leg == NULL)
	{
		LM_ERR("Failed to create new leg\n");
		return 0;
	}
	if(dlg->legs != NULL)
	{
		new_leg->next = dlg->legs;
		new_leg->id = dlg->legs->id + 1;
	}
	dlg->legs = new_leg;
	return new_leg;
}

int b2b_send_req(b2b_dlg_t* dlg, enum b2b_entity_type etype,
		dlg_leg_t* leg, str* method, str* extra_headers, str* body)
{
	dlg_t* td;
	int result;

	if(!dlg->callid.s || !dlg->callid.len)
		return -1;

	if(!dlg->callid.s || !dlg->callid.len)
		return -1;

	LM_DBG("start type=%d\n", etype);
	if(etype== B2B_SERVER)
		td = b2b_server_build_dlg(dlg);
	else
		td = b2b_client_build_dlg(dlg, leg);

	if(td == NULL)
	{
		LM_ERR("Failed to create dialog info structure\n");
		return -1;
	}
	if(method->len == ACK_LEN && strncmp(method->s, ACK, ACK_LEN)==0)
	{
		td->loc_seq.value = dlg->last_invite_cseq;
		if(etype == B2B_SERVER)
			dlg->cseq[CALLEE_LEG]--;
		else
			dlg->cseq[CALLER_LEG]--;
	}

	/* send request */
	result= tmb.t_request_within
		(method,            /* method*/
		extra_headers,      /* extra headers*/
		NULL,               /* body*/
		td,                 /* dialog structure*/
		NULL,               /* callback function*/
		NULL,               /* callback parameter*/
		NULL);
	free_tm_dlg(td);
	return result;
}

static struct sip_msg dummy_msg;

static int build_extra_headers_from_msg(str buf, str *extra_hdr,
													str *new_hdrs, str *body)
{
	struct sip_msg req;
	struct hdr_field *hdr;
	int len;
	char *p;

	memset( &req, 0, sizeof(req) );
	req.buf = buf.s;
	req.len = buf.len;
	if (parse_msg(buf.s, buf.len, &req)!=0) {
		LM_CRIT("BUG - buffer parsing failed!");
		return -1;
	}
	/* parse all headers */
	if (parse_headers(&req, HDR_EOH_F, 0 )<0) {
		LM_ERR("parse_headers failed\n");
		goto error;
	}

	/* first calculate the total len */
	len = extra_hdr->len;
	for( hdr=req.headers; hdr ; hdr=hdr->next ) {
		/* skip all headers that are by default added by build_uac_req()
		 * We want to propagete only custom headers !!! */
		switch(hdr->type){
		case HDR_VIA_T:
		case HDR_TO_T:
		case HDR_FROM_T:
		case HDR_ROUTE_T:
		case HDR_CSEQ_T:
		case HDR_CALLID_T:
		case HDR_MAXFORWARDS_T:
		case HDR_CONTENTLENGTH_T:
		case HDR_USERAGENT_T:
			break;
		default:
			/* count the header (includes the CRLF) */
			len += hdr->len;
		}
	}

	/* allocate */
	new_hdrs->len = len;
	new_hdrs->s = pkg_malloc( len );
	if (new_hdrs->s==NULL) {
		LM_ERR("failed to allocate pkg mem (needed %d)\n",len);
		goto error;
	}

	/* copy headers */
	for( p=new_hdrs->s,hdr=req.headers; hdr ; hdr=hdr->next ) {
		switch(hdr->type){
		case HDR_VIA_T:
		case HDR_TO_T:
		case HDR_FROM_T:
		case HDR_ROUTE_T:
		case HDR_CSEQ_T:
		case HDR_CALLID_T:
		case HDR_MAXFORWARDS_T:
		case HDR_CONTENTLENGTH_T:
		case HDR_USERAGENT_T:
			break;
		default:
			/* copy the header (includes the CRLF) */
			memcpy( p, hdr->name.s , hdr->len);
			p += hdr->len;
		}
	}
	/* and extra */
	memcpy( p, extra_hdr->s, extra_hdr->len);

	if (get_body( &req, body)<0) {
		LM_ERR("failed to extract body\n");
		pkg_free( new_hdrs->s );
		goto error;
	}

	free_sip_msg(&req);

	return 0;
error:
	free_sip_msg(&req);
	new_hdrs->s = body->s = NULL;
	new_hdrs->len = body->len = 0;
	return -1;
}


void b2b_tm_cback(struct cell *t, b2b_table htable, struct tmcb_params *ps)
{
	struct sip_msg * msg;
	str* b2b_key;
	unsigned int hash_index, local_index;
	b2b_notify_t b2b_cback;
	b2b_dlg_t *dlg, *previous_dlg;
	b2b_dlg_t *aux_dlg,*new_dlg;
	str param= {NULL, 0};
	int statuscode = 0;
	dlg_leg_t* leg;
	struct to_body* pto;
	str to_tag, callid, from_tag;
	str extra_headers = {NULL, 0};
	str body = {NULL, 0};
	struct hdr_field* hdr;
	unsigned int method_id = 0;
	struct cseq_body cb;
	struct hdr_field cseq;
	enum b2b_entity_type etype=(htable==server_htable?B2B_SERVER:B2B_CLIENT);
	int dlg_based_search = 0;
	struct hdr_field callid_hdr, from_hdr, to_hdr;
	struct to_body to_hdr_parsed, from_hdr_parsed;
	int dlg_state = 0;
	struct uac_credential* crd;
	struct authenticate_body *auth = NULL;
	static struct authenticate_nc_cnonce auth_nc_cnonce;
	HASHHEX response;
	str *new_hdr;
	char status_buf[INT2STR_MAX_LEN];

	to_hdr_parsed.param_lst = from_hdr_parsed.param_lst = NULL;

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

	LM_DBG("tm [%p] notification cb for [%d] reply\n", t, statuscode);

	if(statuscode == 100)
		return;

	msg = ps->rpl;
	b2b_key = (str*)*ps->param;

	if(b2b_parse_key(b2b_key, &hash_index, &local_index)< 0)
	{
		LM_ERR("Failed to parse b2b logic key [%.*s]\n",b2b_key->len,b2b_key->s);
		return;
	}

	if(parse_method(t->method.s, t->method.s + t->method.len, &method_id) == 0)
	{
		LM_ERR("Failed to parse method [%.*s\n]\n", t->method.len, t->method.s);
		return;
	}

	if(msg && msg!= FAKED_REPLY)
	{
		/* extract the method */
		if(parse_headers(msg, HDR_EOH_F, 0) < 0)
		{
			LM_ERR("Failed to parse headers\n");
			return;
		}

		if( msg->cseq==NULL || msg->cseq->body.s==NULL)
		{
			LM_ERR("failed to parse cseq header\n");
			return;
		}

		if( msg->callid==NULL || msg->callid->body.s==NULL)
		{
			LM_ERR("no callid header found\n");
			return;
		}
		/* examine the from header */
		if (!msg->from || !msg->from->body.s)
		{
			LM_ERR("cannot find 'from' header!\n");
			return;
		}
		if (msg->from->parsed == NULL)
		{
			if ( parse_from_header( msg )<0 )
			{
				LM_ERR("cannot parse From header\n");
				return;
			}
		}

		if (msg->to == NULL)
		{
			LM_ERR("cannot find 'to' header!\n");
			return;
		}
		pto = get_to(msg);
		if (pto == NULL || pto->error != PARSE_OK)
		{
			LM_ERR("'To' header COULD NOT parsed\n");
			return;
		}

		to_tag = pto->tag_value;
		callid = msg->callid->body;
		from_tag = ((struct to_body*)msg->from->parsed)->tag_value;
	} else if (ps->req) {
		from_tag = ((struct to_body*)ps->req->from->parsed)->tag_value;
		to_tag = ((struct to_body*)ps->req->to->parsed)->tag_value;
		callid = ps->req->callid->body;
	} else {
		to_tag.s = NULL;
		to_tag.len = 0;
		from_tag.s = NULL;
		from_tag.len = 0;
		callid.s = NULL;
		callid.len = 0;
	}

	if(callid.s)
		dlg_based_search = 1;

	lock_get(&htable[hash_index].lock);
	if(!dlg_based_search)
	{
		dlg = b2b_search_htable(htable, hash_index, local_index);
	}
	else
	{
		dlg = b2b_search_htable_dlg(htable, hash_index, local_index,
			&from_tag, (method_id==METHOD_CANCEL)?NULL:&to_tag, &callid);
	}

	if(dlg== NULL)
	{
		if(callid.s)
		{
		    /* This is a special case of paralel forking:
		     * - this is the cancelled branch of a paralel call fork
		     *   and the entity was deleted already.
		     */
		    /* FIXME: we may revisit the logic of paralel forking and
		     * properly ignore this kind of callbacks.
		     */
			if (method_id==METHOD_INVITE && statuscode==487)
				LM_DBG("No dialog found reply %d for method %.*s, [%.*s]\n",
					statuscode,
					msg==FAKED_REPLY?get_cseq(ps->req)->method.len:
						get_cseq(msg)->method.len,
					msg==FAKED_REPLY?get_cseq(ps->req)->method.s:
						get_cseq(msg)->method.s,
					callid.len, callid.s);
			else
				LM_ERR("No dialog found reply %d for method %.*s, [%.*s]\n",
					statuscode,
					msg==FAKED_REPLY?get_cseq(ps->req)->method.len:
						get_cseq(msg)->method.len,
					msg==FAKED_REPLY?get_cseq(ps->req)->method.s:
						get_cseq(msg)->method.s,
				callid.len, callid.s);
		}
		lock_release(&htable[hash_index].lock);
		return;
	}

	previous_dlg = dlg;
	while (dlg && method_id==METHOD_INVITE && dlg->uac_tran != t) {
		LM_DBG("Got unmatching dlg [%p] dlg->uac_tran=[%p] for "
			"transaction [%p]\n", dlg, dlg->uac_tran, t);
		if(dlg_based_search)
			dlg = b2b_search_htable_next_dlg( previous_dlg, htable, hash_index,
				local_index, &from_tag,
				(method_id==METHOD_CANCEL)?NULL:&to_tag, &callid);
		else
			dlg = b2b_search_htable_next( previous_dlg, htable, hash_index,
				local_index);

		if (dlg) {
			previous_dlg = dlg;
		}
		else {
			dlg = previous_dlg;
			/* if the transaction is no longer saved or is not the same as
			 * the one that the reply belongs to => exit*/
			LM_DBG("I don't care anymore about this transaction for dlg [%p]"
				" last_method=%d method_id=%d t=[%p] dlg->uac_tran=[%p]\n",
					dlg, dlg->last_method, method_id, t, dlg->uac_tran);
			/* if confirmed - send ACK */
			if(statuscode>=200 && statuscode<300 &&
			(dlg->state==B2B_ESTABLISHED || dlg->state==B2B_TERMINATED))
			{
				leg = b2b_new_leg(msg, &to_tag, PKG_MEM_TYPE);
				if(leg == NULL)
				{
					LM_ERR("Failed to add dialog leg\n");
					lock_release(&htable[hash_index].lock);
					return;
				}
				if(dlg->callid.s==0 || dlg->callid.len==0)
					dlg->callid = msg->callid->body;
				if(b2b_send_req(dlg, etype, leg, &ack, 0,
							(dlg->ack_sdp.s?&dlg->ack_sdp:0)) < 0)
				{
					LM_ERR("Failed to send ACK request\n");
				}
				pkg_free(leg);
			}

			lock_release(&htable[hash_index].lock);
			return;
		}
	}

	b2b_cback = dlg->b2b_cback;
	if(dlg->param.s)
	{
		param.s = (char*)pkg_malloc(dlg->param.len);
		if(param.s == NULL)
		{
			LM_ERR("No more private memory\n");
			lock_release(&htable[hash_index].lock);
			return;
		}
		memcpy(param.s, dlg->param.s, dlg->param.len);
		param.len = dlg->param.len;
	}

	LM_DBG("Received reply [%d] for dialog [%p], method [%.*s]\n",
		statuscode, dlg, t->method.len, t->method.s);

	if(statuscode >= 300)
	{
		if(dlg->uac_tran == t )
		{
			tmb.unref_cell(dlg->uac_tran);
			dlg->uac_tran = NULL;
			LM_DBG("dlg=[%p], uac_tran=NULL\n", dlg);
		}

		if(method_id != METHOD_INVITE)
		{
			current_dlg = dlg;
			dlg_state = dlg->state;
			lock_release(&htable[hash_index].lock);
			if(msg == FAKED_REPLY)
				goto dummy_reply;
			goto done1;
		}

		if(dlg->state >= B2B_CONFIRMED)
		{
			/* if reinvite */
			LM_DBG("Non final negative reply for reINVITE\n");
			current_dlg = dlg;
			dlg_state = dlg->state;
			lock_release(&htable[hash_index].lock);
			if(msg == FAKED_REPLY)
				goto dummy_reply;
			goto done1;
		}
		else
		{
			b2b_delete_legs(&dlg->legs);
			if(msg && msg!= FAKED_REPLY)
			{
				if (str2int( &(get_cseq(msg)->number),
				&dlg->cseq[CALLER_LEG])!=0 )
				{
					LM_ERR("failed to parse cseq number - not an integer\n");
				}
				else
				{
					dlg->last_invite_cseq = dlg->cseq[CALLER_LEG];
				}
			}
			switch(statuscode)
			{
			case 401:
				if (0 == parse_www_authenticate_header(msg))
					auth = get_www_authenticate(msg);
				break;
			case 407:
				if (0 == parse_proxy_authenticate_header(msg))
					auth = get_proxy_authenticate(msg);
				break;
			}
			if(uac_auth_loaded && auth && dlg->state == B2B_NEW)
			{
				crd = uac_auth_api._lookup_realm( &auth->realm );
				if(crd)
				{
					memset(&auth_nc_cnonce, 0,
							sizeof(struct authenticate_nc_cnonce));
					uac_auth_api._do_uac_auth(&t->method, &t->uac[0].uri, crd,
							auth, &auth_nc_cnonce, response);
					new_hdr = uac_auth_api._build_authorization_hdr(statuscode,
							&t->uac[0].uri, crd, auth,
							&auth_nc_cnonce, response);
					if (!new_hdr)
					{
						LM_ERR("failed to build auth hdr\n");
						dlg->state = B2B_TERMINATED;
						lock_release(&htable[hash_index].lock);
						goto error;
					}
					LM_DBG("auth is [%.*s]\n", new_hdr->len, new_hdr->s);
					if (build_extra_headers_from_msg(t->uac[0].request.buffer,
							new_hdr, &extra_headers, &body) < 0 ) {
						LM_ERR("failed to build extra msgs after auth\n");
						dlg->state = B2B_TERMINATED;
						lock_release(&htable[hash_index].lock);
						goto error;
					}
					LM_DBG("extra is [%.*s]\n",
						extra_headers.len, extra_headers.s);
					pkg_free(new_hdr->s);
					new_hdr->s = NULL; new_hdr->len = 0;

					b2b_send_indlg_req(dlg, B2B_CLIENT, b2b_key, &t->method,
							&extra_headers, &body, 0);
					pkg_free(extra_headers.s);

					dlg->state = B2B_NEW_AUTH;
					lock_release(&htable[hash_index].lock);

					/* run the b2b route */
					if(reply_routeid > 0) {
						msg->flags = t->uac[0].br_flags;
						run_top_route(rlist[reply_routeid].a, msg);
						b2b_apply_lumps(msg);
					}
					goto b2b_route;
				}
				else
					dlg->state = B2B_TERMINATED;
			}
			else
			{
				dlg->state = B2B_TERMINATED;
			}
		}

		current_dlg = dlg;
		dlg_state = dlg->state;
		UPDATE_DBFLAG(dlg);
		lock_release(&htable[hash_index].lock);
		if(msg == FAKED_REPLY)
		{
dummy_reply:
			memset(&dummy_msg, 0, sizeof(struct sip_msg));
			dummy_msg.id = 1;
			dummy_msg.first_line.type = SIP_REPLY;
			dummy_msg.first_line.u.reply.statuscode = statuscode;
			dummy_msg.first_line.u.reply.status.s =
				int2bstr( statuscode, status_buf,
				&dummy_msg.first_line.u.reply.status.len);
			dummy_msg.first_line.u.reply.reason.s = "Timeout";
			dummy_msg.first_line.u.reply.reason.len = 7;
			memset(&cb, 0, sizeof(struct cseq_body));
			memset(&cseq, 0, sizeof(struct hdr_field));
			cb.method = t->method;

			dummy_msg.rcv.bind_address = t->uac[0].request.dst.send_sock;
			dummy_msg.rcv.proto = dummy_msg.rcv.bind_address->proto;
			dummy_msg.rcv.src_port = dummy_msg.rcv.dst_port
				= dummy_msg.rcv.bind_address->port_no;
			dummy_msg.rcv.src_ip = dummy_msg.rcv.dst_ip
				= dummy_msg.rcv.bind_address->address;

			from_hdr.next = from_hdr.sibling = NULL;
			to_hdr.next = to_hdr.sibling = NULL;
			callid_hdr.next = callid_hdr.sibling = NULL;
			from_hdr.type = HDR_FROM_T;
			to_hdr.type = HDR_TO_T;
			callid_hdr.type = HDR_CALLID_T;

			parse_to(t->to.s+4, t->to.s+t->to.len, &to_hdr_parsed);
			parse_to(t->from.s+6, t->from.s+t->from.len, &from_hdr_parsed);
			from_hdr.parsed   = (struct hdr_field*)(void*)&from_hdr_parsed;
			to_hdr.parsed     = (struct hdr_field*)(void*)&to_hdr_parsed;

			from_hdr.body  = t->from;
			from_hdr.body.len -=6; from_hdr.body.s += 6;
			to_hdr.body    = t->to;
			to_hdr.body.len -=4; to_hdr.body.s += 4;

			from_hdr.len        = t->from.len;
			to_hdr.len          = t->to.len;
			from_hdr.name.s     = t->from.s;
			from_hdr.name.len   = 4;
			to_hdr.name.s       = t->to.s;
			to_hdr.name.len     = 2;

			callid_hdr.name.s   = t->callid.s;
			callid_hdr.name.len = 7;
			callid_hdr.body.s   = t->callid.s + 9;
			callid_hdr.body.len = t->callid.len - 9;
			trim_r(callid_hdr.body); /* callid in T contains also the CRLF */
			callid_hdr.len      = t->callid.len;

			dummy_msg.callid = &callid_hdr;
			dummy_msg.from = &from_hdr;
			dummy_msg.to = &to_hdr;
			dummy_msg.parsed_flag = HDR_EOH_F;
			cseq.parsed = &cb;
			dummy_msg.cseq = &cseq;

			/* simulate some "body" and "headers" - we fake
			   the body with the "from" buffer */
			dummy_msg.buf = t->from.s;
			dummy_msg.len = t->from.len;
			dummy_msg.eoh = dummy_msg.unparsed = t->from.s+t->from.len;
			dummy_msg.headers = dummy_msg.last_header = &from_hdr;

			msg = &dummy_msg;
		}
		goto done1;
	}
	else
	{
		/* if provisional or 200OK reply */
		if(msg == FAKED_REPLY)
		{
			goto error;
		}
		if(method_id != METHOD_INVITE)
		{
			goto done;
		}

		if(dlg->uac_tran && statuscode>= 200)
		{
			tmb.unref_cell(dlg->uac_tran);
			dlg->uac_tran = NULL;
			LM_DBG("dlg=[%p], uac_tran=NULL\n", dlg);
		}

		/* if 200 OK received for INVITE and the dialog already ended ->
		 * send ACK and terminate the call (it won't have a cback function) */
		if(dlg->state == B2B_TERMINATED)
		{
			if(statuscode >= 200)
			{
				LM_DBG("Received 200 OK after the call was terminated %.*s\n",
					b2b_key->len, b2b_key->s);
				leg = b2b_new_leg(msg, &to_tag, PKG_MEM_TYPE);
				if(leg == NULL)
				{
					LM_ERR("Failed to add dialog leg\n");
					goto error;
				}
				if(dlg->callid.s==0 || dlg->callid.len==0)
					dlg->callid = msg->callid->body;
				if(b2b_send_req(dlg, etype, leg, &ack, 0, 0) < 0)
				{
					LM_ERR("Failed to send ACK request\n");
				}
				if(b2b_send_req(dlg, etype, leg, &bye, 0, 0) < 0)
				{
					LM_ERR("Failed to send BYE request\n");
				}
				pkg_free(leg);
			}
			goto done;
		}

		if(dlg->legs == NULL && (dlg->state == B2B_NEW ||
					dlg->state == B2B_NEW_AUTH ||
					dlg->state == B2B_EARLY))
		{
			new_dlg = b2b_new_dlg(msg, &dlg->contact[CALLER_LEG],
					dlg, &dlg->param);
			if(new_dlg == NULL)
			{
				LM_ERR("Failed to create b2b dialog structure\n");
				goto error;
			}
			LM_DBG("Created new dialog structure %p\n", new_dlg);
			new_dlg->id = dlg->id;
			new_dlg->state = dlg->state;
			new_dlg->b2b_cback = dlg->b2b_cback;
			new_dlg->uac_tran = dlg->uac_tran;
			new_dlg->uas_tran = dlg->uas_tran;
			new_dlg->next = dlg->next;
			new_dlg->prev = dlg->prev;
			new_dlg->add_dlginfo = dlg->add_dlginfo;
			new_dlg->last_method = dlg->last_method;

//			dlg = b2b_search_htable(htable, hash_index, local_index);
			if(dlg->prev)
				dlg->prev->next = new_dlg;
			else
				htable[hash_index].first = new_dlg;

			if(dlg->next)
				dlg->next->prev = new_dlg;

			dlg->next= dlg->prev = NULL;
			b2b_delete_legs(&dlg->legs);
			shm_free(dlg);
			dlg = new_dlg;
			UPDATE_DBFLAG(dlg);
		}

		if(dlg->state == B2B_NEW ||
			dlg->state == B2B_NEW_AUTH ||
			dlg->state == B2B_EARLY)
		{
			if(statuscode < 200)
			{
				dlg->state = B2B_EARLY;
				/* search if an existing or a new leg */
				leg = b2b_find_leg(dlg, to_tag);
				if(leg)
				{
					LM_DBG("Found existing leg  - Nothing to update\n");
				} else {
					leg = b2b_add_leg(dlg, msg, &to_tag);
					if(leg == NULL)
					{
						LM_ERR("Failed to add dialog leg\n");
						goto error;
					}
					UPDATE_DBFLAG(dlg);
				}
				/* PRACK handling */
				/* if the provisional reply contains a
				 * Require: 100rel header -> send PRACK */
				hdr = get_header_by_static_name( msg, "Require");
				while(hdr)
				{
					LM_DBG("Found require hdr\n");
					if ( (hdr->body.len == 6 &&
						strncmp(hdr->body.s, "100rel", 6)==0) ||
					(hdr->body.len == 8 &&
						strncmp(hdr->body.s, "100rel\r\n", 8)==0) )
					{
						LM_DBG("Found 100rel header\n");
						break;
					}
					hdr = hdr->sibling;
				}
				if(hdr)
				{
					str method={"PRACK", 5};
					str extra_headers;
					char buf[128];
					str rseq, cseq;

					hdr = get_header_by_static_name( msg, "RSeq");
					if(!hdr)
					{
						LM_ERR("RSeq header not found\n");
						goto error;
					}
					rseq = hdr->body;
					cseq = msg->cseq->body;
					trim_trailing(&rseq);
					trim_trailing(&cseq);
					sprintf(buf, "RAck: %.*s %.*s\r\n",
							rseq.len, rseq.s, cseq.len, cseq.s);
					extra_headers.s = buf;
					extra_headers.len = strlen(buf);

					if(dlg->callid.s==0 || dlg->callid.len==0)
						dlg->callid = msg->callid->body;
					if(b2b_send_req(dlg, etype, leg, &method, &extra_headers, 0) < 0)
					{
						LM_ERR("Failed to send PRACK\n");
					}
				}
				goto done;
			}
			else /* a final success response */
			{
				LM_DBG("A final response\n");
				/* if the dialog was already confirmed */
				if(dlg->state == B2B_CONFIRMED)
				{
					LM_DBG("The state is already confirmed\n");
					leg = b2b_new_leg(msg, &to_tag, PKG_MEM_TYPE);
					if(leg == NULL)
 					{
						LM_ERR("Failed to add dialog leg\n");
						goto error;
					}

					if(dlg->callid.s==0 || dlg->callid.len==0)
						dlg->callid = msg->callid->body;
					/* send an ACK followed by BYE */
					if(b2b_send_req(dlg, etype, dlg->legs, &ack, 0,
								dlg->ack_sdp.s?&dlg->ack_sdp:0) < 0)
					{
						LM_ERR("Failed to send ACK request\n");
					}
					if(b2b_send_req(dlg, etype, dlg->legs, &bye, 0, 0) < 0)
					{
						LM_ERR("Failed to send BYE request\n");
					}

					lock_release(&htable[hash_index].lock);
					return;
				}
				else
				{
					b2b_dlginfo_t dlginfo;
					b2b_add_dlginfo_t add_infof= dlg->add_dlginfo;

					/* delete all and add the confirmed leg */
					b2b_delete_legs(&dlg->legs);
					leg = b2b_add_leg(dlg, msg, &to_tag);
					if(leg == NULL)
					{
						LM_ERR("Failed to add dialog leg\n");
						goto error;
					}
					dlg->tag[CALLEE_LEG] = leg->tag;
					dlginfo.fromtag = to_tag;
					dlginfo.callid = dlg->callid;
					dlginfo.totag = dlg->tag[CALLER_LEG];
					dlg->state = B2B_CONFIRMED;

					if(b2be_db_mode == WRITE_THROUGH)
					{
						b2be_db_insert(dlg, etype);
					}

					current_dlg = dlg;
					dlg_state = dlg->state;
					lock_release(&htable[hash_index].lock);

					if(add_infof && add_infof(param.s?&param:0, b2b_key,
							etype,&dlginfo)< 0)
					{
						LM_ERR("Failed to add dialoginfo\n");
						goto error1;
					}
					UPDATE_DBFLAG(dlg);
					goto done1;
				}
			}
		}

		LM_DBG("DLG state = %d\n", dlg->state);
		if(dlg->state== B2B_MODIFIED && statuscode >= 200 && statuscode <300)
		{
			LM_DBG("switched the state CONFIRMED [%p]\n", dlg);
			dlg->state = B2B_CONFIRMED;
		}
		else
		if(dlg->state == B2B_CONFIRMED)
		{
			LM_DBG("Retrasmission [%p]\n", dlg);
			goto error;
		}
	}
done:
	if(dlg)
	{
		current_dlg = dlg;
		dlg_state = dlg->state;
	}
	lock_release(&htable[hash_index].lock);
	/* I have to inform the logic that a reply was received */
done1:
	/* run the b2b route */
	if(reply_routeid > 0) {
		msg->flags = t->uac[0].br_flags;
		run_top_route(rlist[reply_routeid].a, msg);
		if (msg != FAKED_REPLY) b2b_apply_lumps(msg);
	}

	b2b_cback(msg, b2b_key, B2B_REPLY, param.s?&param:0);
	if(param.s)
	{
		pkg_free(param.s);
		param.s = NULL;
	}
	if (msg == &dummy_msg) {
		free_lump_list(msg->add_rm);
		free_lump_list(msg->body_lumps);
	}

b2b_route:
	current_dlg = 0;
	if(b2be_db_mode == WRITE_THROUGH && dlg_state>B2B_CONFIRMED)
	{
		lock_get(&htable[hash_index].lock);
		for(aux_dlg = htable[hash_index].first; aux_dlg; aux_dlg = aux_dlg->next)
		{
			if(aux_dlg == dlg)
				break;
		}
		if(!aux_dlg)
		{
			lock_release(&htable[hash_index].lock);
			return;
		}

		b2be_db_update(dlg, etype);
		lock_release(&htable[hash_index].lock);
	}

	if (to_hdr_parsed.param_lst) {
		/* message was built on the fly from T
		 * free side effects of parsing to hdr */
		free_to_params(&to_hdr_parsed);
	}

	if (from_hdr_parsed.param_lst) {
		/* message was built on the fly from T
		 * free side effects of parsing from hdr */
		free_to_params(&from_hdr_parsed);
	}

	return;
error:
	lock_release(&htable[hash_index].lock);
error1:
	if(param.s)
		pkg_free(param.s);
	if (msg == &dummy_msg) {
		free_lump_list(msg->add_rm);
		free_lump_list(msg->body_lumps);
	}
}


static inline int is_CT_present(struct hdr_field* headers)
{
	struct hdr_field* hf;
	for (hf=headers; hf; hf=hf->next) {
		if (hf->type == HDR_CONTENTTYPE_T) {
			return 1;
		}
	}

	return 0;
}

int b2breq_complete_ehdr(str* extra_headers, str* ehdr_out, str* body,
		str* local_contact)
{
	str ehdr= {NULL,0};
	static char buf[BUF_LEN];
	static struct sip_msg foo_msg;

	if((extra_headers?extra_headers->len:0) + 14 + local_contact->len > BUF_LEN)
	{
		LM_ERR("Buffer too small\n");
		return -1;
	}

	ehdr.s = buf;
	if(extra_headers && extra_headers->s && extra_headers->len)
	{
		memcpy(ehdr.s, extra_headers->s, extra_headers->len);
		ehdr.len = extra_headers->len;
	}
	ehdr.len += sprintf(ehdr.s+ ehdr.len, "Contact: <%.*s>\r\n",
		local_contact->len, local_contact->s);



	/* if not present and body present add content type */
	if(body) {
		/* build a fake sip_msg to parse the headers sip-wisely */
		memset(&foo_msg, 0, sizeof(struct sip_msg));
		foo_msg.len = ehdr.len;
		foo_msg.buf = foo_msg.unparsed = ehdr.s;

		if (parse_headers( &foo_msg, HDR_EOH_F, 0) == -1) {
			LM_ERR("Failed to parse headers\n");
			return -1;
		}

		if (!is_CT_present(foo_msg.headers)) {
			/* add content type header */
			if(ehdr.len + 32 > BUF_LEN)
			{
				LM_ERR("Buffer too small, can not add Content-Type header\n");
				return -1;
			}
			memcpy(ehdr.s+ ehdr.len, "Content-Type: application/sdp\r\n", 31);
			ehdr.len += 31;
			ehdr.s[ehdr.len]= '\0';
		}

		if (foo_msg.headers) free_hdr_field_lst(foo_msg.headers);
	}
	*ehdr_out = ehdr;

	return 0;
}


int b2b_apply_lumps(struct sip_msg* msg)
{
	str obuf;
	struct sip_msg tmp;
	str body;

	/* faked reply */
	if (msg==NULL || msg == FAKED_REPLY || msg==&dummy_msg)
		return 0;

	if(!msg->body_lumps && !msg->add_rm)
		return 0;

	if (msg->first_line.type==SIP_REQUEST)
		obuf.s = build_req_buf_from_sip_req(msg, (unsigned int*)&obuf.len,
			msg->rcv.bind_address, msg->rcv.proto, MSG_TRANS_NOVIA_FLAG );
	else
		obuf.s = build_res_buf_from_sip_res(msg, (unsigned int*)&obuf.len,
			msg->rcv.bind_address,0);

	if (!obuf.s) {
		LM_ERR("no more shm mem\n");
		return -1;
	}

	/* temporary copy */
	memcpy(&tmp, msg, sizeof(struct sip_msg));

	/* reset dst uri and path vector to avoid freeing - restored later */
	if(msg->dst_uri.s != NULL)
	{
		msg->dst_uri.s = NULL;
		msg->dst_uri.len = 0;
	}
	if(msg->path_vec.s != NULL)
	{
		msg->path_vec.s = NULL;
		msg->path_vec.len = 0;
	}

	/* free old msg structure */
	free_sip_msg(msg);
	memset(msg, 0, sizeof(struct sip_msg));

	/* restore msg fields */
	msg->buf                = tmp.buf;
	msg->id                 = tmp.id;
	msg->rcv                = tmp.rcv;
	msg->set_global_address = tmp.set_global_address;
	msg->set_global_port    = tmp.set_global_port;
	msg->flags              = tmp.flags;
	msg->msg_flags          = tmp.msg_flags;
	msg->hash_index         = tmp.hash_index;
	msg->force_send_socket  = tmp.force_send_socket;
	msg->dst_uri            = tmp.dst_uri;
	msg->path_vec           = tmp.path_vec;

	memcpy(msg->buf, obuf.s, obuf.len);
	msg->len = obuf.len;
	msg->buf[msg->len] = '\0';

	/* free new buffer - copied in the static buffer from old struct sip_msg */
	pkg_free(obuf.s);

	/* reparse the message */
	if (parse_msg(msg->buf, msg->len, msg) != 0)
		LM_ERR("parse_msg failed\n");

	/* if has body, check for SDP */
	if (get_body(msg,&body) != 0 || body.len == 0)
		return 1;

	if (parse_sdp(msg) < 0) {
		LM_DBG("failed to parse SDP message\n");
		return -1;
	}

	return 1;
}
