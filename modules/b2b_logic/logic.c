/*
 * $Id: logic.c $
 *
 * back-to-back logic module
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
#include <libxml/parser.h>
#include "../../dprint.h"
#include "../../error.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_content.h"
#include "../../parser/parse_methods.h"
#include "../../parser/parse_hname2.h"
#include "../../ut.h"
#include "../../trim.h"
#include "../../mem/shm_mem.h"
#include "../../mem/mem.h"
#include "../b2b_entities/dlg.h"
#include "../presence/hash.h"
#include "../presence/utils_func.h"

#include "records.h"
#include "pidf.h"
#include "b2b_logic.h"

#define BUF_LEN  128

#define UPDATE_DBFLAG(dlg, flag) do{ \
	if(dlg->db_flag==NO_UPDATEDB_FLAG) \
		dlg->db_flag = UPDATEDB_FLAG; \
}while(0)

static str maxfwd_hdr={"Max-Forwards: 70\r\n", 18};
extern b2b_scenario_t* script_scenarios;
extern int_str b2bl_key_avp_name;
extern unsigned short b2bl_key_avp_type;

int b2b_scenario_parse_uri(xmlNodePtr value_node, char* value_content,
		b2bl_tuple_t* tuple, struct sip_msg* msg, str* client_to);

b2bl_entity_id_t* b2bl_search_entity(b2bl_tuple_t* tuple, str* key, int src);
int udh_to_uri(str user, str host, str port, str* uri);
static str method_invite= {INVITE, INVITE_LEN};
static str method_ack   = {ACK, ACK_LEN};
static str method_bye   = {BYE, BYE_LEN};
static str ok = {"OK", 2};

int entity_add_dlginfo(b2bl_entity_id_t* entity, b2b_dlginfo_t* dlginfo)
{
	b2b_dlginfo_t* new_dlginfo= NULL;
	int size;

	size = sizeof(b2b_dlginfo_t)+ dlginfo->callid.len;
	if( dlginfo->totag.s)
		size += dlginfo->totag.len;
	if(dlginfo->fromtag.s)
		  size+= dlginfo->fromtag.len;
	new_dlginfo = (b2b_dlginfo_t*)shm_malloc(size);
	memset(new_dlginfo, 0, size);
	if(new_dlginfo == NULL)
	{
		LM_ERR("No more shared memory\n");
		return -1;
	}
	size = sizeof(b2b_dlginfo_t);

	if( dlginfo->totag.s)
		CONT_COPY(new_dlginfo, new_dlginfo->totag, dlginfo->totag);
	if(dlginfo->fromtag.s)
		CONT_COPY(new_dlginfo, new_dlginfo->fromtag, dlginfo->fromtag);
	CONT_COPY(new_dlginfo, new_dlginfo->callid, dlginfo->callid);
	
	entity->dlginfo = new_dlginfo;

	return 0;
}

int b2b_add_dlginfo(str* key, str* entity_key, int src, b2b_dlginfo_t* dlginfo)
{
	b2bl_tuple_t* tuple;
	b2bl_entity_id_t* entity = NULL;
	unsigned int hash_index, local_index;

	if(b2bl_parse_key(key, &hash_index, &local_index) < 0)
	{
		LM_ERR("Failed to parse key\n");
		return -1;
	}
	lock_get(&b2bl_htable[hash_index].lock);

	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if(tuple == NULL)
	{
		LM_ERR("No entity found\n");
		lock_release(&b2bl_htable[hash_index].lock);
		return -1;
	}
	/* a connected call */
	tuple->lifetime = 0;
	entity = b2bl_search_entity(tuple, entity_key, src);
	if(entity == NULL)
	{
		LM_ERR("No b2b_key match found\n");
		lock_release(&b2bl_htable[hash_index].lock);
		return -1;
	}

	if(entity->dlginfo)
		shm_free(entity->dlginfo);
	if(entity_add_dlginfo(entity, dlginfo) < 0)
	{
		LM_ERR("Failed to add dialoginfo\n");
		lock_release(&b2bl_htable[hash_index].lock);
		return -1;
	}

	/* log the dialog pair */
	if(entity->peer && entity->peer->dlginfo)
	{
		LM_INFO("Dialog pair: [%.*s] - [%.*s]\n",
				entity->peer->dlginfo->callid.len, entity->peer->dlginfo->callid.s,
				dlginfo->callid.len, dlginfo->callid.s);
	}

	lock_release(&b2bl_htable[hash_index].lock);
	return 0;
}

int msg_add_dlginfo(b2bl_entity_id_t* entity, struct sip_msg* msg, str* totag)
{
	str callid, fromtag;
	b2b_dlginfo_t dlginfo;

	if( msg->callid==NULL || msg->callid->body.s==NULL)
	{
		LM_ERR("failed to parse callid header\n");
		return -1;
	}
	callid = msg->callid->body;

	if (msg->from->parsed == NULL)
	{
		if ( parse_from_header( msg )<0 ) 
		{
			LM_ERR("cannot parse From header\n");
			return -1;
		}
	}
	fromtag = ((struct to_body*)msg->from->parsed)->tag_value;

	dlginfo.totag  = *totag;
	dlginfo.callid = callid;
	dlginfo.fromtag= fromtag;
	
	if(entity_add_dlginfo(entity, &dlginfo) < 0)
	{
		LM_ERR("Failed to add dialoginfo\n");
		return -1;
	}

	return 0;
}

int b2b_msg_get_to(struct sip_msg* msg, str* to_uri)
{
	if( parse_sip_msg_uri(msg)< 0)
	{
		LM_ERR("failed to parse R-URI\n");
		return -1;
	}

	if(udh_to_uri(msg->parsed_uri.user, msg->parsed_uri.host,
				msg->parsed_uri.port, to_uri)< 0)
	{
		LM_ERR("failed to construct uri from user and domain\n");
		return -1;
	}
	return 0;
}

int b2b_msg_get_from(struct sip_msg* msg, str* from_uri)
{
	struct to_body *pfrom;

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
	pfrom = (struct to_body*)msg->from->parsed;
	*from_uri = pfrom->uri;

	return 0;
}


b2bl_entity_id_t* b2bl_create_new_entity(enum b2b_entity_type type, str* entity_id,
		str* to_uri,str* from_uri,str*from_dname, str* ssid, struct sip_msg* msg)
{
	unsigned int size;
	b2bl_entity_id_t* entity;

	size = sizeof(b2bl_entity_id_t) + ((ssid!=NULL)?ssid->len:0) +
		((entity_id!=NULL)?entity_id->len:0)+ ((to_uri !=NULL)?to_uri->len:0)
		+ ((from_uri!=NULL)?from_uri->len:0)+ ((from_dname!=NULL)?from_dname->len:0);

	entity = (b2bl_entity_id_t*)shm_malloc(size);
	if(entity == NULL)
	{
		LM_ERR("No more shared memory\n");
		return 0;
	}
	LM_DBG("address: %p\n", entity);
	memset(entity, 0, size);

	size = sizeof(b2bl_entity_id_t);
	
	if(entity_id)
	{
		entity->key.s= (char*)entity+ size;
		memcpy(entity->key.s, entity_id->s, entity_id->len);
		entity->key.len= entity_id->len;
		size+= entity_id->len;
	}
	//CONT_COPY_P(entity, entity->key, entity_id);

	if(ssid)
	{
		entity->scenario_id.s= (char*)entity+ size;
		memcpy(entity->scenario_id.s, ssid->s, ssid->len);
		entity->scenario_id.len= ssid->len;
		size+= ssid->len;
	}

	//CONT_COPY_P(entity, entity->scenario_id, ssid);
	if(to_uri)
	{
		entity->to_uri.s= (char*)entity+ size;
		memcpy(entity->to_uri.s, to_uri->s, to_uri->len);
		entity->to_uri.len= to_uri->len;
		size+= to_uri->len;
	}

	//CONT_COPY_P(entity, entity->to_uri, to_uri);
	if(from_uri)
	{
		entity->from_uri.s= (char*)entity+ size;
		memcpy(entity->from_uri.s, from_uri->s, from_uri->len);
		entity->from_uri.len= from_uri->len;
		size+= from_uri->len;
	}
//		CONT_COPY_P(entity, entity->from_uri, from_uri);

	if(from_dname)
	{
		entity->from_dname.s= (char*)entity+ size;
		memcpy(entity->from_dname.s, from_dname->s, from_dname->len);
		entity->from_dname.len= from_dname->len;
		size+= from_dname->len;
	}

	entity->type = type;

	if(type == B2B_SERVER && msg)
	{
		if( msg_add_dlginfo(entity, msg, entity_id)< 0 )
		{
			LM_ERR("Failed to add dialog information to b2b_logic entity\n");
			shm_free(entity);
			return 0;
		}
	}
	entity->stats.start_time = get_ticks();
	entity->stats.call_time = 0;

	return entity;
}

static inline int bridge_get_entityno(b2bl_tuple_t* tuple, b2bl_entity_id_t* entity)
{
	int i;

	/*check to which entity the reply belongs to */
	for(i = 0; i< 3; i++)
	{
		if(tuple->bridge_entities[i]== entity)
				return i;
	}
	return -1;
}

void b2b_end_dialog(b2bl_entity_id_t* bentity, b2bl_tuple_t* tuple)
{
	str method;

	if(!bentity)
		return;

	if(bentity->key.s)
	{
		if(!bentity->disconnected)
		{
			if(bentity->state == DLG_CONFIRMED)
			{
				method.s = BYE;
				method.len = BYE_LEN;
			}
			else
			{
				method.s = CANCEL;
				method.len = CANCEL_LEN;
			}

			b2b_api.send_request(bentity->type, &bentity->key, &method,
				0, 0, bentity->dlginfo);

			bentity->disconnected = 1;
		}
	}
	else
	{
		LM_DBG("It is not connected yet - delete\n");
		b2bl_delete_entity(bentity, tuple);
	}

}

void b2b_mark_todel( b2bl_tuple_t* tuple)
{
	tuple->to_del = 1;
	tuple->lifetime = 30 + get_ticks();
	tuple->scenario_state = B2B_CANCEL_STATE;
	LM_DBG("%p\n", tuple);
}

int process_bridge_dialog_end(b2bl_tuple_t* tuple, int entity_no,
		b2bl_entity_id_t* bentity)
{
	if(entity_no == 0) /* if a negative reply received from the server */
	{
		/* send cancel or bye to the peers */
		b2b_end_dialog(tuple->bridge_entities[1], tuple);
		b2b_end_dialog(tuple->bridge_entities[2], tuple);
		b2b_mark_todel(tuple);
	}
	else
	if(entity_no == 1)
	{
		/* if the media server in 2 stage connecting did not reply */
		if(tuple->bridge_entities[2])
		{
			/* media server did not reply with success */
			b2bl_delete_entity(bentity, tuple);

			tuple->bridge_entities[1] = tuple->bridge_entities[0];
			tuple->bridge_entities[0] = tuple->bridge_entities[2];
			tuple->bridge_entities[2] = NULL;

			tuple->bridge_entities[1]->peer = tuple->bridge_entities[0];
			tuple->bridge_entities[0]->peer = tuple->bridge_entities[1];
		}
		else
		{
			/* the entity to connect replied with negative reply */
			b2b_end_dialog(tuple->bridge_entities[0], tuple);
			b2b_mark_todel(tuple);
		}
	}
	else
	{
		/* if the final destination replied with negative reply */
		b2b_end_dialog(tuple->bridge_entities[0], tuple);
		b2b_end_dialog(tuple->bridge_entities[1], tuple);
		b2b_mark_todel(tuple);
	}

	return 0;
}

int process_bridge_bye(struct sip_msg* msg,  b2bl_tuple_t* tuple,
		b2bl_entity_id_t* entity)
{
	int entity_no;

	entity_no = bridge_get_entityno(tuple, entity);
	if(entity_no < 0)
	{
		LM_ERR("No match found\n");
		return -1;
	}

	b2b_api.send_reply(entity->type, &entity->key, METHOD_BYE, 200, &ok,
			0, 0, entity->dlginfo);

	return process_bridge_dialog_end(tuple, entity_no, entity);
}


int process_bridge_negreply(b2bl_tuple_t* tuple,
		unsigned int hash_index, b2bl_entity_id_t* entity)
{
	int entity_no;
	str method = str_init(ACK);
	int ret;
	unsigned int local_index;
	unsigned int index;
	b2bl_cback_f cbf;
	void* param;
	int etype;
	b2bl_entity_id_t* e;
	int found = 0;
	b2bl_dlg_stat_t stat;
	str ekey={0, 0};

	entity_no = bridge_get_entityno(tuple, entity);
	if(entity_no < 0)
	{
		LM_ERR("No match found\n");
		return -1;
	}

	if(entity->peer && entity->peer->key.s)
	{
		b2b_api.send_request(entity->peer->type, &entity->peer->key, &method,
			0, 0, entity->peer->dlginfo);
	}
	entity->disconnected =1;
	/* call the callback for brigding faild  */
	if(tuple->cbf && entity == tuple->bridge_entities[1])
	{
		cbf = tuple->cbf;
		if(cbf)
		{
			tuple->cbf = NULL;
			param = tuple->cb_param;
			local_index = tuple->id;
			etype = entity->type;
			stat.start_time =  entity->stats.start_time;
			stat.setup_time = get_ticks() - entity->stats.start_time;
			ekey.s = (char*)pkg_malloc(entity->key.len);
			if(ekey.s == NULL)
			{
				LM_ERR("No more memory\n");
				return -1;
			}
			memcpy(ekey.s, entity->key.s, entity->key.len);
			ekey.len = entity->key.len;

			lock_release(&b2bl_htable[hash_index].lock);
				
			ret = cbf(param, &stat, 0, B2B_REJECT_E2);
			LM_DBG("ret = %d\n", ret);
			
			lock_get(&b2bl_htable[hash_index].lock);
			/* must search the tuple again - you can't know what might have happened with it */
			tuple = b2bl_search_tuple_safe(hash_index, local_index);
			if(tuple == NULL)
			{
				LM_DBG("B2B logic record not found anymore\n");
				pkg_free(ekey.s);
				return 1;
			}
			tuple->cbf = cbf;
			/* search for entity - if not found return 1 (not to do anything else)*/
			if(etype == B2B_SERVER)
			{
				for (index = 0; index < MAX_B2BL_ENT; index++)
				{
					e = tuple->servers[index];
					if (e == entity && e->key.len == ekey.len &&
						strncmp(e->key.s, ekey.s, ekey.len)==0)
					{
						found = 1;
						break;
					}
				}
				if(!found)
				{
					LM_DBG("Server Entity does not exist anymore: return\n");
					pkg_free(ekey.s);
					return 1;
				}
			}
			else
			{
				for (index = 0; index < MAX_B2BL_ENT; index++)
				{
					e = tuple->clients[index];
					if(e == entity && e->key.len == ekey.len &&
						strncmp(e->key.s, ekey.s, ekey.len)==0)
					{
						found = 1;
						break;
					}
				}
				if(!found)
				{
					LM_DBG("Client Entity does not exist anymore: return\n");
					pkg_free(ekey.s);
					return 1;
				}
			}

			pkg_free(ekey.s);
			if(ret == 0)
			{
				/* drop the negative reply */
				b2bl_delete_entity(entity, tuple);
				return 1;
			}
		}
	}
	return process_bridge_dialog_end(tuple, entity_no, entity);
}

b2bl_entity_id_t* b2bl_new_client(str* to_uri, str* from_uri,
		b2bl_tuple_t* tuple, str* ssid, struct sip_msg* msg)
{
	client_info_t ci;
	str* client_id;
	b2bl_entity_id_t* entity;

	memset(&ci, 0, sizeof(client_info_t));
	ci.method        = method_invite;
	ci.to_uri        = *to_uri;
	ci.from_uri      = *from_uri;
	ci.extra_headers = tuple->extra_headers;
	ci.body          = (tuple->sdp.s?&tuple->sdp:0);
	ci.from_tag      = 0;
	ci.send_sock     = msg?msg->rcv.bind_address:0;
	if(msg)
	{
		if (str2int( &(get_cseq(msg)->number), &ci.cseq)!=0 )
		{
			LM_ERR("cannot parse cseq number\n");
			return 0;
		}
	}
	LM_DBG("Send Invite without a body to a new client entity\n");
	client_id = b2b_api.client_new(&ci, b2b_client_notify,
			b2b_add_dlginfo, tuple->key);
	if(client_id == NULL)
	{
		LM_ERR("Failed to create client id\n");
		return 0;
	}
	/* save the client_id in the structure */
	entity = b2bl_create_new_entity(B2B_CLIENT, client_id, &ci.to_uri,
			&ci.from_uri, 0, ssid, 0);
	if(entity == NULL)
	{
		LM_ERR("failed to create new client entity\n");
		pkg_free(client_id);
		return 0;
	}
	pkg_free(client_id);

	return entity;
}
int process_bridge_200OK(struct sip_msg* msg, str* extra_headers,
		str* body, b2bl_tuple_t* tuple, b2bl_entity_id_t* entity)
{
	str* client_id;
	b2bl_entity_id_t* bentity0, *bentity1;
	client_info_t ci;
	int entity_no;
	str to_uri;

	to_uri = get_to(msg)->uri;

	bentity0 = tuple->bridge_entities[0];
	bentity1 = tuple->bridge_entities[1];

	entity_no = bridge_get_entityno(tuple, entity);
	if(entity_no < 0)
	{
		LM_ERR("No match found\n");
		return -1;
	}
	LM_DBG("entity_no = %d, entity=%p, be[0]= %p\n", entity_no, entity, tuple->bridge_entities[0]);

	if(entity_no == 0) /* the first reply -> must send INVITE on the other side  */
	{
		LM_DBG("Send invite to %.*s\n", bentity1->to_uri.len, bentity1->to_uri.s);
		if(bentity1->key.s && bentity1->state < DLG_CONFIRMED) /* already been in this step*/
		{
			LM_ERR("A retransmission of the reply from the first leg\n");
			return -1;
		}
		if(bentity1->type == B2B_CLIENT && bentity1->state!=DLG_CONFIRMED)
		{
			memset(&ci, 0, sizeof(client_info_t));
			ci.method        = method_invite;
			ci.to_uri        = bentity1->to_uri;

			/* it matters if the entity is server or client */
			if(bentity0->type == B2B_CLIENT)
			{
				ci.from_uri      = bentity0->to_uri;
			}
			else
			if(bentity0->type == B2B_SERVER)
			{
				if(bentity1->from_uri.s)
					ci.from_uri = bentity1->from_uri;
				else
					ci.from_uri      = bentity0->from_uri;
				if(bentity1->from_dname.s)
					ci.from_dname = bentity1->from_dname;
				else
					ci.from_dname    = bentity0->from_dname;
				LM_DBG("From dname: %.*s\n", ci.from_dname.len, ci.from_dname.s);
			}

			ci.extra_headers = extra_headers;
			ci.body          = body;
			ci.from_tag      = 0;
			ci.send_sock     = msg->rcv.bind_address;
			if (str2int( &(get_cseq(msg)->number), &ci.cseq)!=0 )
			{
				LM_ERR("cannot parse cseq number\n");
				return -1;
			}
			bentity0->state = DLG_CONFIRMED;
			client_id = b2b_api.client_new(&ci, b2b_client_notify,
					b2b_add_dlginfo, tuple->key);
			if(client_id == NULL)
			{
				LM_ERR("Failed to create new client entity\n");
				return -1;
			}
			/* save the client_id in the structure */
			entity = b2bl_create_new_entity(B2B_CLIENT, client_id, &ci.to_uri,
					&ci.from_uri, 0, &bentity1->scenario_id, 0);
			if(entity == NULL)
			{
				LM_ERR("failed to create new client entity\n");
				pkg_free(client_id);
				return -1;
			}
			entity->no =1;
			pkg_free(client_id);
			b2bl_delete_entity(bentity1, tuple);

			tuple->bridge_entities[1] = entity;
			if (0 != b2bl_add_client(tuple, entity))
				return -1;
		}
		else
		{
			/* send reInvite */
			bentity1->stats.start_time = get_ticks();
			bentity1->stats.call_time = 0;

			if(b2b_api.send_request(bentity1->type, &bentity1->key, &method_invite,
				extra_headers, body, bentity1->dlginfo)< 0)
			{
				LM_ERR("Failed to send second ACK in bridging scenario\n");
				return -1;
			}
		}
		tuple->bridge_entities[1]->peer = tuple->bridge_entities[0];
		tuple->bridge_entities[0]->peer = tuple->bridge_entities[1];
	}
	else
	if(entity_no == 1) /* from provisional media server or from final destination */
	{
		str* ack_body= 0;
		/* the second -> send ACK with body to the first entity
		and ACK without a body to the second entity*/

		bentity1->state = DLG_CONFIRMED;

		bentity1->stats.setup_time = get_ticks() - bentity1->stats.start_time;
		bentity1->stats.start_time = get_ticks();
		bentity0->stats.setup_time = get_ticks() - bentity0->stats.start_time;
		bentity0->stats.start_time = get_ticks();

		/* a complicated combination of conditions that tell us if we need 
		 * to send body in ACK */
		if(!(tuple->sdp.s && bentity0->type == B2B_CLIENT))
		{
			ack_body = body;
		}
		else
			LM_DBG("Don't send body because the tuple already has a body - so it was used in invite\n");

		if(b2b_api.send_request(bentity0->type, &bentity0->key, &method_ack,
				extra_headers, ack_body, bentity0->dlginfo) < 0)
		{
			LM_ERR("Failed to send first ACK in bridging scenario\n");
			return -1;
		}

		/* send ACK without a body to the second entity */
		if(b2b_api.send_request(bentity1->type, &bentity1->key, &method_ack,
			 0, 0, bentity1->dlginfo)< 0)
		{
			LM_ERR("Failed to send second ACK in bridging scenario\n");
			return -1;
		}

		tuple->bridge_entities[1]->peer = tuple->bridge_entities[0];
		tuple->bridge_entities[0]->peer = tuple->bridge_entities[1];
		/* now I have finnished the BRIDGING scenario -> mark this in the record */
		if(tuple->bridge_entities[2] == NULL)
		{
			if(tuple->next_scenario_state>= 0)
			{
				tuple->scenario_state = tuple->next_scenario_state;
				tuple->next_scenario_state = 0;
				LM_DBG("Updated tuple state = %d\n", tuple->scenario_state);
			}
			else
				tuple->scenario_state = B2B_NOTDEF_STATE;
/*			tuple->bridge_entities[0] = tuple->bridge_entities[1] = NULL; */
			LM_DBG("Finished the bridging\n");
		}
		else
		{
			/* contact the real destination */
			entity =  b2bl_new_client(&tuple->bridge_entities[2]->to_uri, &bentity0->from_uri,
					tuple, &tuple->bridge_entities[2]->scenario_id, msg);
			if(entity == NULL)
			{
				LM_ERR("Failed to generate new client\n");
				return -1;
			}
			entity->no = 1;
			b2bl_delete_entity(tuple->bridge_entities[2], tuple);
			if (0 != b2bl_add_client(tuple, entity))
				return -1;
			/* original destination connected in the second step */
			tuple->bridge_entities[2]= entity;
		}
	}
	else /* if a 200 OK from the final destination */
	{
		b2b_end_dialog(bentity1, tuple);

		/* send reinvite to the initial server*/
		bentity0->stats.setup_time = get_ticks() - bentity0->stats.start_time;
		bentity0->stats.start_time = get_ticks();
		if(b2b_api.send_request(bentity0->type, &bentity0->key, &method_invite,
			extra_headers, body, bentity0->dlginfo)< 0)
		{
			LM_ERR("Failed to send second ACK in bridging scenario\n");
			return -1;
		}

		tuple->bridge_entities[1] = tuple->bridge_entities[0];
		tuple->bridge_entities[0] = tuple->bridge_entities[2];
		tuple->bridge_entities[2] = NULL;

		tuple->bridge_entities[1]->peer = tuple->bridge_entities[0];
		tuple->bridge_entities[0]->peer = tuple->bridge_entities[1];
	}
	return 0;
}

b2bl_entity_id_t* b2bl_search_entity(b2bl_tuple_t* tuple, str* key, int src)
{
	int index;
	b2bl_entity_id_t* e;

	/* search the entity */
	if(src == B2B_SERVER)
		for (index = 0; index < MAX_B2BL_ENT; index++)
		{
			e= tuple->servers[index];
			if (e)
			{
				LM_DBG("Key [%.*s]\n",e->key.len,e->key.s);
				if (e->key.len == key->len &&
					strncmp(e->key.s, key->s, key->len) == 0)
					return e;
			}
			e= NULL;
		}
	else
		for (index = 0; index < MAX_B2BL_ENT; index++)
		{
			e = tuple->clients[index];
			if (e)
			{
				LM_DBG("Key [%.*s]\n",e->key.len,e->key.s);
				if (e->key.len == key->len &&
					strncmp(e->key.s, key->s, key->len) == 0)
					return e;
			}
			e= NULL;
		}

	return e;
}

int b2b_logic_notify(int src, struct sip_msg* msg, str* key, int type, void* param)
{
	unsigned int hash_index, local_index;
	unsigned int index;
	str* b2bl_key = (str*)param;
	b2bl_tuple_t* tuple;
	str method, body= {0, 0};
	str extra_headers = {0, 0};
	b2b_scenario_t* scenario;
	b2b_rule_t* rule;
	b2bl_entity_id_t* entity, *peer, *e;
	xmlNodePtr bridge_node, node;
	int state = -1;
	str attr;
	int statuscode;
	int ret;
	unsigned int method_value;
	int_str avp_val;

	if(b2bl_key == NULL)
	{
		LM_ERR("'param' argument NULL\n");
		return -1;
	}
	if(key == NULL)
	{
		LM_ERR("'key' argument NULL\n");
		return -1;
	}

	LM_DBG("b2b_entities notification cb for [%.*s] with entity [%.*s]\n",
			b2bl_key->len, b2bl_key->s, key->len, key->s);

	if(b2bl_parse_key(b2bl_key, &hash_index, &local_index)< 0)
	{
		LM_ERR("Failed to parse b2b logic key [%.*s]\n", b2bl_key->len, b2bl_key->s);
		return -1;
	}

	lock_get(&b2bl_htable[hash_index].lock);
	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if(tuple == NULL)
	{
		LM_ERR("B2B logic record not found\n");
		goto error;
	}
	scenario = tuple->scenario;

	if (parse_headers(msg, HDR_EOH_F, 0) < 0)
	{
		LM_ERR("failed to parse message\n");
		goto error;
	}

	/* extract body if it has one */
	/* process the body */
	if(msg->content_length)
	{
		body.len = get_content_length(msg);
		if(body.len != 0 )
		{
			body.s=get_body(msg);
			if (body.s== NULL) 
			{
				LM_ERR("cannot extract body\n");
				goto error;
			}
		}
	}
	entity = b2bl_search_entity(tuple, key, src);
	if(entity == NULL)
	{
		LM_ERR("No b2b_key match found [%.*s], src=%d\n", key->len, key->s, src);
		goto error;
	}
	peer = entity->peer;

	/* build extra headers */
	if(b2b_extra_headers(msg, 0, &extra_headers)< 0)
	{
		LM_ERR("Failed to construct extra headers\n");
		goto error;
	}

	LM_DBG("b2b_entity key = %.*s\n", key->len, key->s);

	if (b2bl_key_avp_name.n)
	{
		destroy_avps( b2bl_key_avp_type, b2bl_key_avp_name, 1);
		avp_val.s = *b2bl_key;
		if(add_avp(AVP_VAL_STR|b2bl_key_avp_type, b2bl_key_avp_name, avp_val)!=0)
		{
			LM_ERR("failed to build b2bl_key avp\n");
			return -1;
		}
	}

	if(type == B2B_REPLY)
	{
		method = get_cseq(msg)->method;
		if(parse_method(method.s, method.s+method.len, &method_value)< 0)
		{
			LM_ERR("Failed to parse method\n");
			goto error;
		}

		statuscode = msg->first_line.u.reply.statuscode;

		/* if a disconnected entity -> do nothing */
		if(entity->disconnected)
		{
			LM_DBG("This entity is disconnected\n");
			b2bl_delete_entity(entity, tuple);

			if(tuple->to_del && tuple->clients[0]==NULL && tuple->clients[1]==NULL &&
						tuple->servers[0]==NULL && tuple->servers[1]==NULL)
			{
				LM_DBG("Received reply and there are no more entities-> delete\n");
				b2bl_delete(tuple, hash_index, 0);
			}
			goto done;
		}

		/* if a reply from the client side was received, 
		* tell the server side to send a reply also */

		if((scenario && 
				scenario->reply_rules) || tuple->scenario_state == B2B_BRIDGING_STATE)
		{
			if(tuple->scenario_state == B2B_BRIDGING_STATE) /* if in a predefined state */
			{
				LM_DBG("Received a reply [%d] while in BRIDGING scenario\n",
					statuscode);
				/* if the scenario state is B2B_BRIDGING_STATE -> we should have a reply for INVITE */
				/* extract the method from Cseq header */

				if(method_value != METHOD_INVITE)
				{
					LM_ERR("Wrong scenario state [B2B_BRIDGING_STATE] for this"
						" reply(for method %d)\n", method_value);
					goto error;
				}
				/* if a negative reply */
				if(statuscode >= 300)
				{
					ret = process_bridge_negreply(tuple, hash_index,entity);

					if(ret < 0)
					{
						LM_ERR("Failed to process negative reply while in bridging state\n");
						goto error;
					}
					else
					if(ret == 1)
						goto done1;

					if(!entity->peer || !entity->peer->key.s)
					{
						LM_DBG("Delete this b2bl record\n");
						b2bl_delete(tuple, hash_index, 0);
					}
					goto done;
				}
				else
				if(statuscode < 200)
				{
					goto done;
				}

				/* if a reply with 200 OK -> we have two possibilities- either the first 200OK or the final */
				if(process_bridge_200OK(msg, tuple->extra_headers,
							(body.s?&body:0), tuple, entity)< 0)
				{
					LM_ERR("Failed to process bridging 200OK for Invite\n");
					goto error;
				}
			}
			if(scenario && scenario->reply_rules)
			{
				/* TODO -> process and apply reply rules */
			}
			if(statuscode >= 300)
			{
				tuple->to_del = 1;
				tuple->lifetime = 30 + get_ticks();
			}
		}
		else
		{
			if(!peer)
			{
				LM_DBG("No peer found\n");
				goto done;
			}
			if(b2b_api.send_reply(peer->type, &peer->key,
				method_value,statuscode,&msg->first_line.u.reply.reason,
				body.s?&body:0, extra_headers.s?&extra_headers:0,
				peer->dlginfo) < 0)
			{
				LM_ERR("Sending reply failed - %d, [%.*s]\n", statuscode,
						peer->key.len, peer->key.s);
			//	b2bl_delete(tuple, hash_index, 0);
				goto done;
			}

			/* if no other scenario rules defined and this is the reply for BYE */
			if(method_value == METHOD_BYE)
			{
				LM_DBG("Received reply for BYE - delete\n");
				b2bl_delete(tuple, hash_index, 0);
				goto done;
			}
			if(method_value == METHOD_INVITE)
			{
				if(entity->state!=DLG_CONFIRMED)
				{
					if(statuscode >= 300)
					{
						LM_DBG("Negative reply [%d] - delete[%p]\n", statuscode, tuple);
						b2b_mark_todel(tuple);
					}
					else
					if(statuscode >= 200 && statuscode < 300)
					{
						entity->state = DLG_CONFIRMED;
						entity->stats.setup_time = get_ticks() - entity->stats.start_time;
						entity->stats.start_time = get_ticks();
					}
				}
				else
				{
					/* if reINVITE and 481 or 408 reply */
					if(statuscode==481 || statuscode==408)
					{
						LM_DBG("Received terminate dialog reply for reINVITE\n");
						tuple->lifetime = 30 + get_ticks();
					}
				}
			}
		}
	}
	else
	{
		int request_id;

		method = msg->first_line.u.request.method;
		method_value = msg->first_line.u.request.method_value;
		/* extract body if it has a body */

		LM_DBG("request received for tuple[%p]->[%.*s]\n", tuple, tuple->key->len, tuple->key->s);
		request_id = b2b_get_request_id(&method);
		if(request_id < 0)
		{
			LM_DBG("Not a recognized request\n");
			goto send_usual_request;
		}
		/* if the request is an ACK and the tuple is marked to_del -> then delete the record and return */
		if(tuple->to_del)
		{
			if(request_id == B2B_ACK)
			{
				LM_DBG("ACK for a negative reply\n");
			}
			else
			if(request_id == B2B_BYE)
			{
				/* it means that a BYE was already sent to this entity but it did not reply */
				str msg = str_init("OK");
				b2b_api.send_reply(entity->type, &entity->key, METHOD_BYE,
						200, &msg, 0, 0, entity->dlginfo);
				if(entity->peer)
					b2b_api.send_reply(entity->peer->type, &entity->peer->key, METHOD_BYE,
							200, &msg, 0, 0, entity->peer->dlginfo);
			}
			else
			{
				str msg = str_init("Not Acceptable");
				b2b_api.send_reply(entity->type, &entity->key, method_value,
						400, &msg, 0, 0, entity->dlginfo);
			}
			b2bl_delete(tuple, hash_index, 0);
			goto done;
		}
		if(request_id == B2B_BYE)
		{
			entity->disconnected = 1;
			if(tuple->cbf)
			{
				b2bl_dlg_stat_t stat;
				b2bl_cback_f cbf = tuple->cbf;
				void* param = tuple->cb_param;
				int scenario_state = tuple->scenario_state;
				int eno = entity->no;
				int etype= entity->type;
				int found = 0;
				str ekey= {0, 0};

				if(tuple->scenario_state != B2B_BRIDGING_STATE)
					entity->stats.call_time = get_ticks() - entity->stats.start_time;
				else
					entity->stats.call_time = 0;
				memcpy(&stat, &entity->stats, sizeof(b2bl_dlg_stat_t));
				stat.key.s = (char*)pkg_malloc(tuple->key->len);
				if(stat.key.s == NULL)
				{
					LM_ERR("No more memory\n");
					goto error;
				}
				memcpy(stat.key.s, tuple->key->s, tuple->key->len);
				stat.key.len = tuple->key->len;
				ekey.s = (char*)pkg_malloc(entity->key.len);
				if(ekey.s == NULL)
				{
					LM_ERR("No more memory\n");
					pkg_free(stat.key.s);
					goto error;
				}
				memcpy(ekey.s, entity->key.s, entity->key.len);
				ekey.len = entity->key.len;

				tuple->cbf = NULL;
				lock_release(&b2bl_htable[hash_index].lock);
				LM_DBG("eno = %d\n", eno);
				ret = cbf(param, &stat, scenario_state, eno);
				LM_DBG("ret = %d, peer= %p\n", ret, peer);

				pkg_free(stat.key.s);
				lock_get(&b2bl_htable[hash_index].lock);
				/* must search the tuple again - you can't know what might have happened with it */
				tuple = b2bl_search_tuple_safe(hash_index, local_index);
				if(tuple == NULL)
				{
					LM_DBG("B2B logic record not found anymore\n");
					pkg_free(ekey.s);
					goto error;
				}
				tuple->cbf = cbf;
				if(etype == B2B_SERVER)
				{
					for (index = 0; index < MAX_B2BL_ENT; index++)
					{
						e = tuple->servers[index];
						if(e == entity && e->key.len == ekey.len &&
							strncmp(e->key.s, ekey.s, ekey.len)==0)
						{
							found = 1;
							break;
						}
					}
					if(!found)
					{
						LM_DBG("Server Entity does not exist anymore - goto done\n");
						pkg_free(ekey.s);
						goto done;
					}
				}
				else
				{
					for (index = 0; index < MAX_B2BL_ENT; index++)
					{
						e = tuple->clients[index];
						if(e == entity && e->key.len == ekey.len &&
							strncmp(e->key.s, ekey.s, ekey.len)==0)
						{
							found = 1;
							break;
						}
					}
					if(!found)
					{
						LM_DBG("Client Entity does not exist anymore - goto done\n");
						pkg_free(ekey.s);
						goto done;
					}
				}
				pkg_free(ekey.s);

				peer = entity->peer;
				if(ret< 0 )
				{
					LM_ERR("The callback function was unsuccessful\n");
					goto send_usual_request;
				}
				else
				if(ret == 0)
				{
					entity->peer = 0;
					/* send 200 OK for BYE */
					b2b_api.send_reply(entity->type, &entity->key, METHOD_BYE,
							200, &ok, 0, 0, entity->dlginfo);
					b2bl_delete_entity(entity, tuple);
					entity = NULL;
					goto done;
				}
				else
				if(ret == 1)
					goto send_usual_request;
			}

			if(tuple->scenario_state == B2B_BRIDGING_STATE)
			{
				LM_DBG("Scenario is in bridging state\n");
				if(process_bridge_bye(msg, tuple, entity) < 0)
				{
					LM_ERR("Failed to process BYE received in bridging state\n");
					goto error;
				}
				
				if(tuple->to_del && entity->peer==NULL)
				{
					LM_DBG("Delete this b2bl record after process_bridge_bye\n");
					b2bl_delete(tuple, hash_index, 0);
				}

				goto done;
			}
		}
		if(!scenario || !scenario->request_rules[request_id])
		{
			if(request_id == B2B_BYE)
			{
				/* even though I don;t receive a reply, 
				I should delete this record*/
				tuple->lifetime = 30 + get_ticks();
			}
			goto send_usual_request;
		}
		else
		{
			rule = scenario->request_rules[request_id];
			if(tuple->scenario_state != B2B_NOTDEF_STATE)
			{
				while(rule)
				{
					if(tuple->scenario_state == rule->cond_state)
					{
						break;
					}
					else
					{
						LM_DBG("State does not match found [%d], required [%d]\n",
								tuple->scenario_state, rule->cond_state);
					}
					rule = rule->next;
				}
			}
			if(!rule)
			{
				LM_DBG("Did not find a rule to apply for this request -> do normal pass through\n");
				goto send_usual_request;
			}
			else
			{
				LM_DBG("Found rule with id [%d]\n", rule->id);
			}
			/* if a match was found -> check the condition part */
			if(rule->cond_node)
			{
				node = xmlNodeGetChildByName(rule->cond_node, "sender");
				if(node)
				{
					LM_DBG("Found a sender condition\n");
					/* get the sender type */

					attr.s = (char*)xmlNodeGetNodeContentByName(node, "type", NULL);
					if(attr.s == NULL)
					{
						LM_ERR("Bad scenario document - sender condition node"
								" without a type child\n");
						goto error;
					}

					if(xmlStrcasecmp((unsigned char*)attr.s,(unsigned char*) "server") == 0)
					{
						/* check if it is a server request */
						if(src != B2B_SERVER)
						{
							xmlFree(attr.s);
							goto send_usual_request;
						}
					}
					else
					if(xmlStrcasecmp((unsigned char*) attr.s, (unsigned char*)"client") == 0)
					{
						if(src != B2B_CLIENT)
						{
							xmlFree(attr.s);
							goto send_usual_request;
						}
					}
					else
					{
						LM_ERR("Bad scenario document - sender condition type not"
								" known\n");
						xmlFree(attr.s);
						goto error;
					}
					xmlFree(attr.s);

					/* check the id */
					attr.s = xmlNodeGetNodeContentByName(node, "id", NULL);
					if(attr.s)
					{
						attr.len = strlen(attr.s);
						if((attr.len != entity->scenario_id.len ||
								strncmp(attr.s, entity->scenario_id.s, attr.len) != 0))
						{
							LM_DBG("Scenary id did not match - do not apply the rule"
									" found [%.*s] , required [%s]\n", 
									entity->scenario_id.len, entity->scenario_id.s, attr.s);
							xmlFree(attr.s);
							goto send_usual_request;
						}
						xmlFree(attr.s);
					}
					LM_DBG("Sender condition match\n");
				}
				/* TODO - process other conditions */
			}

			/* apply actions */

			/* get next state */
			node = xmlNodeGetChildByName(rule->action_node, "state");
			if(node)
			{
				attr.s = (char*)xmlNodeGetContent(node);
				if(attr.s == NULL)
				{
					LM_ERR("No state node content found\n");
					goto error;
				}
				attr.len = strlen(attr.s);

				if(str2int(&attr, (unsigned int*)&state)< 0)
				{
					LM_ERR("Bad scenario. Scenary state not an integer\n");
					xmlFree(attr.s);
					goto error;
				}
				LM_DBG("Next scenario state is [%d]\n", state);
				xmlFree(attr.s);
			}

		/* handle bridge action */

			bridge_node = xmlNodeGetChildByName(rule->action_node, "bridge");
			if(bridge_node)
			{
				LM_DBG("Found a bridge node\n");

				if(process_bridge_action(msg, entity, tuple, bridge_node) < 0)
				{
					LM_ERR("Failed to process bridge action\n");
					goto send_usual_request;
				}
				/* save next state */
				tuple->next_scenario_state = state;
			}
			else
			{
				/* set the next state now because the action has only one step */
				if(state >= 0)
					tuple->scenario_state = state;
			}

			node = xmlNodeGetChildByName(rule->action_node, "send_reply");
			if(node)
			{
				unsigned int code;

				LM_DBG("Found a send reply node\n");
				/* get code and text */
				attr.s = xmlNodeGetNodeContentByName(node, "code", NULL);
				if(attr.s == NULL)
				{
					LM_ERR("Bad scenario document - No code defined for send_reply node\n");
					goto error;
				}
				attr.len = strlen(attr.s);
				if(str2int(&attr, &code) < 0)
				{
					LM_ERR("Bad scenario - wrong reply code, not an integer\n");
					xmlFree(attr.s);
					goto error;
				}
				xmlFree(attr.s);

				attr.s = xmlNodeGetNodeContentByName(node, "reason", NULL);
				if(attr.s == NULL)
				{
					LM_ERR("Bad scenario document - No code defined for send_reply node\n");
					goto error;
				}
				attr.len = strlen(attr.s);

				b2b_api.send_reply(entity->type, &entity->key, method_value, code,
						&attr, 0, 0, entity->dlginfo);
				LM_DBG("Send reply with code [%d] and text [%s]\n", code, attr.s);

				xmlFree(attr.s);
			}
			/* end_dialog_leg option */
			node = xmlNodeGetChildByName(rule->action_node, "end_dialog_leg");
			if(node)
			{
				LM_DBG("End dialog\n");
				entity->disconnected = 1;
				b2b_api.send_request(entity->type, &entity->key,
						&method_bye, 0, 0, entity->dlginfo);
				if(entity->peer)
					entity->peer->peer = NULL;
				peer = entity->peer = NULL;
			}

			node = xmlNodeGetChildByName(rule->action_node, "delete_entity");
			if(node)
			{
				if(entity->peer)
					entity->peer->peer = 0;
				b2bl_delete_entity(entity, tuple);
				entity = NULL;
				LM_DBG("Deleted current entity\n");
			}
		}

		goto done;

send_usual_request:
		if(request_id == B2B_CANCEL)
			tuple->scenario_state = B2B_CANCEL_STATE;
		else
		if(request_id == B2B_BYE)
		{
			if(!peer || !peer->key.s)
			{
				b2b_api.send_reply(entity->type, &entity->key, METHOD_BYE,
						200, &ok, 0, 0, entity->dlginfo);
				b2bl_delete(tuple, hash_index, 0);
				goto done;
			}
			else
				b2b_mark_todel(tuple);
		}
		if(peer && peer->key.s)
		{
			LM_DBG("Send request [%.*s] to peer [%.*s]\n",
				method.len, method.s, peer->key.len, peer->key.s);
			if(b2b_api.send_request(peer->type, &peer->key, &method,
				extra_headers.len?&extra_headers:0, body.len?&body:0,
				peer->dlginfo) < 0)
			{
				LM_ERR("Sending request failed [%.*s]\n", peer->key.len, peer->key.s);
			//	b2bl_delete(tuple, hash_index, 0);
			}
		}
	}
done:
	UPDATE_DBFLAG(tuple, tuple->db_flag);
done1:
	lock_release(&b2bl_htable[hash_index].lock);
	if(extra_headers.s)
		pkg_free(extra_headers.s);
	return 0;

error:
	lock_release(&b2bl_htable[hash_index].lock);
	if(extra_headers.s)
		pkg_free(extra_headers.s);
	return -1;
}


/* This function does the following actions:
 *	- extract the entities description from the scenario document 
 *	- send invite or reInvite to one of the parties
 *	 - mark in the scenario instantiation which are the bridged entities and
 *	 that this scenario is currently taking place
 *	*/

int process_bridge_action(struct sip_msg* msg, b2bl_entity_id_t* curr_entity,
		b2bl_tuple_t* tuple, xmlNodePtr bridge_node)
{

	b2bl_entity_id_t* bridge_entities[3];
	b2bl_entity_id_t* entity = NULL;
	b2bl_entity_id_t* old_entity= NULL;
	b2bl_entity_id_t* e;
	int count = 0;
	int index = 0;
	str attr= {0, 0};
	str entity_dest;
	xmlNodePtr clientid_node;
	xmlNodePtr dest_node;
	xmlNodePtr client_node;
	xmlNodePtr lft_node;
	xmlNodePtr node;
	str provmedia_uri={0,0};
	client_info_t ci;
	str* client_id;
	char* fdname_content= 0;
	str from_dname= {0, 0};
	xmlNodePtr value_node;
	char* value_content= 0;

	/* extract provisional media uri if exists */
	node = xmlNodeGetChildByName(bridge_node, "provisional_media");
	if(node)
	{
		provmedia_uri.s = (char*)xmlNodeGetContent(node);
		if(provmedia_uri.s)
			provmedia_uri.len = strlen(provmedia_uri.s);
	}
	memset(bridge_entities, 0, 3*sizeof(b2bl_entity_id_t*));

	for(client_node= bridge_node->children; client_node;
			client_node=client_node->next)
	{
		if(xmlStrcasecmp(client_node->name, (unsigned char*)"client") !=0)
			continue;

		if(count == 2)
		{
			LM_ERR("Bad scenario document. Too many entities defined for"
				" bridge node. Only two entities should be defined\n");
			break;
		}
		entity = NULL;
		/* there are 3 ways to identify a client: "this", "peer" or "id" */
		clientid_node = xmlNodeGetChildByName(client_node, "this");
		if(clientid_node)
		{
			LM_DBG("Selected current entity\n");
			if(curr_entity == NULL)
			{
				LM_DBG("You are not allowed to use a 'this' client "
						"specification for this type of route\n");
				goto error;
			}
			entity = curr_entity;
			goto entity_search_done;
		}

		clientid_node = xmlNodeGetChildByName(client_node, "peer");
		if(clientid_node)
		{
			LM_DBG("Selected peer entity\n");
			if(curr_entity == NULL)
			{
				LM_DBG("You are not allowed to use a 'this' client "
						"specification for this type of route\n");
				goto error;
			}

			if(curr_entity->peer == NULL)
			{
				LM_ERR("Requested for the peer entity of the current entity, but it is NULL.\n");
				goto error;
			}
			entity = curr_entity->peer;
			goto entity_search_done;
		}

		/* extract entity id */
		attr.s = (char*)xmlNodeGetNodeContentByName(client_node, "id", NULL);
		if(attr.s == NULL)
		{
			LM_ERR("Entity specification not valid. Accepted values:"
					" this, peer or id\n");
			goto error;
		}
		attr.len = strlen(attr.s);

		/* search through the entities */
		for (index = 0; index < MAX_B2BL_ENT; index++)
		{
			e = tuple->servers[index];
			if (e && e->scenario_id.len == attr.len &&
					strncmp(e->scenario_id.s, attr.s, attr.len)== 0)
			{
				entity = e;
				LM_DBG("Found entity server [%d]\n", count);
				break;
			}
			e = tuple->clients[index];
			if (e && e->scenario_id.len == attr.len &&
					strncmp(e->scenario_id.s, attr.s, attr.len)== 0)
			{
				entity = e;
				LM_DBG("Found entity client [%d]\n", count);
				break;
			}
		}
		/* if I have the 'new' child -> alter the scenario id for the old entity */
		node = xmlNodeGetChildByName(client_node, "new");
		if(node && entity)
		{
			/* write '<' everywhere - it's safe since it's not accepted in xml */
			memset(entity->scenario_id.s, '<', entity->scenario_id.len);
			entity = NULL;
		}

entity_search_done:

		/* must create a new client entity */
		if(entity == NULL)
		{
			/* get the destination */
			LM_DBG("Entity %d for bridge - new client entity\n", count);
			dest_node = xmlNodeGetChildByName(client_node, "destination");
			if(dest_node == NULL)
			{
				LM_ERR("Bad format for b2b scenario. New entity without a destination\n");
				goto error;
			}
			value_node = xmlNodeGetChildByName(dest_node, "value");
			if(value_node == NULL)
			{
				LM_ERR("Bad format for b2b scenario. New entity without a destination\n");
				goto error;
			}
			value_content = (char*)xmlNodeGetContent(value_node);
			if(value_content == NULL)
			{
				LM_ERR("Bad formated scenario document. URI value empty\n");
				goto error;
			}
			if(b2b_scenario_parse_uri(value_node, value_content, tuple, msg,
						&entity_dest) < 0)
			{
				LM_ERR("Failed to parse entity destination specification\n");
				xmlFree(value_content);
				goto error;
			}
			node = xmlNodeGetChildByName(client_node, "from_dname");
			if(node)
			{
				value_node = xmlNodeGetChildByName(node, "value");
				if(value_node == NULL)
				{
					LM_ERR("Bad format for b2b scenario. New entity without a destination\n");
					xmlFree(value_content);
					goto error;
				}
				fdname_content = (char*)xmlNodeGetContent(value_node);
				if(fdname_content == NULL)
				{
					LM_ERR("Bad formated scenario document. URI value empty\n");
					xmlFree(value_content);
					goto error;
				}
				if(b2b_scenario_parse_uri(value_node, fdname_content, tuple, msg,
						&from_dname) < 0)
				{
					LM_DBG("Failed to parse entity destination specification\n");
					xmlFree(value_content);
					goto error;
				}
				
			}
			LM_DBG("New entity, dest = [%.*s]\n", entity_dest.len, entity_dest.s);
			entity = b2bl_create_new_entity(B2B_CLIENT, 0, &entity_dest, 0,
					from_dname.s?&from_dname:0, &attr, 0);
	
			if(fdname_content)
				xmlFree(fdname_content);
			fdname_content = 0;
			from_dname.s=0;
			xmlFree(value_content);
			if(entity == NULL)
			{
				LM_ERR("Failed to create new b2b entity\n");
				goto error;
			}
		}
		else
			old_entity = entity;

		if(attr.s)
			xmlFree(attr.s);
		attr.s = NULL;
		bridge_entities[count++] = entity;
	}

	if(bridge_entities[1] == bridge_entities[0])
	{
		LM_ERR("The scenario tells to bridge the same entity\n");
		goto error;
	}

	/* arrange the entities in vector to have the old first */
	if(old_entity && bridge_entities[0]!= old_entity)
	{
		bridge_entities[1] = bridge_entities[0];
		bridge_entities[0] = old_entity;
	}

	/* I have the two entities ->  now do the first step of the bridging scenario 
	 * -> send reInvite or Invite to one of the parties */
	if(old_entity)
	{
		LM_DBG("Sent reInvite without a body to old entity\n");
		tuple->bridge_entities[0]= bridge_entities[0];
		tuple->bridge_entities[1]= bridge_entities[1];

		if(provmedia_uri.s)
		{
			tuple->bridge_entities[2]= bridge_entities[1];

			tuple->bridge_entities[1] = b2bl_create_new_entity(B2B_CLIENT, 0, &provmedia_uri, 0, 0,0, 0);
			if(tuple->bridge_entities[1] == NULL)
			{
				LM_ERR("Failed to create new b2b entity\n");
				goto error;
			}
		}
		old_entity->stats.start_time = get_ticks();
		old_entity->stats.call_time = 0;
		/* TODO -> Do I need some other info here? */
		b2b_api.send_request(old_entity->type, &old_entity->key, &method_invite,
				 &maxfwd_hdr, 0, old_entity->dlginfo);
	}
	else
	{
		str from_uri   = bridge_entities[1]->to_uri;
		str to_uri     = bridge_entities[0]->to_uri;
		str from_dname = bridge_entities[0]->from_dname;

		memset(&ci, 0, sizeof(client_info_t));
		ci.method        = method_invite;
		ci.to_uri        = to_uri;
		ci.from_uri      = from_uri;
		ci.from_dname    = from_dname;
		ci.extra_headers = tuple->extra_headers;
		ci.body          = 0;
		ci.from_tag      = 0;
		ci.send_sock     = msg?msg->rcv.bind_address:0;
		if(msg)
		{
			if (str2int( &(get_cseq(msg)->number), &ci.cseq)!=0 )
			{
				LM_ERR("cannot parse cseq number\n");
				goto error1;
			}
		}
		LM_DBG("Send Invite without a body to a new client entity\n");
		client_id = b2b_api.client_new(&ci, b2b_client_notify,
				b2b_add_dlginfo, tuple->key);
		if(client_id == NULL)
		{
			LM_ERR("Failed to create new client entity\n");
			goto error1;
		}
		/* save the client_id in the structure */
		entity = b2bl_create_new_entity(B2B_CLIENT, client_id, &to_uri,
				&from_uri,0,&bridge_entities[0]->scenario_id, 0);
		if(entity == NULL)
		{
			LM_ERR("failed to create new client entity\n");
			pkg_free(client_id);
			goto error1;
		}
		pkg_free(client_id);
		entity->stats.call_time = get_ticks();
		entity->type = B2B_CLIENT;
		entity->peer = bridge_entities[1];
		shm_free(bridge_entities[0]);

		tuple->bridge_entities[0] = entity;
		tuple->bridge_entities[1]= bridge_entities[1];

		if (0 != b2bl_add_client(tuple, entity))
			goto error1;
	}
	/* save the pointers to the bridged entities ;
	 * the first (index 0) is the one we sent the first message ( reInvite or Invite)*/
	tuple->scenario_state = B2B_BRIDGING_STATE;

	/* extract the lifetime if one is defined */
	lft_node = xmlNodeGetChildByName(bridge_node, "lifetime");
	if(lft_node)
	{
		attr.s = (char*)xmlNodeGetContent(lft_node);
		if(attr.s == NULL)
		{
			LM_ERR("Failed to extract node content\n");
			goto error;
		}
		attr.len = strlen(attr.s);
		if(str2int(&attr, &tuple->lifetime)< 0)
		{
			LM_ERR("Wrong scenario document. The lifetime value is not an integer");
			xmlFree(attr.s);
			goto error;
		}
		xmlFree(attr.s);
		attr.s = NULL;
		LM_DBG("Lifetime defined = [%d]\n", tuple->lifetime);
		tuple->lifetime+= get_ticks();
	}
	else
		tuple->lifetime = -1;

	LM_DBG("be[0]= %p, be1=[%p]\n", tuple->bridge_entities[0], tuple->bridge_entities[1]);
	return 0;

error1:
	shm_free(bridge_entities[0]);
	shm_free(bridge_entities[1]);

error:
	if(attr.s)
		xmlFree(attr.s);
	return -1;
}

int b2b_server_notify(struct sip_msg* msg, str* key, int type, void* param)
{
	return b2b_logic_notify(B2B_SERVER, msg, key, type, param);
}


int b2b_client_notify(struct sip_msg* msg, str* key, int type, void* param)
{
	return b2b_logic_notify(B2B_CLIENT, msg, key, type, param);
}

str* create_top_hiding_entities(struct sip_msg* msg, b2bl_cback_f cbf,
		void* cb_param)
{
	str* server_id = NULL;
	str* client_id = NULL;
	str body = {0, 0};
	str extra_headers = {0, 0};
	str* b2bl_key;
	b2bl_tuple_t* tuple;
	unsigned int hash_index;
	str from_tag_uac;
	b2b_dlginfo_t* dlginfo, dlginfo_s;
	client_info_t ci;
	char buf[MD5_LEN];
	str src[2];
	str to_uri, from_uri;

	if(b2b_msg_get_to(msg, &to_uri)< 0 || b2b_msg_get_from(msg, &from_uri)< 0)
	{
		LM_ERR("Failed to get to or from from the message\n");
		return 0;
	}
	hash_index = core_hash(&to_uri, &from_uri, b2bl_hsize);

	tuple = b2bl_insert_new(msg, hash_index, 0, 0, 0, &b2bl_key);
	if(tuple== NULL)
	{
		LM_ERR("Failed to insert new scenario instance record\n");
		return 0;
	}
	tuple->cbf = cbf;
	tuple->cb_param = cb_param;

	LM_DBG("b2blogic_key = %.*s\n", b2bl_key->len, b2bl_key->s);

	/* if it will not be confirmed -> delete */
	tuple->lifetime = 60 + get_ticks();

	/* create new server */
	server_id = b2b_api.server_new(msg, b2b_server_notify, b2bl_key);
	if(server_id == NULL)
	{
		LM_ERR("failed to create new b2b server instance\n");
		goto error;
	}

	tuple->servers[0] = b2bl_create_new_entity(B2B_SERVER, server_id, &to_uri, &from_uri,
			0,0, msg);
	if(tuple->servers[0] == NULL)
	{
		LM_ERR("Failed to create server entity\n");
		goto error;
	}
	tuple->servers[0]->type = B2B_SERVER;
	/* process the body */
	if(msg->content_length)
	{
		body.len = get_content_length(msg);
		if(body.len != 0 )
		{
			body.s=get_body(msg);
			if (body.s== NULL) 
			{
				LM_ERR("cannot extract body\n");
				goto error;
			}
		}
	}

	LM_DBG("body = %.*s - len = %d\n", body.len, body.s, body.len);

	if(b2b_extra_headers(msg, b2bl_key, &extra_headers)< 0)
	{
		LM_ERR("Failed to create extra headers\n");
		goto error;
	}
	/* create new client */
	dlginfo = tuple->servers[0]->dlginfo;

	from_tag_uac.len = MD5_LEN;
	from_tag_uac.s = buf;
	src[0] =  dlginfo->callid;
	src[1] =  dlginfo->fromtag;
	MD5StringArray(from_tag_uac.s, src, 2);

	memset(&ci, 0, sizeof(client_info_t));
	ci.method        = msg->first_line.u.request.method;
	ci.to_uri        = to_uri;
	ci.from_uri      = from_uri;
	ci.dst_uri       = msg->dst_uri;
	ci.extra_headers = &extra_headers;
	ci.body          = (body.s?&body:NULL);
	ci.from_tag      = &from_tag_uac;
	ci.send_sock     = msg->rcv.bind_address;
	if (str2int( &(get_cseq(msg)->number), &ci.cseq)!=0 )
	{
		LM_ERR("cannot parse cseq number\n");
		goto error;
	}

	client_id = b2b_api.client_new(&ci, b2b_client_notify,
			b2b_add_dlginfo, b2bl_key);
	if(client_id == NULL)
	{
		LM_ERR("failed to create new b2b client instance\n");
		if(extra_headers.s)
			pkg_free(extra_headers.s);
		goto error;
	}
	if(extra_headers.s)
		pkg_free(extra_headers.s);

	tuple->clients[0] = b2bl_create_new_entity(B2B_CLIENT, client_id, &to_uri, &from_uri,
			0, 0, 0);
	if(tuple->clients[0] == NULL)
	{
		LM_ERR("Failed to create server entity\n");
		goto error;
	}
	LM_DBG("client %.*s\n", tuple->clients[0]->key.len,tuple->clients[0]->key.s);

	memset(&dlginfo_s, 0, sizeof(b2b_dlginfo_t));
	dlginfo_s.callid = *client_id;
	dlginfo_s.totag = from_tag_uac;
	if(entity_add_dlginfo(tuple->clients[0], &dlginfo_s)< 0)
	{
		LM_ERR("Failed to add dialoginfo\n");
		goto error;
	}

	tuple->servers[0]->peer = tuple->clients[0];
	tuple->clients[0]->peer = tuple->servers[0];
	tuple->bridge_entities[0] = tuple->servers[0];
	tuple->bridge_entities[1] = tuple->clients[0];
	lock_release(&b2bl_htable[hash_index].lock);

	pkg_free(server_id);
	pkg_free(client_id);

	return b2bl_key;
error:
	lock_release(&b2bl_htable[hash_index].lock);
	if(server_id)
		pkg_free(server_id);
	if(client_id)
		pkg_free(client_id);
	return 0;
}

/* Function that processes destination node.
 * Accepted value types:
 *	uri: specified inline
 *	param: specified as a parameter
 *	initial: the initial destination(from the initial message)
 *	header: a header field value
 **/

int b2b_scenario_parse_uri(xmlNodePtr value_node, char* value_content,
		b2bl_tuple_t* tuple, struct sip_msg* msg, str* client_to)
{

	str value= {value_content, strlen(value_content)};
	unsigned char* value_type= NULL;
	unsigned int param_no;

	value_type = xmlNodeGetAttrContentByName(value_node, "type");
	if(value_type == NULL)
	{
		LM_ERR("Scenary document not well formed. To type param not defined\n");
		return -1;
	}

	if(xmlStrcasecmp(value_type, (unsigned char*)"uri") == 0)
	{
		LM_DBG("URI of type uri\n");
		*client_to = value;
	}
	else
	if(xmlStrcasecmp(value_type, (unsigned char*)"param") == 0)
	{
		LM_DBG("URI of type param\n");

		if(str2int(&value, &param_no)< 0)
		{
			LM_ERR("Scenary document not well formed. Client to param not a number\n");
			goto error;
		}

		if(param_no > B2B_INIT_MAX_PARAMNO)
		{
			LM_ERR("Scenary document not well formed. Client to param not valid [%d]\n", param_no);
			goto error;
		}
		*client_to = tuple->scenario_params[param_no-1];
		LM_DBG("URI value taken from a parameter [%.*s]\n",
				client_to->len, client_to->s);
	}
	else
	if(xmlStrcasecmp(value_type, (unsigned char*)"initial") == 0)
	{
		LM_DBG("URI of type initial\n");
		// FIXME: this may not exist after a transfer that will leave us with two clients
		if (tuple->servers[0])
			*client_to = tuple->servers[0]->to_uri;
	}
	else
	if(xmlStrcasecmp(value_type, (unsigned char*)"header") == 0)
	{
		struct hdr_field* sip_hdr, hdr;
		char buf[BUF_LEN];
		struct sip_uri sip_uri;

		LM_DBG("URI of type header value\n");
		if(msg == NULL)
		{
			LM_DBG("You are not allowed to use a header specification for this type of scenario\n");
			goto error;
		}
		if(BUF_LEN < value.len + 1)
		{
			LM_ERR("Buffer overflow\n");
			goto error;
		}
		memcpy(buf, value.s, value.len);
		buf[value.len] = ':';

		if(parse_hname2(buf, buf + value.len+1, &hdr) < 0)
		{
			LM_ERR("Failed to parse header name\n");
			goto error;
		}
		if(hdr.type == HDR_OTHER_T)
		{
			LM_DBG("Header other\n");
			sip_hdr = get_header_by_name(msg, value.s, value.len);
			if(sip_hdr == NULL)
			{
				LM_DBG("No header with the name [%.*s] found\n", value.len, value.s);
				goto error;
			}
		}
		else
		if(hdr.type == HDR_ERROR_T)
		{
			LM_DBG("Failed to parse header name\n");
			goto error;
		}
		else
		{
			sip_hdr = msg->headers;
			while(sip_hdr && sip_hdr->type != hdr.type)
				sip_hdr = sip_hdr->next;
			if(sip_hdr == NULL)
			{
				LM_DBG("Did not find header\n");
				goto error;
			}
		}
		*client_to = sip_hdr->body;
		trim(client_to);
		
		if(client_to->s[0] == '<')
		{
			client_to->s++;
			client_to->len-=2;
		}
		if(parse_uri(client_to->s, client_to->len, &sip_uri)< 0)
		{
			LM_ERR("Not a valid sip uri [%.*s]\n", client_to->len, client_to->s);
			goto error;
		}
	}
	else
	{
		LM_ERR("Scenary document not well formed. Client to type not valid\n");
		goto error;
	}

	LM_DBG("URI value = [%.*s]\n", client_to->len, client_to->s);

	xmlFree(value_type);

	return 0;

error:
	if(value_type)
		xmlFree(value_type);
	return -1;
}

int udh_to_uri(str user, str host, str port, str* uri)
{
	int size;

	if(uri==0)
		return -1;
	size = user.len + host.len + port.len+7;
	uri->s = (char*)pkg_malloc(size);
	if(uri->s == NULL)
	{
		LM_ERR("No more memory\n");
		return -1;
	}

	uri->len = sprintf(uri->s, "sip:%.*s@%.*s", user.len, user.s,
			host.len, host.s);
	if(port.s)
	{
		uri->len += sprintf(uri->s+uri->len, ":%.*s", port.len, port.s);
	}
	return 0;
}

str* b2b_process_scenario_init(b2b_scenario_t* scenario_struct,struct sip_msg* msg,
		str* args[], b2bl_cback_f cbf, void* cb_param)
{
	str* server_id= NULL, *client_id= NULL;
	str body= {0, 0};
	str method = {INVITE, INVITE_LEN};
	str* b2bl_key = NULL;
	b2bl_tuple_t* tuple= NULL;
	xmlNodePtr node, init_node, node_aux;
	xmlNodePtr server_node = NULL, clients_node= NULL;
	str entity_sid;
	char* type= NULL;
	str client_to;
	b2bl_entity_id_t* client_entity = NULL;
	unsigned int scenario_state = B2B_NOTDEF_STATE;
	client_info_t ci;
	int clients_no = 0;
	unsigned int hash_index;
	unsigned int index;
	str to_uri, from_uri;
	int eno = 0;

	if(b2b_msg_get_to(msg, &to_uri)< 0 || b2b_msg_get_from(msg, &from_uri)< 0)
	{
		LM_ERR("Failed to get to or from from the message\n");
		return 0;
	}
	hash_index = core_hash(&to_uri, &from_uri, b2bl_hsize);

	if(msg)
	{
		method = msg->first_line.u.request.method;

		/* extract info from the message in case there is a client entity with type message */
		/* process the body */
		if(msg->content_length)
		{
			body.len = get_content_length(msg);
			if(body.len != 0 )
			{
				body.s=get_body(msg);
				if (body.s== NULL) 
				{
					LM_ERR("cannot extract body\n");
					return 0;
				}
			}
			LM_DBG("body = %.*s - len = %d\n", body.len, body.s, body.len);
		}
	}

	/* examine the init part in the scenario XML document */
	init_node = xmlNodeGetChildByName(scenario_struct->init_node, "bridge");
	if(init_node == NULL)
	{
		LM_ERR("Wrong format for b2b scenario document. No bridging node"
				" inside init node\n");
		goto error;
	}

	server_node = xmlNodeGetChildByName(init_node, "server");

	clients_node = xmlNodeGetChildByName(init_node, "client");
	if(server_node == NULL && clients_node == NULL)
	{
		LM_ERR("There must be at least one client or one server entity\n");
		goto error;
	}

	/* create new scenario instance record */
	tuple = b2bl_insert_new(msg, hash_index, scenario_struct,
			args, body.s?&body:0, &b2bl_key);
	if(tuple== NULL)
	{
		LM_ERR("Failed to insert new scenario instance record\n");
		goto error;
	}
	tuple->lifetime = 60 + get_ticks();

	/* set the state of the scenario after the init section */
	node = xmlNodeGetChildByName(scenario_struct->init_node, "state");
	if(node)
	{
		str state_attr;
		state_attr.s = (char*)xmlNodeGetContent(node);
		state_attr.len = strlen(state_attr.s);

		if(str2int(&state_attr, &scenario_state)< 0)
		{
			LM_ERR("Scenary state after init section not an integer\n");
			xmlFree(state_attr.s);
			goto error;
		}
		xmlFree(state_attr.s);

		tuple->scenario_state = scenario_state;
		tuple->next_scenario_state = scenario_state;
	}

	/* go through the document and create the described entities */
	if(server_node)
	{
		if(msg == NULL)
		{
			LM_ERR("A request for a server entity and no message\n");
			goto error;
		}
		/* a server entity can only deal with a message and there can only be one server entity */
		/* extract the id */
		entity_sid.s = (char*)xmlNodeGetNodeContentByName(server_node, "id", NULL);
		if(entity_sid.s == NULL)
		{
			LM_ERR("Wrong formatted xml document. Server node without id parameter\n");
			goto error;
		}
		entity_sid.len = strlen(entity_sid.s);

		/* create new server entity */
		server_id = b2b_api.server_new(msg, b2b_server_notify, b2bl_key);
		if(server_id == NULL)
		{
			LM_ERR("failed to create new b2b server instance\n");
			xmlFree(entity_sid.s);
			goto error;
		}
		tuple->servers[0] = b2bl_create_new_entity(B2B_SERVER, server_id, &to_uri,
				&from_uri,0,&entity_sid,msg);
		tuple->servers[0]->no = eno++;
		tuple->bridge_entities[0] = tuple->servers[0];
		if(tuple->servers[0] == NULL)
		{
			LM_ERR("failed to create new server entity\n");
			xmlFree(entity_sid.s);
			pkg_free(server_id);
			goto error;
		}
		xmlFree(entity_sid.s);
		pkg_free(server_id);
		tuple->servers[0]->type = B2B_SERVER;
	}

	/* create client entities */
	for(node = clients_node; node; node=node->next)
	{
		char* value_content;

		if(xmlStrcasecmp(node->name, (unsigned char*)"client") !=0 )
			continue;

		entity_sid.s = (char*)xmlNodeGetNodeContentByName(node, "id", NULL);
		if(entity_sid.s == NULL)
		{
			LM_ERR("Wrong formated xml document. Client node without id parameter\n");
			goto error;
		}
		entity_sid.len = strlen(entity_sid.s);

		/* get type*/
		type = xmlNodeGetNodeContentByName(node, "type", NULL);
		if(type == NULL)
		{
			LM_ERR("Scenary document not well formed. Client Type node not found\n");
			goto error1;
		}
		/* extract destination */
		node_aux = xmlNodeGetChildByName(node, "destination");
		if(node_aux == NULL)
		{
			LM_ERR("Scenary document not well formed. No client 'to' node defined\n");
			goto error2;
		}

		node_aux = xmlNodeGetChildByName(node_aux, "value");
		if(node_aux == NULL)
		{
			LM_ERR("Bad format for b2b scenario. New entity without a destination\n");
			goto error2;
		}
		value_content = (char*)xmlNodeGetContent(node_aux);
		if(value_content == NULL)
		{
			LM_ERR("Bad formated scenario document. URI value empty\n");
			goto error2;
		}

		if(b2b_scenario_parse_uri(node_aux, value_content, tuple, msg,
					&client_to) < 0)
		{
			LM_ERR("Failed to get the value for the b2b client ruri\n");
			xmlFree(value_content);
			goto error2;
		}
		xmlFree(value_content);

		if(xmlStrcasecmp((unsigned char*)type, (unsigned char*)"message") == 0)
		{
			memset(&ci, 0, sizeof(client_info_t));
			ci.method        = method;
			ci.to_uri        = client_to;
			ci.from_uri      = from_uri;
			ci.extra_headers = tuple->extra_headers;
			ci.body          = (body.s?&body:NULL);
			ci.from_tag      = 0;
			ci.send_sock     = msg->rcv.bind_address;
			if (str2int( &(get_cseq(msg)->number), &ci.cseq)!=0 )
			{
				LM_ERR("cannot parse cseq number\n");
				goto error;
			}

			client_id = b2b_api.client_new(&ci, b2b_client_notify,
					b2b_add_dlginfo, b2bl_key);
			if(client_id == NULL)
			{
				LM_ERR("failed to create new b2b client instance\n");
				goto error2;
			}

			client_entity = b2bl_create_new_entity(B2B_CLIENT, client_id, &client_to,
					&from_uri,0,&entity_sid, 0);
			if(client_entity == NULL)
			{
				LM_ERR("failed to create new client entity\n");
				xmlFree(entity_sid.s);
				pkg_free(client_id);
				goto error2;
			}
			pkg_free(client_id);

			if (0 != b2bl_add_client(tuple, client_entity))
				goto error2;
			client_entity->no = eno++;
			clients_no++;
		}
		xmlFree(type);
		xmlFree(entity_sid.s);
	}

	/* If I have a server entity I consider it peer for all client entities,
	 * and its peer is the first client */
	if(tuple->servers[0])
	{
		if(tuple->clients[0] == NULL)
		{
			LM_ERR("You have to create at least 2 entities in init part\n");
			goto error;
		}
		for (index = 0; index < MAX_B2BL_ENT; index++)
		{
			if (tuple->clients[index])
				tuple->clients[index]->peer = tuple->servers[0];

		}
		tuple->bridge_entities[0] = tuple->servers[0];
		tuple->bridge_entities[1] = tuple->clients[0];
	}
	else
	{
		if(clients_no >= 2) /* make the first 2 peers */
		{
			tuple->bridge_entities[0]= tuple->clients[0];
			tuple->bridge_entities[1]= tuple->clients[1];
		}
		else
		{
			LM_ERR("You have to create at least 2 entities in init part\n");
			goto error;
		}
	}
	tuple->bridge_entities[0]->peer = tuple->bridge_entities[1];
	tuple->bridge_entities[1]->peer = tuple->bridge_entities[0];

	tuple->cbf = cbf;
	tuple->cb_param = cb_param;
	
	lock_release(&b2bl_htable[hash_index].lock);

	return b2bl_key;

error2:
	xmlFree(type);
error1:
	xmlFree(entity_sid.s);
error:
	if(tuple)
	{
		b2bl_delete(tuple, hash_index, 0);
		lock_release(&b2bl_htable[hash_index].lock);
	}
	return 0;
}

str* init_request(struct sip_msg* msg, b2b_scenario_t* scenario_struct,
		str* args[], b2bl_cback_f cbf, void* cb_param)
{
	/* parse message to extract needed info */
	if (parse_headers(msg, HDR_EOH_F, 0) < 0)
	{
		LM_ERR("failed to parse message\n");
		return 0;
	}

	if(scenario_struct == NULL)
		return create_top_hiding_entities(msg, cbf, cb_param);

	return b2b_process_scenario_init(scenario_struct, msg, args, cbf, cb_param);
}

str* internal_init_scenario(struct sip_msg* msg, str* name, str* args[MAX_SCENARIO_PARAMS],
		b2bl_cback_f cbf, void* cb_param)
{
	b2b_scenario_t* scenario_struct;

	if(name->len == B2B_TOP_HIDING_SCENARY_LEN &&
		strncmp(name->s,B2B_TOP_HIDING_SCENARY,B2B_TOP_HIDING_SCENARY_LEN)==0)
	{
		scenario_struct = NULL;
	}
	else
	{
		scenario_struct = get_scenario_id_list(name, script_scenarios);
		if(!scenario_struct)
		{
			LM_ERR("No scenario found with id [%s]\n", name->s);
			return 0;
		}
	}
	b2bl_caller = CALLER_MODULE;
	return init_request(msg, scenario_struct, args, cbf, cb_param);
}

int b2b_init_request(struct sip_msg* msg, str* arg1, str* arg2, str* arg3,
		str* arg4, str* arg5, str* arg6)
{
	str* args[MAX_SCENARIO_PARAMS];
	b2b_scenario_t* scenario_struct;
	str* key;
	int_str avp_val;

	if (b2bl_key_avp_name.n)
		destroy_avps( b2bl_key_avp_type, b2bl_key_avp_name, 1);

	/* find the b2b_logic key for the tuple */
	/* it will encode the position in the hash table */
	/* get the hash_index from to_uri and from_uri */

	/* find the scenario with the corresponding id */
	scenario_struct = (b2b_scenario_t*)arg1;
	b2bl_caller = CALLER_SCRIPT;

	/* call the scenario init processing function */
	args[0] = arg2;
	args[1] = arg3;
	args[2] = arg4;
	args[3] = arg5;
	args[4] = arg6;

	key = init_request(msg, scenario_struct, args, 0, 0);
	if(key)
	{
		if (b2bl_key_avp_name.n)
		{
			avp_val.s = *key;
			if(add_avp(AVP_VAL_STR|b2bl_key_avp_type, b2bl_key_avp_name, avp_val)!=0)
			{
				LM_ERR("failed to build b2bl_key avp\n");
				return -1;
			}
		}
		return 1;
	}
	return -1;
}


int b2bl_bridge(str* key, str* new_dst, str* new_from_dname, int entity_no)
{
	b2bl_tuple_t* tuple;
	b2bl_entity_id_t* entity, *old_entity;
	struct sip_uri uri;
	unsigned int hash_index, local_index;

	if(!key || !new_dst)
	{
		LM_ERR("Wrong arguments\n");
		return -1;
	}

	if(entity_no == 1)
	{
		LM_WARN("Not implemented yet.\n");
		return 0;
	}

	if(parse_uri(new_dst->s, new_dst->len, &uri)< 0)
	{
		LM_ERR("Bad argument. Not a valid uri [%.*s]\n", new_dst->len, new_dst->s);
		return -1;
	}

	if(b2bl_parse_key(key, &hash_index, &local_index) < 0)
	{
		LM_ERR("Failed to parse key\n");
		return -1;
	}

	entity = b2bl_create_new_entity(B2B_CLIENT,0,new_dst,0,new_from_dname,0,0);
	if(entity == NULL)
	{
		LM_ERR("Failed to create new b2b entity\n");
		return -1;
	}
	LM_DBG("Created new client entity [%.*s]\n", new_dst->len, new_dst->s);

	lock_get(&b2bl_htable[hash_index].lock);

	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if(tuple == NULL)
	{
		LM_ERR("No entity found\n");
		goto error;
	}

	// FIXME: we may have no server at some point in time
	if(tuple->servers[0] == NULL)
	{
		LM_ERR("Wrong usage - no server entity present\n");
		goto error;
	}
	LM_DBG("Bridge server %.*s\n",tuple->servers[0]->dlginfo->callid.len,
			tuple->servers[0]->dlginfo->callid.s);
	old_entity = tuple->servers[0]->peer;
	if(old_entity)
	{
		LM_DBG("End peer dialog [%p]\n", old_entity);	
		old_entity->peer = NULL;
		if(old_entity->disconnected && old_entity->state==DLG_CONFIRMED)
		{
			b2b_api.send_reply(old_entity->type, &old_entity->key,
					METHOD_BYE, 200, &ok, 0, 0, old_entity->dlginfo);
			b2bl_delete_entity(old_entity, tuple);
		}
		else
			b2b_end_dialog(old_entity, tuple);
	}
	else
		LM_DBG("No peer found\n");	

	tuple->bridge_entities[0]= tuple->servers[0];
	tuple->bridge_entities[1]= entity;
	tuple->servers[0]->no = 0;
	entity->no = 1;

	tuple->servers[0]->peer = entity;
	entity->peer = tuple->servers[0];

	tuple->scenario_state = B2B_BRIDGING_STATE;
	tuple->servers[0]->stats.start_time = get_ticks();
	tuple->servers[0]->stats.call_time = 0;
	b2b_api.send_request(B2B_SERVER, &tuple->servers[0]->key, &method_invite,
				 0, 0, tuple->servers[0]->dlginfo);

	lock_release(&b2bl_htable[hash_index].lock);

	return 0;

error:
	if(entity)
		shm_free(entity);
	lock_release(&b2bl_htable[hash_index].lock);
	return -1;
}

int b2bl_terminate_call(str* key)
{
	unsigned int hash_index, local_index;
	b2bl_tuple_t* tuple;
	b2bl_entity_id_t* e;
	int i;

	if(b2bl_parse_key(key, &hash_index, &local_index) < 0)
	{
		LM_ERR("Failed to parse key\n");
		return -1;
	}

	lock_get(&b2bl_htable[hash_index].lock);

	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if(tuple == NULL)
	{
		LM_DBG("No entity found [%.*s]\n", key->len, key->s);
		lock_release(&b2bl_htable[hash_index].lock);
		return -1;
	}

	for( i = 0; i<2; i++ )
	{
		e = tuple->bridge_entities[0];
		b2b_end_dialog(e, tuple);
	}
	b2b_mark_todel(tuple);

	lock_release(&b2bl_htable[hash_index].lock);

	return 0;
}

int b2bl_set_state(str* key, int state)
{
	unsigned int hash_index, local_index;
	b2bl_tuple_t* tuple;

	if(b2bl_parse_key(key, &hash_index, &local_index) < 0)
	{
		LM_ERR("Failed to parse key\n");
		return -1;
	}

	lock_get(&b2bl_htable[hash_index].lock);

	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if(tuple == NULL)
	{
		LM_ERR("No entity found\n");
		lock_release(&b2bl_htable[hash_index].lock);
		return -1;
	}

	if(tuple->scenario_state == B2B_BRIDGING_STATE)
		tuple->next_scenario_state = state;
	else
		tuple->scenario_state = state;

	lock_release(&b2bl_htable[hash_index].lock);

	return 0;
}

int b2bl_bridge_2calls(str* key1, str* key2)
{
	b2bl_tuple_t* tuple;
	unsigned int hash_index, local_index;
	b2bl_entity_id_t *e2= 0, *e1= 0;
	b2bl_entity_id_t *e;

	if(!key1 || !key2)
	{
		LM_ERR("Wrong arguments [%p] [%p]\n", key1, key2);
		return -1;
	}

	if(b2bl_parse_key(key2, &hash_index, &local_index) < 0)
	{
		LM_ERR("Failed to parse key [%.*s]\n", key2->len, key2->s);
		return -1;
	}

	/* extract the entity and delete the tuple */
	lock_get(&b2bl_htable[hash_index].lock);

	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if(tuple == NULL)
	{
		LM_ERR("No entity found\n");
		goto error;
	}

	if(tuple->bridge_entities[0] && !tuple->bridge_entities[0]->disconnected)
	{
		e2 = tuple->bridge_entities[0];
		e = tuple->bridge_entities[1];
	}
	else
	if(tuple->bridge_entities[1] && !tuple->bridge_entities[1]->disconnected)
	{
		e2 = tuple->bridge_entities[1];
		e = tuple->bridge_entities[0];
	}
	tuple->cbf = 0;
	if(e2 == NULL)
	{
		LM_ERR("entity not found for key 2 [%.*s]\n", key2->len, key2->s);
		goto error;
	}
	if(e2->state != DLG_CONFIRMED)
	{
		LM_ERR("Wrong state for entity ek= [%.*s], tk=[%.*s]\n",e2->key.len,
				e2->key.s, key2->len, key2->s);
		goto error;
	}

	if(e)
	{
		if(e->disconnected && e->state==DLG_CONFIRMED)
			b2b_api.send_reply(e->type,&e->key,METHOD_BYE,200,&ok,0,0,e->dlginfo);
		else
			b2b_end_dialog(e, tuple);
		e->peer = NULL;
	}

	// FIXME: this logic may need to be updated
	if(e2->type == B2B_SERVER)
	{
		if(e2 == tuple->servers[0])
		{
			tuple->servers[0] = tuple->servers[1];
			tuple->servers[1] = NULL;
		}
		else if(e2 == tuple->servers[1])
			tuple->servers[1] = NULL;
		else
		{
			LM_ERR("BUG: server entity [%.*s] not found\n", e2->key.len, e2->key.s);
			goto error;
		}
	}
	else if (e2->type == B2B_CLIENT)
	{
		if(e2 == tuple->clients[0])
		{
			tuple->clients[0] = tuple->clients[1];
			tuple->clients[1] = NULL;
		}
		else if(e2 == tuple->clients[1])
			tuple->clients[1] = NULL;
		else
		{
			LM_ERR("BUG: client entity [%.*s] not found\n", e2->key.len, e2->key.s);
			goto error;
		}
	}
	else
	{
		LM_ERR("BUG: unexpected entity type [%d] for [%.*s]\n",
				e2->type, e2->key.len, e2->key.s);
		goto error;
	}
	b2bl_delete(tuple, hash_index, 0);
	lock_release(&b2bl_htable[hash_index].lock);
	/* must restore the b2bl_key for this entity in b2b_entities */

	if(b2bl_parse_key(key1, &hash_index, &local_index) < 0)
	{
		LM_ERR("Failed to parse key [%.*s]\n", key1->len, key1->s);
		return -1;
	}

	/* extract the entity and delete the tuple */
	lock_get(&b2bl_htable[hash_index].lock);

	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if(tuple == NULL)
	{
		LM_ERR("No entity found\n");
		goto error;
	}
	
	e1 = tuple->bridge_entities[0];
	if(e1 == NULL || e1->disconnected)
	{
		LM_ERR("entity not found for key 1 [%.*s]\n", key1->len, key1->s);
		goto error;
	}

	e = tuple->bridge_entities[1];
	if(e)
	{
		if(e->disconnected && e->state==DLG_CONFIRMED)
			b2b_api.send_reply(e->type,&e->key,METHOD_BYE,200,&ok,0,0,e->dlginfo);
		b2b_end_dialog(e, tuple);
		e->peer = NULL;
	}

	/* put it in clients list */
	e2->type = B2B_CLIENT;
	if (tuple->clients[0])
		tuple->clients[1] = e2;	
	else
		tuple->clients[0] = e2;	
	tuple->bridge_entities[1]= e2;

	e1->peer = e2;
	e2->peer = e1;
	e1->no = 0;
	e2->no = 1;
	
	if(b2b_api.update_b2bl_param(e2->type, &e2->key, tuple->key) < 0)
	{
		LM_ERR("Failed to update b2bl parameter in b2b_entities\n");
		goto error;
	}
	LM_DBG("Updated b2bl param for entity [%.*s]\n", e2->key.len, e2->key.s);	
	e1->stats.start_time = get_ticks();
	e1->stats.call_time = 0;
	if(b2b_api.send_request(e1->type, &e1->key, &method_invite, &maxfwd_hdr,
			0, e1->dlginfo) > 0)
	{
		LM_ERR("Failed to send reInvite\n");
		goto error;
	}
	tuple->scenario_state = B2B_BRIDGING_STATE;
	tuple->lifetime = -1;
	lock_release(&b2bl_htable[hash_index].lock);

	return 0;
	
error:
	if(tuple)
		b2b_mark_todel(tuple);
	lock_release(&b2bl_htable[hash_index].lock);
	return -1;
}


/* Bridge an initial Invite with an existing dialog */
/* key and entity_no identity the existing call and the which entity from the call
 * to bridge (0 or 1) */
int b2bl_bridge_msg(struct sip_msg* msg, str* key, int entity_no)
{
	b2bl_tuple_t* tuple;
	unsigned int hash_index, local_index;
	b2bl_entity_id_t *bridging_entity= NULL;
	b2bl_entity_id_t *old_entity;
	b2bl_entity_id_t *entity;
	str* server_id;
	str body;
	str to_uri, from_uri;

	if(!msg || !key)
	{
		LM_ERR("Wrong arguments [%p] [%p]\n", msg, key);
		return -1;
	}

	if(b2bl_parse_key(key, &hash_index, &local_index) < 0)
	{
		LM_ERR("Failed to parse key [%.*s]\n", key->len, key->s);
		return -1;
	}

	/* extract the entity and delete the tuple */
	lock_get(&b2bl_htable[hash_index].lock);

	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if(tuple == NULL)
	{
		LM_ERR("No entity found\n");
		goto error;
	}
	if(entity_no!=0 && entity_no!=1)
	{
		LM_ERR("entity_no param can take only 0 or 1 value, got [%d]\n", entity_no);
		goto error;
	}

	if(!tuple->bridge_entities[entity_no] || tuple->bridge_entities[entity_no]->disconnected)
	{
		LM_ERR("Can not bridge requested entity [%p]\n", tuple->bridge_entities[entity_no]);
		goto error;
	}
	bridging_entity = tuple->bridge_entities[entity_no];
	old_entity = tuple->bridge_entities[(entity_no?0:1)];

/*
	if(bridging_entity->state != DLG_CONFIRMED)
	{
		LM_ERR("Wrong state for entity ek= [%.*s], tk=[%.*s]\n",bridging_entity->key.len,
				bridging_entity->key.s, key->len, key->s);
		goto error;
	}
*/

	b2bl_print_tuple(tuple);

	if(old_entity)
	{
		LM_DBG("terminating b2bl_entity [%p]->[%.*s] type [%d]\n",
					old_entity, old_entity->key.len, old_entity->key.s,
					old_entity->type);
		if(old_entity->disconnected)
			b2b_api.send_reply(old_entity->type,&old_entity->key,METHOD_BYE,
					200,&ok,0,0,old_entity->dlginfo);
		else
			b2b_end_dialog(old_entity, tuple);
		if (old_entity->peer->peer == old_entity)
			old_entity->peer->peer = NULL;
		else
		{
			LM_ERR("Unexpected chain: old_entity=[%p] and "
				"old_entity->peer->peer=[%p]\n",
				old_entity, old_entity->peer->peer);
			goto error;
		}
		old_entity->peer = NULL;
	}

	/* remove the disconected entity from the tuple */
	if(0 == b2bl_drop_entity(old_entity, tuple))
	{
		LM_WARN("Inconsistent tuple [%p]\n", tuple);
		b2bl_print_tuple(tuple);
		goto error;
	}

	b2bl_print_tuple(tuple);

	/* create server entity from Invite */
	if(b2b_msg_get_to(msg, &to_uri)< 0 || b2b_msg_get_from(msg, &from_uri)< 0)
	{
		LM_ERR("Failed to get to or from from the message\n");
		goto error;
	}
	server_id = b2b_api.server_new(msg, b2b_server_notify, tuple->key);
	if(server_id == NULL)
	{
		LM_ERR("failed to create new b2b server instance\n");
		goto error;
	}

	entity = b2bl_create_new_entity(B2B_SERVER, server_id, &to_uri, &from_uri,
			0,0, msg);
	if(entity == NULL)
	{
		LM_ERR("Failed to create server entity\n");
		goto error;
	}

	if (0 != b2bl_add_server(tuple, entity))
		goto error;

	entity->peer = bridging_entity;
	bridging_entity->peer = entity;

	entity->stats.start_time = get_ticks();
	entity->stats.call_time = 0;

	bridging_entity->no = 0;
	entity->no = 1;

	/* send reInvite to the old entity*/
	if(msg->content_length)
	{
		body.len = get_content_length(msg);
		if(body.len != 0 )
		{
			body.s=get_body(msg);
			if (body.s== NULL) 
			{
				LM_ERR("cannot extract body\n");
				goto error;
			}
		}
	}

	if(b2b_api.send_request(bridging_entity->type, &bridging_entity->key, &method_invite,
			tuple->extra_headers, &body, bridging_entity->dlginfo) > 0)
	{
		LM_ERR("Failed to send reInvite\n");
		goto error;
	}
	tuple->lifetime = -1;

	tuple->bridge_entities[0] = bridging_entity;
	tuple->bridge_entities[1] = entity;

	b2bl_print_tuple(tuple);

	lock_release(&b2bl_htable[hash_index].lock);
	return 0;

error:
	if(tuple)
		b2b_mark_todel(tuple);
	lock_release(&b2bl_htable[hash_index].lock);
	return -1;
}
