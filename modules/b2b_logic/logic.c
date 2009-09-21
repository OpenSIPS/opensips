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
#include "../../ut.h"
#include "../../mem/shm_mem.h"
#include "../../mem/mem.h"
#include "../b2b_entities/dlg.h"
#include "../presence/hash.h"
#include "../presence/utils_func.h"

#include "records.h"
#include "pidf.h"
#include "b2b_logic.h"

#define CONT_COPY_P(buf, dest, source)\
	dest.s= (char*)buf+ size;\
	memcpy(dest.s, source->s, source->len);\
	dest.len= source->len;\
	size+= source->len;

int b2b_scenario_parse_uri(xmlNodePtr value_node, char* value_content, b2bl_tuple_t* tuple,
		str* client_to);

int b2b_client_notify(struct sip_msg* msg, str* key, int type, void* param);

b2bl_entity_id_t* b2bl_create_new_entity(enum b2b_entity_type type, str* entity_id,
		str* to_uri,str* from_uri, str* ssid)
{
	unsigned int size;
	b2bl_entity_id_t* entity;

	size = sizeof(b2bl_entity_id_t) + ((ssid!=NULL)?ssid->len:0) +
		((entity_id!=NULL)?entity_id->len:0)+ ((to_uri !=NULL)?to_uri->len:0)
		+ ((from_uri!=NULL)?from_uri->len:0);

	entity = (b2bl_entity_id_t*)shm_malloc(size);
	if(entity == NULL)
	{
		LM_ERR("No more shared memory\n");
		return 0;
	}
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

	entity->type = type;

	return entity;
}

/* Take headers to pass on the other side:
 *	Content-Type: 
 *	Allow: 
 *	Supported:
 *	Require
 *	RSeq
 *	Session-Expires
 *	Min-SE
*/

int b2b_extra_headers(struct sip_msg* msg, str* extra_headers)
{
	char* p;
	struct hdr_field* require_hdr;
	struct hdr_field* rseq_hdr;

	if(msg->content_type)
		extra_headers->len = msg->content_type->len;
	if(msg->supported)
		extra_headers->len += msg->supported->len;
	if(msg->allow)
		extra_headers->len += msg->allow->len;
	if(msg->proxy_require)
		extra_headers->len += msg->proxy_require->len;
	if(msg->session_expires)
		extra_headers->len += msg->session_expires->len;
	if(msg->min_se)
		extra_headers->len += msg->min_se->len;

	require_hdr = get_header_by_static_name( msg, "Require");
	if(require_hdr)
		extra_headers->len += require_hdr->len;

	rseq_hdr = get_header_by_static_name( msg, "RSeq");
	if(rseq_hdr)
		extra_headers->len += rseq_hdr->len;

	if(extra_headers->len == 0)
		return 0;

	extra_headers->s = (char*)pkg_malloc(extra_headers->len);
	if(extra_headers->s == NULL)
	{
		LM_ERR("No more memory\n");
		return -1;
	}

	p = extra_headers->s;

	if(msg->content_type)
	{
		memcpy(p, msg->content_type->name.s, msg->content_type->len);
		p+= msg->content_type->len;
	}

	if(msg->supported)
	{
		memcpy(p, msg->supported->name.s, msg->supported->len);
		p+=  msg->supported->len;
	}

	if(msg->allow)
	{
		memcpy(p, msg->allow->name.s, msg->allow->len);
		p+= msg->allow->len;
	}
	
	if(msg->proxy_require)
	{
		memcpy(p, msg->proxy_require->name.s, msg->proxy_require->len);
		p+= msg->proxy_require->len;
	}

	if(require_hdr)
	{
		LM_DBG("Require header found\n");
		memcpy(p, require_hdr->name.s, require_hdr->len);
		p+= require_hdr->len;
	}

	if(rseq_hdr)
	{
		LM_DBG("Require header found\n");
		memcpy(p, rseq_hdr->name.s, rseq_hdr->len);
		p+= rseq_hdr->len;
	}

	if(msg->session_expires)
	{
		memcpy(p, msg->session_expires->name.s, msg->session_expires->len);
		p+= msg->session_expires->len;
	}

	if(msg->min_se)
	{
		memcpy(p, msg->min_se->name.s, msg->min_se->len);
		p+= msg->min_se->len;
	}

	return 0;
}

int process_bridge_200OK(struct sip_msg* msg, str* extra_headers,
		str* body, b2bl_tuple_t* tuple)
{
	str* client_id;
	b2bl_entity_id_t* entity, *bentity0, *bentity1;
	str method={INVITE, INVITE_LEN};

	bentity0 = tuple->bridge_entities[0];
	bentity1 = tuple->bridge_entities[1];

	if(bentity1->key.s == NULL) /* the first reply -> must send INVITE on the other side  */
	{
		LM_DBG("Send invite to %.*s\n", bentity1->to_uri.len, bentity1->to_uri.s);
		client_id = b2b_api.client_new(&method, &bentity1->to_uri,
				&bentity0->to_uri, extra_headers, body, b2b_client_notify, tuple->key);
		if(client_id == NULL)
		{
			LM_ERR("Failed to create new client entity\n");
			return -1;
		}
		/* save the client_id in the structure */
		entity = b2bl_create_new_entity(B2B_CLIENT, client_id, &bentity1->to_uri,
				&bentity0->to_uri, &bentity1->scenario_id);
		if(entity == NULL)
		{
			LM_ERR("failed to create new client entity\n");
			pkg_free(client_id);
			return -1;
		}
		entity->peer = bentity0;
		bentity0->peer = entity;

		pkg_free(client_id);

		shm_free(bentity1);
		tuple->bridge_entities[1] = entity;

		entity->next = tuple->clients;
		tuple->clients = entity;
	}
	else /* the second -> send ACK with body to the first entity
			and ACK without a body to the second entity*/
	{
		method.s = ACK;
		method.len = ACK_LEN;

		if(b2b_api.send_request(bentity0->type, &bentity0->key, &method,
					extra_headers, body) < 0)
		{
			LM_ERR("Failed to send first ACK in bridging scenario\n");
			return -1;
		}

		/* send ACK without a body to the second entity */
		if(b2b_api.send_request(B2B_CLIENT, &bentity1->key, &method, 0, 0)< 0)
		{
			LM_ERR("Failed to send second ACK in bridging scenario\n");
			return -1;
		}
	
		/* now I have finnished the BRIDGING scenario -> mark this in the record */
		if(tuple->next_scenario_state>= 0)
		{
			tuple->scenario_state = tuple->next_scenario_state;
			tuple->next_scenario_state = 0;
		}
		tuple->bridge_entities[0] = tuple->bridge_entities[1] = NULL;
	}
	return 0;
}

int b2b_logic_notify(int src, struct sip_msg* msg, str* key, int type, void* param)
{
	unsigned int hash_index, local_index;
	str* b2bl_key = (str*)param;
	b2bl_tuple_t* tuple;
	str method, body= {0, 0};
	str extra_headers = {0, 0};
	b2b_scenario_t* scenario;
	b2b_rule_t* rule;
	b2bl_entity_id_t* entity;
	xmlNodePtr bridge_node, node;
	int state = -1;
	str attr;

	if(b2bl_key == NULL)
	{
		LM_ERR("'param' argument NULL\n");
		return -1;
	}

	if(b2bl_parse_key(b2bl_key, &hash_index, &local_index)< 0)
	{
		LM_ERR("Failed to parse b2b logic key [%.*s]\n", b2bl_key->len, b2bl_key->s);
		return -1;
	}

	lock_get(&b2bl_htable[hash_index].lock);
	tuple = b2bl_search_tuple_safe(hash_index, local_index);
	if(tuple == NULL)
	{
		LM_DBG("B2B logic record not found\n");
		lock_release(&b2bl_htable[hash_index].lock);
		return -1;
	}
	scenario = tuple->scenario;

	if (parse_headers(msg, HDR_EOH_F, 0) < 0)
	{
		LM_ERR("failed to parse message\n");
		return -1;
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
				return 0;
			}
		}
	}
	
	/* build extra headers */
	if(b2b_extra_headers(msg, &extra_headers)< 0)
	{
		LM_ERR("Failed to construct extra headers\n");
		lock_release(&b2bl_htable[hash_index].lock);
		return -1;
	}

	/* search the entity */
	if(src == B2B_SERVER)
		entity = tuple->server;
	else
	{
		entity = tuple->clients;

		while(entity)
		{
			/* search id */
			if(entity->key.len == key->len &&
					strncmp(entity->key.s, key->s, key->len) == 0)
			{
				break;
			}
			entity = entity->next;
		}
	}
	if(entity == NULL)
	{
		LM_ERR("No b2b_key match found\n");
		goto error;
	}

	if(type == B2B_REPLY)
	{
		str method = get_cseq(msg)->method;
		/* if a reply from the client side was received, 
		* tell the server side to send a reply also */
		if(scenario && 
				(scenario->reply_rules || tuple->scenario_state == B2B_BRIDGING_STATE))
		{
			if(tuple->scenario_state == B2B_BRIDGING_STATE) /* if in a predefined state */
			{
				LM_DBG("Received a reply [%d] while in BRIDGING scenario\n",
						msg->first_line.u.reply.statuscode);
				/* if the scenario state is B2B_BRIDGING_STATE -> we should have a reply for INVITE */
				/* extract the method from Cseq header */

				if(method.len != INVITE_LEN || strncmp(method.s, INVITE, INVITE_LEN)!=0 )
				{
					LM_ERR("Wrong scenario state [B2B_BRIDGING_STATE] for this"
						" reply(for method %.*s).\n", method.len, method.s);
					goto error;
				}
				/* if a negative reply */
				if(msg->first_line.u.reply.statuscode >= 300)
				{
					str meth_bye = {BYE, BYE_LEN};
					if(tuple->bridge_entities[1] &&
							tuple->bridge_entities[1]->key.s != NULL) /* if a negative reply for the second leg send BYE to the first*/
						b2b_api.send_request(entity->peer->type,
								&entity->peer->key, &meth_bye, 0, 0);
					tuple->to_del = 1;
					goto done;
				}
				else
				if(msg->first_line.u.reply.statuscode < 200)
				{
					goto done;
				}

				/* if a reply with 200 OK -> we have two possibilities- either the first 200OK or the final */
				if(process_bridge_200OK(msg, (extra_headers.s?&extra_headers:0),
						(body.s?&body:0), tuple)< 0)
				{
					LM_ERR("Failed to process bridging 200OK for Invite\n");
					goto error;
				}
			}
			if(scenario->reply_rules)
			{
				/* TODO -> process and apply reply rules */
			}
			if(msg->first_line.u.reply.statuscode >= 300)
				tuple->to_del = 1;
		}
		else
		{
			b2b_api.send_reply(entity->peer->type, &entity->peer->key, 
				msg->first_line.u.reply.statuscode,&msg->first_line.u.reply.reason,
				body.s?&body:0, extra_headers.s?&extra_headers:0);

			/* if no other scenario rules defined and this is the reply for BYE */
			if(method.len == BYE_LEN && strncmp(method.s, BYE, BYE_LEN)==0)
			{
				b2bl_delete(tuple, hash_index);
			}
			if(msg->first_line.u.reply.statuscode >= 300)
				tuple->to_del = 1;
		}
	}
	else
	{
		int request_id;

		method = msg->first_line.u.request.method;
		/* extract body if it has a body */

		LM_DBG("I was notified that a request was received\n");
		request_id = b2b_get_request_id(&method);
		if(request_id < 0)
		{
			LM_ERR("Method not supported\n");
			lock_release(&b2bl_htable[hash_index].lock);
			return -1;
		}

		if(tuple->scenario_state == B2B_BRIDGING_STATE && request_id == B2B_BYE &&
				tuple->bridge_entities[0]->key.len == entity->key.len && 
				strncmp(tuple->bridge_entities[0]->key.s, entity->key.s, entity->key.len) == 0 &&
				tuple->bridge_entities[1]->key.s)
		{
		
			str meth_cancel = {CANCEL, CANCEL_LEN};
			str ok = {"OK", 2};

			b2b_api.send_request(entity->peer->type,
					&entity->peer->key, &meth_cancel, 0, 0);
			b2b_api.send_reply(entity->type, &entity->key, 200, &ok, 0, 0);
			tuple->bridge_entities[1] = NULL;
			goto done;
		}
		/* if the request is an ACK and the tuple is marked to_del -> then delete the record and return */
		if(request_id == B2B_ACK && tuple->to_del)
		{
			LM_DBG("ACK for a negative reply received\n");
			b2bl_delete(tuple, hash_index);
			goto done;
		}

		if(!scenario || !scenario->request_rules[request_id])
		{
			goto send_usual_request;
		}
		else
		{
			rule = scenario->request_rules[request_id];
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

			/* apply actions */
			/* handle bridge action */
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

				b2b_api.send_reply(src, &entity->key, code,&attr,0, 0);
				LM_DBG("Send reply with code [%d] and text [%s]\n", code, attr.s);

				xmlFree(attr.s);
			}
			
			node = xmlNodeGetChildByName(rule->action_node, "delete_entity");
			if(node)
			{
				b2bl_entity_id_t* prev;
				
				LM_DBG("Found a delete entity node\n");
				if(src == B2B_SERVER)
				{
					tuple->server = NULL;
				}
				else
				{
					/* search the entity to delete */
					if(tuple->clients == entity)
					{
						tuple->clients = tuple->clients->next;
					}
					else
					{
						prev = tuple->clients;
						while(prev->next != entity)
							prev = prev->next;
						
						prev->next = entity->next;
					}
				}
				b2b_api.entity_delete(src, &entity->key);
				shm_free(entity);
				entity = NULL;
				LM_DBG("Deleted current entity\n");
			}

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

			bridge_node = xmlNodeGetChildByName(rule->action_node, "bridge");

			if(bridge_node)
			{
				LM_DBG("Found a bridge node\n");

				if(process_bridge_action(tuple, bridge_node) < 0)
				{
					LM_ERR("Failed to process bridge action\n");
					goto error;
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
		}

		goto done;

send_usual_request:
		if(entity->peer && entity->peer->key.s)
			b2b_api.send_request(entity->peer->type, &entity->peer->key, &method,
				extra_headers.len?&extra_headers:0, body.len?&body:0);
	}
done:
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

int process_bridge_action(b2bl_tuple_t* tuple, xmlNodePtr bridge_node)
{
	xmlNodePtr node, dest_node;
	b2bl_entity_id_t* entity = NULL, *bridge_entities[2], *old_entity= NULL;
	int count = 0;
	str entity_dest;
	str method = {INVITE, INVITE_LEN};
	str attr;

	bridge_entities[0] = bridge_entities[1] = NULL;

	for(node= bridge_node->children; node; node=node->next)
	{
		if(xmlStrcasecmp(node->name, (unsigned char*)"client") !=0 )
			continue;

		if(count == 2)
		{
			LM_ERR("Bad scenario document. Too many entities defined for"
				" bridge node. Only two entities should be defined\n");
			break;
		}

		/* extract entity id */
		attr.s = (char*)xmlNodeGetNodeContentByName(node, "id", NULL);
		if(attr.s == NULL)
		{
			LM_ERR("No type defined for bridge entity\n");
			goto error;
		}
		attr.len = strlen(attr.s);

		/* search through the entities */
		if(tuple->server && tuple->server->scenario_id.len == attr.len &&
				strncmp(tuple->server->scenario_id.s, attr.s, attr.len)== 0)
		{
			entity = tuple->server;
			LM_DBG("Found entity %d for bridge - the server\n", count);
		}
		else
		{
			/* search through the client entities */
			entity = tuple->clients;
			while(entity)
			{
				if(entity->scenario_id.len == attr.len &&
						strncmp(entity->scenario_id.s, attr.s, attr.len) == 0)
				{
					LM_DBG("Found entity %d for bridge - a client\n", count);
					break;
				}
				entity = entity->next;
			}
		}

		if(entity == NULL)
		{
			xmlNodePtr value_node;
			char* value_content;

			/* must create a new client entity */
			/* get the destination */
			LM_DBG("Entity %d for bridge - new client entity\n", count);
			dest_node = xmlNodeGetChildByName(node, "destination");
			if(dest_node == NULL)
			{
				LM_ERR("Bad format for b2b scenario. New entity without a destination\n");
				xmlFree(attr.s);
				goto error;
			}
			value_node = xmlNodeGetChildByName(dest_node, "value");
			if(value_node == NULL)
			{
				LM_ERR("Bad format for b2b scenario. New entity without a destination\n");
				xmlFree(attr.s);
				goto error;
			}
			value_content = (char*)xmlNodeGetContent(value_node);
			if(value_content == NULL)
			{
				LM_ERR("Bad formated scenario document. URI value empty\n");
				xmlFree(attr.s);
				goto error;
			}

			if(b2b_scenario_parse_uri(value_node, value_content, tuple, &entity_dest)< 0)
			{
				LM_ERR("Failed to parse entity destination specification\n");
				xmlFree(attr.s);
				xmlFree(value_content);
				goto error;
			}
			LM_DBG("New entity, dest = [%.*s]\n", entity_dest.len, entity_dest.s);
			entity = b2bl_create_new_entity(B2B_CLIENT, 0, &entity_dest, 0, &attr);
			if(entity == NULL)
			{
				LM_ERR("Failed to create new b2b entity\n");
				xmlFree(value_content);
				xmlFree(attr.s);
				goto error;
			}

			xmlFree(value_content);
		}
		else
			old_entity = entity;

		xmlFree(attr.s);

		bridge_entities[count++] = entity;
	}

	/* I have the two entities ->  now do the first step of the bridging scenario 
	 * -> send reInvite or Invite to one of the parties */
	if(old_entity)
	{
		LM_DBG("Sent reInvite without a body to old entity\n");
		count = (old_entity== bridge_entities[0]?0:1);
		/* TODO -> Do I need some other info here? */
		b2b_api.send_request(old_entity->type, &old_entity->key, &method, 0, 0);
		
		tuple->bridge_entities[0]= bridge_entities[count];
		tuple->bridge_entities[1]= bridge_entities[(count+1)%2];
	}
	else
	{
		str* client_id;

		LM_DBG("Send Invite without a body to a new client entity\n");
		client_id = b2b_api.client_new(&method, &bridge_entities[0]->to_uri,
				&bridge_entities[1]->to_uri, 0, 0, b2b_client_notify, tuple->key);
		if(client_id == NULL)
		{
			LM_ERR("Failed to create new client entity\n");
			goto error1;
		}
		/* save the client_id in the structure */
		entity = b2bl_create_new_entity(B2B_CLIENT, client_id, &bridge_entities[0]->to_uri,
				&bridge_entities[1]->to_uri, &bridge_entities[0]->scenario_id);
		if(entity == NULL)
		{
			LM_ERR("failed to create new client entity\n");
			pkg_free(client_id);
			goto error1;
		}
		pkg_free(client_id);
		entity->type = B2B_CLIENT;
		entity->peer = bridge_entities[1];
		shm_free(bridge_entities[0]);

		tuple->bridge_entities[0] = entity;
		tuple->bridge_entities[1]= bridge_entities[1];

		entity->next = tuple->clients;
		tuple->clients = entity;

	}
	/* save the pointers to the bridged entities ;
	 * the first (index 0) is the one we sent the first message ( reInvite or Invite)*/
	tuple->scenario_state = B2B_BRIDGING_STATE;

	/* extract the lifetime if one is defined */
	node = xmlNodeGetChildByName(bridge_node, "lifetime");
	if(node)
	{
		attr.s = (char*)xmlNodeGetContent(node);
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

		LM_DBG("Lifetime defined = [%d]\n", tuple->lifetime);
		tuple->lifetime+= get_ticks();
	}
	else
		tuple->lifetime = -1;

	return 0;

error1:
	shm_free(bridge_entities[0]);
	shm_free(bridge_entities[1]);

error:
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

static inline int b2b_scenario_extract_count(xmlNodePtr entity_node, unsigned int* count)
{
	str attr;

	attr.s = xmlNodeGetNodeContentByName(entity_node, "count", NULL);
	if(attr.s == NULL)
	{
		LM_ERR("Count node content NULL\n");
		return -1;
	}
	attr.len = strlen(attr.s);

	if(str2int(&attr, count)< 0 || *count == 0)
	{
		LM_ERR("Wrong servers count\n");
		xmlFree(attr.s);
		return -1;
	}
	xmlFree(attr.s);

	return 0;

}


int create_top_hiding_entities(struct sip_msg* msg, str* to_uri, str* from_uri)
{
	str* server_id = NULL;
	str* client_id = NULL;
	str body = {0, 0};
	str extra_headers = {0, 0};
	str* b2bl_key;
	b2bl_tuple_t* tuple;
	unsigned int hash_index;

	hash_index = core_hash(to_uri, from_uri, b2bl_hsize);

	tuple = b2bl_insert_new(hash_index, 0, 0, &b2bl_key);
	if(tuple== NULL)
	{
		LM_ERR("Failed to insert new scenario instance record\n");
		return -1;
	}

	/* create new server */
	server_id = b2b_api.server_new(msg, b2b_server_notify, b2bl_key);
	if(server_id == NULL)
	{
		LM_ERR("failed to create new b2b server instance\n");
		goto error;
	}

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
	}

	LM_DBG("body = %.*s - len = %d\n", body.len, body.s, body.len);

	if(b2b_extra_headers(msg, &extra_headers)< 0)
	{
		LM_ERR("Failed to create extra headers\n");
		goto error;
	}
	/* create new client */

	client_id = b2b_api.client_new(&msg->first_line.u.request.method, to_uri, from_uri, &extra_headers,
			(body.s?&body:NULL), b2b_client_notify, b2bl_key);
	if(client_id == NULL)
	{
		LM_ERR("failed to create new b2b client instance\n");
		pkg_free(extra_headers.s);
		goto error;
	}
	pkg_free(extra_headers.s);

	/* TODO -> maybe secure access to tuple structure */
	tuple->server = b2bl_create_new_entity(B2B_SERVER, server_id, to_uri, from_uri, 0);
	if(tuple->server == NULL)
	{
		LM_ERR("Failed to create server entity\n");
		goto error;
	}
	tuple->server->type = B2B_SERVER;

	tuple->clients= (b2bl_entity_id_t*)shm_malloc(sizeof(b2bl_entity_id_t));
	if(tuple->clients == NULL)
	{
		LM_ERR("No more shared memory\n");
		goto error;
	}
	
	tuple->clients = b2bl_create_new_entity(B2B_CLIENT, client_id, to_uri, from_uri, 0);
	if(tuple->clients == NULL)
	{
		LM_ERR("Failed to create server entity\n");
		goto error;
	}
	tuple->clients->type = B2B_CLIENT;
	tuple->server->peer = tuple->clients;
	tuple->clients->peer = tuple->server;

	pkg_free(server_id);
	pkg_free(client_id);

	return 0;
error:
	if(server_id)
		pkg_free(server_id);
	if(client_id)
		pkg_free(client_id);
	return -1;
}

int b2b_scenario_parse_uri(xmlNodePtr value_node, char* value_content, b2bl_tuple_t* tuple,
		str* client_to)
{
	unsigned char* value_type= NULL;
	str value;
	unsigned int param_no;

	value.s = value_content;
	value.len = strlen(value_content);

	/* verify how is the destination defined - accepted types: initial, param, list, uri*/
	value_type = xmlNodeGetAttrContentByName(value_node, "type");
	if(value_type == NULL)
	{
		LM_ERR("Scenary document not well formed. To type param not defined\n");
		return -1;
	}

	if(xmlStrcasecmp(value_type, (unsigned char*)"uri") == 0)
	{
		LM_DBG("To of type uri\n");
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
	}
	else
	if(xmlStrcasecmp(value_type, (unsigned char*)"initial") == 0)
	{
		/* TODO -> take the to from the associated server entity */
		LM_DBG("URI of type initial\n");
		*client_to = tuple->server->to_uri;
	}
	else
	{
		LM_ERR("Scenary document not well formed. Client to type not valid\n");
		goto error;
	}

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

int b2b_init_request(struct sip_msg* msg, str* arg1, str* arg2, str* arg3,
		str* arg4, str* arg5, str* arg6)
{
	str to_uri={0, 0}, from_uri;
	struct to_body *pfrom;
	unsigned int hash_index;
	str* args[5];
	b2b_scenario_t* scenario_struct;
	int ret;

	/* find the b2b_logic key for the tuple */
	/* it will encode the position in the hash table */
	/* get the hash_index from to_uri and from_uri */

	/* parse message to extract needed info */
	if (parse_headers(msg, HDR_EOH_F, 0) < 0)
	{
		LM_ERR("failed to parse message\n");
		return -1;
	}

	if( parse_sip_msg_uri(msg)< 0)
	{
		LM_ERR("failed to parse R-URI\n");
		return -1;
	}

	if(udh_to_uri(msg->parsed_uri.user, msg->parsed_uri.host,
				msg->parsed_uri.port, &to_uri)< 0)
	{
		LM_ERR("failed to construct uri from user and domain\n");
		return -1;
	}

	/* examine the from header */
	if (!msg->from || !msg->from->body.s)
	{
		LM_ERR("cannot find 'from' header!\n");
		goto error;
	}
	if (msg->from->parsed == NULL)
	{
		if ( parse_from_header( msg )<0 ) 
		{
			LM_ERR("cannot parse From header\n");
			goto error;
		}
	}
	pfrom = (struct to_body*)msg->from->parsed;
	from_uri = pfrom->uri;

	if(arg1 == NULL)
	{
		if(create_top_hiding_entities(msg, &to_uri, &from_uri)< 0)
		{
			LM_ERR("failed to create top hinding specific entities");
			goto error;
		}
		pkg_free(to_uri.s);
		return 1;
	}

	/* find the scenario with the corresponding id */
	scenario_struct = (b2b_scenario_t*)arg1;

	/* call the scenario init processing function */
	args[0] = arg2;
	args[1] = arg3;
	args[2] = arg4;
	args[3] = arg5;
	args[4] = arg6;

	hash_index = core_hash(&to_uri, &from_uri, b2bl_hsize);

	ret= b2b_process_scenario_init(scenario_struct, msg, hash_index, 
			args, &to_uri, &from_uri);
	pkg_free(to_uri.s);

	return ret;
error:
	if(to_uri.s)
		pkg_free(to_uri.s);
	return -1;
}

int b2b_process_scenario_init(b2b_scenario_t* scenario_struct,struct sip_msg* msg,
		unsigned int hash_index, str* args[], str* to_uri, str* from_uri)
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
	str extra_headers = {0, 0};
	b2bl_entity_id_t* client_entity = NULL;
	unsigned int scenario_state = 0;
	
	
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
		}

		LM_DBG("body = %.*s - len = %d\n", body.len, body.s, body.len);

		if(b2b_extra_headers(msg, &extra_headers)< 0)
		{
			LM_ERR("Failed to create extra headers\n");
			goto error;
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
	}

	/* create new scenario instance record */
	tuple = b2bl_insert_new(hash_index, scenario_struct, args, &b2bl_key);
	if(tuple== NULL)
	{
		LM_ERR("Failed to insert new scenario instance record\n");
		return -1;
	}

	tuple->scenario_state = scenario_state;

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
		if(to_uri == NULL || from_uri == NULL)
		{
			LM_ERR("NULL URIs\n");
			goto error;
		}
		tuple->server = b2bl_create_new_entity(B2B_SERVER, server_id, to_uri,
				from_uri, &entity_sid);
		if(tuple->server == NULL)
		{
			LM_ERR("failed to create new server entity\n");
			xmlFree(entity_sid.s);
			pkg_free(server_id);
			goto error;
		}
		xmlFree(entity_sid.s);
		pkg_free(server_id);
		tuple->server->type = B2B_SERVER;
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

		if(b2b_scenario_parse_uri(node_aux, value_content, tuple, &client_to) < 0)
		{
			LM_ERR("Failed to get the value for the b2b client ruri\n");
			xmlFree(value_content);
			goto error2;
		}
		xmlFree(value_content);

		if(xmlStrcasecmp((unsigned char*)type, (unsigned char*)"message") == 0)
		{
			client_id = b2b_api.client_new(&method, &client_to, from_uri, &extra_headers,
				(body.s?&body:NULL), b2b_client_notify, b2bl_key);
			if(client_id == NULL)
			{
				LM_ERR("failed to create new b2b client instance\n");
				goto error2;
			}

			client_entity = b2bl_create_new_entity(B2B_CLIENT, client_id, &client_to,
					from_uri, &entity_sid);
			if(client_entity == NULL)
			{
				LM_ERR("failed to create new client entity\n");
				xmlFree(entity_sid.s);
				pkg_free(client_id);
				goto error2;
			}
			pkg_free(client_id);
			client_entity->type = B2B_CLIENT;

			client_entity->peer = tuple->server;
			tuple->server->peer = client_entity;

			client_entity->next = tuple->clients;
			tuple->clients = client_entity;
		}
		xmlFree(type);
		xmlFree(entity_sid.s);
	}

	if(extra_headers.s)
		pkg_free(extra_headers.s);
	return 1;

error2:
	xmlFree(type);
error1:
	xmlFree(entity_sid.s);
	
error:
	if(b2bl_key)
		shm_free(b2bl_key);
	if(extra_headers.s)
		pkg_free(extra_headers.s);

	return -1;
}
