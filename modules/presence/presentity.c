/*
 * presence module - presence server implementation
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
 *  2006-08-15  initial version (Anca Vamanu)
 *  2010-10-19  support for extra headers (osas)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../../db/db.h"
#include "../../dprint.h"
#include "../../mem/shm_mem.h"
#include "../../str.h"
#include "../../receive.h"
#include "../../usr_avp.h"
#include "../alias_db/alias_db.h"
#include "../../data_lump_rpl.h"
#include "presentity.h"
#include "presence.h"
#include "notify.h"
#include "publish.h"
#include "hash.h"
#include "utils_func.h"


#define DLG_STATES_NO  4
char* dialog_states[]= {  "trying",
                           "early",
                       "confirmed",
                     "terminated"};
char* presence_notes[]={ "Proceeding",
                         "Proceeding",
                    "On the phone",
                               ""};

unsigned char *xmlNodeGetAttrContentByName(xmlNodePtr node, const char *name);
xmlNodePtr xmlNodeGetNodeByName(xmlNodePtr node, const char *name,
													const char *ns);
static str pu_200_rpl  = str_init("OK");
static str pu_412_rpl  = str_init("Conditional request failed");

static char etag_buf[ETAG_LEN];

int generate_ETag(int publ_count, str* etag)
{
	etag->s = etag_buf;
	memset(etag_buf, 0, ETAG_LEN);

	etag->len = sprintf (etag_buf, "%c.%d.%d.%d.%d",
			prefix, (int)startup_time, pid, counter, publ_count);
	if( etag->len <0 )
	{
		LM_ERR("unsuccessful sprintf\n");
		return -1;
	}
	if(etag->len > ETAG_LEN)
	{
		LM_ERR("buffer size overflown\n");
		return -1;
	}
	LM_DBG("etag= %.*s\n",etag->len, etag->s);
	return 0;
}


int publ_send200ok(struct sip_msg *msg, int lexpire, str etag)
{
	char buf[128];
	int buf_len= 128, size;
	str hdr_append= {0, 0}, hdr_append2= {0, 0} ;

	LM_DBG("send 200OK reply, etag= %.*s\n", etag.len, etag.s);

	hdr_append.s = buf;
	hdr_append.s[0]='\0';

	hdr_append.len = sprintf(hdr_append.s, "Expires: %d\r\n",((lexpire< expires_offset)?0:
			(lexpire - expires_offset)));
	if(hdr_append.len < 0)
	{
		LM_ERR("unsuccessful sprintf\n");
		goto error;
	}
	if(hdr_append.len >= buf_len)
	{
		LM_ERR("buffer size overflown\n");
		goto error;
	}
	hdr_append.s[hdr_append.len]= '\0';

	if (add_lump_rpl( msg, hdr_append.s, hdr_append.len, LUMP_RPL_HDR)==0 )
	{
		LM_ERR("unable to add lump_rl\n");
		goto error;
	}

	size= 20 + etag.len;
	hdr_append2.s = (char *)pkg_malloc(size);
	if(hdr_append2.s == NULL)
	{
		ERR_MEM(PKG_MEM_STR);
	}
	hdr_append2.s[0]='\0';
	hdr_append2.len = sprintf(hdr_append2.s, "SIP-ETag: %.*s\r\n", etag.len, etag.s);
	if(hdr_append2.len < 0)
	{
		LM_ERR("unsuccessful sprintf\n");
		goto error;
	}
	if(hdr_append2.len+1 > size)
	{
		LM_ERR("buffer size overflown\n");
		goto error;
	}

	hdr_append2.s[hdr_append2.len]= '\0';
	if (add_lump_rpl(msg, hdr_append2.s, hdr_append2.len, LUMP_RPL_HDR)==0 )
	{
		LM_ERR("unable to add lump_rl\n");
		goto error;
	}

	if( sigb.reply( msg, 200, &pu_200_rpl, 0)== -1)
	{
		LM_ERR("sending reply\n");
		goto error;
	}

	pkg_free(hdr_append2.s);
	return 0;

error:

	if(hdr_append2.s)
		pkg_free(hdr_append2.s);

	return -1;
}

xmlAttrPtr xmlNodeGetAttrByName(xmlNodePtr node, const char *name)
{
	xmlAttrPtr attr = node->properties;
	while (attr) {
		if (xmlStrcasecmp(attr->name, (unsigned char*)name) == 0)
			return attr;
		attr = attr->next;
	}
	return NULL;
}


unsigned char *xmlNodeGetAttrContentByName(xmlNodePtr node, const char *name)
{
	xmlAttrPtr attr = xmlNodeGetAttrByName(node, name);
	if (attr)
		return xmlNodeGetContent(attr->children);
	else
		return NULL;
}


xmlNodePtr xmlNodeGetChildByName(xmlNodePtr node, const char *name)
{
	xmlNodePtr cur = node->children;
	while (cur) {
		if (xmlStrcasecmp(cur->name, (unsigned char*)name) == 0)
			return cur;
		cur = cur->next;
	}
	return NULL;
}

#define bla_extract_dlginfo(node, callid, fromtag, totag) \
	do {\
	callid  = xmlNodeGetAttrContentByName(node, "call-id");\
	dir     = xmlNodeGetAttrContentByName(node, "direction");\
	if(dir == NULL) {\
		LM_ERR("Dialog direction not specified\n");\
		goto error;\
	}\
	if(xmlStrcasecmp(dir, (unsigned char*)"initiator") == 0) {\
		fromtag = xmlNodeGetAttrContentByName(node, "local-tag");\
		totag   = xmlNodeGetAttrContentByName(node, "remote-tag");\
	} else {\
		totag   = xmlNodeGetAttrContentByName(node, "local-tag");\
		fromtag = xmlNodeGetAttrContentByName(node, "remote-tag");\
	}\
	xmlFree(dir);\
	dir = NULL;\
	}while(0)

int bla_same_dialog(unsigned char* n_callid, unsigned char* n_fromtag, unsigned char* n_totag,
		unsigned char* o_callid, unsigned char* o_fromtag, unsigned char* o_totag)
{
	if(n_callid && o_callid && xmlStrcasecmp(n_callid, o_callid))
		return 0;
	if(n_fromtag && o_fromtag && xmlStrcasecmp(n_fromtag, o_fromtag))
		return 0;
	if(n_totag && o_totag && xmlStrcasecmp(n_totag, o_totag))
		return 0;
	return 1;
}

int dialog_fix_remote_target(str *body, str *fixed_body)
{
	xmlDocPtr doc = NULL;
	xmlNodePtr n_dlg_node;
	xmlNodePtr remote_node;
	xmlNodePtr identity_node;
	xmlNodePtr node;
	xmlErrorPtr	xml_error;
	unsigned char* attr;

	if (!fixed_body)
	{
		LM_ERR("invalid NULL fixed_body pointer\n");
		goto error;
	}

	doc = xmlParseMemory(body->s, body->len);
	if (!doc)
	{
		xml_error = xmlGetLastError();
		LM_ERR("Failed to parse xml dialog body: %s\n",
			xml_error ? xml_error->message : "unknown error");
		goto error;
	}

	n_dlg_node  = xmlNodeGetChildByName(doc->children, "dialog");
	for(; n_dlg_node; n_dlg_node=n_dlg_node->next)
	{
		if(xmlStrcasecmp(n_dlg_node->name, (unsigned char*)"dialog")!= 0)
			continue;

		/* change the remote target - don't let it pass contact on the other side */
		remote_node = xmlNodeGetChildByName(n_dlg_node, "remote");
		if(remote_node)
		{
			node = xmlNodeGetChildByName(remote_node, "target");
			if(node)
			{
				xmlUnlinkNode(node);
				xmlFreeNode(node);
				/* add another target node */
				identity_node = xmlNodeGetChildByName(remote_node, "identity");
				if(identity_node == NULL)
				{
					LM_ERR("No remote identity node found\n");
					goto error;
				}
				attr = xmlNodeGetContent(identity_node);
				if(attr == NULL)
				{
					LM_ERR("No identity node content\n");
					goto error;
				}
				node = xmlNewChild(remote_node, 0, (unsigned char*)"target", 0);
				if(node == NULL)
				{
					LM_ERR("Failed to add new node target\n");
					xmlFree(attr);
					goto error;
				}
				xmlNewProp(node, BAD_CAST "uri", attr);
				xmlFree(attr);
			}
		}
	}

	xmlDocDumpMemory(doc, (xmlChar **)(void *)&fixed_body->s,
		&fixed_body->len);

	xmlFreeDoc(doc);

	return 0;

error:
	if (doc)
		xmlFreeDoc(doc);

	return -1;
}

int get_dialog_state(str body, int *dialog_state)
{
	xmlDocPtr doc;
	xmlNodePtr node;
	unsigned char* state = NULL;
	int i;

	doc = xmlParseMemory(body.s, body.len);
	if(doc== NULL)
	{
		LM_ERR("failed to parse xml document\n");
		return -1;
	}

	node = doc->children;
	node = xmlNodeGetChildByName(node, "dialog");

	if(node == NULL)
	{
		*dialog_state = DLG_DESTROYED;
		xmlFreeDoc(doc);
		return 0;
	}

	node = xmlNodeGetChildByName(node, "state");
	if(node == NULL)
	{
		LM_ERR("Malformed document - no state found\n");
		goto error;
	}
	state = xmlNodeGetContent(node);
	if(state == NULL)
	{
		LM_ERR("Malformed document - null state\n");
		goto error;
	}
	LM_DBG("state = %s\n", state);
	for(i = 0; i< DLG_STATES_NO; i++)
	{
		if(xmlStrcasecmp(state, BAD_CAST dialog_states[i])==0)
		{
			break;
		}
	}
	xmlFree(state);
	xmlFreeDoc(doc);
	xmlCleanupParser();
	xmlMemoryDump();

	if(i == DLG_STATES_NO)
	{
		LM_ERR("Wrong dialog state\n");
		return -1;
	}

	*dialog_state = i;

	return 0;
error:
	xmlFreeDoc(doc);
	return -1;
}

int check_if_dialog(str body, int *is_dialog)
{
	xmlDocPtr doc;
	xmlNodePtr node;

	doc = xmlParseMemory(body.s, body.len);
	if(doc== NULL)
	{
		LM_ERR("failed to parse xml document\n");
		return -1;
	}

	node = doc->children;
	node = xmlNodeGetChildByName(node, "dialog");

	if(node == NULL)
		*is_dialog = 0;
	else
		*is_dialog = 1;

	xmlFreeDoc(doc);
	return 0;
}


int update_presentity(struct sip_msg* msg, presentity_t* presentity,
															int* sent_reply)
{
//	static db_ps_t my_ps_insert = NULL, my_ps_update_no_body = NULL,
//		   my_ps_update_body = NULL;
//	static db_ps_t my_ps_delete = NULL, my_ps_query = NULL;
	db_key_t query_cols[13], update_keys[8], result_cols[1];
	db_op_t  query_ops[13];
	db_val_t query_vals[13], update_vals[8];
	int n_query_cols = 0;
	int n_update_cols = 0;
	str notify_body = {NULL, 0};
	str* rules_doc= NULL;
	str pres_uri= {NULL, 0};
	pres_entry_t* p= NULL;
	unsigned int hash_code;
	unsigned int turn;
	str body = presentity->body;
	str *extra_hdrs = presentity->extra_hdrs;
	db_res_t *result= NULL;

	*sent_reply= 0;
	if(presentity->event->req_auth)
	{
		/* get rules_document */
		if(presentity->event->get_rules_doc(&presentity->user,
					&presentity->domain, &rules_doc))
		{
			LM_ERR("getting rules doc\n");
			goto error;
		}
	}

	if(uandd_to_uri(presentity->user, presentity->domain, &pres_uri)< 0)
	{
		LM_ERR("constructing uri from user and domain\n");
		goto error;
	}

	query_cols[n_query_cols] = &str_domain_col;
	query_ops[n_query_cols] = OP_EQ;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = presentity->domain;
	n_query_cols++;

	query_cols[n_query_cols] = &str_username_col;
	query_ops[n_query_cols] = OP_EQ;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = presentity->user;
	n_query_cols++;

	query_cols[n_query_cols] = &str_event_col;
	query_ops[n_query_cols] = OP_EQ;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = presentity->event->name;
	n_query_cols++;

	result_cols[0] = &str_etag_col;
	hash_code= core_hash(&pres_uri, NULL, phtable_size);

	if(presentity->etag_new)
	{
		if (msg && publ_send200ok(msg, presentity->expires,
		presentity->new_etag)<0)
		{
			LM_ERR("sending 200OK\n");
			goto error;
		}
		*sent_reply= 1;

		/* insert new record in hash_table */
		p = insert_phtable(&pres_uri, presentity->event->evp->parsed,
				&presentity->new_etag, presentity->sphere,
				presentity->flags, 1);
		if (p==NULL)
		{
			LM_ERR("inserting record in hash table\n");
			goto error;
		}

		/* insert new record into database */
		query_cols[n_query_cols] = &str_etag_col;
		query_ops[n_query_cols] = OP_EQ;
		query_vals[n_query_cols].type = DB_STR;
		query_vals[n_query_cols].nul = 0;
		query_vals[n_query_cols].val.str_val = presentity->new_etag;
		n_query_cols++;

		query_cols[n_query_cols] = &str_expires_col;
		query_vals[n_query_cols].type = DB_INT;
		query_vals[n_query_cols].nul = 0;
		query_vals[n_query_cols].val.int_val = presentity->expires+
				(int)time(NULL);
		n_query_cols++;

		query_cols[n_query_cols] = &str_sender_col;
		query_vals[n_query_cols].type = DB_STR;
		query_vals[n_query_cols].nul = 0;

		if( presentity->sender)
		{
			query_vals[n_query_cols].val.str_val = *presentity->sender;
		}
		else
		{
			query_vals[n_query_cols].val.str_val.s = "";
			query_vals[n_query_cols].val.str_val.len = 0;
		}
		n_query_cols++;

		query_cols[n_query_cols] = &str_body_col;
		query_vals[n_query_cols].type = DB_BLOB;
		query_vals[n_query_cols].nul = 0;
		query_vals[n_query_cols].val.str_val = body;
		n_query_cols++;

		query_cols[n_query_cols] = &str_received_time_col;
		query_vals[n_query_cols].type = DB_INT;
		query_vals[n_query_cols].nul = 0;
		query_vals[n_query_cols].val.int_val = presentity->received_time;
		n_query_cols++;

		if(extra_hdrs)
		{
			query_cols[n_query_cols] = &str_extra_hdrs_col;
			query_vals[n_query_cols].type = DB_BLOB;
			query_vals[n_query_cols].nul = 0;
			query_vals[n_query_cols].val.str_val = *extra_hdrs;
			n_query_cols++;
		}

		if (pa_dbf.use_table(pa_db, &presentity_table) < 0)
		{
			LM_ERR("unsuccessful use_table\n");
			goto error;
		}

		LM_DBG("inserting %d cols into table\n",n_query_cols);

		//CON_PS_REFERENCE(pa_db) = &my_ps_insert;
		if (pa_dbf.insert(pa_db, query_cols, query_vals, n_query_cols) < 0)
		{
			LM_ERR("inserting new record in database\n");
			goto error;
		}
		goto send_notify;
	}
	else
	{
		query_cols[n_query_cols] = &str_etag_col;
		query_ops[n_query_cols] = OP_EQ;
		query_vals[n_query_cols].type = DB_STR;
		query_vals[n_query_cols].nul = 0;
		query_vals[n_query_cols].val.str_val = presentity->old_etag;
		n_query_cols++;

		lock_get(&pres_htable[hash_code].lock);
		p = search_phtable_etag(&pres_uri, presentity->event->evp->parsed,
				&presentity->old_etag, hash_code);
		if (p) {

			turn = p->last_turn++;
			LM_DBG("pres <%.*s> my turn is %d, current turn is %d\n",pres_uri.len,
				pres_uri.s, turn, p->current_turn);

			/* wait to get our turn as order of handling pubishs
			   (need to wait the ongoing published to terminate
			   before starting */
			while (p && turn!=p->current_turn) {
				lock_release(&pres_htable[hash_code].lock);
				sleep_us(100);
				lock_get(&pres_htable[hash_code].lock);
				p = search_phtable_etag(&pres_uri,
					presentity->event->evp->parsed, &presentity->old_etag,
					hash_code);
			}

		} else {

			lock_release(&pres_htable[hash_code].lock);
			/* search also in db */
			if (pa_dbf.use_table(pa_db, &presentity_table) < 0)
			{
					LM_ERR("unsuccessful sql use table\n");
					goto error;
			}

			if (pa_dbf.query (pa_db, query_cols, query_ops, query_vals,
					 result_cols, n_query_cols, 1, 0, &result) < 0)
			{
					LM_ERR("unsuccessful sql query\n");
					goto error;
			}
			if(result== NULL)
					goto error;

			if (result->n <= 0)
			{
					pa_dbf.free_result(pa_db, result);
					LM_ERR("No E_Tag match [%.*s]\n", presentity->old_etag.len,
							presentity->old_etag.s);
					if (msg && sigb.reply(msg, 412, &pu_412_rpl, 0)==-1 )
					{
						LM_ERR("sending '412 Conditional request failed' reply\n");
						goto error;
					}
					*sent_reply= 1;
					goto done;
			}

			pa_dbf.free_result(pa_db, result);
			LM_INFO("*** found in db but not in htable [%.*s]\n",
					presentity->old_etag.len, presentity->old_etag.s);
		}

		/* record found */
		if(presentity->expires == 0)
		{
			/* delete from hash table */
			if(p && delete_phtable(p, hash_code)< 0)
			{
					LM_ERR("deleting record from hash table failed\n");
			}
			/* presentity removed, pointer no longer valid */
			p = NULL;

			lock_release(&pres_htable[hash_code].lock);
			if(msg && publ_send200ok(msg, presentity->expires,
			presentity->old_etag)<0)
			{
				LM_ERR("sending 200OK reply\n");
				goto error;
			}
			*sent_reply= 1;

			if(publ_notify(presentity, pres_uri, body.s ? &body : 0,
			&presentity->old_etag, rules_doc, NULL, 1, NULL) < 0)
			{
				LM_ERR("while sending notify\n");
				goto error;
			}

			if (pa_dbf.use_table(pa_db, &presentity_table) < 0)
			{
				LM_ERR("unsuccessful sql use table\n");
				goto error;
			}
			//CON_PS_REFERENCE(pa_db) = &my_ps_delete;
			if(pa_dbf.delete(pa_db,query_cols,0,query_vals,n_query_cols)<0)
			{
				LM_ERR("unsuccessful sql delete operation");
				goto error;
			}
			LM_DBG("Expires=0, deleted from db %.*s\n",
				presentity->user.len,presentity->user.s);
			/* Send another NOTIFY, this time rely on whatever is on the DB,
			 *  so in case there are no documents an empty
			 * NOTIFY will be sent to the watchers */
			if (publ_notify(presentity, pres_uri, NULL, NULL, rules_doc, NULL,
			1, NULL) < 0)
			{
				LM_ERR("while sending notify\n");
				goto error;
			}

			goto send_mxd_notify;
		}

		if(presentity->event->etag_not_new== 0)
		{
			/* if we already have a new etag (probably received via cluster
			 * replication) do not generate a new local one */
			if (presentity->new_etag.s==NULL)
			{
				if(generate_ETag(p?p->etag_count:0, &presentity->new_etag) < 0)
				{
					LM_ERR("while generating etag\n");
					lock_release(&pres_htable[hash_code].lock);
					goto error;
				}
			}
			if(p)
			{
				update_pres_etag(p, &presentity->new_etag);
				p->flags = presentity->flags;
				lock_release(&pres_htable[hash_code].lock);
			}
			else
			{
				lock_release(&pres_htable[hash_code].lock);
				p = insert_phtable(&pres_uri, presentity->event->evp->parsed,
						&presentity->new_etag, presentity->sphere,
						presentity->flags, 1);
				if ( p==NULL )
				{
					LM_ERR("inserting record in hash table\n");
					goto error;
				}
			}
		}
		else
		{
			lock_release(&pres_htable[hash_code].lock);
			presentity->new_etag = presentity->old_etag;
		}

		n_update_cols= 0;
		update_keys[n_update_cols] = &str_etag_col;
		update_vals[n_update_cols].type = DB_STR;
		update_vals[n_update_cols].nul = 0;
		update_vals[n_update_cols].val.str_val = presentity->new_etag;
		n_update_cols++;

		update_keys[n_update_cols] = &str_expires_col;
		update_vals[n_update_cols].type = DB_INT;
		update_vals[n_update_cols].nul = 0;
		update_vals[n_update_cols].val.int_val= presentity->expires +
			(int)time(NULL);
		n_update_cols++;

		update_keys[n_update_cols] = &str_received_time_col;
		update_vals[n_update_cols].type = DB_INT;
		update_vals[n_update_cols].nul = 0;
		update_vals[n_update_cols].val.int_val= presentity->received_time;
		n_update_cols++;

		update_keys[n_update_cols] = &str_sender_col;
		update_vals[n_update_cols].type = DB_STR;
		update_vals[n_update_cols].nul = 0;

		if( presentity->sender)
		{
			update_vals[n_update_cols].val.str_val = *presentity->sender;
		}
		else
		{
			update_vals[n_update_cols].val.str_val.s = "";
			update_vals[n_update_cols].val.str_val.len = 0;
		}
		n_update_cols++;

		if(extra_hdrs)
		{
			update_keys[n_update_cols] = &str_extra_hdrs_col;
			update_vals[n_update_cols].type = DB_BLOB;
			update_vals[n_update_cols].nul = 0;
			update_vals[n_update_cols].val.str_val = *extra_hdrs;
			n_update_cols++;
		}

		if(body.s)
		{
			if (fix_remote_target)
			    {
				if (dialog_fix_remote_target(&body, &notify_body)== 0)
				{
					body.s = notify_body.s;
					body.len = notify_body.len;
				}
				else
				{
					LM_ERR("Failed to fix remote target\n");
				}
			}
			update_keys[n_update_cols] = &str_body_col;
			update_vals[n_update_cols].type = DB_BLOB;
			update_vals[n_update_cols].nul = 0;
			update_vals[n_update_cols].val.str_val = body;
			n_update_cols++;

			/* updated stored sphere */
			if(sphere_enable &&
					presentity->event->evp->parsed== EVENT_PRESENCE)
			{
				if(update_phtable(presentity, pres_uri, body)< 0)
				{
					LM_ERR("failed to update sphere for presentity\n");
					goto error;
				}
			}
			//CON_PS_REFERENCE(pa_db) = &my_ps_update_body;
		}
		else
		{
			//CON_PS_REFERENCE(pa_db) = &my_ps_update_no_body;
		}

		if (pa_dbf.use_table(pa_db, &presentity_table) < 0)
		{
			LM_ERR("unsuccessful sql use table\n");
			goto error;
		}

		if( pa_dbf.update( pa_db,query_cols, query_ops, query_vals,
				update_keys, update_vals, n_query_cols, n_update_cols )<0)
		{
			LM_ERR("updating published info in database\n");
			goto error;
		}

		/* send 200OK */
		if (msg && publ_send200ok(msg, presentity->expires,
		presentity->new_etag)<0 )
		{
			LM_ERR("sending 200OK reply\n");
			goto error;
		}
		*sent_reply= 1;

		if(!body.s && !extra_hdrs)
			goto done;
	}

send_notify:

	if (publ_notify(presentity, pres_uri, body.s?&body:0,
				NULL, rules_doc, NULL, 1, NULL)<0)
	{
		LM_ERR("while sending Notify requests to watchers\n");
		goto error;
	}

send_mxd_notify:
	/* if event dialog -> send Notify for presence also */
	if(mix_dialog_presence && *pres_event_p &&
	presentity->event->evp->parsed == EVENT_DIALOG)
	{
		str* dialog_body = NULL;
		pres_ev_t *ev_bk;

		LM_DBG("Publish for event dialog - try to send Notify for presence\n");

		dialog_body = xml_dialog2presence(&pres_uri, &body);
		if(dialog_body)
		{
			/* send Notify for presence */
			ev_bk = presentity->event;
			presentity->event = *pres_event_p;
			if (publ_notify(presentity, pres_uri, 0, NULL, 0, dialog_body,
			1, NULL)<0)
			{
				LM_ERR("while sending Notify requests to watchers\n");
				presentity->event = ev_bk;
				if(dialog_body && dialog_body!=FAKED_BODY)
				{
					xmlFree(dialog_body->s);
					pkg_free(dialog_body);
				}
				goto error;
			}
			presentity->event = ev_bk;
			if(dialog_body && dialog_body!=FAKED_BODY)
			{
				xmlFree(dialog_body->s);
				pkg_free(dialog_body);
			}
		}
	}

done:
	/* allow next publish to be handled */
	if (p)
		next_turn_phtable( p, hash_code);

	if (notify_body.s)
		xmlFree(notify_body.s);

	if(rules_doc)
	{
		if(rules_doc->s)
			pkg_free(rules_doc->s);
		pkg_free(rules_doc);
	}
	if(pres_uri.s)
		pkg_free(pres_uri.s);
	return 0;

error:
	/* allow next publish to be handled */
	if (p)
		next_turn_phtable( p, hash_code);

	if (notify_body.s)
		xmlFree(notify_body.s);

	if(rules_doc)
	{
		if(rules_doc->s)
			pkg_free(rules_doc->s);
		pkg_free(rules_doc);
	}
	if(pres_uri.s)
		pkg_free(pres_uri.s);
	return -1;
}


/*  This is just a wrappter over "update_presentity" to be able to export the
 *  function via the internal API - basically provides the "publishing" support
 *  without actually having the PUBLISH SIP request, but directly a presentity
 */
int internal_update_presentity(presentity_t* presentity)
{
	int dummy;
	return update_presentity( NULL, presentity, &dummy);
}


int pres_htable_restore(void)
{
	/* query all records from presentity table and insert records
	 * in presentity table */
	db_key_t result_cols[6];
	db_res_t *result= NULL;
	db_row_t *rows= NULL ;
	db_val_t *row_vals;
	int  i;
	str user, domain, ev_str, uri, body;
	int n_result_cols= 0;
	int user_col, domain_col, event_col, expires_col, body_col = 0, etag_col;
	int event;
	event_t ev;
	char* sphere= NULL;
	int nr_rows;
	str etag;
	int no_rows = 10;

	result_cols[user_col= n_result_cols++]= &str_username_col;
	result_cols[domain_col= n_result_cols++]= &str_domain_col;
	result_cols[event_col= n_result_cols++]= &str_event_col;
	result_cols[expires_col= n_result_cols++]= &str_expires_col;
	result_cols[etag_col= n_result_cols++]= &str_etag_col;
	if(sphere_enable)
		result_cols[body_col= n_result_cols++]= &str_body_col;

	if (pa_dbf.use_table(pa_db, &presentity_table) < 0)
	{
		LM_ERR("unsuccessful use table sql operation\n");
		goto error;
	}

	/* select the whole tabel and all the columns */
	if (DB_CAPABILITY(pa_dbf, DB_CAP_FETCH))
	{
		if(pa_dbf.query(pa_db,0,0,0,result_cols, 0,
		n_result_cols, result_cols[user_col], 0) < 0)
		{
			LM_ERR("Error while querying (fetch) database\n");
			return -1;
		}
		no_rows = estimate_available_rows( 32+32+32+4+64, n_result_cols);
		if (no_rows==0) no_rows = 10;
		if(pa_dbf.fetch_result(pa_db,&result, no_rows)<0)
		{
			LM_ERR("fetching rows failed\n");
			return -1;
		}
	} else
	{
		if (pa_dbf.query (pa_db, 0, 0, 0,result_cols,0, n_result_cols,
					result_cols[user_col], &result) < 0)
		{
			LM_ERR("querying presentity\n");
			goto error;
		}
	}

	nr_rows = RES_ROW_N(result);

	do {
		LM_DBG("loading information from database for %i records\n", nr_rows);

		rows = RES_ROWS(result);

		/* for every row */
		for(i=0; i<nr_rows; i++)
		{
			row_vals = ROW_VALUES(rows + i);

			if (VAL_NULL(row_vals) || VAL_NULL(row_vals+1))
			{
				LM_ERR("columns %.*s or/and %.*s cannot be null -> skipping\n",
					str_username_col.len, str_username_col.s,
					str_domain_col.len, str_domain_col.s);
				continue;
			}

			if (VAL_NULL(row_vals+2) || VAL_NULL(row_vals+3))
			{
				LM_ERR("columns %.*s or/and %.*s cannot be null -> skipping\n",
					str_event_col.len, str_event_col.s,
					str_domain_col.len, str_domain_col.s);
				continue;
			}

			if(row_vals[expires_col].val.int_val< (int)time(NULL))
				continue;

			sphere= NULL;
			user.s= (char*)row_vals[user_col].val.string_val;
			user.len= strlen(user.s);
			domain.s= (char*)row_vals[domain_col].val.string_val;
			domain.len= strlen(domain.s);
			ev_str.s= (char*)row_vals[event_col].val.string_val;
			ev_str.len= strlen(ev_str.s);
			etag.s= (char*)row_vals[etag_col].val.string_val;
			etag.len= strlen(etag.s);

			if(event_parser(ev_str.s, ev_str.len, &ev)< 0)
			{
				LM_ERR("parsing event\n");
				free_event_params(ev.params, PKG_MEM_TYPE);
				goto error;
			}
			event= ev.parsed;
			free_event_params(ev.params, PKG_MEM_TYPE);

			if(uandd_to_uri(user, domain, &uri)< 0)
			{
				LM_ERR("constructing uri\n");
				goto error;
			}
			/* insert in hash_table*/

			if(sphere_enable && event== EVENT_PRESENCE )
			{
				body.s= (char*)row_vals[body_col].val.string_val;
				body.len= strlen(body.s);
				sphere= extract_sphere(body);
			}

			if(insert_phtable(&uri, event, &etag, sphere, 0, 0)== NULL)
			{
				LM_ERR("inserting record in presentity hash table\n");
				pkg_free(uri.s);
				if(sphere)
					pkg_free(sphere);
				goto error;
			}
			if(sphere)
				pkg_free(sphere);
			pkg_free(uri.s);
		}

		/* any more data to be fetched ?*/
		if (DB_CAPABILITY(pa_dbf, DB_CAP_FETCH))
		{
			if (pa_dbf.fetch_result( pa_db, &result, no_rows) < 0)
			{
				LM_ERR("fetching more rows failed\n");
				goto error;
			}
			nr_rows = RES_ROW_N(result);
		} else
			nr_rows = 0;

	}while (nr_rows>0);

	pa_dbf.free_result(pa_db, result);

	return 0;

error:
	if(result)
		pa_dbf.free_result(pa_db, result);
	return -1;
}

int pres_expose_evi(pres_ev_t *ev, str *filter)
{
	int user_col, domain_col, expires_col, body_col, etag_col;
	int no_rows = 0, nr_rows, i;
	int n_result_cols= 0;
	presentity_t presentity;
	db_key_t result_cols[5];
	db_key_t query_cols[3];
	db_val_t query_vals[3];
	db_op_t query_ops[3];
	db_res_t* result = NULL;
	db_row_t *rows = NULL;
	db_val_t *row_vals;
	int nr_vals = 0;

	if (pa_dbf.use_table(pa_db, &presentity_table) < 0) {
		LM_ERR("cannot select table \"%.*s\"\n",
				presentity_table.len, presentity_table.s);
		goto error;
	}

	query_cols[nr_vals] = &str_expires_col;
	query_ops[nr_vals] = OP_GT;
	query_vals[nr_vals].nul = 0;
	query_vals[nr_vals].type = DB_INT;
	query_vals[nr_vals].val.int_val = (int)time(NULL);
	nr_vals++;
	query_cols[nr_vals] = &str_event_col;
	query_ops[nr_vals] = OP_EQ;
	query_vals[nr_vals].nul = 0;
	query_vals[nr_vals].type = DB_STR;
	query_vals[nr_vals].val.str_val = ev->name;
	nr_vals++;

	if (filter) {
		query_cols[nr_vals] = &str_username_col;
		query_ops[nr_vals] = " REGEXP ";
		query_vals[nr_vals].nul = 0;
		query_vals[nr_vals].type = DB_STR;
		query_vals[nr_vals].val.str_val = *filter;
		nr_vals++;
	}

	result_cols[user_col = n_result_cols++]= &str_username_col;
	result_cols[domain_col = n_result_cols++]= &str_domain_col;
	result_cols[expires_col = n_result_cols++]= &str_expires_col;
	result_cols[etag_col = n_result_cols++]= &str_etag_col;
	result_cols[body_col = n_result_cols++]= &str_body_col;

	if (DB_CAPABILITY(pa_dbf, DB_CAP_FETCH)) {
		if (pa_dbf.query(pa_db, query_cols, query_ops, query_vals, result_cols,
				nr_vals, n_result_cols, 0, 0) < 0) {
			LM_ERR("cannot query table!\n");
			goto error;
		}
		no_rows = estimate_available_rows(64+64+4+64+512 /* body estimation */,
				n_result_cols);
		if (no_rows==0) no_rows = 10;
		if(pa_dbf.fetch_result(pa_db, &result, no_rows)<0) {
			LM_ERR("Error fetching rows\n");
			goto error;
		}
	} else {
		if (pa_dbf.query(pa_db, query_cols, query_ops, query_vals, result_cols,
				nr_vals, n_result_cols, 0, &result) < 0) {
			LM_ERR("cannot query table!\n");
			goto error;
		}
	}

	LM_DBG("%d records found in %.*s%s%.*s\n",
			RES_ROW_N(result), presentity_table.len, presentity_table.s,
			(filter ? " with filter ": ""), (filter ? filter->len: 0),
			(filter ? filter->s : ""));

	nr_rows = RES_ROW_N(result);

	do {
		LM_DBG("loading information from database for %i records\n", nr_rows);

		rows = RES_ROWS(result);

		/* for every row */
		for(i = 0; i < nr_rows; i++)
		{
			row_vals = ROW_VALUES(rows + i);

			if (VAL_NULL(row_vals + user_col) || VAL_NULL(row_vals + domain_col))
			{
				LM_ERR("columns %.*s or/and %.*s cannot be null -> skipping\n",
					str_username_col.len, str_username_col.s,
					str_domain_col.len, str_domain_col.s);
				continue;
			}

			/* not sure if this is needed */
			if(row_vals[expires_col].val.int_val< (int)time(NULL))
				continue;

			memset(&presentity, 0, sizeof(presentity_t));
			presentity.domain.s = (char*)row_vals[domain_col].val.string_val;
			presentity.domain.len = strlen(presentity.domain.s);
			presentity.user.s = (char*)row_vals[user_col].val.string_val;
			presentity.user.len = strlen(presentity.user.s);
			presentity.new_etag.s = (char*)row_vals[etag_col].val.string_val;
			presentity.new_etag.len = strlen(presentity.new_etag.s);
			presentity.event = ev;
			presentity.expires = row_vals[expires_col].val.int_val;
			presentity.body.s = (char*)row_vals[body_col].val.string_val;
			presentity.body.len = strlen(presentity.body.s);

			/* send event E_PRESENCE_EXPOSED */
			presence_raise_event(exposed_event_id, &presentity);
		}

		/* any more data to be fetched ?*/
		if (DB_CAPABILITY(pa_dbf, DB_CAP_FETCH))
		{
			if (pa_dbf.fetch_result(pa_db, &result, no_rows) < 0)
			{
				LM_ERR("fetching more rows failed\n");
				goto error;
			}
			nr_rows = RES_ROW_N(result);
		} else
			nr_rows = 0;

	} while(nr_rows > 0);

	pa_dbf.free_result(pa_db, result);

	return 0;

error:
	if (result)
		pa_dbf.free_result(pa_db, result);
	return -1;
}

char* extract_sphere(str body)
{

	/* check for a rpid sphere element */
	xmlDocPtr doc= NULL;
	xmlNodePtr node;
	char* cont, *sphere= NULL;


	doc= xmlParseMemory(body.s, body.len);
	if(doc== NULL)
	{
		LM_ERR("failed to parse xml body\n");
		return NULL;
	}

	node= xmlNodeGetNodeByName(doc->children, "sphere", "rpid");

	if(node== NULL)
		node= xmlNodeGetNodeByName(doc->children, "sphere", "r");

	if(node)
	{
		LM_DBG("found sphere definition\n");
		cont= (char*)xmlNodeGetContent(node);
		if(cont== NULL)
		{
			LM_ERR("failed to extract sphere node content\n");
			goto error;
		}
		sphere= (char*)pkg_malloc(strlen(cont)+ 1);
		if(sphere== NULL)
		{
			xmlFree(cont);
			ERR_MEM(PKG_MEM_STR);
		}
		strcpy(sphere, cont);
		xmlFree(cont);
	}
	else
		LM_DBG("didn't find sphere definition\n");

error:
	xmlFreeDoc(doc);
	return sphere;
}

xmlNodePtr xmlNodeGetNodeByName(xmlNodePtr node, const char *name,
													const char *ns)
{
	xmlNodePtr cur = node;
	while (cur) {
		xmlNodePtr match = NULL;
		if (xmlStrcasecmp(cur->name, (unsigned char*)name) == 0) {
			if (!ns || (cur->ns && xmlStrcasecmp(cur->ns->prefix,
							(unsigned char*)ns) == 0))
				return cur;
		}
		match = xmlNodeGetNodeByName(cur->children, name, ns);
		if (match)
			return match;
		cur = cur->next;
	}
	return NULL;
}

char* get_sphere(str* pres_uri)
{
//	static db_ps_t my_ps = NULL;
	unsigned int hash_code;
	char* sphere= NULL;
	pres_entry_t* p;
	db_key_t query_cols[6];
	db_val_t query_vals[6];
	db_key_t result_cols[6];
	db_res_t *result = NULL;
	db_row_t *row= NULL ;
	db_val_t *row_vals;
	int n_result_cols = 0;
	int n_query_cols = 0;
	struct sip_uri uri;
	str body;
	static str query_str = str_init("received_time");

	if(!sphere_enable)
		return NULL;

	/* search in hash table*/
	hash_code= core_hash(pres_uri, NULL, phtable_size);

	lock_get(&pres_htable[hash_code].lock);

	p= search_phtable(pres_uri, EVENT_PRESENCE, hash_code);

	if(p)
	{
		if(p->sphere)
		{
			sphere= (char*)pkg_malloc(strlen(p->sphere));
			if(sphere== NULL)
			{
				lock_release(&pres_htable[hash_code].lock);
				ERR_MEM(PKG_MEM_STR);
			}
			strcpy(sphere, p->sphere);
		}
		lock_release(&pres_htable[hash_code].lock);
		return sphere;
	}
	lock_release(&pres_htable[hash_code].lock);


	/* if record not found and fallback2db query database*/
	if(!fallback2db)
	{
		return NULL;
	}

	if(parse_uri(pres_uri->s, pres_uri->len, &uri)< 0)
	{
		LM_ERR("failed to parse presentity uri\n");
		goto error;
	}

	query_cols[n_query_cols] = &str_domain_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = uri.host;
	n_query_cols++;

	query_cols[n_query_cols] = &str_username_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = uri.user;
	n_query_cols++;

	query_cols[n_query_cols] = &str_event_col;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val.s= "presence";
	query_vals[n_query_cols].val.str_val.len= 8;
	n_query_cols++;

	result_cols[n_result_cols++] = &str_body_col;
	result_cols[n_result_cols++] = &str_extra_hdrs_col;

	if (pa_dbf.use_table(pa_db, &presentity_table) < 0)
	{
		LM_ERR("in use_table\n");
		return NULL;
	}

	// CON_PS_REFERENCE(pa_db) = &my_ps;
	if (pa_dbf.query (pa_db, query_cols, 0, query_vals,
		 result_cols, n_query_cols, n_result_cols, &query_str ,  &result) < 0)
	{
		LM_ERR("failed to query %.*s table\n", presentity_table.len, presentity_table.s);
		if(result)
			pa_dbf.free_result(pa_db, result);
		return NULL;
	}

	if(result== NULL)
		return NULL;

	if (result->n<=0 )
	{
		LM_DBG("no published record found in database\n");
		pa_dbf.free_result(pa_db, result);
		return NULL;
	}

	row = &result->rows[result->n-1];
	row_vals = ROW_VALUES(row);
	if(row_vals[0].val.string_val== NULL)
	{
		LM_ERR("NULL notify body record\n");
		goto error;
	}

	body.s= (char*)row_vals[0].val.string_val;
	body.len= strlen(body.s);
	if(body.len== 0)
	{
		LM_ERR("Empty notify body record\n");
		goto error;
	}

	sphere= extract_sphere(body);

	pa_dbf.free_result(pa_db, result);

	return sphere;

error:
	if(result)
		pa_dbf.free_result(pa_db, result);
	return NULL;

}

int contains_presence(str* pres_uri) {
	unsigned int hash_code;
	db_key_t query_cols[6];
	db_val_t query_vals[6];
	db_key_t result_cols[6];
	db_res_t *result = NULL;
	int n_result_cols = 0;
	int n_query_cols = 0;
	struct sip_uri uri;
	static str query_str = str_init("received_time");
	int ret = -1;

	hash_code= core_hash(pres_uri, NULL, phtable_size);

	lock_get(&pres_htable[hash_code].lock);

	if ( search_phtable(pres_uri, EVENT_PRESENCE, hash_code)!=NULL )
	{
		ret = 1;
	}
	lock_release(&pres_htable[hash_code].lock);
	if ( ret== -1 && fallback2db )
	{
		if(parse_uri(pres_uri->s, pres_uri->len, &uri)< 0)
		{
			LM_ERR("failed to parse presentity uri\n");
			goto done;
		}
		query_cols[n_query_cols] = &str_domain_col;
		query_vals[n_query_cols].type = DB_STR;
		query_vals[n_query_cols].nul = 0;
		query_vals[n_query_cols].val.str_val = uri.host;
		n_query_cols++;

		query_cols[n_query_cols] = &str_username_col;
		query_vals[n_query_cols].type = DB_STR;
		query_vals[n_query_cols].nul = 0;
		query_vals[n_query_cols].val.str_val = uri.user;
		n_query_cols++;

		query_cols[n_query_cols] = &str_event_col;
		query_vals[n_query_cols].type = DB_STR;
		query_vals[n_query_cols].nul = 0;
		query_vals[n_query_cols].val.str_val.s= "presence";
		query_vals[n_query_cols].val.str_val.len= 8;
		n_query_cols++;

		result_cols[n_result_cols++] = &str_body_col;
		result_cols[n_result_cols++] = &str_extra_hdrs_col;

		pa_dbf.use_table(pa_db, &presentity_table);

		if (pa_dbf.query (pa_db, query_cols, 0, query_vals,
			 result_cols, n_query_cols, n_result_cols, &query_str, &result)<0)
		{
			LM_ERR("failed to query %.*s table\n",
				presentity_table.len, presentity_table.s);
			goto done;
		}
		if(result== NULL)
			goto done;
		if (result->n<=0 )
		{
			LM_DBG("no published record found in database\n");
			goto done;
		}
		ret = 1;
	}
done:
	if(result)
		pa_dbf.free_result(pa_db, result);
	return ret;
}

str* xml_dialog_gen_presence(str* pres_uri, int dlg_state)
{
	char* pres_note;
	xmlDocPtr pres_doc;
	xmlNodePtr node, root_node;
	xmlNodePtr tuple_node, person_node;
	str* dialog_body = NULL;
	char* entity;

	LM_DBG("dlg_state = %d\n", dlg_state);

	pres_note = presence_notes[dlg_state];

	/* if state is terminated, do not add anything */
	if(pres_note && strlen(pres_note) == 0)
	{
		LM_DBG("NULL pres note\n");
		return FAKED_BODY;
	}

	pres_doc= xmlNewDoc(BAD_CAST "1.0");
	if(pres_doc== NULL)
	{
		LM_ERR("allocating new xml doc\n");
		goto error;
	}

	root_node = xmlNewNode(NULL, BAD_CAST "presence");
	if(root_node== NULL)
	{
		LM_ERR("Failed to create xml node\n");
		goto error;
	}
	xmlDocSetRootElement(pres_doc, root_node);

	xmlNewProp(root_node, BAD_CAST "xmlns",
			BAD_CAST "urn:ietf:params:xml:ns:pidf");
	xmlNewProp(root_node, BAD_CAST "xmlns:dm",
			BAD_CAST "urn:ietf:params:xml:ns:pidf:data-model");
	xmlNewProp(root_node, BAD_CAST  "xmlns:rpid",
			BAD_CAST "urn:ietf:params:xml:ns:pidf:rpid" );
	xmlNewProp(root_node, BAD_CAST "xmlns:c",
			BAD_CAST "urn:ietf:params:xml:ns:pidf:cipid");

	entity= (char*)pkg_malloc(pres_uri->len + 1);
	if(entity == NULL)
	{
		LM_ERR("No more memory\n");
		goto error;
	}
	memcpy(entity, pres_uri->s, pres_uri->len);
	entity[pres_uri->len] = '\0';
	xmlNewProp(root_node, BAD_CAST "entity", BAD_CAST entity);
	pkg_free(entity);

	tuple_node =xmlNewChild(root_node, NULL, BAD_CAST "tuple", NULL) ;
	if(tuple_node == NULL)
	{
		LM_ERR("while adding child\n");
		goto error;
	}

	xmlNewProp(tuple_node, BAD_CAST "id", BAD_CAST "tuple_mixingid");

	node = xmlNewChild(tuple_node, NULL, BAD_CAST "status", NULL) ;
	if(node == NULL)
	{
		LM_ERR("while adding child\n");
		goto error;
	}
	node = xmlNewChild(node, NULL, BAD_CAST "basic",
			BAD_CAST "open") ;
	if(node ==NULL)
	{
		LM_ERR("while adding child\n");
		goto error;
	}

	if(pres_note && strlen(pres_note))
	{
		node = xmlNewChild(root_node, NULL, BAD_CAST "note",
			BAD_CAST pres_note) ;
		if(node ==NULL)
		{
			LM_ERR("while adding child\n");
			goto error;
		}
		/* put also the person node - to get status indication */
		person_node = xmlNewChild(root_node, 0, BAD_CAST "dm:person", NULL) ;
		if(person_node == NULL)
		{
			LM_ERR("while adding child\n");
			goto error;
		}
		/* now put the id for tuple and person */
		xmlNewProp(person_node, BAD_CAST "id", BAD_CAST "pers_mixingid");

		node = xmlNewChild(person_node, 0, BAD_CAST "rpid:activities", NULL) ;
		if(node == NULL)
		{
			LM_ERR("Failed to add person activities node\n");
			goto error;
		}

		if(xmlNewChild(node, 0, BAD_CAST "rpid:on-the-phone", NULL) == NULL)
		{
			LM_ERR("Failed to add activities child\n");
			goto error;
		}

		if(xmlNewChild(person_node, 0, BAD_CAST "dm:note",
					BAD_CAST pres_note) == NULL)
		{
			LM_ERR("Failed to add activities child\n");
			goto error;
		}
	}

	dialog_body = (str*)pkg_malloc(sizeof(str));
	if(dialog_body == NULL)
	{
		LM_ERR("No more memory\n");
		goto error;
	}
	xmlDocDumpMemory(pres_doc,(xmlChar**)(void*)&dialog_body->s,
			&dialog_body->len);

	LM_DBG("Generated dialog body: %.*s\n", dialog_body->len, dialog_body->s);

error:
	if(pres_doc)
		xmlFreeDoc(pres_doc);
	xmlCleanupParser();
	xmlMemoryDump();

	return dialog_body;
}

str* xml_dialog2presence(str* pres_uri, str* body)
{
	xmlDocPtr dlg_doc = NULL;
	xmlNodePtr node, dialog_node;
	unsigned char* state;
	int i;

	if(body->len == 0)
		return NULL;

	dlg_doc = xmlParseMemory(body->s, body->len);
	if(dlg_doc == NULL)
	{
		LM_ERR("Wrong formatted xml document\n");
		return NULL;
	}
	dialog_node = xmlNodeGetNodeByName(dlg_doc->children, "dialog", 0);
	if(!dialog_node)
	{
		goto done;
	}

	node = xmlNodeGetNodeByName(dialog_node, "state", 0);
	if(!node)
		goto done;

	state = xmlNodeGetContent(node);
	if(!state)
		goto done;

	for(i = 0; i< DLG_STATES_NO; i++)
	{
		if(xmlStrcasecmp(state, BAD_CAST dialog_states[i])==0)
		{
			break;
		}
	}
	xmlFree(state);
	xmlFreeDoc(dlg_doc);
	xmlCleanupParser();
	xmlMemoryDump();

	if(i == DLG_STATES_NO)
	{
		LM_ERR("Unknown dialog state\n");
		return 0;
	}

	return xml_dialog_gen_presence(pres_uri, i);

done:
	xmlFreeDoc(dlg_doc);
	return 0;
}



str* build_offline_presence(str* pres_uri)
{
	xmlDocPtr pres_doc = NULL;
	xmlNodePtr root_node, tuple_node, node;
	char* entity;
	str* body = NULL;

	pres_doc= xmlNewDoc(BAD_CAST "1.0");
	if(pres_doc== NULL)
	{
		LM_ERR("allocating new xml doc\n");
		goto error;
	}

	root_node = xmlNewNode(NULL, BAD_CAST "presence");
	if(root_node== NULL)
	{
		LM_ERR("Failed to create xml node\n");
		goto error;
	}
	xmlDocSetRootElement(pres_doc, root_node);

	xmlNewProp(root_node, BAD_CAST "xmlns",
			BAD_CAST "urn:ietf:params:xml:ns:pidf");
	xmlNewProp(root_node, BAD_CAST "xmlns:dm",
			BAD_CAST "urn:ietf:params:xml:ns:pidf:data-model");
	xmlNewProp(root_node, BAD_CAST  "xmlns:rpid",
			BAD_CAST "urn:ietf:params:xml:ns:pidf:rpid" );
	xmlNewProp(root_node, BAD_CAST "xmlns:c",
			BAD_CAST "urn:ietf:params:xml:ns:pidf:cipid");

	entity= (char*)pkg_malloc(pres_uri->len + 1);
	if(entity == NULL)
	{
		LM_ERR("No more memory\n");
		goto error;
	}
	memcpy(entity, pres_uri->s, pres_uri->len);
	entity[pres_uri->len] = '\0';
	xmlNewProp(root_node, BAD_CAST "entity", BAD_CAST entity);
	pkg_free(entity);

	tuple_node =xmlNewChild(root_node, NULL, BAD_CAST "tuple", NULL) ;
	if(tuple_node == NULL)
	{
		LM_ERR("while adding child\n");
		goto error;
	}

	xmlNewProp(tuple_node, BAD_CAST "id", BAD_CAST "tuple_mixingid");

	node = xmlNewChild(tuple_node, NULL, BAD_CAST "status", NULL) ;
	if(node == NULL)
	{
		LM_ERR("while adding child\n");
		goto error;
	}
	node = xmlNewChild(node, NULL, BAD_CAST "basic",
			BAD_CAST "closed") ;
	if(node ==NULL)
	{
		LM_ERR("while adding child\n");
		goto error;
	}

	body = (str*)pkg_malloc(sizeof(str));
	if(body == NULL)
	{
		LM_ERR("No more memory\n");
		goto error;
	}
	xmlDocDumpMemory(pres_doc,(xmlChar**)(void*)&body->s,
			&body->len);

	LM_DBG("Generated dialog body: %.*s\n", body->len, body->s);

error:
	if(pres_doc)
		xmlFreeDoc(pres_doc);
	xmlCleanupParser();
	xmlMemoryDump();

	return body;
}

