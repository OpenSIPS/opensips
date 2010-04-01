/*
 * $Id$
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 *  2006-08-15  initial version (Anca Vamanu)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../../db/db.h"
#include "../../dprint.h"
#include "../../mem/shm_mem.h"
#include "../../str.h"
#include "../alias_db/alias_db.h"
#include "../../data_lump_rpl.h"
#include "presentity.h"
#include "presence.h" 
#include "notify.h"
#include "publish.h"
#include "hash.h"
#include "utils_func.h"

#define PRESENTITY_FETCH_SIZE			128

unsigned char *xmlNodeGetAttrContentByName(xmlNodePtr node, const char *name);
xmlNodePtr xmlNodeGetNodeByName(xmlNodePtr node, const char *name,
													const char *ns);
static str pu_200_rpl  = str_init("OK");
static str pu_412_rpl  = str_init("Conditional request failed");

#define ETAG_LEN  128

char* generate_ETag(int publ_count)
{
	char* etag= NULL;
	int size = 0;

	etag = (char*)pkg_malloc(ETAG_LEN);
	if(etag ==NULL)
	{
		ERR_MEM(PKG_MEM_STR);
	}
	memset(etag, 0, ETAG_LEN);
	size = sprintf (etag, "%c.%d.%d.%d.%d",
		prefix, (int)startup_time, pid, counter, publ_count);
	if( size <0 )
	{
		LM_ERR("unsuccessfull sprintf\n ");
		pkg_free(etag);
		return NULL;
	}
	if(size+ 1> ETAG_LEN)
	{
		LM_ERR("buffer size overflown\n");
		pkg_free(etag);
		return NULL;
	}

	etag[size] = '\0';
	LM_DBG("etag= %s / %d\n",etag, size);
	return etag;

error:
	return NULL;

}

int publ_send200ok(struct sip_msg *msg, int lexpire, str etag)
{
	char buf[128];
	int buf_len= 128, size;
	str hdr_append= {0, 0}, hdr_append2= {0, 0} ;

	LM_DBG("send 200OK reply\n");	
	LM_DBG("etag= %s - len= %d\n", etag.s, etag.len);

	hdr_append.s = buf;
	hdr_append.s[0]='\0';
	
	hdr_append.len = sprintf(hdr_append.s, "Expires: %d\r\n",((lexpire< expires_offset)?0:
			(lexpire - expires_offset)));
	if(hdr_append.len < 0)
	{
		LM_ERR("unsuccessful sprintf\n");
		goto error;
	}
	if(hdr_append.len > buf_len)
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
	hdr_append2.len = sprintf(hdr_append2.s, "SIP-ETag: %s\r\n", etag.s);
	if(hdr_append2.len < 0)
	{
		LM_ERR("unsuccessful sprintf\n ");
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
presentity_t* new_presentity( str* domain,str* user,int expires, 
		pres_ev_t* event, str* etag, str* sender)
{
	presentity_t *presentity= NULL;
	int size, init_len;
	
	/* allocating memory for presentity */
	size = sizeof(presentity_t)+ domain->len+ user->len+ etag->len +1;
	if(sender)
		size+= sizeof(str)+ sender->len;
	
	init_len= size;

	presentity = (presentity_t*)pkg_malloc(size);
	if(presentity == NULL)
	{
		ERR_MEM(PKG_MEM_STR);
	}
	memset(presentity, 0, size);
	size= sizeof(presentity_t);

	presentity->domain.s = (char*)presentity+ size;
	strncpy(presentity->domain.s, domain->s, domain->len);
	presentity->domain.len = domain->len;
	size+= domain->len;	
	
	presentity->user.s = (char*)presentity+size;
	strncpy(presentity->user.s, user->s, user->len);
	presentity->user.len = user->len;
	size+= user->len;

	presentity->etag.s = (char*)presentity+ size;
	memcpy(presentity->etag.s, etag->s, etag->len);
	presentity->etag.s[etag->len]= '\0';
	presentity->etag.len = etag->len;

	size+= etag->len+1;
	
	if(sender)
	{
		presentity->sender= (str*)((char*)presentity+ size);
		size+= sizeof(str);
		presentity->sender->s= (char*)presentity + size;
		memcpy(presentity->sender->s, sender->s, sender->len);
		presentity->sender->len= sender->len;
		size+= sender->len;
	}

	if(size> init_len)
	{
		LM_ERR("buffer size overflow init_len= %d, size= %d\n", init_len, size);
		goto error;
	}
	presentity->event= event;
	presentity->expires = expires;
	presentity->received_time= (int)time(NULL);
	return presentity;
    
error:
	if(presentity)
		pkg_free(presentity);
	return NULL;
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
		LM_INFO("new:\n%.*s\n", new_body->len, new_body->s);\
		LM_INFO("old:\n%.*s\n", old_body->len, old_body->s);\
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

int bla_aggregate_state(str* old_body, str* new_body,
		int* bla_update_publish, int* allocated, str* fin_body)
{
	xmlDocPtr old_doc= NULL, new_doc= NULL;
	xmlNodePtr dlg_node, n_dlg_node;
	xmlNodePtr aux_dlg_node, state_node, node;
	xmlNodePtr identity_node, remote_node;
	unsigned char* state = NULL;
	unsigned char* attr;
	int dialog_found = 0;
	unsigned char* n_callid= NULL,*n_totag= NULL,*n_fromtag= NULL,*dir= NULL;
	unsigned char* o_callid= NULL,*o_totag= NULL,*o_fromtag= NULL;

	*allocated = 0;
	*bla_update_publish = 0;

	/* check if the old body has a dialog */
	old_doc = xmlParseMemory(old_body->s, old_body->len);
	if(old_doc== NULL)
	{
		LM_ERR("failed to parse old body xml document\n");
		goto error;
	}

	new_doc = xmlParseMemory(new_body->s, new_body->len);
	if(new_doc== NULL)
	{
		LM_ERR("failed to parse new body xml document\n");
		goto error;
	}
	/* if no body in new body, do not update */
	n_dlg_node  = xmlNodeGetChildByName(new_doc->children, "dialog");
	if(n_dlg_node == NULL)
	{
		*allocated = 1;
		LM_INFO("No dialog found in new body, so Notify with the old one\n");
		xmlDocDumpMemory(old_doc,(xmlChar**)(void*)&fin_body->s,
				&fin_body->len);
		xmlFreeDoc(new_doc);
		xmlFreeDoc(old_doc);
		return 0;
	}
	/* change the state to full*/
	if(xmlUnsetProp(new_doc->children, BAD_CAST "state") < 0)
	{
		LM_ERR("Failed to remove attribute state");
		goto error;
	}
	if(xmlNewProp(new_doc->children, BAD_CAST "state", BAD_CAST "full")== 0)
	{
		LM_ERR("Failed to add attribute state=full\n");
		goto error;
	}

/* if there are more dialog nodes-> check for one with state != terminated */
	for(dlg_node= n_dlg_node; dlg_node; dlg_node=dlg_node->next)
	{
		if(xmlStrcasecmp(dlg_node->name, (unsigned char*)"dialog")!= 0)
		{
			continue;
		}

		state_node = xmlNodeGetChildByName(dlg_node, "state");
		if(state_node == NULL) /* no state node found */
		{
			LM_ERR("No state node found in new body\n");
			goto error;
		}
		state = xmlNodeGetContent(state_node);
		if(state == NULL)
		{
			LM_ERR("No state defined for new body dialog\n");
			goto error;
		}
		if(xmlStrcasecmp(state, (unsigned char*)"terminated")== 0)
		{
			xmlFree(state);
			state = NULL;
			continue;
		}
		xmlFree(state);
		state = NULL;
		n_dlg_node = dlg_node;
		break;
	}
	/* extract dialog information from the new body */
	bla_extract_dlginfo(n_dlg_node, n_callid, n_fromtag, n_totag);
	LM_INFO("Extracted callid, from_tag, to_tag");
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
			*allocated= 1;
		}
	}

	dlg_node = xmlNodeGetChildByName(old_doc->children, "dialog");
	if(dlg_node == NULL) /* if no previous record of a dialog, the new body should be written */
	{
		/* if the state in the new body is terminated - do not update */
		state_node = xmlNodeGetChildByName(n_dlg_node, "state");
		if(state_node == NULL) /* no state node found */
		{
			LM_ERR("No state node found in new body\n");
			goto error;
		}
		state = xmlNodeGetContent(state_node);
		if(state == NULL)
		{
			LM_ERR("No state defined for new body dialog\n");
			goto error;
		}
		if(xmlStrcasecmp(state, (unsigned char*)"terminated")== 0)
		{
			*allocated = 1;
			xmlDocDumpMemory(old_doc,(xmlChar**)(void*)&fin_body->s,
				&fin_body->len);
		}
		else
		{
			/* maybe I changed the target */
			if(*allocated)
			{
				xmlDocDumpMemory(new_doc,(xmlChar**)(void*)&fin_body->s,
					&fin_body->len);
			}
			*bla_update_publish = 1;
		}
		xmlFree(state);
		state = NULL;
		goto done;
	}
	/* check the dialogs*/
	/* the only case when a new dialog notification can arrive is when all the others are on hold */
	/* if we find a terminated dialog, delete it */
	while(dlg_node)
	{
		if(xmlStrcasecmp(dlg_node->name, (unsigned char*)"dialog")!= 0)
		{
			dlg_node = dlg_node->next;
			continue;
		}
		bla_extract_dlginfo(dlg_node, o_callid, o_fromtag, o_totag);

		/* if it is the same dialog*/
		if(bla_same_dialog(n_callid, n_fromtag, n_totag,
					o_callid, o_fromtag, o_totag))
		{
			/* rewrite the node with the new one */
			xmlUnlinkNode(dlg_node);
			xmlFreeNode(dlg_node);
			LM_DBG("Found the same dialog - replace the node with the new one\n");
			dialog_found= 1;
			if(o_callid)
				xmlFree(o_callid);
			if(o_fromtag)
				xmlFree(o_fromtag);
			if(o_totag)
				xmlFree(o_totag);
			o_callid= o_fromtag= o_totag= NULL;
			break;
		}
		if(o_callid)
			xmlFree(o_callid);
		if(o_fromtag)
			xmlFree(o_fromtag);
		if(o_totag)
			xmlFree(o_totag);
		o_callid= o_fromtag= o_totag= NULL;
		/* if a different one, check the state */
		state_node = xmlNodeGetChildByName(dlg_node, "state");
		if(state_node== NULL)
		{
			LM_ERR("No state defined for dialog\n");
			goto error;
		}
		/* if state is terminated -> delete the node */
		state = xmlNodeGetContent(state_node) ;
		if(state == NULL)
		{
			LM_ERR("Wrong formated document - no dialog state\n");
			goto error;
		}
		LM_DBG("Found a different dialog state = %s\n", state);
		
		if(xmlStrcasecmp(state, (unsigned char*)"terminated")== 0)
		{
			aux_dlg_node = dlg_node->next;
			xmlFree(state);
			state = NULL;
			xmlUnlinkNode(dlg_node);
			xmlFreeNode(dlg_node);
			dlg_node = aux_dlg_node;
			continue;
		}
#if 0	
	/* if state is confirmed -> check if on hold */
		if(xmlStrcasecmp(state, (unsigned char*)"confirmed")== 0)
		{
			/* check if on hold */
			node = xmlNodeGetChildByName(dlg_node, "local");
			if(node == NULL)
			{
				LM_ERR("local node not found\n");
				goto error;
			}
			node = xmlNodeGetChildByName(node, "target");
			if(node == NULL)
			{
				LM_ERR("local node not found\n");
				goto error;
			}
			for(node= node->children; node; node=node->next)
			{
				if(xmlStrcasecmp(node->name, (unsigned char*)"param") != 0)
				{
					continue;
				}
				attr = xmlNodeGetAttrContentByName(node, "pname");
				if(attr == NULL)
				{
					LM_ERR("pname attribute not found for param node\n");
					goto error;
				}
				if(xmlStrcasecmp(attr, (unsigned char*)"+sip.rendering") != 0)
				{
					xmlFree(attr);
					continue;
				}
				xmlFree(attr);
				attr = xmlNodeGetAttrContentByName(node, "pval");
				if(attr == NULL)
				{
					LM_ERR("pval attribute not found for param node\n");
					goto error;
				}
				/* the call is on hold when <param pname="+sip.rendering" pval="no"/> */
				if(xmlStrcasecmp(attr, (unsigned char*) "no") != 0)
				{
					/* the last call was not on hold -> return error*/
					LM_ERR("Found another call that was not on hold\n");
					LM_ERR("New body:\n%.*s\n", new_body->len, new_body->s);
					LM_ERR("Old body:\n%.*s\n", old_body->len, old_body->s);
					xmlFree(attr);
					if(n_node_state == DLG_DESTROYED)
					{
						bla_update_publish = 0;
						*allocated = 1;
						xmlDocDumpMemory(old_doc,(xmlChar**)(void*)&fin_body->s,
							&fin_body->len);
						goto done;
					}
						
					to_delete = 1; 
					break;
//					goto error;
				}
				xmlFree(attr);
			}
			if(to_delete)
			{
				xmlFree(state);
				aux_dlg_node= dlg_node->next;
				xmlUnlinkNode(dlg_node);
				xmlFreeNode(dlg_node);
				dlg_node = aux_dlg_node;
				continue;
			}
		}
#endif
		xmlFree(state);
		state = NULL;
		dlg_node = dlg_node->next;
	}

	if(!dialog_found)
	{
		/* if the new body has a dialog with state terminated - do not update */
		state_node = xmlNodeGetChildByName(n_dlg_node, "state");
		if(state_node == NULL) /* no state node found */
		{
			LM_ERR("No state node found in new body\n");
			goto error;
		}
		state = xmlNodeGetContent(state_node);
		if(state == NULL)
		{
			LM_ERR("No state defined for new body dialog\n");
			goto error;
		}
		if(xmlStrcasecmp(state, (unsigned char*)"terminated")== 0)
		{
			*allocated = 1;
			xmlDocDumpMemory(old_doc,(xmlChar**)(void*)&fin_body->s,
				&fin_body->len);
			xmlFree(state);
			goto done;
		}
	}

	dlg_node = xmlNodeGetChildByName(old_doc->children, "dialog");
	while(dlg_node)
	{
		if(xmlStrcasecmp(dlg_node->name, (unsigned char*)"dialog")!= 0)
		{
			dlg_node= dlg_node->next;
			continue;
		}
		n_dlg_node= xmlCopyNode(dlg_node, 1);
		if(n_dlg_node== NULL)
		{
			LM_ERR("failed to copy dialog node\n");
			goto error;
		}
		if(xmlAddChild(new_doc->children, n_dlg_node)== NULL)
		{
			LM_ERR("while adding child\n");
			goto error;
		}
		dlg_node = dlg_node->next;
	}
	xmlDocDumpMemory(new_doc,(xmlChar**)(void*)&fin_body->s,
		&fin_body->len);
	*bla_update_publish = 1;
	*allocated = 1;

done:
	xmlFreeDoc(new_doc);
	xmlFreeDoc(old_doc);
	xmlCleanupParser();
	xmlMemoryDump();
	if(n_callid)
		xmlFree(n_callid);
	if(n_totag)
		xmlFree(n_totag);
	if(n_fromtag)
		xmlFree(n_fromtag);
	return 0;

error:
	if(new_doc)
		xmlFreeDoc(new_doc);
	if(old_doc)
		xmlFreeDoc(old_doc);
	if(state)
		xmlFree(state);
	if(n_callid)
		xmlFree(n_callid);
	if(n_totag)
		xmlFree(n_totag);
	if(n_fromtag)
		xmlFree(n_fromtag);
	xmlCleanupParser();
    xmlMemoryDump();
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


int update_presentity(struct sip_msg* msg, presentity_t* presentity, str* body,
		int new_t, int* sent_reply, char* sphere)
{
//	static db_ps_t my_ps_insert = NULL, my_ps_update_no_body = NULL,
//		   my_ps_update_body = NULL;
//	static db_ps_t my_ps_delete = NULL, my_ps_query = NULL;
	db_key_t query_cols[12], update_keys[8], result_cols[5];
	db_op_t  query_ops[12];
	db_val_t query_vals[12], update_vals[8];
	db_res_t *result= NULL;
	int n_query_cols = 0;
	int n_update_cols = 0;
	char* dot= NULL;
	str etag= {0, 0};
	str cur_etag= {0, 0};
	str* rules_doc= NULL;
	str pres_uri= {0, 0};
	int rez_body_col, rez_sender_col, n_result_cols= 0;
	db_row_t *row = NULL ;
	db_val_t *row_vals = NULL;
	str old_body;
//	str sender;
	int bla_update_publish= 1;
	str fin_body={0, 0};
	int allocated = 0;

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

	query_cols[n_query_cols] = &str_etag_col;
	query_ops[n_query_cols] = OP_EQ;
	query_vals[n_query_cols].type = DB_STR;
	query_vals[n_query_cols].nul = 0;
	query_vals[n_query_cols].val.str_val = presentity->etag;
	n_query_cols++;

	result_cols[rez_body_col= n_result_cols++] = &str_body_col;
	result_cols[rez_sender_col= n_result_cols++] = &str_sender_col;

	if(new_t) 
	{
		/* insert new record in hash_table */
	
		if(insert_phtable(&pres_uri, presentity->event->evp->parsed, sphere)< 0)
		{
			LM_ERR("inserting record in hash table\n");
			goto error;
		}
		
		/* insert new record into database */	
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
		query_vals[n_query_cols].val.str_val = *body;
		n_query_cols++;
		
		query_cols[n_query_cols] = &str_received_time_col;
		query_vals[n_query_cols].type = DB_INT;
		query_vals[n_query_cols].nul = 0;
		query_vals[n_query_cols].val.int_val = presentity->received_time;
		n_query_cols++;
		
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
		if( publ_send200ok(msg, presentity->expires, presentity->etag)< 0)
		{
			LM_ERR("sending 200OK\n");
			goto error;
		}
		*sent_reply= 1;
		goto send_notify;
	}
	else
	{	
		if (pa_dbf.use_table(pa_db, &presentity_table) < 0) 
		{
			LM_ERR("unsuccessful sql use table\n");
			goto error;
		}

	//	CON_PS_REFERENCE(pa_db) = &my_ps_query;
		if (pa_dbf.query (pa_db, query_cols, query_ops, query_vals,
			 result_cols, n_query_cols, n_result_cols, 0, &result) < 0) 
		{
			LM_ERR("unsuccessful sql query\n");
			goto error;
		}
		if(result== NULL)
			goto error;

		if (result->n > 0)
		{

			if(presentity->event->evp->parsed == EVENT_DIALOG_SLA
					&& body && body->s)
			{
				/* analize if previous body has a dialog */
				row = &result->rows[0];
				row_vals = ROW_VALUES(row);

				old_body.s = (char*)row_vals[rez_body_col].val.string_val;
				old_body.len = strlen(old_body.s);

			/* the meaning of the parameters
				* bla_update_publish - if what is now in database should be changed 
				* allocated - if fin_body has a pointer to an dynamic allocated memory */

				if(bla_aggregate_state(&old_body, body, &bla_update_publish,
							&allocated, &fin_body) < 0)
				{
					LM_ERR("Failed to aggregate bla state\n");
					/* I should not update - but send 200 OK */
					bla_update_publish = 0;
					allocated = 0;
					//	goto error;
				}

				if(bla_update_publish ||  allocated) /* if an aggregated body */
				{
					body->s = fin_body.s;
					body->len = fin_body.len;
				}
			}
			pa_dbf.free_result(pa_db, result);
			result= NULL;
			if(presentity->expires == 0) 
			{
				if( publ_send200ok(msg, presentity->expires, presentity->etag)< 0)
				{
					LM_ERR("sending 200OK reply\n");
					goto error;
				}
				*sent_reply= 1;
				if( publ_notify( presentity, pres_uri, body, &presentity->etag, rules_doc)< 0 )
				{
					LM_ERR("while sending notify\n");
					goto error;
				}
				
				if (pa_dbf.use_table(pa_db, &presentity_table) < 0) 
				{
					LM_ERR("unsuccessful sql use table\n");
					goto error;
				}

				LM_DBG("expires =0 -> deleting from database\n");
			//	CON_PS_REFERENCE(pa_db) = &my_ps_delete;
				if(pa_dbf.delete(pa_db,query_cols,0,query_vals,n_query_cols)<0)
				{
					LM_ERR("unsuccessful sql delete operation");
					goto error;
				}
				LM_DBG("deleted from db %.*s\n",	presentity->user.len,
						presentity->user.s);

				/* delete from hash table */
	
				if(delete_phtable(&pres_uri, presentity->event->evp->parsed)< 0)
				{
					LM_ERR("deleting record from hash table\n");
					goto error;
				}
				goto done;
			}

			n_update_cols= 0;

			if(presentity->event->etag_not_new== 0)
			{
				/* generate another etag */
				unsigned int publ_nr;
				str str_publ_nr= {0, 0};

				dot= presentity->etag.s+ presentity->etag.len;
				while(*dot!= '.' && str_publ_nr.len< presentity->etag.len)
				{
					str_publ_nr.len++;
					dot--;
				}
				if(str_publ_nr.len== presentity->etag.len)
				{
					LM_ERR("wrong etag\n");
					goto error;
				}	
				str_publ_nr.s= dot+1;
				str_publ_nr.len--;
	
				if( str2int(&str_publ_nr, &publ_nr)< 0)
				{
					LM_ERR("converting string to int\n");
					goto error;
				}
				etag.s = generate_ETag(publ_nr+1);
				if(etag.s == NULL)
				{
					LM_ERR("while generating etag\n");
					goto error;
				}
				etag.len=(strlen(etag.s));
				
				cur_etag= etag;
			}
			else
			{
				cur_etag= presentity->etag;
			}

			update_keys[n_update_cols] = &str_etag_col;
			update_vals[n_update_cols].type = DB_STR;
			update_vals[n_update_cols].nul = 0;
			update_vals[n_update_cols].val.str_val = cur_etag;
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

			if(body && body->s && bla_update_publish)
			{
				update_keys[n_update_cols] = &str_body_col;
				update_vals[n_update_cols].type = DB_BLOB;
				update_vals[n_update_cols].nul = 0;
				update_vals[n_update_cols].val.str_val = *body;
				n_update_cols++;

				/* updated stored sphere */
				if(sphere_enable && 
						presentity->event->evp->parsed== EVENT_PRESENCE)
				{
					if(update_phtable(presentity, pres_uri, *body)< 0)
					{
						LM_ERR("failed to update sphere for presentity\n");
						goto error;
					}
				}
			//	CON_PS_REFERENCE(pa_db) = &my_ps_update_body;
			}
			else
			{
			//	CON_PS_REFERENCE(pa_db) = &my_ps_update_no_body;
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
			if( publ_send200ok(msg, presentity->expires, cur_etag)< 0)
			{
				LM_ERR("sending 200OK reply\n");
				goto error;
			}
			*sent_reply= 1;
			
			if(etag.s)
				pkg_free(etag.s);
			etag.s= NULL;
			
			if(!body)
				goto done;
		
			goto send_notify;
		}  
		else  /* if there isn't no registration with those 3 values */
		{
			pa_dbf.free_result(pa_db, result);
			result= NULL;
			LM_ERR("No E_Tag match\n");
			if (sigb.reply(msg, 412, &pu_412_rpl, 0) == -1)
			{
				LM_ERR("sending '412 Conditional request failed' reply\n");
				goto error;
			}
			*sent_reply= 1;
			goto done;
		}
	}

send_notify:
			
	/* send notify with presence information */
	if (publ_notify(presentity, pres_uri, body, NULL, rules_doc)<0)
	{
		LM_ERR("while sending Notify requests to watchers\n");
		goto error;
	}

done:
	if(rules_doc)
	{
		if(rules_doc->s)
			pkg_free(rules_doc->s);
		pkg_free(rules_doc);
	}
	if(pres_uri.s)
		pkg_free(pres_uri.s);
	if(allocated && fin_body.s)
		xmlFree(fin_body.s);

	return 0;

error:
	if(result)
		pa_dbf.free_result(pa_db, result);
	if(etag.s)
		pkg_free(etag.s);
	if(rules_doc)
	{
		if(rules_doc->s)
			pkg_free(rules_doc->s);
		pkg_free(rules_doc);
	}
	if(pres_uri.s)
		pkg_free(pres_uri.s);
	if(allocated && fin_body.s)
		xmlFree(fin_body.s);
	return -1;

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
	int user_col, domain_col, event_col, expires_col, body_col = 0;
	int event;
	event_t ev;
	char* sphere= NULL;
	int nr_rows;

	result_cols[user_col= n_result_cols++]= &str_username_col;
	result_cols[domain_col= n_result_cols++]= &str_domain_col;
	result_cols[event_col= n_result_cols++]= &str_event_col;
	result_cols[expires_col= n_result_cols++]= &str_expires_col;
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
		if(pa_dbf.fetch_result(pa_db,&result,PRESENTITY_FETCH_SIZE)<0)
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

			if(insert_phtable(&uri, event, sphere)< 0)
			{
				LM_ERR("inserting record in presentity hash table");
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
			if (pa_dbf.fetch_result( pa_db, &result,
			PRESENTITY_FETCH_SIZE ) < 0) 
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
	
		if (pa_dbf.use_table(pa_db, &presentity_table) < 0) 
		{
			LM_ERR("in use_table\n");
			goto done;
		}
		if (pa_dbf.query (pa_db, query_cols, 0, query_vals,
			 result_cols, n_query_cols, n_result_cols, &query_str ,  &result) < 0) 
		{
			LM_ERR("failed to query %.*s table\n", presentity_table.len, presentity_table.s);
			if(result)
				pa_dbf.free_result(pa_db, result);
			goto done;
		}
		if(result== NULL)
			goto done;
		if (result->n<=0 )
		{
			LM_DBG("no published record found in database\n");
			pa_dbf.free_result(pa_db, result);
			goto done;
		}
		pa_dbf.free_result(pa_db, result);
		ret = 1;
	}
done:
	if(result)
		pa_dbf.free_result(pa_db, result);
	return ret;
}
