/*
 * $Id: client.c $
 *
 * back-to-back entities module
 *
 * Copyright (C) 2009 Free Software Fundation
 *
 * This file is part of opensips, a free SIP client.
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

#include "../../crc.h"
#include "../tm/dlg.h"
#include "../../ut.h"
#include "../presence/hash.h"
#include "dlg.h"
#include "client.h"
#include "b2b_entities.h"

#define BUF_LEN   256

void b2b_client_tm_cback( struct cell *t, int type, struct tmcb_params *ps)
{
	return b2b_tm_cback(client_htable, ps);
}

#define FROM_TAG_LEN (MD5_LEN + 1 /* - */ + CRC16_LEN) /* length of FROM tags */

static char from_tag[FROM_TAG_LEN + 1];

static void generate_tag(str* tag, str* src, str* callid)
{
	MD5StringArray(from_tag, src, 1);
	from_tag[MD5_LEN] = '-';

	/* calculate from tag from callid */
	crcitt_string_array(&from_tag[MD5_LEN + 1], callid, 1);
	tag->s = from_tag;
	tag->len = FROM_TAG_LEN;
	LM_DBG("from_tag = %s\n", from_tag);
}

/** 
 * Function to create a new client entity a send send an initial message
 *	method  : the method of the message
 *	to_uri  : the destination URI
 *	from_uri: the source URI
 *	extra_headers: the extra headers to be added in the request
 *	b2b_cback : callback function to notify the logic about a change in dialog
 *	param     : the parameter that will be used when calling b2b_cback function
 *
 *	Return value: dialog key allocated in private memory
 *	*/

str* client_new(str* method, str* to_uri, str* from_uri, str* extra_headers,
		str* body, b2b_notify_t b2b_cback, void* param)
{
	int result;
	b2b_dlg_t* dlg;
	unsigned int hash_index;
	str* callid = NULL;
	int size;
	str ehdr = {0, 0};
	char buffer[BUF_LEN];
	str* b2b_key_shm = NULL;
	dlg_t td;

	if(method == NULL || to_uri == NULL || from_uri == NULL ||
			b2b_cback == NULL)
	{
		LM_ERR("Wrong parameters. 'method', 'to_uri', 'from_uri' and"
				" 'b2b_cback' can not be NULL\n");
		return NULL;
	}

	hash_index = core_hash(from_uri, to_uri, client_hsize);

	/* create a dummy b2b dialog structure to be inserted in the hash table*/
	size = sizeof(b2b_dlg_t) + to_uri->len + from_uri->len;

	/* create record in hash table */
	dlg = (b2b_dlg_t*)shm_malloc(size);
	if(dlg == NULL)
	{
		LM_ERR("No more shared memory\n");
		return 0;
	}
	memset(dlg, 0, size);
	size = sizeof(b2b_dlg_t);

	dlg->from_uri.s = (char*)dlg + size;
	memcpy(dlg->from_uri.s, from_uri->s, from_uri->len);
	dlg->from_uri.len = from_uri->len;
	size+= from_uri->len;

	dlg->to_uri.s = (char*)dlg + size;
	memcpy(dlg->to_uri.s, to_uri->s, to_uri->len);
	dlg->to_uri.len = to_uri->len;
	size+= to_uri->len;

	dlg->b2b_cback = b2b_cback;
	dlg->param = param;
	dlg->last_method = METHOD_INVITE;
	dlg->state = B2B_NEW;
	dlg->cseq[CALLER_LEG] =1;

	/* callid must have the special format */
	callid = b2b_htable_insert(client_htable, dlg, hash_index, B2B_CLIENT);
	if(callid == NULL)
	{
		LM_ERR("Inserting new record in hash table failed\n");
		shm_free(dlg);
		goto error;
	}
	LM_DBG("New client - key = %.*s\n", callid->len, callid->s);

	/* construct extra headers -> add contact */
	if(extra_headers && extra_headers->s && extra_headers->len)
	{
		if(extra_headers->len + 13 + server_address.len > BUF_LEN)
		{
			LM_ERR("Buffer too small\n");
			goto error;
		}
		memcpy(buffer, extra_headers->s, extra_headers->len);
		ehdr.len = extra_headers->len;
	}
	ehdr.len += sprintf(buffer+ ehdr.len, "Contact: <%.*s>\r\n",
		server_address.len, server_address.s);
	ehdr.s = buffer;

	LM_DBG("extra_header = %.*s\n", ehdr.len, ehdr.s);
	
	if(body && body->len && body->s)
		LM_DBG("body = %.*s\n", body->len, body->s);

	/* copy the key in shared memory to transmit it as a parameter to the tm callback */
	b2b_key_shm = b2b_key_copy_shm(callid);
	if(b2b_key_shm== NULL)
	{
		LM_ERR("no more shared memory\n");
		goto error;
	}

	/* create the tm dialog structure with the a costum callid */
	memset(&td, 0, sizeof(dlg_t));
	td.loc_seq.value = 1;
	td.loc_seq.is_set = 1;

	td.id.call_id = *callid;

	generate_tag(&td.id.loc_tag, from_uri, callid);
	LM_DBG("generated tag = [%.*s]\n", td.id.loc_tag.len, td.id.loc_tag.s);

	td.id.rem_tag.s = 0;
	td.id.rem_tag.len = 0;

	td.rem_target = *to_uri;
	td.loc_uri    = *from_uri;
	td.rem_uri    = *to_uri;

	td.state= DLG_CONFIRMED;
	td.T_flags=T_NO_AUTOACK_FLAG|T_PASS_PROVISIONAL_FLAG ;

	tmb.setlocalTholder(&dlg->tm_tran);
	
	/* send request */
	result= tmb.t_request_within
		(method,               /* method*/
		&ehdr,                 /* extra headers*/
		body,                  /* body*/
		&td,                   /* dialog structure*/
		b2b_client_tm_cback,   /* callback function*/
		b2b_key_shm,
		shm_free_param);       /* function to release the parameter*/
	if(result< 0)
	{
		LM_ERR("while sending request with t_request\n");
		pkg_free(callid);
		shm_free(b2b_key_shm);
		return 0;
	}
	tmb.setlocalTholder(0);
	return callid;

error:
	if(callid)
		pkg_free(callid);
	return 0;
}

dlg_t* b2b_client_build_dlg(b2b_dlg_t* dlg, dlg_leg_t* leg)
{
	dlg_t* td =NULL;

	if(dlg->legs == NULL)
	{
		LM_ERR("Tried to send a dialog when no call leg info exists\n");
		return 0;
	}

	td = (dlg_t*)pkg_malloc(sizeof(dlg_t));
	if(td == NULL)
	{
		ERR_MEM(PKG_MEM_STR);
	}
	memset(td, 0, sizeof(dlg_t));

	td->loc_seq.value   = dlg->cseq[CALLER_LEG];
	dlg->cseq[CALLER_LEG]++;
	td->loc_seq.is_set  = 1;

	td->id.call_id = dlg->callid;
	td->id.loc_tag = dlg->tag[CALLER_LEG];
	td->id.rem_tag = leg->tag;

	LM_DBG("*** Rem_target = %.*s\n", leg->contact.len, leg->contact.s);
	td->rem_target = leg->contact;

	td->loc_uri = dlg->from_uri;
	td->rem_uri = dlg->to_uri;

	if(leg->route_set.s && leg->route_set.len)
	{
		if(parse_rr_body(leg->route_set.s, leg->route_set.len,
			&td->route_set)< 0)
		{
			LM_ERR("failed to parse record route body\n");
			goto error;
		}
	}	
	td->state= DLG_CONFIRMED ;
	td->send_sock = leg->bind_addr;

	return td;
error:
	if(td)
		pkg_free(td);

	return 0;
}

