/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History:
 * --------
 *  2009-08-03  initial version (Anca Vamanu)
 */

#include <stdio.h>
#include <stdlib.h>
#include <utime.h>

#include "../../crc.h"
#include "../tm/dlg.h"
#include "../../ut.h"
#include "../presence/hash.h"
#include "../../parser/parse_methods.h"
#include "dlg.h"
#include "client.h"
#include "b2b_entities.h"

void b2b_client_tm_cback( struct cell *t, int type, struct tmcb_params *ps)
{
	b2b_tm_cback(t, client_htable, ps);
}

#define FROM_TAG_LEN (MD5_LEN + 1 /* - */ + CRC16_LEN) /* length of FROM tags */

static char from_tag[FROM_TAG_LEN + 1];

static void generate_tag(str* tag, str* src, str* callid)
{
	int len;

	MD5StringArray(from_tag, src, 1);
	len = MD5_LEN;

	/* calculate from tag from callid */
	if(callid)
	{
		from_tag[len++] = '-';
		crcitt_string_array(&from_tag[MD5_LEN + 1], callid, 1);
		len+= CRC16_LEN;
	}
	tag->s = from_tag;
	tag->len = len;
	LM_DBG("from_tag = %.*s\n", tag->len, tag->s);
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
#define HASH_SIZE 1<<23
str* client_new(client_info_t* ci,b2b_notify_t b2b_cback,
		b2b_add_dlginfo_t add_dlginfo, str *mod_name, str* param)
{
	int result;
	b2b_dlg_t* dlg;
	unsigned int hash_index;
	str* callid = NULL;
	int size;
	str ehdr = {0, 0};
	str* b2b_key_shm = NULL;
	dlg_t td;
	str from_tag;
	str random_info = {0, 0};

	if(ci == NULL || b2b_cback == NULL || param== NULL)
	{
		LM_ERR("Wrong parameters.\n");
		return NULL;
	}
	if(param && param->len > B2BL_MAX_KEY_LEN)
	{
		LM_ERR("parameter too long, received [%d], maximum [%d]\n",
				param->len, B2BL_MAX_KEY_LEN);
		return 0;
	}

	hash_index = core_hash(&ci->from_uri, &ci->to_uri, client_hsize);

	if(ci->from_tag)
		from_tag = *ci->from_tag;
	else
		generate_tag(&from_tag, &ci->from_uri, ci->extra_headers);

	/* create a dummy b2b dialog structure to be inserted in the hash table*/
	size = sizeof(b2b_dlg_t) + ci->to_uri.len + ci->from_uri.len
		+ ci->from_dname.len + ci->to_dname.len +
		from_tag.len + ci->local_contact.len + B2B_MAX_KEY_SIZE +
		B2BL_MAX_KEY_LEN + mod_name->len;

	/* create record in hash table */
	dlg = (b2b_dlg_t*)shm_malloc(size);
	if(dlg == NULL)
	{
		LM_ERR("No more shared memory\n");
		return 0;
	}
	memset(dlg, 0, size);
	size = sizeof(b2b_dlg_t);

	CONT_COPY(dlg, dlg->from_uri, ci->from_uri);
	CONT_COPY(dlg, dlg->to_uri, ci->to_uri);
	if(ci->to_dname.s)
		CONT_COPY(dlg, dlg->to_dname, ci->to_dname);
	if(ci->from_dname.s)
		CONT_COPY(dlg, dlg->from_dname, ci->from_dname);
	CONT_COPY(dlg, dlg->tag[CALLER_LEG], from_tag);
	CONT_COPY(dlg, dlg->contact[CALLER_LEG], ci->local_contact);

	if(param && param->s)
	{
		dlg->param.s = (char*)dlg + size;
		memcpy(dlg->param.s, param->s, param->len);
		dlg->param.len = param->len;
		size+= B2BL_MAX_KEY_LEN;
	}
	dlg->b2b_cback = b2b_cback;
	dlg->add_dlginfo = add_dlginfo;

	CONT_COPY(dlg, dlg->mod_name, (*mod_name));

	if(parse_method(ci->method.s, ci->method.s+ci->method.len, &dlg->last_method) == 0)
	{
		LM_ERR("wrong method %.*s\n", ci->method.len, ci->method.s);
		shm_free(dlg);
		goto error;
	}
	dlg->state = B2B_NEW;
	dlg->cseq[CALLER_LEG] =(ci->cseq?ci->cseq:1);
	dlg->send_sock = ci->send_sock;

	random_info.s = int2str(rand(), &random_info.len);

	dlg->send_sock = ci->send_sock;
	dlg->id = core_hash(&from_tag, random_info.s?&random_info:0, HASH_SIZE);

	/* callid must have the special format */
	dlg->db_flag = NO_UPDATEDB_FLAG;
	callid = b2b_htable_insert(client_htable, dlg, hash_index, 0, B2B_CLIENT, 0, 0);
	if(callid == NULL)
	{
		LM_ERR("Inserting new record in hash table failed\n");
		shm_free(dlg);
		goto error;
	}

	if(b2breq_complete_ehdr(ci->extra_headers, ci->client_headers,
			&ehdr, ci->body, &ci->local_contact)< 0)
	{
		LM_ERR("Failed to complete extra headers\n");
		goto error;
	}

	/* copy the key in shared memory to transmit it as a parameter to the tm callback */
	b2b_key_shm = b2b_key_copy_shm(callid);
	if(b2b_key_shm== NULL)
	{
		LM_ERR("no more shared memory\n");
		goto error;
	}
	CONT_COPY(dlg, dlg->callid, (*callid));

	/* create the tm dialog structure with the a costum callid */
	memset(&td, 0, sizeof(dlg_t));
	td.loc_seq.value = dlg->cseq[CALLER_LEG];
	dlg->last_invite_cseq = dlg->cseq[CALLER_LEG];
	td.loc_seq.is_set = 1;

	td.id.call_id = *callid;
	td.id.loc_tag = from_tag;
	td.id.rem_tag.s = 0;
	td.id.rem_tag.len = 0;

	td.rem_uri = ci->to_uri;
	if(ci->req_uri.s)
		td.rem_target    = ci->req_uri;
	else
		td.rem_target    = ci->to_uri;
	if(td.rem_target.s[0] == '<')
	{
		td.rem_target.s++;
		td.rem_target.len-=2;
	}

	td.rem_dname  = ci->to_dname;

	td.loc_uri    = ci->from_uri;
	td.loc_dname  = ci->from_dname;

	td.state= DLG_CONFIRMED;
	td.T_flags=T_NO_AUTOACK_FLAG|T_PASS_PROVISIONAL_FLAG ;

	td.send_sock = ci->send_sock;

	if(ci->dst_uri.len)
		td.obp = ci->dst_uri;

	td.avps = ci->avps;

	tmb.setlocalTholder(&dlg->uac_tran);

	/* send request */
	result= tmb.t_request_within
		(&ci->method,          /* method*/
		&ehdr,                 /* extra headers*/
		ci->body,              /* body*/
		&td,                   /* dialog structure*/
		b2b_client_tm_cback,   /* callback function*/
		b2b_key_shm,
		shm_free_param);       /* function to release the parameter*/

	if(td.route_set)
		pkg_free(td.route_set);
	if(result< 0)
	{
		LM_ERR("while sending request with t_request\n");
		pkg_free(callid);
		shm_free(b2b_key_shm);
		return NULL;
	}
	tmb.setlocalTholder(NULL);

	LM_DBG("new client entity [%p] callid=[%.*s] tag=[%.*s] param=[%.*s]"
			" last method=[%d] dlg->uac_tran=[%p]\n",
			dlg, callid->len, callid->s,
			dlg->tag[CALLER_LEG].len, dlg->tag[CALLER_LEG].s,
			dlg->param.len, dlg->param.s, dlg->last_method, dlg->uac_tran);

	return callid;

error:
	if(callid)
		pkg_free(callid);
	return NULL;
}

dlg_t* b2b_client_build_dlg(b2b_dlg_t* dlg, dlg_leg_t* leg)
{
	dlg_t* td =NULL;

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

	td->loc_uri = dlg->from_uri;
	td->rem_uri = dlg->to_uri;
	td->loc_dname = dlg->from_dname;
	td->rem_dname = dlg->to_dname;

	if(leg)
	{
		if(leg->route_set.s && leg->route_set.len)
		{
			if(parse_rr_body(leg->route_set.s, leg->route_set.len,
				&td->route_set)< 0)
			{
				LM_ERR("failed to parse record route body\n");
				goto error;
			}
		}

		td->id.rem_tag = leg->tag;

		LM_DBG("Rem_target = %.*s\n", leg->contact.len, leg->contact.s);
		td->rem_target = leg->contact;
	}
	td->state= DLG_CONFIRMED ;
	td->send_sock = dlg->send_sock;
	if(dlg->send_sock)
		LM_DBG("send sock= %.*s\n", dlg->send_sock->address_str.len,
			dlg->send_sock->address_str.s);

	return td;
error:
	if(td)
		pkg_free(td);

	return 0;
}

