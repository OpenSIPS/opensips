/*
 * $Id$
 *
 * registrant module
 *
 * Copyright (C) 2011 VoIP Embedded Inc.
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
 *  2011-02-11  initial version (Ovidiu Sas)
 */

#include <stdio.h>
#include <stdlib.h>

#include "reg_records.h"

extern unsigned int default_expires;

static char call_id_ftag_buf[MD5_LEN];


void reg_print_record(reg_record_t *rec) {
	LM_DBG("checking uac=[%p] state=[%d] expires=[%d]"
			" last_register_sent=[%d] registration_timeout=[%d]"
			" auth_user[%p][%d]->[%.*s] auth_password=[%p][%d]->[%.*s] sock=[%p]\n",
		rec, rec->state, rec->expires,
		(unsigned int)rec->last_register_sent, (unsigned int)rec->registration_timeout,
		rec->auth_user.s, rec->auth_user.len, rec->auth_user.len, rec->auth_user.s,
		rec->auth_password.s, rec->auth_password.len,
		rec->auth_password.len, rec->auth_password.s, rec->td.send_sock);
	LM_DBG("    RURI=[%p][%d]->[%.*s]\n", rec->td.rem_target.s, rec->td.rem_target.len,
			rec->td.rem_target.len, rec->td.rem_target.s);
	LM_DBG("      To=[%p][%d]->[%.*s]\n", rec->td.rem_uri.s, rec->td.rem_uri.len,
			rec->td.rem_uri.len, rec->td.rem_uri.s);
	LM_DBG("    From=[%p][%d]->[%.*s] tag=[%p][%d]->[%.*s]\n",
			rec->td.loc_uri.s, rec->td.loc_uri.len,
			rec->td.loc_uri.len, rec->td.loc_uri.s,
			rec->td.id.loc_tag.s, rec->td.id.loc_tag.len,
			rec->td.id.loc_tag.len, rec->td.id.loc_tag.s);
	LM_DBG(" Call-Id=[%p][%d]->[%.*s]\n", rec->td.id.call_id.s, rec->td.id.call_id.len,
			rec->td.id.call_id.len, rec->td.id.call_id.s);
	LM_DBG(" Contact=[%p][%d]->[%.*s] [%p][%d]->[%.*s]\n",
			rec->contact_uri.s, rec->contact_uri.len,
			rec->contact_uri.len, rec->contact_uri.s,
			rec->contact_params.s, rec->contact_params.len,
			rec->contact_params.len, rec->contact_params.s);
	if (rec->td.obp.s && rec->td.obp.len) {
		LM_DBG(" Proxy=[%p][%d]->[%.*s]\n",
			rec->td.obp.s, rec->td.obp.len, rec->td.obp.len, rec->td.obp.s);
	}

	return;
}


static void gen_call_id_ftag(str *aor, str *now, str *call_id_ftag)
{
	int i = 0;
	str src[2];

	call_id_ftag->len = MD5_LEN;
	call_id_ftag->s = call_id_ftag_buf;

	src[i++] = *aor;
	if(now->s && now->len)
		src[i++] = *now;

	MD5StringArray(call_id_ftag->s, src, i);
	return;
}


void new_call_id_ftag_4_record(reg_record_t *rec, str *now)
{
	str call_id_ftag;
	char *p = (char *)(rec + 1);

	/* generate the new Call-ID and From tag */
	gen_call_id_ftag(&rec->td.rem_uri, now, &call_id_ftag);
	memcpy(p, call_id_ftag.s, call_id_ftag.len);

	/* reset the CSeq for the new Call-ID/ftag */
	rec->td.loc_seq.value = 0;
	//rec->td.loc_seq.is_set = 1;

	return;
}


int add_record(uac_reg_map_t *uac, str *now)
{
	reg_record_t *rec, *prev_rec, *record;
	unsigned int size, expires;
	dlg_t *td;
	str call_id_ftag;
	char *p;

	if (uac->expires.s && uac->expires.len) {
		if (str2int(&uac->expires, &expires)<0) {
			LM_ERR("unable to get expiry from [%.*s]\n",
				uac->expires.len, uac->expires.s);
			return -1;
		}
	} else {
		expires = default_expires;
	}

	/* Reserve space for record */
	size = sizeof(reg_record_t) + MD5_LEN +
		uac->to_uri.len + uac->from_uri.len + uac->registrar_uri.len +
		uac->auth_user.len + uac->auth_password.len +
		uac->contact_uri.len + uac->contact_params.len + uac->proxy_uri.len;
	record = (reg_record_t *)shm_malloc(size);
	if(!record) {
		LM_ERR("oom\n");
		return -1;
	}
	memset(record, 0, size);

	record->expires = expires;

	td = &(record->td);
	p = (char *)(record + 1);

	/* Setting the td->id */
	gen_call_id_ftag(&uac->to_uri, now, &call_id_ftag);
	memcpy(p, call_id_ftag.s, call_id_ftag.len);
	td->id.call_id.s = p;
	td->id.call_id.len = MD5_LEN - 5;
	td->id.loc_tag.s = p + MD5_LEN - 5;
	td->id.loc_tag.len = 5;
	p += MD5_LEN;

	//td->id.rem_tag.s = NULL;
	//td->id.rem_tag.len = 0;

	/* Setting the CSeq */
	td->loc_seq.value = 0;
	td->loc_seq.is_set = 1;
	//td->loc_seq.rem_tag.s = NULL;
	//td->loc_seq.rem_tag.len = 0;

	/* Setting the remote URI */
	td->rem_uri.s = p;
	td->rem_uri.len = uac->to_uri.len;
	memcpy(p, uac->to_uri.s, uac->to_uri.len);
	p += uac->to_uri.len;

	/* Setting the outbound proxy */
	if (uac->proxy_uri.s && uac->proxy_uri.len) {
		td->obp.s = p;
		td->obp.len = uac->proxy_uri.len;
		memcpy(p, uac->proxy_uri.s, uac->proxy_uri.len);
		p += uac->proxy_uri.len;
	}

	/* Setting the local URI */
	if(uac->from_uri.s && uac->from_uri.len) {
		LM_DBG("got from [%.*s]\n", uac->from_uri.len, uac->from_uri.s);
		td->loc_uri.s = p;
		td->loc_uri.len = uac->from_uri.len;
		memcpy(p, uac->from_uri.s, uac->from_uri.len);
		p += uac->from_uri.len;
	} else {
		td->loc_uri.s = td->rem_uri.s;
		td->loc_uri.len = td->rem_uri.len;
	}

	/* Setting the Remote target URI */
	td->rem_target.s = p;
	td->rem_target.len = uac->registrar_uri.len;
	memcpy(p, uac->registrar_uri.s, uac->registrar_uri.len);
	p += uac->registrar_uri.len;

	/* Setting the Local/Remote Display Name */
	//td->loc_dname.s = td->rem_dname.s = NULL;
	//td->loc_dname.len = td->rem_dname.len = 0;

	//td->T_flags = 0;
	td->state = DLG_CONFIRMED;

	/* Setting the Route set */
	//td->route_set = NULL;
	/* Setting the hooks */
	//td->hooks <- no hooks for REGISTER
	/* Setting the socket */
	td->send_sock = uac->send_sock;
	/* Done with td */

	if (uac->auth_user.s && uac->auth_user.len) {
		record->auth_user.s = p;
		record->auth_user.len = uac->auth_user.len;
		memcpy(p, uac->auth_user.s, uac->auth_user.len);
		p += uac->auth_user.len;
	}

	if (uac->auth_password.s && uac->auth_password.len) {
		record->auth_password.s = p;
		record->auth_password.len = uac->auth_password.len;
		memcpy(p, uac->auth_password.s, uac->auth_password.len);
		p += uac->auth_password.len;
	}

	record->contact_uri.s = p;
	record->contact_uri.len = uac->contact_uri.len;
	memcpy(p, uac->contact_uri.s, uac->contact_uri.len);
	p += uac->contact_uri.len;

	if (uac->contact_params.s && uac->contact_params.len) {
		record->contact_params.s = p;
		record->contact_params.len = uac->contact_params.len;
		memcpy(p, uac->contact_params.s, uac->contact_params.len);
		p += uac->contact_params.len;
	}

	reg_print_record(record);

	rec = reg_htable[uac->hash_code].first;
	if (rec) {
		while(rec) {
			prev_rec = rec;
			rec = rec->next;
		}
		prev_rec->next = record;
		record->prev = prev_rec;
	} else {
		reg_htable[uac->hash_code].first = record;
		record->prev = record->next = NULL;
	}
	
	return 0;
}


int init_reg_htable(void) {
	int i;

	reg_htable = (reg_table_t)shm_malloc(reg_hsize * sizeof(reg_entry_t));
	if(!reg_htable) {
		LM_ERR("oom\n");
		return -1;
	}

	for(i= 0; i<reg_hsize; i++) {
		lock_init(&reg_htable[i].lock);
		reg_htable[i].first = NULL;
	}
	return 0;
}


void destroy_reg_htable(void) {
	int i;
	reg_record_t *record;

	if (reg_htable) {
		for(i=0; i<reg_hsize; i++) {
			lock_destroy(&reg_htable[i].lock);
			record = reg_htable[i].first;

			while(record) {
				//delete the record
				record = record->next;
			}
		}
		shm_free(reg_htable);
		reg_htable = NULL;
	}
}

