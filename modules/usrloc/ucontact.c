/*
 * Usrloc contact structure
 *
 * Copyright (C) 2001-2003 FhG Fokus
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
 * ---------
 * 2003-03-12 added replication mark and three zombie states (nils)
 * 2004-03-17 generic callbacks added (bogdan)
 * 2004-06-07 updated to the new DB api (andrei)
 */

/*! \file
 *  \brief USRLOC - Usrloc contact structure
 *  \ingroup usrloc
 */

#include "ucontact.h"
#include <string.h>             /* memcpy */
#include "../../parser/parse_uri.h"
#include "../../parser/parse_rr.h"
#include "../../mem/shm_mem.h"
#include "../../ut.h"
#include "../../ip_addr.h"
#include "../../socket_info.h"
#include "../../dprint.h"
#include "../../db/db.h"
#include "../../db/db_insertq.h"

#include "ul_mod.h"
#include "ul_callback.h"
#include "urecord.h"
#include "ucontact.h"
#include "ul_cluster.h"
#include "ul_timer.h"
#include "ul_evi.h"
#include "udomain.h"
#include "dlist.h"
#include "utime.h"
#include "usrloc.h"
#include "kv_store.h"

/*
 * Determines the IP address of the next hop on the way to given contact based
 * on following URIs: path URI -> received URI -> contact URI
 *
 * @contact:     input/output param; results are written in contact->next_hop
 */
static int compute_next_hop(ucontact_t *contact)
{
	str uri = {0,0};
	struct sip_uri puri;

	if (contact->path.s && contact->path.len > 0) {
		if (get_path_dst_uri(&contact->path, &uri) < 0) {
			LM_ERR("failed to get dst_uri for Path '%.*s'\n",
			        contact->path.len, contact->path.s);
			return -1;
		}

	} else if (contact->received.s && contact->received.len > 0)
		uri = contact->received;
	else if (contact->c.s && contact->c.len > 0)
		uri = contact->c;

	if (parse_uri(uri.s, uri.len, &puri) < 0) {
		LM_ERR("failed to parse URI of next hop: '%.*s'\n", uri.len, uri.s);
		return -1;
	}

	memset(&contact->next_hop, 0, sizeof contact->next_hop);

	contact->next_hop.port  = puri.port_no;
	contact->next_hop.proto = puri.proto;
	contact->next_hop.name  = puri.host;

	return 0;
}


/*! \brief
 * Create a new contact structure
 */
ucontact_t*
new_ucontact(str* _dom, str* _aor, str* _contact, ucontact_info_t* _ci)
{
	struct sip_uri ct_uri;
	ucontact_t *c;
	int_str_t shtag, *shtagp;

	c = (ucontact_t*)shm_malloc(sizeof(ucontact_t));
	if (!c) {
		LM_ERR("no more shm memory\n");
		return NULL;
	}
	memset(c, 0, sizeof(ucontact_t));

	if (have_mem_storage()) {
		if (!ZSTRP(_ci->packed_kv_storage))
			c->kv_storage = store_deserialize(_ci->packed_kv_storage);
		else
			c->kv_storage = map_create(AVLMAP_SHARED);

		if (!c->kv_storage)
			goto mem_error;
	}

	if (parse_uri(_contact->s, _contact->len, &ct_uri) < 0) {
		LM_ERR("contact [%.*s] is not valid! Will not store it!\n",
			  _contact->len, _contact->s);
		goto out_free;
	}

	if (shm_str_dup( &c->c, _contact) < 0) goto mem_error;
	if (shm_str_dup( &c->callid, _ci->callid) < 0) goto mem_error;

	/* an additional null byte may be needed by "regexec" later on */
	if (shm_nt_str_dup( &c->user_agent, _ci->user_agent) < 0) goto mem_error;

	if (_ci->received.s && _ci->received.len) {
		if (shm_str_dup( &c->received, &_ci->received) < 0) goto mem_error;
	}

	if (_ci->instance.s && _ci->instance.len) {
		if (shm_str_dup( &c->instance, &_ci->instance) < 0) goto mem_error;
	}

	if (_ci->path && _ci->path->len) {
		if (shm_str_dup( &c->path, _ci->path) < 0) goto mem_error;
	}

	if (_ci->attr && _ci->attr->len) {
		if (shm_str_dup( &c->attr, _ci->attr) < 0) goto mem_error;
	}

	if (_ci->cdb_key.s && _ci->cdb_key.len) {
		if (shm_str_dup( &c->cdb_key, &_ci->cdb_key) < 0) goto mem_error;
	}

	if (_ci->shtag.s) {
		if (shm_str_dup(&c->shtag, &_ci->shtag) < 0)
			goto mem_error;

		shtag.is_str = 1;
		shtag.s = _ci->shtag;
		if (!kv_put(c->kv_storage, &ul_shtag_key, &shtag))
			goto mem_error;
	} else if (have_mem_storage()) {
		shtagp = kv_get(c->kv_storage, &ul_shtag_key);
		if (shtagp && shm_str_dup(&c->shtag, &shtagp->s) < 0)
			goto mem_error;
	}

	get_act_time();

	c->domain = _dom;
	c->aor = _aor;
	c->expires = _ci->expires;
	c->expires_in = _ci->expires - act_time;
	c->expires_out = _ci->expires_out;
	c->refresh_time = _ci->refresh_time;
	c->q = _ci->q;
	c->sock = _ci->sock;
	c->cseq = _ci->cseq;
	c->state = CS_NEW;
	c->flags = _ci->flags;
	c->cflags = _ci->cflags;
	c->methods = _ci->methods;
	c->last_modified = _ci->last_modified;
	c->label = CID_GET_CLABEL(_ci->contact_id);
	c->contact_id = _ci->contact_id;

	if (compute_next_hop(c) != 0) {
		LM_ERR("failed to resolve next hop\n");
		goto out_free;
	}

	INIT_LIST_HEAD(&c->refresh_list);
	if (c->refresh_time)
		start_refresh_timer(c);

	return c;

mem_error:
	LM_ERR("no more shm memory\n");

out_free:
	if (c->path.s) shm_free(c->path.s);
	if (c->received.s) shm_free(c->received.s);
	if (c->user_agent.s) shm_free(c->user_agent.s);
	if (c->callid.s) shm_free(c->callid.s);
	if (c->c.s) shm_free(c->c.s);
	if (c->instance.s) shm_free(c->instance.s);
	if (c->attr.s) shm_free(c->attr.s);
	if (c->cdb_key.s) shm_free(c->cdb_key.s);
	if (c->shtag.s) shm_free(c->shtag.s);
	if (c->kv_storage) store_destroy(c->kv_storage);
	shm_free(c);
	return NULL;
}



/*! \brief
 * Free all memory associated with given contact structure
 */
void free_ucontact(ucontact_t* _c)
{
	if (!_c) return;

	if (_c->flags & FL_EXTRA_HOP)
		goto skip_fields;

	if (_c->path.s) shm_free(_c->path.s);
	if (_c->received.s) shm_free(_c->received.s);
	if (_c->instance.s) shm_free(_c->instance.s);
	if (_c->user_agent.s) shm_free(_c->user_agent.s);
	if (_c->callid.s) shm_free(_c->callid.s);
	if (_c->c.s) shm_free(_c->c.s);
	if (_c->attr.s) shm_free(_c->attr.s);
	if (_c->cdb_key.s) shm_free(_c->cdb_key.s);
	if (_c->shtag.s) shm_free(_c->shtag.s);
	if (_c->kv_storage) store_destroy(_c->kv_storage);

skip_fields:
	shm_free( _c );
}


/*! \brief
 * Update ucontact structure in memory
 */
int mem_update_ucontact(ucontact_t* _c, ucontact_info_t* _ci)
{
	/* "user_agent" must be null-terminated (see e5cb9805b) */
#define update_str(_old,_new,_nt) \
	do{\
		if ((_old)->len < (_new)->len) { \
			ptr = shm_malloc((_new)->len + ((_nt) ? 1 : 0)); \
			if (ptr == 0) \
				goto out_oom; \
			memcpy(ptr, (_new)->s, (_new)->len);\
			if ((_old)->s) shm_free((_old)->s);\
			(_old)->s = ptr;\
		} else {\
			memcpy((_old)->s, (_new)->s, (_new)->len);\
		}\
		(_old)->len = (_new)->len;\
		if (_nt) \
			(_old)->s[(_old)->len] = '\0'; \
	} while(0)

	char* ptr;
	int_str_t shtag, *shtagp;

	/* RFC 3261 states 'All registrations from a UAC SHOULD use
	 * the same Call-ID header field value for registrations sent
	 * to a particular registrar.', but it is not a 'MUST'. So
	 * always update the call ID to be safe. */
	update_str( &_c->callid, _ci->callid, 0);

	update_str( &_c->user_agent, _ci->user_agent, 1);

	if (_ci->c)
		update_str( &_c->c, _ci->c, 0);

	if (_ci->received.s && _ci->received.len) {
		update_str( &_c->received, &_ci->received, 0);
	} else {
		if (_c->received.s) shm_free(_c->received.s);
		_c->received.s = NULL;
		_c->received.len = 0;
	}

	if (_ci->path) {
		update_str( &_c->path, _ci->path, 0);
	} else {
		if (_c->path.s) shm_free(_c->path.s);
		_c->path.s = NULL;
		_c->path.len = 0;
	}

	if (_ci->attr && _ci->attr->s && _ci->attr->len) {
		update_str( &_c->attr, _ci->attr, 0);
	} else {
		if (_c->attr.s) shm_free(_c->attr.s);
		_c->attr.s = NULL;
		_c->attr.len = 0;
	}

	get_act_time();

	_c->sock = _ci->sock;
	_c->expires = _ci->expires;
	_c->expires_in = _ci->expires - act_time;
	_c->expires_out = _ci->expires_out;
	_c->refresh_time = _ci->refresh_time;
	_c->q = _ci->q;
	_c->cseq = _ci->cseq;
	_c->methods = _ci->methods;
	_c->last_modified = _ci->last_modified;
	_c->flags = _ci->flags;
	_c->cflags = _ci->cflags;

	if (have_mem_storage()) {
		if (!ZSTRP(_ci->packed_kv_storage)) {
			if (_c->kv_storage)
				store_destroy(_c->kv_storage);

			_c->kv_storage = store_deserialize(_ci->packed_kv_storage);
			if (!_c->kv_storage)
				goto out_oom;
		}
	}

	if (_ci->shtag.s) {
		update_str(&_c->shtag, &_ci->shtag, 0);

		shtag.is_str = 1;
		shtag.s = _ci->shtag;
		if (!kv_put(_c->kv_storage, &ul_shtag_key, &shtag))
			goto out_oom;
	} else if (have_mem_storage()) {
		shtagp = kv_get(_c->kv_storage, &ul_shtag_key);
		if (shtagp) {
			update_str(&_c->shtag, &shtagp->s, 0);
		} else {
			if (_c->shtag.s)
				shm_free(_c->shtag.s);

			_c->shtag.s = NULL;
			_c->shtag.len = 0;

			kv_del(_c->kv_storage, &ul_shtag_key);
		}
	}

	if (compute_next_hop(_c) != 0)
		LM_ERR("failed to resolve next hop. keeping old one - '%.*s'\n",
		        _c->next_hop.name.len, _c->next_hop.name.s);

	if (_c->refresh_time)
		start_refresh_timer(_c);

	ul_raise_contact_event(ei_c_update_id, _c);

	return 0;

out_oom:
	LM_ERR("oom\n");
	return -1;
}


/* ================ State related functions =============== */


/*! \brief
 * Update state of the contact
 */
void st_update_ucontact(ucontact_t* _c)
{
	switch(_c->state) {
	case CS_NEW:
			 /* Contact is new and is not in the database yet,
			  * we remain in the same state here because the
			  * contact must be inserted later in the timer
			  */
		break;

	case CS_SYNC:
			 /* For db mode 1 & 2 & 3 a modified contact needs to be
			  * updated also in the database, so transit into
			  * CS_DIRTY and let the timer to do the update
			  * again. For db mode 1 we try to update right
			  * now and if fails, let the timer to do the job
			  */
		if (cluster_mode != CM_NONE || rr_persist == RRP_LOAD_FROM_SQL) {
			_c->state = CS_DIRTY;
		}
		break;

	case CS_DIRTY:
			 /* Modification of dirty contact results in
			  * dirty contact again, don't change anything
			  */
		break;
	}
}


/*! \brief
 * Update state of the contact
 * \return 1 if the contact should be deleted from memory immediately,
 * 0 otherwise
 */
int st_delete_ucontact(ucontact_t* _c)
{
	switch(_c->state) {
	case CS_NEW:
		     /* Contact is new and isn't in the database
		      * yet, we can delete it from the memory
		      * safely.
		      */
		return 1;

	case CS_SYNC:
	case CS_DIRTY:
		     /* Contact is in the database,
		      * we cannot remove it from the memory
		      * directly, but we can set expires to zero
		      * and the timer will take care of deleting
		      * the contact from the memory as well as
		      * from the database
		      */
		if (sql_wmode != SQL_WRITE_THROUGH) {
			_c->expires = UL_EXPIRED_TIME;
			return 0;
		} else {
			     /* WRITE_THROUGH -- we can
			      * remove it from memory immediately and
			      * the calling function would also remove
			      * it from the database if needed
			      */
			return 1;
		}
	}

	return 0; /* Makes gcc happy */
}


/*! \brief
 * Called when the timer is about to delete
 * an expired contact.
 * \return 1 if the contact should be removed from
 * the database and 0 otherwise
 */
int st_expired_ucontact(ucontact_t* _c)
{
	     /* There is no need to change contact
	      * state, because the contact will
	      * be deleted anyway
	      */

	switch(_c->state) {
	case CS_NEW:
		     /* Contact is not in the database
		      * yet, remove it from memory only
		      */
		return 0;

	case CS_SYNC:
	case CS_DIRTY:
		     /* Remove from database here */
		return 1;
	}

	return 0; /* Makes gcc happy */
}


/*! \brief
 * Called when the timer is about flushing the contact,
 * updates contact state and returns 1 if the contact
 * should be inserted, 2 if update and 0 otherwise
 */
int st_flush_ucontact(ucontact_t* _c)
{
	switch(_c->state) {
	case CS_NEW:
		     /* Contact is new and is not in
		      * the database yet so we have
		      * to insert it
		      */
		_c->state = CS_SYNC;
		return 1;

	case CS_SYNC:
		     /* Contact is synchronized, do
		      * nothing
		      */
		return 0;

	case CS_DIRTY:
		     /* Contact has been modified and
		      * is in the db already so we
		      * have to update it
		      */
		_c->state = CS_SYNC;
		return 2;
	}

	return 0; /* Makes gcc happy */
}


/* ============== Database related functions ================ */

/*! \brief
 * Insert contact into the database
 */
int db_insert_ucontact(ucontact_t* _c,query_list_t **ins_list, int update)
{
	int nr_vals = UL_COLS - 1;
	int start = 0;

	static db_ps_t myI_ps = NULL;
	static db_ps_t myR_ps = NULL;
	char* dom;
	db_key_t keys[UL_COLS];
	db_val_t vals[UL_COLS];

	if (_c->flags & FL_MEM) {
		return 0;
	}

	/* in CM_SQL_ONLY, we let the SQL engine auto-generate the ucontact_id */
	if (cluster_mode == CM_SQL_ONLY) {
		start++;
		nr_vals--;
	}

	keys[0] = &contactid_col;
	keys[1] = &user_col;
	keys[2] = &contact_col;
	keys[3] = &expires_col;
	keys[4] = &q_col;
	keys[5] = &callid_col;
	keys[6] = &cseq_col;
	keys[7] = &flags_col;
	keys[8] = &cflags_col;
	keys[9] = &user_agent_col;
	keys[10] = &received_col;
	keys[11] = &path_col;
	keys[12] = &sock_col;
	keys[13] = &methods_col;
	keys[14] = &last_mod_col;
	keys[15] = &sip_instance_col;
	keys[16] = &kv_store_col;
	keys[17] = &attr_col;
	keys[UL_COLS - 1] = &domain_col; /* "domain" always stays last */

	memset(vals, 0, sizeof vals);

	vals[0].type = DB_BIGINT;
	vals[0].val.bigint_val = _c->contact_id;

	vals[1].type = DB_STR;
	vals[1].val.str_val.s = _c->aor->s;
	vals[1].val.str_val.len = _c->aor->len;

	vals[2].type = DB_STR;
	vals[2].val.str_val.s = _c->c.s;
	vals[2].val.str_val.len = _c->c.len;

	vals[3].type = DB_INT;
	vals[3].val.int_val = _c->expires;

	vals[4].type = DB_DOUBLE;
	vals[4].val.double_val = q2double(_c->q);

	vals[5].type = DB_STR;
	vals[5].val.str_val.s = _c->callid.s;
	vals[5].val.str_val.len = _c->callid.len;

	vals[6].type = DB_INT;
	vals[6].val.int_val = _c->cseq;

	vals[7].type = DB_INT;
	vals[7].val.bitmap_val = _c->flags;

	vals[8].type = DB_STR;
	vals[8].val.str_val = bitmask_to_flag_list(FLAG_TYPE_BRANCH, _c->cflags);

	vals[9].type = DB_STR;
	vals[9].val.str_val.s = _c->user_agent.s;
	vals[9].val.str_val.len = _c->user_agent.len;

	vals[10].type = DB_STR;
	if (_c->received.s == 0) {
		vals[10].nul = 1;
	} else {
		vals[10].val.str_val.s = _c->received.s;
		vals[10].val.str_val.len = _c->received.len;
	}

	vals[11].type = DB_STR;
	if (_c->path.s == 0) {
		vals[11].nul = 1;
	} else {
		vals[11].val.str_val.s = _c->path.s;
		vals[11].val.str_val.len = _c->path.len;
	}

	vals[12].type = DB_STR;
	if (_c->sock) {
		vals[12].val.str_val =  _c->sock->adv_sock_str.len ?
								_c->sock->adv_sock_str:  _c->sock->sock_str;
	} else {
		vals[12].nul = 1;
	}

	vals[13].type = DB_BITMAP;
	if (_c->methods == 0xFFFFFFFF) {
		vals[13].nul = 1;
	} else {
		vals[13].val.bitmap_val = _c->methods;
	}

	vals[14].type = DB_DATETIME;
	vals[14].val.time_val = _c->last_modified;

	vals[15].type = DB_STR;
	if (_c->instance.s == 0) {
		vals[15].nul = 1;
	} else {
		vals[15].val.str_val.s = _c->instance.s;
		vals[15].val.str_val.len = _c->instance.len;
	}

	vals[16].type = DB_STR;
	if (!_c->kv_storage || map_size(_c->kv_storage) == 0) {
		LM_DBG("zero map size\n");
		vals[16].nul = 1;
	} else {
		vals[16].val.str_val = store_serialize(_c->kv_storage);
		if (ZSTR(vals[16].val.str_val))
			vals[16].nul = 1;
	}

	vals[17].type = DB_STR;
	if (_c->attr.s == 0) {
		vals[17].nul = 1;
	} else {
		vals[17].val.str_val.s = _c->attr.s;
		vals[17].val.str_val.len = _c->attr.len;
	}

	if (use_domain) {
		vals[UL_COLS - 1].type = DB_STR;

		dom = q_memchr(_c->aor->s, '@', _c->aor->len);
		if (dom==0) {
			vals[1].val.str_val.len = 0;
			vals[UL_COLS - 1].val.str_val = *_c->aor;
		} else {
			vals[1].val.str_val.len = dom - _c->aor->s;
			vals[UL_COLS - 1].val.str_val.s = dom + 1;
			vals[UL_COLS - 1].val.str_val.len =
			         _c->aor->s + _c->aor->len - dom - 1;
		}

		nr_vals++;
	}

	if (ul_dbf.use_table(ul_dbh, _c->domain) < 0) {
		LM_ERR("sql use_table failed\n");
		goto out_err;
	}

	if ( !update ) {
		/* do simple insert */
		CON_PS_REFERENCE(ul_dbh) = &myI_ps;
		if (ins_list) {
			if (con_set_inslist(&ul_dbf,ul_dbh,ins_list,keys + start,
						nr_vals) < 0 )
				CON_RESET_INSLIST(ul_dbh);
		}

		if (ul_dbf.insert(ul_dbh, keys + start, vals + start, nr_vals) < 0) {
			LM_ERR("inserting contact in db failed\n");
			goto out_err;
		}
	} else {
		/* do insert-update / replace */
		CON_PS_REFERENCE(ul_dbh) = &myR_ps;
		if (ul_dbf.insert_update(ul_dbh, keys + start, vals + start, nr_vals) < 0) {
			LM_ERR("inserting contact in db failed\n");
			goto out_err;
		}
	}

	store_free_buffer(&vals[16].val.str_val);
	return 0;
out_err:
	store_free_buffer(&vals[16].val.str_val);
	return -1;
}


/*! \brief
 * Update contact in the database
 */
int db_update_ucontact(ucontact_t* _c)
{
	static db_ps_t my_ps = NULL;
	db_key_t keys1[1];
	db_val_t vals1[1];
	db_key_t keys2[15];
	db_val_t vals2[15];

	if (_c->flags & FL_MEM) {
		return 0;
	}

	memset(vals1, 0, sizeof vals1);

	keys1[0] = &contactid_col;
	vals1[0].type = DB_BIGINT;
	vals1[0].val.bigint_val = _c->contact_id;

	keys2[0] = &contactid_col;
	keys2[1] = &expires_col;
	keys2[2] = &q_col;
	keys2[3] = &cseq_col;
	keys2[4] = &flags_col;
	keys2[5] = &cflags_col;
	keys2[6] = &user_agent_col;
	keys2[7] = &received_col;
	keys2[8] = &path_col;
	keys2[9] = &sock_col;
	keys2[10] = &methods_col;
	keys2[11] = &last_mod_col;
	keys2[12] = &kv_store_col;
	keys2[13] = &attr_col;

	memset(vals2, 0, sizeof vals2);

	vals2[0].type = DB_BIGINT;
	vals2[0].val.bigint_val = _c->contact_id;

	vals2[1].type = DB_INT;
	vals2[1].val.int_val = _c->expires;

	vals2[2].type = DB_DOUBLE;
	vals2[2].val.double_val = q2double(_c->q);

	vals2[3].type = DB_INT;
	vals2[3].val.int_val = _c->cseq;

	vals2[4].type = DB_BITMAP;
	vals2[4].val.bitmap_val = _c->flags;

	vals2[5].type = DB_STR;
	vals2[5].val.str_val = bitmask_to_flag_list(FLAG_TYPE_BRANCH, _c->cflags);

	vals2[6].type = DB_STR;
	vals2[6].val.str_val = _c->user_agent;

	vals2[7].type = DB_STR;
	if (_c->received.s == 0) {
		vals2[7].nul = 1;
	} else {
		vals2[7].val.str_val = _c->received;
	}

	vals2[8].type = DB_STR;
	if (_c->path.s == 0) {
		vals2[8].nul = 1;
	} else {
		vals2[8].val.str_val = _c->path;
	}

	vals2[9].type = DB_STR;
	if (_c->sock) {
		vals2[9].val.str_val = _c->sock->adv_sock_str.len ?
								_c->sock->adv_sock_str:  _c->sock->sock_str;
	} else {
		vals2[9].nul = 1;
	}

	vals2[10].type = DB_BITMAP;
	if (_c->methods == 0xFFFFFFFF) {
		vals2[10].nul = 1;
	} else {
		vals2[10].val.bitmap_val = _c->methods;
	}

	vals2[11].type = DB_DATETIME;
	vals2[11].val.time_val = _c->last_modified;

	vals2[12].type = DB_STR;
	if (!_c->kv_storage || map_size(_c->kv_storage) == 0) {
		vals2[12].nul = 1;
	} else {
		vals2[12].val.str_val = store_serialize(_c->kv_storage);
		if (ZSTR(vals2[12].val.str_val))
			vals2[12].nul = 1;
	}

	vals2[13].type = DB_STR;
	if (_c->attr.s == 0) {
		vals2[13].nul = 1;
	} else {
		vals2[13].val.str_val = _c->attr;
	}

	/* callid is part of the update */
	keys2[14] = &callid_col;
	vals2[14].type = DB_STR;
	vals2[14].nul = 0;
	vals2[14].val.str_val = _c->callid;

	if (ul_dbf.use_table(ul_dbh, _c->domain) < 0) {
		LM_ERR("sql use_table failed\n");
		goto out_err;
	}

	CON_PS_REFERENCE(ul_dbh) = &my_ps;

	if (ul_dbf.update(ul_dbh, keys1, 0, vals1, keys2, vals2, 1, 15)<0) {
		LM_ERR("updating database failed\n");
		goto out_err;
	}

	store_free_buffer(&vals2[12].val.str_val);
	return 0;
out_err:
	store_free_buffer(&vals2[12].val.str_val);
	return -1;
}




/*! \brief
 * Delete contact from the database
 */
int db_delete_ucontact(ucontact_t* _c)
{
	static db_ps_t my_ps = NULL;
	db_key_t keys[1];
	db_val_t vals[1];

	if (_c->flags & FL_MEM)
		return 0;

	keys[0] = &contactid_col;

	VAL_TYPE(vals) = DB_BIGINT;
	VAL_NULL(vals) = 0;
	VAL_BIGINT(vals) = (long long)_c->contact_id;

	if (ul_dbf.use_table(ul_dbh, _c->domain) < 0) {
		LM_ERR("sql use_table failed\n");
		return -1;
	}

	CON_PS_REFERENCE(ul_dbh) = &my_ps;

	if (ul_dbf.delete(ul_dbh, keys, 0, vals, 1) < 0) {
		LM_ERR("deleting from database failed\n");
		return -1;
	}

	return 0;
}

/*
 * Delete multiple contacts from the database
 * having the cids; cids are stored in vals param
 * WARNING: FL_MEM flag for a contact MUST be checked before
 * append a contact id to cids list */
int db_multiple_ucontact_delete(str *domain, db_key_t *keys,
											db_val_t *vals, int clen)
{
	if (keys == NULL || vals == NULL) {
		LM_ERR("null params\n");
		return -1;
	}

	if (ul_dbf.use_table(ul_dbh, domain) < 0) {
		LM_ERR("sql use_table failed\n");
		return -1;
	}

	CON_USE_OR_OP(ul_dbh);

	if (ul_dbf.delete(ul_dbh, keys, 0, vals, clen) < 0) {
		LM_ERR("deleting from database failed\n");
		return -1;
	}

	return 0;
}


static inline void unlink_contact(struct urecord* _r, ucontact_t* _c)
{
	if (_c->prev) {
		_c->prev->next = _c->next;
		if (_c->next) {
			_c->next->prev = _c->prev;
		}
	} else {
		_r->contacts = _c->next;
		if (_c->next) {
			_c->next->prev = 0;
		}
	}
}


static inline void update_contact_pos(struct urecord* _r, ucontact_t* _c)
{
	ucontact_t *pos, *ppos;

	if (desc_time_order) {
		/* order by time - first the newest */
		if (_c->prev==0)
			return;
		unlink_contact(_r, _c);
		/* insert it at the beginning */
		_c->next = _r->contacts;
		_c->prev = 0;
		_r->contacts->prev = _c;
		_r->contacts = _c;
	} else {
		/* order by q - first the smaller q */
		if ( (_c->prev==0 || _c->q<=_c->prev->q)
		&& (_c->next==0 || _c->q>=_c->next->q)  )
			return;
		/* need to move , but where? */
		unlink_contact(_r, _c);
		_c->next = _c->prev = 0;
		for(pos=_r->contacts,ppos=0;pos&&pos->q<_c->q;ppos=pos,pos=pos->next);
		if (pos) {
			if (!pos->prev) {
				pos->prev = _c;
				_c->next = pos;
				_r->contacts = _c;
			} else {
				_c->next = pos;
				_c->prev = pos->prev;
				pos->prev->next = _c;
				pos->prev = _c;
			}
		} else if (ppos) {
			ppos->next = _c;
			_c->prev = ppos;
		} else {
			_r->contacts = _c;
		}
	}
}


/*! \brief
 * Update ucontact with new values
 */
int update_ucontact(struct urecord* _r, ucontact_t* _c, ucontact_info_t* _ci,
                    const struct ct_match *match, char skip_replication)
{
	int ret, persist_kv_store = 1;

	/* we have to update memory in any case, but database directly
	 * only in sql_wmode SQL_WRITE_THROUGH */
	if (mem_update_ucontact(_c, _ci) < 0) {
		LM_ERR("failed to update memory\n");
		return -1;
	}

	if (skip_replication && _c->kv_storage)
		restore_urecord_kv_store(_r, _c);

	if (!skip_replication && have_data_replication()) {
		if (persist_urecord_kv_store(_r) != 0)
			LM_ERR("failed to persist latest urecord K/V storage\n");
		else
			persist_kv_store = 0;

		replicate_ucontact_update(_r, _c, match);
	}

	/* run callbacks for UPDATE event */
	if (exists_ulcb_type(UL_CONTACT_UPDATE))
	{
		LM_DBG("exists callback for type= UL_CONTACT_UPDATE\n");
		run_ul_callbacks( UL_CONTACT_UPDATE, _c);
	}

	if (have_mem_storage())
		update_contact_pos( _r, _c);

	st_update_ucontact(_c);

	if (sql_wmode == SQL_WRITE_THROUGH) {
		if (persist_kv_store && persist_urecord_kv_store(_r) != 0)
			LM_ERR("failed to persist latest urecord K/V storage\n");

		ret = db_update_ucontact(_c) ;
		if (ret < 0) {
			LM_ERR("failed to update database\n");
		} else {
			_c->state = CS_SYNC;
		}
	}
	return 0;
}

int ucontact_coords_cmp(ucontact_coords _a, ucontact_coords _b)
{
	ucontact_sip_coords *a, *b;

	if (cluster_mode != CM_FULL_SHARING_CACHEDB)
		return _a == _b ? 0 : -1;

	a = (ucontact_sip_coords *)(unsigned long)_a;
	b = (ucontact_sip_coords *)(unsigned long)_b;

	if (!str_match(&a->aor, &b->aor) || !str_match(&a->ct_key, &b->ct_key))
		return -1;

	return 0;
}

void free_ucontact_coords(ucontact_coords coords)
{
	if (cluster_mode == CM_FULL_SHARING_CACHEDB)
		shm_free((ucontact_sip_coords *)(unsigned long)coords);
}

int_str_t *get_ucontact_key(ucontact_t* _ct, const str* _key)
{
	return kv_get(_ct->kv_storage, _key);
}

int_str_t *put_ucontact_key(ucontact_t* _ct, const str* _key,
                            const int_str_t* _val)
{
	return kv_put(_ct->kv_storage, _key, _val);
}

int is_my_ucontact(ucontact_t *c)
{
	return _is_my_ucontact(c);
}
