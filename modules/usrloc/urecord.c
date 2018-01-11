/*
 * Usrloc record structure
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
 * 2003-03-12 added replication mark and zombie state support (nils)
 * 2004-03-17 generic callbacks added (bogdan)
 * 2004-06-07 updated to the new DB api (andrei)
 */

/*! \file
 *  \brief USRLOC - Usrloc record structure
 *  \ingroup usrloc
 */


#include "urecord.h"
#include <string.h>
#include "../../mem/shm_mem.h"
#include "../../dprint.h"
#include "../../ut.h"
#include "../../hash_func.h"
#include "../../db/db_insertq.h"
#include "ul_mod.h"
#include "utime.h"
#include "ul_callback.h"
#include "ureplication.h"
#include "udomain.h"
#include "dlist.h"
#include "usrloc.h"
#include "kv_store.h"

extern int max_contact_delete;
extern db_key_t *cid_keys;
extern db_val_t *cid_vals;
extern int cid_len;

int matching_mode = CONTACT_ONLY;

int cseq_delay = 20;

extern event_id_t ei_c_ins_id;
extern event_id_t ei_c_del_id;

/*! \brief
 * Create and initialize new record structure
 */
int new_urecord(str* _dom, str* _aor, urecord_t** _r)
{
	*_r = (urecord_t*)shm_malloc(sizeof(urecord_t));
	if (*_r == 0) {
		LM_ERR("no more share memory\n");
		return -1;
	}
	memset(*_r, 0, sizeof(urecord_t));

	(*_r)->kv_storage = map_create(AVLMAP_SHARED);
	if (!(*_r)->kv_storage) {
		LM_ERR("oom\n");
		shm_free(*_r);
		*_r = NULL;
		return -1;
	}

	(*_r)->aor.s = (char*)shm_malloc(_aor->len);
	if ((*_r)->aor.s == 0) {
		LM_ERR("no more share memory\n");
		shm_free(*_r);
		*_r = NULL;
		return -1;
	}
	memcpy((*_r)->aor.s, _aor->s, _aor->len);
	(*_r)->aor.len = _aor->len;
	(*_r)->domain = _dom;
	(*_r)->aorhash = core_hash(_aor, 0, 0);

	return 0;
}


/*! \brief
 * Free all memory used by the given structure
 * The structure must be removed from all linked
 * lists first
 */
void free_urecord(urecord_t* _r)
{
	ucontact_t* ptr;

	while(_r->contacts) {
		ptr = _r->contacts;
		_r->contacts = _r->contacts->next;
		free_ucontact(ptr);
	}

	destroy_store(_r->kv_storage);

	/* if mem cache is not used, the urecord struct is static*/
	if (db_mode!=DB_ONLY) {
		if (_r->aor.s) shm_free(_r->aor.s);
		shm_free(_r);
	} else {
		_r->contacts = NULL;
	}
}


/*! \brief
 * Print a record
 */
void print_urecord(FILE* _f, urecord_t* _r)
{
	ucontact_t* ptr;

	fprintf(_f, "...Record(%p)...\n", _r);
	fprintf(_f, "domain : '%.*s'\n", _r->domain->len, ZSW(_r->domain->s));
	fprintf(_f, "aor    : '%.*s'\n", _r->aor.len, ZSW(_r->aor.s));
	fprintf(_f, "aorhash: '%u'\n", (unsigned)_r->aorhash);
	fprintf(_f, "slot:    '%d'\n", _r->aorhash&(_r->slot->d->size-1));

	if (_r->contacts) {
		ptr = _r->contacts;
		while(ptr) {
			print_ucontact(_f, ptr);
			ptr = ptr->next;
		}
	}

	fprintf(_f, ".../Record...\n");
}


/*! \brief
 * Add a new contact
 * Contacts are ordered by: 1) q
 *                          2) descending modification time
 * before calling this function one must calculate the
 * contact_id inside the ucontact_info structure
 */
ucontact_t* mem_insert_ucontact(urecord_t* _r, str* _c, ucontact_info_t* _ci)
{
	ucontact_t* ptr, *prev = 0;
	ucontact_t* c;

	if ( (c=new_ucontact(_r->domain, &_r->aor, _c, _ci)) == 0) {
		LM_ERR("failed to create new contact\n");
		return 0;
	}

	if_update_stat( _r->slot, _r->slot->d->contacts, 1);

	ptr = _r->contacts;

	if (!desc_time_order) {
		while(ptr) {
			if (ptr->q < c->q) break;
			prev = ptr;
			ptr = ptr->next;
		}
	}

	if (ptr) {
		if (!ptr->prev) {
			ptr->prev = c;
			c->next = ptr;
			_r->contacts = c;
		} else {
			c->next = ptr;
			c->prev = ptr->prev;
			ptr->prev->next = c;
			ptr->prev = c;
		}
	} else if (prev) {
		prev->next = c;
		c->prev = prev;
	} else {
		_r->contacts = c;
	}

	ul_raise_contact_event(ei_c_ins_id, c);
	return c;
}


/*! \brief
 * Remove the contact from lists
 */
void mem_remove_ucontact(urecord_t* _r, ucontact_t* _c)
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
	ul_raise_contact_event(ei_c_del_id, _c);
}



/*! \brief
 * Remove contact from the list and delete
 */
void mem_delete_ucontact(urecord_t* _r, ucontact_t* _c)
{
	mem_remove_ucontact(_r, _c);
	if_update_stat( _r->slot, _r->slot->d->contacts, -1);
	free_ucontact(_c);
}


/*! \brief
 * This timer routine is used when
 * db_mode is set to NO_DB
 */
static inline int nodb_timer(urecord_t* _r)
{
	ucontact_t* ptr, *t;

	ptr = _r->contacts;

	while(ptr) {
		if (!VALID_CONTACT(ptr, act_time)) {
			/* run callbacks for EXPIRE event */
			if (exists_ulcb_type(UL_CONTACT_EXPIRE))
				run_ul_callbacks( UL_CONTACT_EXPIRE, ptr);

			LM_DBG("Binding '%.*s','%.*s' has expired\n",
				ptr->aor->len, ZSW(ptr->aor->s),
				ptr->c.len, ZSW(ptr->c.s));

			t = ptr;
			ptr = ptr->next;

			mem_delete_ucontact(_r, t);
			update_stat( _r->slot->d->expires, 1);
		} else {
			ptr = ptr->next;
		}
	}

	return 0;
}



/*! \brief
 * This routine is used when db_mode is
 * set to WRITE_THROUGH
 */
static inline int ALLOW_UNUSED wt_timer(urecord_t* _r)
{
	ucontact_t* ptr, *t;

	ptr = _r->contacts;

	while(ptr) {
		if (!VALID_CONTACT(ptr, act_time)) {
			/* run callbacks for EXPIRE event */
			if (exists_ulcb_type(UL_CONTACT_EXPIRE)) {
				run_ul_callbacks( UL_CONTACT_EXPIRE, ptr);
			}

			LM_DBG("Binding '%.*s','%.*s' has expired\n",
				ptr->aor->len, ZSW(ptr->aor->s),
				ptr->c.len, ZSW(ptr->c.s));

			t = ptr;
			ptr = ptr->next;

			if (db_delete_ucontact(t) < 0) {
				LM_ERR("deleting contact from database failed\n");
			}
			mem_delete_ucontact(_r, t);
			update_stat( _r->slot->d->expires, 1);
		} else {
			ptr = ptr->next;
		}
	}

	return 0;
}



/*! \brief
 * Write-back timer
 */
static inline int wb_timer(urecord_t* _r,query_list_t **ins_list)
{
	ucontact_t* ptr, *t;
	cstate_t old_state;
	int op,ins_done=0;

	ptr = _r->contacts;

	while(ptr) {
		if (!VALID_CONTACT(ptr, act_time)) {
			/* run callbacks for EXPIRE event */
			if (exists_ulcb_type(UL_CONTACT_EXPIRE)) {
				run_ul_callbacks( UL_CONTACT_EXPIRE, ptr);
			}

			LM_DBG("Binding '%.*s','%.*s' has expired\n",
				ptr->aor->len, ZSW(ptr->aor->s),
				ptr->c.len, ZSW(ptr->c.s));
			if (db_mode != DB_ONLY)
				update_stat( _r->slot->d->expires, 1);

			t = ptr;
			ptr = ptr->next;

			/* Should we remove the contact from the database ? */
			if (st_expired_ucontact(t) == 1 && !(t->flags & FL_MEM)) {
				VAL_BIGINT(cid_vals+cid_len) = t->contact_id;
				if ((++cid_len) == max_contact_delete) {
					if (db_multiple_ucontact_delete(_r->domain, cid_keys,
												cid_vals, cid_len) < 0) {
						LM_ERR("failed to delete contacts from database\n");
						/* pass over these contacts; we will try to delete
						 * them later */
						cid_len = 0;

						/* do not delete from memory now - if we do, we'll get
						 * a stuck record in DB. Future registrations will not
						 * be able to get inserted due to index collision */
						continue;
					}
					cid_len = 0;
				}
			}

			mem_delete_ucontact(_r, t);
		} else {
			/* Determine the operation we have to do */
			old_state = ptr->state;
			op = st_flush_ucontact(ptr);

			switch(op) {
			case 0: /* do nothing, contact is synchronized */
				break;

			case 1: /* insert */
				if (db_insert_ucontact(ptr,ins_list,0) < 0) {
					LM_ERR("inserting contact into database failed\n");
					ptr->state = old_state;
				}
				if (ins_done == 0)
					ins_done = 1;
				break;

			case 2: /* update */
				if (db_update_ucontact(ptr) < 0) {
					LM_ERR("updating contact in db failed\n");
					ptr->state = old_state;
				}
				break;
			}

			ptr = ptr->next;
		}
	}


	return ins_done;
}

/**
 * \not a timer function but it wraps up over wb_timer function
 */
static inline int db_only_timer(urecord_t* _r) {

	if (!_r) {
		LM_ERR("no urecord!\n");
		return -1;
	}

	if (wb_timer(_r, 0) < 0) {
		LM_ERR("failed to sync with db\n");
		return -1;
	}

	/* delete all the contacts left pending in the "to-be-delete" buffer */
	if (cid_len &&
	db_multiple_ucontact_delete(_r->domain, cid_keys, cid_vals, cid_len) < 0) {
		LM_ERR("failed to delete contacts from database\n");
		return -1;
	}

	return 0;
}





int timer_urecord(urecord_t* _r,query_list_t **ins_list)
{
	switch(db_mode) {
	case NO_DB:         return nodb_timer(_r);
	/* use also the write_back timer routine to handle the failed
	 * realtime inserts/updates */
	case WRITE_THROUGH: return wb_timer(_r,ins_list); /*wt_timer(_r);*/
	case WRITE_BACK:    return wb_timer(_r,ins_list);
	default:
		return 0; /* Makes gcc happy */
	}
}



int db_delete_urecord(urecord_t* _r)
{
	static db_ps_t my_ps = NULL;
	db_key_t keys[2];
	db_val_t vals[2];
	char* dom;

	keys[0] = &user_col;
	keys[1] = &domain_col;

	memset(vals, 0, sizeof vals);

	vals[0].type = DB_STR;
	vals[0].val.str_val.s = _r->aor.s;
	vals[0].val.str_val.len = _r->aor.len;

	if (use_domain) {
		dom = q_memchr(_r->aor.s, '@', _r->aor.len);
		vals[0].val.str_val.len = dom - _r->aor.s;

		vals[1].type = DB_STR;
		vals[1].val.str_val.s = dom + 1;
		vals[1].val.str_val.len = _r->aor.s + _r->aor.len - dom - 1;
	}

	if (ul_dbf.use_table(ul_dbh, _r->domain) < 0) {
		LM_ERR("use_table failed\n");
		return -1;
	}

	CON_PS_REFERENCE(ul_dbh) = &my_ps;

	if (ul_dbf.delete(ul_dbh, keys, 0, vals, (use_domain) ? (2) : (1)) < 0) {
		LM_ERR("failed to delete from database\n");
		return -1;
	}

	return 0;
}


/*! \brief
 * Release urecord previously obtained
 * through get_urecord
 */
void release_urecord(urecord_t* _r, char is_replicated)
{
	if (db_mode==DB_ONLY) {
		/* force flushing to DB*/
		if (db_only_timer(_r) < 0)
			LM_ERR("failed to sync with db\n");
		/* now simply free everything */
		free_urecord(_r);
	} else if (_r->no_clear_ref <= 0 && _r->contacts == 0) {
		if (exists_ulcb_type(UL_AOR_DELETE))
			run_ul_callbacks(UL_AOR_DELETE, _r);

		if (!is_replicated && ul_replicate_cluster)
			replicate_urecord_delete(_r);

		mem_delete_urecord(_r->slot->d, _r);
	}
}


/*! \brief
 * Create and insert new contact
 * into urecord
 */
int insert_ucontact(urecord_t* _r, str* _contact, ucontact_info_t* _ci,
										ucontact_t** _c, char is_replicated)
{
	int first_contact = _r->contacts == NULL ? 1 : 0;

	/* not used in db only mode */
	if (_ci->contact_id == 0) {
		_ci->contact_id =
		        pack_indexes((unsigned short)_r->aorhash,
		                                     _r->label,
		                    ((unsigned short)_r->next_clabel));
		_r->next_clabel = CLABEL_INC_AND_TEST(_r->next_clabel);
	}

	if ( ((*_c)=mem_insert_ucontact(_r, _contact, _ci)) == 0) {
		LM_ERR("failed to insert contact\n");
		return -1;
	}

	if (!is_replicated && ul_replicate_cluster && db_mode != DB_ONLY)
		replicate_ucontact_insert(_r, _contact, _ci);

	if (exists_ulcb_type(UL_CONTACT_INSERT))
		run_ul_callbacks(UL_CONTACT_INSERT, *_c);

	if (!first_contact && exists_ulcb_type(UL_AOR_UPDATE))
		run_ul_callbacks(UL_AOR_UPDATE, _r);

	if (db_mode == WRITE_THROUGH) {
		if (db_insert_ucontact(*_c,0,0) < 0) {
			LM_ERR("failed to insert in database\n");
		} else {
			(*_c)->state = CS_SYNC;
		}
	}

	return 0;
}


/*! \brief
 * Delete ucontact from urecord
 */
int delete_ucontact(urecord_t* _r, struct ucontact* _c, char is_replicated)
{
	if (!is_replicated && ul_replicate_cluster && db_mode != DB_ONLY)
		replicate_ucontact_delete(_r, _c);

	if (exists_ulcb_type(UL_CONTACT_DELETE)) {
		run_ul_callbacks( UL_CONTACT_DELETE, _c);
	}

	if (exists_ulcb_type(UL_AOR_UPDATE))
		run_ul_callbacks(UL_AOR_UPDATE, _r);

	LM_DBG("deleting contact '%.*s'\n", _c->c.len, _c->c.s);

	if (st_delete_ucontact(_c) > 0) {
		if (db_mode == WRITE_THROUGH) {
			if (db_delete_ucontact(_c) < 0) {
				LM_ERR("failed to remove contact from database\n");
			}
		}

		mem_delete_ucontact(_r, _c);

		if (db_mode == DB_ONLY) {
			/* force flushing to DB*/
			if (db_only_timer(_r) < 0)
				LM_ERR("failed to sync with db\n");
		}
	}

	return 0;
}


static inline struct ucontact* contact_match( ucontact_t* ptr, str* _c)
{
	while(ptr) {
		if ((_c->len == ptr->c.len) && !memcmp(_c->s, ptr->c.s, _c->len)) {
			return ptr;
		}

		ptr = ptr->next;
	}
	return 0;
}


static inline struct ucontact* contact_callid_match( ucontact_t* ptr,
														str* _c, str *_callid)
{
	while(ptr) {
		if ( (_c->len==ptr->c.len) && (_callid->len==ptr->callid.len)
		&& !memcmp(_c->s, ptr->c.s, _c->len)
		&& !memcmp(_callid->s, ptr->callid.s, _callid->len)
		) {
			return ptr;
		}

		ptr = ptr->next;
	}
	return 0;
}


/*! \brief
 * Get pointer to ucontact with given contact
 * Returns:
 *      0 - found
 *      1 - not found
 *     -1 - invalid found
 *     -2 - found, but to be skipped (same cseq)
 */
int get_ucontact(urecord_t* _r, str* _c, str* _callid, int _cseq,
														struct ucontact** _co)
{
	ucontact_t* ptr;
	int no_callid;

	ptr = 0;
	no_callid = 0;
	*_co = 0;

	switch (matching_mode) {
		case CONTACT_ONLY:
			ptr = contact_match( _r->contacts, _c);
			break;
		case CONTACT_CALLID:
			ptr = contact_callid_match( _r->contacts, _c, _callid);
			no_callid = 1;
			break;
		default:
			LM_CRIT("unknown matching_mode %d\n", matching_mode);
			return -1;
	}

	if (ptr) {
		/* found -> check callid and cseq */
		if ( no_callid || (ptr->callid.len==_callid->len
		&& memcmp(_callid->s, ptr->callid.s, _callid->len)==0 ) ) {
			if (_cseq<ptr->cseq)
				return -1;
			if (_cseq==ptr->cseq) {
				get_act_time();
				return (ptr->last_modified+cseq_delay>act_time)?-2:-1;
			}
		}
		*_co = ptr;
		return 0;
	}

	return 1;
}


/* similar to get_ucontact, but does not use callid and cseq
   to be used from MI functions where we have only contact */
int get_simple_ucontact(urecord_t* _r, str* _c, struct ucontact** _co)
{
	*_co = contact_match( _r->contacts, _c);
	return (*_co)?0:1;
}


uint64_t next_contact_id(urecord_t* _r)
{
	uint64_t contact_id;

	contact_id =
		pack_indexes((unsigned short)_r->aorhash,
		                             _r->label,
		            ((unsigned short)_r->next_clabel));
		_r->next_clabel = CLABEL_INC_AND_TEST(_r->next_clabel);

	return contact_id;
}

int_str_t *get_urecord_key(urecord_t* _rec, const str* _key)
{
	return kv_get(_rec->kv_storage, _key);
}

int_str_t *put_urecord_key(urecord_t* _rec, const str* _key,
                           const int_str_t* _val)
{
	return kv_put(_rec->kv_storage, _key, _val);
}
