/*
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2020 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <string.h>
#include <inttypes.h>
#include "udomain.h"
#include "dlist.h"
#include "../../parser/parse_methods.h"
#include "../../mem/shm_mem.h"
#include "../../dprint.h"
#include "../../db/db.h"
#include "../../socket_info.h"
#include "../../ut.h"
#include "../../hash_func.h"
#include "../../cachedb/cachedb.h"

#include "ul_mod.h"            /* usrloc module parameters */
#include "ul_evi.h"
#include "utime.h"
#include "ul_cluster.h"
#include "ul_callback.h"
#include "usrloc.h"


extern int max_contact_delete;
extern int cid_regen;
extern db_key_t *cid_keys;
extern db_val_t *cid_vals;
int cid_len=0;

/*! \brief
 * Create a new domain structure
 * _n is pointer to str representing
 * name of the domain, the string is
 * not copied, it should point to str
 * structure stored in domain list
 * _s is hash table size
 */
int new_udomain(str* _n, int _s, udomain_t** _d)
{
	int i;
#ifdef STATISTICS
	char *name;
#endif

	/* Must be always in shared memory, since
	 * the cache is accessed from timer which
	 * lives in a separate process
	 */

	*_d = (udomain_t*)shm_malloc(sizeof(udomain_t));
	if (!(*_d)) {
		LM_ERR("new_udomain(): No memory left\n");
		goto error0;
	}
	memset(*_d, 0, sizeof(udomain_t));

	(*_d)->table = (hslot_t*)shm_malloc(sizeof(hslot_t) * _s);
	if (!(*_d)->table) {
		LM_ERR("no memory left 2\n");
		goto error1;
	}

	(*_d)->name = _n;

	for(i = 0; i < _s; i++) {
		if (init_slot(*_d, &((*_d)->table[i]), i) < 0) {
			LM_ERR("initializing hash table failed\n");
			goto error2;
		}
	}

	(*_d)->size = _s;

#ifdef STATISTICS
	/* register the statistics */
	if ( (name=build_stat_name(_n,"users"))==0 || register_stat("usrloc",
	name, &(*_d)->users, STAT_NO_RESET|STAT_SHM_NAME)!=0 ) {
		LM_ERR("failed to add stat variable\n");
		goto error2;
	}
	if ( (name=build_stat_name(_n,"contacts"))==0 || register_stat("usrloc",
	name, &(*_d)->contacts, STAT_NO_RESET|STAT_SHM_NAME)!=0 ) {
		LM_ERR("failed to add stat variable\n");
		goto error2;
	}
	if ( (name=build_stat_name(_n,"expires"))==0 || register_stat("usrloc",
	name, &(*_d)->expires, STAT_SHM_NAME)!=0 ) {
		LM_ERR("failed to add stat variable\n");
		goto error2;
	}
#endif

	return 0;
error2:
	shm_free((*_d)->table);
error1:
	shm_free(*_d);
error0:
	return -1;
}


/*! \brief
 * Free all memory allocated for
 * the domain
 */
void free_udomain(udomain_t* _d)
{
	int i;

	if (_d->table) {
		for(i = 0; i < _d->size; i++)
			deinit_slot(_d->table + i);
		shm_free(_d->table);
	}
	shm_free(_d);
}

/*! \brief
 * Returns a static dummy urecord for temporary usage
 */
static inline void
get_static_urecord(const udomain_t* _d, const str* _aor, struct urecord** _r)
{
	static struct urecord r = {
		.is_static = 1,
	};

	free_urecord(&r);
	memset(&r, 0, sizeof r);

	r.aor = *_aor;
	r.domain = _d->name;
	r.aorhash = core_hash(_aor, 0, DB_AOR_HASH_MASK);
	r.is_static = 1;

	*_r = &r;
}

/*! \brief
 * expects (UL_COLS - 4) fields:
 *   contact, expires, q, callid, cseq, flags, cflags, ua,
 *   received, path, socket, methods, last_modified, instance, attr)
 */
static inline ucontact_info_t *
cdb_ctdict2info(const cdb_dict_t *ct_fields, str *contact)
{
	static ucontact_info_t ci;
	static str callid, ua, received, host, path, instance;
	static str attr;
	struct list_head *_;

	cdb_pair_t *pair;
	int port, proto;

	memset(&ci, 0, sizeof(ucontact_info_t));

	/* TODO: find a less convoluted way of implementing this */
	list_for_each (_, ct_fields) {
		pair = list_entry(_, cdb_pair_t, list);

		switch (pair->key.name.s[0]) {
		case 'a':
			attr = pair->val.val.st;
			ci.attr = &attr;
			break;
		case 'c':
			switch (pair->key.name.s[1]) {
			case 'a':
				callid = pair->val.val.st;
				ci.callid = &callid;
				break;
			case 'f':
				ci.cflags = flag_list_to_bitmask(&pair->val.val.st,
				                                 FLAG_TYPE_BRANCH, FLAG_DELIM);
				break;
			case 'o':
				*contact = pair->val.val.st;
				break;
			case 's':
				ci.cseq = pair->val.val.i32;
				break;
			}
			break;
		case 'e':
			ci.expires = pair->val.val.i32;
			break;
		case 'f':
			ci.flags = pair->val.val.i32;
			break;
		case 'l':
			ci.last_modified = pair->val.val.i64;
			break;
		case 'm':
			if (pair->val.type == CDB_NULL)
				ci.methods = ALL_METHODS;
			else
				ci.methods = pair->val.val.i32;
			break;
		case 'p':
			path = pair->val.val.st;
			ci.path = &path;
			break;
		case 'q':
			ci.q = pair->val.val.i32;
			break;
		case 'r':
			received = pair->val.val.st;
			ci.received = received;
			break;
		case 's':
			switch (pair->key.name.s[1]) {
			case 'i':
				instance = pair->val.val.st;
				ci.instance = instance;
				break;
			case 'o':
				if (ZSTR(pair->val.val.st)) {
					ci.sock = NULL;
				} else {
					if (parse_phostport(pair->val.val.st.s, pair->val.val.st.len,
					                    &host.s, &host.len, &port, &proto) != 0) {
						LM_ERR("bad socket <%.*s>\n", pair->val.val.st.len,
						       pair->val.val.st.s);
						return NULL;
					}

					ci.sock = grep_sock_info(&host, (unsigned short)port, proto);
					if (!ci.sock)
						LM_DBG("non-local socket <%.*s>...ignoring\n",
						       pair->val.val.st.len, pair->val.val.st.s);
				}
				break;
			}
			break;
		case 'u':
			ua = pair->val.val.st;
			ci.user_agent = &ua;
			break;
		}
	}

	return &ci;
}

/*! \brief
 * expects (UL_COLS - 2) columns:
 *   contact_id, contact, expires, q, callid, cseq, flags, cflags, ua,
 *   received, path, socket, methods, last_modified, instance, kv_store, attr)
 */
static inline ucontact_info_t* dbrow2info(db_val_t *vals, str *contact)
{
	static ucontact_info_t ci;
	static str callid, ua, received, host, path, instance;
	static str attr, packed_kv, flags;
	int port, proto;
	char *p;

	memset( &ci, 0, sizeof(ucontact_info_t));

	ci.contact_id = VAL_BIGINT(vals);
	if (VAL_NULL(vals)) {
		LM_CRIT("bad contact id\n");
		return 0;
	}

	contact->s = (char*)VAL_STRING(vals+1);
	if (VAL_NULL(vals+1) || contact->s==0 || contact->s[0]==0) {
		LM_CRIT("bad contact\n");
		return 0;
	}
	contact->len = strlen(contact->s);

	if (VAL_NULL(vals+2)) {
		LM_CRIT("empty expire\n");
		return 0;
	}
	ci.expires = VAL_INT(vals+2);

	if (VAL_NULL(vals+3)) {
		LM_CRIT("empty q\n");
		return 0;
	}
	ci.q = double2q(VAL_DOUBLE(vals+3));

	if (VAL_NULL(vals+5)) {
		LM_CRIT("empty cseq_nr\n");
		return 0;
	}
	ci.cseq = VAL_INT(vals+5);

	callid.s = (char*)VAL_STRING(vals+4);
	if (VAL_NULL(vals+4) || !callid.s || !callid.s[0]) {
		LM_CRIT("bad callid\n");
		return 0;
	}
	callid.len  = strlen(callid.s);
	ci.callid = &callid;

	if (VAL_NULL(vals+6)) {
		LM_CRIT("empty flag\n");
		return 0;
	}
	ci.flags  = VAL_BITMAP(vals+6);

	if (!VAL_NULL(vals+7)) {
		flags.s   = (char *)VAL_STRING(vals+7);
		flags.len = strlen(flags.s);
		LM_DBG("flag str: '%.*s'\n", flags.len, flags.s);

		ci.cflags = flag_list_to_bitmask(&flags, FLAG_TYPE_BRANCH, FLAG_DELIM);

		LM_DBG("set flags: %d\n", ci.cflags);
	}

	ua.s  = (char*)VAL_STRING(vals+8);
	if (VAL_NULL(vals+8) || !ua.s || !ua.s[0]) {
		ua.s = 0;
		ua.len = 0;
	} else {
		ua.len = strlen(ua.s);
	}
	ci.user_agent = &ua;

	received.s  = (char*)VAL_STRING(vals+9);
	if (VAL_NULL(vals+9) || !received.s || !received.s[0]) {
		received.len = 0;
		received.s = 0;
	} else {
		received.len = strlen(received.s);
	}
	ci.received = received;

	path.s  = (char*)VAL_STRING(vals+10);
		if (VAL_NULL(vals+10) || !path.s || !path.s[0]) {
			path.len = 0;
			path.s = 0;
		} else {
			path.len = strlen(path.s);
		}
	ci.path= &path;

	/* socket name */
	p  = (char*)VAL_STRING(vals+11);
	if (VAL_NULL(vals+11) || p==0 || p[0]==0){
		ci.sock = 0;
	} else {
		if (parse_phostport( p, strlen(p), &host.s, &host.len,
		&port, &proto)!=0) {
			LM_ERR("bad socket <%s>\n", p);
			return 0;
		}
		ci.sock = grep_sock_info( &host, (unsigned short)port, proto);
		if (ci.sock==0) {
			LM_DBG("non-local socket <%s>...ignoring\n", p);
		}
	}

	/* supported methods */
	if (VAL_NULL(vals+12)) {
		ci.methods = ALL_METHODS;
	} else {
		ci.methods = VAL_BITMAP(vals+12);
	}

	/* last modified time */
	if (!VAL_NULL(vals+13)) {
		ci.last_modified = VAL_TIME(vals+13);
	}

	instance.s  = (char*)VAL_STRING(vals+14);
	if (VAL_NULL(vals+14) || !instance.s || !instance.s[0]) {
		instance.len = 0;
		instance.s = 0;
	} else {
		instance.len = strlen(instance.s);
	}
	ci.instance = instance;

	packed_kv.s = (char*)VAL_STRING(vals+15);
	if (VAL_NULL(vals+15) || !packed_kv.s) {
		packed_kv.s = NULL;
		packed_kv.len = 0;
	} else {
		packed_kv.len  = strlen(packed_kv.s);
	}
	ci.packed_kv_storage = &packed_kv;

	attr.s = (char*)VAL_STRING(vals+16);
	if (VAL_NULL(vals+16) || !attr.s) {
		attr.s = NULL;
		attr.len = 0;
	} else {
		attr.len  = strlen(attr.s);
	}

	ci.attr = &attr;

	return &ci;
}


int preload_udomain(db_con_t* _c, udomain_t* _d)
{
	/* no use to try prepared statements here as this query is performed
	   once at startup -bogdan */
	int sl;
	char uri[MAX_URI_SIZE];
	ucontact_info_t *ci;
	db_row_t *row;
	db_key_t columns[UL_COLS];
	db_res_t* res = NULL;
	str user, contact;
	char* domain;
	int i;
	int n;
	int ret;
	int no_rows = 10;
	unsigned short aorhash, clabel;
	unsigned int   rlabel;
	UNUSED(n);

	char suggest_regen=0;

	urecord_t* r;
	ucontact_t* c;

	/* user column first in order to check if null */
	columns[0] = &user_col;
	columns[1] = &contactid_col;
	columns[2] = &contact_col;
	columns[3] = &expires_col;
	columns[4] = &q_col;
	columns[5] = &callid_col;
	columns[6] = &cseq_col;
	columns[7] = &flags_col;
	columns[8] = &cflags_col;
	columns[9] = &user_agent_col;
	columns[10] = &received_col;
	columns[11] = &path_col;
	columns[12] = &sock_col;
	columns[13] = &methods_col;
	columns[14] = &last_mod_col;
	columns[15] = &sip_instance_col;
	columns[16] = &kv_store_col;
	columns[17] = &attr_col;
	columns[UL_COLS - 1] = &domain_col; /* "domain" always stays last */

	if (ul_dbf.use_table(_c, _d->name) < 0) {
		LM_ERR("sql use_table failed\n");
		return -1;
	}

#ifdef EXTRA_DEBUG
	LM_NOTICE("load start time [%d]\n", (int)time(NULL));
#endif

	if (DB_CAPABILITY(ul_dbf, DB_CAP_FETCH)) {
		if (ul_dbf.query(_c, 0, 0, 0, columns, 0,
		                 use_domain ? UL_COLS : UL_COLS - 1, 0, 0) < 0) {
			LM_ERR("db_query (1) failed\n");
			return -1;
		}
		no_rows = estimate_available_rows( 8+32+64+4+8+128+8+4+4+64
			+32+128+16+8+8+255+255+32+255, UL_COLS);
		if (no_rows==0) no_rows = 10;
		if(ul_dbf.fetch_result(_c, &res, no_rows)<0) {
			LM_ERR("fetching rows failed\n");
			return -1;
		}
	} else {
		if (ul_dbf.query(_c, 0, 0, 0, columns, 0,
		                 use_domain ? UL_COLS : UL_COLS - 1, 0, &res) < 0) {
			LM_ERR("db_query failed\n");
			return -1;
		}
	}

	if (RES_ROW_N(res) == 0) {
		LM_DBG("table is empty\n");
		ul_dbf.free_result(_c, res);
		return 0;
	}


	n = 0;
	do {
		LM_DBG("loading records - cycle [%d]\n", ++n);
		for(i = 0; i < RES_ROW_N(res); i++) {
			time_t old_expires = 0;
			row = RES_ROWS(res) + i;

			user.s = (char*)VAL_STRING(ROW_VALUES(row));
			if (VAL_NULL(ROW_VALUES(row)) || user.s==0 || user.s[0]==0) {
				LM_CRIT("empty username record in table %s...skipping\n",
						_d->name->s);
				continue;
			}
			user.len = strlen(user.s);

			ci = dbrow2info( ROW_VALUES(row)+1, &contact);
			if (ci==0) {
				LM_ERR("sipping record for %.*s in table %s\n",
						user.len, user.s, _d->name->s);
				continue;
			}

			if (use_domain) {
				domain = (char*)VAL_STRING(ROW_VALUES(row) + UL_COLS - 1);
				if (VAL_NULL(ROW_VALUES(row) + UL_COLS - 1) || !domain ||
				     domain[0] == '\0'){
					LM_CRIT("empty domain record for user %.*s...skipping\n",
							user.len, user.s);
					continue;
				}
				/* user.s cannot be NULL - checked previosly */
				user.len = snprintf(uri, MAX_URI_SIZE, "%.*s@%s",
					user.len, user.s, domain);
				user.s = uri;
				if (user.s[user.len]!=0) {
					LM_CRIT("URI '%.*s@%s' longer than %d\n", user.len, user.s,
							domain,	MAX_URI_SIZE);
					continue;
				}
			}

			unpack_indexes(ci->contact_id, &aorhash, &rlabel, &clabel);

			lock_udomain(_d, &user);

			if ((ret=get_urecord(_d, &user, &r)) > 0) {
				if (mem_insert_urecord(_d, &user, &r) < 0) {
					LM_ERR("failed to create a record\n");
					unlock_udomain(_d, &user);
					goto error;
				}

				/* set the record label */
				sl = r->aorhash&(_d->size-1);

				if ((unsigned short)r->aorhash == aorhash) {
					r->label = rlabel;
				}/* else we'll get in trouble below */

			} else if (ret < 0) {
				unlock_udomain(_d, &user);
				goto error;
			} else {
				/* record found */
				sl = r->aorhash&(_d->size-1);
			}

			if ((unsigned short)r->aorhash != aorhash) {
				/* we've got an invalid contact;
				 * if regeneration not set we throw error else we will try generate
				 * new indexes for record and contact labels */
				if ( !cid_regen ) {
					suggest_regen=1;
					LM_ERR("failed to match aorhashes for user %.*s,"
							"db aorhash [%u] new aorhash [%u],"
							"db contactid [%" PRIu64 "]\n",
							user.len, user.s, aorhash,
							(unsigned short)(r->aorhash&(_d->size-1)),
							ci->contact_id);
					if (ret > 0) {
						LM_DBG("release bogus urecord\n");
						release_urecord(r, 0);
					}
					unlock_udomain(_d, &user);
					continue;
				} else {
					/* invalid contact
					 * regenerate aor label and contact label if they're not */
					if ( r->label == 0 ) {
						if (_d->table[sl].next_label == 0)
							_d->table[sl].next_label = rand();

						r->label = CID_NEXT_RLABEL(_d, sl);
					} else {
						if (_d->table[sl].next_label == 0)
							_d->table[sl].next_label = r->label;
					}

					if (r->next_clabel == 0)
						r->next_clabel = rand();

					old_expires = ci->expires;

					/* mark contact with broken contact id as expired for deletion */
					ci->expires = 1;
				}
			} else {
				/* we've got a valid contact */
				/* update indexes accordingly */
				sl = r->aorhash&(_d->size-1);

				if (_d->table[sl].next_label <= rlabel)
					_d->table[sl].next_label = rlabel + 1;

				if (r->next_clabel <= clabel || r->next_clabel == 0)
					r->next_clabel = CLABEL_INC_AND_TEST(clabel);

				r->label = rlabel;
			}


			if ( (c=mem_insert_ucontact(r, &contact, ci)) == 0) {
				LM_ERR("inserting contact failed\n"
						"Found a bad contact with id:[%" PRIu64 "] "
						"aor:[%.*s] contact:[%.*s] received:[%.*s]!\n"
						"Will continue but that contact needs to be REMOVED!!\n",
						ci->contact_id,
						r->aor.len, r->aor.s,
						contact.len, contact.s,
						ci->received.len, ci->received.s);
				unlock_udomain(_d, &user);
				free_ucontact(c);
				continue;
			}


			/* We have to do this, because insert_ucontact sets state to CS_NEW
			 * and we have the contact in the database already */
			/* if contact id regeneration requested then we need to update the
			 * database so we set the state to CS_DIRTY */
			if ( !cid_regen )
				c->state = CS_SYNC;
			else {
				/* mark for removal if we've it has an invalid aorhash */
				if (old_expires)
					c->state = CS_DIRTY;
				else
					c->state = CS_SYNC;
			}

			/* if we've found a broken contact id and regeneration set
			 * reinsert the newly created contact that will have a valid contact id */
			if (cid_regen && old_expires) {
				/* rebuild the contact id for this contact */
				ci->contact_id = pack_indexes(r->aorhash, r->label, r->next_clabel);
				r->next_clabel = CLABEL_INC_AND_TEST(r->next_clabel);

				ci->expires = old_expires;

				if ( (c=mem_insert_ucontact(r, &contact, ci)) == 0) {
					LM_ERR("inserting contact failed\n"
							"Found a bad contact with id:[%" PRIu64 "] "
							"aor:[%.*s] contact:[%.*s] received:[%.*s]!\n"
							"Will continue but that contact needs to be REMOVED!!\n",
							ci->contact_id,
							r->aor.len, r->aor.s,
							contact.len, contact.s,
							ci->received.len, ci->received.s);
					unlock_udomain(_d, &user);
					free_ucontact(c);
					continue;
				}

				/* mark for database insertion */
				c->state = CS_NEW;

				LM_DBG("regenerated contact id to %"PRIu64"\n", ci->contact_id);
			}

			unlock_udomain(_d, &user);
		}

		if (DB_CAPABILITY(ul_dbf, DB_CAP_FETCH)) {
			if(ul_dbf.fetch_result(_c, &res, no_rows)<0) {
				LM_ERR("fetching rows (1) failed\n");
				ul_dbf.free_result(_c, res);
				return -1;
			}
		} else {
			break;
		}
	} while(RES_ROW_N(res)>0);

	ul_dbf.free_result(_c, res);

	if ( suggest_regen ) {
		LM_NOTICE("At least 1 contact(s) from the database has invalid contact_id!\n"
				"Possible causes for this can be:\n"
				"\t* you are migrating your location table from a version older than 2.2\n"
				"\t* you have changed 'hash_size' module parameter from "
				"when current contact_id's were generated;\n"
				"If you want to regenerate new contact_id's for the broken entries"
				" enable 'regen_broken_contactid' module parameter.\n");
	}

	/* for each not populated slot with record label
	 * populate it*/
	for (sl=0; sl < _d->size; sl++) {
		if (_d->table[sl].next_label == 0)
			_d->table[sl].next_label = rand();
	}

#ifdef EXTRA_DEBUG
	LM_NOTICE("load end time [%d]\n", (int)time(NULL));
#endif

	return 0;
error:
	ul_dbf.free_result(_c, res);
	return -1;
}


/*! \brief
 * loads from DB all contacts for an AOR
 */
urecord_t* db_load_urecord(db_con_t* _c, udomain_t* _d, str *_aor)
{
	/*static db_ps_t my_ps = NULL;*/
	ucontact_info_t *ci;
	db_key_t columns[UL_COLS - 2];
	db_key_t keys[2];
	db_val_t vals[2];
	db_key_t order = &q_col;
	db_res_t* res = NULL;
	str contact;
	char *domain;
	int i;

	urecord_t* r;
	ucontact_t* c;

	keys[0] = &user_col;
	keys[1] = &domain_col;

	columns[0] = &contactid_col;
	columns[1] = &contact_col;
	columns[2] = &expires_col;
	columns[3] = &q_col;
	columns[4] = &callid_col;
	columns[5] = &cseq_col;
	columns[6] = &flags_col;
	columns[7] = &cflags_col;
	columns[8] = &user_agent_col;
	columns[9] = &received_col;
	columns[10] = &path_col;
	columns[11] = &sock_col;
	columns[12] = &methods_col;
	columns[13] = &last_mod_col;
	columns[14] = &sip_instance_col;
	columns[15] = &kv_store_col;
	columns[16] = &attr_col;

	if (desc_time_order)
		order = &last_mod_col;

	memset(vals, 0, sizeof vals);

	vals[0].type = DB_STR;
	if (use_domain) {
		vals[1].type = DB_STR;
		domain = q_memchr(_aor->s, '@', _aor->len);
		vals[0].val.str_val.s   = _aor->s;
		if (domain==0) {
			vals[0].val.str_val.len = 0;
			vals[1].val.str_val = *_aor;
		} else {
			vals[0].val.str_val.len = domain - _aor->s;
			vals[1].val.str_val.s   = domain+1;
			vals[1].val.str_val.len = _aor->s + _aor->len - domain - 1;
		}
	} else {
		vals[0].val.str_val = *_aor;
	}

	if (ul_dbf.use_table(_c, _d->name) < 0) {
		LM_ERR("failed to use table %.*s\n", _d->name->len, _d->name->s);
		return 0;
	}

	/* CON_PS_REFERENCE(_c) = &my_ps; - this is still dangerous with STMT */

	if (ul_dbf.query(_c, keys, 0, vals, columns, use_domain ? 2:1, UL_COLS - 2,
	                 order, &res) < 0) {
		LM_ERR("db_query failed\n");
		return 0;
	}

	if (RES_ROW_N(res) == 0) {
		LM_DBG("aor %.*s not found in table %.*s\n",_aor->len, _aor->s,
			_d->name->len, _d->name->s);
		ul_dbf.free_result(_c, res);
		return 0;
	}

	r = 0;

	for(i = 0; i < RES_ROW_N(res); i++) {
		ci = dbrow2info(  ROW_VALUES(RES_ROWS(res) + i), &contact);
		if (ci==0) {
			LM_ERR("skipping record for %.*s in table %s\n",
					_aor->len, _aor->s, _d->name->s);
			continue;
		}

		if ( r==0 )
			get_static_urecord( _d, _aor, &r);

		if ( (c=mem_insert_ucontact(r, &contact, ci)) == 0) {
			LM_ERR("mem_insert failed\n");
			free_urecord(r);
			ul_dbf.free_result(_c, res);
			return 0;
		}

		/* We have to do this, because insert_ucontact sets state to CS_NEW
		 * and we have the contact in the database already */
		c->state = CS_SYNC;
	}

	ul_dbf.free_result(_c, res);
	return r;
}

int
cdb_load_urecord_locations(const udomain_t *_d, const str *_aor, urecord_t *_r)
{
	static const cdb_key_t aor_key = {str_init("aor"), 0}; /* TODO */
	static const cdb_key_t home_ip_key = {str_init("home_ip"), 0}; /* TODO */
	struct list_head *_;
	cdb_filter_t *aor_filter;
	int_str_t val;
	cdb_res_t res;
	cdb_row_t *row;
	cdb_pair_t *pair;
	ucontact_t *ct;
	str my_sip_addr;

	shm_free_all(_r->remote_aors);
	_r->remote_aors = NULL;

	if (clusterer_api.get_my_sip_addr(location_cluster, &my_sip_addr) != 0) {
		LM_ERR("failed to get local PoP SIP addr\n");
		return -1;
	}

	val.is_str = 1;
	val.s = *_aor;

	aor_filter = cdb_append_filter(NULL, &aor_key, CDB_OP_EQ, &val);
	if (!aor_filter) {
		LM_ERR("oom\n");
		return -1;
	}

	LM_DBG("querying AoR %.*s\n", _aor->len, _aor->s);

	if (cdbf.query(cdbc, aor_filter, &res) != 0) {
		LM_ERR("query failed for AoR %.*s\n", _aor->len, _aor->s);
		goto out_err;
	}

	LM_DBG("res.count: %d\n", res.count);

	if (res.count == 0)
		goto out;

	list_for_each (_, &res.rows) {
		row = list_entry(_, cdb_row_t, list);
		pair = cdb_dict_fetch(&home_ip_key, &row->dict);
		if (!pair) {
			LM_ERR("metadata with no home_ip, aor: %.*s", _aor->len, _aor->s);
			continue;
		}

		if (str_match(&my_sip_addr, &pair->val.val.st)) {
			LM_DBG("skipping my own SIP addr (%.*s)\n",
			       my_sip_addr.len, my_sip_addr.s);
			continue;
		}

		ct = shm_malloc(sizeof *ct + 4 + _aor->len + 4 + pair->val.val.st.len);
		if (!ct) {
			LM_ERR("oom\n");
			goto out_err;
		}
		memset(ct, 0, sizeof *ct);

		/* future R-URI */
		ct->c.s = (char *)(ct + 1);
		memcpy(ct->c.s, "sip:", 4);
		memcpy(ct->c.s + 4, _aor->s, _aor->len);
		ct->c.len = 4 + _aor->len;

		/* future outbound proxy */
		ct->received.s = ct->c.s + ct->c.len;
		memcpy(ct->received.s, "sip:", 4);
		memcpy(ct->received.s + 4, pair->val.val.st.s, pair->val.val.st.len);
		ct->received.len = 4 + pair->val.val.st.len;

		ct->flags = FL_EXTRA_HOP;
		ct->next = _r->remote_aors;
		_r->remote_aors = ct;
	}

out:
	cdb_free_rows(&res);
	cdb_free_filters(aor_filter);
	pkg_free(my_sip_addr.s);
	return 0;

out_err:
	cdb_free_rows(&res);
	cdb_free_filters(aor_filter);
	shm_free_all(_r->remote_aors);
	pkg_free(my_sip_addr.s);
	return -1;
}

/*! \brief
 * loads from cache DB all contacts of an AOR
 */
urecord_t* cdb_load_urecord(const udomain_t* _d, const str *_aor)
{
	static const cdb_key_t aor_key = {str_init("aor"), 1}; /* TODO */
	struct list_head *_;
	ucontact_info_t *ci;
	cdb_filter_t *aor_filter;
	int_str_t val;
	cdb_res_t res;
	cdb_row_t *row;
	cdb_pair_t *contacts, *pair;
	str contact, contacts_key = str_init("contacts"); /* TODO */

	urecord_t *r;
	ucontact_t *c;

	val.is_str = 1;
	val.s = *_aor;

	aor_filter = cdb_append_filter(NULL, &aor_key, CDB_OP_EQ, &val);
	if (!aor_filter) {
		LM_ERR("oom\n");
		return NULL;
	}

	LM_DBG("querying AoR %.*s\n", _aor->len, _aor->s);

	if (cdbf.query(cdbc, aor_filter, &res) != 0) {
		LM_ERR("query failed for AoR %.*s\n", _aor->len, _aor->s);
		goto out_null;
	}

	/* TODO: implement use table _d->name */

	if (res.count == 0) {
		LM_DBG("aor %.*s not found in table %.*s\n", _aor->len, _aor->s,
		       _d->name->len, _d->name->s);
		cdb_free_filters(aor_filter);
		return NULL;
	}

	if (res.count != 1)
		LM_BUG("more than 1 result for AoR %.*s\n", _aor->len, _aor->s);

	r = NULL;

	row = list_entry(res.rows.next, cdb_row_t, list);
	list_for_each (_, &row->dict) {
		contacts = list_entry(_, cdb_pair_t, list);
		if (str_match(&contacts->key.name, &contacts_key)) {
			if (contacts->val.type == CDB_NULL)
				goto done_loading;

			goto have_contacts;
		}
	}

	LM_ERR("no 'contacts' field for AoR %.*s\n", _aor->len, _aor->s);
	goto out_null;

have_contacts:
	list_for_each (_, &contacts->val.val.dict) {
		pair = list_entry(_, cdb_pair_t, list);

		ci = cdb_ctdict2info(&pair->val.val.dict, &contact);
		if (!ci) {
			LM_ERR("skipping record for %.*s in table %s\n",
			       _aor->len, _aor->s, _d->name->s);
			continue;
		}
		/* save also the name of the key, to be used later, during
		 * the update operation */
		ci->cdb_key = pair->key.name;

		if (!r)
			get_static_urecord(_d, _aor, &r);

		if (!(c = mem_insert_ucontact(r, &contact, ci))) {
			LM_ERR("mem_insert failed\n");
			free_urecord(r);
			goto out_null;
		}

		/* We have to do this, because insert_ucontact sets state to CS_NEW
		 * and we have the contact in the database already */
		c->state = CS_SYNC;
	}

done_loading:
	cdb_free_rows(&res);
	cdb_free_filters(aor_filter);
	return r;

out_null:
	cdb_free_filters(aor_filter);
	cdb_free_rows(&res);
	return NULL;
}

int db_timer_udomain(udomain_t* _d)
{
	static db_ps_t my_ps = NULL;
	db_key_t keys[2];
	db_op_t  ops[2];
	db_val_t vals[2];

	if (ul_dbf.use_table(ul_dbh, _d->name) < 0) {
		LM_ERR("failed to change table\n");
		return -1;
	}

	memset(vals, 0, sizeof vals);

	keys[0] = &expires_col;
	ops[0] = "<";
	vals[0].type = DB_INT;
	vals[0].val.int_val = act_time + 1;

	keys[1] = &expires_col;
	ops[1] = "!=";
	vals[1].type = DB_INT;
	vals[1].val.int_val = 0;

	CON_PS_REFERENCE(ul_dbh) = &my_ps;
	if (ul_dbf.delete(ul_dbh, keys, ops, vals, 2) < 0) {
		LM_ERR("failed to delete from table %s\n",_d->name->s);
		return -1;
	}

	return 0;
}


/*! \brief performs a dummy query just to see if DB is ok */
int testdb_udomain(db_con_t* con, udomain_t* d)
{
	db_key_t key[1], col[1];
	db_val_t val[1];
	db_res_t* res = NULL;

	if (ul_dbf.use_table(con, d->name) < 0) {
		LM_ERR("failed to change table\n");
		return -1;
	}

	key[0] = &user_col;

	col[0] = &user_col;
	VAL_TYPE(val) = DB_STRING;
	VAL_NULL(val) = 0;
	VAL_STRING(val) = "dummy_user";

	if (ul_dbf.query( con, key, 0, val, col, 1, 1, 0, &res) < 0) {
		LM_ERR("failure in db_query\n");
		return -1;
	}

	ul_dbf.free_result( con, res);
	return 0;
}


/*! \brief
 * Insert a new record into domain
 */
int mem_insert_urecord(udomain_t* _d, str* _aor, struct urecord** _r)
{
	int sl;

	if (new_urecord(_d->name, _aor, _r) < 0) {
		LM_ERR("creating urecord failed\n");
		return -1;
	}

	sl = ((*_r)->aorhash)&(_d->size-1);

	if( slot_add(&_d->table[sl], *_r) < 0)
	{
		LM_ERR("adding slot\n");
		free_urecord(*_r);
		*_r = 0;
		return -1;
	}

	ul_raise_aor_event(ei_ins_id, *_r);
	update_stat( _d->users, 1);
	return 0;
}


/*! \brief
 * Remove a record from domain
 */
void mem_delete_urecord(udomain_t* _d, struct urecord* _r)
{
	ul_raise_aor_event(ei_del_id, _r);
	slot_rem(_r->slot, _r);
	free_urecord(_r);
	update_stat( _d->users, -1);
}


int mem_timer_udomain(udomain_t* _d)
{
	struct urecord* ptr;
	void ** dest;
	int i,ret=0,flush=0;
	map_iterator_t it,prev;

	cid_len = 0;
	for(i=0; i<_d->size; i++)
	{
		lock_ulslot(_d, i);

		map_first(_d->table[i].records,&it);

		while(iterator_is_valid(&it))
		{

			dest = iterator_val(&it);
			if( dest == NULL ) {
				unlock_ulslot(_d, i);
				return -1;
			}

			ptr = (struct urecord *)*dest;

			prev = it;
			iterator_next(&it);

			if ((ret =timer_urecord(ptr,&_d->ins_list)) < 0) {
				LM_ERR("timer_urecord failed\n");
				unlock_ulslot(_d, i);
				return -1;
			}

			if (ret)
				flush=1;

			/* Remove the entire record if it is empty */
			if (ptr->no_clear_ref <= 0 && ptr->contacts == NULL)
			{
				if (exists_ulcb_type(UL_AOR_EXPIRE))
					run_ul_callbacks(UL_AOR_EXPIRE, ptr);

				if (location_cluster) {
					if (cluster_mode == CM_FEDERATION_CACHEDB &&
					    cdb_update_urecord_metadata(&ptr->aor, 1) != 0)
						LM_ERR("failed to delete metadata, aor: %.*s\n",
						       ptr->aor.len, ptr->aor.s);
				}

				iterator_delete(&prev);
				mem_delete_urecord(_d, ptr);
			}
		}

		unlock_ulslot(_d, i);
	}

	/* delete all the contacts left pending in the "to-be-delete" buffer */
	if (cid_len &&
	db_multiple_ucontact_delete(_d->name, cid_keys, cid_vals, cid_len) < 0) {
		LM_ERR("failed to delete contacts from database\n");
		return -1;
	}

	if (flush) {
		LM_DBG("usrloc timer attempting to flush rows to DB\n");
		/* flush everything to DB
		 * so that next-time timer fires
		 * we are sure that DB updates will be successful */
		if (ql_flush_rows(&ul_dbf,ul_dbh,_d->ins_list) < 0)
			LM_ERR("failed to flush rows to DB\n");
	}

	return 0;
}


/*! \brief
 * Get lock
 */
void lock_udomain(udomain_t* _d, str* _aor)
{
	unsigned int sl;
	if (have_mem_storage())
	{
		sl = core_hash(_aor, 0, _d->size);

#ifdef GEN_LOCK_T_PREFERED
		lock_get(_d->table[sl].lock);
#else
		ul_lock_idx(_d->table[sl].lockidx);
#endif
	}
}


/*! \brief
 * Release lock
 */
void unlock_udomain(udomain_t* _d, str* _aor)
{
	unsigned int sl;
	if (have_mem_storage())
	{
		sl = core_hash(_aor, 0, _d->size);
#ifdef GEN_LOCK_T_PREFERED
		lock_release(_d->table[sl].lock);
#else
		ul_release_idx(_d->table[sl].lockidx);
#endif
	}
}

/*! \brief
 * Get lock
 */
void lock_ulslot(udomain_t* _d, int i)
{
	if (have_mem_storage())
#ifdef GEN_LOCK_T_PREFERED
		lock_get(_d->table[i].lock);
#else
		ul_lock_idx(_d->table[i].lockidx);
#endif
}


/*! \brief
 * Release lock
 */
void unlock_ulslot(udomain_t* _d, int i)
{
	if (have_mem_storage())
#ifdef GEN_LOCK_T_PREFERED
		lock_release(_d->table[i].lock);
#else
		ul_release_idx(_d->table[i].lockidx);
#endif
}


int cdb_update_urecord_metadata(const str *_aor, int unpublish)
{
	static const cdb_key_t id_key = {str_init("id"), 1}; /* TODO */
	static str id_print_buf;
	cdb_filter_t *id_filter = NULL;
	int_str_t val;
	cdb_dict_t my_pop_info;
	str sip_addr;

	LM_DBG("%spublishing metadata for AoR %.*s\n", unpublish ? "un" : "",
	       _aor->len, _aor->s);

	cdb_dict_init(&my_pop_info);

	if (clusterer_api.get_my_sip_addr(location_cluster, &sip_addr) != 0) {
		LM_ERR("failed to get local PoP SIP addr\n");
		return -1;
	}

	if (pkg_str_extend(&id_print_buf, _aor->len + sip_addr.len) != 0) {
		LM_ERR("oom\n");
		goto out_err;
	}

	memcpy(id_print_buf.s, _aor->s, _aor->len);
	memcpy(id_print_buf.s + _aor->len, sip_addr.s, sip_addr.len);

	val.is_str = 1;
	val.s.s = id_print_buf.s;
	val.s.len = _aor->len + sip_addr.len;

	if (unpublish) {
		if (cdbf._remove(cdbc, &val.s, &id_key.name) < 0) {
			LM_ERR("fail to del metadata, AoR %.*s\n", _aor->len, _aor->s);
			return -1;
		}

		goto out;
	}

	id_filter = cdb_append_filter(NULL, &id_key, CDB_OP_EQ, &val);
	if (!id_filter) {
		LM_ERR("oom\n");
		goto out_err;
	}

	if (CDB_DICT_ADD_STR(&my_pop_info, "aor", _aor) != 0 ||
	    CDB_DICT_ADD_STR(&my_pop_info, "home_ip", &sip_addr) != 0) {
		goto out_err;
	}

	dbg_cdb_dict("my pop: ", &my_pop_info);

	if (cdbf.update(cdbc, id_filter, &my_pop_info) < 0) {
		LM_ERR("cache update query for AoR %.*s failed!\n",
		       _aor->len, _aor->s);
		goto out_err;
	}

out:
	pkg_free(sip_addr.s);
	cdb_free_filters(id_filter);
	cdb_free_entries(&my_pop_info, NULL);
	return 0;

out_err:
	pkg_free(sip_addr.s);
	cdb_free_filters(id_filter);
	cdb_free_entries(&my_pop_info, NULL);
	return -1;
}


/*! \brief
 * Create and insert a new record
 */
int insert_urecord(udomain_t* _d, str* _aor, struct urecord** _r,
                   char skip_replication)
{
	if (have_mem_storage()) {
		if (mem_insert_urecord(_d, _aor, _r) < 0) {
			LM_ERR("inserting record failed\n");
			return -1;
		}

		if (!skip_replication) {
			init_urecord_labels(*_r, _d);

			if (cluster_mode == CM_FEDERATION_CACHEDB
			        && cdb_update_urecord_metadata(_aor, 0) != 0) {
				LM_ERR("failed to publish cachedb location for AoR %.*s\n",
				       _aor->len, _aor->s);
			}

			if (location_cluster)
				replicate_urecord_insert(*_r);
		}
	} else {
		get_static_urecord( _d, _aor, _r);
	}

	if (exists_ulcb_type(UL_AOR_INSERT))
		run_ul_callbacks(UL_AOR_INSERT, *_r);

	return 0;
}

static inline urecord_t *find_mem_urecord(udomain_t *_d, const str *_aor)
{
	unsigned int sl, aorhash;
	urecord_t **r;

	aorhash = core_hash(_aor, 0, 0);
	sl = aorhash & (_d->size - 1);

	r = (urecord_t **)map_find(_d->table[sl].records, *_aor);
	return r ? *r : NULL;
}

/*! \brief
 * obtain urecord pointer if urecord exists;
 */
int get_urecord(udomain_t* _d, str* _aor, struct urecord** _r)
{
	urecord_t* r;

	switch (cluster_mode) {
	case CM_NONE:
	case CM_FULL_SHARING:
	case CM_FEDERATION_CACHEDB:
		r = find_mem_urecord(_d, _aor);
		if (!r)
			goto out;

		*_r = r;
		return 0;
	case CM_FULL_SHARING_CACHEDB:
		r = cdb_load_urecord(_d, _aor);
		if (r) {
			*_r = r;
			return 0;
		}
		break;
	case CM_SQL_ONLY:
		/* search in DB */
		r = db_load_urecord( ul_dbh, _d, _aor);
		if (r) {
			*_r = r;
			return 0;
		}
		break;
	default:
		abort();
	}

out:
	*_r = NULL;
	return 1;   /* Nothing found */
}

/*! \brief
 * Only relevant in a federation @cluster_mode.
 * Obtain urecord pointer if AoR exists in at least one location.
 *
 * This function performs two lookups:
 *  - mem lookup, thus providing @_r->contacts
 *  - cachedb query, populating @_r->remote_aors
 */
int get_global_urecord(udomain_t* _d, str* _aor, struct urecord** _r)
{
	urecord_t* r;

	switch (cluster_mode) {
	case CM_FEDERATION_CACHEDB:
		r = find_mem_urecord(_d, _aor);
		if (!r)
			get_static_urecord(_d, _aor, &r);

		if (cdb_load_urecord_locations(_d, _aor, r) != 0) {
			if (r->is_static)
				goto out;
		}

		/* static, empty record -> return "not found" instead */
		if (r->is_static && !r->remote_aors)
			goto out;

		*_r = r;
		return 0;
	default:
		abort();
	}

out:
	*_r = NULL;
	return 1;   /* Nothing found */
}

/*! \brief
 * Delete a urecord from domain
 */
int delete_urecord(udomain_t* _d, str* _aor, struct urecord* _r,
                   char skip_replication)
{
	struct ucontact* c, *t;

	switch (cluster_mode) {
	case CM_SQL_ONLY:
		if (!_r)
			get_static_urecord(_d, _aor, &_r);
		if (db_delete_urecord(_r) < 0) {
			LM_ERR("DB delete failed\n");
			return -1;
		}
		free_urecord(_r);
		return 0;

	case CM_FULL_SHARING_CACHEDB:
		if (!_r)
			get_static_urecord(_d, _aor, &_r);
		if (cdb_delete_urecord(_r) < 0) {
			LM_ERR("failed to delete %.*s from cache\n", _aor->len, _aor->s);
			return -1;
		}
		free_urecord(_r);
		return 0;

	case CM_FEDERATION_CACHEDB:
		if (!skip_replication && cdb_update_urecord_metadata(_aor, 1) != 0)
			LM_ERR("failed to delete metadata, aor: %.*s\n",
			       _aor->len, _aor->s);
		break;

	default:
		break;
	}

	if (!_r) {
		if (get_urecord(_d, _aor, &_r) > 0) {
			return 0;
		}
	}

	c = _r->contacts;
	while(c) {
		t = c;
		c = c->next;
		if (delete_ucontact(_r, t, NULL, skip_replication) < 0) {
			LM_ERR("deleting contact failed\n");
			return -1;
		}
	}

	if (_r->no_clear_ref > 0)
		return 0;

	if (!skip_replication && location_cluster)
		replicate_urecord_delete(_r);

	release_urecord(_r, skip_replication);
	return 0;
}


