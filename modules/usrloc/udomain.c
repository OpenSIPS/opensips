/*
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
 * 2003-03-11 changed to the new locking scheme: locking.h (andrei)
 * 2003-03-12 added replication mark and zombie state (nils)
 * 2004-06-07 updated to the new DB api (andrei)
 * 2004-08-23  hash function changed to process characters as unsigned
 *             -> no negative results occur (jku)
 *
 */

/*! \file
 *  \brief USRLOC -
 *  \ingroup usrloc
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
#include "ul_mod.h"            /* usrloc module parameters */
#include "utime.h"
#include "ureplication.h"
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


static event_id_t ei_ins_id = EVI_ERROR;
static event_id_t ei_del_id = EVI_ERROR;
event_id_t ei_c_ins_id = EVI_ERROR;
event_id_t ei_c_del_id = EVI_ERROR;
event_id_t ei_c_update_id = EVI_ERROR;
static str ei_ins_name = str_init("E_UL_AOR_INSERT");
static str ei_del_name = str_init("E_UL_AOR_DELETE");
static str ei_contact_ins_name = str_init("E_UL_CONTACT_INSERT");
static str ei_contact_del_name = str_init("E_UL_CONTACT_DELETE");
static str ei_contact_update_name = str_init("E_UL_CONTACT_UPDATE");
static str ei_aor_name = str_init("aor");
static str ei_c_uri_name = str_init("uri");
static str ei_c_recv_name = str_init("received");
static str ei_c_path_name = str_init("path");
static str ei_c_qval_name = str_init("qval");
static str ei_c_socket_name = str_init("socket");
static str ei_c_bflags_name = str_init("bflags");
static str ei_c_expires_name = str_init("expires");
static str ei_callid_name = str_init("callid");
static str ei_cseq_name = str_init("cseq");
static evi_params_p ul_contact_event_params;
static evi_params_p ul_event_params;
static evi_param_p ul_aor_param;
static evi_param_p ul_c_aor_param;
static evi_param_p ul_c_uri_param;
static evi_param_p ul_c_recv_param;
static evi_param_p ul_c_path_param;
static evi_param_p ul_c_qval_param;
static evi_param_p ul_c_socket_param;
static evi_param_p ul_c_bflags_param;
static evi_param_p ul_c_expires_param;
static evi_param_p ul_c_callid_param;
static evi_param_p ul_c_cseq_param;

/*! \brief
 * Initialize event structures
 */
int ul_event_init(void)
{
	ei_ins_id = evi_publish_event(ei_ins_name);
	if (ei_ins_id == EVI_ERROR) {
		LM_ERR("cannot register aor insert event\n");
		return -1;
	}

	ei_del_id = evi_publish_event(ei_del_name);
	if (ei_del_id == EVI_ERROR) {
		LM_ERR("cannot register aor delete event\n");
		return -1;
	}

	ei_c_ins_id = evi_publish_event(ei_contact_ins_name);
	if (ei_c_ins_id == EVI_ERROR) {
		LM_ERR("cannot register contact insert event\n");
		return -1;
	}

	ei_c_del_id = evi_publish_event(ei_contact_del_name);
	if (ei_c_del_id == EVI_ERROR) {
		LM_ERR("cannot register contact delete event\n");
		return -1;
	}

	ei_c_update_id = evi_publish_event(ei_contact_update_name);
	if (ei_c_update_id == EVI_ERROR) {
		LM_ERR("cannot register contact delete event\n");
		return -1;
	}

	ul_event_params = pkg_malloc(sizeof(evi_params_t));
	if (!ul_event_params) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}
	memset(ul_event_params, 0, sizeof(evi_params_t));
	ul_aor_param = evi_param_create(ul_event_params, &ei_aor_name);
	if (!ul_aor_param) {
		LM_ERR("cannot create AOR parameter\n");
		return -1;
	}

	ul_contact_event_params = pkg_malloc(sizeof(evi_params_t));
	if (!ul_contact_event_params) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}
	memset(ul_contact_event_params, 0, sizeof(evi_params_t));

	ul_c_aor_param = evi_param_create(ul_contact_event_params, &ei_aor_name);
	if (!ul_c_aor_param) {
		LM_ERR("cannot create contact aor parameter\n");
		return -1;
	}

	ul_c_uri_param = evi_param_create(ul_contact_event_params,
		&ei_c_uri_name);
	if (!ul_c_uri_param) {
		LM_ERR("cannot create contact address parameter\n");
		return -1;
	}

	ul_c_recv_param = evi_param_create(ul_contact_event_params, 
		&ei_c_recv_name);
	if (!ul_c_recv_param) {
		LM_ERR("cannot create received parameter\n");
		return -1;
	}

	ul_c_path_param = evi_param_create(ul_contact_event_params, 
		&ei_c_path_name);
	if (!ul_c_path_param) {
		LM_ERR("cannot create path parameter\n");
		return -1;
	}

	ul_c_qval_param = evi_param_create(ul_contact_event_params, 
		&ei_c_qval_name);
	if (!ul_c_qval_param) {
		LM_ERR("cannot create Qval parameter\n");
		return -1;
	}

	ul_c_socket_param = evi_param_create(ul_contact_event_params, 
		&ei_c_socket_name);
	if (!ul_c_socket_param) {
		LM_ERR("cannot create socket parameter\n");
		return -1;
	}

	ul_c_bflags_param = evi_param_create(ul_contact_event_params, 
		&ei_c_bflags_name);
	if (!ul_c_bflags_param) {
		LM_ERR("cannot create bflags parameter\n");
		return -1;
	}

	ul_c_expires_param = evi_param_create(ul_contact_event_params, 
		&ei_c_expires_name);
	if (!ul_c_expires_param) {
		LM_ERR("cannot create expires parameter\n");
		return -1;
	}

	ul_c_callid_param = evi_param_create(ul_contact_event_params,
		&ei_callid_name);
	if (!ul_c_callid_param) {
		LM_ERR("cannot create callid parameter\n");
		return -1;
	}

	ul_c_cseq_param = evi_param_create(ul_contact_event_params, &ei_cseq_name);
	if (!ul_c_cseq_param) {
		LM_ERR("cannot create cseq parameter\n");
		return -1;
	}

	return 0;
}

/*! \brief
 * Raise an event when an AOR is inserted/deleted
 */
static void ul_raise_event(event_id_t _e, struct urecord* _r)
{
	if (_e == EVI_ERROR) {
		LM_ERR("event not yet registered %d\n", _e);
		return;
	}
	if (evi_param_set_str(ul_aor_param, &_r->aor) < 0) {
		LM_ERR("cannot set AOR parameter\n");
		return;
	}
	if (evi_raise_event(_e, ul_event_params) < 0)
		LM_ERR("cannot raise event\n");
}


void ul_raise_contact_event(event_id_t _e, struct ucontact *_c)
{
	if (_e == EVI_ERROR) {
		LM_ERR("event not yet registered %d\n", _e);
		return;
	}

	/* the AOR */
	if (evi_param_set_str(ul_c_aor_param, _c->aor) < 0) {
		LM_ERR("cannot set contact aor parameter\n");
		return;
	}

	/* the contact URI */
	if (evi_param_set_str(ul_c_uri_param, &_c->c) < 0) {
		LM_ERR("cannot set contact URI parameter\n");
		return;
	}

	/* the received URI */
	if (evi_param_set_str(ul_c_recv_param, &_c->received) < 0) {
		LM_ERR("cannot set received parameter\n");
		return;
	}

	/* the PATH URI */
	if (evi_param_set_str(ul_c_path_param, &_c->path) < 0) {
		LM_ERR("cannot set path parameter\n");
		return;
	}

	/* the Q value */
	if (evi_param_set_int(ul_c_qval_param, &_c->q) < 0) {
		LM_ERR("cannot set Qval parameter\n");
		return;
	}

	/* the socket */
	if (evi_param_set_str(ul_c_socket_param, &_c->sock->sock_str) < 0) {
		LM_ERR("cannot set socket parameter\n");
		return;
	}

	/* the Branch flags */
	if (evi_param_set_int(ul_c_bflags_param, &_c->flags) < 0) {
		LM_ERR("cannot set bflags parameter\n");
		return;
	}

	/* the Expires value */
	if (evi_param_set_int(ul_c_expires_param, &_c->expires) < 0) {
		LM_ERR("cannot set expires parameter\n");
		return;
	}

	/* the Call-ID value */
	if (evi_param_set_str(ul_c_callid_param, &_c->callid) < 0) {
		LM_ERR("cannot set callid parameter\n");
		return;
	}

	/* the CSeq value */
	if (evi_param_set_int(ul_c_cseq_param, &_c->cseq) < 0) {
		LM_ERR("cannot set cseq parameter\n");
		return;
	}

	if (evi_raise_event(_e, ul_contact_event_params) < 0)
		LM_ERR("cannot raise event\n");
}


/*! \brief
 * Free all memory allocated for
 * the domain
 */
void free_udomain(udomain_t* _d)
{
	int i;

	if (_d->table) {
		for(i = 0; i < _d->size; i++) {
			lock_ulslot(_d, i);
			deinit_slot(_d->table + i);
			unlock_ulslot(_d, i);
		}
		shm_free(_d->table);
	}
	shm_free(_d);
}

/*! \brief
 * Returns a static dummy urecord for temporary usage
 */
static inline void
get_static_urecord(udomain_t* _d, str* _aor, struct urecord** _r)
{
	static struct urecord r;

	free_urecord( &r );
	memset( &r, 0, sizeof(struct urecord) );
	r.aor = *_aor;
	r.domain = _d->name;
	r.aorhash = core_hash(_aor, 0, 0)&(_d->size-1);

	*_r = &r;
}

/*! \brief
 * Just for debugging
 */
void print_udomain(FILE* _f, udomain_t* _d)
{
		int i;
	int max=0, slot=0, n=0,count;
	map_iterator_t it;
	fprintf(_f, "---Domain---\n");
	fprintf(_f, "name : '%.*s'\n", _d->name->len, ZSW(_d->name->s));
	fprintf(_f, "size : %d\n", _d->size);
	fprintf(_f, "table: %p\n", _d->table);
	/*fprintf(_f, "lock : %d\n", _d->lock); -- can be a structure --andrei*/
	fprintf(_f, "\n");
	for(i=0; i<_d->size; i++)
	{
		count = map_size( _d->table[i].records);
		n += count;
		if(max<count){
			max= count;
			slot = i;
		}

		for ( map_first( _d->table[i].records, &it);
			iterator_is_valid(&it);
			iterator_next(&it) )
			print_urecord(_f, (struct urecord *)*iterator_val(&it));

	}

	fprintf(_f, "\nMax slot: %d (%d/%d)\n", max, slot, n);
	fprintf(_f, "\n---/Domain---\n");
}


/*! \brief
 * expects 15 rows (contact_id, contact, expires, q, callid, cseq, flags, cflags,
 *   ua, received, path, socket, methods, last_modified, instance)
 */
static inline ucontact_info_t* dbrow2info( db_val_t *vals, str *contact)
{
	static ucontact_info_t ci;
	static str callid, ua, received, host, path, instance, attr, flags;
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
	ci.expires = VAL_TIME(vals+2);

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

	attr.s = (char*)VAL_STRING(vals+15);
	if (VAL_NULL(vals+15) || !attr.s) {
		attr.s = NULL;
		attr.len = 0;
	} else
		attr.len  = strlen(attr.s);

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
	db_key_t columns[18];
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

	time_t old_expires=0;
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
	columns[16] = &attr_col;
	columns[17] = &domain_col;

	if (ul_dbf.use_table(_c, _d->name) < 0) {
		LM_ERR("sql use_table failed\n");
		return -1;
	}

#ifdef EXTRA_DEBUG
	LM_NOTICE("load start time [%d]\n", (int)time(NULL));
#endif

	if (DB_CAPABILITY(ul_dbf, DB_CAP_FETCH)) {
		if (ul_dbf.query(_c, 0, 0, 0, columns, 0, (use_domain)?(18):(17), 0,
		0) < 0) {
			LM_ERR("db_query (1) failed\n");
			return -1;
		}
		no_rows = estimate_available_rows( 8+32+64+4+8+128+8+4+4+64
			+32+128+16+8+8+255+32+255, 18);
		if (no_rows==0) no_rows = 10;
		if(ul_dbf.fetch_result(_c, &res, no_rows)<0) {
			LM_ERR("fetching rows failed\n");
			return -1;
		}
	} else {
		if (ul_dbf.query(_c, 0, 0, 0, columns, 0, (use_domain)?(18):(17), 0,
		&res) < 0) {
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
				domain = (char*)VAL_STRING(ROW_VALUES(row) + 17);
				if (VAL_NULL(ROW_VALUES(row)+17) || domain==0 || domain[0]==0){
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

			if (unpack_indexes(ci->contact_id, &aorhash, &rlabel, &clabel)) {
				LM_ERR("unpacking failed\n");
				return -1;
			}

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

				if (_d->table[sl].next_label < rlabel || _d->table[sl].next_label == 0)
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
	db_key_t columns[16];
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
	columns[15] = &attr_col;

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

	if (ul_dbf.query(_c, keys, 0, vals, columns, (use_domain)?2:1, 16, order,
				&res) < 0) {
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


int db_timer_udomain(udomain_t* _d)
{
	static db_ps_t my_ps = NULL;
	db_key_t keys[2];
	db_op_t  ops[2];
	db_val_t vals[2];

	if (my_ps==NULL) {
		keys[0] = &expires_col;
		ops[0] = "<";
		keys[1] = &expires_col;
		ops[1] = "!=";
	}

	memset(vals, 0, sizeof vals);

	vals[0].type = DB_DATETIME;
	vals[0].val.time_val = act_time + 1;

	vals[1].type = DB_DATETIME;
	vals[1].val.time_val = 0;

	CON_PS_REFERENCE(ul_dbh) = &my_ps;
	ul_dbf.use_table(ul_dbh, _d->name);

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

	ul_raise_event(ei_ins_id, *_r);
	update_stat( _d->users, 1);
	return 0;
}


/*! \brief
 * Remove a record from domain
 */
void mem_delete_urecord(udomain_t* _d, struct urecord* _r)
{
	ul_raise_event(ei_del_id, _r);
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
			if (ptr->contacts == NULL)
			{
				if (exists_ulcb_type(UL_AOR_EXPIRE))
					run_ul_callbacks(UL_AOR_EXPIRE, ptr);

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
	if (db_mode!=DB_ONLY)
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
	if (db_mode!=DB_ONLY)
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
	if (db_mode!=DB_ONLY)
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
	if (db_mode!=DB_ONLY)
#ifdef GEN_LOCK_T_PREFERED
		lock_release(_d->table[i].lock);
#else
		ul_release_idx(_d->table[i].lockidx);
#endif
}



/*! \brief
 * Create and insert a new record
 * after inserting and urecord one must populate the
 * label field outside this function
 */
int insert_urecord(udomain_t* _d, str* _aor, struct urecord** _r,
                   char is_replicated)
{
	int sl;

	if (db_mode!=DB_ONLY) {
		if (mem_insert_urecord(_d, _aor, _r) < 0) {
			LM_ERR("inserting record failed\n");
			return -1;
		}
		/* make sure it does not overflows 14 bits */
		(*_r)->next_clabel = (rand()&CLABEL_MASK);
		sl = (*_r)->aorhash&(_d->size-1);

		(*_r)->label = CID_NEXT_RLABEL(_d, sl);

		if (!is_replicated && ul_replicate_cluster)
			replicate_urecord_insert(*_r);
	} else {
		get_static_urecord( _d, _aor, _r);
	}

	if (exists_ulcb_type(UL_AOR_INSERT))
		run_ul_callbacks(UL_AOR_INSERT, *_r);

	return 0;
}


/*! \brief
 * obtain urecord pointer if urecord exists;
 */
int get_urecord(udomain_t* _d, str* _aor, struct urecord** _r)
{
	unsigned int sl, aorhash;
	urecord_t* r;
	void ** dest;

	if (db_mode!=DB_ONLY) {
		/* search in cache */
		aorhash = core_hash(_aor, 0, 0);
		sl = aorhash&(_d->size-1);

		dest = map_find(_d->table[sl].records, *_aor);

		if( dest == NULL )
			return 1;

		*_r = *dest;

		return 0;
	} else {
		/* search in DB */
		r = db_load_urecord( ul_dbh, _d, _aor);
		if (r) {
			*_r = r;
			return 0;
		}
	}

	return 1;   /* Nothing found */
}

/*! \brief
 * Delete a urecord from domain
 */
int delete_urecord(udomain_t* _d, str* _aor, struct urecord* _r,
                   char is_replicated)
{
	struct ucontact* c, *t;

	if (db_mode==DB_ONLY) {
		if (_r==0)
			get_static_urecord( _d, _aor, &_r);
		if (db_delete_urecord(_r)<0) {
			LM_ERR("DB delete failed\n");
			return -1;
		}
		free_urecord(_r);
		return 0;
	}

	if (_r==0) {
		if (get_urecord(_d, _aor, &_r) > 0) {
			return 0;
		}
	}

	if (!is_replicated && ul_replicate_cluster)
		replicate_urecord_delete(_r);

	c = _r->contacts;
	while(c) {
		t = c;
		c = c->next;
		if (delete_ucontact(_r, t, is_replicated) < 0) {
			LM_ERR("deleting contact failed\n");
			return -1;
		}
	}
	release_urecord(_r, is_replicated);
	return 0;
}


