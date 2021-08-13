/*
 * List of registered domains
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
 * ========
 * 2005-07-11 get_all_ucontacts returns also the contact's flags (bogdan)
 * 2006-11-28 added get_number_of_users() (Jeffrey Magder - SOMA Networks)
 * 2007-09-12 added partitioning support for fetching all ul contacts
 *            (bogdan)
 */

/*! \file
 *  \brief USRLOC - List of registered domains
 *  \ingroup usrloc
 */


#include <inttypes.h>
#include <stdlib.h>	       /* abort */
#include <string.h>            /* strlen, memcmp */
#include <stdio.h>             /* printf */
#include "../../ut.h"
#include "../../db/db_ut.h"
#include "../../mem/shm_mem.h"
#include "../../daemonize.h"
#include "../../dprint.h"
#include "../../ip_addr.h"
#include "../../socket_info.h"
#include "../../parser/parse_rr.h"
#include "../../parser/parse_uri.h"
#include "dlist.h"
#include "udomain.h"           /* new_udomain, free_udomain */
#include "utime.h"
#include "ul_mod.h"
#include "ul_evi.h"
#include "ul_callback.h"
#include "ul_cluster.h"
#include "usrloc.h"



/*! \brief
 * List of all registered domains
 */
dlist_t* root = 0;


/*! \brief
 * Returned the first udomain if input param in NULL or the next following
 * udomain after the given udomain
 */
udomain_t* get_next_udomain(udomain_t *_d)
{
	dlist_t *it;

	/* if not domain registered, return NULL directly */
	if (root==NULL)
		return NULL;

	/* if no input provide, return the first domain */
	if (_d==NULL)
		return root->d;

	for( it=root ; it ; it=it->next)
		if (it->d == _d) return (it->next==NULL)?NULL:it->next->d ;
	return NULL;
}


/*! \brief
 * Find domain with the given name
 * \return 0 if the domain was found
 * and 1 of not
 */
static inline int find_dlist(str* _n, dlist_t** _d)
{
	dlist_t* ptr;

	ptr = root;
	while(ptr) {
		if ((_n->len == ptr->name.len) &&
		    !memcmp(_n->s, ptr->name.s, _n->len)) {
			*_d = ptr;
			return 0;
		}

		ptr = ptr->next;
	}

	return 1;
}


static int get_domain_db_ucontacts(udomain_t *d, void *buf, int *len,
		unsigned int flags, unsigned int part_idx,
		unsigned int part_max, char zero_end, int pack_coords)
{
	static char query_buf[512];
	static str query_str;
	static struct sip_uri puri;

	struct socket_info *sock;
	struct proxy_l next_hop;
	db_res_t *res = NULL;
	db_row_t *row;
	db_val_t *val;
	str flag_list;
	int i, no_rows = 10;
	time_t now;
	char *p, *p1;
	int port, proto, p_len, p1_len;
	unsigned int dbflags;
	int needed;
	int shortage = 0;
	uint64_t contact_id;
	void *record_start;

	/* Reserve space for terminating 0000 */
	if (zero_end)
		*len -= (int)sizeof p_len;

	/* get the current time in DB format */
	now = time(NULL);

	/* this is a very noisy log :(  */
	//LM_DBG("buf: %p. flags: %d\n", buf, flags);

	/* read the destinations */
	if (ul_dbf.use_table(ul_dbh, d->name) < 0) {
		LM_ERR("cannot select table \"%.*s\"\n", d->name->len,
		       d->name->s);
		goto error;
	}

	i = snprintf(query_buf, sizeof query_buf, "select %.*s, %.*s, %.*s,"
#ifdef ORACLE_USRLOC
	" %.*s, %.*s, %.*s from %s where %.*s > %lu and mod(contact_id, %u) = %u",
#else
	" %.*s, %.*s, %.*s from %s where %.*s > %lu and contact_id %% %u = %u",
#endif
		received_col.len, received_col.s,
		contact_col.len, contact_col.s,
		sock_col.len, sock_col.s,
		cflags_col.len, cflags_col.s,
		path_col.len, path_col.s,
		contactid_col.len, contactid_col.s,
		d->name->s,
		expires_col.len, expires_col.s,
		now,
		part_max, part_idx);

	LM_DBG("query: %.*s\n", (int)(sizeof query_buf), query_buf);
	if (i >= sizeof query_buf) {
		LM_ERR("DB query too long\n");
		goto error;
	}

	query_str.s = query_buf;
	query_str.len = i;

	if (DB_CAPABILITY(ul_dbf, DB_CAP_FETCH)) {
		if (ul_dbf.raw_query(ul_dbh, &query_str, 0) < 0) {
			LM_ERR("raw_query failed\n");
			goto error;
		}

		no_rows = estimate_available_rows(20+128+20+128+64, 5);
		if (no_rows == 0)
			no_rows = 10;

		LM_DBG("fetching %d rows\n", no_rows);

		if (ul_dbf.fetch_result(ul_dbh, &res, no_rows) < 0) {
			LM_ERR("Error fetching rows\n");
			goto error;
		}
	} else if (ul_dbf.raw_query(ul_dbh, &query_str, &res) < 0) {
		LM_ERR("raw_query failed\n");
		goto error;
	}

	do {
		for (i = 0; i < RES_ROW_N(res); i++) {
			row = RES_ROWS(res) + i;
			val = ROW_VALUES(row) + 3; /* cflags */
			flag_list.s   = (char *)VAL_STRING(val);
			flag_list.len = flag_list.s ? strlen(flag_list.s) : 0;

			LM_DBG("contact cflags: '%.*s'\n", flag_list.len, flag_list.s);

			/* contact is not flagged at all */
			if (flags && (val->nul || !flag_list.s))
				continue;

			dbflags = flag_list_to_bitmask(&flag_list,
			                FLAG_TYPE_BRANCH, FLAG_DELIM);

			LM_DBG("masks: param: %d --- %d :db\n", flags, dbflags);

			/* check if contact flags match the given bitmask */
			if ((dbflags & flags) != flags)
				continue;

			/* received */
			p = (char*)VAL_STRING(ROW_VALUES(row));
			if (VAL_NULL(ROW_VALUES(row)) || !p || !p[0]) {
				/* contact */
				p = (char*)VAL_STRING(ROW_VALUES(row) + 1);
				if (VAL_NULL(ROW_VALUES(row) + 1) || !p || *p == '\0') {
					LM_ERR("empty contact -> skipping\n");
					continue;
				}
			}
			p_len = strlen(p);

			/* path */
			p1 = (char*)VAL_STRING(ROW_VALUES(row) + 4);
			if (VAL_NULL(ROW_VALUES(row) + 4) || !p1 || *p1 == '\0') {
				p1 = NULL;
				p1_len = 0;
			} else
				p1_len = strlen(p1);

			/* contact id*/
			contact_id = VAL_BIGINT(ROW_VALUES(row) + 5);

			needed = (int)(p_len + sizeof p_len + p1_len + sizeof p1_len +
			               sizeof sock + sizeof dbflags + sizeof next_hop);

			if (pack_coords)
				needed += sizeof(ucontact_coords);

			LM_DBG("len: %d, needed: %d\n", *len, needed);

			if (*len < needed) {
				shortage += needed;
				continue;
			}

			/* We cannot add items that point to p or p1 here,
			 * unless they point into the buffer we're keeping.
			 * So: we write to buf, but keep a pointer to the
			 * start, so we can revert this record if needed. */
			record_start = buf;

			/* write received/contact */
			memcpy(buf, &p_len, sizeof p_len);
			buf += sizeof p_len;
			memcpy(buf, p, p_len);
			p = buf; /* point to to-be-kept copy of p */
			buf += p_len;

			/* write path */
			memcpy(buf, &p1_len, sizeof p1_len);
			buf += sizeof p1_len;
			memcpy(buf, p1, (unsigned)p1_len);
			p1 = buf; /* point to to-be-kept copy of p1 */
			buf += p1_len;

			/* determine and parse the URI of this contact's next hop */
			if (p1_len > 0) {
				/* send to first URI in path */
				str uri, host;
				host.s   = p1;
				host.len = p1_len;
				if (get_path_dst_uri(&host, &uri) < 0) {
					LM_ERR("failed to get dst_uri for Path\n");
					/* revert writing this record, continue with next */
					buf = record_start;
					continue;
				}
				if (parse_uri(uri.s, uri.len, &puri) < 0) {
					LM_ERR("failed to parse path URI of next hop: '%.*s'\n",
					        p1_len, p1);
					return -1;
				}
			} else {
				if (parse_uri(p, p_len, &puri) < 0) {
					LM_ERR("failed to parse contact of next hop: '%.*s'\n",
					        p_len, p);
					return -1;
				}
			}

			/* sock */
			p  = (char*)VAL_STRING(ROW_VALUES(row) + 2);
			if (VAL_NULL(ROW_VALUES(row)+2) || !p || *p == '\0') {
				sock = NULL;
			} else {
				str host;
				if (parse_phostport(p, strlen(p), &host.s, &host.len,
				    &port, &proto) != 0) {
					LM_ERR("bad socket <%s>...ignoring\n", p);
					sock = NULL;
				} else {
					sock = grep_sock_info(&host, (unsigned short)port, proto);
					if (!sock)
						LM_DBG("non-local socket <%s>...ignoring\n", p);
				}
			}

			/* write sock and flags */
			memcpy(buf, &sock, sizeof sock);
			buf += sizeof sock;
			memcpy(buf, &dbflags, sizeof dbflags);
			buf += sizeof dbflags;

			memset(&next_hop, 0, sizeof next_hop);
			next_hop.port  = puri.port_no;
			next_hop.proto = puri.proto;
			next_hop.name.len  = puri.host.len;
			next_hop.name.s  = puri.host.s; /* points into buffer already */

			/* write the next hop */
			memcpy(buf, &next_hop, sizeof next_hop);
			buf += sizeof next_hop;

			*len -= needed;
			if (!pack_coords)
				continue;

			/* write the contact id */
			memcpy(buf, &contact_id, sizeof contact_id);
			buf += sizeof contact_id;
		}

		if (DB_CAPABILITY(ul_dbf, DB_CAP_FETCH)) {
			if (ul_dbf.fetch_result(ul_dbh, &res, no_rows) < 0) {
				LM_ERR("fetching rows (1)\n");
				goto error;
			}
		} else
			break;

	} while (RES_ROW_N(res) > 0);

	ul_dbf.free_result(ul_dbh, res);

	/* len < 0 is possible, if size of the buffer < sizeof c->c.len */
	if (zero_end && *len >= 0)
		memset(buf, 0, sizeof p_len);

	/* Shouldn't happen */
	if (shortage > 0 && *len > shortage)
		abort();

	shortage -= *len;

	return shortage > 0 ? shortage : 0;

error:
	if (res)
		ul_dbf.free_result(ul_dbh, res);
	return -1;
}

static int
cdb_pack_ping_data(const str *aor, const cdb_pair_t *contact,
                   unsigned int ct_match_cflags, char **cpos,
                   int *len, int pack_coords)
{
	enum {
		COL_CONTACT = 1 << 0,
		COL_RECEIVED = 1 << 1,
		COL_PATH = 1 << 2,
		COL_CFLAGS = 1 << 3,
	};

	ucontact_sip_coords *coords = NULL;
	cdb_dict_t *ct_fields = (cdb_dict_t *)&contact->val.val.dict;
	cdb_pair_t *pair;
	struct sip_uri puri;
	struct list_head *_;
	unsigned int cflags = 0;
	struct socket_info *sock = NULL;
	struct proxy_l next_hop;
	str ct_uri, received = STR_NULL, path = STR_NULL;
	int needed;
	char *cp = *cpos;
	int cols_needed = COL_CONTACT | COL_RECEIVED | COL_PATH | COL_CFLAGS;

	if (!pack_coords)
		goto skip_coords;

	coords = shm_malloc(sizeof *coords + aor->len + contact->key.name.len);
	if (!coords) {
		LM_ERR("oom\n");
		return 0;
	}

	coords->aor.s = (char *)(coords + 1);
	str_cpy(&coords->aor, aor);

	coords->ct_key.s = coords->aor.s + aor->len;
	str_cpy(&coords->ct_key, &contact->key.name);

skip_coords:
	list_for_each (_, ct_fields) {
		if (!cols_needed)
			break;

		pair = list_entry(_, cdb_pair_t, list);
		switch (pair->key.name.s[0]) {
		case 'c':
			switch (pair->key.name.s[1]) {
			case 'o':
				ct_uri = pair->val.val.st;
				cols_needed &= ~COL_CONTACT;
				break;

			case 'f':
				cflags = flag_list_to_bitmask(&pair->val.val.st,
				                              FLAG_TYPE_BRANCH, FLAG_DELIM);
				cols_needed &= ~COL_CFLAGS;
				break;

			default:
				continue;
			}
			break;

		case 'p':
			path = pair->val.val.st;
			cols_needed &= ~COL_PATH;
			break;

		case 'r':
			received = pair->val.val.st;
			cols_needed &= ~COL_RECEIVED;
			break;

		default:
			continue;
		}
	}

	if (cols_needed) {
		LM_BUG("missing contact columns in AoR %.*s\n", aor->len, aor->s);
		goto out_free;
	}

	if ((cflags & ct_match_cflags) != ct_match_cflags)
		goto out_free;

	if (!ZSTR(received))
		ct_uri = received;

	needed = (int)(sizeof ct_uri.len + ct_uri.len + sizeof path.len + path.len
	               + sizeof sock + sizeof cflags + sizeof next_hop);

	if (pack_coords)
		needed += sizeof(ucontact_coords);

	if (*len < needed)
		return needed;

	memcpy(cp, &ct_uri.len, sizeof ct_uri.len);
	cp += sizeof ct_uri.len;
	memcpy(cp, ct_uri.s, ct_uri.len);
	ct_uri.s = cp; /* point into to-be-kept buffer */
	cp += ct_uri.len;

	memcpy(cp, &path.len, sizeof path.len);
	cp += sizeof path.len;
	memcpy(cp, path.s, path.len);
	path.s = cp; /* point into to-be-kept buffer */
	cp += path.len;

	memcpy(cp, &sock, sizeof sock);
	cp += sizeof sock;

	memcpy(cp, &cflags, sizeof cflags);
	cp += sizeof cflags;

	/* determine the next hop towards this contact */
	{
		str next_hop_uri;
		if (ZSTR(path)) {
			next_hop_uri = ct_uri;
		} else {
			if (get_path_dst_uri(&path, &next_hop_uri) < 0) {
				LM_ERR("failed to get dst_uri for Path\n");
				goto out_free;
			}
		}
		if (parse_uri(next_hop_uri.s, next_hop_uri.len, &puri) < 0) {
			LM_ERR("failed to parse URI of next hop: '%.*s'\n",
				   next_hop_uri.len, next_hop_uri.s);
			goto out_free;
		}
	}

	memset(&next_hop, 0, sizeof next_hop);
	next_hop.port  = puri.port_no;
	next_hop.proto = puri.proto;
	next_hop.name.len = puri.host.len;
	next_hop.name.s = puri.host.s; /* points into buffer already */
	memcpy(cp, &next_hop, sizeof next_hop);
	cp += sizeof next_hop;

	*len -= needed;
	if (pack_coords) {
		memcpy(cp, &coords, sizeof(ucontact_coords));
		cp += sizeof(ucontact_coords);
	}

	*cpos = cp;
	return 0;

out_free:
	shm_free(coords);
	return 0;
}

static int
get_domain_cdb_ucontacts(udomain_t *d, void *buf, int *len,
                         unsigned int flags, unsigned int part_idx,
                         unsigned int part_max, char zero_end, int pack_coords)
{
	static const cdb_key_t aorhash_key = {str_init("aorhash"), 0}; /* TODO */
	struct list_head *_, *__;
	int cur_node_idx = 0, nr_nodes = 1, min, max;
	char *cpos;
	double unit;
	cdb_filter_t *aorh_filter;
	cdb_res_t res;
	cdb_row_t *row;
	int_str_t val;
	cdb_pair_t *pair;
	cdb_dict_t *contacts;
	str contacts_key = str_init("contacts"); /* TODO */
	str *aor;
	enum cdb_filter_op rhs_op;
	int shortage;

	cur_node_idx = clusterer_api.get_my_index(
	                 location_cluster, &contact_repl_cap, &nr_nodes);

	unit = MAX_DB_AOR_HASH / (double)(part_max * nr_nodes);
	min = (int)(unit * part_max * cur_node_idx + unit * part_idx);
	max = (int)(unit * part_max * cur_node_idx + unit * (part_idx + 1));

	val.is_str = 0;
	val.i = min;
	aorh_filter = cdb_append_filter(NULL, &aorhash_key, CDB_OP_GTE, &val);
	if (!aorh_filter) {
		LM_ERR("oom\n");
		return -1;
	}

	rhs_op = (max == MAX_DB_AOR_HASH) ? CDB_OP_LTE : CDB_OP_LT;

	val.i = max;
	aorh_filter = cdb_append_filter(aorh_filter, &aorhash_key, rhs_op, &val);
	if (!aorh_filter) {
		LM_ERR("oom\n");
		return -1;
	}

	LM_DBG("idx=%d/max=%d, node=%d/nr_nodes=%d, "
	       "filter: %d <= aorhash <%s %d\n", part_idx, part_max, cur_node_idx,
	       nr_nodes, min, max == MAX_DB_AOR_HASH ? "=" : "", max);

	/* spread ping workload evenly across pinging interval second ticks,
	 * CPU cores and current number of cluster nodes, all in one query! */
	if (cdbf.query(cdbc, aorh_filter, &res) != 0) {
		LM_ERR("failed to fetch contacts to ping\n");
		return -1;
	}

	LM_DBG("fetched %d results\n", res.count);

	/* Reserve space for terminating 0000 */
	if (zero_end)
		*len -= (int)sizeof ((ucontact_t *)0)->c.len;

	cpos = buf;
	shortage = 0;

	list_for_each (_, &res.rows) {
		row = list_entry(_, cdb_row_t, list);
		aor = NULL;
		contacts = NULL;

		/* locate the 'aor' and 'contacts' fields */
		list_for_each (__, &row->dict) {
			pair = list_entry(__, cdb_pair_t, list);
			if (pair->key.is_pk) {
				aor = &pair->val.val.st;
				if (contacts)
					goto pack_data;
			} else {
				if (str_match(&pair->key.name, &contacts_key)) {
					if (pair->val.type == CDB_NULL)
						goto done_packing;

					contacts = &pair->val.val.dict;
					if (aor)
						goto pack_data;
				}
			}
		}

		LM_BUG("found entry with missing 'contacts' or 'aor' field!\n");
		continue;

pack_data:
		list_for_each (__, contacts) {
			pair = list_entry(__, cdb_pair_t, list);
			shortage += cdb_pack_ping_data(aor, pair, flags, &cpos, len,
			                               pack_coords);
		}
	}

done_packing:
	cdb_free_rows(&res);
	cdb_free_filters(aorh_filter);

	if (zero_end && *len >= 0)
		memset(cpos, 0, sizeof ((ucontact_t *)0)->c.len);

	if (shortage)
		return shortage - *len;

	return 0;
}

static inline int
get_domain_mem_ucontacts(udomain_t *d,void *buf, int *len, unsigned int flags,
								unsigned int part_idx, unsigned int part_max,
								char zero_end, int pack_coords)
{
	urecord_t *r;
	ucontact_t *c;
	void *cp;
	void **dest;
	map_iterator_t it;
	int shortage;
	int needed;
	int count;
	int i = 0;
	int cur_node_idx = 0, nr_nodes = 0;

	cp = buf;
	shortage = 0;
	/* Reserve space for terminating 0000 */
	if (zero_end)
		*len -= (int)sizeof(c->c.len);

	if (pinging_mode == PMD_COOPERATION)
		cur_node_idx = clusterer_api.get_my_index(
		         location_cluster, &contact_repl_cap, &nr_nodes);

	/* this is a very noisy log :( */
	//LM_DBG("part/max: %d/%d, idx/nodes: %d/%d\n",
	//       part_idx, part_max, cur_node_idx, nr_nodes);

	for(i=0; i<d->size; i++) {

		if ( (i % part_max) != part_idx )
			continue;

		lock_ulslot( d, i);
		count = map_size(d->table[i].records);

		if( count <= 0 )
		{
			unlock_ulslot(d, i);
			continue;
		}

		for ( map_first( d->table[i].records, &it);
			iterator_is_valid(&it);
			iterator_next(&it) ) {

			dest = iterator_val(&it);
			if( dest == NULL ) {
				unlock_ulslot(d, i);
				return -1;
			}
			r =( urecord_t * ) *dest;

			/* distribute ping workload across cluster nodes */
			if (pinging_mode == PMD_COOPERATION &&
				r->aorhash % nr_nodes != cur_node_idx)
					continue;

			for (c = r->contacts; c != NULL; c = c->next) {
				if (c->c.len <= 0)
					continue;
				/*
				 * List only contacts that have all requested
				 * flags set
				 */
				if ((c->cflags & flags) != flags)
					continue;

				/* a lot slower than fetching all tags before the outermost
				 * loop, but at least we have proper responsiveness to tag
				 * switches! */
				if (pinging_mode == PMD_OWNERSHIP && !_is_my_ucontact(c))
					continue;

				needed = (int)((c->received.s?
							(sizeof(c->received.len) + c->received.len):
							(sizeof(c->c.len) + c->c.len)) +
						sizeof(c->path.len) + c->path.len +
						sizeof(c->sock) + sizeof(c->cflags) +
						sizeof(c->next_hop));
				if (pack_coords)
					needed += sizeof(ucontact_coords);

				if (*len >= needed) {
					struct proxy_l next_hop;
					memcpy(&next_hop, &c->next_hop, sizeof(c->next_hop));

					if (c->received.s) {
						memcpy(cp,&c->received.len,sizeof(c->received.len));
						cp = (char*)cp + sizeof(c->received.len);
						memcpy(cp, c->received.s, c->received.len);
						/* next_hop host needs to skip the 'sip:[...@]' part
						 * of the uri; it's already relative to c->received
						 * (a potentially fragile assumption) */
						if (c->path.len == 0)
							next_hop.name.s = cp + (c->next_hop.name.s - c->received.s);
						cp = (char*)cp + c->received.len;
					} else {
						memcpy(cp,&c->c.len,sizeof(c->c.len));
						cp = (char*)cp + sizeof(c->c.len);
						memcpy(cp, c->c.s, c->c.len);
						if (c->path.len == 0)
							/* c->next_hop.name is relative to c->c
							 * (a potentially fragile assumption) */
							next_hop.name.s = cp + (c->next_hop.name.s - c->c.s);
						cp = (char*)cp + c->c.len;
					}
					memcpy(cp, &c->path.len, sizeof(c->path.len));
					cp = (char*)cp + sizeof(c->path.len);
					memcpy(cp, c->path.s, c->path.len);
					if (c->path.len != 0)
						/* c->next_hop.name is relative to c->path
						 * (a potentially fragile assumption) */
						next_hop.name.s = cp + (c->next_hop.name.s - c->path.s);
					cp = (char*)cp + c->path.len;
					memcpy(cp, &c->sock, sizeof(c->sock));
					cp = (char*)cp + sizeof(c->sock);
					memcpy(cp, &c->cflags, sizeof(c->cflags));
					cp = (char*)cp + sizeof(c->cflags);
					memcpy(cp, &next_hop, sizeof(next_hop)); /* points into buffer already */
					cp = (char*)cp + sizeof(next_hop);

					*len -= needed;
					if (!pack_coords)
						continue;

					memcpy(cp, &c->contact_id, sizeof(c->contact_id));
					cp = (char*)cp + sizeof(c->contact_id);

				} else {
					shortage += needed;
				}
			}
		}
		unlock_ulslot(d, i);
	}
	/* len < 0 is possible, if size of the buffer < sizeof(c->c.len) */
	if (zero_end && *len >= 0)
		memset(cp, 0, sizeof(c->c.len));

	/* Shouldn't happen */
	if (shortage > 0 && *len > shortage) {
		abort();
	}

	shortage -= *len;

	return shortage > 0 ? shortage : 0;
}


/*! \brief
 * Return list of all contacts for all currently registered
 * users in all currently defined domains.  The packed data format is identical
 * to @get_domain_ucontacts.
 */
int get_all_ucontacts(void *buf, int len, unsigned int flags,
                 unsigned int part_idx, unsigned int part_max, int pack_coords)
{
	dlist_t *p;
	ucontact_t c;
	int shortage=0;
	int res, ini_len, cur_pos=0;


	/* Reserve space for terminating 0000 */
	len -= sizeof(c.c.len);

	for (p = root; p != NULL; p = p->next) {
		ini_len = len;
		if (cluster_mode != CM_SQL_ONLY) {
			shortage +=
				get_domain_mem_ucontacts(p->d, buf+cur_pos, &len, flags,
					part_idx, part_max, 0 /* don't add zeroed contact*/,
					pack_coords);
		} else {
			res =
				get_domain_db_ucontacts(p->d, buf+cur_pos, &len, flags,
					part_idx, part_max, 0, pack_coords);
			if (res >= 0) {
				shortage += res;
			} else {
				LM_ERR("get db ucontacts failed; domain %.*s\n",
						p->d->name->len, p->d->name->s);
				return -1;
			}
		}
		cur_pos += ini_len - len;
	}
	/* len < 0 is possible, if size of the buffer < sizeof(c->c.len) */
	if (!shortage && len >= 0)
		memset(buf + cur_pos, 0, sizeof(c.c.len));

	return shortage > 0 ? shortage : 0;
}


/*! \brief
 * Return list of all contacts for all currently registered
 * users in the given domain. Caller must provide a buffer of
 * sufficient length to fit all those contacts. If the buffer
 * is exhausted, the function returns the estimated amount
 * of additional space needed. In this case the caller is
 * expected to repeat the call using this value as the hint.
 *
 * Information is packed into the buffer as follows:
 *
 * +------------+----------+---------+-------+------------+--------+--------+---------------+
 * |int         |char[]    |int      |char[] |socket_info*|unsigned|proxy_l |uint64         |
 * +============+==========+=========+=======+============+========+========+===============+
 * |contact1.len|contact1.s|path1.len|path1.s|sock1       |dbflags |next_hop|contact_coords1|
 * +------------+----------+---------+-------+------------+--------+--------+---------------+
 * |contact2.len|contact2.s|path2.len|path2.s|sock2       |dbflags |next_hop|contact_coords2|
 * +------------+----------+---------+-------+------------+--------+--------+---------------+
 * |........................................................................................|
 * +------------+----------+---------+-------+------------+--------+--------+---------------+
 * |contactN.len|contactN.s|pathN.len|pathN.s|sockN       |dbflags |next_hop|contact_coordsN|
 * +------------+----------+---------+-------+------------+--------+--------+---------------+
 * |000000000000|
 * +------------+
 *
 * if @pack_coords is false, all "contact_coordsX" parts will be omitted
 */
int get_domain_ucontacts(udomain_t *d, void *buf, int len, unsigned int flags,
                 unsigned int part_idx, unsigned int part_max, int pack_coords)
{
	if (cluster_mode == CM_SQL_ONLY)
		return get_domain_db_ucontacts(d, buf, &len,
							flags, part_idx, part_max, 1, pack_coords);
	else if (cluster_mode == CM_FULL_SHARING_CACHEDB)
		return get_domain_cdb_ucontacts(d, buf, &len,
		                    flags, part_idx, part_max, 1, pack_coords);
	else
		return get_domain_mem_ucontacts(d, buf, &len, flags,
											part_idx, part_max, 1, pack_coords);
}


/*! \brief
 * Create a new domain structure
 * \return 0 if everything went OK, otherwise value < 0 is returned
 *
 * \note The structure is NOT created in shared memory so the
 * function must be called before ser forks if it should
 * be available to all processes
 */
static inline int new_dlist(str* _n, dlist_t** _d)
{
	dlist_t* ptr;

	if (get_osips_state()>STATE_STARTING) {
		LM_ERR("cannot register new domain during runtime\n");
		return -1;
	}

	/* Domains are created before ser forks,
	 * so we can create them using pkg_malloc
	 */
	ptr = (dlist_t*)shm_malloc(sizeof(dlist_t));
	if (ptr == 0) {
		LM_ERR("no more share memory\n");
		return -1;
	}
	memset(ptr, 0, sizeof(dlist_t));

	/* copy domain name as null terminated string */
	ptr->name.s = (char*)shm_malloc(_n->len+1);
	if (ptr->name.s == 0) {
		LM_ERR("no more memory left\n");
		shm_free(ptr);
		return -2;
	}

	memcpy(ptr->name.s, _n->s, _n->len);
	ptr->name.len = _n->len;
	ptr->name.s[ptr->name.len] = 0;

	if (new_udomain(&(ptr->name), ul_hash_size, &(ptr->d)) < 0) {
		LM_ERR("creating domain structure failed\n");
		shm_free(ptr->name.s);
		shm_free(ptr);
		return -3;
	}

	*_d = ptr;
	return 0;
}


/*! \brief
 * Function registers a new domain with usrloc
 * if the domain exists, pointer to existing structure
 * will be returned, otherwise a new domain will be
 * created
 */
int register_udomain(const char* _n, udomain_t** _d)
{
	dlist_t* d;
	str s;
	db_con_t* con;

	s.s = (char*)_n;
	s.len = strlen(_n);

	if (find_dlist(&s, &d) == 0) {
		*_d = d->d;
		return 0;
	}

	if (new_dlist(&s, &d) < 0) {
		LM_ERR("failed to create new domain\n");
		return -1;
	}

	/* Test tables from database if we are gonna
	 * to use database
	 */
	if (sql_wmode != SQL_NO_WRITE) {
		con = ul_dbf.init(&db_url);
		if (!con) {
			LM_ERR("failed to open database connection\n");
			goto err;
		}

		if(db_check_table_version(&ul_dbf, con, &s, UL_TABLE_VERSION) < 0) {
			LM_ERR("error during table version check.\n");
			goto err;
		}
		/* test if DB really exists */
		if (testdb_udomain(con, d->d) < 0) {
			LM_ERR("testing domain '%.*s' failed\n", s.len, ZSW(s.s));
			goto err;
		}

		ul_dbf.close(con);
	}

	d->next = root;
	root = d;

	*_d = d->d;
	return 0;

err:
	if (con) ul_dbf.close(con);
	free_udomain(d->d);
	shm_free(d->name.s);
	shm_free(d);
	return -1;
}


/*! \brief
 * Free all allocated memory
 */
void free_all_udomains(void)
{
	dlist_t* ptr;

	while(root) {
		ptr = root;
		root = root->next;

		free_udomain(ptr->d);
		shm_free(ptr->name.s);
		shm_free(ptr);
	}
}


/*! \brief
 *  Loops through all domains summing up the number of users.
 */
unsigned long get_number_of_users(void* foo)
{
	int numberOfUsers = 0;

	dlist_t* current_dlist;

	current_dlist = root;

	while (current_dlist)
	{
		numberOfUsers += get_stat_val(current_dlist->d->users);
		current_dlist  = current_dlist->next;
	}

	return numberOfUsers;
}


/*! \brief
 * Run through each udomain and:
 *  - on SQL_ONLY:
 *		* delete any expired contacts
 *  - on mem storage:
 *		* update DB state (bulk inserts/updates/deletes)
 *		* clean up any in-memory expired contacts or empty records
 */
int _synchronize_all_udomains(void)
{
	int res = 0;
	dlist_t* ptr;

	get_act_time(); /* Get and save actual time */

	if (cluster_mode == CM_SQL_ONLY) {
		for( ptr=root ; ptr ; ptr=ptr->next)
			res |= db_timer_udomain(ptr->d);
	} else if (have_mem_storage()) {
		for( ptr=root ; ptr ; ptr=ptr->next)
			res |= mem_timer_udomain(ptr->d);
	} /* TODO: add a form of cleanup here, or implement cache API TTLs */

	return res;
}


/*! \brief
 * Find a particular domain
 */
int find_domain(str* _d, udomain_t** _p)
{
	dlist_t* d;

	if (find_dlist(_d, &d) == 0) {
	        *_p = d->d;
		return 0;
	}

	return 1;
}


ucontact_t* get_ucontact_from_id(udomain_t *d, uint64_t contact_id, urecord_t **_r)
{
	int count;
	void **dest;
	unsigned int sl;
	unsigned int rlabel;
	unsigned short aorhash, clabel;

	urecord_t *r;
	ucontact_t *c;

	map_iterator_t it;

	unpack_indexes(contact_id, &aorhash, &rlabel, &clabel);

	sl = aorhash&(d->size-1);
	lock_ulslot(d, sl);

	count = map_size(d->table[sl].records);
	if (count <= 0) {
		unlock_ulslot(d, sl);
		return NULL;
	}

	for (map_first( d->table[sl].records, &it);
			iterator_is_valid(&it);
			iterator_next(&it) ) {

		dest = iterator_val(&it);
		if (dest == NULL) {
			unlock_ulslot(d, sl);
			return NULL;
		}

		r = (urecord_t *)*dest;
		if (r->label != rlabel)
			continue;

		for (c = r->contacts; c != NULL; c = c->next)
			if ((unsigned short)c->label == clabel) {
				*_r = r;
				return c;
			}
	}

	unlock_ulslot(d, sl);
	return NULL;
}

int cdb_delete_ucontact_coords(ucontact_sip_coords *sip_key)
{
	static const cdb_key_t aor_key = {{"aor", 3}, 1}; /* TODO */
	int_str_t val;
	cdb_filter_t *aor_filter;
	cdb_pair_t *pair;
	cdb_dict_t updates;
	cdb_key_t contacts_key;
	int rc = 0;

	val.is_str = 1;
	val.s = sip_key->aor;
	aor_filter = cdb_append_filter(NULL, &aor_key, CDB_OP_EQ, &val);
	if (!aor_filter) {
		LM_ERR("oom\n");
		return -1;
	}

	cdb_dict_init(&updates);
	cdb_key_init(&contacts_key, "contacts"); /* TODO */
	pair = cdb_mk_pair(&contacts_key, &sip_key->ct_key);
	if (!pair) {
		cdb_free_filters(aor_filter);
		LM_ERR("oom\n");
		return -1;
	}

	pair->unset = 1;

	cdb_dict_add(pair, &updates);
	if (cdbf.update(cdbc, aor_filter, &updates) < 0) {
		LM_ERR("failed to delete AoR %.*s, ct: %.*s\n",
		       sip_key->aor.len, sip_key->aor.s,
		       sip_key->ct_key.len, sip_key->ct_key.s);
		rc = -1;
	}

	cdb_free_filters(aor_filter);
	cdb_free_entries(&updates, NULL);
	return rc;
}

int delete_ucontact_from_coords(udomain_t *d, ucontact_coords ct_coords,
                                char skip_replication)
{
	ucontact_t *c, virt_c;
	urecord_t *r;
	ucontact_id contact_id = (ucontact_id)ct_coords;

	LM_DBG("deleting ucoords %llu\n", (unsigned long long)ct_coords);

	/* if contact only in database */
	if (cluster_mode == CM_SQL_ONLY) {
		virt_c.contact_id = contact_id;
		virt_c.domain = d->name;

		if (db_delete_ucontact(&virt_c) < 0) {
			LM_ERR("failed to remove contact from db\n");
			return -1;
		}
		return 0;
	} else if (cluster_mode == CM_FULL_SHARING_CACHEDB) {
		if (cdb_delete_ucontact_coords((ucontact_sip_coords *)(unsigned long)ct_coords)) {
			LM_ERR("failed to remove contact from cache\n");
			return -1;
		}

		return 0;
	}

	c = get_ucontact_from_id(d, contact_id, &r);
	if (!c) {
		LM_DBG("contact with contact id [%"PRIu64"] not found\n", contact_id);
		return 0;
	}

	if (!skip_replication && location_cluster)
		replicate_ucontact_delete(r, c, NULL);

	if (exists_ulcb_type(UL_CONTACT_DELETE)) {
		run_ul_callbacks( UL_CONTACT_DELETE, c);
	}

	if (st_delete_ucontact(c) > 0) {
		if (sql_wmode == SQL_WRITE_THROUGH) {
			if (db_delete_ucontact(c) < 0) {
				LM_ERR("failed to remove contact from database\n");
			}
		}

		mem_delete_ucontact(r, c);
	}

	_unlock_ulslot(d, contact_id);
	return 0;
}

int update_sipping_latency(udomain_t *d, ucontact_coords ct_coords,
                           int new_latency)
{
	ucontact_t *c;
	urecord_t *r;
	ucontact_id contact_id = (ucontact_id)ct_coords;
	int old_latency;

	/* TODO: add cachedb queries for latency updates */
	if (cluster_mode == CM_SQL_ONLY || cluster_mode == CM_FULL_SHARING_CACHEDB)
		return 0;

	c = get_ucontact_from_id(d, contact_id, &r);
	if (c == NULL) {
		LM_WARN("contact with contact id [%" PRIu64 "] not found\n",
				contact_id);
		return 0;
	}
	LM_DBG("sipping latency changed: %d us -> %d us\n",
	       c->sipping_latency, new_latency);

	old_latency = c->sipping_latency;
	c->sipping_latency = new_latency;

	if (latency_event_min_us && new_latency >= latency_event_min_us)
		goto raise_event;

	if (latency_event_min_us_delta && old_latency
	        && abs(new_latency - old_latency >= latency_event_min_us_delta))
		goto raise_event;

	if (!latency_event_min_us && !latency_event_min_us_delta)
		goto raise_event;

	_unlock_ulslot(d, contact_id);
	return 0;

raise_event:
	ul_raise_contact_event(ei_c_latency_update_id, c);
	_unlock_ulslot(d, contact_id);
	return 0;
}


