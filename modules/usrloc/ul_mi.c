/*
 * Header file for USRLOC MI functions
 *
 * Copyright (C) 2006 Voice Sistem SRL
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
 *
 * 2006-12-01  created (bogdan)
 */

/*! \file
 *  \brief USRLOC - Usrloc MI functions
 *  \ingroup usrloc
 */

#include <string.h>
#include <stdio.h>
#include "../../mi/mi.h"
#include "../../dprint.h"
#include "../../ut.h"
#include "../../qvalue.h"
#include "../../ip_addr.h"
#include "../../rw_locking.h"
#include "ul_mi.h"
#include "dlist.h"
#include "udomain.h"
#include "utime.h"
#include "ul_mod.h"
#include "usrloc.h"
#include "ul_cluster.h"
#include "kv_store.h"


#define MI_UL_CSEQ 1
static str mi_ul_cid = str_init("dfjrewr12386fd6-343@opensips.mi");
static str mi_ul_ua  = str_init("OpenSIPS MI Server");
rw_lock_t *sync_lock = 0;

extern int mi_dump_kv_store;

/************************ helper functions ****************************/

static inline udomain_t* mi_find_domain(str* table)
{
	dlist_t* dom;

	for( dom=root ; dom ; dom=dom->next ) {
		if ((dom->name.len == table->len) &&
		!memcmp(dom->name.s, table->s, table->len))
			return dom->d;
	}
	return 0;
}

static inline int mi_fix_aor(str *aor)
{
	char *p;

	p = memchr( aor->s, '@', aor->len);
	if (use_domain) {
		if (p==NULL)
			return -1;
	} else {
		if (p)
			aor->len = p - aor->s;
	}

	return 0;
}



static inline int mi_add_aor_node(mi_item_t *aor_item, urecord_t* r,
													time_t t, int short_dump)
{
	mi_item_t *cts_arr, *ct_item;
	ucontact_t* c;
	str st, kv_buf;
	char *p;
	int len;

	if (add_mi_string(aor_item, MI_SSTR("AOR"), r->aor.s, r->aor.len) < 0)
		return -1;

	if (short_dump)
		return 0;

	cts_arr = add_mi_array(aor_item, MI_SSTR("Contacts"));
	if (!cts_arr)
		return -1;

	for( c=r->contacts ; c ; c=c->next) {
		/* contact */
		ct_item = add_mi_object(cts_arr, NULL, 0);
		if (!ct_item)
			return -1;

		if (add_mi_string(ct_item, MI_SSTR("Contact"), c->c.s, c->c.len) < 0)
			return -1;

		if (add_mi_string_fmt(ct_item, MI_SSTR("ContactID"), "%llu", c->contact_id) < 0)
			return -1;

		if (c->expires == 0) {
			if (add_mi_string(ct_item, MI_SSTR("Expires"), MI_SSTR("permanent")) < 0)
				return -1;
		} else if (c->expires == UL_EXPIRED_TIME) {
			if (add_mi_string(ct_item, MI_SSTR("Expires"), MI_SSTR("deleted")) < 0)
				return -1;
		} else if (t > c->expires) {
			if (add_mi_string(ct_item, MI_SSTR("Expires"), MI_SSTR("expired")) < 0)
				return -1;
		} else {
			if (add_mi_number(ct_item, MI_SSTR("Expires"), c->expires - t) < 0)
				return -1;
		}

		p = q2str(c->q, (unsigned int*)&len);
		if (add_mi_string(ct_item, MI_SSTR("Q"), p, len) < 0)
			return -1;

		if (add_mi_string(ct_item, MI_SSTR("Callid"),
			c->callid.s, c->callid.len) < 0)
			return -1;

		if (add_mi_number(ct_item, MI_SSTR("Cseq"), c->cseq) < 0)
			return -1;

		if (c->user_agent.len)
			if (add_mi_string(ct_item, MI_SSTR("User-agent"),
				c->user_agent.s, c->user_agent.len) < 0)
				return -1;

		if (c->received.len)
			if (add_mi_string(ct_item, MI_SSTR("Received"),
				c->received.s, c->received.len) < 0)
				return -1;

		if (c->path.len)
			if (add_mi_string(ct_item, MI_SSTR("Path"),
				c->path.s, c->path.len) < 0)
				return -1;

		if (c->state == CS_NEW) {
			if (add_mi_string(ct_item, MI_SSTR("State"), MI_SSTR("CS_NEW")) < 0)
				return -1;
		} else if (c->state == CS_SYNC) {
			if (add_mi_string(ct_item, MI_SSTR("State"), MI_SSTR("CS_SYNC")) < 0)
				return -1;
		} else if (c->state== CS_DIRTY) {
			if (add_mi_string(ct_item, MI_SSTR("State"), MI_SSTR("CS_DIRTY")) < 0)
				return -1;
		} else {
			if (add_mi_string(ct_item, MI_SSTR("State"), MI_SSTR("CS_UNKNOWN")) < 0)
				return -1;
		}

		if (add_mi_number(ct_item, MI_SSTR("Flags"), c->flags) < 0)
			return -1;

		st = bitmask_to_flag_list(FLAG_TYPE_BRANCH, c->cflags);
		if (add_mi_string(ct_item, MI_SSTR("Cflags"), st.s, st.len) < 0)
			return -1;

		if (c->sock) {
			if(c->sock->adv_sock_str.len) {
				if (add_mi_string(ct_item, MI_SSTR("Socket"),
					c->sock->adv_sock_str.s, c->sock->adv_sock_str.len) < 0)
					return -1;
			} else {
				if (add_mi_string(ct_item, MI_SSTR("Socket"),
					c->sock->sock_str.s, c->sock->sock_str.len) < 0)
					return -1;
			}
		}

		if (add_mi_number(ct_item, MI_SSTR("Methods"), c->methods) < 0)
			return -1;

		if (c->attr.len)
			if (add_mi_string(ct_item, MI_SSTR("Attr"), c->attr.s, c->attr.len) < 0)
				return -1;

		if (c->instance.len && c->instance.s)
			if (add_mi_string(ct_item, MI_SSTR("SIP_instance"),
				c->instance.s, c->instance.len) < 0)
				return -1;

		if (c->sipping_latency > 0)
			if (add_mi_number(ct_item, MI_SSTR("Ping-Latency"),
				c->sipping_latency) < 0)
				return -1;

		if (mi_dump_kv_store) {
			kv_buf = store_serialize(c->kv_storage);
			if (!ZSTR(kv_buf) && (add_mi_string(ct_item, MI_SSTR("KV-Store"),
				kv_buf.s, kv_buf.len) < 0)) {
				store_free_buffer(&kv_buf);
				return -1;
			}

			store_free_buffer(&kv_buf);
		}

	} /* for */

	if (mi_dump_kv_store) {
		kv_buf = store_serialize(r->kv_storage);
		if (!ZSTR(kv_buf) && (add_mi_string(aor_item, MI_SSTR("KV-Store"),
				kv_buf.s, kv_buf.len) < 0)) {
				store_free_buffer(&kv_buf);
				return -1;
			}

		store_free_buffer(&kv_buf);
	}

	return 0;
}




/*************************** MI functions *****************************/

/*! \brief
 * Expects 2 nodes: the table name and the AOR
 */
mi_response_t *mi_usrloc_rm_aor(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	udomain_t *dom;
	str aor;
	str table;

	if (get_mi_string_param(params, "table_name", &table.s, &table.len) < 0)
		return init_mi_param_error();

	dom = mi_find_domain(&table);
	if (dom==NULL)
		return init_mi_error(404, MI_SSTR("Table not found"));

	if (get_mi_string_param(params, "aor", &aor.s, &aor.len) < 0)
		return init_mi_param_error();
	if ( mi_fix_aor(&aor)!=0 )
		return init_mi_error(400, MI_SSTR("Domain missing in AOR"));

	lock_udomain( dom, &aor);
	if (delete_urecord( dom, &aor, NULL, 0) < 0) {
		unlock_udomain( dom, &aor);
		return init_mi_error(500, MI_SSTR("Failed to delete AOR"));
	}

	unlock_udomain( dom, &aor);
	return init_mi_result_ok();
}


/*! \brief
 * Expects 3 nodes: the table name, the AOR and contact
 */
mi_response_t *mi_usrloc_rm_contact(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	udomain_t *dom;
	urecord_t *rec;
	ucontact_t* con;
	str aor;
	str contact;
	int ret;
	str table;

	if (get_mi_string_param(params, "table_name", &table.s, &table.len) < 0)
		return init_mi_param_error();

	dom = mi_find_domain(&table);
	if (dom==NULL)
		return init_mi_error(404, MI_SSTR("Table not found"));

	/* process the aor */
	if (get_mi_string_param(params, "aor", &aor.s, &aor.len) < 0)
		return init_mi_param_error();
	if ( mi_fix_aor(&aor)!=0 )
		return init_mi_error(400, MI_SSTR("Domain missing in AOR"));

	lock_udomain( dom, &aor);

	ret = get_urecord( dom, &aor, &rec);
	if (ret == 1) {
		unlock_udomain( dom, &aor);
		return init_mi_error(404, MI_SSTR("AOR not found"));
	}

	if (get_mi_string_param(params, "contact", &contact.s, &contact.len) < 0)
		return init_mi_param_error();
	ret = get_simple_ucontact( rec, &contact, &con);
	if (ret < 0) {
		unlock_udomain( dom, &aor);
		return 0;
	}
	if (ret > 0) {
		unlock_udomain( dom, &aor);
		return init_mi_error(404, MI_SSTR("Contact not found"));
	}

	if (delete_ucontact(rec, con, NULL, 0) < 0) {
		unlock_udomain( dom, &aor);
		return 0;
	}

	release_urecord(rec, 0);
	unlock_udomain( dom, &aor);
	return init_mi_result_ok();
}


mi_response_t *mi_usrloc_dump(const mi_params_t *params, int short_dump)
{
	struct urecord* r;
	dlist_t* dl;
	udomain_t* dom;
	time_t t;
	int i;
	map_iterator_t it;
	void ** dest;
	mi_response_t *resp;
	mi_item_t *resp_obj;
	mi_item_t *domains_arr, *domain_item, *aors_arr, *aor_item;

	resp = init_mi_result_object(&resp_obj);
	if (!resp) {
		LM_ERR("Failed to init mi result\n");
		return 0;
	}

	domains_arr = add_mi_array(resp_obj, MI_SSTR("Domains"));
	if (!domains_arr) {
		LM_ERR("Failed to add mi item\n");
		goto error;
	}

	t = time(0);

	for( dl=root ; dl ; dl=dl->next ) {
		/* add a domain node */
		domain_item = add_mi_object(domains_arr, NULL, 0);
		if (!domain_item) {
			LM_ERR("Failed to add mi item\n");
			goto error;
		}

		if (add_mi_string(domain_item, MI_SSTR("name"),
			dl->name.s, dl->name.len) < 0) {
			LM_ERR("Failed to add mi item\n");
			goto error;
		}

		dom = dl->d;

		if (add_mi_number(domain_item, MI_SSTR("hash_size"), dom->size) < 0) {
			LM_ERR("Failed to add mi item\n");
			goto error;
		}

		aors_arr = add_mi_array(domain_item, MI_SSTR("AORs"));
		if (!aors_arr) {
			LM_ERR("Failed to add mi item\n");
			goto error;
		}

		/* add the entries per hash */
		for(i=0; i<dom->size; i++) {
			lock_ulslot( dom, i);

			for ( map_first( dom->table[i].records, &it);
				iterator_is_valid(&it);
				iterator_next(&it) ) {

				dest = iterator_val(&it);
				if( dest == NULL ) {
					LM_ERR("Failed to get urecord\n");
					goto error_unlock;
				}
				r =( urecord_t * ) *dest;

				aor_item = add_mi_object(aors_arr, NULL, 0);
				if (!aor_item) {
					LM_ERR("Failed to add mi item\n");
					goto error_unlock;
				}

				/* add entry */
				if (mi_add_aor_node(aor_item, r, t, short_dump)!=0) {
					LM_ERR("Failed to add AOR info\n");
					goto error_unlock;
				}
			}

			unlock_ulslot( dom, i);
		}

	}

	return resp;

error_unlock:
	unlock_ulslot( dom, i);
error:
	LM_ERR("Failed to build mi response\n");
	free_mi_response(resp);
	return 0;
}

mi_response_t *w_mi_usrloc_dump(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	return mi_usrloc_dump(params, 0);
}

mi_response_t *w_mi_usrloc_dump_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	int brief;

	if (get_mi_int_param(params, "brief", &brief) < 0)
		return init_mi_param_error();

	return mi_usrloc_dump(params, brief);
}

mi_response_t *mi_usrloc_flush(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	_synchronize_all_udomains();
	return init_mi_result_ok();
}


/*! \brief
 * Expects 7 nodes:
 *        table name,
 *        AOR
 *        contact
 *        expires
 *        Q
 *        useless - backward compat.
 *        flags
 *        cflags
 *        methods
 */
mi_response_t *mi_usrloc_add(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	struct ct_match cmatch = {CT_MATCH_CONTACT_CALLID, NULL};
	ucontact_info_t ci;
	urecord_t* r;
	ucontact_t* c;
	udomain_t *dom;
	str aor;
	str contact;
	int expires_val;
	int n;
	str table;
	str qval;

	if (get_mi_string_param(params, "table_name", &table.s, &table.len) < 0)
		return init_mi_param_error();

	dom = mi_find_domain(&table);
	if (dom==NULL)
		return init_mi_error(404, MI_SSTR("Table not found"));

	if (get_mi_string_param(params, "aor", &aor.s, &aor.len) < 0)
		return init_mi_param_error();
	if ( mi_fix_aor(&aor)!=0 )
		return init_mi_error(400, MI_SSTR("Domain missing in AOR"));

	if (get_mi_string_param(params, "contact", &contact.s, &contact.len) < 0)
		return init_mi_param_error();
	memset( &ci, 0, sizeof(ucontact_info_t));

	if (get_mi_int_param(params, "expires", &expires_val) < 0)
		return init_mi_param_error();
	ci.expires = expires_val;

	if (get_mi_string_param(params, "q", &qval.s, &qval.len) < 0)
		return init_mi_param_error();
	if (str2q( &ci.q, qval.s, qval.len) < 0)
		goto bad_syntax;

	if (get_mi_int_param(params, "flags", (int*)&ci.flags) < 0)
		return init_mi_param_error();

	/* branch flags value (param 8) */
	if (get_mi_int_param(params, "cflags", (int*)&ci.cflags) < 0)
		return init_mi_param_error();

	/* methods value (param 9) */
	if (get_mi_int_param(params, "methods", (int*)&ci.methods) < 0)
		return init_mi_param_error();

	lock_udomain( dom, &aor);

	n = get_urecord( dom, &aor, &r);
	if ( n==1) {
		if (insert_urecord( dom, &aor, &r, 0) < 0)
			goto lock_error;

		c = 0;
	} else {
		if (get_simple_ucontact( r, &contact, &c) < 0)
			goto lock_error;
	}

	get_act_time();

	ci.user_agent = &mi_ul_ua;
	/* 0 expires means permanent contact */
	if (ci.expires!=0)
		ci.expires += act_time;

	if (c) {
		/* update contact record */
		ci.callid = &mi_ul_cid;
		ci.cseq = c->cseq;
		if (update_ucontact( r, c, &ci, &cmatch, 0) < 0)
			goto release_error;
	} else {
		/* new contact record */
		ci.callid = &mi_ul_cid;
		ci.cseq = MI_UL_CSEQ;
		if ( insert_ucontact( r, &contact, &ci, &cmatch, 0, &c) < 0 )
			goto release_error;
	}

	release_urecord(r, 0);

	unlock_udomain( dom, &aor);

	return init_mi_result_ok();
bad_syntax:
	return init_mi_error(400, MI_SSTR("Bad parameter value"));
release_error:
	release_urecord(r, 0);
lock_error:
	unlock_udomain( dom, &aor);
	return init_mi_error(500, MI_SSTR("Internal Error"));
}


/*! \brief
 * Expects 2 nodes: the table name and the AOR
 */
mi_response_t *mi_usrloc_show_contact(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp = NULL;
	mi_item_t *resp_obj;
	udomain_t *dom;
	urecord_t *rec;
	str aor;
	int ret;
	time_t t;
	str table;

	if (get_mi_string_param(params, "table_name", &table.s, &table.len) < 0)
		return init_mi_param_error();
	/* look for table */
	dom = mi_find_domain(&table);
	if (dom==NULL)
		return init_mi_error(404, MI_SSTR("Table not found"));

	/* process the aor */
	if (get_mi_string_param(params, "aor", &aor.s, &aor.len) < 0)
		return init_mi_param_error();
	if ( mi_fix_aor(&aor)!=0 )
		return init_mi_error(400, MI_SSTR("Domain missing in AOR"));

	t = time(0);

	lock_udomain( dom, &aor);

	ret = get_urecord( dom, &aor, &rec);
	if (ret == 1) {
		unlock_udomain( dom, &aor);
		return init_mi_error(404, MI_SSTR("AOR not found"));
	}

	get_act_time();

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		goto error;

	if (mi_add_aor_node(resp_obj, rec, t, 0)!=0)
		goto error;

	unlock_udomain( dom, &aor);

	return resp;

error:
	unlock_udomain( dom, &aor);
	if (resp)
		free_mi_response(resp);
	return 0;
}

static int mi_process_sync(void *param, str key, void *value)
{
	struct ucontact* c;
	struct urecord* rec = (struct urecord *)value;

	if (!rec) {
		LM_ERR("invalid record value for key '%.*s'\n", key.len, key.s);
		return -1;
	}

	for (c = rec->contacts; c; c = c->next) {
		c->state = CS_NEW;
	}
	return 0;
}

static mi_response_t *mi_sync_domain(udomain_t *dom)
{
	int i;
	static db_ps_t my_ps = NULL;

	/* delete whole table */
	if (ul_dbf.use_table(ul_dbh, dom->name) < 0) {
		LM_ERR("use_table failed\n");
		return 0;
	}

	CON_PS_REFERENCE(ul_dbh) = &my_ps;

	if (ul_dbf.delete(ul_dbh, 0, 0, 0, 0) < 0) {
		LM_ERR("failed to delete from database\n");
		return 0;
	}

	for(i=0; i < dom->size; i++) {
		lock_ulslot(dom, i);

		if (map_for_each(dom->table[i].records, mi_process_sync, 0)) {
			LM_ERR("cannot process sync\n");
			goto error;
		}

		unlock_ulslot(dom, i);
	}
	return init_mi_result_ok();
error:
	unlock_ulslot(dom, i);
	return 0;
}

static mi_response_t *mi_sync_aor(udomain_t *dom, str *aor)
{
	urecord_t *rec;

	lock_udomain( dom, aor);
	if (get_urecord( dom, aor, &rec) == 1) {
		unlock_udomain( dom, aor);
		return init_mi_error(404, MI_SSTR("AOR not found"));
	}

	if (db_delete_urecord(rec) < 0) {
		LM_ERR("DB delete failed\n");
		goto error;
	}

	if (mi_process_sync(dom, *aor, rec))
		goto error;

	unlock_udomain( dom, aor);
	return init_mi_result_ok();
error:
	unlock_udomain( dom, aor);
	return 0;
}

mi_response_t *mi_usrloc_sync_1(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	udomain_t *dom;
	str table;
	mi_response_t *res;

	if (sql_wmode == SQL_NO_WRITE)
		return init_mi_error(200, MI_SSTR("Contacts already synced"));

	if (get_mi_string_param(params, "table_name", &table.s, &table.len) < 0)
		return init_mi_param_error();

	dom = mi_find_domain(&table);
	if (dom==NULL)
		return init_mi_error(404, MI_SSTR("Table not found"));

	if (sync_lock)
		lock_start_write(sync_lock);
	res = mi_sync_domain(dom);
	if (sync_lock)
		lock_stop_write(sync_lock);
	return res;
}

mi_response_t *mi_usrloc_sync_2(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	udomain_t *dom;
	str table;
	str aor;

	if (sql_wmode == SQL_NO_WRITE)
		return init_mi_error(200, MI_SSTR("Contacts already synced"));

	if (get_mi_string_param(params, "table_name", &table.s, &table.len) < 0)
		return init_mi_param_error();

	dom = mi_find_domain(&table);
	if (dom==NULL)
		return init_mi_error(404, MI_SSTR("Table not found"));

	if (get_mi_string_param(params, "aor", &aor.s, &aor.len) < 0)
		return init_mi_param_error();

	return mi_sync_aor(dom, &aor);
}

mi_response_t *mi_usrloc_cl_sync(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	if (!location_cluster)
		return init_mi_error(400, MI_SSTR("Clustering not enabled"));

	if (clusterer_api.request_sync(&contact_repl_cap, location_cluster) < 0)
		return init_mi_error(400, MI_SSTR("Failed to send sync request"));
	else
		return init_mi_result_ok();
}
