/*
 * user location clustering
 *
 * Copyright (C) 2013-2019 OpenSIPS Solutions
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

#include "../../forward.h"

#include "ul_cluster.h"
#include "ul_mod.h"
#include "dlist.h"
#include "kv_store.h"

str contact_repl_cap = str_init("usrloc-contact-repl");

struct clusterer_binds clusterer_api;
str ul_shtag_key = str_init("_st");

int ul_init_cluster(void)
{
	if (location_cluster == 0)
		return 0;

	if (location_cluster < 0) {
		LM_ERR("Invalid 'location_cluster'!  It must be a positive integer!\n");
		return -1;
	}

	if (load_clusterer_api(&clusterer_api) != 0) {
		LM_ERR("failed to load clusterer API\n");
		return -1;
	}

	/* register handler for processing usrloc packets to the clusterer module */
	if (clusterer_api.register_capability(&contact_repl_cap,
		receive_binary_packets, receive_cluster_event, location_cluster,
		rr_persist == RRP_SYNC_FROM_CLUSTER? 1 : 0,
		(cluster_mode == CM_FEDERATION
		 || cluster_mode == CM_FEDERATION_CACHEDB) ?
			NODE_CMP_EQ_SIP_ADDR : NODE_CMP_ANY) < 0) {
		LM_ERR("cannot register callbacks to clusterer module!\n");
		return -1;
	}

	if (rr_persist == RRP_SYNC_FROM_CLUSTER &&
	    clusterer_api.request_sync(&contact_repl_cap, location_cluster) < 0)
		LM_ERR("Sync request failed\n");

	return 0;
}

/* packet sending */

static inline void bin_push_urecord(bin_packet_t *packet, urecord_t *r)
{
	bin_push_str(packet, r->domain);
	bin_push_str(packet, &r->aor);
	bin_push_int(packet, r->label);
	bin_push_int(packet, r->next_clabel);
}

void replicate_urecord_insert(urecord_t *r)
{
	int rc;
	bin_packet_t packet;

	if (bin_init(&packet, &contact_repl_cap, REPL_URECORD_INSERT,
	             UL_BIN_VERSION, 1024) != 0) {
		LM_ERR("failed to replicate this event\n");
		return;
	}

	bin_push_urecord(&packet, r);

	if (cluster_mode == CM_FEDERATION_CACHEDB)
		rc = clusterer_api.send_all_having(&packet, location_cluster,
		                                   NODE_CMP_EQ_SIP_ADDR);
	else
		rc = clusterer_api.send_all(&packet, location_cluster);
	switch (rc) {
	case CLUSTERER_CURR_DISABLED:
		LM_INFO("Current node is disabled in cluster: %d\n", location_cluster);
		goto error;
	case CLUSTERER_DEST_DOWN:
		LM_INFO("All destinations in cluster: %d are down or probing\n",
			location_cluster);
		goto error;
	case CLUSTERER_SEND_ERR:
		LM_ERR("Error sending in cluster: %d\n", location_cluster);
		goto error;
	}

	bin_free_packet(&packet);
	return;

error:
	LM_ERR("replicate urecord insert failed\n");
	bin_free_packet(&packet);
}

void replicate_urecord_delete(urecord_t *r)
{
	int rc;
	bin_packet_t packet;

	if (bin_init(&packet, &contact_repl_cap, REPL_URECORD_DELETE,
	             UL_BIN_VERSION, 1024) != 0) {
		LM_ERR("failed to replicate this event\n");
		return;
	}

	bin_push_str(&packet, r->domain);
	bin_push_str(&packet, &r->aor);

	if (cluster_mode == CM_FEDERATION_CACHEDB)
		rc = clusterer_api.send_all_having(&packet, location_cluster,
		                                   NODE_CMP_EQ_SIP_ADDR);
	else
		rc = clusterer_api.send_all(&packet, location_cluster);
	switch (rc) {
	case CLUSTERER_CURR_DISABLED:
		LM_INFO("Current node is disabled in cluster: %d\n", location_cluster);
		goto error;
	case CLUSTERER_DEST_DOWN:
		LM_INFO("All destinations in cluster: %d are down or probing\n",
			location_cluster);
		goto error;
	case CLUSTERER_SEND_ERR:
		LM_ERR("Error sending in cluster: %d\n", location_cluster);
		goto error;
	}

	bin_free_packet(&packet);
	return;

error:
	LM_ERR("replicate urecord delete failed\n");
	bin_free_packet(&packet);
}

void bin_push_ctmatch(bin_packet_t *packet, const struct ct_match *match)
{
	str_list *param;
	int np = 0;

	bin_push_int(packet, match->mode);
	if (match->mode != CT_MATCH_PARAMS)
		return;

	for (param = match->match_params; param; param = param->next, np++) {}

	bin_push_int(packet, np);
	for (param = match->match_params; param; param = param->next)
		bin_push_str(packet, &param->s);
}

/* NOTICE: remember to free @match->match_params when done with it! */
void bin_pop_ctmatch(bin_packet_t *packet, struct ct_match *match)
{
	int np;

	memset(match, 0, sizeof *match);

	bin_pop_int(packet, &match->mode);
	if (match->mode != CT_MATCH_PARAMS)
		return;

	bin_pop_int(packet, &np);

	for (; np > 0; np--) {
		str_list *param = pkg_malloc(sizeof *param);
		if (!param) {
			LM_ERR("oom\n");
			free_pkg_str_list(match->match_params);
			*match = (struct ct_match){CT_MATCH_CONTACT_CALLID, NULL};
			return;
		}
		memset(param, 0, sizeof *param);

		bin_pop_str(packet, &param->s);
		add_last(param, match->match_params);
	}
}

void bin_push_contact(bin_packet_t *packet, urecord_t *r, ucontact_t *c,
        const struct ct_match *match)
{
	str st;

	bin_push_str(packet, r->domain);
	bin_push_str(packet, &r->aor);
	bin_push_str(packet, &c->c);

	st.s = (char *)&c->contact_id;
	st.len = sizeof c->contact_id;
	bin_push_str(packet, &st);

	bin_push_str(packet, &c->callid);
	bin_push_str(packet, &c->user_agent);
	bin_push_str(packet, &c->path);
	bin_push_str(packet, &c->attr);
	bin_push_str(packet, &c->received);
	bin_push_str(packet, &c->instance);

	st.s = (char *) &c->expires;
	st.len = sizeof c->expires;
	bin_push_str(packet, &st);

	st.s = (char *) &c->q;
	st.len = sizeof c->q;
	bin_push_str(packet, &st);

	bin_push_str(packet, c->sock?get_socket_internal_name(c->sock):NULL);
	bin_push_int(packet, c->cseq);
	bin_push_int(packet, c->flags);
	bin_push_int(packet, c->cflags);
	bin_push_int(packet, c->methods);

	st.s   = (char *)&c->last_modified;
	st.len = sizeof c->last_modified;
	bin_push_str(packet, &st);

	st = store_serialize(c->kv_storage);
	bin_push_str(packet, &st);
	store_free_buffer(&st);

	bin_push_ctmatch(packet, match);
}

void replicate_ucontact_insert(urecord_t *r, str *contact, ucontact_t *c,
        const struct ct_match *match)
{
	int rc;
	bin_packet_t packet;

	if (bin_init(&packet, &contact_repl_cap, REPL_UCONTACT_INSERT,
	             UL_BIN_VERSION, 0) != 0) {
		LM_ERR("failed to replicate this event\n");
		return;
	}

	bin_push_contact(&packet, r, c, match);

	if (cluster_mode == CM_FEDERATION_CACHEDB)
		rc = clusterer_api.send_all_having(&packet, location_cluster,
		                                   NODE_CMP_EQ_SIP_ADDR);
	else
		rc = clusterer_api.send_all(&packet, location_cluster);
	switch (rc) {
	case CLUSTERER_CURR_DISABLED:
		LM_INFO("Current node is disabled in cluster: %d\n", location_cluster);
		goto error;
	case CLUSTERER_DEST_DOWN:
		LM_INFO("All destinations in cluster: %d are down or probing\n",
			location_cluster);
		goto error;
	case CLUSTERER_SEND_ERR:
		LM_ERR("Error sending in cluster: %d\n", location_cluster);
		goto error;
	}

	bin_free_packet(&packet);
	return;

error:
	LM_ERR("replicate ucontact insert failed\n");
	bin_free_packet(&packet);
}

void replicate_ucontact_update(urecord_t *r, ucontact_t *ct,
        const struct ct_match *match)
{
	str st;
	int rc;
	bin_packet_t packet;

	if (bin_init(&packet, &contact_repl_cap, REPL_UCONTACT_UPDATE,
	             UL_BIN_VERSION, 0) != 0) {
		LM_ERR("failed to replicate this event\n");
		return;
	}

	bin_push_str(&packet, r->domain);
	bin_push_str(&packet, &r->aor);
	bin_push_str(&packet, &ct->c);
	bin_push_str(&packet, &ct->callid);
	bin_push_str(&packet, &ct->user_agent);
	bin_push_str(&packet, &ct->path);
	bin_push_str(&packet, &ct->attr);
	bin_push_str(&packet, &ct->received);
	bin_push_str(&packet, &ct->instance);

	st.s = (char *) &ct->expires;
	st.len = sizeof ct->expires;
	bin_push_str(&packet, &st);

	st.s = (char *) &ct->q;
	st.len = sizeof ct->q;
	bin_push_str(&packet, &st);

	bin_push_str(&packet, ct->sock?get_socket_internal_name(ct->sock):NULL);
	bin_push_int(&packet, ct->cseq);
	bin_push_int(&packet, ct->flags);
	bin_push_int(&packet, ct->cflags);
	bin_push_int(&packet, ct->methods);

	st.s   = (char *)&ct->last_modified;
	st.len = sizeof ct->last_modified;
	bin_push_str(&packet, &st);

	st = store_serialize(ct->kv_storage);
	bin_push_str(&packet, &st);
	store_free_buffer(&st);

	st.s = (char *)&ct->contact_id;
	st.len = sizeof ct->contact_id;
	bin_push_str(&packet, &st);

	bin_push_ctmatch(&packet, match);

	if (cluster_mode == CM_FEDERATION_CACHEDB)
		rc = clusterer_api.send_all_having(&packet, location_cluster,
		                                   NODE_CMP_EQ_SIP_ADDR);
	else
		rc = clusterer_api.send_all(&packet, location_cluster);
	switch (rc) {
	case CLUSTERER_CURR_DISABLED:
		LM_INFO("Current node is disabled in cluster: %d\n", location_cluster);
		goto error;
	case CLUSTERER_DEST_DOWN:
		LM_INFO("All destinations in cluster: %d are down or probing\n",
			location_cluster);
		goto error;
	case CLUSTERER_SEND_ERR:
		LM_ERR("Error sending in cluster: %d\n", location_cluster);
		goto error;
	}

	bin_free_packet(&packet);
	return;

error:
	LM_ERR("replicate ucontact update failed\n");
	bin_free_packet(&packet);
}

void replicate_ucontact_delete(urecord_t *r, ucontact_t *c,
        const struct ct_match *_match)
{
	struct ct_match match;
	int rc;
	bin_packet_t packet;

	if (bin_init(&packet, &contact_repl_cap, REPL_UCONTACT_DELETE,
	             UL_BIN_VERSION, 0) != 0) {
		LM_ERR("failed to replicate this event\n");
		return;
	}

	if (!_match)
		match = (struct ct_match){CT_MATCH_CONTACT_CALLID, NULL};
	else
		match = *_match;

	bin_push_str(&packet, r->domain);
	bin_push_str(&packet, &r->aor);
	bin_push_str(&packet, &c->c);
	bin_push_str(&packet, &c->callid);
	bin_push_int(&packet, c->cseq);
	bin_push_ctmatch(&packet, &match);

	if (cluster_mode == CM_FEDERATION_CACHEDB)
		rc = clusterer_api.send_all_having(&packet, location_cluster,
		                                   NODE_CMP_EQ_SIP_ADDR);
	else
		rc = clusterer_api.send_all(&packet, location_cluster);
	switch (rc) {
	case CLUSTERER_CURR_DISABLED:
		LM_INFO("Current node is disabled in cluster: %d\n", location_cluster);
		goto error;
	case CLUSTERER_DEST_DOWN:
		LM_INFO("All destinations in cluster: %d are down or probing\n",
			location_cluster);
		goto error;
	case CLUSTERER_SEND_ERR:
		LM_ERR("Error sending in cluster: %d\n", location_cluster);
		goto error;
	}

	bin_free_packet(&packet);
	return;

error:
	LM_ERR("replicate ucontact delete failed\n");
	bin_free_packet(&packet);
}

/* packet receiving */

/**
 * Note: prevents the creation of any duplicate AoR
 */
static int receive_urecord_insert(bin_packet_t *packet)
{
	str d, aor;
	urecord_t *r;
	udomain_t *domain;
	int sl;

	bin_pop_str(packet, &d);
	bin_pop_str(packet, &aor);
	if (aor.len == 0) {
		LM_ERR("the AoR URI is missing the 'username' part!\n");
		goto out_err;
	}

	if (find_domain(&d, &domain) != 0) {
		LM_ERR("domain '%.*s' is not local\n", d.len, d.s);
		goto out_err;
	}

	lock_udomain(domain, &aor);

	if (get_urecord(domain, &aor, &r) == 0)
		goto out;

	if (insert_urecord(domain, &aor, &r, 1) != 0) {
		unlock_udomain(domain, &aor);
		goto out_err;
	}

	bin_pop_int(packet, &r->label);
	bin_pop_int(packet, &r->next_clabel);

	sl = r->aorhash & (domain->size - 1);
	if (domain->table[sl].next_label <= r->label)
		domain->table[sl].next_label = r->label + 1;

out:
	unlock_udomain(domain, &aor);

	return 0;

out_err:
	LM_ERR("failed to replicate event locally. dom: '%.*s', aor: '%.*s'\n",
		d.len, d.s, aor.len, aor.s);
	return -1;
}

static int receive_urecord_delete(bin_packet_t *packet)
{
	str d, aor;
	udomain_t *domain;

	bin_pop_str(packet, &d);
	bin_pop_str(packet, &aor);
	if (aor.len == 0) {
		LM_ERR("the AoR URI is missing the 'username' part!\n");
		goto out_err;
	}

	if (find_domain(&d, &domain) != 0) {
		LM_ERR("domain '%.*s' is not local\n", d.len, d.s);
		goto out_err;
	}

	lock_udomain(domain, &aor);

	if (delete_urecord(domain, &aor, NULL, 1) != 0) {
		unlock_udomain(domain, &aor);
		goto out_err;
	}

	unlock_udomain(domain, &aor);

	return 0;

out_err:
	LM_ERR("failed to process replication event. dom: '%.*s', aor: '%.*s'\n",
		d.len, d.s, aor.len, aor.s);
	return -1;
}

static int receive_ucontact_insert(bin_packet_t *packet)
{
	static ucontact_info_t ci;
	static str d, aor, host, contact_str, callid,
		user_agent, path, attr, st, sock, kv_str;
	udomain_t *domain;
	urecord_t *record;
	ucontact_t *contact, *ct;
	int rc, port, proto, sl;
	unsigned short _, clabel;
	unsigned int rlabel;
	struct ct_match cmatch = {CT_MATCH_NONE, NULL};
	short pkg_ver = get_bin_pkg_version(packet);

	memset(&ci, 0, sizeof ci);

	bin_pop_str(packet, &d);
	bin_pop_str(packet, &aor);
	if (aor.len == 0) {
		LM_ERR("the AoR URI is missing the 'username' part!\n");
		goto error;
	}

	if (find_domain(&d, &domain) != 0) {
		LM_ERR("domain '%.*s' is not local\n", d.len, d.s);
		goto error;
	}

	bin_pop_str(packet, &contact_str);

	bin_pop_str(packet, &st);
	memcpy(&ci.contact_id, st.s, sizeof ci.contact_id);

	bin_pop_str(packet, &callid);
	ci.callid = &callid;

	bin_pop_str(packet, &user_agent);
	ci.user_agent = &user_agent;

	bin_pop_str(packet, &path);
	ci.path = &path;

	bin_pop_str(packet, &attr);
	ci.attr = &attr;

	bin_pop_str(packet, &ci.received);
	bin_pop_str(packet, &ci.instance);

	bin_pop_str(packet, &st);
	memcpy(&ci.expires, st.s, sizeof ci.expires);

	bin_pop_str(packet, &st);
	memcpy(&ci.q, st.s, sizeof ci.q);

	bin_pop_str(packet, &sock);

	if (sock.s && sock.s[0]) {
		if (parse_phostport(sock.s, sock.len, &host.s, &host.len,
			&port, &proto) != 0) {
			LM_ERR("bad socket <%.*s>\n", sock.len, sock.s);
			goto error;
		}

		ci.sock = grep_internal_sock_info(&host, (unsigned short) port,
			(unsigned short) proto);
		if (!ci.sock)
			LM_DBG("non-local socket <%.*s>\n", sock.len, sock.s);
	} else {
		ci.sock =  NULL;
	}

	bin_pop_int(packet, &ci.cseq);
	bin_pop_int(packet, &ci.flags);
	bin_pop_int(packet, &ci.cflags);
	bin_pop_int(packet, &ci.methods);

	bin_pop_str(packet, &st);
	memcpy(&ci.last_modified, st.s, sizeof ci.last_modified);

	bin_pop_str(packet, &kv_str);
	ci.packed_kv_storage = &kv_str;

	if (pkg_ver <= UL_BIN_V2)
		cmatch = (struct ct_match){CT_MATCH_CONTACT_CALLID, NULL};
	else
		bin_pop_ctmatch(packet, &cmatch);

	if (skip_replicated_db_ops)
		ci.flags |= FL_MEM;

	unpack_indexes(ci.contact_id, &_, &rlabel, &clabel);

	lock_udomain(domain, &aor);

	if (get_urecord(domain, &aor, &record) != 0) {
		LM_INFO("failed to fetch local urecord - creating new one "
			"(ci: '%.*s') \n", callid.len, callid.s);

		if (insert_urecord(domain, &aor, &record, 1) != 0) {
			LM_ERR("failed to insert new record\n");
			unlock_udomain(domain, &aor);
			goto error;
		}

		record->label = rlabel;
		sl = record->aorhash & (domain->size - 1);
		if (domain->table[sl].next_label <= rlabel)
			domain->table[sl].next_label = rlabel + 1;
	}

	if (record->label != rlabel) {
		int has_good_cts = 0;

		for (ct = record->contacts; ct; ct = ct->next)
			if (ct->expires != UL_EXPIRED_TIME) {
				has_good_cts = 1;
				break;
			}

		if (has_good_cts) {
			LM_BUG("differring rlabels (%u vs. %u, ci: '%.*s')",
			       record->label, rlabel, callid.len, callid.s);
		} else {
			/* no contacts -> it's safe to inherit the active node's rlabel */
			record->label = rlabel;
			sl = record->aorhash & (domain->size - 1);
			if (domain->table[sl].next_label <= rlabel)
				domain->table[sl].next_label = rlabel + 1;
		}
	}

	if (record->next_clabel <= clabel)
		record->next_clabel = CLABEL_INC_AND_TEST(clabel);

	rc = get_ucontact(record, &contact_str, &callid, ci.cseq, &cmatch,
		&contact);

	switch (rc) {
	case -2:
		/* received data is consistent with what we have */
	case -1:
		/* received data is older than what we have */
		break;
	case 0:
		/* received data is newer than what we have */
		if (update_ucontact(record, contact, &ci, NULL, 1) != 0) {
			LM_ERR("failed to update ucontact (ci: '%.*s')\n", callid.len, callid.s);
			unlock_udomain(domain, &aor);
			goto error;
		}
		break;
	case 1:
		if (insert_ucontact(record, &contact_str, &ci, NULL, 1, &contact) != 0) {
			LM_ERR("failed to insert ucontact (ci: '%.*s')\n", callid.len, callid.s);
			unlock_udomain(domain, &aor);
			goto error;
		}
		break;
	}

	unlock_udomain(domain, &aor);

	free_pkg_str_list(cmatch.match_params);
	return 0;

error:
	free_pkg_str_list(cmatch.match_params);
	LM_ERR("failed to process replication event. dom: '%.*s', aor: '%.*s'\n",
		d.len, d.s, aor.len, aor.s);
	return -1;
}

static int receive_ucontact_update(bin_packet_t *packet)
{
	static ucontact_info_t ci;
	static str d, aor, host, contact_str, callid,
		user_agent, path, attr, st, kv_str, sock;
	udomain_t *domain;
	urecord_t *record;
	ucontact_t *contact;
	int port, proto, rc, sl;
	unsigned short _, clabel;
	unsigned int rlabel;
	struct ct_match cmatch = {CT_MATCH_NONE, NULL};
	short pkg_ver = get_bin_pkg_version(packet);

	memset(&ci, 0, sizeof ci);

	bin_pop_str(packet, &d);
	bin_pop_str(packet, &aor);
	if (aor.len == 0) {
		LM_ERR("the AoR URI is missing the 'username' part!\n");
		goto error;
	}

	if (find_domain(&d, &domain) != 0) {
		LM_ERR("domain '%.*s' is not local\n", d.len, d.s);
		goto error;
	}

	bin_pop_str(packet, &contact_str);

	bin_pop_str(packet, &callid);
	ci.callid = &callid;

	bin_pop_str(packet, &user_agent);
	ci.user_agent = &user_agent;

	bin_pop_str(packet, &path);
	ci.path = &path;

	bin_pop_str(packet, &attr);
	ci.attr = &attr;

	bin_pop_str(packet, &ci.received);
	bin_pop_str(packet, &ci.instance);

	bin_pop_str(packet, &st);
	memcpy(&ci.expires, st.s, sizeof ci.expires);

	bin_pop_str(packet, &st);
	memcpy(&ci.q, st.s, sizeof ci.q);

	bin_pop_str(packet, &sock);

	if (sock.s && sock.s[0]) {
		if (parse_phostport(sock.s, sock.len, &host.s, &host.len,
			&port, &proto) != 0) {
			LM_ERR("bad socket <%.*s>\n", sock.len, sock.s);
			goto error;
		}

		ci.sock = grep_internal_sock_info(&host, (unsigned short) port,
			(unsigned short) proto);
		if (!ci.sock)
			LM_DBG("non-local socket <%.*s>\n", sock.len, sock.s);
	} else {
		ci.sock = NULL;
	}

	bin_pop_int(packet, &ci.cseq);
	bin_pop_int(packet, &ci.flags);
	bin_pop_int(packet, &ci.cflags);
	bin_pop_int(packet, &ci.methods);

	bin_pop_str(packet, &st);
	memcpy(&ci.last_modified, st.s, sizeof ci.last_modified);

	bin_pop_str(packet, &kv_str);
	ci.packed_kv_storage = &kv_str;

	if (skip_replicated_db_ops)
		ci.flags |= FL_MEM;

	bin_pop_str(packet, &st);
	memcpy(&ci.contact_id, st.s, sizeof ci.contact_id);

	unpack_indexes(ci.contact_id, &_, &rlabel, &clabel);

	if (pkg_ver <= UL_BIN_V2)
		cmatch = (struct ct_match){CT_MATCH_CONTACT_CALLID, NULL};
	else
		bin_pop_ctmatch(packet, &cmatch);

	lock_udomain(domain, &aor);

	/* failure in retrieving a urecord may be ok, because packet order in UDP
	 * is not guaranteed, so update commands may arrive before inserts */
	if (get_urecord(domain, &aor, &record) != 0) {
		LM_INFO("failed to fetch local urecord - create new record and contact"
			" (ci: '%.*s')\n", callid.len, callid.s);

		if (insert_urecord(domain, &aor, &record, 1) != 0) {
			LM_ERR("failed to insert urecord\n");
			unlock_udomain(domain, &aor);
			goto error;
		}

		record->label = rlabel;
		sl = record->aorhash & (domain->size - 1);
		if (domain->table[sl].next_label <= record->label)
			domain->table[sl].next_label = record->label + 1;

		if (insert_ucontact(record, &contact_str, &ci, NULL, 1, &contact) != 0) {
			LM_ERR("failed (ci: '%.*s')\n", callid.len, callid.s);
			unlock_udomain(domain, &aor);
			goto error;
		}

		if (record->next_clabel <= clabel)
			record->next_clabel = CLABEL_INC_AND_TEST(clabel);
	} else {
		rc = get_ucontact(record, &contact_str, &callid, ci.cseq + 1, &cmatch,
			&contact);
		if (rc == 1) {
			LM_INFO("contact '%.*s' not found, inserting new (ci: '%.*s')\n",
				contact_str.len, contact_str.s, callid.len, callid.s);

			if (insert_ucontact(record, &contact_str, &ci, NULL, 1, &contact) != 0) {
				LM_ERR("failed to insert ucontact (ci: '%.*s')\n",
					callid.len, callid.s);
				unlock_udomain(domain, &aor);
				goto error;
			}

			if (record->next_clabel <= clabel)
				record->next_clabel = CLABEL_INC_AND_TEST(clabel);

		} else if (rc == 0) {
			if (update_ucontact(record, contact, &ci, NULL, 1) != 0) {
				LM_ERR("failed to update ucontact '%.*s' (ci: '%.*s')\n",
					contact_str.len, contact_str.s, callid.len, callid.s);
				unlock_udomain(domain, &aor);
				goto error;
			}
		} /* XXX: for -2 and -1, the master should have already handled
			 these errors - so we can skip them - razvanc */
	}

	unlock_udomain(domain, &aor);

	free_pkg_str_list(cmatch.match_params);
	return 0;

error:
	free_pkg_str_list(cmatch.match_params);
	LM_ERR("failed to process replication event. dom: '%.*s', aor: '%.*s'\n",
		d.len, d.s, aor.len, aor.s);
	return -1;
}

static int receive_ucontact_delete(bin_packet_t *packet)
{
	udomain_t *domain;
	urecord_t *record;
	ucontact_t *contact;
	str d, aor, contact_str, callid;
	int cseq, rc;
	struct ct_match cmatch = {CT_MATCH_NONE, NULL};
	short pkg_ver = get_bin_pkg_version(packet);

	bin_pop_str(packet, &d);
	bin_pop_str(packet, &aor);
	if (aor.len == 0) {
		LM_ERR("the AoR URI is missing the 'username' part!\n");
		goto error;
	}

	bin_pop_str(packet, &contact_str);
	bin_pop_str(packet, &callid);
	bin_pop_int(packet, &cseq);

	if (pkg_ver <= UL_BIN_V2)
		cmatch = (struct ct_match){CT_MATCH_CONTACT_CALLID, NULL};
	else
		bin_pop_ctmatch(packet, &cmatch);

	if (find_domain(&d, &domain) != 0) {
		LM_ERR("domain '%.*s' is not local\n", d.len, d.s);
		goto error;
	}

	lock_udomain(domain, &aor);

	/* failure in retrieving a urecord may be ok, because packet order in UDP
	 * is not guaranteed, so urecord_delete commands may arrive before
	 * ucontact_delete's */
	if (get_urecord(domain, &aor, &record) != 0) {
		LM_INFO("failed to fetch local urecord - ignoring request "
			"(ci: '%.*s')\n", callid.len, callid.s);
		unlock_udomain(domain, &aor);
		goto out;
	}

	/* simply specify a higher cseq and completely avoid any complications */
	rc = get_ucontact(record, &contact_str, &callid, cseq + 1, &cmatch,
		&contact);
	if (rc != 0 && rc != 2) {
		LM_ERR("contact '%.*s' not found: (ci: '%.*s')\n", contact_str.len,
			contact_str.s, callid.len, callid.s);
		unlock_udomain(domain, &aor);
		goto error;
	}

	if (skip_replicated_db_ops)
		contact->flags |= FL_MEM;

	if (delete_ucontact(record, contact, NULL, 1) != 0) {
		LM_ERR("failed to delete ucontact '%.*s' (ci: '%.*s')\n",
			contact_str.len, contact_str.s, callid.len, callid.s);
		unlock_udomain(domain, &aor);
		goto error;
	}

	unlock_udomain(domain, &aor);

out:
	free_pkg_str_list(cmatch.match_params);
	return 0;

error:
	free_pkg_str_list(cmatch.match_params);
	LM_ERR("failed to process replication event. dom: '%.*s', aor: '%.*s'\n",
	        d.len, d.s, aor.len, aor.s);
	return -1;
}

static int receive_sync_packet(bin_packet_t *packet)
{
	int is_contact;
	int rc = -1;

	while (clusterer_api.sync_chunk_iter(packet)) {
		bin_pop_int(packet, &is_contact);
		if (is_contact) {
			if (receive_ucontact_insert(packet) == 0)
				rc = 0;
		} else
			if (receive_urecord_insert(packet) == 0)
				rc = 0;
	}

	return rc;
}

void receive_binary_packets(bin_packet_t *packet)
{
	int rc;
	bin_packet_t *pkt;

	for (pkt = packet; pkt; pkt = pkt->next) {
		/* Supported smooth BIN transitions:
			UL_BIN_V2 -> UL_BIN_V3: the "cmatch" has been added
							(assume: CT_MATCH_CONTACT_CALLID if not present)
		*/
		short ver = get_bin_pkg_version(pkt);

		LM_DBG("received a binary packet [%d]!\n", pkt->type);

		switch (pkt->type) {
		case REPL_URECORD_INSERT:
			if (ver != UL_BIN_V2)
				ensure_bin_version(pkt, UL_BIN_VERSION);
			rc = receive_urecord_insert(pkt);
			break;

		case REPL_URECORD_DELETE:
			if (ver != UL_BIN_V2)
				ensure_bin_version(pkt, UL_BIN_VERSION);
			rc = receive_urecord_delete(pkt);
			break;

		case REPL_UCONTACT_INSERT:
			if (ver != UL_BIN_V2)
				ensure_bin_version(pkt, UL_BIN_VERSION);
			rc = receive_ucontact_insert(pkt);
			break;

		case REPL_UCONTACT_UPDATE:
			if (ver != UL_BIN_V2)
				ensure_bin_version(pkt, UL_BIN_VERSION);
			rc = receive_ucontact_update(pkt);
			break;

		case REPL_UCONTACT_DELETE:
			if (ver != UL_BIN_V2)
				ensure_bin_version(pkt, UL_BIN_VERSION);
			rc = receive_ucontact_delete(pkt);
			break;

		case SYNC_PACKET_TYPE:
			if (ver != UL_BIN_V2)
				_ensure_bin_version(pkt, UL_BIN_VERSION, "usrloc sync packet");
			rc = receive_sync_packet(pkt);
			break;

		default:
			rc = -1;
			LM_ERR("invalid usrloc binary packet type: %d\n", pkt->type);
		}

		if (rc != 0)
			LM_ERR("failed to process binary packet!\n");
	}
}

static int receive_sync_request(int node_id)
{
	struct ct_match cmatch = {CT_MATCH_CONTACT_CALLID, NULL};
	bin_packet_t *sync_packet;
	dlist_t *dl;
	udomain_t *dom;
	map_iterator_t it;
	struct urecord *r;
	ucontact_t* c;
	void **p;
	int i;

	for (dl = root; dl; dl = dl->next) {
		dom = dl->d;
		for(i = 0; i < dom->size; i++) {
			lock_ulslot(dom, i);
			for (map_first(dom->table[i].records, &it);
				iterator_is_valid(&it);
				iterator_next(&it)) {

				p = iterator_val(&it);
				if (p == NULL)
					goto error_unlock;
				r = (urecord_t *)*p;

				sync_packet = clusterer_api.sync_chunk_start(&contact_repl_cap,
									location_cluster, node_id, UL_BIN_VERSION);
				if (!sync_packet)
					goto error_unlock;

				/* urecord in this chunk */
				bin_push_int(sync_packet, 0);
				bin_push_urecord(sync_packet, r);

				for (c = r->contacts; c; c = c->next) {
					sync_packet = clusterer_api.sync_chunk_start(&contact_repl_cap,
										location_cluster, node_id, UL_BIN_VERSION);
					if (!sync_packet)
						goto error_unlock;

					/* ucontact in this chunk */
					bin_push_int(sync_packet, 1);
					bin_push_contact(sync_packet, r, c, &cmatch);
				}
			}
			unlock_ulslot(dom, i);
		}
	}

	return 0;

error_unlock:
	unlock_ulslot(dom, i);
	return -1;
}

void receive_cluster_event(enum clusterer_event ev, int node_id)
{
	if (ev == SYNC_REQ_RCV && receive_sync_request(node_id) < 0)
		LM_ERR("Failed to send sync data to node: %d\n", node_id);
}

