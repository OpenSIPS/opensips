/*
 * Usrloc record and contact replication
 *
 * Copyright (C) 2013 OpenSIPS Solutions
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
 * --------
 *  2013-10-09 initial version (Liviu)
 */

#include "ureplication.h"
#include "dlist.h"
#include "../../forward.h"

str repl_module_name = str_init("ul");

/* Skip all DB operations when receiving replicated data */
int skip_replicated_db_ops;
struct clusterer_binds clusterer_api;

/* packet sending */

void replicate_urecord_insert(urecord_t *r)
{
	int rc;
	bin_packet_t packet;

	if (bin_init(&packet, &repl_module_name, REPL_URECORD_INSERT, BIN_VERSION, 1024) != 0) {
		LM_ERR("failed to replicate this event\n");
		return;
	}

	bin_push_str(&packet, r->domain);
	bin_push_str(&packet, &r->aor);

	rc = clusterer_api.send_all(&packet, ul_replicate_cluster);
	switch (rc) {
	case CLUSTERER_CURR_DISABLED:
		LM_INFO("Current node is disabled in cluster: %d\n", ul_replicate_cluster);
		goto error;
	case CLUSTERER_DEST_DOWN:
		LM_INFO("All destinations in cluster: %d are down or probing\n",
			ul_replicate_cluster);
		goto error;
	case CLUSTERER_SEND_ERR:
		LM_ERR("Error sending in cluster: %d\n", ul_replicate_cluster);
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

	if (bin_init(&packet, &repl_module_name, REPL_URECORD_DELETE, BIN_VERSION, 1024) != 0) {
		LM_ERR("failed to replicate this event\n");
		return;
	}

	bin_push_str(&packet, r->domain);
	bin_push_str(&packet, &r->aor);

	rc = clusterer_api.send_all(&packet, ul_replicate_cluster);
	switch (rc) {
	case CLUSTERER_CURR_DISABLED:
		LM_INFO("Current node is disabled in cluster: %d\n", ul_replicate_cluster);
		goto error;
	case CLUSTERER_DEST_DOWN:
		LM_INFO("All destinations in cluster: %d are down or probing\n",
			ul_replicate_cluster);
		goto error;
	case CLUSTERER_SEND_ERR:
		LM_ERR("Error sending in cluster: %d\n", ul_replicate_cluster);
		goto error;
	}

	bin_free_packet(&packet);
	return;

error:
	LM_ERR("replicate urecord delete failed\n");
	bin_free_packet(&packet);
}

void replicate_ucontact_insert(urecord_t *r, str *contact, ucontact_info_t *ci)
{
	str st;
	int rc;
	bin_packet_t packet;

	if (bin_init(&packet, &repl_module_name, REPL_UCONTACT_INSERT, BIN_VERSION, 0) != 0) {
		LM_ERR("failed to replicate this event\n");
		return;
	}

	bin_push_str(&packet, r->domain);
	bin_push_str(&packet, &r->aor);
	bin_push_str(&packet, contact);
	bin_push_str(&packet, ci->callid);
	bin_push_str(&packet, ci->user_agent);
	bin_push_str(&packet, ci->path);
	bin_push_str(&packet, ci->attr);
	bin_push_str(&packet, &ci->received);
	bin_push_str(&packet, &ci->instance);

	st.s = (char *) &ci->expires;
	st.len = sizeof ci->expires;
	bin_push_str(&packet, &st);

	st.s = (char *) &ci->q;
	st.len = sizeof ci->q;
	bin_push_str(&packet, &st);

	bin_push_str(&packet, ci->sock?&ci->sock->sock_str:NULL);
	bin_push_int(&packet, ci->cseq);
	bin_push_int(&packet, ci->flags);
	bin_push_int(&packet, ci->cflags);
	bin_push_int(&packet, ci->methods);

	st.s   = (char *)&ci->last_modified;
	st.len = sizeof ci->last_modified;
	bin_push_str(&packet, &st);

	rc = clusterer_api.send_all(&packet, ul_replicate_cluster);
	switch (rc) {
	case CLUSTERER_CURR_DISABLED:
		LM_INFO("Current node is disabled in cluster: %d\n", ul_replicate_cluster);
		goto error;
	case CLUSTERER_DEST_DOWN:
		LM_INFO("All destinations in cluster: %d are down or probing\n",
			ul_replicate_cluster);
		goto error;
	case CLUSTERER_SEND_ERR:
		LM_ERR("Error sending in cluster: %d\n", ul_replicate_cluster);
		goto error;
	}

	bin_free_packet(&packet);
	return;

error:
	LM_ERR("replicate ucontact insert failed\n");
	bin_free_packet(&packet);
}

void replicate_ucontact_update(urecord_t *r, str *contact, ucontact_info_t *ci)
{
	str st;
	int rc;
	bin_packet_t packet;

	if (bin_init(&packet, &repl_module_name, REPL_UCONTACT_UPDATE, BIN_VERSION, 0) != 0) {
		LM_ERR("failed to replicate this event\n");
		return;
	}

	bin_push_str(&packet, r->domain);
	bin_push_str(&packet, &r->aor);
	bin_push_str(&packet, contact);
	bin_push_str(&packet, ci->callid);
	bin_push_str(&packet, ci->user_agent);
	bin_push_str(&packet, ci->path);
	bin_push_str(&packet, ci->attr);
	bin_push_str(&packet, &ci->received);
	bin_push_str(&packet, &ci->instance);

	st.s = (char *) &ci->expires;
	st.len = sizeof ci->expires;
	bin_push_str(&packet, &st);

	st.s = (char *) &ci->q;
	st.len = sizeof ci->q;
	bin_push_str(&packet, &st);

	bin_push_str(&packet, ci->sock?&ci->sock->sock_str:NULL);
	bin_push_int(&packet, ci->cseq);
	bin_push_int(&packet, ci->flags);
	bin_push_int(&packet, ci->cflags);
	bin_push_int(&packet, ci->methods);

	st.s   = (char *)&ci->last_modified;
	st.len = sizeof ci->last_modified;
	bin_push_str(&packet, &st);

	rc = clusterer_api.send_all(&packet, ul_replicate_cluster);
	switch (rc) {
	case CLUSTERER_CURR_DISABLED:
		LM_INFO("Current node is disabled in cluster: %d\n", ul_replicate_cluster);
		goto error;
	case CLUSTERER_DEST_DOWN:
		LM_INFO("All destinations in cluster: %d are down or probing\n",
			ul_replicate_cluster);
		goto error;
	case CLUSTERER_SEND_ERR:
		LM_ERR("Error sending in cluster: %d\n", ul_replicate_cluster);
		goto error;
	}

	bin_free_packet(&packet);
	return;

error:
	LM_ERR("replicate ucontact update failed\n");
	bin_free_packet(&packet);
}

void replicate_ucontact_delete(urecord_t *r, ucontact_t *c)
{
	int rc;
	bin_packet_t packet;

	if (bin_init(&packet, &repl_module_name, REPL_UCONTACT_DELETE, BIN_VERSION, 0) != 0) {
		LM_ERR("failed to replicate this event\n");
		return;
	}

	bin_push_str(&packet, r->domain);
	bin_push_str(&packet, &r->aor);
	bin_push_str(&packet, &c->c);
	bin_push_str(&packet, &c->callid);
	bin_push_int(&packet, c->cseq);

	rc = clusterer_api.send_all(&packet, ul_replicate_cluster);
	switch (rc) {
	case CLUSTERER_CURR_DISABLED:
		LM_INFO("Current node is disabled in cluster: %d\n", ul_replicate_cluster);
		goto error;
	case CLUSTERER_DEST_DOWN:
		LM_INFO("All destinations in cluster: %d are down or probing\n",
			ul_replicate_cluster);
		goto error;
	case CLUSTERER_SEND_ERR:
		LM_ERR("Error sending in cluster: %d\n", ul_replicate_cluster);
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

	bin_pop_str(packet, &d);
	bin_pop_str(packet, &aor);

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
		user_agent, path, attr, st, sock;
	udomain_t *domain;
	urecord_t *record;
	ucontact_t *contact;
	int port, proto;

	bin_pop_str(packet, &d);
	bin_pop_str(packet, &aor);

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

		ci.sock = grep_sock_info(&host, (unsigned short) port,
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

	if (skip_replicated_db_ops)
		ci.flags |= FL_MEM;

	lock_udomain(domain, &aor);

	if (get_urecord(domain, &aor, &record) != 0) {
		LM_INFO("failed to fetch local urecord - creating new one "
			"(ci: '%.*s') \n", callid.len, callid.s);

		if (insert_urecord(domain, &aor, &record, 1) != 0) {
			LM_ERR("failed to insert new record\n");
			unlock_udomain(domain, &aor);
			goto error;
		}
	}

	if (insert_ucontact(record, &contact_str, &ci, &contact, 1) != 0) {
		LM_ERR("failed to insert ucontact (ci: '%.*s')\n", callid.len, callid.s);
		unlock_udomain(domain, &aor);
		goto error;
	}

	unlock_udomain(domain, &aor);

	return 0;

error:
	LM_ERR("failed to process replication event. dom: '%.*s', aor: '%.*s'\n",
		d.len, d.s, aor.len, aor.s);
	return -1;
}

static int receive_ucontact_update(bin_packet_t *packet)
{
	static ucontact_info_t ci;
	static str d, aor, host, contact_str, callid,
		user_agent, path, attr, st, sock;
	udomain_t *domain;
	urecord_t *record;
	ucontact_t *contact;
	int port, proto;
	int rc;

	bin_pop_str(packet, &d);
	bin_pop_str(packet, &aor);

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

		ci.sock = grep_sock_info(&host, (unsigned short) port,
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

	if (skip_replicated_db_ops)
		ci.flags |= FL_MEM;

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

		if (insert_ucontact(record, &contact_str, &ci, &contact, 1) != 0) {
			LM_ERR("failed (ci: '%.*s')\n", callid.len, callid.s);
			unlock_udomain(domain, &aor);
			goto error;
		}
	} else {
		rc = get_ucontact(record, &contact_str, &callid, ci.cseq + 1, &contact);
		if (rc == 1) {
			LM_INFO("contact '%.*s' not found, inserting new (ci: '%.*s')\n",
				contact_str.len, contact_str.s, callid.len, callid.s);

			if (insert_ucontact(record, &contact_str, &ci, &contact, 1) != 0) {
				LM_ERR("failed to insert ucontact (ci: '%.*s')\n",
					callid.len, callid.s);
				unlock_udomain(domain, &aor);
				goto error;
			}
		} else if (rc == 0) {
			if (update_ucontact(record, contact, &ci, 1) != 0) {
				LM_ERR("failed to update ucontact '%.*s' (ci: '%.*s')\n",
					contact_str.len, contact_str.s, callid.len, callid.s);
				unlock_udomain(domain, &aor);
				goto error;
			}
		} /* XXX: for -2 and -1, the master should have already handled
			 these errors - so we can skip them - razvanc */
	}

	unlock_udomain(domain, &aor);

	return 0;

error:
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

	bin_pop_str(packet, &d);
	bin_pop_str(packet,&aor);
	bin_pop_str(packet,&contact_str);
	bin_pop_str(packet,&callid);
	bin_pop_int(packet,&cseq);

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
		return 0;
	}

	/* simply specify a higher cseq and completely avoid any complications */
	rc = get_ucontact(record, &contact_str, &callid, cseq + 1, &contact);
	if (rc != 0 && rc != 2) {
		LM_ERR("contact '%.*s' not found: (ci: '%.*s')\n", contact_str.len,
			contact_str.s, callid.len, callid.s);
		unlock_udomain(domain, &aor);
		goto error;
	}

	if (skip_replicated_db_ops)
		contact->flags |= FL_MEM;

	if (delete_ucontact(record, contact, 1) != 0) {
		LM_ERR("failed to delete ucontact '%.*s' (ci: '%.*s')\n",
			contact_str.len, contact_str.s, callid.len, callid.s);
		unlock_udomain(domain, &aor);
		goto error;
	}

	unlock_udomain(domain, &aor);

	return 0;

error:
	LM_ERR("failed to process replication event. dom: '%.*s', aor: '%.*s'\n",
	        d.len, d.s, aor.len, aor.s);
	return -1;
}

void receive_binary_packet(enum clusterer_event ev, bin_packet_t *packet, int packet_type,
				struct receive_info *ri, int cluster_id, int src_id, int dest_id)
{
	int rc;

	if (ev == CLUSTER_NODE_DOWN || ev == CLUSTER_NODE_UP)
		return;
	else if (ev == CLUSTER_ROUTE_FAILED) {
		LM_INFO("Failed to route replication packet of type %d from node id: %d "
			"to node id: %d in cluster: %d\n", cluster_id, packet_type, src_id, dest_id);
		return;
	}

	LM_DBG("received a binary packet [%d]!\n", packet_type);

	switch (packet_type) {
	case REPL_URECORD_INSERT:
		rc = receive_urecord_insert(packet);
		break;

	case REPL_URECORD_DELETE:
		rc = receive_urecord_delete(packet);
		break;

	case REPL_UCONTACT_INSERT:
		rc = receive_ucontact_insert(packet);
		break;

	case REPL_UCONTACT_UPDATE:
		rc = receive_ucontact_update(packet);
		break;

	case REPL_UCONTACT_DELETE:
		rc = receive_ucontact_delete(packet);
		break;

	default:
		rc = -1;
		LM_ERR("invalid usrloc binary packet type: %d\n", packet_type);
	}

	if (rc != 0)
		LM_ERR("failed to process a binary packet!\n");
}

