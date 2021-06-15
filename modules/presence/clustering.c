/*
 * Copyright (C) 2018 OpenSIPS Solutions
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


#include "../../lib/csv.h"
#include "../../mi/mi.h"
#include "presence.h"
#include "notify.h"
#include "utils_func.h"
#include "clustering.h"

int pres_cluster_id = 0;

int cluster_federation = 0;

str clustering_events = {NULL,0};

static unsigned char clustered_events[EVENT_LINE_SEIZE];

struct clusterer_binds c_api;

static str presence_capability = str_init("presence");

static str empty_val = str_init(" ");

#define CL_PRESENCE_PUBLISH     1
#define CL_PRESENCE_PRES_QUERY  2

#define BIN_VERSION    1

static void bin_packet_handler(bin_packet_t *packet);
static void cluster_event_handler(enum clusterer_event ev, int node_id);


int init_pres_clustering(void)
{
	csv_record *list, *it;
	event_t e;

	/* is clustering needed ? */
	if (!is_presence_cluster_enabled())
		return 0;

	/* load the clusterer api */
	if (load_clusterer_api(&c_api) != 0 ){
		LM_ERR("failed to load clusterer API..that is weird :(\n");
		return -1;
	}

	/* register handler for receiving packets from the clusterer module */
	if (c_api.register_capability( &presence_capability,
		bin_packet_handler, cluster_event_handler, pres_cluster_id,
		(cluster_federation == FEDERATION_FULL_SHARING) ? 1 : 0,
		NODE_CMP_ANY) < 0) {
		LM_ERR("cannot register callbacks to clusterer module!\n");
		return -1;
	}

	if (clustering_events.s) {
		/* parse the event list  */
		clustering_events.len = strlen(clustering_events.s);
		list = parse_csv_record(&clustering_events);
		if (list==NULL) {
			LM_ERR("failed to parse the event CSV list <%.*s>, "
				"ignoring...\n", clustering_events.len,
				clustering_events.s);
		}
		for (it=list ; it ; it=it->next ) {
			if (event_parser( it->s.s, it->s.len, &e)<0) {
				LM_ERR("unknown event <%.*s>, ignoring...\n",
					it->s.len, it->s.s);
			} else {
				clustered_events[e.parsed] = 1;
			}
		}
		free_csv_record(list);
	} else {
		/* enable all the events */
		memset( clustered_events, 1, sizeof(clustered_events) );
	}

	if (cluster_federation == FEDERATION_FULL_SHARING &&
		c_api.request_sync(&presence_capability, pres_cluster_id) < 0)
		LM_ERR("Sync request failed\n");

	return 0;
}


int is_event_clustered( int event_parsed )
{
	return clustered_events[ event_parsed ];
}


static void cluster_broadcast(bin_packet_t *packet, int c_id)
{
	int rc;

	rc = c_api.send_all(packet, c_id);
	switch (rc) {
	case CLUSTERER_CURR_DISABLED:
		LM_INFO("Current node is disabled in cluster: %d\n", c_id);
		return;
	case CLUSTERER_DEST_DOWN:
		LM_INFO("All destinations in cluster: %d are down or probing\n", c_id);
		return;
	case CLUSTERER_SEND_ERR:
		LM_ERR("Error sending in cluster: %d\n", c_id);
		return;
	}

	return;
}


static void cluster_send_to_node(bin_packet_t *packet, int c_id, int node_id)
{
	int rc;

	rc = c_api.send_to(packet, c_id, node_id);
	switch (rc) {
	case CLUSTERER_CURR_DISABLED:
		LM_INFO("cluster %d not reachable\n",c_id);
		return;
	case CLUSTERER_DEST_DOWN:
		LM_INFO("node %d is disabled in cluster %d\n", node_id, c_id);
		return;
	case CLUSTERER_SEND_ERR:
		LM_ERR("Error sending to node %d in cluster %d\n", node_id, c_id);
		return;
	}

	return;
}


static int bin_push_presentity(bin_packet_t *packet, presentity_t *pres)
{
	int step=0;
	str s;

	if (bin_push_str(packet, &pres->user) < 0)
		goto error;
	step++;

	if (bin_push_str(packet, &pres->domain) < 0)
		goto error;
	step++;

	if (bin_push_str(packet, &pres->event->name) < 0)
		goto error;
	step++;

	if (pres->old_etag.s) {
		if (bin_push_str(packet, &pres->old_etag) < 0)
			goto error;
	} else {
		if (bin_push_str(packet, &empty_val) < 0)
			goto error;
	}
	step++;

	if (bin_push_str(packet, &pres->new_etag) < 0)
		goto error;
	step++;

	if (bin_push_int(packet, pres->expires) < 0)
		goto error;
	step++;

	if (bin_push_int(packet, pres->received_time) < 0)
		goto error;
	step++;

	if (pres->sender) {
		if (bin_push_str(packet, pres->sender) < 0)
			goto error;
	} else {
		if (bin_push_str(packet, &empty_val) < 0)
			goto error;
	}
	step++;

	if (pres->extra_hdrs) {
		if (bin_push_str(packet, pres->extra_hdrs) < 0)
			goto error;
	} else {
		if (bin_push_str(packet, &empty_val) < 0)
			goto error;
	}
	step++;

	if (pres->sphere) {
		s.s = pres->sphere;
		s.len = strlen(s.s);
		if (bin_push_str(packet, &s) < 0)
			goto error;
	} else {
		if (bin_push_str(packet, &empty_val) < 0)
			goto error;
	}
	step++;

	if (bin_push_str(packet, &pres->body) < 0)
		goto error;
	step++;

	return 0;
error:
	LM_ERR("failed to push data (step=%d) into bin packet\n",step);
	return -1;
}


void replicate_publish_on_cluster(presentity_t *pres)
{
	bin_packet_t packet;

	memset( &packet, 0, sizeof(bin_packet_t) );
	if (bin_init(&packet, &presence_capability,
		CL_PRESENCE_PUBLISH, BIN_VERSION, 0) < 0)
		LM_ERR("cannot initiate bin packet\n");

	if (bin_push_presentity( &packet, pres)<0) {
		LM_ERR("failed to build replicated publish\n");
	} else {
		cluster_broadcast(&packet, pres_cluster_id);
	}

	bin_free_packet(&packet);

	return;
}


void query_cluster_for_presentity(str *pres_uri, event_t *evp)
{
	bin_packet_t packet;
	unsigned int hash_code;
	cluster_query_entry_t* p;
	int step=0;

	/* check if the presentity is not in the pending list */
	hash_code= core_hash( pres_uri, NULL, phtable_size);
	lock_get( &pres_htable[hash_code].lock );
	p = search_cluster_query( pres_uri, evp->parsed, hash_code);
	if (p!=NULL) {
		lock_release( &pres_htable[hash_code].lock );
		LM_DBG("already waiting for presentity <%.*s>\n",
			pres_uri->len, pres_uri->s);
		return;
	}
	p = insert_cluster_query( pres_uri, evp->parsed, hash_code);
	lock_release( &pres_htable[hash_code].lock );

	if (p==NULL) {
		LM_ERR("failed to insert new cluster query for "
			"presentity <%.*s>, nothing broken but too "
			"much cluster traffic\n",
			pres_uri->len, pres_uri->s);
	}

	if (bin_init(&packet, &presence_capability,
	CL_PRESENCE_PRES_QUERY, BIN_VERSION, 0) < 0) {
		LM_ERR("cannot initiate bin packet\n");
		return;
	}

	if (bin_push_str(&packet, pres_uri) < 0)
		goto error;
	step++;

	if (bin_push_str(&packet, &evp->text) < 0)
		goto error;

	cluster_broadcast(&packet, pres_cluster_id);

	bin_free_packet(&packet);

	return;
error:
	LM_ERR("failed to push data (step=%d) into bin packet\n",step);
	bin_free_packet(&packet);
	return;

}

static int handle_replicated_publish(bin_packet_t *packet)
{
	unsigned int hash_code;
	presentity_t pres;
	event_t ev;
	str sender, extra_hdrs, s;
	int sent_reply;
	pres_entry_t* p;
	int step = 0;

	memset(&pres, 0, sizeof(presentity_t));

	/* username */
	if (bin_pop_str(packet, &pres.user) < 0)
		goto error;
	step++;

	/* domain */
	if (bin_pop_str(packet, &pres.domain) < 0)
		goto error;
	step++;
	LM_DBG("replicated PUBLISH for %.*s / %.*s \n",
		pres.user.len,pres.user.s,
		pres.domain.len,pres.domain.s);

	/* event (convert from name to pointer) */
	if (bin_pop_str(packet, &s) < 0)
		goto error;
	step++;
	if (event_parser(s.s, s.len, &ev) < 0 ||
	(pres.event=search_event(&ev)) == NULL) {
		LM_ERR("Bad/inexisting event <%.*s> received\n", s.len, s.s);
		goto error_all;
	}
	/* do we cluster on this event ?? */
	if (!is_event_clustered( ev.parsed ))
		return 0;

	/* old (received) etag */
	if (bin_pop_str(packet, &s) < 0)
		goto error;
	step++;
	if ( !(s.len==empty_val.len && memcmp(s.s, empty_val.s, s.len)==0) ) {
		pres.old_etag = s;
	}

	/* new (saved) etag */
	if (bin_pop_str(packet, &pres.new_etag) < 0)
		goto error;
	step++;

	/* expires */
	if (bin_pop_int(packet, &pres.expires) < 0)
		goto error;
	step++;

	/* received time */
	if (bin_pop_int(packet, &pres.received_time) < 0)
		goto error;
	step++;

	/* at this point we can check if we are interested in this Publish 
	 * We are if we still have subscribers for it. If there are no 
	 * subscribers for it; but still having the presentity refered by this
	 * PUBLISH, better force the expiration of the presentity in order
	 * to get rid of it and free us from ballast data */
	if ( uandd_to_uri( pres.user, pres.domain, &s)<0) {
		LM_ERR("failed to create presentity uri\n");
		goto error_all;
	}
	/* do we have any record of this presentity ? Let's search */
	hash_code = core_hash( &s, NULL, phtable_size);
	lock_get( &pres_htable[hash_code].lock );
	if (pres.old_etag.s) {
		p = search_phtable_etag( &s, ev.parsed,
				&pres.old_etag, hash_code);
	} else {
		p = NULL;
	}
	/* take the chance of the lock and delete the record for
	 * waiting for a cluster query on this presentity */
	if (cluster_federation == FEDERATION_ON_DEMAND)
		delete_cluster_query( &s, ev.parsed, hash_code);
	lock_release( &pres_htable[hash_code].lock );

	if (cluster_federation == FEDERATION_FULL_SHARING) {
		LM_DBG("Keeping presentity regardless of subscriber existence\n");
	} else if (presentity_has_subscribers(&s, pres.event) == 0) {
		LM_DBG("Presentity has NO local subscribers\n");
		/* no subscribers for this presentity, discard the publish */
		if (p==NULL) {
			pkg_free(s.s); // allocated by uandd_to_uri()
			return 0;
		}

		LM_DBG("Forcing expires 0\n");
		/* force an expire of the presentity */
		pres.expires = 0;
	} else {
		LM_DBG("Presentity has some local subscribers\n");
	}
	pkg_free(s.s); // allocated by uandd_to_uri()

	/* the publish is worthy to be handle, carry on */
	if (p) {
		pres.etag_new = 0;
	} else {
		p = NULL;
		pres.etag_new = 1;
		/* reset the old (received tag) as useless for us; we wil handle
		 * this presentity as a newly created one */
		pres.old_etag.s = NULL;
		pres.old_etag.len = 0;
	}

	/* sender, it may be empty */
	if (bin_pop_str(packet, &s) < 0)
		goto error;
	step++;
	if ( !(s.len==empty_val.len && memcmp(s.s, empty_val.s, s.len)==0) ) {
		sender = s;
		pres.sender = &sender;
	}

	/* extra headers, it may be empty */
	if (bin_pop_str(packet, &s) < 0)
		goto error;
	step++;
	if ( !(s.len==empty_val.len && memcmp(s.s, empty_val.s, s.len)==0) ) {
		extra_hdrs = s;
		pres.extra_hdrs = &extra_hdrs;
	}

	/* sphere, it may be empty */
	if (bin_pop_str(packet, &s) < 0)
		goto error;
	step++;
	if ( !(s.len==empty_val.len && memcmp(s.s, empty_val.s, s.len)==0) ) { 
		/* make it null terminated */
		if ( (pres.sphere = pkg_malloc(s.len+1))==NULL ) {
			LM_ERR("failed to allocate sphere buffer (l=%d)\n",s.len+1);
			goto error_all;
		}
		memcpy(pres.sphere, s.s, s.len);
		pres.sphere[s.len] = '\0';
	}

	/* body */
	if (bin_pop_str(packet, &pres.body) < 0)
		goto error;
	step++;

	/* flags */
	pres.flags = PRES_FLAG_REPLICATED;

	LM_DBG("Updating presentity\n");
	if (update_presentity(NULL/*msg*/, &pres, &sent_reply) <0) {
		LM_ERR("failed to update presentity based on replicated Publish\n");
		goto error_all;
	}

	return 0;
error:
	LM_ERR("failed to pop data (step=%d) from bin packet\n",step);
	return -1;
error_all:
	LM_ERR("failed to handle bin packet %d from node %d\n",
		packet->type, packet->src_id);
	if (pres.sphere)
		pkg_free(pres.sphere);
	return -1;
}


int pack_repl_presentity(bin_packet_t *packet, str *pres_uri, pres_ev_t *ev)
{
	presentity_t pres;
	db_res_t *res = NULL;
	struct sip_uri uri;
	int body_col, extra_hdrs_col, expires_col, etag_col= 0;
	str s;

	/* get the presentity body from the DB, if there */
	if(parse_uri(pres_uri->s, pres_uri->len, &uri)< 0) {
		LM_ERR("failed to parse preentity uri <%.*s>\n",
			pres_uri->len, pres_uri->s);
		return -1;
	}

	res = pres_search_db(&uri, &ev->evp->text, &body_col, &extra_hdrs_col,
		&expires_col, &etag_col);
	if(res==NULL)
		return -1;
	if (res->n<=0 ) {
		LM_DBG("presentity not found in DB: [username]='%.*s'"
			" [domain]='%.*s' [event]='%.*s'\n",uri.user.len, uri.user.s,
			uri.host.len, uri.host.s, ev->evp->text.len, ev->evp->text.s);
		pa_dbf.free_result(pa_db, res);
		return 0;
	}

	/* we have a valid presentity to send back as reply */
	memset(&pres, 0, sizeof(pres));
	pres.user = uri.user;
	pres.domain = uri.host;
	pres.event = ev;
	pres.new_etag.s = (char*)VAL_STRING(ROW_VALUES(RES_ROWS(res))+etag_col);
	pres.new_etag.len = strlen(pres.new_etag.s);
	pres.expires = VAL_INT(ROW_VALUES(RES_ROWS(res))+expires_col) -
		(int)time(NULL);
	pres.received_time = (int)time(NULL);
	if (!VAL_NULL(ROW_VALUES(RES_ROWS(res))+extra_hdrs_col)) {
		s.s = (char*)VAL_STRING(ROW_VALUES(RES_ROWS(res))+extra_hdrs_col);
		s.len = strlen(s.s);
		pres.extra_hdrs = &s;
	}
	pres.body.s = (char*)VAL_STRING(ROW_VALUES(RES_ROWS(res))+body_col);
	pres.body.len = strlen(pres.body.s);

	/* pack and end*/
	if (bin_push_presentity(packet, &pres)<0) {
		LM_ERR("failed to build replicated publish\n");
		bin_free_packet(packet);
		return -1;
	}

	return 1;
}

static int handle_presentity_query(bin_packet_t *packet)
{
	bin_packet_t reply_packet;
	unsigned int hash_code;
	event_t event;
	str pres_uri, s;
	pres_entry_t* p;
	pres_ev_t *ev;
	int step = 0;
	int rc;

	/* presentity URI */
	if (bin_pop_str(packet, &pres_uri) < 0)
		goto error;
	step++;

	/* event (convert from name to pointer) */
	if (bin_pop_str(packet, &s) < 0)
		goto error;
	step++;
	if (event_parser(s.s, s.len, &event) < 0 ) {
		LM_ERR("Bad/inexisting event <%.*s> received\n", s.len, s.s);
		return -1;
	}
	/* do we cluster on this event ?? */
	if (!is_event_clustered( event.parsed ))
		return 0;

	ev = search_event(&event);
	if (!ev)
		return 0;

	/* now, search the presentity ! */
	hash_code= core_hash(&pres_uri, NULL, phtable_size);
	lock_get(&pres_htable[hash_code].lock);
	p= search_phtable(&pres_uri, event.parsed, hash_code);
	lock_release(&pres_htable[hash_code].lock);

	if (p && (p->flags & PRES_FLAG_REPLICATED)!=0 ) {
		/* our presentity is a replicated copy, so we do not answer
		 * to the query; only the real owner of the presentity will
		 * reply */
		return 0;
	}

	memset(&reply_packet, 0, sizeof(bin_packet_t));
	if (bin_init(&reply_packet, &presence_capability,
		CL_PRESENCE_PUBLISH, BIN_VERSION, 0) < 0)
		LM_ERR("cannot initiate bin packet\n");

	rc = pack_repl_presentity(&reply_packet, &pres_uri, ev);
	if (rc < 0) {
		LM_ERR("Failed to pack presentity BIN packet\n");
		bin_free_packet(&reply_packet);
		return -1;
	} else if (rc == 0) { /* presentity not found in DB - we do not answer back */
		bin_free_packet(&reply_packet);
		return 0;
	}

	cluster_send_to_node( &reply_packet, pres_cluster_id, packet->src_id);

	bin_free_packet(&reply_packet);

	return 0;
error:
	LM_ERR("failed to pop data (step=%d) from bin packet\n",step);
	return -1;
}


static void bin_packet_handler(bin_packet_t *packet)
{
	int rc;
	bin_packet_t *pkt;

	for (pkt = packet; pkt; pkt = pkt->next) {
		switch (pkt->type) {
			case CL_PRESENCE_PUBLISH:
				ensure_bin_version(pkt, BIN_VERSION);
				rc = handle_replicated_publish(pkt);
				break;
			case CL_PRESENCE_PRES_QUERY:
				ensure_bin_version(pkt, BIN_VERSION);
				rc = handle_presentity_query(pkt);
				break;
			case SYNC_PACKET_TYPE:
				_ensure_bin_version(pkt, BIN_VERSION, "presence sync packet");
				rc = 0;
				while (c_api.sync_chunk_iter(pkt))
					if (handle_replicated_publish(pkt) < 0) {
						LM_WARN("failed to process sync chunk!\n");
						rc = -1;
					}
				break;
			default:
				LM_ERR("Unknown binary packet %d received from node %d in "
					"presence cluster %d)\n", pkt->type,
					pkt->src_id, pres_cluster_id);
				rc = -1;
		}

		if (rc != 0)
			LM_ERR("failed to process binary packet!\n");
	}
}

static int receive_sync_request(int node_id)
{
	bin_packet_t *sync_packet;
	unsigned int i;
	pres_entry_t* p;
	pres_ev_t *ev;
	event_t event;

	for (i = 0; i < phtable_size; i++)
	{
		lock_get(&pres_htable[i].lock);
		p = pres_htable[i].entries->next;
		while (p) {
			if (!is_event_clustered(p->event)) {
				p = p->next;
				continue;
			}

			memset(&event, 0, sizeof(event));
			event.parsed = p->event;
			ev = search_event(&event);
			if (!ev) {
				p = p->next;
				continue;
			}

			sync_packet = c_api.sync_chunk_start(&presence_capability,
				pres_cluster_id, node_id, BIN_VERSION);
			if (!sync_packet)
				goto error;

			if (pack_repl_presentity(sync_packet, &p->pres_uri, ev) != 1) {
				LM_ERR("Failed to pack presentity BIN packet\n");
				goto error;
			}

			p = p->next;
		}
		lock_release(&pres_htable[i].lock);
	}

	return 0;

error:
	lock_release(&pres_htable[i].lock);
	return -1;
}

static void cluster_event_handler(enum clusterer_event ev, int node_id)
{
	if (ev == SYNC_REQ_RCV && receive_sync_request(node_id) < 0)
		LM_ERR("Failed to send sync data to node: %d\n", node_id);
}
