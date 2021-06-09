/*
 * Copyright (C) 2021 OpenSIPS Solutions
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

#include "pua.h"
#include "clustering.h"

int pua_cluster_id = 0;
str pua_sh_tag = {NULL,0};

struct clusterer_binds c_api;

static str pua_capability = str_init("pua");

static str empty_val = str_init(" ");


#define CL_PUA_UPDATE_PRES     1
#define CL_PUA_BIN_VERSION     1


static void bin_packet_handler(bin_packet_t *packet);


int init_pua_clustering(void)
{
	/* is clustering needed ? */
	if (is_pua_cluster_enabled()) {
		if (pua_sh_tag.s==NULL) {
			LM_ERR("when enabling clustering, you need to set a "
				"'sharing_tag' value too\n");
				return -1;
		}
		pua_sh_tag.len = strlen(pua_sh_tag.s);
	} else {
		if (pua_sh_tag.s) {
			LM_WARN("'sharing_tag' configured, but clustering disabled,"
				" ignoring...\n");
			pkg_free( pua_sh_tag.s);
			pua_sh_tag.s = NULL;
			pua_sh_tag.len = 0;
		}
		return 0;
	}

	/* load the clusterer api */
	if (load_clusterer_api(&c_api) != 0 ){
		LM_ERR("failed to load clusterer API..that is weird :(\n");
		return -1;
	}

	/* register handler for receiving packets from the clusterer module */
	if (c_api.register_capability( &pua_capability,
		bin_packet_handler, NULL, pua_cluster_id, 0/*sync*/,
		NODE_CMP_ANY) < 0) {
		LM_ERR("cannot register callbacks to clusterer module!\n");
		return -1;
	}

	return 0;
}


static int handle_pres_update(bin_packet_t *packet)
{
	unsigned int hash_index, label_index;
	ua_pres_t pres;
	str s, uri;
	int step = 0;

	memset(&pres, 0, sizeof(ua_pres_t));

	/* uri */
	if (bin_pop_str(packet, &uri) < 0)
		goto error;
	pres.pres_uri = &uri;
	step++;

	/* flags */
	if (bin_pop_int(packet, &pres.flag) < 0)
		goto error;
	step++;

	/* id */
	if (bin_pop_str(packet, &pres.id) < 0)
		goto error;
	step++;

	/* event id */
	if (bin_pop_int(packet, &pres.event) < 0)
		goto error;
	step++;

	/* etag */
	if (bin_pop_str(packet, &s) < 0)
		goto error;
	step++;
	if ( !(s.len==empty_val.len && memcmp(s.s, empty_val.s, s.len)==0) ) {
		pres.etag = s;
	}

	LM_DBG("replicated PUA update for %.*s / id <%.*s> \n",
		pres.pres_uri->len, pres.pres_uri->s,
		pres.id.len, pres.id.s);

	/* we have all the data about the update presentity, let's search for it
	 * If we find it, we will have to remove it from hash and reload from DB 
	 * If not found, it means we not care about this presentity, so discard */

	if (get_record_coordinates( &pres, &hash_index, &label_index)<0) {
		LM_DBG("not having this presentity in hash, nothing to updated\n");
		return 0;
	}

	/* load the presentity record (updated) from DB
	 * and do the replacement */
	pres.hash_index = hash_index;
	pres.local_index = label_index;
	if ( db_restore( &pres ) < 0 ) {
		LM_ERR("failed to restore updated record from DB\n");
		return -1;
	}

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
			case CL_PUA_UPDATE_PRES:
				ensure_bin_version(pkt, CL_PUA_BIN_VERSION);
				rc = handle_pres_update(pkt);
				break;
			default:
				LM_ERR("Unknown binary packet %d received from node %d in "
					"pua cluster %d)\n", pkt->type,
					pkt->src_id, pua_cluster_id);
				rc = -1;
		}

		if (rc != 0)
			LM_ERR("failed to process binary packet!\n");
	}

}


static void pua_cluster_broadcast(bin_packet_t *packet, int c_id)
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


static int bin_push_pres_update(bin_packet_t *packet, ua_pres_t *pres)
{
	int step=0;

	if (bin_push_str(packet, pres->pres_uri) < 0)
		goto error;
	step++;

	if (bin_push_int(packet, pres->flag) < 0)
		goto error;
	step++;

	if (bin_push_str(packet, &pres->id) < 0)
		goto error;
	step++;

	if (bin_push_int(packet, pres->event) < 0)
		goto error;
	step++;

	if (pres->etag.s) {
		if (bin_push_str(packet, &pres->etag) < 0)
			goto error;
	} else {
		if (bin_push_str(packet, &empty_val) < 0)
			goto error;
	}
	step++;

	return 0;
error:
	LM_ERR("failed to push data (step=%d) into bin packet\n",step);
	return -1;
}


void replicate_pres_change(ua_pres_t* pres)
{
	bin_packet_t packet;

	memset( &packet, 0, sizeof(bin_packet_t) );
	if (bin_init(&packet, &pua_capability,
		CL_PUA_UPDATE_PRES, CL_PUA_BIN_VERSION, 0) < 0)
		LM_ERR("cannot initiate bin packet\n");

	if (bin_push_pres_update( &packet, pres)<0) {
		LM_ERR("failed to build replicated publish\n");
	} else {
		pua_cluster_broadcast(&packet, pua_cluster_id);
	}

	bin_free_packet(&packet);

	return;
}


