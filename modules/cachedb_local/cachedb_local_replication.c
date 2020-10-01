/*
 * memory cache system replication
 *
 * Copyright (C) 2018 Fabian Gast
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
 */

#include "../../cachedb/cachedb.h"
#include "../../cachedb/cachedb_con.h"
#include "../../timer.h"
#include "hash.h"
#include "cachedb_local.h"
#include "cachedb_local_replication.h"

struct clusterer_binds clusterer_api;

int cache_replicated_insert(bin_packet_t *packet)
{
        int expires;
        str attr, value, col_name;
        lcache_col_t *col;

        LM_DBG("Received replicated cache entry\n");
        if (bin_pop_str(packet, &col_name) < 0)
                goto error;
        if (bin_pop_str(packet, &attr) < 0)
                goto error;
        if (bin_pop_str(packet, &value) < 0)
                goto error;

        if (bin_pop_int(packet, &expires) < 0)
                expires = 0;

        for (col = lcache_collection; col && str_strcmp(&col_name, &col->col_name);
                col = col->next) ;
        if (!col) {
                LM_ERR("Collection: %.*s not found\n", col_name.len, col_name.s);
                return -1;
        }

        if ((_lcache_htable_insert(col, &attr, &value, expires, 1)) < 0) {
                LM_ERR("Can not insert...\n");
                return -1;
        }

        return 0;
error:
        LM_ERR("Failed to pop data from bin packet\n");
        return -1;
}

int cache_replicated_remove(bin_packet_t *packet)
{
        str attr, col_name;
        lcache_col_t *col;

        LM_DBG("Received replicated cache remove\n");
        if (bin_pop_str(packet, &col_name) < 0)
                goto error;
        if (bin_pop_str(packet, &attr) < 0)
                goto error;

        for (col = lcache_collection; col && str_strcmp(&col_name, &col->col_name);
                col = col->next) ;
        if (!col) {
                LM_ERR("Collection: %.*s not found\n", col_name.len, col_name.s);
                return -1;
        }

        if ((_lcache_htable_remove(col, &attr, 1)) < 0) {
                LM_ERR("Can not remove from cache\n");
                return -1;
        }
        return 0;
error:
        LM_ERR("Failed to pop data from bin packet\n");
        return -1;
}

void replicate_cache_insert(str* col, str* attr, str* value, int expires)
{
        int rc;
        bin_packet_t packet;

        if (bin_init(&packet, &cache_repl_cap, REPL_CACHE_INSERT, BIN_VERSION, 1024) != 0) {
                LM_ERR("failed to replicate this event\n");
                return;
        }

        bin_push_str(&packet, col);
        bin_push_str(&packet, attr);
        bin_push_str(&packet, value);
        bin_push_int(&packet, expires);

        rc = clusterer_api.send_all(&packet, cluster_id);
        switch (rc) {
                case CLUSTERER_CURR_DISABLED:
                        LM_INFO("Current node is disabled in cluster: %d\n", cluster_id);
                        goto error;
                case CLUSTERER_DEST_DOWN:
                	LM_INFO("All destinations in cluster: %d are down or probing\n",
                	cluster_id);
                	goto error;
                case CLUSTERER_SEND_ERR:
                	LM_ERR("Error sending in cluster: %d\n", cluster_id);
                	goto error;
        }
        bin_free_packet(&packet);
        return;

error:
        LM_ERR("replicate local cache insert failed (%d)\n", rc);
        bin_free_packet(&packet);
}

void replicate_cache_remove(str* col, str *attr)
{
        int rc;
        bin_packet_t packet;

        if (bin_init(&packet, &cache_repl_cap, REPL_CACHE_REMOVE, BIN_VERSION, 1024) != 0) {
                LM_ERR("failed to replicate this event\n");
                return;
        }

        bin_push_str(&packet, col);
        bin_push_str(&packet, attr);

        rc = clusterer_api.send_all(&packet, cluster_id);
        switch (rc) {
                case CLUSTERER_CURR_DISABLED:
                        LM_INFO("Current node is disabled in cluster: %d\n", cluster_id);
                        goto error;
                case CLUSTERER_DEST_DOWN:
                	LM_INFO("All destinations in cluster: %d are down or probing\n",
                	cluster_id);
                	goto error;
                case CLUSTERER_SEND_ERR:
                	LM_ERR("Error sending in cluster: %d\n", cluster_id);
                	goto error;
        }
        bin_free_packet(&packet);
        return;

error:
        LM_ERR("replicate local cache insert failed (%d)\n", rc);
        bin_free_packet(&packet);
}

int receive_sync_request(int node_id)
{
        int i;
        lcache_col_t *col;
        lcache_entry_t *data;
        bin_packet_t *sync_packet;

        for ( col=lcache_collection; col; col=col->next ) {
                LM_DBG("Found collection %.*s\n", col->col_name.len, col->col_name.s);

                for (i =0; i < col->size; i++) {
                        lock_get(&col->col_htable[i].lock);
                        data = col->col_htable[i].entries;
                        while(data) {
                                if (data->expires == 0 || data->expires > get_ticks()) {
                                        sync_packet = clusterer_api.sync_chunk_start(&cache_repl_cap,
                                                                        cluster_id, node_id, BIN_VERSION);
                                        if (!sync_packet) {
                                                LM_ERR("Can not create sync packet!\n");
                                                return -1;
                                        }
                                        bin_push_str(sync_packet, &col->col_name);
                                        bin_push_str(sync_packet, &data->attr);
                                        bin_push_str(sync_packet, &data->value);
                                        bin_push_int(sync_packet, data->expires);
                                }
                                data = data->next;
                        }
                        lock_release(&col->col_htable[i].lock);
                }
        }

        return 0;
}

void receive_cluster_event(enum clusterer_event ev, int node_id)
{
	if (ev == SYNC_REQ_RCV && receive_sync_request(node_id) < 0)
		LM_ERR("Failed to send sync data to node: %d\n", node_id);
}

void receive_binary_packet(bin_packet_t *packet)
{
        int rc = 0;
        bin_packet_t * pkt;
        for (pkt = packet; pkt; pkt = pkt->next) {
                LM_DBG("Got cache replication packet %d\n", pkt->type);
                switch(pkt->type) {
                        case REPL_CACHE_INSERT:
                        rc = cache_replicated_insert(pkt);
                        break;
                        case REPL_CACHE_REMOVE:
                        rc = cache_replicated_remove(pkt);
                        break;
                        case SYNC_PACKET_TYPE:
        			while (clusterer_api.sync_chunk_iter(pkt))
        				if (cache_replicated_insert(pkt) < 0) {
        					LM_ERR("Failed to process sync packet\n");
        					return;
        				}
        			break;
                default:
                        rc = -1;
                        LM_WARN("Invalid cache binary packet command: %d "
                                "(from node: %d in cluster: %d)\n", pkt->type, pkt->src_id,
                                cluster_id);
                }
                if (rc != 0)
			LM_ERR("Failed to process a binary packet!\n");
        }
}
