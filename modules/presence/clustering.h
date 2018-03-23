/*
 * presence module - presence server implementation
 *
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



#ifndef _PRESENCE_CLUSTERING_H
#define _PRESENCE_CLUSTERING_H

#include "../clusterer/api.h"
#include "presentity.h"

#define is_sharding_cluster_enabled() (shard_cluster_id>0)

/* The ID of the cluster for distributing/sharding data */
extern int shard_cluster_id;

/* events to be replicated via the sharding cluster */
extern str clustering_events;

int init_pres_clustering(void);

int is_event_clustered( int event_parsed );

void replicate_publish_on_cluster(presentity_t *pres);

void query_cluster_for_presentity(str *pres_uri, event_t *evp);

#endif
