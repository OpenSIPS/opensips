/*
 * Copyright (C) 2011 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef CACHEDB_REDIS_MI_H
#define CACHEDB_REDIS_MI_H

#include "../../mi/mi.h"

#define MI_REDIS_CLUSTER_INFO    "redis_cluster_info"
#define MI_REDIS_CLUSTER_REFRESH "redis_cluster_refresh"
#define MI_REDIS_PING_NODES      "redis_ping_nodes"

mi_response_t *mi_redis_cluster_info(const mi_params_t *params,
    struct mi_handler *async_hdl);
mi_response_t *mi_redis_cluster_info_1(const mi_params_t *params,
    struct mi_handler *async_hdl);
mi_response_t *mi_redis_cluster_refresh(const mi_params_t *params,
    struct mi_handler *async_hdl);
mi_response_t *mi_redis_cluster_refresh_1(const mi_params_t *params,
    struct mi_handler *async_hdl);
mi_response_t *mi_redis_ping_nodes(const mi_params_t *params,
    struct mi_handler *async_hdl);
mi_response_t *mi_redis_ping_nodes_1(const mi_params_t *params,
    struct mi_handler *async_hdl);

#endif
