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


#ifndef _PUA_CLUSTERING_H
#define _PUA_CLUSTERING_H

#include "../../mi/mi.h"
#include "../clusterer/api.h"
#include "hash.h"

/* The ID of the pua cluster */
extern int pua_cluster_id;
/* The clustering sharing TAG for this PUA node */
extern str pua_sh_tag;
extern struct clusterer_binds c_api;


#define is_pua_cluster_enabled() (pua_cluster_id>0)

int init_pua_clustering(void);

void replicate_pres_change(ua_pres_t* pres);

#endif
