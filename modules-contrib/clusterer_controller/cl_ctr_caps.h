/*
 * clusterer_controller - capability bits: declarations
 *
 * Copyright (C) 2026 Yury Kirsanov
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

#ifndef CL_CTR_CAPS_H
#define CL_CTR_CAPS_H

#include "cl_ctr.h"

/* advertised on ALIVE after the maintenance byte; used only towards nodes with
 * the bit (or while all live members have it) - append, never renumber */
#define CL_CTR_CAP_PROBE            0x00000001u /* answers MASTER_PROBE       */
#define CL_CTR_CAP_MAINT_SET        0x00000002u /* applies MAINT_SET to itself */
#define CL_CTR_CAP_MAINT_FULL       0x00000004u /* acts on the full level      */
#define CL_CTR_CAP_ADMISSION        0x00000008u /* waits on JOIN_WAIT, reads the
                                                   CONNECTING relay            */
#define CL_CTR_CAP_HEARTBEAT        0x00000010u /* links and capability states
                                                   ride ALIVE, no BIN pings    */
#define CL_CTR_CAP_MCAST_DATA       0x00000020u /* takes module broadcasts by
                                                   multicast (mcast_broadcasts) */
/* a test build with -DCL_CTR_CAPS_MINE=0 stands in for an older one of the
 * same wire version (netns suite, T27) */
#ifndef CL_CTR_CAPS_MINE
#define CL_CTR_CAPS_MINE            (CL_CTR_CAP_PROBE | CL_CTR_CAP_MAINT_SET | \
                                     CL_CTR_CAP_MAINT_FULL | CL_CTR_CAP_ADMISSION | \
                                     CL_CTR_CAP_HEARTBEAT | CL_CTR_CAP_MCAST_DATA)
#endif
#define CL_CTR_CAPS_SZ              4

/* this node's bits in @cl: mcast-data only while its broadcast socket is open */
uint32_t cl_ctr_caps_mine(cl_ctr_cluster_t *cl);

/* bits every live member in this node's table shares, self included -
 * meaningful on the master, which hears them all */
uint32_t cl_ctr_table_caps(cl_ctr_cluster_t *cl);
/* bits every live member shares: computed on the master, as last relayed on
 * a member */
uint32_t cl_ctr_cluster_caps(cl_ctr_cluster_t *cl);
/* an MI array @name of the capability names set in @caps */
int  cl_ctr_mi_add_caps(mi_item_t *obj, const char *name, int name_len,
                        uint32_t caps);

#endif /* CL_CTR_CAPS_H */
