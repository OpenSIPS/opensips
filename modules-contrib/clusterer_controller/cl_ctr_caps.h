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
/* a test build with -DCL_CTR_CAPS_MINE=0 stands in for an older one of the
 * same wire version (netns suite, T27) */
#ifndef CL_CTR_CAPS_MINE
#define CL_CTR_CAPS_MINE            (CL_CTR_CAP_PROBE | CL_CTR_CAP_MAINT_SET | \
                                     CL_CTR_CAP_MAINT_FULL)
#endif
#define CL_CTR_CAPS_SZ              4

/* bits every live member in this node's table shares, self included -
 * meaningful on the master, which hears them all */
uint32_t cl_ctr_table_caps(cl_ctr_cluster_t *cl);
/* bits every live member shares: computed on the master, as last relayed on
 * a member */
uint32_t cl_ctr_cluster_caps(cl_ctr_cluster_t *cl);
/* an MI array @name of the capability names set in @caps */
int  cl_ctr_mi_add_caps(mi_item_t *obj, const char *name, int name_len,
                        uint32_t caps);
/* can maintenance @st be set here or on another node (@remote), given what every
 * live member shares? 0, or -1 with the reason in @why */
int  cl_ctr_maint_supported(cl_ctr_cluster_t *cl, int remote, int st,
                            char *why, int why_sz);

#endif /* CL_CTR_CAPS_H */
