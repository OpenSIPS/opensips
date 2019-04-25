/*
 * Copyright (C) 2014 OpenSIPS Solutions
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
 *
 */


#ifndef _MC_H
#define _MC_H

#include "../../parser/msg_parser.h"
#define MC_BYTE_SIZE 8
#define HDR_MASK_SIZE (((HDR_EOH_T+1)/(sizeof(char) * MC_BYTE_SIZE)) + 1)
#define WH_TYPE_STR 0
#define WH_TYPE_PVS 1

#define HDR_TYPE_STR 0
#define HDR_TYPE_INT 1

#include "../../pvar.h"

typedef struct mc_other_hdr_lst
{
	str hdr_name;
	struct mc_other_hdr_lst* next;

} mc_other_hdr_lst_t, *mc_other_hdr_lst_p;



typedef struct mc_whitelist
{
	unsigned char hdr_mask[HDR_MASK_SIZE];
	struct mc_other_hdr_lst* other_hdr;
} mc_whitelist_t, *mc_whitelist_p;

typedef struct body_fragm
{
	int begin, end;
	struct body_fragm* next;
} body_frag_t, *body_frag_p;


struct mc_comp_args {
	mc_whitelist_p hdr2compress_list;
	int flags;
	int algo;
};

#endif

