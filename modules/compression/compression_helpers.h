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


#ifndef _MC_HLP_H
#define _MC_HLP_H

#include "compression.h"

extern unsigned char* compact_form_mask;
extern unsigned char* mnd_hdrs_mask;
#define B64_ENCODED_FLG		1 << 0
#define BODY_COMP_FLG		1 << 1
#define HDR_COMP_FLG		1 << 2
#define SEPARATE_COMP_FLG	1 << 3

unsigned char get_compact_form(struct hdr_field*);
int append_hdr(mc_whitelist_p, str*);
int build_hdr_masks(void);
int parse_whitelist(str*, mc_whitelist_p*, unsigned char*);
int fixup_compression_flags(void**);
int fixup_compression_flags_free(void **);
int free_whitelist(mc_whitelist_p whitelist);
int free_hdr_list(struct hdr_field** hdr_lst_p);
int free_hdr_mask(struct hdr_field** hdr_mask);
int check_zlib_rc(int rc);
int wrap_realloc(str* buf, int new_len);
#endif
