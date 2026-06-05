/*
 *
 * Copyright (C) 2026 Genesys Cloud Services, Inc.
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

#ifndef _TH_NO_DLG_LOGIC_H
#define _TH_NO_DLG_LOGIC_H

#include "th_common_logic.h"

#include "../tm/t_hooks.h"
#include "../../str.h"
#include "../../context.h"
#include "../../sr_module.h"

enum encode_scheme {ENC_BASE64, ENC_BASE32};

#define TH_INFO_PASSWORD_ROTATION_SIZE 2
#define MAX_ENCODED_SIP_URIS 12

#define DEFAULT_PARAM str_init("thinfo")
#define DEFAULT_PW str_init("ToPoCtPaSS")

typedef struct {
	str param_name;
	str param_password;
	int compact_encoding;
} thinfo_options_t;

extern str decoded_uris[MAX_ENCODED_SIP_URIS];
extern int decoded_uris_count;
extern int ctx_decoded_routes_valid_idx;

#define ctx_decoded_routes_set_valid() \
	context_put_int(CONTEXT_GLOBAL, current_processing_ctx, ctx_decoded_routes_valid_idx, 1)

#define ctx_decoded_routes_is_valid() \
	context_get_int(CONTEXT_GLOBAL, current_processing_ctx, ctx_decoded_routes_valid_idx)

int topo_hiding_no_dlg(struct sip_msg *req, struct cell* t, unsigned int extra_flags, struct th_params *params);
int topo_hiding_match_no_dlg(struct sip_msg *msg);

void th_free_param_passwords(void);
int th_add_encode_param_password(modparam_t type, void *val);
int th_set_use_param(str *);

#endif