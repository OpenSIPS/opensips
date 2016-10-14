/*
 * SDP parser helpers
 *
 * Copyright (C) 2008 SOMA Networks, INC.
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
 *
 *
 * History:
 * --------
 * 2007-09-09 ported helper functions from nathelper module (osas)
 * 2008-04-22 integrated RFC4975 attributes - patch provided by Denis Bilenko (denik)
 *
 */



#ifndef _SDP_HLPR_FUNCS_H
#define  _SDP_HLPR_FUNCS_H

#include "../../str.h"
#include "../msg_parser.h"

int extract_field(str *body, str *value, str field);
int extract_rtpmap(str *body, str *rtpmap_payload, str *rtpmap_encoding, str *rtpmap_clockrate, str *rtpmap_parmas);
int extract_fmtp( str *body, str *fmtp_payload, str *fmtp_string );
int extract_ptime(str *body, str *ptime);
int extract_sendrecv_mode(str *body, str *sendrecv_mode, int *is_on_hold);
int extract_mediaip(str *body, str *mediaip, int *pf, char *line);
int extract_media_attr(str *body, str *mediamedia, str *mediaport, str *mediatransport, str *mediapayload, int *is_rtp);
int extract_bwidth(str *body, str *bwtype, str *bwwitdth);

/* RFC3605 attributes */
int extract_rtcp(str *body, str *rtcp);

/* RFC4975 attributes */
int extract_accept_types(str *body, str *accept_types);
int extract_accept_wrapped_types(str *body, str *accept_wrapped_types);
int extract_max_size(str *body, str *max_size);
int extract_path(str *body, str *path);

char *find_sdp_line(char *p, char *plimit, char linechar);
char *find_next_sdp_line(char *p, char *plimit, char linechar, char *defptr);
char *find_sdp_line_complex(char* p, char* plimit, char * name);

char* get_sdp_hdr_field(char* , char* , struct hdr_field* );

#endif
