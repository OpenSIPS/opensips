/*
 * 32-bit Digest parameter name parser
 *
 * Copyright (C) 2001-2003 FhG Fokus
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


#ifndef PARAM_PARSER_H
#define PARAM_PARSER_H

#include "../../str.h"


/*
 * Digest parameter types
 */
typedef enum dig_par {
	PAR_USERNAME,  /* username parameter */
	PAR_REALM,     /* realm parameter */
	PAR_NONCE,     /* nonce parameter */
	PAR_URI,       /* uri parameter */
	PAR_RESPONSE,  /* response parameter */
	PAR_CNONCE,    /* cnonce parameter */
	PAR_OPAQUE,    /* opaque parameter */
	PAR_QOP,       /* qop parameter */
	PAR_NC,        /* nonce-count parameter */
	PAR_ALGORITHM, /* algorithm parameter */
	PAR_AUTS,      /* auts parameter */
	PAR_OTHER      /* unknown parameter */
} dig_par_t;


/*
 * Parse digest parameter name
 */
int parse_param_name(str* _s, dig_par_t* _type);

#endif /* PARAM_PARSER_H */
