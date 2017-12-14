/*
 * Copyright (C) 2017 OpenSIPS Project
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


#include "../str.h"
#include "hf.h"

/* Set of functions to parse (split into a list of tokens) body headers
 * holding comma separated lists of generic tokens (like Supported, Allow)
 */


/* Linked list element holding an option/token/value from the CSV list
 */
struct list_hdr {
	str token;
	struct list_hdr *next;
};


/* Parses a CSV-body-like header and returns a linked list (in revert order)
 * with all the options/tokens from the body.
 * The body must contain only the CSV (hdr body) part without header name or
 * CRLF.
 * The head of the resulting list is returned via the "lh" parameter.
 * Returns :
 *   0 - on success
 *  -2 - on parse/mem failure
 */
int parse_list_hdr(char *body, int len, struct list_hdr **lh);


/* Checks if the option "val" is present in a CSV body-like header.
 * The header is given directly as an "hdr_field" pointer  and the search
 * will go through all its siblings (instances with same name) IF the 
 * header has a known type (it will not work for HDR_OTHER)
 * Input:
 *    - hdr - the hdr field pointer
 *    - opt - the option to be checked (string)
 * Returns:
 *     0 on the first occurace of the option in the header instances.
 *    -1 on hdr or option not found or on parsing error.
 */
int list_hdr_has_option(struct hdr_field *hdr, str *opt);


/* Frees (pkg mem) a linked list of options/tokens resulted from
 * parsing a CSV-body-like header (see parse_list_hdr() )
 */
void free_list_hdr( struct list_hdr *lh);

