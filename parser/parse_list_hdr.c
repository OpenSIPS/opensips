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

#include <ctype.h>
#include <strings.h>
#include "../mem/mem.h"
#include "parse_list_hdr.h"


/* Frees (pkg mem) a linked list of options/tokens resulted from
 * parsing a CSV-body-like header (see parse_list_hdr() )
 */
void free_list_hdr( struct list_hdr *lh)
{
	if (lh==NULL)
		return;
	free_list_hdr(lh->next);
	pkg_free(lh);
}


#define add_token_to_list(_token_start, _token_end, _head) \
	do { \
		curr = (struct list_hdr*)pkg_malloc(sizeof(struct list_hdr)); \
		if (curr==NULL) { \
			LM_ERR("failed to allocate new token in pkg\n"); \
			goto error; \
		} \
		curr->token.s = _token_start; \
		curr->token.len = _token_end - _token_start; \
		curr->next = head; \
		head = curr; \
	}while(0)


/* Parses a CSV-body-like header and returns a linked list (in revert order)
 * with all the options/tokens from the body.
 * The body must contain only the CSV (hdr body) part without header name or
 * CRLF.
 * The head of the resulting list is returned via the "lh" parameter.
 * Returns :
 *   0 - on success
 *  -2 - on parse/mem failure
 */
int parse_list_hdr(char *body, int len, struct list_hdr **lh)
{
	struct list_hdr *head, *curr;
	char *token_start, *token_end;
	char *p, *end;

	p = body;
	end = body + len;

	head = NULL;

	while (p<end) {
		/* eat spaces */
		while (isspace(*p) && p<end)
			p++;
		if (p==end)
			goto parse_error;

		/* eat token */
		token_start = p;
		while ((isalnum(*p) || (*p=='-') || (*p=='.') || (*p=='!')
		|| (*p=='%') || (*p=='*') || (*p=='_') || (*p=='+') || (*p=='`')
		|| (*p=='\'') || (*p=='~')) && p<end)
			p++;
		if (p==token_start)
			goto parse_error;
		token_end = p;

		/* eat spaces */
		while (isspace(*p) && p<end)
			p++;
		if (p==end || *p==',')
			add_token_to_list(token_start, token_end, head);
		if (*p==',') p++;
	}

	*lh = head;
	return 0;

parse_error:
	LM_ERR("parse error in list hdr body [%.*s] around position "
		"%d\n", len, body, (int)(long)(p-body));
error:
	free_list_hdr( head );
	return -1;
}


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
int list_hdr_has_option(struct hdr_field *hdr, str *opt)
{
	struct list_hdr *lh, *lh_it;

	while (hdr) {

		/* parse the body of the header */
		if (parse_list_hdr( hdr->body.s, hdr->body.len, &lh)!=0) {

			LM_ERR("failed to parse body <%.*s> as CSV for hdr <%.*s>\n",
				hdr->body.len, hdr->body.s, hdr->name.len, hdr->name.s);
			/* skip this header, try next */

		} else {

			/* search the value in the list */
			for( lh_it=lh ; lh_it ; lh_it=lh_it->next ) {
				LM_DBG("testing option <%.*s>/%d against <%.*s>/%d\n",
					lh_it->token.len, lh_it->token.s, lh_it->token.len,
					opt->len, opt->s, opt->len);
				if (lh_it->token.len==opt->len &&
				strncasecmp(lh_it->token.s, opt->s, opt->len)==0 ) {
					/* found */
					free_list_hdr(lh);
					return 0;
				}
			}
			free_list_hdr(lh);
			lh = NULL;

		}

		/* not in this header, try the next hdr if any */
		hdr = hdr->sibling;
	}

	/* option not found in any header instaces */
	return -1;
}
