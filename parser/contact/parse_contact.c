/*
 * Contact header field body parser
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
 *
 * History:
 * -------
 *  2003-03-25 Adapted to use new parameter parser (janakj)
 */

#include <string.h>          /* memset */
#include "../hf.h"
#include "../../mem/mem.h"   /* pkg_malloc, pkg_free */
#include "../../dprint.h"
#include "../../trim.h"      /* trim_leading */
#include "../../errinfo.h"      /* trim_leading */
#include "parse_contact.h"



static inline int contact_parser(char* _s, int _l, contact_body_t* _c)
{
	str tmp;

	tmp.s = _s;
	tmp.len = _l;

	trim_leading(&tmp);

	if (tmp.len == 0) {
		LM_ERR("empty body\n");
		return -1;
	}

	if (tmp.s[0] == '*') {
		_c->star = 1;
		if (tmp.len!=1) {
			LM_ERR("invalid START Contact header (more than START only)\n");
			return -2;
		}
	} else {
		if (parse_contacts(&tmp, &(_c->contacts)) < 0) {
			LM_ERR("failed to parse contacts\n");
			return -3;
		}
	}

	return 0;
}


/*
 * Parse contact header field body
 */
int parse_contact(struct hdr_field* _h)
{
	contact_body_t* b;

	if (_h->parsed != 0) {
		return 0;  /* Already parsed */
	}

	b = (contact_body_t*)pkg_malloc(sizeof(contact_body_t));
	if (b == 0) {
		LM_ERR("no pkg memory left\n");
		return -1;
	}

	memset(b, 0, sizeof(contact_body_t));

	if (contact_parser(_h->body.s, _h->body.len, b) < 0) {
		LM_ERR("failed to parse contact\n");
		pkg_free(b);
		set_err_info(OSER_EC_PARSER, OSER_EL_MEDIUM,
			"error parsing CONTACT headers");
		set_err_reply(400, "bad headers");
		return -2;
	}

	_h->parsed = (void*)b;
	return 0;
}


/*
 * Free all memory
 */
void free_contact(contact_body_t** _c)
{
	if ((*_c)->contacts) {
		free_contacts(&((*_c)->contacts));
	}

	pkg_free(*_c);
	*_c = 0;
}


/*
 * Print structure, for debugging only
 */
void log_contact(contact_body_t* _c)
{
	LM_DBG("===Contact body===\n");
	LM_DBG("star: %d\n", _c->star);
	log_contacts(_c->contacts);
	LM_DBG("===/Contact body===\n");
}


/*
 * Contact header field iterator, returns next contact if any, it doesn't
 * parse message header if not absolutely necessary
 */
int contact_iterator(contact_t** c, struct sip_msg* msg, contact_t* prev)
{
	static struct hdr_field* hdr = 0;
	struct hdr_field* last;
	contact_body_t* cb;

	if (!msg) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}

	if (!prev) {
		     /* No pointer to previous contact given, find topmost
		      * contact and return pointer to the first contact
		      * inside that header field
		      */
		hdr = msg->contact;
		if (!hdr) {
			if (parse_headers(msg, HDR_CONTACT_F, 0) == -1) {
				LM_ERR("failed to parse headers\n");
				return -1;
			}

			hdr = msg->contact;
		}

		if (hdr) {
			if (parse_contact(hdr) < 0) {
				LM_ERR("failed to parse Contact\n");
				return -1;
			}
		} else {
			*c = 0;
			return 1;
		}

		cb = (contact_body_t*)hdr->parsed;
		*c = cb->contacts;
		return 0;
	} else {
		     /* Check if there is another contact in the
		      * same header field and if so then return it
		      */
		if (prev->next) {
			*c = prev->next;
			return 0;
		}

		     /* Try to find and parse another Contact
		      * header field
		      */
		last = hdr;
		hdr = hdr->next;

		     /* Search another already parsed Contact
		      * header field
		      */
		while(hdr && hdr->type != HDR_CONTACT_T) {
			hdr = hdr->next;
		}

		if (!hdr) {
			     /* Look for another Contact HF in unparsed
			      * part of the message header
			      */
			if (parse_headers(msg, HDR_CONTACT_F, 1) == -1) {
				LM_ERR("failed to parse message header\n");
				return -1;
			}

			     /* Check if last found header field is Contact
			      * and if it is not the same header field as the
			      * previous Contact HF (that indicates that the previous
			      * one was the last header field in the header)
			      */
			if ((msg->last_header->type == HDR_CONTACT_T) &&
			    (msg->last_header != last)) {
				hdr = msg->last_header;
			} else {
				*c = 0;
				return 1;
			}
		}

		if (parse_contact(hdr) < 0) {
			LM_ERR("failed to parse Contact HF body\n");
			return -1;
		}

		     /* And return first contact within that
		      * header field
		      */
		cb = (contact_body_t*)hdr->parsed;
		*c = cb->contacts;
		return 0;
	}
}
