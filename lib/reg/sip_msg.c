/*
 * Registrar specific SIP message processing
 *
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2016 OpenSIPS Solutions
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

#include "../../parser/contact/parse_contact.h"
#include "sip_msg.h"
#include "rerrno.h"

/*! \brief
 * Parse the whole message and bodies of all header fields
 * that will be needed by registrar
 */
int parse_reg_headers(struct sip_msg* _m)
{
	struct hdr_field* ptr;

	if (parse_headers(_m, HDR_EOH_F, 0) == -1) {
		rerrno = R_PARSE;
		LM_ERR("failed to parse headers\n");
		return -1;
	}

	if (!_m->to) {
		rerrno = R_TO_MISS;
		LM_ERR("To not found\n");
		return -2;
	}

	if (!_m->callid) {
		rerrno = R_CID_MISS;
		LM_ERR("Call-ID not found\n");
		return -3;
	}

	if (!_m->cseq) {
		rerrno = R_CS_MISS;
		LM_ERR("CSeq not found\n");
		return -4;
	}

	if (_m->expires && !_m->expires->parsed && (parse_expires(_m->expires) < 0)) {
		rerrno = R_PARSE_EXP;
		LM_ERR("failed to parse expires body\n");
		return -5;
	}

	if (_m->contact) {
		ptr = _m->contact;
		while(ptr) {
			if (ptr->type == HDR_CONTACT_T) {
				if (!ptr->parsed && (parse_contact(ptr) < 0)) {
					rerrno = R_PARSE_CONT;
					LM_ERR("failed to parse Contact body\n");
					return -6;
				}
			}
			ptr = ptr->next;
		}
	}

	return 0;
}

#define has_nonzero_exp(_m) \
	(!_m->expires || !((exp_body_t*)_m->expires->parsed)->valid || \
	 ((exp_body_t*)_m->expires->parsed)->val != 0)

/*! \brief
 * Check if the originating REGISTER message was formed correctly
 * The whole message must be parsed before calling the function
 * _s indicates whether the contact was star
 */
int check_contacts(struct sip_msg* _m, int* _s)
{
	struct hdr_field* p;
	contact_t*  c;

	*_s = 0;
	/* Message without contacts is OK */
	if (_m->contact == 0) return 0;

	if (((contact_body_t*)_m->contact->parsed)->star == 1) {
		/* The first Contact HF is star */
		/* Expires must be zero */
		if (has_nonzero_exp(_m)) {
			rerrno = R_STAR_EXP;
			return 1;
		}

		/* Message must contain no contacts */
		if (((contact_body_t*)_m->contact->parsed)->contacts) {
			rerrno = R_STAR_CONT;
			return 1;
		}

		/* Message must contain no other Contact HFs */
		p = _m->contact->next;
		while(p) {
			if (p->type == HDR_CONTACT_T) {
				rerrno = R_STAR_CONT;
				return 1;
			}
			p = p->next;
		}

		*_s = 1;
	} else { /* The first Contact HF is not star */
		/* Message must contain no star Contact HF */
		p = _m->contact->next;
		while(p) {
			if (p->type == HDR_CONTACT_T) {
				if (((contact_body_t*)p->parsed)->star == 1) {
					rerrno = R_STAR_CONT;
					return 1;
				}
				/* check also the lenght of all contacts */
				for(c=((contact_body_t*)p->parsed)->contacts ; c ; c=c->next) {
					if (c->uri.len > CONTACT_MAX_SIZE
					|| (c->received && c->received->len>RECEIVED_MAX_SIZE) ) {
						rerrno = R_CONTACT_LEN;
						return 1;
					}
				}
			}
			p = p->next;
		}
	}

	return 0;
}

