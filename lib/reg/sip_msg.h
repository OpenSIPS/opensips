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

#ifndef __LIB_REG_CONTACT__
#define __LIB_REG_CONTACT__

#include "../../parser/hf.h"
#include "../../dprint.h"
#include "../../parser/parse_expires.h"
#include "../../parser/contact/contact.h"
#include "../../ut.h"
#include "../../qvalue.h"

#define allowed_method(_msg, _c, _f) \
	(!((_f) & REG_LOOKUP_METHODFILTER_FLAG) || \
		((_msg)->REQ_METHOD) & ((_c)->methods))

extern int disable_gruu;
extern char tgruu_dec[];
extern str gruu_secret;

/*! \brief
 * Parse the whole message and bodies of all header fields
 * that will be needed by registrar
 */
int parse_reg_headers(struct sip_msg* _m);

/*! \brief
 * Extract Address Of Record
 */
int extract_aor(str* _uri, str* _a, str *sip_instance, str* call_id,
                int use_domain);

/*! \brief
 * Check if the originating REGISTER message was formed correctly
 * The whole message must be parsed before calling the function
 * @_s indicates whether the contact was star
 *
 * Return
 *	0 (success): Contacts OK or completely missing or unparsed
 *  1 (failure): star Contact related error or Contact length exceeded
 */
int check_contacts(struct sip_msg* _m, int* _s);

/*! \brief
 * Calculate contact q value as follows:
 * 1) If q parameter exist, use it
 * 2) If the parameter doesn't exist, use default value
 */
extern qvalue_t default_q;
int calc_contact_q(param_t* _q, qvalue_t* _r);


/*! \brief
 * Iterators through all Contact hf values of a SIP request
 *
 * Note: each pair of functions has a global state, so two pairs are
 * provided in order to satisfy most nested iteration needs
 *
 * Return: NULL on star, missing or unparsed Contact header, otherwise the ptr
 */
contact_t* get_first_contact(struct sip_msg* _m);
contact_t* get_next_contact(contact_t* _c);
void reset_first_contact(void);

contact_t* get_first_contact2(struct sip_msg* _m);
contact_t* get_next_contact2(contact_t* _c);
void reset_first_contact2(void);

#endif /* __LIB_REG_CONTACT__ */
