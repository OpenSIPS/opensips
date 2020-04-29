/*
 * Lookup contacts in usrloc
 *
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2020 OpenSIPS Solutions
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

/*!
 * \file
 * \brief SIP registrar module - lookup contacts in usrloc
 * \ingroup registrar
 */


#ifndef LOOKUP_H
#define LOOKUP_H

#include "../../parser/msg_parser.h"


/*! \brief
 * Lookup a contact in usrloc and rewrite R-URI if found
 *
 * Return: see lookup_rc
 */
int reg_lookup(struct sip_msg* _m, void* _t, str* flags_s, str* uri);

/*! \brief the is_registered() function
 * Return 1 if the AOR is registered, -1 otherwise
 * AOR comes from:
 *	- "from" header on REGISTER
 *	- "to" header on any other SIP REQUEST
 *	- aor parameter of the function
 */
int is_registered(struct sip_msg* _m, void *_d, str* _a);

/*! \brief the is_contact_registered() function
 * Return 1 if the contact and/or callid is registered
 * for a given AOR, -1 when not found
 * AOR comes from:
 *	- "from" header on REGISTER
 *	- "to" header on any other SIP REQUEST
 *	- aor parameter of the function
 *
 * Contact comes from:
 *  - first valid "Contact" header when neither contact nor
 *  callid params are provided
 *  - the contact parameter (third parameter)
 */
int is_contact_registered(struct sip_msg* _m, void *_d, str* _a,
							str* _c, str* _cid);

/*! \brief the is_ip_registered() function
 * Return 1 if the IPs are registered for the received parameter
 * for a contact inside the given AOR
 * -1 when not found
 *
 * IPs comes from:
 * - the IPs avp given as a third parameter
 */
int is_ip_registered(struct sip_msg* _m, void* _d, str* _a, pv_spec_t *spec);
#endif /* LOOKUP_H */
