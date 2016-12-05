/*
 * SIP message related functions
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
/*!
 * \file
 * \brief SIP registrar module - SIP message related functions
 * \ingroup registrar
 */


#ifndef SIP_MSG_H
#define SIP_MSG_H

#include "../../qvalue.h"
#include "../../parser/msg_parser.h"
#include "../../parser/contact/parse_contact.h"

struct save_ctx {
	unsigned int flags;
	str aor;
	unsigned int max_contacts;
	unsigned int min_expires;
	unsigned int max_expires;
};

/*! \brief
 * Calculate absolute expires value per contact as follows:
 * 1) If the contact has expires value, use the value. If it
 *    is not zero, add actual time to it
 * 2) If the contact has no expires parameter, use expires
 *    header field in the same way
 * 3) If the message contained no expires header field, use
 *    the default value
 */
void calc_contact_expires(struct sip_msg* _m, param_t* _ep, int* _e, struct save_ctx *_sctx);


/*! \brief
 * Calculate contact q value as follows:
 * 1) If q parameter exist, use it
 * 2) If the parameter doesn't exist, use default value
 */
int calc_contact_q(param_t* _q, qvalue_t* _r);

#endif /* SIP_MSG_H */
