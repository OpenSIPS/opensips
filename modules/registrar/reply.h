/*
 * Send a reply
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
 * \brief SIP registrar module - send a reply
 * \ingroup registrar
 */


#ifndef REPLY_H
#define REPLY_H

#include "../../parser/msg_parser.h"
#include "../usrloc/ucontact.h"

/*! \brief
 * Send a reply
 */
int send_reply(struct sip_msg* _m, unsigned int _flags);


/*! \brief
 * Build Contact HF for reply
 */
int build_contact(ucontact_t* c,struct sip_msg *_m);


/*! \brief
 * Release contact buffer if any
 */
void free_contact_buf(void);


#endif /* REPLY_H */
