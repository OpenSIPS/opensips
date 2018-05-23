/*
 * Functions that process REGISTER message
 * and store data in usrloc
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
 * 2003-03-21  save_noreply added, provided by Maxim Sobolev
 *             <sobomax@portaone.com> (janakj)
 * 2006-11-22  save_noreply and save_memory merged into save() (bogdan)
 */
/*!
 * \file
 * \brief SIP registrar module - process REGISTER message
 * \ingroup registrar
 */


#ifndef SAVE_H
#define SAVE_H


#include "../../parser/msg_parser.h"

/*! \brief
 * Process REGISTER request and save it's contacts
 */
int save(struct sip_msg* _m, char* _d, char* _cflags, char* _s);

int w_remove_2(struct sip_msg *msg, char *udomain, char *aor_gp);
int w_remove_3(struct sip_msg *msg, char *udomain, char *aor_gp,
               char *contact_gp);
int w_remove_4(struct sip_msg *msg, char *udomain, char *aor_gp,
               char *contact_gp, char *next_hop_gp);

int _remove(struct sip_msg *msg, char *udomain, char *aor_gp, char *contact_gp,
            char *next_hop_gp, char *sip_instance_gp);

#endif /* SAVE_H */
