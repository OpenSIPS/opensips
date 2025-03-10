/*
 * presence_reginfo module - Presence Handling of reg events
 *
 * Copyright (C) 2011, 2023 Carsten Bock, carsten@ng-voice.com
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

/*! \file
 * \brief Kamailio presence reginfo  ::
 * \ref notify_body.c
 * \ingroup presence_reginfo
 */


#ifndef _NBODY_H_
#define _NBODY_H_

str *reginfo_agg_nbody(str *pres_user, str *pres_domain, str **body_array,
		int n, int off_index);

str *reginfo_body_setversion(subs_t *subs, str *body);

void free_xml_body(char *body);

#endif
