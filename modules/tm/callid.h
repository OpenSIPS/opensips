/*
 * Fast Call-ID Generator
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
 * ----------
 * 2003-04-09 Created by janakj
 */

#ifndef CALLID_H
#define CALLID_H

#include "../../str.h"


/*
 * Initialize the Call-ID generator -- generates random prefix
 */
int init_callid(void);


/*
 * Child initialization -- generates suffix
 */
int child_init_callid(int rank);


/*
 * Get a unique Call-ID
 */
void generate_callid(str* callid);


#endif /* CALLID_H */
