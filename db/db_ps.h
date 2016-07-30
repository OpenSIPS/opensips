/*
 * Copyright (C) 2009 Voice Sistem SRL
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

#ifndef _DB_PS_H
#define _DB_PS_H

typedef void * db_ps_t;

/** Is any prepared statement provided for the next query? */
#define CON_HAS_PS(cn)  ((cn)->curr_ps)

/** Does the connection has attached an uninitialized prepared statemen? */
#define CON_HAS_UNINIT_PS(cn)  (*((cn)->curr_ps)==NULL)


/** Pointer to the current used prepared statment */
#define CON_CURR_PS(cn)      (*(cn)->curr_ps)

/** Pointer to the address of the current used prepared statment */
#define CON_PS_REFERENCE(cn)      ((cn)->curr_ps)

#define CON_RESET_CURR_PS(cn)    *((void***)&cn->curr_ps)=NULL
#define CON_SET_CURR_PS(cn, ptr)    *((void***)&cn->curr_ps)=ptr

#endif


