/*
 * $Id$
 *
 * Copyright (C) 2001-2003 FhG Fokus
 *
 * This file is part of openser, a free SIP server.
 *
 * openser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * openser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _ITEMS_H_
#define _ITEMS_H_

#include "parser/msg_parser.h"

#define XL_DISABLE_NONE		0
#define XL_THROW_ERROR		1
#define XL_DISABLE_MULTI	2
#define XL_DISABLE_COLORS	4

typedef int (*item_func_t) (struct sip_msg*, str*, str*, int);

typedef struct _xl_elem
{
	str text;
	str hparam;
	int hindex;
	item_func_t itf;
	struct _xl_elem *next;
} xl_elem_t, *xl_elem_p;

int xl_elem_free_all(xl_elem_p list);
char* xl_parse_item(char *s, xl_elem_p el, int flags);
int xl_parse_format(char *s, xl_elem_p *el, int flags);
int xl_printf(struct sip_msg* msg, xl_elem_p list, char *buf, int *len);

#endif

