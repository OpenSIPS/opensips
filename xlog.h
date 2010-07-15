/*
 * $Id: xl_lib.h 5901 2009-07-21 07:45:05Z bogdan_iancu $
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _XLOG_H_
#define _XLOG_H_

#include "pvar.h"

typedef struct _xl_level
{
	int type;
	union {
		long level;
		pv_spec_t sp;
	} v;
} xl_level_t, *xl_level_p;

extern int xlog_buf_size;
extern int xlog_force_color;

int xlog_1(struct sip_msg*, char*, char*);
int xlog_2(struct sip_msg*, char*, char*);
int xdbg(struct sip_msg*, char*, char*);

int pv_parse_color_name(pv_spec_p sp, str *in);
int pv_get_color(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);

#endif

