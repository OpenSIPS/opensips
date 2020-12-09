/*
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

typedef struct _xl_trace
{
	struct sip_msg* msg;
	str buf;


} xl_trace_t;

extern int xlog_buf_size;
extern int xlog_force_color;
extern int xlog_print_level;
extern int *xlog_level;

int xlog_1(struct sip_msg*, char*);
int xlog_2(struct sip_msg*, char*, char*);
int xdbg(struct sip_msg*, char*);

int pv_parse_color_name(pv_spec_p sp, str *in);
int pv_get_color(struct sip_msg *msg, pv_param_t *param,
		pv_value_t *res);

int init_xlog(void);

void set_shared_xlog_level(int new_level);
void set_local_xlog_level(int new_level);
void reset_xlog_level(void);

#endif

