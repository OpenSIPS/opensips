/*
 * Copyright (C) 2014 OpenSIPS Solutions
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
 * --------
 *  2014-10-30 initial version (liviu)
 */

#ifndef __T_CTX_H
#define __T_CTX_H

typedef int (*t_ctx_register_int_f)(context_destroy_f f);
typedef int (*t_ctx_register_str_f)(context_destroy_f f);
typedef int (*t_ctx_register_ptr_f)(context_destroy_f f);
typedef void (*t_ctx_put_int_f)(struct cell *t, int pos, int data);
typedef void (*t_ctx_put_str_f)(struct cell *t, int pos, str *data);
typedef void (*t_ctx_put_ptr_f)(struct cell *t, int pos, void *data);
typedef int   (*t_ctx_get_int_f)(struct cell *t, int pos);
typedef str  *(*t_ctx_get_str_f)(struct cell *t, int pos);
typedef void *(*t_ctx_get_ptr_f)(struct cell *t, int pos);

int t_ctx_register_int(context_destroy_f f);
int t_ctx_register_str(context_destroy_f f);
int t_ctx_register_ptr(context_destroy_f);

void t_ctx_put_int(struct cell *t, int pos, int data);
void t_ctx_put_str(struct cell *t, int pos, str *data);
void t_ctx_put_ptr(struct cell *t, int pos, void *data);

int   t_ctx_get_int(struct cell *t, int pos);
str  *t_ctx_get_str(struct cell *t, int pos);
void *t_ctx_get_ptr(struct cell *t, int pos);

#endif /* __T_CTX_H */
