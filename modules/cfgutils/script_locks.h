/**
 * Copyright (C) 2012 OpenSIPS Solutions
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
 * History
 * -------
 * 2012-11-21  created (Liviu)
 *
 */

#ifndef __SCRIPT_LOCKS_H__
#define __SCRIPT_LOCKS_H__

#include "../../locking.h"
#include "../../ut.h"
#include "../../mod_fix.h"

int fixup_static_lock(void **param);
int create_dynamic_locks(void);

int get_static_lock(struct sip_msg *msg, gen_lock_t *lock);
int release_static_lock(struct sip_msg *msg, gen_lock_t *lock);

int get_dynamic_lock(struct sip_msg *msg, str *string);
int release_dynamic_lock(struct sip_msg *msg, str *string);
int strings_share_lock(struct sip_msg *msg, str *s1, str *s2);

void destroy_script_locks(void);

typedef struct _static_lock {
	str name;
	gen_lock_t *lock;
	struct _static_lock *next;
} static_lock;

#endif /* __SCRIPT_LOCKS_H__  */
