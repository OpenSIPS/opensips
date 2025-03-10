/*
 * Copyright (C) 2024 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "cond.h"
#include "../dprint.h"

int cond_init(gen_cond_t *cond)
{
	int ret = -1;
	pthread_condattr_t cattr;
	pthread_mutexattr_t mattr;

	if (pthread_mutexattr_init(&mattr) != 0) {
		LM_ERR("could not initialize mutex attributes\n");
		return -1;
	}
	if (pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED) != 0) {
		LM_ERR("could not mark mutex attribute as shared\n");
		goto mutex_error;
	}
	if (pthread_mutexattr_setrobust(&mattr, PTHREAD_MUTEX_ROBUST) != 0) {
		LM_ERR("could not mark mutex attribute as robust\n");
		goto mutex_error;
	}
	if (pthread_mutex_init(&cond->m, &mattr) != 0) {
		LM_ERR("could not initialize mutex\n");
		goto mutex_error;
	}
	if (pthread_condattr_init(&cattr) != 0) {
		LM_ERR("could not initialize cond attributes\n");
		goto cond_error;
	}
	if (pthread_condattr_setpshared(&cattr, PTHREAD_PROCESS_SHARED) != 0) {
		LM_ERR("could not mark mutex cond as shared\n");
		goto cond_error;
	}
	if (pthread_cond_init(&cond->c, &cattr) != 0) {
		LM_ERR("could not initialize cond\n");
		goto cond_error;
	}
	return 0;
cond_error:
	pthread_condattr_destroy(&cattr);
mutex_error:
	pthread_mutexattr_destroy(&mattr);
	return ret;
}

void cond_destroy(gen_cond_t *cond)
{
	pthread_cond_destroy(&cond->c);
	pthread_mutex_destroy(&cond->m);
}
