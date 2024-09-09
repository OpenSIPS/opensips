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

#ifndef __OSIPS_COND__
#define __OSIPS_COND__

#include <pthread.h>

typedef struct gen_cond {
	pthread_mutex_t m;
	pthread_cond_t c;
} gen_cond_t;

/* initializes a condition allocated in shared memory */
int cond_init(gen_cond_t *cond);

/* destroyes a condition */
void cond_destroy(gen_cond_t *cond);

#define cond_lock(_c) pthread_mutex_lock(&(_c)->m)
#define cond_unlock(_c) pthread_mutex_unlock(&(_c)->m)
#define cond_wait(_c) pthread_cond_wait(&(_c)->c, &(_c)->m)
/* make sure we reset the errno, to avoid confusion when resumed */
#define cond_timedwait(_c, _ts) \
	do { \
		errno = 0; \
		pthread_cond_timedwait(&(_c)->c, &(_c)->m, (_ts)); \
	} while (0)
#define cond_has_timedout(_c) (errno == ETIMEDOUT || errno == EAGAIN)/* TODO do we need to store this during wait? */
#define cond_signal(_c) pthread_cond_signal(&(_c)->c)
#define cond_broadcast(_c) pthread_cond_broadcast(&(_c)->c)

#endif /* __OSIPS_COND__ */
