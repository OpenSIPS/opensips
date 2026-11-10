/*
 * Copyright (C) 2026 OpenSIPS Solutions
 * Copyright (C) 2026 Norm Brandinger <n.brandinger@gmail.com>
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/*
 * Table of the JetStream messages being retried (see nats_js_retry.h).
 *
 * Open addressing with linear probing, keyed by the natsMsg pointer;
 * removal shifts the following entries of the probe run back, so no
 * tombstones are needed and a lookup stops at the first empty slot.
 * libc and pthread only, so the unit test links it alone.
 */

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

#include "nats_js_retry.h"

typedef struct {
	const void *msg;      /* NULL: free slot */
	int         retries;  /* resends done */
} retry_slot;

static retry_slot      _slots[NATS_JS_RETRY_SLOTS];
static int             _used;
static pthread_mutex_t _mu = PTHREAD_MUTEX_INITIALIZER;

static size_t slot_of(const void *msg)
{
	uintptr_t h = (uintptr_t)msg;

	/* pointers are aligned: mix the high bits into the low ones */
	h ^= h >> 17;
	h *= (uintptr_t)0x9E3779B97F4A7C15ULL;
	h ^= h >> 29;
	return (size_t)(h & (NATS_JS_RETRY_SLOTS - 1));
}

/* index of @msg, or of the free slot where it would go, or -1 */
static long find(const void *msg)
{
	size_t i = slot_of(msg), n;

	for (n = 0; n < NATS_JS_RETRY_SLOTS; n++) {
		if (_slots[i].msg == msg || _slots[i].msg == NULL)
			return (long)i;
		i = (i + 1) & (NATS_JS_RETRY_SLOTS - 1);
	}
	return -1;
}

int nats_js_retry_track(const void *msg)
{
	long i;
	int done;

	if (!msg)
		return -1;
	pthread_mutex_lock(&_mu);
	i = find(msg);
	if (i < 0) {
		pthread_mutex_unlock(&_mu);
		return -1;
	}
	/* find() returned a free slot: the table is not full (a full one
	 * makes find() return -1 for a message it does not hold) */
	if (_slots[i].msg == NULL) {
		_slots[i].msg = msg;
		_slots[i].retries = 0;
		_used++;
	}
	done = _slots[i].retries++;
	pthread_mutex_unlock(&_mu);
	return done;
}

void nats_js_retry_forget(const void *msg)
{
	long i;
	size_t hole, j, home;

	if (!msg)
		return;
	pthread_mutex_lock(&_mu);
	if (_used == 0) {
		pthread_mutex_unlock(&_mu);
		return;
	}
	i = find(msg);
	if (i < 0 || _slots[i].msg != msg) {
		pthread_mutex_unlock(&_mu);
		return;
	}
	hole = (size_t)i;
	_slots[hole].msg = NULL;
	_used--;
	/* shift back the entries of the probe run that could have used the
	 * hole: an entry at j belongs before the hole when its home slot is
	 * not cyclically in (hole, j] */
	j = hole;
	for (;;) {
		j = (j + 1) & (NATS_JS_RETRY_SLOTS - 1);
		if (_slots[j].msg == NULL)
			break;
		home = slot_of(_slots[j].msg);
		if ((j > hole && (home <= hole || home > j)) ||
		    (j < hole && (home <= hole && home > j))) {
			_slots[hole] = _slots[j];
			_slots[j].msg = NULL;
			hole = j;
		}
	}
	pthread_mutex_unlock(&_mu);
}

int nats_js_retry_tracked(void)
{
	int n;

	pthread_mutex_lock(&_mu);
	n = _used;
	pthread_mutex_unlock(&_mu);
	return n;
}
