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
 * nats_rpc_wake.c -- consumer -> worker reply wake for the async
 * nats_request transport.  See nats_rpc_wake.h for the design and
 * threading contract; behavior is unit-locked in
 * test/test_rpc_wake_ipc.c.
 */

#ifdef TEST_SHIM
#include "tests/test_shim.h"
/* ipc.h drags in the full core header stack (pt.h & co.); the unit
 * test links a recording ipc_send_rpc with the real signature. */
typedef void (ipc_rpc_f)(int sender, void *param);
int ipc_send_rpc(int dst_proc, ipc_rpc_f *rpc, void *param);
#else
#include "../../mem/mem.h"
#include "../../dprint.h"
#include "../../ipc.h"
#endif

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/timerfd.h>

#ifdef UNIT_TESTS
/* the unit test suite records the wake instead of sending it */
int (*nc_ut_wake_ipc_send)(int dst_proc, ipc_rpc_f *rpc, void *param) =
	ipc_send_rpc;
#define WAKE_IPC_SEND nc_ut_wake_ipc_send
#else
#define WAKE_IPC_SEND ipc_send_rpc
#endif

#include "nats_rpc_ipc.h"
#include "nats_rpc_wake.h"

/*
 * Per-worker registry: one entry per async slot index.  Only entries
 * for calls THIS worker has in flight are in_use; the generation
 * disambiguates a wake meant for a previous claim of a reused slot.
 * Process-local, single-threaded (worker main thread only).
 */
typedef struct wake_entry {
	uint32_t gen;
	int      timerfd;
	uint8_t  in_use;
} wake_entry_t;

static wake_entry_t *g_wake;
static uint32_t      g_wake_count;

int nats_rpc_wake_init(uint32_t slots)
{
	if (g_wake)
		return 0;
	if (slots < 1)
		return -1;
	g_wake = pkg_malloc((size_t)slots * sizeof(*g_wake));
	if (!g_wake) {
		LM_ERR("nats_rpc_wake: pkg_malloc(%u entries) failed -- "
			"replies fall back to the guard tick\n", slots);
		return -1;
	}
	memset(g_wake, 0, (size_t)slots * sizeof(*g_wake));
	g_wake_count = slots;
	return 0;
}

void nats_rpc_wake_destroy(void)
{
	if (g_wake) {
		pkg_free(g_wake);
		g_wake = NULL;
		g_wake_count = 0;
	}
}

int nats_rpc_wake_register(uint32_t slot_idx, uint32_t gen, int timerfd)
{
	if (!g_wake || slot_idx >= g_wake_count || timerfd < 0)
		return -1;
	g_wake[slot_idx].gen     = gen;
	g_wake[slot_idx].timerfd = timerfd;
	g_wake[slot_idx].in_use  = 1;
	return 0;
}

void nats_rpc_wake_unregister(uint32_t slot_idx)
{
	if (!g_wake || slot_idx >= g_wake_count)
		return;
	g_wake[slot_idx].in_use = 0;
}

void nats_rpc_async_on_wake(int sender, void *param)
{
	uint32_t          slot_idx, gen;
	struct itimerspec its;

	(void)sender;
	nats_rpc_ipc_unpack(param, &slot_idx, &gen);

	if (!g_wake || slot_idx >= g_wake_count)
		return;
	if (!g_wake[slot_idx].in_use || g_wake[slot_idx].gen != gen)
		return;

	/* Poke the guard timer to fire now, keeping its periodic
	 * interval: the reactor then runs the normal resume function,
	 * which reads the slot state.  Any failure here just leaves the
	 * original guard tick in place. */
	if (timerfd_gettime(g_wake[slot_idx].timerfd, &its) < 0) {
		LM_DBG("nats_rpc_wake: timerfd_gettime(slot %u): %s\n",
			slot_idx, strerror(errno));
		return;
	}
	its.it_value.tv_sec  = 0;
	its.it_value.tv_nsec = 1;
	if (timerfd_settime(g_wake[slot_idx].timerfd, 0, &its, NULL) < 0)
		LM_DBG("nats_rpc_wake: timerfd_settime(slot %u): %s\n",
			slot_idx, strerror(errno));
}

int nats_rpc_wake_send(int owner_proc, uint32_t slot_idx, uint32_t gen)
{
	if (owner_proc < 0)
		return -1;
	if (WAKE_IPC_SEND(owner_proc, nats_rpc_async_on_wake,
			nats_rpc_ipc_pack(slot_idx, gen)) < 0) {
		LM_DBG("nats_rpc_wake: ipc_send_rpc to proc %d refused; "
			"slot %u resumes on the guard tick\n",
			owner_proc, slot_idx);
		return -1;
	}
	return 0;
}
