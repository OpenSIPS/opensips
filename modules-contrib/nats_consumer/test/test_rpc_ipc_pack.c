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
 *
 * The async-RPC worker->consumer hop rides core IPC
 * (ipc_send_rpc), and the whole payload -- {slot_idx u32, generation
 * u32} -- is packed INTO the opaque `void *param` (zero SHM allocation
 * on the hot path).  This locks the pack/unpack pair:
 *
 *   - roundtrip identity across the full u32 x u32 domain corners
 *     (0, 1, 0x7FFFFFFF, 0xFFFFFFFF for both fields),
 *   - the two fields cannot bleed into each other (slot in the low
 *     word, generation in the high word),
 *   - pack(0,0) is a NULL pointer -- the receiver must still decode
 *     it, not treat it as a sentinel.
 *
 * Runs in the nats_consumer unit test suite (make test-nats_consumer).
 */

#include <tap.h>
#include <stdio.h>
#include <stdint.h>

#include "../nats_rpc_ipc.h"

#include "nc_ut.h"

#define CHECK(cond, label) ok((cond), "rpc_ipc_pack: %s", (label))

static void roundtrip(uint32_t slot, uint32_t gen, const char *label)
{
	void    *p = nats_rpc_ipc_pack(slot, gen);
	uint32_t s2 = 0xDEADBEEFu, g2 = 0xDEADBEEFu;

	nats_rpc_ipc_unpack(p, &s2, &g2);
	CHECK(s2 == slot && g2 == gen, label);
}

void nc_ut_rpc_ipc_pack(void)
{
	uint32_t corners[] = {0u, 1u, 0x7FFFFFFFu, 0xFFFFFFFFu};
	char label[80];
	unsigned i, j;

	printf("pack/unpack roundtrip over the corner grid:\n");
	for (i = 0; i < 4; i++)
		for (j = 0; j < 4; j++) {
			snprintf(label, sizeof(label),
				"roundtrip slot=0x%08x gen=0x%08x",
				corners[i], corners[j]);
			roundtrip(corners[i], corners[j], label);
		}

	printf("field isolation:\n");
	{
		uint32_t s = 0, g = 0;
		nats_rpc_ipc_unpack(nats_rpc_ipc_pack(0xFFFFFFFFu, 0), &s, &g);
		CHECK(s == 0xFFFFFFFFu && g == 0,
			"all-ones slot leaves generation zero");
		nats_rpc_ipc_unpack(nats_rpc_ipc_pack(0, 0xFFFFFFFFu), &s, &g);
		CHECK(s == 0 && g == 0xFFFFFFFFu,
			"all-ones generation leaves slot zero");
	}

	printf("pack(0,0) == NULL is still a valid encoding:\n");
	{
		uint32_t s = 7, g = 7;
		void *p = nats_rpc_ipc_pack(0, 0);
		CHECK(p == NULL, "pack(0,0) is the NULL pointer");
		nats_rpc_ipc_unpack(p, &s, &g);
		CHECK(s == 0 && g == 0, "NULL decodes to {0,0}, not rejected");
	}

}
