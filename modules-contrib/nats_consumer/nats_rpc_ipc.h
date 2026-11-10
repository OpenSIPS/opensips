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
 * nats_rpc_ipc.h -- worker -> consumer-process publish hop for the
 * consumer-process-routed async nats_request transport.
 *
 * This hop rides OpenSIPS core IPC: the SIP worker calls
 * ipc_send_rpc(<consumer proc>, nats_rpc_ipc_on_publish, param) and the
 * whole payload -- {slot_idx u32, generation u32} -- is packed INTO the
 * opaque param pointer (zero allocation; the pipe is the queue).  The
 * consumer process pumps its IPC fd from the main loop, gated on a live
 * broker connection, so entries wait in the pipe across reconnects
 * exactly like they used to wait in the SHM ring.
 *
 * The generation captured at send time lets the consumer reject a stale
 * entry whose slot was freed and re-claimed before the pump
 * (nats_rpc_slot_entry_is_current -- prevents a double-publish).
 * Producers transition the slot CLAIMED -> INFLIGHT via
 * nats_rpc_slot_publish() BEFORE sending.
 *
 * If the send fails (pipe full / consumer proc not yet up) the producer
 * sees -1 and surfaces -5 (capacity exhausted) to the script -- the
 * same fail-fast contract as the old bounded SHM queue.
 *
 * The pack/unpack pair is unit-locked in test/test_rpc_ipc_pack.c.
 */

#ifndef NATS_RPC_IPC_H
#define NATS_RPC_IPC_H

#include <stdint.h>

/*
 * The logical message.  Kept as a struct for the tests that model the
 * consumer's stale-entry decision (test_rpc_ipc_generation.c); on the
 * wire the two fields travel packed in the IPC param pointer.
 */
typedef struct nats_rpc_ipc_msg {
	uint32_t slot_idx;       /* index into the nats_rpc_slot pool */
	uint32_t generation;     /* slot generation captured at send */
} nats_rpc_ipc_msg_t;

/**
 * {slot_idx, generation} <-> the opaque ipc_send_rpc param.  Slot in
 * the low word, generation in the high word; pack(0,0) is NULL and is
 * still a valid encoding (the receiver decodes, never sentinel-checks).
 *
 * @param slot_idx    Index into the nats_rpc_slot pool.
 * @param generation  Slot claim generation captured at send time.
 * @param param       (unpack) the packed pointer to decode; the two out
 *                    pointers must be non-NULL and receive the fields.
 * @return            (pack) the packed opaque pointer; unpack returns
 *                    nothing.
 *
 * Pure inline bit-packing: no allocation, no locking; safe in any
 * process or thread.  Producers are SIP workers (pack, before
 * ipc_send_rpc); consumers are the consumer process's IPC handlers and
 * the worker-side wake handler (unpack).
 */
static inline void *nats_rpc_ipc_pack(uint32_t slot_idx, uint32_t generation)
{
	return (void *)(uintptr_t)(((uint64_t)generation << 32)
	                           | (uint64_t)slot_idx);
}

static inline void nats_rpc_ipc_unpack(void *param,
	uint32_t *slot_idx, uint32_t *generation)
{
	uint64_t v = (uint64_t)(uintptr_t)param;

	*slot_idx   = (uint32_t)(v & 0xFFFFFFFFu);
	*generation = (uint32_t)(v >> 32);
}

#endif /* NATS_RPC_IPC_H */
