/*
 * Copyright (C) 2025 OpenSIPS Solutions
 * Copyright (C) 2025 Norm Brandinger <n.brandinger@gmail.com>
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
 */

/*
 * event_nats.h — Event Interface (EVI) transport for NATS
 *
 * Module:  event_nats
 *
 * Defines the transport identity constants used to register event_nats
 * as an EVI transport with the OpenSIPS event interface.  These constants
 * are referenced during module initialization (mod_init) when calling
 * evi_publish_event() and in the transport match/parse callbacks.
 *
 * Key constants:
 *   NATS_NAME         — transport protocol name string ("nats")
 *   NATS_STR          — str struct initializer for NATS_NAME
 *   NATS_FLAG         — unique bit flag identifying this transport
 *   NATS_DEFAULT_URL  — fallback NATS server URL
 */

#ifndef _EV_NATS_H_
#define _EV_NATS_H_

/* Transport protocol name, used in subscribe_event() socket URIs.
 * Example:  subscribe_event("E_PIKE_BLOCKED", "nats:pike.blocked") */
#define NATS_NAME    "nats"

/* str struct initializer for NATS_NAME.
 * Provides {char*, int} pair as required by OpenSIPS str type. */
#define NATS_STR     { NATS_NAME, sizeof(NATS_NAME) - 1 }

/* Unique bit flag for the NATS EVI transport.
 * Each EVI transport must claim a distinct bit position (0-31).
 * Bit 25 is assigned to event_nats; do not reuse in other transports. */
#define NATS_FLAG    (1 << 25)

/* Default NATS server URL used when no "nats_url" module parameter
 * is configured in opensips.cfg.  Connects to localhost on the
 * standard NATS client port (4222) without TLS. */
#ifndef NATS_DEFAULT_URL
#define NATS_DEFAULT_URL "nats://127.0.0.1:4222"
#endif

#ifdef UNIT_TESTS
#include "../../evi/evi_transport.h"

/* Unit-test entry points (test/): the module's child_init() and
 * mod_destroy(), the callback it gives the pool for JetStream acks, and
 * its EVI transport table. */
extern int nats_jetstream;
int event_nats_test_child_init(int rank);
void event_nats_test_mod_destroy(void);
void event_nats_test_js_ack_cb(int outcome);
const evi_export_t *event_nats_test_transport(void);
#endif

#endif /* _EV_NATS_H_ */
