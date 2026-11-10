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
 * nats_consumer.h -- public module types and entry points.
 *
 * Module: modules-contrib/nats_consumer -- script-controlled JetStream pull
 * consumer with SHM handle registry and per-worker async yield.
 *
 * See README.md and the per-section design notes in
 * nats_consumer_proc.c for the full design.
 */

#ifndef NATS_CONSUMER_H
#define NATS_CONSUMER_H

#include "../../str.h"

/* Module version -- appears in MI help and log lines. */
#define NATS_CONSUMER_VERSION "0.8.0-persist"

/* Default registry size -- hash bucket count.  Fixed at init. */
#define NATS_CONSUMER_REGISTRY_BUCKETS 256

#endif /* NATS_CONSUMER_H */
