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
 * nats_handle_parse.h -- parse a k=v;k=v bind-parameter string into a
 * freshly-allocated nats_handle_t.
 */

#ifndef NATS_HANDLE_PARSE_H
#define NATS_HANDLE_PARSE_H

#include "../../str.h"
#include "nats_handle_registry.h"

/**
 * Parse a semicolon-separated k=v config string into a freshly-allocated
 * SHM handle.  Unknown keys are rejected as config errors.
 *
 * @param config_str  Bind-parameter string; borrowed for the duration of
 *                    the call (the parser copies what it keeps).  NULL /
 *                    empty is a parse error.
 * @param err         Optional error out-parameter; may be NULL.  On
 *                    failure set to a borrowed static string describing
 *                    the first error -- must NOT be freed.  Reset to NULL
 *                    on entry.
 * @return            New handle on success; NULL on parse / validation /
 *                    allocation failure (any partially-built handle is
 *                    freed internally before returning).
 *
 * Allocation: the handle and every str field inside it are shm_malloc'd.
 * The CALLER owns the result -- either transfer ownership with
 * nats_registry_bind() (which takes it on rc == 0) or release it with
 * nats_handle_free().
 *
 * Locking: none taken.
 *
 * Context: any process; real callers are mod_init (pre-fork, `bind`
 * modparam), the startup-route script bind and the MI bind handler.
 */
nats_handle_t *nats_handle_parse(const str *config_str, const char **err);

#endif /* NATS_HANDLE_PARSE_H */
