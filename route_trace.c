/*
 * Route tracing hooks for external instrumentation
 *
 * Copyright (C) 2026 OpenSIPS Project
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

#include "route_trace.h"
#include "dprint.h"

route_trace_handlers_t *route_trace_handlers;

int register_route_tracer(route_trace_handlers_t *handlers)
{
	if (!handlers)
		return -1;

	if (route_trace_handlers && route_trace_handlers != handlers) {
		LM_ERR("route tracer already registered\n");
		return -1;
	}

	route_trace_handlers = handlers;
	return 0;
}

void unregister_route_tracer(route_trace_handlers_t *handlers)
{
	if (route_trace_handlers == handlers)
		route_trace_handlers = NULL;
}
