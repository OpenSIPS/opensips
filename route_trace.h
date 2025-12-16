/*
 * Route tracing hooks for external instrumentation
 *
 * Copyright (C) 2024
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

#ifndef ROUTE_TRACE_H
#define ROUTE_TRACE_H

#include <stddef.h>

struct sip_msg;

typedef struct route_trace_handlers {
	void (*on_msg_start)(struct sip_msg *msg, int route_type,
		const char *route_name, int stack_size, int stack_start);
	void (*on_msg_end)(struct sip_msg *msg, int route_type,
		const char *route_name, int stack_size, int stack_start, int status);
	void (*on_route_enter)(struct sip_msg *msg, int route_type,
		const char *route_name, const char *file, int line,
		int stack_size, int stack_start);
	void (*on_route_exit)(struct sip_msg *msg, int route_type,
		const char *route_name, const char *file, int line,
		int stack_size, int stack_start, int status);
} route_trace_handlers_t;

extern route_trace_handlers_t *route_trace_handlers;

int register_route_tracer(route_trace_handlers_t *handlers);
void unregister_route_tracer(route_trace_handlers_t *handlers);

static inline int route_trace_enabled(void)
{
	return route_trace_handlers != NULL;
}

static inline void route_trace_msg_start(struct sip_msg *msg, int route_type,
	const char *route_name, int stack_size, int stack_start)
{
	if (route_trace_handlers && route_trace_handlers->on_msg_start)
		route_trace_handlers->on_msg_start(msg, route_type, route_name,
			stack_size, stack_start);
}

static inline void route_trace_msg_end(struct sip_msg *msg, int route_type,
	const char *route_name, int stack_size, int stack_start, int status)
{
	if (route_trace_handlers && route_trace_handlers->on_msg_end)
		route_trace_handlers->on_msg_end(msg, route_type, route_name,
			stack_size, stack_start, status);
}

static inline void route_trace_route_enter(struct sip_msg *msg, int route_type,
	const char *route_name, const char *file, int line,
	int stack_size, int stack_start)
{
	if (route_trace_handlers && route_trace_handlers->on_route_enter)
		route_trace_handlers->on_route_enter(msg, route_type, route_name,
			file, line, stack_size, stack_start);
}

static inline void route_trace_route_exit(struct sip_msg *msg, int route_type,
	const char *route_name, const char *file, int line,
	int stack_size, int stack_start, int status)
{
	if (route_trace_handlers && route_trace_handlers->on_route_exit)
		route_trace_handlers->on_route_exit(msg, route_type, route_name,
			file, line, stack_size, stack_start, status);
}

#endif /* ROUTE_TRACE_H */
