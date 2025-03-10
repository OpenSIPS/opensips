/*
 *
 * Copyright (C) 2023 OpenSIPS Solutions
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

#ifndef LOG_INTERFACE_H
#define LOG_INTERFACE_H

#include <stdarg.h>

/* printing function to be registered by a generic logging consumer */
typedef void (*log_print_f)(int log_level, int facility, const char *module, const char *func,
	char *format, va_list ap);

int register_log_consumer(char *name, log_print_f print_func,
	int level_filter, int muted);

#endif /* ifndef LOG_INTERFACE_H */
