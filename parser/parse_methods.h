/*
 * Copyright (c) 2004 Juha Heinanen
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

#ifndef PARSE_METHODS_H
#define PARSE_METHODS_H

#include "../str.h"

#define ALL_METHODS  (0xFFFFFFFF)

/*
 * Parse comma separated list of methods pointed by _body and assign their
 * enum bits to _methods.  Returns 1 on success and 0 on failure.
 */
char* parse_method(char* start, char* end, unsigned int* method);
int parse_methods(str* _body, unsigned int* _methods);


#endif /* PARSE_METHODS_H */
