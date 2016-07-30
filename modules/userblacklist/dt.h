/*
 * Copyright (C) 2007 1&1 Internet AG
 *
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
 *
 */

#ifndef _DT_H_
#define _DT_H_


#include "../../sr_module.h"


struct dt_node_t {
	struct dt_node_t *child[10];
	char leaf;
	char whitelist;
};


int dt_init(struct dt_node_t **root);
void dt_destroy(struct dt_node_t **root);
void dt_clear(struct dt_node_t *root);
void dt_insert(struct dt_node_t *root, const char *number, char whitelist);
int dt_longest_match(struct dt_node_t *root, const char *number, char *whitelist);

#endif
