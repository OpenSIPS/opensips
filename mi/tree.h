/*
 * $Id$
 *
 * Copyright (C) 2006 Voice Sistem SRL
 *
 * This file is part of openser, a free SIP server.
 *
 * openser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * openser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *
 * History:
 * ---------
 *  2006-09-08  first version (bogdan)
 */



#ifndef _MI_TREE_H
#define _MI_TREE_H

#include <stdarg.h>
#include "../str.h"

struct mi_node;

#include "attr.h"

#define MI_DUP_NAME   (1<<0)
#define MI_DUP_VALUE  (1<<1)

#define MI_200_OK_S   "200 OK"
#define MI_200_OK_LEN (sizeof(MI_200_OK_S)-1)

struct mi_node{
	str value;
	str name;
	struct mi_node *kids;
	struct mi_node *next;
	struct mi_node *last;
	struct mi_attr *attributes;
};


struct mi_node *init_mi_tree(char *reason, int reason_len);

void free_mi_tree(struct mi_node *parent);

struct mi_node *add_mi_node_sibling(struct mi_node *brother, int flags,
	char *name, int name_len, char *value, int value_len);

struct mi_node *addf_mi_node_sibling(struct mi_node *brother, int flags,
	char *name, int name_len, char *fmt_val, ...);

struct mi_node *add_mi_node_child(struct mi_node *parent, int flags,
	char *name, int name_len, char *value, int value_len);

struct mi_node *addf_mi_node_child(struct mi_node *parent, int flags,
	char *name, int name_len, char *fmt_val, ...);

#endif

