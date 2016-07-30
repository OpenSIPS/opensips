/*
 * Copyright (C) 2006 Voice Sistem SRL
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
 *
 * History:
 * ---------
 *  2006-09-08  first version (bogdan)
 */

/*!
 * \file
 * \brief MI :: Tree
 * \ingroup mi
 */




#ifndef _MI_TREE_H
#define _MI_TREE_H

#include <stdarg.h>
#include "../str.h"

struct mi_node;
struct mi_handler;

#include "attr.h"

#define MI_DUP_NAME   		(1<<0)
#define MI_DUP_VALUE  		(1<<1)
#define MI_NOT_COMPLETED  	(1<<2)
#define MI_WRITTEN			(1<<3)
/*
 * Known issue when building arrays into your modules' MI trees:
 *  +----------------------------------------------------+
 *  |        only use MI_IS_ARRAY iff all "name"         |
 *  |   attributes of each array object are identical,   |
 *  |             see mi_ps() or mi_which()              |
 *  +----------------------------------------------------+
 *
 * Why?
 *	 commit 459dffba introduced a "common denominator" optimization:
 *	   - [GOOD] reduces the amount of redundant data in all mi_json output
 *	   - [BAD] breaks all code which builds arrays of items with
 *	           non-identical "name" attributes
 */
#define MI_IS_ARRAY			(1<<4)

#define MI_OK_S              "OK"
#define MI_OK_LEN            (sizeof(MI_OK_S)-1)
#define MI_INTERNAL_ERR_S    "Server Internal Error"
#define MI_INTERNAL_ERR_LEN  (sizeof(MI_INTERNAL_ERR_S)-1)
#define MI_MISSING_PARM_S    "Too few or too many arguments"
#define MI_MISSING_PARM_LEN  (sizeof(MI_MISSING_PARM_S)-1)
#define MI_BAD_PARM_S        "Bad parameter"
#define MI_BAD_PARM_LEN      (sizeof(MI_BAD_PARM_S)-1)

#define MI_SSTR(_s)           _s,(sizeof(_s)-1)
#define MI_OK                 MI_OK_S
#define MI_INTERNAL_ERR       MI_INTERNAL_ERR_S
#define MI_MISSING_PARM       MI_MISSING_PARM_S
#define MI_BAD_PARM           MI_BAD_PARM_S

#define MI_DATE_BUF_LEN 21

struct mi_node {
	str value;
	str name;
	unsigned int flags;
	struct mi_node *kids;
	struct mi_node *next;
	struct mi_node *last;
	struct mi_attr *attributes;
};

struct mi_root {
	unsigned int       code;
	str                reason;
	struct mi_handler  *async_hdl;
	struct mi_node     node;
};

struct mi_root *init_mi_tree(unsigned int code, char *reason, int reason_len);

void free_mi_tree(struct mi_root *parent);

void free_mi_node(struct mi_node *parent);

struct mi_node *add_mi_node_sibling(struct mi_node *brother, int flags,
	char *name, int name_len, char *value, int value_len);

struct mi_node *addf_mi_node_sibling(struct mi_node *brother, int flags,
	char *name, int name_len, char *fmt_val, ...);

struct mi_node *add_mi_node_child(struct mi_node *parent, int flags,
	char *name, int name_len, char *value, int value_len);

struct mi_node *addf_mi_node_child(struct mi_node *parent, int flags,
	char *name, int name_len, char *fmt_val, ...);

struct mi_root* clone_mi_tree(struct mi_root *org, int shm);

void free_shm_mi_tree(struct mi_root *parent);

#endif

