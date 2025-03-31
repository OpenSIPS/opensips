 /*
￼ * Trie Module
￼ *
￼ * Copyright (C) 2024 OpenSIPS Project
￼ *
￼ * opensips is free software; you can redistribute it and/or modify
￼ * it under the terms of the GNU General Public License as published by
￼ * the Free Software Foundation; either version 2 of the License, or
￼ * (at your option) any later version.
￼ *
￼ * opensips is distributed in the hope that it will be useful,
￼ * but WITHOUT ANY WARRANTY; without even the implied warranty of
￼ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
￼ * GNU General Public License for more details.
￼ *
￼ * You should have received a copy of the GNU General Public License
￼ * along with this program; if not, write to the Free Software
￼ * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
￼ *
￼ * History:
￼ * --------
￼ * 2024-12-03 initial release (vlad)
￼ */

#include "../../ut.h"
#include "trie_db_def.h"

/* DR rule table related defs */
#define PREFIX_TRIE_COL    "prefix"
#define ATTRS_TRIE_COL     "attrs"
#define DISABLED_TRIE_COL  "enabled"

str trie_table = str_init("trie");
str prefix_trie_col = str_init(PREFIX_TRIE_COL);
str attrs_trie_col = str_init(ATTRS_TRIE_COL);
str enabled_trie_col = str_init(DISABLED_TRIE_COL);
