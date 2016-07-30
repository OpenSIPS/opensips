/*
 * Copyright (C) 2012 OpenSIPS Solutions
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
 * History:
 * -------
 *  2012-01-19  created (vlad)
 */

#ifndef _parser_h_
#define _parser_h_

#include "menus.h"
#include "cfg.h"

#define GRP_START_STR	"#DEFS_GROUP_START"
#define GRP_END_STR		"#DEFS_GROUP_END"

#define SKIP_LINE_STR "##"
#define SKIP_LINE_STRL 2

int parse_dep_line(char *line,select_menu *parent);
int parse_include_line(char *line,select_menu *parent);
int parse_defs_line(char *line,select_menu *parent,int *group_idx,int *start_grp);
int parse_prefix_line(char *line,select_menu *menu);
int parse_defs_m4_line(char *line,select_menu *menu);
int parse_defs_m4(select_menu *curr_menu,cfg_gen_t *curr_cfg);
int parse_make_conf();
#endif
