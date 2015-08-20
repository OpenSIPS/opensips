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


#ifndef _commands_h_
#define _commands_h_

#include "menus.h"

int run_make_install(select_menu *menu,void *arg);
int run_make_proper(select_menu *menu,void *arg);
int generate_cfg(select_menu *menu,void *arg);
int save_m4_def(select_menu *menu,void *arg);
int dump_make_conf(select_menu *menu,void *arg);
int read_install_prefix(select_menu *menu,void *arg);
int reset_unsaved_compile(select_menu *menu,void *arg);
int save_all_changes(select_menu *menu,void *arg);

#endif
