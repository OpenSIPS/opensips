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

#ifndef _menus_h_
#define _menus_h_

#include "items.h"

typedef int (*run_action) (void * menu,void *arg);

#define INTERNAL_COMMAND	(1<<0)
#define EXIT_MENUCONFIG		(1<<1)
typedef struct sel_menu {
	char *name;			/* menu display name */
	run_action action;		/* action that should be ran when menu is entered */
	int flags;			/* type of menu */
	select_item *item_list;		/* select items that menu displays after selection */
	int item_no;			/* number of items in item_list. For fast detection of scrolling */
	int child_changed;		/* did any of the childs for this menu suffer any changes ? */
	struct sel_menu *parent;	/* parent of the current menu */
	struct sel_menu *child;		/* select menus that this menu displays after selection */
	struct sel_menu *next_sibling;	/* menus that should be shown along this menu */
	struct sel_menu *prev_sibling;	/* menus that should be shown along this menu */
} select_menu;

select_menu *find_menu(char *name,select_menu *menu);
select_menu *init_menu(char *menu_name,int flags,run_action action);
void link_sibling(select_menu *dest,select_menu *to_link);
void link_child(select_menu *dest,select_menu *to_link);
int gen_scripts_menu(select_menu *parent);
int exec_menu_action(select_menu *menu);
int is_top_menu(select_menu *menu);
#endif
