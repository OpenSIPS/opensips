/*
 * $Id$
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * -------
 *  2012-01-19  created (vlad)
 */


#ifndef _items_h_
#define _items_h_

struct sel_menu;

#define CHILD_NO_CHANGES	0
#define CHILD_CHANGED		1
#define CHILD_CHANGE_IGNORED	2
#define MAX_DEPENDENCY_NO	5
typedef struct sel_item {
	char *name;				/* item display name */
	char *dependency[MAX_DEPENDENCY_NO];	/* item dependencies */
	char *description;			/* item description */
	int dependency_no;			/* number of dependencies */
	int enabled;				/* is item selected or not */
	int prev_state;				/* previous item state, used for resetting */
	struct sel_item *next;			/* items that should be shown along this item */
} select_item;

select_item* create_item(char *item_name,char *description);
int add_dependency(select_item *item,char *desc);
void link_item(struct sel_menu *menu,select_item *item);
void enable_item(struct sel_menu *parent,char *name,int len);
#endif
