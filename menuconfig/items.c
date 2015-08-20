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


#include<stdlib.h>
#include<stdio.h>
#include<string.h>

#include "items.h"
#include "main.h"

/* Allocate mem & init an item with passed
 * name & description */
select_item* create_item(char *item_name,char *description)
{
	select_item *ret;
	int name_len = strlen(item_name);
	int desc_len = description?strlen(description):-1;
	int ret_len = sizeof(select_item) + name_len + desc_len + 2;

	ret = malloc(ret_len);
	if (!ret) {
		fprintf(output,"Failed to alloc mem\n");
		return 0;
	}

	memset(ret,0,ret_len);
	ret->name = (char *) (ret + 1);
	memcpy(ret->name,item_name,name_len);

	if (description) {
		ret->description=(char *)(ret+1) + name_len+1;
		memcpy(ret->description,description,desc_len);
	}

	return ret;
}

/* Add an external dependency for the item. */
int add_dependency(select_item *item,char *desc)
{
	int len = strlen(desc);

	if (item->dependency_no == MAX_DEPENDENCY_NO) {
		fprintf(output,"MAX dependencies reached\n");
		return -1;
	}

	item->dependency[item->dependency_no] = malloc(len+1);
	if (item->dependency[item->dependency_no] == NULL) {
		fprintf(output,"Failed to alloc mem\n");
		return -1;
	}

	memset(item->dependency[item->dependency_no],0,len+1);

	memcpy(item->dependency[item->dependency_no],desc,len);
	item->dependency_no++;

	return 0;
}

/* Link the current item to it's parent menu */
void link_item(select_menu *menu,select_item *item)
{
	select_item *it;

	if (menu->item_list == NULL)
		menu->item_list = item;
	else {
		for (it=menu->item_list;it->next;it=it->next)
			;
		it->next = item;
	}

	menu->item_no++;
}

/* Mark the item with the passed name as enabled */
void enable_item(select_menu *parent,char *name,int len)
{
	select_item *it;
	for (it=parent->item_list;it;it=it->next) {
		if (memcmp(it->name,name,len) == 0) {
			it->enabled = 1;
			it->prev_state= 1;
			break;
		}
	}

	if (!it) {
		fprintf(output,"BUG - include modules invalid list - %.*s\n",len,name);
	}
}

