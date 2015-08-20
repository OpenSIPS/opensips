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

#include "main.h"

/* Finds the menu with the passed name,
 * starting from menu
 *
 * returns the found menu on success, or NULL on failure
*/
select_menu *find_menu(char *name,select_menu *menu)
{
	select_menu *ret;

	if (strcmp(name,menu->name) == 0)
		return menu;

	if (menu->child) {
		/* search through the children */
		ret=find_menu(name,menu->child);
		if (ret)
			return ret;
	}

	/* search through the siblings */
	if (menu->next_sibling)
		return find_menu(name,menu->next_sibling);

	return NULL;
}

/* Allocate & Init a menu with the passed name, flags, & actions
 *
 * Returns a pointer to the menu or NULL in case of failure
*/
select_menu *init_menu(char *menu_name,int flags,run_action action)
{
	select_menu *ret;
	int len;

	len = strlen(menu_name);

	ret = malloc(sizeof(select_menu)+len+1);
	if (!ret) {
		fprintf(output,"Failed to alloc mem\n");
		return 0;
	}

	memset(ret,0,sizeof(select_menu)+len+1);
	ret->name = (char *) (ret+1);
	memcpy(ret->name,menu_name,len);
	ret->flags = flags;

	if (flags & INTERNAL_COMMAND) {
		/* save action callback only for internall commands */
		ret->action = action;
	}

	return ret;
}

/* Link 'to_link' to 'dest' list of siblings */
void link_sibling(select_menu *dest,select_menu *to_link)
{
	select_menu *it;

	for (it=dest;it->next_sibling;it=it->next_sibling)
		;

	it->next_sibling = to_link;
	to_link->prev_sibling=it;
	to_link->parent = dest->parent;

}

/* Link 'to_link' to 'dest' list of childs
 * also link all the childs as sibling between each other
 */
void link_child(select_menu *dest,select_menu *to_link)
{
	if (dest->child == NULL) {
		dest->child = to_link;
		to_link->parent = dest;
		return;
	} else {
		link_sibling(dest->child,to_link);
	}
}

/* Generate menu entries for all the types of
 * cfg entries that have been added
*/
int gen_scripts_menu(select_menu *parent)
{
	static char name_buf[128];
	cfg_gen_t *it;
	select_menu *m1,*m2,*m3,*m4;

	for (it=configs;it->name;it++) {
		/* Menu entry will have the same name as cfg entry */
		m1 = init_menu(it->name,0,0);
		if (!m1) {
			fprintf(output,"Failed to init menu\n");
			return -1;
		}
		link_child(parent,m1);

		/* Generate Configure, Save & Generate menus and
		 * link them as children */
		strcpy(name_buf,"Configure ");
		strcat(name_buf,it->name);
		m2=init_menu(name_buf,0,0);
		if (!m2) {
			fprintf(output,"Failed to init menu\n");
			return -1;
		}
		link_child(m1,m2);
		if (parse_defs_m4(m2,it) < 0) {
			fprintf(output,"Failed to parse m4 for %s\n",it->name);
			return -1;
		}

		strcpy(name_buf,"Save ");
		strcat(name_buf,it->name);
		m3=init_menu(name_buf,INTERNAL_COMMAND,(run_action)save_m4_def);
		if (!m3) {
			fprintf(output,"Failed to init menu\n");
			return -1;
		}
		link_child(m1,m3);

		strcpy(name_buf,"Generate ");
		strcat(name_buf,it->name);
		m4=init_menu(name_buf,INTERNAL_COMMAND,(run_action)generate_cfg);
		if (!m4) {
			fprintf(output,"Failed to init menu\n");
			return -1;
		}
		link_child(m1,m4);

	}

	return 0;
}

/* Returns 1 if the menu parameter is a top level menu
 * exiting such a menu will lead to exiting the curses app
 */
int is_top_menu(select_menu *menu)
{
	select_menu *it;
	for (it=main_menu;it;it=it->next_sibling)
		if (it == menu)
			return 1;

	return 0;
}

/* Execute menu's associated action when the user
 * enters the menu
*/
int exec_menu_action(select_menu *menu)
{
	int ret;

	if (menu->flags & INTERNAL_COMMAND) {
		/* run internal command, just call function */
		ret=menu->action(menu,NULL);
		if (ret < 0)
			fprintf(output,"Failed to run command for menu [%s]\n",menu->name);
		if (menu->flags & EXIT_MENUCONFIG) {
			cleanup();
			exit(0);
		}
	} else {
			if (menu->child) {
				/* display the children of this menu */
				return draw_sibling_menu(menu->child);
			}
			else if (menu->item_list) {
				/* display the select items bound to this menu */
				return draw_item_list(menu);
			}
	}

	return 0;
}

