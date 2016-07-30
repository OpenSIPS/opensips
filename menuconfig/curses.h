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


#ifndef _menuconfigcurses_h_
#define _menuconfigcurses_h_

#include<curses.h>
#include<stdarg.h>
#include "menus.h"

#define MIN_X	80
#define MIN_Y	20

extern volatile int max_x;
extern volatile int max_y;

void cleanup();
void set_xy_size(int sig);
void _quit_handler(int sig);
int draw_sibling_menu(select_menu *menu);
int draw_item_list(select_menu *menu);

#define HIGH_NOTICE_Y	(max_y/16)

#define NOTICE_Y	(max_y*3/4)
#define NOTICE_X	(10)

#define print_notice(y,x,prompt,...) \
	do { \
		mvprintw(y,x, __VA_ARGS__); \
		clrtobot(); \
		if (prompt) \
			getch(); \
	} while (0)

#endif
