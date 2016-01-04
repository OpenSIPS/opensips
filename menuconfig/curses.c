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
#include<string.h>

#include<sys/ioctl.h>
#include<errno.h>

#include "curses.h"
#include "main.h"

volatile int max_x = 0;
volatile int max_y = 0;

/* Cleanup on exit.
 * Mandatory to be called on all permanent exits from menuconfig
 * Otherwise, console will be messed up
*/
void cleanup(void)
{
	delwin(stdscr);
	endwin();
	refresh();
	fclose(output);
}

/* Update actual console size
 * Note - Console size will be updated on the spot,
 * as this is called on a signal, but actual re-drawing will
 * be done on another key press */
void set_xy_size(int sig)
{
	struct winsize ws;

	/* ioctl for the window size. TODO - is this portable ? */
	if (ioctl(0,TIOCGWINSZ,&ws)!=0) {
		fprintf(stdout,"Updating window size failed:%s\n",strerror(errno));
		return;
	}

	max_x = ws.ws_col;
	max_y = ws.ws_row;
	if (max_x < MIN_X || max_y < MIN_Y) {
		fprintf(output, "Terminal must be at least %d x %d.\n", MIN_X, MIN_Y);
		max_x = MIN_X - 1;
		max_y = MIN_Y - 1;
	}
}

void _quit_handler(int sig)
{
	fprintf(output,"QUIT RECEIVED\n");
	cleanup();
	exit(0);
}

int draw_sibling_menu(select_menu *menu)
{
	int i,c,maxopt,d;
	char buf[40];
	select_menu *it;
	int cur_index=0;
	int skip=0;
	int max_len=0,len;
again:
	wclear(menu_window);

	/* print title in colour */
	attron(COLOR_PAIR(1));
	mvprintw(HIGH_NOTICE_Y,max_x/2-20,menu->parent?menu->parent->name:"OpenSIPS Main Configuration Menu");
	/* print footer */
	print_notice(NOTICE_Y,NOTICE_X,0,"Press h for navigation help.");
	attroff(COLOR_PAIR(1));

	/* draw actual menu */
	i=0;
	for (it=menu;it;it=it->next_sibling) {
		wmove(menu_window, max_y/4+i++, max_x / 2 - 20);
		snprintf(buf, sizeof(buf), " %s", it->name);
		waddstr(menu_window, buf);
		len = strlen(it->name) +6;
		if (len > max_len)
			max_len = len;
	}

	/* draw selection marker */
	wmove(menu_window, max_y/4+cur_index, (max_x / 2) - 25);
	waddstr(menu_window, "--->");

	/* print box with color */
	wattron(menu_window,COLOR_PAIR(2));
	for (d=-1;d<i+1;d++) {
		wmove(menu_window,max_y/4+d,max_x/2-30);
		wprintw(menu_window,"|");
		wmove(menu_window,max_y/4+d,max_x/2-20+max_len);
		wprintw(menu_window,"|");
	}

	for (d=0;d<max_len+9;d++) {
		wmove(menu_window,max_y/4-2,max_x/2-29+d);
		wprintw(menu_window,"_");
		wmove(menu_window,max_y/4+i,max_x/2-29+d);
		wprintw(menu_window,"_");
	}

	wattroff(menu_window,COLOR_PAIR(2));
	wmove(menu_window, 0, 0);
	wrefresh(menu_window);

	maxopt = i-1;

	c = getch();
	switch (c) {
		case KEY_UP:
			if (cur_index > 0)
				cur_index--;
			break;
		case KEY_DOWN:
			if (cur_index < maxopt)
				cur_index++;
			break;
		case KEY_RIGHT:
		case KEY_ENTER:
		case '\n':
			for (i=0,it=menu;i<cur_index;i++,it=it->next_sibling)
				;
			c = exec_menu_action(it);
			break;
		case 'h':
		case 'H':
			clear();
			print_notice(max_y/2,20,0,"Use UP and DOWN arrow keys to navigate.");
			print_notice(max_y/2+1,20,0,"Use RIGHT arrow or ENTER key to enter a certain menu.");
			print_notice(max_y/2+2,20,0,"Use LEFT arror or Q key to go back.");
			print_notice(max_y/2+3,20,0,"Use SPACE to toggle an entry ON/OFF.\n");
			print_notice(max_y/2+4,20,1,"Press any key to return to menuconfig.");
			refresh();
			break;
		case KEY_LEFT:
		case 'q':
		case 'Q':
			for (it=menu;it;it=it->next_sibling) {
				if (it->child_changed == CHILD_CHANGED) {
					if (skip == 0) {
						/* have we asked before and got negative response ? */
						print_notice(NOTICE_Y,NOTICE_X,0,"You have not saved changes. Go back anyway ? [y/n] ");
						c = getch();
						if (c == 'n' || c == 'N')
							goto again;
						else {
							it->child_changed = CHILD_CHANGE_IGNORED;
							skip=1;
							return 0;
						}
					} else
						it->child_changed = CHILD_CHANGE_IGNORED;
				}
			}
			if (skip == 1)
				return 0;
			return 0;
	}

	goto again;
}

int draw_item_list(select_menu *menu)
{
	select_item *it, *it_2;
	int i=0,j=0,k=0,d,sc=0;
	int c,curopt=0;
	char buf[40];
	select_item *current=NULL;
	int should_scroll,max_display;
	int len,max_len=0;
	int disp_start=0,actual_pos=0;
again:
	i=0;j=0;k=0;
	max_display=max_y/2-2;
	should_scroll=menu->item_no>max_display?1:0;

	wclear(menu_window);

	/* print title in colour */
	attron(COLOR_PAIR(1));
	mvprintw(HIGH_NOTICE_Y,max_x/2-20,menu->name);
	attroff(COLOR_PAIR(1));

	if (should_scroll) {
		for (it=menu->item_list,sc=0;it;it=it->next,sc++) {
			/* only draw visible part of menu */
			if (sc>=disp_start && i < max_display) {
				wmove(menu_window, max_y/4+j++, max_x / 2 - 20);
				i++;
				snprintf(buf, sizeof(buf), "%s%s%s %s", it->group_idx ? "(" : "[",
					it->enabled ? "*" : " ", it->group_idx ? ")" : "]", it->name);
				waddstr(menu_window, buf);
				len=strlen(it->name);
				if (len > max_len)
					max_len=len;
			}
		}
	} else {
		for (it=menu->item_list,sc=0;it;it=it->next,sc++) {
			/* draw everything */
			wmove(menu_window, max_y/4+j++, max_x / 2 - 20);
			i++;
			snprintf(buf, sizeof(buf), "%s%s%s %s", it->group_idx ? "(" : "[",
					it->enabled ? "*" : " ", it->group_idx ? ")" : "]", it->name);
			waddstr(menu_window, buf);
			len=strlen(it->name);
			if (len > max_len)
				max_len=len;
		}

		/* marker is always in par with the selected option */
		actual_pos=curopt;
	}

	for(it=menu->item_list;it;it=it->next)
		if (k++ == curopt) {
			current=it;
			break;
		}

	/* print current item description */
	if (current->description) {
		attron(COLOR_PAIR(1));
		print_notice(NOTICE_Y,NOTICE_X,0,current->description);
		attroff(COLOR_PAIR(1));
	}

	move(max_y/4+actual_pos,max_x/2-19);

	/* draw box */
	wattron(menu_window,COLOR_PAIR(2));
	for (d=-1;d<i+1;d++) {
		wmove(menu_window,max_y/4+d,max_x/2-26);
		wprintw(menu_window,"|");
		wmove(menu_window,max_y/4+d,max_x/2-10+max_len);
		wprintw(menu_window,"|");
	}

	for (d=0;d<max_len+15;d++) {
		wmove(menu_window,max_y/4-2,max_x/2-25+d);
		wprintw(menu_window,"_");
		wmove(menu_window,max_y/4+i,max_x/2-25+d);
		wprintw(menu_window,"_");
	}

	/* show scrolling notifications if it's the case */
	if (should_scroll && disp_start > 0) {
		wmove(menu_window,max_y/4,max_x/2-5+max_len);
		wprintw(menu_window,"Scroll up for more");
	}

	if (should_scroll && disp_start + max_display < menu->item_no) {
		wmove(menu_window,max_y/4+max_display-1,max_x/2-5+max_len);
		wprintw(menu_window,"Scroll down for more");
	}

	wattroff(menu_window,COLOR_PAIR(2));

	wrefresh(menu_window);
	k=0;

	while ((c = getch())) {
		switch (c) {
			case KEY_UP:
				if (should_scroll && curopt != 0) {
					if (curopt == disp_start) {
						disp_start--;
						actual_pos=0;
					} else
						actual_pos--;
					curopt--;
				} else if (curopt!=0) {
					curopt--;
				}
				break;
			case KEY_DOWN:
				if (should_scroll && curopt < menu->item_no-1) {
					if (curopt == (disp_start+max_display-1)) {
						disp_start++;
						actual_pos=i-1;
					} else
						actual_pos++;
					curopt++;
				} else if (curopt < i-1) {
					curopt++;
				}
				break;
			case ' ':
				for (it=menu->item_list;it;it=it->next) {
					if (k++ == curopt) {
						it->enabled=it->enabled?0:1;
						menu->child_changed=CHILD_CHANGED;

						it->group_idx = it->group_idx ? -it->group_idx : 0;
						if (it->group_idx<0)
							for(it_2=menu->item_list;it_2;it_2=it_2->next)
								if (it!=it_2 && it_2->group_idx<0 && it->group_idx==it_2->group_idx) {
									it_2->group_idx = -it_2->group_idx;
									it_2->enabled=0;
									menu->child_changed=CHILD_CHANGED;
									break;
								}
					}
				}
				break;
			case KEY_LEFT:
			case 'q':
			case 'Q':
				wclear(menu_window);
				return 0;
		}

		goto again;
	}

	return 0;
}