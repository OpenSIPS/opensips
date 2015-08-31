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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <curses.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "main.h"

FILE *output;
select_menu *main_menu;
WINDOW *menu_window;
char *install_prefix=NULL;
char *prev_prefix=NULL;
int run_locally=0;

/* Init all the menus. Logic is hardcoded */
int init_main_menu(void)
{
	select_menu *aux;

#if MENUCONFIG_HAVE_SOURCES > 0
	main_menu = init_menu(CONF_COMPILE_OPT,0,0);
	if (!main_menu) {
		fprintf(output,"Failed to create main menu\n");
		return -1;
	}

	aux = init_menu(MAKE_INSTALL,INTERNAL_COMMAND,(run_action)run_make_install);
	if (!aux) {
		fprintf(output,"Failed to create menu\n");
		return -1;
	}
	link_sibling(main_menu,aux);

	aux = init_menu(MAKE_PROPER,INTERNAL_COMMAND,(run_action)run_make_proper);
	if (!aux) {
		fprintf(output,"Failed to create menu\n");
		return -1;
	}
	link_sibling(main_menu,aux);

	aux = init_menu(CONF_SCRIPT,0,0);
	if (!aux) {
		fprintf(output,"Failed to create menu\n");
		return -1;
	}
	link_sibling(main_menu,aux);

	if (gen_scripts_menu(aux) < 0) {
		fprintf(output,"Failed to get all script options\n");
		return -1;
	}

	aux = init_menu(EXIT_SAVE_EVERYTHING,INTERNAL_COMMAND|EXIT_MENUCONFIG,(run_action)save_all_changes);
	if (!aux) {
		fprintf(output,"Failed to create menu\n");
		return -1;
	}
	link_sibling(main_menu,aux);

	aux = init_menu(CONF_COMPILE_FLAGS,0,0);
	if (!aux) {
		fprintf(output,"Failed to create menu\n");
		return -1;
	}
	link_child(main_menu,aux);

	aux = init_menu(CONF_EXCLUDED_MODS,0,0);
	if (!aux) {
		fprintf(output,"Failed to create menu\n");
		return -1;
	}
	link_child(main_menu,aux);

	aux = init_menu(CONF_INSTALL_PREFIX,INTERNAL_COMMAND,(run_action)read_install_prefix);
	if (!aux) {
		fprintf(output,"Failed to create menu\n");
		return -1;
	}
	link_child(main_menu,aux);

	aux = init_menu(CONF_RESET_CHANGES,INTERNAL_COMMAND,
			(run_action)reset_unsaved_compile);
	if (!aux) {
		fprintf(output,"Failed to create menu\n");
		return -1;
	}
	link_child(main_menu,aux);

	aux = init_menu(CONF_SAVE_CHANGES,INTERNAL_COMMAND,
			(run_action)dump_make_conf);
	if (!aux) {
		fprintf(output,"Failed to create menu\n");
		return -1;
	}
	link_child(main_menu,aux);

	if (parse_make_conf() < 0) {
		fprintf(output,"Failed to parse %s\n", MAKE_CONF_FILE);
		return -1;
	}
#else
	if (run_locally) {
		main_menu = init_menu(CONF_COMPILE_OPT,0,0);
		if (!main_menu) {
			fprintf(output,"Failed to create main menu\n");
			return -1;
		}

		aux = init_menu(MAKE_INSTALL,INTERNAL_COMMAND,(run_action)run_make_install);
		if (!aux) {
			fprintf(output,"Failed to create menu\n");
			return -1;
		}
		link_sibling(main_menu,aux);

		aux = init_menu(MAKE_PROPER,INTERNAL_COMMAND,(run_action)run_make_proper);
		if (!aux) {
			fprintf(output,"Failed to create menu\n");
			return -1;
		}
		link_sibling(main_menu,aux);

		aux = init_menu(CONF_SCRIPT,0,0);
		if (!aux) {
			fprintf(output,"Failed to create menu\n");
			return -1;
		}
		link_sibling(main_menu,aux);

		if (gen_scripts_menu(aux) < 0) {
			fprintf(output,"Failed to get all script options\n");
			return -1;
		}

		aux = init_menu(EXIT_SAVE_EVERYTHING,INTERNAL_COMMAND|EXIT_MENUCONFIG,(run_action)save_all_changes);
		if (!aux) {
			fprintf(output,"Failed to create menu\n");
			return -1;
		}
		link_sibling(main_menu,aux);

		aux = init_menu(CONF_COMPILE_FLAGS,0,0);
		if (!aux) {
			fprintf(output,"Failed to create menu\n");
			return -1;
		}
		link_child(main_menu,aux);

		aux = init_menu(CONF_EXCLUDED_MODS,0,0);
		if (!aux) {
			fprintf(output,"Failed to create menu\n");
			return -1;
		}
		link_child(main_menu,aux);

		aux = init_menu(CONF_INSTALL_PREFIX,INTERNAL_COMMAND,(run_action)read_install_prefix);
		if (!aux) {
			fprintf(output,"Failed to create menu\n");
			return -1;
		}
		link_child(main_menu,aux);

		aux = init_menu(CONF_RESET_CHANGES,INTERNAL_COMMAND,
				(run_action)reset_unsaved_compile);
		if (!aux) {
			fprintf(output,"Failed to create menu\n");
			return -1;
		}
		link_child(main_menu,aux);

		aux = init_menu(CONF_SAVE_CHANGES,INTERNAL_COMMAND,
				(run_action)dump_make_conf);
		if (!aux) {
			fprintf(output,"Failed to create menu\n");
			return -1;
		}
		link_child(main_menu,aux);

		if (parse_make_conf() < 0) {
			fprintf(output,"Failed to parse %s\n", MAKE_CONF_FILE);
			return -1;
		}
	} else {
		main_menu = init_menu(CONF_SCRIPT,0,0);
		if (!main_menu) {
			fprintf(output,"Failed to create menu\n");
			return -1;
		}

		if (gen_scripts_menu(main_menu) < 0) {
			fprintf(output,"Failed to get all script options\n");
			return -1;
		}

		aux = init_menu(EXIT_SAVE_EVERYTHING,INTERNAL_COMMAND|EXIT_MENUCONFIG,(run_action)save_all_changes);
		if (!aux) {
			fprintf(output,"Failed to create menu\n");
			return -1;
		}
		link_sibling(main_menu,aux);
	}
#endif
	return 0;
}


int main(int argc,char **argv)
{
	int ret=0;

	/* Open debugging output file */
	output = fopen("curses.out","w");
	if (output == NULL) {
		fprintf(stderr,"Error opening output file\n");
		return -1;
	}

	if (argc > 1 && memcmp(argv[1],"--local",7) == 0) {
		run_locally=1;
		fprintf(output,"Running in local mode\n");
	}

	/*  Initialize ncurses  */
	if ( initscr() == NULL ) {
		fprintf(stderr, "Error initialising ncurses.\n");
		return-1;
	}

	fprintf(output,"Initialized main window\n");

	set_xy_size(0);
	signal(SIGWINCH, set_xy_size);	/* handle window resizing in xterm	 */
	signal(SIGINT, _quit_handler);		/* handle forced closured		 */

	if (max_x < MIN_X || max_y < MIN_Y) {
		fprintf(output, "Terminal must be at least %d x %d.\n", MIN_X, MIN_Y);
		ret=-1;
		goto cleanup;
	}

	/* don't buffer input until the enter key is pressed */
	cbreak();
	/* don't echo user input to the screen */
	noecho();
	/* allow the use of arrow keys */
	keypad(stdscr, TRUE);
	/* Clear anything that might be on the screen */
	clear();
	refresh();

	/* Create & bind all menu entries */
	init_main_menu();
	menu_window = newwin(max_y, max_x, 0, 0);

	/* enable colours support */
	if(has_colors() != FALSE) {
		start_color();
		init_pair(1, COLOR_GREEN, COLOR_BLACK);
		init_pair(2, COLOR_BLUE, COLOR_BLACK);
	}

	/* Start drawing everything on screen */
	draw_sibling_menu(main_menu);

	/* We got here - the user exited the menu. Check for unsaved stuff */
	/* TODO */
cleanup:
	delwin(stdscr);
	endwin();
	refresh();

	fclose(output);
	return ret;
}
