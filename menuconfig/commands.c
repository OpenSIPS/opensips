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
#include<unistd.h>
#include<sys/types.h>
#include<sys/wait.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<time.h>
#include<curses.h>
#include<signal.h>
#include<errno.h>

#include "main.h"

#define MENUCONFIG_CFG_PATH_LEN		strlen(MENUCONFIG_CFG_PATH)

/* Will globally save everything the user has altered */
int save_all_changes(select_menu *menu,void *arg)
{
	static char name_buf[128];
	select_menu *current;
	cfg_gen_t *it;

#if MENUCONFIG_HAVE_SOURCES > 0
	/* Take care of compile related options */
	if (dump_make_conf(menu,arg) < 0)
		fprintf(output,"Failed to save all compile related options\n");
#else
	if (run_locally && dump_make_conf(menu,arg) < 0)
		fprintf(output,"Failed to save all compile related options\n");
#endif

	/* Save changes to all types of configs */
	for (it=configs;it->name;it++) {
		strcpy(name_buf,"Save ");
		strcat(name_buf,it->name);
		current=find_menu(name_buf,main_menu);
		if (save_m4_def(current,NULL) < 0)
			fprintf(output,"Failed to save cfg %s\n",it->name);
	}

	return 0;
}

/* Resets all unsaved compile related options */
int reset_unsaved_compile(select_menu *menu,void *arg)
{
	select_menu *current;
	select_item *it;

	current=find_menu(CONF_EXCLUDED_MODS,main_menu);
	for (it=current->item_list;it;it=it->next)
		it->enabled=it->prev_state;
	current->child_changed=CHILD_NO_CHANGES;

	current=find_menu(CONF_COMPILE_FLAGS,main_menu);
	for (it=current->item_list;it;it=it->next) {
		if (it->group_idx && it->prev_state != it->enabled)
			it->group_idx = -it->group_idx;
		it->enabled=it->prev_state;
	}
	current->child_changed=CHILD_NO_CHANGES;

	current=find_menu(CONF_INSTALL_PREFIX,main_menu);
	if (install_prefix != prev_prefix) {
		if (install_prefix) {
			free(install_prefix);
			install_prefix=NULL;
		}
		install_prefix=prev_prefix;
	}
	current->child_changed=CHILD_NO_CHANGES;


	print_notice(NOTICE_Y,NOTICE_X,1,"Changes have been reset. Press any key to continue");

	return 0;
}

/* Runs 'make install' */
int run_make_install(select_menu *menu,void *arg)
{
	int ret=0,status;

	/* save current tty modes */
	def_prog_mode();
	/* restore original tty modes */
	endwin();

	/* temporarily ignore SIGINT
	 * in case child is killed, we do not want to also exit main app
	 */
	signal(SIGINT, SIG_IGN);
	ret=fork();
	if (ret<0) {
		fprintf(output,"Failed to fork process\n");
		goto end;
	}
	if (ret > 0) {
		/* parent */
		wait(&status);
		if (status != 0) {
			fprintf(output,"Command failed to execute properly\n");
			goto end;
		}
	} else {
		/* child */
		/* Do not propagate SIGINT to parent
		   but propagate SIGWINCH to adjust
		window size */
		signal(SIGINT, SIG_DFL);
		execlp("make","make","install",(char *)0);
		exit(-1);
	}

end:
	/* Restore SIGINT handler */
	signal(SIGINT,_quit_handler);
	printf("\n\nPress any key to return to menuconfig\n\n");
	getch();

	/* restore save modes, repaint screen */
	refresh();
	return ret;
}

/* Runs 'make proper' */
int run_make_proper(select_menu *menu,void *arg)
{
	int ret=0,status;

	/* save current tty modes */
	def_prog_mode();
	/* restore original tty modes */
	endwin();

	/* temporarily ignore SIGINT
	 * in case child is killed, we do not want to also exit main app
	 */
	signal(SIGINT, SIG_IGN);
	ret=fork();
	if (ret<0) {
		fprintf(output,"Failed to fork process\n");
		goto end;
	}
	if (ret > 0) {
		/* parent */
		wait(&status);
		if (status != 0) {
			fprintf(output,"Command failed to execute properly\n");
			goto end;
		}
	} else {
		/* child */
		/* Do not propagate SIGINT to parent
		   but propagate SIGWINCH to adjust
		window size */
		signal(SIGINT, SIG_DFL);
		execlp("make","make","proper",(char *)0);
		exit(-1);
	}

end:
	/* Restore SIGINT handler */
	signal(SIGINT,_quit_handler);
	printf("\n\nPress any key to return to menuconfig\n\n");
	getch();

	/* restore save modes, repaint screen */
	refresh();
	return ret;
}

/* Generates an actual cfg based on users selected
 * m4 defs
*/
int generate_cfg(select_menu *menu,void *arg)
{
	static char generated_name[128];
	static char defs_cfg_path[256];
	static char cfg_path[256];
	static char buffer[1024];
	char *p, *error_msg;
	int bytes, pipe_fd[2];
	cfg_gen_t *m4_cfg;
	int n,ret,fd,status;
	time_t now;
	struct tm now_tm;
	select_menu *items_menu = menu->prev_sibling->prev_sibling;

	/* Kind of bogus. Maybe menu should have backpointer to cfg entry */
	p = memchr(items_menu->name,' ',strlen(items_menu->name));
	if (!p) {
		fprintf(output,"Invalid menu name [%s]\n",items_menu->name);
		return -1;
	}

	p++;
	m4_cfg = find_cfg_entry(p);

	if (!m4_cfg) {
		fprintf(output,"Failed to find cfg entry for %s\n",items_menu->name);
		return -1;
	}

	/* Save everything that was configured */
	if (save_m4_def(menu->prev_sibling,(void *)1) < 0) {
		fprintf(output,"Failed to save m4 defs\n");
		return -1;
	}

	/* generate config name */
	now=time(NULL);
	localtime_r(&now, &now_tm);
	n = snprintf(generated_name,128,"%sopensips_%s_%d-%d-%d_%d:%d:%d.cfg",
			run_locally?"etc/":MENUCONFIG_GEN_PATH,
			m4_cfg->output_name,now_tm.tm_year+1900,now_tm.tm_mon+1,
			now_tm.tm_mday,now_tm.tm_hour,now_tm.tm_min,now_tm.tm_sec);
	if (n<0 || n>128) {
		fprintf(output,"Failed to create command to generate cfg\n");
		return -1;
	}
	if (pipe(pipe_fd) < 0) {
		fprintf(output,"Failed to allocate pipe fd\n");
		return -1;
	}

	/* skip all the signal crap. M4 should be much much faster than make install */
	ret = fork();
	if (ret < 0) {
		fprintf(output,"Failed to fork process \n");
		return -1;
	} else if (ret > 0) {
		close(pipe_fd[1]);

		bytes = read(pipe_fd[0], buffer, 1024);
		close(pipe_fd[0]);
		/* parent */
		wait(&status);
		if (!status)
			print_notice(NOTICE_Y,NOTICE_X,1,
				"Config generated : %s = SUCCESS. Press any key to continue",
				generated_name);
		else
			print_notice(NOTICE_Y,NOTICE_X,1,
				"Config generated : %s = FAILED (%.*s). Press any key to continue",
				generated_name, bytes, buffer);
	} else {
		close(pipe_fd[0]);
		fd = open(generated_name,O_RDWR|O_CREAT,S_IRUSR|S_IWUSR);
		if (fd < 0) {
			fprintf(output,"Failed to open output file\n");
			exit(-1);
		}

		memcpy(cfg_path,run_locally?"menuconfig/configs/":MENUCONFIG_CFG_PATH,
				run_locally?19:MENUCONFIG_CFG_PATH_LEN);
		memcpy(cfg_path+(run_locally?19:MENUCONFIG_CFG_PATH_LEN),
				m4_cfg->cfg_m4,strlen(m4_cfg->cfg_m4)+1);
		memcpy(defs_cfg_path,run_locally?"menuconfig/configs/":MENUCONFIG_CFG_PATH,
				run_locally?19:MENUCONFIG_CFG_PATH_LEN);
		memcpy(defs_cfg_path+(run_locally?19:MENUCONFIG_CFG_PATH_LEN),
				m4_cfg->defs_m4,strlen(m4_cfg->defs_m4)+1);
		/* child */
		/* redirect child output to generated file name */
		dup2(fd,STDOUT_FILENO);
		dup2(pipe_fd[1],STDERR_FILENO);
		close(pipe_fd[1]);
		close(fd);
		execlp("m4","m4",defs_cfg_path,cfg_path,(char *)0);
		switch(errno) {
			case EACCES:
				error_msg = "permissions error";
				break;
			case ENOENT:
				error_msg = "'m4' not found - make sure you have 'm4' installed";
				break;
			default:
				error_msg = strerror(errno);
		}

		if (write(STDERR_FILENO, error_msg, strlen(error_msg) < 0))
			fprintf(output,"write error %d (%s)\n", errno, strerror(errno));

		fprintf(output,"Error generating config: %s\n", error_msg);
		exit(-1);
	}

	return 0;
}

/* Reads install prefix from user */
int read_install_prefix(select_menu *menu,void *arg)
{
	#define query_msg		"Enter install prefix "
	#define folder_ok		"Folder exists and is accesible "
	char str[256];
	char *p;
	int ret,len;

	print_notice(NOTICE_Y,NOTICE_X,0,"%s (Current = '%s') : ",query_msg,
			install_prefix?install_prefix:DEFAULT_INSTALL_PREFIX);

	/* print directory that user is typing */
	echo();

	ret=getstr(str);
	if (ret != 0) {
		fprintf(output,"Failed to read new install prefix\n");
		return -1;
	}

	/* disable echoing character on the window */
	noecho();

	/* Empty directory = default directory */
	if (strlen(str) != 0) {
		p = str;
		/* trim the spaces before the prefix */
		while (*p && *p == ' ') p++;
		prev_prefix=install_prefix;

		len = strlen(p);
		install_prefix = malloc(p[len-1]=='/'?len+1:len+2);
		if (!install_prefix) {
			fprintf(output,"No more mem\n");
			return -1;
		}

		memset(install_prefix,0,p[len-1]=='/'?len+1:len+2);
		memcpy(install_prefix,p,len);
		if (p[len-1] != '/')
			install_prefix[len]='/';

		print_notice(NOTICE_Y,NOTICE_X,0,"%s. Install prefix is currently [%s]",folder_ok,
			install_prefix?install_prefix:DEFAULT_INSTALL_PREFIX);
		clrtoeol();
		print_notice(NOTICE_Y+1,NOTICE_X,1,"Press any key to continue !");
		clrtoeol();
	} else {
		/* NULL = default prefix */
		prev_prefix=install_prefix;
		install_prefix=NULL;
		print_notice(NOTICE_Y,NOTICE_X,0,"%s. Install prefix is currently [%s]",folder_ok,
			install_prefix?install_prefix:DEFAULT_INSTALL_PREFIX);
		clrtoeol();
		print_notice(NOTICE_Y+1,NOTICE_X,1,"Press any key to continue !");
		clrtoeol();
	}

	menu->child_changed=CHILD_CHANGED;
	return 0;
}

/* Saves all the configured changes
 * for the cfg entry associated to the current menu
 */
int save_m4_def(select_menu *menu,void *arg)
{
	char *p;
	select_menu *items_menu = menu->prev_sibling;
	select_item *it;
	cfg_gen_t *m4_cfg;
	static char cfg_path[256];
	FILE *f;

	/* A little bogus, maybe menu should have back-pointer to cfg entry */
	p = memchr(items_menu->name,' ',strlen(items_menu->name));
	if (!p) {
		fprintf(output,"Invalid menu name [%s]\n",items_menu->name);
		return -1;
	}

	p++;
	m4_cfg = find_cfg_entry(p);

	if (!m4_cfg) {
		fprintf(output,"Failed to find cfg entry for %s\n",items_menu->name);
		return -1;
	}

	memcpy(cfg_path,run_locally?"menuconfig/configs/":MENUCONFIG_CFG_PATH,
			run_locally?19:MENUCONFIG_CFG_PATH_LEN);
	memcpy(cfg_path+(run_locally?19:MENUCONFIG_CFG_PATH_LEN),
			m4_cfg->defs_m4,strlen(m4_cfg->defs_m4)+1);

	f = fopen(cfg_path,"w");
	if (!f) {
		fprintf(output,"Failed to open m4 defs\n");
		return -1;
	}

	fprintf(f,"divert(-1)\n");
	for (it=items_menu->item_list;it;it=it->next) {
		fprintf(f,"define(`%s', `%s') #%s\n",it->name,it->enabled?"yes":"no",
			it->description);
	}
	fprintf(f,"divert");

	if (arg == NULL) {
		print_notice(NOTICE_Y,NOTICE_X,1,"Script configurations saved for %s. Press any key to continue !",m4_cfg->name);
	}

	fclose(f);
	items_menu->child_changed=CHILD_NO_CHANGES;
	return 0;
}

/* Save all related compile options to Makefile.conf*/
int dump_make_conf(select_menu *menu,void *arg)
{
	select_menu *current;
	select_item *it;
	int i,k=0;
	int start_grp=0, prev_grp=0;

	FILE *f = fopen(MAKE_CONF_FILE,"w");
	if (!f) {
		fprintf(stderr,"Failed to open [%s]\n",MAKE_CONF_FILE);
		return -1;
	}

	/* START compile MODULES related options */
	current = find_menu(CONF_EXCLUDED_MODS,main_menu);
	for (it=current->item_list;it;it=it->next) {
		for (i=0;i<it->dependency_no;i++) {
			if (i==0)
				fprintf(f,"#%s=%s|%s\n",it->name,it->description,it->dependency[i]);
			else
				fprintf(f,"#%s=%s\n",it->name,it->dependency[i]);
			if (it->enabled) {
				print_notice(NOTICE_Y+k++,NOTICE_X,0,
					"You have enabled the '%s' module, so please install '%s'\n",
					it->name,it->dependency[i]);
			}
		}
		it->prev_state=it->enabled;
	}

	print_notice(NOTICE_Y+k,NOTICE_X,1,"Press any key to continue\n");

	fprintf(f,"\nexclude_modules?= ");
	for (it=current->item_list;it;it=it->next) {
		fprintf(f,"%s ",it->name);
	}

	fprintf(f,"\n\ninclude_modules?= ");
	for (it=current->item_list;it;it=it->next) {
		if (it->enabled)
			fprintf(f,"%s ",it->name);
	}

	current->child_changed=CHILD_NO_CHANGES;
	/* END compile MODULES related options */
	fprintf(f,"\n\n");

	/* START compile DEFS related options */
	current = find_menu(CONF_COMPILE_FLAGS,main_menu);
	for (it=current->item_list;it;it=it->next) {
		if (it->group_idx && !start_grp) {
			start_grp = 1;
			prev_grp = it->group_idx>0 ? it->group_idx : -it->group_idx;
			fprintf(f, "%s\n", GRP_START_STR);
		}
		if (start_grp)
			if ((it->group_idx>0 && (it->group_idx != prev_grp)) ||
				(it->group_idx<0 && (-it->group_idx != prev_grp)) ||
				it->group_idx==0) {
				start_grp = 0;
				fprintf(f, "%s\n", GRP_END_STR);
			}

		fprintf(f,"%sDEFS+= -D%s #%s",
			it->enabled?"":"#",it->name,it->description);
		it->prev_state=it->enabled;
	}

	if (!it && start_grp)
		fprintf(f, "%s\n", GRP_END_STR);

	current->child_changed=CHILD_NO_CHANGES;
	/* END compile DEFS related options */

	/* START install prefix related options */
	current=find_menu(CONF_INSTALL_PREFIX,main_menu);
	fprintf(f,"\nPREFIX ?= %s",install_prefix?install_prefix:DEFAULT_INSTALL_PREFIX);

	prev_prefix=install_prefix;
	current->child_changed=CHILD_NO_CHANGES;
	/* END install prefix related options */

	fclose(f);
	return 0;
}

