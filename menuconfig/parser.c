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

#include "parser.h"
#include "main.h"

#define MAX_MODULE_NAME_SIZE 20
#define MENUCONFIG_CFG_PATH_LEN		strlen(MENUCONFIG_CFG_PATH)

static char prev_module[MAX_MODULE_NAME_SIZE];
static int prev_module_len=0;
static select_item *prev_item;

/* Parses a single module dependency line */
int parse_dep_line(char *line,select_menu *parent)
{
	char *mod_name,*mod_dep,*mod_desc,*p;
	int name_len,desc_len,dep_len;
	select_item *item;

	mod_name = line+1;
	int len = strlen(line)-1;
	p = memchr(line,'=',len);
	if (!p) {
		fprintf(output,"Malformed dep line\n");
		return -1;
	}

	name_len = p - mod_name;
	mod_name[name_len]=0;

	/* Is this still the previous module ? */
	if (name_len == prev_module_len && memcmp(prev_module,mod_name,name_len) == 0) {
		/* Previously found module with multiple deps.
		 * Just add the new dependency */
		fprintf(output,"found prev module %s with extra deps\n",mod_name);

		mod_dep = p+1;
		dep_len = (line+len) - mod_dep;
		mod_dep[dep_len]=0;

		if (add_dependency(prev_item,mod_dep) < 0) {
			fprintf(output,"Failed to add dependency\n");
			return -1;
		}
	} else {
		fprintf(output,"found new module %s\n",mod_name);

		/* nope, new module, get description */
		mod_desc=p+1;
		p = memchr(mod_desc,'|',line+len-mod_desc);
		if (!p) {
			fprintf(output,"Malformed desc line\n");
			return -1;
		}

		desc_len = p-mod_desc;
		mod_desc[desc_len]=0;

		item = create_item(mod_name,mod_desc);
		if (item == NULL) {
			fprintf(output,"Failed to create item\n");
			return -1;
		}

		mod_dep = p+1;
		dep_len = (line+len) - mod_dep;
		mod_dep[dep_len]=0;

		/* Add the dependency */
		if (add_dependency(item,mod_dep) < 0) {
			fprintf(output,"Failed to add dependency\n");
			return -1;
		}

		/* And link it */
		link_item(parent,item);
		prev_item = item;

		strcpy(prev_module,mod_name);
		prev_module_len = name_len;
	}

	return 0;
}

/* Parse the include modules line */
int parse_include_line(char *line,select_menu *parent)
{
	char *p,*start=NULL,*end;
	int len = strlen(line),mod_len=0;
	int found_mod=0;

	p=memchr(line,'=',len);
	if (!p) {
		fprintf(output,"Malformed include line\n");
		return -1;
	}
	p++;

	for (;*p==' ';p++)
		;

	for (;p<line+len-1;p++) {
		switch (*p) {
			case ' ':
				if (!found_mod)
					continue;
				else {
					end=p;
					mod_len = end-start;
					/* found an included module, mark it as enabled */
					enable_item(parent,start,mod_len);
					found_mod=0;
					break;
				}
			default:
				if (found_mod)
					continue;
				else {
					start = p;
					found_mod=1;
					break;
				}
		}
	}

	if (found_mod) {
		/* We skipped the last one, enable it as well */
		mod_len = line+len-start-1;
		enable_item(parent,start,mod_len);
	}

	return 0;
}

/* Parse a single compile flags DEFS line */
int parse_defs_line(char *line,select_menu *parent,int *group_idx,int *start_grp)
{
	char *start,*end,*desc_start;
	int def_len,enabled=1;
	select_item *item;
	int len = strlen(line);

	/* allows commenting out menuconfig features */
	if (!strncmp(line, SKIP_LINE_STR, SKIP_LINE_STRL))
		return 0;

	if (!strncmp(line,GRP_START_STR,17)) {
		if (!(*start_grp)) {
			*start_grp = 1;
			return 0;
		} else {
			fprintf(output,"Malformed DEFS line\n");
			return -1;
		}
	} else if(!strncmp(line,GRP_END_STR,15)) {
		if (*start_grp == 1) {
			(*group_idx)++;
			*start_grp = 0;
			return 0;
		} else {
			fprintf(output,"Malformed DEFS line\n");
			return -1;
		}
	}

	start = memchr(line,'-',len);
	if (!start) {
		fprintf(output,"Malformed DEFS line\n");
		return -1;
	}

	if (*line == '#')
		enabled=0;

	start+=2; /* -D */

	end = memchr(start,'#',len-(start-line));
	if (!end) {
		fprintf(output,"Malformed DEFS line\n");
		return -1;
	}

	end--;
	desc_start=end+2;
	desc_start[len]=0;

	def_len = end-start;
	start[def_len]=0;

	/* we have all info here. Create & Link it */
	item = create_item(start,desc_start);
	if (item == NULL) {
		fprintf(output,"Failed to create item\n");
		return -1;
	}

	item->enabled=enabled;
	item->prev_state=enabled;
	item->group_idx = *start_grp ? *group_idx : 0;
	if (item->group_idx && enabled)
		item->group_idx = -item->group_idx;
	link_item(parent,item);

	return 0;
}

/* Parse the install prefix line */
int parse_prefix_line(char *line,select_menu *menu)
{
	char *p;
	int pref_len, len = strlen(line);
	int new_buf_len;

	p=memchr(line,'=',len);
	if (!p) {
		fprintf(output,"Malformed prefix line\n");
		return -1;
	}

	p++;
	pref_len=line+len-1-p;
	while (pref_len > 0 && *p == ' ') {
		pref_len--;
		p++;
	}

	/* fix missing trailing slash */
	if (p[pref_len-1] != '/')
		new_buf_len = pref_len + 2;
	else
		new_buf_len = pref_len + 1;

	install_prefix = malloc(new_buf_len);
	if (!install_prefix) {
		fprintf(output,"No more memory\n");
		return -1;
	}
	memset(install_prefix, 0, new_buf_len);

	memcpy(install_prefix, p, pref_len);
	if (p[pref_len-1] != '/')
		install_prefix[pref_len] = '/';

	/* also init the prev prefix, used for
	 * resetting changes */
	prev_prefix=install_prefix;
	return 0;
}

/* Parse an m4 defs line for a cfg entry */
#define READ_BUF_SIZE	1024
static char read_buf[READ_BUF_SIZE];
int parse_defs_m4_line(char *line,select_menu *menu)
{
	char *start,*end,*value_start,*value_end,*desc_start;
	select_item *item;
	int len=strlen(line);

	len--;

	start=memchr(line,'`',len);
	if (!start) {
		fprintf(output,"Failed to find macro start\n");
		return -1;
	}

	start++;
	end=memchr(start,'\'',line+len-start);
	if (!end) {
		fprintf(output,"Failed to find macro end\n");
		return -1;
	}

	start[end-start]=0;

	value_start=memchr(end,'`',line+len-end);
	if (!value_start) {
		fprintf(output,"Failed to find macro value start\n");
		return -1;
	}

	value_start++;
	value_end=memchr(value_start,'\'',line+len-value_start);
	if (!value_end) {
		fprintf(output,"Failed to find macro value end\n");
		return -1;
	}

	desc_start=memchr(value_end,'#',line+len-value_end);
	if (!desc_start) {
		fprintf(output,"Failed to find macro description\n");
		return -1;
	}
	desc_start++;
	line[len]=0;

	item = create_item(start,desc_start);
	if (item == NULL) {
		fprintf(output,"Failed to create item\n");
		return -1;
	}

	if (memcmp(value_start,"yes",3)==0) {
		item->enabled=1;
		item->prev_state=1;
	}

	link_item(menu,item);
	return 0;
}

int parse_defs_m4(select_menu *curr_menu,cfg_gen_t *curr_cfg)
{
	FILE *f;
	char *p;
	static char cfg_path[256];

	if (!curr_menu || !curr_cfg) {
		fprintf(output,"Failed to locate menu with name [%s]\n",curr_menu->name);
		return -1;
	}

	memcpy(cfg_path,run_locally?"menuconfig/configs/":MENUCONFIG_CFG_PATH,
			run_locally?19:MENUCONFIG_CFG_PATH_LEN);
	memcpy(cfg_path+(run_locally?19:MENUCONFIG_CFG_PATH_LEN),
			curr_cfg->defs_m4,strlen(curr_cfg->defs_m4)+1);

	f=fopen(cfg_path,"r");
	if (!f) {
		fprintf(output,"Failed to open [%s]",curr_cfg->defs_m4);
		return -1;
	}

	while ( fgets( read_buf, READ_BUF_SIZE,f) != NULL) {
		p=strstr(read_buf,"define");
		if (!p)
			continue;

		if (parse_defs_m4_line(p,curr_menu) < 0) {
			fprintf(output,"Failed to parse m4 line [%s]\n",p);
			return -1;
		}
	}

	fclose(f);
	return 0;
}


enum dep_states { PARSE_DEPENDENCIES, PARSE_INCLUDE_MODULES,
				PARSE_COMPILE_DEFS, PARSE_PREFIX };

int parse_make_conf(void)
{
	enum dep_states state;
	FILE *conf = fopen(MAKE_CONF_FILE,"r");
	char *p;
	int defs=0;
	int start_grp=0, group_idx=1;

	if (!conf) {
		/* if we cannot find the Makefile.conf, try the template */
		conf = fopen(MAKE_TEMP_FILE, "r");
		if (!conf) {
			fprintf(output,"Failed to open [%s]\n",MAKE_TEMP_FILE);
			return -1;
		}
	}
	state = PARSE_DEPENDENCIES;

	while ( fgets ( read_buf, READ_BUF_SIZE, conf ) != NULL ) {
		p = read_buf;
		if (*p=='\n') {
			if (state == PARSE_COMPILE_DEFS && defs==1)
				state=PARSE_PREFIX;
			continue;
		}

		switch ((unsigned char)state) {
			case PARSE_DEPENDENCIES:
				if (*p == '#') {
					if (parse_dep_line(p,find_menu(CONF_EXCLUDED_MODS,main_menu)) < 0) {
						fprintf(output,"Failed to parse dep line [%s]\n",p);
					}
				} else if (*p == 'e') {
					state = PARSE_INCLUDE_MODULES;
				}
				break;
			case PARSE_INCLUDE_MODULES:
				if (parse_include_line(p,find_menu(CONF_EXCLUDED_MODS,main_menu)) < 0) {
					fprintf(output,"Failed to parse include line [%s]\n",p);
				}
				state = PARSE_COMPILE_DEFS;
				break;
			case PARSE_COMPILE_DEFS:
				if (parse_defs_line(p,find_menu(CONF_COMPILE_FLAGS,main_menu),&group_idx,&start_grp) < 0) {
					fprintf(output,"Failed to parse compile defs [%s]\n",p);
				}
				defs=1;
				break;
			case PARSE_PREFIX:
				if (parse_prefix_line(p,find_menu(CONF_INSTALL_PREFIX,main_menu)) < 0) {
					fprintf(output,"Failed to parse prefix line [%s]\n",p);
				}
				break;
		}
	}

	fclose(conf);
	return 0;
}

