/*
 * Copyright (C) 2015-2016 OpenSIPS Solutions
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
 * --------
 *  2015-10-01 initial version (Ionel Cerghit)
 */

#include <dlfcn.h>
#include <string.h>

#include "module_info.h"
#include "../dprint.h"
#include "shm_mem.h"

char buff[60];


unsigned int mem_free_idx = 1;
struct multi_str* mod_names = NULL;
void* main_handle = NULL;
volatile struct module_info* memory_mods_stats = NULL;
int core_index;

int set_mem_idx(char* mod_name, int  mem_free_idx){

	int *var;
	if(!main_handle){
		main_handle = dlopen(NULL, RTLD_LAZY);
		if(!main_handle){
			LM_CRIT("could not load main binary handle\n");
			return -1;
		}
	}

	if(strlen(mod_name) == 4 && (strncmp("core", mod_name, 4) == 0))
		core_index = mem_free_idx;

	strcpy(buff, mod_name);
	strcat(buff, STAT_SUFIX);

	var = (int*) dlsym(main_handle, buff);

	if(!var){
		LM_CRIT("The module %s was not found, be sure it is the same as the NAME variable from the module's Makefile"
			    "(without .so) and run 'make generate-mem-stat'\n", mod_name);
		return -1;
	}

	*var = mem_free_idx;
	LM_INFO("changed module variable %s = %d\n", buff, *var);

	return 0;
}

inline void update_module_stats(long mem_used, long real_used, int frags, int group_idx){
	if(mem_free_idx == 1)
		return;
#ifdef SHM_SHOW_DEFAULT_GROUP
	update_stat(memory_mods_stats[group_idx].fragments, frags);
	update_stat(memory_mods_stats[group_idx].memory_used, mem_used);
	update_stat(memory_mods_stats[group_idx].real_used, real_used);
#else
	if(group_idx == 0)
		return;
	update_stat(memory_mods_stats[group_idx - 1].fragments, frags);
	update_stat(memory_mods_stats[group_idx - 1].memory_used, mem_used);
	update_stat(memory_mods_stats[group_idx - 1].real_used, real_used);
#endif
}