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
#include "common.h"

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
			    "(without .so) and run 'make generate-mem-stats'\n", mod_name);
		return -1;
	}

	*var = mem_free_idx;
	LM_INFO("changed module variable %s = %d\n", buff, *var);

	return 0;
}

inline void update_module_stats(long mem_used, long real_used, int frags, int group_idx){
#ifdef SHM_SHOW_DEFAULT_GROUP
	if(!memory_mods_stats)
		return;
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

int alloc_group_stat(void) {
	int size_prealoc, j, one_full_entry, groups;
	char *start;
	struct module_info* new_stats_vec;
#ifndef SHM_SHOW_DEFAULT_GROUP
	groups = mem_free_idx - 1;
#else
	groups = mem_free_idx;
#endif

	one_full_entry = 3 * (sizeof(stat_var) + sizeof(stat_val));
	size_prealoc = groups * sizeof(struct module_info) + groups * one_full_entry;

#ifndef DBG_QM_MALLOC
	new_stats_vec = MY_MALLOC_UNSAFE(shm_block, size_prealoc);
#else
	new_stats_vec = MY_MALLOC_UNSAFE(shm_block, size_prealoc, __FILE__, __FUNCTION__, __LINE__ );
#endif

	if(!new_stats_vec){
		LM_CRIT("could not alloc shared memory");
		return -1;
	}
	memset( (void*)new_stats_vec, 0, size_prealoc);
	start = (char*)new_stats_vec + groups * sizeof(struct module_info);
	for(j = 0; j < groups; j++){
		new_stats_vec[j].fragments = (stat_var *)(start + j * one_full_entry);
		new_stats_vec[j].memory_used = (stat_var *)(start + j * one_full_entry + sizeof(stat_var));
		new_stats_vec[j].real_used = (stat_var *)(start + j * one_full_entry + 2 * sizeof(stat_var));

		new_stats_vec[j].fragments->u.val = (stat_val*)(start + j * one_full_entry + 3 * sizeof(stat_var));
		new_stats_vec[j].memory_used->u.val = (stat_val*)(start + j * one_full_entry + 3 * sizeof(stat_var) + sizeof(stat_val));
		new_stats_vec[j].real_used->u.val = (stat_val*)(start + j * one_full_entry + 3 * sizeof(stat_var) + 2 * sizeof(stat_val));
	}
#ifndef SHM_SHOW_DEFAULT_GROUP
	if(core_index != 0) {
		update_stat(new_stats_vec[core_index - 1].fragments, 1);
		update_stat(new_stats_vec[core_index - 1].memory_used, size_prealoc);
		update_stat(new_stats_vec[core_index - 1].real_used, size_prealoc + FRAG_OVERHEAD);
	}
#else
	update_stat(new_stats_vec[0].fragments, get_stat_val(memory_mods_stats[0].fragments));
	update_stat(new_stats_vec[0].memory_used, one_full_entry + get_stat_val(memory_mods_stats[0].memory_used));
	update_stat(new_stats_vec[0].real_used, one_full_entry + get_stat_val(memory_mods_stats[0].real_used));
#endif

	if(memory_mods_stats){
	#ifndef DBG_QM_MALLOC
		MY_FREE_UNSAFE(shm_block, (void*)memory_mods_stats);
	#else
		MY_FREE_UNSAFE(shm_block, (void*)memory_mods_stats, __FILE__, __FUNCTION__, __LINE__ );
	#endif
	}
	memory_mods_stats = new_stats_vec;
	return 0;
}