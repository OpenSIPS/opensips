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

#ifndef _MODULE_INFO__
#define _MODULE_INFO__

#include "../statistics.h"

#define STAT_SUFIX "_mem_stat"
#define STAT_PREFIX "shmem_group_"
#define STAT_PREFIX_LEN 12

extern struct multi_str* mod_names;
extern unsigned int mem_free_idx;
extern void* main_handle;
extern volatile struct module_info* memory_mods_stats;
extern int core_index;

struct module_info{
	stat_var* fragments;
	stat_var* memory_used;
	stat_var* real_used;
};

struct multi_str{
	char *s;
	struct multi_str* next;
};

int set_mem_idx(char* mod_name, int  mem_free_idx);

void update_module_stats(long mem_used, long real_used, int frags, int group_idx);
#endif