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