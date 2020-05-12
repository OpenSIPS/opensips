/*
 * Copyright (C) 2001-2003 FhG Fokus
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
 */

/*!
 * \file
 * \brief Flag management
 */


#ifndef _FLAGS_H
#define _FLAGS_H

#include <limits.h>

typedef unsigned int flag_t;

#define MAX_FLAG  ((unsigned int)( sizeof(flag_t) * CHAR_BIT - 1 ))
#define PRINT_BUFFER_SIZE         2048
#define NAMED_FLAG_ERROR          33
#define FLAG_DELIM                ' '

#define fix_flag_name(_s, _flag) \
     do { \
		if (!_s && (int)(_flag) > 0) { \
			LM_WARN("Integer flags are now deprecated! " \
			        "Use unique quoted strings!\n"); \
			_s = int2str(_flag, NULL); \
		} \
	 } while (0)

enum flag_type {
	FLAG_TYPE_MSG=0,
	FLAG_TYPE_BRANCH,
	FLAG_LIST_COUNT,
};

struct sip_msg;

struct flag_entry {
	str name;
	int bit;      /* 0 .. 31 */

	struct flag_entry *next;
};

int flag_in_range( flag_t flag );

int setflag( struct sip_msg* msg, flag_t flag );
int resetflag( struct sip_msg* msg, flag_t flag );
int isflagset( struct sip_msg* msg, flag_t flag );
int flag_idx2mask(int *flag);

/**
 * returns a string representation of the named flags set in the bitmask
 *
 * Note: prints data in a static buffer, flags are delimited by FLAG_DELIM
 */
str bitmask_to_flag_list(enum flag_type type, int bitmask);

/**
 * parses a list of named flags and returns the corresponding bitmask
 *
 * Note: flags which are not used at script level and are not instantiated with
 * get_flag_id_by_name will be ignored
 */
int flag_list_to_bitmask(str *flags, enum flag_type type, char delim);

unsigned int fixup_flag(int flag_type, str *flag_name);
int get_flag_id_by_name(int flag_type, char *flag_name, int flag_name_len);

#endif
