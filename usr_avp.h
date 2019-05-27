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
 *
 * TODO (by bogdan)
 * ----------------
 *    1) int_str -> (int,str)
 *    2) avp is double linked list (faster at delete and insert)
 *
 * History:
 * ---------
 *  2004-07-21  created (bogdan)
 *  2004-11-14  global aliases support added (bogdan)
 *  2005-02-14  list with FLAGS USAGE added (bogdan)
 */

#ifndef _SER_URS_AVP_H_
#define _SER_URS_AVP_H_

/*
 *   LIST with the allocated flags, their meaning and owner
 *   [0-7] - internal flags; [8-15] - to be used by script
 *
 *   flag no.    owner            description
 *   -------------------------------------------------------
 *     0        avp_core          avp has a string name
 *     1        avp_core          avp has a string value
 *     2        core              contact avp qvalue change
 *     7        avpops module     avp was loaded from DB
 *
 */


#include "str.h"

typedef union {
	int  n;
	str s;
} int_str;


struct usr_avp {
	int id;
	unsigned short flags;
	struct usr_avp *next;
	void *data;
};

#define AVP_NAME_DELIM	':'

#define AVP_NAME_VALUE_MASK	0x0003
#define AVP_CORE_MASK		0x00ff
#define AVP_SCRIPT_MASK		0xff00
#define avp_core_flags(f)	((f)&0x00ff)
#define avp_script_flags(f)	(((f)<<8)&0xff00)
#define avp_get_script_flags(f)	(((f)&0xff00)>>8)

#define AVP_NAME_STR     (1<<0)
#define AVP_VAL_STR      (1<<1)
#define AVP_VAL_NULL     (1<<2)

#define is_avp_str_name(a)	(a->flags&AVP_NAME_STR)
#define is_avp_str_val(a)	(a->flags&AVP_VAL_STR)

#define GALIAS_CHAR_MARKER  '$'

/* init functions */
int init_global_avps();
int init_extra_avps();

struct usr_avp* new_avp(unsigned short flags, int name, int_str val);
struct usr_avp *clone_avp_list(struct usr_avp *old);

/* add functions */
int add_avp( unsigned short flags, int id, int_str val);
int add_avp_last( unsigned short flags, int id, int_str val);

/* search functions */
struct usr_avp *search_first_avp( unsigned short flags, int id,
									int_str *val,  struct usr_avp *start);
struct usr_avp *search_next_avp( struct usr_avp *avp, int_str *val  );
struct usr_avp *search_index_avp(unsigned short flags,
					int name, int_str *val, unsigned int index);

/* free functions */
void reset_avps( );
void destroy_avp( struct usr_avp *avp);
void destroy_index_avp( unsigned short flags, int name, int index);
int  destroy_avps( unsigned short flags, int name, int all);
void destroy_avp_list( struct usr_avp **list );
void destroy_avp_list_unsafe( struct usr_avp **list );
void destroy_avp_list_bulk( struct usr_avp **list );

/* get func */
void get_avp_val(struct usr_avp *avp, int_str *val );
str* get_avp_name(struct usr_avp *avp);
str* get_avp_name_id(int id);
struct usr_avp** set_avp_list( struct usr_avp **list );
struct usr_avp** get_avp_list( );

/* replace function */
int replace_avp(unsigned short flags, int name, int_str val, int index);

/* global alias functions (manipulation and parsing)*/
int get_avp_id(str *alias);
int parse_avp_spec( str *name, int *avp_name);

#endif

