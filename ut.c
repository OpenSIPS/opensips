/*
 *$Id$
 *
 * - various general purpose functions
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History
 * ------
 * 2006-09-25  created by movind user2uid and group2gid from main.c (bogdan)
 */


#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include "ut.h"

char int2str_buf[INT2STR_MAX_LEN];

/* make a null-termianted copy of the given string (in STR format) into
 * a static local buffer
 * !!IMPORTANT!! sequential calls do overwrite the previous values.
 */
char * NTcopy_str( str *s )
{
	static char *p=NULL;
	static unsigned int len = 0;

	if (p!=NULL) {
		if ( len < s->len+1 ) {
			p = pkg_realloc( p , s->len+1 );
			if (p==NULL) {
				LM_ERR("no more pkg mem (%d)\n", s->len+1);
				return NULL;
			}
			len = s->len+1;
		}
	} else {
		p = pkg_malloc(s->len+1);
		if (p==NULL) {
			LM_ERR("no more pkg mem (%d)\n", s->len+1);
			return NULL;
		}
		len = s->len+1;
	}

	memcpy( p , s->s, s->len);
	p[s->len] = 0;

	return p;
}


/* converts a username into uid:gid,
 * returns -1 on error & 0 on success */
int user2uid(int* uid, int* gid, char* user)
{
	char* tmp;
	struct passwd *pw_entry;
	
	if (user){
		*uid=strtol(user, &tmp, 10);
		if ((tmp==0) ||(*tmp)){
			/* maybe it's a string */
			pw_entry=getpwnam(user);
			if (pw_entry==0){
				goto error;
			}
			*uid=pw_entry->pw_uid;
			if (gid) *gid=pw_entry->pw_gid;
		}
		return 0;
	}
error:
	return -1;
}


int group2gid(int* gid, char* group)
{
	char* tmp;
	struct group  *gr_entry;
	
	if (group){
		*gid=strtol(group, &tmp, 10);
		if ((tmp==0) ||(*tmp)){
			/* maybe it's a string */
			gr_entry=getgrnam(group);
			if (gr_entry==0){
				goto error;
			}
			*gid=gr_entry->gr_gid;
		}
		return 0;
	}
error:
	return -1;
}

/* utility function to give each children a unique seed */
void seed_child(unsigned int seed)
{
	srand(seed);
}


int parse_reply_codes( str *options_reply_codes_str,
							int **options_reply_codes, int *options_codes_no)
{
	str code_str;
	unsigned int code;
	int index= 0;
	char* sep1, *sep2, *aux;

	*options_reply_codes = (int*)pkg_malloc(
			options_reply_codes_str->len/3 * sizeof(int));

	if(*options_reply_codes== NULL) {
		LM_ERR("no more memory\n");
		return -1;
	}

	sep1 = options_reply_codes_str->s;
	sep2 = strchr(options_reply_codes_str->s, ',');

	while(sep2 != NULL) {

		aux = sep2;
		while(*sep1 == ' ')
			sep1++;
		
		sep2--;
		while(*sep2 == ' ')
			sep2--;

		code_str.s = sep1;
		code_str.len = sep2-sep1+1;

		if(str2int(&code_str, &code)< 0) {
			LM_ERR("Bad format - not am integer [%.*s]\n", 
					code_str.len, code_str.s);
			return -1;
		}
		if(code<100 ||code > 700) {
			LM_ERR("Wrong number [%d]- must be a valid SIP reply code\n",code);
			return -1;
		}
		(*options_reply_codes)[index] = code;
		index++;
	
		sep1 = aux +1;
		sep2 = strchr(sep1, ',');
	}

	while(*sep1 == ' ')
		sep1++;
	sep2 = options_reply_codes_str->s+options_reply_codes_str->len -1;
	while(*sep2 == ' ')
		sep2--;

	code_str.s = sep1;
	code_str.len = sep2 -sep1 +1;
	if(str2int(&code_str, &code)< 0) {
		LM_ERR("Bad format - not am integer [%.*s]\n",
				code_str.len, code_str.s);
		return -1;
	}
	if(code<100 ||code > 700) {
		LM_ERR("Wrong number [%d]- must be a valid SIP reply code\n", code);
		return -1;
	}
	(*options_reply_codes)[index] = code;
	index++;

	*options_codes_no = index;

	return 0;
}










