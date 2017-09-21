/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
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

static const char base64digits[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const char word64digits[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+.";

#define BAD     ((unsigned char)-1)
static const unsigned char base64val[] = {
BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD,
BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD,
BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD, 62, BAD,BAD,BAD, 63,
52, 53, 54, 55,  56, 57, 58, 59,  60, 61,BAD,BAD, BAD,BAD,BAD,BAD,
BAD,  0,  1,  2,   3,  4,  5,  6,   7,  8,  9, 10,  11, 12, 13, 14,
15, 16, 17, 18,  19, 20, 21, 22,  23, 24, 25,BAD, BAD,BAD,BAD,BAD,
BAD, 26, 27, 28,  29, 30, 31, 32,  33, 34, 35, 36,  37, 38, 39, 40,
41, 42, 43, 44,  45, 46, 47, 48,  49, 50, 51,BAD, BAD,BAD,BAD,BAD,

BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD,
BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD,
BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD,
BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD,
BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD,
BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD,
BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD,
BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD
};
#define DECODE64(c)  (isascii(c) ? base64val[c] : BAD)

static const unsigned char word64val[] = {
BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD,
BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD,
BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD, 62, BAD,BAD, 63,BAD,
52, 53, 54, 55,  56, 57, 58, 59,  60, 61,BAD,BAD, BAD,BAD,BAD,BAD,
BAD,  0,  1,  2,   3,  4,  5,  6,   7,  8,  9, 10,  11, 12, 13, 14,
15, 16, 17, 18,  19, 20, 21, 22,  23, 24, 25,BAD, BAD,BAD,BAD,BAD,
BAD, 26, 27, 28,  29, 30, 31, 32,  33, 34, 35, 36,  37, 38, 39, 40,
41, 42, 43, 44,  45, 46, 47, 48,  49, 50, 51,BAD, BAD,BAD,BAD,BAD,

BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD,
BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD,
BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD,
BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD,
BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD,
BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD,
BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD,
BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD, BAD,BAD,BAD,BAD
};


/* function that encodes to base64
 * output buffer is assumed to have the right length */
void base64encode(unsigned char *out, unsigned char *in, int inlen)
{
	for (; inlen >= 3; inlen -= 3)
	{
		*out++ = base64digits[in[0] >> 2];
		*out++ = base64digits[((in[0] << 4) & 0x30) | (in[1] >> 4)];
		*out++ = base64digits[((in[1] << 2) & 0x3c) | (in[2] >> 6)];
		*out++ = base64digits[in[2] & 0x3f];
		in += 3;
	}

	if (inlen > 0)
	{
		unsigned char fragment;

		*out++ = base64digits[in[0] >> 2];
		fragment = (in[0] << 4) & 0x30;

		if (inlen > 1)
			fragment |= in[1] >> 4;

		*out++ = base64digits[fragment];
		*out++ = (inlen < 2) ? '=' : base64digits[(in[1] << 2) & 0x3c];
		*out++ = '=';

	}
}

/* function that encodes to word64
 * output buffer is assumed to have the right length */
void word64encode(unsigned char *out, unsigned char *in, int inlen)
{
	for (; inlen >= 3; inlen -= 3)
	{
		*out++ = word64digits[in[0] >> 2];
		*out++ = word64digits[((in[0] << 4) & 0x30) | (in[1] >> 4)];
		*out++ = word64digits[((in[1] << 2) & 0x3c) | (in[2] >> 6)];
		*out++ = word64digits[in[2] & 0x3f];
		in += 3;
	}

	if (inlen > 0)
	{
		unsigned char fragment;

		*out++ = word64digits[in[0] >> 2];
		fragment = (in[0] << 4) & 0x30;

		if (inlen > 1)
			fragment |= in[1] >> 4;

		*out++ = word64digits[fragment];
		*out++ = (inlen < 2) ? '-' : word64digits[(in[1] << 2) & 0x3c];
		*out++ = '-';
	}
}

/* function that decodes from base64
 * output buffer is assumed to have the right length */
int base64decode(unsigned char *out, unsigned char *in, int len)
{
	int i=0;
	unsigned char c1,c2,c3,c4;
	int out_len=0;

	while (len > i)
	{
		do
		{
			c1 = base64val[in[i++]];
		} while (i<len && c1 == BAD);

		if (c1 == BAD)
			break;

		do
		{
			c2 = base64val[in[i++]];
		} while (i<len && c2 == BAD);

		if (c2 == BAD)
			break;

		out[out_len++] = (c1 << 2) | ((c2 & 0x30) >> 4);

		do
		{
			c3 = in[i++];
			if (c3 == 61)
				return out_len;

			c3 = base64val[c3];
		} while (i<len && c3 == BAD);

		if (c3 == BAD)
			break;

		out[out_len++] = ((c2 & 0x0f) << 4) | ((c3 & 0x3c) >> 2);

		do
		{
			c4 = in[i++];
			if (c4 == 61)
				return out_len;
			c4 = base64val[c4];
		} while (i<len && c4 == BAD);

		if (c4 == BAD)
			break;

		out[out_len++] = ((c3 & 0x03) << 6) | c4;
	}

	return out_len;
}

/* function that decodes from word64
 * output buffer is assumed to have the right length */
int word64decode(unsigned char *out, unsigned char *in, int len)
{
	int i=0;
	unsigned char c1,c2,c3,c4;
	int out_len=0;

	while (len > i)
	{
		do
		{
			c1 = word64val[in[i++]];
		} while (i<len && c1 == BAD);

		if (c1 == BAD)
			break;

		do
		{
			c2 = word64val[in[i++]];
		} while (i<len && c2 == BAD);

		if (c2 == BAD)
			break;

		out[out_len++] = (c1 << 2) | ((c2 & 0x30) >> 4);

		do
		{
			c3 = in[i++];
			if (c3 == 61)
				return out_len;

			c3 = word64val[c3];
		} while (i<len && c3 == BAD);

		if (c3 == BAD)
			break;

		out[out_len++] = ((c2 & 0x0f) << 4) | ((c3 & 0x3c) >> 2);

		do
		{
			c4 = in[i++];
			if (c4 == 61)
				return out_len;
			c4 = word64val[c4];
		} while (i<len && c4 == BAD);

		if (c4 == BAD)
			break;

		out[out_len++] = ((c3 & 0x03) << 6) | c4;
	}

	return out_len;
}
