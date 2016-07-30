/*
 * Copyright (C) 2007 voice-system.ro
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
 */

/*! \file
 * \brief Support for transformations
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>

#include "dprint.h"
#include "mem/mem.h"
#include "ut.h"
#include "trim.h"
#include "dset.h"
#include "usr_avp.h"
#include "errinfo.h"
#include "resolve.h"
#include "ip_addr.h"

#include "parser/parse_param.h"
#include "parser/parse_uri.h"
#include "parser/parse_via.h"
#include "parser/parse_to.h"
#include "parser/sdp/sdp_helpr_funcs.h"

#include "strcommon.h"
#include "transformations.h"
#include "re.h"

#define TR_BUFFER_SIZE 65536

/* structure for CSV transformation */

typedef struct csv {
	str body;
	struct csv* next;
} csv_t;

static char _tr_buffer[TR_BUFFER_SIZE];

int run_transformations(struct sip_msg *msg, trans_t *tr, pv_value_t *val)
{
	trans_t *it;
	int ret = 0;

	if(tr==NULL || val==NULL){

		LM_DBG("null pointer\n");
		return -1;
	}

	it = tr;
	while(it)
	{
		ret = (*it->trf)(msg, it->params, it->subtype, val);
		if(ret!=0)
			return ret;
		it = it->next;
	}
	return 0;
}

static void trans_fill_left(pv_value_t *val, str pad, int len)
{
	char *p;
	int r;

	/* fill with a single char */
	if (pad.len == 1) {
		memset(_tr_buffer, pad.s[0], len);
		memcpy(_tr_buffer + len, val->rs.s, val->rs.len);

		val->flags = PV_VAL_STR;
		val->rs.s = _tr_buffer;
		val->rs.len += len;

	/* fill with a string */
	} else {
		p = _tr_buffer;
		r = len % pad.len;
		/* handle the first non-even pad */
		if (r != 0) {
			memcpy(p, pad.s + (pad.len - r), r);
			p += r;
			len -= r;
			val->rs.len += r;
		}

		/* save initial string len */
		r = val->rs.len;

		while (len > 0) {
			memcpy(p, pad.s, pad.len);
			p += pad.len;
			val->rs.len += pad.len;
			len -= pad.len;
		}

		memcpy(p + len, val->rs.s, r);

		val->flags = PV_VAL_STR;
		val->rs.s = _tr_buffer;
	}
}

static void trans_fill_right(pv_value_t *val, str pad, int len)
{
	char *p;
	int r;

	memcpy(_tr_buffer, val->rs.s, val->rs.len);

	/* fill with a single char */
	if (pad.len == 1) {
		memset(_tr_buffer + val->rs.len, pad.s[0], len);

		val->flags = PV_VAL_STR;
		val->rs.s = _tr_buffer;
		val->rs.len += len;

	/* fill with a string */
	} else {
		p = _tr_buffer + val->rs.len;

		while (len > 0) {
			r = len < pad.len ? len : pad.len;
			memcpy(p, pad.s, r);
			p += r;
			val->rs.len += r;
			len -= pad.len;
		}

		val->flags = PV_VAL_STR;
		val->rs.s = _tr_buffer;
	}
}

int tr_eval_string(struct sip_msg *msg, tr_param_t *tp, int subtype,
		pv_value_t *val)
{
	int i, j;
	char *p, *s;
	str st;
	pv_value_t v;

	if(val==NULL || val->flags&PV_VAL_NULL)
		return -1;

	switch(subtype)
	{
		case TR_S_LEN:
			if(!(val->flags&PV_VAL_STR))
				val->rs.s = int2str(val->ri, &val->rs.len);

			val->flags = PV_TYPE_INT|PV_VAL_INT|PV_VAL_STR;
			val->ri = val->rs.len;
			val->rs.s = int2str(val->ri, &val->rs.len);
			break;
		case TR_S_INT:
			if(!(val->flags&PV_VAL_INT))
			{
				//Default conversion to 0
				val->ri = 0;
				/*Ignore the return value of str2sint.
				  str2sint will convert the string up until it finds a non-number char
				  which is the desired behavior for the script level transformation*/
				str2sint(&val->rs, &val->ri);
			} else {
				if(!(val->flags&PV_VAL_STR))
					val->rs.s = int2str(val->ri, &val->rs.len);
			}

			val->flags = PV_TYPE_INT|PV_VAL_INT|PV_VAL_STR;
			break;
		case TR_S_MD5:
			if(!(val->flags&PV_VAL_STR))
				val->rs.s = int2str(val->ri, &val->rs.len);

			compute_md5(_tr_buffer, val->rs.s, val->rs.len);
			_tr_buffer[MD5_LEN] = '\0';
			val->flags = PV_VAL_STR;
			val->ri = 0;
			val->rs.s = _tr_buffer;
			val->rs.len = MD5_LEN;
			break;
		case TR_S_CRC32:
			if(!(val->flags&PV_VAL_STR))
				val->rs.s = int2str(val->ri, &val->rs.len);
			unsigned int crc_val;
			int length = 10;
			crc32_uint(&val->rs,&crc_val);
			val->rs.len = length;
			val->rs.s = int2str(crc_val,&length);
			val->flags = PV_VAL_STR;
			break;
		case TR_S_ENCODEHEXA:
			if(!(val->flags&PV_VAL_STR))
				val->rs.s = int2str(val->ri, &val->rs.len);
			if(val->rs.len>TR_BUFFER_SIZE/2-1)
				return -1;
			j = 0;
			for(i=0; i<val->rs.len; i++)
			{
				_tr_buffer[j++] = fourbits2char[(unsigned char)val->rs.s[i] >> 4];
				_tr_buffer[j++] = fourbits2char[(unsigned char)val->rs.s[i] & 0xf];
			}
			_tr_buffer[j] = '\0';
			memset(val, 0, sizeof(pv_value_t));
			val->flags = PV_VAL_STR;
			val->rs.s = _tr_buffer;
			val->rs.len = j;
			break;
		case TR_S_DECODEHEXA:
			if(!(val->flags&PV_VAL_STR))
				val->rs.s = int2str(val->ri, &val->rs.len);
			if(val->rs.len>TR_BUFFER_SIZE*2-1)
				return -1;
			for(i=0; i<val->rs.len/2; i++)
			{
				if(val->rs.s[2*i]>='0'&&val->rs.s[2*i]<='9')
					_tr_buffer[i] = (val->rs.s[2*i]-'0') << 4;
				else if(val->rs.s[2*i]>='a'&&val->rs.s[2*i]<='f')
					_tr_buffer[i] = (val->rs.s[2*i]-'a'+10) << 4;
				else if(val->rs.s[2*i]>='A'&&val->rs.s[2*i]<='F')
					_tr_buffer[i] = (val->rs.s[2*i]-'A'+10) << 4;
				else return -1;

				if(val->rs.s[2*i+1]>='0'&&val->rs.s[2*i+1]<='9')
					_tr_buffer[i] += val->rs.s[2*i+1]-'0';
				else if(val->rs.s[2*i+1]>='a'&&val->rs.s[2*i+1]<='f')
					_tr_buffer[i] += val->rs.s[2*i+1]-'a'+10;
				else if(val->rs.s[2*i+1]>='A'&&val->rs.s[2*i+1]<='F')
					_tr_buffer[i] += val->rs.s[2*i+1]-'A'+10;
				else return -1;
			}
			_tr_buffer[i] = '\0';
			memset(val, 0, sizeof(pv_value_t));
			val->flags = PV_VAL_STR;
			val->rs.s = _tr_buffer;
			val->rs.len = i;
			break;
		case TR_S_HEX2DEC:
			if(val->flags&PV_VAL_INT)
				break; /* already converted */
			s = NULL;
			if (hexstr2int(val->rs.s, val->rs.len, (unsigned int *)&i) < 0)
				return -1;
			val->rs.s = int2str(i, &val->rs.len);
			val->ri = i;
			val->flags = PV_TYPE_INT|PV_VAL_INT|PV_VAL_STR;
			break;
		case TR_S_DEC2HEX:
			if(!(val->flags&PV_VAL_INT))
			{
				if(str2sint(&val->rs, &val->ri)!=0)
					return -1;
			}
			val->rs.len = snprintf(_tr_buffer, TR_BUFFER_SIZE, "%x", val->ri);
			if (val->rs.len < 0 || val->rs.len > TR_BUFFER_SIZE)
				return -1;
			val->ri = 0;
			val->rs.s = _tr_buffer;
			val->flags = PV_VAL_STR;
			break;
		case TR_S_ESCAPECOMMON:
			if(!(val->flags&PV_VAL_STR))
				val->rs.s = int2str(val->ri, &val->rs.len);
			if(val->rs.len>TR_BUFFER_SIZE/2-1)
				return -1;
			i = escape_common(_tr_buffer, val->rs.s, val->rs.len);
			_tr_buffer[i] = '\0';
			memset(val, 0, sizeof(pv_value_t));
			val->flags = PV_VAL_STR;
			val->rs.s = _tr_buffer;
			val->rs.len = i;
			break;
		case TR_S_UNESCAPECOMMON:
			if(!(val->flags&PV_VAL_STR))
				val->rs.s = int2str(val->ri, &val->rs.len);
			if(val->rs.len>TR_BUFFER_SIZE-1)
				return -1;
			i = unescape_common(_tr_buffer, val->rs.s, val->rs.len);
			_tr_buffer[i] = '\0';
			memset(val, 0, sizeof(pv_value_t));
			val->flags = PV_VAL_STR;
			val->rs.s = _tr_buffer;
			val->rs.len = i;
			break;
		case TR_S_ESCAPEUSER:
			if(!(val->flags&PV_VAL_STR))
				val->rs.s = int2str(val->ri, &val->rs.len);
			if(val->rs.len>TR_BUFFER_SIZE/2-1)
				return -1;
			st.s = _tr_buffer;
			st.len = TR_BUFFER_SIZE;
			if (escape_user(&val->rs, &st))
				return -1;
			memset(val, 0, sizeof(pv_value_t));
			val->flags = PV_VAL_STR;
			val->rs = st;
			break;
		case TR_S_UNESCAPEUSER:
			if(!(val->flags&PV_VAL_STR))
				val->rs.s = int2str(val->ri, &val->rs.len);
			if(val->rs.len>TR_BUFFER_SIZE-1)
				return -1;
			st.s = _tr_buffer;
			st.len = TR_BUFFER_SIZE;
			if (unescape_user(&val->rs, &st))
				return -1;
			memset(val, 0, sizeof(pv_value_t));
			val->flags = PV_VAL_STR;
			val->rs = st;
			break;
		case TR_S_ESCAPEPARAM:
			if(!(val->flags&PV_VAL_STR))
				val->rs.s = int2str(val->ri, &val->rs.len);
			if(val->rs.len>TR_BUFFER_SIZE/2-1)
				return -1;
			st.s = _tr_buffer;
			st.len = TR_BUFFER_SIZE;
			if (escape_param(&val->rs, &st) < 0)
				return -1;
			memset(val, 0, sizeof(pv_value_t));
			val->flags = PV_VAL_STR;
			val->rs = st;
			break;
		case TR_S_UNESCAPEPARAM:
			if(!(val->flags&PV_VAL_STR))
				val->rs.s = int2str(val->ri, &val->rs.len);
			if(val->rs.len>TR_BUFFER_SIZE-1)
				return -1;
			st.s = _tr_buffer;
			st.len = TR_BUFFER_SIZE;
			if (unescape_param(&val->rs, &st) < 0)
				return -1;
			memset(val, 0, sizeof(pv_value_t));
			val->flags = PV_VAL_STR;
			val->rs = st;
			break;
		case TR_S_SUBSTR:
			if(tp==NULL || tp->next==NULL)
			{
				LM_ERR("substr invalid parameters\n");
				return -1;
			}
			if(!(val->flags&PV_VAL_STR))
				val->rs.s = int2str(val->ri, &val->rs.len);
			if(tp->type==TR_PARAM_NUMBER)
			{
				i = tp->v.n;
			} else {
				if(pv_get_spec_value(msg, (pv_spec_p)tp->v.data, &v)!=0
						|| (!(v.flags&PV_VAL_INT)))
				{
					LM_ERR("substr cannot get p1\n");
					return -1;
				}
				i = v.ri;
			}
			if(tp->next->type==TR_PARAM_NUMBER)
			{
				j = tp->next->v.n;
			} else {
				if(pv_get_spec_value(msg, (pv_spec_p)tp->next->v.data, &v)!=0
						|| (!(v.flags&PV_VAL_INT)))
				{
					LM_ERR("substr cannot get p2\n");
					return -1;
				}
				j = v.ri;
			}
			LM_DBG("i=%d j=%d\n", i, j);
			if(j<0)
			{
				LM_ERR("substr negative offset\n");
				return -1;
			}
			val->flags = PV_VAL_STR;
			val->ri = 0;
			if(i>=0)
			{
				if(i>=val->rs.len)
				{
					LM_ERR("substr out of range\n");
					return -1;
				}
				if(i+j>=val->rs.len) j=0;
				if(j==0)
				{ /* to end */
					val->rs.s += i;
					val->rs.len -= i;
					break;
				}
				val->rs.s += i;
				val->rs.len = j;
				break;
			}
			i = -i;
			if(i>val->rs.len)
			{
				LM_ERR("substr out of range\n");
				return -1;
			}
			if(i<j) j=0;
			if(j==0)
			{ /* to end */
				val->rs.s += val->rs.len-i;
				val->rs.len = i;
				break;
			}
			val->rs.s += val->rs.len-i;
			val->rs.len = j;
			break;

		case TR_S_SELECT:
			if(tp==NULL || tp->next==NULL)
			{
				LM_ERR("select invalid parameters\n");
				return -1;
			}
			if(!(val->flags&PV_VAL_STR))
				val->rs.s = int2str(val->ri, &val->rs.len);
			if(tp->type==TR_PARAM_NUMBER)
			{
				i = tp->v.n;
			} else {
				if(pv_get_spec_value(msg, (pv_spec_p)tp->v.data, &v)!=0
						|| (!(v.flags&PV_VAL_INT)))
				{
					LM_ERR("select cannot get p1\n");
					return -1;
				}
				i = v.ri;
			}
			val->flags = PV_VAL_STR;
			val->ri = 0;
			if(i<0)
			{
				s = val->rs.s+val->rs.len-1;
				p = s;
				i = -i;
				i--;
				while(p>=val->rs.s)
				{
					if(*p==tp->next->v.s.s[0])
					{
						if(i==0)
							break;
						s = p-1;
						i--;
					}
					p--;
				}
				if(i==0)
				{
					val->rs.s = p+1;
					val->rs.len = s-p;
				} else {
					val->rs.s = "";
					val->rs.len = 0;
				}
			} else {
				s = val->rs.s;
				p = s;
				while(p<val->rs.s+val->rs.len)
				{
					if(*p==tp->next->v.s.s[0])
					{
						if(i==0)
							break;
						s = p + 1;
						i--;
					}
					p++;
				}
				if(i==0)
				{
					val->rs.s = s;
					val->rs.len = p-s;
				} else {
					val->rs.s = "";
					val->rs.len = 0;
				}
			}
			break;

		case TR_S_TOLOWER:
			if(!(val->flags&PV_VAL_STR))
			{
				val->rs.s = int2str(val->ri, &val->rs.len);
				val->flags |= PV_VAL_STR;
				break;
			}
			if(val->rs.len>TR_BUFFER_SIZE-1)
				return -1;
			st.s = _tr_buffer;
			st.len = val->rs.len;
			for (i=0; i<st.len; i++)
				st.s[i]=(val->rs.s[i]>='A' && val->rs.s[i]<='Z')
							?('a' + val->rs.s[i] -'A'):val->rs.s[i];
			memset(val, 0, sizeof(pv_value_t));
			val->flags = PV_VAL_STR;
			val->rs = st;
			break;

		case TR_S_TOUPPER:
			if(!(val->flags&PV_VAL_STR))
			{
				val->rs.s = int2str(val->ri, &val->rs.len);
				val->flags |= PV_VAL_STR;
				break;
			}
			if(val->rs.len>TR_BUFFER_SIZE-1)
				return -1;
			st.s = _tr_buffer;
			st.len = val->rs.len;
			for (i=0; i<st.len; i++)
				st.s[i]=(val->rs.s[i]>='a' && val->rs.s[i]<='z')
							?('A' + val->rs.s[i] -'a'):val->rs.s[i];
			memset(val, 0, sizeof(pv_value_t));
			val->flags = PV_VAL_STR;
			val->rs = st;
			break;
		case TR_S_INDEX:
		case TR_S_RINDEX:
			/* Ensure it is in string format */
			if(!(val->flags&PV_VAL_STR))
			{
				val->rs.s = int2str(val->ri, &val->rs.len);
				val->flags |= PV_VAL_STR;
			}

			/* Needle to look for in haystack */
			if(tp->type==TR_PARAM_STRING)
			{
				st = tp->v.s;
			} else {
				if(pv_get_spec_value(msg, (pv_spec_p)tp->v.data, &v)!=0
                                                || (!(v.flags&PV_VAL_STR)) || v.rs.len<=0)
				{
					LM_ERR("index/rindex cannot get p1\n");
					return -1;
				}

				st = v.rs;
			}

			/* User supplied starting position */
			if (tp->next != NULL) {
				if(tp->next->type==TR_PARAM_NUMBER)
				{
					i = tp->next->v.n;
				} else {
					if(pv_get_spec_value(msg, (pv_spec_p)tp->next->v.data, &v)!=0
							|| (!(v.flags&PV_VAL_INT)))
					{
						LM_ERR("index/rindex cannot get p2\n");
						return -1;
					}
					i = v.ri;
				}
			} else {
				/* Default start positions: 0 for index, end of str for rindex */
				i = (subtype == TR_S_INDEX ? 0 : (val->rs.len - 1));
			}

			/* If start is negative base it off end of string
			   e.g -2 on 10 char str start of 8. */
			if (i < 0 ){
				if ( val->rs.len > 0 ) {
					/* Support wrapping on negative index
					   e.g -2 and -12 index are same on strlen of 10 */
					i = ( (i * -1) % val->rs.len );
					/* No remainder means we start at 0
					   otherwise take remainder off the end */
					if ( i > 0) {
						i = (val->rs.len - i);
					}
				} else {
					/* Case of searching through an empty string is caught later */
					i = 0;
				}
			}

			/* Index */
			if (subtype == TR_S_INDEX) {
				/* If start index is beyond end of string or
				   Needle is bigger than haystack return -1 */
				if ( i >= val->rs.len || st.len > (val->rs.len - i)) {
					memset(val, 0, sizeof(pv_value_t));
					val->flags = PV_TYPE_INT|PV_VAL_INT|PV_VAL_STR;
					val->ri = -1;
					val->rs.s = int2str(val->ri, &val->rs.len);
					break;
				}

				/* Iterate through string starting at index
				   After j there are no longer enough characters left to match the needle */
				j = (val->rs.len - st.len);
				while (i <= j) {
					if (val->rs.s[i] == st.s[0]) {
						/* First character matches, do a full comparison
						   shortcut for single character lookups */
						if (st.len == 1 || strncmp(val->rs.s + i, st.s, st.len) == 0) {
							/* Bingo, found it */
							memset(val, 0, sizeof(pv_value_t));
							val->flags = PV_TYPE_INT|PV_VAL_INT|PV_VAL_STR;
							val->ri = i;
							val->rs.s = int2str(val->ri, &val->rs.len);
							return 0;
						}
					}
					i++;
				}
			/* Rindex */
			} else {
				/* Needle bigger than haystack */
				if ( st.len > val->rs.len ) {
					memset(val, 0, sizeof(pv_value_t));
					val->flags = PV_TYPE_INT|PV_VAL_INT|PV_VAL_STR;
					val->ri = -1;
					val->rs.s = int2str(val->ri, &val->rs.len);
					break;
				}

				/* Incase of RINDEX clamp index to end of string */
				if (i >= val->rs.len) {
					i = (val->rs.len - 1);
				}

				/* Start position does not leave enough characters to match needle, jump ahead */
				if ( st.len > (val->rs.len - i) ) {
					/* Minimum start position allowing for matches */
					i = (val->rs.len - st.len);
				}

				/* Iterate through string starting at index and going backwards */
				while (i >= 0) {
					if (val->rs.s[i] == st.s[0]) {
						/* First character matches, do a full comparison
						   shortcut for single character lookups */
						if (st.len == 1 || strncmp(val->rs.s + i, st.s, st.len) == 0) {
							/* Bingo, found it */
							memset(val, 0, sizeof(pv_value_t));
							val->flags = PV_TYPE_INT|PV_VAL_INT|PV_VAL_STR;
							val->ri = i;
							val->rs.s = int2str(val->ri, &val->rs.len);
							return 0;
						}
					}
					i--;
				}

			}

			/* Not found */
			memset(val, 0, sizeof(pv_value_t));
			val->flags = PV_TYPE_INT|PV_VAL_INT|PV_VAL_STR;
			val->ri = -1;
			val->rs.s = int2str(val->ri, &val->rs.len);
			break;
		case TR_S_FILL_LEFT:
		case TR_S_FILL_RIGHT:

			/* padding string parameter */
			st = tp->v.s;

			/* padded final length parameter */
			i = tp->next->v.n;

			if (val->flags & PV_VAL_STR)
			{
				i -= val->rs.len;
			} else if (val->flags & PV_VAL_INT)
			{
				val->rs.s = int2str(val->ri, &val->rs.len);
				i -= val->rs.len;
			}

			/* no need for padding */
			if (i < 0)
				return 0;

			if (subtype == TR_S_FILL_LEFT)
				trans_fill_left(val, st, i);
			else
				trans_fill_right(val, st, i);

			break;
		case TR_S_WIDTH:
			if(tp==NULL || tp->next!=NULL)
			{
				LM_ERR("width invalid parameters\n");
				return -1;
			}
			if(!(val->flags&PV_VAL_STR))
				val->rs.s = int2str(val->ri, &val->rs.len);
			if(tp->type==TR_PARAM_NUMBER)
			{
				i = tp->v.n;
			} else {
				if(pv_get_spec_value(msg, (pv_spec_p)tp->v.data, &v)!=0
						|| (!(v.flags&PV_VAL_INT)))
				{
					LM_ERR("substr cannot get p1\n");
					return -1;
				}
				i = v.ri;
			}
			if (i <= 0) {
				LM_ERR("width invalid (must be >= 1)\n");
				return -1;
			}
			if (i <= val->rs.len) {
				/* since the requested width is less than
				   the value length, just update the length */
				val->rs.len = i;
				break;
			}

			if(i>TR_BUFFER_SIZE-1)
				/* width cant be greater than buffer */
				return -1;

			j = i - val->rs.len; /* calc extra length */
			p = _tr_buffer;

			/* copy existing string to buffer and append j spaces */
			memcpy(p, val->rs.s, val->rs.len);
			memset(p+val->rs.len, ' ', j);
			memset(val, 0, sizeof(pv_value_t));

			val->flags = PV_VAL_STR;
			val->rs.s = _tr_buffer;
			val->rs.len = i;
			break;
		case TR_S_B64ENCODE:
			if(!(val->flags&PV_VAL_STR))
			{
				val->rs.s = int2str(val->ri, &val->rs.len);
				val->flags |= PV_VAL_STR;
				break;
			}
			if(val->rs.len>TR_BUFFER_SIZE-1) {
				LM_ERR("b64encode value larger than buffer\n");
				return -1;
			}
			st.s = _tr_buffer;
			st.len = calc_base64_encode_len(val->rs.len);

			base64encode((unsigned char *)st.s,
				     (unsigned char *)val->rs.s,
				     val->rs.len);

			memset(val, 0, sizeof(pv_value_t));
			val->flags = PV_VAL_STR;
			val->rs = st;
			break;
		case TR_S_B64DECODE:
			if(!(val->flags&PV_VAL_STR))
			{
				val->rs.s = int2str(val->ri, &val->rs.len);
				val->flags |= PV_VAL_STR;
				break;
			}
			if(val->rs.len>TR_BUFFER_SIZE-1) {
				LM_ERR("b64decode value larger than buffer\n");
				return -1;
			}
                        st.s = _tr_buffer;
                        st.len = base64decode((unsigned char *)st.s, 
                                              (unsigned char *)val->rs.s,
                                              val->rs.len);
                        memset(val, 0, sizeof(pv_value_t));
                        val->flags = PV_VAL_STR;
                        val->rs = st;
                        break;
		case TR_S_XOR:
			/* ensure string format */
			if(!(val->flags&PV_VAL_STR))
			{
				val->rs.s = int2str(val->ri, &val->rs.len);
				val->flags |= PV_VAL_STR;
			}
			if(val->rs.len>TR_BUFFER_SIZE-1) {
				LM_ERR("xor value larger than buffer\n");
				return -1;
			}
			/* secret to use */
			if(tp->type==TR_PARAM_STRING)
			{
				st = tp->v.s;
			} else {
				if(pv_get_spec_value(msg, (pv_spec_p)tp->v.data, &v)!=0
                                                || (!(v.flags&PV_VAL_STR)) || v.rs.len<=0)
				{
					LM_ERR("xor cannot get p1\n");
					return -1;
				}
				st = v.rs;
			}
			
			p = _tr_buffer;
			for (i=0; i<val->rs.len; i++) {
				*p = val->rs.s[i] ^ st.s[i % st.len];
				p++;
			}
			/* leave val flags and length in tact and update with result */
                        val->rs.s = _tr_buffer;
			break;
		case TR_S_TRIM:
			if (!(val->flags & PV_VAL_STR))
			{
				val->rs.s = int2str(val->ri, &val->rs.len);
				val->flags |= PV_VAL_STR;
			}

			trim(&val->rs);
			break;
		case TR_S_TRIMR:
			if (!(val->flags & PV_VAL_STR))
			{
				val->rs.s = int2str(val->ri, &val->rs.len);
				val->flags |= PV_VAL_STR;
			}

			trim_trailing(&val->rs);
			break;
		case TR_S_TRIML:
			if (!(val->flags & PV_VAL_STR))
			{
				val->rs.s = int2str(val->ri, &val->rs.len);
				val->flags |= PV_VAL_STR;
			}

			trim_leading(&val->rs);
			break;
		default:
			LM_ERR("unknown subtype %d\n",
					subtype);
			return -1;
	}
	return 0;
}

static str _tr_empty = { "", 0 };
static str _tr_uri = {0, 0};
static struct sip_uri _tr_parsed_uri;
static param_t* _tr_uri_params = NULL;

int tr_eval_uri(struct sip_msg *msg, tr_param_t *tp, int subtype,
		pv_value_t *val)
{
	pv_value_t v;
	str sv;
	param_hooks_t phooks;
	param_t *pit=NULL;

	if(val==NULL || (!(val->flags&PV_VAL_STR)) || val->rs.len<=0)
		return -1;

	if(_tr_uri.len==0 || _tr_uri.len!=val->rs.len ||
			strncmp(_tr_uri.s, val->rs.s, val->rs.len)!=0)
	{
		if(val->rs.len>_tr_uri.len)
		{
			if(_tr_uri.s) pkg_free(_tr_uri.s);
			_tr_uri.s = (char*)pkg_malloc((val->rs.len+1)*sizeof(char));
			if(_tr_uri.s==NULL)
			{
				LM_ERR("no more private memory\n");
				if(_tr_uri_params != NULL)
				{
					free_params(_tr_uri_params);
					_tr_uri_params = 0;
				}
				memset(&_tr_uri, 0, sizeof(str));
				memset(&_tr_parsed_uri, 0, sizeof(struct sip_uri));
				return -1;
			}
		}
		_tr_uri.len = val->rs.len;
		memcpy(_tr_uri.s, val->rs.s, val->rs.len);
		_tr_uri.s[_tr_uri.len] = '\0';
		/* reset old values */
		memset(&_tr_parsed_uri, 0, sizeof(struct sip_uri));
		if(_tr_uri_params != NULL)
		{
			free_params(_tr_uri_params);
			_tr_uri_params = 0;
		}
		/* parse uri -- params only when requested */
		if(parse_uri(_tr_uri.s, _tr_uri.len, &_tr_parsed_uri)!=0)
		{
			LM_ERR("invalid uri [%.*s]\n", val->rs.len,
					val->rs.s);
			if(_tr_uri_params != NULL)
			{
				free_params(_tr_uri_params);
				_tr_uri_params = 0;
			}
			pkg_free(_tr_uri.s);
			memset(&_tr_uri, 0, sizeof(str));
			memset(&_tr_parsed_uri, 0, sizeof(struct sip_uri));
			return -1;
		}
	}
	memset(val, 0, sizeof(pv_value_t));
	val->flags = PV_VAL_STR;

	switch(subtype)
	{
		case TR_URI_USER:
			val->rs = (_tr_parsed_uri.user.s)?_tr_parsed_uri.user:_tr_empty;
			break;
		case TR_URI_HOST:
			val->rs = (_tr_parsed_uri.host.s)?_tr_parsed_uri.host:_tr_empty;
			break;
		case TR_URI_PASSWD:
			val->rs = (_tr_parsed_uri.passwd.s)?_tr_parsed_uri.passwd:_tr_empty;
			break;
		case TR_URI_PORT:
			val->flags |= PV_TYPE_INT|PV_VAL_INT;
			val->rs = (_tr_parsed_uri.port.s)?_tr_parsed_uri.port:_tr_empty;
			val->ri = _tr_parsed_uri.port_no;
			break;
		case TR_URI_PARAMS:
			val->rs = (_tr_parsed_uri.params.s)?_tr_parsed_uri.params:_tr_empty;
			break;
		case TR_URI_PARAM:
			if(tp==NULL)
			{
				LM_ERR("param invalid parameters\n");
				return -1;
			}
			if(_tr_parsed_uri.params.len<=0)
			{
				val->rs = _tr_empty;
				val->flags = PV_VAL_STR;
				val->ri = 0;
				break;
			}

			if(_tr_uri_params == NULL)
			{
				sv = _tr_parsed_uri.params;
				if (parse_params(&sv, CLASS_ANY, &phooks, &_tr_uri_params)<0)
					return -1;
			}
			if(tp->type==TR_PARAM_STRING)
			{
				sv = tp->v.s;
			} else {
				if(pv_get_spec_value(msg, (pv_spec_p)tp->v.data, &v)!=0
						|| (!(v.flags&PV_VAL_STR)) || v.rs.len<=0)
				{
					LM_ERR("param cannot get p1\n");
					return -1;
				}
				sv = v.rs;
			}
			for (pit = _tr_uri_params; pit; pit=pit->next)
			{
				if (pit->name.len==sv.len
						&& strncasecmp(pit->name.s, sv.s, sv.len)==0)
				{
					val->rs = pit->body;
					goto done;
				}
			}
			val->rs = _tr_empty;
			break;
		case TR_URI_HEADERS:
			val->rs = (_tr_parsed_uri.headers.s)?_tr_parsed_uri.headers:
						_tr_empty;
			break;
		case TR_URI_TRANSPORT:
			val->rs = (_tr_parsed_uri.transport_val.s)?
				_tr_parsed_uri.transport_val:_tr_empty;
			break;
		case TR_URI_TTL:
			val->rs = (_tr_parsed_uri.ttl_val.s)?
				_tr_parsed_uri.ttl_val:_tr_empty;
			break;
		case TR_URI_UPARAM:
			val->rs = (_tr_parsed_uri.user_param_val.s)?
				_tr_parsed_uri.user_param_val:_tr_empty;
			break;
		case TR_URI_MADDR:
			val->rs = (_tr_parsed_uri.maddr_val.s)?
				_tr_parsed_uri.maddr_val:_tr_empty;
			break;
		case TR_URI_METHOD:
			val->rs = (_tr_parsed_uri.method_val.s)?
				_tr_parsed_uri.method_val:_tr_empty;
			break;
		case TR_URI_LR:
			val->rs = (_tr_parsed_uri.lr_val.s)?
				_tr_parsed_uri.lr_val:_tr_empty;
			break;
		case TR_URI_R2:
			val->rs = (_tr_parsed_uri.r2_val.s)?
				_tr_parsed_uri.r2_val:_tr_empty;
			break;
		case TR_URI_SCHEMA:
			val->rs.s = _tr_uri.s;
			/* maximum size of schema can be 4 so the ':' shall be found after
			 * five chars */
			val->rs.len = q_memchr(val->rs.s, ':', 5) - val->rs.s;
			break;
		default:
			LM_ERR("unknown subtype %d\n",
					subtype);
			return -1;
	}
done:
	return 0;
}


/* last via string */
static str _tr_via = {0, 0};
/* the actual len of the allocated buffer (to hold the via) */
static int _tr_via_buf_len = 0;
/* holder for the parsed via */
static struct via_body *_tr_parsed_via = 0;

int tr_eval_via(struct sip_msg *msg, tr_param_t *tp, int subtype,
		pv_value_t *val)
{
	pv_value_t v;
	str sv;
	struct via_param *pit;

	// WATCHOUT: need at least 2 chars so \r\n check wont segfault
	if(val==NULL || (!(val->flags&PV_VAL_STR)) || val->rs.len<=2)
		return -1;

	if(_tr_via_buf_len==0 || _tr_via.len!=val->rs.len ||
			strncmp(_tr_via.s, val->rs.s, val->rs.len)!=0
			|| _tr_parsed_via==0)
	{
		if (val->rs.len+4 > _tr_via_buf_len)
		{
			if(_tr_via.s) pkg_free(_tr_via.s);
			_tr_via.s = (char*)pkg_malloc((val->rs.len+4)*sizeof(char));
			if(_tr_via.s==NULL)
			{
				_tr_via_buf_len = 0;
				LM_ERR("no more private memory\n");
				goto error;
			}
			_tr_via_buf_len = val->rs.len+4;
		}
		_tr_via.len = val->rs.len;
		memcpy(_tr_via.s, val->rs.s, val->rs.len);
		// $hdr PV strips off the terminating CRLR
		// parse_via wants to parse a full message (including
		// multiple vias), not just a header line.  Fake this
		_tr_via.s[_tr_via.len+0] = '\r';
		_tr_via.s[_tr_via.len+1] = '\n';
		_tr_via.s[_tr_via.len+2] = 'A';	// anything other than V
		_tr_via.s[_tr_via.len+3] = '\0';
		/* reset old values */
		free_via_list(_tr_parsed_via);
		if ( (_tr_parsed_via=pkg_malloc(sizeof(struct via_body))) == NULL ) {
			LM_ERR("no more private memory\n");
			goto error;
		}
		memset(_tr_parsed_via, 0, sizeof(struct via_body));
		parse_via(_tr_via.s, _tr_via.s+_tr_via.len+4, _tr_parsed_via);
		if(_tr_parsed_via->error != PARSE_OK) {
			LM_ERR("invalid via [%.*s]\n", val->rs.len,
					val->rs.s);
			goto error;
		}
	}
	memset(val, 0, sizeof(pv_value_t));
	val->flags = PV_VAL_STR;

	switch(subtype)
	{
		case TR_VIA_NAME:
			val->rs = (_tr_parsed_via->name.s)?_tr_parsed_via->name:_tr_empty;
			break;
		case TR_VIA_VERSION:
			val->rs = (_tr_parsed_via->version.s)?_tr_parsed_via->version:_tr_empty;
			break;
		case TR_VIA_TRANSPORT:
			val->rs = (_tr_parsed_via->transport.s)?_tr_parsed_via->transport:_tr_empty;
			break;
		case TR_VIA_HOST:
			val->rs = (_tr_parsed_via->host.s)?_tr_parsed_via->host:_tr_empty;
			break;
		case TR_VIA_PORT:
			val->flags |= PV_TYPE_INT|PV_VAL_INT;
			val->rs = (_tr_parsed_via->port_str.s)?_tr_parsed_via->port_str:_tr_empty;
			val->ri = _tr_parsed_via->port;
			break;
		case TR_VIA_PARAMS:
			val->rs = (_tr_parsed_via->params.s)?_tr_parsed_via->params:_tr_empty;
			break;
		case TR_VIA_COMMENT:
			val->rs = (_tr_parsed_via->comment.s)?_tr_parsed_via->comment:_tr_empty;
			break;
		case TR_VIA_PARAM:	// param by name
			if(tp==NULL)
			{
				LM_ERR("param invalid parameters\n");
				return -1;
			}
			if(_tr_parsed_via->params.len<=0)
			{
				val->rs = _tr_empty;
				val->flags = PV_VAL_STR;
				val->ri = 0;
				break;
			}

			if(tp->type==TR_PARAM_STRING)
			{
				sv = tp->v.s;
			} else {
				if(pv_get_spec_value(msg, (pv_spec_p)tp->v.data, &v)!=0
						|| (!(v.flags&PV_VAL_STR)) || v.rs.len<=0)
				{
					LM_ERR("param cannot get p1\n");
					return -1;
				}
				sv = v.rs;
			}
			for (pit = _tr_parsed_via->param_lst; pit; pit=pit->next)
			{
				if (pit->name.len==sv.len
						&& strncasecmp(pit->name.s, sv.s, sv.len)==0)
				{
					val->rs = pit->value;
					goto done;
				}
			}
			val->rs = _tr_empty;
			break;
		case TR_VIA_BRANCH:
			val->rs = (_tr_parsed_via->branch&&_tr_parsed_via->branch->value.s)?_tr_parsed_via->branch->value: _tr_empty;
			break;
		case TR_VIA_RECEIVED:
			val->rs = (_tr_parsed_via->received&&_tr_parsed_via->received->value.s)?_tr_parsed_via->received->value: _tr_empty;
			break;
		case TR_VIA_RPORT:
			val->rs = (_tr_parsed_via->rport&&_tr_parsed_via->rport->value.s)?_tr_parsed_via->rport->value: _tr_empty;
			break;
		default:
			LM_ERR("unknown subtype %d\n",
					subtype);
			return -1;
	}
done:
	return 0;

error:
	if ( _tr_via.s ) {
		pkg_free(_tr_via.s);
	}
	memset(&_tr_via, 0, sizeof(str));
	if ( _tr_parsed_via ) {
	    	free_via_list(_tr_parsed_via);
		_tr_parsed_via = 0;
	}
	return -1;
}

static str _tr_csv_str = {0,0};
static csv_t* _tr_csv_list = NULL;

static int init_csv(csv_t **t,char *s,int len)
{
	*t = (csv_t *)pkg_malloc(sizeof(csv_t));
	if (*t == NULL)
	{
		return -1;
	}

	memset(*t,0,sizeof(csv_t));
	(*t)->body.s = s;
	(*t)->body.len = len;

	return 0;
}

void free_csv_list(csv_t *list)
{
	csv_t *cit;
	for (cit=list;cit;cit=cit->next)
		pkg_free(cit);
}

static int parse_csv(str *s,csv_t **list)
{
	csv_t *t = NULL;
	csv_t *last = NULL;
	char *string,*limit,*aux;
	int len;

	if (!s || !list)
	{
		LM_ERR("Invalid parameter values\n");
		return -1;
	}

	last = NULL;
	*list = 0;

	if (!s->s)
	{
		LM_DBG("empty csv params, skipping\n");
		return 0;
	}

	LM_DBG("Parsing csv for : [%.*s]\n",s->len,s->s);

	string = s->s;
	limit = string+s->len;

	while (*string)
	{
		t = NULL;
		/* quoted token */
		if (*string == '\"')
		{
			aux = string+1;
search:
			/* find coresponding quote */
			while (*aux != '\"') aux++;
			if ( *(aux+1) != '\"')
			{
				/* end of current token, also skip the following comma */
				len = aux-string+1;
				if (init_csv(&t,string,len) < 0)
				{
					LM_ERR("no more memory");
					goto error;
				}
				string +=len+1;
				if (string > limit)
				{
					/* again, end of string */
					if (last) { last->next = t;} else {*list = t;}
					return 0;
				}
			}
			else
			{
				/* quoted string inside token */
				aux +=2;
				/* keep searching for final double quote*/
				goto search;
			}
		}
		else
		{
			/* non quoted csv , find comma */
			aux = strchr(string,',');
			if (aux == NULL)
			{
				len = strlen(string);
				if (init_csv(&t,string,len) < 0)
				{
					LM_ERR("no more memory");
					goto error;
				}

				/* should be end of string ! */
				if (last) { last->next = t;} else {*list = t;}
				return 0;
			}
			else
			{
				len = aux - string;
				if (init_csv(&t,string,len) < 0)
				{
					LM_ERR("no more memory");
					goto error;
				}
				string +=len+1;
			}
		}

		if (last) { last->next = t;} else {*list = t;}
		last = t;
	}

	return 0;

error:
	if (t) pkg_free(t);
	free_csv_list(*list);
	*list = NULL;
	return -1;
}


int tr_eval_csv(struct sip_msg *msg, tr_param_t *tp,int subtype,
		pv_value_t *val)
{
	str sv;
	csv_t *cit=NULL;
	int n,i,list_size=0;
	pv_value_t v;

	if(val==NULL || (!(val->flags&PV_VAL_STR)) || val->rs.len<=0)
	{
		return -1;
	}

	if(_tr_csv_str.len==0 || _tr_csv_str.len!=val->rs.len ||
			strncmp(_tr_csv_str.s, val->rs.s, val->rs.len)!=0)
	{
		if(val->rs.len>_tr_csv_str.len)
		{
			if(_tr_csv_str.s) pkg_free(_tr_csv_str.s);
				_tr_csv_str.s = (char*)pkg_malloc((val->rs.len+1));
			if(_tr_csv_str.s==NULL)
			{
				LM_ERR("no more private memory\n");
				memset(&_tr_csv_str, 0, sizeof(str));
				if(_tr_csv_list != NULL)
				{
					free_csv_list(_tr_csv_list);
					_tr_csv_list = 0;
				}
				return -1;
			}
		}
		_tr_csv_str.len = val->rs.len;
		memcpy(_tr_csv_str.s, val->rs.s, val->rs.len);
		_tr_csv_str.s[_tr_csv_str.len] = '\0';

		/* reset old values */
		if(_tr_csv_list != NULL)
		{
			free_csv_list(_tr_csv_list);
			_tr_csv_list = 0;
		}

		/* parse csv */
		sv = _tr_csv_str;
		if (parse_csv(&sv,&_tr_csv_list)<0)
			return -1;
	}

	if (_tr_csv_list == NULL)
		return -1;

	switch(subtype)
	{
		case TR_CSV_COUNT:
			val->ri = 0;
			for (cit=_tr_csv_list;cit;cit=cit->next)
				val->ri++;

			val->rs.s = int2str(val->ri, &val->rs.len);
			val->flags = PV_VAL_INT | PV_VAL_STR | PV_TYPE_INT;
			break;
		case TR_CSV_VALUEAT:
			if(tp==NULL)
			{
				LM_ERR("csv invalid parameters\n");
				return -1;
			}
			if(tp->type==TR_PARAM_NUMBER)
			{
				n = tp->v.n;
			} else {
				if(pv_get_spec_value(msg, (pv_spec_p)tp->v.data, &v)!=0
						|| (!(v.flags&PV_VAL_INT)))
				{
					LM_ERR("cannot get parameter\n");
					return -1;
				}
				n = v.ri;
			}

			if (n<0)
			{
				for (cit=_tr_csv_list;cit;cit=cit->next)
					list_size++;
				n = list_size + n;
				if (n<0)
				{
					LM_ERR("Too large negative index\n");
					return -1;
				}
			}

			cit = _tr_csv_list;
			for (i=0;i<n;i++)
			{
				cit=cit->next;
				if (!cit)
				{
					LM_ERR("Index out of bounds\n");
					return -1;
				}
			}

			val->rs = cit->body;
			val->flags =  PV_VAL_STR;
			break;

		default:
			LM_ERR("unknown subtype %d\n",subtype);
			return -1;
	}

	return 0;
}

static str _tr_sdp_str = {0,0};

int tr_eval_sdp(struct sip_msg *msg, tr_param_t *tp,int subtype,
		pv_value_t *val)
{
	char *bodylimit;
	char *answer;
	char *answerEnd;
	char searchLine;
	int entryNo,i;
	pv_value_t v;

	if(val==NULL || (!(val->flags&PV_VAL_STR)) || val->rs.len<=0)
		return -1;

	if (!tp || !tp->next)
		return -1;

	if(_tr_sdp_str.len==0 || _tr_sdp_str.len!=val->rs.len ||
			strncmp(_tr_sdp_str.s, val->rs.s, val->rs.len)!=0)
	{
		if(val->rs.len>_tr_sdp_str.len)
		{
			if(_tr_sdp_str.s) pkg_free(_tr_sdp_str.s);
				_tr_sdp_str.s = (char*)pkg_malloc((val->rs.len+1));
			if(_tr_sdp_str.s==NULL)
			{
				LM_ERR("no more private memory\n");
				memset(&_tr_sdp_str, 0, sizeof(str));
				return -1;
			}
		}

		_tr_sdp_str.len = val->rs.len;
		memcpy(_tr_sdp_str.s, val->rs.s, val->rs.len);
		_tr_sdp_str.s[_tr_sdp_str.len] = '\0';

	}

	switch (subtype)
	{
		case TR_SDP_LINEAT:
			bodylimit = _tr_sdp_str.s + _tr_sdp_str.len;
			searchLine = *(tp->v.s.s);
			if(tp->next->type==TR_PARAM_NUMBER)
				entryNo = tp->next->v.n;
			else
			{
				if(pv_get_spec_value(msg, (pv_spec_p)tp->next->v.data, &v)!=0
						|| (!(v.flags&PV_VAL_INT)))
				{
					LM_ERR("cannot get parameter\n");
					return -1;
				}
				entryNo = v.ri;
			}
			if (entryNo < 0)
			{
				LM_ERR("negative index provided for sdp.lineat\n");
				return -1;
			}

			answer = find_sdp_line(_tr_sdp_str.s, bodylimit, searchLine);
			if (!answer) {
				LM_DBG("No such line [%c=]\n", searchLine);
				return pv_get_null(NULL, NULL, val);
			}

			for (i=1;i<=entryNo;i++)
			{
				answer = find_next_sdp_line(answer,bodylimit,searchLine,bodylimit);
				if (!answer || answer == bodylimit)
				{
					val->flags = PV_VAL_STR;
					val->rs.s = "";
					val->rs.len = 0;

					LM_DBG("No such line [%c] nr %d in SDP body. Max fields = %d\n",
							searchLine,entryNo,i);
					return 0;
				}
			}

			/* find CR */
			answerEnd = strchr(answer,13);
			if (answerEnd == NULL)
			{
				LM_ERR("malformed SDP body\n");
				return -1;
			}

			val->flags = PV_VAL_STR;
			val->rs.s = answer;
			val->rs.len = answerEnd - answer;

			break;
		default:
			LM_ERR("unknown subtype %d\n",subtype);
			return -1;
	}

	return 0;
}

int tr_eval_ip(struct sip_msg *msg, tr_param_t *tp,int subtype,
		pv_value_t *val)
{
	char *buffer;
	struct ip_addr *binary_ip;
	str inet = str_init("INET");
	str inet6 = str_init("INET6");
	struct hostent *server;
	struct ip_addr ip;

	if(val==NULL || (!(val->flags&PV_VAL_STR)) || val->rs.len<=0)
		return -1;

	switch (subtype)
	{
		case TR_IP_FAMILY:
			if (val->rs.len == 4)
			{
				memcpy(val->rs.s,inet.s,inet.len);
				val->rs.len = inet.len;
			}
			else if (val->rs.len == 16)
			{
				memcpy(val->rs.s,inet6.s,inet6.len);
				val->rs.len = inet6.len;
			}
			else
			{
				LM_ERR("Invalid ip address provided for ip.family. Binary format expected !\n");
				return -1;
			}

			val->flags = PV_VAL_STR;
			break;
		case TR_IP_NTOP:
			if (val->rs.len == 4)
				ip.af = AF_INET;
			else if (val->rs.len == 16)
				ip.af = AF_INET6;
			else
			{
				LM_ERR("Invalid ip address provided for ip.ntop. Binary format expected !\n");
				return -1;
			}

			memcpy(ip.u.addr,val->rs.s,val->rs.len);
			ip.len = val->rs.len;
			buffer = ip_addr2a(&ip);
			val->rs.s = buffer;
			val->rs.len = strlen(buffer);
			val->flags = PV_VAL_STR;
			break;
		case TR_IP_ISIP:
			if(!(val->flags&PV_VAL_STR))
				val->rs.s = int2str(val->ri, &val->rs.len);

			if ( str2ip(&(val->rs)) || str2ip6(&(val->rs)) )
				val->ri = 1;
			else
				val->ri = 0;

			val->flags = PV_TYPE_INT|PV_VAL_INT|PV_VAL_STR;
			val->rs.s = int2str(val->ri, &val->rs.len);
			break;
		case TR_IP_PTON:
			binary_ip = str2ip(&(val->rs));
			if (!binary_ip)
			{
				binary_ip = str2ip6(&(val->rs));
				if (!binary_ip)
				{
					LM_ERR("pton transformation applied to invalid IP\n");
					return -1;
				}
			}
			val->rs.s = (char *)binary_ip->u.addr;
			val->rs.len = binary_ip->len;
			val->flags = PV_VAL_STR;
			break;
		case TR_IP_RESOLVE:
			val->flags = PV_VAL_STR;
			server = resolvehost(val->rs.s,0);
			if (!server || !server->h_addr)
			{
				val->rs.s = "";
				val->rs.len = 0;
				return 0;
			}

			if (server->h_addrtype == AF_INET)
			{
				memcpy(ip.u.addr,server->h_addr,4);
				ip.len = 4;
				ip.af = AF_INET;
			}
			else if (server->h_addrtype == AF_INET6)
			{
				memcpy(ip.u.addr,server->h_addr,16);
				ip.len = 16;
				ip.af = AF_INET6;
			}
			else
			{
				LM_ERR("Unexpected IP address type \n");
				val->rs.s = "";
				val->rs.len = 0;
				return 0;
			}

			buffer = ip_addr2a(&ip);
			val->rs.s = buffer;
			val->rs.len = strlen(buffer);
			break;

		default:
			LM_ERR("unknown subtype %d\n",subtype);
			return -1;
	}

	return 0;
}

#define RE_MAX_SIZE 1024
static char reg_input_buf[RE_MAX_SIZE];
static struct subst_expr *subst_re = NULL;
static char reg_buf[RE_MAX_SIZE];
static int reg_buf_len = -1;
int tr_eval_re(struct sip_msg *msg, tr_param_t *tp, int subtype,
		pv_value_t *val)
{
	int match_no=0;
	pv_value_t v;
	str *result;
	str sv;

	if(val==NULL || (!(val->flags&PV_VAL_STR)) || val->rs.len<=0)
		return -1;

	switch (subtype) {
		case TR_RE_SUBST:
				if (tp->type == TR_PARAM_STRING) {
					sv = tp->v.s;
				} else {
					if(pv_get_spec_value(msg, (pv_spec_p)tp->v.data, &v)!=0
							|| (!(v.flags&PV_VAL_STR)) || v.rs.len<=0) {
						LM_ERR("cannot get value from spec\n");
						return -1;
					}
					sv = v.rs;
				}
				LM_DBG("Trying to apply regexp [%.*s] on : [%.*s]\n",
						sv.len,sv.s,val->rs.len, val->rs.s);
				if (reg_buf_len != sv.len || memcmp(reg_buf,sv.s,sv.len) != 0) {
					LM_DBG("we must compile the regexp\n");
					if (subst_re != NULL) {
						LM_DBG("freeing prev regexp\n");
						subst_expr_free(subst_re);
					}
					subst_re=subst_parser(&sv);
					if (subst_re==0) {
						LM_ERR("Can't compile regexp\n");
						return -1;
					}
					reg_buf_len = sv.len;
					memcpy(reg_buf,sv.s,sv.len);
				} else
					LM_DBG("yay, we can use the pre-compile regexp\n");

				memcpy(reg_input_buf,val->rs.s,val->rs.len);
				reg_input_buf[val->rs.len]=0;

				result=subst_str(reg_input_buf, msg, subst_re, &match_no);
				if (result == NULL) {
					if (match_no == 0) {
						LM_DBG("no match for subst expression\n");
						break;
					} else if (match_no < 0) {
						LM_ERR("subst failed\n");
						return -1;
					}
				}

				memcpy(reg_input_buf,result->s,result->len);
				reg_input_buf[result->len]=0;
				val->flags = PV_VAL_STR;
				val->rs.s = reg_input_buf;
				val->rs.len = result->len;
				pkg_free(result->s);
				pkg_free(result);
				return 0;
		default:
			LM_ERR("Unexpected subtype for RE : %d\n",subtype);
			return -1;
	}
	return 0;
}

static str _tr_params_str = {0, 0};
static param_t* _tr_params_list = NULL;

int tr_eval_paramlist(struct sip_msg *msg, tr_param_t *tp, int subtype,
		pv_value_t *val)
{
	pv_value_t v;
	str sv;
	int n, i;
	param_hooks_t phooks;
	param_t *pit=NULL;

	if(val==NULL || (!(val->flags&PV_VAL_STR)) || val->rs.len<=0)
		return -1;

	if(_tr_params_str.len==0 || _tr_params_str.len!=val->rs.len ||
			strncmp(_tr_params_str.s, val->rs.s, val->rs.len)!=0)
	{

		if(val->rs.len>_tr_params_str.len)
		{
			if(_tr_params_str.s) pkg_free(_tr_params_str.s);
			_tr_params_str.s = (char*)pkg_malloc((val->rs.len+1)*sizeof(char));
			if(_tr_params_str.s==NULL)
			{
				LM_ERR("no more private memory\n");
				memset(&_tr_params_str, 0, sizeof(str));
				if(_tr_params_list != NULL)
				{
					free_params(_tr_params_list);
					_tr_params_list = 0;
				}
				return -1;
			}
		}
		_tr_params_str.len = val->rs.len;
		memcpy(_tr_params_str.s, val->rs.s, val->rs.len);
		_tr_params_str.s[_tr_params_str.len] = '\0';

		/* reset old values */
		if(_tr_params_list != NULL)
		{
			free_params(_tr_params_list);
			_tr_params_list = 0;
		}

		/* parse params */
		sv = _tr_params_str;
		if (parse_params(&sv, CLASS_ANY, &phooks, &_tr_params_list)<0)
			return -1;

	}

	if(_tr_params_list==NULL)
		return -1;

	memset(val, 0, sizeof(pv_value_t));
	val->flags = PV_VAL_STR;

	switch(subtype)
	{
		case TR_PL_VALUE:
			if(tp==NULL)
			{
				LM_ERR("value invalid parameters\n");
				return -1;
			}

			if(tp->type==TR_PARAM_STRING)
			{
				sv = tp->v.s;
			} else {
				if(pv_get_spec_value(msg, (pv_spec_p)tp->v.data, &v)!=0
						|| (!(v.flags&PV_VAL_STR)) || v.rs.len<=0)
				{
					LM_ERR("value cannot get p1\n");
					return -1;
				}
				sv = v.rs;
			}

			for (pit = _tr_params_list; pit; pit=pit->next)
			{
				if (pit->name.len==sv.len
						&& strncasecmp(pit->name.s, sv.s, sv.len)==0)
				{
					val->rs = pit->body;
					goto done;
				}
			}
			val->rs = _tr_empty;
			break;

		case TR_PL_VALUEAT:
			if(tp==NULL)
			{
				LM_ERR("name invalid parameters\n");
				return -1;
			}

			if(tp->type==TR_PARAM_NUMBER)
			{
				n = tp->v.n;
			} else {
				if(pv_get_spec_value(msg, (pv_spec_p)tp->v.data, &v)!=0
						|| (!(v.flags&PV_VAL_INT)))
				{
					LM_ERR("name cannot get p1\n");
					return -1;
				}
				n = v.ri;
			}
			if(n>=0)
			{
				for (pit = _tr_params_list; pit; pit=pit->next)
				{
					if(n==0)
					{
						val->rs = pit->body;
						goto done;
					}
					n--;
				}
			} else {
				/* ugly hack -- params are in reverse order
				 * - first count then find */
				n = -n;
				n--;

				i = 0;
				for (pit = _tr_params_list; pit; pit=pit->next)
					i++;
				if(n<i)
				{
					n = i - n - 1;
					for (pit = _tr_params_list; pit; pit=pit->next)
					{
						if(n==0)
						{
							val->rs = pit->body;
							goto done;
						}
						n--;
					}
				}
			}
			val->rs = _tr_empty;
			break;

		case TR_PL_NAME:
			if(tp==NULL)
			{
				LM_ERR("name invalid parameters\n");
				return -1;
			}

			if(tp->type==TR_PARAM_NUMBER)
			{
				n = tp->v.n;
			} else {
				if(pv_get_spec_value(msg, (pv_spec_p)tp->v.data, &v)!=0
						|| (!(v.flags&PV_VAL_INT)))
				{
					LM_ERR("name cannot get p1\n");
					return -1;
				}
				n = v.ri;
			}
			if(n>=0)
			{
				for (pit = _tr_params_list; pit; pit=pit->next)
				{
					if(n==0)
					{
						val->rs = pit->name;
						goto done;
					}
					n--;
				}
			} else {
				/* ugly hack -- params are in sorted order
				 * - first count then find */
				n = -n;
				n--;

				i = 0;
				for (pit = _tr_params_list; pit; pit=pit->next)
					i++;
				if(n<i)
				{
					n = i - n - 1;
					for (pit = _tr_params_list; pit; pit=pit->next)
					{
						if(n==0)
						{
							val->rs = pit->name;
							goto done;
						}
						n--;
					}
				}
			}
			val->rs = _tr_empty;
			break;

		case TR_PL_COUNT:
			val->ri = 0;
			for (pit = _tr_params_list; pit; pit=pit->next) {
				val->ri++;
			}
			val->flags = PV_TYPE_INT|PV_VAL_INT|PV_VAL_STR;
			val->rs.s = int2str(val->ri, &val->rs.len);
			break;


		case TR_PL_EXIST:
			if(tp==NULL)
			{
				LM_ERR("value invalid parameters\n");
				return -1;
			}

			if(tp->type==TR_PARAM_STRING)
			{
				sv = tp->v.s;
			} else {
				if(pv_get_spec_value(msg, (pv_spec_p)tp->v.data, &v)!=0
						|| (!(v.flags&PV_VAL_STR)) || v.rs.len<=0)
				{
					LM_ERR("value cannot get p1\n");
					return -1;
				}
				sv = v.rs;
			}

			val->ri = 0;
			for (pit = _tr_params_list; pit; pit=pit->next)
			{
				if (pit->name.len==sv.len
						&& strncasecmp(pit->name.s, sv.s, sv.len)==0)
				{
					val->ri = 1;
					break;
				}
			}
			val->flags = PV_TYPE_INT|PV_VAL_INT|PV_VAL_STR;
			val->rs.s = int2str(val->ri, &val->rs.len);
			goto done;

		default:
			LM_ERR("unknown subtype %d\n",
					subtype);
			return -1;
	}
done:
	return 0;
}

static str nameaddr_str = {0, 0};
static struct to_body *nameaddr_to_body = NULL;

int tr_eval_nameaddr(struct sip_msg *msg, tr_param_t *tp, int subtype,
		pv_value_t *val)
{
	struct to_param* topar;

	if(val==NULL || (!(val->flags&PV_VAL_STR)) || val->rs.len<=0)
		return -1;

	LM_DBG("String to transform %.*s\n", val->rs.len, val->rs.s);

	if(nameaddr_str.len==0 || nameaddr_str.len!=val->rs.len ||
			strncmp(nameaddr_str.s, val->rs.s, val->rs.len)!=0)
	{
		/* copy the value in the global variable */
		if(val->rs.len+CRLF_LEN > nameaddr_str.len)
		{
			if(nameaddr_str.s) pkg_free(nameaddr_str.s);
			nameaddr_str.s =
					(char*)pkg_malloc((val->rs.len+CRLF_LEN+1)*sizeof(char));
			if(nameaddr_str.s==NULL)
			{
				LM_ERR("no more private memory\n");
				memset(&nameaddr_str, 0, sizeof(str));
				return -1;
			}
		}
		nameaddr_str.len = val->rs.len + CRLF_LEN;
		memcpy(nameaddr_str.s, val->rs.s, val->rs.len);
		memcpy(nameaddr_str.s + val->rs.len, CRLF, CRLF_LEN);
		nameaddr_str.s[nameaddr_str.len] = '\0';

		/* reset old values */
		if (nameaddr_to_body) {
			free_to(nameaddr_to_body);
			nameaddr_to_body = NULL;
		}

		/* parse TO hdr + params */
		nameaddr_to_body = (struct to_body*)pkg_malloc(sizeof(struct to_body));
		if(nameaddr_to_body==NULL)
		{
			LM_ERR("no more private memory\n");
			/* keep the buffer, but flush the content to force the realloc
			   next time */
			nameaddr_str.s[0] = 0;
			return -1;
		}
		parse_to(nameaddr_str.s, nameaddr_str.s + nameaddr_str.len,
			nameaddr_to_body);
	}

	if (nameaddr_to_body->error == PARSE_ERROR)
	{
		LM_ERR("Wrong syntax. It must have the To header format\n");
		return -1;
	}

	memset(val, 0, sizeof(pv_value_t));
	val->flags = PV_VAL_STR;

	switch(subtype)
	{
		case TR_NA_URI:
			val->rs =(nameaddr_to_body->uri.s)?nameaddr_to_body->uri:_tr_empty;
			break;
		case TR_NA_LEN:
			val->flags = PV_TYPE_INT|PV_VAL_INT|PV_VAL_STR;
			val->ri = nameaddr_to_body->body.len;
			val->rs.s = int2str(val->ri, &val->rs.len);
			break;
		case TR_NA_NAME:
			val->rs = (nameaddr_to_body->display.s)?
				nameaddr_to_body->display:_tr_empty;
			break;
		case TR_NA_PARAM:
			if(tp->type != TR_PARAM_STRING)
			{
				LM_ERR("Wrong type for parameter, it must string\n");
				return -1;
			}
			topar = nameaddr_to_body->param_lst;
			/* search the parameter */
			while(topar)
			{
				if(topar->name.len == tp->v.s.len &&
						strncmp(topar->name.s, tp->v.s.s, topar->name.len)== 0)
					break;
				topar = topar->next;
			}
			val->rs = (topar)?topar->value:_tr_empty;
			break;
		case TR_NA_PARAMS:
			topar = nameaddr_to_body->param_lst;
			if (!topar) {
				LM_DBG("no params\n");
				val->rs = _tr_empty;
			}
			else {
				LM_DBG("We have params\n");
				val->rs.s = topar->name.s;
				if (nameaddr_to_body->last_param->value.s==NULL) {
					val->rs.len = nameaddr_to_body->last_param->name.s +
						nameaddr_to_body->last_param->name.len - val->rs.s;
				} else {
					val->rs.len = nameaddr_to_body->last_param->value.s +
						nameaddr_to_body->last_param->value.len - val->rs.s;
					/* compensate the len if the value of the last param is
					 * a quoted value (include the closing quote in the len) */
					if ( (val->rs.s+val->rs.len<nameaddr_str.len+nameaddr_str.s) &&
					(val->rs.s[val->rs.len]=='"' || val->rs.s[val->rs.len]=='\'' ) )
						val->rs.len++;
				}
			}
			break;

		default:
			LM_ERR("unknown subtype %d\n", subtype);
			return -1;
	}
	return 0;
}



#define is_in_str(p, in) (p<in->s+in->len && *p)

char* parse_transformation(str *in, trans_t **tr)
{
	char *p;
	char *p0;
	str tclass;
	trans_t *t = NULL;
	trans_t *t0 = NULL;
	str s;

	if(in==NULL || in->s==NULL || tr==NULL)
		return NULL;

	p = in->s;
	do {
		while(is_in_str(p, in) && is_ws(*p)) p++;
		if(*p != TR_LBRACKET)
			break;
		p++;

		t = (trans_t*)pkg_malloc(sizeof(trans_t));
		if(t == NULL)
		{
			LM_ERR("no more private memory\n");
			return NULL;
		}
		memset(t, 0, sizeof(trans_t));
		if(t0==NULL)
			*tr = t;
		else
			t0->next = t;
		t0 = t;

		/* find transformation class */
		tclass.s = p;
		while(is_in_str(p, in) && *p!=TR_CLASS_MARKER) p++;
		if(*p!=TR_CLASS_MARKER || tclass.s == p)
		{
			LM_ERR("invalid transformation: %.*s (%c)!\n", in->len, in->s, *p);
			goto error;
		}
		tclass.len = p - tclass.s;
		p++;

		if(tclass.len==1 && (*tclass.s=='s' || *tclass.s=='S'))
		{
			t->type = TR_STRING;
			t->trf = tr_eval_string;
			s.s = p; s.len = in->s + in->len - p;
			p0 = tr_parse_string(&s, t);
			if(p0==NULL)
				goto error;
			p = p0;
		} else if(tclass.len==3 && strncasecmp(tclass.s, "uri", 3)==0) {
			t->type = TR_URI;
			t->trf = tr_eval_uri;
			s.s = p; s.len = in->s + in->len - p;
			p0 = tr_parse_uri(&s, t);
			if(p0==NULL)
				goto error;
			p = p0;
		} else if(tclass.len==3 && strncasecmp(tclass.s, "via", 3)==0) {
			t->type = TR_VIA;
			t->trf = tr_eval_via;
			s.s = p; s.len = in->s + in->len - p;
			p0 = tr_parse_via(&s, t);
			if(p0==NULL)
				goto error;
			p = p0;
		} else if(tclass.len==5 && strncasecmp(tclass.s, "param", 5)==0) {
			t->type = TR_PARAMLIST;
			t->trf = tr_eval_paramlist;
			s.s = p; s.len = in->s + in->len - p;
			p0 = tr_parse_paramlist(&s, t);
			if(p0==NULL)
				goto error;
			p = p0;
		} else if(tclass.len==8 && strncasecmp(tclass.s, "nameaddr", 8)==0) {
			t->type = TR_NAMEADDR;
			t->trf = tr_eval_nameaddr;
			s.s = p; s.len = in->s + in->len - p;
			p0 = tr_parse_nameaddr(&s, t);
			if(p0==NULL)
				goto error;
			p = p0;
		}
		else if (tclass.len==3 && strncasecmp(tclass.s, "csv", 3) == 0) {
			t->type = TR_CSV;
			t->trf = tr_eval_csv;
			s.s = p; s.len = in->s + in->len - p;
			p0 = tr_parse_csv(&s,t);
			if (p0==NULL)
				goto error;
			p = p0;
		}
		else if (tclass.len==3 && strncasecmp(tclass.s,"sdp",3) == 0) {
			t->type = TR_SDP;
			t->trf = tr_eval_sdp;
			s.s = p; s.len = in->s + in->len - p;
			p0 = tr_parse_sdp(&s,t);
			if (p0==NULL)
				goto error;
			p = p0;
		}
		else if (tclass.len==2 && strncasecmp(tclass.s,"ip",2) == 0) {
			t->type = TR_IP;
			t->trf = tr_eval_ip;
			s.s = p; s.len = in->s + in->len - p;
			p0 = tr_parse_ip(&s,t);
			if (p0==NULL)
				goto error;
			p = p0;
		} else if (tclass.len==2 && strncasecmp(tclass.s,"re",2) == 0) {
			t->type = TR_RE;
			t->trf = tr_eval_re;
			s.s = p; s.len = in->s + in->len - p;
			p0 = tr_parse_re(&s,t);
			if (p0==NULL)
				goto error;
			p = p0;
		}
		else {
			LM_ERR("unknown transformation: [%.*s] in [%.*s]\n",
				tclass.len, tclass.s, in->len, in->s);
			goto error;
		}

		if(*p != TR_RBRACKET)
		{
			LM_ERR("invalid transformation: %.*s | %c !!\n", in->len, in->s, *p);
			goto error;
		}

		p++;
		if(!is_in_str(p, in))
			break;
	} while(1);

	return p;
error:
	LM_ERR("error parsing [%.*s]\n", in->len, in->s);
	t = *tr;
	while(t)
	{
		t0 = t;
		t = t->next;
		destroy_transformation(t0);
		pkg_free(t0);
	}
	return NULL;
}

#define _tr_parse_nparam(_p, _p0, _tp, _spec, _n, _sign, _in, _s) \
	while(is_in_str(_p, _in) && is_ws(*(_p))) _p++; \
	if(*_p==PV_MARKER) \
	{ /* pseudo-variable */ \
		_spec = (pv_spec_t*)pkg_malloc(sizeof(pv_spec_t)); \
		if(_spec==NULL) \
		{ \
			LM_ERR("no more private memory!\n"); \
			goto error; \
		} \
		_s.s = _p; _s.len = _in->s + _in->len - _p; \
		_p0 = pv_parse_spec(&_s, _spec); \
		if(_p0==NULL) \
		{ \
			LM_ERR("invalid spec in substr transformation: %.*s!\n", \
				_in->len, _in->s); \
			goto error; \
		} \
		_p = _p0; \
		_tp = (tr_param_t*)pkg_malloc(sizeof(tr_param_t)); \
		if(_tp==NULL) \
		{ \
			LM_ERR("no more private memory!\n"); \
			goto error; \
		} \
		memset(_tp, 0, sizeof(tr_param_t)); \
		_tp->type = TR_PARAM_SPEC; \
		_tp->v.data = (void*)_spec; \
	} else { \
		if(*_p=='+' || *_p=='-' || (*_p>='0' && *_p<='9')) \
		{ /* number */ \
			_sign = 1; \
			if(*_p=='-') { \
				_p++; \
				_sign = -1; \
			} else if(*_p=='+') _p++; \
			_n = 0; \
			while(is_in_str(_p, _in) && is_ws(*(_p))) \
					_p++; \
			while(is_in_str(_p, _in) && *_p>='0' && *_p<='9') \
			{ \
				_n = _n*10 + *_p - '0'; \
				_p++; \
			} \
			_tp = (tr_param_t*)pkg_malloc(sizeof(tr_param_t)); \
			if(_tp==NULL) \
			{ \
				LM_ERR("no more private memory!\n"); \
				goto error; \
			} \
			memset(_tp, 0, sizeof(tr_param_t)); \
			_tp->type = TR_PARAM_NUMBER; \
			_tp->v.n = sign*n; \
		} else { \
			LM_ERR("tinvalid param in transformation: %.*s!!\n", \
				_in->len, _in->s); \
			goto error; \
		} \
	}

#define tr_parse_sparam(_p, _p0, _tp, _spec, _ps, _in, _s) \
	__tr_parse_sparam(_p, _p0, _tp, _spec, _ps, _in, _s, 0) \

/*
 * Not all transformation string parameters have the same meaning
 * Some of them are SIP headers, thus they cannot contain whitespace,
 * while others may just be strings with no additional restrictions.
 *
 * Set "skip_param_ws" to 1 if your param may contain inside whitespace
 *		-> e.g. ' ', "foo bar", "foob\tar" ...
 */
#define __tr_parse_sparam(_p, _p0, _tp, _spec, _ps, _in, _s, skip_param_ws) \
	while(is_in_str(_p, _in) && is_ws(*(_p))) _p++; \
	if(*_p==PV_MARKER) \
	{ /* pseudo-variable */ \
		_spec = (pv_spec_t*)pkg_malloc(sizeof(pv_spec_t)); \
		if(_spec==NULL) \
		{ \
			LM_ERR("no more private memory!\n"); \
			goto error; \
		} \
		_s.s = _p; _s.len = _in->s + _in->len - _p; \
		_p0 = pv_parse_spec(&_s, _spec); \
		if(_p0==NULL) \
		{ \
			LM_ERR("invalid spec in substr transformation: %.*s!\n", \
				_in->len, _in->s); \
			goto error; \
		} \
		_p = _p0; \
		_tp = (tr_param_t*)pkg_malloc(sizeof(tr_param_t)); \
		if(_tp==NULL) \
		{ \
			LM_ERR("no more private memory!\n"); \
			goto error; \
		} \
		memset(_tp, 0, sizeof(tr_param_t)); \
		_tp->type = TR_PARAM_SPEC; \
		_tp->v.data = (void*)_spec; \
	} else { /* string */ \
		_ps = _p; \
		while(is_in_str(_p, _in) && (skip_param_ws || !is_ws(*_p)) \
				&& *_p!=TR_PARAM_MARKER && *_p!=TR_RBRACKET) \
				_p++; \
		if(*_p=='\0') \
		{ \
			LM_ERR("invalid param in transformation: %.*s!!\n", \
				_in->len, _in->s); \
			goto error; \
		} \
		_tp = (tr_param_t*)pkg_malloc(sizeof(tr_param_t)); \
		if(_tp==NULL) \
		{ \
			LM_ERR("no more private memory!\n"); \
			goto error; \
		} \
		memset(_tp, 0, sizeof(tr_param_t)); \
		_tp->type = TR_PARAM_STRING; \
		_tp->v.s.s = _ps; \
		_tp->v.s.len = _p - _ps; \
	}


char* tr_parse_string(str* in, trans_t *t)
{
	char *p, *cp;
	char *p0;
	char *ps;
	str name;
	str s;
	pv_spec_t *spec = NULL;
	int n;
	int sign;
	tr_param_t *tp = NULL;

	if(in==NULL || t==NULL)
		return NULL;

	p = in->s;
	name.s = in->s;

	/* find next token */
	while(is_in_str(p, in) && *p!=TR_PARAM_MARKER && *p!=TR_RBRACKET) p++;
	if(*p=='\0')
	{
		LM_ERR("invalid transformation: %.*s\n",
				in->len, in->s);
		goto error;
	}
	name.len = p - name.s;
	trim(&name);

	if(name.len==3 && strncasecmp(name.s, "len", 3)==0)
	{
		t->subtype = TR_S_LEN;
		return p;
	} else if(name.len==3 && strncasecmp(name.s, "int", 3)==0) {
		t->subtype = TR_S_INT;
		return p;
	} else if(name.len==3 && strncasecmp(name.s, "md5", 3)==0) {
		t->subtype = TR_S_MD5;
		return p;
	} else if(name.len==5 && strncasecmp(name.s, "crc32", 5)==0) {
		t->subtype = TR_S_CRC32;
		return p;
	} else if(name.len==7 && strncasecmp(name.s, "tolower", 7)==0) {
		t->subtype = TR_S_TOLOWER;
		return p;
	} else if(name.len==7 && strncasecmp(name.s, "toupper", 7)==0) {
		t->subtype = TR_S_TOUPPER;
		return p;
	} else if(name.len==11 && strncasecmp(name.s, "encode.hexa", 11)==0) {
		t->subtype = TR_S_ENCODEHEXA;
		return p;
	} else if(name.len==11 && strncasecmp(name.s, "decode.hexa", 11)==0) {
		t->subtype = TR_S_DECODEHEXA;
		return p;
	} else if(name.len==7 && strncasecmp(name.s, "hex2dec", 7)==0) {
		t->subtype = TR_S_HEX2DEC;
		return p;
	} else if(name.len==7 && strncasecmp(name.s, "dec2hex", 7)==0) {
		t->subtype = TR_S_DEC2HEX;
		return p;
	} else if(name.len==13 && strncasecmp(name.s, "escape.common", 13)==0) {
		t->subtype = TR_S_ESCAPECOMMON;
		return p;
	} else if(name.len==15 && strncasecmp(name.s, "unescape.common", 15)==0) {
		t->subtype = TR_S_UNESCAPECOMMON;
		return p;
	} else if(name.len==11 && strncasecmp(name.s, "escape.user", 11)==0) {
		t->subtype = TR_S_ESCAPEUSER;
		return p;
	} else if(name.len==13 && strncasecmp(name.s, "unescape.user", 13)==0) {
		t->subtype = TR_S_UNESCAPEUSER;
		return p;
	} else if(name.len==12 && strncasecmp(name.s, "escape.param", 12)==0) {
		t->subtype = TR_S_ESCAPEPARAM;
		return p;
	} else if(name.len==14 && strncasecmp(name.s, "unescape.param", 14)==0) {
		t->subtype = TR_S_UNESCAPEPARAM;
		return p;
	} else if(name.len==5 && strncasecmp(name.s, "index", 5)==0) {
		t->subtype = TR_S_INDEX;
		if(*p!=TR_PARAM_MARKER)
		{
			LM_ERR("invalid index transformation: %.*s!\n", in->len, in->s);
			goto error;
		}
		p++;
		tr_parse_sparam(p, p0, tp, spec, ps, in, s);
		t->params = tp;
		tp = 0;
		trim_ws(p);
		if(*p!=TR_PARAM_MARKER && *p!=TR_RBRACKET)
		{
			LM_ERR("invalid index transformation: %.*s!\n",
				in->len, in->s);
			goto error;
		}
		if (*p!=TR_RBRACKET) {
			p++;
			_tr_parse_nparam(p, p0, tp, spec, n, sign, in, s);
			t->params->next = tp;
		} else {
			t->params->next = NULL;
		}

		tp = 0;
		while(is_in_str(p, in) && is_ws(*p)) p++;
		if(*p!=TR_RBRACKET)
		{
			LM_ERR("invalid index transformation: %.*s!!\n",
				in->len, in->s);
			goto error;
		}
		return p;
	} else if(name.len==6 && strncasecmp(name.s, "rindex", 6)==0) {
		t->subtype = TR_S_RINDEX;
		if(*p!=TR_PARAM_MARKER)
		{
			LM_ERR("invalid rindex transformation: %.*s!\n", in->len, in->s);
			goto error;
		}
		p++;
		tr_parse_sparam(p, p0, tp, spec, ps, in, s);
		t->params = tp;
		tp = 0;
		trim_ws(p);
		if(*p!=TR_PARAM_MARKER && *p!=TR_RBRACKET)
		{
			LM_ERR("invalid rindex transformation: %.*s!\n",
				in->len, in->s);
			goto error;
		}
		if (*p!=TR_RBRACKET) {
			p++;
			_tr_parse_nparam(p, p0, tp, spec, n, sign, in, s);
			t->params->next = tp;
		} else {
			t->params->next = NULL;
		}

		tp = 0;
		while(is_in_str(p, in) && is_ws(*p)) p++;
		if(*p!=TR_RBRACKET)
		{
			LM_ERR("invalid rindex transformation: %.*s!!\n",
				in->len, in->s);
			goto error;
		}
		return p;
	} else if(name.len==6 && strncasecmp(name.s, "substr", 6)==0) {
		t->subtype = TR_S_SUBSTR;
		if(*p!=TR_PARAM_MARKER)
		{
			LM_ERR("invalid substr transformation: %.*s!\n", in->len, in->s);
			goto error;
		}
		p++;
		_tr_parse_nparam(p, p0, tp, spec, n, sign, in, s);
		t->params = tp;
		tp = 0;
		trim_ws(p);
		if(*p!=TR_PARAM_MARKER)
		{
			LM_ERR("invalid substr transformation: %.*s!\n",
				in->len, in->s);
			goto error;
		}
		p++;
		_tr_parse_nparam(p, p0, tp, spec, n, sign, in, s);
		if(tp->type==TR_PARAM_NUMBER && tp->v.n<0)
		{
			LM_ERR("substr negative offset\n");
			goto error;
		}
		t->params->next = tp;
		tp = 0;
		while(is_in_str(p, in) && is_ws(*p)) p++;
		if(*p!=TR_RBRACKET)
		{
			LM_ERR("invalid substr transformation: %.*s!!\n",
				in->len, in->s);
			goto error;
		}
		return p;
	} else if(name.len==6 && strncasecmp(name.s, "select", 6)==0) {
		t->subtype = TR_S_SELECT;
		if(*p!=TR_PARAM_MARKER)
		{
			LM_ERR("invalid select transformation: %.*s!\n",
					in->len, in->s);
			goto error;
		}
		p++;
		_tr_parse_nparam(p, p0, tp, spec, n, sign, in, s);
		t->params = tp;
		tp = 0;
		trim_ws(p);
		if(*p!=TR_PARAM_MARKER || *(p+1)=='\0')
		{
			LM_ERR("invalid select transformation: %.*s!\n", in->len, in->s);
			goto error;
		}
		p++;
		tp = (tr_param_t*)pkg_malloc(sizeof(tr_param_t));
		if(tp==NULL)
		{
			LM_ERR("no more private memory!\n");
			goto error;
		}
		memset(tp, 0, sizeof(tr_param_t));
		tp->type = TR_PARAM_STRING;
		tp->v.s.s = p;
		tp->v.s.len = 1;
		t->params->next = tp;
		tp = 0;
		p++;
		trim_ws(p);
		if(*p!=TR_RBRACKET)
		{
			LM_ERR("invalid select transformation: %.*s!!\n",
				in->len, in->s);
			goto error;
		}
		return p;
	} else if ((name.len==9 && strncasecmp(name.s, "fill.left", 9)==0) ||
			  (name.len==10 && strncasecmp(name.s, "fill.right", 10)==0)) {

		t->subtype = (name.len == 9 ? TR_S_FILL_LEFT : TR_S_FILL_RIGHT);
		if (*p != TR_PARAM_MARKER)
		{
			LM_ERR("invalid fill transformation: %.*s!\n", in->len, in->s);
			goto error;
		}
		p++;
		__tr_parse_sparam(p, p0, tp, spec, ps, in, s, 1);
		if (tp->type == TR_PARAM_SPEC)
		{
			LM_ERR("fill transformation does not allow PVs: %.*s!\n", in->len, in->s);
			goto error;
		}
		if (tp->v.s.len == 0)
		{
			LM_ERR("fill transformation is a NOP, maybe use quotes? %.*s\n",
					in->len, in->s);
			goto error;
		}

		if (tp->v.s.len > 1) {
			/* we allowed all whitespace, so manually skip trailing ws */
			cp = &tp->v.s.s[tp->v.s.len - 1];
			trim_trail_ws(cp);
			tp->v.s.len -= &tp->v.s.s[tp->v.s.len - 1] - cp;

			/* support for quoted chars/strings */
			if (tp->v.s.len > 1 &&
				((tp->v.s.s[0] == '\'' && tp->v.s.s[tp->v.s.len - 1] == '\'') ||
				(tp->v.s.s[0] == '\"' && tp->v.s.s[tp->v.s.len - 1] == '\"'))) {

				if (tp->v.s.len == 2)
				{
					LM_ERR("fill transformation is a NOP, maybe use quotes? %.*s\n",
							in->len, in->s);
					goto error;
				}

				tp->v.s.len -= 2;
				tp->v.s.s++;
			}
		}
		t->params = tp;
		tp = 0;
		trim_ws(p);
		if (*p != TR_PARAM_MARKER || *(p+1) == '\0')
		{
			LM_ERR("invalid fill transformation: %.*s!\n", in->len, in->s);
			goto error;
		}
		p++;
		_tr_parse_nparam(p, p0, tp, spec, n, sign, in, s);
		if (tp->type == TR_PARAM_SPEC)
		{
			LM_ERR("fill transformation does not allow PVs: %.*s!\n", in->len, in->s);
			goto error;
		}
		t->params->next = tp;

		tp = 0;
		while(is_in_str(p, in) && is_ws(*p)) p++;
		if (*p != TR_RBRACKET)
		{
			LM_ERR("invalid fill transformation: %.*s!!\n", in->len, in->s);
			goto error;
		}
		return p;
	} else if(name.len==5 && strncasecmp(name.s, "width", 5)==0) {
		t->subtype = TR_S_WIDTH;
		if(*p!=TR_PARAM_MARKER)
		{
			LM_ERR("invalid substr transformation: %.*s!\n", in->len, in->s);
			goto error;
		}
		p++;
		_tr_parse_nparam(p, p0, tp, spec, n, sign, in, s);
		if(tp->type==TR_PARAM_NUMBER && tp->v.n<0)
		{
			LM_ERR("width negative\n");
			goto error;
		}
		t->params = tp;
		tp = 0;
		while(is_in_str(p, in) && (*p==' ' || *p=='\t' || *p=='\n')) p++;
		if(*p!=TR_RBRACKET)
		{
			LM_ERR("invalid width transformation: %.*s!!\n",
				in->len, in->s);
			goto error;
		}
		return p;
	} else if(name.len==9 && strncasecmp(name.s, "b64encode", 9)==0) {
		t->subtype = TR_S_B64ENCODE;
		return p;
	} else if(name.len==9 && strncasecmp(name.s, "b64decode", 9)==0) {
		t->subtype = TR_S_B64DECODE;
		return p;
	} else if(name.len==3 && strncasecmp(name.s, "xor", 3)==0) {
		t->subtype = TR_S_XOR;
		if(*p!=TR_PARAM_MARKER)
		{
			LM_ERR("invalid xor transformation: %.*s!\n", in->len, in->s);
			goto error;
		}
		p++;
		tr_parse_sparam(p, p0, tp, spec, ps, in, s);
		t->params = tp;
		tp = 0;
		trim_ws(p);

		while(is_in_str(p, in) && is_ws(*p)) p++;
		if(*p!=TR_RBRACKET)
		{
			LM_ERR("invalid xor transformation: %.*s!!\n",
				in->len, in->s);
			goto error;
		}
		return p;
	} else if (strncasecmp(name.s, "trim", 4) == 0) {
		if (name.len == 4)
			t->subtype = TR_S_TRIM;
		else if (name.len > 4 && strncasecmp(name.s, "trimr", 5) == 0)
			t->subtype = TR_S_TRIMR;
		else if (name.len > 4 && strncasecmp(name.s, "triml", 5) == 0)
			t->subtype = TR_S_TRIML;
		else {
			LM_ERR("bad trim transformation!\n");
			goto error;
		}

		return p;
	}

	LM_ERR("unknown transformation: %.*s/%.*s/%d!\n", in->len, in->s,
			name.len, name.s, name.len);
error:
	if(tp)
		free_tr_param(tp);
	if(spec)
		pv_spec_free(spec);
	return NULL;
}

char* tr_parse_uri(str* in, trans_t *t)
{
	char *p;
	char *p0;
	char *ps;
	str name;
	str s;
	pv_spec_t *spec = NULL;
	tr_param_t *tp = NULL;

	if(in==NULL || in->s==NULL || t==NULL)
		return NULL;
	p = in->s;
	name.s = in->s;

	/* find next token */
	while(*p && *p!=TR_PARAM_MARKER && *p!=TR_RBRACKET) p++;
	if(*p=='\0')
	{
		LM_ERR("invalid transformation: %.*s\n", in->len, in->s);
		goto error;
	}
	name.len = p - name.s;
	trim(&name);

	if(name.len==4 && strncasecmp(name.s, "user", 4)==0)
	{
		t->subtype = TR_URI_USER;
		return p;
	} else if((name.len==4 && strncasecmp(name.s, "host", 4)==0)
			|| (name.len==6 && strncasecmp(name.s, "domain", 6)==0)) {
		t->subtype = TR_URI_HOST;
		return p;
	} else if(name.len==6 && strncasecmp(name.s, "passwd", 6)==0) {
		t->subtype = TR_URI_PASSWD;
		return p;
	} else if(name.len==4 && strncasecmp(name.s, "port", 4)==0) {
		t->subtype = TR_URI_PORT;
		return p;
	} else if(name.len==6 && strncasecmp(name.s, "params", 6)==0) {
		t->subtype = TR_URI_PARAMS;
		return p;
	} else if(name.len==5 && strncasecmp(name.s, "param", 5)==0) {
		t->subtype = TR_URI_PARAM;
		if(*p!=TR_PARAM_MARKER)
		{
			LM_ERR("invalid param transformation: %.*s\n", in->len, in->s);
			goto error;
		}
		p++;
		tr_parse_sparam(p, p0, tp, spec, ps, in, s);
		t->params = tp;
		trim_ws(p);
		if(*p!=TR_RBRACKET)
		{
			LM_ERR("invalid param transformation: %.*s!\n", in->len, in->s);
			goto error;
		}
		return p;
	} else if(name.len==9 && strncasecmp(name.s, "transport", 9)==0) {
		t->subtype = TR_URI_TRANSPORT;
		return p;
	} else if(name.len==7 && strncasecmp(name.s, "headers", 7)==0) {
		t->subtype = TR_URI_HEADERS;
		return p;
	} else if(name.len==3 && strncasecmp(name.s, "ttl", 3)==0) {
		t->subtype = TR_URI_TTL;
		return p;
	} else if(name.len==6 && strncasecmp(name.s, "uparam", 6)==0) {
		t->subtype = TR_URI_UPARAM;
		return p;
	} else if(name.len==5 && strncasecmp(name.s, "maddr", 5)==0) {
		t->subtype = TR_URI_MADDR;
		return p;
	} else if(name.len==6 && strncasecmp(name.s, "method", 6)==0) {
		t->subtype = TR_URI_METHOD;
		return p;
	} else if(name.len==2 && strncasecmp(name.s, "lr", 2)==0) {
		t->subtype = TR_URI_LR;
		return p;
	} else if(name.len==2 && strncasecmp(name.s, "r2", 2)==0) {
		t->subtype = TR_URI_R2;
		return p;
	} else if (name.len==6 && strncasecmp(name.s, "schema", 6)==0) {
		t->subtype = TR_URI_SCHEMA;
		return p;
	}

	LM_ERR("unknown transformation: %.*s/%.*s!\n", in->len,
			in->s, name.len, name.s);
error:
	if(spec)
		pv_spec_free(spec);
	return NULL;
}


char* tr_parse_via(str* in, trans_t *t)
{
	char *p;
	char *p0;
	char *ps;
	str name;
	str s;
	pv_spec_t *spec = NULL;
	tr_param_t *tp = NULL;

	if(in==NULL || in->s==NULL || t==NULL)
		return NULL;
	p = in->s;
	name.s = in->s;

	/* find next token */
	while(*p && *p!=TR_PARAM_MARKER && *p!=TR_RBRACKET) p++;
	if(*p=='\0')
	{
		LM_ERR("invalid transformation: %.*s\n", in->len, in->s);
		goto error;
	}
	name.len = p - name.s;
	trim(&name);

	if(name.len==4 && strncasecmp(name.s, "name", 4)==0)
	{
		t->subtype = TR_VIA_NAME;
		return p;
	} else if(name.len==7 && strncasecmp(name.s, "version", 7)==0)
	{
		t->subtype = TR_VIA_VERSION;
		return p;
	} else if(name.len==9 && strncasecmp(name.s, "transport", 9)==0) {
		t->subtype = TR_VIA_TRANSPORT;
		return p;
	} else if((name.len==4 && strncasecmp(name.s, "host", 4)==0)
			|| (name.len==6 && strncasecmp(name.s, "domain", 6)==0)) {
		t->subtype = TR_VIA_HOST;
		return p;
	} else if(name.len==4 && strncasecmp(name.s, "port", 4)==0) {
		t->subtype = TR_VIA_PORT;
		return p;
	} else if(name.len==6 && strncasecmp(name.s, "params", 6)==0) {
		t->subtype = TR_VIA_PARAMS;
		return p;
	} else if(name.len==5 && strncasecmp(name.s, "param", 5)==0) {
		t->subtype = TR_VIA_PARAM;
		if(*p!=TR_PARAM_MARKER)
		{
			LM_ERR("invalid param transformation: %.*s\n", in->len, in->s);
			goto error;
		}
		p++;
		tr_parse_sparam(p, p0, tp, spec, ps, in, s);
		t->params = tp;
		trim_ws(p);
		if(*p!=TR_RBRACKET)
		{
			LM_ERR("invalid param transformation: %.*s!\n", in->len, in->s);
			goto error;
		}
		return p;
	} else if(name.len==7 && strncasecmp(name.s, "comment", 7)==0) {
		t->subtype = TR_VIA_COMMENT;
		return p;
	} else if(name.len==6 && strncasecmp(name.s, "branch", 6)==0) {
		t->subtype = TR_VIA_BRANCH;
		return p;
	} else if(name.len==8 && strncasecmp(name.s, "received", 8)==0) {
		t->subtype = TR_VIA_RECEIVED;
		return p;
	} else if(name.len==5 && strncasecmp(name.s, "rport", 5)==0) {
		t->subtype = TR_VIA_RPORT;
		return p;
	}


	LM_ERR("unknown transformation: %.*s/%.*s!\n", in->len,
			in->s, name.len, name.s);
error:
	if(spec)
		pv_spec_free(spec);
	return NULL;
}

char* tr_parse_paramlist(str* in, trans_t *t)
{
	char *p;
	char *p0;
	char *ps;
	str s;
	str name;
	int n;
	int sign;
	pv_spec_t *spec = NULL;
	tr_param_t *tp = NULL;

	if(in==NULL || in->s==NULL || t==NULL)
		return NULL;

	p = in->s;
	name.s = in->s;

	/* find next token */
	while(is_in_str(p, in) && *p!=TR_PARAM_MARKER && *p!=TR_RBRACKET) p++;
	if(*p=='\0')
	{
		LM_ERR("invalid transformation: %.*s\n",
				in->len, in->s);
		goto error;
	}
	name.len = p - name.s;
	trim(&name);

	if(name.len==5 && strncasecmp(name.s, "value", 5)==0)
	{
		t->subtype = TR_PL_VALUE;
		if(*p!=TR_PARAM_MARKER)
		{
			LM_ERR("invalid value transformation: %.*s\n",
					in->len, in->s);
			goto error;
		}
		p++;
		tr_parse_sparam(p, p0, tp, spec, ps, in, s);
		t->params = tp;
		trim_ws(p);
		if(*p!=TR_RBRACKET)
		{
			LM_ERR("invalid value transformation: %.*s!\n",
					in->len, in->s);
			goto error;
		}
		return p;

	} else if(name.len==5 && strncasecmp(name.s, "exist", 5)==0) {
		t->subtype = TR_PL_EXIST;
		if(*p!=TR_PARAM_MARKER)
		{
			LM_ERR("invalid value transformation: %.*s\n",
					in->len, in->s);
			goto error;
		}
		p++;
		tr_parse_sparam(p, p0, tp, spec, ps, in, s);
		t->params = tp;
		trim_ws(p);
		if(*p!=TR_RBRACKET)
		{
			LM_ERR("invalid value transformation: %.*s!\n",
					in->len, in->s);
			goto error;
		}
		return p;
	} else if(name.len==7 && strncasecmp(name.s, "valueat", 7)==0) {
		t->subtype = TR_PL_VALUEAT;
		if(*p!=TR_PARAM_MARKER)
		{
			LM_ERR("invalid name transformation: %.*s\n",
					in->len, in->s);
			goto error;
		}
		p++;
		_tr_parse_nparam(p, p0, tp, spec, n, sign, in, s)
		t->params = tp;
		while(is_in_str(p, in) && is_ws(*p)) p++;
		if(*p!=TR_RBRACKET)
		{
			LM_ERR("invalid name transformation: %.*s!\n",
					in->len, in->s);
			goto error;
		}
		return p;
	} else if(name.len==4 && strncasecmp(name.s, "name", 4)==0) {
		t->subtype = TR_PL_NAME;
		if(*p!=TR_PARAM_MARKER)
		{
			LM_ERR("invalid name transformation: %.*s\n",
					in->len, in->s);
			goto error;
		}
		p++;
		_tr_parse_nparam(p, p0, tp, spec, n, sign, in, s)
		t->params = tp;
		while(is_in_str(p, in) && is_ws(*p)) p++;
		if(*p!=TR_RBRACKET)
		{
			LM_ERR("invalid name transformation: %.*s!\n",
					in->len, in->s);
			goto error;
		}
		return p;
	} else if(name.len==5 && strncasecmp(name.s, "count", 5)==0) {
		t->subtype = TR_PL_COUNT;
		return p;
	}

	LM_ERR("unknown transformation: %.*s/%.*s!\n",
			in->len, in->s, name.len, name.s);
error:
	if(spec)
		pv_spec_free(spec);
	return NULL;
}

char* tr_parse_nameaddr(str* in, trans_t *t)
{
	char *p;
	str name;
	char *p0;
	char *ps;
	str s;
	pv_spec_t *spec = NULL;
	tr_param_t *tp = NULL;


	if(in==NULL || t==NULL)
		return NULL;

	p = in->s;
	name.s = in->s;

	/* find next token */
	while(is_in_str(p, in) && *p!=TR_PARAM_MARKER && *p!=TR_RBRACKET) p++;
	if(*p=='\0')
	{
		LM_ERR("invalid transformation: %.*s\n",
				in->len, in->s);
		goto error;
	}
	name.len = p - name.s;
	trim(&name);

	if(name.len==3 && strncasecmp(name.s, "uri", 3)==0)
	{
		t->subtype = TR_NA_URI;
		return p;
	} else if(name.len==3 && strncasecmp(name.s, "len", 3)==0)
	{
		t->subtype = TR_NA_LEN;
		return p;
	} else if(name.len==4 && strncasecmp(name.s, "name", 4)==0) {
		t->subtype = TR_NA_NAME;
		return p;
	} else if(name.len==5 && strncasecmp(name.s, "param", 5)==0) {
		t->subtype = TR_NA_PARAM;
		if(*p!=TR_PARAM_MARKER)
		{
			LM_ERR("invalid value transformation: %.*s\n",
					in->len, in->s);
			goto error;
		}
		p++;
		tr_parse_sparam(p, p0, tp, spec, ps, in, s);
		t->params = tp;
		tp = 0;
		trim_ws(p);
		if(*p!=TR_RBRACKET)
		{
			LM_ERR("invalid value transformation: %.*s!\n",
					in->len, in->s);
			goto error;
		}
		return p;
	} else if(name.len==6 && strncasecmp(name.s, "params", 6)==0) {
		t->subtype = TR_NA_PARAMS;
		return p;
	}

	LM_ERR("unknown transformation: %.*s/%.*s/%d!\n", in->len, in->s,
			name.len, name.s, name.len);
error:
	return NULL;
}

char * tr_parse_csv(str *in, trans_t *t)
{
	char *p;
	str name;
	pv_spec_t *spec = NULL;
	tr_param_t *tp = NULL;
	char *p0;
	str s;
	int n;
	int sign;

	if (in == NULL || t == NULL)
		return NULL;

	p = in->s;
	name.s = in->s;

	/* find next token */
	while (is_in_str(p,in) && *p!=TR_PARAM_MARKER && *p!=TR_RBRACKET) p++;
	if (*p == '\0')
	{
		LM_ERR("invalid transformation: %.*s\n",in->len,in->s);
		return NULL;
	}

	name.len = p - name.s;
	trim(&name);

	if (name.len==5 && strncasecmp(name.s,"count",5)==0)
	{
		t->subtype = TR_CSV_COUNT;
		return p;
	}
	else if (name.len==5 && strncasecmp(name.s,"value",5)==0)
	{
		t->subtype = TR_CSV_VALUEAT;
		if(*p!=TR_PARAM_MARKER)
		{
			LM_ERR("invalid name transformation: %.*s\n",
					in->len, in->s);
			goto error;
		}
		p++;
		_tr_parse_nparam(p, p0, tp, spec, n, sign, in, s)
		t->params = tp;
		tp = 0;
		while(is_in_str(p, in) && is_ws(*p)) p++;
		if(*p!=TR_RBRACKET)
		{
			LM_ERR("invalid name transformation: %.*s!\n",
					in->len, in->s);
			goto error;
		}
		return p;
	}

	LM_ERR("unknown transformation: %.*s/%.*s/%d!\n", in->len, in->s,
			name.len, name.s, name.len);
error:
	return NULL;

}

char * tr_parse_sdp(str *in, trans_t *t)
{
	char *p;
	char *p0;
	char *ps;
	str name;
	pv_spec_t *spec = NULL;
	tr_param_t *tp = NULL;
	str s;
	int n;
	int sign;

	if (in == NULL || t == NULL)
		return NULL;

	p = in->s;
	name.s = in->s;

	/* find next token */
	while (is_in_str(p,in) && *p!=TR_PARAM_MARKER && *p!=TR_RBRACKET) p++;
	if (*p == '\0')
	{
		LM_ERR("invalid transformation: %.*s\n",in->len,in->s);
		return NULL;
	}

	name.len = p - name.s;
	trim(&name);

	if (name.len==4 && strncasecmp(name.s,"line",4)==0)
	{
		t->subtype = TR_SDP_LINEAT;
		if(*p!=TR_PARAM_MARKER)
		{
			LM_ERR("invalid lineat transformation: %.*s!\n", in->len, in->s);
			goto error;
		}
		p++;
		tr_parse_sparam(p, p0, tp, spec,ps, in, s);
		t->params = tp;
		tp = 0;
		trim_ws(p);
		if(*p!=TR_PARAM_MARKER)
		{
			/* lineat has only one parameter */
			tp = (tr_param_t*)pkg_malloc(sizeof(tr_param_t));
			if (!tp)
			{
				LM_ERR("no more pkg memory\n");
				goto error;
			}
			memset(tp, 0, sizeof(tr_param_t));
			tp->type = TR_PARAM_NUMBER;
			tp->v.n = 0;
			t->params->next = tp;
			LM_DBG("sdp.lineat with only one parameter. default = 1\n");
			return p;
		}
		p++;
		if (spec)
		{
			pkg_free(spec);
			spec = NULL;
		}

		_tr_parse_nparam(p, p0, tp, spec,n,sign, in, s);
		if(tp->type==TR_PARAM_NUMBER && tp->v.n<0)
		{
			LM_ERR("lineat negative argument\n");
			goto error;
		}
		t->params->next = tp;
		tp = 0;
		while(is_in_str(p, in) && is_ws(*p)) p++;
		if(*p!=TR_RBRACKET)
		{
			LM_ERR("invalid lineat transformation: %.*s!!\n",
				in->len, in->s);
			goto error;
		}

		return p;
	}

	LM_ERR("unknown transformation: %.*s/%.*s/%d!\n", in->len, in->s,
			name.len, name.s, name.len);
error:
	return NULL;
}

char * tr_parse_ip(str *in, trans_t *t)
{
	char *p;
	str name;

	if (in == NULL || t == NULL)
		return NULL;

	p = in->s;
	name.s = in->s;

	/* find next token */
	while (is_in_str(p,in) && *p!=TR_PARAM_MARKER && *p!=TR_RBRACKET) p++;
	if (*p == '\0')
	{
		LM_ERR("invalid transformation: %.*s\n",in->len,in->s);
		goto error;
	}

	name.len = p - name.s;
	trim(&name);

	if (name.len==6 && strncasecmp(name.s,"family",6)==0)
	{
		t->subtype = TR_IP_FAMILY;
		return p;
	}
	else if (name.len==4 && strncasecmp(name.s,"ntop",4)==0)
	{
		t->subtype = TR_IP_NTOP;
		return p;
	}
	else if (name.len == 4 && strncasecmp(name.s,"isip",4) == 0) {
		t->subtype = TR_IP_ISIP;
		return p;
	} else if (name.len == 4 && strncasecmp(name.s,"pton",4) == 0) {
		t->subtype = TR_IP_PTON;
		return p;
	} else if (name.len == 7 && strncasecmp(name.s,"resolve",7) == 0) {
		t->subtype = TR_IP_RESOLVE;
		return p;
	}


	LM_ERR("unknown transformation: %.*s/%.*s/%d!\n", in->len, in->s,
			name.len, name.s, name.len);
error:
	return NULL;

}

char* tr_parse_re(str *in,trans_t *t)
{
	char *p,*p0,*ps;
	str name,s;
	pv_spec_t *spec = NULL;
	tr_param_t *tp = NULL;

	if (in == NULL || t == NULL)
		return NULL;

	p = in->s;
	name.s = in->s;

	/* find next token */
	while (is_in_str(p,in) && *p!=TR_PARAM_MARKER && *p!=TR_RBRACKET) p++;
	if (*p == '\0')
	{
		LM_ERR("invalid transformation: %.*s\n",in->len,in->s);
		goto error;
	}

	name.len = p - name.s;
	trim(&name);

	if (name.len==5 && strncasecmp(name.s,"subst",5)==0)
	{
		t->subtype = TR_RE_SUBST;
		if(*p!=TR_PARAM_MARKER)
		{
			LM_ERR("invalid value transformation: %.*s\n",
					in->len, in->s);
			goto error;
		}
		p++;
		LM_INFO("preparing to parse param\n");
		tr_parse_sparam(p, p0, tp, spec, ps, in, s);
		t->params = tp;
		tp = 0;
		trim_ws(p);
		if(*p!=TR_RBRACKET)
		{
			LM_ERR("invalid value transformation: %.*s!\n",
					in->len, in->s);
			goto error;
		}
		return p;
	}

	LM_ERR("unknown transformation: %.*s/%.*s/%d!\n", in->len, in->s,
			name.len, name.s, name.len);
error:
	return NULL;
}

void destroy_transformation(trans_t *t)
{
	tr_param_t *tp;
	tr_param_t *tp0;
	if(t==NULL) return;

	tp = t->params;
	while(tp)
	{
		tp0 = tp;
		tp = tp->next;
		free_tr_param(tp0);
	}
	memset(t, 0, sizeof(trans_t));
}

void free_transformation(trans_t *t)
{
	trans_t *t0;

	while(t)
	{
		t0 = t;
		t = t->next;
		destroy_transformation(t0);
		pkg_free(t0);
	}
}

void free_tr_param(tr_param_t *tp)
{
	tr_param_t *tp0;

	if(tp==NULL) return;
	while(tp)
	{
		tp0 = tp;
		tp = tp->next;
		if(tp0->type==TR_PARAM_SPEC)
			pv_spec_free((pv_spec_t*)tp0->v.data);
		pkg_free(tp0);
	}
}
