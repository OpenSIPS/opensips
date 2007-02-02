/*
 * $Id$
 *
 * Copyright (C) 2007 voice-system.ro
 *
 * This file is part of openser, a free SIP server.
 *
 * openser is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * openser is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "ut.h"
#include "strcommon.h"

/*
 * add backslashes to special characters
 */
int escape_common(char *dst, char *src, int src_len)
{
	int i, j;

	if(dst==0 || src==0 || src_len<=0)
		return 0;
	j = 0;
	for(i=0; i<src_len; i++)
	{
		switch(src[i])
		{
			case '\'':
				dst[j++] = '\\';
				dst[j++] = src[i];
				break;
			case '\\':
				dst[j++] = '\\';
				dst[j++] = src[i];
				break;
			case '\0':
				dst[j++] = '\\';
				dst[j++] = '0';
				break;
			default:
				dst[j++] = src[i];
		}
	}
	return j;
}
/*
 * remove backslashes to special characters
 */
int unescape_common(char *dst, char *src, int src_len)
{
	int i, j;

	if(dst==0 || src==0 || src_len<=0)
		return 0;
	j = 0;
	i = 0;
	while(i<src_len)
	{
		if(src[i]=='\\' && i+1<src_len)
		{
			switch(src[i+1])
			{
				case '\'':
					dst[j++] = '\'';
					i++;
					break;
				case '\\':
					dst[j++] = '\\';
					i++;
					break;
				case '\0':
					dst[j++] = '\0';
					i++;
					break;
				default:
					dst[j++] = src[i];
			}
		} else {
			dst[j++] = src[i];
		}
		i++;
	}
	return j;
}

void compute_md5(char *dst, char *src, int src_len)
{
	MD5_CTX context;
	unsigned char digest[16];
	MD5Init (&context);
  	MD5Update (&context, src, src_len);
	MD5Final (digest, &context);
	string2hex(digest, 16, dst);
}
