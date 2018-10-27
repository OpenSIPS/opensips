/*
 * Copyright (C) 2013 OpenSIPS Solutions
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
 * -------
 * 2013-02-28: Created (Liviu)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rest_cb.h"

/**
 * write_func - callback; reallocates and extends the @body buffer each time.
 * @ptr:	pointer to the raw data
 * @size:	size of a block
 * @nmemb:	number of blocks
 * @body:	parameter previously set with the CURLOPT_WRITEDATA option
 */
size_t write_func(char *ptr, size_t size, size_t nmemb, void *body)
{
	int len = size * nmemb;
	str *buff = (str *)body;

#ifdef EXTRA_DEBUG
	LM_DBG("got body piece! bs: %lu, blocks: %lu\n", size, nmemb);
#endif

	if (len == 0)
		return 0;

	if (len < 0)
		len = strlen(ptr);

	buff->s = pkg_realloc(buff->s, buff->len + len + 1);
	if (!buff->s) {
		buff->len = 0;
		LM_ERR("No more pkg memory!\n");
		return E_OUT_OF_MEM;
	}

	memcpy(buff->s + buff->len, ptr, len);
	buff->len += len;
	buff->s[buff->len] = '\0';

	return len;
}

/**
 * header_func - callback; called once for each header. retrieves "Content-Type"
 * @ptr:	pointer to the current header info
 * @size:	size of a block
 * @nmemb:	number of blocks
 * @body:	parameter previously set with the CURLOPT_HEADERFUNCTION option
 */
size_t header_func(char *ptr, size_t size, size_t nmemb, void *userdata)
{
	int len, left;
	str *st = (str *)userdata;

	len = left = size * nmemb;

	if (len > CONTENT_TYPE_HDR_LEN && *ptr == 'C' &&
	    strncasecmp(ptr, HTTP_HDR_CONTENT_TYPE, CONTENT_TYPE_HDR_LEN) == 0) {

		ptr += CONTENT_TYPE_HDR_LEN + 1;
		left -= CONTENT_TYPE_HDR_LEN + 1;

		while (*ptr == ' ') {
			ptr++;
			left--;
		}

		st->s = pkg_realloc(st->s, left);
		if (!st->s) {
			LM_ERR("no more pkg mem\n");
			return E_OUT_OF_MEM;
		}

		st->len = left;
		memcpy(st->s, ptr, left);
	}

	LM_DBG("Received: %.*s\n", len, ptr);

	return len;
}

