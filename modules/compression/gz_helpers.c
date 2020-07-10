/*
 * Copyright (C) 2014 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zlib.h"

#include "compression_helpers.h"
#include "../../ut.h"

/*
 *
 */
int gzip_compress(unsigned char* in, unsigned long ilen, str* out, unsigned long* olen, int level)
{
	z_stream zlibStream;
	int rc, neededSize;

	if (!in || ilen == 0) {
		LM_ERR("nothing to compress\n");
		return -1;
	}

	zlibStream.zalloc = Z_NULL; //deflateInit2 will set all the funcions
	zlibStream.zfree = Z_NULL;  //set now with Z_NULL
	zlibStream.opaque = Z_NULL;
	zlibStream.total_out = 0;   //Total number of out bytes produced so far
	zlibStream.next_in = in;
	zlibStream.avail_in = ilen;

	/*
		Deflate init parameters:
			zlibStream - input data
			level - compression level(1-9)
			Z_DEFLATED - compression method(only Z_DEFLATED)
			(15+16) - base two log for the history buffer.
				For simple deflate should be between
				8-15.16 is added for gzip compression
			level - memory allocated for internal compression
				state. 8 is default, 1 means less mem
				9 maximum mem for better performance
			Z_DEFAULT_STRATEGY - tune the algorithm.Also
					Z_FILTERED(data prduced by a filter),
					Z_HUFFMAN_ONLY force huffman encoding
					only
 	*/

	rc = deflateInit2(&zlibStream, level, Z_DEFLATED,
				(15+16), level, Z_DEFAULT_STRATEGY);

	if (rc != Z_OK) {
		return rc;
	}

	/* zlib doc states that dest buffer size must be 10% +12 larger than
		the input buffer */
	neededSize = (int)((float)ilen * 1.1 + 12);

	if (!out->s) {
		out->s = pkg_malloc(neededSize);
		out->len = neededSize;
		if (!out)
			goto memerr;
	} else if (ilen > out->len) {
		out->s = pkg_realloc(out->s, neededSize);
		out->len = neededSize;
		if (!out->s)
			goto memerr;
	}

	do {
		zlibStream.next_out = (unsigned char*)(out->s + zlibStream.total_out);
		zlibStream.avail_out = neededSize - zlibStream.total_out;

		rc = deflate(&zlibStream, Z_FINISH);
	} while (rc == Z_OK);

	if (rc != Z_STREAM_END) {
		deflateEnd(&zlibStream);
		return rc;
	}

	*olen = zlibStream.total_out;
	deflateEnd(&zlibStream);

	return Z_OK;
memerr:
	LM_ERR("no more pkg mem\n");
	return -1;
}

/*
 *
 */
int gzip_uncompress(unsigned char* in, unsigned long ilen, str* out, unsigned long* olen)
{
	z_stream zlibStream;
	int rc, neededSize;

	if (!in || !ilen) {
		LM_ERR("nothing to compress\n");
		return -1;
	}

	/* Gzip holds the length of the original message
		in the last 4 bytes */
	*olen = (in[ilen-1] << 24) + (in[ilen-2] << 16) +
				(in[ilen-3] << 8) + in[ilen-4];
	neededSize = *olen+1; /*'\0'*/

	zlibStream.zalloc = Z_NULL;
	zlibStream.zfree = Z_NULL;
	zlibStream.opaque = Z_NULL;
	zlibStream.avail_in = 0;
	zlibStream.next_in = Z_NULL;
	zlibStream.total_out = 0;

	/* zlib doc says that window for inflateInit
		must be at least equal with the window
		used for compression */
	rc = inflateInit2(&zlibStream, (15+16));

	if (rc != Z_OK)
		return rc;

	if (!out->s) {
		out->s = pkg_malloc(neededSize);
		out->len = neededSize;
		if (!out->s)
			goto memerr;
	} else if (*olen > out->len) {
		out->s = pkg_realloc(out->s, neededSize);
		out->len = neededSize;
		if (!out->s)
			goto memerr;
	}

	zlibStream.avail_in = ilen;
	zlibStream.next_in = in;

	do {
		zlibStream.avail_out = neededSize - zlibStream.total_out;
		zlibStream.next_out = (unsigned char*)out->s +
							zlibStream.total_out;

		rc = inflate(&zlibStream, Z_NO_FLUSH);
		switch (rc) {
			case Z_NEED_DICT:
				rc = Z_DATA_ERROR;
				/* fall through */
		case Z_DATA_ERROR:
		case Z_MEM_ERROR:
		case Z_BUF_ERROR:
			inflateEnd(&zlibStream);
			return rc;
		}
	} while (rc != Z_STREAM_END);

	deflateEnd(&zlibStream);
	return Z_OK;
memerr:
	inflateEnd(&zlibStream);
	LM_ERR("no more pkg mem\n");
	return -1;
}
