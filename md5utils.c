/*
 * Copyright (C) 2007 1&1 Internet AG
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
 * \brief OpenSIPS MD5 handling functions
 */


#include <stdio.h>
#include <sys/stat.h>

#include "md5global.h"
#include "md5.h"
#include "md5utils.h"
#include "dprint.h"
#include "ut.h"


/*! \brief
  * Calculate a MD5 digests over a string array and stores
  * the result in the destination char array.
  * This function assumes 32 bytes in the destination buffer.
  * \param dest destination
  * \param src string input array
  * \param size elements in the input array
  */
void MD5StringArray(char *dest, str src[], unsigned int size)
{
	MD5_CTX context;
	unsigned char digest[16];
	int i, len;
	char *tmp;

	MD5Init (&context);
	for (i=0; i < size; i++) {
		trim_len(len, tmp, src[i]);
		MD5Update(&context, tmp, len);
	}
	MD5Final(digest, &context);

	string2hex(digest, 16, dest);
	LM_DBG("MD5 calculated: %.*s\n", MD5_LEN, dest);
}

/*! \brief
  * Calculate a MD5 digest over a file.
  * This function assumes 32 bytes in the destination buffer.
  * \param dest destination
  * \param file_name file for that the digest should be calculated
  * \return zero on success, negative on errors
  */
int MD5File(char *dest, const char *file_name)
{
	if (!dest || !file_name) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}

	MD5_CTX context;
	FILE *input;
	unsigned char buffer[32768];
	unsigned char hash[16];
	unsigned int counter, size;

	struct stat stats;
    if (stat(file_name, &stats) != 0) {
		LM_ERR("could not stat file %s\n", file_name);
		return -1;
	}
	size = stats.st_size;

	MD5Init(&context);
	if((input = fopen(file_name, "rb")) == NULL) {
		LM_ERR("could not open file %s\n", file_name);
		return -1;
	}

	while(size) {
		counter = (size > sizeof(buffer)) ? sizeof(buffer) : size;
		if ((counter = fread(buffer, 1, counter, input)) <= 0) {
			fclose(input);
			return -1;
		}
		MD5Update(&context, buffer, counter);
		size -= counter;
	}
	fclose(input);
	MD5Final(hash, &context);

	string2hex(hash, 16, dest);
	LM_DBG("MD5 calculated: %.*s for file %s\n", MD5_LEN, dest, file_name);

	return 0;
}
