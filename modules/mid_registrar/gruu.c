/*
 * Handling for Globally Routable UA URIs
 *
 * This module is intended to be used as a middle layer SIP component in
 * environments where a large proportion of SIP UAs (e.g. mobile devices)
 * register at high enough frequencies that they actually degrade the
 * performance of their registrars.
 *
 * Copyright (C) 2016-2020 OpenSIPS Solutions
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

#include "../../ut.h"
#include "../../data_lump.h"

#include "../../lib/reg/common.h"

#include "mid_registrar.h"
#include "lookup.h"
#include "encode.h"
#include "gruu.h"


#define MAX_TGRUU_SIZE 255
#define GR_MAGIC 73
str default_gruu_secret=str_init("0p3nS1pS");

int calc_temp_gruu_len(str* aor,str* instance,str *callid)
{
	int time_len,temp_gr_len;

	int2str((unsigned long)get_act_time(),&time_len);
	temp_gr_len = time_len + aor->len + instance->len - 2 + callid->len + 3; /* <instance> and blank spaces */
	temp_gr_len = (temp_gr_len/3 + (temp_gr_len%3?1:0))*4; /* base64 encoding */
	return temp_gr_len;
}

#define MAX_TEMP_GRUU_SIZE	255
static char temp_gruu_buf[MAX_TEMP_GRUU_SIZE];
char * build_temp_gruu(str *aor,str *instance,str *callid,int *len)
{
	int time_len,i;
	char *p;
	char *time_str = int2str((unsigned long)get_act_time(),&time_len);
	str *magic;

	*len = time_len + aor->len + instance->len + callid->len + 3 - 2; /* +3 blank spaces, -2 discarded chars of instance in memcpy below */
	p = temp_gruu_buf;

	memcpy(p,time_str,time_len);
	p+=time_len;
	*p++=' ';

	memcpy(p,aor->s,aor->len);
	p+=aor->len;
	*p++=' ';

	memcpy(p,instance->s+1,instance->len-2);
	p+=instance->len-2;
	*p++=' ';

	memcpy(p,callid->s,callid->len);

	LM_DBG("build temp gruu [%.*s]\n",*len,temp_gruu_buf);
	if (gruu_secret.s != NULL)
		magic = &gruu_secret;
	else
		magic = &default_gruu_secret;

	for (i=0;i<*len;i++)
		temp_gruu_buf[i] ^= magic->s[i%magic->len];
	return temp_gruu_buf;
}

