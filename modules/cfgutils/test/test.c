/*
 * Copyright (C) 2020 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <tap.h>

#include "../../../parser/msg_parser.h"
#include "../../../str.h"
#include "../../../ut.h"
#include "../../../time_rec.h"

extern int check_time_rec(struct sip_msg *_, str *time_str, str *tz,
                          unsigned int *ptime);

void mod_tests(void)
{
	str rec = STR_NULL;
	str utc = str_init("UTC"), ro = str_init("Europe/Bucharest"),
	     au = str_init("Pacific/Auckland");
	unsigned int now = 1591357895 /* 2020-06-05, 11:51:35 UTC */;

	/* no timezone, DTSTART is inclusive, local time */
	shm_str_sync(&rec, _str("20200605T115135|20200605T230000"));
	ok(check_time_rec(NULL, &rec, NULL, &now) == 1, "tmrec-1");
	shm_str_sync(&rec, _str("20200605T115136|20200605T230000"));
	ok(check_time_rec(NULL, &rec, NULL, &now) == -1, "tmrec-2");

	/* no timezone, DTEND is non-inclusive, local time */
	shm_str_sync(&rec, _str("20200101T000000|20200605T115135"));
	ok(check_time_rec(NULL, &rec, NULL, &now) == -1, "tmrec-3");
	shm_str_sync(&rec, _str("20200101T000000|20200605T115136"));
	ok(check_time_rec(NULL, &rec, NULL, &now) == 1, "tmrec-4");


	/* DTSTART is inclusive, UTC */
	shm_str_sync(&rec, _str("20200605T115135|20200605T230000"));
	ok(check_time_rec(NULL, &rec, &utc, &now) == 1, "tmrec-5");
	shm_str_sync(&rec, _str("20200605T115136|20200605T230000"));
	ok(check_time_rec(NULL, &rec, &utc, &now) == -1, "tmrec-6");

	/* DTEND is non-inclusive, UTC */
	shm_str_sync(&rec, _str("20200101T000000|20200605T115135"));
	ok(check_time_rec(NULL, &rec, &utc, &now) == -1, "tmrec-7");
	shm_str_sync(&rec, _str("20200101T000000|20200605T115136"));
	ok(check_time_rec(NULL, &rec, &utc, &now) == 1, "tmrec-8");


	/* DTSTART is inclusive, RO timezone */
	shm_str_sync(&rec, _str("20200605T115135|20200605T230000"));
	ok(check_time_rec(NULL, &rec, &ro, &now) == 1, "tmrec-9");
	shm_str_sync(&rec, _str("20200605T115136|20200605T230000"));
	ok(check_time_rec(NULL, &rec, &ro, &now) == -1, "tmrec-10");

	/* DTEND is non-inclusive, RO timezone */
	shm_str_sync(&rec, _str("20200101T000000|20200605T115135"));
	ok(check_time_rec(NULL, &rec, &ro, &now) == -1, "tmrec-11");
	shm_str_sync(&rec, _str("20200101T000000|20200605T115136"));
	ok(check_time_rec(NULL, &rec, &ro, &now) == 1, "tmrec-12");


	/* DTSTART is inclusive, AU timezone */
	shm_str_sync(&rec, _str("20200605T115135|20200605T230000"));
	ok(check_time_rec(NULL, &rec, &au, &now) == 1, "tmrec-13");
	shm_str_sync(&rec, _str("20200605T115136|20200605T230000"));
	ok(check_time_rec(NULL, &rec, &au, &now) == -1, "tmrec-14");

	/* DTEND is non-inclusive, AU timezone */
	shm_str_sync(&rec, _str("20200101T000000|20200605T115135"));
	ok(check_time_rec(NULL, &rec, &au, &now) == -1, "tmrec-15");
	shm_str_sync(&rec, _str("20200101T000000|20200605T115136"));
	ok(check_time_rec(NULL, &rec, &au, &now) == 1, "tmrec-16");
}
