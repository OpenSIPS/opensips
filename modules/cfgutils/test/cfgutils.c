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


void test_check_time_rec(void)
{
	/* it seems check_time_rec() writes to the input buffer, so dup it! */
	#define init_rec(p) \
		do { \
			if (rec.s) \
				shm_free(rec.s); \
			rec.len = strlen(p); \
			rec.s = shm_malloc(rec.len + 1); \
			memcpy(rec.s, p, rec.len); \
			rec.s[rec.len] = '\0'; \
		} while (0)

	str rec = STR_NULL;
	str utc = str_init("UTC"), ro = str_init("Europe/Bucharest"),
	     au = str_init("Pacific/Auckland");
	unsigned int now = 1591357895 /* 2020-06-05 (Friday), 11:51:35 UTC */;

	/* no timezone, DTSTART is inclusive, local time */
	init_rec("20200605T115135|20200605T230000");
	ok(check_time_rec(NULL, &rec, NULL, &now) == 1);
	init_rec("20200605T115136|20200605T230000");
	ok(check_time_rec(NULL, &rec, NULL, &now) == -1);

	/* no timezone, DTEND is non-inclusive, local time */
	init_rec("20200101T000000|20200605T115135");
	ok(check_time_rec(NULL, &rec, NULL, &now) == -1);
	init_rec("20200101T000000|20200605T115136");
	ok(check_time_rec(NULL, &rec, NULL, &now) == 1);


	/* DTSTART is inclusive, UTC */
	init_rec("20200605T115135|20200605T230000");
	ok(check_time_rec(NULL, &rec, &utc, &now) == 1);
	init_rec("20200605T115136|20200605T230000");
	ok(check_time_rec(NULL, &rec, &utc, &now) == -1);

	/* DTEND is non-inclusive, UTC */
	init_rec("20200101T000000|20200605T115135");
	ok(check_time_rec(NULL, &rec, &utc, &now) == -1);
	init_rec("20200101T000000|20200605T115136");
	ok(check_time_rec(NULL, &rec, &utc, &now) == 1);


	/* DTSTART is inclusive, RO timezone */
	init_rec("20200605T115135|20200605T230000");
	ok(check_time_rec(NULL, &rec, &ro, &now) == 1);
	init_rec("20200605T115136|20200605T230000");
	ok(check_time_rec(NULL, &rec, &ro, &now) == -1);

	/* DTEND is non-inclusive, RO timezone */
	init_rec("20200101T000000|20200605T115135");
	ok(check_time_rec(NULL, &rec, &ro, &now) == -1);
	init_rec("20200101T000000|20200605T115136");
	ok(check_time_rec(NULL, &rec, &ro, &now) == 1);


	/* DTSTART is inclusive, AU timezone */
	init_rec("20200605T115135|20200605T230000");
	ok(check_time_rec(NULL, &rec, &au, &now) == 1);
	init_rec("20200605T115136|20200605T230000");
	ok(check_time_rec(NULL, &rec, &au, &now) == -1);

	/* DTEND is non-inclusive, AU timezone */
	init_rec("20200101T000000|20200605T115135");
	ok(check_time_rec(NULL, &rec, &au, &now) == -1);
	init_rec("20200101T000000|20200605T115136");
	ok(check_time_rec(NULL, &rec, &au, &now) == 1);

	              /* time recurrence checks */

	/* local timezone */
	init_rec("19990101T000000|19990101T115135||DAILY");
	ok(check_time_rec(NULL, &rec, NULL, &now) == -1);
	init_rec("19990101T000000|19990101T115136||DAILY");
	ok(check_time_rec(NULL, &rec, NULL, &now) == 1);

	/* custom timezone */
	init_rec("19990101T000000|19990101T115135||DAILY");
	ok(check_time_rec(NULL, &rec, &ro, &now) == -1);
	init_rec("19990101T000000|19990101T115136||DAILY");
	ok(check_time_rec(NULL, &rec, &ro, &now) == 1);


	/* local timezone, daily overlapping, over 1d -> always match! */
	init_rec("19981230T235959|19990101T115135||DAILY");
	ok(check_time_rec(NULL, &rec, &ro, &now) == 1);

	/* local timezone, weekly overlapping, over 1w -> always match! */
	init_rec("19981220T235959|19990101T115135||WEEKLY");
	ok(check_time_rec(NULL, &rec, &ro, &now) == 1);
	init_rec("19981231T235959|19990101T115135||WEEKLY");
	ok(check_time_rec(NULL, &rec, &ro, &now) == -1);

	/* local timezone, monthly overlapping, over 1m -> always match! */
	init_rec("19981120T235959|19990101T115135||MONTHLY");
	ok(check_time_rec(NULL, &rec, &ro, &now) == 1);
	init_rec("19981210T235959|19990101T115135||MONTHLY");
	ok(check_time_rec(NULL, &rec, &ro, &now) == -1);

	/* local timezone, yearly overlapping, over 1y -> always match! */
	init_rec("19971131T235959|19990101T115135||YEARLY");
	ok(check_time_rec(NULL, &rec, &ro, &now) == 1);
	init_rec("19981101T235959|19990101T115135||YEARLY");
	ok(check_time_rec(NULL, &rec, &ro, &now) == -1);


	/* local timezone, daily recurring but under 1d! */
	init_rec("19990101T000000|19990101T115135||DAILY");
	ok(check_time_rec(NULL, &rec, &ro, &now) == -1);
	init_rec("19990101T000000|19990101T115136||DAILY");
	ok(check_time_rec(NULL, &rec, &ro, &now) == 1);
	init_rec("19981231T115136|19990101T115135||DAILY");
	ok(check_time_rec(NULL, &rec, &ro, &now) == -1);
	init_rec("19981231T115137|19990101T115136||DAILY");
	ok(check_time_rec(NULL, &rec, &ro, &now) == 1);

	/* local timezone, weekly recursion is ok but day is wrong! */
	init_rec("20200111T115134|20200111T115136||WEEKLY"); /* 2020-01-06: Mon */
	ok(check_time_rec(NULL, &rec, &ro, &now) == -1);

	/* local timezone, weekly recurring but under 1w! */
	init_rec("20200110T115136|20200117T115135||WEEKLY");
	ok(check_time_rec(NULL, &rec, &ro, &now) == -1);
	init_rec("20200109T115136|20200116T115135||WEEKLY");
	ok(check_time_rec(NULL, &rec, &ro, &now) == 1);

	init_rec("20200110T235959|20200112T115136||WEEKLY");
	ok(check_time_rec(NULL, &rec, &ro, &now) == -1);
	init_rec("20200106T235959|20200110T115136||WEEKLY");
	ok(check_time_rec(NULL, &rec, &ro, &now) == 1);
	init_rec("20200106T235959|20200110T115135||WEEKLY");
	ok(check_time_rec(NULL, &rec, &ro, &now) == -1);
	init_rec("20200112T235959|20200118T115135||WEEKLY");
	ok(check_time_rec(NULL, &rec, &ro, &now) == 1);
	init_rec("20200112T235959|20200117T115135||WEEKLY");
	ok(check_time_rec(NULL, &rec, &ro, &now) == -1);
	init_rec("20200109T235959|20200117T115135||WEEKLY");
	ok(check_time_rec(NULL, &rec, &ro, &now) == 1);

	/* local timezone, monthly recurring but under 1m! */
	init_rec("20200101T000000|20200105T115135||MONTHLY");
	ok(check_time_rec(NULL, &rec, &ro, &now) == -1);
	init_rec("20200101T000000|20200105T115136||MONTHLY");
	ok(check_time_rec(NULL, &rec, &ro, &now) == 1);

	init_rec("20200101T235959|20200104T115136||MONTHLY");
	ok(check_time_rec(NULL, &rec, &ro, &now) == -1);
	init_rec("20200101T235959|20200105T115135||MONTHLY");
	ok(check_time_rec(NULL, &rec, &ro, &now) == -1);
	init_rec("20200101T235959|20200105T115136||MONTHLY");
	ok(check_time_rec(NULL, &rec, &ro, &now) == 1);
	init_rec("20200101T235959|20200106T115135||MONTHLY");
	ok(check_time_rec(NULL, &rec, &ro, &now) == 1);

	/* local timezone, yearly recurring but under 1y! */
	init_rec("19990101T000000|19990606T115135||YEARLY");
	ok(check_time_rec(NULL, &rec, &ro, &now) == -1);
	init_rec("19990101T000000|19990606T115136||YEARLY");
	ok(check_time_rec(NULL, &rec, &ro, &now) == 1);

	init_rec("19990607T235959|20000604T115136||YEARLY");
	ok(check_time_rec(NULL, &rec, &ro, &now) == -1);
	init_rec("19990607T235959|20000605T115135||YEARLY");
	ok(check_time_rec(NULL, &rec, &ro, &now) == -1);
	init_rec("19990607T235959|20000605T115136||YEARLY");
	ok(check_time_rec(NULL, &rec, &ro, &now) == 1);
	init_rec("19990607T235959|20000606T115135||YEARLY");
	ok(check_time_rec(NULL, &rec, &ro, &now) == 1);
}


void mod_tests(void)
{
	test_check_time_rec();
}
