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

int ctr(const char *_rec, str *tz, unsigned int *ts)
{
	str rec;
	int rc;

	/* it seems check_time_rec() writes to the input buffer, so dup it! */
	rec.len = strlen(_rec);
	rec.s = shm_malloc(rec.len + 1);
	memcpy(rec.s, _rec, rec.len);
	rec.s[rec.len] = '\0';

	rc = check_time_rec(NULL, &rec, tz, ts);
	shm_free(rec.s);

	return rc;
}

void test_check_time_rec(void)
{
	int rc1, rc2;
	str utc = str_init("UTC"), ro = str_init("Europe/Bucharest"),
	     us = str_init("America/Chihuahua"), au = str_init("Pacific/Auckland");
	unsigned int now = 1591357895 /* 2020-06-05 (Friday), 11:51:35 UTC */;

	/* no timezone, DTSTART is inclusive, local time */
	ok(ctr("20200605T115135|20200605T230000", NULL, &now) == 1);
	ok(ctr("20200605T115136|20200605T230000", NULL, &now) == -1);

	/* no timezone, DTEND is non-inclusive, local time */
	ok(ctr("20200101T000000|20200605T115135", NULL, &now) == -1);
	ok(ctr("20200101T000000|20200605T115136", NULL, &now) == 1);


	/* DTSTART is inclusive, UTC */
	ok(ctr("20200605T115135|20200605T230000", &utc, &now) == 1);
	ok(ctr("20200605T115136|20200605T230000", &utc, &now) == -1);

	/* DTEND is non-inclusive, UTC */
	ok(ctr("20200101T000000|20200605T115135", &utc, &now) == -1);
	ok(ctr("20200101T000000|20200605T115136", &utc, &now) == 1);


	/* DTSTART is inclusive, RO timezone */
	ok(ctr("20200605T115135|20200605T230000", &ro, &now) == 1);
	ok(ctr("20200605T115136|20200605T230000", &ro, &now) == -1);

	/* DTEND is non-inclusive, RO timezone */
	ok(ctr("20200101T000000|20200605T115135", &ro, &now) == -1);
	ok(ctr("20200101T000000|20200605T115136", &ro, &now) == 1);


	/* DTSTART is inclusive, AU timezone */
	ok(ctr("20200605T115135|20200605T230000", &au, &now) == 1);
	ok(ctr("20200605T115136|20200605T230000", &au, &now) == -1);

	/* DTEND is non-inclusive, AU timezone */
	ok(ctr("20200101T000000|20200605T115135", &au, &now) == -1);
	ok(ctr("20200101T000000|20200605T115136", &au, &now) == 1);

	              /* time recurrence checks */

	/* local timezone */
	ok(ctr("19990101T000000|19990101T115135||DAILY", NULL, &now) == -1);
	ok(ctr("19990101T000000|19990101T115136||DAILY", NULL, &now) == 1);

	/* custom timezone */
	ok(ctr("19990101T000000|19990101T115135||DAILY", &ro, &now) == -1);
	ok(ctr("19990101T000000|19990101T115136||DAILY", &ro, &now) == 1);

	/* local timezone, daily overlapping, over 1d -> always match! */
	ok(ctr("19981230T235959|19990101T115135||DAILY", &ro, &now) == 1);

	/* local timezone, weekly overlapping, over 1w -> always match! */
	ok(ctr("19981220T235959|19990101T115135||WEEKLY", &ro, &now) == 1);
	ok(ctr("19981231T235959|19990101T115135||WEEKLY", &ro, &now) == -1);

	/* local timezone, monthly overlapping, over 1m -> always match! */
	ok(ctr("19981120T235959|19990101T115135||MONTHLY", &ro, &now) == 1);
	ok(ctr("19981210T235959|19990101T115135||MONTHLY", &ro, &now) == -1);

	/* local timezone, yearly overlapping, over 1y -> always match! */
	ok(ctr("19971131T235959|19990101T115135||YEARLY", &ro, &now) == 1);
	ok(ctr("19981101T235959|19990101T115135||YEARLY", &ro, &now) == -1);


	/* local timezone, daily recurring but under 1d! */
	ok(ctr("19990101T000000|19990101T115135||DAILY", &ro, &now) == -1);
	ok(ctr("19990101T000000|19990101T115136||DAILY", &ro, &now) == 1);
	ok(ctr("19981231T115136|19990101T115135||DAILY", &ro, &now) == -1);
	ok(ctr("19981231T115137|19990101T115136||DAILY", &ro, &now) == 1);

	/* local timezone, weekly recursion is ok but day is wrong! */
	ok(ctr("20200111T115134|20200111T115136||WEEKLY", &ro, &now) == -1);

	/* local timezone, weekly recurring but under 1w! */
	ok(ctr("20200110T115136|20200117T115135||WEEKLY", &ro, &now) == -1);
	ok(ctr("20200109T115136|20200116T115135||WEEKLY", &ro, &now) == 1);

	ok(ctr("20200110T235959|20200112T115136||WEEKLY", &ro, &now) == -1);
	ok(ctr("20200106T235959|20200110T115136||WEEKLY", &ro, &now) == 1);
	ok(ctr("20200106T235959|20200110T115135||WEEKLY", &ro, &now) == -1);
	ok(ctr("20200112T235959|20200118T115135||WEEKLY", &ro, &now) == 1);
	ok(ctr("20200112T235959|20200117T115135||WEEKLY", &ro, &now) == -1);
	ok(ctr("20200109T235959|20200117T115135||WEEKLY", &ro, &now) == 1);

	/* local timezone, monthly recurring but under 1m! */
	ok(ctr("20200101T000000|20200105T115135||MONTHLY", &ro, &now) == -1);
	ok(ctr("20200101T000000|20200105T115136||MONTHLY", &ro, &now) == 1);

	ok(ctr("20200101T235959|20200104T115136||MONTHLY", &ro, &now) == -1);
	ok(ctr("20200101T235959|20200105T115135||MONTHLY", &ro, &now) == -1);
	ok(ctr("20200101T235959|20200105T115136||MONTHLY", &ro, &now) == 1);
	ok(ctr("20200101T235959|20200106T115135||MONTHLY", &ro, &now) == 1);

	/* local timezone, yearly recurring but under 1y! */
	ok(ctr("19990101T000000|19990606T115135||YEARLY", &ro, &now) == -1);
	ok(ctr("19990101T000000|19990606T115136||YEARLY", &ro, &now) == 1);

	ok(ctr("19990607T235959|20000604T115136||YEARLY", &ro, &now) == -1);
	ok(ctr("19990607T235959|20000605T115135||YEARLY", &ro, &now) == -1);
	ok(ctr("19990607T235959|20000605T115136||YEARLY", &ro, &now) == 1);
	ok(ctr("19990607T235959|20000606T115135||YEARLY", &ro, &now) == 1);

	/* disjoint intervals produce differing results regardless of TZ & time! */
	rc1 = ctr("20200101T000000|20200101T120000||DAILY", &us, NULL);
	rc2 = ctr("20200101T120000|20200102T000000||DAILY", &us, NULL);
	ok(rc1 != rc2);
	rc2 = ctr("20200101T120000|20200101T235959||DAILY", &us, NULL);
	ok(rc1 != rc2);

	rc1 = ctr("20200101T000000|20200101T120000||DAILY", &au, NULL);
	rc2 = ctr("20200101T120000|20200102T000000||DAILY", &au, NULL);
	ok(rc1 != rc2);
	rc2 = ctr("20200101T120000|20200101T235959||DAILY", &au, NULL);
	ok(rc1 != rc2);

	rc1 = ctr("20200101T000000|20200101T120000||DAILY", &utc, NULL);
	rc2 = ctr("20200101T120000|20200102T000000||DAILY", &utc, NULL);
	ok(rc1 != rc2);
	rc2 = ctr("20200101T120000|20200101T235959||DAILY", &utc, NULL);
	ok(rc1 != rc2);
}


void mod_tests(void)
{
	test_check_time_rec();
}
