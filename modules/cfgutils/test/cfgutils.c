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


#define TEST_TIME 1591357895U   /* 2020-06-05 (Friday), 11:51:35 UTC */;
#define UTC "UTC"
#define US  "America/Chihuahua" /* UTC-7, DST is ON at TEST_TIME (-6) */
#define RO  "Europe/Bucharest"  /* UTC+2, DST is ON at TEST_TIME (+3) */
#define AUS "Pacific/Auckland"  /* UTC+12, DST is OFF at TEST_TIME (+12) */

extern int check_time_rec(struct sip_msg *_, char *time_rec,
                          unsigned int *ptime);


int ctr(const char *_rec, time_t *ts)
{
	char *rec;
	int rc, len;
	time_t _ts;

	if (!ts) {
		_ts = time(NULL);
		ts = &_ts;
	}

	/* it seems _tmrec_check_str() writes to the input buffer, so dup it! */
	len = strlen(_rec);
	rec = shm_malloc(len + 1);
	memcpy(rec, _rec, len);
	rec[len] = '\0';

	rc = _tmrec_check_str(rec, *ts);
	shm_free(rec);

	return rc;
}


int cmtr(const char *_rec, unsigned int ts)
{
	char *rec;
	int rc1, rc2, len;
	tmrec *tr;

	/* it seems _tmrec_check_str() writes to the input buffer, so dup it! */
	len = strlen(_rec);
	rec = shm_malloc(len + 1);
	memcpy(rec, _rec, len);
	rec[len] = '\0';

	/* rc1: quick string parsing & evaluation */
	rc1 = check_time_rec(NULL, rec, &ts);

	/* rc2: parse -> eval -> free */
	tr = tmrec_expr_parse(rec, SHM_ALLOC);
	if (!tr) {
		rc2 = -2;
	} else {
		rc2 = _tmrec_expr_check(tr, (time_t)ts);
		tmrec_expr_free(tr);
	}

	ok(rc1 == rc2);
	shm_free(rec);

	return rc1;
}


void test_check_single_tmrec(void)
{
	int rc1, rc2;
	time_t now = TEST_TIME;

	_tz_set(US);
	/* no timezone, DTSTART is inclusive, local time */
	ok(ctr("20200605T055135|20200605T230000", &now) == 1);
	ok(ctr("20200605T055136|20200605T230000", &now) == -1);

	/* no timezone, DTEND is non-inclusive, local time */
	ok(ctr("20200101T000000|20200605T055135", &now) == -1);
	ok(ctr("20200101T000000|20200605T055136", &now) == 1);
	tz_reset();


	/* DTSTART is inclusive, UTC */
	ok(ctr(UTC"|20200605T115135|20200605T230000", &now) == 1);
	ok(ctr(UTC"|20200605T115136|20200605T230000", &now) == -1);

	/* DTEND is non-inclusive, UTC */
	ok(ctr(UTC"|20200101T000000|20200605T115135", &now) == -1);
	ok(ctr(UTC"|20200101T000000|20200605T115136", &now) == 1);


	/* DTSTART is inclusive, RO timezone */
	ok(ctr(RO"|20200605T145135|20200605T230000", &now) == 1);
	ok(ctr(RO"|20200605T145136|20200605T230000", &now) == -1);

	/* DTEND is non-inclusive, RO timezone */
	ok(ctr(RO"|20200101T000000|20200605T145135", &now) == -1);
	ok(ctr(RO"|20200101T000000|20200605T145136", &now) == 1);


	/* DTSTART is inclusive, AU timezone */
	ok(ctr(AUS"|20200605T235135|20200605T235959", &now) == 1);
	ok(ctr(AUS"|20200605T235136|20200605T235959", &now) == -1);
	ok(ctr(AUS"|20200605T235135|20200605T235960", &now) == 1);
	ok(ctr(AUS"|20200605T235136|20200605T235960", &now) == -1);
	ok(ctr(AUS"|20200605T235135|20200606T000000", &now) == 1);
	ok(ctr(AUS"|20200605T235136|20200606T000000", &now) == -1);

	/* DTEND is non-inclusive, AU timezone */
	ok(ctr(AUS"|20200101T000000|20200605T235135", &now) == -1);
	ok(ctr(AUS"|20200101T000000|20200605T235136", &now) == 1);

	              /* time recurrence checks */

	/* local timezone */
	_tz_set(US);
	ok(ctr("19990101T055100|19990101T055135||DAILY", &now) == -1);
	ok(ctr("19990101T055100|19990101T055136||DAILY", &now) == 1);
	tz_reset();

	/* custom timezone */
	ok(ctr(RO"|19990101T000000|19990101T145135||DAILY", &now) == -1);
	ok(ctr(RO"|19990101T000000|19990101T145136||DAILY", &now) == 1);

	/* local timezone, daily overlapping, over 1d -> always match! */
	ok(ctr(RO"|19981230T235959|19990101T145135||DAILY", &now) == 1);

	/* local timezone, weekly overlapping, over 1w -> always match! */
	ok(ctr(RO"|19981220T235959|19990101T145135||WEEKLY", &now) == 1);
	ok(ctr(RO"|19981231T235959|19990101T145135||WEEKLY", &now) == -1);

	/* local timezone, monthly overlapping, over 1m -> always match! */
	ok(ctr(RO"|19981120T235959|19990101T145135||MONTHLY", &now) == 1);
	ok(ctr(RO"|19981210T235959|19990101T145135||MONTHLY", &now) == -1);

	/* local timezone, yearly overlapping, over 1y -> always match! */
	ok(ctr(RO"|19971131T235959|19990101T145135||YEARLY", &now) == 1);
	ok(ctr(RO"|19981101T235959|19990101T145135||YEARLY", &now) == -1);


	/* local timezone, daily recurring but under 1d! */
	ok(ctr(RO"|19990101T000000|19990101T145135||DAILY", &now) == -1);
	ok(ctr(RO"|19990101T000000|19990101T145136||DAILY", &now) == 1);
	ok(ctr(RO"|19981231T145136|19990101T145135||DAILY", &now) == -1);
	ok(ctr(RO"|19981231T145137|19990101T145136||DAILY", &now) == 1);

	/* local timezone, weekly recursion is ok but day is wrong! */
	ok(ctr(RO"|20200111T145134|20200111T145136||WEEKLY", &now) == -1);

	/* local timezone, weekly recurring but under 1w! */
	ok(ctr(RO"|20200110T145136|20200117T145135||WEEKLY", &now) == -1);
	ok(ctr(RO"|20200109T145136|20200116T145135||WEEKLY", &now) == 1);

	ok(ctr(RO"|20200110T235959|20200112T145136||WEEKLY", &now) == -1);
	ok(ctr(RO"|20200106T235959|20200110T145136||WEEKLY", &now) == 1);
	ok(ctr(RO"|20200106T235959|20200110T145135||WEEKLY", &now) == -1);
	ok(ctr(RO"|20200112T235959|20200118T145135||WEEKLY", &now) == 1);
	ok(ctr(RO"|20200112T235959|20200117T145135||WEEKLY", &now) == -1);
	ok(ctr(RO"|20200109T235959|20200117T145135||WEEKLY", &now) == 1);

	/* local timezone, monthly recurring but under 1m! */
	ok(ctr(RO"|20200101T000000|20200105T145135||MONTHLY", &now) == -1);
	ok(ctr(RO"|20200101T000000|20200105T145136||MONTHLY", &now) == 1);

	ok(ctr(RO"|20200101T235959|20200104T145136||MONTHLY", &now) == -1);
	ok(ctr(RO"|20200101T235959|20200105T145135||MONTHLY", &now) == -1);
	ok(ctr(RO"|20200101T235959|20200105T145136||MONTHLY", &now) == 1);
	ok(ctr(RO"|20200101T235959|20200106T145135||MONTHLY", &now) == 1);

	/* local timezone, yearly recurring but under 1y! */
	ok(ctr(RO"|19990101T000000|19990606T145135||YEARLY", &now) == -1);
	ok(ctr(RO"|19990101T000000|19990606T145136||YEARLY", &now) == 1);

	ok(ctr(RO"|19990607T235959|20000604T145136||YEARLY", &now) == -1);
	ok(ctr(RO"|19990607T235959|20000605T145135||YEARLY", &now) == -1);
	ok(ctr(RO"|19990607T235959|20000605T145136||YEARLY", &now) == 1);
	ok(ctr(RO"|19990607T235959|20000606T145135||YEARLY", &now) == 1);

	/* disjoint intervals produce differing results regardless of TZ & time! */
	rc1 = ctr(US"|20200101T000000|20200101T120000||DAILY", NULL);
	rc2 = ctr(US"|20200101T120000|20200102T000000||DAILY", NULL);
	ok(rc1 != rc2);
	rc2 = ctr(US"|20200101T120000|20200101T235959||DAILY", NULL);
	ok(rc1 != rc2);

	rc1 = ctr(AUS"|20200101T000000|20200101T120000||DAILY", NULL);
	rc2 = ctr(AUS"|20200101T120000|20200102T000000||DAILY", NULL);
	ok(rc1 != rc2);
	rc2 = ctr(AUS"|20200101T120000|20200101T235959||DAILY", NULL);
	ok(rc1 != rc2);

	rc1 = ctr(UTC"|20200101T000000|20200101T120000||DAILY", NULL);
	rc2 = ctr(UTC"|20200101T120000|20200102T000000||DAILY", NULL);
	ok(rc1 != rc2);
	rc2 = ctr(UTC"|20200101T120000|20200101T235959||DAILY", NULL);
	ok(rc1 != rc2);

	                      /* timezone checks */

	ok(ctr(UTC"|20200605T100000|20200605T110000||DAILY", &now) == -1);
	ok(ctr(RO"|20200605T130000|20200605T140000||DAILY", &now) == -1);
	ok(ctr(US"|20200605T040000|20200605T050000||DAILY", &now) == -1);
	ok(ctr(AUS"|20200605T220000|20200605T230000||DAILY", &now) == -1);

	ok(ctr(UTC"|20200605T110000|20200605T120000||DAILY", &now) == 1);
	ok(ctr(RO"|20200605T140000|20200605T150000||DAILY", &now) == 1);
	ok(ctr(US"|20200605T050000|20200605T060000||DAILY", &now) == 1);
	ok(ctr(AUS"|20200605T230000|20200606T000000||DAILY", &now) == 1);

	ok(ctr(UTC"|20200605T120000|20200605T130000||DAILY", &now) == -1);
	ok(ctr(RO"|20200605T150000|20200605T160000||DAILY", &now) == -1);
	ok(ctr(US"|20200605T060000|20200605T070000||DAILY", &now) == -1);
	ok(ctr(AUS"|20200606T000000|20200606T010000||DAILY", &now) == -1);


	/* OpenSIPS 3.2 time rec syntax vs. OpenSIPS 3.1 and below */

	_tz_set(UTC);
	/* backwards-compatible (BC): this is still a dtstart */
	ok(ctr("20200605T115136", &now) == -1);
	ok(ctr("20200605T115135", &now) == 1);

	/* backwards-incompatible (BI): dtend -> dtstart */
	ok(ctr("|20200605T115136", &now) == -1);
	ok(ctr("|20200605T115135", &now) == 1);

	/* BI: this is now a syntax error */
	ok(ctr("|20200605T115135|p30d", &now) == -2);
	ok(ctr("|20200605T115136|p30d", &now) == -2);

	/* missing dtstart always matches (3.2 syntax) + implicit tz */
	ok(ctr("||20200605T115136", &now) == 1);
	ok(ctr("||20200605T115136", &now) == 1);
	tz_reset();


	_tz_set(AUS);
	/* missing dtstart always matches (3.2 syntax) + explicit tz */
	ok(ctr(UTC"||20200605T115136", &now) == 1);
	ok(ctr(UTC"||20200605T115136", &now) == 1);

	/* explicit timezone, just dtstart */
	ok(ctr(UTC"|20200605T115135", &now) == 1);
	ok(ctr(UTC"|20200605T115136", &now) == -1);
	tz_reset();


	_tz_set(UTC);
	/* BC: dtstart + dtend (3.1 syntax) */
	ok(ctr("20200605T115135|20200605T115135", &now) == -1);
	ok(ctr("20200605T115135|20200605T115136", &now) == 1);

	/* dtstart + dtend (3.2 syntax) + implicit tz */
	ok(ctr("|20200605T115135|20200605T115135", &now) == -1);
	ok(ctr("|20200605T115135|20200605T115136", &now) == 1);
	tz_reset();


	_tz_set(RO);
	/* dtstart + dtend (3.2 syntax) + explicit tz */
	ok(ctr(UTC"|20200605T115135|20200605T115135", &now) == -1);
	ok(ctr(UTC"|20200605T115135|20200605T115136", &now) == 1);
	tz_reset();
}


void test_check_tmrec_expr(void)
{
	#define _1 UTC"|20200605T115135|20200605T115136"
	#define _0 UTC"|20200605T115135|20200605T115135"
	#define _ctr(_tr) cmtr(_tr, now)

	unsigned int now = TEST_TIME;

	/* OR operator: basic test */
	ok(_ctr(_0 "/") == -2);
	ok(_ctr(_1 "/") == -2);
	ok(_ctr(_1 "/" _1 "/") == -2);
	ok(_ctr(_1 "/ foobar") == -2);

	ok(_ctr(_0 "/" _0) == -1);
	ok(_ctr(_1 "/" _0) == 1);
	ok(_ctr(_0 "/" _1) == 1);
	ok(_ctr(_1 "/" _1) == 1);
	ok(_ctr(_0 " / " _0) == -1);
	ok(_ctr(_1 " / " _0) == 1);
	ok(_ctr(_0 " / " _1) == 1);
	ok(_ctr(_1 " / " _1) == 1);

	/* OR operator: multiple operands */
	ok(_ctr(_0 "/" _0 "/" _0 "/" _0) == -1);
	ok(_ctr(_0 "/" _0 "/" _0 "/" _1) == 1);
	ok(_ctr(_0 "/" _1 "/" _0 "/" _0) == 1);
	ok(_ctr(_1 "/" _0 "/" _0 "/" _0) == 1);


	/* AND operator: basic test */
	ok(_ctr(_0 "&") == -2);
	ok(_ctr(_1 "&") == -2);
	ok(_ctr(_0 "&" _0 "&") == -2);
	ok(_ctr(_0 "& foobar") == -2);

	ok(_ctr(_0 "&" _0) == -1);
	ok(_ctr(_1 "&" _0) == -1);
	ok(_ctr(_0 "&" _1) == -1);
	ok(_ctr(_1 "&" _1) == 1);
	ok(_ctr(_0 " &" _0) == -1);
	ok(_ctr(_1 " &" _0) == -1);
	ok(_ctr(_0 " &" _1) == -1);
	ok(_ctr(_1 " &" _1) == 1);

	/* AND operator: multiple operands */
	ok(_ctr(_0 "&" _0 "&" _0 "&" _0) == -1);
	ok(_ctr(_0 "&" _0 "&" _0 "&" _1) == -1);
	ok(_ctr(_1 "&" _0 "&" _0 "&" _0) == -1);
	ok(_ctr(_1 "&" _1 "&" _0 "&" _1) == -1);
	ok(_ctr(_1 "&" _1 "&" _1 "&" _1) == 1);


	/* simple parenthesization */
	ok(_ctr("("_0")") == -1);
	ok(_ctr("("_1")") == 1);
	ok(_ctr("("_1 "/" _1 "&" _1")") == -2);
	ok(_ctr("("_1 "&" _1 "/" _1")") == -2);
	ok(_ctr("("_1 " / " _1 " & " _1")") == -2);
	ok(_ctr("("_1 " & " _1 " / " _1")") == -2);

	ok(_ctr("("_0 "/" _0")") == -1);
	ok(_ctr("("_1 "/" _0")") == 1);
	ok(_ctr("("_1 "/" _0 "/" _0")") == 1);

	ok(_ctr("("_0 "&" _0")") == -1);
	ok(_ctr("("_1 "&" _0")") == -1);
	ok(_ctr("("_1 "&" _0 "&" _1")") == -1);
	ok(_ctr("("_1 "&" _1 "&" _1")") == 1);

	ok(_ctr("("_1 "/" _0") &" _0) == -1);
	ok(_ctr(_1 "/ ("_0 "&" _0")") == 1);

	/* each singly parenthesized expression must contain one operator type */
	ok(_ctr(_1 "&" _1 "/" _1) == -2);
	ok(_ctr(_1 "/" _1 "&" _1) == -2);
	ok(_ctr(_1 " & " _1 " / " _1) == -2);
	ok(_ctr(_1 " / " _1 " & " _1) == -2);


	/* complex parenthesization */
	ok(_ctr("("_1 "/ (("_1"/"_0")&"_0")) &" _0) == -1);
	ok(_ctr(_1 "/ ((("_1"/"_0")&"_0") &" _0")") == 1);

	/* test WS trimming (same expression as above) */
	ok(_ctr(_1 "  /\
				((\
				  (\
					"_1" /		"_0")&\
				  "_0		") &	" _0\
			    ")") == 1);


	/* negation operator tests */
	ok(_ctr("!" _0) == 1);
	ok(_ctr("! !" _0) == -1);
	ok(_ctr("!" _1) == -1);
	ok(_ctr("!	!" _1) == 1);
	ok(_ctr("!(" _0")") == 1);
	ok(_ctr("!(" _1")") == -1);
	ok(_ctr("(!" _0")") == 1);
	ok(_ctr("(!" _1")") == -1);

	ok(_ctr("!(" _1") & " _1) == -1);
	ok(_ctr("!(" _1") / !(" _1")") == -1);
	ok(_ctr("!(" _0") & !(" _0")") == 1);

	ok(cmtr("Europe/Bucharest|20190723T070000||PT8H|WEEKLY|||MO,TU,WE,TH,FR", now) == 1);
	ok(cmtr("Europe/Bucharest|20190723T070000||PT7H|WEEKLY|||MO,TU,WE,TH,FR", now) == -1);
	ok(cmtr("!Europe/Bucharest|20190723T070000||PT8H|WEEKLY|||MO,TU,WE,TH,FR", now) == -1);
	ok(cmtr("!Europe/Bucharest|20190723T070000||PT7H|WEEKLY|||MO,TU,WE,TH,FR", now) == 1);


	/* buggy, but still somewhat _reasonable_ corner-cases */
	ok(_ctr("") == -1);
	ok(_ctr("!") == 1);
	ok(_ctr("!!") == -1);
	ok(_ctr("()") == -1);
	ok(_ctr("!()") == 1);
	ok(_ctr("() / ()") == -1);
	ok(_ctr("() / " _1) == 1);
	ok(_ctr("!() & !()") == 1);
	ok(_ctr("!() & " _0) == -1);
	ok(_ctr("(())") == -1);
	ok(_ctr("!((()))") == 1);


	/* bad syntax tests */
	ok(_ctr("/") == -2);
	ok(_ctr("(") == -2);
	ok(_ctr(")") == -2);
	ok(_ctr(")(") == -2);
	ok(_ctr("(()") == -2);
	ok(_ctr("())") == -2);
	ok(_ctr("!(") == -2);
	ok(_ctr("!(()") == -2);
	ok(_ctr("!())") == -2);
	ok(_ctr("!()!") == -2);

	ok(_ctr("&") == -2);
	ok(_ctr("/") == -2);
	ok(_ctr("&()") == -2);
	ok(_ctr("()&") == -2);
	ok(_ctr("/()") == -2);
	ok(_ctr("()/") == -2);

	ok(_ctr("()()") == -2);
	ok(_ctr(_0"(") == -2);
	ok(_ctr(_0 _1) == -2);
	ok(_ctr("("_1")"_0) == -2);
	ok(_ctr(_1"("_0")") == -2);
	ok(_ctr("("_1")("_0")") == -2);
	ok(_ctr(_0 "&&" _1) == -2);
	ok(_ctr(_0 "//" _1) == -2);

	ok(_ctr("("_0 "&" _1 ") &&" _1) == -2);
	ok(_ctr("("_0 "&" _1 ") //" _1) == -2);
	ok(_ctr(_0 "//" "("_0 "&" _1 ")") == -2);
	ok(_ctr(_0 "&&" "("_0 "&" _1 ")") == -2);
	ok(_ctr("("_0 "&" _1 ") !" _1) == -2);
}


void mod_tests(void)
{
	test_check_single_tmrec();
	test_check_tmrec_expr();
}
