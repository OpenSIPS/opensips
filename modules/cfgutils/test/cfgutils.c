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


static time_t now = 1591357895U; /* 2020-06-05 (Friday), 11:51:35 UTC */;

#define UTC "UTC"
#define US  "America/Chihuahua" /* UTC-7, DST is ON @now (-6) */
#define RO  "Europe/Bucharest"  /* UTC+2, DST is ON @now (+3) */
#define NZ  "Pacific/Auckland"  /* UTC+12, DST is OFF @now (+12) */

extern int check_time_rec(struct sip_msg *_, char *time_rec,
                          unsigned int *ptime);


int ctr(const char *_rec, time_t *ts)
{
	char *rec;
	int rc;
	time_t _ts;

	if (!ts) {
		_ts = time(NULL);
		ts = &_ts;
	}

	/* it seems _tmrec_check_str() writes to the input buffer, so dup it! */
	rec = shm_strdup(_rec);

	rc = _tmrec_check_str(rec, *ts);
	shm_free(rec);

	return rc;
}


int cmtr(const char *_rec, unsigned int ts)
{
	char *rec;
	int rc1, rc2;
	tmrec *tr;

	/* it seems _tmrec_check_str() writes to the input buffer, so dup it! */
	rec = shm_strdup(_rec);

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


void test_tz_dynamic(time_t t)
{
	int utc_h, ro_h, aus_h;
	char trb[100];

	_tz_set("UTC");
	utc_h = localtime(&t)->tm_hour;
	tz_reset();
	ro_h = (utc_h + _tz_offset(RO, t) / 3600 + 24) % 24;
	aus_h = (utc_h + _tz_offset(NZ, t) / 3600 + 24) % 24;

	sprintf(trb, "%s%02d%s%s%02d%s", UTC
			"|20200101T", (utc_h - 1 + 24) % 24, "0000",
			"|20200101T", utc_h, "0000||DAILY");
	ok(ctr(trb, &t) == -1);
	sprintf(trb, "%s%02d%s%s%02d%s", UTC
			"|20200101T", utc_h, "0000",
			"|20200101T", utc_h + 1, "0000||DAILY");
	ok(ctr(trb, &t) == 1);
	sprintf(trb, "%s%02d%s%s%02d%s", UTC
			"|20200101T", utc_h + 1, "0000",
			"|20200101T", utc_h + 2, "0000||DAILY");
	ok(ctr(trb, &t) == -1);


	sprintf(trb, "%s%02d%s%s%02d%s", RO
			"|20200101T", (ro_h - 1 + 24) % 24, "0000",
			"|20200101T", ro_h, "0000||DAILY");
	ok(ctr(trb, &t) == -1);
	sprintf(trb, "%s%02d%s%s%02d%s", RO
			"|20200101T", ro_h, "0000",
			"|20200101T", ro_h + 1, "0000||DAILY");
	ok(ctr(trb, &t) == 1);
	sprintf(trb, "%s%02d%s%s%02d%s", RO
			"|20200101T", ro_h + 1, "0000",
			"|20200101T", ro_h + 2, "0000||DAILY");
	ok(ctr(trb, &t) == -1);


	sprintf(trb, "%s%02d%s%s%02d%s", NZ
			"|20200101T", (aus_h - 1 + 24) % 24, "0000",
			"|20200101T", aus_h, "0000||DAILY");
	ok(ctr(trb, &t) == -1);
	sprintf(trb, "%s%02d%s%s%02d%s", NZ
			"|20200101T", aus_h, "0000",
			"|20200101T", aus_h + 1, "0000||DAILY");
	ok(ctr(trb, &t) == 1);
	sprintf(trb, "%s%02d%s%s%02d%s", NZ
			"|20200101T", aus_h + 1, "0000",
			"|20200101T", aus_h + 2, "0000||DAILY");
	ok(ctr(trb, &t) == -1);
}


void test_single_tmrec_byxxx(void)
{
	time_t next_month = now + 2592000, prev_month = now - 2592000;
	time_t next_week = now + 604800, prev_week = now - 604800,
		   last_week_of_mo = now + 604800 * 3;
	time_t next_day = now + 86400, prev_day = now - 86400;


	/* bymonth */
	ok(ctr(UTC"|19700101T000000|||YEARLY|||||||5", &now) == -1);
	ok(ctr(UTC"|19700101T000000|||YEARLY|||||||6", &now) == 1);
	ok(ctr(UTC"|19700101T000000|||YEARLY|||||||7", &now) == -1);

	ok(ctr(UTC"|19700101T000000|||YEARLY|||||||4", &prev_month) == -1);
	ok(ctr(UTC"|19700101T000000|||YEARLY|||||||5", &prev_month) == 1);
	ok(ctr(UTC"|19700101T000000|||YEARLY|||||||6", &prev_month) == -1);

	ok(ctr(UTC"|19700101T000000|||YEARLY|||||||6", &next_month) == -1);
	ok(ctr(UTC"|19700101T000000|||YEARLY|||||||7", &next_month) == 1);
	ok(ctr(UTC"|19700101T000000|||YEARLY|||||||8", &next_month) == -1);


	/* byweekno */
	ok(ctr(UTC"|19700101T000000|||YEARLY||||||22", &now) == -1);
	ok(ctr(UTC"|19700101T000000|||YEARLY||||||23", &now) == 1);
	ok(ctr(UTC"|19700101T000000|||YEARLY||||||24", &now) == -1);

	ok(ctr(UTC"|19700101T000000|||YEARLY||||||21", &prev_week) == -1);
	ok(ctr(UTC"|19700101T000000|||YEARLY||||||22", &prev_week) == 1);
	ok(ctr(UTC"|19700101T000000|||YEARLY||||||23", &prev_week) == -1);

	ok(ctr(UTC"|19700101T000000|||YEARLY||||||23", &next_week) == -1);
	ok(ctr(UTC"|19700101T000000|||YEARLY||||||24", &next_week) == 1);
	ok(ctr(UTC"|19700101T000000|||YEARLY||||||25", &next_week) == -1);


	/* byyearday */
	ok(ctr(UTC"|19700101T000000|||YEARLY|||||156", &now) == -1);
	ok(ctr(UTC"|19700101T000000|||YEARLY|||||157", &now) == 1);
	ok(ctr(UTC"|19700101T115135|||YEARLY|||||157", &now) == 1);
	ok(ctr(UTC"|19700101T115136|||YEARLY|||||157", &now) == -1);
	ok(ctr(UTC"|20200101T115135|||YEARLY|||||157", &now) == 1);
	ok(ctr(UTC"|20200101T115136|||YEARLY|||||157", &now) == -1);
	ok(ctr(UTC"|19700101T000000|||YEARLY|||||158", &now) == -1);

	ok(ctr("UTC+12|19700101T000000|||YEARLY|||||155", &now) == -1);
	ok(ctr("UTC+12|19700101T000000|||YEARLY|||||156", &now) == 1);
	ok(ctr("UTC+12|19700101T000000|||YEARLY|||||157", &now) == -1);

	ok(ctr("UTC-13|19700101T000000|||YEARLY|||||157", &now) == -1);
	ok(ctr("UTC-13|19700101T000000|||YEARLY|||||158", &now) == 1);
	ok(ctr("UTC-13|19700101T000000|||YEARLY|||||159", &now) == -1);

	ok(ctr(UTC"|20200201T000000|||YEARLY|20201201T235959||||32,336", &now) == -1);
	ok(ctr(UTC"|20200101T000000|||YEARLY|20201201T235959||||156", &now) == -1);

	/* the UNTIL component is inclusive */
	ok(ctr(UTC"|20200101T000000|||YEARLY|20200605T115134||||157", &now) == -1);
	ok(ctr(UTC"|20200101T000000|||YEARLY|20200605T115135||||157", &now) == 1);

	ok(ctr(UTC"|20200101T000000|20200101T115135||YEARLY|20201201T235959||||156", &now) == -1);
	ok(ctr(UTC"|20200101T000000|20200101T115136||YEARLY|20201201T235959||||156", &now) == -1);
	ok(ctr(UTC"|20200101T000000|20200101T115135||YEARLY|20201201T235959||||157", &now) == -1);
	ok(ctr(UTC"|20200101T000000|20200101T115136||YEARLY|20201201T235959||||157", &now) == 1);
	ok(ctr(UTC"|20200101T000000|20200101T115135||YEARLY|20201201T235959||||158", &now) == -1);
	ok(ctr(UTC"|20200101T000000|20200101T115136||YEARLY|20201201T235959||||158", &now) == -1);


	/* bymonthday */
	ok(ctr(UTC"|19700101T000000|||MONTHLY||||4", &now) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY||||5", &now) == 1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY||||6", &now) == -1);

	ok(ctr(UTC"|19700101T000000|||MONTHLY||||3", &prev_day) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY||||4", &prev_day) == 1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY||||5", &prev_day) == -1);

	ok(ctr(UTC"|19700101T000000|||MONTHLY||||5", &next_day) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY||||6", &next_day) == 1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY||||7", &next_day) == -1);


	/* byday ... WEEKLY */
	ok(ctr(UTC"|19700101T000000|||WEEKLY|||TH", &now) == -1);
	ok(ctr(UTC"|19700101T000000|||WEEKLY|||FR", &now) == 1);
	ok(ctr(UTC"|19700101T000000|||WEEKLY|||SA", &now) == -1);

	ok(ctr(UTC"|19700101T000000|||WEEKLY|||WE", &prev_day) == -1);
	ok(ctr(UTC"|19700101T000000|||WEEKLY|||TH", &prev_day) == 1);
	ok(ctr(UTC"|19700101T000000|||WEEKLY|||FR", &prev_day) == -1);

	ok(ctr(UTC"|19700101T000000|||WEEKLY|||FR", &next_day) == -1);
	ok(ctr(UTC"|19700101T000000|||WEEKLY|||SA", &next_day) == 1);
	ok(ctr(UTC"|19700101T000000|||WEEKLY|||SU", &next_day) == -1);


	/* byday ... MONTHLY (minimal syntax) */
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||TH", &now) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||FR", &now) == 1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||SA", &now) == -1);

	ok(ctr(UTC"|19700101T000000|||MONTHLY|||WE", &prev_day) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||TH", &prev_day) == 1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||FR", &prev_day) == -1);

	ok(ctr(UTC"|19700101T000000|||MONTHLY|||FR", &next_day) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||SA", &next_day) == 1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||SU", &next_day) == -1);


	/* byday ... MONTHLY (complex syntax) */
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||+1TH", &now) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||+1FR", &now) == 1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||+1SA", &now) == -1);

	ok(ctr(UTC"|19700101T000000|||MONTHLY|||+2TH", &now) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||+2FR", &now) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||+2SA", &now) == -1);

	ok(ctr(UTC"|19700101T000000|||MONTHLY|||-1TH", &now) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||-1FR", &now) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||-1SA", &now) == -1);


	/* in the previous week, Friday was the last of May */
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||-2TH", &prev_week) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||-2FR", &prev_week) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||-2SA", &prev_week) == -1);

	ok(ctr(UTC"|19700101T000000|||MONTHLY|||-1TH", &prev_week) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||-1FR", &prev_week) == 1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||-1SA", &prev_week) == -1);

	ok(ctr(UTC"|19700101T000000|||MONTHLY|||+1TH", &prev_week) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||+1FR", &prev_week) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||+1SA", &prev_week) == -1);


	/* in the next week, Friday will be the 2nd one of June */
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||+1TH", &next_week) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||+1FR", &next_week) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||+1SA", &next_week) == -1);

	ok(ctr(UTC"|19700101T000000|||MONTHLY|||+2TH", &next_week) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||+2FR", &next_week) == 1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||+2SA", &next_week) == -1);

	ok(ctr(UTC"|19700101T000000|||MONTHLY|||-1TH", &next_week) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||-1FR", &next_week) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||-1SA", &next_week) == -1);

	ok(ctr(UTC"|19700101T000000|||MONTHLY|||-2TH", &next_week) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||-2FR", &next_week) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||-2SA", &next_week) == -1);

	/* 2nd Friday of June is also the next-next-to-last one */
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||-3TH", &next_week) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||-3FR", &next_week) == 1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||-3SA", &next_week) == -1);


	ok(ctr(UTC"|19700101T000000|||MONTHLY|||+1TH", &last_week_of_mo) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||+1FR", &last_week_of_mo) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||+1SA", &last_week_of_mo) == -1);

	ok(ctr(UTC"|19700101T000000|||MONTHLY|||+2TH", &last_week_of_mo) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||+2FR", &last_week_of_mo) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||+2SA", &last_week_of_mo) == -1);

	ok(ctr(UTC"|19700101T000000|||MONTHLY|||+3TH", &last_week_of_mo) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||+3FR", &last_week_of_mo) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||+3SA", &last_week_of_mo) == -1);

	ok(ctr(UTC"|19700101T000000|||MONTHLY|||+4TH", &last_week_of_mo) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||+4FR", &last_week_of_mo) == 1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||+4SA", &last_week_of_mo) == -1);

	ok(ctr(UTC"|19700101T000000|||MONTHLY|||-1TH", &last_week_of_mo) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||-1FR", &last_week_of_mo) == 1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||-1SA", &last_week_of_mo) == -1);

	ok(ctr(UTC"|19700101T000000|||MONTHLY|||-2TH", &last_week_of_mo) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||-2FR", &last_week_of_mo) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||-2SA", &last_week_of_mo) == -1);

	ok(ctr(UTC"|19700101T000000|||MONTHLY|||-3TH", &last_week_of_mo) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||-3FR", &last_week_of_mo) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||-3SA", &last_week_of_mo) == -1);

	ok(ctr(UTC"|19700101T000000|||MONTHLY|||-4TH", &last_week_of_mo) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||-4FR", &last_week_of_mo) == -1);
	ok(ctr(UTC"|19700101T000000|||MONTHLY|||-4SA", &last_week_of_mo) == -1);


	/* byday ... YEARLY (minimal syntax) */
	ok(ctr(UTC"|19700101T000000|||YEARLY|||TH", &now) == -1);
	ok(ctr(UTC"|19700101T000000|||YEARLY|||FR", &now) == -1);
	ok(ctr(UTC"|19700101T000000|||YEARLY|||SA", &now) == -1);

	/* byday ... YEARLY (complex syntax) */
	ok(ctr(UTC"|19700101T000000|||YEARLY|||+1TH", &now) == -1);
	ok(ctr(UTC"|19700101T000000|||YEARLY|||+1FR", &now) == -1);
	ok(ctr(UTC"|19700101T000000|||YEARLY|||+1SA", &now) == -1);

	ok(ctr(UTC"|19700101T000000|||YEARLY|||+22TH", &now) == -1);
	ok(ctr(UTC"|19700101T000000|||YEARLY|||+22FR", &now) == -1);
	ok(ctr(UTC"|19700101T000000|||YEARLY|||+22SA", &now) == -1);

	ok(ctr(UTC"|19700101T000000|||YEARLY|||+23TH", &now) == -1);
	ok(ctr(UTC"|19700101T000000|||YEARLY|||+23FR", &now) == 1);
	ok(ctr(UTC"|19700101T000000|||YEARLY|||+23SA", &now) == -1);

	ok(ctr(UTC"|19700101T000000|||YEARLY|||+24TH", &now) == -1);
	ok(ctr(UTC"|19700101T000000|||YEARLY|||+24FR", &now) == -1);
	ok(ctr(UTC"|19700101T000000|||YEARLY|||+24SA", &now) == -1);

	ok(ctr(UTC"|19700101T000000|||YEARLY|||-29TH", &now) == -1);
	ok(ctr(UTC"|19700101T000000|||YEARLY|||-29FR", &now) == -1);
	ok(ctr(UTC"|19700101T000000|||YEARLY|||-29SA", &now) == -1);

	ok(ctr(UTC"|19700101T000000|||YEARLY|||-30TH", &now) == -1);
	ok(ctr(UTC"|19700101T000000|||YEARLY|||-30FR", &now) == 1);
	ok(ctr(UTC"|19700101T000000|||YEARLY|||-30SA", &now) == -1);

	ok(ctr(UTC"|19700101T000000|||YEARLY|||-31TH", &now) == -1);
	ok(ctr(UTC"|19700101T000000|||YEARLY|||-31FR", &now) == -1);
	ok(ctr(UTC"|19700101T000000|||YEARLY|||-31SA", &now) == -1);
}


void test_check_single_tmrec(void)
{
	int rc1, rc2;

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
	ok(ctr(NZ"|20200605T235135|20200605T235959", &now) == 1);
	ok(ctr(NZ"|20200605T235136|20200605T235959", &now) == -1);
	ok(ctr(NZ"|20200605T235135|20200605T235960", &now) == 1);
	ok(ctr(NZ"|20200605T235136|20200605T235960", &now) == -1);
	ok(ctr(NZ"|20200605T235135|20200606T000000", &now) == 1);
	ok(ctr(NZ"|20200605T235136|20200606T000000", &now) == -1);

	/* DTEND is non-inclusive, AU timezone */
	ok(ctr(NZ"|20200101T000000|20200605T235135", &now) == -1);
	ok(ctr(NZ"|20200101T000000|20200605T235136", &now) == 1);

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
	rc2 = ctr(US"|20200101T120000|20200101T235960||DAILY", NULL);
	ok(rc1 != rc2);

	rc1 = ctr(NZ"|20200101T000000|20200101T120000||DAILY", NULL);
	rc2 = ctr(NZ"|20200101T120000|20200102T000000||DAILY", NULL);
	ok(rc1 != rc2);
	rc2 = ctr(NZ"|20200101T120000|20200101T235960||DAILY", NULL);
	ok(rc1 != rc2);

	rc1 = ctr(UTC"|20200101T000000|20200101T120000||DAILY", NULL);
	rc2 = ctr(UTC"|20200101T120000|20200102T000000||DAILY", NULL);
	ok(rc1 != rc2);
	rc2 = ctr(UTC"|20200101T120000|20200101T235960||DAILY", NULL);
	ok(rc1 != rc2);

	                      /* timezone checks (fixed time) */

	ok(ctr(UTC"|20200605T100000|20200605T110000||DAILY", &now) == -1);
	ok(ctr(RO"|20200605T130000|20200605T140000||DAILY", &now) == -1);
	ok(ctr(US"|20200605T040000|20200605T050000||DAILY", &now) == -1);
	ok(ctr(NZ"|20200605T220000|20200605T230000||DAILY", &now) == -1);

	ok(ctr(UTC"|20200605T110000|20200605T120000||DAILY", &now) == 1);
	ok(ctr(RO"|20200605T140000|20200605T150000||DAILY", &now) == 1);
	ok(ctr(US"|20200605T050000|20200605T060000||DAILY", &now) == 1);
	ok(ctr(NZ"|20200605T230000|20200606T000000||DAILY", &now) == 1);

	ok(ctr(UTC"|20200605T120000|20200605T130000||DAILY", &now) == -1);
	ok(ctr(RO"|20200605T150000|20200605T160000||DAILY", &now) == -1);
	ok(ctr(US"|20200605T060000|20200605T070000||DAILY", &now) == -1);
	ok(ctr(NZ"|20200606T000000|20200606T010000||DAILY", &now) == -1);

	                      /* timezone checks (dynamic time) */

	test_tz_dynamic(1585559602); /* 2020, Mar 31: RO DST: ON, NZ DST: ON */
	test_tz_dynamic(1602359602); /* 2020, Oct 10: RO DST: ON, NZ DST: ON */
	test_tz_dynamic(1579559602); /* 2020, Jan 21: RO DST: OFF, NZ DST: ON */
	test_tz_dynamic(1593559602); /* 2020, Jul 1: RO DST: ON, NZ DST: OFF */
	test_tz_dynamic(time(NULL)); /* random test (just use current time) */


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


	_tz_set(NZ);
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

	test_single_tmrec_byxxx();
}


void test_check_tmrec_expr(void)
{
	#define _1 UTC"|20200605T115135|20200605T115136"
	#define _0 UTC"|20200605T115135|20200605T115135"
	#define _ctr(_tr) cmtr(_tr, now)

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
