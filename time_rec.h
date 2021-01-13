/*
 * Copyright (C) 2001-2003 FhG Fokus
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

#ifndef _TIME_REC_H_
#define _TIME_REC_H_

#include <time.h>

#include "mem/common.h"
#include "lib/list.h"

typedef void tmrec;
typedef void tmrec_expr;

#define SHM_ALLOC    1
#define PKG_ALLOC    2
#define TR_BYXXX     4


tmrec *tmrec_parse(const char *tr, char alloc_type);

int _tmrec_check(const tmrec *tr, time_t check_time);
static inline int tmrec_check(const tmrec *tr)
{
	return _tmrec_check(tr, time(NULL));
}

void tmrec_free(tmrec *tr);

int tmrec_print(const tmrec *tr);

/**
 * _tmrec_check_str() - verify that a time recurrence string matches, at the
 *                      given point in time
 *
 * Return:
 *    1 - match
 *   -1 - no match
 *   -2 - parse error (bad input)
 *   -3 - internal error
 *
 * FIXME: @tr must be write-able memory, otherwise I will segfault!
 */
int _tmrec_check_str(const char *tr, time_t check_time);
static inline int tmrec_check_str(const char *tr)
{
	return _tmrec_check_str(tr, time(NULL));
}


tmrec_expr *tmrec_expr_parse(const char *trx, char alloc_type);

int _tmrec_expr_check(const tmrec_expr *trx, time_t check_time);
static inline int tmrec_expr_check(const tmrec_expr *trx)
{
	return _tmrec_expr_check(trx, time(NULL));
}

void tmrec_expr_free(tmrec_expr *trx);

int tmrec_expr_print(const tmrec_expr *trx);

/**
 * This function expects the @trx string to be trim()'ed beforehand.
 *
 * Return:
 *     1: match
 *    -1: no match
 *    -2: parse error (bad input)
 *    -3: internal error
 */
int _tmrec_expr_check_str(const char *trx, time_t check_time);
static inline int tmrec_expr_check_str(const char *trx)
{
	return _tmrec_expr_check_str(trx, time(NULL));
}


/**
 * Set the current timezone to @tz while also making sure to back up the
 * existing timezone such that tz_reset() can be later used to restore it.
 *
 * If @tz is an invalid timezone, no change will be made.
 */
void tz_set(const str *tz);
void _tz_set(const char *tz);


/**
 * Restore the timezone to the value stored by the last tz_set() call and clear
 * the currently backed up timezone (i.e. subsequent calls to this function
 * without calling tz_set() again will be NOPs).
 */
void tz_reset(void);


/**
 * Obtain an equivalent to the @unix_time UNIX timestamp
 * that matches the @tz timezone, including the current DST status
 *
 * Note: If @tz == NULL, @unix_time will be ajusted to local time
 */
time_t tz_adjust_ts(time_t unix_time, const str *tz);


/**
 * tz_offset() - fetch the GMT offset of the given @tz timezone at the
 *               current point in time or at the @t UNIX timestamp
 */
int _tz_offset(const char *tz, time_t t);
static inline int tz_offset(const char *tz)
{
	return _tz_offset(tz, time(NULL));
}


/*************** RFC 2445/5545 low-level abstractions ****************/

#define FREQ_NOFREQ  0
#define FREQ_YEARLY  1
#define FREQ_MONTHLY 2
#define FREQ_WEEKLY  3
#define FREQ_DAILY   4

typedef struct _tr_byxxx
{
	int nr;
	int *xxx;
	int *req;
	char flags;
} tr_byxxx_t, *tr_byxxx_p;

tr_byxxx_p tr_byxxx_new(char);
int tr_byxxx_init(tr_byxxx_p, int);
int tr_byxxx_free(tr_byxxx_p);

typedef struct _tmrec
{
	time_t dtstart;
	struct tm ts;
	time_t dtend;
	time_t duration;
	time_t until;
	int freq;
	int interval;
	tr_byxxx_p byday;
	tr_byxxx_p bymday;
	tr_byxxx_p byyday;
	tr_byxxx_p bymonth;
	tr_byxxx_p byweekno;
	int wkst;
	char flags;
	char *tz;
} tmrec_t, *tmrec_p;

typedef struct _tmrec_expr
{
	char is_leaf;
	char flags;

	char op;
	struct list_head operands;
	char inverted;

	tmrec_t tr;
	struct list_head list;
} tmrec_expr_t;

tmrec_p tmrec_new(char);

int tr_parse_tz(tmrec_p, char*);
int tr_parse_dtstart(tmrec_p, char*);
int tr_parse_dtend(tmrec_p, char*);
int tr_parse_duration(tmrec_p, char*);
int tr_parse_until(tmrec_p, char*);
int tr_parse_freq(tmrec_p, char*);
int tr_parse_interval(tmrec_p, char*);
int tr_parse_byday(tmrec_p, char*);
int tr_parse_bymday(tmrec_p, char*);
int tr_parse_byyday(tmrec_p, char*);
int tr_parse_bymonth(tmrec_p, char*);
int tr_parse_byweekno(tmrec_p, char*);
int tr_parse_wkst(tmrec_p, char*);


#endif
