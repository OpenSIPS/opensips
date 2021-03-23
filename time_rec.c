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

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "mem/mem.h"
#include "mem/shm_mem.h"
#include "lib/osips_malloc.h"
#include "time_rec.h"
#include "ut.h"

/*
 * USE_YWEEK_U	-- Sunday system - see strftime %U
 * USE_YWEEK_V	-- ISO 8601 - see strftime %V
 * USE_YWEEK_W	-- Monday system - see strftime %W
 */

#ifndef USE_YWEEK_U
#ifndef USE_YWEEK_V
#ifndef USE_YWEEK_W
  #define USE_YWEEK_W		/* Monday system */
#endif
#endif
#endif

#define WDAY_SU 0
#define WDAY_MO 1
#define WDAY_TU 2
#define WDAY_WE 3
#define WDAY_TH 4
#define WDAY_FR 5
#define WDAY_SA 6
#define WDAY_NU 7

#define SEC_DAILY        (60 * 60 * 24)
#define SEC_WEEKLY       (7 * SEC_DAILY)
#define SEC_MONTHLY_MAX  (31 * SEC_DAILY)
#define SEC_YEARLY_MAX   (366 * SEC_DAILY)

#ifdef USE_YWEEK_U
#define SUN_WEEK(t)	(int)(((t)->tm_yday + 7 - \
				((t)->tm_wday)) / 7)
#else
#define MON_WEEK(t)	(int)(((t)->tm_yday + 7 - \
				((t)->tm_wday ? (t)->tm_wday - 1 : 6)) / 7)
#endif

#define ac_get_wday_yr(t) (int)((t)->tm_yday/7)
#define ac_get_wday_mr(t) (int)(((t)->tm_mday-1)/7)

#define is_leap_year(yyyy) ((((yyyy)%400))?(((yyyy)%100)?(((yyyy)%4)?0:1):0):1)

#define REC_ERR    -1
#define REC_MATCH   0
#define REC_NOMATCH 1

#define _IS_SET(x) ((x) != (time_t)-1)
#define _D(c) ((c) -'0')

#define TR_SEPARATOR '|'

#define load_TR_value( _p,_s, _tr, _func, _err, _done) \
	do{ \
		int _rc = 0; \
		_s = strchr(_p, (int)TR_SEPARATOR); \
		if (_s) \
			*_s = 0; \
		/* LM_DBG("----parsing tr param <%s>\n",_p); \ */\
		if(_s != _p) {\
			_rc = _func( _tr, _p); \
			if (_rc < 0) {\
				LM_DBG("func error\n"); \
				if (_s) *_s = TR_SEPARATOR; \
				goto _err; \
			} \
		} \
		if (_s) { \
			*_s = TR_SEPARATOR; \
			if (_rc == 0) \
				_p = _s+1; /* rc > 1 means: "input not consumed" */ \
			if ( *(_p)==0 ) \
				goto _done; \
		} else if (_rc == 0) { /* if all "input is consumed" */ \
			goto _done; \
		}\
	} while(0)

#if 0 /* debugging mode */
#define LM_DEV LM_ERR
#else
#define LM_DEV(...)
#endif

typedef struct _ac_maxval
{
	int yweek;
	int yday;  /* current year's max days (365-366) */
	int ywday;
	int mweek; /* current month's max number of weeks (4-5) */
	int mday;  /* current month's max days (28-31) */
	int mwday; /* current month's max occurrences of current day (4-5) */
} ac_maxval_t, *ac_maxval_p;

typedef struct _ac_tm
{
	time_t time;
	struct tm t;
	int mweek;
	int yweek;
	int ywday;
	int wom; /* current day's week of the month (0-4) */
	char flags;
} ac_tm_t, *ac_tm_p;

#define TR_OP_NUL 0
#define TR_OP_AND 1
#define TR_OP_OR  2

int ac_tm_reset(ac_tm_p);

int ac_get_mweek(struct tm*);
int ac_get_yweek(struct tm*);
int ac_get_wkst();

int ac_print(ac_tm_p);

time_t ic_parse_datetime(char*,struct tm*);
time_t ic_parse_duration(char*);

tr_byxxx_p ic_parse_byday(char*, char);
tr_byxxx_p ic_parse_byxxx(char*, char);
int ic_parse_wkst(char*);


static inline int strz2int(char *_bp)
{
	int _v;
	char *_p;

	_v = 0;
	_p = _bp;
	while(*_p && *_p>='0' && *_p<='9')
	{
		_v += *_p - '0';
		_p++;
	}
	return _v;
}


/**
 * Check if @x falls within the recurring [@bgn, @end) time interval,
 * according to @freq.
 *
 * @x: value to check
 * @bgn: interval start
 * @end: interval end
 * @dur: duration of the interval (effectively: @end - @bgn)
 * @freq: FREQ_WEEKLY / FREQ_MONTHLY / FREQ_YEARLY
 *
 * Return: REC_MATCH or REC_NOMATCH
 */
int check_recur_itv(struct tm *x, struct tm *bgn, struct tm *end,
                    time_t dur, int freq);


static inline void ac_tm_fill(ac_tm_p _atp, struct tm* _tm)
{
	_atp->t = *_tm;

#if 0
	_atp->mweek = ac_get_mweek(_tm);
#endif
	_atp->yweek = ac_get_yweek(_tm);
	_atp->ywday = ac_get_wday_yr(_tm);
	_atp->wom = ac_get_wday_mr(_tm);
}


#define TZ_INTACT ((char *)-1)
static char *old_tz = TZ_INTACT;

void tz_set(const str *tz)
{
#define TZBUF_SZ 50
	char tzbuf[TZBUF_SZ];

	if (tz->len >= TZBUF_SZ)
		return;

	memcpy(tzbuf, tz->s, tz->len);
	tzbuf[tz->len] = '\0';

	_tz_set(tzbuf);
#undef TZBUF_SZ
}


void _tz_set(const char *tz)
{
	LM_DBG("setting timezone to: '%s'\n", tz);

	old_tz = getenv("TZ");

	setenv("TZ", tz, 1);
	tzset();
}


void tz_reset(void)
{
	if (old_tz == TZ_INTACT)
		return;

	if (!old_tz) {
		LM_DBG("resetting timezone to system default\n");
		unsetenv("TZ");
	} else {
		LM_DBG("resetting timezone to '%s'\n", old_tz);
		setenv("TZ", old_tz, 1);
	}

	tzset();
	old_tz = TZ_INTACT;
}


time_t tz_adjust_ts(time_t unix_time, const str *tz)
{
	struct tm local_tm;
	time_t adj_ts;

	tz_set(_str("UTC"));
	localtime_r(&unix_time, &local_tm );
	tz_reset();

	if (tz)
		tz_set(tz);

	adj_ts = mktime(&local_tm);
	tz_reset();

	if (local_tm.tm_isdst > 0)
		adj_ts -= 3600;

	LM_DBG("UNIX ts: %ld, local-adjusted ts: %ld (tz: '%.*s', DST: %s)\n",
	       (long int)unix_time, (long int)adj_ts, tz ? tz->len : 4,
	       tz ? tz->s : "null", local_tm.tm_isdst == 1 ? "on" :
	       local_tm.tm_isdst == 0 ? "off" : "unavail");

	return adj_ts;
}


static inline void ac_tm_set_time(ac_tm_p _atp, time_t _t)
{
	struct tm ltime;

	memset(_atp, 0, sizeof *_atp);
	_atp->time = _t;

	localtime_r(&_t, &ltime);
	ac_tm_fill(_atp, &ltime);
}

int ac_get_mweek(struct tm* _tm)
{
	if(!_tm)
		return -1;
#ifdef USE_YWEEK_U
	return ((_tm->tm_mday-1)/7 + (7-_tm->tm_wday+(_tm->tm_mday-1)%7)/7);
#else
	return ((_tm->tm_mday-1)/7 + (7-(6+_tm->tm_wday)%7+(_tm->tm_mday-1)%7)/7);
#endif
}


int ac_get_yweek(struct tm* _tm)
{
	int week = -1;
#ifdef USE_YWEEK_V
	int days;
#endif

	if(!_tm)
		return -1;

#ifdef USE_YWEEK_U
	week = SUN_WEEK(_tm);
#else
	week = MON_WEEK(_tm);
#endif

#ifdef USE_YWEEK_V
	days = ((_tm->tm_yday + 7 - (_tm->tm_wday ? _tm->tm_wday-1 : 6)) % 7);

	if(days >= 4)
		week++;
	else
		if(week == 0)
			week = 53;
#endif
	return week;
}

int ac_get_wkst(void)
{
#ifdef USE_YWEEK_U
	return 0;
#else
	return 1;
#endif
}

int ac_tm_reset(ac_tm_p _atp)
{
	if(!_atp)
		return -1;
	memset(_atp, 0, sizeof(ac_tm_t));
	return 0;
}

static ac_maxval_p ac_get_maxval(ac_tm_p _atp)
{
	static ac_maxval_t _amp;
	struct tm _tm;
	int _v;

	/* the number of the days in the year */
	_amp.yday = 365 + is_leap_year(_atp->t.tm_year+1900);

	/* the number of the days in the month */
	switch(_atp->t.tm_mon)
	{
		case 1:
			if(_amp.yday == 366)
				_amp.mday = 29;
			else
				_amp.mday = 28;
		break;
		case 3: case 5: case 8: case 10:
			_amp.mday = 30;
		break;
		default:
			_amp.mday = 31;
	}

	/* maximum occurrences of a week day in the year */
	memset(&_tm, 0, sizeof(struct tm));
	_tm.tm_year = _atp->t.tm_year;
	_tm.tm_mon = 11;
	_tm.tm_mday = 31;
	mktime(&_tm);
	_v = 0;
	if(_atp->t.tm_wday > _tm.tm_wday)
		_v = _atp->t.tm_wday - _tm.tm_wday + 1;
	else
		_v = _tm.tm_wday - _atp->t.tm_wday;
	_amp.ywday = (int)((_tm.tm_yday-_v)/7) + 1;

	/* maximum number of weeks in the year */
	_amp.yweek = ac_get_yweek(&_tm) + 1;

	/* maximum number of the week day in the month */
	_amp.mwday=(int)((_amp.mday-1-(_amp.mday-_atp->t.tm_mday)%7)/7)+1;

#if 0
	/* maximum number of weeks in the month */
	_v = (_atp->t.tm_wday + (_amp.mday - _atp->t.tm_mday)%7)%7;
#ifdef USE_YWEEK_U
	_amp.mweek = (int)((_amp.mday-1)/7+(7-_v+(_amp.mday-1)%7)/7)+1;
#else
	_amp.mweek = (int)((_amp.mday-1)/7+(7-(6+_v)%7+(_amp.mday-1)%7)/7)+1;
#endif
#endif

	return &_amp;
}


int ac_print(ac_tm_p _atp)
{
	static char *_wdays[] = {"SU", "MO", "TU", "WE", "TH", "FR", "SA"};
	if(!_atp)
	{
		printf("\n(null)\n");
		return -1;
	}

	printf("\nSys time: %d\nTime: %02d:%02d:%02d\n", (int)_atp->time,
				_atp->t.tm_hour, _atp->t.tm_min, _atp->t.tm_sec);
	printf("Date: %s, %04d-%02d-%02d\n", _wdays[_atp->t.tm_wday],
				_atp->t.tm_year+1900, _atp->t.tm_mon+1, _atp->t.tm_mday);
	printf("Year day: %d\nYear week-day: %d\nYear week: %d\n", _atp->t.tm_yday,
			_atp->ywday, _atp->yweek);
	printf("Month week: %d\nMonth week-day: %d\n", _atp->mweek, _atp->wom);
	return 0;
}






tr_byxxx_p tr_byxxx_new(char alloc)
{
	tr_byxxx_p _bxp = NULL;
	if (alloc & PKG_ALLOC)
		_bxp = (tr_byxxx_p)pkg_malloc(sizeof(tr_byxxx_t));
	else
		_bxp = (tr_byxxx_p)shm_malloc(sizeof(tr_byxxx_t));
	if(!_bxp)
		return NULL;
	memset(_bxp, 0, sizeof(tr_byxxx_t));
	_bxp->flags = alloc;
	return _bxp;
}

int tr_byxxx_init(tr_byxxx_p _bxp, int _nr)
{
	_bxp->nr = _nr;
	if (_bxp->flags & PKG_ALLOC) {
		_bxp->xxx = (int*)pkg_malloc(_nr*sizeof(int));
		_bxp->req = (int*)pkg_malloc(_nr*sizeof(int));
	} else {
		_bxp->xxx = (int*)shm_malloc(_nr*sizeof(int));
		_bxp->req = (int*)shm_malloc(_nr*sizeof(int));
	}

	if (!_bxp->xxx || !_bxp->req)
		goto oom;

	memset(_bxp->xxx, 0, _nr*sizeof(int));
	memset(_bxp->req, 0, _nr*sizeof(int));

	return 0;
oom:
	LM_ERR("oom\n");
	if (_bxp->flags & PKG_ALLOC) {
		pkg_free(_bxp->xxx);
		pkg_free(_bxp->req);
	} else {
		shm_free(_bxp->xxx);
		shm_free(_bxp->req);
	}
	return -1;
}


int tr_byxxx_free(tr_byxxx_p _bxp)
{
	if (!_bxp)
		return -1;

	if (_bxp->flags & PKG_ALLOC) {
		pkg_free(_bxp->xxx);
		pkg_free(_bxp->req);
		pkg_free(_bxp);
	} else {
		shm_free(_bxp->xxx);
		shm_free(_bxp->req);
		shm_free(_bxp);
	}

	return 0;
}

static inline void tmrec_init(tmrec_p t)
{
	memset(t, 0, sizeof *t);

	/* these values may be legitimately set to 0 (i.e. UNIX start time) */
	t->dtstart  = (time_t)-1;
	t->dtend    = (time_t)-1;
	t->duration = (time_t)-1;

	t->freq     = (time_t)-1;
	t->until    = (time_t)-1;
	t->interval = (time_t)-1;
}

static inline void tmrec_expr_init(tmrec_expr_t *e)
{
	memset(e, 0, sizeof *e);
	INIT_LIST_HEAD(&e->operands);
	tmrec_init(&e->tr);
}

tmrec_p tmrec_new(char alloc)
{
	tmrec_p _trp;
	if (alloc & PKG_ALLOC)
		_trp = (tmrec_p)pkg_malloc(sizeof(tmrec_t));
	else
		_trp = (tmrec_p)shm_malloc(sizeof(tmrec_t));
	if(!_trp)
		return NULL;

	tmrec_init(_trp);
	_trp->flags = alloc;
	return _trp;
}

void tmrec_free(tmrec *tr)
{
	tmrec_p _trp = (tmrec_p)tr;

	if(!_trp)
		return;

	tr_byxxx_free(_trp->byday);
	tr_byxxx_free(_trp->bymday);
	tr_byxxx_free(_trp->byyday);
	tr_byxxx_free(_trp->bymonth);
	tr_byxxx_free(_trp->byweekno);

	if (_trp->flags & PKG_ALLOC) {
		pkg_free(_trp->tz);
		pkg_free(_trp);
	} else {
		shm_free(_trp->tz);
		shm_free(_trp);
	}
}

int tr_parse_tz(tmrec_p _trp, char *_in)
{
	if (!_trp || !_in)
		return -1;

	if (*_in < 'A' || *_in > 'Z')
		return 1;

	if (_trp->flags & PKG_ALLOC)
		_trp->tz = pkg_strdup(_in);
	else
		_trp->tz = shm_strdup(_in);

	if (!_trp->tz) {
		LM_ERR("oom\n");
		return -1;
	}

	return 0;
}

int tr_parse_dtstart(tmrec_p _trp, char *_in)
{
	if (!_in)
		return -1;
	_trp->dtstart = ic_parse_datetime(_in, &(_trp->ts));
	return (_trp->dtstart == (time_t)-1) ? -1 : 0;
}

int tr_parse_dtend(tmrec_p _trp, char *_in)
{
	struct tm _tm;
	if (!_in)
		return -1;
	_trp->dtend = ic_parse_datetime(_in,&_tm);
	return (_trp->dtend == (time_t)-1) ? -1 : 0;
}

int tr_parse_duration(tmrec_p _trp, char *_in)
{
	if (!_in)
		return -1;
	_trp->duration = ic_parse_duration(_in);
	return (_trp->duration == (time_t)-1) ? -1 : 0;
}

int tr_parse_until(tmrec_p _trp, char *_in)
{
	struct tm _tm;
	if (!_in)
		return -1;
	_trp->until = ic_parse_datetime(_in, &_tm);
	return (_trp->until == (time_t)-1) ? -1 : 0;
}

int tr_parse_freq(tmrec_p _trp, char *_in)
{
	if (!_in)
		return -1;

	if(strlen(_in)<5)
	{
		_trp->freq = FREQ_NOFREQ;
		return 0;
	}
	if(!strcasecmp(_in, "daily"))
	{
		_trp->freq = FREQ_DAILY;
		return 0;
	}
	if(!strcasecmp(_in, "weekly"))
	{
		_trp->freq = FREQ_WEEKLY;
		return 0;
	}
	if(!strcasecmp(_in, "monthly"))
	{
		_trp->freq = FREQ_MONTHLY;
		return 0;
	}
	if(!strcasecmp(_in, "yearly"))
	{
		_trp->freq = FREQ_YEARLY;
		return 0;
	}

	_trp->freq = FREQ_NOFREQ;
	return 0;
}

int tr_parse_interval(tmrec_p _trp, char *_in)
{
	if (!_in)
		return -1;
	_trp->interval = strz2int(_in);
	return 0;
}

int tr_parse_byday(tmrec_p _trp, char *_in)
{
	if (!_in)
		return -1;

	_trp->byday = ic_parse_byday(_in, _trp->flags);
	_trp->flags |= TR_BYXXX;
	return 0;
}

int tr_parse_bymday(tmrec_p _trp, char *_in)
{
	if (!_in)
		return -1;

	_trp->bymday = ic_parse_byxxx(_in, _trp->flags);
	_trp->flags |= TR_BYXXX;
	return 0;
}

int tr_parse_byyday(tmrec_p _trp, char *_in)
{
	if (!_in)
		return -1;

	_trp->byyday = ic_parse_byxxx(_in, _trp->flags);
	_trp->flags |= TR_BYXXX;
	return 0;
}

int tr_parse_bymonth(tmrec_p _trp, char *_in)
{
	if (!_in)
		return -1;

	_trp->bymonth = ic_parse_byxxx(_in, _trp->flags);
	_trp->flags |= TR_BYXXX;
	return 0;
}

int tr_parse_byweekno(tmrec_p _trp, char *_in)
{
	if (!_in)
		return -1;

	_trp->byweekno = ic_parse_byxxx(_in, _trp->flags);
	_trp->flags |= TR_BYXXX;
	return 0;
}

int tr_parse_wkst(tmrec_p _trp, char *_in)
{
	if (!_in)
		return -1;

	_trp->wkst = ic_parse_wkst(_in);
	return 0;
}

int tmrec_print(const tmrec *tr)
{
	static char *_wdays[] = {"SU", "MO", "TU", "WE", "TH", "FR", "SA"};
	tmrec_p _trp = (tmrec_p)tr;
	int i;

	if(!_trp)
	{
		printf("\n(null)\n");
		return -1;
	}
	printf("Recurrence definition\n-- start time ---\n");
	printf("Sys time: %d\n", (int)_trp->dtstart);
	printf("Time: %02d:%02d:%02d\n", _trp->ts.tm_hour,
				_trp->ts.tm_min, _trp->ts.tm_sec);
	printf("Date: %s, %04d-%02d-%02d\n", _wdays[_trp->ts.tm_wday],
				_trp->ts.tm_year+1900, _trp->ts.tm_mon+1, _trp->ts.tm_mday);
	printf("---\n");
	printf("End time: %d\n", (int)_trp->dtend);
	printf("Duration: %d\n", (int)_trp->duration);
	printf("Until: %d\n", (int)_trp->until);
	printf("Freq: %d\n", (int)_trp->freq);
	printf("Interval: %d\n", (int)_trp->interval);
	if(_trp->byday)
	{
		printf("Byday: ");
		for(i=0; i<_trp->byday->nr; i++)
			printf(" %d%s", _trp->byday->req[i], _wdays[_trp->byday->xxx[i]]);
		printf("\n");
	}
	if(_trp->bymday)
	{
		printf("Bymday: %d:", _trp->bymday->nr);
		for(i=0; i<_trp->bymday->nr; i++)
			printf(" %d", _trp->bymday->xxx[i]*_trp->bymday->req[i]);
		printf("\n");
	}
	if(_trp->byyday)
	{
		printf("Byyday:");
		for(i=0; i<_trp->byyday->nr; i++)
			printf(" %d", _trp->byyday->xxx[i]*_trp->byyday->req[i]);
		printf("\n");
	}
	if(_trp->bymonth)
	{
		printf("Bymonth: %d:", _trp->bymonth->nr);
		for(i=0; i< _trp->bymonth->nr; i++)
			printf(" %d", _trp->bymonth->xxx[i]*_trp->bymonth->req[i]);
		printf("\n");
	}
	if(_trp->byweekno)
	{
		printf("Byweekno: ");
		for(i=0; i<_trp->byweekno->nr; i++)
			printf(" %d", _trp->byweekno->xxx[i]*_trp->byweekno->req[i]);
		printf("\n");
	}
	printf("Weekstart: %d\n", _trp->wkst);
	return 0;
}

time_t ic_parse_datetime(char *_in, struct tm *_tm)
{
	struct tm t;

	if (!_in || strlen(_in)!=15)
		return (time_t)-1;

	t.tm_year = _D(_in[0])*1000 + _D(_in[1])*100
			+ _D(_in[2])*10 + _D(_in[3]);
	if (t.tm_year < 1970) {
		LM_ERR("invalid year in Date-Time: '%s'\n", _in);
		return (time_t)-1;
	}

	t.tm_year -= 1900; /* per man ctime(3) */
	t.tm_mon = _D(_in[4])*10 + _D(_in[5]) - 1;
	t.tm_mday = _D(_in[6])*10 + _D(_in[7]);
	if (t.tm_mon == -1 || t.tm_mday == 0) {
		LM_ERR("month or month day cannot be zero in Date-Time: '%s'\n", _in);
		return (time_t)-1;
	}

	t.tm_hour = _D(_in[9])*10 + _D(_in[10]);
	t.tm_min = _D(_in[11])*10 + _D(_in[12]);
	t.tm_sec = _D(_in[13])*10 + _D(_in[14]);
	t.tm_isdst = -1 /*daylight*/;

	*_tm = t;
	return mktime(_tm);
}

time_t ic_parse_duration(char *_in)
{
	time_t _t, _ft;
	char *_p;
	int _fl;

	if(!_in || strlen(_in)<2)
		return (time_t)-1;

	if(*_in == 'P' || *_in=='p')
	{
		_p = _in+1;
		_fl = 1;
	} else {
		_p = _in;
		_fl = 0;
	}

	_t = _ft = 0;

	while(*_p)
	{
		switch(*_p)
		{
			case '0': case '1': case '2':
			case '3': case '4': case '5':
			case '6': case '7': case '8':
			case '9':
				_t = _t*10 + *_p - '0';
			break;

			case 'w':
			case 'W':
				if(!_fl)
				{
					LM_ERR("week duration not allowed"
						" here (%d) [%s]\n", (int)(_p-_in), _in);
					return 0;
				}
				_ft += _t*7*24*3600;
				_t = 0;
			break;
			case 'd':
			case 'D':
				if(!_fl)
				{
					LM_ERR("day duration not allowed"
						" here (%d) [%s]\n", (int)(_p-_in), _in);
					return 0;
				}
				_ft += _t*24*3600;
				_t = 0;
			break;
			case 'h':
			case 'H':
				if(_fl)
				{
					LM_ERR("hour duration not allowed"
						" here (%d) [%s]\n", (int)(_p-_in), _in);
					return 0;
				}
				_ft += _t*3600;
				_t = 0;
			break;
			case 'm':
			case 'M':
				if(_fl)
				{
					LM_ERR("minute duration not allowed"
						" here (%d) [%s]\n", (int)(_p-_in), _in);
					return 0;
				}
				_ft += _t*60;
				_t = 0;
			break;
			case 's':
			case 'S':
				if(_fl)
				{
					LM_ERR("second duration not allowed"
						" here (%d) [%s]\n", (int)(_p-_in), _in);
					return 0;
				}
				_ft += _t;
				_t = 0;
			break;
			case 't':
			case 'T':
				if(!_fl)
				{
					LM_ERR("'T' not allowed"
						" here (%d) [%s]\n", (int)(_p-_in), _in);
					return 0;
				}
				_fl = 0;
			break;
			default:
				LM_ERR("bad character here (%d) [%s]\n",
					(int)(_p-_in), _in);
				return 0;
		}
		_p++;
	}

	return _ft;
}

tr_byxxx_p ic_parse_byday(char *_in, char type)
{
	tr_byxxx_p _bxp = NULL;
	int _nr, _s, _v;
	char *_p;

	if(!_in)
		return NULL;
	_bxp = tr_byxxx_new(type);
	if(!_bxp)
		return NULL;
	_p = _in;
	_nr = 1;
	while(*_p)
	{
		if(*_p == ',')
			_nr++;
		_p++;
	}
	if(tr_byxxx_init(_bxp, _nr) < 0)
	{
		tr_byxxx_free(_bxp);
		return NULL;
	}
	_p = _in;
	_nr = _v = 0;
	_s = 1;
	while(*_p && _nr < _bxp->nr)
	{
		switch(*_p)
		{
			case '0': case '1': case '2':
			case '3': case '4': case '5':
			case '6': case '7': case '8':
			case '9':
				_v = _v*10 + *_p - '0';
			break;

			case 's':
			case 'S':
				_p++;
				switch(*_p)
				{
					case 'a':
					case 'A':
						_bxp->xxx[_nr] = WDAY_SA;
					break;
					case 'u':
					case 'U':
						_bxp->xxx[_nr] = WDAY_SU;
					break;
					default:
						goto error;
				}

				_bxp->req[_nr] = _s * _v;
				if (_bxp->req[_nr] > 0)
					_bxp->req[_nr]--;
				_s = 1;
				_v = 0;
				break;
			case 'm':
			case 'M':
				_p++;
				if(*_p!='o' && *_p!='O')
					goto error;
				_bxp->xxx[_nr] = WDAY_MO;

				_bxp->req[_nr] = _s * _v;
				if (_bxp->req[_nr] > 0)
					_bxp->req[_nr]--;
				_s = 1;
				_v = 0;
				break;
			case 't':
			case 'T':
				_p++;
				switch(*_p)
				{
					case 'h':
					case 'H':
						_bxp->xxx[_nr] = WDAY_TH;
					break;
					case 'u':
					case 'U':
						_bxp->xxx[_nr] = WDAY_TU;
					break;
					default:
						goto error;
				}

				_bxp->req[_nr] = _s * _v;
				if (_bxp->req[_nr] > 0)
					_bxp->req[_nr]--;
				_s = 1;
				_v = 0;
				break;
			case 'w':
			case 'W':
				_p++;
				if(*_p!='e' && *_p!='E')
					goto error;
				_bxp->xxx[_nr] = WDAY_WE;
				_s = 1;
				_v = 0;

				_bxp->req[_nr] = _s * _v;
				if (_bxp->req[_nr] > 0)
					_bxp->req[_nr]--;
				break;
			case 'f':
			case 'F':
				_p++;
				if(*_p!='r' && *_p!='R')
					goto error;
				_bxp->xxx[_nr] = WDAY_FR;

				_bxp->req[_nr] = _s * _v;
				if (_bxp->req[_nr] > 0)
					_bxp->req[_nr]--;
				_s = 1;
				_v = 0;
				break;
			case '-':
				_s = -1;
			break;
			case '+':
			case ' ':
			case '\t':
			break;
			case ',':
				_nr++;
			break;
			default:
				goto error;
		}
		_p++;
	}

	return _bxp;

error:
	tr_byxxx_free(_bxp);
	return NULL;
}

tr_byxxx_p ic_parse_byxxx(char *_in, char type)
{
	tr_byxxx_p _bxp = NULL;
	int _nr, _s, _v;
	char *_p;

	if(!_in)
		return NULL;
	_bxp = tr_byxxx_new(type);
	if(!_bxp)
		return NULL;
	_p = _in;
	_nr = 1;
	while(*_p)
	{
		if(*_p == ',')
			_nr++;
		_p++;
	}
	if(tr_byxxx_init(_bxp, _nr) < 0)
	{
		tr_byxxx_free(_bxp);
		return NULL;
	}

	_nr = _v = 0;
	_s = 1;

	for (_p = _in; *_p; _p++) {
		switch (*_p) {
		case '0': case '1': case '2':
		case '3': case '4': case '5':
		case '6': case '7': case '8':
		case '9':
			_v = _v*10 + *_p - '0';
			break;

		case '-':
			_s = -1;
			break;
		case '+':
		case ' ':
		case '\t':
			break;

		case ',':
			_bxp->xxx[_nr] = _v;
			_bxp->req[_nr] = _s;
			_s = 1;
			_v = 0;
			_nr++;
			break;

		default:
			goto error;
		}
	}

	/* store the last item of the list */
	_bxp->xxx[_nr] = _v;
	_bxp->req[_nr] = _s;

	return _bxp;

error:
	tr_byxxx_free(_bxp);
	return NULL;
}

int ic_parse_wkst(char *_in)
{
	if(!_in || strlen(_in)!=2)
		goto error;

	switch(_in[0])
	{
		case 's':
		case 'S':
			switch(_in[1])
			{
				case 'a':
				case 'A':
					return WDAY_SA;
				case 'u':
				case 'U':
					return WDAY_SU;
				default:
					goto error;
			}
		case 'm':
		case 'M':
			if(_in[1]!='o' && _in[1]!='O')
				goto error;
			return WDAY_MO;
		case 't':
		case 'T':
			switch(_in[1])
			{
				case 'h':
				case 'H':
					return WDAY_TH;
				case 'u':
				case 'U':
					return WDAY_TU;
				default:
					goto error;
			}
		case 'w':
		case 'W':
			if(_in[1]!='e' && _in[1]!='E')
				goto error;
			return WDAY_WE;
		case 'f':
		case 'F':
			if(_in[1]!='r' && _in[1]!='R')
				goto error;
			return WDAY_FR;
		break;
		default:
			goto error;
	}

error:
#ifdef USE_YWEEK_U
	return WDAY_SU;
#else
	return WDAY_MO;
#endif
}



/*** local headers ***/
int check_min_unit(tmrec_p _trp, ac_tm_p _atp);
int check_freq_interval(tmrec_p _trp, ac_tm_p _atp);
int check_byxxx(tmrec_p, ac_tm_p);

/**
 *
 * return 0/REC_MATCH - the time falls in
 *       -1/REC_ERR - error
 *        1/REC_NOMATCH - the time falls out
 */
int check_tmrec(const tmrec_p _trp, ac_tm_p _atp)
{
	/* it is before the start date or outside a non-recurring interval? */
	if (_atp->time < _trp->dtstart ||
	        (!_IS_SET(_trp->freq) && _atp->time >= _trp->dtend))
		return REC_NOMATCH;

	LM_DEV("1) %ld + %ld = %ld\n", _trp->dtstart, _trp->duration, _trp->dtend);

	if (!_IS_SET(_trp->freq) && _atp->time < _trp->dtend)
		return REC_MATCH;

	LM_DEV("2) check freq\n");

	/* check if the instance of recurrence matches the 'interval' */
	if (check_freq_interval(_trp, _atp) != REC_MATCH)
		return REC_NOMATCH;

	LM_DEV("3) check min unit\n");

	if (check_min_unit(_trp, _atp) != REC_MATCH)
		return REC_NOMATCH;

	LM_DEV("4) check byxxx\n");

	if (check_byxxx(_trp, _atp) != REC_MATCH)
		return REC_NOMATCH;

	LM_DEV("5) check until\n");

	return (!_IS_SET(_trp->until) || _atp->time <= _trp->until) ?
	            REC_MATCH : REC_NOMATCH;
}


int check_freq_interval(tmrec_p _trp, ac_tm_p _atp)
{
	int _t0, _t1;
	struct tm _tm;

	if(!_IS_SET(_trp->freq))
		return REC_NOMATCH;

	LM_DEV("have freq\n");

	if(!_IS_SET(_trp->interval) || _trp->interval==1)
		return REC_MATCH;

	LM_DEV("have interval (%d)\n", _trp->interval);

	switch(_trp->freq)
	{
		case FREQ_DAILY:
		case FREQ_WEEKLY:
			memset(&_tm, 0, sizeof(struct tm));
			_tm.tm_year = _trp->ts.tm_year;
			_tm.tm_mon = _trp->ts.tm_mon;
			_tm.tm_mday = _trp->ts.tm_mday;
			_t0 = (int)mktime(&_tm);
			memset(&_tm, 0, sizeof(struct tm));
			_tm.tm_year = _atp->t.tm_year;
			_tm.tm_mon = _atp->t.tm_mon;
			_tm.tm_mday = _atp->t.tm_mday;
			_t1 = (int)mktime(&_tm);
			if(_trp->freq == FREQ_DAILY)
				return (((_t1-_t0)/(24*3600))%_trp->interval==0)?
					REC_MATCH:REC_NOMATCH;
#ifdef USE_YWEEK_U
			_t0 -= _trp->ts.tm_wday*24*3600;
			_t1 -= _atp->t.tm_wday*24*3600;
#else
			_t0 -= ((_trp->ts.tm_wday+6)%7)*24*3600;
			_t1 -= ((_atp->t.tm_wday+6)%7)*24*3600;
#endif
			return (((_t1-_t0)/(7*24*3600))%_trp->interval==0)?
					REC_MATCH:REC_NOMATCH;
		case FREQ_MONTHLY:
			_t0 = (_atp->t.tm_year-_trp->ts.tm_year)*12
					+ _atp->t.tm_mon-_trp->ts.tm_mon;
			return (_t0%_trp->interval==0)?REC_MATCH:REC_NOMATCH;
		case FREQ_YEARLY:
			return ((_atp->t.tm_year-_trp->ts.tm_year)%_trp->interval==0)?
					REC_MATCH:REC_NOMATCH;
	}

	return REC_NOMATCH;
}

static inline int get_min_interval(tmrec_p _trp)
{
	if(_trp->freq == FREQ_DAILY || _trp->byday || _trp->bymday || _trp->byyday)
		return FREQ_DAILY;
	if(_trp->freq == FREQ_WEEKLY || _trp->byweekno)
		return FREQ_WEEKLY;
	if(_trp->freq == FREQ_MONTHLY || _trp->bymonth)
		return FREQ_MONTHLY;
	if(_trp->freq == FREQ_YEARLY)
		return FREQ_YEARLY;

	return FREQ_NOFREQ;
}


int check_recur_itv(struct tm *x, struct tm *bgn, struct tm *end,
                    time_t dur, int freq)
{
	int d1, d2, dx;
	long diff;

	switch (freq) {
	case FREQ_YEARLY:
		LM_DEV("YEARLY\n");
		d1 = bgn->tm_yday;
		d2 = end->tm_yday;
		dx = x->tm_yday;
		break;

	case FREQ_MONTHLY:
		LM_DEV("MONTHLY\n");
		d1 = bgn->tm_mday;
		d2 = end->tm_mday;
		dx = x->tm_mday;
		break;

	case FREQ_WEEKLY:
		LM_DEV("WEEKLY\n");
		d1 = bgn->tm_wday;
		d2 = end->tm_wday;
		dx = x->tm_wday;
		break;

	case FREQ_DAILY:
	default:
		LM_DEV("DAILY\n");
		if (bgn->tm_mday == end->tm_mday) {
			LM_DEV("DAILY-1\n");
			diff = x->tm_hour*3600 + x->tm_min*60 + x->tm_sec -
					(bgn->tm_hour*3600 + bgn->tm_min*60 + bgn->tm_sec);
			if (diff < 0)
				return REC_NOMATCH;

			diff = end->tm_hour*3600 + end->tm_min*60 + end->tm_sec -
					(x->tm_hour*3600 + x->tm_min*60 + x->tm_sec);
			if (diff <= 0)
				return REC_NOMATCH;

			LM_DEV("MATCH\n");
			return REC_MATCH;

		} else {
			LM_DEV("DAILY-2\n");
			diff = bgn->tm_hour*3600 + bgn->tm_min*60 + bgn->tm_sec -
					(x->tm_hour*3600 + x->tm_min*60 + x->tm_sec);
			if (diff <= 0)
				return REC_MATCH;

			diff = x->tm_hour*3600 + x->tm_min*60 + x->tm_sec -
					(end->tm_hour*3600 + end->tm_min*60 + end->tm_sec);
			if (diff < 0)
				return REC_MATCH;

			LM_DEV("NOMATCH\n");
			return REC_NOMATCH;
		}
	}

	LM_DEV("check intervals\n");

	/* continuous interval (e.g. "M [ T W T F ] S S") */
	if (d1 < d2) {
		LM_DEV("CI-1\n");
		if (dx < d1 || dx > d2)
			return REC_NOMATCH;

		if (dx > d1 && dx < d2)
			return REC_MATCH;

	/* overlapping interval (e.g. "1 2 ... 20 ] 21 ... 29 [ 30 31") */
	} else if (d2 < d1) {
		LM_DEV("CI-2\n");
		if (dx > d2 && dx < d1)
			return REC_NOMATCH;

		if (dx < d2 || dx > d1)
			return REC_MATCH;

	} else if (dx != d1) {
		LM_DEV("CI-3\n");
		if (dur <= SEC_DAILY)
			return REC_NOMATCH;
		else
			return REC_MATCH;

	} else {
		LM_DEV("CI-4\n");
		diff = x->tm_hour*3600 + x->tm_min*60 + x->tm_sec -
				(bgn->tm_hour*3600 + bgn->tm_min*60 + bgn->tm_sec);
		if (diff < 0)
			return REC_NOMATCH;

		diff = end->tm_hour*3600 + end->tm_min*60 + end->tm_sec -
				(x->tm_hour*3600 + x->tm_min*60 + x->tm_sec);
		if (diff <= 0)
			return REC_NOMATCH;

		return REC_MATCH;
	}

	if (dx == d1)
		diff = x->tm_hour*3600 + x->tm_min*60 + x->tm_sec -
			(bgn->tm_hour*3600 + bgn->tm_min*60 + bgn->tm_sec);
	else
		diff = end->tm_hour*3600 + end->tm_min*60 + end->tm_sec -
			(x->tm_hour*3600 + x->tm_min*60 + x->tm_sec);

	return diff > 0 ? REC_MATCH : REC_NOMATCH;
}


int check_min_unit(tmrec_p _trp, ac_tm_p _atp)
{
	int min_itv;
	struct tm end;

	min_itv = get_min_interval(_trp);
	LM_DEV("min_itv: %d\n", min_itv);

	switch (min_itv) {
	case FREQ_DAILY:
		if (_trp->duration >= SEC_DAILY)
			return REC_MATCH;
		break;

	case FREQ_WEEKLY:
		if (_trp->duration >= SEC_WEEKLY)
			return REC_MATCH;
		break;

	case FREQ_MONTHLY:
		if (_trp->duration >= SEC_MONTHLY_MAX)
			return REC_MATCH;
		break;

	case FREQ_YEARLY:
		if (_trp->duration >= SEC_YEARLY_MAX)
			return REC_MATCH;
		break;

	default:
		return REC_NOMATCH;
	}

	LM_DEV("check recur...\n");

	localtime_r(&_trp->dtend, &end);
	return check_recur_itv(&_atp->t, &_trp->ts, &end, _trp->duration, min_itv);
}

int check_byxxx(tmrec_p _trp, ac_tm_p _atp)
{
	int i;
	ac_maxval_p _amp;

	if (!(_trp->flags & TR_BYXXX))
		return REC_MATCH;

	_amp = ac_get_maxval(_atp);

	if(_trp->bymonth)
	{
		for(i=0; i<_trp->bymonth->nr; i++)
		{
			if(_atp->t.tm_mon ==
					((_trp->bymonth->xxx[i] - 1)*_trp->bymonth->req[i]+12)%12)
				break;
		}
		if(i>=_trp->bymonth->nr)
			return REC_NOMATCH;
	}
	if(_trp->freq==FREQ_YEARLY && _trp->byweekno)
	{
		for(i=0; i<_trp->byweekno->nr; i++)
		{
			if(_atp->yweek == ((_trp->byweekno->xxx[i] - 1) *_trp->byweekno->req[i]+
							_amp->yweek)%_amp->yweek)
				break;
		}
		if(i>=_trp->byweekno->nr)
			return REC_NOMATCH;
	}
	if(_trp->byyday)
	{
		for(i=0; i<_trp->byyday->nr; i++)
		{
			if(_atp->t.tm_yday == ((_trp->byyday->xxx[i] - 1)*_trp->byyday->req[i]+
						_amp->yday)%_amp->yday)
				break;
		}
		if(i>=_trp->byyday->nr)
			return REC_NOMATCH;
	}
	if(_trp->bymday)
	{
		for(i=0; i<_trp->bymday->nr; i++)
		{
#ifdef EXTRA_DEBUG
			LM_DBG("%d == %d\n", _atp->t.tm_mday,
				(_trp->bymday->xxx[i]*_trp->bymday->req[i]+
				_amp->mday)%_amp->mday + ((_trp->bymday->req[i]<0)?1:0));
#endif
			if(_atp->t.tm_mday == (_trp->bymday->xxx[i]*_trp->bymday->req[i]+
						_amp->mday)%_amp->mday + ((_trp->bymday->req[i]<0)?1:0))
				break;
		}
		if(i>=_trp->bymday->nr)
			return REC_NOMATCH;
	}
	if(_trp->byday)
	{
		for(i=0; i<_trp->byday->nr; i++)
		{
			if(_trp->freq==FREQ_YEARLY)
			{
#ifdef EXTRA_DEBUG
				LM_DBG("%d==%d && %d==%d\n", _atp->t.tm_wday,
					_trp->byday->xxx[i], _atp->ywday,
					(_trp->byday->req[i]+_amp->ywday)%_amp->ywday);
#endif
				if(_atp->t.tm_wday == _trp->byday->xxx[i] &&
						_atp->ywday == (_trp->byday->req[i]+_amp->ywday)%
						_amp->ywday)
					break;
			}
			else
			{
				if(_trp->freq==FREQ_MONTHLY)
				{
#ifdef EXTRA_DEBUG
					LM_DBG("%d==%d && %d==%d [%d]\n", _atp->t.tm_wday,
						_trp->byday->xxx[i], _atp->wom,
						(_trp->byday->req[i]+_amp->mwday)%_amp->mwday,
						_amp->mwday);
#endif
					if(_atp->t.tm_wday == _trp->byday->xxx[i] &&
							_atp->wom==(_trp->byday->req[i]+
							_amp->mwday)%_amp->mwday)
						break;
				}
				else
				{
					if(_atp->t.tm_wday == _trp->byday->xxx[i])
						break;
				}
			}
		}
		if(i>=_trp->byday->nr)
			return REC_NOMATCH;
	}

	return REC_MATCH;
}


static inline int _tmrec_parse(const char *tr, tmrec_t *time_rec)
{
	char *p, *s;
	osips_free_t free_f = (time_rec->flags & PKG_ALLOC ?
	                           osips_pkg_free : osips_shm_free);

	/* empty definition? */
	if (!tr || *tr == '\0')
		return 0;

	p = (char *)tr;

	load_TR_value(p, s, time_rec, tr_parse_tz, parse_error, done);

	/* Important: make sure to set the tz NOW, before more parsing... */
	if (time_rec->tz)
		_tz_set(time_rec->tz);

	load_TR_value(p, s, time_rec, tr_parse_dtstart, parse_error, done);
	load_TR_value(p, s, time_rec, tr_parse_dtend, parse_error, done);
	load_TR_value(p, s, time_rec, tr_parse_duration, parse_error, done);
	load_TR_value(p, s, time_rec, tr_parse_freq, parse_error, done);
	load_TR_value(p, s, time_rec, tr_parse_until, parse_error, done);
	load_TR_value(p, s, time_rec, tr_parse_interval, parse_error, done);
	load_TR_value(p, s, time_rec, tr_parse_byday, parse_error, done);
	load_TR_value(p, s, time_rec, tr_parse_bymday, parse_error, done);
	load_TR_value(p, s, time_rec, tr_parse_byyday, parse_error, done);
	load_TR_value(p, s, time_rec, tr_parse_byweekno, parse_error, done);
	load_TR_value(p, s, time_rec, tr_parse_bymonth, parse_error, done);

done:
	if (time_rec->tz)
		tz_reset();

	if (!_IS_SET(time_rec->dtstart))
		time_rec->dtstart = 0; /* invalid; auto-fix to 19700101T000000 */

	if (!_IS_SET(time_rec->duration)) {
		if (!_IS_SET(time_rec->dtend)) {
			/* invalid; since we don't support mementos, we need a duration */
			switch (get_min_interval(time_rec)) {
			case FREQ_DAILY:
				time_rec->dtend = time_rec->dtstart + SEC_DAILY -
				    (time_rec->ts.tm_hour * 3600 + time_rec->ts.tm_min * 60
				     + time_rec->ts.tm_sec); /* until the end of the day */
				break;
			case FREQ_WEEKLY:
				time_rec->dtend = time_rec->dtstart + SEC_WEEKLY -
				    (time_rec->ts.tm_wday * SEC_DAILY
				     + time_rec->ts.tm_hour * 3600 + time_rec->ts.tm_min * 60
				     + time_rec->ts.tm_sec); /* until the end of the week */
				break;
			case FREQ_MONTHLY:
				time_rec->dtend = time_rec->dtstart + SEC_MONTHLY_MAX -
				    (time_rec->ts.tm_mday * SEC_DAILY
				     + time_rec->ts.tm_hour * 3600 + time_rec->ts.tm_min * 60
				     + time_rec->ts.tm_sec); /* until the end of the month */
				break;
			case FREQ_YEARLY:
				time_rec->dtend = time_rec->dtstart + SEC_YEARLY_MAX -
				    (time_rec->ts.tm_yday * SEC_DAILY
				     + time_rec->ts.tm_hour * 3600 + time_rec->ts.tm_min * 60
				     + time_rec->ts.tm_sec); /* until the end of the year */
				break;
			default:
				time_rec->dtend = 4294967295UL; /* auto-fix to +136 years */
			}
		}

		time_rec->duration = time_rec->dtend - time_rec->dtstart;
	} else {
		time_rec->dtend = time_rec->dtstart + time_rec->duration;
	}

	if (!_IS_SET(time_rec->freq) &&
	        (_IS_SET(time_rec->until) || _IS_SET(time_rec->interval)
	         || time_rec->flags & TR_BYXXX)) {
		LM_ERR("missing FREQ component in time rec: '%s'\n", tr);
		return -1;
	}

	return 0;

parse_error:
	LM_ERR("parse error in <%s> around position %i\n",
	       tr, (int)(long)(p-tr));
	if (time_rec->tz) {
		free_f(time_rec->tz);
		tz_reset();
		time_rec->tz = NULL;
	}

	return -1;
}


tmrec *tmrec_parse(const char *tr, char alloc)
{
	tmrec_p time_rec;

	time_rec = tmrec_new(alloc);
	if (!time_rec) {
		LM_ERR("oom\n");
		return NULL;
	}

	if (_tmrec_parse(tr, time_rec) < 0) {
		tmrec_free(time_rec);
		return NULL;
	}

	return (tmrec *)time_rec;
}


int _tmrec_check(const tmrec *_tr, time_t time)
{
	tmrec_t *tr = (tmrec_p)_tr;
	ac_tm_t att;
	int rc;

	/* shortcut: if there is no dstart, timerec is valid */
	if (!_IS_SET(tr->dtstart))
		return 1;

	if (tr->tz)
		_tz_set(tr->tz);

	/* set current time */
	ac_tm_set_time(&att, time);

	/* does the recv_time match the specified interval?  */
	rc = check_tmrec(tr, &att);

	if (tr->tz)
		tz_reset();

	return rc == 0;
}


int _tmrec_check_str(const char *tr, time_t check_time)
{
	tmrec_t time_rec;
	int rc;

	LM_DBG("checking: '%s'\n", tr);
	tmrec_init(&time_rec);
	time_rec.flags = PKG_ALLOC;

	if (_tmrec_parse(tr, &time_rec) < 0) {
		LM_ERR("failed to parse time rec\n");
		return -2;
	}

	rc = _tmrec_check(&time_rec, check_time) ? 1 : -1;

	if (time_rec.tz)
		pkg_free(time_rec.tz);

	return rc;
}


int _tmrec_expr_check_str(const char *trx, time_t check_time)
{
	char *p, *q, bkp, tmp = 77, need_close, invert_next = 0, op = 0;
	str aux;
	enum {
		NEED_OPERAND,
		NEED_OPERATOR,
	} state = NEED_OPERAND;

	int rc = 0, _rc;
	char is_valid;

	LM_DBG("checking: %s\n", trx);

	/* NULL input -> nothing to match against -> no match! */
	if (!trx)
		return -1;

	for (p = (char *)trx; *p != '\0'; p++) {
		if (is_ws(*p))
			continue;

		switch (state) {
		case NEED_OPERAND:
			switch (*p) {
			case ')':
			case '&':
			case '/':
				LM_ERR("failed to parse time rec (unexpected '%c')\n", *p);
				goto parse_err;

			case '!':
				invert_next = !invert_next;
				continue;

			case '(':
				for (need_close = 1, q = p + 1; *q != '\0'; q++) {
					switch (*q) {
					case '(':
						need_close++;
						break;

					case ')':
						need_close--;
						break;

					default:
						continue;
					}

					if (!need_close)
						break;
				}

				if (need_close) {
					LM_ERR("failed to parse time rec (bad parentheses)\n");
					goto parse_err;
				}

				aux.s = p + 1;
				aux.len = q - aux.s;
				trim(&aux);

				bkp = aux.s[aux.len];
				aux.s[aux.len] = '\0';
				_rc = _tmrec_expr_check_str(aux.s, check_time) + 1;
				aux.s[aux.len] = bkp;

				if (_rc < 0)
					goto parse_err;

				p = q;

				if (invert_next) {
					invert_next = 0;
					_rc = (_rc + 2) % 4;
				}

				if (op == 1)
					rc &= _rc;
				else if (op == 2)
					rc |= _rc;
				else
					rc = tmp = _rc;

				state = NEED_OPERATOR;
				break;

			default:
				for (is_valid = 0, q = p + 1; *q != '\0'; q++) {
					if (*q == '!' || *q == '(' || *q == ')') {
						LM_ERR("failed to parse multi time rec at '%c' "
						       "(unexpected character)\n", *q);
						goto parse_err;
					} else if (*q == TR_SEPARATOR) {
						is_valid = 1;
					}

					if (is_ws(*q)) {
						state = NEED_OPERATOR;
						break;
					} else if (*q == '&' || (*q == '/' && is_valid)) {
						break;
					}
				}

				aux.s = p;
				aux.len = q - aux.s;
				trim(&aux);

				bkp = aux.s[aux.len];
				aux.s[aux.len] = '\0';
				_rc = _tmrec_check_str(aux.s, check_time) + 1;
				aux.s[aux.len] = bkp;

				if (_rc < 0) {
					LM_ERR("failed to parse single time rec: '%.*s'\n",
					       aux.len, aux.s);
					return _rc - 1;
				}

				if (invert_next) {
					invert_next = 0;
					_rc = (_rc + 2) % 4;
				}

				if (*q == '&') {
					if (op == 2) {
						LM_ERR("failed to parse rec at '&' (only 1 operator "
						       "type is allowed within an expression)\n");
						goto parse_err;
					}

					if (op == 0)
						rc = _rc;
					op = 1;
				} else if (*q == '/') {
					if (op == 1) {
						LM_ERR("failed to parse rec at '/' (only 1 operator "
						       "type is allowed within an expression)\n");
						goto parse_err;
					}

					op = 2;
				}

				if (op == 1)
					rc &= _rc;
				else if (op == 2)
					rc |= _rc;
				else
					rc = tmp = _rc;

				if (*q == '\0')
					return rc - 1;

				p = q;
			}
			break;

		case NEED_OPERATOR:
			switch (*p) {
				case '&':
					if (op == 2) {
						LM_ERR("failed to parse rec at '&' (only 1 operator "
						       "type is allowed within an expression)\n");
						goto parse_err;
					} else if (op == 0) {
						rc = tmp;
					}

					op = 1;
					state = NEED_OPERAND;
					break;

				case '/':
					if (op == 1) {
						LM_ERR("failed to parse rec at '/' (only 1 operator "
						       "type is allowed within an expression)\n");
						goto parse_err;
					}

					op = 2;
					state = NEED_OPERAND;
					break;

				default:
					LM_ERR("failed to parse the rec string (bad char: '%c', "
					       "expected operator)\n", *p);
					goto parse_err;
			}
		}
	}

	if (state == NEED_OPERAND && op != 0) {
		LM_ERR("failed to parse the rec string (missing operand)\n");
		LM_ERR("input given: '%s'\n", trx);
		return -2;
	}

	if (invert_next)
		return (rc + 2) % 4 - 1;
	else
		return rc - 1;

	return rc;

parse_err:
	LM_ERR("input given: '%s'\n", trx);
	return -2;
}


tmrec_expr *tmrec_expr_parse(const char *trx, char alloc_type)
{
	enum {
		NEED_OPERAND,
		NEED_OPERATOR,
	} state = NEED_OPERAND;

	tmrec_expr_t *exp, *e;
	osips_malloc_t malloc_f;
	char *p, *q, bkp, need_close, invert_next = 0, is_valid;
	str aux;
	int rc;

	LM_DBG("checking: %s\n", trx);

	if (!trx)
		return NULL;

	malloc_f = (alloc_type & PKG_ALLOC ?
	                osips_pkg_malloc : osips_shm_malloc);
	exp = malloc_f(sizeof *exp);
	if (!exp) {
		LM_ERR("oom\n");
		return NULL;
	}

	tmrec_expr_init(exp);
	exp->flags = alloc_type;

	for (p = (char *)trx; *p != '\0'; p++) {
		if (is_ws(*p))
			continue;

		switch (state) {
		case NEED_OPERAND:
			switch (*p) {
			case ')':
			case '&':
			case '/':
				LM_ERR("failed to parse time rec (unexpected '%c')\n", *p);
				goto parse_err;

			case '!':
				invert_next = !invert_next;
				continue;

			case '(':
				for (need_close = 1, q = p + 1; *q != '\0'; q++) {
					switch (*q) {
					case '(':
						need_close++;
						break;

					case ')':
						need_close--;
						break;

					default:
						continue;
					}

					if (!need_close)
						break;
				}

				if (need_close) {
					LM_ERR("failed to parse time rec (bad parentheses)\n");
					goto parse_err;
				}

				aux.s = p + 1;
				aux.len = q - aux.s;
				trim(&aux);

				bkp = aux.s[aux.len];
				aux.s[aux.len] = '\0';
				e = tmrec_expr_parse(aux.s, alloc_type);
				aux.s[aux.len] = bkp;

				if (!e)
					goto parse_err;

				if (invert_next) {
					invert_next = 0;
					e->inverted = 1;
				}

				list_add_tail(&e->list, &exp->operands);
				p = q;
				state = NEED_OPERATOR;
				break;

			default:
				for (is_valid = 0, q = p + 1; *q != '\0'; q++) {
					if (*q == '!' || *q == '(' || *q == ')') {
						LM_ERR("failed to parse multi time rec at '%c' "
						       "(unexpected character)\n", *q);
						goto parse_err;
					} else if (*q == TR_SEPARATOR) {
						is_valid = 1;
					}

					if (is_ws(*q)) {
						state = NEED_OPERATOR;
						break;
					} else if (*q == '&' || (*q == '/' && is_valid)) {
						break;
					}
				}

				e = malloc_f(sizeof *e);
				if (!e) {
					LM_ERR("oom\n");
					goto parse_err;
				}

				tmrec_expr_init(e);
				e->flags = e->tr.flags = alloc_type;
				e->is_leaf = 1;

				list_add_tail(&e->list, &exp->operands);

				aux.s = p;
				aux.len = q - aux.s;
				trim(&aux);

				bkp = aux.s[aux.len];
				aux.s[aux.len] = '\0';
				rc = _tmrec_parse(aux.s, &e->tr);
				aux.s[aux.len] = bkp;

				if (rc < 0)
					goto parse_err;

				if (invert_next) {
					invert_next = 0;
					e->inverted = 1;
				}

				if (*q == '&') {
					if (exp->op == TR_OP_OR) {
						LM_ERR("failed to parse rec at '&' (only 1 operator "
						       "type is allowed within an expression)\n");
						goto parse_err;
					}

					exp->op = TR_OP_AND;
				} else if (*q == '/') {
					if (exp->op == TR_OP_AND) {
						LM_ERR("failed to parse rec at '/' (only 1 operator "
						       "type is allowed within an expression)\n");
						goto parse_err;
					}

					exp->op = TR_OP_OR;
				}

				if (*q == '\0')
					return exp;

				p = q;
			}
			break;

		case NEED_OPERATOR:
			switch (*p) {
				case '&':
					if (exp->op == TR_OP_OR) {
						LM_ERR("failed to parse rec at '&' (only 1 operator "
						       "type is allowed within an expression)\n");
						goto parse_err;
					}

					exp->op = TR_OP_AND;
					state = NEED_OPERAND;
					break;

				case '/':
					if (exp->op == TR_OP_AND) {
						LM_ERR("failed to parse rec at '/' (only 1 operator "
						       "type is allowed within an expression)\n");
						goto parse_err;
					}

					exp->op = TR_OP_OR;
					state = NEED_OPERAND;
					break;

				default:
					LM_ERR("failed to parse the rec string (bad char: '%c', "
					       "expected operator)\n", *p);
					goto parse_err;
			}
		}
	}

	if (state == NEED_OPERAND && exp->op != TR_OP_NUL) {
		LM_ERR("failed to parse the rec string (missing operand)\n");
		goto parse_err;
	}

	if (invert_next)
		exp->inverted = 1;

	return exp;

parse_err:
	tmrec_expr_free(exp);
	LM_ERR("parsing failed, input given: '%s'\n", trx);
	return NULL;
}


int _tmrec_expr_check(const tmrec_expr *_trx, time_t check_time)
{
	struct list_head *el;
	const tmrec_expr_t *exp, *trx = (const tmrec_expr_t *)_trx;
	int rc = 0;

	if (!trx)
		return -1;

	if (trx->is_leaf) {
		rc = _tmrec_check(&trx->tr, check_time) ? 2 : 0;
		goto out;
	}

	if (list_empty(&trx->operands))
		goto out;

	rc = (trx->op == TR_OP_AND ? 2 : 0);

	list_for_each (el, &trx->operands) {
		exp = list_entry(el, tmrec_expr_t, list);

		if (trx->op == TR_OP_AND)
			rc = rc & (_tmrec_expr_check(exp, check_time) + 1);
		else
			rc = rc | (_tmrec_expr_check(exp, check_time) + 1);
	}

out:
	if (trx->inverted) {
		LM_DEV("result: %d\n", (rc + 2) % 4 - 1);
		return (rc + 2) % 4 - 1;
	}

	LM_DEV("result: %d\n", rc - 1);
	return rc - 1;
}


void tmrec_expr_free(tmrec_expr *_trx)
{
	struct list_head *el, *next;
	tmrec_expr_t *exp, *trx = (tmrec_expr_t *)_trx;
	osips_free_t free_f;

	if (!trx)
		return;

	free_f = (trx->flags & PKG_ALLOC ?
	              osips_pkg_free : osips_shm_free);

	list_for_each_safe (el, next, &trx->operands) {
		exp = list_entry(el, tmrec_expr_t, list);
		tmrec_expr_free(exp);
	}

	free_f(trx->tr.tz);
	free_f(trx);
}


int _tz_offset(const char *tz, time_t t)
{
	struct tm lt = {0};

	_tz_set(tz);
	localtime_r(&t, &lt);
	tz_reset();

	return lt.tm_gmtoff;
}
