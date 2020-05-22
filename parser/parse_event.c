/*
 * Event header field body parser.
 * The parser was written for Presence Agent module only.
 * it recognize presence package only, no sub-packages, no parameters
 * It should be replaced by a more generic parser if sub-packages or
 * parameters should be parsed too.
 *
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
 *
 * History:
 * --------
 * 2003-04-26 ZSW (jiri)
 */


#include <string.h>        /* memset */
#include <stdio.h>         /* printf */
#include "../mem/mem.h"    /* pkg_malloc, pkg_free */
#include "../dprint.h"
#include "../trim.h"       /* trim_leading */
#include "../ut.h"
#include "../errinfo.h"
#include "parse_event.h"


#define PRES_STR "presence"
#define PRES_STR_LEN 8

#define PRES_WINFO_STR "presence.winfo"
#define PRES_WINFO_STR_LEN 14

#define PRES_XCAP_DIFF_STR "xcap-diff"
#define PRES_XCAP_DIFF_STR_LEN 9

#define PRES_SIP_PROFILE_STR "sip-profile"
#define PRES_SIP_PROFILE_STR_LEN 11

#define MWI_STR "message-summary"
#define MWI_STR_LEN 15

#define DIALOG_STR "dialog"
#define DIALOG_STR_LEN 6

#define DIALOG_SLA_STR "dialog;sla"
#define DIALOG_SLA_STR_LEN 10

#define CALL_INFO_STR "call-info"
#define CALL_INFO_STR_LEN 9

#define LINE_SEIZE_STR "line-seize"
#define LINE_SEIZE_STR_LEN 10

#define AS_FEATURE_STR "as-feature-event"
#define AS_FEATURE_LEN 16

#define REFER_STR "refer"
#define REFER_STR_LEN 5


static inline char* skip_token(char* _b, int _l)
{
	int i = 0;

	for(i = 0; i < _l; i++) {
		switch(_b[i]) {
		case ' ':
		case '\r':
		case '\n':
		case '\t':
		case ';':
			return _b + i;
		}
	}

	return _b + _l;
}


int event_parser(char* _s, int _l, event_t* _e)
{
	str tmp;
	char* end;
	param_hooks_t phooks;

	tmp.s = _s;
	tmp.len = _l;

	trim_leading(&tmp);

	if (tmp.len == 0) {
		LM_ERR("empty body\n");
		goto parse_error;
	}

	_e->text.s = tmp.s;

	end = skip_token(tmp.s, tmp.len);

	_e->text.len = end - tmp.s;

	if ((_e->text.len == PRES_STR_LEN) &&
		!strncasecmp(PRES_STR, tmp.s, _e->text.len)) {
		_e->parsed = EVENT_PRESENCE;
	} else if ((_e->text.len == PRES_XCAP_DIFF_STR_LEN) &&
		   !strncasecmp(PRES_XCAP_DIFF_STR, tmp.s, _e->text.len)) {
		_e->parsed = EVENT_XCAP_DIFF;
	} else if ((_e->text.len == PRES_WINFO_STR_LEN) &&
		   !strncasecmp(PRES_WINFO_STR, tmp.s, _e->text.len)) {
		_e->parsed = EVENT_PRESENCE_WINFO;
	} else if ((_e->text.len == PRES_SIP_PROFILE_STR_LEN) &&
		   !strncasecmp(PRES_SIP_PROFILE_STR, tmp.s, _e->text.len)) {
		_e->parsed = EVENT_SIP_PROFILE;
	} else if ((_e->text.len == DIALOG_STR_LEN) &&
		   !strncasecmp(DIALOG_STR, tmp.s, _e->text.len)) {
		_e->parsed = EVENT_DIALOG;
	} else if ((_e->text.len == MWI_STR_LEN) &&
		   !strncasecmp(MWI_STR, tmp.s, _e->text.len)) {
		_e->parsed = EVENT_MWI;
	} else if ((_e->text.len == CALL_INFO_STR_LEN) &&
		   !strncasecmp(CALL_INFO_STR, tmp.s, _e->text.len)) {
		_e->parsed = EVENT_CALL_INFO;
	} else if ((_e->text.len == LINE_SEIZE_STR_LEN) &&
		   !strncasecmp(LINE_SEIZE_STR, tmp.s, _e->text.len)) {
		_e->parsed = EVENT_LINE_SEIZE;
	} else if ((_e->text.len == AS_FEATURE_LEN) &&
		   !strncasecmp(AS_FEATURE_STR, tmp.s, _e->text.len)) {
		_e->parsed = EVENT_AS_FEATURE;
	} else if ((_e->text.len == REFER_STR_LEN) &&
		   !strncasecmp(REFER_STR, tmp.s, _e->text.len)) {
		_e->parsed = EVENT_REFER;
	} else {
		_e->parsed = EVENT_OTHER;
	}

	if( (_e->text.len < tmp.len) && (*end)== ';')
	{
		str params_str;
		params_str.s = end+1;
		params_str.len = tmp.len- _e->text.len- 1;

		if (parse_params(&params_str, CLASS_ANY, &phooks, &_e->params)<0)
			goto parse_error;

		if(_e->parsed == EVENT_DIALOG && _e->params!= NULL
		&& _e->params->name.len== 3 &&
		strncasecmp(_e->params->name.s, "sla", 3)== 0 )
		{
			_e->parsed = EVENT_DIALOG_SLA;
		}
	} else {
		_e->params= NULL;
	}

	return 0;

parse_error:
	return -1;
}


/*
 * Parse Event header field body
 */
int parse_event(struct hdr_field* _h)
{
	event_t* e;

	if (_h->parsed != 0) {
		return 0;
	}

	e = (event_t*)pkg_malloc(sizeof(event_t));
	if (e == 0) {
		LM_ERR("no pkg memory left\n");
		return -1;
	}

	memset(e, 0, sizeof(event_t));

	if (event_parser(_h->body.s, _h->body.len, e) < 0) {
		LM_ERR("event_parser failed\n");
		pkg_free(e);
		set_err_info(OSER_EC_PARSER, OSER_EL_MEDIUM,
			"error parsing EVENT header");
		set_err_reply(400, "bad headers");
		return -2;
	}

	_h->parsed = (void*)e;
	return 0;
}


/*
 * Free all memory
 */
void free_event(event_t** _e)
{
	if (*_e)
	{
		if((*_e)->params)
			free_params((*_e)->params);
		pkg_free(*_e);
	}
	*_e = 0;
}


/*
 * Print structure, for debugging only
 */
void print_event(event_t* _e)
{
	printf("===Event===\n");
	printf("text  : \'%.*s\'\n", _e->text.len, ZSW(_e->text.s));
	printf("parsed: %s\n",
	       (_e->parsed == EVENT_PRESENCE) ? ("EVENT_PRESENCE") : ("EVENT_OTHER"));
	printf("===/Event===\n");
}
