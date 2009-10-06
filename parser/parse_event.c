/*
 * $Id$
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * --------
 * 2003-04-26 ZSW (jiri)
 */


#include "parse_event.h"
#include "../mem/mem.h"    /* pkg_malloc, pkg_free */
#include "../dprint.h"
#include <string.h>        /* memset */
#include "../trim.h"       /* trim_leading */
#include <stdio.h>         /* printf */
#include "../ut.h"


#define PRES_STR "presence"
#define PRES_STR_LEN 8

#define PRES_WINFO_STR "presence.winfo"
#define PRES_WINFO_STR_LEN 14

#define PRES_XCAP_CHANGE_STR "xcap-change"
#define PRES_XCAP_CHANGE_STR_LEN 11

#define PRES_SIP_PROFILE_STR "sip-profile"
#define PRES_SIP_PROFILE_STR_LEN 11

#define MWI_STR "message-summary"
#define MWI_STR_LEN 15

#define DIALOG_STR "dialog"
#define DIALOG_STR_LEN 6

#define DIALOG_SLA_STR "dialog;sla"
#define DIALOG_SLA_STR_LEN 10

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
		return -1;
	}

	_e->text.s = tmp.s;

	end = skip_token(tmp.s, tmp.len);

	_e->text.len = end - tmp.s;

	if ((_e->text.len == PRES_STR_LEN) && 
	    !strncasecmp(PRES_STR, tmp.s, _e->text.len)) {
		_e->parsed = EVENT_PRESENCE;
	} else if ((_e->text.len == PRES_XCAP_CHANGE_STR_LEN) && 
		   !strncasecmp(PRES_XCAP_CHANGE_STR, tmp.s, _e->text.len)) {
		_e->parsed = EVENT_XCAP_CHANGE;
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
	} else {
		_e->parsed = EVENT_OTHER;
	}
	

	if( (_e->text.len < tmp.len) && (*end)== ';')
	{
		str params_str;
		params_str.s = end+1;
		params_str.len = tmp.len- _e->text.len- 1;

		if (parse_params(&params_str, CLASS_ANY, &phooks, &_e->params)<0)
			return -1;
		
		if(_e->parsed == EVENT_DIALOG && _e->params!= NULL && _e->params->next== NULL&&
				_e->params->name.len== 3 && strncasecmp(_e->params->name.s, "sla", 3)== 0 )
		{
			_e->parsed = EVENT_DIALOG_SLA;
		}

	}
	else
		_e->params= NULL;

	return 0;
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
