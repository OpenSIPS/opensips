/*
 * Expires header field body parser
 *
 * Copyright (C) 2001-2003 FhG Fokus
 *
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


#include <stdio.h>          /* printf */
#include <string.h>         /* memset */
#include "../mem/mem.h"     /* pkg_malloc, pkg_free */
#include "../dprint.h"
#include "../trim.h"        /* trim_leading */
#include "../ut.h"
#include "../errinfo.h"
#include "parse_expires.h"


static inline int expires_parser(char* _s, int _l, exp_body_t* _e)
{
	str tmp;

	tmp.s = _s;
	tmp.len = _l;

	trim(&tmp);

	if (tmp.len == 0) {
		LM_ERR("empty body\n");
		_e->valid = 0;
		return -1;
	}

	if ( str2int( &tmp, (unsigned int*)&_e->val)!=0 ) {
		LM_ERR("body is not a number <%.*s>\n",tmp.len,tmp.s);
		_e->valid = 0;
		return -2;
	}

	_e->text = tmp;
	_e->valid = 1;

	return 0;
}


/*
 * Parse expires header field body
 */
int parse_expires(struct hdr_field* _h)
{
	exp_body_t* e;

	if (_h->parsed) {
		return 0;  /* Already parsed */
	}

	e = (exp_body_t*)pkg_malloc(sizeof(exp_body_t));
	if (e == 0) {
		LM_ERR("no pkg memory left\n");
		return -1;
	}

	memset(e, 0, sizeof(exp_body_t));

	if (expires_parser(_h->body.s, _h->body.len, e) < 0) {
		LM_ERR("failed to parse\n");
		set_err_info(OSER_EC_PARSER, OSER_EL_MEDIUM,
			"error parsing EXPIRE header");
		set_err_reply(400, "bad headers");
		pkg_free(e);
		return -2;
	}

	_h->parsed = (void*)e;
	return 0;
}


/*
 * Free all memory associated with exp_body_t
 */
void free_expires(exp_body_t** _e)
{
	pkg_free(*_e);
	*_e = 0;
}


/*
 * Print exp_body_t content, for debugging only
 */
void print_expires(exp_body_t* _e)
{
	printf("===Expires===\n");
	printf("text: \'%.*s\'\n", _e->text.len, ZSW(_e->text.s));
	printf("val : %d\n", _e->val);
	printf("===/Expires===\n");
}
