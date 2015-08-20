/*
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
 */

#include <string.h>

#include "parse_sipifmatch.h"
#include "../dprint.h"
#include "parse_def.h"
#include "../mem/mem.h"
#include "../trim.h"
#include "../errinfo.h"

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


int
etag_parser(char *_s, int _l, str *_e)
{
        char* end;

        _e->s = _s;
        _e->len = _l;

        trim_leading(_e);

        if (_e->len == 0) {
                LM_ERR("empty body\n");
                return -1;
        }

        end = skip_token(_e->s, _e->len);
        _e->len = end - _e->s;

	return 0;
}


int
parse_sipifmatch(struct hdr_field* _h)
{
	str *e;

	LM_DBG("called\n");

        if (_h->parsed != 0) {
                return 0;
        }

        e = (str*)pkg_malloc(sizeof(str));
        if (e == 0) {
                LM_ERR("no pkg memory left\n");
                return -1;
        }

        memset(e, 0, sizeof(str));

        if (etag_parser(_h->body.s, _h->body.len, e) < 0) {
                LM_ERR("error in etag_parser\n");
                pkg_free(e);
				set_err_info(OSER_EC_PARSER, OSER_EL_MEDIUM,
					"error parsing etag headers");
				set_err_reply(400, "bad headers");
                return -2;
        }

        _h->parsed = (void*)e;
        return 0;
}


void free_sipifmatch(str** _e)
{
	if (*_e)
		pkg_free(*_e);
	*_e = 0;
}
