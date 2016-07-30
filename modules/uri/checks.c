/*
 * Various URI checks and Request URI manipulation
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
 * 2003-02-26: Created by janakj
 * 2004-03-20: has_totag introduced (jiri)
 * 2004-04-14: uri_param and add_uri_param introduced (jih)
 */

#include <string.h>
#include "../../str.h"
#include "../../dprint.h"               /* Debugging */
#include "../../mem/mem.h"
#include "../../parser/digest/digest.h" /* get_authorized_cred */
#include "../../parser/parse_from.h"
#include "../../parser/parse_uri.h"
#include "../../parser/parse_param.h"
#include "../../db/db.h"                /* Database API */
#include "../../dset.h"
#include "../../pvar.h"
#include "checks.h"


/*
 * Checks if From includes a To-tag -- good to identify
 * if a request creates a new dialog
 */
int has_totag(struct sip_msg* _m, char* _foo, char* _bar)
{
	str tag;

	if (!_m->to && parse_headers(_m, HDR_TO_F,0)==-1) {
		LM_ERR("To parsing failed\n");
		return -1;
	}
	if (!_m->to) {
		LM_ERR("no To\n");
		return -1;
	}
	tag=get_to(_m)->tag_value;
	if (tag.s==0 || tag.len==0) {
		LM_DBG("no totag\n");
		return -1;
	}
	LM_DBG("totag found\n");
	return 1;
}


/*
 * Check if the username matches the username in credentials
 */
int is_user(struct sip_msg* _m, char* _user, char* _str2)
{
	str* s;
	struct hdr_field* h;
	auth_body_t* c;

	s = (str*)_user;

	get_authorized_cred(_m->authorization, &h);
	if (!h) {
		get_authorized_cred(_m->proxy_auth, &h);
		if (!h) {
			LM_ERR("no authorized credentials found (error in scripts)\n");
			LM_ERR("Call {www,proxy}_authorize before calling is_user function !\n");
			return -1;
		}
	}

	c = (auth_body_t*)(h->parsed);

	if (!c->digest.username.user.len) {
		LM_DBG("username not found in credentials\n");
		return -1;
	}

	if (s->len != c->digest.username.user.len) {
		LM_DBG("username length does not match\n");
		return -1;
	}

	if (!memcmp(s->s, c->digest.username.user.s, s->len)) {
		LM_DBG("username matches\n");
		return 1;
	} else {
		LM_DBG("username differs\n");
		return -1;
	}
}


/*
 * Find if Request URI has a given parameter with no value
 */
int uri_param_1(struct sip_msg* _msg, char* _param, char* _str2)
{
	return uri_param_2(_msg, _param, (char*)0);
}


/*
 * Find if Request URI has a given parameter with matching value
 */
int uri_param_2(struct sip_msg* _msg, char* _param, char* _value)
{
	str *param, *value, t;

	param_hooks_t hooks;
	param_t* params;

	param = (str*)_param;
	value = (str*)_value;

	if (parse_sip_msg_uri(_msg) < 0) {
	        LM_ERR("ruri parsing failed\n");
	        return -1;
	}

	t = _msg->parsed_uri.params;

	if (parse_params(&t, CLASS_ANY, &hooks, &params) < 0) {
	        LM_ERR("ruri parameter parsing failed\n");
	        return -1;
	}

	while (params) {
		if ((params->name.len == param->len) &&
		    (strncmp(params->name.s, param->s, param->len) == 0)) {
			if (value) {
				if ((value->len == params->body.len) &&
				    strncmp(value->s, params->body.s, value->len) == 0) {
					goto ok;
				} else {
					goto nok;
				}
			} else {
				if (params->body.len > 0) {
					goto nok;
				} else {
					goto ok;
				}
			}
		} else {
			params = params->next;
		}
	}

nok:
	free_params(params);
	return -1;

ok:
	free_params(params);
	return 1;
}



/*
 * Removes a given parameter from Request URI
 */
int del_uri_param(struct sip_msg* _msg, char* _param, char* _s)
{
	str *param;
	str params;

	char  *tok_end;
	struct sip_uri *parsed_uri;

	str    param_tok, key;
	str    new_uri, old_uri;

	int begin_len, end_len;

	param = (str*)_param;

	if (param->len == 0) {
		return 1;
	}

	if (parse_sip_msg_uri(_msg) < 0) {
	        LM_ERR("ruri parsing failed\n");
	        return -1;
	}

	parsed_uri = &(_msg->parsed_uri);

	params = parsed_uri->params;
	if (0 == params.s || 0 == params.len) {
		LM_WARN("RURI contains no params to delete! Returning...\n");
		return 0;
	}

	while (params.len) {
		tok_end = q_memchr(params.s, ';', params.len);

		param_tok.s = params.s;
		if (tok_end == NULL) {
			param_tok.len = params.len;
			params.len = 0;
		} else {
			param_tok.len = tok_end - params.s;
			params.len -= (param_tok.len + 1/*';' char*/);
			params.s   += (param_tok.len + 1);
		}

		tok_end = q_memchr(param_tok.s, '=', param_tok.len);
		if (tok_end == NULL) {
			key       = param_tok;
		} else {
			key.s     = param_tok.s;
			key.len   = tok_end - param_tok.s;
		}

		if (!str_strcmp(param, &key)) {
			/* found the param to remove */
			old_uri = *GET_RURI(_msg);
			new_uri.len = old_uri.len - param_tok.len;
			new_uri.s = pkg_malloc(new_uri.len);
			if (!new_uri.s) {
				LM_ERR("no more pkg mem\n");
				return -1;
			}

			begin_len = param_tok.s - old_uri.s - 1/*remove also the ';'
													before the param */;
			memcpy(new_uri.s, old_uri.s, begin_len);

			end_len = old_uri.len - ((param_tok.s + param_tok.len) - old_uri.s);
			if (end_len)
				memcpy(new_uri.s + begin_len, param_tok.s + param_tok.len, end_len+1);

			if (set_ruri(_msg, &new_uri) == 1) {
				pkg_free(new_uri.s);
				return  0;
			} else {
				pkg_free(new_uri.s);
				return -1;
			}
		}
	}

	LM_DBG("requested key not found in RURI\n");

	return 0;
}

/*
 * Adds a new parameter to Request URI
 */
int add_uri_param(struct sip_msg* _msg, char* _param, char* _s2)
{
	str *param, *cur_uri, new_uri;
	struct sip_uri *parsed_uri;
	char *at;

	param = (str*)_param;

	if (param->len == 0) {
		return 1;
	}

	if (parse_sip_msg_uri(_msg) < 0) {
	        LM_ERR("ruri parsing failed\n");
	        return -1;
	}

	parsed_uri = &(_msg->parsed_uri);

	/* if current ruri has no headers, pad param at the end */
	if (parsed_uri->headers.len == 0) {
		cur_uri =  GET_RURI(_msg);
		new_uri.len = cur_uri->len + param->len + 1;
		if (new_uri.len > MAX_URI_SIZE) {
			LM_ERR("new ruri too long\n");
			return -1;
		}
		new_uri.s = pkg_malloc(new_uri.len);
		if (new_uri.s == 0) {
			LM_ERR("add_uri_param(): Memory allocation failure\n");
			return -1;
		}
		memcpy(new_uri.s, cur_uri->s, cur_uri->len);
		*(new_uri.s + cur_uri->len) = ';';
		memcpy(new_uri.s + cur_uri->len + 1, param->s, param->len);
		if (set_ruri(_msg, &new_uri ) == 1) {
			goto ok;
		} else {
			goto nok;
		}
	}

	/* otherwise take the long path */
	new_uri.len = 4 +
		(parsed_uri->user.len ? parsed_uri->user.len + 1 : 0) +
		(parsed_uri->passwd.len ? parsed_uri->passwd.len + 1 : 0) +
		parsed_uri->host.len +
		(parsed_uri->port.len ? parsed_uri->port.len + 1 : 0) +
		parsed_uri->params.len + param->len + 1 +
		parsed_uri->headers.len + 1;
	if (new_uri.len > MAX_URI_SIZE) {
	        LM_ERR("new ruri too long\n");
		return -1;
	}

	new_uri.s = pkg_malloc(new_uri.len);
	if (new_uri.s == 0) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}

	at = new_uri.s;
	memcpy(at, "sip:", 4);
	at = at + 4;
	if (parsed_uri->user.len) {
		memcpy(at, parsed_uri->user.s, parsed_uri->user.len);
		if (parsed_uri->passwd.len) {
			*at = ':';
			at = at + 1;
			memcpy(at, parsed_uri->passwd.s, parsed_uri->passwd.len);
			at = at + parsed_uri->passwd.len;
		};
		*at = '@';
		at = at + 1;
	}
	memcpy(at, parsed_uri->host.s, parsed_uri->host.len);
	at = at + parsed_uri->host.len;
	if (parsed_uri->port.len) {
		*at = ':';
		at = at + 1;
		memcpy(at, parsed_uri->port.s, parsed_uri->port.len);
		at = at + parsed_uri->port.len;
	}
	memcpy(at, parsed_uri->params.s, parsed_uri->params.len);
	at = at + parsed_uri->params.len;
	*at = ';';
	at = at + 1;
	memcpy(at, param->s, param->len);
	at = at + param->len;
	*at = '?';
	at = at + 1;
	memcpy(at, parsed_uri->headers.s, parsed_uri->headers.len);

	if (set_ruri(_msg, &new_uri) == 1) {
		goto ok;
	}

nok:
	pkg_free(new_uri.s);
	return -1;

ok:
	pkg_free(new_uri.s);
	return 1;
}


/*
 * Converts Request-URI, if it is tel URI, to SIP URI.  Returns 1, if
 * conversion succeeded or if no conversion was needed, i.e., Request-URI
 * was not tel URI.  Returns -1, if conversion failed.
 */
int tel2sip(struct sip_msg* _msg, char* _s1, char* _s2)
{
	str *ruri;
	struct sip_uri *pfuri;
	str suri;
	char* at;

	ruri = GET_RURI(_msg);

	if (ruri->len < 4) return 1;

	if (strncasecmp(ruri->s, "tel:", 4) != 0){
		return 1;
	}

	if ((pfuri=parse_from_uri(_msg))==NULL) {
		LM_ERR("parsing From header failed\n");
		return -1;
	}

	suri.len = 4 + ruri->len - 4 + 1 + pfuri->host.len + 1 + 10;
	suri.s = pkg_malloc(suri.len);
	if (suri.s == 0) {
		LM_ERR("no more pkg memory\n");
		return -1;
	}
	at = suri.s;
	memcpy(at, "sip:", 4);
	at = at + 4;
	memcpy(at, ruri->s + 4, ruri->len - 4);
	at = at + ruri->len - 4;
	*at = '@';
	at = at + 1;
	memcpy(at, pfuri->host.s, pfuri->host.len);
	at = at + pfuri->host.len;
	*at = ';';
	at = at + 1;
	memcpy(at, "user=phone", 10);

	if (set_ruri(_msg, &suri) == 1) {
		pkg_free(suri.s);
		return 1;
	} else {
		pkg_free(suri.s);
		return -1;
	}
}


/*
 * Check if parameter is an e164 number.
 */
static inline int e164_check(str* _user)
{
    int i;
    char c;

    if ((_user->len > 2) && (_user->len < 17) && ((_user->s)[0] == '+')) {
	for (i = 1; i < _user->len; i++) {
	    c = (_user->s)[i];
	    if (c < '0' || c > '9') return -1;
	}
	return 1;
    }
    return -1;
}


/*
 * Check if user part of URI in pseudo variable is an e164 number
 */
int is_uri_user_e164(struct sip_msg* _m, char* _sp, char* _s2)
{
    pv_spec_t *sp;
    pv_value_t pv_val;
    struct sip_uri puri;

    sp = (pv_spec_t *)_sp;

    if (sp && (pv_get_spec_value(_m, sp, &pv_val) == 0)) {
	if (pv_val.flags & PV_VAL_STR) {
	    if (pv_val.rs.len == 0 || pv_val.rs.s == NULL) {
		LM_DBG("missing uri\n");
		return -1;
	    }
	    if (parse_uri(pv_val.rs.s, pv_val.rs.len, &puri) < 0) {
		LM_ERR("parsing URI failed\n");
		return -1;
	    }
	    return e164_check(&(puri.user));
	} else {
	    LM_ERR("pseudo variable value is not string\n");
	    return -1;
	}
    } else {
	LM_ERR("failed to get pseudo variable value\n");
	return -1;
    }
}

