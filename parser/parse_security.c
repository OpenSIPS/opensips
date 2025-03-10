/*
 * Security-{Client,Server,Verify} header field body parser
 *
 * Copyright (c) 2024 OpenSIPS Solutions
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

#include "../ut.h"
#include "../mem/mem.h"
#include "parse_security.h"

static void free_sec_agree_body(sec_agree_body_t *s)
{
	sec_agree_param_t *it, *next;
	for (it = s->params; it; it = next) {
		next = it->next;
		pkg_free(it);
	}
	s->params = NULL;
	pkg_free(s);
}


enum sec_agree_state {
	SEC_AGREE_STATE_INVALID,
	SEC_AGREE_STATE_START,
	SEC_AGREE_STATE_MECHANISM,
	SEC_AGREE_STATE_PARAM_NAME_START,
	SEC_AGREE_STATE_PARAM_NAME,
	SEC_AGREE_STATE_PARAM_START_VALUE,
	SEC_AGREE_STATE_PARAM_VALUE,
	SEC_AGREE_STATE_PARAM_VALUE_ENC,
	SEC_AGREE_STATE_PARAM_VALUE_END,
};


void free_sec_agree(sec_agree_body_t **_s)
{
	sec_agree_body_t *bit;
	bit = *_s;
	while (bit) {
		*_s = (*_s)->next;
		free_sec_agree_body(bit);
		bit = *_s;
	}
}

sec_agree_mechanism_t parse_sec_agree_mechanism(str *mech)
{
	LM_DBG("new mechanism %.*s\n", mech->len, mech->s);
	/* 3GPP TS 33.203 */
	if (str_match(mech, _str("ipsec-3gpp")))
		return SEC_AGREE_MECHANISM_IPSEC_3GPP;
	/* RFC 3329 */
	if (str_match(mech, _str("tls")))
		return SEC_AGREE_MECHANISM_TLS;
	if (str_match(mech, _str("digest")))
		return SEC_AGREE_MECHANISM_DIGEST;
	if (str_match(mech, _str("ipsec-ike")))
		return SEC_AGREE_MECHANISM_IPSEC_IKE;
	if (str_match(mech, _str("ipsec-man")))
		return SEC_AGREE_MECHANISM_IPSEC_IKE;
	return SEC_AGREE_MECHANISM_OTHER;
}

int parse_sec_agree_parameter_pref(str *value)
{
	int i, val = 0;
	trim(value);
	if (value->len < 1)
		goto error;
	if (value->s[0] == '1') {
		if (value->len > 1) {
			if (value->s[1] != '.')
				goto error;
			for (i = 2; i < value->len; i++)
				if (value->s[i] != '0')
					goto error;
		}
		return 1000;
	} else if (value->s[0] != '0') {
		goto error;
	}
	if (value->len > 1 && value->s[1] != '.')
		goto error;
	for (i = 2; i < value->len; i++) {
		if (value->s[i] < '0' || value->s[i] > '9')
			goto error;
		val = 10 * val + (value->s[i] - '0');
	}
	val = val * 100;
	return val;
error:
	LM_ERR("invalid preference value [%.*s]\n", value->len, value->s);
	return -1;
}

int parse_sec_agree_parameter(sec_agree_body_t *sa, str *name, str *value)
{
	char *err;
	sec_agree_param_t *sp = NULL;
	static sec_agree_param_t *last_sp = NULL;
	unsigned int tmp;

	LM_DBG("parsing %p[%.*s] [%.*s]=[%.*s]\n", sa, sa->mechanism_str.len,
			sa->mechanism_str.s, name->len, name->s, value->len, value->s);

	switch (sa->mechanism) {
	case SEC_AGREE_MECHANISM_IPSEC_3GPP:
		if (str_match(name, _str("q"))) {
			sa->ts3gpp.pref_str = *value;
			sa->ts3gpp.pref = parse_sec_agree_parameter_pref(value);
			if (sa->ts3gpp.pref < 0) {
				err = "invalid preference value";
				goto error;
			}
			return 0;
		}
		/* TODO: do we need to parse these fields? */
		if (str_match(name, _str("alg"))) {
			sa->ts3gpp.alg_str = *value;
			return 0;
		}
		if (str_match(name, _str("mod"))) {
			sa->ts3gpp.mod_str = *value;
			return 0;
		}
		if (str_match(name, _str("ealg"))) {
			sa->ts3gpp.ealg_str = *value;
			return 0;
		}
		if (str_match(name, _str("spi-c"))) {
			sa->ts3gpp.spi_c_str = *value;
			if (str2int(value, &sa->ts3gpp.spi_c) < 0) {
				err = "invalid spi-c value";
				goto error;
			}
			return 0;
		}
		if (str_match(name, _str("spi-s"))) {
			sa->ts3gpp.spi_s_str = *value;
			if (str2int(value, &sa->ts3gpp.spi_s) < 0) {
				err = "invalid spi-s value";
				goto error;
			}
			return 0;
		}
		if (str_match(name, _str("port-c"))) {
			sa->ts3gpp.port_c_str = *value;
			if (str2int(value, &tmp) < 0 || tmp == 0 || tmp > 65535) {
				err = "invalid port-c value";
				goto error;
			}
			sa->ts3gpp.port_c = (unsigned short)tmp;
			return 0;
		}
		if (str_match(name, _str("port-s"))) {
			sa->ts3gpp.port_s_str = *value;
			if (str2int(value, &tmp) < 0 || tmp == 0 || tmp > 65535) {
				err = "invalid port-s value";
				goto error;
			}
			sa->ts3gpp.port_s = (unsigned short)tmp;
			return 0;
		}
		break;
	default:
		/* treat all the other the same */
		if (str_match(name, _str("q"))) {
			sa->def.preference_str = *value;
			sa->def.preference = parse_sec_agree_parameter_pref(value);
			if (sa->def.preference < 0) {
				err = "invalid preference value";
				goto error;
			}
			return 0;
		}
		if (str_match(name, _str("d-alg"))) {
			sa->def.algorithm_str = *value;
			return 0;
		}
		if (str_match(name, _str("d-qop"))) {
			sa->def.qop_str = *value;
			return 0;
		}
		if (str_match(name, _str("d-ver"))) {
			sa->def.verify_str = *value;
			return 0;
		}
		break;
	}
	
	sp = pkg_malloc(sizeof *sp);
	if (!sp) {
		err = "oom for extra sec-agree param";
		goto error;
	}
	memset(sp, 0, sizeof *sp);
	sp->name = *name;
	sp->value = *value;
	if (sa->params)
		last_sp->next = sp;
	else
		sa->params = sp;
	last_sp = sp;
		LM_DBG("adding extra param %p [%.*s]=[%.*s]\n", sa, sp->name.len, sp->name.s,
			sp->value.len, sp->value.s);
	return 0;
error:
	LM_ERR("%s %.*s=%.*s\n", err, name->len, name->s, value->len, value->s);
	return -1;
}

#define SEC_AGREE_FILL_MECHANISM() \
	do { \
		sa->mechanism_str.s = s; \
		sa->mechanism_str.len = p - s; \
		trim(&sa->mechanism_str); \
		if (sa->mechanism_str.len <= 0) { \
			LM_ERR("invalid sec-agree mechanism\n"); \
			goto free_sa; \
		} \
		sa->mechanism = parse_sec_agree_mechanism(&sa->mechanism_str); \
		if (!last) \
			first = sa; \
		else \
			last->next = sa; \
		last = sa; \
		if (*p == ',') { \
			state = SEC_AGREE_STATE_START; \
			sa = NULL; \
		} else { \
			state = SEC_AGREE_STATE_PARAM_NAME_START; \
			s = p + 1; \
		} \
	} while (0)


sec_agree_body_t *parse_sec_agree_body(str *body)
{
	sec_agree_body_t *sa = NULL, *last = NULL, *first = NULL;
	char *p, *s = NULL, *end = body->s + body->len;
	enum sec_agree_state state = SEC_AGREE_STATE_START;
	str name, value;

	LM_DBG("parsing %.*s\n", body->len, body->s);
	for (p = body->s; p < end; p++) {
		switch (state) {
		case SEC_AGREE_STATE_START:

			if (sa) {
				sec_agree_param_t *sp;
				for (sp = sa->params; sp; sp = sp->next) {
					LM_DBG("extra param %p [%.*s]=[%.*s]\n", sa, sp->name.len, sp->name.s,
							sp->value.len, sp->value.s);
				}
			}
			sa = pkg_malloc(sizeof *sa);
			if (!sa) {
				LM_ERR("oom for new sec-agree field\n");
				goto out;
			}
			memset(sa, 0, sizeof *sa);
			s = p;
			state = SEC_AGREE_STATE_MECHANISM;
			break;

		case SEC_AGREE_STATE_MECHANISM:
			switch(*p) {
			case ',':
			case ';':
				SEC_AGREE_FILL_MECHANISM();
				break;
			default: /* valid character */
				break;
			}
			break;
		case SEC_AGREE_STATE_PARAM_NAME_START:
			switch (*p) {
			case ' ':
			case '\r':
			case '\n':
			case '\t':
				s = p;
				break;
			case ',':
				state = SEC_AGREE_STATE_START;
				break;
			default:
				s = p;
				state = SEC_AGREE_STATE_PARAM_NAME;
				break;
			}
			break;
		case SEC_AGREE_STATE_PARAM_NAME:
			switch (*p) {
			case '=':
				name.s = s;
				name.len = p - s;
				trim(&name);
				if (name.len <= 0) {
					LM_ERR("invalid sec-agree param name!\n");
					state = SEC_AGREE_STATE_INVALID;
				} else {
					state = SEC_AGREE_STATE_PARAM_START_VALUE;
				}
			}
			break;
		case SEC_AGREE_STATE_PARAM_START_VALUE:
			switch (*p) {
			case ' ':
			case '\r':
			case '\n':
			case '\t':
				s = p;
				break;
			case ',':
				state = SEC_AGREE_STATE_START;
				break;
			case '"':
				state = SEC_AGREE_STATE_PARAM_VALUE_ENC;
				s = p + 1;
			default:
				state = SEC_AGREE_STATE_PARAM_VALUE;
				s = p;
				break;
			}
			break;
		case SEC_AGREE_STATE_PARAM_VALUE_ENC:
			switch (*p) {
			case '"':
				if (*(p - 1) == '/')
					break;
				/* got to the end of parameter */
				value.s = s;
				value.len = p - s - 1;
				if (value.len <= 0) {
					LM_ERR("invalid parameter %.*s value len (enc)\n", name.len, name.s);
					state = SEC_AGREE_STATE_INVALID;
				} else {
					state = SEC_AGREE_STATE_PARAM_VALUE_END;
				}
				break;
			}
			break;
		case SEC_AGREE_STATE_PARAM_VALUE_END:
			switch (*p) {
			case ' ':
			case '\r':
			case '\n':
			case '\t':
				break;
			case ',':
				if (!parse_sec_agree_parameter(sa, &name, &value)) {
					state = SEC_AGREE_STATE_START;
					sa = NULL;
				} else {
					state = SEC_AGREE_STATE_INVALID;
				}
				break;
			case ';':
				if (!parse_sec_agree_parameter(sa, &name, &value)) {
					state = SEC_AGREE_STATE_PARAM_NAME_START;
					s = p + 1;
				} else {
					state = SEC_AGREE_STATE_INVALID;
				}
				break;
			default:
				LM_ERR("invalid parameter %.*s value extra [%.*s]\n",
						name.len, name.s, (int)(p - s), s);
				state = SEC_AGREE_STATE_INVALID;
				break;
			}
			break;
		case SEC_AGREE_STATE_PARAM_VALUE:
			switch (*p) {
			case ',':
			case ';':
				/* got to the end of parameter */
				value.s = s;
				value.len = p - s;
				if (value.len <= 0) {
					LM_ERR("invalid parameter %.*s value len\n", name.len, name.s);
					state = SEC_AGREE_STATE_INVALID;
				} else {
					if (!parse_sec_agree_parameter(sa, &name, &value))
						if (*p == ',')
							state = SEC_AGREE_STATE_START;
						else
							state = SEC_AGREE_STATE_PARAM_NAME_START;
					else
						state = SEC_AGREE_STATE_INVALID;
				}
				break;
			}
			break;
		case SEC_AGREE_STATE_INVALID:
			sa->invalid = 1;
			/* best effort - search for next param */
			switch (*p) {
			case ',':
				sa = NULL;
				state = SEC_AGREE_STATE_START;
				break;
			case ';':
				state = SEC_AGREE_STATE_PARAM_NAME_START;
				break;
			}
			break;
		}
	}

	/* final states */
	switch (state) {
		case SEC_AGREE_STATE_START:
			goto free_sa;
		case SEC_AGREE_STATE_MECHANISM:
			SEC_AGREE_FILL_MECHANISM();
			break;
		case SEC_AGREE_STATE_PARAM_NAME_START:
			break;
		case SEC_AGREE_STATE_PARAM_NAME:
			LM_ERR("invalid parameter %.*s without name\n", (int)(p - s), s);
			goto invalid;
		case SEC_AGREE_STATE_PARAM_START_VALUE:
			LM_ERR("invalid parameter %.*s without value\n", (int)(p - s), s);
			goto invalid;
		case SEC_AGREE_STATE_INVALID:
			goto invalid;
		case SEC_AGREE_STATE_PARAM_VALUE:
			value.s = s;
			value.len = p - s;
		case SEC_AGREE_STATE_PARAM_VALUE_END:
			if (value.len <= 0 || parse_sec_agree_parameter(sa, &name, &value) < 0) {
				LM_ERR("invalid parameter %.*s value len\n", name.len, name.s);
				goto invalid;
			}
			break;
		case SEC_AGREE_STATE_PARAM_VALUE_ENC:
			LM_ERR("invalid parameter %.*s value (not enclosed)\n", (int)(p - s), s);
			goto invalid;
	}
out:
	if (!first) {
		if (sa) /* should not be reached */
			free_sec_agree_body(sa);
		return NULL;
	}
	return first;
invalid:
	if (sa)
		sa->invalid = 1;
	return first;
free_sa:
	if (sa)
		free_sec_agree_body(sa);
	return first;
}
#undef SEC_AGREE_FILL_MECHANISM

int parse_sec_agree(struct hdr_field* _h)
{
	sec_agree_body_t *sa = NULL;
	if (_h->parsed)
		return 0;
	sa = parse_sec_agree_body(&_h->body);
	if (!sa) {
		LM_ERR("could not parse header [%.*s]!\n",
				_h->body.len, _h->body.s);
		return -1;
	}
	_h->parsed = sa;
	return 0;
}
