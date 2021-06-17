/*
 * Registrar specific SIP message processing
 *
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2016-2020 OpenSIPS Solutions
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

#include "../../parser/contact/parse_contact.h"
#include "../../parser/parse_uri.h"

#include "common.h"

#define TEMP_GRUU		"tgruu."
#define TEMP_GRUU_SIZE	(sizeof(TEMP_GRUU)-1)

#define MAX_TGRUU_SIZE 255
#define GR_MAGIC 73
char tgruu_dec[MAX_TGRUU_SIZE];

/* each variable must be exported by each registrar */
extern int case_sensitive;

extern str default_gruu_secret;

/*! \brief
 * Parse the whole message and bodies of all header fields
 * that will be needed by registrar
 */
int parse_reg_headers(struct sip_msg* _m)
{
	struct hdr_field* ptr;

	if (parse_headers(_m, HDR_EOH_F, 0) == -1) {
		rerrno = R_PARSE;
		LM_ERR("failed to parse headers\n");
		return -1;
	}

	if (!_m->to) {
		rerrno = R_TO_MISS;
		LM_ERR("To not found\n");
		return -2;
	}

	if (!_m->callid) {
		rerrno = R_CID_MISS;
		LM_ERR("Call-ID not found\n");
		return -3;
	}

	if (!_m->cseq) {
		rerrno = R_CS_MISS;
		LM_ERR("CSeq not found\n");
		return -4;
	}

	if (_m->expires && !_m->expires->parsed && (parse_expires(_m->expires) < 0)) {
		rerrno = R_PARSE_EXP;
		LM_ERR("failed to parse expires body\n");
		return -5;
	}

	if (_m->contact) {
		for (ptr = _m->contact; ptr; ptr = ptr->next) {
			if (ptr->type == HDR_CONTACT_T && !ptr->parsed &&
			        parse_contact(ptr) < 0) {
				rerrno = R_PARSE_CONT;
				LM_ERR("failed to parse Contact body\n");
				return -6;
			}
		}
	}

	return 0;
}


/*! \brief
 * Extract Address of Record
 * In case of public GRUUs, also populates sip_instance
 * In case of temp GRUUs, also populates call_id
 */
int extract_aor(str* _uri, str* _a, str *sip_instance, str* call_id,
                int use_domain)
{
	static char *aor_buf;

	str tmp;
	struct sip_uri puri;
	int user_len,tgruu_len,dec_size,i;
	str *magic;

	if (parse_uri(_uri->s, _uri->len, &puri) < 0) {
		rerrno = R_AOR_PARSE;
		LM_ERR("failed to parse Address of Record\n");
		return -1;
	}

	/* if have ;gr param and func caller is interested in
	 * potentially extracting the sip instance */
	if ((puri.gr.s && puri.gr.len) && sip_instance)
	{
		LM_DBG("has gruu\n");

		/* ;gr param detected */
		if (memcmp(puri.user.s,TEMP_GRUU,TEMP_GRUU_SIZE) == 0)
		{
			LM_DBG("temp gruu\n");
			/* temp GRUU, decode and extract aor, sip_instance
			 * and call_id */
			tgruu_len = puri.user.len - TEMP_GRUU_SIZE;
			memcpy(tgruu_dec,puri.user.s+TEMP_GRUU_SIZE,tgruu_len);

			if (gruu_secret.s)
				magic = &gruu_secret;
			else
				magic = &default_gruu_secret;

			dec_size = base64decode((unsigned char *)tgruu_dec,
					(unsigned char *)tgruu_dec,tgruu_len);

			for (i=0;i<tgruu_len;i++)
				tgruu_dec[i] ^= magic->s[i%magic->len];

			LM_DBG("decoded [%.*s]\n",dec_size,tgruu_dec);
			/* extract aor - skip tgruu generation time at
			 * the beggining */
			_a->s = (char *)memchr(tgruu_dec,' ',dec_size) + 1;
			if (_a->s == NULL) {
				rerrno = R_AOR_PARSE;
				LM_ERR("failed to parse Address of Record\n");
				return -1;
			}
			_a->len = (char *)memchr(_a->s,' ',dec_size - (_a->s-tgruu_dec)) - _a->s;
			if (_a->len < 0) {
				rerrno = R_AOR_PARSE;
				LM_ERR("failed to parse Address of Record\n");
				return -1;
			}

			sip_instance->s = _a->s+_a->len+1; /* skip ' ' */
			if (sip_instance->s >= tgruu_dec + dec_size) {
				rerrno = R_AOR_PARSE;
				LM_ERR("failed to parse Address of Record\n");
				return -1;
			}
			sip_instance->len = (char *)memchr(sip_instance->s,' ',
					dec_size-(sip_instance->s-tgruu_dec)) - sip_instance->s;
			if (sip_instance->len < 0) {
				rerrno = R_AOR_PARSE;
				LM_ERR("failed to parse Address of Record\n");
				return -1;
			}

			call_id->s = sip_instance->s + sip_instance->len + 1;
			if (call_id->s >= tgruu_dec + dec_size) {
				rerrno = R_AOR_PARSE;
				LM_ERR("failed to parse Address of Record\n");
				return -1;
			}
			call_id->len = (tgruu_dec+dec_size) - call_id->s;

			LM_DBG("extracted aor [%.*s] and instance [%.*s] and callid [%.*s]\n",_a->len,_a->s,
					sip_instance->len,sip_instance->s,call_id->len,call_id->s);

			/* skip checks - done at save() */
			return 0;
		}
		else
		{
			LM_DBG("public gruu\n");
			*sip_instance = puri.gr_val;
		}
	}

	if ( (puri.user.len + puri.host.len + 1) > max_aor_len
	|| puri.user.len > max_username_len
	||  puri.host.len > max_domain_len ) {
		rerrno = R_AOR_LEN;
		LM_ERR("Address Of Record too long\n");
		return -2;
	}

	if (!aor_buf) {
		aor_buf = pkg_malloc(max_aor_len + 1);
		if (!aor_buf) {
			LM_ERR("oom\n");
			rerrno = R_INTERNAL;
			return -1;
		}
	}

	_a->s = aor_buf;
	_a->len = puri.user.len;

	/* per RFC 3261 § 10.3.5 (conversion to canonical form) */
	if (un_escape(&puri.user, _a) < 0) {
		rerrno = R_UNESCAPE;
		LM_ERR("failed to unescape username\n");
		return -3;
	}

	user_len = _a->len;

	if (use_domain) {
		if (user_len)
			aor_buf[_a->len++] = '@';
		/* strip prefix (if defined) */
		if (realm_prefix.len && realm_prefix.len<puri.host.len &&
		(memcmp(realm_prefix.s, puri.host.s, realm_prefix.len)==0) ) {
			memcpy(aor_buf + _a->len, puri.host.s + realm_prefix.len,
					puri.host.len - realm_prefix.len);
			_a->len += puri.host.len - realm_prefix.len;
		} else {
			memcpy(aor_buf + _a->len, puri.host.s, puri.host.len);
			_a->len += puri.host.len;
		}
	}

	_a->s[_a->len] = '\0';

	if (case_sensitive && user_len) {
		tmp.s = _a->s + user_len + 1;
		tmp.len = _a->s + _a->len - tmp.s;
		strlower(&tmp);
	} else {
		strlower(_a);
	}

	return 0;
}

#define has_nonzero_exp(_m) \
	(!_m->expires || !((exp_body_t*)_m->expires->parsed)->valid || \
	 ((exp_body_t*)_m->expires->parsed)->val != 0)


int check_contacts(struct sip_msg* _m, int* _s)
{
	struct hdr_field* p;
	contact_t*  c;

	*_s = 0;

	/* Message without contacts is OK */
	if (!_m->contact || !_m->contact->parsed)
		return 0;

	if (((contact_body_t*)_m->contact->parsed)->star == 1) {
		/* The first Contact HF is star */
		/* Expires must be zero */
		if (has_nonzero_exp(_m)) {
			rerrno = R_STAR_EXP;
			return 1;
		}

		/* Message must contain no contacts */
		if (((contact_body_t*)_m->contact->parsed)->contacts) {
			rerrno = R_STAR_CONT;
			return 1;
		}

		/* Message must contain no other Contact HFs */
		for (p = _m->contact->next; p; p = p->next) {
			if (p->type == HDR_CONTACT_T) {
				rerrno = R_STAR_CONT;
				return 1;
			}
		}

		*_s = 1;
	} else { /* The first Contact HF is not star */
		/* Message must contain no star Contact HF */
		for (p = _m->contact->next; p; p = p->next) {
			if (p->type != HDR_CONTACT_T)
				continue;

			if (((contact_body_t*)p->parsed)->star == 1) {
				rerrno = R_STAR_CONT;
				return 1;
			}

			/* check also the length of all contacts */
			for (c = ((contact_body_t *)p->parsed)->contacts; c; c = c->next) {
				if (c->uri.len > max_contact_len
				|| (c->received && c->received->len > RECEIVED_MAX_SIZE)) {
					rerrno = R_CONTACT_LEN;
					return 1;
				}
			}
		}
	}

	return 0;
}

static struct hdr_field* act_contact_1;
static struct hdr_field* act_contact_2;

/*! \brief
 * Get the first contact in message
 */
static contact_t* __get_first_contact(struct sip_msg* _m, struct hdr_field **act_contact)
{
	if (!_m->contact || !_m->contact->parsed)
		return NULL;

	*act_contact = _m->contact;
	return (((contact_body_t*)_m->contact->parsed)->contacts);
}

/*! \brief
 * Get next contact in message
 */
static contact_t* __get_next_contact(contact_t* _c, struct hdr_field **act_contact)
{
	struct hdr_field* p = NULL;
	if (_c->next == 0) {
		if (*act_contact)
			p = (*act_contact)->next;
		while(p) {
			if (p->type == HDR_CONTACT_T) {
				*act_contact = p;
				return (((contact_body_t*)p->parsed)->contacts);
			}
			p = p->next;
		}
		return 0;
	} else {
		return _c->next;
	}
}

/*! \brief
 * Set to NULL the pointer to the first contact in message
 */
static void __reset_first_contact(struct hdr_field **act_contact)
{
	*act_contact = NULL;
}

contact_t* get_first_contact(struct sip_msg* _m)
{
	return __get_first_contact(_m, &act_contact_1);
}

contact_t* get_next_contact(contact_t* _c)
{
	return __get_next_contact(_c, &act_contact_1);
}

void reset_first_contact(void)
{
	return __reset_first_contact(&act_contact_1);
}

contact_t* get_first_contact2(struct sip_msg* _m)
{
	return __get_first_contact(_m, &act_contact_2);
}

contact_t* get_next_contact2(contact_t* _c)
{
	return __get_next_contact(_c, &act_contact_2);
}

void reset_first_contact2(void)
{
	return __reset_first_contact(&act_contact_2);
}

/*! \brief
 * Calculate contact q value as follows:
 * 1) If q parameter exists, use it
 * 2) If the parameter doesn't exist, use the default value
 */
int calc_contact_q(param_t* _q, qvalue_t* _r)
{
	int rc;

	if (!_q || (_q->body.len == 0)) {
		*_r = default_q;
	} else {
		rc = str2q(_r, _q->body.s, _q->body.len);
		if (rc < 0) {
			rerrno = R_INV_Q; /* Invalid q parameter */
			LM_ERR("invalid qvalue (%.*s): %s\n",
					_q->body.len, _q->body.s, qverr2str(rc));
			return -1;
		}
	}
	return 0;
}
