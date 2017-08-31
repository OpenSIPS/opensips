/*
 * mid-registrar contact storing
 *
 * This module is intended to be used as a middle layer SIP component in
 * environments where a large proportion of SIP UAs (e.g. mobile devices)
 * register at high enough frequencies that they actually degrade the
 * performance of their registrars.
 *
 * Copyright (C) 2016 OpenSIPS Solutions
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
 *  2016-10-24 initial version (liviu)
 */

#include "mid_registrar.h"
#include "lookup.h"
#include "encode.h"
#include "save.h"
#include "gruu.h"

#include "../../parser/parse_rr.h"
#include "../../parser/parse_uri.h"
#include "../../parser/contact/contact.h"
#include "../../parser/contact/parse_contact.h"
#include "../../parser/parse_methods.h"
#include "../../parser/parse_supported.h"
#include "../../parser/parse_allow.h"
#include "../../dset.h"

#include "../../parser/parse_from.h"
#include "../../mod_fix.h"
#include "../../data_lump.h"
#include "../../data_lump_rpl.h"

#include "../../lib/path.h"
#include "../../lib/reg/ci.h"
#include "../../lib/reg/sip_msg.h"
#include "../../lib/reg/rerrno.h"
#include "../../lib/reg/regtime.h"
#include "../../lib/reg/path.h"

#include "../../trim.h"

#include "../usrloc/usrloc.h"
#include "../usrloc/urecord.h"

static struct {
	char* buf;
	int buf_len;
	int data_len;
} contact = {0, 0, 0};

#define MAX_AOR_LEN 256

#define MSG_200 "OK"
#define MSG_400 "Bad Request"
#define MSG_420 "Bad Extension"
#define MSG_500 "Server Internal Error"
#define MSG_503 "Service Unavailable"

#define RETRY_AFTER "Retry-After: "
#define RETRY_AFTER_LEN (sizeof(RETRY_AFTER) - 1)

/*
 * @_e: output param (integer) - value of the ";expires" Contact hf param or "Expires" hf
 */
void calc_contact_expires(struct sip_msg* _m, param_t* _ep, int* _e, struct save_ctx *_sctx)
{
	if (!_ep || !_ep->body.len) {
		*_e = get_expires_hf(_m);
	} else {
		if (str2int(&_ep->body, (unsigned int*)_e) < 0) {
			*_e = default_expires;
		}
	}

	if ((*_e != 0) && ((*_e) < min_expires))
		*_e = min_expires;

	if ((*_e != 0) && max_expires && ((*_e) > max_expires))
		*_e = max_expires;

	LM_DBG("expires: %d\n", *_e);
}

/* with the optionally added outgoing timeout extension
 *
 * @_e: output param (UNIX timestamp) - expiration time on the main registrar
 */
void calc_ob_contact_expires(struct sip_msg* _m, param_t* _ep, int* _e, struct save_ctx *_sctx)
{
	if (!_ep || !_ep->body.len) {
		*_e = get_expires_hf(_m);
	} else {
		if (str2int(&_ep->body, (unsigned int*)_e) < 0) {
			*_e = default_expires;
		}
	}

	/* extend outgoing timeout, thus "throttling" heavy incoming traffic */
	if (*_e > 0 && *_e < outgoing_expires)
		*_e = outgoing_expires;

	/* Convert to absolute value */
	if (*_e > 0) *_e += get_act_time();

	if (*_e > 0 && (*_e - get_act_time()) < min_expires) {
		*_e = min_expires + get_act_time();
	}

	/* cutting timeout down to "max_expires" */
	if (*_e > 0 && max_expires && ((*_e - get_act_time()) > max_expires)) {
		*_e = max_expires + get_act_time();
	}

	LM_DBG("outgoing expires: %d\n", *_e);
}

static int trim_to_single_contact(struct sip_msg *msg, str *aor)
{
	contact_t *c = NULL;
	struct socket_info *adv_sock;
	struct lump *anchor = NULL;
	char *buf;
	int e, is_dereg = 1, len, len1;
	struct hdr_field *ct;

	adv_sock = *get_sock_info_list(PROTO_UDP);

	/* completely remove all Contact hfs, except the last one */
	for (ct = msg->contact; ct && ct->sibling; ct = ct->sibling) {
		LM_DBG("deleting Contact '%.*s'\n", ct->len, ct->name.s);
		anchor = del_lump(msg, ct->name.s - msg->buf, ct->len, HDR_CONTACT_T);
		if (!anchor)
			return -1;
	}

	for (c = ((contact_body_t *)ct->parsed)->contacts; c;
	     c = get_next_contact(c)) {
		calc_contact_expires(msg, c->expires, &e, NULL);
		if (e != 0)
			is_dereg = 0;

		LM_DBG("deleting Contact '%.*s'\n", c->len, c->name.s);
		anchor = del_lump(msg, c->name.s - msg->buf, c->len, HDR_CONTACT_T);
		if (!anchor)
			return -1;
	}

	if (anchor == NULL) {
		anchor = anchor_lump(msg, msg->unparsed - msg->buf, 0);
		if (anchor == NULL) {
			LM_ERR("failed to add anchor lump\n");
			return -1;
		}
	}

	/*   <   sip:            @                                 :ddddd  > */
	len = 1 + 4 + aor->len + 1 + strlen(adv_sock->address_str.s) + 6 + 1 +
	      + 9 + 10 + 1;
	        /* ;expires=<integer> \0 */

	buf = pkg_malloc(len);
	if (buf == NULL) {
		LM_ERR("out of pkg memory\n");
		return -1;
	}

	/* if use_domain is enabled then don't append proxy ip:port */
	if (reg_use_domain == 0)
		len1 = sprintf(buf, "<sip:%.*s@%s:%s>", aor->len, aor->s,
		               adv_sock->address_str.s, adv_sock->port_no_str.s);
	else
		len1 = sprintf(buf, "<sip:%.*s>", aor->len, aor->s);

	if (!msg->expires || msg->expires->body.len == 0) {
		len1 += sprintf(buf + len1, ";expires=%d",
		                is_dereg ? 0 : outgoing_expires);
	}

	if (len1 >= len) {
		LM_BUG("buffer overflow");
		abort();
	}

	LM_DBG("inserting new Contact '%.*s'\n", len1, buf);

	if (insert_new_lump_after(anchor, buf, len1, HDR_CONTACT_T) == 0) {
		pkg_free(buf);
		return -1;
	}

	return 0;
}

static int overwrite_all_contact_hostports(struct sip_msg *msg)
{
	struct sip_uri uri;
	contact_t *c = NULL;
	struct socket_info *adv_sock;
	struct lump *anchor;
	int is_enclosed;
	str hostport, left, left2;
	char *cp, *buf, temp, *p;
	int len, len1;
	str enct = { NULL, 0 };

	adv_sock = *get_sock_info_list(PROTO_UDP);

	for (c = get_first_contact(msg); c; c = get_next_contact(c)) {
		/* contact found -> parse it */
		if (parse_uri(c->uri.s, c->uri.len, &uri) < 0 || uri.host.len <= 0) {
			LM_ERR("failed to parse Contact URI\n");
			return -1;
		}

		/* if uri string points outside the original msg buffer, it means
		   the URI was already changed, and we cannot do it again */
		if (c->uri.s < msg->buf || c->uri.s > msg->buf + msg->len) {
			LM_ERR("SCRIPT BUG - second attempt to change URI Contact\n");
			return -1;
		}

		hostport = uri.host;
		if (uri.port.len > 0)
			hostport.len = uri.port.s + uri.port.len - uri.host.s;

		LM_DBG("hostport: '%.*s'\n", hostport.len, hostport.s);

		left.s = hostport.s + hostport.len;
		left.len = c->uri.s+c->uri.len - left.s;

		LM_DBG("left: '%.*s'\n", left.len, left.s);
		LM_DBG("uri.maddr: '%.*s'\n", uri.maddr_val.len, uri.maddr_val.s);

		if (uri.maddr.len) {
			left2.s = uri.maddr_val.s + uri.maddr_val.len;
			left2.len = left.s + left.len - left2.s;
			left.len=uri.maddr.s-1-left.s;
		} else {
			left2.s = "";
			left2.len = 0;
		}

		LM_DBG("left2: '%.*s'\n", left2.len, left2.s);

		LM_DBG("c->name: '%.*s'\nin: %.*s\n", c->len, (c->name.s?c->name.s:c->uri.s), c->uri.len, c->uri.s);

		if (encrypt_str(&c->uri, &enct)) {
			LM_ERR("failed to encrypt contact\n");
			return -1;
		}

		is_enclosed = 0;
		p = hostport.s + hostport.len; /*start searching after ip:port */
		cp = (c->name.s?c->name.s:c->uri.s) + c->len; /* where to end */
		for( ; p<cp ; p++ )
			if (*p=='>') {is_enclosed=1;hostport.len=p-uri.host.s;break;}

		anchor = del_lump(msg, hostport.s - msg->buf /* offset */,
			hostport.len /* len */, HDR_CONTACT_T);
		if (!anchor)
			return -1;

		//cp = ip_addr2a(&msg->rcv.src_ip);
		len = strlen(adv_sock->address_str.s)
			+ 6 /* :port */
			+ 2 /* just in case if IPv6 */
			+ 1 + left.len + left2.len
			+ 1 + matching_param.len + 1 + enct.len;

		buf = pkg_malloc(len);
		if (buf == NULL) {
			LM_ERR("out of pkg memory\n");
			return -1;
		}
		temp = hostport.s[0]; hostport.s[0] = '\0';

		LM_DBG("building new Contact:\nuri: '%s'\nadv_sock: '%s'\nport: '%s'\n"
		       "l1: '%.*s'\nl2: '%.*s'\nfull Contact: '%.*s\n"
		       "enc Contact: '%.*s'\n", c->uri.s, adv_sock->address_str.s,
			adv_sock->port_no_str.s,left.len,left.s,left2.len,left2.s,
		    c->uri.len, c->uri.s,
			enct.len, enct.s);

		len1 = snprintf(buf, len, "%s:%s%.*s%.*s;%.*s=%.*s",
		         adv_sock->address_str.s, adv_sock->port_no_str.s,
				 left.len, left.s, left2.len, left2.s,
				 matching_param.len, matching_param.s, enct.len, enct.s);

		if (len1 < len)
			len = len1;

		hostport.s[0] = temp;

		LM_DBG("new hostport;param lump: '%.*s' (%d - %d)\n", len, buf, len1, len);

		if (insert_new_lump_after(anchor, buf, len, HDR_CONTACT_T) == 0) {
			pkg_free(buf);
			return -1;
		}

		if (is_enclosed) {
			c->uri.s = buf;
			c->uri.len = len1;
		} else {
			c->uri.s = buf + 1;
			c->uri.len = len - 2;
		}
	}

	return 0;
}

static int replace_expires_hf(struct sip_msg *msg, int new_expiry)
{
	struct lump *lump;
	char *p;
	int len;

	if (msg->expires && msg->expires->body.len > 0) {
		LM_DBG("....... Exp hdr: '%.*s'\n",
		       msg->expires->body.len, msg->expires->body.s);

		lump = del_lump(msg, msg->expires->body.s - msg->buf,
		                msg->expires->body.len, HDR_EXPIRES_T);
		if (!lump) {
			LM_ERR("fail del_lump on 'Expires:' hf value!\n");
			return -1;
		}

		p = pkg_malloc(10);
		if (!p)
			return -1;

		len = sprintf(p, "%d", new_expiry);

		if (!insert_new_lump_after(lump, p, len, HDR_OTHER_T)) {
			LM_ERR("fail to insert_new_lump over 'Expires' hf value!\n");
			return -1;
		}

		return 0;
	}

	return 1;
}

static int replace_expires(contact_t *c, struct sip_msg *msg, int new_expires,
                            int *skip_exp_header)
{
	/* TODO FIXME we're now assuming the request has an "Expires: " header */
	if (c->expires == NULL || c->expires->body.len == 0) {
		if (*skip_exp_header == 0 && replace_expires_hf(msg, new_expires) == 0)
			*skip_exp_header = 1;
	} else {
		/* TODO ";expires" overwriting!!! */
	}

	return 0;
}

void overwrite_contact_expirations(struct sip_msg *req, struct mid_reg_info *mri)
{
	contact_t *c;
	int e, expiry_tick, new_expires;
	int skip_exp_header = 0;

	for (c = get_first_contact(req); c; c = get_next_contact(c)) {
		calc_contact_expires(req, c->expires, &e, NULL);
		calc_ob_contact_expires(req, c->expires, &expiry_tick, NULL);
		if (expiry_tick == 0)
			new_expires = 0;
		else
			new_expires = expiry_tick - get_act_time();

		LM_DBG("....... contact: '%.*s' Calculated TIMEOUT = %d (%d)\n",
		       c->len, c->uri.s, expiry_tick, new_expires);

		mri->expires = e;
		mri->expires_out = new_expires;

		if (e != new_expires &&
		    replace_expires(c, req, new_expires, &skip_exp_header) != 0) {
			LM_ERR("failed to replace expires for ct '%.*s'\n",
			       c->uri.len, c->uri.s);
		}
	}
}


void mid_reg_req_fwded(struct cell *t, int type, struct tmcb_params *params)
{
	struct sip_msg *req = params->req;
	struct mid_reg_info *mri = *(struct mid_reg_info **)(params->param);
	str user = {NULL, 0};

	parse_reg_headers(req);
	if (req->expires)
		LM_DBG("msg expires: '%.*s'\n", req->expires->body.len, req->expires->body.s);

	if (reg_mode != MID_REG_MIRROR) {
		overwrite_contact_expirations(req, mri);
	}

	shm_str_dup(&mri->main_reg_uri, GET_NEXT_HOP(req));

	if (reg_mode == MID_REG_THROTTLE_AOR) {
		LM_DBG("trimming all Contact URIs into one...\n");
		if (trim_to_single_contact(req, &mri->aor))
			LM_ERR("failed to overwrite Contact URI\n");
	}

	if (insertion_mode == INSERT_BY_PATH) {
		if (prepend_path(req, &user, 0, 0))
			LM_ERR("failed to append Path header for aor '%.*s'!\n",
			       mri->aor.len, mri->aor.s);
	} else {
		if (reg_mode == MID_REG_MIRROR || reg_mode == MID_REG_THROTTLE_CT) {
			LM_DBG("fixing Contact URI ...\n");
			if (overwrite_all_contact_hostports(req))
				LM_ERR("failed to overwrite Contact URI\n");
		}
	}

	LM_DBG("REQ FORWARDED TO '%.*s', expires=%d\n",
	       mri->main_reg_uri.len, mri->main_reg_uri.s, mri->expires_out);
}

int replace_response_expires(struct sip_msg *msg, contact_t *ct, int expires)
{
	struct lump *lump;
	int len;
	char *p;

	LM_DBG("replacing expires for ct '%.*s' '%.*s' with %d, %p -> %p (? %p)\n",
	       ct->uri.len, ct->uri.s, ct->expires->body.len, ct->expires->body.s,
	       expires, msg->buf, msg->buf+msg->len, ct->expires->body.s);

	lump = del_lump(msg, ct->expires->body.s - msg->buf, ct->expires->body.len,
	                HDR_EXPIRES_T);
	if (!lump) {
		LM_ERR("del_lump() failed!\n");
		return -1;
	}

	p = pkg_malloc(10);
	if (!p)
		return -1;

	len = sprintf(p, "%d", expires);

	if (!insert_new_lump_after(lump, p, len, HDR_OTHER_T)) {
		LM_ERR("insert_new_lump_after() failed!\n");
		return -1;
	}

	return 0;
}

static struct mid_reg_info *mri_dup(struct mid_reg_info *mri)
{
	struct mid_reg_info *ret;

	ret = shm_malloc(sizeof *ret);
	if (!ret)
		return NULL;
	memset(ret, 0, sizeof *ret);

	ret->reg_flags = mri->reg_flags;

	if (mri->aor.s)
		shm_str_dup(&ret->aor, &mri->aor);

	if (mri->from.s)
		shm_str_dup(&ret->from, &mri->from);

	if (mri->to.s)
		shm_str_dup(&ret->to, &mri->to);

	if (mri->callid.s)
		shm_str_dup(&ret->callid, &mri->callid);

	if (mri->ct_uri.s)
		shm_str_dup(&ret->ct_uri, &mri->ct_uri);

	if (mri->main_reg_uri.s)
		shm_str_dup(&ret->main_reg_uri, &mri->main_reg_uri);

	return ret;
}

static inline unsigned int calc_buf_len(ucontact_t* c,int build_gruu,
		struct sip_msg *_m)
{
	unsigned int len;
	int qlen;
	struct socket_info *sock;

	len = 0;
	while(c) {
		if (VALID_CONTACT(c, get_act_time())) {
			if (len) len += CONTACT_SEP_LEN;
			len += 2 /* < > */ + c->c.len;
			qlen = len_q(c->q);
			if (qlen) len += Q_PARAM_LEN + qlen;
			len += EXPIRES_PARAM_LEN + INT2STR_MAX_LEN;
			if (c->received.s) {
				len += 1 /* ; */
					+ rcv_param.len
					+ 1 /* = */
					+ 1 /* dquote */
					+ c->received.len
					+ 1 /* dquote */
					;
			}
			if (build_gruu && c->instance.s) {
				sock = (c->sock)?(c->sock):(_m->rcv.bind_address);
				/* pub gruu */
				len += PUB_GRUU_SIZE
					+ 1 /* quote */
					+ SIP_PROTO_SIZE
					+ c->aor->len
					+ (reg_use_domain ?0:(1 /* @ */ + sock->name.len + 1 /* : */ + sock->port_no_str.len))
					+ GR_PARAM_SIZE
					+ (c->instance.len - 2)
					+ 1 /* quote */
					;
				/* temp gruu */
				len += TEMP_GRUU_SIZE
					+ 1 /* quote */
					+ SIP_PROTO_SIZE
					+ TEMP_GRUU_HEADER_SIZE
					+ calc_temp_gruu_len(c->aor,&c->instance,&c->callid)
					+ 1 /* @ */
					+ sock->name.len
					+ 1 /* : */
					+ sock->port_no_str.len
					+ GR_NO_VAL_SIZE
					+ 1 /* quote */
					;
				/* sip.instance */
				len += SIP_INSTANCE_SIZE
					+ 1 /* quote */
					+ (c->instance.len - 2)
					+ 1 /* quote */
					;
			}
		}
		c = c->next;
	}

	if (len) len += CONTACT_BEGIN_LEN + CRLF_LEN;
	return len;
}


int build_contact(ucontact_t* c,struct sip_msg *_m)
{
	char *p, *cp, *tmpgr;
	int fl, len,grlen;
	int build_gruu = 0;
	struct socket_info *sock;

	LM_DBG("building contact ...\n");

	if (!disable_gruu && _m->supported && parse_supported(_m) == 0 &&
		(get_supported(_m) & F_SUPPORTED_GRUU))
		build_gruu=1;

	contact.data_len = calc_buf_len(c,build_gruu,_m);
	if (!contact.data_len) return 0;

	if (!contact.buf || (contact.buf_len < contact.data_len)) {
		if (contact.buf) pkg_free(contact.buf);
		contact.buf = (char*)pkg_malloc(contact.data_len);
		if (!contact.buf) {
			contact.data_len = 0;
			contact.buf_len = 0;
			LM_ERR("no pkg memory left\n");
			return -1;
		} else {
			contact.buf_len = contact.data_len;
		}
	}

	p = contact.buf;

	memcpy(p, CONTACT_BEGIN, CONTACT_BEGIN_LEN);
	p += CONTACT_BEGIN_LEN;

	fl = 0;
	while(c) {
		if (VALID_CONTACT(c, get_act_time())) {
			if (fl) {
				memcpy(p, CONTACT_SEP, CONTACT_SEP_LEN);
				p += CONTACT_SEP_LEN;
			} else {
				fl = 1;
			}

			*p++ = '<';
			memcpy(p, c->c.s, c->c.len);
			p += c->c.len;
			*p++ = '>';

			len = len_q(c->q);
			if (len) {
				memcpy(p, Q_PARAM, Q_PARAM_LEN);
				p += Q_PARAM_LEN;
				memcpy(p, q2str(c->q, 0), len);
				p += len;
			}

			memcpy(p, EXPIRES_PARAM, EXPIRES_PARAM_LEN);
			p += EXPIRES_PARAM_LEN;
			cp = int2str((int)(c->expires - get_act_time()), &len);
			memcpy(p, cp, len);
			p += len;

			if (c->received.s) {
				*p++ = ';';
				memcpy(p, rcv_param.s, rcv_param.len);
				p += rcv_param.len;
				*p++ = '=';
				*p++ = '\"';
				memcpy(p, c->received.s, c->received.len);
				p += c->received.len;
				*p++ = '\"';
			}

			if (build_gruu && c->instance.s) {
				sock = (c->sock)?(c->sock):(_m->rcv.bind_address);
				/* build pub GRUU */
				memcpy(p,PUB_GRUU,PUB_GRUU_SIZE);
				p += PUB_GRUU_SIZE;
				*p++ = '\"';
				memcpy(p,SIP_PROTO,SIP_PROTO_SIZE);
				p += SIP_PROTO_SIZE;
				memcpy(p,c->aor->s,c->aor->len);
				p += c->aor->len;
				if (!reg_use_domain) {
					*p++ = '@';
					memcpy(p,sock->name.s,sock->name.len);
					p += sock->name.len;
					*p++ = ':';
					memcpy(p,sock->port_no_str.s,sock->port_no_str.len);
					p += sock->port_no_str.len;
				}
				memcpy(p,GR_PARAM,GR_PARAM_SIZE);
				p += GR_PARAM_SIZE;
				memcpy(p,c->instance.s+1,c->instance.len-2);
				p += c->instance.len-2;
				*p++ = '\"';

				/* build temp GRUU */
				memcpy(p,TEMP_GRUU,TEMP_GRUU_SIZE);
				p += TEMP_GRUU_SIZE;
				*p++ = '\"';
				memcpy(p,SIP_PROTO,SIP_PROTO_SIZE);
				p += SIP_PROTO_SIZE;
				memcpy(p,TEMP_GRUU_HEADER,TEMP_GRUU_HEADER_SIZE);
				p += TEMP_GRUU_HEADER_SIZE;

				tmpgr = build_temp_gruu(c->aor,&c->instance,&c->callid,&grlen);
				base64encode((unsigned char *)p,
						(unsigned char *)tmpgr,grlen);
				p += calc_temp_gruu_len(c->aor,&c->instance,&c->callid);
				*p++ = '@';
				memcpy(p,sock->name.s,sock->name.len);
				p += sock->name.len;
				*p++ = ':';
				memcpy(p,sock->port_no_str.s,sock->port_no_str.len);
				p += sock->port_no_str.len;
				memcpy(p,GR_NO_VAL,GR_NO_VAL_SIZE);
				p += GR_NO_VAL_SIZE;
				*p++ = '\"';

				/* build +sip.instance */
				memcpy(p,SIP_INSTANCE,SIP_INSTANCE_SIZE);
				p += SIP_INSTANCE_SIZE;
				*p++ = '\"';
				memcpy(p,c->instance.s+1,c->instance.len-2);
				p += c->instance.len-2;
				*p++ = '\"';
			}
		}

		c = c->next;
	}

	memcpy(p, CRLF, CRLF_LEN);
	p += CRLF_LEN;

	contact.data_len = p - contact.buf;

	LM_DBG("created Contact HF: %.*s\n", contact.data_len, contact.buf);
	return 0;
}

static int match_contact(struct sip_uri *ct, struct sip_msg *msg, contact_t **out)
{
	contact_t *c;
	struct sip_uri uri, match_uri;
	str match_tok, dec_uri;
	int i;

	for (c = get_first_contact2(msg); c; c = get_next_contact2(c)) {
		LM_DBG("it='%.*s'\n", c->uri.len, c->uri.s);

		if (insertion_mode == INSERT_BY_PATH) {
			dec_uri = c->uri;
		} else {
			if (get_match_token(&c->uri, &match_tok, &uri, &i) != 0) {
				LM_ERR("failed to get match token\n");
				return -1;
			}

			if (decrypt_str(&match_tok, &dec_uri)) {
				LM_ERR("failed to decrypt matching Contact param (%.*s=%.*s)\n",
				       matching_param.len, matching_param.s,
				       match_tok.len, match_tok.s);
				return -1;
			}
		}

		if (parse_uri(dec_uri.s, dec_uri.len, &match_uri) < 0) {
			pkg_free(dec_uri.s);
			LM_ERR("failed to parse decrypted uri <%.*s>\n",
			       dec_uri.len, dec_uri.s);
			return -1;
		}

		/* try to match the request Contact with a Contact from the reply */
		if (compare_uris(NULL, &match_uri, NULL, ct) == 0) {
			*out = c;
			return 0;
		}
	}

	return -1;
}

/**
 * RFC 3261, section 10.3.8 - "Processing REGISTER requests"
 *
 * "The binding updates MUST be committed (that is, made visible to
 * the proxy or redirect server) if and only if all binding
 * updates and additions succeed.  If any one of them fails (for
 * example, because the back-end database commit failed), the
 * request MUST fail with a 500 (Server Error) response and all
 * tentative binding updates MUST be removed."
 *
 * Since a 200 OK was received, we can safely assume all request contacts
 * are contained in the reply. However, we still do need to do some matching
 * in order to determine each new ";expires" value, since responses MUST
 * contain all bindings, not just the ones from the request!
 */
static inline int save_rpl_contacts(struct sip_msg *req, struct sip_msg* rpl,
			struct mid_reg_info *mri, str* _a, urecord_t *r)
{
	struct mid_reg_info *cti;
	ucontact_info_t* ci = NULL;
	ucontact_t* c;
	contact_t *_c = NULL, *__c;
	unsigned int cflags;
	int e, e_out;
	int e_max = 0;
	int tcp_check = 0;
	struct sip_uri uri;
	str ct_uri;

	cflags = (mri->reg_flags&REG_SAVE_MEMORY_FLAG)?FL_MEM:FL_NONE;
	if (is_tcp_based_proto(req->rcv.proto) && (req->flags & tcp_persistent_flag)) {
		tcp_check = 1;
	}

	if (!r) {
		if (ul_api.insert_urecord(mri->dom, _a, &r, 0) < 0) {
			rerrno = R_UL_NEW_R;
			LM_ERR("failed to insert new record structure\n");
			goto error;
		}
	}

	LM_DBG("running\n");

	for (__c = get_first_contact(req); __c; __c = get_next_contact(__c)) {
		/* calculate expires */
		calc_contact_expires(req, __c->expires, &e, NULL);

		if (parse_uri(__c->uri.s, __c->uri.len, &uri) < 0) {
			LM_ERR("failed to parse contact <%.*s>\n",
					__c->uri.len, __c->uri.s);
			return -1;
		}

		LM_DBG("REQ ct: [name='%.*s', uri='%.*s']\n",
		       uri.user.len, uri.user.s, __c->uri.len, __c->uri.s);

		if (match_contact(&uri, rpl, &_c) != 0) {
			if (e != 0) {
				LM_ERR("Contact '%.*s' not found in reply from main registrar!\n",
				       __c->uri.len, __c->uri.s);
				return -1;
			}

			/* Contact deleted on main registrar! We can also delete it now! */
			goto update_usrloc;
		}

		calc_contact_expires(rpl, _c->expires, &e_out, NULL);

		/*
		 * if (mri->max_contacts && (num >= mri->max_contacts)) {
		 * 	if (mri->reg_flags&REG_SAVE_FORCE_REG_FLAG) {
		 * 		// we are overflowing the number of maximum contacts,
		 * 		 //  so remove the first (oldest) one to prevent this
		 * 		if (r==NULL || r->contacts==NULL) {
		 * 			LM_CRIT("BUG - overflow detected with r=%p and "
		 * 				"contacts=%p\n",r,r->contacts);
		 * 			goto error;
		 * 		}
		 * 		if (ul_api.delete_ucontact( r, r->contacts, 0)!=0) {
		 * 			LM_ERR("failed to remove contact\n");
		 * 			goto error;
		 * 		}
		 * 	} else {
		 * 		LM_ERR("too many contacts (%d) for AOR <%.*s>, max=%d\n",
		 * 				num, _a->len, _a->s, mri->max_contacts);
		 * 		rerrno = R_TOO_MANY;
		 * 		goto error;
		 * 	}
		 * } else {
		 * 	num++;
		 * }
		 */

		LM_DBG("    >> REGISTER %ds ------- %ds 200 OK <<!\n", e, e_out);

		if (e != e_out) {
			if (replace_response_expires(rpl, _c, e)) {
				LM_ERR("failed to mangle 200 OK response!\n");
				return -1;
			}
		}

update_usrloc:
		c = NULL;
		/* pack the contact_info */
		ci = pack_ci(req, __c, e + get_act_time(), cflags,
		             ul_api.nat_flag, mri->reg_flags);
		if (ci == NULL) {
			LM_ERR("failed to extract contact info\n");
			goto error;
		}
		ci->expires_out = e_out;

		if ((r->contacts==0 ||
		ul_api.get_ucontact(r, &__c->uri, ci->callid, ci->cseq+1, &c)!=0) && e > 0) {
			LM_DBG("INSERTING .....\n");
			LM_DBG(":: inserting contact with expires %lu\n", ci->expires);

			if (reg_mode != MID_REG_MIRROR) {
				cti = mri_dup(mri);
				ct_uri.len = _c->uri.len;
				ct_uri.s = _c->uri.s;

				shm_str_dup(&cti->ct_uri, &ct_uri);

				cti->expires = e;
				cti->expires_out = e_out;
				cti->last_reg_ts = get_act_time();
				set_ct(cti);
			}

			if (ul_api.insert_ucontact( r, &__c->uri, ci, &c, 0) < 0) {
				rerrno = R_UL_INS_C;
				LM_ERR("failed to insert contact\n");
				goto error;
			}

			set_ct(NULL);

		} else if (c != NULL) {
			if (e == 0) {
				cti = (struct mid_reg_info *)c->attached_data[ucontact_data_idx];
				cti->skip_dereg = 1;

				if (ul_api.delete_ucontact(r, c, 0) < 0) {
					rerrno = R_UL_UPD_C;
					LM_ERR("failed to update contact\n");
					goto error;
				}
				continue;
			}

			LM_DBG("UPDATING .....\n");
			if (reg_mode != MID_REG_MIRROR) {
				cti = c->attached_data[ucontact_data_idx];
				cti->expires_out = e_out;
				set_ct(cti);
			}

			if (ul_api.update_ucontact( r, c, ci, 0) < 0) {
				rerrno = R_UL_UPD_C;
				LM_ERR("failed to update contact\n");
				goto error;
			}

			set_ct(NULL);
		}

		if (tcp_check) {
			/* parse contact uri to see if transport is TCP */
			if (parse_uri( __c->uri.s, __c->uri.len, &uri)<0) {
				LM_ERR("failed to parse contact <%.*s>\n",
						__c->uri.len, __c->uri.s);
			} else if ( is_tcp_based_proto(uri.proto) ) {
				if (e_max) {
					LM_WARN("multiple TCP contacts on single REGISTER\n");
					if (e_out>e_max) e_max = e_out;
				} else {
					e_max = e_out;
				}
			}
		}
	}

	if (r) {
		ul_api.release_urecord(r, 0);
	}

	if ( tcp_check && e_max>0 ) {
		e_max -= get_act_time();
		trans_set_dst_attr( &req->rcv, DST_FCNTL_SET_LIFETIME,
			(void*)(long)(e_max + 10) );
	}

	return 0;
error:
	if (r)
		ul_api.delete_urecord(mri->dom, _a, r, 0);
	return -1;
}

/* only relevant in MID_REG_THROTTLE_AOR mode */
static inline int save_restore_req_contacts(struct sip_msg *req, struct sip_msg* rpl,
                         struct mid_reg_info *mri, str* _a, urecord_t *r)
{
	struct mid_reg_info *ri, *cti;
	ucontact_info_t* ci = NULL;
	ucontact_t* c;
	contact_t *_c, *__c, *__cn;
	unsigned int cflags;
	int e, e_out = -1;
	int e_max = 0;
	int tcp_check = 0;
	struct sip_uri uri;
	struct lump *anchor;
	str ct;
	char *buf;
	int len;

	cflags = (mri->reg_flags&REG_SAVE_MEMORY_FLAG)?FL_MEM:FL_NONE;
	if (is_tcp_based_proto(req->rcv.proto) && (req->flags & tcp_persistent_flag)) {
		tcp_check = 1;
	}

	LM_DBG("saving + restoring all contact URIs ... \n");

	/* in MID_REG_THROTTLE_AOR mode, any reply will only contain 1 contact */
	_c = get_first_contact(rpl);
	if (_c != NULL)
		calc_contact_expires(rpl, _c->expires, &e_out, NULL);

	if (!r) {
		/*
		 * AoR not yet stored here, and the main registrar is also clean!
		 * Just skip processing any contacts found in the request, we're good.
		 */
		if (_c == NULL)
			return 0;

		ri = mri_dup(mri);
		ct.len = _c->uri.len;
		ct.s = _c->uri.s;
		shm_str_dup(&ri->ct_uri, &ct);
		ri->expires_out = e_out;
		ri->last_reg_ts = get_act_time();

		set_ct(ri);

		if (ul_api.insert_urecord(mri->dom, _a, &r, 0) < 0) {
			rerrno = R_UL_NEW_R;
			LM_ERR("failed to insert new record structure\n");
			goto error;
		}

		set_ct(NULL);
	} else {
		ri = (struct mid_reg_info *)r->attached_data[urecord_data_idx];
		if (_c == NULL) {
			ri->last_reg_ts = 0;
			ri->skip_dereg = 1;
		} else {
			ri->last_reg_ts = get_act_time();
		}
	}

	if (_c != NULL) {
		/**
		 * we now replace the single reply Contact hf with all Contact hfs
		 * present in the initial request
		 */
		if (del_lump(rpl, rpl->contact->name.s - rpl->buf,
		                  rpl->contact->len, HDR_CONTACT_T) == NULL) {
			LM_ERR("failed to delete contact '%.*s'\n", rpl->contact->name.len,
			       rpl->contact->name.s);
			return -1;
		}
	}

#ifdef EXTRA_DEBUG
	log_contacts(get_first_contact(req));
#endif

	for (__c = get_first_contact(req); __c; __c = __cn) {
		__cn = get_next_contact(__c);

		/* calculate expires */
		calc_contact_expires(req, __c->expires, &e, NULL);
		if (_c == NULL) {
			if (e != 0)
				LM_ERR("200 OK from main registrar is missing Contact '%.*s'\n",
				       __c->uri.len, __c->uri.s);
			goto update_usrloc;
		}

		/* the main registrar might enforce shorter lifetimes */
		if (e_out < e) {
			e = e_out;
		}

		LM_DBG("expires: %d - %d\n", e, e_out);

		LM_DBG("REQ ct: '%.*s']\n", __c->uri.len, __c->uri.s);

		LM_DBG("appending initial Contact to reply: '%.*s'\n",
		       req->contact->len, req->contact->name.s);

		len = contact_hdr.len + __c->len + 2 + expires_param.len + 10 + CRLF_LEN + CRLF_LEN;
		buf = pkg_malloc(len + 1);
		if (buf == NULL) {
			LM_ERR("out of pkg mem\n");
			return -1;
		}

		len = sprintf(buf, "%.*s%.*s", contact_hdr.len, contact_hdr.s,
		              __c->len, __c->name.s);

		if (__c->expires == NULL)
			len += sprintf(buf + len, ";expires=%d\r\n", e);
		if (__cn == NULL)
			len += sprintf(buf + len, "\r\n");

		anchor = anchor_lump(rpl, rpl->unparsed - rpl->buf, 0);
		if (insert_new_lump_after(anchor, buf, len, HDR_CONTACT_T) == NULL) {
			pkg_free(buf);
			return -1;
		}

		LM_DBG("    >> REGISTER %ds ------- %ds 200 OK <<!\n", e, e_out);

update_usrloc:
		c = NULL;
		/* pack the contact_info */
		ci = pack_ci(req, __c, e + get_act_time(), cflags,
		             ul_api.nat_flag, mri->reg_flags);
		if (ci == NULL) {
			LM_ERR("failed to extract contact info\n");
			goto error;
		}
		ci->expires_out = e_out;

		if ((r->contacts == NULL ||
		    ul_api.get_ucontact(r, &__c->uri, ci->callid, ci->cseq+1, &c) != 0) && e > 0) {
			LM_DBG("INSERTING .....\n");
			LM_DBG(":: inserting contact with expires %lu\n", ci->expires);

			if (reg_mode != MID_REG_MIRROR) {
				cti = mri_dup(mri);
				ct.len = _c->uri.len;
				ct.s = _c->uri.s;

				shm_str_dup(&cti->ct_uri, &ct);

				cti->expires = e;
				cti->expires_out = e_out;
				cti->last_reg_ts = mri->last_reg_ts;
				set_ct(cti);
			}

			if (ul_api.insert_ucontact( r, &__c->uri, ci, &c, 0) < 0) {
				rerrno = R_UL_INS_C;
				LM_ERR("failed to insert contact\n");
				goto error;
			}

			set_ct(NULL);

		} else if (c != NULL) {
			if (e == 0) {
				if (ul_api.delete_ucontact(r, c, 0) < 0) {
					rerrno = R_UL_UPD_C;
					LM_ERR("failed to update contact\n");
					goto error;
				}
				continue;
			}

			LM_DBG("UPDATING .....\n");
			if (reg_mode != MID_REG_MIRROR) {
				cti = c->attached_data[ucontact_data_idx];
				cti->expires = e;
				cti->expires_out = e_out;
				set_ct(cti);
			}

			if (ul_api.update_ucontact( r, c, ci, 0) < 0) {
				rerrno = R_UL_UPD_C;
				LM_ERR("failed to update contact\n");
				goto error;
			}

			set_ct(NULL);
		}

		if (tcp_check) {
			/* parse contact uri to see if transport is TCP */
			if (parse_uri( __c->uri.s, __c->uri.len, &uri)<0) {
				LM_ERR("failed to parse contact <%.*s>\n",
						__c->uri.len, __c->uri.s);
			} else if ( is_tcp_based_proto(uri.proto) ) {
				if (e_max) {
					LM_WARN("multiple TCP contacts on single REGISTER\n");
					if (e_out>e_max) e_max = e_out;
				} else {
					e_max = e_out;
				}
			}
		}
	}

	if (r) {
		ul_api.release_urecord(r, 0);
	}

	if ( tcp_check && e_max>0 ) {
		e_max -= get_act_time();
		trans_set_dst_attr( &req->rcv, DST_FCNTL_SET_LIFETIME,
			(void*)(long)(e_max + 10) );
	}

	return 0;
error:
	if (r)
		ul_api.delete_urecord(mri->dom, _a, r, 0);
	return -1;
}

/*
 * Fixes the required 200 OK reply Contact header field domain
 * so it matches the one from the INVITE
 */
static int restore_reply_contacts(struct sip_msg *req, struct sip_msg *rpl)
{
	contact_t *c, *req_ct;
	struct sip_uri newuri, uri, match_uri;
	str match_tok, hostport, dec_uri;
	char *buf;
	int i;
	struct lump *anchor;

	LM_DBG("fixing reply domain by Contact\n");

	/* TODO: add proper handling for multiple Contacts!!! */
	req_ct = get_first_contact(req);
	if (parse_uri(req_ct->uri.s, req_ct->uri.len, &newuri) < 0) {
		LM_ERR("failed to parse contact <%.*s>\n",
				req_ct->uri.len, req_ct->uri.s);
		return -1;
	}

	for (c = get_first_contact(rpl); c; c = get_next_contact(c)) {
		memset(&match_tok, 0, sizeof match_tok);

		if (get_match_token(&c->uri, &match_tok, &uri, &i) != 0) {
			LM_ERR("failed to get match token\n");
			return -1;
		}

		if (decrypt_str(&match_tok, &dec_uri)) {
			LM_ERR("failed to decrypt matching Contact param (%.*s=%.*s)\n",
			       matching_param.len, matching_param.s,
			       match_tok.len, match_tok.s);
			return -1;
		}

		if (parse_uri(dec_uri.s, dec_uri.len, &match_uri) < 0) {
			pkg_free(dec_uri.s);
			LM_ERR("failed to parse decrypted uri <%.*s>\n",
			       dec_uri.len, dec_uri.s);
			return -1;
		}

		/* try to match the request Contact with a Contact from the reply */
		if (compare_uris(NULL, &match_uri, NULL, &newuri))
			continue;

		hostport = uri.host;
		if (uri.port.len > 0)
			hostport.len = uri.port.s + uri.port.len - uri.host.s;

		LM_DBG("> hostport for dec_uri '%.*s' is '%.*s\n", dec_uri.len,
		       dec_uri.s, hostport.len, hostport.s);

		/* ERASE host:port part */

		anchor = del_lump(rpl, hostport.s - rpl->buf /* offset */,
		                  hostport.len, HDR_CONTACT_T);
		if (!anchor) {
			LM_ERR("del_lump 1 failed for reply Contact URI '%.*s'\n",
			       c->uri.len, c->uri.s);
			return -1;
		}

		hostport = match_uri.host;
		if (match_uri.port.len > 0)
			hostport.len = match_uri.port.s + match_uri.port.len - match_uri.host.s;

		buf = pkg_malloc(hostport.len + 1);
		if (buf == NULL) {
			LM_ERR("out of pkg memory\n");
			return -1;
		}

		memcpy(buf, hostport.s, hostport.len);
		buf[hostport.len] = '\0';

		LM_DBG("inserting new uri: '%s'\n", buf);

		if (insert_new_lump_after(anchor, buf, hostport.len, HDR_CONTACT_T) == 0) {
			pkg_free(buf);
			return -1;
		}

		LM_DBG("deleting param '%.*s' @ %p\n", uri.u_name[i].len, uri.u_name[i].s, uri.u_name[i].s);

		/* We now erase the ";param=value" part */

		if (matching_mode == MATCH_BY_PARAM) {
			/* remove our added matching parameter on the way back to the UAC */
			if (!del_lump(rpl, uri.u_name[i].s - rpl->buf - 1 /* offset */,
				1 + uri.u_name[i].len + 1 + match_tok.len /* ;param=value */, HDR_OTHER_T)) {
				LM_ERR("del_lump 2 failed for reply Contact URI '%.*s'\n",
				       c->uri.len, c->uri.s);
				return -1;
			}
		}

		pkg_free(dec_uri.s);
	}

	return 0;
}

/*! \brief
 * Process request that contained a star, in that case,
 * we will remove all bindings with the given username
 * from the usrloc and return 200 OK response
 */
static inline int star(udomain_t* _d, struct mid_reg_info *mri,
		struct sip_msg *_m)
{
	urecord_t* r;
	ucontact_t* c;

	ul_api.lock_udomain(_d, &mri->aor);

	if (!ul_api.get_urecord(_d, &mri->aor, &r)) {
		c = r->contacts;
		while(c) {
			if (mri->reg_flags&REG_SAVE_MEMORY_FLAG) {
				c->flags |= FL_MEM;
			} else {
				c->flags &= ~FL_MEM;
			}
			c = c->next;
		}
	}

	if (ul_api.delete_urecord(_d, &mri->aor, NULL, 0) < 0) {
		LM_ERR("failed to remove record from usrloc\n");

		     /* Delete failed, try to get corresponding
		      * record structure and send back all existing
		      * contacts
		      */
		rerrno = R_UL_DEL_R;
		if (!ul_api.get_urecord(_d, &mri->aor, &r)) {
			build_contact(r->contacts,_m);
		}
		ul_api.unlock_udomain(_d, &mri->aor);
		return -1;
	}
	ul_api.unlock_udomain(_d, &mri->aor);
	return 0;
}


void mid_reg_trans_deleted(struct cell *t, int type, struct tmcb_params *params)
{
	struct mid_reg_info *mri = *(struct mid_reg_info **)(params->param);
	mri_free(mri);
}

void mid_reg_resp_in(struct cell *t, int type, struct tmcb_params *params)
{
	struct mid_reg_info *mri = *(struct mid_reg_info **)(params->param);
	urecord_t *rec = NULL;
	struct sip_msg *rpl = params->rpl;
	struct sip_msg *req = params->req;
	int code;

	code = rpl->first_line.u.reply.statuscode;
	LM_DBG("pushing reply back to caller: %d\n", code);
	LM_DBG("request -------------- \n%s\nxxx: \n", req->buf);
	LM_DBG("reply -------------- \n%s\n", rpl->buf);

	if (code < 200 || code >= 300)
		goto out_free;

	update_act_time();

	parse_reg_headers(req);
	parse_reg_headers(rpl);

	if (mri->star) {
		if (star(mri->dom, mri, req) < 0) {
			LM_ERR("failed to fully delete AoR '%.*s'\n",
			       mri->aor.len, mri->aor.s);
		}

		goto out_free;
	}

	if (reg_mode != MID_REG_THROTTLE_AOR && insertion_mode == INSERT_BY_CONTACT) {
		LM_DBG("restoring contact URIs ... \n");
		if (restore_reply_contacts(req, rpl)) {
			LM_ERR("failed to overwrite Contact header field domain\n");
		}
	}

	ul_api.lock_udomain(mri->dom, &mri->aor);
	ul_api.get_urecord(mri->dom, &mri->aor, &rec);

	LM_DBG("rec=%p\n", rec);

	if (reg_mode == MID_REG_MIRROR || reg_mode == MID_REG_THROTTLE_CT) {
		if (save_rpl_contacts(req, rpl, mri, &mri->aor, rec)) {
			LM_ERR("failed to process rpl contacts for AoR '%.*s'\n",
			       mri->aor.len, mri->aor.s);
		}
	} else if (reg_mode == MID_REG_THROTTLE_AOR) {
		if (save_restore_req_contacts(req, rpl, mri, &mri->aor, rec)) {
			LM_ERR("failed to process req contacts for AoR '%.*s'\n",
			       mri->aor.len, mri->aor.s);
		}
	}

	ul_api.unlock_udomain(mri->dom, &mri->aor);

	LM_DBG("got ptr back: %p\n", mri);
	LM_DBG("RESPONSE FORWARDED TO caller!\n");

out_free:
	LM_DBG("not yet freeing mri: %p\n", mri);
}

/* !! retcodes: 1 or -1 !! */
static int prepare_forward(struct sip_msg *msg, udomain_t *ud,
                           str *aor, struct save_ctx *sctx)
{
	struct mid_reg_info *mri;
	struct to_body *to, *from;

	LM_DBG("from: '%.*s'\n", msg->from->body.len, msg->from->body.s);
	LM_DBG("Call-ID: '%.*s'\n", msg->callid->body.len, msg->callid->body.s);
	LM_DBG("Contact: '%.*s'\n", msg->contact->body.len, msg->contact->body.s);

	mri = shm_malloc(sizeof *mri);
	if (mri == NULL) {
		LM_ERR("no more shm\n");
		return -1;
	}

	memset(mri, 0, sizeof *mri);

	mri->expires = 0;
	mri->expires_out = sctx->expires_out;
	mri->dom = ud;
	mri->reg_flags = sctx->flags;
	mri->star = sctx->star;

	if (aor)
		shm_str_dup(&mri->aor, aor);

	if (parse_from_header(msg) != 0) {
		LM_ERR("failed to parse From hf\n");
		mri_free(mri);
		return -1;
	}

	from = get_from(msg);
	shm_str_dup(&mri->from, &from->uri);

	to = get_to(msg);
	shm_str_dup(&mri->to, &to->uri);

	shm_str_dup(&mri->callid, &msg->callid->body);

	LM_DBG("registering callback on TMCB_TRANS_DELETED, mri=%p ...\n", mri);
	if (tm_api.register_tmcb(msg, NULL, TMCB_TRANS_DELETED,
	    mid_reg_trans_deleted, mri, NULL) <= 0) {
		LM_ERR("cannot register additional callbacks\n");
		mri_free(mri);
		return -1;
	}

	LM_DBG("registering ptr %p on TMCB_REQUEST_FWDED ...\n", mri);
	if (tm_api.register_tmcb(msg, NULL, TMCB_REQUEST_FWDED,
	    mid_reg_req_fwded, mri, NULL) <= 0) {
		LM_ERR("cannot register additional callbacks\n");
		return -1;
	}

	LM_DBG("registering callback on TMCB_RESPONSE_FWDED, mri=%p ...\n", mri);
	if (tm_api.register_tmcb(msg, NULL, TMCB_RESPONSE_IN,
	    mid_reg_resp_in, mri, NULL) <= 0) {
		LM_ERR("cannot register additional callbacks\n");
		return -1;
	}

	return 1;
}

static int add_retry_after(struct sip_msg* _m)
{
	char* buf, *ra_s;
	int ra_len;

 	ra_s = int2str(retry_after, &ra_len);
 	buf = (char*)pkg_malloc(RETRY_AFTER_LEN + ra_len + CRLF_LEN);
 	if (!buf) {
 		LM_ERR("no pkg memory left\n");
 		return -1;
 	}
 	memcpy(buf, RETRY_AFTER, RETRY_AFTER_LEN);
 	memcpy(buf + RETRY_AFTER_LEN, ra_s, ra_len);
 	memcpy(buf + RETRY_AFTER_LEN + ra_len, CRLF, CRLF_LEN);
 	add_lump_rpl(_m, buf, RETRY_AFTER_LEN + ra_len + CRLF_LEN,
 		     LUMP_RPL_HDR | LUMP_RPL_NODUP);
 	return 0;
}

#define PATH "Path: "
#define PATH_LEN (sizeof(PATH) - 1)

static int add_path(struct sip_msg* _m, str* _p)
{
	char* buf;

 	buf = (char*)pkg_malloc(PATH_LEN + _p->len + CRLF_LEN);
 	if (!buf) {
 		LM_ERR("no pkg memory left\n");
 		return -1;
 	}
 	memcpy(buf, PATH, PATH_LEN);
 	memcpy(buf + PATH_LEN, _p->s, _p->len);
 	memcpy(buf + PATH_LEN + _p->len, CRLF, CRLF_LEN);
 	add_lump_rpl(_m, buf, PATH_LEN + _p->len + CRLF_LEN,
 		     LUMP_RPL_HDR | LUMP_RPL_NODUP);
 	return 0;
}

#define UNSUPPORTED "Unsupported: "
#define UNSUPPORTED_LEN (sizeof(UNSUPPORTED) - 1)
static int add_unsupported(struct sip_msg* _m, str* _p)
{
	char* buf;

 	buf = (char*)pkg_malloc(UNSUPPORTED_LEN + _p->len + CRLF_LEN);
 	if (!buf) {
 		LM_ERR("no pkg memory left\n");
 		return -1;
 	}
 	memcpy(buf, UNSUPPORTED, UNSUPPORTED_LEN);
 	memcpy(buf + UNSUPPORTED_LEN, _p->s, _p->len);
 	memcpy(buf + UNSUPPORTED_LEN + _p->len, CRLF, CRLF_LEN);
 	add_lump_rpl(_m, buf, UNSUPPORTED_LEN + _p->len + CRLF_LEN,
 		     LUMP_RPL_HDR | LUMP_RPL_NODUP);
 	return 0;
}


int send_reply(struct sip_msg* _m, unsigned int _flags)
{
	str unsup = str_init(SUPPORTED_PATH_STR);
	long code;
	str msg = str_init(MSG_200); /* makes gcc shut up */
	char* buf;

	LM_DBG("contact buf: %.*s\n", contact.data_len, contact.buf);

	if (contact.data_len > 0) {
		add_lump_rpl( _m, contact.buf, contact.data_len, LUMP_RPL_HDR|LUMP_RPL_NODUP|LUMP_RPL_NOFREE);
		contact.data_len = 0;
	}

	if (rerrno == R_FINE && (_flags&REG_SAVE_PATH_FLAG) && _m->path_vec.s) {
		if ( (_flags&REG_SAVE_PATH_OFF_FLAG)==0 ) {
			if (parse_supported(_m)<0 && (_flags&REG_SAVE_PATH_STRICT_FLAG)) {
				rerrno = R_PATH_UNSUP;
				if (add_unsupported(_m, &unsup) < 0)
					return -1;
				if (add_path(_m, &_m->path_vec) < 0)
					return -1;
			}
			else if (get_supported(_m) & F_SUPPORTED_PATH) {
				if (add_path(_m, &_m->path_vec) < 0)
					return -1;
			} else if ((_flags&REG_SAVE_PATH_STRICT_FLAG)) {
				rerrno = R_PATH_UNSUP;
				if (add_unsupported(_m, &unsup) < 0)
					return -1;
				if (add_path(_m, &_m->path_vec) < 0)
					return -1;
			}
		}
	}

	code = rerr_codes[rerrno];
	switch(code) {
	case 200: msg.s = MSG_200; msg.len = sizeof(MSG_200)-1; break;
	case 400: msg.s = MSG_400; msg.len = sizeof(MSG_400)-1;break;
	case 420: msg.s = MSG_420; msg.len = sizeof(MSG_420)-1;break;
	case 500: msg.s = MSG_500; msg.len = sizeof(MSG_500)-1;break;
	case 503: msg.s = MSG_503; msg.len = sizeof(MSG_503)-1;break;
	}

	if (code != 200) {
		buf = (char*)pkg_malloc(E_INFO_LEN + error_info[rerrno].len + CRLF_LEN + 1);
		if (!buf) {
			LM_ERR("no pkg memory left\n");
			return -1;
		}
		memcpy(buf, E_INFO, E_INFO_LEN);
		memcpy(buf + E_INFO_LEN, error_info[rerrno].s, error_info[rerrno].len);
		memcpy(buf + E_INFO_LEN + error_info[rerrno].len, CRLF, CRLF_LEN);
		add_lump_rpl( _m, buf, E_INFO_LEN + error_info[rerrno].len + CRLF_LEN,
			LUMP_RPL_HDR|LUMP_RPL_NODUP);

		if (code >= 500 && code < 600 && retry_after) {
			if (add_retry_after(_m) < 0) {
				return -1;
			}
		}
	}

	if (sig_api.reply(_m, code, &msg, NULL) == -1) {
		LM_ERR("failed to send %ld %.*s\n", code, msg.len,msg.s);
		return -1;
	} else return 0;
}

int extract_aor(str* _uri, str* _a,str *sip_instance,str *call_id)
{
	static char aor_buf[MAX_AOR_LEN];
	memset(aor_buf, 0, MAX_AOR_LEN);

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

			if (gruu_secret.s != NULL)
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

	if ( (puri.user.len + puri.host.len + 1) > MAX_AOR_LEN
	|| puri.user.len > USERNAME_MAX_SIZE
	||  puri.host.len > DOMAIN_MAX_SIZE ) {
		rerrno = R_AOR_LEN;
		LM_ERR("Address Of Record too long\n");
		return -2;
	}

	_a->s = aor_buf;
	_a->len = puri.user.len;

	if (un_escape(&puri.user, _a) < 0) {
		rerrno = R_UNESCAPE;
		LM_ERR("failed to unescape username\n");
		return -3;
	}

	user_len = _a->len;

	if (reg_use_domain) {
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

	if (case_sensitive && user_len) {
		tmp.s = _a->s + user_len + 1;
		tmp.len = _a->s + _a->len - tmp.s;
		strlower(&tmp);
	} else {
		strlower(_a);
	}

	return 0;
}

/**
 * In MID_REG_THROTTLE_CT mode, when a REGISTER comes in:
 * -----------
 *	 if AoR not found:
 *     forward whole REGISTER!
 *
 *	 for each contact:
 *     if it unregisters:
 *         forward whole REGISTER!
 *	   if not registered:
 *         forward whole REGISTER!
 *     if ct_time_since_last_register_out >= (e_out - e_in):
 *         forward whole REGISTER!
 *         TODO: optimization: prune contacts which can be absorbed!
 * -----------
 *
 * return: fwd / nfwd / error
 */
static int process_contacts_by_ct(struct sip_msg *msg, urecord_t *urec,
                                  unsigned int flags)
{
	int e, ret, cflags;
	struct mid_reg_info *mri;
	ucontact_info_t *ci;
	ucontact_t *c;
	contact_t *ct;

	LM_DBG("processing contacts...\n");
	cflags = (flags&REG_SAVE_MEMORY_FLAG)?FL_MEM:FL_NONE;

	/* pack the contact_info */
	if ( (ci=pack_ci(msg, 0, 0, 0, ul_api.nat_flag, cflags))==0 ) {
		LM_ERR("failed to initial pack contact info\n");
		return -1;
	}

	/* if there are any new contacts, we must return a "forward" code */
	for (ct = get_first_contact(msg); ct; ct = get_next_contact(ct)) {
		calc_contact_expires(msg, ct->expires, &e, NULL);
		if (e == 0) {
			LM_DBG("FWD 1\n");
			return 1;
		}

		ret = ul_api.get_ucontact(urec, &ct->uri, ci->callid, ci->cseq, &c);
		if (ret == -1) {
			LM_ERR("invalid cseq for aor <%.*s>\n",urec->aor.len,urec->aor.s);
			rerrno = R_INV_CSEQ;
			return -1;
		} else if (ret == -2) { /* duplicate or lower cseq */
			continue;
		} else if (ret == 0) { /* found */
			LM_DBG("found >> %d --- [ %ld, %ld ]\n", e, c->expires_in, c->expires_out);

			mri = c->attached_data[ucontact_data_idx];

			if (get_act_time() - mri->last_reg_ts >= mri->expires_out - e) {
				LM_DBG("FWD 2\n");
				/* FIXME: should update "last_reg_out_ts" for all cts? */
				return 1;
			} else {
				/* pack the contact specific info */
				ci = pack_ci(msg, ct, e + get_act_time(), 0,
				             ul_api.nat_flag, cflags);
				if (!ci) {
					LM_ERR("failed to pack contact specific info\n");
					rerrno = R_UL_UPD_C;
					return -1;
				}
				ci->expires_out = c->expires_out;

				if (ul_api.update_ucontact(urec, c, ci, 0) < 0) {
					rerrno = R_UL_UPD_C;
					LM_ERR("failed to update contact\n");
					return -1;
				}

				continue;
			}
		}

		/* not found */
		return 1;
	}

	return 2;
}

static int calc_max_ct_diff(urecord_t *urec)
{
	ucontact_t *ct;
	int max_diff = -1;
	struct mid_reg_info *mri;

	for (ct = urec->contacts; ct; ct = ct->next) {
		mri = (struct mid_reg_info *)ct->attached_data[ucontact_data_idx];
		LM_DBG("ct - %d - %d - %d\n", mri->expires_out, mri->expires, max_diff);
		if (mri->expires_out - mri->expires > max_diff)
			max_diff = mri->expires_out - mri->expires;
	}

	LM_DBG("max diff: %d\n", max_diff);

	return max_diff;
}


/**
 * In MID_REG_THROTTLE_AOR mode, when a REGISTER comes in:
 * -----------
 *	 if AoR not found:
 *     forward whole REGISTER!
 *
 *   for each contact:
 *     if it unregisters:
 *       unregister
 *       continue
 *
 *     if not registered:
 *       register
 *
 *     max_diff = max_diff or (e_out - e_in)
 *
 *   if aor_time_since_last_register_out >= max_diff:
 *     forward whole REGISTER!
 * -----------
 *
 * return: fwd / nfwd / error
 */
static int process_contacts_by_aor(struct sip_msg *req, urecord_t *urec,
                                   unsigned int flags)
{
	int e, ret, ctno = 0, cflags, max_diff = -1;
	struct mid_reg_info *cinfo, *rinfo;
	ucontact_info_t *ci;
	ucontact_t *c;
	contact_t *ct;
	int e_out;

	if (urec->contacts == NULL)
		return 1;

	rinfo = urec->attached_data[ucontact_data_idx];
	e_out = rinfo->expires_out;

	LM_DBG("AoR info: e=%d, e_out=%d, lrts=%d...\n",
	       rinfo->expires, rinfo->expires_out, rinfo->last_reg_ts);

	cflags = (flags&REG_SAVE_MEMORY_FLAG)?FL_MEM:FL_NONE;

	/* pack the contact_info */
	if ( (ci=pack_ci(req, 0, 0, 0, ul_api.nat_flag, cflags))==0 ) {
		LM_ERR("failed to initial pack contact info\n");
		return -1;
	}

	for (c = urec->contacts; c; c = c->next)
		ctno++;

	/* if there are any new contacts, we must return a "forward" code */
	for (ct = get_first_contact(req); ct; ct = get_next_contact(ct)) {
		calc_contact_expires(req, ct->expires, &e, NULL);
		if (e > e_out) {
			LM_DBG("reducing contact expiration from %d sec to %d sec!\n",
			       e, e_out);
			e = e_out;
		}

		ret = ul_api.get_ucontact(urec, &ct->uri, ci->callid, ci->cseq, &c);
		if (ret == -1) {
			LM_ERR("invalid cseq for aor <%.*s>\n",urec->aor.len,urec->aor.s);
			rerrno = R_INV_CSEQ;
			return -1;
		} else if (ret == 0) { /* found */
			if (e == 0) {
				/* immediately forward De-REGISTERs for the last contact */
				if (ctno == 1) {
					LM_DBG("quickly forward last contact de-register\n");
					return 1;
				}

				if (ul_api.delete_ucontact(urec, c, 0) < 0) {
					rerrno = R_UL_UPD_C;
					return -1;
				}
				continue;
			}
			LM_DBG("found >> [ %ld, %ld ], e=%d, e_out=%d\n",
			       c->expires_in, c->expires_out, e, e_out);

			cinfo = c->attached_data[ucontact_data_idx];
			cinfo->expires = e;
			cinfo->expires_out = e_out;
			set_ct(cinfo);

			/* pack the contact specific info */
			ci = pack_ci(req, ct, e + get_act_time(), 0,
			             ul_api.nat_flag, cflags);
			if (!ci) {
				LM_ERR("failed to pack contact specific info\n");
				rerrno = R_UL_UPD_C;
				return -1;
			}
			ci->expires_out = c->expires_out;

			if (ul_api.update_ucontact(urec, c, ci, 0) < 0) {
				rerrno = R_UL_UPD_C;
				LM_ERR("failed to update contact\n");
				return -1;
			}
			set_ct(NULL);
		} else if (ret == 1) {
			/* not found */
			cinfo = shm_malloc(sizeof *cinfo);
			memset(cinfo, 0, sizeof *cinfo);
			cinfo->expires = e;
			cinfo->expires_out = e_out;
			set_ct(cinfo);

			/* pack the contact specific info */
			ci = pack_ci(req, ct, e + get_act_time(), 0,
			             ul_api.nat_flag, cflags);
			if (!ci) {
				LM_ERR("failed to pack contact specific info\n");
				rerrno = R_UL_UPD_C;
				return -1;
			}
			ci->expires_out = e_out;

			if (ul_api.insert_ucontact(urec, &ct->uri, ci, &c, 0) < 0) {
				rerrno = R_UL_INS_C;
				LM_ERR("failed to insert contact\n");
				return -1;
			}
			set_ct(NULL);
		}

		/* ignore contacts with duplicate / lower cseq (ret == -2) */
	}

	max_diff = calc_max_ct_diff(urec);

	LM_DBG("max diff: %d, absorb until=%d, current time=%ld\n",
	       max_diff, rinfo->last_reg_ts + max_diff, get_act_time());
	if (max_diff >= 0 && rinfo->last_reg_ts + max_diff <= get_act_time()) {
		return 1;
	}

	return 2;
}

static void parse_save_flags(str *flags_s, struct save_ctx *out_sctx)
{
	int st;

	for( st=0 ; st< flags_s->len ; st++ ) {
		switch (flags_s->s[st]) {
			case 'm': out_sctx->flags |= REG_SAVE_MEMORY_FLAG; break;
			case 'r': out_sctx->flags |= REG_SAVE_NOREPLY_FLAG; break;
			case 's': out_sctx->flags |= REG_SAVE_SOCKET_FLAG; break;
			case 'v': out_sctx->flags |= REG_SAVE_PATH_RECEIVED_FLAG; break;
			case 'f': out_sctx->flags |= REG_SAVE_FORCE_REG_FLAG; break;
			case 'c':
				out_sctx->max_contacts = 0;
				while (st<flags_s->len-1 && isdigit(flags_s->s[st+1])) {
					out_sctx->max_contacts = out_sctx->max_contacts*10 +
						flags_s->s[st+1] - '0';
					st++;
				}
				break;
			case 'e':
				out_sctx->min_expires = 0;
				while (st<flags_s->len-1 && isdigit(flags_s->s[st+1])) {
					out_sctx->min_expires = out_sctx->min_expires*10 +
						flags_s->s[st+1] - '0';
					st++;
				}
				break;
			case 'E':
				out_sctx->max_expires = 0;
				while (st<flags_s->len-1 && isdigit(flags_s->s[st+1])) {
					out_sctx->max_expires = out_sctx->max_expires*10 +
						flags_s->s[st+1] - '0';
					st++;
				}
				break;
			case 'p':
				if (st<flags_s->len-1) {
					st++;
					if (flags_s->s[st]=='2') {
						out_sctx->flags |= REG_SAVE_PATH_STRICT_FLAG; break; }
					if (flags_s->s[st]=='1') {
						out_sctx->flags |= REG_SAVE_PATH_LAZY_FLAG; break; }
					if (flags_s->s[st]=='0') {
						out_sctx->flags |= REG_SAVE_PATH_OFF_FLAG; break; }
				}
			default: LM_WARN("unsupported flag %c \n",flags_s->s[st]);
		}
	}
}

int mid_reg_save(struct sip_msg *msg, char *dom, char *flags_gp,
                          char *to_uri_gp, char *expires_gp)
{
	udomain_t *ud = (udomain_t *)dom;
	urecord_t *rec = NULL;
	str flags_str = { NULL, 0 }, to_uri = { NULL, 0 };
	struct save_ctx sctx;
	int rc = -1, st;

	if (msg->REQ_METHOD != METHOD_REGISTER) {
		LM_ERR("ignoring non-REGISTER SIP request (%d)\n", msg->REQ_METHOD);
		return -1;
	}

	rerrno = R_FINE;
	memset(&sctx, 0, sizeof sctx);

	LM_DBG("saving to %.*s...\n", ud->name->len, ud->name->s);

	if (flags_gp) {
		if (fixup_get_svalue(msg, (gparam_p)flags_gp, &flags_str)) {
			LM_ERR("invalid flags parameter");
			return -1;
		}

		parse_save_flags(&flags_str, &sctx);
	}

	parse_reg_headers(msg);

	if (!to_uri_gp) {
		to_uri = get_to(msg)->uri;
	} else if (fixup_get_svalue(msg, (gparam_p)to_uri_gp, &to_uri)) {
		LM_ERR("invalid AoR parameter");
		return -1;
	}

	if (!expires_gp) {
		sctx.expires_out = outgoing_expires;
	} else if (fixup_get_ivalue(msg, (gparam_p)expires_gp, &sctx.expires_out)) {
		LM_ERR("invalid outgoing_expires parameter");
		return -1;
	}

	if (extract_aor(&to_uri, &sctx.aor, 0, 0) < 0) {
		LM_ERR("failed to extract Address Of Record\n");
		ul_api.unlock_udomain(ud, &sctx.aor);
		return -1;
	}

	if (check_contacts(msg, &st) > 0) {
		goto out_error;
	}

	if (get_first_contact(msg) == NULL) {
		if (st) {
			sctx.star = 1;
			return prepare_forward(msg, ud, &sctx.aor, &sctx);
		}
		goto quick_reply;
	}

	/* in mirror mode, all REGISTER requests simply pass through */
	if (reg_mode == MID_REG_MIRROR)
		return prepare_forward(msg, ud, &sctx.aor, &sctx);

	update_act_time();
	ul_api.lock_udomain(ud, &sctx.aor);

	if (ul_api.get_urecord(ud, &sctx.aor, &rec) != 0) {
		ul_api.unlock_udomain(ud, &sctx.aor);
		return prepare_forward(msg, ud, &sctx.aor, &sctx);
	}

	if (reg_mode == MID_REG_THROTTLE_CT)
		rc = process_contacts_by_ct(msg, rec, sctx.flags);
	else if (reg_mode == MID_REG_THROTTLE_AOR)
		rc = process_contacts_by_aor(msg, rec, sctx.flags);

	if (rc == -1)
		goto out_error;
	else if (rc == 1)
		goto out_forward;

quick_reply:
	/* forwarding not needed! This REGISTER will be absorbed */

	/* prepare the Contact header field for a quick 200 OK response */
	if (rec != NULL && rec->contacts != NULL)
		build_contact(rec->contacts, msg);

	/* no contacts need updating on the far end registrar */
	ul_api.unlock_udomain(ud, &sctx.aor);

	/* quick SIP reply */
	if (!(sctx.flags & REG_SAVE_NOREPLY_FLAG))
		send_reply(msg, sctx.flags);

	return 2;

out_forward:
	ul_api.unlock_udomain(ud, &sctx.aor);
	return prepare_forward(msg, ud, &sctx.aor, &sctx);

out_error:
	ul_api.unlock_udomain(ud, &sctx.aor);
	if (!(sctx.flags & REG_SAVE_NOREPLY_FLAG))
		send_reply(msg, sctx.flags);
	return -1;
}

