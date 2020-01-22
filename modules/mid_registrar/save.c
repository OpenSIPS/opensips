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
#include "ul_storage.h"
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
#include "../../daemonize.h"
#include "../../mod_fix.h"
#include "../../data_lump.h"
#include "../../data_lump_rpl.h"

#include "../../lib/reg/ci.h"
#include "../../lib/reg/sip_msg.h"
#include "../../lib/reg/rerrno.h"
#include "../../lib/reg/regtime.h"
#include "../../lib/reg/path.h"
#include "../../lib/reg/save_flags.h"

#include "../../trim.h"
#include "../../strcommon.h"

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

int prepare_rpl_path(struct sip_msg *req, str *path, int flags, struct sip_msg *rpl);

/*
 * @_e: output param (integer) - value of the ";expires" Contact hf param or "Expires" hf
 */
void calc_contact_expires(struct sip_msg* _m, param_t* _ep, int* _e,
                          int enforce_expires_limits)
{
	if (!_ep || !_ep->body.len) {
		*_e = get_expires_hf(_m);
	} else {
		if (str2int(&_ep->body, (unsigned int*)_e) < 0) {
			*_e = default_expires;
		}
	}

	if (enforce_expires_limits) {
		if ((*_e != 0) && min_expires && ((*_e) < min_expires))
			*_e = min_expires;

		if ((*_e != 0) && max_expires && ((*_e) > max_expires))
			*_e = max_expires;
	}

	LM_DBG("expires: %d\n", *_e);
}

/* with the optionally added outgoing timeout extension
 *
 * @_e: output param (UNIX timestamp) - expiration time on the main registrar
 * @egress: if true, the "outgoing_expires" modparam will be applied as a
 *			minimal value (useful when forcing egress expirations)
 */
void calc_ob_contact_expires(struct sip_msg* _m, param_t* _ep, int* _e, int egress)
{
	if (!_ep || !_ep->body.len) {
		*_e = get_expires_hf(_m);
	} else {
		if (str2int(&_ep->body, (unsigned int*)_e) < 0) {
			*_e = default_expires;
		}
	}

	/* extend outgoing timeout, thus throttling heavy incoming traffic */
	if (reg_mode != MID_REG_MIRROR && egress &&
			*_e > 0 && *_e < outgoing_expires)
		*_e = outgoing_expires;

	/* Convert to absolute value */
	if (*_e > 0) *_e += get_act_time();

	LM_DBG("outgoing expires: %d\n", *_e);
}

static int trim_to_single_contact(struct sip_msg *msg, str *aor)
{
	static str escape_buf;
	contact_t *c = NULL;
	struct socket_info *send_sock;
	struct lump *anchor = NULL;
	char *buf;
	int e, is_dereg = 1, len, len1;
	struct hdr_field *ct;
	union sockaddr_union _;
	str extra_ct_params, esc_aor, *adv_host, *adv_port;

	/* get the source socket on the way to the next hop */
	send_sock = uri2sock(msg, GET_NEXT_HOP(msg), &_, PROTO_NONE);
	if (!send_sock) {
		LM_ERR("failed to obtain next hop socket, ci=%.*s\n",
		       msg->callid->body.len, msg->callid->body.s);
		return -1;
	}

	adv_host = _get_adv_host(send_sock, msg);
	adv_port = _get_adv_port(send_sock, msg);

	/* completely remove all Contact hfs, except the last one */
	for (ct = msg->contact; ct && ct->sibling; ct = ct->sibling) {
		LM_DBG("deleting Contact '%.*s'\n", ct->len, ct->name.s);
		anchor = del_lump(msg, ct->name.s - msg->buf, ct->len, HDR_CONTACT_T);
		if (!anchor)
			return -1;
	}

	for (c = ((contact_body_t *)ct->parsed)->contacts; c;
	     c = get_next_contact(c)) {
		calc_contact_expires(msg, c->expires, &e, 1);
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

	extra_ct_params = get_extra_ct_params(msg);

	if (!reg_use_domain) {
		esc_aor = *aor;
	} else {
		if (pkg_str_extend(&escape_buf, 3 * aor->len + 1) != 0) {
			LM_ERR("oom\n");
			return -1;
		}

		esc_aor = escape_buf;
		if (escape_param(aor, &esc_aor) != 0) {
			LM_ERR("failed to escape AoR string: %.*s\n", aor->len, aor->s);
			return -1;
		}
	}

	/*    <   sip:               @                  :ddddd */
	len = 1 + 4 + esc_aor.len + 1 + adv_host->len + 6 +
	      extra_ct_params.len + 1 + 9 + 10 + 1;
	                   /* > ;expires=<integer> \0 */

	buf = pkg_malloc(len);
	if (buf == NULL) {
		LM_ERR("oom\n");
		return -1;
	}

	len1 = sprintf(buf, "<sip:%.*s@%.*s:%.*s%.*s>", esc_aor.len, esc_aor.s,
	               adv_host->len, adv_host->s, adv_port->len, adv_port->s,
	               extra_ct_params.len, extra_ct_params.s);

	if (!msg->expires || msg->expires->body.len == 0) {
		len1 += sprintf(buf + len1, ";expires=%d",
		                is_dereg ? 0 : outgoing_expires);
	}

	if (len1 >= len) {
		LM_BUG("buffer overflow");
		abort();
	}

	LM_DBG("inserting new Contact '%.*s'\n", len1, buf);

	if (!insert_new_lump_after(anchor, buf, len1, HDR_CONTACT_T)) {
		pkg_free(buf);
		return -1;
	}

	return 0;
}

void free_ct_mappings(struct list_head *mappings)
{
	struct list_head *_, *__;
	struct ct_mapping *ctmap;

	list_for_each_safe(_, __, mappings) {
		list_del(_);
		ctmap = list_entry(_, struct ct_mapping, list);

		shm_free(ctmap->req_ct_uri.s);
		shm_free(ctmap->instance.s);
		shm_free(ctmap->received.s);
		shm_free(ctmap);
	}
}

/**
 * Overwrites each Contact header field of the request.
 * Saves all these mappings to the mri->ct_mappings list.
 */
static int overwrite_req_contacts(struct sip_msg *req,
                                  struct mid_reg_info *mri)
{
	contact_t *c = NULL;
	urecord_t *r;
	ucontact_t *uc;
	struct sip_uri puri;
	struct socket_info *send_sock;
	struct lump *anchor;
	str new_username;
	char *lump_buf;
	int expiry_tick, expires, len, len1;
	int cseq;
	ucontact_id ctid;
	struct ct_mapping *ctmap;
	struct list_head *_;
	union sockaddr_union __;
	str extra_ct_params, ctid_str, *adv_host, *adv_port;

	ul_api.lock_udomain(mri->dom, &mri->aor);
	ul_api.get_urecord(mri->dom, &mri->aor, &r);
	if (!r && ul_api.insert_urecord(mri->dom, &mri->aor, &r, 0) < 0) {
		rerrno = R_UL_NEW_R;
		LM_ERR("failed to insert new record structure\n");
		goto out_err;
	}

	r->no_clear_ref++;

	if (str2int(&get_cseq(req)->number, (unsigned int*)&cseq) < 0) {
		rerrno = R_INV_CSEQ;
		LM_ERR("failed to convert cseq number, ci: %.*s\n",
		       req->callid->body.len, req->callid->body.s);
		goto out_err;
	}

	/* get the source socket on the way to the next hop */
	send_sock = uri2sock(req, GET_NEXT_HOP(req), &__, PROTO_NONE);
	if (!send_sock) {
		LM_ERR("failed to obtain next hop socket, ci=%.*s\n",
		       req->callid->body.len, req->callid->body.s);
		goto out_err;
	}

	adv_host = _get_adv_host(send_sock, req);
	adv_port = _get_adv_port(send_sock, req);

	c = get_first_contact(req);
	list_for_each(_, &mri->ct_mappings) {
		ctmap = list_entry(_, struct ct_mapping, list);

		/* if uri string points outside the original msg buffer, it means
		   the URI was already changed, and we cannot do it again */
		if (c->uri.s < req->buf || c->uri.s > req->buf + req->len) {
			LM_ERR("SCRIPT BUG - second attempt to change URI Contact\n");
			goto out_err;
		}

		ul_api.get_ucontact(r, &c->uri, &req->callid->body, cseq + 1, 
			&mri->cmatch, &uc);
		if (!uc)
			ctid = ul_api.next_contact_id(r);
		else
			ctid = uc->contact_id;

		ctid_str.s = int2str(ctid, &ctid_str.len);

		if (ctid_insertion == MR_APPEND_PARAM) {
			if (parse_uri(c->uri.s, c->uri.len, &puri) < 0) {
				LM_ERR("failed to parse reply contact uri <%.*s>\n",
				       c->uri.len, c->uri.s);
				goto out_err;
			}

			new_username = puri.user;
		} else {
			new_username = ctid_str;
		}

		calc_ob_contact_expires(req, c->expires, &expiry_tick, 1);
		expires = expiry_tick == 0 ? 0 : expiry_tick - get_act_time();
		ctmap->ctid = ctid;

		if (expires == 0)
			ctmap->zero_expires = 1;

		anchor = del_lump(req, (c->name.s ? c->name.s : c->uri.s) - req->buf,
		                  c->len, HDR_CONTACT_T);
		if (!anchor)
			goto out_err;

		extra_ct_params = get_extra_ct_params(req);

		len = new_username.len + 1 + adv_host->len +
		      6 /*port*/ + extra_ct_params.len + 2 /*IPv6*/ +
		      15 /* <sip:>;expires= */ + 10 /* len(expires) */ + 1 /*\0*/ +
			  (ctid_insertion == MR_APPEND_PARAM ?
					ctid_str.len + 2 + ctid_param.len : 0);

		lump_buf = pkg_malloc(len);
		if (!lump_buf) {
			LM_ERR("oom\n");
			goto out_err;
		}

		LM_DBG("building new Contact URI:\nuser: '%.*s'\n"
		       "adv_host: '%.*s'\nadv_port: '%.*s'\nfull Contact: '%.*s'\n"
			   "ctid_str: %.*s, ctid_param: %.*s\n",
		       new_username.len, new_username.s, adv_host->len, adv_host->s,
		       adv_port->len, adv_port->s, c->uri.len, c->uri.s,
			   ctid_str.len, ctid_str.s, ctid_param.len, ctid_param.s);

		if (ctid_insertion == MR_APPEND_PARAM) {
			LM_DBG("param insertion\n");
			len1 = snprintf(lump_buf, len,
					"<sip:%.*s@%.*s:%.*s;%.*s=%llu%.*s>;expires=%d",
			         new_username.len, new_username.s,
			         adv_host->len, adv_host->s, adv_port->len, adv_port->s,
			         ctid_param.len, ctid_param.s, (unsigned long long)ctid,
			         extra_ct_params.len, extra_ct_params.s, expires);
		} else {
			LM_DBG("username insertion\n");
			len1 = snprintf(lump_buf, len,
			                "<sip:%.*s@%.*s:%.*s%.*s>;expires=%d",
			           new_username.len, new_username.s,
			           adv_host->len, adv_host->s, adv_port->len, adv_port->s,
			           extra_ct_params.len, extra_ct_params.s, expires);
		}

		LM_DBG("final buffer: %.*s\n", len1, lump_buf);

		if (len1 < len)
			len = len1;

		if (insert_new_lump_after(anchor, lump_buf, len, HDR_CONTACT_T) == 0) {
			pkg_free(lump_buf);
			goto out_err;
		}

		c = get_next_contact(c);
	}

	ul_api.unlock_udomain(mri->dom, &mri->aor);
	return 0;

out_err:
	ul_api.unlock_udomain(mri->dom, &mri->aor);
	return -1;
}

static int replace_expires_hf(struct sip_msg *msg, int new_expiry)
{
	struct lump *lump;
	char *p;
	int len;

	if (!msg->expires || msg->expires->body.len <= 0)
		return 1;

	LM_DBG("....... Exp hdr: '%.*s'\n",
	       msg->expires->body.len, msg->expires->body.s);

	lump = del_lump(msg, msg->expires->body.s - msg->buf,
	                msg->expires->body.len, HDR_EXPIRES_T);
	if (!lump) {
		LM_ERR("fail del_lump on 'Expires:' hf value!\n");
		return -1;
	}

	p = pkg_malloc(11);
	if (!p)
		return -1;

	len = sprintf(p, "%d", new_expiry);

	if (!insert_new_lump_after(lump, p, len, HDR_OTHER_T)) {
		LM_ERR("fail to insert_new_lump over 'Expires' hf value!\n");
		return -1;
	}

	return 0;
}

int replace_expires_ct_param(struct sip_msg *msg, contact_t *ct, int expires)
{
	struct lump *lump;
	int len;
	char *p;

	if (!ct->expires) {
		LM_DBG("adding expires, ct '%.*s' with %d, %p -> %p\n",
		       ct->uri.len, ct->uri.s, expires, msg->buf, msg->buf+msg->len);

		lump = anchor_lump(msg, ct->name.s + ct->len - msg->buf, HDR_OTHER_T);
		if (!lump) {
			LM_ERR("oom\n");
			return -1;
		}

		p = pkg_malloc(20);
		if (!p)
			return -1;

		len = sprintf(p, ";expires=%d", expires);
	} else {
		LM_DBG("replacing expires, ct '%.*s' '%.*s' with %d, %p -> %p (%p)\n",
		       ct->uri.len, ct->uri.s, ct->expires->body.len,
		       ct->expires->body.s, expires, msg->buf, msg->buf+msg->len,
		       ct->expires->body.s);

		lump = del_lump(msg, ct->expires->body.s - msg->buf, ct->expires->body.len,
		                HDR_EXPIRES_T);
		if (!lump) {
			LM_ERR("oom\n");
			return -1;
		}

		p = pkg_malloc(11);
		if (!p)
			return -1;

		len = sprintf(p, "%d", expires);
	}

	if (!insert_new_lump_after(lump, p, len, HDR_OTHER_T)) {
		LM_ERR("insert_new_lump_after() failed!\n");
		return -1;
	}

	return 0;
}


static void remove_expires_hf(struct sip_msg *msg)
{
	if (msg->expires && msg->expires->body.len > 0) {
		LM_DBG("remove Exp hdr: '%.*s'\n",
		       msg->expires->body.len, msg->expires->body.s);

		if (!del_lump(msg, msg->expires->name.s - msg->buf,
		              msg->expires->len, HDR_EXPIRES_T))
			LM_ERR("fail del_lump on 'Expires:' hf value!\n");
	}
}

static int replace_expires(contact_t *c, struct sip_msg *msg, int new_expires,
                           int *skip_exp_header)
{
	if (!c->expires || c->expires->body.len <= 0) {
		if (*skip_exp_header == 0 && replace_expires_hf(msg, new_expires) == 0)
			*skip_exp_header = 1;
	} else {
		if (replace_expires_ct_param(msg, c, new_expires) != 0) {
			LM_ERR("failed to replace contact hf param expires, ci=%.*s\n",
			       msg->callid->body.len, msg->callid->body.s);
			return -1;
		}
	}

	return 0;
}

void overwrite_contact_expirations(struct sip_msg *req, struct mid_reg_info *mri)
{
	contact_t *c;
	int e, expiry_tick, new_expires;
	int skip_exp_header = 0;

	for (c = get_first_contact(req); c; c = get_next_contact(c)) {
		calc_contact_expires(req, c->expires, &e, 1);
		calc_ob_contact_expires(req, c->expires, &expiry_tick, 1);
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

int dup_req_info(struct sip_msg *req, struct mid_reg_info *mri)
{
	contact_t *c;
	struct ct_mapping *ctmap;
	unsigned int allowed;
	str *ua, no_ua = str_init("n/a");

	if (parse_headers(req, HDR_USERAGENT_F, 0) != -1 && req->user_agent &&
	     req->user_agent->body.len > 0 &&
	     req->user_agent->body.len < UA_MAX_SIZE) {
		ua = &req->user_agent->body;
	} else {
		ua = &no_ua;
	}

	if (shm_str_sync(&mri->user_agent, ua) != 0) {
		LM_ERR("oom\n");
		return -1;
	}

	mri->cflags = getb0flags(req);

	if (req && parse_allow(req) != -1)
		allowed = get_allow_methods(req);
	else
		allowed = ALL_METHODS;

	free_ct_mappings(&mri->ct_mappings);
	for (c = get_first_contact(req); c; c = get_next_contact(c)) {
		ctmap = shm_malloc(sizeof *ctmap);
		if (!ctmap) {
			LM_ERR("oom\n");
			return -1;
		}
		memset(ctmap, 0, sizeof *ctmap);

		if (shm_str_dup(&ctmap->req_ct_uri, &c->uri) != 0) {
			LM_ERR("oom\n");
			goto err_free;
		}

		update_act_time();
		calc_contact_expires(req, c->expires, &ctmap->expires, 1);

		/* q */
		if (calc_contact_q(c->q, &ctmap->q) < 0) {
			rerrno = R_INV_Q;
			LM_ERR("failed to calculate q\n");
			goto err_free;
		}

		/* methods */
		if (c->methods) {
			if (parse_methods(&c->methods->body, &ctmap->methods) < 0) {
				rerrno = R_PARSE;
				LM_ERR("failed to parse contact methods\n");
				goto err_free;
			}
		} else {
			ctmap->methods = allowed;
		}

		/* instance */
		if (c->instance && shm_str_dup(&ctmap->instance,
		                               &c->instance->body) != 0) {
			LM_ERR("oom\n");
			goto err_free;
		}

		/* received */
		if (c->received) {
			if (shm_str_dup(&ctmap->received, &c->received->body) != 0) {
				LM_ERR("oom\n");
				goto err_free;
			}
		}

		list_add_tail(&ctmap->list, &mri->ct_mappings);
	}

	return 0;

err_free:
	shm_free(ctmap->req_ct_uri.s);
	shm_free(ctmap->instance.s);
	shm_free(ctmap);
	return -1;
}

/* called exactly once per outgoing branch */
void mid_reg_req_fwded(struct cell *t, int type, struct tmcb_params *params)
{
	struct sip_msg *req = params->req;
	struct mid_reg_info *mri = *(struct mid_reg_info **)(params->param);
	str *next_hop = NULL;

	lock_start_write(mri->tm_lock);

	mri->pending_replies++;

	if (parse_reg_headers(req) != 0) {
		LM_ERR("failed to parse req headers\n");
		goto out;
	}

	if (req->expires)
		LM_DBG("msg expires: '%.*s'\n", req->expires->body.len, req->expires->body.s);

	if (shm_str_sync(&mri->main_reg_uri, GET_RURI(req)) != 0) {
		LM_ERR("oom\n");
		goto out;
	}

	if (GET_RURI(req) != GET_NEXT_HOP(req))
		next_hop = GET_NEXT_HOP(req);

	if (shm_str_sync(&mri->main_reg_next_hop, next_hop) != 0) {
		LM_ERR("oom\n");
		goto out;
	}

	if (mri->star)
		goto out;

	if (reg_mode != MID_REG_MIRROR)
		overwrite_contact_expirations(req, mri);

	if (reg_mode == MID_REG_THROTTLE_AOR) {
		LM_DBG("trimming all Contact URIs into one...\n");
		if (trim_to_single_contact(req, &mri->aor)) {
			LM_ERR("failed to overwrite Contact URI\n");
			goto out;
		}
	}

	/* TODO: the TMCB_RESPONSE_IN callback provides the initial request as an
	 * SHM'ized struct sip_msg, and does not proceed to free any PKG structures
	 * resulted when parse_headers() operations are performed on it during the
	 * callback, leading to PKG memory leaks.
	 *
	 * The current workaround is to dup any info we need from the request
	 * earliest, before sending out the request and almost ignore the
	 * un-parsable "req" sip_msg provided during TMCB_RESPONSE_IN.
	 */
	if (dup_req_info(req, mri) != 0) {
		LM_ERR("oom\n");
		goto out;
	}

	if (reg_mode == MID_REG_MIRROR || reg_mode == MID_REG_THROTTLE_CT) {
		LM_DBG("fixing Contact URI ...\n");
		if (overwrite_req_contacts(req, mri)) {
			LM_ERR("failed to overwrite Contact URIs\n");
			goto out;
		}
	}

out:
	LM_DBG("REQ FORWARDED TO '%.*s' (obp: %.*s), expires=%d\n",
	       mri->main_reg_uri.len, mri->main_reg_uri.s,
	       mri->main_reg_next_hop.len, mri->main_reg_next_hop.s,
	       mri->expires_out);

	lock_stop_write(mri->tm_lock);
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

static contact_t *match_contact(ucontact_id ctid, struct sip_msg *msg)
{
	contact_t *c;
	struct sip_uri puri;
	str ctid_str;
	int idx;

	ctid_str.s = int2str(ctid, &ctid_str.len);

	for (c = get_first_contact2(msg); c; c = get_next_contact2(c)) {
		LM_DBG("it='%.*s'\n", c->uri.len, c->uri.s);

		if (parse_uri(c->uri.s, c->uri.len, &puri) < 0) {
			LM_ERR("failed to parse reply contact uri <%.*s>\n",
			       c->uri.len, c->uri.s);
			return NULL;
		}

		/* try to match the request Contact with a Contact from the reply */
		if (ctid_insertion == MR_APPEND_PARAM) {
			idx = get_uri_param_idx(&ctid_param, &puri);
			if (idx < 0) {
				LM_DBG("failed to locate our ';%.*s=' param, ci = %.*s!\n",
				       ctid_param.len, ctid_param.s,
				       msg->callid->body.len, msg->callid->body.s);
				continue;
			}

			if (!str_strcmp(&ctid_str, &puri.u_val[idx]))
				return c;

		} else {
			if (!str_strcmp(&ctid_str, &puri.user))
				return c;
		}
	}

	return NULL;
}

/**
 * Ensures that a given @msg includes all registering contact usernames from
 * the @ct_mappings list.
 */
static int validate_msg_contacts(struct sip_msg *msg,
                                 struct list_head *ct_mappings)
{
	struct ct_mapping *ctmap;
	struct list_head *_;

	list_for_each(_, ct_mappings) {
		ctmap = list_entry(_, struct ct_mapping, list);
		if (!ctmap->zero_expires && !match_contact(ctmap->ctid, msg))
			return -1;
	}

	return 0;
}

int append_contacts(ucontact_t *contacts, struct sip_msg *msg)
{
	struct lump *anchor;
	char *buf;
	int len;

	build_contact(contacts, msg);

	buf = pkg_malloc(contact.data_len + 1);
	if (!buf) {
		LM_ERR("oom\n");
		return -1;
	}

	anchor = anchor_lump(msg, msg->unparsed - msg->buf, 0);
	if (!anchor) {
		pkg_free(buf);
		LM_ERR("oom\n");
		return -1;
	}

	len = sprintf(buf, "%.*s", contact.data_len, contact.buf);
	if (insert_new_lump_after(anchor, buf, len, HDR_CONTACT_T) == NULL) {
		pkg_free(buf);
		return -1;
	}

	return 0;
}

int trim_contacts(urecord_t *r, int trims)
{
	ucontact_t *uc;

	for (uc = r->contacts; uc && trims > 0; uc = uc->next) {
		if (!VALID_CONTACT(uc, get_act_time()))
			continue;

		LM_DBG("overflow on inserting new contact -> removing <%.*s>\n",
		       uc->c.len, uc->c.s);

		if (ul_api.delete_ucontact(r, uc, 0) != 0) {
			LM_ERR("failed to remove contact, aor: %.*s\n",
			       r->aor.len, r->aor.s);
			return -1;
		}

		/* our usrloc callbacks will take care of De-REG'ing from main reg */

		trims--;
	}

	if (trims != 0)
		LM_BUG("non-zero trims, aor: %.*s", r->aor.len, r->aor.s);

	return 0;
}

static ucontact_t **contacts_bak;
static int contacts_bak_no;
static int contacts_bak_sz;

/* temporarily filter the contacts of a record using various conditions */
int filter_contacts(urecord_t *r, struct list_head *by_ctmaps,
                        struct sip_msg *by_msg)
{
	contact_t *c;
	ucontact_t *uc, *_uc;
	struct ct_mapping *ctmap;
	struct list_head *_;
	int i;

	/* back up the original list using a static array */
	contacts_bak_no = 0;
	for (i = 0, uc = r->contacts; uc; uc = uc->next, i++) {
		if (i >= contacts_bak_sz) {
			contacts_bak = pkg_realloc(contacts_bak,
			                        (i ? 2 * contacts_bak_sz : 10) * sizeof r);
			if (!contacts_bak) {
				LM_ERR("oom\n");
				return -1;
			}

			contacts_bak_sz = (i ? 2 * contacts_bak_sz : 10);
		}

		contacts_bak[i] = uc;
	}
	contacts_bak_no = i;

	uc = NULL;
	if (by_ctmaps) {
		list_for_each (_, by_ctmaps) {
			ctmap = list_entry(_, struct ct_mapping, list);
			if (!ctmap->uc)
				continue;

			if (!uc) {
				uc = ctmap->uc;
			} else {
				uc->next = ctmap->uc;
				uc = ctmap->uc;
			}
		}
	} else {
		for (c = get_first_contact(by_msg); c; c = get_next_contact(c)) {
			for (_uc = r->contacts; _uc; _uc = _uc->next) {
				if (str_strcmp(&c->uri, &_uc->c))
					continue;

				if (!uc) {
					uc = _uc;
				} else {
					uc->next = _uc;
					uc = _uc;
				}

				break;
			}
		}
	}

	if (uc)
		uc->next = NULL;

	/* expose the filtered list */
	r->contacts = uc;
	return 0;
}

void restore_contacts(urecord_t *r)
{
	int i;

	if (contacts_bak_no == 0)
		return;

	/* restore in-between links */
	for (i = 0; i < contacts_bak_no - 1; i++)
		contacts_bak[i]->next = contacts_bak[i + 1];

	contacts_bak[contacts_bak_no - 1]->next = NULL;
	r->contacts = contacts_bak[0];
}

/* NB: always ensure update_act_time() has been recently called beforehand */
struct ucontact_info *mid_reg_pack_ci(struct sip_msg *req, struct sip_msg *rpl,
                        struct mid_reg_info *mri, struct ct_mapping *ctmap)
{
	static ucontact_info_t ci;
	static int_str attr_avp_value;
	static str callid;
	static str path, path_received;

	struct usr_avp *avp_attr;
	int_str src_if;
	str received = {NULL, 0};

	memset(&ci, 0, sizeof ci);

	/* Get callid of the message */
	callid = rpl->callid->body;
	trim_trailing(&callid);
	if (callid.len > CALLID_MAX_SIZE) {
		rerrno = R_CALLID_LEN;
		LM_ERR("callid too long: %.*s\n", callid.len, callid.s);
		return NULL;
	}
	ci.callid = &callid;

	/* Get CSeq number of the message */
	if (str2int(&get_cseq(rpl)->number, (unsigned int*)&ci.cseq) < 0) {
		rerrno = R_INV_CSEQ;
		LM_ERR("failed to convert cseq number\n");
		return NULL;
	}

	ci.sock = req->rcv.bind_address;
	ci.user_agent = &mri->user_agent;
	ci.last_modified = get_act_time();
	ci.flags = mri->ul_flags;
	ci.cflags = mri->cflags;
	ci.expires = ctmap->expires + get_act_time();
	ci.shtag = mri->ownership_tag;

	ci.q = ctmap->q;
	ci.methods = ctmap->methods;
	ci.instance = ctmap->instance;

	/* get received */
	if (ci.received.len == 0) {
		if (ctmap->received.s) {
			ci.received = ctmap->received;
		} else {
			memset(&src_if, 0, sizeof src_if);
			if (rcv_avp_name >= 0 &&
			     search_first_avp(rcv_avp_type, rcv_avp_name, &src_if, 0) &&
			     src_if.s.len > 0) {
				if (src_if.s.len > RECEIVED_MAX_SIZE) {
					rerrno = R_CONTACT_LEN;
					LM_ERR("received too long\n");
					return NULL;
				}
				received = src_if.s;
			} else {
				received.s = NULL;
				received.len = 0;
			}

			ci.received = received;
		}
	}

	/* extract Path headers */
	if (mri->reg_flags & REG_SAVE_PATH_FLAG) {
		if (build_path_vector(req, &path, &path_received, mri->reg_flags) < 0) {
			rerrno = R_PARSE_PATH;
			return NULL;
		}

		if (path.len && path.s)
			ci.path = &path;

		if (path_received.len && path_received.s) {
			ci.cflags |= ul_api.nat_flag;
			ci.received = path_received;
		}
	}

	/* additional information (script pvar) */
	if (attr_avp_name != -1) {
		avp_attr = search_first_avp(attr_avp_type, attr_avp_name,
									&attr_avp_value, NULL);
		if (avp_attr) {
			ci.attr = &attr_avp_value.s;

			LM_DBG("Attributes: %.*s\n", ci.attr->len, ci.attr->s);
		}
	}

#ifdef EXTRA_DEBUG
	print_ci(&ci);
#endif

	return &ci;
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
static inline int save_restore_rpl_contacts(struct sip_msg *req,
						struct sip_msg* rpl, struct mid_reg_info *mri, str* _a)
{
	ucontact_info_t* ci = NULL;
	ucontact_t* c;
	urecord_t *r;
	contact_t *_c = NULL;
	int_str_t value;
	int e_out, vct, was_valid;
	int e_max = 0;
	int tcp_check = 0;
	struct sip_uri uri;
	struct ct_mapping *ctmap;
	struct hdr_field *hdr;
	struct list_head *_;

	if (validate_msg_contacts(rpl, &mri->ct_mappings) != 0) {
		LM_ERR("200 OK reply does not include all req contacts! (ci: %.*s)\n",
		       mri->callid.len, mri->callid.s);
		return -1;
	}

	ul_api.lock_udomain(mri->dom, &mri->aor);
	ul_api.get_urecord(mri->dom, &mri->aor, &r);
	if (!r) {
		LM_ERR("failed to retrieve urecord, ci: %.*s\n",
		       mri->callid.len, mri->callid.s);
		ul_api.unlock_udomain(mri->dom, &mri->aor);
		return -1;
	}

	if (mri->reg_flags & REG_SAVE_MEMORY_FLAG)
		mri->ul_flags = FL_MEM;
	else
		mri->ul_flags = FL_NONE;

	if (is_tcp_based_proto(req->rcv.proto) && (req->flags & tcp_persistent_flag)) {
		tcp_check = 1;
	}

	LM_DBG("running\n");

	/* remove all "Contact" headers from the reply */
	for (hdr = rpl->contact; hdr; hdr = hdr->next) {
		if (hdr->type == HDR_CONTACT_T) {
			if (del_lump(rpl, hdr->name.s - rpl->buf,
			                  hdr->len, HDR_CONTACT_T) == NULL) {
				LM_ERR("failed to delete contact '%.*s'\n", hdr->name.len,
				       hdr->name.s);
				goto error;
			}
		}
	}

	if (mri->max_contacts) {
		for (c = r->contacts, vct = 0; c; c = c->next) {
			if (VALID_CONTACT(c, get_act_time()))
				vct++;
		}
	}

	/* both lists (req contacts and ct_mappings) have equal lengths
	 * and their contacts match at each index since the latter was
	 * generated out of the former */
	list_for_each(_, &mri->ct_mappings) {
		ctmap = list_entry(_, struct ct_mapping, list);
		_c = match_contact(ctmap->ctid, rpl);

		/* contact is not present in the reply because it de-registered! */
		if (!_c)
			goto update_usrloc;

		calc_ob_contact_expires(rpl, _c->expires, &e_out, 0);
		e_out -= get_act_time();

		/* the main registrar might enforce shorter lifetimes */
		if (e_out < ctmap->expires)
			ctmap->expires = e_out;

		LM_DBG("    >> REGISTER %ds ------- %ds 200 OK <<!\n", ctmap->expires,
		       e_out);

update_usrloc:
		c = NULL;
		/* pack the contact_info */
		ci = mid_reg_pack_ci(req, rpl, mri, ctmap);
		if (!ci) {
			LM_ERR("failed to extract contact info\n");
			goto error;
		}
		ci->expires_out = e_out;
		ci->contact_id = ctmap->ctid;

		if ((!r->contacts || ul_api.get_ucontact(r, &ctmap->req_ct_uri,
		     ci->callid, ci->cseq+1, &mri->cmatch, &c) != 0) &&
			ctmap->expires > 0) {
			/* contact not found and not present on main reg either */
			if (!_c)
				continue;

			if (mri->max_contacts && vct >= mri->max_contacts) {
				if (!(mri->reg_flags & REG_SAVE_FORCE_REG_FLAG)) {
					LM_INFO("AOR <%.*s> is already at max contacts (%d)\n",
					        r->aor.len, r->aor.s, mri->max_contacts);
					rerrno = R_TOO_MANY;
					goto error;
				}

				if (trim_contacts(r, vct - mri->max_contacts + 1) != 0)
					goto error;
			}

			LM_DBG("INSERTING contact with expires %lu\n", ci->expires);

			if (ul_api.insert_ucontact( r, &ctmap->req_ct_uri, ci, &c, 0) < 0) {
				rerrno = R_UL_INS_C;
				LM_ERR("failed to insert contact\n");
				goto error;
			}

			vct++;

			if (reg_mode == MID_REG_THROTTLE_CT &&
			    store_ucontact_data(c, mri, &_c->uri, ctmap->expires, e_out,
			                        get_act_time(), ci->cseq) != 0) {
				LM_ERR("failed to attach ucontact data - oom?\n");
				goto error;
			}
		} else if (c != NULL) {
			/* delete expired or stale contact (not present on main reg) */
			if (ctmap->expires == 0 || !_c) {
				if (reg_mode == MID_REG_THROTTLE_CT) {
					value.is_str = 0;
					value.i = 1;
					if (!ul_api.put_ucontact_key(c, &ul_key_skip_dereg, &value))
						LM_ERR("oom\n");
				}

				was_valid = VALID_CONTACT(c, get_act_time());
				if (ul_api.delete_ucontact(r, c, 0) < 0) {
					rerrno = R_UL_UPD_C;
					LM_ERR("failed to delete contact\n");
					goto error;
				} else if (was_valid)
					vct--;

				continue;
			}

			LM_DBG("UPDATING .....\n");

			if (!VALID_CONTACT(c, get_act_time()))
				vct++;

			if (mri->max_contacts && vct > mri->max_contacts) {
				if (!(mri->reg_flags & REG_SAVE_FORCE_REG_FLAG)) {
					LM_INFO("AOR <%.*s> is already at max contacts (%d)\n",
					        r->aor.len, r->aor.s, mri->max_contacts);
					rerrno = R_TOO_MANY;
					goto error;
				}

				if (trim_contacts(r, vct - mri->max_contacts) != 0)
					goto error;
			}

			if (reg_mode == MID_REG_THROTTLE_CT &&
				store_ucontact_data(c, mri, &_c->uri, ctmap->expires, e_out,
				                    get_act_time(), ci->cseq) != 0) {
				LM_ERR("failed to update ucontact data - oom?\n");
				goto error;
			}

			if (ul_api.update_ucontact(r, c, ci, 0) < 0) {
				rerrno = R_UL_UPD_C;
				LM_ERR("failed to update contact\n");
				goto error;
			}
		}

		ctmap->uc = c;

		if (tcp_check) {
			/* parse contact uri to see if transport is TCP */
			if (parse_uri(ctmap->req_ct_uri.s, ctmap->req_ct_uri.len, &uri)<0) {
				LM_ERR("failed to parse contact <%.*s>\n",
						ctmap->req_ct_uri.len, ctmap->req_ct_uri.s);
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

	if (prepare_rpl_path(req, ci->path, mri->reg_flags, rpl) != 0)
		LM_ERR("failed to prepare reply Path header, ci: %.*s\n",
		       mri->callid.len, mri->callid.s);

	if (r->contacts) {
		/* only include the request's contacts in the 200 OK reply
		 * (technically speaking, this is against RFC 3261) */
		if (mri->reg_flags & REG_SAVE_REQ_CT_ONLY_FLAG)
			filter_contacts(r, &mri->ct_mappings, NULL);

		append_contacts(r->contacts, rpl);

		if (mri->reg_flags & REG_SAVE_REQ_CT_ONLY_FLAG)
			restore_contacts(r);
	}

	r->no_clear_ref--;
	ul_api.release_urecord(r, 0);
	ul_api.unlock_udomain(mri->dom, &mri->aor);

	/* we're always re-building the Contact headers to include ";expires" */
	remove_expires_hf(rpl);

	if ( tcp_check && e_max>0 ) {
		e_max -= get_act_time();
		trans_set_dst_attr( &req->rcv, DST_FCNTL_SET_LIFETIME,
			(void*)(long)(e_max + 10) );
	}

	return 0;

error:
	r->no_clear_ref--;
	ul_api.delete_urecord(mri->dom, _a, r, 0);
	ul_api.unlock_udomain(mri->dom, &mri->aor);
	return -1;
}


/* only relevant in MID_REG_THROTTLE_AOR mode */
static inline int save_restore_req_contacts(struct sip_msg *req,
						struct sip_msg* rpl, struct mid_reg_info *mri, str* _a)
{
	ucontact_info_t* ci = NULL;
	ucontact_t* c;
	urecord_t *r = NULL;
	contact_t *_c;
	unsigned int cseq;
	int e_out = -1, vct, was_valid;
	int e_max = 0;
	int tcp_check = 0;
	struct sip_uri uri;
	struct list_head *_;
	struct ct_mapping *ctmap;

	if (str2int(&get_cseq(rpl)->number, &cseq) < 0) {
		rerrno = R_INV_CSEQ;
		LM_ERR("failed to convert cseq number\n");
		return -1;
	}

	if (is_tcp_based_proto(req->rcv.proto) && (req->flags & tcp_persistent_flag)) {
		tcp_check = 1;
	}

	LM_DBG("saving + restoring all contact URIs ... \n");

	/* in MID_REG_THROTTLE_AOR mode, any reply will only contain 1 contact */
	_c = get_first_contact(rpl);
	if (_c != NULL)
		calc_contact_expires(rpl, _c->expires, &e_out, 0);

	ul_api.lock_udomain(mri->dom, &mri->aor);
	ul_api.get_urecord(mri->dom, &mri->aor, &r);

	if (!r) {
		/*
		 * AoR not yet stored here, and the main registrar is also clean!
		 * Just skip processing any contacts found in the request, we're good.
		 */
		if (_c == NULL)
			goto out;

		if (ul_api.insert_urecord(mri->dom, _a, &r, 0) < 0) {
			rerrno = R_UL_NEW_R;
			LM_ERR("failed to insert new record structure\n");
			goto out_err;
		}
	}

	/* replicated AoRs will have an empty k/v store */
	if (!ul_api.get_urecord_key(r, &ul_key_callid) && _c) {
		if (store_urecord_data(r, mri, &_c->uri, e_out, get_act_time(),
		                       cseq) != 0) {
			LM_ERR("failed to attach urecord data - oom?\n");
			goto out_err;
		}
	} else {
		if (update_urecord_data(r, _c == NULL, &mri->callid, cseq) != 0) {
			LM_ERR("failed to update urecord data - oom?\n");
			goto out_err;
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
			goto out_clear_err;
		}
	}

#ifdef EXTRA_DEBUG
	log_contacts(get_first_contact(req));
#endif

	if (mri->max_contacts) {
		for (c = r->contacts, vct = 0; c; c = c->next) {
			if (VALID_CONTACT(c, get_act_time()))
				vct++;
		}
	}

	list_for_each(_, &mri->ct_mappings) {
		ctmap = list_entry(_, struct ct_mapping, list);

		if (_c == NULL) {
			if (ctmap->expires != 0)
				LM_ERR("200 OK from main registrar is missing Contact '%.*s'\n",
				       ctmap->req_ct_uri.len, ctmap->req_ct_uri.s);
			goto update_usrloc;
		}

		/* the main registrar might enforce shorter lifetimes */
		if (e_out < ctmap->expires)
			ctmap->expires = e_out;

update_usrloc:
		c = NULL;
		/* pack the contact_info */
		ci = mid_reg_pack_ci(req, rpl, mri, ctmap);
		if (ci == NULL) {
			LM_ERR("failed to extract contact info\n");
			goto out_clear_err;
		}
		ci->expires_out = e_out;

		if ((r->contacts == NULL ||
			ul_api.get_ucontact(r, &ctmap->req_ct_uri, ci->callid, ci->cseq+1,
			&mri->cmatch, &c) != 0) && ctmap->expires > 0) {
			/* contact not found and not present on main reg either */
			if (!_c)
				continue;

			if (mri->max_contacts && vct >= mri->max_contacts) {
				if (!(mri->reg_flags & REG_SAVE_FORCE_REG_FLAG)) {
					LM_INFO("AOR <%.*s> is already at max contacts (%d)\n",
					        r->aor.len, r->aor.s, mri->max_contacts);
					rerrno = R_TOO_MANY;
					goto out_clear_err;
				}

				if (trim_contacts(r, vct - mri->max_contacts + 1) != 0)
					goto out_clear_err;
			}

			LM_DBG("INSERTING contact with expires %lu\n", ci->expires);

			if (ul_api.insert_ucontact( r, &ctmap->req_ct_uri, ci, &c, 0) < 0) {
				rerrno = R_UL_INS_C;
				LM_ERR("failed to insert contact\n");
				goto out_clear_err;
			}

			vct++;

			if (reg_mode == MID_REG_THROTTLE_AOR &&
			    store_ucontact_data(c, mri, &_c->uri, ctmap->expires, e_out,
			                        mri->last_reg_ts, ci->cseq) != 0) {
				LM_ERR("failed to attach ucontact data - oom?\n");
				goto out_clear_err;
			}
		} else if (c != NULL) {
			/* delete expired or stale contact (not present on main reg) */
			if (ctmap->expires == 0 || !_c) {
				was_valid = VALID_CONTACT(c, get_act_time());
				if (ul_api.delete_ucontact(r, c, 0) < 0) {
					rerrno = R_UL_UPD_C;
					LM_ERR("failed to update contact\n");
					goto out_clear_err;
				} else if (was_valid)
					vct--;

				continue;
			}

			if (!VALID_CONTACT(c, get_act_time()))
				vct++;

			if (mri->max_contacts && vct > mri->max_contacts) {
				if (!(mri->reg_flags & REG_SAVE_FORCE_REG_FLAG)) {
					LM_INFO("AOR <%.*s> is already at max contacts (%d)\n",
					        r->aor.len, r->aor.s, mri->max_contacts);
					rerrno = R_TOO_MANY;
					goto out_clear_err;
				}

				if (trim_contacts(r, vct - mri->max_contacts) != 0)
					goto out_clear_err;
			}

			if (reg_mode == MID_REG_THROTTLE_AOR &&
			    update_ucontact_data(c, ctmap->expires, e_out, ci->cseq) != 0) {
				LM_ERR("failed to update ucontact data - oom?\n");
				goto out_clear_err;
			}

			if (ul_api.update_ucontact( r, c, ci, 0) < 0) {
				rerrno = R_UL_UPD_C;
				LM_ERR("failed to update contact\n");
				goto out_clear_err;
			}
		}

		ctmap->uc = c;

		if (tcp_check) {
			/* parse contact uri to see if transport is TCP */
			if (parse_uri(ctmap->req_ct_uri.s, ctmap->req_ct_uri.len, &uri)<0) {
				LM_ERR("failed to parse contact <%.*s>\n",
				       ctmap->req_ct_uri.len, ctmap->req_ct_uri.s);
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

	if (prepare_rpl_path(req, ci->path, mri->reg_flags, rpl) != 0)
		LM_ERR("failed to prepare reply Path header, ci: %.*s\n",
		       mri->callid.len, mri->callid.s);

	if (r) {
		if (r->contacts) {
			if (mri->reg_flags & REG_SAVE_REQ_CT_ONLY_FLAG)
				filter_contacts(r, &mri->ct_mappings, NULL);

			append_contacts(r->contacts, rpl);

			if (mri->reg_flags & REG_SAVE_REQ_CT_ONLY_FLAG)
				restore_contacts(r);
		}

		ul_api.release_urecord(r, 0);
	}

	if ( tcp_check && e_max>0 ) {
		e_max -= get_act_time();
		trans_set_dst_attr( &req->rcv, DST_FCNTL_SET_LIFETIME,
			(void*)(long)(e_max + 10) );
	}

out:
	ul_api.unlock_udomain(mri->dom, &mri->aor);
	return 0;
out_clear_err:
	if (r)
		ul_api.delete_urecord(mri->dom, _a, r, 0);
out_err:
	ul_api.unlock_udomain(mri->dom, &mri->aor);
	return -1;
}

/*! \brief
 * Process request that contained a star, in that case,
 * we will remove all bindings with the given username
 * from the usrloc and return 200 OK response
 */
static inline void star(struct mid_reg_info *mri, struct sip_msg *_m)
{
	urecord_t* r;
	ucontact_t* c;
	udomain_t *_d = mri->dom;

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

	if (ul_api.delete_urecord(_d, &mri->aor, NULL, 0) != 0)
		LM_ERR("failed to delete urcord %.*s\n", mri->aor.len, mri->aor.s);

	ul_api.unlock_udomain(_d, &mri->aor);
}


void mid_reg_resp_in(struct cell *t, int type, struct tmcb_params *params)
{
	struct mid_reg_info *mri = *(struct mid_reg_info **)(params->param);
	struct sip_msg *rpl = params->rpl;
	struct sip_msg *req = params->req;
	int code = rpl->first_line.u.reply.statuscode;

	LM_DBG("request -------------- \n%s\n", req->buf);
	LM_DBG("reply: %d -------------- \n%s\n", code, rpl->buf);

	lock_start_write(mri->tm_lock);

	/* no processing on replies with missing Contact headers or retransmits */
	if (code < 200 || code >= 300 || mri->pending_replies == 0)
		goto out;

	update_act_time();

	if (parse_reg_headers(rpl) != 0) {
		LM_ERR("failed to parse rpl headers\n");
		goto out;
	}

	if (mri->star) {
		star(mri, req);
		goto out;
	}

	if (reg_mode == MID_REG_MIRROR || reg_mode == MID_REG_THROTTLE_CT) {
		if (save_restore_rpl_contacts(req, rpl, mri, &mri->aor)) {
			LM_ERR("failed to process rpl contacts for AoR '%.*s'\n",
			       mri->aor.len, mri->aor.s);
		}
	} else if (reg_mode == MID_REG_THROTTLE_AOR) {
		if (save_restore_req_contacts(req, rpl, mri, &mri->aor)) {
			LM_ERR("failed to process req contacts for AoR '%.*s'\n",
			       mri->aor.len, mri->aor.s);
		}
	}

	mri->pending_replies--;
out:
	lock_stop_write(mri->tm_lock);

	LM_DBG("got ptr back: %p\n", mri);
	LM_DBG("RESPONSE FORWARDED TO caller!\n");
}

void mid_reg_tmcb_deleted(struct cell *t, int type, struct tmcb_params *params)
{
	struct mid_reg_info *mri = *(struct mid_reg_info **)(params->param);
	urecord_t *r;

	/* no response from downstream - clear up any lingering refs! */
	if (mri->pending_replies && (reg_mode != MID_REG_THROTTLE_AOR) &&
	        get_osips_state() < STATE_TERMINATING) {
		ul_api.lock_udomain(mri->dom, &mri->aor);
		ul_api.get_urecord(mri->dom, &mri->aor, &r);
		if (!r) {
			LM_ERR("failed to retrieve urecord, ci: %.*s\n",
			       mri->callid.len, mri->callid.s);
			ul_api.unlock_udomain(mri->dom, &mri->aor);
			goto out_free;
		}

		r->no_clear_ref -= mri->pending_replies;
		ul_api.release_urecord(r, 0);
		ul_api.unlock_udomain(mri->dom, &mri->aor);
	}

out_free:
	mri_free(mri);
}

/* !! retcodes: 1 or -1 !! */
static int prepare_forward(struct sip_msg *msg, udomain_t *ud,
                           struct save_ctx *sctx)
{
	struct mid_reg_info *mri;
	struct to_body *to, *from;

	LM_DBG("from: '%.*s'\n", msg->from->body.len, msg->from->body.s);
	LM_DBG("Call-ID: '%.*s'\n", msg->callid->body.len, msg->callid->body.s);
	LM_DBG("Contact: '%.*s'\n", msg->contact->body.len, msg->contact->body.s);

	mri = mri_alloc();
	if (!mri) {
		LM_ERR("oom\n");
		return -1;
	}

	mri->expires = 0;
	mri->expires_out = sctx->expires_out;
	mri->max_contacts = sctx->max_contacts;
	mri->dom = ud;
	mri->reg_flags = sctx->flags;
	mri->star = sctx->star;

	if (shm_str_dup(&mri->aor, &sctx->aor) != 0) {
		LM_ERR("oom\n");
		goto out_free;
	}

	if (sctx->ownership_tag.s
		&& shm_str_dup(&mri->ownership_tag, &sctx->ownership_tag) != 0) {
		LM_ERR("oom\n");
		goto out_free;
	}

	mri->cmatch.mode = sctx->cmatch.mode;
	if (sctx->cmatch.param.s &&
	shm_str_dup(&mri->cmatch.param, &sctx->cmatch.param) != 0) {
		LM_ERR("oom\n");
		goto out_free;
	}

	if (parse_from_header(msg) != 0) {
		LM_ERR("failed to parse From hf\n");
		goto out_free;
	}

	from = get_from(msg);
	if (shm_str_dup(&mri->from, &from->uri) != 0) {
		LM_ERR("oom\n");
		goto out_free;
	}

	to = get_to(msg);
	if (shm_str_dup(&mri->to, &to->uri) != 0) {
		LM_ERR("oom\n");
		goto out_free;
	}

	if (shm_str_dup(&mri->callid, &msg->callid->body) != 0) {
		LM_ERR("oom\n");
		goto out_free;
	}

	LM_DBG("registering ptr %p on TMCB_REQUEST_FWDED ...\n", mri);
	if (tm_api.register_tmcb(msg, NULL, TMCB_REQUEST_FWDED,
	    mid_reg_req_fwded, mri, NULL) <= 0) {
		LM_ERR("cannot register additional callbacks\n");
		goto out_free;
	}

	LM_DBG("registering for TMCB_RESPONSE_FWDED, mri=%p ...\n", mri);
	if (tm_api.register_tmcb(msg, NULL, TMCB_RESPONSE_IN,
	    mid_reg_resp_in, mri, NULL) <= 0) {
		LM_ERR("cannot register additional callbacks\n");
		return -1;
	}

	LM_DBG("registering for TMCB_RESPONSE_DELETED, mri=%p ...\n", mri);
	if (tm_api.register_tmcb(msg, NULL, TMCB_TRANS_DELETED,
	    mid_reg_tmcb_deleted, mri, NULL) <= 0) {
		LM_ERR("cannot register additional callbacks\n");
		return -1;
	}

	return 1;

out_free:
	mri_free(mri);
	return -1;
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
static int add_path(struct sip_msg* _m, str* _p, int is_reply)
{
	char* buf;
	struct lump *anchor;

	buf = (char*)pkg_malloc(PATH_LEN + _p->len + CRLF_LEN);
	if (!buf) {
		LM_ERR("no pkg memory left\n");
		return -1;
	}
	memcpy(buf, PATH, PATH_LEN);
	memcpy(buf + PATH_LEN, _p->s, _p->len);
	memcpy(buf + PATH_LEN + _p->len, CRLF, CRLF_LEN);

	if (is_reply) {
		anchor = anchor_lump(_m, _m->unparsed - _m->buf, 0);
		if (!anchor) {
			LM_ERR("Failed to get anchor lump\n");
			return -1;
		}

		if (!insert_new_lump_before(anchor, buf, PATH_LEN + _p->len + CRLF_LEN, 0)) {
			LM_ERR("Failed to insert lump\n");
			return -1;
		}
	} else {
		add_lump_rpl(_m, buf, PATH_LEN + _p->len + CRLF_LEN,
			     LUMP_RPL_HDR | LUMP_RPL_NODUP);
	}

	return 0;
}

#define UNSUPPORTED "Unsupported: "
#define UNSUPPORTED_LEN (sizeof(UNSUPPORTED) - 1)
static int add_unsupported(struct sip_msg* _m, str* _p, int is_reply)
{
	char* buf;
	struct lump *anchor;

	buf = (char*)pkg_malloc(UNSUPPORTED_LEN + _p->len + CRLF_LEN);
	if (!buf) {
		LM_ERR("no pkg memory left\n");
		return -1;
	}
	memcpy(buf, UNSUPPORTED, UNSUPPORTED_LEN);
	memcpy(buf + UNSUPPORTED_LEN, _p->s, _p->len);
	memcpy(buf + UNSUPPORTED_LEN + _p->len, CRLF, CRLF_LEN);

	if (is_reply) {
		anchor = anchor_lump(_m, _m->unparsed - _m->buf, 0);
		if (!anchor) {
			LM_ERR("Failed to get anchor lump\n");
			return -1;
		}

		if (!insert_new_lump_before(anchor, buf, UNSUPPORTED_LEN + _p->len + CRLF_LEN, 0)) {
			LM_ERR("Failed to insert lump\n");
			return -1;
		}
	} else {
		add_lump_rpl(_m, buf, UNSUPPORTED_LEN + _p->len + CRLF_LEN,
			     LUMP_RPL_HDR | LUMP_RPL_NODUP);
	}

	return 0;
}

int prepare_rpl_path(struct sip_msg *req, str *path, int flags, struct sip_msg *rpl)
{
	str unsup = str_init(SUPPORTED_PATH_STR);

	if (rerrno != R_FINE || !(flags & REG_SAVE_PATH_FLAG) ||
	        ZSTRP(path) || (flags & REG_SAVE_PATH_OFF_FLAG))
		return 0;

	if (parse_supported(req) < 0 && (flags & REG_SAVE_PATH_STRICT_FLAG)) {
		rerrno = R_PATH_UNSUP;
		if (add_unsupported(rpl ? rpl : req, &unsup, !!rpl) < 0)
			return -1;
		if (add_path(rpl ? rpl : req, path, !!rpl) < 0)
			return -1;

	} else if (get_supported(req) & F_SUPPORTED_PATH) {
		if (add_path(rpl ? rpl : req, path, !!rpl) < 0)
			return -1;

	} else if (flags & REG_SAVE_PATH_STRICT_FLAG) {
		rerrno = R_PATH_UNSUP;
		if (add_unsupported(rpl ? rpl : req, &unsup, !!rpl) < 0)
			return -1;
		if (add_path(rpl ? rpl : req, path, !!rpl) < 0)
			return -1;
	}

	return 0;
}

int send_reply(struct sip_msg* _m, unsigned int _flags)
{
	long code;
	str msg = str_init(MSG_200); /* makes gcc shut up */
	char* buf;

	LM_DBG("contact buf: %.*s\n", contact.data_len, contact.buf);

	if (contact.data_len > 0) {
		add_lump_rpl( _m, contact.buf, contact.data_len, LUMP_RPL_HDR|LUMP_RPL_NODUP|LUMP_RPL_NOFREE);
		contact.data_len = 0;
	}

	if (prepare_rpl_path(_m, &_m->path_vec, _flags, NULL) != 0)
		return -1;

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
													struct save_ctx *_sctx)
{
	int e, expires_out, ret, cflags;
	unsigned int last_reg_ts;
	ucontact_info_t *ci;
	ucontact_t *c;
	contact_t *ct;
	int_str_t value, *valuep;

	LM_DBG("processing contacts...\n");
	cflags = (_sctx->flags&REG_SAVE_MEMORY_FLAG)?FL_MEM:FL_NONE;

	/* pack the contact_info */
	if ( (ci=pack_ci(msg, 0, 0, cflags, ul_api.nat_flag, _sctx->flags,
						&_sctx->ownership_tag, &_sctx->cmatch))==0 ) {
		LM_ERR("failed to initial pack contact info\n");
		return -1;
	}

	/* if there are any new contacts, we must return a "forward" code */
	for (ct = get_first_contact(msg); ct; ct = get_next_contact(ct)) {
		calc_contact_expires(msg, ct->expires, &e, 1);
		if (e == 0) {
			LM_DBG("forwarding REGISTER (ct with expires == 0)\n");
			return 1;
		}

		ret = ul_api.get_ucontact(urec, &ct->uri, ci->callid, ci->cseq,
			&_sctx->cmatch, &c);
		if (ret == -1) {
			LM_ERR("invalid cseq for aor <%.*s>\n",urec->aor.len,urec->aor.s);
			rerrno = R_INV_CSEQ;
			return -1;
		} else if (ret == -2) { /* duplicate or lower cseq */
			continue;
		} else if (ret == 0) { /* found */
			LM_DBG("found >> %d --- [ %ld, %ld ]\n", e,
				c->expires_in, c->expires_out);

			valuep = ul_api.get_ucontact_key(c, &ul_key_last_reg_ts);
			if (!valuep) {
				LM_DBG("'last_reg_ts' key not found! Forwarding request...\n");
				return 1;
			}
			last_reg_ts = valuep->i;

			valuep = ul_api.get_ucontact_key(c, &ul_key_expires_out);
			if (!valuep) {
				LM_DBG("'expires_out' key not found! Forwarding request...\n");
				return 1;
			}
			expires_out = valuep->i;

			if (get_act_time() - last_reg_ts >= expires_out - e) {
				LM_DBG("forwarding REGISTER (%ld - %d >= %d - %d)\n",
				       get_act_time(), last_reg_ts, expires_out, e);
				/* FIXME: should update "last_reg_out_ts" for all cts? */
				return 1;
			} else {
				/* pack the contact specific info */
				ci = pack_ci(msg, ct, e + get_act_time(), cflags,
					ul_api.nat_flag, _sctx->flags, &_sctx->ownership_tag,
					&_sctx->cmatch);
				if (!ci) {
					LM_ERR("failed to pack contact specific info\n");
					rerrno = R_UL_UPD_C;
					return -1;
				}
				ci->expires_out = c->expires_out;

				value.is_str = 0;
				value.i = ci->cseq;
				if (!ul_api.put_ucontact_key(c, &ul_key_last_cseq, &value))
					LM_ERR("failed to update CSeq - oom?\n");

				if (ul_api.update_ucontact(urec, c, ci, 0) < 0) {
					rerrno = R_UL_UPD_C;
					LM_ERR("failed to update contact\n");
					return -1;
				}

				continue;
			}
		}

		LM_DBG("forwarding REGISTER (ct not found)\n");

		/* not found */
		return 1;
	}

	return 2;
}

static int calc_max_ct_diff(urecord_t *urec)
{
	ucontact_t *ct;
	int expires, expires_out, max_diff = -1;
	int_str_t *valuep;

	for (ct = urec->contacts; ct; ct = ct->next) {
		valuep = ul_api.get_ucontact_key(ct, &ul_key_expires);
		if (!valuep) {
			LM_DBG("'expires' key not found!\n");
			return -1;
		}
		expires = valuep->i;

		valuep = ul_api.get_ucontact_key(ct, &ul_key_expires_out);
		if (!valuep) {
			LM_DBG("'expires_out' key not found!\n");
			return -1;
		}
		expires_out = valuep->i;

		LM_DBG("ct - %d - %d - %d\n", expires_out, expires, max_diff);
		if (expires_out - expires > max_diff)
			max_diff = expires_out - expires;
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
														struct save_ctx *_sctx)
{
	int e, ret, ctno = 0, cflags, max_diff = -1;
	ucontact_info_t *ci;
	ucontact_t *c;
	contact_t *ct;
	int e_out, vct;
	unsigned int last_reg_ts;
	int_str_t *value;

	if (urec->contacts == NULL)
		return 1;

	value = ul_api.get_urecord_key(urec, &ul_key_last_reg_ts);
	if (!value) {
		LM_DBG("'last_reg_ts' key not found! Forwarding request\n");
		return 1;
	}
	last_reg_ts = value->i;

	value = ul_api.get_urecord_key(urec, &ul_key_expires_out);
	if (!value) {
		LM_DBG("'expires_out' key not found! Forwarding request\n");
		return 1;
	}
	e_out = value->i;

	LM_DBG("AoR info: e_out=%d, lrts=%d...\n", e_out, last_reg_ts);

	cflags = (_sctx->flags&REG_SAVE_MEMORY_FLAG)?FL_MEM:FL_NONE;

	/* pack the contact_info */
	if ( (ci=pack_ci(req, 0, 0, cflags, ul_api.nat_flag, _sctx->flags,
						&_sctx->ownership_tag, &_sctx->cmatch))==0 ) {
		LM_ERR("failed to initial pack contact info\n");
		return -1;
	}

	for (c = urec->contacts; c; c = c->next)
		ctno++;

	if (_sctx->max_contacts) {
		for (c = urec->contacts, vct = 0; c; c = c->next) {
			if (VALID_CONTACT(c, get_act_time()))
				vct++;
		}
	}

	/* if there are any new contacts, we must return a "forward" code */
	for (ct = get_first_contact(req); ct; ct = get_next_contact(ct)) {
		calc_contact_expires(req, ct->expires, &e, 1);
		if (e > e_out) {
			LM_DBG("reducing contact expiration from %d sec to %d sec!\n",
			       e, e_out);
			e = e_out;
		}

		ret = ul_api.get_ucontact(urec, &ct->uri, ci->callid, ci->cseq,
			&_sctx->cmatch, &c);
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

			if (!VALID_CONTACT(c, get_act_time()))
				vct++;

			if (_sctx->max_contacts && vct > _sctx->max_contacts) {
				if (!(_sctx->flags & REG_SAVE_FORCE_REG_FLAG)) {
					LM_INFO("AOR <%.*s> is already at max contacts (%d)\n",
						urec->aor.len, urec->aor.s, _sctx->max_contacts);
					rerrno = R_TOO_MANY;
					return -1;
				}

				if (trim_contacts(urec, vct - _sctx->max_contacts) != 0)
					return -1;
			}

			/* pack the contact specific info */
			ci = pack_ci(req, ct, e + get_act_time(), cflags,
				ul_api.nat_flag, _sctx->flags, &_sctx->ownership_tag,
				&_sctx->cmatch);
			if (!ci) {
				LM_ERR("failed to pack contact specific info\n");
				rerrno = R_UL_UPD_C;
				return -1;
			}
			ci->expires_out = c->expires_out;

			if (update_ucontact_data(c, e, e_out, ci->cseq) != 0) {
				LM_ERR("failed to update ucontact data - oom?\n");
				return -1;
			}

			if (ul_api.update_ucontact(urec, c, ci, 0) < 0) {
				rerrno = R_UL_UPD_C;
				LM_ERR("failed to update contact\n");
				return -1;
			}
		} else if (ret == 1) {
			/* not found */
			if (e == 0)
				continue;

			if (_sctx->max_contacts && vct >= _sctx->max_contacts) {
				if (!(_sctx->flags & REG_SAVE_FORCE_REG_FLAG)) {
					LM_INFO("AOR <%.*s> is already at max contacts (%d)\n",
						urec->aor.len, urec->aor.s, _sctx->max_contacts);
					rerrno = R_TOO_MANY;
					return -1;
				}

				if (trim_contacts(urec, vct - _sctx->max_contacts + 1) != 0)
					return -1;
			}

			/* pack the contact specific info */
			ci = pack_ci(req, ct, e + get_act_time(), cflags,
				ul_api.nat_flag, _sctx->flags, &_sctx->ownership_tag,
				&_sctx->cmatch);
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

			vct++;

			if (update_ucontact_data(c, e, e_out, ci->cseq) != 0) {
				LM_ERR("failed to update ucontact data - oom?\n");
				return -1;
			}
		}

		/* ignore contacts with duplicate / lower cseq (ret == -2) */
	}

	max_diff = calc_max_ct_diff(urec);

	LM_DBG("max diff: %d, absorb until=%d, current time=%ld\n",
	       max_diff, last_reg_ts + max_diff, get_act_time());
	if (max_diff < 0 || last_reg_ts + max_diff <= get_act_time())
		return 1;

	return 2;
}


int mid_reg_save(struct sip_msg *msg, udomain_t *ud, str *flags_str,
                          str *to_uri, int *expires, str *owtag)
{
	urecord_t *rec = NULL;
	struct save_ctx sctx;
	struct hdr_field *path;
	int rc = -1, st, unlock_udomain = 0;

	if (msg->REQ_METHOD != METHOD_REGISTER) {
		LM_ERR("ignoring non-REGISTER SIP request (%d)\n", msg->REQ_METHOD);
		return -1;
	}

	if (((int (*)(struct sip_msg *))tm_api.t_check_trans)(msg) == 0) {
		LM_INFO("absorbing retransmission, use t_check_trans() earlier!\n");
		return 0;
	}

	rerrno = R_FINE;
	memset(&sctx, 0, sizeof sctx);

	sctx.max_contacts = max_contacts;

	LM_DBG("saving to %.*s...\n", ud->name->len, ud->name->s);

	if (flags_str)
		reg_parse_save_flags(flags_str, &sctx);

	if (parse_reg_headers(msg) != 0) {
		LM_ERR("failed to parse req headers\n");
		return -1;
	}

	if (!to_uri)
		to_uri = &get_to(msg)->uri;

	if (!expires)
		sctx.expires_out = outgoing_expires;
	else
		sctx.expires_out = *expires;

	if (owtag)
		sctx.ownership_tag = *owtag;

	if (extract_aor(to_uri, &sctx.aor, 0, 0) < 0) {
		LM_ERR("failed to extract Address Of Record\n");
		return -1;
	}

	if (check_contacts(msg, &st) > 0) {
		goto out_error;
	}

	if (get_first_contact(msg) == NULL) {
		if (st) {
			sctx.star = 1;
			return prepare_forward(msg, ud, &sctx);
		}
		goto quick_reply;
	}

	/* mid-registrar always rewrites the Contact, so any Path hf must go! */
	if (parse_headers(msg, HDR_PATH_F, 0) == 0 && msg->path) {
		for (path = msg->path; path; path = path->sibling) {
			if (!del_lump(msg, path->name.s - msg->buf,
			              path->len, HDR_PATH_T)) {
				LM_ERR("failed to remove Path HF\n");
				return -1;
			}
		}
	}

	/* in mirror mode, all REGISTER requests simply pass through */
	if (reg_mode == MID_REG_MIRROR)
		return prepare_forward(msg, ud, &sctx);

	update_act_time();
	unlock_udomain = 1;
	ul_api.lock_udomain(ud, &sctx.aor);

	if (ul_api.get_urecord(ud, &sctx.aor, &rec) != 0) {
		ul_api.unlock_udomain(ud, &sctx.aor);
		return prepare_forward(msg, ud, &sctx);
	}

	if (reg_mode == MID_REG_THROTTLE_CT)
		rc = process_contacts_by_ct(msg, rec, &sctx);
	else if (reg_mode == MID_REG_THROTTLE_AOR)
		rc = process_contacts_by_aor(msg, rec, &sctx);

	if (rc == -1)
		goto out_error;
	else if (rc == 1)
		goto out_forward;

quick_reply:
	/* forwarding not needed! This REGISTER will be absorbed */

	/* prepare the Contact header field for a quick 200 OK response */
	if (rec != NULL && rec->contacts != NULL) {
		if (sctx.flags & REG_SAVE_REQ_CT_ONLY_FLAG)
			filter_contacts(rec, NULL, msg);

		build_contact(rec->contacts, msg);

		if (sctx.flags & REG_SAVE_REQ_CT_ONLY_FLAG)
			restore_contacts(rec);
	}

	if (unlock_udomain)
		ul_api.unlock_udomain(ud, &sctx.aor);

	/* quick SIP reply */
	if (!(sctx.flags & REG_SAVE_NOREPLY_FLAG))
		send_reply(msg, sctx.flags);

	return 2;

out_forward:
	clear_path_vector(msg);

	ul_api.unlock_udomain(ud, &sctx.aor);
	return prepare_forward(msg, ud, &sctx);

out_error:
	if (unlock_udomain)
		ul_api.unlock_udomain(ud, &sctx.aor);
	if (!(sctx.flags & REG_SAVE_NOREPLY_FLAG))
		send_reply(msg, sctx.flags);
	return -1;
}
