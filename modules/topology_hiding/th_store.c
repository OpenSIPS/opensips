/*
 * Copyright (C) 2026 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <ctype.h>
#include <string.h>
#include <time.h>

#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../ut.h"
#include "../../trim.h"
#include "../../md5utils.h"
#include "../../socket_info.h"
#include "../../cachedb/cachedb.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_to.h"
#include "../../parser/parse_expires.h"
#include "../../parser/parse_param.h"
#include "../../parser/parse_sst.h"
#include "../../parser/parse_uri.h"
#include "../../parser/contact/parse_contact.h"

#include "th_common_logic.h"
#include "th_store.h"

#define TH_KEY_PREFIX "th:"
#define TH_KEY_PREFIX_LEN (sizeof(TH_KEY_PREFIX) - 1)

/* a refresh may come right at the end of the interval it renews */
#define TH_STATE_TTL_MARGIN 30
/* memcached takes a longer expiration for an absolute time */
#define TH_STATE_TTL_LIMIT 2592000

#define TH_STATE_MAX_LEN 4096
#define TH_PUT_WARN_PERIOD 60

#define SUB_STATE_HDR "Subscription-State"
#define SUB_STATE_HDR_LEN (sizeof(SUB_STATE_HDR) - 1)

str th_state_url = STR_NULL;
int th_state_ttl = 3600;
int th_state_ttl_short = 60;
int th_state_ttl_max = 86400;
int th_state_options = 1;

extern struct th_ct_params *th_param_list;
extern struct th_ct_params *th_hdr_param_list;

static cachedb_funcs th_cdbf;
static cachedb_con *th_cdbc;
static int th_store_on;

static char th_fetch_buf[TH_STATE_MAX_LEN];
static str th_fetched;

/* states are only removed by their expiration, which this backend ignores,
 * and cachedb has no capability telling it */
static int th_store_check_scheme(void)
{
	str scheme;
	char *p;

	p = q_memchr(th_state_url.s, ':', th_state_url.len);
	if (!p)
		return 0;

	scheme.s = th_state_url.s;
	scheme.len = p - th_state_url.s;
	if (str_casematch_nt(&scheme, "mongodb")) {
		LM_ERR("the mongodb backend ignores the expiration of what it "
			"stores, the states would never be removed from th_state_url\n");
		return -1;
	}

	return 0;
}

int th_store_init(int stored_encoding)
{
	if (!th_state_url.s) {
		if (stored_encoding) {
			LM_ERR("encoding type S needs th_state_url\n");
			return -1;
		}
		return 0;
	}

	th_state_url.len = strlen(th_state_url.s);

	if (th_store_check_scheme() < 0)
		return -1;

	if (th_state_ttl_max <= 0 || th_state_ttl_max > TH_STATE_TTL_LIMIT) {
		LM_ERR("th_state_ttl_max must be within 1..%d\n", TH_STATE_TTL_LIMIT);
		return -1;
	}

	if (th_state_ttl <= 0 || th_state_ttl_short <= 0 ||
	th_state_ttl > th_state_ttl_max || th_state_ttl_short > th_state_ttl_max) {
		LM_ERR("th_state_ttl and th_state_ttl_short must be within "
			"1..th_state_ttl_max\n");
		return -1;
	}

	if (cachedb_bind_mod(&th_state_url, &th_cdbf) < 0) {
		LM_ERR("cannot bind functions for th_state_url %s\n",
			db_url_escape(&th_state_url));
		return -1;
	}

	if (!CACHEDB_CAPABILITY(&th_cdbf,
	CACHEDB_CAP_GET|CACHEDB_CAP_SET|CACHEDB_CAP_REMOVE)) {
		LM_ERR("the th_state_url backend lacks get/set/remove support\n");
		return -1;
	}

	if (!stored_encoding)
		LM_INFO("no encoding type S in use, th_state_url is only read\n");

	th_store_on = 1;
	return 0;
}

int th_store_child_init(void)
{
	if (!th_store_on)
		return 0;

	th_cdbc = th_cdbf.init(&th_state_url);
	if (!th_cdbc) {
		LM_ERR("cannot connect to th_state_url %s\n",
			db_url_escape(&th_state_url));
		return -1;
	}

	return 0;
}

void th_store_destroy(void)
{
	if (th_cdbc) {
		th_cdbf.destroy(th_cdbc);
		th_cdbc = NULL;
	}
}

static int th_msg_method(struct sip_msg *msg)
{
	if (msg->first_line.type == SIP_REQUEST)
		return msg->first_line.u.request.method_value;

	return (msg->cseq && get_cseq(msg)) ?
		get_cseq(msg)->method_id : METHOD_UNDEF;
}

/* the tag owned by the party whose Contact @msg carries */
static str *th_msg_key_tag(struct sip_msg *msg)
{
	str *tag;

	if ((!msg->callid && parse_headers(msg, HDR_CALLID_F, 0) < 0) ||
	!msg->callid)
		return NULL;

	if (msg->first_line.type == SIP_REQUEST) {
		if (parse_from_header(msg) < 0 || !msg->from || !get_from(msg))
			return NULL;
		tag = &get_from(msg)->tag_value;
	} else {
		if (parse_to_header(msg) < 0 || !msg->to || !get_to(msg))
			return NULL;
		tag = &get_to(msg)->tag_value;
	}

	return tag->len ? tag : NULL;
}

/* deterministic, so a refresh of the same leg overwrites its state in
 * place; the password keeps it from being guessed off call-id and tag.
 * The lengths go in too, or a call-id and tag split elsewhere would hash
 * the same */
static void th_make_key(const str *pw, str *callid, str *tag, char *key)
{
	char md5[MD5_LEN], cl_buf[INT2STR_MAX_LEN], tl_buf[INT2STR_MAX_LEN];
	str seeds[5], c = *callid, t = *tag;
	char *p;

	trim(&c);
	trim(&t);
	seeds[0] = *pw;
	p = int2str(c.len, &seeds[1].len);
	memcpy(cl_buf, p, seeds[1].len);
	cl_buf[seeds[1].len++] = ':';
	seeds[1].s = cl_buf;
	seeds[2] = c;
	p = int2str(t.len, &seeds[3].len);
	memcpy(tl_buf, p, seeds[3].len);
	tl_buf[seeds[3].len++] = ':';
	seeds[3].s = tl_buf;
	seeds[4] = t;
	MD5StringArray(md5, seeds, 5);
	memcpy(key, md5, TH_KEY_LEN);
}

static str *th_full_key(const char *key)
{
	static char buf[TH_KEY_PREFIX_LEN + TH_KEY_LEN] = TH_KEY_PREFIX;
	static str full = { buf, TH_KEY_PREFIX_LEN + TH_KEY_LEN };

	memcpy(buf + TH_KEY_PREFIX_LEN, key, TH_KEY_LEN);
	return &full;
}

/* nothing is ever routed to the Contact of an OPTIONS or its reply */
int th_store_no_state(struct sip_msg *msg)
{
	return !th_state_options && th_msg_method(msg) == METHOD_OPTIONS;
}

int th_store_is_key(const str *val)
{
	int i;

	if (!th_store_on || val->len != TH_KEY_WIRE_LEN ||
	val->s[0] != TH_KEY_MARKER)
		return 0;

	for (i = 1; i < TH_KEY_WIRE_LEN; i++)
		if (!isxdigit((unsigned char)val->s[i]))
			return 0;

	return 1;
}

/* the Contact ;expires only means something to a REGISTER (RFC 3261
 * 10.2.1.1), where it comes before the Expires header */
static long th_msg_expires(struct sip_msg *msg, int ct_param)
{
	exp_body_t *exp;
	contact_t *ct;
	unsigned int ct_exp;

	if (ct_param && (msg->contact ||
	(parse_headers(msg, HDR_CONTACT_F, 0) == 0 && msg->contact))) {
		if (msg->contact->parsed || parse_contact(msg->contact) == 0) {
			ct = ((contact_body_t *)msg->contact->parsed)->contacts;
			if (ct && ct->expires && ct->expires->body.len &&
			str2int(&ct->expires->body, &ct_exp) == 0)
				return ct_exp;
		}
	}

	if (parse_headers(msg, HDR_EXPIRES_F, 0) == 0 && msg->expires) {
		if (msg->expires->parsed || parse_expires(msg->expires) == 0) {
			exp = (exp_body_t *)msg->expires->parsed;
			if (exp && exp->valid && exp->val >= 0)
				return exp->val;
		}
	}

	return -1;
}

/* what the notifier granted (RFC 6665 4.1.3): 0 if terminated, -1 if
 * the NOTIFY does not say */
static long th_notify_sub_expires(struct sip_msg *msg)
{
	struct hdr_field *hf;
	param_hooks_t hooks;
	param_t *params = NULL, *p;
	str body, state;
	unsigned int val;
	long ret = -1;
	char *sep;

	if (parse_headers(msg, HDR_EOH_F, 0) < 0)
		return -1;

	for (hf = msg->headers; hf; hf = hf->next)
		if (hf->type == HDR_OTHER_T && hf->name.len == SUB_STATE_HDR_LEN &&
		strncasecmp(hf->name.s, SUB_STATE_HDR, SUB_STATE_HDR_LEN) == 0)
			break;
	if (!hf)
		return -1;

	body = hf->body;
	trim(&body);
	sep = q_memchr(body.s, ';', body.len);

	state = body;
	if (sep)
		state.len = sep - body.s;
	trim(&state);
	if (state.len == 10 && strncasecmp(state.s, "terminated", 10) == 0)
		return 0;

	if (!sep)
		return -1;

	body.len -= sep - body.s + 1;
	body.s = sep + 1;
	if (body.len <= 0 || parse_params(&body, CLASS_ANY, &hooks, &params) < 0)
		return -1;

	for (p = params; p; p = p->next)
		if (p->name.len == 7 && strncasecmp(p->name.s, "expires", 7) == 0) {
			if (str2int(&p->body, &val) == 0)
				ret = val;
			break;
		}

	free_params(params);
	return ret;
}

static long th_sub_expires(struct sip_msg *msg, int method)
{
	long expires = -1;

	if (method == METHOD_NOTIFY)
		expires = th_notify_sub_expires(msg);

	if (expires < 0)
		expires = th_msg_expires(msg, 0);

	return expires;
}

/* a lifetime out of a header, bounded: it comes from the far end */
static int th_ttl(unsigned long secs)
{
	if (secs >= (unsigned long)th_state_ttl_max - TH_STATE_TTL_MARGIN)
		return th_state_ttl_max;

	return (int)secs + TH_STATE_TTL_MARGIN;
}

/* @ttl_src is the request a reply answers: a 200 OK may well not repeat
 * the lifetime its NOTIFY or INVITE carried */
static int th_state_msg_ttl(struct sip_msg *msg, struct sip_msg *ttl_src)
{
	struct session_expires se;
	int ttl, method = th_msg_method(msg);
	long expires;

	switch (method) {
	case METHOD_SUBSCRIBE:
	case METHOD_NOTIFY:
		if (method == METHOD_SUBSCRIBE &&
		msg->first_line.type == SIP_REPLY && msg->REPLY_STATUS >= 300)
			return th_state_ttl_short;
		expires = th_sub_expires(msg, method);
		if (expires < 0 && ttl_src)
			expires = th_sub_expires(ttl_src, th_msg_method(ttl_src));
		if (expires < 0)
			ttl = th_state_ttl;
		/* a subscription being torn down only needs its final NOTIFY */
		else if (expires == 0)
			ttl = th_state_ttl_short;
		else
			ttl = th_ttl(expires);
		/* a forked SUBSCRIBE gives all its notifier dialogs the subscriber's
		 * key, which one of them may not shorten under the others */
		if ((method == METHOD_SUBSCRIBE) == (msg->first_line.type ==
		SIP_REQUEST) && ttl < th_state_ttl)
			ttl = th_state_ttl;
		return ttl;
	case METHOD_INVITE:
	case METHOD_UPDATE:
		if (parse_session_expires(msg, &se) == parse_sst_success &&
		se.interval > 0)
			return th_ttl(se.interval);
		if (ttl_src &&
		parse_session_expires(ttl_src, &se) == parse_sst_success &&
		se.interval > 0)
			return th_ttl(se.interval);
		return th_state_ttl;
	case METHOD_REGISTER:
		expires = th_msg_expires(msg, 1);
		if (expires < 0 && ttl_src)
			expires = th_msg_expires(ttl_src, 1);
		if (expires < 0)
			return th_state_ttl;
		return expires ? th_ttl(expires) : th_state_ttl_short;
	case METHOD_OPTIONS:
	case METHOD_MESSAGE:
	case METHOD_INFO:
	case METHOD_PUBLISH:
		/* not target refreshes (RFC 3261 12.2.1.2): only the transaction
		 * needs their Contact */
		return th_state_ttl_short;
	default:
		return th_state_ttl;
	}
}

/* @req is the request a reply answers */
static int th_msg_in_dialog(struct sip_msg *msg, struct sip_msg *req)
{
	struct sip_msg *r = msg->first_line.type == SIP_REQUEST ? msg : req;

	if (!r || (!r->to && (parse_headers(r, HDR_TO_F, 0) < 0 || !r->to)))
		return 0;

	return get_to(r)->tag_value.len > 0;
}

static int th_msg_target_refresh(struct sip_msg *msg)
{
	switch (th_msg_method(msg)) {
	case METHOD_INVITE:
	case METHOD_UPDATE:
	case METHOD_SUBSCRIBE:
	case METHOD_NOTIFY:
	case METHOD_REFER:
		return 1;
	default:
		return 0;
	}
}

static int th_has_session_timer(struct sip_msg *msg)
{
	struct session_expires se;

	return parse_session_expires(msg, &se) == parse_sst_success &&
		se.interval > 0;
}

/* @store: TH_STORE_DECIDE for a new dialog, else what it came in with (0 or
 * its kind); @req is the request a reply answers. Returns the kind of
 * dialog to store the state for, or 0 to send it inline */
int th_store_wanted(struct sip_msg *msg, struct sip_msg *req, int store)
{
	str *tag;
	int method;

	if (!th_store_on || !store || !(tag = th_msg_key_tag(msg)))
		return 0;

	/* a reply tagged as its caller would take the caller's key */
	if (msg->first_line.type == SIP_REPLY && parse_from_header(msg) == 0 &&
	str_match(tag, &get_from(msg)->tag_value))
		return 0;

	method = th_msg_method(msg);
	if (th_msg_in_dialog(msg, req)) {
		if (store < 0)
			return 0;
		/* each usage of a dialog shares its keys: only the messages of the
		 * one which created it may touch them, the rest go inline */
		switch (store) {
		case TH_KIND_CALL:
			return (method == METHOD_INVITE || method == METHOD_UPDATE) &&
				th_has_session_timer(msg) ? store : 0;
		case TH_KIND_SUB:
			return method == METHOD_SUBSCRIBE || method == METHOD_NOTIFY ?
				store : 0;
		default:
			/* a non target refresh would overwrite its leg's state, and
			 * the far end ignores its Contact (RFC 3261 12.2.1.2) */
			return th_msg_target_refresh(msg) ? store : 0;
		}
	}

	switch (method) {
	case METHOD_INVITE:
	case METHOD_UPDATE:
		/* only session timers bound a call, else its state stays inline */
		return th_has_session_timer(msg) ? TH_KIND_CALL : 0;
	case METHOD_SUBSCRIBE:
	case METHOD_NOTIFY:
	case METHOD_REFER:
		return TH_KIND_SUB;
	default:
		return TH_KIND_OTHER;
	}
}

static char *th_pack_field(char *p, const str *f)
{
	char *l;
	int len;

	l = int2str(f->len, &len);
	memcpy(p, l, len);
	p += len;
	*p++ = ':';
	if (f->len)
		memcpy(p, f->s, f->len);
	return p + f->len;
}

static int th_unpack_field(str *in, str *f)
{
	char *p = in->s, *end = in->s + in->len;
	int len = 0;

	while (p < end && *p >= '0' && *p <= '9' && len < TH_STATE_MAX_LEN)
		len = len * 10 + (*p++ - '0');

	if (p == in->s || p >= end || *p != ':' || len > end - p - 1)
		return -1;

	f->s = p + 1;
	f->len = len;
	in->s = f->s + len;
	in->len = end - in->s;
	return 0;
}

/* an outage fails every write, so tell about them once in a while */
static void th_put_failed(void)
{
	static time_t last;
	static unsigned int failed;
	time_t now = time(NULL);

	failed++;
	if (now - last < TH_PUT_WARN_PERIOD)
		return;

	LM_WARN("%u topology hiding state(s) could not be stored in "
		"th_state_url, they travel inline in the Contact\n", failed);
	last = now;
	failed = 0;
}

/* kept as printable "<len>:<bytes>" fields: off the wire, the state
 * needs neither the obfuscation nor the URI-safe encoding */
static int th_store_put(struct sip_msg *msg, const str *pw, str *rr_set,
		str *contact, uint16_t flags, int kind, struct sip_msg *ttl_src,
		char *key)
{
	char kind_buf = '0' + kind;
	str kind_str = { &kind_buf, 1 };
	char flags_buf[INT2STR_MAX_LEN];
	str flags_str, val, *tag;
	const str *sock;
	char *p;
	int ttl;

	if (!th_cdbc) {
		th_put_failed();
		return -1;
	}

	if (!(tag = th_msg_key_tag(msg))) {
		LM_BUG("no call-id or tag to key the state on\n");
		return -1;
	}
	th_make_key(pw, &msg->callid->body, tag, key);

	p = int2str(flags, &flags_str.len);
	memcpy(flags_buf, p, flags_str.len);
	flags_str.s = flags_buf;
	sock = &msg->rcv.bind_address->sock_str;

	val.len = rr_set->len + contact->len + flags_str.len + sock->len +
		kind_str.len + 5 * INT2STR_MAX_LEN;
	if (val.len > TH_STATE_MAX_LEN) {
		LM_ERR("topology hiding state too long (%d)\n", val.len);
		return -1;
	}

	val.s = pkg_malloc(val.len);
	if (!val.s) {
		LM_ERR("no more pkg\n");
		return -1;
	}

	p = th_pack_field(val.s, rr_set);
	p = th_pack_field(p, contact);
	p = th_pack_field(p, &flags_str);
	p = th_pack_field(p, sock);
	p = th_pack_field(p, &kind_str);
	val.len = p - val.s;

	ttl = th_state_msg_ttl(msg, ttl_src);
	if (th_cdbf.set(th_cdbc, th_full_key(key), &val, ttl) < 0) {
		th_put_failed();
		pkg_free(val.s);
		return -1;
	}

	LM_DBG("stored %d bytes under <%.*s> for %d s\n", val.len,
		TH_KEY_LEN, key, ttl);
	pkg_free(val.s);
	return 0;
}

char *th_store_ct_suffix(struct sip_msg *msg, str *rr_set, uint16_t flags,
		const str *param_name, const str *pw, int kind,
		struct sip_msg *ttl_src, int *suffix_len)
{
	contact_body_t *cb;
	contact_t *ct;
	struct sip_uri ctu;
	struct th_ct_params *el;
	param_t *it;
	char key[TH_KEY_LEN];
	char *suffix, *s;
	int i, len = 1 /* > */;

	if (parse_headers(msg, HDR_EOH_F, 0) < 0 || !msg->contact ||
	parse_contact(msg->contact) < 0) {
		LM_ERR("bad Contact HDR\n");
		return NULL;
	}

	cb = (contact_body_t *)msg->contact->parsed;
	if (cb->star || !cb->contacts || cb->contacts->next) {
		LM_ERR("bad Contact HDR\n");
		return NULL;
	}
	ct = cb->contacts;

	if (parse_uri(ct->uri.s, ct->uri.len, &ctu) < 0) {
		LM_ERR("Bad Contact URI\n");
		return NULL;
	}

	if (param_name) {
		if (th_store_put(msg, pw, rr_set, &ct->uri, flags, kind, ttl_src,
		key) < 0)
			return NULL;
		len += 1 /* ; */ + param_name->len + 1 /* = */ + TH_KEY_WIRE_LEN;
	}

	for (el = th_param_list; el; el = el->next)
		for (i = 0; i < ctu.u_params_no; i++)
			if (str_match(&el->param_name, &ctu.u_name[i]))
				len += topo_ct_param_len(&ctu.u_name[i], &ctu.u_val[i], 0);

	for (el = th_hdr_param_list; el; el = el->next)
		for (it = ct->params; it; it = it->next)
			if (str_match(&el->param_name, &it->name))
				len += topo_ct_param_len(&it->name, &it->body, 1);

	suffix = pkg_malloc(len);
	if (!suffix) {
		LM_ERR("no more pkg\n");
		return NULL;
	}

	s = suffix;
	if (param_name) {
		*s++ = ';';
		memcpy(s, param_name->s, param_name->len);
		s += param_name->len;
		*s++ = '=';
		*s++ = TH_KEY_MARKER;
		memcpy(s, key, TH_KEY_LEN);
		s += TH_KEY_LEN;
	}

	for (el = th_param_list; el; el = el->next)
		for (i = 0; i < ctu.u_params_no; i++)
			if (str_match(&el->param_name, &ctu.u_name[i]))
				s = topo_ct_param_copy(s, &ctu.u_name[i], &ctu.u_val[i], 0);

	*s++ = '>';

	for (el = th_hdr_param_list; el; el = el->next)
		for (it = ct->params; it; it = it->next)
			if (str_match(&el->param_name, &it->name))
				s = topo_ct_param_copy(s, &it->name, &it->body, 1);

	*suffix_len = s - suffix;
	return suffix;
}

/* a request may only use the key of the party it is sent to, i.e. the
 * one of its own call-id and To tag */
static int th_key_of_request(struct sip_msg *msg, const str *wire,
		const str *pw)
{
	char key[TH_KEY_LEN];

	if ((!msg->callid && (parse_headers(msg, HDR_CALLID_F, 0) < 0 ||
	!msg->callid)) || parse_to_header(msg) < 0 || !msg->to ||
	!get_to(msg)->tag_value.len)
		return 0;

	th_make_key(pw, &msg->callid->body, &get_to(msg)->tag_value, key);
	return memcmp(key, wire->s + 1, TH_KEY_LEN) == 0;
}

int th_store_fetch(struct sip_msg *msg, const str *wire, const str *pw)
{
	str val = STR_NULL, *full;
	int rc;

	if (!th_key_of_request(msg, wire, pw)) {
		LM_WARN("key <%.*s> does not belong to the dialog of the "
			"request\n", wire->len, wire->s);
		return -1;
	}

	if (!th_cdbc) {
		LM_ERR("not connected to th_state_url\n");
		return -1;
	}

	full = th_full_key(wire->s + 1);
	rc = th_cdbf.get(th_cdbc, full, &val);

	/* a miss is an expired (or never stored) state, not a backend failure */
	if (rc == -2 || (rc >= 0 && !val.len)) {
		LM_WARN("no topology hiding state under <%.*s>, it may have "
			"expired\n", full->len, full->s);
		if (val.s)
			pkg_free(val.s);
		return -1;
	}

	if (rc < 0) {
		LM_ERR("failed to fetch the topology hiding state under <%.*s>\n",
			full->len, full->s);
		return -1;
	}

	if (val.len > TH_STATE_MAX_LEN) {
		LM_ERR("topology hiding state under <%.*s> too long (%d)\n",
			full->len, full->s, val.len);
		pkg_free(val.s);
		return -1;
	}

	memcpy(th_fetch_buf, val.s, val.len);
	th_fetched.s = th_fetch_buf;
	th_fetched.len = val.len;
	pkg_free(val.s);
	return 0;
}

int th_store_unpack(str *routes, str *contact, str *flags, str *sock,
		int *kind)
{
	str in = th_fetched, k;

	if (th_unpack_field(&in, routes) < 0 || th_unpack_field(&in, contact) < 0 ||
	th_unpack_field(&in, flags) < 0 || th_unpack_field(&in, sock) < 0 ||
	th_unpack_field(&in, &k) < 0 || in.len || k.len != 1 ||
	k.s[0] < '0' + TH_KIND_CALL || k.s[0] > '0' + TH_KIND_OTHER) {
		LM_ERR("malformed topology hiding state <%.*s>\n",
			th_fetched.len, th_fetched.s);
		return -1;
	}

	*kind = k.s[0] - '0';
	return 0;
}

/* a rejected (or challenged) initial SUBSCRIBE gets no dialog to ever use
 * its subscriber's state; a retry under the same key stores it again */
void th_store_drop_rejected(struct sip_msg *rpl, const str *pw)
{
	char key[TH_KEY_LEN];
	str *full;

	if (!th_cdbc || rpl->REPLY_STATUS < 300 ||
	th_msg_method(rpl) != METHOD_SUBSCRIBE)
		return;

	if (!rpl->callid || parse_from_header(rpl) < 0 ||
	!get_from(rpl)->tag_value.len)
		return;

	th_make_key(pw, &rpl->callid->body, &get_from(rpl)->tag_value, key);
	full = th_full_key(key);
	if (th_cdbf.remove(th_cdbc, full) < 0)
		LM_WARN("failed to drop <%.*s>, leaving it to expire\n",
			full->len, full->s);
}
