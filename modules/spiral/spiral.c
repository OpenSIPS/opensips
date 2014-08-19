/*
 * $Id$
 *
 * spiral module - support for callid mangling
 *
 * Copyright (C) 2014 VoIPGRID B.V.
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
 *  2014-06-09 initial version (Walter Doekes)
 */

#include <stdio.h>

#include "../../sr_module.h"
#ifndef MAX_MOD_DEPS
# define PRE_1_12_MODULE_DEPS
#endif

#include "../../data_lump.h"
#include "../../mod_fix.h"
#include "../../msg_translator.h"
#include "../../parser/parse_from.h"
#include "../../parser/parse_rr.h"
#include "../../parser/parse_uri.h"
#include "../../script_cb.h"
#include "../../ut.h"

#include "../rr/api.h"

static int mod_init(void);

static struct rr_binds d_rrb;

/* spiral callid mangling */
/* RFC4475: Call-ID: intmeth.word%ZK-!.*_+'@word`~)(><:\/"][?}{ */
/* NOTE: we cannot chain two of these manglers, or we'll think that we mangled
 * it if the previous opensips did. But we can set a different mangling_prefix
 * for a second opensips instance. */
static str callid_mangling_prefix = str_init("~{}~"); /* asterisk chokes on ~%S~ */

/* This is added as a temporary header while inside the core. It's
 * added in the pre-handler and removed in the post-handler. */
static const str cookie_header_key = str_init("XX-SPIRAL");

static int spiral_pre_raw(str *data);
static int spiral_post_raw(str *data);

static param_export_t mod_params[] = {
	{"callid_mangling_prefix", STR_PARAM, &callid_mangling_prefix.s},
	{0, 0, 0}
};

#ifndef PRE_1_12_MODULE_DEPS
static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "rr",   DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "tm",   DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};
#endif

struct module_exports exports= {
	"spiral",        /* module's name */
#ifndef PRE_1_12_MODULE_DEPS
	MOD_TYPE_DEFAULT,/* class of this module */
#endif
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
#ifndef PRE_1_12_MODULE_DEPS
	&deps,           /* OpenSIPS module dependencies */
#endif
	NULL,            /* exported functions */
	mod_params,      /* param exports */
	NULL,            /* exported statistics */
	NULL,            /* exported MI functions */
	NULL,            /* exported pseudo-variables */
	0,               /* extra processes */
	mod_init,        /* module initialization function */
	NULL,            /* reply processing function */
	NULL,            /* module unloading/cleanup function */
	NULL             /* per-child init function */
};

static int mod_init(void)
{
	LM_INFO("Spiral module - initializing\n");

	callid_mangling_prefix.len = strlen(callid_mangling_prefix.s);
	if (!callid_mangling_prefix.len) {
		LM_ERR("invalid value for callid_mangling_prefix\n");
		return -1;
	}

	/* Load RR API. Make sure the fromtag "ftag" is appended. */
	if (load_rr_api(&d_rrb) != 0) {
		LM_ERR("can't load RR API\n");
		return -1;
	}
	if (!d_rrb.append_fromtag) {
		LM_WARN("explicitly enabling RR append_fromtag\n");
		d_rrb.append_fromtag = 1;
	}

	/* Set spiral callid mangling callbacks (pre and post) */
	if (register_raw_processing_cb(spiral_pre_raw, PRE_RAW_PROCESSING) < 0) {
		LM_ERR("failed to initialize pre raw support\n");
		return -1;
	}
	if (register_raw_processing_cb(spiral_post_raw, POST_RAW_PROCESSING) < 0) {
		LM_ERR("failed to initialize post raw support\n");
		return -1;
	}

	return 0;
}

static inline int spiral_has_totag(struct sip_msg *msg)
{
	/* If it has a to-tag, this is an in-dialog request */
	if (parse_to_header(msg) < 0) {
		LM_ERR("cannot parse TO header\n");
		return -1;
	}
	if (get_to(msg)->tag_value.len > 0) {
		return 1;
	}
	return 0;
}

/* Return 1 if the parameter `name` was found, value is placed in `value`. */
static int spiral_get_param_value(str *in, const str *name, str *value)
{
	param_t *params = NULL;
	param_t *p = NULL;
	param_hooks_t phooks;
	if (parse_params(in, CLASS_ANY, &phooks, &params) < 0) {
		return -1;
	}
	for (p = params; p; p = p->next) {
		if (p->name.len == name->len &&
				strncasecmp(p->name.s, name->s, name->len) == 0) {
			*value = p->body;
			free_params(params);
			return 0;
		}
	}

	if (params) {
		free_params(params);
	}
	return 1;
}

/* Return 1 if the packet is from the CALLER to CALLEE. */
static inline int spiral_direction_downstream(struct sip_msg *msg)
{
	rr_t *rr;
	struct sip_uri puri;
	const str ftag = {"ftag", 4}; /* hardcoded ftag equal to the RR one */
	str rr_ftag = {0, 0};
	const str *fromtag;

	if (!msg->route) {
		LM_DBG("no route header - downstream\n");
		return 1;
	}
	if (parse_rr(msg->route) < 0) {
		LM_ERR("failed to parse RR header\n");
		return -1;
	}

	/* We wanted to use d_rrb.is_direction(msg, RR_FLOW_DOWNSTREAM) == 0)
	 * but unfortunately that silently fails if loose_route() hasn't been
	 * called yet. Instead we have to replicate its efforts here. */
	if (parse_from_header(msg) < 0) {
		LM_ERR("cannot parse FROM header\n");
		return -1;
	}
	fromtag = &get_from(msg)->tag_value;
	if (fromtag->len <= 0) {
		LM_ERR("failed to get from header tag\n");
		return -1;
	}
	rr = (rr_t*)msg->route->parsed;
	if (parse_uri(rr->nameaddr.uri.s, rr->nameaddr.uri.len, &puri) < 0) {
		LM_ERR("failed to parse the first route URI\n");
		return -1;
	}
	if (spiral_get_param_value(&puri.params, &ftag, &rr_ftag) != 0) {
		return 0;
	}
	if (fromtag->len == rr_ftag.len &&
			memcmp(fromtag->s, rr_ftag.s, rr_ftag.len) == 0) {
		LM_DBG("ftag match, is_downstream\n");
		return 1;
	}
	LM_DBG("ftag mismatch, is_upstream\n");
	return 0;
}

static int spiral_needs_unmangling(struct sip_msg *msg)
{
	const str *callid;

	if (msg->callid == NULL) {
		LM_ERR("callid missing\n");
		return 0;
	}

	callid = &msg->callid->body;
	if (callid->len > callid_mangling_prefix.len &&
			memcmp(callid->s, callid_mangling_prefix.s,
				callid_mangling_prefix.len) == 0) {
		return 1;
	}

	return 0;
}

int spiral_mangle_callid(struct sip_msg *msg)
{
	struct lump *del;
	str new_callid;

	if (msg->callid == NULL) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}

	new_callid.len = msg->callid->body.len + callid_mangling_prefix.len;
	new_callid.s = pkg_malloc(new_callid.len);
	if (new_callid.s == NULL) {
		LM_ERR("failed to allocate callid len\n");
		return -1;
	}

	if (new_callid.s == NULL) {
		LM_ERR("failed to encode callid\n");
		return -1;
	}

	memcpy(new_callid.s, callid_mangling_prefix.s, callid_mangling_prefix.len);
	memcpy((new_callid.s + callid_mangling_prefix.len), msg->callid->body.s,
			msg->callid->body.len);

	del = del_lump(msg, msg->callid->body.s - msg->buf, msg->callid->body.len, HDR_CALLID_T);
	if (del == NULL) {
		LM_ERR("failed to delete old callid\n");
		pkg_free(new_callid.s);
		return -1;
	}

	if (insert_new_lump_after(del, new_callid.s, new_callid.len, HDR_CALLID_T) == NULL) {
		LM_ERR("failed to insert new callid\n");
		pkg_free(new_callid.s);
		return -1;
	}

	return 0;
}

int spiral_unmangle_callid(struct sip_msg *msg)
{
	struct lump *del;
	str new_callid;
	int new_size;

	if (msg->callid == NULL) {
		LM_ERR("message with no callid\n");
		return -1;
	}

	new_size = msg->callid->body.len - callid_mangling_prefix.len;
	new_callid.s = pkg_malloc(new_size);
	if (new_callid.s == NULL) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}

	new_callid.len = new_size;
	memcpy(new_callid.s, (msg->callid->body.s + callid_mangling_prefix.len), new_callid.len);

	del = del_lump(msg, msg->callid->body.s - msg->buf, msg->callid->body.len, HDR_CALLID_T);
	if (del == NULL) {
		LM_ERR("failed to delete old callid\n");
		pkg_free(new_callid.s);
		return -1;
	}

	if (insert_new_lump_after(del, new_callid.s, new_callid.len, HDR_CALLID_T) == NULL) {
		LM_ERR("failed to insert new callid\n");
		pkg_free(new_callid.s);
		return -1;
	}

	return 0;
}

static int spiral_add_cookie(struct sip_msg *msg, const str *cookie_header_value)
{
	struct lump* anchor;
	int pos;
	str h, v;

	/* Add header cookie */
	h.len = cookie_header_key.len + 2 + cookie_header_value->len + CRLF_LEN;
	h.s = (char*)pkg_malloc(h.len + 1);
	if (h.s == 0) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}

	anchor = anchor_lump(msg, msg->unparsed - msg->buf, 0);
	if (anchor == 0) {
		LM_ERR("can't get header anchor\n");
		pkg_free(h.s);
		return -1;
	}

	memcpy(h.s, cookie_header_key.s, cookie_header_key.len);
	memcpy(h.s + cookie_header_key.len, ": ", 2);
	memcpy(h.s + cookie_header_key.len + 2, cookie_header_value->s, cookie_header_value->len);
	memcpy(h.s + cookie_header_key.len + 2 + cookie_header_value->len, CRLF, CRLF_LEN);
	h.s[h.len] = '\0';

	if (insert_new_lump_before(anchor, h.s, h.len, 0) == 0)	{
		LM_ERR("can't insert header lump\n");
		pkg_free(h.s);
		return -1;
	}

	/* Add Via cookie as well */
	if (msg->via1->params.s) {
		pos = msg->via1->params.s - msg->via1->hdr.s - 1;
	} else {
		pos = msg->via1->host.s - msg->via1->hdr.s + msg->via1->host.len;
		if (msg->via1->port != 0)
			pos += msg->via1->port_str.len + 1; /* +1 for ':' */
	}
	anchor = anchor_lump(msg, msg->via1->hdr.s - msg->buf + pos, 0);
	if (anchor == 0) {
		LM_ERR("can't get Via anchor\n");
		return -1;
	}

	v.len = 1 + cookie_header_key.len + 1 + cookie_header_value->len;
	v.s = (char*)pkg_malloc(v.len + 1);
	if (v.s == 0) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}
	v.s[0] = ';';
	memcpy(v.s + 1, cookie_header_key.s, cookie_header_key.len);
	v.s[cookie_header_key.len + 1] = '=';
	memcpy(v.s + cookie_header_key.len + 2, cookie_header_value->s, cookie_header_value->len);
	v.s[v.len] = '\0';

	if (insert_new_lump_after(anchor, v.s, v.len, 0) == 0) {
		LM_ERR("can't insert Via lump\n");
		pkg_free(h.s);
		return -1;
	}

	LM_DBG("spiral: added cookie in header/Via %.*s [%.*s]\n",
			cookie_header_key.len, cookie_header_key.s, h.len, h.s);
	return 0;
}

static void spiral_del_cookie(struct sip_msg *msg)
{
	struct lump* anchor;
	struct hdr_field *hf;
	struct via_param *p;

	/* Remove cooke from headers */
	for (hf = msg->headers; hf; hf = hf->next) {
		/* strncasecmp not needed, we put the cookie there with the
		 * same case */
		if (hf->name.len == cookie_header_key.len &&
				memcmp(hf->name.s, cookie_header_key.s,
					cookie_header_key.len) == 0) {
			anchor = del_lump(msg, hf->name.s-msg->buf, hf->len, 0);
			if (anchor == 0) {
				LM_ERR("spiral: unable to delete header cookie\n");
			}
			break;
		}
	}

	/* Remove cookie from Via as well */
	if (msg->via1 == NULL) {
		/* If the 487 to a CANCELed call is misconstructed with
		 * a single Via, that Via gets stripped and now we end
		 * up here without any Via at all. Don't die. */
		LM_DBG("spiral: no Via header to remove cookie from\n");
		return;
	}

	/* For requests, it is in via2, for replies it is in via1 */
	if (msg->first_line.type == SIP_REQUEST) {
		/* There must be a via2, if there wasn't a via1, we
		 * wouldn't be here. And we add the via2. */
		p = msg->via2->param_lst;
	} else {
		p = msg->via1->param_lst;
	}
	for (; p; p = p->next) {
		if (p->name.len == cookie_header_key.len &&
				memcmp(p->name.s, cookie_header_key.s,
					cookie_header_key.len) == 0) {
			anchor = del_lump(msg, p->start-msg->buf - 1, p->size + 1, 0);
			if (anchor == 0) {
				LM_ERR("spiral: unable to delete Via cookie\n");
			}
			break;
		}
	}
}

int spiral_get_cookie(struct sip_msg *msg, str *dest)
{
	struct hdr_field *hf;
	struct via_param *p;

	/* Get header cookie */
	for (hf = msg->headers; hf; hf = hf->next) {
		/* strncasecmp not needed, we put the cookie there with the
		 * same case */
		if (hf->name.len == cookie_header_key.len &&
				memcmp(hf->name.s, cookie_header_key.s,
					cookie_header_key.len) == 0) {
			/* Copy at most the input length. */
			if (dest->len > hf->body.len + 1)
				dest->len = hf->body.len + 1;
			dest->s[0] = 'h';
			memcpy(dest->s + 1, hf->body.s, dest->len);
			LM_DBG("spiral: got header cookie %.*s [%.*s]\n", cookie_header_key.len,
					cookie_header_key.s, dest->len, dest->s);
			return 1;
		}
	}
	LM_DBG("spiral: no header cookie %.*s found\n",
			cookie_header_key.len, cookie_header_key.s);

	/* Get Via cookie if no header cookie can be found */
	for (p = msg->via1->param_lst; p; p = p->next) {
		if (p->name.len == cookie_header_key.len &&
				memcmp(p->name.s, cookie_header_key.s,
					cookie_header_key.len) == 0) {
			/* Copy at most the input length. */
			if (dest->len > p->value.len + 1)
				dest->len = p->value.len + 1;
			dest->s[0] = 'v';
			memcpy(dest->s + 1, p->value.s, dest->len + 1);
			LM_DBG("spiral: got Via cookie %.*s [%.*s]\n", cookie_header_key.len,
					cookie_header_key.s, dest->len, dest->s);
			return 1;
		}
	}
	LM_DBG("spiral: no Via cookie %.*s found\n",
			cookie_header_key.len, cookie_header_key.s);

	return 0;
}

static inline char *spiral_rebuild_req(struct sip_msg *msg, int *len)
{
	char *ret = build_req_buf_from_sip_req(msg, (unsigned int*)len, NULL,
			PROTO_NONE, MSG_TRANS_NOVIA_FLAG);
	return ret;
}

static inline char *spiral_rebuild_rpl(struct sip_msg *msg, int *len)
{
	char *ret = build_res_buf_from_sip_res(msg, (unsigned int*)len, NULL,
			MSG_TRANS_NOVIA_FLAG);
	return ret;
}

int spiral_parse_msg(struct sip_msg *msg)
{
	if (parse_msg(msg->buf, msg->len, msg) != 0) {
		LM_ERR("invalid SIP msg\n");
		return -1;
	}
	if (parse_headers(msg, HDR_EOH_F, 0) < 0) {
		LM_ERR("failed to parse SIP headers\n");
		return -1;
	}
#if 0
	/* 2nd via parsing here so we can do msg.via2 checking later. */
	if (parse_headers(msg, HDR_VIA2_F, 0) == -1 ||
			(msg->via2 == 0) || (msg->via2->error != PARSE_OK)) {
		LM_DBG("no second via in this message\n");
	}
#endif
	return 0;
}

#define MSG_SKIP_BITMASK (METHOD_REGISTER|METHOD_PUBLISH|METHOD_OPTIONS| \
		METHOD_NOTIFY|METHOD_SUBSCRIBE)
int spiral_skip_msg(struct sip_msg *msg)
{
	if (msg->cseq == NULL || get_cseq(msg) == NULL) {
		LM_ERR("failed to parse CSEQ header\n");
		return -1; /* error */
	}
	if ((get_cseq(msg)->method_id) & MSG_SKIP_BITMASK) {
		LM_DBG("skipping method %d for spiral callid mangling\n",
				get_cseq(msg)->method_id);
		return 1; /* skip */
	}
	return 0;
}
#undef MSG_SKIP_BITMASK

/* Call flow diagram:
 *
 * > INVITE >>> where=post, action=mangle (downstream)
 * <<<<<< 200 < where=pre,  action=unmangle (upstream)
 * > ACK >>>>>> where=post, action=mangle (downstream)
 *
 * <<<<<< BYE < where=pre,  action=unmangle (upstream)
 * > 200 >>>>>> where=post, action=mangle (downstream)
 *
 * Summarizing:
 *
 * - In pre, we only do unmangling. We can ignore the RR headers and
 *   simply use the "magic" callid prefix to determine whether we
 *   need to do any unmangling.
 * - In post, we only do mangling. Here we use the RR ftag to check
 *   in which direction this call was started. If ftag==from-tag then
 */

static int spiral_pre_raw(str *data)
{
	struct sip_msg msg = { 0, };
	str cookie = {"..", 2};
	int in_dialog;
	int is_downstream;

	msg.buf = data->s;
	msg.len = data->len;

	if (spiral_parse_msg(&msg) != 0) {
		goto done;
	}
	if (spiral_skip_msg(&msg)) {
		goto done;
	}

#if 0
	if (msg.first_line.type == SIP_REQUEST) {
		LM_DBG("%.*s %.*s %.*s: R", msg.callid->body.len, msg.callid->body.s,
				get_cseq(&msg)->number.len, get_cseq(&msg)->number.s,
				get_cseq(&msg)->method.len, get_cseq(&msg)->method.s);
	} else {
		LM_DBG("%.*s %.*s %.*s: %.*s", msg.callid->body.len, msg.callid->body.s,
				get_cseq(&msg)->number.len, get_cseq(&msg)->number.s,
				get_cseq(&msg)->method.len, get_cseq(&msg)->method.s,
				msg.first_line.u.reply.status.len, msg.first_line.u.reply.status.s);
	}
#endif

	/* ... */
	if (msg.first_line.type == SIP_REQUEST) {
		in_dialog = spiral_has_totag(&msg);
		if (in_dialog) {
			is_downstream = spiral_direction_downstream(&msg);
			if (is_downstream < 0) {
				LM_ERR("unable to detect direction\n");
				goto error;
			}
			cookie.s = is_downstream ? "dc" : "uc"; /* downstream, continue */
		} else {
			/* For in-dialog requests we don't need to touch RR. */
			cookie.s = "di"; /* downstream, initial */
		}

		/* Do any unmangling, if needed. If not, we do mangling
		 * on the output side. */
		if (in_dialog && !is_downstream) {
			if (!spiral_needs_unmangling(&msg)) {
				LM_ERR("expected the need for %.*s request callid %.*s "
					"unmangling!\n", 
					msg.first_line.u.request.method.len,
					msg.first_line.u.request.method.s,
					msg.callid->body.len, msg.callid->body.s);
				goto error;
			}
			if (spiral_unmangle_callid(&msg) != 0)
				goto error;
		}

	} else /*if (msg.first_line.type == SIP_REPLY)*/ {
#if 0
		/* We could check msg.via2 == 0 here to skip handling
		 * replies to locally generated requests. But that
		 * does not seem to have any added value. */
		if (msg.via2 == 0 && (get_cseq(&msg)->method_id) & (METHOD_CANCEL)) {
			goto done;
		}
#endif

		if (spiral_needs_unmangling(&msg)) {
			cookie.s = "uc"; /* upstream, continue */
			if (spiral_unmangle_callid(&msg) != 0)
				goto error;
		} else {
			cookie.s = "dc"; /* downstream, continue */
			/* Do mangling on the output side. */
		}
	}

	spiral_add_cookie(&msg, &cookie);
	if (msg.first_line.type == SIP_REQUEST) {
		data->s = spiral_rebuild_req(&msg, &data->len);
	} else /*if (msg.first_line.type == SIP_REPLY)*/ {
		data->s = spiral_rebuild_rpl(&msg, &data->len);
	}

done:
	free_sip_msg(&msg);
	return 0;

error:
	free_sip_msg(&msg);
	return -1;
}

static int spiral_post_raw(str *data)
{
	struct sip_msg msg = { 0, };
	/* The cookiebuf will hold three characters:
	 * [.hv] unset, Header, Via
	 * [.du] unset, Downstream, Upstream
	 * [.ic] unset, Initial, Continue */
	char cookiebuf[3] = "...";
	str cookie = {cookiebuf, 3};

	msg.buf = data->s;
	msg.len = data->len;

	if (spiral_parse_msg(&msg) != 0) {
		goto done;
	}
	if (spiral_skip_msg(&msg)) {
		goto done;
	}

	if (spiral_get_cookie(&msg, &cookie)) {
		spiral_del_cookie(&msg);
	}

	if (msg.first_line.type == SIP_REQUEST) {
		int in_dialog;
		int is_downstream;
		int is_local = (cookie.s[1] == '.'); /* upstream nor downstream */

		/* Locally generated requests */
		if (is_local) {
			/* ACK and CANCEL go downstream
			 * (only followups to initial requests, e2e ack is not is_local) */
			if (get_cseq(&msg)->method_id & (METHOD_ACK|METHOD_CANCEL)) {
				if (spiral_mangle_callid(&msg) != 0)
					goto error;
			} else {
				/* All other local stuff goes upstream
				 * (no cookies were set/removed, nothing to do) */
				goto done;
			}

		/* Non-local requests */
		} else {
			in_dialog = spiral_has_totag(&msg);
			if (in_dialog) {
				is_downstream = (cookie.s[1] == 'd'); /* upstream/downstream */
				if (is_downstream) {
					if (spiral_mangle_callid(&msg) != 0)
						goto error;
				}
			} else {
				/* Initial request is downstream */
				if (spiral_mangle_callid(&msg) != 0)
					goto error;
			}
		}

	} else /*if (msg.first_line.type == SIP_REPLY)*/ {
		int is_downstream;
		int is_local = (cookie.s[0] == '.' || cookie.s[0] == 'v');

		/* Locally generated response */
		if (is_local) {
			if (cookie.s[1] == '.') {
				/* No cookies at all? This is something
				 * unrelated to us. Don't touch. */
				goto done;
			}
			if (cookie.s[1] == 'u') {
				/* The transaction was upstream, this is e.g. a
				 * provisional reply back down. */
				if (spiral_mangle_callid(&msg) != 0)
					goto error;
			} else {
				/* The transaction was downstream and this is
				 * e.g. a generated 100/401/407 that we reply. */
			}
		/* Non-local responses */
		} else {
			is_downstream = (cookie.s[1] == 'd'); /* upstream/downstream */
			if (is_downstream) {
				if (spiral_mangle_callid(&msg) != 0)
					goto error;
			}
		}
	}

	if (msg.first_line.type == SIP_REQUEST) {
		data->s = spiral_rebuild_req(&msg, &data->len);
	} else /*if (msg.first_line.type == SIP_REPLY)*/ {
		data->s = spiral_rebuild_rpl(&msg, &data->len);
	}

done:
	free_sip_msg(&msg);
	return 0;

error:
	free_sip_msg(&msg);
	return -1;
}
