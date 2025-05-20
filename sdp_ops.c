/*
 * Copyright (C) 2024-2025 OpenSIPS Solutions
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

#include "pvar.h"
#include "sdp_ops.h"
#include "ut.h"
#include "parser/sdp/sdp.h"

enum sdp_pv_name {
	SDP_PV_NAME_P1_NAME,
	SDP_PV_NAME_P2_STREAM,
	SDP_PV_NAME_P3_LINE,
	SDP_PV_NAME_P4_TOKEN,
};


int pv_set_sdp(struct sip_msg *msg, pv_param_t *param,
			int op, pv_value_t *val)
{
	struct sdp_body_part_ops *ops;
	int null_before = 0;

	if (!msg || !param) {
		LM_ERR("bad parameters\n");
		return -1;
	}

	if (!msg->sdp_ops) {
		ops = pkg_malloc(sizeof *ops);
		if (!ops) {
			LM_ERR("oom\n");
			return -1;
		}
		memset(ops, 0, sizeof *ops);
		msg->sdp_ops = ops;
	} else {
		ops = msg->sdp_ops;
	}

	if (!val) {
		LM_ERR("sdp-set: NULL\n");
		ops->flags |= SDP_OPS_FL_NULL;
		if (msg->body) {
			free_sip_body(msg->body);
			msg->body = NULL;
		}

	} else {
		LM_ERR("sdp-set: non-NULL!\n");

		if (!(val->flags & PV_VAL_STR) || val->rs.len <= 0) {
			LM_ERR("non-empty str value required to set SDP body\n");
			goto error;
		}

		if (pkg_str_sync(&ops->sdp, &val->rs) != 0) {
			LM_ERR("oom\n");
			return -1;
		}

		if (ops->flags & SDP_OPS_FL_NULL) {
			null_before = 1;
			ops->flags &= ~SDP_OPS_FL_NULL;
		}

		if (msg->body) {
			free_sip_body(msg->body);
			msg->body = NULL;
		}

		if (parse_sip_body(msg) != 0) {
			LM_ERR("bad body provided (%.*s ...), refusing to set in SIP msg\n",
			        val->rs.len>=40 ? 40:val->rs.len, val->rs.s);
			pkg_free(ops->sdp.s);
			ops->sdp = STR_NULL;
			if (null_before)
				ops->flags |= SDP_OPS_FL_NULL;
			return -1;
		}

		if (!parse_sdp(msg)) {
			LM_ERR("bad SDP provided (%.*s ...), refusing to set in SIP msg\n",
			        val->rs.len>=40 ? 40:val->rs.len, val->rs.s);
			free_sip_body(msg->body);
			msg->body = NULL;
			pkg_free(ops->sdp.s);
			ops->sdp = STR_NULL;
			if (null_before)
				ops->flags |= SDP_OPS_FL_NULL;
			return -1;
		}

		ops->flags &= ~SDP_OPS_FL_NULL;

		/* detect separator */
		ops->sep.s = ops->sdp.s + ops->sdp.len - 1;
		if (*ops->sep.s != '\n' && *ops->sep.s != '\r') {
			LM_ERR("unrecognized SDP separator (ending): '%c' (%d)\n",
			        *ops->sep.s, *ops->sep.s);
			free_sip_body(msg->body);
			msg->body = NULL;
			pkg_free(ops->sdp.s);
			ops->sdp = ops->sep = STR_NULL;
			if (null_before)
				ops->flags |= SDP_OPS_FL_NULL;
			return -1;
		}

		if (*ops->sep.s == '\n' && *(ops->sep.s-1) == '\r') {
			ops->sep.s--;
			ops->sep.len = 2;
		} else {
			ops->sep.len = 1;
		}

		LM_DBG("separator: %d %d (%d)\n", ops->sep.s[ops->sep.len-2],
		        ops->sep.s[ops->sep.len-1], ops->sep.len);
	}

	return 0;
error:
	return -1;
}


static char *parse_sdp_pv_index(char *in, int len, int *idx)
{
	char *lim = in + len, *end;
	long val = -1;

	val = strtol(in, &end, 10);
	if (errno == ERANGE) {
		LM_ERR("failed to parse index: value too big\n");
		return NULL;
	}

	if (val == -1) {
		LM_ERR("failed to parse index, given input: ...[%.*s\n", len, in);
		return NULL;
	}

	while (end < lim && is_ws(*end))
		end++;

	if (end == lim || *end != ']') {
		LM_ERR("failed to parse index, given input: ...[%.*s\n", len, in);
		return NULL;
	}

	while (end+1 < lim && is_ws(*(end+1)))
		end++;

	*idx = val;
	return end;
}


int pv_parse_sdp_name(pv_spec_p sp, const str *_in)
{
	// TODO -- add support for custom SDP holders
	str in = *_in, tok;
	int escape = 0, i;
	enum sdp_pv_name nm = SDP_PV_NAME_P3_LINE;
	struct sdp_pv_param *param;
	char *p, *lim = in.s + in.len;

	if (!sp)
		return -1;

	LM_DBG("parse sdp name: '%.*s'\n", in.len, in.s);
	trim(&in);
	if (!in.s || in.len == 0)
		goto done;

	if (in.s[0] == PV_MARKER) {
		LM_ERR("no support for dynamic names in $sdp.line\n");
		return -1;
	} else if (in.s[0] == '@') {
		// TODO: impl custom SDP holders (perhaps using a map)
		return -1;
	}

	param = pkg_malloc(sizeof *param);
	if (!param) {
		LM_ERR("oom\n");
		return -1;
	}
	memset(param, 0, sizeof *param);

	tok.s = in.s;
	for (i = 0; i < in.len; i++) {
		int idx = 0;

		if (escape && (in.s[i] == '\\' || in.s[i] == '/')) {
			memmove(&in.s[i-1], &in.s[i], in.len - i);
			in.len--;
			i--;
			escape = 0;
			continue;
		}

		if (in.s[i] == '\\') {
			escape = 1;
			continue;
		}
		escape = 0;

		if (in.s[i] == '[') {
			p = parse_sdp_pv_index(in.s + i + 1, in.len - i - 1, &idx);
			if (!p) {
				LM_ERR("error while parsing index in $sdp name: '%.*s'\n", in.len, in.s);
				return -1;
			}

			if (p < lim && *p != '/') {
				LM_ERR("error after index part in $sdp name: '%.*s'\n", in.len, in.s);
				return -1;
			}

			i += p - (in.s + i);
			continue;
		}

		if (in.s[i] == '/' && nm <= SDP_PV_NAME_P4_TOKEN) {
			tok.len = i - (tok.s - in.s);
			// save tok
			switch (nm) {
			case SDP_PV_NAME_P1_NAME:
			case SDP_PV_NAME_P2_STREAM:
			case SDP_PV_NAME_P3_LINE:
				param->match_line.prefix = tok;
				tok.s = in.s + i + 1;
				break;
			case SDP_PV_NAME_P4_TOKEN:
				param->match_token.prefix = tok;
				break;
			}

			nm++;
			continue;
		}
	}

	LM_DBG("parse sdp name: '%.*s'\n", in.len, in.s);

	sp->pvp.pvn.type = PV_NAME_PVAR;
	sp->pvp.pvn.u.dname = param;

done:
	return 0;
}

#define first_part_by_mime( _part_start, _part_end, _mime) \
	do {\
		_part_end = _part_start;\
		while( (_part_end) && \
		!(is_body_part_received(_part_end) && ((_mime)==0 || \
		(_mime)==(_part_end)->mime )) ) { \
			_part_end = (_part_end)->next; \
		} \
	}while(0)

int pv_get_sdp_line(struct sip_msg *msg, pv_param_t *param, pv_value_t *res)
{
	struct sdp_pv_param *pvp = (struct sdp_pv_param *)param->pvn.u.dname;
	struct sip_msg_body *sbody;
	struct body_part *body_part;
	str body, line = STR_NULL, pfx, token = STR_NULL;
	char *p, *lim, sep, *start;
	int idx, sep_len = 1;

	if (!msg || !res)
		return -1;

	if (msg->body_lumps) {
		/* TODO: rebuild SDP body, clear the body lumps */
	}

	if (parse_sip_body(msg)<0 || !(sbody=msg->body)) {
		LM_DBG("no body found\n");
		return pv_get_null(msg, param, res);
	}

	first_part_by_mime( &sbody->first, body_part, (TYPE_APPLICATION<<16)+SUBTYPE_SDP );
	body = body_part->body;

	idx = pvp->match_line.idx;
	pfx = pvp->match_line.prefix;
	lim = body.s + body.len;

	sep = *(lim-1);
	if (sep != '\n' && sep != '\r') {
		LM_ERR("unrecognized SDP separator (ending): '%c' (%d)\n", sep, sep);
		return pv_get_null(msg, param, res);
	}

	if (sep == '\n' && *(lim-2) == '\r') {
		sep = '\r';
		sep_len = 2;
	}

	start = body.s;
	for (p = body.s; p < lim; p++) {
		if (*p != sep || (sep_len == 2 && p < (lim-1) && *(p+1) != '\n'))
			continue;

		/* have prefix and doesn't match current line => skip line */
		if (pfx.len && (pfx.len > (p-start) || strncasecmp(pfx.s, start, pfx.len))) {
			start = p + sep_len;
			continue;
		}

		/* have index, but still too high => skip line */
		if (idx > 0) {
			idx--;
			start = p + sep_len;
			continue;
		}

		/* line found */
		line.s = start;
		line.len = p - start;
		break;
	}

	if (!line.s)
		return pv_get_null(msg, param, res);

	if (!pvp->match_token.prefix.s)
		return pv_get_strval(msg, param, res, &line);

	idx = pvp->match_token.idx;
	pfx = pvp->match_token.prefix;
	start = line.s;
	lim = line.s + line.len;
	while (start < lim && is_ws(*start))
		start++;

	for (p = start; p <= lim; p++) {
		if (p < lim && !is_ws(*p))
			continue;

		/* have prefix and doesn't match current token => skip token */
		if (pfx.len && (pfx.len > (p-start) || strncasecmp(pfx.s, start, pfx.len))) {
			while (p < lim && is_ws(*p))
				p++;
			start = p;
			continue;
		}

		if (idx > 0) {
			idx--;
			start = p;
			while (start < lim && is_ws(*start))
				start++;
			continue;
		}

		token.s = start;
		token.len = p - start;
		break;
	}

	if (!token.s)
		return pv_get_null(msg, param, res);

	return pv_get_strval(msg, param, res, &token);
}


int pv_set_sdp_line(struct sip_msg *msg, pv_param_t *param,
			int op, pv_value_t *val)
{
	return 0;
}

int pv_parse_sdp_line_name(pv_spec_p sp, const str *_in)
{
	str in = *_in, tok;
	int escape = 0, i, midx = 0;
	struct sdp_pv_param *param;
	struct sdp_chunk_match *matches[3];
	char *p;

	if (!sp)
		return -1;

	if (!in.s || in.len == 0)
		goto done;

	if (in.s[0] == PV_MARKER) {
		LM_ERR("no support for dynamic names in $sdp.line\n");
		return -1;
	} else if (in.s[0] == '@') {
		// TODO: impl custom SDP holders (perhaps using a map)
		return -1;
	}

	param = pkg_malloc(sizeof *param);
	if (!param) {
		LM_ERR("oom\n");
		return -1;
	}
	memset(param, 0, sizeof *param);

	matches[0] = &param->match_line;
	matches[1] = &param->match_token;
	matches[2] = NULL;

	tok.s = in.s;
	for (i = 0; i < in.len; i++) {
		if (!matches[midx])
			break;

		if (escape && (in.s[i] == '\\' || in.s[i] == '/')) {
			memmove(&in.s[i-1], &in.s[i], in.len - i);
			in.len--;
			i--;
			escape = 0;
			continue;
		}

		if (in.s[i] == '\\') {
			escape = 1;
			continue;
		}
		escape = 0;

		if (in.s[i] == '[' || in.s[i] == '/') {
			tok.len = i - (tok.s - in.s);
			trim_leading(&tok);

			if (in.s[i] == '[') {
				p = parse_sdp_pv_index(in.s + i + 1, in.len - i - 1, &matches[midx]->idx);
				if (!p) {
					LM_ERR("error while parsing index in $sdp name: '%.*s'\n", in.len, in.s);
					return -1;
				}

				p = q_memchr(p, '/', in.s + in.len - p);
				if (!p) {
					matches[midx++]->prefix = tok;
					break;
				}
			} else {
				p = in.s + i;
			}

			// slash here
			i = p - in.s;
			matches[midx++]->prefix = tok;
			tok.s = in.s + i+1;
		}

		if ((i+1) == in.len) {
			tok.len = i+1 - (tok.s - in.s);
			trim_leading(&tok);
			matches[midx++]->prefix = tok;
		}
	}

	LM_DBG("parse sdp.line name: '%.*s', c1: '%.*s/%p'[%d], c2: '%.*s/%p'[%d], c3: '%.*s/%p'[%d]\n",
	        in.len, in.s,
			param->match_stream.prefix.len, param->match_stream.prefix.s, param->match_stream.prefix.s, param->match_stream.idx,
			param->match_line.prefix.len, param->match_line.prefix.s, param->match_line.prefix.s, param->match_line.idx,
			param->match_token.prefix.len, param->match_token.prefix.s, param->match_token.prefix.s, param->match_token.idx);

	sp->pvp.pvn.type = PV_NAME_PVAR;
	sp->pvp.pvn.u.dname = param;

done:
	return 0;
}


int pv_get_sdp_stream(struct sip_msg *msg, pv_param_t *param, pv_value_t *res)
{
	if (!msg || !res)
		return -1;

	return pv_get_strval(msg, param, res, &msg->first_line.u.request.uri);
}


int pv_set_sdp_stream(struct sip_msg *msg, pv_param_t *param,
			int op, pv_value_t *val)
{
	return 0;
}


int pv_parse_sdp_stream_name(pv_spec_p sp, const str *_in)
{
	str in = *_in, tok;
	int escape = 0, i;
	enum sdp_pv_name nm = SDP_PV_NAME_P3_LINE;
	struct sdp_pv_param *param;

	if (!sp)
		return -1;

	LM_DBG("parse sdp name: '%.*s'\n", in.len, in.s);
	trim(&in);
	if (!in.s || in.len == 0)
		goto done;

	if (in.s[0] == PV_MARKER) {
		LM_ERR("no support for dynamic names in $sdp.line\n");
		return -1;
	} else if (in.s[0] == '@') {
		// TODO: impl custom SDP holders (perhaps using a map)
		return -1;
	}

	param = pkg_malloc(sizeof *param);
	if (!param) {
		LM_ERR("oom\n");
		return -1;
	}
	memset(param, 0, sizeof *param);

	tok.s = in.s;
	for (i = 0; i < in.len; i++) {
		if (escape && (in.s[i] == '\\' || in.s[i] == '/')) {
			memmove(&in.s[i-1], &in.s[i], in.len - i);
			in.len--;
			i--;
			escape = 0;
			continue;
		}

		if (in.s[i] == '\\') {
			escape = 1;
			continue;
		}
		escape = 0;

		if (in.s[i] == '/' && nm <= SDP_PV_NAME_P4_TOKEN) {
			tok.len = i - (tok.s - in.s);
			// save tok
			switch (nm) {
			case SDP_PV_NAME_P1_NAME:
			case SDP_PV_NAME_P2_STREAM:
			case SDP_PV_NAME_P3_LINE:
				param->match_line.prefix = tok;
				tok.s = in.s + i + 1;
				nm++;
				break;
			case SDP_PV_NAME_P4_TOKEN:
				param->match_token.prefix = tok;
				break;
			}

			continue;
		}
	}

	LM_DBG("parse sdp name: '%.*s'\n", in.len, in.s);

	sp->pvp.pvn.type = PV_NAME_PVAR;
	sp->pvp.pvn.u.dname = param;

done:
	return 0;
}


int pv_get_sdp_session(struct sip_msg *msg, pv_param_t *param, pv_value_t *res)
{
	if (!msg || !res)
		return -1;

	return pv_get_strval(msg, param, res, &msg->first_line.u.request.uri);
}


int pv_set_sdp_session(struct sip_msg *msg, pv_param_t *param,
			int op, pv_value_t *val)
{
	return 0;
}


int pv_parse_sdp_session_name(pv_spec_p sp, const str *_in)
{
	str in = *_in, tok;
	int escape = 0, i;
	enum sdp_pv_name nm = SDP_PV_NAME_P3_LINE;
	struct sdp_pv_param *param;

	if (!sp)
		return -1;

	LM_DBG("parse sdp name: '%.*s'\n", in.len, in.s);
	trim(&in);
	if (!in.s || in.len == 0)
		goto done;

	if (in.s[0] == PV_MARKER) {
		LM_ERR("no support for dynamic names in $sdp.line\n");
		return -1;
	} else if (in.s[0] == '@') {
		// TODO: impl custom SDP holders (perhaps using a map)
		return -1;
	}

	param = pkg_malloc(sizeof *param);
	if (!param) {
		LM_ERR("oom\n");
		return -1;
	}
	memset(param, 0, sizeof *param);

	tok.s = in.s;
	for (i = 0; i < in.len; i++) {
		if (escape && (in.s[i] == '\\' || in.s[i] == '/')) {
			memmove(&in.s[i-1], &in.s[i], in.len - i);
			in.len--;
			i--;
			escape = 0;
			continue;
		}

		if (in.s[i] == '\\') {
			escape = 1;
			continue;
		}
		escape = 0;

		if (in.s[i] == '/' && nm <= SDP_PV_NAME_P4_TOKEN) {
			tok.len = i - (tok.s - in.s);
			// save tok
			switch (nm) {
			case SDP_PV_NAME_P1_NAME:
			case SDP_PV_NAME_P2_STREAM:
			case SDP_PV_NAME_P3_LINE:
				param->match_line.prefix = tok;
				tok.s = in.s + i + 1;
				nm++;
				break;
			case SDP_PV_NAME_P4_TOKEN:
				param->match_token.prefix = tok;
				break;
			}

			continue;
		}
	}

	LM_DBG("parse sdp name: '%.*s'\n", in.len, in.s);

	sp->pvp.pvn.type = PV_NAME_PVAR;
	sp->pvp.pvn.u.dname = param;

done:
	return 0;
}


int sdp_get_custom_body(struct sip_msg *msg, str *body)
{
	struct sdp_body_part_ops *ops = msg->sdp_ops;

	if (!ops || !ops->sdp.s)
		return -1;

	if (ops->flags & SDP_OPS_FL_NULL) {
		*body = STR_NULL;
		return 0;
	}

	if (!(ops->flags & SDP_OPS_FL_DIRTY))
		goto out;

	/* TODO: actually rebuild .sdp */

	ops->flags &= ~SDP_OPS_FL_DIRTY;

out:
	*body = ops->sdp;
	return 0;
}


void free_sdp_ops(struct sdp_body_part_ops *ops)
{
	if (!ops)
		return;

	pkg_free(ops->sdp.s);
	pkg_free(ops);
}
