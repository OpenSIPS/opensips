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

#define SDP_PV_IDX_INSERT  1
#define SDP_PV_IDX_AINSERT 2

void free_sdp_ops_lines(struct sdp_body_part_ops *ops);

struct sdp_body_part_ops *mk_sdp_ops(void)
{
	struct sdp_body_part_ops *ops;

	ops = pkg_malloc(sizeof *ops);
	if (!ops) {
		LM_ERR("oom\n");
		return NULL;
	}
	memset(ops, 0, sizeof *ops);

	return ops;
}


/* fetch the value of a static/dynamic index */
static inline int IDX(struct sip_msg *msg, struct sdp_pv_idx *idx)
{
	pv_value_t val;

	if (!idx->is_pv_idx)
		return idx->idx;

	if (pv_get_spec_value(msg, &idx->idx_pv, &val) != 0) {
		LM_ERR("failed to get idx spec value\n");
		return -1;
	}

	if (!(val.flags & PV_VAL_INT)) {
		LM_ERR("SDP idx spec contains non-INT value ('%.*s')\n",
		        val.rs.len, val.rs.s);
		return -1;
	}

	return val.ri;
}


/* returns a string representation of the index (useful for debugging) */
static inline char *IDX_STR(struct sdp_pv_idx *idx)
{
#define idx_buf_cnt 4
	static char buf[idx_buf_cnt][20];
	static int buf_idx;
	char *p;

	p = buf[buf_idx];
	buf_idx = (buf_idx+1) % idx_buf_cnt;

	if (!idx->is_pv_idx)
		sprintf(p, "%d", idx->idx);
	else
		sprintf(p, "pv type %d", idx->idx_pv.type);

	return p;
}


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
		ops = msg->sdp_ops = mk_sdp_ops();
		if (!ops) {
			LM_ERR("oom\n");
			return -1;
		}
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

		/* detect separator */
		ops->sep[0] = ops->sdp.s[ops->sdp.len-1];
		if (ops->sep[0] != '\n' && ops->sep[0] != '\r') {
			LM_ERR("unrecognized SDP separator (ending): '%c' (%d)\n",
			        ops->sep[0], ops->sep[0]);
			free_sip_body(msg->body);
			msg->body = NULL;
			pkg_free(ops->sdp.s);
			ops->sdp = STR_NULL;
			memset(ops->sep, 0, 2);
			if (null_before)
				ops->flags |= SDP_OPS_FL_NULL;
			return -1;
		}

		if (ops->sep[0] == '\n' && ops->sdp.s[ops->sdp.len-2] == '\r') {
			ops->sep[0] = '\r';
			ops->sep[1] = '\n';
			ops->sep_len = 2;
		} else {
			ops->sep_len = 1;
		}

		free_sdp_ops_lines(ops);
		if (ops->rebuilt_sdp.s) {
			pkg_free(ops->rebuilt_sdp.s);
			ops->rebuilt_sdp = STR_NULL;
		}

		LM_DBG("separator: %d %d (%d)\n", ops->sdp.s[ops->sdp.len-2],
		        ops->sdp.s[ops->sdp.len-1], ops->sep_len);
	}

	return 0;
error:
	return -1;
}


static char *parse_sdp_pv_index(char *in, int len, struct sdp_pv_idx *idx)
{
	char *lim = in + len, *end;
	long val = -1;

	if (len <= 0)
		return NULL;

	if (in[0] == PV_MARKER) {
		str input = {.s = in, .len = len};

		if (!(end = pv_parse_spec(&input, &idx->idx_pv))) {
			LM_ERR("failed to parse spec idx!  input: '%.*s'\n", len, in);
			return NULL;
		}

		idx->is_pv_idx = 1;
		goto parse_bracket;
	}

	val = strtol(in, &end, 10);
	if (errno == ERANGE) {
		LM_ERR("failed to parse index: value too big\n");
		return NULL;
	}

	if (val == -1) {
		LM_ERR("failed to parse index, given input: ...[%.*s\n", len, in);
		return NULL;
	}

parse_bracket:
	while (end < lim && is_ws(*end))
		end++;

	if (end == lim || *end != ']') {
		LM_ERR("failed to parse index, given input: ...[%.*s\n", len, in);
		return NULL;
	}

	while (end+1 < lim && is_ws(*(end+1)))
		end++;

	idx->idx = val;
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
		struct sdp_pv_idx idx = {0};

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


int pv_parse_sdp_line_index(pv_spec_p sp, const str *in)
{
	#define SDP_INSERT_IDX  "insert"
	#define SDP_AINSERT_IDX "insertAfter"

	if (!in || !in->s || !sp)
		return -1;

	if (str_casematch(in, &str_init(SDP_INSERT_IDX))) {
		sp->pvp.pvi.type = SDP_PV_IDX_INSERT;
		return 0;
	}

	if (str_casematch(in, &str_init(SDP_AINSERT_IDX))) {
		sp->pvp.pvi.type = SDP_PV_IDX_AINSERT;
		return 0;
	}

	LM_ERR("unsupported SDP variable index: '%.*s'\n", in->len, in->s);
	return -1;
}


int sdp_ops_parse_lines(struct sdp_body_part_ops *ops, str *body)
{
	char *p, *lim = body->s + body->len, sep, *start;
	int sep_len = 1, i = 0;

	if (!ops->sep_len) {
		sep = *(lim-1);
		if (sep != '\n' && sep != '\r') {
			LM_ERR("unrecognized SDP separator (ending): '%c' (%d)\n", sep, sep);
			return -1;
		}

		if (sep == '\n' && *(lim-2) == '\r') {
			sep = '\r';
			sep_len = 2;
		}
	} else {
		sep = ops->sep[0];
		sep_len = ops->sep_len;
	}

	start = body->s;
	for (p = start; p < lim; p++) {
		if (*p != sep || (sep_len == 2 && p < (lim-1) && *(p+1) != '\n'))
			continue;

		/* lines are stored *without* the ending separator */
		ops->lines[i].line.s = start;
		ops->lines[i].line.len = p - start;
		ops->lines[i++].newbuf = 0;

		start = p + sep_len;
	}

	LM_DBG("parsed %d SDP lines in total\n", i);
	ops->lines_sz = i;

	memcpy(ops->sep, lim-sep_len, sep_len);
	ops->sep_len = sep_len;

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

/* @until_line: non-inclusive (i.e. must be next-after last valid line) */
int _sdp_ops_find_line(struct sdp_body_part_ops *ops, int idx,
            str *prefix, str *token, int from_line, int until_line)
{
	int i;

	if ((from_line+idx) > until_line || (from_line+idx) >= SDP_MAX_LINES ||
	        (token->s && (from_line+idx) == until_line)) {
		LM_DBG("index out of bounds (trying to fetch line %d, prefix: %.*s/%d"
		            ", have %d lines)\n",
		        idx, prefix->len, prefix->s, prefix->len, until_line);
		return -1;
	}

	if (prefix->len == 0)
		return from_line + idx;

	for (i = from_line; i < until_line; i++) {
		/* have prefix and doesn't match current line => skip it */
		if (prefix->len > ops->lines[i].line.len
		        || strncasecmp(prefix->s, ops->lines[i].line.s, prefix->len))
			continue;

		/* have index, but still too high => skip line */
		if (idx > 0) {
			idx--;
			continue;
		}

		/* line found */
		return i;
	}

	return -1;
}

/* Note: MAY return the very "next last" line idx, to enable INSERT ops */
static inline int sdp_ops_find_line(struct sip_msg *msg, struct sdp_body_part_ops *ops, int idx,
        int by_session, struct sdp_chunk_match *by_stream, str *prefix, str *token)
{
	int i, j, have_stream = 0, stream_idx;
	struct sdp_ops_line *lines;

	if (!by_stream) {
		if (!by_session)
			return _sdp_ops_find_line(ops, idx, prefix, token, 0, ops->lines_sz);

		/* the SDP session ends at the first m= line */
		lines = ops->lines;
		for (i = 0; i < ops->lines_sz; i++) {
			if (lines[i].line.len < 2 || strncasecmp("m=", lines[i].line.s, 2))
				continue;
			break;
		}

		idx = _sdp_ops_find_line(ops, idx, prefix, token, 0, i);
		return (idx > i || (idx == i && by_session == 1)) ? -1 : idx;
	}

	lines = ops->lines;
	stream_idx = IDX(msg, &by_stream->idx);
	for (i = 0; i < ops->lines_sz; i++) {
		if (lines[i].line.len < 2 || strncasecmp("m=", lines[i].line.s, 2))
			continue;

		if (by_stream->prefix.len > (lines[i].line.len-2)
		        || strncasecmp(by_stream->prefix.s, lines[i].line.s+2, by_stream->prefix.len))
			continue;

		if (stream_idx-- > 0)
			continue;

		have_stream = 1;
		break;
	}

	if (!have_stream) {
		LM_DBG("failed to locate a stream by prefix: '%.*s', index: %d\n",
		        by_stream->prefix.len, by_stream->prefix.s, IDX(msg, &by_stream->idx));
		return -1;
	}

	for (j = i+1; j < ops->lines_sz; j++) {
		if (lines[j].line.len < 2 || strncasecmp("m=", lines[j].line.s, 2))
			continue;
		break;
	}

	LM_DBG("located stream by prefix: '%.*s', idx: %d; interval: [%d, %d)\n",
		        by_stream->prefix.len, by_stream->prefix.s, IDX(msg, &by_stream->idx), i, j);

	return _sdp_ops_find_line(ops, idx, prefix, token, i, j);
}


int pv_get_sdp_line(struct sip_msg *msg, pv_param_t *param, pv_value_t *res)
{
	struct sdp_pv_param *pvp = (struct sdp_pv_param *)param->pvn.u.dname;
	struct sdp_body_part_ops *ops;
	struct sip_msg_body *sbody;
	struct body_part *body_part;
	str body, line = STR_NULL, pfx, token = STR_NULL;
	char *p, *lim, *start;
	int idx;

	if (!msg || !res)
		return pv_get_null(msg, param, res);

	if (msg->body_lumps) {
		/* TODO: rebuild SDP body, clear the body lumps; assert lines_sz == 0 */
	}

	if (!have_sdp_ops(msg) || msg->sdp_ops->lines_sz == 0) {
		if (parse_sip_body(msg)<0 || !(sbody=msg->body)) {
			LM_ERR("current SIP message has no SDP body!\n");
			return pv_get_null(msg, param, res);
		}

		first_part_by_mime( &sbody->first, body_part, (TYPE_APPLICATION<<16)+SUBTYPE_SDP );
		if (!body_part) {
			LM_ERR("current SIP message has a body, but no SDP part!\n");
			return pv_get_null(msg, param, res);
		}

		ops = msg->sdp_ops;
		/* first time working with SDP ops => allocate DS */
		if (!ops && !(ops = msg->sdp_ops = mk_sdp_ops())) {
			LM_ERR("oom\n");
			return pv_get_null(msg, param, res);
		}

		body = body_part->body;
		if (ops->lines_sz == 0 && sdp_ops_parse_lines(ops, &body) != 0) {
			LM_ERR("oom\n");
			return pv_get_null(msg, param, res);
		}
	} else {
		ops = msg->sdp_ops;
	}

	idx = sdp_ops_find_line(msg, ops, IDX(msg, &pvp->match_line.idx), 0, NULL,
					&pvp->match_line.prefix, &pvp->match_token.prefix);
	if (idx < 0 || idx >= ops->lines_sz)    // out of bounds
		return pv_get_null(msg, param, res);

	line = ops->lines[idx].line;

	if (!pvp->match_token.prefix.s)
		return pv_get_strval(msg, param, res, &line);

	idx = IDX(msg, &pvp->match_token.idx);
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
	struct sdp_pv_param *pvp = (struct sdp_pv_param *)param->pvn.u.dname;
	struct sip_msg_body *sbody;
	struct sdp_body_part_ops *ops;
	struct body_part *body_part;
	str body, dup_line, src_line;
	int idx, insert = 0;

	if (!msg)
		return -1;

	if (val && !(val->flags & PV_VAL_STR)) {
		LM_ERR("refusing to set SDP line to non-string value (val flags: %d)\n",
		            val->flags);
		return -1;
	}

	if (msg->body_lumps) {
		/* TODO: rebuild SDP body, clear the body lumps; assert lines_sz == 0 */
	}

	if (!have_sdp_ops(msg) || msg->sdp_ops->lines_sz == 0) {
		if (parse_sip_body(msg)<0 || !(sbody=msg->body)) {
			LM_ERR("current SIP message has no SDP body!\n");
			return -1;
		}

		first_part_by_mime( &sbody->first, body_part, (TYPE_APPLICATION<<16)+SUBTYPE_SDP );
		if (!body_part) {
			LM_ERR("current SIP message has a body, but no SDP part!\n");
			return -1;
		}

		ops = msg->sdp_ops;
		/* first time working with SDP ops => allocate DS */
		if (!ops && !(ops = msg->sdp_ops = mk_sdp_ops())) {
			LM_ERR("oom\n");
			return -1;
		}

		body = body_part->body;
		if (ops->lines_sz == 0 && sdp_ops_parse_lines(ops, &body) != 0) {
			LM_ERR("oom\n");
			return -1;
		}
	} else {
		ops = msg->sdp_ops;
	}

	idx = IDX(msg, &pvp->match_line.idx);
	switch (param->pvi.type) {
	case SDP_PV_IDX_INSERT:
		insert = 1;
		break;

	case SDP_PV_IDX_AINSERT:
		insert = 1;
		idx++; /* convert it to "INSERT" operation */
		break;

	default:
		break;
	}

	idx = sdp_ops_find_line(msg, ops, idx, 0, NULL, &pvp->match_line.prefix,
	                             &pvp->match_token.prefix);
	if (idx < 0) {
		LM_ERR("failed to locate SDP line for writing for line %d, match_token: "
		        "'%.*s'\n", IDX(msg, &pvp->match_line.idx),
		        pvp->match_line.prefix.len, pvp->match_line.prefix.s);
		return -1;
	}

	if (pvp->match_token.prefix.s)
		goto handle_token_edit;

	/* delete line operation -> ignore the index */
	if (!val) {
		if (idx == ops->lines_sz) {
			LM_ERR("index out of bounds (trying to delete SDP line %d, have %d lines)\n",
			        idx, ops->lines_sz);
			return -1;
		}

		if (ops->lines[idx].newbuf)
			pkg_free(ops->lines[idx].line.s);

		memmove(&ops->lines[idx], &ops->lines[idx+1], (ops->lines_sz-idx-1)*sizeof *ops->lines);
		ops->lines[idx].have_gap = 1;
		ops->lines_sz--;
		goto out_success;
	}

	/* trim any trailing \n, \r or \r\n from the input */
	src_line = val->rs;
	if (src_line.len > 0 && (src_line.s[src_line.len-1] == '\n' || src_line.s[src_line.len-1] == '\r')) {
		src_line.len--;
		if (src_line.len > 0 && src_line.s[src_line.len] == '\n' && src_line.s[src_line.len-1] == '\r')
			src_line.len--;
	}

	if (pkg_str_dup(&dup_line, &src_line) != 0) {
		LM_ERR("oom\n");
		return -1;
	}

	if (insert) {
		/* insert line operation */
		memmove(&ops->lines[idx+1], &ops->lines[idx], (ops->lines_sz-idx)*sizeof *ops->lines);
		ops->lines_sz++;
	} else {
		/* edit line operation -> ignore the PV index */
		if (ops->lines[idx].newbuf)
			pkg_free(ops->lines[idx].line.s);
	}

	ops->lines[idx].line = dup_line;
	ops->lines[idx].newbuf = 1;
	goto out_success;

handle_token_edit:
	
out_success:
	ops->flags |= SDP_OPS_FL_DIRTY;
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

	LM_DBG("parse sdp.line name: '%.*s', c1: '%.*s/%p'[%s], c2: '%.*s/%p'[%s], c3: '%.*s/%p'[%s]\n",
	        in.len, in.s,
			param->match_stream.prefix.len, param->match_stream.prefix.s, param->match_stream.prefix.s, IDX_STR(&param->match_stream.idx),
			param->match_line.prefix.len, param->match_line.prefix.s, param->match_line.prefix.s, IDX_STR(&param->match_line.idx),
			param->match_token.prefix.len, param->match_token.prefix.s, param->match_token.prefix.s, IDX_STR(&param->match_token.idx));

	sp->pvp.pvn.type = PV_NAME_PVAR;
	sp->pvp.pvn.u.dname = param;

done:
	return 0;
}


int pv_parse_sdp_stream_name(pv_spec_p sp, const str *_in)
{
	str in = *_in, tok;
	int escape = 0, i, midx = 0;
	struct sdp_pv_param *param;
	struct sdp_chunk_match *matches[4];
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

	matches[0] = &param->match_stream;
	matches[1] = &param->match_line;
	matches[2] = &param->match_token;
	matches[3] = NULL;

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

	LM_DBG("parse sdp.stream name: '%.*s',"
	            " c1: '%.*s/%p'[%s], c2: '%.*s/%p'[%s], c3: '%.*s/%p'[%s]\n",
	        in.len, in.s,
			param->match_stream.prefix.len, param->match_stream.prefix.s,
				param->match_stream.prefix.s, IDX_STR(&param->match_stream.idx),
			param->match_line.prefix.len, param->match_line.prefix.s,
				param->match_line.prefix.s, IDX_STR(&param->match_line.idx),
			param->match_token.prefix.len, param->match_token.prefix.s,
				param->match_token.prefix.s, IDX_STR(&param->match_token.idx));

	sp->pvp.pvn.type = PV_NAME_PVAR;
	sp->pvp.pvn.u.dname = param;

done:
	return 0;
}


int pv_get_sdp_stream(struct sip_msg *msg, pv_param_t *param, pv_value_t *res)
{
	struct sdp_pv_param *pvp = (struct sdp_pv_param *)param->pvn.u.dname;
	struct sdp_body_part_ops *ops;
	struct sip_msg_body *sbody;
	struct body_part *body_part;
	str body, line = STR_NULL, pfx, token = STR_NULL;
	char *p, *lim, *start;
	int idx;

	if (!msg || !res)
		return pv_get_null(msg, param, res);

	if (msg->body_lumps) {
		/* TODO: rebuild SDP body, clear the body lumps; assert lines_sz == 0 */
	}

	if (!have_sdp_ops(msg) || msg->sdp_ops->lines_sz == 0) {
		if (parse_sip_body(msg)<0 || !(sbody=msg->body)) {
			LM_ERR("current SIP message has no SDP body!\n");
			return pv_get_null(msg, param, res);
		}

		first_part_by_mime( &sbody->first, body_part, (TYPE_APPLICATION<<16)+SUBTYPE_SDP );
		if (!body_part) {
			LM_ERR("current SIP message has a body, but no SDP part!\n");
			return pv_get_null(msg, param, res);
		}

		ops = msg->sdp_ops;
		/* first time working with SDP ops => allocate DS */
		if (!ops && !(ops = msg->sdp_ops = mk_sdp_ops())) {
			LM_ERR("oom\n");
			return pv_get_null(msg, param, res);
		}

		body = body_part->body;
		if (ops->lines_sz == 0 && sdp_ops_parse_lines(ops, &body) != 0) {
			LM_ERR("oom\n");
			return pv_get_null(msg, param, res);
		}
	} else {
		ops = msg->sdp_ops;
	}

	idx = sdp_ops_find_line(msg, ops, IDX(msg, &pvp->match_line.idx), 0,
				&pvp->match_stream, &pvp->match_line.prefix,
	            &pvp->match_token.prefix);
	if (idx < 0 || idx >= ops->lines_sz)    // out of bounds
		return pv_get_null(msg, param, res);

	line = ops->lines[idx].line;

	if (!pvp->match_token.prefix.s)
		return pv_get_strval(msg, param, res, &line);

	idx = IDX(msg, &pvp->match_token.idx);
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


int pv_set_sdp_stream(struct sip_msg *msg, pv_param_t *param,
			int op, pv_value_t *val)
{
	struct sdp_pv_param *pvp = (struct sdp_pv_param *)param->pvn.u.dname;
	struct sip_msg_body *sbody;
	struct sdp_body_part_ops *ops;
	struct body_part *body_part;
	str body, dup_line, src_line;
	int idx, insert = 0;

	if (!msg)
		return -1;

	if (val && !(val->flags & PV_VAL_STR)) {
		LM_ERR("refusing to set SDP line to non-string value (val flags: %d)\n",
		            val->flags);
		return -1;
	}

	if (msg->body_lumps) {
		/* TODO: rebuild SDP body, clear the body lumps; assert lines_sz == 0 */
	}

	if (!have_sdp_ops(msg) || msg->sdp_ops->lines_sz == 0) {
		if (parse_sip_body(msg)<0 || !(sbody=msg->body)) {
			LM_ERR("current SIP message has no SDP body!\n");
			return -1;
		}

		first_part_by_mime( &sbody->first, body_part, (TYPE_APPLICATION<<16)+SUBTYPE_SDP );
		if (!body_part) {
			LM_ERR("current SIP message has a body, but no SDP part!\n");
			return -1;
		}

		ops = msg->sdp_ops;
		/* first time working with SDP ops => allocate DS */
		if (!ops && !(ops = msg->sdp_ops = mk_sdp_ops())) {
			LM_ERR("oom\n");
			return -1;
		}

		body = body_part->body;
		if (ops->lines_sz == 0 && sdp_ops_parse_lines(ops, &body) != 0) {
			LM_ERR("oom\n");
			return -1;
		}
	} else {
		ops = msg->sdp_ops;
	}

	idx = IDX(msg, &pvp->match_line.idx);
	switch (param->pvi.type) {
	case SDP_PV_IDX_INSERT:
		insert = 1;
		break;

	case SDP_PV_IDX_AINSERT:
		insert = 1;
		idx++; /* convert it to "INSERT" operation */
		break;

	default:
		break;
	}

	idx = sdp_ops_find_line(msg, ops, idx, 0, &pvp->match_stream,
				&pvp->match_line.prefix, &pvp->match_token.prefix);
	if (idx < 0) {
		LM_ERR("failed to locate SDP line for writing for line %d, match_token: "
		        "'%.*s'\n", IDX(msg, &pvp->match_line.idx), pvp->match_line.prefix.len,
		        pvp->match_line.prefix.s);
		return -1;
	}

	if (pvp->match_token.prefix.s)
		goto handle_token_edit;

	/* delete line operation -> ignore the index */
	if (!val) {
		if (idx == ops->lines_sz) {
			LM_ERR("index out of bounds (trying to delete SDP line %d, have %d lines)\n",
			        idx, ops->lines_sz);
			return -1;
		}

		if (ops->lines[idx].newbuf) {
			pkg_free(ops->lines[idx].line.s);
			memset(&ops->lines[idx], 0, sizeof ops->lines[idx]);
		}

		memmove(&ops->lines[idx], &ops->lines[idx+1], (ops->lines_sz-idx-1)*sizeof *ops->lines);
		ops->lines[idx].have_gap = 1;
		ops->lines_sz--;
		goto out_success;
	}

	/* trim any trailing \n, \r or \r\n from the input */
	src_line = val->rs;
	if (src_line.len > 0 && (src_line.s[src_line.len-1] == '\n' || src_line.s[src_line.len-1] == '\r')) {
		src_line.len--;
		if (src_line.len > 0 && src_line.s[src_line.len] == '\n' && src_line.s[src_line.len-1] == '\r')
			src_line.len--;
	}

	if (pkg_str_dup(&dup_line, &src_line) != 0) {
		LM_ERR("oom\n");
		return -1;
	}

	if (insert) {
		/* insert line operation */
		memmove(&ops->lines[idx+1], &ops->lines[idx], (ops->lines_sz-idx)*sizeof *ops->lines);
		ops->lines_sz++;
	} else {
		/* edit line operation -> ignore the PV index */
		if (ops->lines[idx].newbuf)
			pkg_free(ops->lines[idx].line.s);
	}

	ops->lines[idx].line = dup_line;
	ops->lines[idx].newbuf = 1;
	goto out_success;

handle_token_edit:
	
out_success:
	ops->flags |= SDP_OPS_FL_DIRTY;
	return 0;
}


int pv_get_sdp_stream_idx(struct sip_msg *msg, pv_param_t *param, pv_value_t *res)
{
	struct sdp_pv_param *pvp = (struct sdp_pv_param *)param->pvn.u.dname;
	struct sdp_body_part_ops *ops;
	struct sip_msg_body *sbody;
	struct body_part *body_part;
	str body;
	int idx;

	if (!msg || !res)
		return pv_get_null(msg, param, res);

	if (msg->body_lumps) {
		/* TODO: rebuild SDP body, clear the body lumps; assert lines_sz == 0 */
	}

	if (!have_sdp_ops(msg) || msg->sdp_ops->lines_sz == 0) {
		if (parse_sip_body(msg)<0 || !(sbody=msg->body)) {
			LM_ERR("current SIP message has no SDP body!\n");
			return pv_get_null(msg, param, res);
		}

		first_part_by_mime( &sbody->first, body_part, (TYPE_APPLICATION<<16)+SUBTYPE_SDP );
		if (!body_part) {
			LM_ERR("current SIP message has a body, but no SDP part!\n");
			return pv_get_null(msg, param, res);
		}

		ops = msg->sdp_ops;
		/* first time working with SDP ops => allocate DS */
		if (!ops && !(ops = msg->sdp_ops = mk_sdp_ops())) {
			LM_ERR("oom\n");
			return pv_get_null(msg, param, res);
		}

		body = body_part->body;
		if (ops->lines_sz == 0 && sdp_ops_parse_lines(ops, &body) != 0) {
			LM_ERR("oom\n");
			return pv_get_null(msg, param, res);
		}
	} else {
		ops = msg->sdp_ops;
	}

	idx = sdp_ops_find_line(msg, ops, IDX(msg, &pvp->match_line.idx), 0,
				&pvp->match_stream, &pvp->match_line.prefix,
	            &pvp->match_token.prefix);
	if (idx < 0 || idx >= ops->lines_sz)    // out of bounds
		return pv_get_null(msg, param, res);

	return pv_get_sintval(msg, param, res, idx);
}


int pv_get_sdp_session(struct sip_msg *msg, pv_param_t *param, pv_value_t *res)
{
	struct sdp_pv_param *pvp = (struct sdp_pv_param *)param->pvn.u.dname;
	struct sdp_body_part_ops *ops;
	struct sip_msg_body *sbody;
	struct body_part *body_part;
	str body, line = STR_NULL, pfx, token = STR_NULL;
	char *p, *lim, *start;
	int idx;

	if (!msg || !res)
		return pv_get_null(msg, param, res);

	if (msg->body_lumps) {
		/* TODO: rebuild SDP body, clear the body lumps; assert lines_sz == 0 */
	}

	if (!have_sdp_ops(msg) || msg->sdp_ops->lines_sz == 0) {
		if (parse_sip_body(msg)<0 || !(sbody=msg->body)) {
			LM_ERR("current SIP message has no SDP body!\n");
			return pv_get_null(msg, param, res);
		}

		first_part_by_mime( &sbody->first, body_part, (TYPE_APPLICATION<<16)+SUBTYPE_SDP );
		if (!body_part) {
			LM_ERR("current SIP message has a body, but no SDP part!\n");
			return pv_get_null(msg, param, res);
		}

		ops = msg->sdp_ops;
		/* first time working with SDP ops => allocate DS */
		if (!ops && !(ops = msg->sdp_ops = mk_sdp_ops())) {
			LM_ERR("oom\n");
			return pv_get_null(msg, param, res);
		}

		body = body_part->body;
		if (ops->lines_sz == 0 && sdp_ops_parse_lines(ops, &body) != 0) {
			LM_ERR("oom\n");
			return pv_get_null(msg, param, res);
		}
	} else {
		ops = msg->sdp_ops;
	}

	idx = sdp_ops_find_line(msg, ops, IDX(msg, &pvp->match_line.idx), 1,
				NULL, &pvp->match_line.prefix, &pvp->match_token.prefix);
	if (idx < 0 || idx >= ops->lines_sz)    // out of bounds
		return pv_get_null(msg, param, res);

	line = ops->lines[idx].line;

	if (!pvp->match_token.prefix.s)
		return pv_get_strval(msg, param, res, &line);

	idx = IDX(msg, &pvp->match_token.idx);
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


int pv_set_sdp_session(struct sip_msg *msg, pv_param_t *param,
			int op, pv_value_t *val)
{
	struct sdp_pv_param *pvp = (struct sdp_pv_param *)param->pvn.u.dname;
	struct sip_msg_body *sbody;
	struct sdp_body_part_ops *ops;
	struct body_part *body_part;
	str body, dup_line, src_line;
	int idx, insert = 0;

	if (!msg)
		return -1;

	if (val && !(val->flags & PV_VAL_STR)) {
		LM_ERR("refusing to set SDP line to non-string value (val flags: %d)\n",
		            val->flags);
		return -1;
	}

	if (msg->body_lumps) {
		/* TODO: rebuild SDP body, clear the body lumps; assert lines_sz == 0 */
	}

	if (!have_sdp_ops(msg) || msg->sdp_ops->lines_sz == 0) {
		if (parse_sip_body(msg)<0 || !(sbody=msg->body)) {
			LM_ERR("current SIP message has no SDP body!\n");
			return -1;
		}

		first_part_by_mime( &sbody->first, body_part, (TYPE_APPLICATION<<16)+SUBTYPE_SDP );
		if (!body_part) {
			LM_ERR("current SIP message has a body, but no SDP part!\n");
			return -1;
		}

		ops = msg->sdp_ops;
		/* first time working with SDP ops => allocate DS */
		if (!ops && !(ops = msg->sdp_ops = mk_sdp_ops())) {
			LM_ERR("oom\n");
			return -1;
		}

		body = body_part->body;
		if (ops->lines_sz == 0 && sdp_ops_parse_lines(ops, &body) != 0) {
			LM_ERR("oom\n");
			return -1;
		}
	} else {
		ops = msg->sdp_ops;
	}

	idx = IDX(msg, &pvp->match_line.idx);
	switch (param->pvi.type) {
	case SDP_PV_IDX_INSERT:
		insert = 1;
		break;

	case SDP_PV_IDX_AINSERT:
		insert = 1;
		idx++; /* convert it to "INSERT" operation */
		break;

	default:
		break;
	}

	idx = sdp_ops_find_line(msg, ops, idx, 2, NULL,
				&pvp->match_line.prefix, &pvp->match_token.prefix);
	if (idx < 0) {
		LM_ERR("failed to locate SDP line for writing for line %d, match_token: "
		        "'%.*s'\n", IDX(msg, &pvp->match_line.idx), pvp->match_line.prefix.len,
		        pvp->match_line.prefix.s);
		return -1;
	}

	if (pvp->match_token.prefix.s)
		goto handle_token_edit;

	/* delete line operation -> ignore the index */
	if (!val) {
		if (idx == ops->lines_sz) {
			LM_ERR("index out of bounds (trying to delete SDP line %d, have %d lines)\n",
			        idx, ops->lines_sz);
			return -1;
		}

		if (ops->lines[idx].newbuf)
			pkg_free(ops->lines[idx].line.s);

		memmove(&ops->lines[idx], &ops->lines[idx+1], (ops->lines_sz-idx-1)*sizeof *ops->lines);
		ops->lines[idx].have_gap = 1;
		ops->lines_sz--;
		goto out_success;
	}

	/* trim any trailing \n, \r or \r\n from the input */
	src_line = val->rs;
	if (src_line.len > 0 && (src_line.s[src_line.len-1] == '\n' || src_line.s[src_line.len-1] == '\r')) {
		src_line.len--;
		if (src_line.len > 0 && src_line.s[src_line.len] == '\n' && src_line.s[src_line.len-1] == '\r')
			src_line.len--;
	}

	if (pkg_str_dup(&dup_line, &src_line) != 0) {
		LM_ERR("oom\n");
		return -1;
	}

	if (insert) {
		/* insert line operation */
		memmove(&ops->lines[idx+1], &ops->lines[idx], (ops->lines_sz-idx)*sizeof *ops->lines);
		ops->lines_sz++;
	} else {
		/* edit line operation -> ignore the PV index */
		if (ops->lines[idx].newbuf)
			pkg_free(ops->lines[idx].line.s);
	}

	ops->lines[idx].line = dup_line;
	ops->lines[idx].newbuf = 1;
	goto out_success;

handle_token_edit:
	
out_success:
	ops->flags |= SDP_OPS_FL_DIRTY;
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
	struct sdp_ops_line *lines;
	int i, len = 0, sep_len, rem, cpy_len = 0;
	char *p, *start_cpy = NULL;
	char *newbuf;

	if (!ops)
		return -1;

	if (ops->flags & SDP_OPS_FL_NULL) {
		*body = STR_NULL;
		LM_DBG("SDP has been explicitly cleared, returning NULL\n");
		return 0;
	}

	if (!(ops->flags & SDP_OPS_FL_DIRTY)) {
		if (!ops->rebuilt_sdp.s && !ops->sdp.s) {
			LM_DBG("SDP has been ops-READ, with no changes => using msg SDP\n");
			return -1;
		}

		LM_DBG("found previously re-built custom SDP => quick-return\n");
		goto out;
	}

	/* DIRTY flag is on => need to do a full rebuild */
	LM_DBG("DIRTY flag detected => rebuild SDP\n");

	sep_len = ops->sep_len;
	lines = ops->lines;
	for (i = 0; i < ops->lines_sz; i++)
		len += lines[i].line.len;
	len += sep_len * ops->lines_sz;

	if (!(newbuf = pkg_malloc(len))) {
		LM_ERR("oom\n");
		return -1;
	}

	p = newbuf;
	rem = len;

	for (i = 0; i < ops->lines_sz; i++) {
		if (lines[i].newbuf || lines[i].have_gap) {
			if (start_cpy) {
				memcpy(p, start_cpy, cpy_len);
				p += cpy_len;
				rem -= cpy_len;
				start_cpy = NULL;
				cpy_len = 0;
			}

			memcpy(p, lines[i].line.s, lines[i].line.len);
			p += lines[i].line.len;
			rem -= lines[i].line.len;

			memcpy(p, ops->sep, sep_len);
			p += sep_len;
			rem -= sep_len;

		} else if (!start_cpy) {
			start_cpy = lines[i].line.s;
			cpy_len += lines[i].line.len + sep_len;
		} else {
			cpy_len += lines[i].line.len + sep_len;
		}
	}

	if (start_cpy) {
		memcpy(p, start_cpy, cpy_len);
		p += cpy_len;
		rem -= cpy_len;
	}

	if (rem != 0) {
		LM_BUG("SDP rebuild line mismatch (%d vs. %d), in buffer: '%.*s ...'\n",
		        len, rem, len > 100 ? 100 : len, ops->sdp.s);
		ops->sdp.len = len;
	}

	ops->flags &= ~SDP_OPS_FL_DIRTY;

	pkg_free(ops->rebuilt_sdp.s);
	ops->rebuilt_sdp.s = newbuf;
	ops->rebuilt_sdp.len = len;

out:
	if (ops->rebuilt_sdp.s)
		*body = ops->rebuilt_sdp;
	else
		*body = ops->sdp;
	return 0;
}


void free_sdp_ops_lines(struct sdp_body_part_ops *ops)
{
	int i;

	for (i = 0; i < ops->lines_sz; i++)
		if (ops->lines[i].newbuf) {
			pkg_free(ops->lines[i].line.s);
			ops->lines[i].newbuf = 0;
			ops->lines[i].have_gap = 0;
		}

	ops->lines_sz = 0;
	ops->flags &= ~SDP_OPS_FL_PARSED; /* TODO - optimize with lazy parsing */
}


void free_sdp_ops(struct sdp_body_part_ops *ops)
{
	if (!ops)
		return;

	free_sdp_ops_lines(ops);
	pkg_free(ops->sdp.s);
	pkg_free(ops->rebuilt_sdp.s);
	pkg_free(ops);
}
