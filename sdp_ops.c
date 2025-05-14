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
	}

	return 0;
error:
	return -1;
}


int pv_parse_sdp_name(pv_spec_p sp, const str *_in)
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


int pv_get_sdp_line(struct sip_msg *msg, pv_param_t *param, pv_value_t *res)
{
	if (!msg || !res)
		return -1;

	return pv_get_strval(msg, param, res, &msg->first_line.u.request.uri);
}


int pv_set_sdp_line(struct sip_msg *msg, pv_param_t *param,
			int op, pv_value_t *val)
{
	return 0;
}

int pv_parse_sdp_line_name(pv_spec_p sp, const str *_in)
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
