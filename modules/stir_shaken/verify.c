/* Copyright (C) 2026 OpenSIPS Project
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "verify.h"
#include "div.h"
#include <math.h>
#include <limits.h>
#include "../../context.h"
#include "../../parser/parse_uri.h"

/* The default earlier-token window is three hours, increased at startup if
 * needed to leave 60 seconds above the normal outermost window. Per-call -1
 * disables only earlier-token age checks. */
#define INNER_FRESHNESS_MARGIN 60
int verify_date_div_freshness = 10800;
static int snapshot_ctx = -1;

struct vs_snapshot {
	struct sip_msg *msg;
	char *buf;
	unsigned int id;
	int count;
	struct parsed_identity tokens[DIV_MAX_PASSPORTS];
	str raw[DIV_MAX_PASSPORTS];
	int parsed[DIV_MAX_PASSPORTS];
	int status[DIV_MAX_PASSPORTS];
	const char *chain_status;
	str attest;
	int previous_verification;
};

static void free_snapshot(void *ptr)
{
	struct vs_snapshot *s = ptr;
	int i;
	if (!s) return;
	for (i = 0; i < s->count; i++) {
		passport_identity_cleanup(&s->tokens[i]);
		pkg_free(s->raw[i].s);
	}
	pkg_free(s);
}

static int resolve_freshness(int *outer, int inner_configured, int *inner)
{
	if (*outer < 0) {
		LM_ERR("verify_date_freshness must not disable outermost freshness\n");
		return -1;
	}
	if (*outer > INT_MAX - INNER_FRESHNESS_MARGIN) {
		*outer = INT_MAX - INNER_FRESHNESS_MARGIN;
		LM_WARN("reducing verify_date_freshness to %d to leave room for verify_date_div_freshness\n",
			*outer);
	}
	if (!inner_configured && *inner < *outer + INNER_FRESHNESS_MARGIN) {
		*inner = *outer + INNER_FRESHNESS_MARGIN;
		LM_INFO("using default verify_date_div_freshness=%d to exceed verify_date_freshness=%d\n",
			*inner, *outer);
	}
	if (*inner != -1 && *inner <= *outer) {
		LM_ERR("verify_date_div_freshness must be -1 or exceed verify_date_freshness\n");
		return -1;
	}
	return 0;
}

int verify_init(int *outer, int inner_configured)
{
	if (resolve_freshness(outer, inner_configured, &verify_date_div_freshness) < 0)
		return -1;
	snapshot_ctx = context_register_ptr(CONTEXT_GLOBAL, free_snapshot);
	return snapshot_ctx < 0 ? -1 : 0;
}

static int json_string(cJSON *j, str *out)
{
	if (!j || j->type != cJSON_String || !j->valuestring) return -1;
	init_str(out, j->valuestring);
	return 0;
}

static int unique_object(cJSON *obj)
{
	cJSON *a, *b;
	if (!obj || obj->type != cJSON_Object) return 0;
	for (a = obj->child; a; a = a->next)
		for (b = a->next; b; b = b->next)
			if (!strcmp(a->string, b->string)) return 0;
	return 1;
}

static int profile(struct parsed_identity *p)
{
	str ppt, v, info;
	cJSON *item, *claim, *values;
	int i, is_div;
	if (!unique_object(p->header) || !unique_object(p->payload) ||
		json_string(cJSON_GetObjectItem(p->header, "ppt"), &ppt) ||
		str_strcmp(&ppt, &p->ppt_hdr_param)) return -4;
	is_div = !str_strcmp(&ppt, const_str("div"));
	if (!is_div && str_strcmp(&ppt, const_str("shaken"))) return -5;
	if (json_string(cJSON_GetObjectItem(p->header, "alg"), &v) ||
		str_strcmp(&v, const_str("ES256")) ||
		(p->alg_hdr_param.len && str_strcmp(&v, &p->alg_hdr_param)) ||
		json_string(cJSON_GetObjectItem(p->header, "typ"), &v) ||
		str_strcmp(&v, const_str("passport")) ||
		json_string(p->x5u, &v) || !v.len || p->dec_signature.len != RAW_SIG_LEN)
		return -4;
	info = p->info_hdr_param;
	if (info.len < 3 || info.s[0] != '<' || info.s[info.len-1] != '>') return -4;
	info.s++; info.len -= 2;
	if (str_strcmp(&info, &v)) return -4;
	if (!unique_object(cJSON_GetObjectItem(p->payload, "orig")) ||
		div_get_claim(p->payload, "orig", 0, 0, &v)) return -4;
	claim = cJSON_GetObjectItem(p->payload, "dest");
	if (!unique_object(claim)) return -4;
	values = cJSON_GetObjectItem(claim, "tn");
	if (!values) values = cJSON_GetObjectItem(claim, "uri");
	if (!values || values->type != cJSON_Array || !cJSON_GetArraySize(values)) return -4;
	for (i = 0; i < cJSON_GetArraySize(values); i++)
		if (div_get_claim(p->payload, "dest", 1, i, &v)) return -4;
	item = p->iat;
	if (!item || item->type != cJSON_Number || !isfinite(item->valuedouble) ||
		item->valuedouble < 0 || item->valuedouble > 9007199254740991.0 ||
		floor(item->valuedouble) != item->valuedouble) return -4;
	if (is_div) {
		if (!unique_object(cJSON_GetObjectItem(p->payload, "div")) ||
			div_get_claim(p->payload, "div", 0, 0, &v) ||
			cJSON_GetObjectItem(p->payload, "opt") ||
			cJSON_GetObjectItem(p->payload, "attest") ||
			cJSON_GetObjectItem(p->payload, "origid")) return -4;
	} else {
		if (cJSON_GetObjectItem(p->payload, "div") ||
			cJSON_GetObjectItem(p->payload, "opt") ||
			json_string(p->attest, &v) || v.len != 1 ||
			(v.s[0] != 'A' && v.s[0] != 'B' && v.s[0] != 'C') ||
			json_string(p->origid, &v) || !v.len) return -4;
	}
	return 0;
}

static struct vs_snapshot *snapshot(struct sip_msg *msg)
{
	struct vs_snapshot *s;
	struct hdr_field *hf;
	int i = 0, same;
	if (!current_processing_ctx || parse_headers(msg, HDR_EOH_F, 0) < 0) return NULL;
	s = context_get_ptr(CONTEXT_GLOBAL, current_processing_ctx, snapshot_ctx);
	same = s && s->msg == msg && s->buf == msg->buf && s->id == msg->id;
	if (same) {
		for (hf = get_header_by_static_name(msg, "Identity"); hf;
			hf = get_next_header_by_static_name(hf, "Identity"), i++)
			if (i >= s->count || str_strcmp(&s->raw[i], &hf->body)) { same = 0; break; }
		if (same && i == s->count) return s;
	}
	free_snapshot(s);
	context_put_ptr(CONTEXT_GLOBAL, current_processing_ctx, snapshot_ctx, NULL);
	s = pkg_malloc(sizeof(*s));
	if (!s) return NULL;
	memset(s, 0, sizeof(*s));
	s->msg = msg; s->buf = msg->buf; s->id = msg->id;
	s->chain_status = "unverified";
	s->previous_verification = -1;
	for (hf = get_header_by_static_name(msg, "Identity"); hf;
		hf = get_next_header_by_static_name(hf, "Identity")) {
		if (s->count == DIV_MAX_PASSPORTS) goto error;
		i = s->count;
		s->raw[i].s = pkg_malloc(hf->body.len+2);
		if (!s->raw[i].s) goto error;
		s->raw[i].len = hf->body.len;
		memcpy(s->raw[i].s, hf->body.s, hf->body.len);
		s->raw[i].s[hf->body.len] = s->raw[i].s[hf->body.len+1] = 0;
		s->count++;
		s->parsed[i] = passport_parse_identity(&s->raw[i], &s->tokens[i]) < 0 ? -4 : 0;
		if (!s->parsed[i]) s->parsed[i] = profile(&s->tokens[i]);
		s->status[i] = s->parsed[i];
	}
	context_put_ptr(CONTEXT_GLOBAL, current_processing_ctx, snapshot_ctx, s);
	return s;
error:
	free_snapshot(s);
	return NULL;
}

int stir_shaken_previous_verification(struct sip_msg *msg)
{
	struct vs_snapshot *s = snapshot(msg);
	return s ? s->previous_verification : -1;
}

int stir_shaken_record_verification(struct sip_msg *msg, int result)
{
	struct vs_snapshot *s = snapshot(msg);
	if (!s) return -1;
	s->previous_verification = result;
	return 0;
}

int stir_shaken_record_authenticated(struct sip_msg *msg)
{
	return stir_shaken_record_verification(msg, 1);
}

int stir_shaken_verify_passport(struct sip_msg *msg, int *index, str *cert,
	pv_spec_t *code, pv_spec_t *reason)
{
	struct vs_snapshot *s = snapshot(msg);
	struct parsed_identity *p;
	str authority;
	int rc;
	if (s) {
		s->chain_status = "unverified"; s->attest = STR_NULL;
		s->previous_verification = -1;
	}
	if (!s || !index || *index < 0 || *index >= s->count) rc = -2;
	else {
		p = &s->tokens[*index];
		s->chain_status = "unverified"; s->attest = STR_NULL;
		rc = s->parsed[*index];
		if (!rc) {
			div_get_claim(p->payload, cJSON_GetObjectItem(p->payload, "div") ? "div" : "orig",
				0, 0, &authority);
			rc = stir_shaken_verify_credential(cert, p, &authority);
		}
		s->status[*index] = rc;
		if (rc < 0) s->previous_verification = 0;
	}
	return stir_shaken_verify_result(msg, code, reason, rc, "PASSporT verification");
}

struct vs_graph {
	unsigned char edge[DIV_MAX_PASSPORTS][DIV_MAX_PASSPORTS];
	unsigned char mark[DIV_MAX_PASSPORTS];
	int order[DIV_MAX_PASSPORTS], count, used;
};

static int visit(struct vs_graph *g, int node)
{
	int i;
	if (g->mark[node] == 1) return -1;
	if (g->mark[node] == 2) return 0;
	g->mark[node] = 1;
	for (i = 0; i < g->count; i++)
		if (g->edge[i][node] && visit(g, i)) return -1;
	g->mark[node] = 2;
	g->order[g->used++] = node;
	return 0;
}

int stir_shaken_verify_chain(struct sip_msg *msg, pv_spec_t *code,
	pv_spec_t *reason, str *orig_arg, str *dest_arg, int *inner_arg, int *outer_arg)
{
	struct vs_snapshot *s = snapshot(msg);
	struct vs_graph graph = {0};
	str orig, dest, claim, from, attest = STR_NULL, ruri;
	struct sip_uri uri;
	int i, j, roots = 0, parent, children, rc = -2, has_div = 0;
	int inner = inner_arg ? *inner_arg : verify_date_div_freshness;
	int outer = outer_arg ? *outer_arg : stir_shaken_outer_freshness();
	time_t now = time(NULL);
	if (!s) goto done;
	s->chain_status = "failed"; s->attest = STR_NULL;
	if (!s->count) { s->chain_status = "no-validation"; goto done; }
	if (outer < 0) { rc = -3; goto done; }
	if (inner != -1 && inner <= stir_shaken_outer_freshness()) { rc = -3; goto done; }
	if (now == (time_t)-1) { rc = -1; goto done; }
	if (orig_arg) orig = *orig_arg;
	else if (stir_shaken_verify_caller(msg, &orig)) { rc = -3; goto done; }
	if (div_normalize(&orig, 0)) { rc = -3; goto done; }
	for (i = 0; i < s->count; i++)
		if (cJSON_GetObjectItem(s->tokens[i].payload, "div")) has_div = 1;
	if (dest_arg) dest = *dest_arg;
	else if (!has_div) {
		if (stir_shaken_verify_destination(msg, &dest)) { rc = -3; goto done; }
	}
	else {
		ruri = *GET_RURI(msg);
		if (ruri.len >= 4 && !memcmp(ruri.s, "urn:", 4)) dest = ruri;
		else {
			if (parse_uri(ruri.s, ruri.len, &uri) < 0 ||
				(uri.type != SIP_URI_T && uri.type != SIPS_URI_T &&
				uri.type != TEL_URI_T && uri.type != TELS_URI_T)) { rc = -3; goto done; }
			dest = uri.user; trim_user_params(&dest);
		}
	}
	if (div_normalize(&dest, 1)) { rc = -3; goto done; }
	graph.count = s->count;
	for (i = 0; i < s->count; i++) {
		if (s->status[i] != 1) {
			rc = s->status[i] ? s->status[i] : -10;
			if (rc == -5) s->chain_status = "unsupported";
			goto done;
		}
		div_get_claim(s->tokens[i].payload, "orig", 0, 0, &claim);
		if (str_strcmp(&claim, &orig)) { rc = -9; goto done; }
		if (!cJSON_GetObjectItem(s->tokens[i].payload, "div")) {
			roots++;
			json_string(s->tokens[i].attest, &claim);
			/* Conservatively report the weakest attestation when several
			 * independently authenticated SHAKEN roots share the call. */
			if (!attest.s || claim.s[0] > attest.s[0]) attest = claim;
			continue;
		}
		div_get_claim(s->tokens[i].payload, "div", 0, 0, &from);
		parent = 0;
		for (j = 0; j < s->count; j++)
			if (j != i && div_has_destination(s->tokens[j].payload, &from)) {
				graph.edge[j][i] = 1; parent++;
			}
		if (!parent) { rc = -7; goto broken; }
	}
	if (!roots) { rc = -7; goto broken; }
	for (i = 0; i < s->count; i++)
		if (visit(&graph, i)) { rc = -7; goto broken; }
	/* Every leaf must reach the current recipient. Multiple roots may share
 * links, and complete independent chains may coexist. */
	for (j = 0; j < graph.used; j++) {
		i = graph.order[j];
		children = 0;
		for (parent = 0; parent < s->count; parent++) children += graph.edge[i][parent];
		if (!children && !div_has_destination(s->tokens[i].payload, &dest)) {
			rc = -7; goto broken;
		}
		if (!children && fabs((double)now - s->tokens[i].iat->valuedouble) >
			outer) {
			rc = -6; s->chain_status = "stale";
			goto done;
		}
	}
	/* Outermost freshness takes priority over any earlier-token age failure,
	 * so it cannot be hidden from the subsequent AS signing guard. */
	if (inner != -1) {
		for (i = 0; i < s->count; i++) {
			children = 0;
			for (j = 0; j < s->count; j++) children += graph.edge[i][j];
			if (children && fabs((double)now-s->tokens[i].iat->valuedouble) > inner) {
				rc = -11; s->chain_status = "inner-stale";
				goto done;
			}
		}
	}
	s->attest = attest; s->chain_status = "passed"; rc = 1;
	goto done;
broken:
	s->chain_status = "broken";
done:
	if (s) s->previous_verification = rc == 1 ? 1 :
		(rc == -1 || rc == -2 || rc == -3 || rc == -10) ? -1 : 0;
	return stir_shaken_verify_result(msg, code, reason, rc, "PASSporT chain verification");
}

enum { VS_COUNT, VS_STATUS, VS_PPT, VS_X5U, VS_ORIG, VS_ORIG_TYPE,
	VS_DEST, VS_DEST_TYPE, VS_DIV, VS_DIV_TYPE, VS_IAT, VS_ATTEST,
	VS_ORIGID, VS_HEADER, VS_PAYLOAD, VS_RAW, VS_CHAIN_STATUS, VS_CHAIN_ATTEST };

int pv_parse_identity_all(pv_spec_p sp, const str *name)
{
	static const char *names[] = {"count", "status", "ppt", "x5u", "orig", "orig_type",
		"dest", "dest_type", "div", "div_type", "iat", "attest", "origid",
		"header", "payload", "raw", "chain_status", "chain_attest"};
	unsigned int i;
	for (i = 0; i < sizeof(names)/sizeof(names[0]); i++)
		if (name->len == strlen(names[i]) && !memcmp(name->s, names[i], name->len)) {
			sp->pvp.pvn.u.isname.name.n = i; return 0;
		}
	return -1;
}

int pv_get_identity_all(struct sip_msg *msg, pv_param_t *param, pv_value_t *res)
{
	struct vs_snapshot *s = snapshot(msg);
	struct parsed_identity *p;
	int i = 0, flags, field = param->pvn.u.isname.name.n;
	cJSON *value = NULL, *claim;
	str out = STR_NULL;
	const char *name;
	if (!s) return pv_get_null(msg, param, res);
	if (field == VS_COUNT) return pv_get_sintval(msg, param, res, s->count);
	if (field == VS_CHAIN_STATUS) { init_str(&out, s->chain_status); goto string; }
	if (field == VS_CHAIN_ATTEST) { out = s->attest; goto string; }
	if (param->pvi.type) {
		if (pv_get_spec_index(msg, param, &i, &flags) ||
			(flags != PV_IDX_INT && flags != PV_IDX_PVAR) ||
			i < 0 || i >= s->count) return pv_get_null(msg, param, res);
	} else {
		for (i = 0; i < s->count; i++)
			if (!s->parsed[i] && !str_strcmp(&s->tokens[i].ppt_hdr_param, const_str("shaken"))) break;
		if (i == s->count) return pv_get_null(msg, param, res);
	}
	p = &s->tokens[i];
	if (field == VS_RAW) { out = s->raw[i]; goto string; }
	if (field == VS_STATUS) {
		init_str(&out, s->status[i] == 1 ? "verified" : s->status[i] == 0 ? "unverified" :
			s->status[i] == -5 ? "unsupported" : s->parsed[i] ? "malformed" : "failed");
		goto string;
	}
	if (s->parsed[i] == -4) return pv_get_null(msg, param, res);
	switch (field) {
	case VS_PPT: value = cJSON_GetObjectItem(p->header, "ppt"); break;
	case VS_X5U: value = p->x5u; break;
	case VS_ATTEST: value = p->attest; break;
	case VS_ORIGID: value = p->origid; break;
	case VS_HEADER: out = p->dec_header; goto string;
	case VS_PAYLOAD: out = p->dec_payload; goto string;
	case VS_IAT:
		if (!p->iat || p->iat->type != cJSON_Number || !isfinite(p->iat->valuedouble) ||
			p->iat->valuedouble < 0 || p->iat->valuedouble > 9007199254740991.0)
			return pv_get_null(msg, param, res);
		res->rs.s = int2str((uint64_t)p->iat->valuedouble, &res->rs.len);
		res->flags = PV_VAL_STR;
		if (p->iat->valuedouble <= INT_MAX) {
			res->ri = (int)p->iat->valuedouble;
			res->flags |= PV_VAL_INT|PV_TYPE_INT;
		}
		return 0;
	case VS_ORIG: case VS_ORIG_TYPE: case VS_DEST: case VS_DEST_TYPE:
	case VS_DIV: case VS_DIV_TYPE:
		name = field == VS_ORIG || field == VS_ORIG_TYPE ? "orig" :
			field == VS_DEST || field == VS_DEST_TYPE ? "dest" : "div";
		claim = cJSON_GetObjectItem(p->payload, name);
		value = cJSON_GetObjectItem(claim, "tn");
		if (field == VS_ORIG_TYPE || field == VS_DEST_TYPE || field == VS_DIV_TYPE) {
			if (!value && !cJSON_GetObjectItem(claim, "uri")) return pv_get_null(msg, param, res);
			init_str(&out, value ? "tn" : "uri"); goto string;
		}
		if (!value) value = cJSON_GetObjectItem(claim, "uri");
		if (value && value->type == cJSON_Array) value = cJSON_GetArrayItem(value, 0);
		break;
	default: return pv_get_null(msg, param, res);
	}
	if (json_string(value, &out)) return pv_get_null(msg, param, res);
string:
	if (!out.s) return pv_get_null(msg, param, res);
	return pv_get_strval(msg, param, res, &out);
}

#ifdef UNIT_TESTS
int stir_shaken_test_freshness(int *outer, int inner_configured, int *inner)
{
	return resolve_freshness(outer, inner_configured, inner);
}
#endif
