/* Copyright (C) 2026 OpenSIPS Project
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <math.h>
#include "div.h"
#include "../../dprint.h"
#include "../../ut.h"

int div_normalize(str *id, int allow_uri)
{
	int i, component = 0;
	if (!id->s || !id->len)
		return -1;
	if (allow_uri && id->len >= 15 &&
		!memcmp(id->s, "urn:service:sos", 15)) {
		if (id->len == 15)
			return 0;
		if (id->s[15] != '.')
			return -1;
		for (i = 16; i < id->len; i++) {
			char c = id->s[i];
			if (c == '.') {
				if (!component)
					return -1;
				component = 0;
			} else if ((c >= 'a' && c <= 'z') ||
				(c >= '0' && c <= '9') || c == '-') {
				component++;
			} else {
				return -1;
			}
		}
		return component ? 0 : -1;
	}
	if (id->s[0] == '+') {
		id->s++;
		id->len--;
	}
	if (!id->len || id->len > 15)
		return -1;
	for (i = 0; i < id->len; i++)
		if (id->s[i] < '0' || id->s[i] > '9')
			return -1;
	return 0;
}

static int emergency(str id)
{
	return (id.len == 3 && !memcmp(id.s, "911", 3)) ||
		(id.len >= 15 && !memcmp(id.s, "urn:service:sos", 15));
}

int div_identity_equal(str a, str b)
{
	if (div_normalize(&a, 1) || div_normalize(&b, 1))
		return 0;
	return !str_strcmp(&a, &b) || (emergency(a) && emergency(b));
}

static int string_value(cJSON *value, str *out)
{
	if (!value || value->type != cJSON_String || !value->valuestring)
		return -1;
	init_str(out, value->valuestring);
	return 0;
}

/* dest is an array, while orig and div each contain a single identifier. */
static int claim_value(cJSON *payload, const char *name, int array,
	int index, str *out)
{
	cJSON *claim = cJSON_GetObjectItem(payload, name), *value;
	int uri = 0;
	if (!claim || claim->type != cJSON_Object)
		return -1;
	value = cJSON_GetObjectItem(claim, "tn");
	if (!value) {
		value = cJSON_GetObjectItem(claim, "uri");
		uri = 1;
	} else if (cJSON_GetObjectItem(claim, "uri")) {
		return -1;
	}
	if (uri && !strcmp(name, "orig"))
		return -1;
	if (array) {
		if (!value || value->type != cJSON_Array)
			return -1;
		value = cJSON_GetArrayItem(value, index);
	}
	if (string_value(value, out) || div_normalize(out, uri))
		return -1;
	if (uri && (out->len < 15 || memcmp(out->s, "urn:service:sos", 15)))
		return -1;
	return 0;
}

static int destination_has(cJSON *payload, str *id)
{
	str candidate;
	int i;
	for (i = 0; !claim_value(payload, "dest", 1, i, &candidate); i++)
		if (div_identity_equal(candidate, *id))
			return 1;
	return 0;
}

int div_chain_add(struct div_chain *chain, str *body)
{
	struct parsed_identity *p;
	if (chain->count == DIV_MAX_PASSPORTS)
		return -1;
	p = &chain->tokens[chain->count++];
	return passport_parse_identity(body, p);
}

int div_get_claim(cJSON *payload, const char *name, int array, int index, str *out)
{
	return claim_value(payload, name, array, index, out);
}

int div_has_destination(cJSON *payload, str *id)
{
	return destination_has(payload, id);
}

int div_chain_select(struct div_chain *chain, str *requested_div)
{
	int root = -1, current, i, next, steps = 0;
	unsigned char used[DIV_MAX_PASSPORTS] = {0};
	str ppt, orig, from, dest, extra;
	cJSON *type, *iat, *claim, *values;
	int j;
	for (i = 0; i < chain->count; i++) {
		struct parsed_identity *p = &chain->tokens[i];
		type = cJSON_GetObjectItem(p->header, "ppt");
		if (string_value(type, &ppt) || str_strcmp(&ppt, &p->ppt_hdr_param))
			return -7;
		if (strcmp(type->valuestring, "shaken") && strcmp(type->valuestring, "div"))
			continue;
		if (string_value(cJSON_GetObjectItem(p->header, "alg"), &dest) ||
			str_strcmp(&dest, const_str("ES256")) ||
			(p->alg_hdr_param.len && str_strcmp(&p->alg_hdr_param, &dest)) ||
			string_value(cJSON_GetObjectItem(p->header, "typ"), &dest) ||
			str_strcmp(&dest, const_str("passport")) ||
			string_value(p->x5u, &dest) || !dest.len ||
			p->dec_signature.len != RAW_SIG_LEN)
			return -7;
		if (claim_value(p->payload, "orig", 0, 0, &orig) ||
			claim_value(p->payload, "dest", 1, 0, &dest))
			return -7;
		claim = cJSON_GetObjectItem(p->payload, "dest");
		values = cJSON_GetObjectItem(claim, "tn");
		if (!values)
			values = cJSON_GetObjectItem(claim, "uri");
		for (j = 0; j < cJSON_GetArraySize(values); j++)
			if (claim_value(p->payload, "dest", 1, j, &dest))
				return -7;
		iat = cJSON_GetObjectItem(p->payload, "iat");
		if (!iat || iat->type != cJSON_Number || !isfinite(iat->valuedouble) ||
			iat->valuedouble < 0 || iat->valuedouble > 9007199254740991.0 ||
			floor(iat->valuedouble) != iat->valuedouble)
			return -7;
		if (!strcmp(type->valuestring, "shaken")) {
			if (string_value(p->attest, &dest) || dest.len != 1 ||
				(dest.s[0] != 'A' && dest.s[0] != 'B' && dest.s[0] != 'C') ||
				string_value(p->origid, &dest) || !dest.len)
				return -7;
			/* Multiple distinct SHAKEN roots need an explicit multi-chain API. */
			if (root != -1)
				return -7;
			root = i;
			chain->orig = orig;
		} else if (claim_value(p->payload, "div", 0, 0, &from) ||
			cJSON_GetObjectItem(p->payload, "opt")) {
			return -7;
		}
	}
	if (root == -1)
		return -2;
	current = root;
	for (;;) {
		used[current] = 1;
		next = -1;
		for (i = 0; i < chain->count; i++) {
			cJSON *payload = chain->tokens[i].payload;
			if (claim_value(payload, "div", 0, 0, &from))
				continue;
			if (!destination_has(chain->tokens[current].payload, &from))
				continue;
			if (used[i] || next != -1 ||
				claim_value(payload, "orig", 0, 0, &orig) ||
				str_strcmp(&orig, &chain->orig))
				return -7;
			next = i;
		}
		if (next == -1)
			break;
		if (++steps >= chain->count)
			return -7;
		current = next;
	}
	for (i = 0; i < chain->count; i++)
		if (!used[i] && cJSON_GetObjectItem(chain->tokens[i].payload, "div"))
			return -7;
	if (requested_div) {
		if (!destination_has(chain->tokens[current].payload, requested_div))
			return -7;
		chain->previous = *requested_div;
	} else {
		if (claim_value(chain->tokens[current].payload, "dest", 1, 0, &dest) ||
			!claim_value(chain->tokens[current].payload, "dest", 1, 1, &extra))
			return -7;
		chain->previous = dest;
	}
	iat = cJSON_GetObjectItem(chain->tokens[current].payload, "iat");
	/* Bound the conversion to time_t: freshness comparisons use the double. */
	if (iat->valuedouble > 2147483647.0 && sizeof(time_t) < 8)
		return -7;
	chain->iat = (time_t)iat->valuedouble;
	return 0;
}

void div_chain_cleanup(struct div_chain *chain)
{
	int i;
	for (i = 0; i < chain->count; i++)
		passport_identity_cleanup(&chain->tokens[i]);
}
