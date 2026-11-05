/* Copyright (C) 2026 OpenSIPS Project
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "verstat.h"
#include "../../context.h"
#include "../../data_lump.h"
#include "../../parser/parse_to.h"
#include "../../parser/parse_uri.h"

/* State owns neither the live lumps nor their buffers: the message does.
 * Saved pointers are only compared until located in the current live list. */
struct verstat_edit {
	struct sip_msg *msg;
	char *buf;
	unsigned int id, offset, len;
	struct lump *del, *add;
	char *value;
	struct verstat_edit *next;
};

struct verstat_plan {
	struct verstat_edit *edit;
	str value;
	int fresh;
	struct verstat_plan *next;
};

static int verstat_ctx = -1;

static void free_edits(void *ptr)
{
	struct verstat_edit *p = ptr, *next;
	while (p) {
		next = p->next;
		pkg_free(p);
		p = next;
	}
}

int verstat_init(void)
{
	verstat_ctx = context_register_ptr(CONTEXT_GLOBAL, free_edits);
	return verstat_ctx < 0 ? -1 : 0;
}

static int is_verstat(char *p, int len)
{
	return len == 7 && !strncasecmp(p, "verstat", 7);
}

/* Copy parameters, omitting every verstat occurrence (including valueless or
 * duplicated instances). The bounds are URI grammar boundaries, not a search
 * through arbitrary display names or URI headers. */
static void copy_params(char **out, char *p, char *end)
{
	char *start, *name, *eq;
	while (p < end) {
		start = p++;
		name = p;
		while (p < end && *p != ';') p++;
		eq = memchr(name, '=', p-name);
		if (!is_verstat(name, eq ? eq-name : p-name)) {
			memcpy(*out, start, p-start);
			*out += p-start;
		}
	}
}

static int rewrite_uri(str uri, str *value, char **out)
{
	struct sip_uri parsed;
	char *p = uri.s, *end = p+uri.len, *param, *at, *query;
	if (parse_uri(p, uri.len, &parsed) < 0)
		return -1;
	if (parsed.type == SIP_URI_T || parsed.type == SIPS_URI_T) {
		if (!parsed.user.s || !parsed.user.len || parsed.passwd.len)
			return -1;
		at = parsed.user.s + parsed.user.len;
		if (at >= end || *at != '@')
			return -1;
		param = memchr(parsed.user.s, ';', parsed.user.len);
		if (!param) param = at;
		memcpy(*out, p, param-p);
		*out += param-p;
		copy_params(out, param, at);
		if (value) {
			memcpy(*out, ";verstat=", 9); *out += 9;
			memcpy(*out, value->s, value->len); *out += value->len;
		}
		/* Also remove the host-side spelling seen in deployed networks. */
		query = memchr(at, '?', end-at);
		if (!query) query = end;
		param = memchr(at, ';', query-at);
		if (!param) param = query;
		memcpy(*out, at, param-at); *out += param-at;
		copy_params(out, param, query);
		memcpy(*out, query, end-query); *out += end-query;
	} else if (parsed.type == TEL_URI_T || parsed.type == TELS_URI_T) {
		param = memchr(p, ';', end-p);
		if (!param) param = end;
		memcpy(*out, p, param-p); *out += param-p;
		copy_params(out, param, end);
		if (value) {
			memcpy(*out, ";verstat=", 9); *out += 9;
			memcpy(*out, value->s, value->len); *out += value->len;
		}
	} else {
		return -1;
	}
	return 0;
}

static int rewrite_body(struct hdr_field *hf, str *value, str *result)
{
	struct to_body *parsed = pkg_malloc(sizeof(*parsed)), *b;
	struct to_param *tp;
	char *cursor = hf->body.s, *end = cursor+hf->body.len, *out;
	char *start, *finish;
	int count = 0, bracketed, rc = -1;
	if (!parsed) return -1;
	memset(parsed, 0, sizeof(*parsed));
	if (hf->type == HDR_PAI_T)
		parse_multi_to(cursor, end+1, parsed);
	else
		parse_to(cursor, end+1, parsed);
	if (parsed->error == PARSE_ERROR) {
		/* parse_multi_to already frees the tail on error, but leaves next. */
		parsed->next = NULL;
		goto done;
	}
	for (b = parsed; b; b = b->next) count++;
	result->s = pkg_malloc(hf->body.len + count*(11 + (value ? value->len : 0)) + 1);
	if (!result->s) goto done;
	out = result->s;
	for (b = parsed; b; b = b->next) {
		if (!b->uri.len || b->uri.s < cursor || b->uri.s+b->uri.len > end)
			goto bad;
		memcpy(out, cursor, b->uri.s-cursor); out += b->uri.s-cursor;
		bracketed = b->uri.s > hf->body.s && b->uri.s[-1] == '<';
		if (!bracketed) *out++ = '<';
		if (rewrite_uri(b->uri, value, &out)) goto bad;
		if (!bracketed) *out++ = '>';
		cursor = b->uri.s+b->uri.len;
		/* Remove misplaced header-level verstat too, retaining tag/other params. */
		for (tp = b->param_lst; tp; tp = tp->next) {
			if (!is_verstat(tp->name.s, tp->name.len)) continue;
			start = tp->name.s;
			while (start > cursor && start[-1] != ';') start--;
			if (start <= cursor || start[-1] != ';') goto bad;
			start--;
			finish = tp->value.s ? tp->value.s+tp->value.len : tp->name.s+tp->name.len;
			if (finish < start || finish > end) goto bad;
			/* parse_to excludes quote delimiters from a quoted value. */
			if (finish < end && *finish == '"') finish++;
			memcpy(out, cursor, start-cursor); out += start-cursor;
			cursor = finish;
		}
	}
	memcpy(out, cursor, end-cursor); out += end-cursor;
	result->len = out-result->s;
	*out = '\0';
	rc = 0;
	goto done;
bad:
	pkg_free(result->s);
	result->s = NULL;
done:
	free_to(parsed);
	return rc;
}

static int check_conflicts(struct sip_msg *msg, unsigned int off,
	unsigned int len, struct verstat_edit *own)
{
	struct lump *p;
	int found = !own;
	for (p = msg->add_rm; p; p = p->next) {
		if (own && p == own->del) {
			/* Do not dereference a cached lump unless it is still live. */
			if (p->op != LUMP_DEL || p->u.offset != off || p->len != len ||
				p->after || p->before != own->add || !p->before ||
				p->before->before || p->before->after ||
				p->before->op != LUMP_ADD || p->before->u.value != own->value ||
				((p->flags | p->before->flags) & LUMPFLAG_SHMEM)) return -1;
			found = 1;
			continue;
		}
		if (p->op == LUMP_DEL && p->u.offset < off+len &&
			p->u.offset+p->len > off) return -1;
		if ((p->op == LUMP_DEL || p->op == LUMP_NOP) &&
			(p->before || p->after) && p->u.offset >= off &&
			p->u.offset <= off+len) return -1;
		if (p->op == LUMP_NOP && p->u.offset >= off && p->u.offset <= off+len)
			return -1;
	}
	return found ? 0 : -1;
}

static int update_verstat(struct sip_msg *msg, str *target, str *value)
{
	struct hdr_field *hf;
	struct verstat_edit *state, *e;
	struct verstat_plan *plans = NULL, *p, *next;
	struct sip_msg stage;
	struct lump **link;
	int which, rc = -1;
	if (!str_strcmp(target, const_str("from"))) which = 1;
	else if (!str_strcmp(target, const_str("pai"))) which = 2;
	else if (!str_strcmp(target, const_str("both"))) which = 3;
	else return -3;
	if (!current_processing_ctx || parse_headers(msg, HDR_EOH_F, 0) < 0)
		return -2;
	if (init_lump_flags & LUMPFLAG_SHMEM)
		return -4;
	state = context_get_ptr(CONTEXT_GLOBAL, current_processing_ctx, verstat_ctx);
	/* Prepare every requested header before changing any live lump. */
	for (hf = msg->headers; hf; hf = hf->next) {
		if (!((hf->type == HDR_FROM_T && (which & 1)) ||
			(hf->type == HDR_PAI_T && (which & 2)))) continue;
		for (e = state; e; e = e->next)
			if (e->msg == msg && e->buf == msg->buf && e->id == msg->id &&
				e->offset == (unsigned int)(hf->body.s-msg->buf)) break;
		if (check_conflicts(msg, hf->body.s-msg->buf, hf->body.len, e)) {
			rc = -4;
			goto done;
		}
		p = pkg_malloc(sizeof(*p));
		if (!p) goto done;
		memset(p, 0, sizeof(*p));
		p->next = plans; plans = p;
		if (rewrite_body(hf, value, &p->value)) { rc = -2; goto done; }
		p->edit = e;
		if (!e) {
			e = pkg_malloc(sizeof(*e));
			if (!e) goto done;
			memset(e, 0, sizeof(*e));
			p->edit = e; p->fresh = 1;
			e->msg = msg; e->buf = msg->buf; e->id = msg->id;
			e->offset = hf->body.s-msg->buf; e->len = hf->body.len;
			/* Native lump helpers operate on a detached staging list. */
			stage = *msg; stage.add_rm = NULL;
			e->del = del_lump(&stage, e->offset, e->len, hf->type);
			if (!e->del) goto done;
			e->add = insert_new_lump_before(e->del, p->value.s, p->value.len, hf->type);
			if (!e->add) goto done;
			e->value = p->value.s;
			p->value.s = NULL; /* staged lump owns the buffer */
		}
	}
	/* No allocations or parsing can fail from this point onwards. */
	for (p = plans; p; p = p->next) {
		e = p->edit;
		if (p->fresh) {
			for (link = &msg->add_rm; *link; link = &(*link)->next)
				if (((*link)->op == LUMP_DEL || (*link)->op == LUMP_NOP) &&
					(*link)->u.offset > e->offset) break;
			e->del->next = *link; *link = e->del;
			e->next = state; state = e;
		} else {
			pkg_free(e->add->u.value);
			e->add->u.value = p->value.s;
			e->add->len = p->value.len;
			e->value = p->value.s;
			p->value.s = NULL;
		}
	}
	context_put_ptr(CONTEXT_GLOBAL, current_processing_ctx, verstat_ctx, state);
	rc = 1;
done:
	for (p = plans; p; p = next) {
		next = p->next;
		if (p->value.s) pkg_free(p->value.s);
		if (rc < 0 && p->fresh) {
			if (p->edit->del) free_lump_list(p->edit->del);
			pkg_free(p->edit);
		}
		pkg_free(p);
	}
	if (rc < 0) LM_NOTICE("verstat edit refused (rc=%d)\n", rc);
	return rc;
}

int stir_shaken_set_verstat(struct sip_msg *msg, str *target, str *value)
{
	if (str_strcmp(value, const_str("TN-Validation-Passed")) &&
		str_strcmp(value, const_str("TN-Validation-Failed")) &&
		str_strcmp(value, const_str("No-TN-Validation"))) return -3;
	return update_verstat(msg, target, value);
}

int stir_shaken_remove_verstat(struct sip_msg *msg, str *target)
{
	return update_verstat(msg, target, NULL);
}
