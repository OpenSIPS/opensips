/*
 * Copyright (C) 2021 OpenSIPS Project
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

#include "siprec_var.h"
#include "../../ut.h"
#include "../../context.h"

#define SIPREC_VAR_INVAID_ID				(-1)
#define SIPREC_VAR_GROUP_ID					(1 << 0)
#define SIPREC_VAR_CALLER_ID				(1 << 1)
#define SIPREC_VAR_CALLEE_ID				(1 << 2)
#define SIPREC_VAR_HEADERS_ID				(1 << 3)
#define SIPREC_VAR_MEDIA_ID					(1 << 4)
#define SIPREC_VAR_SOCKET_ID				(1 << 5)
#define SIPREC_GROUP_CUSTOM_EXTENSION_ID	(1 << 6)
#define SIPREC_SESSION_CUSTOM_EXTENSION_ID	(1 << 7)

struct {
	const char *name;
	const int id;
} siprec_var_names[] = {
	{"group", SIPREC_VAR_GROUP_ID},
	{"caller", SIPREC_VAR_CALLER_ID},
	{"callee", SIPREC_VAR_CALLEE_ID},
	{"media", SIPREC_VAR_MEDIA_ID},
	{"media_ip", SIPREC_VAR_MEDIA_ID},
	{"headers", SIPREC_VAR_HEADERS_ID},
	{"socket", SIPREC_VAR_SOCKET_ID},
	{"group_custom_extension", SIPREC_GROUP_CUSTOM_EXTENSION_ID},
	{"session_custom_extension", SIPREC_SESSION_CUSTOM_EXTENSION_ID},
};

static int srec_msg_idx;

#define SIPREC_GET_VAR() (struct srec_var *)\
	(context_get_ptr(CONTEXT_GLOBAL, current_processing_ctx, srec_msg_idx))

struct srec_var *get_srec_var(void)
{
	return SIPREC_GET_VAR();
}

static struct srec_var *get_srec_var_new(void)
{
	struct srec_var *var = SIPREC_GET_VAR();
	if (var)
		return var;
	/* not found - create a new one */
	var = pkg_malloc(sizeof *var);
	if (!var) {
		LM_ERR("oom for siprec var!\n");
		return NULL;
	}
	memset(var, 0, sizeof *var);
	context_put_ptr(CONTEXT_GLOBAL, current_processing_ctx, srec_msg_idx, var);
	return var;
}

static void free_srec_var(void *v)
{
	struct srec_var *sv = (struct srec_var *)v;
	if (sv->group.s)
		pkg_free(sv->group.s);
	if (sv->caller.s)
		pkg_free(sv->caller.s);
	if (sv->callee.s)
		pkg_free(sv->callee.s);
	if (sv->media.s)
		pkg_free(sv->media.s);
	if (sv->headers.s)
		pkg_free(sv->headers.s);
	if (sv->group_custom_extension.s)
		pkg_free(sv->group_custom_extension.s);
	if (sv->session_custom_extension.s)
		pkg_free(sv->session_custom_extension.s);
	pkg_free(sv);
}


static int pv_parse_siprec_name(const str *name)
{
	int s;
	for (s = 0; s < (sizeof(siprec_var_names)/sizeof(siprec_var_names[0])); s++) {
		if (str_match_nt(name, siprec_var_names[s].name))
			return siprec_var_names[s].id;
	}
	LM_ERR("unknwon siprec variable %.*s\n", name->len, name->s);
	return SIPREC_VAR_INVAID_ID;
}

static int pv_parse_siprec_get_name(struct sip_msg *msg, pv_param_t *p)
{
	pv_value_t tv;

	if (p->pvn.type == PV_NAME_INTSTR)
		return p->pvn.u.isname.type;

	if(pv_get_spec_value(msg, (const pv_spec_p)(p->pvn.u.dname), &tv)!=0)
	{
		LM_ERR("cannot get siprec value\n");
		return SIPREC_VAR_INVAID_ID;
	}

	if(tv.flags&PV_VAL_NULL || tv.flags&PV_VAL_EMPTY)
	{
		LM_ERR("null or empty name\n");
		return -1;
	}

	if(!(tv.flags&PV_VAL_STR))
		tv.rs.s = int2str(tv.ri, &tv.rs.len);

	return pv_parse_siprec_name(&tv.rs);
}

int pv_parse_siprec(pv_spec_p sp, const str *in)
{
	char *p;
	char *s;
	pv_spec_p nsp = 0;

	if(in==NULL || in->s==NULL || sp==NULL)
		return -1;
	p = in->s;
	if(*p==PV_MARKER)
	{
		nsp = (pv_spec_p)pkg_malloc(sizeof(pv_spec_t));
		if(nsp==NULL)
		{
			LM_ERR("no more memory\n");
			return -1;
		}
		s = pv_parse_spec(in, nsp);
		if(s==NULL)
		{
			LM_ERR("invalid name [%.*s]\n", in->len, in->s);
			pv_spec_free(nsp);
			return -1;
		}
		sp->pvp.pvn.type = PV_NAME_PVAR;
		sp->pvp.pvn.u.dname = (void*)nsp;
		return 0;
	}
	sp->pvp.pvn.type = PV_NAME_INTSTR;
	sp->pvp.pvn.u.isname.type = pv_parse_siprec_name(in);
	return (sp->pvp.pvn.u.isname.type == SIPREC_VAR_INVAID_ID)?-1:0;
}

int pv_get_siprec(struct sip_msg *msg,  pv_param_t *param,
		pv_value_t *val)
{
	str *field = NULL;
	struct srec_var *sv = SIPREC_GET_VAR();
	if (!sv)
		return pv_get_null(msg, param, val);

	switch (pv_parse_siprec_get_name(msg, param)) {
		case SIPREC_VAR_GROUP_ID:
			field = &sv->group;
			break;
		case SIPREC_VAR_CALLER_ID:
			field = &sv->caller;
			break;
		case SIPREC_VAR_CALLEE_ID:
			field = &sv->callee;
			break;
		case SIPREC_VAR_MEDIA_ID:
			field = &sv->media;
			break;
		case SIPREC_VAR_HEADERS_ID:
			field = &sv->headers;
			break;
		case SIPREC_VAR_SOCKET_ID:
			if (!sv->si)
				return pv_get_null(msg, param, val);
			field = get_socket_real_name(sv->si);
			break;
		case SIPREC_GROUP_CUSTOM_EXTENSION_ID:
			field = &sv->group_custom_extension;
			break;
		case SIPREC_SESSION_CUSTOM_EXTENSION_ID:
			field = &sv->session_custom_extension;
			break;
		default:
			LM_BUG("unknown field!\n");
		case SIPREC_VAR_INVAID_ID:
			return -1;
	}
	if (!field) {
		LM_BUG("unknown field!\n");
		return -1;
	}

	if (field->len < 0)
		return pv_get_null(msg, param, val);

	val->rs = *field;
	val->flags = PV_VAL_STR;

	return 0;
}

int pv_set_siprec(struct sip_msg* msg, pv_param_t *param,
		int op, pv_value_t *val)
{
	int rc;
	str *field = NULL, tmp;
	struct srec_var *sv = get_srec_var_new();
	if (!sv)
		return -1;

	switch (pv_parse_siprec_get_name(msg, param)) {
		case SIPREC_VAR_GROUP_ID:
			field = &sv->group;
			break;
		case SIPREC_VAR_CALLER_ID:
			field = &sv->caller;
			break;
		case SIPREC_VAR_CALLEE_ID:
			field = &sv->callee;
			break;
		case SIPREC_VAR_MEDIA_ID:
			field = &sv->media;
			break;
		case SIPREC_VAR_HEADERS_ID:
			field = &sv->headers;
			break;
		case SIPREC_VAR_SOCKET_ID:
			if (!(val->flags & PV_VAL_STR)) {
				LM_ERR("invalid socket type!\n");
				return -1;
			}
			sv->si = parse_sock_info(&val->rs);
			if (!sv->si) {
				LM_ERR("socket info not existing %.*s\n",
						val->rs.len, val->rs.s);
				return -1;
			}
			return 1;
		case SIPREC_GROUP_CUSTOM_EXTENSION_ID:
			field = &sv->group_custom_extension;
			break;
		case SIPREC_SESSION_CUSTOM_EXTENSION_ID:
			field = &sv->session_custom_extension;
			break;
		default:
			LM_BUG("unknown field %d!\n", pv_parse_siprec_get_name(msg, param));
		case SIPREC_VAR_INVAID_ID:
			return -1;
	}
	if (!field) {
		LM_BUG("unknown field!\n");
		return -1;
	}
	if (!(val->flags & PV_VAL_STR)) {
		tmp.s = int2str(val->ri, &tmp.len);
		rc = pkg_str_sync(field, &tmp);
	} else {
		rc = pkg_str_sync(field, &val->rs);
	}

	return rc;
}

int init_srec_var(void)
{
	srec_msg_idx = context_register_ptr(CONTEXT_GLOBAL, free_srec_var);
	return 0;
}
