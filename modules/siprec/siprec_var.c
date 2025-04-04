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
#include "../../lib/list.h"
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
#define SIPREC_VAR_FROM_URI_ID				(1 << 8)
#define SIPREC_VAR_TO_URI_ID				(1 << 9)

str siprec_default_instance = str_init(SIPREC_DEFAULT_INSTANCE);

struct {
	const char *name;
	const int id;
} siprec_var_names[] = {
	{"group", SIPREC_VAR_GROUP_ID},
	{"caller", SIPREC_VAR_CALLER_ID},
	{"callee", SIPREC_VAR_CALLEE_ID},
	{"media", SIPREC_VAR_MEDIA_ID},
	{"headers", SIPREC_VAR_HEADERS_ID},
	{"socket", SIPREC_VAR_SOCKET_ID},
	{"group_custom_extension", SIPREC_GROUP_CUSTOM_EXTENSION_ID},
	{"session_custom_extension", SIPREC_SESSION_CUSTOM_EXTENSION_ID},
	{"from_uri", SIPREC_VAR_FROM_URI_ID},
	{"to_uri", SIPREC_VAR_TO_URI_ID},
};

static int srec_msg_idx;

struct srec_var_inst {
	str instance;
	struct srec_var var;
	struct list_head list;
};

#define srec_inst_list list_head
#define SIPREC_GET_INST_LIST() (struct list_head *)\
	(context_get_ptr(CONTEXT_GLOBAL, current_processing_ctx, srec_msg_idx))

static struct srec_var_inst *get_srec_var_inst(struct srec_inst_list *inst_list, str *instance)
{
	struct list_head *it;
	struct srec_var_inst *inst;

	list_for_each(it, inst_list) {
		inst = list_entry(it, struct srec_var_inst, list);
		if (str_match(&inst->instance, instance))
			return inst;
	}
	return NULL;
}

struct srec_var *get_srec_var(str *instance)
{
	struct srec_inst_list *inst_list = SIPREC_GET_INST_LIST();
	struct srec_var_inst *inst;

	if (!inst_list)
		return NULL;
	if (!instance)
		instance = &siprec_default_instance;
	inst = get_srec_var_inst(inst_list, instance);
	return (inst?&inst->var:NULL);
}

static struct srec_var *get_srec_var_new(str *instance)
{
	struct srec_inst_list *inst_list = SIPREC_GET_INST_LIST();
	struct srec_var_inst *inst;

	if (inst_list) {
		inst = get_srec_var_inst(inst_list, instance);
		if (inst)
			return &inst->var;
	} else {
		inst_list = pkg_malloc(sizeof *inst_list);
		if (!inst_list) {
			LM_ERR("could not alloc new variable instance!\n");
			return NULL;
		}
		INIT_LIST_HEAD(inst_list);
		context_put_ptr(CONTEXT_GLOBAL, current_processing_ctx, srec_msg_idx, inst_list);
	}
	/* not found - create a new one */
	inst = pkg_malloc(sizeof *inst + instance->len);
	if (!inst) {
		LM_ERR("oom for siprec var!\n");
		return NULL;
	}
	memset(inst, 0, sizeof *inst);
	inst->instance.s = (char *)(inst + 1);
	memcpy(inst->instance.s, instance->s, instance->len);
	inst->instance.len = instance->len;
	list_add(&inst->list, inst_list);
	return &inst->var;
}

static void free_srec_var_inst(void *v)
{
	struct srec_inst_list *inst_list = (struct srec_inst_list *)v;
	struct list_head *it, *safe;
	struct srec_var_inst *inst;

	list_for_each_safe(it, safe, inst_list) {
		inst = list_entry(it, struct srec_var_inst, list);
		if (inst->var.group.s)
			pkg_free(inst->var.group.s);
		if (inst->var.caller.s)
			pkg_free(inst->var.caller.s);
		if (inst->var.callee.s)
			pkg_free(inst->var.callee.s);
		if (inst->var.media.s)
			pkg_free(inst->var.media.s);
		if (inst->var.headers.s)
			pkg_free(inst->var.headers.s);
		if (inst->var.group_custom_extension.s)
			pkg_free(inst->var.group_custom_extension.s);
		if (inst->var.session_custom_extension.s)
			pkg_free(inst->var.session_custom_extension.s);
		if (inst->var.from_uri.s)
			pkg_free(inst->var.from_uri.s);
		if (inst->var.to_uri.s)
			pkg_free(inst->var.to_uri.s);
		pkg_free(inst);
	}
	pkg_free(inst_list);
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

static str *pv_get_siprec_instance(struct sip_msg *msg, pv_param_p sp)
{
	static pv_value_t tv;

	switch (sp->pvi.type) {
		case PV_IDX_PVAR:
			if(pv_get_spec_value(msg,
					sp->pvi.u.dval, &tv)!=0) {
				LM_ERR("cannot get index value\n");
				return NULL;
			}
			if (!(tv.flags & PV_VAL_STR)) {
				LM_ERR("only string instances are allowed\n");
				return NULL;
			}
			return &tv.rs;
			break;
		case PV_IDX_ALL:
			return (str *)sp->pvi.u.dval;
		default:
			return &siprec_default_instance;
	}
}

int pv_get_siprec(struct sip_msg *msg,  pv_param_t *param,
		pv_value_t *val)
{
	const str *field = NULL;
	str *instance = pv_get_siprec_instance(msg, param);
	struct srec_var *sv = get_srec_var(instance);
	if (!sv || !instance)
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
		case SIPREC_VAR_FROM_URI_ID:
			field = &sv->from_uri;
			break;
		case SIPREC_VAR_TO_URI_ID:
			field = &sv->to_uri;
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
	str *instance = pv_get_siprec_instance(msg, param);
	struct srec_var *sv = get_srec_var_new(instance);

	if (!sv || !instance)
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
		case SIPREC_VAR_FROM_URI_ID:
			field = &sv->from_uri;
			break;
		case SIPREC_VAR_TO_URI_ID:
			field = &sv->to_uri;
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

int pv_parse_siprec_instance(pv_spec_p sp, const str *in)
{
	char *p, *s;
	str *instance;
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
		memset(nsp, 0, sizeof(pv_spec_t));
		s = pv_parse_spec(in, nsp);
		if(s==NULL)
		{
			LM_ERR("invalid index [%.*s]\n", in->len, in->s);
			pv_spec_free(nsp);
			return -1;
		}
		sp->pvp.pvi.type = PV_IDX_PVAR;
		sp->pvp.pvi.u.dval = (void*)nsp;
		return 0;
	}
	instance = pkg_malloc(sizeof *instance + in->len);
	if (!instance) {
		LM_ERR("could not allocate instance\n");
		return -1;
	}
	instance->s = (char *)(instance + 1);
	instance->len = in->len;
	memcpy(instance->s, in->s, in->len);
	sp->pvp.pvi.u.dval = instance;
	sp->pvp.pvi.type = PV_IDX_ALL;
	return 0;
}

int init_srec_var(void)
{
	srec_msg_idx = context_register_ptr(CONTEXT_GLOBAL, free_srec_var_inst);
	return 0;
}
