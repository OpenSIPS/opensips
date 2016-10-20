/**
 *
 * Copyright (C) 2016 OpenSIPS Foundation
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * History
 * -------
 *  2016-09-xx  initial version (rvlad-patrascu)
 */

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../pvar.h"
#include "../../ut.h"
#include "../../parser/parse_body.h"
#include "isup.h"
#include "sip_i.h"

static int mod_init(void);
static int child_init(int rank);
static void mod_destroy(void);

/* $isup_msg_type */
int pv_get_isup_msg_type(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
/* $isup_param */
int pv_parse_isup_param_name(pv_spec_p sp, str *in);
int pv_parse_isup_param_index(pv_spec_p sp, str* in);
int pv_get_isup_param(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);

static pv_export_t mod_items[] = {
	{{"isup_msg_type", sizeof("isup_msg_type") - 1}, 1000, pv_get_isup_msg_type,
		0, 0, 0, 0, 0},
	{{"isup_param", sizeof("isup_param") - 1}, 1000, pv_get_isup_param,
		0, pv_parse_isup_param_name, pv_parse_isup_param_index, 0, 0},
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};

struct module_exports exports= {
	"sip_i",        	/* module's name */
	MOD_TYPE_DEFAULT,	/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, 	/* dlopen flags */
	0,           		/* OpenSIPS module dependencies */
	0,            		/* exported functions */
	0,               	/* exported async functions */
	0,      			/* param exports */
	0,       			/* exported statistics */
	0,         			/* exported MI functions */
	mod_items,       	/* exported pseudo-variables */
	0,               	/* extra processes */
	mod_init,        	/* module initialization function */
	0,               	/* reply processing function */
	mod_destroy,
	child_init       	/* per-child init function */
};

static int mod_init(void)
{
	return 0;
}

static void mod_destroy(void)
{
	return;
}

static int child_init(int rank)
{
	return 0;
}

int pv_parse_isup_param_name(pv_spec_p sp, str *in)
{
	str param_s = {0, 0}, subfield_s = {0, 0};
	int i, j;
	struct isup_parse_fixup *parse_fix;
	int isup_params_idx, subfield_id;

	if (!in || !in->s || !in->len) {
		LM_ERR("Bad subname for $isup_param\n");
		return -1;
	}
	if (!sp) {
		LM_ERR("Bad pv spec for $isup_param\n");
		return -1;
	}

	param_s.s = in->s;

	subfield_s.s = q_memchr(in->s, DEFAULT_PARAM_SUBF_SEP, in->len);

	if (subfield_s.s) {
		param_s.len = subfield_s.s - param_s.s;
		subfield_s.len = in->len - param_s.len - 1;

		if (!subfield_s.len) {
			LM_ERR("Bad subfield for ISUP paramater: %.*s\n", param_s.len, param_s.s);
			return -1;
		}

		subfield_s.s++;	/* skip delimiter */

		str_trim_spaces_lr(param_s);
		str_trim_spaces_lr(subfield_s);
	} else {
		param_s.len = in->len;
		str_trim_spaces_lr(param_s);
	}

	/* search provided param in isup params list */
	for (i = 0; i < NO_ISUP_PARAMS; i++) {
		if (!str_strcasecmp(&param_s, &isup_params[i].name)) {
			isup_params_idx = i;

			/* if we parsed a subfield, search in the known subfields for this param */
			if (subfield_s.s && subfield_s.len) {
				if (!isup_params[i].subfield_list) {
					subfield_id = 0;
					LM_INFO("No subfields defined for ISUP parameter: %.*s, returning whole parameter\n",
						isup_params[i].name.len, isup_params[i].name.s);
					break;
				}

				for (j = 0; isup_params[i].subfield_list[j].id; j++) {
					if (!str_strcasecmp(&subfield_s, &isup_params[i].subfield_list[j].name)) {
						subfield_id = isup_params[i].subfield_list[j].id;
						break;
					}
				}
				if (!isup_params[i].subfield_list[j].id) {
					subfield_id = 0;
					LM_INFO("Unknown subfield: %.*s for ISUP parameter: %.*s, returning whole parameter\n",
						subfield_s.len, subfield_s.s, isup_params[i].name.len, isup_params[i].name.s);
				}
			} else /* return whole parameter */
				subfield_id = 0;

			break;
		}
	}
	if (i == NO_ISUP_PARAMS) {
		LM_ERR("Unknown ISUP parameter: %.*s\n", param_s.len, param_s.s);
		return -1;
	}

	parse_fix = pkg_malloc(sizeof(struct isup_parse_fixup));
	if (!parse_fix) {
		LM_ERR("No more pkg mem!\n");
		return -1;
	}

	parse_fix->isup_params_idx = isup_params_idx;
	parse_fix->subfield_id = subfield_id;

	sp->pvp.pvn.type = PV_NAME_PVAR;
	sp->pvp.pvn.u.dname = (void *)parse_fix;
	sp->pvp.pvv.s = NULL;
	sp->pvp.pvv.len = 0;

	return 0;
}

int pv_parse_isup_param_index(pv_spec_p sp, str* in)
{
	int idx;

	LM_DBG("PPP Entering index parsing function\n");

	if (!in || !in->s || !in->len) {
		LM_ERR("Bad index for $isup_param\n");
		return -1;
	}
	if (!sp) {
		LM_ERR("Bad pv spec for $isup_param\n");
		return -1;
	}

	if (!sp->pvp.pvn.u.dname) {
		LM_ERR("Subname for $isup_param was not parsed successfully\n");
		return -1;
	}

	if (str2sint(in, &idx) < 0) {
		LM_ERR("Bad index! not a number! <%.*s>!\n", in->len, in->s);
		return -1;
	}
	if (idx < 0) {
		LM_ERR("Bad index! negative value!\n");
		return -1;
	}

	sp->pvp.pvi.type = PV_IDX_INT;
	sp->pvp.pvi.u.ival = idx;

	return 0;
}

void free_isup_parsed(void *param)
{
	struct opt_param *it, *tmp;

	it = ((struct isup_parsed_struct *)param)->opt_params_list;
	while (it) {
		tmp = it;
		it = it->next;
		pkg_free(tmp);
	}

	pkg_free(param);
}

static struct body_part *get_isup_part(struct sip_msg *msg)
{
	struct body_part *p;

	if (parse_sip_body(msg) < 0) {
		LM_ERR("Unable to parse body\n");
		return NULL;
	}

	if (!msg->body) {
		LM_INFO("No body found\n");
		return NULL;
	}

	for (p = &msg->body->first; p; p = p->next)
		if (p->mime == ((TYPE_APPLICATION << 16) + SUBTYPE_ISUP))
			return p;

	return NULL;
}

static struct isup_parsed_struct *parse_isup_body(struct sip_msg *msg)
{
	struct isup_parsed_struct *parse_struct;
	struct body_part *p;
	int remain_len;
	int offset = 0;
	int i;
	int msg_idx = -1, isup_param_idx = -1;
	char *param_pointer;
	struct opt_param *new;

	p = get_isup_part(msg);
	if (!p) {
		LM_INFO("No ISUP body for this message\n");
		return NULL;
	}

	if (p->body.len == 0) {
		LM_WARN("empty ISUP body\n");
		return NULL;
	}

	remain_len = p->body.len;

	parse_struct = pkg_malloc(sizeof(struct isup_parsed_struct));
	if (!parse_struct) {
		LM_ERR("No more pkg mem for isup parse struct\n");
		return NULL;
	}

	/* parse message type */
	parse_struct->message_type = *(unsigned char*)p->body.s;
	offset++;
	remain_len--;

	msg_idx = get_msg_idx_by_type(parse_struct->message_type);
	if (msg_idx < 0) {
		LM_ERR("Unknown ISUP message type\n");
		return NULL;
	}

	/* parse mandatory fixed parms */
	for (i = 0; i < isup_messages[msg_idx].mand_fixed_params; i++) {
		parse_struct->mand_fix_params[i].param_code = isup_messages[msg_idx].mand_param_list[i];

		isup_param_idx = get_param_idx_by_code(isup_messages[msg_idx].mand_param_list[i]);
		if (isup_param_idx < 0) {
			LM_ERR("BUG - isup param not found in the isup params list\n");
			return NULL;

		}

		parse_struct->mand_fix_params[i].len = isup_params[isup_param_idx].len;
		memcpy(parse_struct->mand_fix_params[i].val, p->body.s + offset,
				isup_params[isup_param_idx].len);

		remain_len -= isup_params[isup_param_idx].len;
		offset += isup_params[isup_param_idx].len;
	}

	param_pointer = p->body.s + offset;

	/* parse mandatory variable params */
	for (i = 0; i < isup_messages[msg_idx].mand_var_params && remain_len > 0 && *param_pointer; i++) {
		parse_struct->mand_var_params[i].param_code =
			isup_messages[msg_idx].mand_param_list[isup_messages[msg_idx].mand_fixed_params + i];

		parse_struct->mand_var_params[i].len =
			*(unsigned char*)(param_pointer + *(unsigned char*)param_pointer);
		memcpy(parse_struct->mand_var_params[i].val, param_pointer + *(unsigned char*)param_pointer + 1,
			parse_struct->mand_var_params[i].len);

		/* 1 byte for pointer + 1 byte for length indicator + param len */
		remain_len -= (2 + parse_struct->mand_var_params[i].len);
		param_pointer++;
		offset++;
	}

	parse_struct->opt_params_list = NULL;

	/* parse optional params */
	if (remain_len > 0 && *param_pointer) {
		offset += *(unsigned char*)param_pointer;
		remain_len-- ;	/* optional parameter pointer */

		for (i = 0; remain_len > 0 && *(p->body.s + offset); i++) {
			new = pkg_malloc(sizeof *new);
			new->next = parse_struct->opt_params_list;
			parse_struct->opt_params_list = new;

			parse_struct->opt_params_list->param.param_code = *(unsigned char *)(p->body.s + offset);

			parse_struct->opt_params_list->param.len = *(unsigned char *)(p->body.s + offset + 1);
			memcpy(parse_struct->opt_params_list->param.val, p->body.s + offset + 2,
					parse_struct->opt_params_list->param.len);

			remain_len -= (2 + parse_struct->opt_params_list->param.len);
			offset += 2 + parse_struct->opt_params_list->param.len;
		}
	}

	p->parsed = (void*)parse_struct;
	p->free_parsed_f = (free_parsed_part_function)free_isup_parsed;

	return parse_struct;
}

static void print_hex(char *hex_str, unsigned char *val, int len)
{
	int i;

	for (i = 0; i < len; i++)
		sprintf(hex_str + 2*i, "%02x", val[i]);
}

int pv_get_isup_param(struct sip_msg *msg, pv_param_t *param, pv_value_t *res)
{
	struct body_part *isup_part;
	struct isup_parse_fixup *fix;
	struct isup_parsed_struct *parse_struct;
	int pv_idx = -1;
	struct param_parsed_struct *p = NULL;
	struct opt_param *opt_p;
	int i;
	int msg_idx;
	char *ch;
	int l;
	int int_res = -1;
	static char buf[PV_RES_BUF_MAXLEN];
	str str_res = {buf, 0};

	if (!param)
		return -1;

	if (!param->pvn.u.dname) {
		LM_ERR("Bad subname for $isup_param\n");
		return pv_get_null(msg, param, res);
	}

	if (param->pvi.type == PV_IDX_INT) {
		if (param->pvi.u.ival < 0) {
			LM_ERR("Bad index for $isup_param\n");
			return pv_get_null(msg, param, res);
		}

		pv_idx = param->pvi.u.ival;
	} /* else - index not provided */

	fix = (struct isup_parse_fixup *)param->pvn.u.dname;

	if (!msg) {
		LM_WARN("No sip msg\n");
		return pv_get_null(msg, param, res);
	}

	/* Parse IUSP message if not done already */
	isup_part = get_isup_part(msg);
	if (!isup_part) {
		LM_INFO("No ISUP body for this message\n");
		return pv_get_null(msg, param, res);
	}
	if (isup_part->parsed)  /* already parsed */
		parse_struct = (struct isup_parsed_struct*)isup_part->parsed;
	else {
		parse_struct = parse_isup_body(msg);
		if (!parse_struct) {
			LM_DBG("Unable to parse ISUP message\n");
			return pv_get_null(msg, param, res);
		}
	}

	msg_idx = get_msg_idx_by_type(parse_struct->message_type);
	if (msg_idx < 0) {
		LM_ERR("BUG - Unknown ISUP message type: %d\n", parse_struct->message_type);
		return pv_get_null(msg, param, res);
	}

	/* find required parameter in the parse struct */
	for (i = 0; i < isup_messages[msg_idx].mand_fixed_params; i++)
		if (isup_params[fix->isup_params_idx].param_code ==
			parse_struct->mand_fix_params[i].param_code) {
			p = parse_struct->mand_fix_params + i;
			break;
		}
	if (!p)
		for (i = 0; i < isup_messages[msg_idx].mand_var_params; i++)
			if (isup_params[fix->isup_params_idx].param_code ==
				parse_struct->mand_var_params[i].param_code) {
				p = parse_struct->mand_var_params + i;
				break;
			}
	if (!p)
		for (opt_p = parse_struct->opt_params_list; opt_p; opt_p = opt_p->next)
			if (isup_params[fix->isup_params_idx].param_code == opt_p->param.param_code) {
				p = &opt_p->param;
				break;
			}
	if (!p) {
		LM_INFO("parameter: %.*s not found in this ISUP message\n",
			isup_params[fix->isup_params_idx].name.len, isup_params[fix->isup_params_idx].name.s);
		return pv_get_null(msg, param, res);
	}

	if (isup_params[fix->isup_params_idx].parse_func && fix->subfield_id) {
		if (pv_idx >= 0)
			LM_INFO("Ignoring index for ISUP param: %.*s, known subfield provided\n",
				isup_params[fix->isup_params_idx].name.len, isup_params[fix->isup_params_idx].name.s);

		isup_params[fix->isup_params_idx].parse_func(fix->subfield_id, p->val, p->len,
														&int_res, &str_res);

		/* int or str val according to parse function for this subfield */
		if (int_res != -1) {
			ch = int2str(int_res, &l);
			res->rs.s = ch;
			res->rs.len = l;
			res->ri = int_res;
			res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;
		} else {
			res->rs.len = str_res.len;
			res->rs.s = str_res.s;
			res->flags = PV_VAL_STR;
		}

		return 0;
	} else if (!isup_params[fix->isup_params_idx].parse_func && fix->subfield_id) {
		LM_ERR("BUG - Subfield known but no specific parse function\n");
		return pv_get_null(msg, param, res);
	}

	if (pv_idx < 0) {	/* we don't have an index, print whole param as hex */
		print_hex(buf, p->val, p->len);
		res->flags = PV_VAL_STR;
		res->rs.len = 2 * p->len;
		res->rs.s = buf;
	} else {
		if (pv_idx > p->len - 1) {
			LM_ERR("Index: %d out of bounds, parameter length is: %d\n", pv_idx, p->len);
			return pv_get_null(msg, param, res);
		}
		ch = int2str(p->val[pv_idx], &l);
		res->rs.s = ch;
		res->rs.len = l;
		res->ri = p->val[pv_idx];
		res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;
	}

	return 0;
}

int pv_get_isup_msg_type(struct sip_msg *msg, pv_param_t *param, pv_value_t *res)
{
	struct body_part *p;
	int msg_idx = -1;

	p = get_isup_part(msg);
	if (!p) {
		LM_INFO("No ISUP body for this message\n");
		return pv_get_null(msg, param, res);
	}

	if (p->body.len == 0) {
		LM_WARN("empty ISUP body\n");
		return pv_get_null(msg, param, res);
	}

	msg_idx = get_msg_idx_by_type(*(unsigned char*)p->body.s);
	if (msg_idx < 0) {
		LM_ERR("Unknown ISUP message type\n");
		return pv_get_null(msg, param, res);
	}

	res->flags = PV_VAL_STR;
	res->rs.s = isup_messages[msg_idx].name.s;
	res->rs.len = isup_messages[msg_idx].name.len;

	return 0;
}

