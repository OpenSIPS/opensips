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
int pv_set_isup_param(struct sip_msg* msg, pv_param_t *param, int op, pv_value_t *val);

/* script functions */
static int add_isup_part_cmd(struct sip_msg *msg, char *param);

static pv_export_t mod_items[] = {
	{{"isup_msg_type", sizeof("isup_msg_type") - 1}, 1000, pv_get_isup_msg_type,
		0, 0, 0, 0, 0},
	{{"isup_param", sizeof("isup_param") - 1}, 1000, pv_get_isup_param,
		pv_set_isup_param, pv_parse_isup_param_name, pv_parse_isup_param_index, 0, 0},
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};

static cmd_export_t cmds[] = {
	{"add_isup_part", (cmd_function)add_isup_part_cmd, 0, 0, 0, REQUEST_ROUTE | FAILURE_ROUTE |
		 ONREPLY_ROUTE | LOCAL_ROUTE},
	{"add_isup_part", (cmd_function)add_isup_part_cmd, 1, 0, 0, REQUEST_ROUTE | FAILURE_ROUTE |
		 ONREPLY_ROUTE | LOCAL_ROUTE},
	{0,0,0,0,0,0}
};

struct module_exports exports= {
	"sip_i",        	/* module's name */
	MOD_TYPE_DEFAULT,	/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, 	/* dlopen flags */
	0,           		/* OpenSIPS module dependencies */
	cmds,            	/* exported functions */
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

str isup_mime = str_init(ISUP_MIME_S);

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

	if (idx > PARAM_MAX_LEN - 1) {
		LM_ERR("Index too big!\n");
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
		if ((p->mime == ((TYPE_APPLICATION << 16) + SUBTYPE_ISUP)) ||
			(p->flags & SIP_BODY_FLAG_NEW && !str_strcmp(&p->mime_s, &isup_mime))) /* newly added isup part */
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

	parse_struct->total_len = 0;

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
		parse_struct->total_len += isup_params[isup_param_idx].len;
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
		parse_struct->total_len += parse_struct->mand_var_params[i].len;
		memcpy(parse_struct->mand_var_params[i].val, param_pointer + *(unsigned char*)param_pointer + 1,
			parse_struct->mand_var_params[i].len);

		/* 1 byte for pointer + 1 byte for length indicator + param len */
		remain_len -= (2 + parse_struct->mand_var_params[i].len);
		param_pointer++;
		offset++;
	}

	parse_struct->opt_params_list = NULL;
	parse_struct->no_opt_params = 0;

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
			parse_struct->total_len += parse_struct->opt_params_list->param.len;
			memcpy(parse_struct->opt_params_list->param.val, p->body.s + offset + 2,
					parse_struct->opt_params_list->param.len);

			parse_struct->no_opt_params++;

			remain_len -= (2 + parse_struct->opt_params_list->param.len);
			offset += 2 + parse_struct->opt_params_list->param.len;
		}
	}

	p->parsed = (void*)parse_struct;
	p->free_parsed_f = (free_parsed_part_function)free_isup_parsed;

	return parse_struct;
}

static int build_isup_body(str *buf, struct isup_parsed_struct *p)
{
	struct opt_param *it;
	int offset = 0;
	int msg_idx;
	unsigned char param_pointer = 0;
	int total_varp_len = 0;
	int i;

	msg_idx = get_msg_idx_by_type(p->message_type);
	if (msg_idx < 0)
		return -1;

	/* for each mand var param we have 2 extra bytes for the pointer and length idicator,
	 * for each opt param we have 2 extra bytes for the param code and length idicator
	 * and also, we have 1 byte for the message type code and 1 for the pointer to start of optional part(we
	 * assume is we always have this pointer) */
	buf->len = p->total_len + 2*isup_messages[msg_idx].mand_var_params + 2*p->no_opt_params + 2;
	buf->len += p->no_opt_params > 0 ? 1 : 0;	/* end of optional params byte if needed */
	buf->s = pkg_malloc(buf->len);
	if (!buf->s) {
		LM_ERR("No more pkg mem\n");
		return -1;
	}

	buf->s[0] = p->message_type;
	offset++;

	/* mandatory fixed parms */
	for (i = 0; i < isup_messages[msg_idx].mand_fixed_params; i++) {
		memcpy(buf->s + offset, p->mand_fix_params[i].val, p->mand_fix_params[i].len);
		offset += p->mand_fix_params[i].len;

	}

	/* mandatory variable params */
	for (i = 0; i < isup_messages[msg_idx].mand_var_params; i++) {
		param_pointer = isup_messages[msg_idx].mand_var_params + 1 + total_varp_len;
		total_varp_len += p->mand_var_params[i].len;

		/* param pointer */
		buf->s[offset] = param_pointer;
		/* len indicator */
		buf->s[offset + param_pointer] = p->mand_var_params[i].len;
		/* actual parameter */
		memcpy(buf->s+offset+param_pointer+1, p->mand_var_params[i].val, p->mand_var_params[i].len);

		offset++;
	}

	/* pointer to start of opt params */
	if (p->no_opt_params > 0) {
		param_pointer = 1 + isup_messages[msg_idx].mand_var_params + total_varp_len;
		buf->s[offset] = param_pointer;
	} else	/* no opt params, pointer has to be 0 */
		buf->s[offset] = 0;

	/* jump to opt params */
	offset += param_pointer;

	/* optional params */
	for (it = p->opt_params_list; it; it = it->next) {
		buf->s[offset] = it->param.param_code;
		buf->s[offset + 1] = it->param.len;
		memcpy(buf->s + offset + 2, it->param.val, it->param.len);
		offset += 2 + it->param.len;
	}

	/* end of optional parameters if needed */
	if (p->no_opt_params > 0)
		buf->s[offset] = 0;

	return 0;
}

int isup_dump(void *p, struct sip_msg *msg, str *buf)
{
	return build_isup_body(buf, (struct isup_parsed_struct *)p);
}

static int read_hex_param(char *hex_str, unsigned char *param_val, int param_len)
{
	int i;
	unsigned int byte_val;

	for (i = 0; i < param_len; i++)
		if (hexstr2int(hex_str + 2*i, 2, &byte_val) < 0)
			return -1;
		else
			param_val[i] = byte_val;

	return 0;
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
			LM_WARN("Unable to parse ISUP message\n");
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
		string2hex(p->val, p->len, buf);
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

int pv_set_isup_param(struct sip_msg* msg, pv_param_t *param, int op, pv_value_t *val)
{
	struct isup_parse_fixup *fix;
	struct body_part *isup_part;
	struct isup_parsed_struct *isup_struct;
	struct param_parsed_struct *p = NULL;
	struct opt_param *opt_p, *tmp;
	int pv_idx = -1;
	int msg_idx;
	int i;
	int param_type = -1;
	int rc;
	int new_len = 0;

	if (!param)
		return -1;
	if (!param->pvn.u.dname) {
		LM_ERR("Bad subname for $isup_param\n");
		return -1;
	}

	if (param->pvi.type == PV_IDX_INT) {
		if (param->pvi.u.ival < 0) {
			LM_ERR("Bad index for $isup_param\n");
			return -1;
		}

		pv_idx = param->pvi.u.ival;
	} /* else - index not provided */

	fix = (struct isup_parse_fixup *)param->pvn.u.dname;

	if (!msg) {
		LM_WARN("No sip msg\n");
		return -1;
	}

	/* Parse IUSP message if not done already */
	isup_part = get_isup_part(msg);
	if (!isup_part) {
		LM_INFO("No ISUP body for this message\n");
		return -1;
	}
	if (isup_part->parsed)  /* already parsed */
		isup_struct = (struct isup_parsed_struct*)isup_part->parsed;
	else {
		isup_struct = parse_isup_body(msg);
		if (!isup_struct) {
			LM_WARN("Unable to parse ISUP message\n");
			return -1;
		}
	}

	msg_idx = get_msg_idx_by_type(isup_struct->message_type);
	if (msg_idx < 0) {
		LM_ERR("BUG - Unknown ISUP message type: %d\n", isup_struct->message_type);
		return -1;
	}

	/* find required parameter in the parsed struct */
	for (i = 0; i < isup_messages[msg_idx].mand_fixed_params; i++)
		if (isup_params[fix->isup_params_idx].param_code ==
			isup_struct->mand_fix_params[i].param_code) {
			p = isup_struct->mand_fix_params + i;
			param_type = 0;
			break;
		}
	if (!p)
		for (i = 0; i < isup_messages[msg_idx].mand_var_params; i++)
			if (isup_params[fix->isup_params_idx].param_code ==
				isup_struct->mand_var_params[i].param_code) {
				p = isup_struct->mand_var_params + i;
				param_type = 1;
				break;
			}
	if (!p)
		for (opt_p = isup_struct->opt_params_list; opt_p; opt_p = opt_p->next)
			if (isup_params[fix->isup_params_idx].param_code == opt_p->param.param_code) {
				p = &opt_p->param;
				param_type = 2;
				break;
			}
	if (!p) {	/* param not found in parsed struct so it should be a new optional param */
		opt_p = pkg_malloc(sizeof *opt_p);
		opt_p->next = isup_struct->opt_params_list;
		memset(&opt_p->param, 0, sizeof(struct param_parsed_struct));
		opt_p->param.param_code = isup_params[fix->isup_params_idx].param_code;
		isup_struct->opt_params_list = opt_p;
		isup_struct->no_opt_params++;
		p = &opt_p->param;
		param_type = 3;
	}

	if (isup_params[fix->isup_params_idx].write_func && fix->subfield_id) {
		if (pv_idx >= 0)
			LM_INFO("Ignoring index for ISUP param: %.*s, known subfield provided\n",
				isup_params[fix->isup_params_idx].name.len, isup_params[fix->isup_params_idx].name.s);

		new_len = p->len;
		rc = isup_params[fix->isup_params_idx].write_func(fix->subfield_id, p->val, &new_len, val);
		if (new_len != p->len)
			isup_struct->total_len += new_len - p->len;
		p->len = new_len;
		if (rc < 0) {
			LM_WARN("Unable to write $isup_param(%*.s)\n",
				isup_params[fix->isup_params_idx].name.len, isup_params[fix->isup_params_idx].name.s);
			return -1;
		}

		isup_part->dump_f = (dump_part_function)isup_dump;

		return 0;
	} else if (!isup_params[fix->isup_params_idx].write_func && fix->subfield_id) {
		LM_ERR("BUG - Subfield known but no specific parse function\n");
		return -1;
	}

	if (pv_idx < 0) {	/* we don't have an index, read whole param from hex str */

		if (val == NULL || val->flags & PV_VAL_NULL) {
			if (param_type < 2)	/* for mandatory params, fill with 0 */
				memset(p->val, 0, p->len);
			else {	/* if opt param, remove param from message */
				opt_p = isup_struct->opt_params_list;
				if (opt_p->param.param_code == p->param_code) {
					isup_struct->opt_params_list = opt_p->next;
					isup_struct->no_opt_params--;
					pkg_free(opt_p);
				} else
					for (; opt_p->next; opt_p = opt_p->next)
						if (opt_p->next->param.param_code == p->param_code) {
							tmp = opt_p->next;
							opt_p->next = opt_p->next->next;
							isup_struct->no_opt_params--;
							pkg_free(tmp);
							break;
						}
			}

			isup_part->dump_f = (dump_part_function)isup_dump;
		} else if (val->flags & PV_TYPE_INT || val->flags & PV_VAL_INT) {
			LM_WARN("Hex string value required for $isup_param(%*.s)\n",
				isup_params[fix->isup_params_idx].name.len, isup_params[fix->isup_params_idx].name.s);

			return -1;
		} else if (val->flags & PV_VAL_STR) {
			if (param_type == 0 && val->rs.len/2 != isup_params[fix->isup_params_idx].len) {
				LM_WARN("Incorrect length: %d for $isup_param(%.*s), it must be exactly: %d\n",
					val->rs.len/2, isup_params[fix->isup_params_idx].name.len,
					isup_params[fix->isup_params_idx].name.s, isup_params[fix->isup_params_idx].len);
					return -1;
			}

			if (param_type == 3)	/* new optional param */
				isup_struct->total_len += val->rs.len/2;
			else if (param_type == 1 || param_type == 2)
				isup_struct->total_len += val->rs.len/2 - p->len;

			p->len = val->rs.len/2;

			if (read_hex_param(val->rs.s, p->val, p->len) < 0) {
				LM_WARN("Invalid hex value for $isup_param(%*.s)\n",
					isup_params[fix->isup_params_idx].name.len, isup_params[fix->isup_params_idx].name.s);
				return -1;
			}

			isup_part->dump_f = (dump_part_function)isup_dump;
		} else {
			LM_ERR("Invalid value for $isup_param\n");
			return -1;
		}

	} else {	/* we have an index, set the corresponding byte */

		if (param_type == 0 && pv_idx > p->len - 1) { /* fixed length exceeded */
			LM_ERR("Index: %d out of bounds, fixed parameter length is: %d\n", pv_idx, p->len);
			return -1;
		}

		if (val == NULL || val->flags & PV_VAL_NULL) {
			if (pv_idx > p->len - 1) {	/* extending the param */
				/* fill the rest of the bytes up to the index with 0 */
				memset(p->val + p->len, 0, pv_idx - p->len);
				isup_struct->total_len += pv_idx + 1 - p->len;
				p->len = pv_idx + 1;
			}

			p->val[pv_idx] = 0;

			isup_part->dump_f = (dump_part_function)isup_dump;
		} else if (val->flags & PV_TYPE_INT || val->flags & PV_VAL_INT) {
			if (pv_idx > p->len - 1) {	/* extending the param */
				/* fill the rest of the bytes up to the index with 0 */
				memset(p->val + p->len, 0, pv_idx - p->len);
				isup_struct->total_len += pv_idx + 1 - p->len;
				p->len = pv_idx + 1;
			}

			p->val[pv_idx] = val->ri;

			isup_part->dump_f = (dump_part_function)isup_dump;
		} else if (val->flags & PV_VAL_STR) {
			LM_WARN("Integer value required for %d byte of $isup_param(%*.s)\n", pv_idx,
				isup_params[fix->isup_params_idx].name.len, isup_params[fix->isup_params_idx].name.s);
			return -1;
		} else {
			LM_ERR("Invalid value for $isup_param\n");
			return -1;
		}
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

static int add_isup_part_cmd(struct sip_msg *msg, char *param)
{
	struct isup_parsed_struct *isup_struct;
	struct body_part *isup_part;
	int isup_msg_idx = -1;
	str param_msg_type;
	int i;

	/* if isup message type not provided as param, try to map sip msg to
	 * isup msg type by defaault */
	if (!param) {
		if (msg->first_line.type == SIP_REQUEST) {
			if (msg->REQ_METHOD == METHOD_INVITE) {
				/* INVITE -> IAM */
				isup_msg_idx = get_msg_idx_by_type(ISUP_IAM);
			} else if (msg->REQ_METHOD == METHOD_BYE) {
				/* BYE -> REL */
				isup_msg_idx = get_msg_idx_by_type(ISUP_REL);
			} else {
				LM_WARN("Could not map SIP message to ISUP message type by default\n");
				return -1;
			}
		} else if (msg->first_line.type == SIP_REPLY) {
			if (msg->REPLY_STATUS == 180 || msg->REPLY_STATUS == 183)
				/* 180, 183 -> ACM */
				isup_msg_idx = get_msg_idx_by_type(ISUP_ACM);
			else if (msg->REPLY_STATUS/100 == 4 || msg->REPLY_STATUS/100 == 5)
				/* 4xx, 5xx -> REL */
				isup_msg_idx = get_msg_idx_by_type(ISUP_REL);
			else if (msg->REPLY_STATUS == 200) {
				if (get_cseq(msg)->method_id == METHOD_INVITE)
					/* 200 OK INVITE -> ANM */
					isup_msg_idx = get_msg_idx_by_type(ISUP_REL);
				else if (get_cseq(msg)->method_id == METHOD_BYE)
					/* 200 OK INVITE -> RLC */
					isup_msg_idx = get_msg_idx_by_type(ISUP_RLC);
				else {
					LM_WARN("Could not map SIP message to ISUP message type by default\n");
					return -1;
				}
			} else {
				LM_WARN("Could not map SIP message to ISUP message type by default\n");
				return -1;
			}
		} else {
			LM_ERR("Invalid SIP message\n");
			return -1;
		}
	} else {
		param_msg_type.len = strlen(param);
		param_msg_type.s = param;

		for (i = 0; i < NO_ISUP_MESSAGES; i++)
			if (!str_strcasecmp(&isup_messages[i].name, &param_msg_type)) {
				isup_msg_idx = get_param_idx_by_code(isup_messages[i].message_type);
				break;
			}

		if (isup_msg_idx < 0) {
			LM_ERR("Unknown ISUP message type\n");
			return -1;
		}
	}

	/* build a blank isup message (no optional params, all mandatory params zeroed) */

	isup_struct = pkg_malloc(sizeof(struct isup_parsed_struct));
	if (!isup_struct) {
		LM_ERR("No more pkg mem for isup struct\n");
		return -1;
	}

	memset(isup_struct, 0, sizeof(struct isup_parsed_struct));

	isup_struct->message_type = isup_messages[isup_msg_idx].message_type;

	for (i = 0; i < isup_messages[isup_msg_idx].mand_fixed_params; i++) {
		isup_struct->mand_fix_params[i].param_code =
			isup_messages[isup_msg_idx].mand_param_list[i];
		isup_struct->mand_fix_params[i].len =
			isup_params[get_param_idx_by_code(isup_messages[isup_msg_idx].mand_param_list[i])].len;

		isup_struct->total_len += isup_struct->mand_fix_params[i].len;
	}

	for (i = 0; i < isup_messages[isup_msg_idx].mand_var_params; i++)
		isup_struct->mand_var_params[i].param_code =
			isup_messages[isup_msg_idx].mand_param_list[isup_messages[isup_msg_idx].mand_fixed_params+i];

	isup_part = add_body_part(msg, &isup_mime, NULL);
	if (!isup_part) {
		LM_ERR("Failed to add isup body part\n");
		return -1;
	}

	isup_part->parsed = isup_struct;
	isup_part->dump_f = (dump_part_function)isup_dump;
	isup_part->free_parsed_f = (free_parsed_part_function)free_isup_parsed;

	return 1;
}