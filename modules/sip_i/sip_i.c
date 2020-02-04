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
#include "../../trim.h"
#include "../../mod_fix.h"
#include "../../parser/parse_body.h"
#include "../../parser/parse_pai.h"
#include "../../parser/parse_privacy.h"
#include "../../parser/parse_uri.h"
#include "../../transformations.h"
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
int pv_get_isup_param_str(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
int pv_set_isup_param(struct sip_msg* msg, pv_param_t *param, int op, pv_value_t *val);

/* script functions */
static int add_isup_part_cmd(struct sip_msg *msg, str *msg_type, str *hdrs);

/* script transformations */
int tr_isup_parse(str* in, trans_t *t);
int tr_isup_eval(struct sip_msg *msg, tr_param_t *tp, int subtype,
		pv_value_t *val);

static trans_export_t trans[] = {
	{str_init("isup"), tr_isup_parse, tr_isup_eval},
	{{0,0},0,0}
};

static pv_export_t mod_items[] = {
	{{"isup_msg_type", sizeof("isup_msg_type") - 1}, 1000, pv_get_isup_msg_type,
		0, 0, 0, 0, 0},
	{{"isup_param", sizeof("isup_param") - 1}, 1000, pv_get_isup_param,
		pv_set_isup_param, pv_parse_isup_param_name, pv_parse_isup_param_index, 0, 0},
	{{"isup_param_str", sizeof("isup_param_str") - 1}, 1000, pv_get_isup_param_str,
		0, pv_parse_isup_param_name, 0, 0, 0},
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};

static cmd_export_t cmds[] = {
	{"add_isup_part", (cmd_function)add_isup_part_cmd, {
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|ONREPLY_ROUTE|LOCAL_ROUTE|BRANCH_ROUTE},
	{0,0,{{0,0,0}},0}
};

static str param_subf_sep = str_init(DEFAULT_PARAM_SUBF_SEP);
static str isup_mime = str_init(ISUP_MIME_S);
static str country_code = str_init(DEFAULT_COUNTRY_CODE);
static str default_part_headers = str_init(DEFAULT_PART_HEADERS);

static param_export_t params[] = {
	{"param_subfield_separator", STR_PARAM, &param_subf_sep.s},
	{"isup_mime_str", STR_PARAM, &isup_mime.s},
	{"country_code", STR_PARAM, &country_code.s},
	{"default_part_headers", STR_PARAM, &default_part_headers.s},
	{0,0,0}
};

struct module_exports exports= {
	"sip_i",        	/* module's name */
	MOD_TYPE_DEFAULT,	/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, 	/* dlopen flags */
	0,				 	/* load function */
	0,           		/* OpenSIPS module dependencies */
	cmds,            	/* exported functions */
	0,               	/* exported async functions */
	params,      			/* param exports */
	0,       			/* exported statistics */
	0,         			/* exported MI functions */
	mod_items,       	/* exported pseudo-variables */
	trans,					/* exported transformations */
	0,               	/* extra processes */
	0,               	/* module pre-initialization function */
	mod_init,        	/* module initialization function */
	0,               	/* reply processing function */
	mod_destroy,
	child_init,       	/* per-child init function */
	0					/* reload confirm function */
};

static int mod_init(void)
{
	/* update the len of the str's, if changed via modparam */
	param_subf_sep.len = strlen( param_subf_sep.s );
	isup_mime.len = strlen( isup_mime.s );
	country_code.len = strlen( country_code.s );
	if (country_code.len < 2 || country_code.len > 4) {
		LM_ERR("Invalid country code parameter, must be a \"+\" sign "
			"followed by 1-3 digits\n");
		return -1;
	}
	default_part_headers.len = strlen( default_part_headers.s );

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

static inline unsigned int get_param_idx_by_code(int param_code)
{
	int i;

	for (i = 0; i < NO_ISUP_PARAMS; i++)
		if (param_code == isup_params[i].param_code)
			return i;

	return PARM_INVAL_IDX;
}

static inline int get_msg_idx_by_type(int msg_type)
{
	int i;

	for (i = 0; i < NO_ISUP_MESSAGES; i++)
		if (msg_type == isup_messages[i].message_type)
			return i;
	return -1;
}

int pv_parse_isup_param_name(pv_spec_p sp, str *in)
{
	str param_s = {0, 0}, subfield_s = {0, 0};
	int i, j;
	struct isup_parse_fixup *parse_fix;
	int isup_params_idx, subfield_idx = -1;

	if (!in || !in->s || !in->len) {
		LM_ERR("Bad subname for $isup_param\n");
		return -1;
	}
	if (!sp) {
		LM_ERR("Bad pv spec for $isup_param\n");
		return -1;
	}

	param_s.s = in->s;

	subfield_s.s = q_memchr(in->s, param_subf_sep.s[0], in->len);

	if (subfield_s.s) {
		param_s.len = subfield_s.s - param_s.s;
		subfield_s.len = in->len - param_s.len - 1;

		if (!subfield_s.len) {
			LM_ERR("Bad subfield for ISUP parameter: %.*s\n", param_s.len, param_s.s);
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
		if (str_strcasecmp(&param_s, &isup_params[i].name) == 0) {
			isup_params_idx = i;

			/* if we parsed a subfield, search in the known subfields for this param */
			if (subfield_s.s && subfield_s.len) {
				if (!isup_params[i].subfield_list) {
					subfield_idx = -1;
					LM_ERR("No subfields supported for ISUP parameter <%.*s>\n",
						isup_params[i].name.len, isup_params[i].name.s);
					return -1;
				}

				for (j = 0; isup_params[i].subfield_list[j].name.s; j++) {
					if (str_strcasecmp(&subfield_s, &isup_params[i].subfield_list[j].name) == 0) {
						subfield_idx = j;
						break;
					}
				}
				if (subfield_idx < 0) {
					LM_ERR("Unknown subfield <%.*s> for ISUP parameter <%.*s>\n",
						subfield_s.len, subfield_s.s, isup_params[i].name.len, isup_params[i].name.s);
					return -1;
				}
			} else /* return whole parameter */
				subfield_idx = -1;

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
	parse_fix->subfield_idx = subfield_idx;

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

void free_isup_parsed(void *parsed, osips_free_f free_f)
{
	struct opt_param *it, *tmp;

	it = ((struct isup_parsed_struct *)parsed)->opt_params_list;
	while (it) {
		tmp = it;
		it = it->next;
		func_free(free_f, tmp);
	}

	func_free(free_f, parsed);
}

void *clone_isup_parsed(struct body_part *old_part, struct body_part *new_part,
			struct sip_msg *src_msg, struct sip_msg *dst_msg, osips_malloc_f malloc_f)
{
	struct isup_parsed_struct *new_ps, *old_ps;
	struct opt_param *optp_it, *optp_new = NULL, *optp_prev = NULL;

	if (!old_part) {
		LM_ERR("No old ISUP body part\n");
		return NULL;
	}

	old_ps = (struct isup_parsed_struct *)old_part->parsed;
	if (!old_ps) {
		LM_ERR("Old parsed data not found\n");
		return NULL;
	}

	new_ps = func_malloc(malloc_f, sizeof(struct isup_parsed_struct));
	if (!new_ps) {
		LM_ERR("No more pkg mem for cloned data\n");
		return NULL;
	}

	memcpy(new_ps, old_ps, sizeof(struct isup_parsed_struct));
	new_ps->opt_params_list = NULL;

	/* clone list of optional params */
	for (optp_it = old_ps->opt_params_list; optp_it; optp_it = optp_it->next) {
		optp_new = func_malloc(malloc_f, sizeof(struct opt_param));
		if (!optp_new) {
			LM_ERR("No more pkg mem\n");
			return NULL;
		}

		if (optp_it == old_ps->opt_params_list)
			new_ps->opt_params_list = optp_new;

		memcpy(optp_new, optp_it, sizeof(struct opt_param));
		optp_new->next = NULL;
		if (optp_prev)
			optp_prev->next = optp_new;
		optp_prev = optp_new;
	}

	return (void *)new_ps;
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
			(p->flags & SIP_BODY_PART_FLAG_NEW && !str_strcmp(&p->mime_s, &isup_mime))) /* newly added isup part */
			return p;

	return NULL;
}

static struct isup_parsed_struct *parse_isup(str isup_buffer)
{
	struct isup_parsed_struct *parse_struct = NULL;
	int remain_len;
	int offset = 0;
	int i;
	int msg_idx = -1, isup_param_idx = -1;
	char *param_pointer;
	struct opt_param *new = NULL;

	parse_struct = pkg_malloc(sizeof(struct isup_parsed_struct));
	if (!parse_struct) {
		LM_ERR("No more pkg mem for isup parse struct\n");
		return NULL;
	}

	remain_len = isup_buffer.len;

	parse_struct->total_len = 0;

	/* parse message type */
	parse_struct->message_type = *(unsigned char*)isup_buffer.s;
	offset++;
	remain_len--;

	msg_idx = get_msg_idx_by_type(parse_struct->message_type);
	if (msg_idx < 0) {
		LM_ERR("Unknown ISUP message type\n");
		goto error;
	}

	/* parse mandatory fixed parms */
	for (i = 0; i < isup_messages[msg_idx].mand_fixed_params; i++) {
		parse_struct->mand_fix_params[i].param_code =
							isup_messages[msg_idx].mand_param_list[i];

		isup_param_idx = get_param_idx_by_code(isup_messages[msg_idx].mand_param_list[i]);

		parse_struct->mand_fix_params[i].len = isup_params[isup_param_idx].len;
		parse_struct->total_len += isup_params[isup_param_idx].len;

		memcpy(parse_struct->mand_fix_params[i].val, isup_buffer.s + offset,
				isup_params[isup_param_idx].len);

		remain_len -= isup_params[isup_param_idx].len;
		offset += isup_params[isup_param_idx].len;
	}

	param_pointer = isup_buffer.s + offset;

	/* parse mandatory variable params */
	for (i = 0; i < isup_messages[msg_idx].mand_var_params && remain_len > 0 &&
															*param_pointer; i++) {
		parse_struct->mand_var_params[i].param_code =
			isup_messages[msg_idx].mand_param_list[
									isup_messages[msg_idx].mand_fixed_params + i];

		parse_struct->mand_var_params[i].len =
			*(unsigned char*)(param_pointer + *(unsigned char*)param_pointer);

		parse_struct->total_len += parse_struct->mand_var_params[i].len;

		memcpy(parse_struct->mand_var_params[i].val,
			param_pointer + *(unsigned char*)param_pointer + 1,
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

		for (i = 0; remain_len > 0 && *(isup_buffer.s + offset); i++) {
			new = pkg_malloc(sizeof *new);
			if (!new) {
				LM_ERR("No more pkg memory\n");
				goto error;
			}
			new->next = parse_struct->opt_params_list;
			parse_struct->opt_params_list = new;

			parse_struct->opt_params_list->param.param_code =
									*(unsigned char *)(isup_buffer.s + offset);

			parse_struct->opt_params_list->param.len =
								*(unsigned char *)(isup_buffer.s + offset + 1);

			parse_struct->total_len += parse_struct->opt_params_list->param.len;

			memcpy(parse_struct->opt_params_list->param.val,
				isup_buffer.s + offset + 2, parse_struct->opt_params_list->param.len);

			parse_struct->no_opt_params++;

			remain_len -= (2 + parse_struct->opt_params_list->param.len);
			offset += 2 + parse_struct->opt_params_list->param.len;
		}
	}

	return parse_struct;

error:
	if (parse_struct)
		pkg_free(parse_struct);
	return NULL;
}

static struct isup_parsed_struct *parse_isup_body(struct sip_msg *msg)
{
	struct isup_parsed_struct *parse_struct;
	struct body_part *p;

	p = get_isup_part(msg);
	if (!p) {
		LM_INFO("No ISUP body for this message\n");
		return NULL;
	}

	if (p->body.len == 0) {
		LM_WARN("empty ISUP body\n");
		return NULL;
	}

	parse_struct = parse_isup(p->body);
	if (!parse_struct)
		return NULL;

	p->parsed = (void*)parse_struct;
	p->free_parsed_f = (free_parsed_part_function)free_isup_parsed;
	p->clone_parsed_f = (clone_parsed_part_function)clone_isup_parsed;

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

	if (hex_str[0] != '0')
		return -1;
	if (hex_str[1] != 'x')
		return -1;
	hex_str += 2;

	for (i = 0; i < param_len; i++)
		if (hexstr2int(hex_str + 2*i, 2, &byte_val) < 0)
			return -1;
		else
			param_val[i] = byte_val;

	return 0;
}

struct param_parsed_struct *get_isup_param(struct isup_parsed_struct *parse_struct,
											int isup_params_idx, int *param_type)
{
	struct param_parsed_struct *p = NULL;
	struct opt_param *opt_p;
	int i, msg_idx;

	msg_idx = get_msg_idx_by_type(parse_struct->message_type);
	if (msg_idx < 0) {
		LM_ERR("BUG - Unknown ISUP message type: %d\n", parse_struct->message_type);
		return NULL;
	}

	/* find required parameter in the parse struct */
	for (i = 0; i < isup_messages[msg_idx].mand_fixed_params; i++)
		if (isup_params[isup_params_idx].param_code ==
			parse_struct->mand_fix_params[i].param_code) {
			p = parse_struct->mand_fix_params + i;
			*param_type = 0;
			break;
		}
	if (!p)
		for (i = 0; i < isup_messages[msg_idx].mand_var_params; i++)
			if (isup_params[isup_params_idx].param_code ==
				parse_struct->mand_var_params[i].param_code) {
				p = parse_struct->mand_var_params + i;
				*param_type = 1;
				break;
			}
	if (!p)
		for (opt_p = parse_struct->opt_params_list; opt_p; opt_p = opt_p->next)
			if (isup_params[isup_params_idx].param_code == opt_p->param.param_code) {
				p = &opt_p->param;
				*param_type = 2;
				break;
			}

	return p;
}

int get_isup_param_msg(struct sip_msg *msg, pv_param_t *param, int *pv_idx,
	struct isup_parse_fixup **fix, struct param_parsed_struct **p,
	struct isup_parsed_struct **parse_struct, struct body_part **isup_part,
	int *param_type)
{
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

		*pv_idx = param->pvi.u.ival;
	} /* else - index not provided */

	*fix = (struct isup_parse_fixup *)param->pvn.u.dname;

	if (!msg) {
		LM_WARN("No sip msg\n");
		return -1;
	}

	/* Parse IUSP message if not done already */
	*isup_part = get_isup_part(msg);
	if (!*isup_part) {
		LM_INFO("No ISUP body for this message\n");
		return -1;
	}
	if ((*isup_part)->parsed)  /* already parsed */
		*parse_struct = (struct isup_parsed_struct*)(*isup_part)->parsed;
	else {
		*parse_struct = parse_isup_body(msg);
		if (!*parse_struct) {
			LM_WARN("Unable to parse ISUP message\n");
			return -1;
		}
	}

	*p = get_isup_param(*parse_struct, (*fix)->isup_params_idx, param_type);

	return 0;
}

static char pv_tr_res_buf[PV_RES_BUF_MAXLEN];
static str pv_tr_str_res = {pv_tr_res_buf, 0};

int get_param_pval(int isup_params_idx, int subfield_idx, int byte_idx,
					struct param_parsed_struct *p, pv_value_t *res)
{
	int int_res = -1;
	int l;
	char *ch;

	if (isup_params[isup_params_idx].parse_func && subfield_idx >= 0) {
		if (byte_idx >= 0)
			LM_INFO("Ignoring index for ISUP param: %.*s, known subfield provided\n",
				isup_params[isup_params_idx].name.len,
				isup_params[isup_params_idx].name.s);

		isup_params[isup_params_idx].parse_func(subfield_idx, p->val, p->len,
														&int_res, &pv_tr_str_res);

		/* int or str val according to parse function for this subfield */
		if (int_res != -1) {
			ch = int2str(int_res, &l);
			res->rs.s = ch;
			res->rs.len = l;
			res->ri = int_res;
			res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;
		} else {
			res->rs.len = pv_tr_str_res.len;
			res->rs.s = pv_tr_str_res.s;
			res->flags = PV_VAL_STR;
		}

		return 0;
	} else if (!isup_params[isup_params_idx].parse_func && subfield_idx >= 0) {
		LM_ERR("BUG - Subfield known but no specific parse function\n");
		return -1;
	}

	if (byte_idx < 0) {
		/* if we have predefined values for a param that is a single field */
		if (isup_params[isup_params_idx].single_fld_pvals) {
			/* print param value as integer */
			ch = int2str(p->val[0], &l);
			res->rs.s = ch;
			res->rs.len = l;
			res->ri = p->val[0];
			res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;
		} else {	/* else print param as hex representation */
			pv_tr_res_buf[0] = '0';
			pv_tr_res_buf[1] = 'x';
			string2hex(p->val, p->len, pv_tr_res_buf + 2);
			res->flags = PV_VAL_STR;
			res->rs.len = 2 * p->len + 2;
			res->rs.s = pv_tr_res_buf;
		}
	} else {	/* we have an index, return corresponding byte from param */
		if (byte_idx > p->len - 1) {
			LM_ERR("Index: %d out of bounds, parameter length is: %d\n", byte_idx, p->len);
			return -1;
		}
		ch = int2str(p->val[byte_idx], &l);
		res->rs.s = ch;
		res->rs.len = l;
		res->ri = p->val[byte_idx];
		res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;
	}

	return 0;
}

int get_param_pval_str(int isup_params_idx, int subfield_idx,
						struct param_parsed_struct *p, pv_value_t *res)
{
	int int_res = -1;
	int l;
	char *ch;
	int i;

	res->flags = PV_VAL_STR;

	if (isup_params[isup_params_idx].parse_func && subfield_idx >= 0) {
		isup_params[isup_params_idx].parse_func(subfield_idx, p->val, p->len,
											&int_res, &pv_tr_str_res);
		if (int_res != -1) {
			/* search for the string alias for this value */
			for (i = 0; i < isup_params[isup_params_idx].subfield_list[subfield_idx].predef_vals.no_vals; i++)
				if (isup_params[isup_params_idx].subfield_list[subfield_idx].predef_vals.vals[i] == int_res) {
					res->rs.len = isup_params[isup_params_idx].subfield_list[subfield_idx].predef_vals.aliases[i].len;
					res->rs.s = isup_params[isup_params_idx].subfield_list[subfield_idx].predef_vals.aliases[i].s;
					return 0;
				}

			/* alias not found or aliases not supported at all, print the integer value anyway */
			if (isup_params[isup_params_idx].subfield_list[subfield_idx].predef_vals.no_vals == 0)
				LM_DBG("No string aliases supported for subfield <%.*s>\n",
					isup_params[isup_params_idx].subfield_list[subfield_idx].name.len,
					isup_params[isup_params_idx].subfield_list[subfield_idx].name.s);
			if (i == isup_params[isup_params_idx].subfield_list[subfield_idx].predef_vals.no_vals)
				LM_DBG("No string alias for value: %d of subfield <%.*s>\n", int_res,
					isup_params[isup_params_idx].subfield_list[subfield_idx].name.len,
					isup_params[isup_params_idx].subfield_list[subfield_idx].name.s);

			ch = int2str(int_res, &l);
			res->rs.s = ch;
			res->rs.len = l;
			res->ri = int_res;
			res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;

			return 0;

		} else { /* already a string */
			res->rs.len = pv_tr_str_res.len;
			res->rs.s = pv_tr_str_res.s;
			return 0;
		}
	} else if (!isup_params[isup_params_idx].parse_func && subfield_idx >= 0) {
		LM_ERR("BUG - Subfield known but no specific parse function\n");
		return -1;
	}
	/* no subfield if we reach this point */

	/* if we have aliases for a param that is a single field */
	if (isup_params[isup_params_idx].single_fld_pvals) {
		/* search for the string alias of the param value */
		for (i = 0; i < isup_params[isup_params_idx].single_fld_pvals->no_vals; i++)
			if (isup_params[isup_params_idx].single_fld_pvals->vals[i] == p->val[0]) {
				res->rs.len = isup_params[isup_params_idx].single_fld_pvals->aliases[i].len;
				res->rs.s = isup_params[isup_params_idx].single_fld_pvals->aliases[i].s;
				return 0;
			}

		/* alias not found, print the integer value anyway */
		LM_DBG("No string alias for value: %d of parameter <%.*s>\n", p->val[0],
			isup_params[isup_params_idx].name.len, isup_params[isup_params_idx].name.s);

		ch = int2str(p->val[0], &l);
		res->rs.s = ch;
		res->rs.len = l;
		res->ri = p->val[0];
		res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;

		return 0;
	}

	/* no aliases, print whole param as hex */
	pv_tr_res_buf[0] = '0';
	pv_tr_res_buf[1] = 'x';
	string2hex(p->val, p->len, pv_tr_res_buf + 2);
	res->flags = PV_VAL_STR;
	res->rs.len = 2 * p->len + 2;
	res->rs.s = pv_tr_res_buf;

	return 0;
}

int pv_get_isup_param(struct sip_msg *msg, pv_param_t *param, pv_value_t *res)
{
	struct isup_parse_fixup *fix = NULL;
	struct isup_parsed_struct *isup_struct;
	struct param_parsed_struct *p = NULL;
	struct body_part *isup_part;
	int pv_idx = -1;
	int param_type;

	if (get_isup_param_msg(msg, param, &pv_idx, &fix, &p, &isup_struct,
			&isup_part, &param_type) < 0)
		return pv_get_null(msg, param, res);

	if (!p) {
		LM_INFO("parameter: %.*s not found in this ISUP message\n",
			isup_params[fix->isup_params_idx].name.len,
			isup_params[fix->isup_params_idx].name.s);
		return pv_get_null(msg, param, res);
	}

	if (get_param_pval(fix->isup_params_idx, fix->subfield_idx, pv_idx, p, res) < 0)
		return pv_get_null(msg, param, res);

	return 0;
}

int pv_get_isup_param_str(struct sip_msg *msg, pv_param_t *pv_param, pv_value_t *res)
{
	struct isup_parse_fixup *fix = NULL;
	struct isup_parsed_struct *isup_struct;
	struct param_parsed_struct *p = NULL;
	struct body_part *isup_part;
	int pv_idx = -1;
	int param_type;

	if (get_isup_param_msg(msg, pv_param, &pv_idx, &fix, &p, &isup_struct,
			&isup_part, &param_type) < 0)
		return pv_get_null(msg, pv_param, res);

	if (!p) {
		LM_INFO("parameter: %.*s not found in this ISUP message\n",
			isup_params[fix->isup_params_idx].name.len,
			isup_params[fix->isup_params_idx].name.s);
		return pv_get_null(msg, pv_param, res);
	}

	if (get_param_pval_str(fix->isup_params_idx, fix->subfield_idx, p, res) < 0)
		return pv_get_null(msg, pv_param, res);

	return 0;
}

int pv_set_isup_param(struct sip_msg* msg, pv_param_t *param, int op, pv_value_t *val)
{
	struct isup_parse_fixup *fix = NULL;
	struct body_part *isup_part;
	struct isup_parsed_struct *isup_struct;
	struct param_parsed_struct *p = NULL;
	struct opt_param *opt_p, *tmp;
	int pv_idx = -1;
	int param_type = -1;
	int rc;
	int new_len = 0;
	int i;
	int new_val;

	if (get_isup_param_msg(msg, param, &pv_idx, &fix, &p, &isup_struct,
			&isup_part, &param_type) < 0)
		return -1;

	if (!p) {	/* param not found in parsed struct so it should be a new optional param */
		opt_p = pkg_malloc(sizeof *opt_p);
		if (!opt_p) {
			LM_ERR("No more pkg memory!\n");
			return -1;
		}
		opt_p->next = isup_struct->opt_params_list;
		memset(&opt_p->param, 0, sizeof(struct param_parsed_struct));
		opt_p->param.param_code = isup_params[fix->isup_params_idx].param_code;
		isup_struct->opt_params_list = opt_p;
		isup_struct->no_opt_params++;
		p = &opt_p->param;
		param_type = 3;
	}

	if (isup_params[fix->isup_params_idx].write_func && fix->subfield_idx >= 0) {
		if (pv_idx >= 0)
			LM_INFO("Ignoring index for ISUP param: %.*s, known subfield provided\n",
				isup_params[fix->isup_params_idx].name.len,
				isup_params[fix->isup_params_idx].name.s);

		new_len = p->len;
		rc = isup_params[fix->isup_params_idx].write_func(fix->isup_params_idx,
										fix->subfield_idx, p->val, &new_len, val);
		if (new_len != p->len)
			isup_struct->total_len += new_len - p->len;
		p->len = new_len;
		if (rc < 0) {
			LM_WARN("Unable to write $isup_param(%.*s)\n",
				isup_params[fix->isup_params_idx].name.len,
				isup_params[fix->isup_params_idx].name.s);
			return -1;
		}

		isup_part->dump_f = (dump_part_function)isup_dump;

		return 0;
	} else if (!isup_params[fix->isup_params_idx].write_func && fix->subfield_idx >= 0) {
		LM_ERR("BUG - Subfield known but no specific parse function\n");
		return -1;
	}

	if (pv_idx < 0) {	/* we don't have an index */

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

			return 0;
		} else if (val->flags & PV_TYPE_INT || val->flags & PV_VAL_INT) {
			/* if we have predefined values for a param that is a single field */
			if (isup_params[fix->isup_params_idx].single_fld_pvals) {
				if (param_type == 3)	/* new optional param */
					isup_struct->total_len += 1;
				else if (param_type == 1 || param_type == 2)
					isup_struct->total_len += 1 - p->len;

				p->len = 1;
				p->val[0] = val->ri;

				isup_part->dump_f = (dump_part_function)isup_dump;

				return 0;
			} else {
				LM_WARN("Hex string value required for $isup_param(%.*s)\n",
					isup_params[fix->isup_params_idx].name.len,
					isup_params[fix->isup_params_idx].name.s);

				return -1;
			}
		} else if (val->flags & PV_VAL_STR) {
			if (val->rs.s[0] == '0' && val->rs.s[1] == 'x') {
				/* read whole param from hex str */
				if (param_type == 0 &&
					(val->rs.len-2)/2 != isup_params[fix->isup_params_idx].len) {
					LM_WARN("Incorrect length: %d for $isup_param(%.*s), it must be exactly: %d\n",
						(val->rs.len-2)/2, isup_params[fix->isup_params_idx].name.len,
						isup_params[fix->isup_params_idx].name.s,
						isup_params[fix->isup_params_idx].len);
						return -1;
				}

				if (param_type == 3)	/* new optional param */
					isup_struct->total_len += (val->rs.len-2)/2;
				else if (param_type == 1 || param_type == 2)
					isup_struct->total_len += (val->rs.len-2)/2 - p->len;

				p->len = (val->rs.len-2)/2;

				if (read_hex_param(val->rs.s, p->val, p->len) < 0) {
					LM_WARN("Invalid hex value for $isup_param(%.*s)\n",
						isup_params[fix->isup_params_idx].name.len,
						isup_params[fix->isup_params_idx].name.s);
					return -1;
				}

				isup_part->dump_f = (dump_part_function)isup_dump;

				return 0;
			} else if (isup_params[fix->isup_params_idx].single_fld_pvals) {
				/* if we have aliases for a param that is a single field */
				if (p->len > 1) {
					LM_ERR("Bad length for ISUP param <%.*s>\n",
						isup_params[fix->isup_params_idx].name.len,
						isup_params[fix->isup_params_idx].name.s);
					return -1;
				}
				/* search for the value for this alias */
				new_val = -1;
				for (i = 0; i < isup_params[fix->isup_params_idx].single_fld_pvals->no_vals; i++)
					if (!memcmp(isup_params[fix->isup_params_idx].single_fld_pvals->aliases[i].s,
								val->rs.s, val->rs.len)) {
						new_val = isup_params[fix->isup_params_idx].single_fld_pvals->vals[i];
						break;
					}

				if (new_val != -1) {
					if (param_type == 3)	/* new optional param */
						isup_struct->total_len += 1;
					else if (param_type == 1 || param_type == 2)
						isup_struct->total_len += 1 - p->len;

					p->len = 1;
					p->val[0] = new_val;

					isup_part->dump_f = (dump_part_function)isup_dump;

					return 0;
				} else {
					LM_ERR("Unknown value alias <%.*s>\n", val->rs.len, val->rs.s);
					return -1;
				}
			} else {
				LM_WARN("Hex string value required for $isup_param(%.*s)\n",
					isup_params[fix->isup_params_idx].name.len,
					isup_params[fix->isup_params_idx].name.s);
				return -1;
			}
		} else {
			LM_ERR("Invalid value for $isup_param(%.*s)\n",
				isup_params[fix->isup_params_idx].name.len,
				isup_params[fix->isup_params_idx].name.s);
			return -1;
		}

	} else {	/* we have an index, set the corresponding byte */

		if (param_type == 0 && pv_idx > p->len - 1) { /* fixed length exceeded */
			LM_ERR("Index [%d] out of bounds, fixed parameter length is: %d\n",
				pv_idx, p->len);
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

			return 0;
		} else if (val->flags & PV_TYPE_INT || val->flags & PV_VAL_INT) {
			if (pv_idx > p->len - 1) {	/* extending the param */
				/* fill the rest of the bytes up to the index with 0 */
				memset(p->val + p->len, 0, pv_idx - p->len);
				isup_struct->total_len += pv_idx + 1 - p->len;
				p->len = pv_idx + 1;
			}

			p->val[pv_idx] = val->ri;

			isup_part->dump_f = (dump_part_function)isup_dump;

			return 0;
		} else if (val->flags & PV_VAL_STR) {
			LM_WARN("Integer value required for byte [%d] of $isup_param(%.*s)\n",
				pv_idx, isup_params[fix->isup_params_idx].name.len,
				isup_params[fix->isup_params_idx].name.s);
			return -1;
		} else {
			LM_ERR("Invalid value for $isup_param(%.*s)\n",
				isup_params[fix->isup_params_idx].name.len,
				isup_params[fix->isup_params_idx].name.s);
			return -1;
		}
	}
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
	res->rs.s = isup_messages[msg_idx].short_name;
	res->rs.len = 3;

	return 0;
}


static inline struct opt_param *alloc_opt_param(int param_code)
{
	struct opt_param *new_opt_param;

	new_opt_param = pkg_malloc(sizeof *new_opt_param);
	if (!new_opt_param) {
		LM_ERR("No more pkg mem!\n");
		return NULL;
	}
	new_opt_param->next = NULL;
	memset(&new_opt_param->param, 0, sizeof(struct param_parsed_struct));
	new_opt_param->param.param_code = param_code;

	return new_opt_param;
}

static inline void link_new_opt_param(struct isup_parsed_struct *isup_struct,
										struct opt_param *new_param, int len)
{
	new_param->param.len = len;
	isup_struct->opt_params_list = new_param;
	isup_struct->no_opt_params++;
	isup_struct->total_len += len;
}

static int init_iam_default(struct sip_msg *sip_msg, struct isup_parsed_struct *isup_struct)
{
	pv_value_t val;
	str *ruri;
	char number[MAX_NUM_LEN];
	char intl_num = 0;
	char *p;
	int i = 0;
	struct opt_param *cgpn = NULL;
	struct to_body* pai;
	int apri_val;
	int new_len = 0;
	int rc = 0;

	val.flags = PV_VAL_INT;

	/* set Nature of Connection Indicators */
	val.ri = 1;
	isup_params[PARM_NATURE_OF_CONNECTION_IND_IDX].write_func(PARM_NATURE_OF_CONNECTION_IND_IDX,
										0, isup_struct->mand_fix_params[0].val, &new_len, &val);
	/* set Forward Call Indicators */
	val.ri = 1;
	isup_params[PARM_FORWARD_CALL_IND_IDX].write_func(PARM_FORWARD_CALL_IND_IDX,
							2, isup_struct->mand_fix_params[1].val, &new_len, &val);
	val.ri = 1;
	isup_params[PARM_FORWARD_CALL_IND_IDX].write_func(PARM_FORWARD_CALL_IND_IDX,
							5, isup_struct->mand_fix_params[1].val, &new_len, &val);

	/* set Calling Party's Category */
	isup_struct->mand_fix_params[2].val[0] = 10; /* ordinary calling subscriber */

	/* set Transmission Medium Requirement */
	isup_struct->mand_fix_params[3].val[0] = 3; /* 3.1 kHz audio */

	/* set Called Party Number */
	new_len = 0;

	val.ri = 1;	/* routing to internal network number not allowed */
	isup_params[PARM_CALLED_PARTY_NUM_IDX].write_func(PARM_CALLED_PARTY_NUM_IDX,
							2, isup_struct->mand_var_params[0].val, &new_len, &val);
	val.ri = 1;	/* ISDN numbering plan */
	isup_params[PARM_CALLED_PARTY_NUM_IDX].write_func(PARM_CALLED_PARTY_NUM_IDX,
							3, isup_struct->mand_var_params[0].val, &new_len, &val);

	/* check RURI */
	ruri = GET_RURI(sip_msg);
	if (!ruri->s || ruri->len < 7) {
		LM_INFO("invalid R-URI length\n");
		goto cpn_err;
	}
	/* sip: URI required */
	if (memcmp(ruri->s, "sip:", 4)) {
		LM_INFO("\"sip:\" URI required for the R-URI\n");
		goto cpn_err;
	}
	/* user=phone parameter required for RURI */
	if (!l_memmem(ruri->s, "user=phone", ruri->len, 10)) {
		LM_INFO("\"user=phone\" parameter required for R-URI\n");
		goto cpn_err;
	}
	/* if "+" prefix is present it is an international call */
	if (ruri->s[4] == '+')
		intl_num = 1;

	/* get number from RURI */
	for (p = ruri->s + (intl_num?5:4);
		 i < MAX_NUM_LEN && *p != '@' && *p != ';' && p - ruri->s < ruri->len;
		 p++)
		if ((*p >= '0' && *p <= '9') || char2digit(*p)) /* phone or dtmf digit */
			number[i++] = *p;
		else if (*p != '-' && *p != '.' && *p != '(' && *p != ')') {
			/* not a visual separator */
			LM_INFO("Unknown char <%c> in R-URI number\n", *p);
			goto cpn_err;
		}
	if (i < 3) {
		LM_INFO("R-URI number to short\n");
		goto cpn_err;
	}
	if (i == MAX_NUM_LEN && *p != '@' && *p != ';' && p - ruri->s < ruri->len) {
		LM_INFO("R-URI number to long should have max 15 digits (E.164)\n");
		goto cpn_err;
	}

	val.ri = intl_num ? 4 : 3; /* international or national number */
	isup_params[PARM_CALLED_PARTY_NUM_IDX].write_func(PARM_CALLED_PARTY_NUM_IDX,
							1, isup_struct->mand_var_params[0].val, &new_len, &val);

	/* Address signal */
	val.flags = PV_VAL_STR;
	val.rs.s = number;
	val.rs.len = i;
	isup_params[PARM_CALLED_PARTY_NUM_IDX].write_func(PARM_CALLED_PARTY_NUM_IDX,
							4, isup_struct->mand_var_params[0].val, &new_len, &val);
	LM_INFO("Called party number set to: %.*s\n", i, number);

	isup_struct->mand_var_params[0].len = new_len;
	isup_struct->total_len += new_len;

	goto set_cgpn;

cpn_err:
	rc = -1;
	LM_INFO("Unable to map Called Party Number from SIP by default\n");
set_cgpn:
	/* set Calling Party Number */
	new_len = 0;

	/* if P-Asserted-Identity absent, don't set CgPN */
	if (parse_headers(sip_msg, HDR_PAI_F | HDR_PRIVACY_F, 0)) {
		LM_ERR("Unable to parse Privacy and/or P-Asserted-Identity headers\n");
		goto cgpn_err;
	}
	if (!sip_msg->pai)
		return 0;
	if (parse_pai_header(sip_msg) < 0) {
		LM_ERR("Unable to parse P-Asserted-Identity\n");
		goto cgpn_err;
	}
	pai = get_pai(sip_msg);
	if (parse_uri(pai->uri.s, pai->uri.len, &pai->parsed_uri) < 0) {
		LM_ERR("Unable to parse P-Asserted-Identity URI\n");
		goto cgpn_err;
	}

	/* P-Asserted-Identity should be a sip: or tel: URI with a global number in the form: "+"CC + NDC + SN */
	if (pai->parsed_uri.type != SIP_URI_T && pai->parsed_uri.type != TEL_URI_T) {
		LM_INFO("\"sip:\" URI required for P-Asserted-Identity\n");
		goto cgpn_err;
	}
	if (pai->parsed_uri.user.s[0] != '+') {
		LM_INFO("P-Asserted-Identity number should start with \"+\" sign\n");
		goto cgpn_err;
	}

	/* add the new optional parameter to isup struct */
	if ((cgpn = alloc_opt_param(ISUP_PARM_CALLING_PARTY_NUM)) == NULL)
		goto cgpn_err;

	val.flags = PV_VAL_INT;

	/* Numbering plan indicator */
	val.ri = 1; /* ISDN (Telephony) numbering plan */
	isup_params[PARM_CALLING_PARTY_NUM_IDX].write_func(PARM_CALLING_PARTY_NUM_IDX,
												3, cgpn->param.val, &new_len, &val);

	/* Screening Indicator */
	val.ri = 3; /* network provided */
	isup_params[PARM_CALLING_PARTY_NUM_IDX].write_func(PARM_CALLING_PARTY_NUM_IDX,
												5, cgpn->param.val, &new_len, &val);

	/* Nature of Address Indicator */
	if (memcmp(pai->parsed_uri.user.s, country_code.s, country_code.len))
		intl_num = 1;
	else
		intl_num = 0;
	val.ri = intl_num ? 4 : 3; /* international or national number */
	isup_params[PARM_CALLING_PARTY_NUM_IDX].write_func(PARM_CALLING_PARTY_NUM_IDX,
												1, cgpn->param.val, &new_len, &val);

	/* Address Presentation Restricted Indicator */
	apri_val = 0; /* presentation allowed */
	if (sip_msg->privacy) {
		if (parse_privacy(sip_msg) < 0) {
			LM_ERR("Unable to parse Privacy header\n");
			goto cgpn_err;
		}
		/* presentation restricted */
		if ((get_privacy_values(sip_msg) & (PRIVACY_NONE | PRIVACY_ID)) == (PRIVACY_NONE | PRIVACY_ID))
			apri_val = 1;
		else if (get_privacy_values(sip_msg) & (PRIVACY_HEADER | PRIVACY_USER | PRIVACY_ID))
			apri_val = 1;
	}
	val.ri = apri_val;
	isup_params[PARM_CALLING_PARTY_NUM_IDX].write_func(PARM_CALLING_PARTY_NUM_IDX,
												4, cgpn->param.val, &new_len, &val);

	/* Address signal */
	i = 0;
	for (p = pai->parsed_uri.user.s + 1;
		 i < MAX_NUM_LEN && *p != ';' && p - pai->parsed_uri.user.s < pai->parsed_uri.user.len;
		 p++)
		if ((*p >= '0' && *p <= '9') || char2digit(*p)) /* phone or dtmf digit */
			number[i++] = *p;
		else if (*p != '-' && *p != '.' && *p != '(' && *p != ')') { /* not a visual separator */
			LM_INFO("Unknown char <%c> in P-Asserted-Identity number\n", *p);
			goto cgpn_err;
		}
	if (i < 3) {
		LM_INFO("P-Asserted-Identity number to short, only <%d> digits\n", i);
		goto cgpn_err;
	}
	if (i == MAX_NUM_LEN && *p != ';' && p - pai->parsed_uri.user.s < pai->parsed_uri.user.len) {
		LM_INFO("P-Asserted-Identity number to long, should have max 15 digits (E.164)\n");
		goto cgpn_err;
	}

	val.flags = PV_VAL_STR;
	val.rs.s = intl_num ? number : number + country_code.len - 1;
	val.rs.len = intl_num ? i : i - country_code.len + 1;
	isup_params[PARM_CALLING_PARTY_NUM_IDX].write_func(PARM_CALLING_PARTY_NUM_IDX,
												6, cgpn->param.val, &new_len, &val);
	LM_INFO("Calling party number set to: %.*s\n", val.rs.len, val.rs.s);

	link_new_opt_param(isup_struct, cgpn, new_len);

	return rc;

cgpn_err:
	LM_INFO("Unable to map Callig Party Number from SIP by default\n");
	if (cgpn)
		pkg_free(cgpn);
	return -1;
}

static unsigned int get_cause_from_reason(struct sip_msg *sip_msg) {
	struct hdr_field *reason_hdr;
	char *p;
	char cause_val_s[3];
	str cause_val_str = {0, 0};
	unsigned int cause_val;

	if (parse_headers(sip_msg, HDR_EOH_F, 0) < 0) {
		LM_ERR("Failed to parse all headers\n");
		return -1;
	}

	reason_hdr = get_header_by_static_name(sip_msg, "Reason");
	if (!reason_hdr)
		return -1;

	if (!l_memmem(reason_hdr->body.s, "Q.850", reason_hdr->body.len, 5)) {
		LM_DBG("\"Q.850\" protocol required in Reason header\n");
		return -1;
	}

	if ((p = l_memmem(reason_hdr->body.s, "cause=", reason_hdr->body.len, 6)) == NULL) {
		LM_DBG("protocol-cause in the from \"cause=XX\" required in Reason header\n");
		return -1;
	}

	cause_val_str.s = cause_val_s;
	for (p = p + 6; *p >= '0' && *p <= '9' && cause_val_str.len < 3; p++)
		cause_val_str.s[cause_val_str.len++] = *p;
	if (cause_val_str.len == 0 || str2int(&cause_val_str, &cause_val) < 0) {
		LM_DBG("Invalid cause value in Reason header\n");
		return -1;
	}

	return cause_val;
}

static int init_rel_default(struct sip_msg *sip_msg, struct isup_parsed_struct *isup_struct)
{
	pv_value_t val;
	int new_len = 0;

	val.flags = PV_VAL_INT;

	/* set Cause indicators */

	/* Location */
	val.ri = 10; /* network beyond interworking point */
	isup_params[PARM_CAUSE_IDX].write_func(PARM_CAUSE_IDX, 0,
			isup_struct->mand_var_params[0].val, &new_len, &val);

	if (sip_msg->first_line.type == SIP_REQUEST) {
		if (sip_msg->REQ_METHOD == METHOD_BYE) {
			val.ri = get_cause_from_reason(sip_msg);
			if (val.ri < 1 || val.ri > 127)
				val.ri = 16; /* Normal call clearing */
		}
		else if (sip_msg->REQ_METHOD == METHOD_CANCEL) {
			val.ri = get_cause_from_reason(sip_msg);
			if (val.ri < 1 || val.ri > 127)
				val.ri = 31; /* Normal, unspecified */
		} else
			goto error;
	} else if (sip_msg->first_line.type == SIP_REPLY && sip_msg->REPLY_STATUS/100 >= 4) {
		val.ri = get_cause_from_reason(sip_msg);
		if (val.ri < 1 || val.ri > 127)
			switch (sip_msg->REPLY_STATUS) {
				case 404:
					val.ri = 1; /* Unallocated number */
					break;
				case 410:
					val.ri = 22; /* Number changed */
					break;
				case 480:
					val.ri = 20; /* Subscriber absent */
					break;
				case 484:
					val.ri = 28; /* Invalid Number format */
					break;
				case 486:
					val.ri = 17; /* User busy */
					break;
				case 491:
					goto error; /* No mapping */
				case 600:
					val.ri = 17; /* User busy */
					break;
				case 603:
					val.ri = 21; /* Call rejected */
					break;
				case 604:
					val.ri = 1; /* Unallocated number */
					break;
				default:
					val.ri = 127; /* Interworking */
			}
	} else
		goto error;

	isup_params[PARM_CAUSE_IDX].write_func(PARM_CAUSE_IDX, 2,
			isup_struct->mand_var_params[0].val, &new_len, &val);

	LM_DBG("Cause value from Cause Indicators set to: %d\n", val.ri);

	isup_struct->mand_var_params[0].len = new_len;
	isup_struct->total_len += new_len;

	return 0;

error:
	LM_INFO("Unable to map Cause indicators from SIP by default\n");
	return -1;
}

static int init_acm_default(struct sip_msg *sip_msg, struct isup_parsed_struct *isup_struct)
{
	pv_value_t val;
	int new_len = 0;

	val.flags = PV_VAL_INT;

	/* set Backward call indicators */

	/* Called Party's Status Indicator */
	val.ri = 1; /* subscriber free */
	isup_params[PARM_BACKWARD_CALL_IND_IDX].write_func(PARM_BACKWARD_CALL_IND_IDX,
							1, isup_struct->mand_fix_params[0].val, &new_len, &val);
	/* Interworking Indicator */
	val.ri = 1; /* interworking encountered */
	isup_params[PARM_BACKWARD_CALL_IND_IDX].write_func(PARM_BACKWARD_CALL_IND_IDX,
							4, isup_struct->mand_fix_params[0].val, &new_len, &val);

	return 0;
}

static int init_cpg_default(struct sip_msg *sip_msg, struct isup_parsed_struct *isup_struct)
{
	pv_value_t val;
	int new_len = 0;
	struct opt_param *b_ind;

	if (sip_msg->first_line.type == SIP_REPLY && sip_msg->REPLY_STATUS == 180)
		isup_struct->mand_fix_params[0].val[0] = 1; /* set Event information to ALERTING */
	else if (sip_msg->first_line.type == SIP_REPLY && sip_msg->REPLY_STATUS == 183)
		isup_struct->mand_fix_params[0].val[0] = 2; /* set Event information to PROGRESS */
	else {
		LM_INFO("Unable to map Event information and Backward call indicators from SIP by default\n");
		return -1;
	}

	/* set Backward call indicators */

	/* add the new optional parameter to isup struct */
	if ((b_ind = alloc_opt_param(ISUP_PARM_BACKWARD_CALL_IND)) == NULL)
		return -1;

	val.flags = PV_VAL_INT;

	/* Called Party's Status Indicator */
	val.ri = 1; /* subscriber free */
	isup_params[PARM_BACKWARD_CALL_IND_IDX].write_func(PARM_BACKWARD_CALL_IND_IDX,
												1, b_ind->param.val, &new_len, &val);
	/* Interworking Indicator */
	val.ri = 1; /* interworking encountered */
	isup_params[PARM_BACKWARD_CALL_IND_IDX].write_func(PARM_BACKWARD_CALL_IND_IDX,
												4, b_ind->param.val, &new_len, &val);

	link_new_opt_param(isup_struct, b_ind, new_len);

	return 0;
}

static int init_con_default(struct sip_msg *sip_msg, struct isup_parsed_struct *isup_struct)
{
	pv_value_t val;
	int new_len = 0;

	val.flags = PV_VAL_INT;

	/* set Backward call indicators */

	val.ri = 1; /* interworking encountered */
	isup_params[PARM_BACKWARD_CALL_IND_IDX].write_func(PARM_BACKWARD_CALL_IND_IDX,
							4, isup_struct->mand_fix_params[0].val, &new_len, &val);

	return 0;
}

static int init_anm_default(struct sip_msg *sip_msg, struct isup_parsed_struct *isup_struct)
{
	pv_value_t val;
	int new_len = 0;
	struct opt_param *b_ind;

	/* set Backward call indicators */

	/* add the new optional parameter to isup struct */
	if ((b_ind = alloc_opt_param(ISUP_PARM_BACKWARD_CALL_IND)) == NULL)
		return -1;

	val.flags = PV_VAL_INT;

	/* Interworking Indicator */
	val.ri = 1; /* interworking encountered */
	isup_params[PARM_BACKWARD_CALL_IND_IDX].write_func(PARM_BACKWARD_CALL_IND_IDX,
												4, b_ind->param.val, &new_len, &val);

	link_new_opt_param(isup_struct, b_ind, new_len);

	return 0;
}


static int add_isup_part_cmd(struct sip_msg *msg, str *msg_type, str *hdrs)
{
	struct isup_parsed_struct *isup_struct;
	struct body_part *isup_part;
	int isup_msg_idx = -1;
	str sip_hdrs;
	int i;
	int rc;

	/* if isup message type not provided as param, try to map sip msg to
	 * isup msg type by default */
	if (!msg_type) {
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
		if(msg_type->s==NULL || msg_type->len==0) {
			LM_ERR("null/empty param found\n");
			return -1;
		}

		for (i = 0; i < NO_ISUP_MESSAGES; i++)
			if (msg_type->len == 3) {
				if (!memcmp(&isup_messages[i].short_name, msg_type->s, 3)) {
					isup_msg_idx = get_msg_idx_by_type(isup_messages[i].message_type);
					break;
				}
			} else {
				if (str_strcasecmp(&isup_messages[i].name, msg_type) == 0) {
					isup_msg_idx = get_msg_idx_by_type(isup_messages[i].message_type);
					break;
				}
			}

		if (isup_msg_idx < 0) {
			LM_ERR("Unknown ISUP message type\n");
			return -1;
		}

		if (isup_messages[isup_msg_idx].message_type == ISUP_IAM &&
			(msg->first_line.type != SIP_REQUEST ||
			msg->REQ_METHOD != METHOD_INVITE)) {
			LM_WARN("Initial address message maps only to INVITE\n");
			return -1;
		}
	}

	/* handle the extra SIP headers */
	if (hdrs!=NULL) {
		sip_hdrs = *hdrs;
	} else if (default_part_headers.len) {
		sip_hdrs = default_part_headers;
	} else {
		sip_hdrs.len = 0;
		sip_hdrs.s = NULL;
	}

	/* first, build a blank isup message (no optional params, all mandatory fixed params zeroed) */

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


	/* set parameter fields to default values for some message types */
	switch (isup_messages[isup_msg_idx].message_type) {
		case ISUP_IAM:
			rc = init_iam_default(msg, isup_struct);
			break;
		case ISUP_REL:
			rc = init_rel_default(msg, isup_struct);
			break;
		case ISUP_ACM:
			rc = init_acm_default(msg, isup_struct);
			break;
		case ISUP_CPG:
			rc = init_cpg_default(msg, isup_struct);
			break;
		case ISUP_ANM:
			rc = init_anm_default(msg, isup_struct);
			break;
		case ISUP_CON:
			rc = init_con_default(msg, isup_struct);
			break;
		default:
			rc = 1;
	}

	if (rc < 0)
		LM_INFO("Unable to set all %.*s message parameters by default\n",
			isup_messages[isup_msg_idx].name.len, isup_messages[isup_msg_idx].name.s);
	else if (rc == 0)
		LM_DBG("%.*s message parameters set by default\n",
			isup_messages[isup_msg_idx].name.len, isup_messages[isup_msg_idx].name.s);

	isup_part = add_body_part(msg, &isup_mime, sip_hdrs.s?&sip_hdrs:NULL, NULL);
	if (!isup_part) {
		LM_ERR("Failed to add isup body part\n");
		return -1;
	}
	isup_part->parsed = isup_struct;
	isup_part->dump_f = (dump_part_function)isup_dump;
	isup_part->free_parsed_f = (free_parsed_part_function)free_isup_parsed;
	isup_part->clone_parsed_f = (clone_parsed_part_function)clone_isup_parsed;

	return 1;
}


int tr_isup_parse(str* in, trans_t *t)
{
	char *p, *pp;
	str name;
	tr_param_t *tp = NULL;
	int i, j;

	if(in == NULL || in->s == NULL || t == NULL)
		return -1;

	p = in->s;
	name.s = in->s;

	/* find next token */
	while (*p && *p != TR_PARAM_MARKER && *p != TR_RBRACKET) p++;
	if (*p == '\0') {
		LM_ERR("invalid transformation: %.*s\n", in->len, in->s);
		return -1;
	}
	if (*p == TR_RBRACKET) {
		LM_ERR("ISUP parameter name required in transformation\n");
		return -1;
	}

	name.len = p - name.s;

	p++;
	trim_ws(p);
	pp = p;

	/* find next token */
	while (*p && *p != TR_PARAM_MARKER && *p != TR_RBRACKET) p++;
	if (*p == '\0') {
		LM_ERR("invalid transformation: %.*s\n", in->len, in->s);
		return -1;
	}

	/* ISUP parameter name */
	tp = pkg_malloc(sizeof *tp);
	if (!tp) {
		LM_ERR("no more private memory!\n");
		return -1;
	}
	tp->v.s.s = pp;
	tp->v.s.len = p - pp;
	tp->next = NULL;

	t->params = tp;

	if (*p == TR_PARAM_MARKER) {
		p++;
		trim_ws(p);
		pp = p;
		while (*p && *p != TR_RBRACKET) p++;
		if (*p == '\0') {
			LM_ERR("invalid transformation: %.*s\n", in->len, in->s);
			return -1;
		}

		/* subfield name */
		tp = NULL;
		tp = pkg_malloc(sizeof *tp);
		if (!tp) {
			LM_ERR("no more private memory!\n");
			return -1;
		}
		tp->v.s.s = pp;
		tp->v.s.len = p - pp;
		tp->next = NULL;

		t->params->next = tp;
	}

	/* search provided ISUP param in the isup_params array */
	for (i = 0; i < NO_ISUP_PARAMS; i++)
		if (str_strcasecmp(&t->params->v.s, &isup_params[i].name) == 0) {
			/* pass the index in the isup_params array to the transformation
			 * eval func instead of the actual isup param name */
			t->params->v.n = i;

			/* if subfield specified, search in the known subfields for this param */
			if (t->params->next && t->params->next->v.s.len) {
				if (!isup_params[i].subfield_list) {
					LM_ERR("No subfields supported for ISUP parameter <%.*s>\n",
						isup_params[i].name.len, isup_params[i].name.s);
					return -1;
				}

				for (j = 0; isup_params[i].subfield_list[j].name.s; j++)
					if (str_strcasecmp(&t->params->next->v.s,
							&isup_params[i].subfield_list[j].name) == 0) {
						/* same as for isup param name */
						t->params->next->v.n = j;
						break;
					}

				if (!isup_params[i].subfield_list[j].name.s) {
					LM_ERR("Unknown subfield <%.*s> for ISUP parameter <%.*s>\n",
						t->params->next->v.s.len, t->params->next->v.s.s,
						isup_params[i].name.len, isup_params[i].name.s);
					return -1;
				}
			}

			break;
		}

	if (i == NO_ISUP_PARAMS) {
		LM_ERR("Unknown ISUP parameter: %.*s\n", t->params->v.s.len, t->params->v.s.s);
		return -1;
	}

	if (name.len == 5 && !memcmp(name.s, "param", 5))
		t->subtype = TR_ISUP_PARAM;
	else if (name.len == 9 && !memcmp(name.s, "param.str", 9))
		t->subtype = TR_ISUP_PARAM_STR;
	else {
		LM_ERR("Unknown isup transformation: <%.*s>\n", name.len, name.s);
		return -1;
	}

	return 0;
}

int tr_isup_eval(struct sip_msg *msg, tr_param_t *tp, int subtype,
		pv_value_t *val)
{
	struct param_parsed_struct *p = NULL;
	struct isup_parsed_struct *parse_struct = NULL;
	int param_type;

	if (!val)
		return -1;

	if (val->flags & PV_VAL_NULL)
		return 0;

	if((!(val->flags&PV_VAL_STR)) || val->rs.len<=0)
		goto error;

	parse_struct = parse_isup(val->rs);
	if (!parse_struct) {
		LM_WARN("Unable to parse ISUP message\n");
		goto error;
	}

	p = get_isup_param(parse_struct, tp->v.n, &param_type);

	if (!p) {
		LM_INFO("parameter: <%.*s> not found in this ISUP message\n",
			isup_params[tp->v.n].name.len, isup_params[tp->v.n].name.s);
		goto error;
	}

	if (subtype == TR_ISUP_PARAM) {
		if (get_param_pval(tp->v.n, tp->next ? tp->next->v.n : -1, -1, p, val) < 0)
			goto error;
	} else if (subtype == TR_ISUP_PARAM_STR) {
		if (get_param_pval_str(tp->v.n, tp->next ? tp->next->v.n : -1, p, val) < 0)
			goto error;
	} else {
		LM_BUG("Unknown transformation subtype [%d]\n", subtype);
		goto error;
	}

	return 0;

error:
	val->flags = PV_VAL_NULL;
	return -1; 
}
