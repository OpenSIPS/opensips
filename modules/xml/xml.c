/*
 * Copyright (C) 2017 OpenSIPS Solutions
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
 * History:
 * --------
 *  2017-02-15 initial version (rvlad-patrascu)
 */


#include "../../sr_module.h"
#include "../../mem/mem.h"
#include "../../dprint.h"
#include "../../pvar.h"
#include "../../ut.h"

#include <libxml/parser.h>
#include <libxml/tree.h>


enum {
	EL_VAR_TAG  = 1,
	EL_VAR_IDX  = 2,
};

enum {
	ACCESS_EL,
	ACCESS_EL_VAL,
	ACCESS_EL_ATTR
};

typedef struct _xml_element {
	str tag;
	int idx;
	int var_flags;
	pv_spec_t tag_var;
	pv_spec_t idx_var;
	struct _xml_element *next;
} xml_element_t;

typedef struct _xml_path {
	str obj_name;
	str attr;		  /* name of accessed attribute */
	int access_mode;  /* access mode of the last node in the path */
	int attr_is_var;
	pv_spec_t attr_var;
	xml_element_t *elements;
} xml_path_t;


static int mod_init(void);
static int child_init(int);
static void mod_destroy(void);

/* PV functions */
static int pv_set_xml(struct sip_msg*,  pv_param_t*, int, pv_value_t*);
static int pv_get_xml(struct sip_msg*,  pv_param_t*, pv_value_t*);
static int pv_parse_xml_name(pv_spec_p , str *);


static pv_export_t mod_items[] = {
	{ {"xml", sizeof("xml")-1}, PVT_XML, pv_get_xml, pv_set_xml,
		pv_parse_xml_name, 0, 0, 0},
	  { {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};

struct module_exports exports= {
	"xml",        	 /* module's name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	NULL,            /* OpenSIPS module dependencies */
	NULL,            /* exported functions */
	0,               /* exported async functions */
	0,      		 /* param exports */
	0,       		 /* exported statistics */
	0,         		 /* exported MI functions */
	mod_items,       /* exported pseudo-variables */
	0,               /* extra processes */
	mod_init,        /* module initialization function */
	0,               /* reply processing function */
	mod_destroy,
	child_init       /* per-child init function */
};


static int new_parsed_elem(xml_path_t *id, str tag_str, str idx_str)
{
	xml_element_t *elem = NULL;

	elem = pkg_malloc(sizeof *elem);
	if (!elem) {
		LM_ERR("No more pkg memory\n");
		return -1;
	}
	memset(elem, 0, sizeof *elem);

	if (!tag_str.s) {
		LM_ERR("No element name\n");
		return -1;
	}
	if (*tag_str.s == '$') {
		if (!pv_parse_spec(&tag_str, &elem->tag_var)) {
			LM_ERR("Unable to parse variable in element name\n");
			return -1;
		}
		elem->var_flags |= EL_VAR_TAG;
	} else
		elem->tag = tag_str;

	elem->idx = -1;
	if (idx_str.s) {
		if (*idx_str.s == '$') {
			if (!pv_parse_spec(&idx_str, &elem->idx_var)) {
				LM_ERR("Unable to parse variable in index\n");
				return -1;
			}
			elem->var_flags |= EL_VAR_IDX;
		} else
			if (str2sint(&idx_str, &elem->idx) < 0) {
				LM_ERR("Invalid index\n");
				return -1;
			}
	}

	elem->next = id->elements;
	id->elements = elem;

	return 0;
}

enum {
	ST_START_NAME = 0,
	ST_START_IDX = 1,
	ST_END_IDX = 2,
	ST_ACCESS = 3,
};

int pv_parse_xml_name(pv_spec_p sp, str *in)
{
	xml_path_t *id = NULL;
	char *cur, *start;
	int prev_state = -1;
	str tag_str = {0,0}, idx_str = {0,0}, attr_str;

	id = pkg_malloc(sizeof *id);
	if(!id) {
		LM_ERR("No more pkg memory\n");
		return -1;
	}

	id->elements = NULL;

	/* first, get this xml object name */
	start = q_memchr(in->s, '/', in->len);
	if (!in->s || in->len == 0 || start == in->s) {
		LM_ERR("name required for this $xml var\n");
		return -1;
	}
	id->obj_name.s = in->s;
	id->obj_name.len = start ? start - in->s : in->len;

	id->attr.s = NULL;
	id->attr_is_var = 0;
	id->access_mode = ACCESS_EL;

	/* get each element in path */
	start = in->s + id->obj_name.len;
	for (cur = start; cur < in->s + in->len; cur++) {
		switch (*cur) {
		case '/':
			/* parsed an element */
			if (prev_state == ST_START_NAME) {
				tag_str.len = cur - start;
				if (tag_str.len == 0) {
					LM_ERR("No element name\n");
					return -1;
				}
				tag_str.s = start;

				if (new_parsed_elem(id, tag_str, idx_str) < 0)
					return -1;
			} else if (prev_state == ST_END_IDX) {
				if (new_parsed_elem(id, tag_str, idx_str) < 0)
					return -1;
			}

			/* new element in path to parse */
			start = cur + 1;
			idx_str.s = NULL;
			tag_str.s = NULL;
			prev_state = ST_START_NAME;
			break;
		case '[':
			if (prev_state != ST_START_NAME) {
				LM_ERR("Index must follow an element name\n");
				return -1;
			}

			tag_str.len = cur - start;
			if (tag_str.len == 0) {
				LM_ERR("No element name\n");
				return -1;
			}
			tag_str.s = start;

			start = cur + 1;
			prev_state = ST_START_IDX;
			break;
		case ']':
			if (prev_state != ST_START_IDX) {
				LM_ERR("Mismatched parenthesis, must correspond with opening \'[\'\n");
				return -1;
			}
			idx_str.len = cur - start;
			if (idx_str.len == 0) {
				LM_ERR("Empty index\n");
				return -1;
			}
			idx_str.s = start;
			prev_state = ST_END_IDX;
			break;
		case '.':
			if (prev_state != ST_START_NAME && prev_state != ST_END_IDX) {
				LM_ERR("<.attr> or <.val> must follow a complete path\n");
				return -1;
			}

			if (prev_state == ST_START_NAME) {
				tag_str.len = cur - start;
				if (tag_str.len == 0) {
					LM_ERR("No element name\n");
					return -1;
				}
				tag_str.s = start;
			}

			if (!memcmp(cur+1, "val", 3)) {
				id->access_mode = ACCESS_EL_VAL;
			} else if (!memcmp(cur+1, "attr", 4)) {
				id->access_mode = ACCESS_EL_ATTR;

				attr_str.len = in->len - (cur - in->s + 6); /* 6 = len(".attr/") */
				if (attr_str.len == 0) {
					LM_ERR("Empty attribute\n");
					return -1;
				}
				attr_str.s = cur + 6;
				if (*attr_str.s == '$') {
					if (!pv_parse_spec(&attr_str, &id->attr_var)) {
						LM_ERR("Unable to parse variable in element attribute\n");
						return -1;
					}
					id->attr_is_var = 1;
				} else
					id->attr = attr_str;
			} else {
				LM_ERR("Invalid access type, must be: <.attr> or <.val>\n");
				return -1;
			}

			/* it was the final element in the path */
			cur = in->s + in->len;
			prev_state = ST_ACCESS;
			break;
		}
	}

	if (prev_state == ST_END_IDX || prev_state == ST_ACCESS) {
		if (new_parsed_elem(id, tag_str, idx_str) < 0) {
					return -1;
		}
	} else if (prev_state == ST_START_NAME) {
		tag_str.len = cur - start;
		if (tag_str.len == 0) {
			LM_ERR("No element name\n");
			return -1;
		}
		tag_str.s = start;

		if (new_parsed_elem(id, tag_str, idx_str) < 0)
					return -1;
	}

	sp->pvp.pvn.u.dname = id;

	return 0;
}

static void dbg_print_path(xml_path_t *id)
{
	xml_element_t *it;

	LM_DBG("path: obj_name = <%.*s> attr = <%.*s> attr_is_var = <%d> access_mode = <%d>\n",
		id->obj_name.len, id->obj_name.s, id->attr.len, id->attr.s, id->attr_is_var, id->access_mode);

	for (it = id->elements; it; it = it->next) {
		LM_DBG("element: tag = <%.*s> idx = <%d> var_flags = <%d>\n",
			it->tag.len, it->tag.s, it->idx, it->var_flags);
	}
}

int pv_get_xml(struct sip_msg* msg,  pv_param_t* pvp, pv_value_t* val)
{
	return pv_get_null( msg, pvp, val);
}

int pv_set_xml(struct sip_msg* msg,  pv_param_t* pvp, int flag, pv_value_t* val)
{
	return -1;
}

static int mod_init(void)
{
	return 0;
}

static int child_init(int rank)
{
	return 0;
}

static void mod_destroy(void)
{
	return;
}

