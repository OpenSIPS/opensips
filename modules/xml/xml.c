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
#include <string.h>


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

typedef struct _xml_object_t {
	str name;
	xmlDoc *xml_doc;
	struct _xml_object_t *next;
} xml_object_t;


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
	0,				 /* load function */
	NULL,            /* OpenSIPS module dependencies */
	NULL,            /* exported functions */
	0,               /* exported async functions */
	0,      		 /* param exports */
	0,       		 /* exported statistics */
	0,         		 /* exported MI functions */
	mod_items,       /* exported pseudo-variables */
	0,				 /* exported transformations */
	0,               /* extra processes */
	0,               /* module pre-initialization function */
	mod_init,        /* module initialization function */
	0,               /* reply processing function */
	mod_destroy,
	child_init,      /* per-child init function */
	0                /* reload confirm function */
};


xml_object_t *objects;


static int new_parsed_elem(xml_path_t *path, str tag_str, str idx_str)
{
	xml_element_t *elem = NULL, *it;

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

	if (idx_str.s) {
		if (*idx_str.s == '$') {
			if (!pv_parse_spec(&idx_str, &elem->idx_var)) {
				LM_ERR("Unable to parse variable in index\n");
				return -1;
			}
			elem->var_flags |= EL_VAR_IDX;
		} else {
			if (str2sint(&idx_str, &elem->idx) < 0) {
				LM_ERR("Invalid index\n");
				return -1;
			}
			if (elem->idx < 0) {
				LM_ERR("Negative index\n");
				return -1;
			}
		}
	}

	if (!path->elements)
		path->elements = elem;
	else {
		for (it = path->elements; it->next; it = it->next) ;
		it->next = elem;
	}

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
	xml_path_t *path = NULL;
	char *cur, *start;
	int prev_state = -1;
	str tag_str = {0,0}, idx_str = {0,0}, attr_str;

	path = pkg_malloc(sizeof *path);
	if(!path) {
		LM_ERR("No more pkg memory\n");
		return -1;
	}

	path->elements = NULL;

	/* first, get this xml object name */
	start = q_memchr(in->s, '/', in->len);
	if (!in->s || in->len == 0 || start == in->s) {
		LM_ERR("name required for this $xml var\n");
		return -1;
	}
	path->obj_name.s = in->s;
	path->obj_name.len = start ? start - in->s : in->len;

	path->attr.s = NULL;
	path->attr_is_var = 0;
	path->access_mode = ACCESS_EL;

	/* get each element in path */
	start = in->s + path->obj_name.len;
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

				if (new_parsed_elem(path, tag_str, idx_str) < 0)
					return -1;
			} else if (prev_state == ST_END_IDX) {
				if (new_parsed_elem(path, tag_str, idx_str) < 0)
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
				path->access_mode = ACCESS_EL_VAL;
			} else if (!memcmp(cur+1, "attr", 4)) {
				path->access_mode = ACCESS_EL_ATTR;

				attr_str.len = in->len - (cur - in->s + 6); /* 6 = len(".attr/") */
				if (attr_str.len == 0) {
					LM_ERR("Empty attribute\n");
					return -1;
				}
				attr_str.s = cur + 6;
				if (*attr_str.s == '$') {
					if (!pv_parse_spec(&attr_str, &path->attr_var)) {
						LM_ERR("Unable to parse variable in element attribute\n");
						return -1;
					}
					path->attr_is_var = 1;
				} else
					path->attr = attr_str;
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
		if (new_parsed_elem(path, tag_str, idx_str) < 0) {
					return -1;
		}
	} else if (prev_state == ST_START_NAME) {
		tag_str.len = cur - start;
		if (tag_str.len == 0) {
			LM_ERR("No element name\n");
			return -1;
		}
		tag_str.s = start;

		if (new_parsed_elem(path, tag_str, idx_str) < 0)
					return -1;
	}

	sp->pvp.pvn.u.dname = path;
	sp->pvp.pvv.s = NULL;

	return 0;
}


static inline xml_object_t *get_xml_obj(xml_path_t *path)
{
	xml_object_t *obj;

	for (obj = objects; obj; obj = obj->next)
		if (!str_strcmp(&obj->name, &path->obj_name))
			return obj;

	return NULL;
}

static int path_eval_vars(struct sip_msg* msg, xml_path_t *path)
{
	pv_value_t val;
	xml_element_t *el;

	memset(&val, 0, sizeof(pv_value_t));

	for (el = path->elements; el; el = el->next) {
		if (el->var_flags & EL_VAR_TAG) {
			if( pv_get_spec_value(msg, &el->tag_var ,&val) < 0) {
				LM_ERR("Unable to get value from element variable\n");
				return -1;
			}
			if (!(val.flags & PV_VAL_STR)) {
				LM_ERR("Non string value for element name\n");
				return -1;
			}
			el->tag = val.rs;
		}

		if (el->var_flags & EL_VAR_IDX) {
			if( pv_get_spec_value(msg, &el->idx_var ,&val) < 0) {
				LM_ERR("Unable to get value from index variable\n");
				return -1;
			}
			if (!(val.flags & PV_VAL_INT)) {
				LM_ERR("Non integer value for index\n");
				return -1;
			}
			el->idx = val.ri;
		}
	}

	if (path->attr_is_var) {
		if( pv_get_spec_value(msg, &path->attr_var ,&val) < 0) {
			LM_ERR("Unable to get value from attribute variable\n");
			return -1;
		}
		if (!(val.flags & PV_VAL_STR)) {
			LM_ERR("Non string value for attribute name\n");
			return -1;
		}
		path->attr = val.rs;
	}

	return 0;
}

static xmlNode *get_node_by_path(xmlNode *root, xml_element_t *path_el)
{
	xmlNode *cur;
	str n_name;
	int i;
	char *p;

	cur = root;
	while (path_el) {
		i = 0;
		while (cur) {
			n_name.s = (char *)cur->name;
			n_name.len = strlen(n_name.s);

			/* skip an undefined namespace prefix that may appear
			 * in the element name */
			p = q_memchr(n_name.s, ':', n_name.len);
			if (p) {
				n_name.len = n_name.len - (p - n_name.s + 1);
				n_name.s = p + 1;
			}

			if (!str_strcmp(&path_el->tag, &n_name)) {
				if (i == path_el->idx)
					break;
				else
					i++;
			}

			cur = xmlNextElementSibling(cur);
		}
		if (!cur) {
			if (i != 0) {
				LM_DBG("Invalid path for xml var - bad index [%d] for element: <%.*s>\n",
					path_el->idx, path_el->tag.len, path_el->tag.s);
				return NULL;
			} else {
				LM_DBG("Invalid path for xml var - no element named: <%.*s> \n",
					path_el->tag.len, path_el->tag.s);
				return NULL;
			}
		}

		if (!path_el->next)
			return cur;
		else {
			cur = cur->children;
			path_el = path_el->next;
		}
	}

	return NULL;
}


static int get_node_content(xmlNode *node, xmlBufferPtr xml_buf)
{
	xmlNode *n_it;

	for (n_it = node->children; n_it; n_it = n_it->next)
		if (n_it->type == XML_TEXT_NODE && xmlBufferCat(xml_buf, n_it->content) < 0) {
			LM_ERR("Unable to append string to xml buffer\n");
			return -1;
		}

	return 0;
}

static xmlAttr *get_node_attr(xmlNode *node, str attr_name)
{
	xmlAttr *cur_attr;
	str cur_attr_name;

	for (cur_attr = node->properties; cur_attr; cur_attr = cur_attr->next) {
		cur_attr_name.s = (char *)cur_attr->name;
		cur_attr_name.len = strlen(cur_attr_name.s);
		if (!str_strcmp(&cur_attr_name, &attr_name))
			return cur_attr;
	}

	return NULL;
}

static str res_buf;

int pv_get_xml(struct sip_msg* msg,  pv_param_t* pvp, pv_value_t* res)
{
	xml_path_t *path = NULL;
	xml_object_t *obj;
	xmlNode *root = NULL, *node;
	xmlBufferPtr xml_buf = NULL;
	xmlAttr *attr;
	char *xml_buf_s;
	int xml_buf_len;

	path = (xml_path_t *)pvp->pvn.u.dname;
	if (!path) {
		LM_BUG("No path for xml var\n");
		return pv_get_null( msg, pvp, res);
	}

	/* get the object refered in this xml var */
	obj = get_xml_obj(path);
	if (!obj) {
		LM_DBG("Unknown object <%.*s>\n", path->obj_name.len, path->obj_name.s);
		return pv_get_null( msg, pvp, res);
	}

	if (!obj->xml_doc) {
		LM_DBG("Empty xml object\n");
		return pv_get_null( msg, pvp, res);
	}

	if (path_eval_vars(msg, path) < 0)
		return -1;

	root = xmlDocGetRootElement(obj->xml_doc);
	if (path->elements) {
		node = get_node_by_path(root, path->elements);
		if (!node) {
			LM_DBG("Element not found\n");
			return pv_get_null( msg, pvp, res);
		}
	} else
		/* in case of dumping entire object, we do this from the root node */
		node = root;

	switch (path->access_mode) {
	case ACCESS_EL:
		if (!path->elements) {
			xmlDocDumpMemory(obj->xml_doc, (xmlChar **)&xml_buf_s, &xml_buf_len);
			/* libxml seems to place an unnecessary newline at the end of the doc dump */
			if (xml_buf_s[xml_buf_len-1] == '\n')
				xml_buf_len--;
		} else {
			xml_buf = xmlBufferCreate();
			if (!xml_buf) {
				LM_ERR("Unable to obtain xml buffer\n");
				return pv_get_null( msg, pvp, res);
			}

			xml_buf_len = xmlNodeDump(xml_buf, obj->xml_doc, node, 0, 0);
			if (xml_buf_len == -1) {
				LM_ERR("Unable to dump node to xml buffer\n");
				goto err_free_xml_buf;
			}

			xml_buf_s = (char *)xmlBufferContent(xml_buf);
			if (!xml_buf_s) {
				LM_ERR("Unable to obtain xml buffer content\n");
				goto err_free_xml_buf;
			}
		}

		if (pkg_str_extend(&res_buf, xml_buf_len) != 0) {
			LM_ERR("No more pkg mem\n");
			if (xml_buf)
				xmlBufferFree(xml_buf);
			else
				xmlFree(xml_buf_s);
			return pv_get_null( msg, pvp, res);
		}

		memcpy(res_buf.s, xml_buf_s, xml_buf_len);

		if (xml_buf)
			xmlBufferFree(xml_buf);
		else
			xmlFree(xml_buf_s);

		res->rs.s = res_buf.s;
		res->rs.len = xml_buf_len;

		break;
	case ACCESS_EL_VAL:
		xml_buf = xmlBufferCreate();
		if (!xml_buf) {
			LM_ERR("Unable to obtain xml buffer\n");
			return pv_get_null( msg, pvp, res);
		}

		if (get_node_content(node, xml_buf) < 0) {
			LM_ERR("Unable to get node text content\n");
			goto err_free_xml_buf;
		}

		xml_buf_len = xmlBufferLength(xml_buf);
		if (pkg_str_extend(&res_buf, xml_buf_len) != 0) {
			LM_ERR("No more pkg mem\n");
			goto err_free_xml_buf;
		}

		xml_buf_s = (char *)xmlBufferContent(xml_buf);
		if (!xml_buf_s) {
			LM_ERR("Unable to obtain xml buffer content\n");
			goto err_free_xml_buf;
		}
		memcpy(res_buf.s, xml_buf_s, xml_buf_len);

		xmlBufferFree(xml_buf);

		res->rs.s = res_buf.s;
		res->rs.len = xml_buf_len;

		break;
	case ACCESS_EL_ATTR:
		attr = get_node_attr(node, path->attr);
		if (!attr) {
			LM_DBG("Attribute: %.*s not found\n", path->attr.len, path->attr.s);
			return pv_get_null( msg, pvp, res);
		}
		res->rs.s = (char *)attr->children->content;
		res->rs.len = strlen(res->rs.s);
	}

	res->flags = PV_VAL_STR;

	return 0;

err_free_xml_buf:
	xmlBufferFree(xml_buf);
	return pv_get_null( msg, pvp, res);
}


static int insert_new_node(xmlDoc *doc, xmlNode *parent, xmlDoc *new_doc, xml_path_t *path, str xml_str)
{
	xmlNode *new_root, *lead_ws_node, *trail_ws_node;
	char lead_ws[64] = {0}, trail_ws[64] = {0};
	char *c;
	int lead_ws_len = 0, trail_ws_len = 0;

	/* libxml ignores leading and trailing whitespaces when parsing an XML
	 * block (if they are not contained IN the root node) so, when adding a
	 * new node, it would be impossible to insert it with indentation under
	 * an existing node unless we add the whitespaces manually as nodes in the tree
	 */

	/* add leading whitespaces node to existing tree */
	for (c = xml_str.s; c - xml_str.s < xml_str.len &&
		(*c == ' ' || *c == '\t' || *c == '\n'); c++)
		lead_ws[lead_ws_len++] = *c;

	if (lead_ws_len) {
		if ((lead_ws_node = xmlNewText(BAD_CAST lead_ws)) == NULL) {
			LM_ERR("Unable to create node with leading whitespaces\n");
			return -1;
		}
		if (!xmlAddChild(parent, lead_ws_node)) {
			LM_ERR("Unable to add node with leading whitespaces\n");
			return -1;
		}
	}

	/* add root of new xml block */
	new_root = xmlDocGetRootElement(new_doc);
	xmlSetTreeDoc(new_root, doc);
	if (!xmlAddChild(parent, new_root)) {
		LM_ERR("Unable to link new xml block into existing tree\n");
		return -1;
	}

	/* add trailing whitespaces node */
	c = NULL;
	for (c = xml_str.s + xml_str.len - 1; c > xml_str.s &&
		(*c == ' ' || *c == '\t' || *c == '\n'); c--) ;
	trail_ws_len = xml_str.len - (c+1 - xml_str.s);

	if (trail_ws_len) {
		memcpy(trail_ws, c+1, trail_ws_len);

		if ((trail_ws_node = xmlNewText(BAD_CAST trail_ws)) == NULL) {
			LM_ERR("Unable to create node with trailing whitespaces\n");
			return -1;
		}
		if (!xmlAddChild(parent, trail_ws_node)) {
			LM_ERR("Unable to add node with trailing whitespaces\n");
			return -1;
		}
	}

	return 0;
}

static int set_node_content(xmlNode *node, str new_content)
{
	xmlNode *n_it, *tmp = NULL, *new_txt;
	int set = 0;

	/* remove all text nodes */
	if (!new_content.s)
		set = 1;

	for (n_it = node->children; n_it; n_it = tmp) {
		tmp = n_it->next;

		if (n_it->type == XML_TEXT_NODE && !xmlIsBlankNode(n_it)) {
			if (!set) {
				/* replace existing text node content with given string */
				xmlNodeSetContentLen(n_it, BAD_CAST new_content.s, new_content.len);
				set = 1;
			} else {
				/* remove any other text node */
				xmlUnlinkNode(n_it);
				xmlFreeNode(n_it);
			}
		}
	}

	/* no existing text nodes, create one */
	if (new_content.s && !set) {
		if ((new_txt = xmlNewTextLen(BAD_CAST new_content.s, new_content.len)) == NULL) {
			LM_ERR("Unable to create text node\n");
			return -1;
		}
		if (!xmlAddChild(node, new_txt)) {
			LM_ERR("Unable to add text node\n");
			return -1;
		}
	}

	return 0;
}

int pv_set_xml(struct sip_msg* msg,  pv_param_t* pvp, int flag, pv_value_t* val)
{
	xml_path_t *path = NULL;
	xml_object_t *obj;
	xmlDoc *new_doc = NULL;
	xmlNode *root, *node = NULL;
	str empty_str = {0,0};
	char *attr_name_s, *attr_val_s;

	path = (xml_path_t *)pvp->pvn.u.dname;
	if (!path) {
		LM_BUG("No path for xml var\n");
		return -1;
	}

	/* get the object refered in this xml var */
	obj = get_xml_obj(path);

	if (path_eval_vars(msg, path) < 0)
		return -1;

	if (obj && obj->xml_doc && path->elements) {
		root = xmlDocGetRootElement(obj->xml_doc);
		node = get_node_by_path(root, path->elements);
		if (!node) {
			LM_NOTICE("Element not found\n");
			return -1;
		}
	}

	if (!val || val->flags & PV_VAL_NULL) {
		if (!obj) {
			LM_ERR("Uninitialized xml object: %.*s\n", path->obj_name.len,
				path->obj_name.s);
			return -1;
		}

		switch (path->access_mode) {
		case ACCESS_EL:
			if (!path->elements) { /* we only have the object name in path */
				if (!obj->xml_doc) /* attempted to clear empty xml object */
					return 0;

				/* clear the entire object */
				xmlFreeDoc(obj->xml_doc);
				obj->xml_doc = NULL;
			} else {
				/* delete node */
				if (!node) {
					LM_NOTICE("Element not found\n");
					return -1;
				}

				xmlUnlinkNode(node);
				xmlFreeNode(node);
			}
			break;
		case ACCESS_EL_VAL:
			if (!obj->xml_doc) {
				LM_NOTICE("Empty xml object\n");
				return -1;
			}
			if (!node) {
				LM_NOTICE("Element not found\n");
				return -1;
			}

			if (set_node_content(node, empty_str) < 0) {
				LM_ERR("Unable to clear text content for element <%s>\n", node->name);
				return -1;
			}
			break;
		case ACCESS_EL_ATTR:
			if (!obj->xml_doc) {
				LM_DBG("Empty xml object\n");
				return -1;
			}
			if (!node) {
				LM_NOTICE("Element not found\n");
				return -1;
			}

			attr_name_s = pkg_malloc(path->attr.len+1);
			if (!attr_name_s) {
				LM_ERR("No more pkg mem\n");
				return -1;
			}
			memcpy(attr_name_s, path->attr.s, path->attr.len);
			attr_name_s[path->attr.len] = 0;

			if (xmlUnsetProp(node, BAD_CAST attr_name_s) < 0) {
				LM_ERR("Unable to remove attribute: %s\n", attr_name_s);
				pkg_free(attr_name_s);
				return -1;
			}
			pkg_free(attr_name_s);
		}
	} else if (val->flags & PV_VAL_STR) {
		switch (path->access_mode) {
		case ACCESS_EL:
			if (!obj) {
				if (!path->elements) {
					/* "instantiate" xml object */
					obj = pkg_malloc(sizeof *obj);
					if (!obj) {
						LM_ERR("No more pkg memory\n");
						return -1;
					}
					obj->xml_doc = NULL;
					obj->name.len = path->obj_name.len;
					obj->name.s = path->obj_name.s;

					obj->next = objects;
					objects = obj;
				} else {
					LM_ERR("Unknown object <%.*s>\n", path->obj_name.len, path->obj_name.s);
					return -1;
				}
			}

			if (val->rs.len == 0) {
				if (!path->elements) {
					if (obj->xml_doc)
						/* clear the entire object if not empty */
						xmlFreeDoc(obj->xml_doc);

					obj->xml_doc = NULL;
				} else {
					LM_ERR("Empty string\n");
					return -1;
				}
			} else {
				/* parse given XML block and build a tree */
				new_doc = xmlParseMemory(val->rs.s, val->rs.len);
				if (!new_doc) {
					LM_ERR("Failed to parse xml block\n");
					return -1;
				}

				if (!path->elements) {
					/* clear the entire object if not empty */
					if (obj->xml_doc)
						xmlFreeDoc(obj->xml_doc);

					/* initialize object with given xml block */
					obj->xml_doc = new_doc;
				} else {
					if (insert_new_node(obj->xml_doc, node, new_doc, path, val->rs) < 0) {
						LM_ERR("Unable to add new element\n");
						return -1;
					}
				}
			}
			break;
		case ACCESS_EL_VAL:
			if (!obj) {
				LM_ERR("Uninitialized xml object: %.*s\n", path->obj_name.len,
					path->obj_name.s);
				return -1;
			}
			if (!obj->xml_doc) {
				LM_DBG("Empty xml object\n");
				return -1;
			}
			if (!node) {
				LM_NOTICE("Element not found\n");
				return -1;
			}

			if (set_node_content(node, val->rs) < 0) {
				LM_ERR("Unable to set content for element <%s>\n", node->name);
				return -1;
			}
			break;
		case ACCESS_EL_ATTR:
			if (!obj) {
				LM_ERR("Uninitialized xml object: %.*s\n", path->obj_name.len,
					path->obj_name.s);
				return -1;
			}
			if (!obj->xml_doc) {
				LM_DBG("Empty xml object\n");
				return -1;
			}
			if (!node) {
				LM_NOTICE("Element not found\n");
				return -1;
			}

			attr_name_s = pkg_malloc(path->attr.len+1);
			if (!attr_name_s) {
				LM_ERR("No more pkg mem\n");
				return -1;
			}
			memcpy(attr_name_s, path->attr.s, path->attr.len);
			attr_name_s[path->attr.len] = 0;

			attr_val_s = pkg_malloc(val->rs.len+1);
			if (!attr_val_s) {
				LM_ERR("No more pkg mem\n");
				return -1;
			}
			memcpy(attr_val_s, val->rs.s, val->rs.len);
			attr_val_s[val->rs.len] = 0;

			if (!xmlSetProp(node, BAD_CAST attr_name_s, BAD_CAST attr_val_s)) {
				LM_ERR("Unable to set/reset attribute: %s\n", attr_name_s);
				pkg_free(attr_name_s);
				pkg_free(attr_val_s);
				return -1;
			}
			pkg_free(attr_name_s);
			pkg_free(attr_val_s);
		}
	} else {
		LM_ERR("Non-string value\n");
		return -1;
	}

	return 0;
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
