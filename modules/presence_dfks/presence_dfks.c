/*
 * Copyright (C) 2019 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 *
 */

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <string.h>

#include "../../sr_module.h"
#include "../../mem/mem.h"
#include "../../dprint.h"
#include "../../pvar.h"
#include "../../ut.h"
#include "../../route.h"
#include "../../mi/mi.h"
#include "../../ipc.h"
#include "../../parser/parse_event.h"
#include "../presence/bind_presence.h"

#include "presence_dfks.h"

static int mod_init(void);

static int pv_set_dfks(struct sip_msg *msg, pv_param_t *param, int op,
	pv_value_t *val);
static int pv_get_dfks(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
static int pv_parse_dfks_name(pv_spec_p sp, str *in);

static str *dfks_handle_subscribe(str *pres_uri, str *subs_body,
	str *ct_type, int *suppress_notify);
static void pkg_free_w(char* s);

static mi_response_t *mi_dfks_set(const mi_params_t *params,
	struct mi_handler *async_hdl);

presence_api_t pres_api;
pres_ev_t *dfks_event;

static char *dfks_get_route = DEFAULT_GET_ROUTE_NAME;
static char *dfks_set_route = DEFAULT_SET_ROUTE_NAME;
static int dfks_get_route_idx;
static int dfks_set_route_idx;

static struct dfks_ctx feature_ctx;

static int features_no = BASE_FEATURES_NO;
static str feature_names[MAX_FEATURES_NO] = {str_init(FEATURE_DND_NAME),
	str_init(FEATURE_CFA_NAME), str_init(FEATURE_CFB_NAME),
	str_init(FEATURE_CFNA_NAME)};

static char *resp_root_nodes[MAX_FEATURES_NO] = {RESP_ROOT_NODE_DND,
	RESP_ROOT_NODE_FWD, RESP_ROOT_NODE_FWD, RESP_ROOT_NODE_FWD};
static char *req_root_nodes[MAX_FEATURES_NO] = {REQ_ROOT_NODE_DND,
	REQ_ROOT_NODE_FWD, REQ_ROOT_NODE_FWD, REQ_ROOT_NODE_FWD};

static char *resp_status_nodes[MAX_FEATURES_NO] = {STATUS_NODE_DND,
	RESP_STATUS_NODE_FWD, RESP_STATUS_NODE_FWD, RESP_STATUS_NODE_FWD};
static char *req_status_nodes[MAX_FEATURES_NO] = {STATUS_NODE_DND,
	REQ_STATUS_NODE_FWD, REQ_STATUS_NODE_FWD, REQ_STATUS_NODE_FWD};

static char *resp_value_nodes[MAX_FEATURES_NO][MAX_VALUES_NO] = {
	{NULL},
	{RESP_VALUE_NODE_FWD, NULL},
	{RESP_VALUE_NODE_FWD, NULL},
	{RESP_VALUE_NODE_FWD, VALUE_NODE_RING, NULL}
};
static char *req_value_nodes[MAX_FEATURES_NO][MAX_VALUES_NO] = {
	{NULL},
	{REQ_VALUE_NODE_FWD, NULL},
	{REQ_VALUE_NODE_FWD, NULL},
	{REQ_VALUE_NODE_FWD, VALUE_NODE_RING, NULL}
};

static char *type_nodes[MAX_FEATURES_NO] = {NULL,
	TYPE_NODE_FWD, TYPE_NODE_FWD, TYPE_NODE_FWD};

static char *type_values[MAX_FEATURES_NO] = {NULL,
	TYPE_VAL_FWD_CFA, TYPE_VAL_FWD_CFB, TYPE_VAL_FWD_CFNA};

static pv_export_t mod_items[] = {
	{ {"dfks", sizeof("dfks")-1}, 1000, pv_get_dfks, pv_set_dfks,
		pv_parse_dfks_name, 0, 0, 0},
	  { {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};

static param_export_t params[] = {
	{"get_route", STR_PARAM, &dfks_get_route},
	{"set_route", STR_PARAM, &dfks_set_route},
	{0, 0, 0}
};

static mi_export_t mi_cmds[] = {
	{ "dfks_set_feature", 0, 0, 0, {
		{mi_dfks_set, {"presentity", "feature", "status", 0}},
		{mi_dfks_set, {"presentity", "feature", "status", "values", 0}},
		{mi_dfks_set, {"presentity", "feature", "status", "route_param", 0}},
		{mi_dfks_set, {"presentity", "feature", "status", "route_param", "values", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "presence", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

struct module_exports exports = {
	"presence_dfks",    /* module name*/
	MOD_TYPE_DEFAULT, /* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,  /* dlopen flags */
	0,   		/* load function */
	&deps,          /* OpenSIPS module dependencies */
	0,          /* exported functions */
	0,          /* exported async functions */
	params,     /* module parameters */
	0,          /* exported statistics */
	mi_cmds,    /* exported MI functions */
	mod_items,  /* exported pseudo-variables */
	0,			/* exported transformations */
	0,          /* extra processes */
	0,          /* module pre-initialization function */
	mod_init,   /* module initialization function */
	0,          /* response function */
	0,			/* destroy function */
	0,          /* per-child init function */
	0           /* reload confirm function */
};

static int dfks_add_event(void)
{
	pres_ev_t event;
	event_t ev;

	memset(&event, 0, sizeof(pres_ev_t));
	event.name.s = DFKS_EVENT_NAME_S;
	event.name.len = DFKS_EVENT_NAME_LEN;
	event.content_type.s = CT_TYPE_DFKS;
	event.content_type.len = CT_TYPE_DFKS_LEN;
	event.default_expires= 3600;
	event.mandatory_body = 0;
	event.mandatory_timeout_notification = 0;
	event.type = PUBL_TYPE;

	event.build_notify_body = dfks_handle_subscribe;
	event.free_body = (free_body_t*)pkg_free_w;

	if (pres_api.add_event(&event) < 0)
		return -1;

	ev.parsed = EVENT_AS_FEATURE;
	ev.text = event.name;
	dfks_event = pres_api.search_event(&ev);
	if (!dfks_event) {
		LM_CRIT("Failed to get back the registered event\n");
		return -1;
	}

	return 0;
}

static int mod_init(void)
{
	bind_presence_t bind_presence;

	dfks_get_route_idx = get_script_route_ID_by_name(dfks_get_route,
		sroutes->request, RT_NO);
	if (dfks_get_route_idx == -1) {
		LM_ERR("GET route <%s> not defined in the script\n", dfks_get_route);
		return -1;
	}
	dfks_set_route_idx = get_script_route_ID_by_name(dfks_set_route,
		sroutes->request, RT_NO);
	if (dfks_set_route_idx == -1) {
		LM_ERR("SET route <%s> not defined in the script\n", dfks_set_route);
		return -1;
	}

	bind_presence = (bind_presence_t)find_export("bind_presence", 0);
	if (!bind_presence) {
		LM_ERR("Cannot find presence API export\n");
		return -1;
	}
	if (bind_presence(&pres_api) < 0) {
		LM_ERR("Cannot bind presence API\n");
		return -1;
	}

	if (dfks_add_event() < 0) {
		LM_ERR("Failed to add 'as-feature-event' presence event\n");
		return -1;
	}

	return 0;
}

static int pv_parse_dfks_name(pv_spec_p sp, str *in)
{
	struct dfks_pv_name *name;
	str val_node;

	name = pkg_malloc(sizeof *name);
	if (!name) {
		LM_ERR("oom\n");
		return -1;
	}
	memset(name, 0, sizeof *name);

	if (in->len > PV_SUBNAME_VALUE_LEN &&
		!memcmp(in->s, PV_SUBNAME_VALUE, PV_SUBNAME_VALUE_LEN)) {
		val_node.s = in->s + PV_SUBNAME_VALUE_LEN;
		val_node.len = in->len - PV_SUBNAME_VALUE_LEN;
		if (pkg_str_dup(&name->value_node, &val_node) < 0) {
			LM_ERR("oom\n");
			return -1;
		}
		name->type = PV_TYPE_VALUE;
	} else if (!str_strcmp(in, _str(PV_SUBNAME_ASSIGN))) {
		name->type = PV_TYPE_ASSIGN;
	} else if (!str_strcmp(in, _str(PV_SUBNAME_STATUS))) {
		name->type = PV_TYPE_STATUS;
	} else if (!str_strcmp(in, _str(PV_SUBNAME_FEATURE))) {
		name->type = PV_TYPE_FEATURE;
	} else if (!str_strcmp(in, _str(PV_SUBNAME_PRESENTITY))) {
		name->type = PV_TYPE_PRESENTITY;
	} else if (!str_strcmp(in, _str(PV_SUBNAME_NOTIFY))) {
		name->type = PV_TYPE_NOTIFY;
	} else if (!str_strcmp(in, _str(PV_SUBNAME_PARAM))) {
		name->type = PV_TYPE_PARAM;
	} else {
		LM_ERR("Bad subname for $dfks\n");
		return -1;
	}

	sp->pvp.pvn.u.dname = (void*)name;

	return 0;
}

static int get_value_idx(int feature_idx, str *val_node)
{
	int i, idx = -1;

	for (i = 0; i < MAX_VALUES_NO && resp_value_nodes[feature_idx][i]; i++)
		if (!str_strcmp(_str(resp_value_nodes[feature_idx][i]), val_node))
			idx = i;

	if (idx == -1)
		LM_DBG("Unknown value: %.*s\n", val_node->len,
			val_node->s);

	return idx;
}

static int pv_set_dfks(struct sip_msg *msg, pv_param_t *param, int op,
	pv_value_t *val)
{
	struct dfks_pv_name *name = (struct dfks_pv_name *)param->pvn.u.dname;
	int val_idx;

	switch (name->type) {
	case PV_TYPE_ASSIGN:
		if (!val || val->flags & PV_VAL_NULL)
			feature_ctx.assigned = 0;
		else if (val->flags & (PV_TYPE_INT|PV_VAL_INT))
			feature_ctx.assigned = val->ri ? 1 : 0;
		else {
			LM_ERR("Value should be an integer\n");
			return -1;
		}
		break;
	case PV_TYPE_NOTIFY:
		if (!val || val->flags & PV_VAL_NULL)
			feature_ctx.notify = 0;
		else if (val->flags & (PV_TYPE_INT|PV_VAL_INT))
			feature_ctx.notify = val->ri ? 1 : 0;
		else {
			LM_ERR("Value should be an integer\n");
			return -1;
		}
		break;
	case PV_TYPE_STATUS:
		if (!val || val->flags & PV_VAL_NULL)
			feature_ctx.status = 0;
		else if (val->flags & (PV_TYPE_INT|PV_VAL_INT))
			feature_ctx.status = val->ri ? 1 : 0;
		else {
			LM_ERR("Value should be an integer\n");
			return -1;
		}
		break;
	case PV_TYPE_VALUE:
		if ((val_idx = get_value_idx(feature_ctx.idx, &name->value_node)) < 0) {
			return 0;
		}

		if (!val || val->flags & PV_VAL_NULL) {
			feature_ctx.values[val_idx].s = NULL;
			feature_ctx.values[val_idx].len = 0;
		} else if (val->flags & PV_VAL_STR) {
			/* free the value if already strdup'ed */
			if (feature_ctx.values[val_idx].s)
				pkg_free(feature_ctx.values[val_idx].s);

			if (pkg_str_dup(&feature_ctx.values[val_idx], &val->rs) < 0) {
				LM_ERR("oom!\n");
				return -1;
			}
		}
		else {
			LM_ERR("Value should be a string\n");
			return -1;
		}
		break;
	case PV_TYPE_FEATURE:
		LM_INFO("$dfks(feature) is read-only\n");
		break;
	case PV_TYPE_PRESENTITY:
		LM_INFO("$dfks(presentity) is read-only\n");
		break;
	case PV_TYPE_PARAM:
		LM_INFO("$dfks(route_param) is read-only\n");
		break;
	default:
		LM_ERR("Bad $dfks subname\n");
		return -1;
	}

	return 0;
}

static int pv_get_dfks(struct sip_msg *msg, pv_param_t *param, pv_value_t *res)
{
	struct dfks_pv_name *name = (struct dfks_pv_name *)param->pvn.u.dname;
	int val_idx;

	switch (name->type) {
	case PV_TYPE_ASSIGN:
		res->ri = feature_ctx.assigned;
		res->rs.s = int2str(res->ri, &res->rs.len);
		res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;
		break;
	case PV_TYPE_NOTIFY:
		res->ri = feature_ctx.notify;
		res->rs.s = int2str(res->ri, &res->rs.len);
		res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;
		break;
	case PV_TYPE_STATUS:
		res->ri = feature_ctx.status;
		res->rs.s = int2str(res->ri, &res->rs.len);
		res->flags = PV_VAL_STR|PV_VAL_INT|PV_TYPE_INT;
		break;
	case PV_TYPE_VALUE:
		if ((val_idx = get_value_idx(feature_ctx.idx, &name->value_node)) < 0)
			return pv_get_null(msg, param, res);

		if (feature_ctx.values[val_idx].s) {
			res->rs = feature_ctx.values[val_idx];
			res->flags = PV_VAL_STR;
		} else
			return pv_get_null(msg, param, res);
		break;
	case PV_TYPE_FEATURE:
		res->rs = feature_names[feature_ctx.idx];
		res->flags = PV_VAL_STR;
		break;
	case PV_TYPE_PRESENTITY:
		res->rs = feature_ctx.pres_uri;
		res->flags = PV_VAL_STR;
		break;
	case PV_TYPE_PARAM:
		if (feature_ctx.param.len == 0 && feature_ctx.param.s == NULL)
			return pv_get_null(msg, param, res);
		res->rs = feature_ctx.param;
		res->flags = PV_VAL_STR;
		break;
	default:
		LM_ERR("Bad $dfks subname\n");
		return pv_get_null(msg, param, res);
	}

	return 0;
}

static int run_dfks_route(int route_idx)
{
	struct sip_msg *req;

	/* prepare a fake/dummy request */
	req = get_dummy_sip_msg();
	if(req == NULL) {
		LM_ERR("cannot create new dummy sip request\n");
		return -1;
	}

	set_route_type(REQUEST_ROUTE);

	LM_DBG("Running DFKS %s route for feature <%.*s> presentity <%.*s>\n",
		route_idx == dfks_get_route_idx ? "GET" : "SET",
		feature_names[feature_ctx.idx].len, feature_names[feature_ctx.idx].s,
		feature_ctx.pres_uri.len, feature_ctx.pres_uri.s);
	run_top_route(sroutes->request[route_idx].a, req);

	release_dummy_sip_msg(req);

	/* remove all added AVP - here we use all the time the default AVP list */
	reset_avps( );

	return 0;
}

static xmlDoc *build_feature_doc(int feature_idx)
{
	xmlDoc *doc;
	xmlNode *root_node, *node, *text_node;
	xmlNs *default_ns;
	int j;

	doc = xmlNewDoc(BAD_CAST XML_VERSION_STR);
	if (!doc) {
		LM_ERR("Failed to create xml document\n");
		return NULL;
	}

	root_node = xmlNewNode(NULL, BAD_CAST resp_root_nodes[feature_idx]);
	if (!root_node) {
		LM_ERR("Failed to create xml node\n");
		goto error;
	}
	xmlDocSetRootElement(doc, root_node);

	default_ns = xmlNewNs(root_node, BAD_CAST DFKS_NS_STR, NULL);
	if (!default_ns) {
		LM_ERR("Failed to create xml namespace\n");
		goto error;
	}

	node = xmlNewTextChild(root_node, NULL,
		BAD_CAST DEVICE_NODE_NAME, BAD_CAST DEVICE_NODE_MAGIC_VAL);
	if (!node) {
		LM_ERR("Failed to create xml node\n");
		goto error;
	}

	if (type_nodes[feature_idx]) {
		node = xmlNewTextChild(root_node, NULL,
			BAD_CAST type_nodes[feature_idx], BAD_CAST type_values[feature_idx]);
		if (!node) {
			LM_ERR("Failed to create xml node\n");
			goto error;
		}
	}

	node = xmlNewTextChild(root_node, NULL,
		BAD_CAST resp_status_nodes[feature_idx], feature_ctx.status ?
		BAD_CAST STATUS_VAL_TRUE : BAD_CAST STATUS_VAL_FALSE);
	if (!node) {
		LM_ERR("Failed to create xml node\n");
		goto error;
	}

	for (j = 0; j < MAX_VALUES_NO; j++) {
		if (feature_ctx.values[j].s && resp_value_nodes[feature_idx][j]) {
			node = xmlNewChild(root_node, NULL,
				BAD_CAST resp_value_nodes[feature_idx][j], NULL);
			if (!node) {
				LM_ERR("Failed to create xml node\n");
				goto error;
			}
			text_node = xmlNewTextLen(BAD_CAST feature_ctx.values[j].s,
				feature_ctx.values[j].len);
			if (!text_node) {
				LM_ERR("Failed to create xml node\n");
				goto error;
			}
			if (!xmlAddChild(node, text_node)) {
				LM_ERR("Failed to add xml node to parent\n");
				goto error;
			}
		}
	}

	return doc;

error:
	xmlFreeDoc(doc);
	return NULL;
}

static void free_ctx_values(void)
{
	int j;

	for (j = 0; j < MAX_VALUES_NO; j++)
		if (feature_ctx.values[j].s) {
			pkg_free(feature_ctx.values[j].s);
			feature_ctx.values[j].s = NULL;
		}
}

static str *build_full_notify(str *pres_uri, str *content_type)
{
	int i;
	int no_xmls = 0;
	str xml_bufs[MAX_FEATURES_NO];
	xmlDoc *doc;
	int len=0;
	str *notify_body = NULL;

	memset(xml_bufs, 0, MAX_FEATURES_NO * sizeof(str));

	for (i = 0; i < features_no; i++) {
		feature_ctx.assigned = 1;
		feature_ctx.notify = 1;
		feature_ctx.status = 0;
		memset(feature_ctx.values, 0, MAX_VALUES_NO * sizeof(str));
		feature_ctx.idx = i;
		feature_ctx.pres_uri = *pres_uri;
		run_dfks_route(dfks_get_route_idx);

		if (feature_ctx.assigned && feature_ctx.notify) {
			doc = build_feature_doc(i);

			free_ctx_values();

			if (!doc) {
				LM_ERR("Failed to build XML document for feature <%.*s>\n",
					feature_names[i].len, feature_names[i].s);
				continue;
			}

			xmlDocDumpMemoryEnc(doc,
				(xmlChar **)&xml_bufs[i].s, &xml_bufs[i].len, XML_ENC);
			if (!xml_bufs[i].s || xml_bufs[i].len == 0)
				LM_ERR("Failed to dump XML document for feature <%.*s>\n",
					feature_names[i].len, feature_names[i].s);
			else {
				if (xml_bufs[i].s[xml_bufs[i].len-1] == '\n')
					xml_bufs[i].len--;
				no_xmls++;
			}

			xmlFreeDoc(doc);
		} else {
			free_ctx_values();
		}
	}

	if (no_xmls == 0) {
		LM_DBG("Empty NOTIFY body\n");
		content_type->s = NULL;
		content_type->len = 0;
		return NULL;
	} else if (no_xmls == 1) {
		if (pkg_str_dup(content_type, _str(CT_TYPE_DFKS)) < 0) {
			LM_ERR("oom!\n");
			goto error;
		}
	} else {
		if (pkg_str_dup(content_type, _str(CT_TYPE_MULTIPART)) < 0) {
			LM_ERR("oom!\n");
			goto error;
		}
	}

	notify_body = pkg_malloc(sizeof *notify_body);
	if (!notify_body) {
		LM_ERR("oom\n");
		goto error;
	}

	notify_body->len = 0;
	if (no_xmls > 1)
		notify_body->len += no_xmls * (MULTIPART_BOUNDARY_LEN + CRLF_LEN +
			CT_TYPE_DFKS_HDR_LEN + CRLF_LEN + CRLF_LEN + CRLF_LEN) +
			MULTIPART_BOUNDARY_END_LEN + CRLF_LEN;
	else
		notify_body->len += CRLF_LEN;
	for (i = 0; i < features_no; i++)
		if (xml_bufs[i].s)
			notify_body->len += xml_bufs[i].len;

	notify_body->s = pkg_malloc(notify_body->len);
	if (!notify_body->s) {
		LM_ERR("oom\n");
		for (i = 0; i < features_no; i++)
			if (xml_bufs[i].s)
				xmlFree(xml_bufs[i].s);
		goto error;
	}

	for (i = 0; i < features_no; i++) {
		if (!xml_bufs[i].s)
			continue;

		if (no_xmls > 1) {
			memcpy(notify_body->s+len, MULTIPART_BOUNDARY, MULTIPART_BOUNDARY_LEN);
			len += MULTIPART_BOUNDARY_LEN;
			memcpy(notify_body->s+len, CRLF, CRLF_LEN);
			len += CRLF_LEN;

			memcpy(notify_body->s+len, CT_TYPE_DFKS_HDR, CT_TYPE_DFKS_HDR_LEN);
			len += CT_TYPE_DFKS_HDR_LEN;
			memcpy(notify_body->s+len, CRLF, CRLF_LEN);
			len += CRLF_LEN;

			memcpy(notify_body->s+len, CRLF, CRLF_LEN);
			len += CRLF_LEN;
		}

		memcpy(notify_body->s + len, xml_bufs[i].s, xml_bufs[i].len);
		len += xml_bufs[i].len;
		memcpy(notify_body->s+len, CRLF, CRLF_LEN);
		len += CRLF_LEN;

		xmlFree(xml_bufs[i].s);
	}

	if (no_xmls > 1) {
		memcpy(notify_body->s+len, MULTIPART_BOUNDARY_END,
			MULTIPART_BOUNDARY_END_LEN);
		len += MULTIPART_BOUNDARY_END_LEN;
		memcpy(notify_body->s+len, CRLF, CRLF_LEN);
		len += CRLF_LEN;
	}

	return notify_body;
error:
	if (notify_body) {
		if (notify_body->s)
			pkg_free(notify_body->s);
		pkg_free(notify_body);
	}
	content_type->s = NULL;
	content_type->len = 0;
	return (str*)-1;
}

static char *get_node_content(xmlNode *root, char *name, int required,
	str *content)
{
	xmlNode *node;
	char *xml_s;

	for (node = root->children; node; node = xmlNextElementSibling(node))
		if (!strcmp((char *)node->name, name))
			break;
	if (!node) {
		if (required) {
			LM_ERR("Missing '%s' node\n", name);
			return NULL;
		} else
			return NULL;
	}
	xml_s = (char *)xmlNodeGetContent(node);
	if (!xml_s) {
		LM_ERR("No content for '%s' node\n", name);
		return NULL;
	}
	init_str(content, xml_s);
	trim_len(content->len, content->s, *content);

	return xml_s;
}

static int parse_subscribe_xml(str *subs_body, int *feature_idx)
{
	xmlDoc *doc;
	xmlNode *root;
	int i, j;
	str ct = {NULL,0};
	char *xml_s = NULL;
	int rc = 0;

	doc = xmlParseMemory(subs_body->s, subs_body->len);
	if (!doc) {
		LM_ERR("Failed to parse xml\n");
		return -1;
	}

	root = xmlDocGetRootElement(doc);
	if (!root) {
		LM_ERR("Failed to get root node\n");
		rc = -1;
		goto end;
	}

	for (i = 0; i < features_no; i++) {
		if (strcmp((char *)root->name, req_root_nodes[i]))
			continue;

		/* if a 'type' node is defined, the feature is matched by
		 * root node _and_ type node's value */
		if (type_nodes[i]) {
			if (!xml_s) {
				xml_s = get_node_content(root, type_nodes[i], 1, &ct);
				if (!xml_s) {
					rc = -1;
					goto end;
				}
			}

			if (!str_strcmp(&ct, _str(type_values[i])))
				break;
		} else
			break;
	}
	if (i == features_no) {
		LM_ERR("Unknown feature <%s> <%.*s>\n", BAD_CAST root->name,
			ct.len, ct.s);
		rc = -1;
		goto end;
	}
	*feature_idx = i;

	xmlFree(xml_s);

	xml_s = get_node_content(root, req_status_nodes[*feature_idx], 1, &ct);
	if (!xml_s) {
		rc = -1;
		goto end;
	}
	if (!str_strcmp(&ct, _str(STATUS_VAL_TRUE)))
		feature_ctx.status = 1;
	else if (!str_strcmp(&ct, _str(STATUS_VAL_FALSE)))
		feature_ctx.status = 0;
	else {
		LM_ERR("Bad value for '%s' node\n", req_status_nodes[*feature_idx]);
		rc = -1;
		goto end;
	}

	xmlFree(xml_s);
	xml_s = NULL;

	for (j = 0; j < MAX_VALUES_NO; j++)
		if (!req_value_nodes[*feature_idx][j]) {
			feature_ctx.values[j].s = NULL;
			feature_ctx.values[j].len = 0;
			continue;
		} else {
			xml_s = get_node_content(root,
				req_value_nodes[*feature_idx][j], 0, &ct);
			if (!xml_s) {
				feature_ctx.values[j].s = NULL;
				feature_ctx.values[j].len = 0;
			} else {
				if (pkg_str_dup(&feature_ctx.values[j], &ct) < 0) {
					LM_ERR("oom!\n");
					rc = -1;
				}

				xmlFree(xml_s);
				xml_s = NULL;
			}
		}

end:
	if (xml_s)
		xmlFree(xml_s);
	xmlFreeDoc(doc);
	return rc;
}

static str *build_feature_notify(str *pres_uri, int feature_idx, int from_subs,
	str *param, str *content_type)
{
	xmlDoc *doc = NULL;
	str xml_buf = {0,0};
	str *notify_body = NULL;

	feature_ctx.assigned = 1;
	feature_ctx.notify = 1;
	feature_ctx.idx = feature_idx;
	feature_ctx.pres_uri = *pres_uri;
	if (!param) {
		feature_ctx.param.len = 0;
		feature_ctx.param.s = NULL;
	} else {
		feature_ctx.param = *param;
	}

	run_dfks_route(dfks_set_route_idx);

	if (!feature_ctx.notify)
		goto end;

	if (feature_ctx.assigned ||
		/* if not triggered by a SUBSCRIBE, the NOTIFY must always have a body
		 * (even if $dfks(assigned) is set to 0 in the SET route) */
		!from_subs) {
		doc = build_feature_doc(feature_idx);
		if (!doc) {
			LM_ERR("Failed to build XML document tree\n");
			goto error;
		}

		xmlDocDumpMemoryEnc(doc,
			(xmlChar **)&xml_buf.s, &xml_buf.len, XML_ENC);
		if (!xml_buf.s || xml_buf.len == 0) {
			LM_ERR("Failed to dump XML document\n");
			goto error;
		}
		if (xml_buf.s[xml_buf.len-1] == '\n')
			xml_buf.len--;

		notify_body = pkg_malloc(sizeof *notify_body);
		if (!notify_body) {
			LM_ERR("oom\n");
			goto error;
		}
		if (pkg_str_dup(notify_body, &xml_buf) < 0) {
			LM_ERR("oom!\n");
			goto error;
		}

		xmlFree(xml_buf.s);
		xml_buf.s = NULL;
		xmlFreeDoc(doc);
		doc = NULL;

		if (pkg_str_dup(content_type, _str(CT_TYPE_DFKS)) < 0) {
			LM_ERR("oom!\n");
			goto error;
		}
	} else {
		LM_DBG("Empty NOTIFY body\n");
		content_type->s = NULL;
		content_type->len = 0;
	}
end:
	free_ctx_values();

	return notify_body;
error:
	if (notify_body) {
		if (notify_body->s)
			pkg_free(notify_body->s);
		pkg_free(notify_body);
	}
	free_ctx_values();
	if (xml_buf.s)
		xmlFree(xml_buf.s);
	if (doc)
		xmlFreeDoc(doc);
	return (str*)-1;
}

static str *dfks_handle_subscribe(str *pres_uri, str *subs_body,
		str *ct_type, int *suppress_notify)
{
	str *notify_body;
	int feature_idx;

	if (subs_body->len == 0) {
		if ((notify_body = build_full_notify(pres_uri, ct_type)) == (str*)-1) {
			LM_ERR("Failed to build NOTIFY body\n");
			goto no_repl;
		}

		if (!feature_ctx.notify) {
			LM_DBG("NOTIFY suppressed\n");
			goto no_repl;
		}

		LM_DBG("Built full feature status for presentity <%.*s>\n",
			pres_uri->len, pres_uri->s);
		return notify_body;
	} else {
		if (parse_subscribe_xml(subs_body, &feature_idx) < 0) {
			LM_ERR("Invalid XML in SUBSCRIBE body\n");
			goto no_repl;
		}
		LM_DBG("Received feature status update for feature <%.*s>, "
			"presentity <%.*s> - new status <%d>\n",
			feature_names[feature_idx].len, feature_names[feature_idx].s,
			pres_uri->len, pres_uri->s, feature_ctx.status);

		notify_body = build_feature_notify(pres_uri, feature_idx, 1, NULL, ct_type);
		if (notify_body == (str*)-1) {
			LM_ERR("Failed to build NOTIFY body\n");
			goto no_repl;
		}

		if (!feature_ctx.notify) {
			LM_DBG("NOTIFY suppressed\n");
			goto no_repl;
		}

		if (pres_api.notify_all_on_publish(pres_uri, dfks_event, notify_body) < 0)
			LM_ERR("Failed to notify all subscribers\n");

		if (notify_body) {
			if (notify_body->s)
				pkg_free(notify_body->s);
			pkg_free(notify_body);
		}
		if (ct_type->s)
			pkg_free(ct_type->s);
	}

no_repl:
	*suppress_notify = 1;
	return NULL;
}

static void pkg_free_w(char* s)
{
	pkg_free(s);
}

void mi_feature_notify(int sender, void *_params)
{
	struct dfks_ipc_params *params = (struct dfks_ipc_params *)_params;
	str *notify_body = NULL;
	str ct_type = {NULL, 0};
	int j;

	feature_ctx.status = params->status ? 1 : 0;
	memset(feature_ctx.values, 0, MAX_VALUES_NO * sizeof(str));

	for (j = 0; j < MAX_VALUES_NO; j++)
		if (params->values[j].s &&
			pkg_str_dup(&feature_ctx.values[j], &params->values[j]) < 0) {
			LM_ERR("oom!\n");
			goto end;
		}

	notify_body = build_feature_notify(&params->pres_uri, params->feature_idx,
		0, &params->param, &ct_type);
	if (notify_body == (str*)-1) {
		LM_ERR("Failed to build NOTIFY body\n");
		goto end;
	}

	if (!feature_ctx.notify) {
		LM_DBG("NOTIFY suppressed\n");
		goto end;
	}

	if (ct_type.s)
		pkg_free(ct_type.s);

	if (pres_api.notify_all_on_publish(&params->pres_uri, dfks_event,
		notify_body) < 0) {
		LM_ERR("Failed to notify subscribers\n");
		goto end;
	}

end:
	if (params->param.len && params->param.s)
		shm_free(params->param.s);
	shm_free(params->pres_uri.s);
	for (j = 0; j < MAX_VALUES_NO; j++)
		if (params->values[j].s)
			shm_free(params->values[j].s);
	shm_free(params);

	if (notify_body) {
		if (notify_body->s)
			pkg_free(notify_body->s);
		pkg_free(notify_body);
	}
}

int ipc_dispatch_feature_notify(str *pres_uri, int feature_idx, int status,
	str *values, str *param)
{
	struct dfks_ipc_params *params;
	int i;
	str val_node;
	str val;
	int val_idx;

	params = shm_malloc(sizeof *params);
	if (!params) {
		LM_ERR("oom!\n");
		return -1;
	}
	memset(params, 0, sizeof *params);

	params->feature_idx = feature_idx;
	params->status = status;

	if (param->s && param->len && shm_str_dup(&params->param, param) < 0) {
		LM_ERR("oom!\n");
		goto error;
	}

	if (shm_str_dup(&params->pres_uri, pres_uri) < 0) {
		LM_ERR("oom!\n");
		goto error;
	}

	memset(params->values, 0, MAX_VALUES_NO * sizeof(str));

	for (i = 0; i < MAX_VALUES_NO; i++)
		if (values[i].s) {
			val.s = q_memchr(values[i].s, '/', values[i].len);
			if (!val.s) {
				LM_ERR("Missing '/' value separator\n");
				goto error;
			}
			val_node.s = values[i].s;
			val_node.len = val.s - values[i].s;
			val.s++;
			val.len = values[i].len - val_node.len - 1;

			val_idx = get_value_idx(feature_idx, &val_node);
			if (val_idx < 0) {
				LM_ERR("Unknown value node: %.*s\n", val_node.len, val_node.s);
				goto error;
			}

			if (shm_str_dup(&params->values[val_idx], &val) < 0) {
				LM_ERR("oom!\n");
				goto error;
			}
		}

	return ipc_dispatch_rpc(mi_feature_notify, params);

error:
	if (params->param.s)
		shm_free(params->param.s);
	if (params->pres_uri.s)
		shm_free(params->pres_uri.s);
	for (i = 0; i < MAX_VALUES_NO; i++)
		if (params->values[i].s)
			shm_free(params->values[i].s);
	shm_free(params);
	return -1;
}

static mi_response_t *mi_dfks_set(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	str param;
	str pres_uri;
	str feature;
	int status;
	str values[MAX_VALUES_NO];
	int i, j;
	mi_item_t *vals_arr;
	int no_vals = 0;

	if (get_mi_string_param(params, "presentity", &pres_uri.s, &pres_uri.len) < 0)
		return init_mi_param_error();

	if (get_mi_string_param(params, "feature", &feature.s, &feature.len) < 0)
		return init_mi_param_error();
	for (i = 0; i < features_no; i++)
		if (!str_strcmp(&feature, &feature_names[i]))
			break;
	if (i == features_no)
		return init_mi_error(400, MI_SSTR("Unknown feature"));

	if (get_mi_int_param(params, "status", &status) < 0)
		return init_mi_param_error();

	if (try_get_mi_string_param(params, "route_param", &param.s, &param.len) < 0) {
		param.len = 0;
		param.s = NULL;
	}

	memset(values, 0, MAX_VALUES_NO * sizeof(str));

	if (try_get_mi_array_param(params, "values", &vals_arr, &no_vals) == 0) {
		for (j = 0; j < no_vals; j++)
			if (get_mi_arr_param_string(vals_arr, j,
				&values[j].s, &values[j].len) < 0)
				return init_mi_param_error();
	}

	if (ipc_dispatch_feature_notify(&pres_uri, i, status, values, &param) < 0) {
		LM_ERR("Failed to dispatch NOTIFY sending to worker process\n");
		return init_mi_error(500, MI_SSTR("Internal Error"));
	}

	return init_mi_result_ok();
}
