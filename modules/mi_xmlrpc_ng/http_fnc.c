/*
 * Copyright (C) 2013 VoIP Embedded, Inc.
 *
 * This file is part of Open SIP Server (opensips).
 *
 * opensips is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */


#include <libxml/parser.h>

#include "../../str.h"
#include "../../ut.h"
#include "../../strcommon.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../mi/mi.h"
#include "../../config.h"
#include "../../globals.h"
#include "../../locking.h"
#include "../../strcommon.h"

#include "http_fnc.h"
#include "../../mi/mi_trace.h"
#include "../httpd/httpd_load.h"


#define MI_XMLRPC_XML_METHOD_CALL_NODE 	"methodCall"
#define MI_XMLRPC_XML_METHOD_NAME_NODE 	"methodName"
#define MI_XMLRPC_XML_PARAMS_NODE      	"params"
#define MI_XMLRPC_XML_PARAM_NODE       	"param"
#define MI_XMLRPC_XML_VALUE_NODE       	"value"

#define MI_XMLRPC_XML_STRING_NODE      	"string"
#define MI_XMLRPC_XML_INT_NODE      	"int"
#define MI_XMLRPC_XML_I4_NODE      		"i4"
#define MI_XMLRPC_XML_ARRAY_NODE      	"array"
#define MI_XMLRPC_XML_DATA_NODE      	"data"
#define MI_XMLRPC_XML_STRUCT_NODE      	"struct"
#define MI_XMLRPC_XML_MEMBER_NODE      	"member"
#define MI_XMLRPC_XML_NAME_NODE      	"name"


extern str http_root;
extern trace_dest t_dst;
extern httpd_api_t httpd_api;
extern int mi_trace_mod_id;

gen_lock_t* mi_xmlrpc_http_lock;

#define MI_XMLRPC_HTTP_COPY(p,str)	\
do{	\
	if ((int)((p)-buf)+(str).len>max_page_len) {	\
		goto error;	\
	}	\
	memcpy((p), (str).s, (str).len); (p) += (str).len;	\
}while(0)

#define MI_XMLRPC_HTTP_COPY_2(p,str1,str2)	\
do{	\
	if ((int)((p)-buf)+(str1).len+(str2).len>max_page_len) {	\
		goto error;	\
	}	\
	memcpy((p), (str1).s, (str1).len); (p) += (str1).len;	\
	memcpy((p), (str2).s, (str2).len); (p) += (str2).len;	\
}while(0)

#define MI_XMLRPC_HTTP_ESC_COPY(p,str,temp_holder,temp_counter)	\
do{	\
	(temp_holder).s = (str).s;	\
	(temp_holder).len = 0;	\
	for((temp_counter)=0;(temp_counter)<(str).len;(temp_counter)++) {	\
		switch((str).s[(temp_counter)]) {	\
		case '<':	\
			(temp_holder).len = (temp_counter) - (temp_holder).len;	\
			MI_XMLRPC_HTTP_COPY_2(p, (temp_holder), MI_XMLRPC_HTTP_ESC_LT);	\
			(temp_holder).s += (temp_holder).len + 1;	\
			(temp_holder).len = (temp_counter) + 1;	\
			break;	\
		case '>':	\
			(temp_holder).len = (temp_counter) - (temp_holder).len;	\
			MI_XMLRPC_HTTP_COPY_2(p, (temp_holder), MI_XMLRPC_HTTP_ESC_GT);	\
			(temp_holder).s += (temp_holder).len + 1;	\
			(temp_holder).len = (temp_counter) + 1;	\
			break;	\
		case '&':	\
			(temp_holder).len = (temp_counter) - (temp_holder).len;	\
			MI_XMLRPC_HTTP_COPY_2(p, (temp_holder), MI_XMLRPC_HTTP_ESC_AMP);	\
			(temp_holder).s += (temp_holder).len + 1;	\
			(temp_holder).len = (temp_counter) + 1;	\
			break;	\
		case '"':	\
			(temp_holder).len = (temp_counter) - (temp_holder).len;	\
			MI_XMLRPC_HTTP_COPY_2(p, (temp_holder), MI_XMLRPC_HTTP_ESC_QUOT);	\
			(temp_holder).s += (temp_holder).len + 1;	\
			(temp_holder).len = (temp_counter) + 1;	\
			break;	\
		case '\'':	\
			(temp_holder).len = (temp_counter) - (temp_holder).len;	\
			MI_XMLRPC_HTTP_COPY_2(p, (temp_holder), MI_XMLRPC_HTTP_ESC_SQUOT);	\
			(temp_holder).s += (temp_holder).len + 1;	\
			(temp_holder).len = (temp_counter) + 1;	\
			break;	\
		}	\
	}	\
	(temp_holder).len = (temp_counter) - (temp_holder).len;	\
	MI_XMLRPC_HTTP_COPY(p, (temp_holder));	\
}while(0)

static const str MI_XMLRPC_HTTP_XML_START = str_init(MI_XMLRPC_XML_START);
static const str MI_XMLRPC_HTTP_XML_STOP = str_init(MI_XMLRPC_XML_STOP);

static const str MI_XMLRPC_HTTP_ESC_LT =    str_init("&lt;");   /* < */
static const str MI_XMLRPC_HTTP_ESC_GT =    str_init("&gt;");   /* > */
static const str MI_XMLRPC_HTTP_ESC_AMP =   str_init("&amp;");  /* & */
static const str MI_XMLRPC_HTTP_ESC_QUOT =  str_init("&quot;"); /* " */
static const str MI_XMLRPC_HTTP_ESC_SQUOT = str_init("&#39;");  /* ' */

static const str MI_XMLRPC_HTTP_STRUCT_START = str_init("<struct>");
static const str MI_XMLRPC_HTTP_STRUCT_END = str_init("</struct>");
static const str MI_XMLRPC_HTTP_MEMBER_START = str_init("<member>");
static const str MI_XMLRPC_HTTP_MEMBER_END = str_init("</member>");
static const str MI_XMLRPC_HTTP_NAME_START = str_init("<name>");
static const str MI_XMLRPC_HTTP_NAME_END = str_init("</name>");
static const str MI_XMLRPC_HTTP_VALUE_START = str_init("<value>");
static const str MI_XMLRPC_HTTP_VALUE_END = str_init("</value>");

static const str MI_XMLRPC_HTTP_BOOL_START = str_init("<boolean>");
static const str MI_XMLRPC_HTTP_BOOL_END = str_init("</boolean>");
static const str MI_XMLRPC_HTTP_NIL = str_init("<nil/>");
static const str MI_XMLRPC_HTTP_INT_START = str_init("<int>");
static const str MI_XMLRPC_HTTP_INT_END = str_init("</int>");
static const str MI_XMLRPC_HTTP_DOUBLE_START = str_init("<double>");
static const str MI_XMLRPC_HTTP_DOUBLE_END = str_init("</double>");
static const str MI_XMLRPC_HTTP_STRING_START = str_init("<string>");
static const str MI_XMLRPC_HTTP_STRING_END = str_init("</string>");

static const str MI_XMLRPC_HTTP_FALSE_VALUE = str_init("0");
static const str MI_XMLRPC_HTTP_TRUE_VALUE = str_init("1");

static const str MI_XMLRPC_HTTP_ARRAY_START = str_init("<array>");
static const str MI_XMLRPC_HTTP_ARRAY_END = str_init("</array>");
static const str MI_XMLRPC_HTTP_DATA_START = str_init("<data>");
static const str MI_XMLRPC_HTTP_DATA_END = str_init("</data>");

static int mi_xmlrpc_get_param(xmlNodePtr value_node, mi_item_t *req_params_item,
									const char *name);

int mi_xmlrpc_http_init_async_lock(void)
{
	mi_xmlrpc_http_lock = lock_alloc();
	if (mi_xmlrpc_http_lock==NULL) {
		LM_ERR("failed to create lock\n");
		return -1;
	}
	if (lock_init(mi_xmlrpc_http_lock)==NULL) {
		LM_ERR("failed to init lock\n");
		return -1;
	}
	return 0;
}

xmlNodePtr mi_xmlNodeGetNodeByName(xmlNodePtr node, const char *name)
{
	xmlNodePtr cur = node;
	while (cur) {
		if(xmlStrcasecmp(cur->name, (const xmlChar*)name)==0)
			return cur;
		cur = cur->next;
	}
	return NULL;
}

void mi_xmlrpc_http_destroy_async_lock(void)
{
	if (mi_xmlrpc_http_lock) {
		lock_destroy(mi_xmlrpc_http_lock);
		lock_dealloc(mi_xmlrpc_http_lock);
	}
}

static void mi_xmlrpc_http_close_async(mi_response_t *resp, struct mi_handler *hdl, int done)
{
	mi_response_t *shm_resp = NULL;
	gen_lock_t* lock;
	mi_xmlrpc_http_async_resp_data_t *async_resp_data;
	int x;

	if (hdl==NULL) {
		LM_CRIT("null mi handler\n");
		return;
	}

	LM_DBG("resp [%p], hdl [%p], hdl->param [%p] and done [%u]\n",
		resp, hdl, hdl->param, done);

	if (!done) {
		/* we do not pass provisional stuff (yet) */
		if (resp) free_mi_response( resp );
		return;
	}

	async_resp_data = (mi_xmlrpc_http_async_resp_data_t*)(hdl+1);
	lock = async_resp_data->lock;

	if (resp==NULL || (shm_resp=shm_clone_mi_response(resp))==NULL) {
		LM_WARN("Unable to process async reply [%p]\n", resp);
		/* mark it as invalid */
		shm_resp = MI_XMLRPC_ASYNC_FAILED;
	}
	if (resp) free_mi_response(resp);

	lock_get(lock);
	if (hdl->param==NULL) {
		hdl->param = shm_resp;
		x = 0;
	} else {
		x = 1;
	}
	LM_DBG("shm_resp [%p], hdl [%p], hdl->param [%p]\n",
		shm_resp, hdl, hdl->param);
	lock_release(lock);

	if (x) {
		if (shm_resp!=MI_XMLRPC_ASYNC_FAILED)
			free_shm_mi_response(shm_resp);
		shm_free(hdl);
	}

	return;
}


static inline struct mi_handler* mi_xmlrpc_build_async_handler(void)
{
	struct mi_handler *hdl;
	mi_xmlrpc_http_async_resp_data_t *async_resp_data;
	unsigned int len;

	len = sizeof(struct mi_handler)+sizeof(mi_xmlrpc_http_async_resp_data_t);
	hdl = (struct mi_handler*)shm_malloc(len);
	if (hdl==NULL) {
		LM_ERR("oom\n");
		return NULL;
	}

	memset(hdl, 0, len);
	async_resp_data = (mi_xmlrpc_http_async_resp_data_t*)(hdl+1);

	hdl->handler_f = mi_xmlrpc_http_close_async;
	hdl->param = NULL;

	async_resp_data->lock = mi_xmlrpc_http_lock;

	LM_DBG("hdl [%p], hdl->param [%p], mi_xmlrpc_http_lock=[%p]\n",
		hdl, hdl->param, async_resp_data->lock);

	return hdl;
}

static int mi_xmlrpc_get_array_param(xmlNodePtr array_node,
	mi_item_t *req_params_item, const char *name)
{
	xmlNodePtr node;
	mi_item_t *p_arr;
	int rc;

	node = mi_xmlNodeGetNodeByName(array_node->children,
				MI_XMLRPC_XML_DATA_NODE);
	if (node==NULL) {
		LM_ERR("missing node %s\n", MI_XMLRPC_XML_DATA_NODE);
		return 1;
	}

	p_arr = cJSON_CreateArray();
	if (!p_arr) {
		LM_ERR("Failed to create array item in temporary json request\n");
		return -1;
	}

	if (req_params_item->type & cJSON_Array)
		cJSON_AddItemToArray(req_params_item, p_arr);
	else if (req_params_item->type & cJSON_Object)
		cJSON_AddItemToObject(req_params_item, name, p_arr);
	else {
		LM_ERR("Bad params item type\n");
		return -1;
	}

	for (node = node->children; node; node=node->next) {
		if (xmlStrcasecmp(node->name,
			(const xmlChar*)MI_XMLRPC_XML_VALUE_NODE) != 0)
			continue;

		rc = mi_xmlrpc_get_param(node, p_arr, NULL);
		if (rc != 0)
			return rc;
	}

	return 0;
}

static int mi_xmlrpc_get_param(xmlNodePtr value_node, mi_item_t *req_params_item,
									const char *name)
{
	static str esc_buf = {NULL, 0};
	str val = {NULL, 0}, esc_val = {NULL, 0};
	xmlNodePtr string_node = NULL;
	xmlNodePtr int_node = NULL;
	xmlNodePtr array_node = NULL;
	int intval;
	mi_item_t *param_item;

	string_node = mi_xmlNodeGetNodeByName(value_node->children,
			MI_XMLRPC_XML_STRING_NODE);
	if (string_node) {
		val.s = (char*)xmlNodeGetContent(string_node);
		if(val.s==NULL){
			LM_ERR("No content for node [%s]\n",
				string_node->name);
			return 1;
		}
		val.len = strlen(val.s);
		if(val.len==0){
			LM_ERR("Empty content for node [%s]\n",
				string_node->name);
			return 1;
		}

		if (val.len > esc_buf.len) {
			esc_buf.s = shm_realloc(esc_buf.s, val.len);
			if (!esc_buf.s) {
				LM_ERR("No more shm memory\n");
				esc_buf.len = 0;
				return -1;
			}
			esc_buf.len = val.len;
		}

		esc_val.s = esc_buf.s;
		esc_val.len = unescape_xml(esc_val.s, val.s, val.len);
		LM_DBG("got escaped string param [%.*s]\n", esc_val.len, esc_val.s);

		xmlFree(val.s);

		param_item = cJSON_CreateStr(esc_val.s, esc_val.len);
		if (!param_item) {
			LM_ERR("Failed to create string item in temporary json request\n");
			return -1;
		}

		if (name)
			cJSON_AddItemToObject(req_params_item, name, param_item);
		else
			cJSON_AddItemToArray(req_params_item, param_item);

		return 0;
	}

	int_node = mi_xmlNodeGetNodeByName(value_node->children,
		MI_XMLRPC_XML_INT_NODE);
	if (!int_node)
		int_node = mi_xmlNodeGetNodeByName(value_node->children,
			MI_XMLRPC_XML_I4_NODE);
	if (int_node) {
		val.s = (char*)xmlNodeGetContent(int_node);
		if(val.s==NULL){
			LM_ERR("No content for node [%s]\n",
				int_node->name);
			return 1;
		}
		val.len = strlen(val.s);
		if(val.len==0){
			LM_ERR("Empty content for node [%s]\n",
				int_node->name);
			return 1;
		}

		if (str2sint(&val, &intval) < 0) {
			LM_ERR("<int> param is not an integer\n");
			return 1;
		}

		xmlFree(val.s);

		param_item = cJSON_CreateNumber(intval);
		if (!param_item) {
			LM_ERR("Failed to create integer item in temporary json request\n");
			return -1;
		}

		if (name)
			cJSON_AddItemToObject(req_params_item, name, param_item);
		else
			cJSON_AddItemToArray(req_params_item, param_item);

		return 0;
	}

	array_node = mi_xmlNodeGetNodeByName(value_node->children,
		MI_XMLRPC_XML_ARRAY_NODE);
	if (array_node)
		return mi_xmlrpc_get_array_param(array_node, req_params_item, name);

	LM_ERR("Unsupported type in param's value\n");
	return 1;
}

static int mi_xmlrpc_get_named_params(xmlNodePtr struct_node,
									mi_item_t *req_params_item)
{
	xmlNodePtr member_node;
	xmlNodePtr name_node;
	xmlNodePtr value_node;
	char *name_s;
	int rc = 1;

	for (member_node=struct_node->children; member_node;
		 member_node=member_node->next) {
		if (xmlStrcasecmp(member_node->name,
			(const xmlChar*)MI_XMLRPC_XML_MEMBER_NODE) != 0)
			continue;

		name_node = mi_xmlNodeGetNodeByName(member_node->children,
					MI_XMLRPC_XML_NAME_NODE);
		if (name_node==NULL) {
			LM_ERR("missing node %s\n", MI_XMLRPC_XML_NAME_NODE);
			return 1;
		}

		name_s = (char*)xmlNodeGetContent(name_node);
		if(name_s==NULL){
			LM_ERR("No content for node [%s]\n",
				name_node->name);
			return 1;
		}
		if(strlen(name_s)==0){
			LM_ERR("Empty content for node [%s]\n",
				name_node->name);
			return 1;
		}

		value_node = mi_xmlNodeGetNodeByName(member_node->children,
					MI_XMLRPC_XML_VALUE_NODE);
		if (value_node==NULL) {
			LM_ERR("missing node %s\n", MI_XMLRPC_XML_VALUE_NODE);
			return 1;
		}

		rc = mi_xmlrpc_get_param(value_node, req_params_item, name_s);

		xmlFree(name_s);

		if (rc != 0)
			return rc;
	}

	return rc;
}

static int mi_xmlrpc_parse_params(xmlNodePtr params_node, mi_request_t *req_item)
{
	xmlNodePtr struct_node;
	xmlNodePtr param_node;
	xmlNodePtr value_node;
	int rc;

	param_node = mi_xmlNodeGetNodeByName(params_node->children,
		MI_XMLRPC_XML_PARAM_NODE);
	if (!param_node)
		return 0;

	value_node = mi_xmlNodeGetNodeByName(param_node->children,
				MI_XMLRPC_XML_VALUE_NODE);
	if (value_node==NULL) {
		LM_ERR("missing node %s\n", MI_XMLRPC_XML_VALUE_NODE);
		req_item->invalid = 1;
		return 0;
	}

	struct_node = mi_xmlNodeGetNodeByName(value_node->children,
		MI_XMLRPC_XML_STRUCT_NODE);
	if (struct_node) {
		req_item->params = cJSON_CreateObject();
		if (!req_item->params) {
			LM_ERR("Failed to add 'params' to temporary json request\n");
			return -1;
		}
		cJSON_AddItemToObject(req_item->req_obj, JSONRPC_PARAMS_S,
			req_item->params);

		rc = mi_xmlrpc_get_named_params(struct_node, req_item->params);
		if (rc<0)
			return -1;
		else if (rc>0)
			req_item->invalid = 1;

		return 0;
	}

	/* positional parameters */

	req_item->params = cJSON_CreateArray();
	if (!req_item->params) {
		LM_ERR("Failed to add 'params' to temporary json request\n");
		return -1;
	}
	cJSON_AddItemToObject(req_item->req_obj, JSONRPC_PARAMS_S,
		req_item->params);

	rc = mi_xmlrpc_get_param(value_node, req_item->params, NULL);
	if (rc<0)
		return -1;
	else if (rc>0) {
		req_item->invalid = 1;
		return 0;
	}

	for (param_node=param_node->next; param_node;
		 param_node=param_node->next) {

		if (xmlStrcasecmp(param_node->name,
			(const xmlChar*)MI_XMLRPC_XML_PARAM_NODE) != 0)
			continue;

		value_node = mi_xmlNodeGetNodeByName(param_node->children,
				MI_XMLRPC_XML_VALUE_NODE);
		if (value_node==NULL) {
			LM_ERR("missing node %s\n", MI_XMLRPC_XML_VALUE_NODE);
			req_item->invalid = 1;
			return 0;
		}

		rc = mi_xmlrpc_get_param(value_node, req_item->params, NULL);
		if (rc<0)
			return -1;
		else if (rc>0) {
			req_item->invalid = 1;
			return 0;
		}
	}

	return 0;
}

mi_response_t *mi_xmlrpc_run_mi_cmd(const char *req_buf, int req_buf_len,
		struct mi_handler **async_hdl, union sockaddr_union* cl_socket,
		int* is_traced)
{
	xmlDocPtr doc;
	xmlNodePtr methodCall_node;
	xmlNodePtr methodName_node;
	xmlNodePtr params_node;
	mi_request_t req_item;
	char *req_method = NULL;
	struct mi_cmd *cmd = NULL;
	mi_response_t *resp = NULL;
	struct mi_handler *hdl = NULL;

	/* trace all errors */
	*is_traced = 1;

	memset(&req_item, 0, sizeof req_item);

	doc = xmlParseMemory(req_buf, req_buf_len);
	if(doc==NULL) {
		LM_ERR("Failed to parse xml document: [%.*s]\n", req_buf_len, req_buf);
		goto handle_req;
	}

	req_item.req_obj = cJSON_CreateObject();
	if (!req_item.req_obj) {
		LM_ERR("Failed to build temporary json request\n");
		goto xml_error;
	}

	methodCall_node = mi_xmlNodeGetNodeByName(doc->children,
						MI_XMLRPC_XML_METHOD_CALL_NODE);
	if (methodCall_node==NULL) {
		LM_ERR("missing node %s\n", MI_XMLRPC_XML_METHOD_CALL_NODE);
		req_item.invalid = 1;
		goto handle_req;
	}

	methodName_node = mi_xmlNodeGetNodeByName(methodCall_node->children,
						MI_XMLRPC_XML_METHOD_NAME_NODE);
	if (methodName_node==NULL) {
		LM_ERR("missing node %s\n", MI_XMLRPC_XML_METHOD_NAME_NODE);
		req_item.invalid = 1;
		goto handle_req;
	}

	req_method = (char*)xmlNodeGetContent(methodName_node);
	if (req_method==NULL) {
		LM_ERR("missing content for node %s\n",
				MI_XMLRPC_XML_METHOD_NAME_NODE);
		req_item.invalid = 1;
		goto handle_req;
	} else {
		LM_DBG("got methodName=%s\n", req_method);
		cmd = lookup_mi_cmd(req_method, strlen(req_method));
		if (!cmd)
			goto handle_req;
	}

	*is_traced = is_mi_cmd_traced(mi_trace_mod_id, cmd);

	if (cmd->flags & MI_ASYNC_RPL_FLAG) {
		LM_DBG("command is async\n");
		/* We need to build an async handler */
		hdl = mi_xmlrpc_build_async_handler();
		if (hdl==NULL) {
			LM_ERR("failed to build async handler\n");
			goto xml_error;
		}
	}

	params_node = mi_xmlNodeGetNodeByName(methodCall_node->children,
		MI_XMLRPC_XML_PARAMS_NODE);

	if (params_node && mi_xmlrpc_parse_params(params_node, &req_item) < 0)
		goto xml_error;

handle_req:
	resp = handle_mi_request(&req_item, cmd, hdl);
	LM_DBG("got mi response = [%p]\n", resp);

	if ( *is_traced )
		trace_xml_request(cmd, req_method, cl_socket, req_item.params);

	*async_hdl = hdl;

	if (req_item.req_obj)
		cJSON_Delete(req_item.req_obj);
	
	if (req_method)
		xmlFree(req_method);
	if (doc)
		xmlFreeDoc(doc);

	return resp;

xml_error:
	trace_xml_request(cmd, req_method, cl_socket, req_item.params);

	if (req_item.req_obj)
		cJSON_Delete(req_item.req_obj);

	if (req_method)
		xmlFree(req_method);
	if (doc)
		xmlFreeDoc(doc);

	if (hdl) shm_free(hdl);
	*async_hdl = NULL;

	return NULL;
}

static int mi_xmlrpc_recur_write_res(char** p, char *buf, int max_page_len,
								mi_item_t *item)
{
	str tmp_s;
	int tmp_i;
	str val;
	mi_item_t *subitem;

	MI_XMLRPC_HTTP_COPY(*p, MI_XMLRPC_HTTP_VALUE_START);

	if (item->type & (cJSON_False|cJSON_True)) {
		MI_XMLRPC_HTTP_COPY(*p, MI_XMLRPC_HTTP_BOOL_START);

		if (item->type & cJSON_False)
			MI_XMLRPC_HTTP_COPY(*p, MI_XMLRPC_HTTP_FALSE_VALUE);
		else
			MI_XMLRPC_HTTP_COPY(*p, MI_XMLRPC_HTTP_TRUE_VALUE);

		MI_XMLRPC_HTTP_COPY(*p, MI_XMLRPC_HTTP_BOOL_END);
	} else if (item->type & cJSON_NULL) {
		MI_XMLRPC_HTTP_COPY(*p, MI_XMLRPC_HTTP_NIL);
	} else if (item->type & cJSON_Number) {
		if (cJSON_NumberIsInt(item)) {
			MI_XMLRPC_HTTP_COPY(*p, MI_XMLRPC_HTTP_INT_START);

			val.s = sint2str(item->valueint, &val.len);
			if (!val.s) {
				LM_ERR("Failed to print int value\n");
				return -1;
			}
			MI_XMLRPC_HTTP_COPY(*p, val);

			MI_XMLRPC_HTTP_COPY(*p, MI_XMLRPC_HTTP_INT_END);
		} else {
			MI_XMLRPC_HTTP_COPY(*p, MI_XMLRPC_HTTP_DOUBLE_START);

			if ((int)(*p-buf) + MI_XMLRPC_DOUBLE_MAX_PRINT_LEN > max_page_len)
				goto error;

			val.len = snprintf(*p, MI_XMLRPC_DOUBLE_MAX_PRINT_LEN,
				"%f", item->valuedouble);
			if (val.len < 0) {
				LM_ERR("Failed to print double value\n");
				return -1;
			}
			*p += val.len;

			MI_XMLRPC_HTTP_COPY(*p, MI_XMLRPC_HTTP_DOUBLE_END);
		}
	} else if (item->type & cJSON_String) {
		MI_XMLRPC_HTTP_COPY(*p, MI_XMLRPC_HTTP_STRING_START);

		val.s = item->valuestring;
		val.len = strlen(val.s);
		MI_XMLRPC_HTTP_ESC_COPY(*p, val, tmp_s, tmp_i);

		MI_XMLRPC_HTTP_COPY(*p, MI_XMLRPC_HTTP_STRING_END);
	} else if (item->type & cJSON_Array) {
		MI_XMLRPC_HTTP_COPY(*p, MI_XMLRPC_HTTP_ARRAY_START);
		MI_XMLRPC_HTTP_COPY(*p, MI_XMLRPC_HTTP_DATA_START);

		for (subitem = item->child; subitem; subitem = subitem->next)
			if (mi_xmlrpc_recur_write_res(p, buf, max_page_len, subitem) < 0)
				return -1;

		MI_XMLRPC_HTTP_COPY(*p, MI_XMLRPC_HTTP_DATA_END);
		MI_XMLRPC_HTTP_COPY(*p, MI_XMLRPC_HTTP_ARRAY_END);
	} else if (item->type & cJSON_Object) {
		MI_XMLRPC_HTTP_COPY(*p, MI_XMLRPC_HTTP_STRUCT_START);

		for (subitem = item->child; subitem; subitem = subitem->next) {
			MI_XMLRPC_HTTP_COPY(*p, MI_XMLRPC_HTTP_MEMBER_START);

			MI_XMLRPC_HTTP_COPY(*p, MI_XMLRPC_HTTP_NAME_START);

			val.s = subitem->string;
			val.len = strlen(val.s);
			MI_XMLRPC_HTTP_ESC_COPY(*p, val, tmp_s, tmp_i);

			MI_XMLRPC_HTTP_COPY(*p, MI_XMLRPC_HTTP_NAME_END);

			if (mi_xmlrpc_recur_write_res(p, buf, max_page_len, subitem) < 0)
				return -1;

			MI_XMLRPC_HTTP_COPY(*p, MI_XMLRPC_HTTP_MEMBER_END);
		}

		MI_XMLRPC_HTTP_COPY(*p, MI_XMLRPC_HTTP_STRUCT_END);
	} else {
		LM_ERR("Bad type for jsonrpc 'result' member\n");
		return -1;
	}

	MI_XMLRPC_HTTP_COPY(*p, MI_XMLRPC_HTTP_VALUE_END);

	return 0;

error:
	LM_ERR("Buffer to small\n");
	return -1;
}

int mi_xmlrpc_build_page(str *page, int max_page_len,
				mi_response_t *response)
{
	mi_item_t *item, *err_msg, *err_code;
	char *p, *buf;

	item = cJSON_GetObjectItem(response, JSONRPC_ERROR_S);
	if (item) {  /* this is an error reponse */
		err_code = cJSON_GetObjectItem(item, JSONRPC_ERR_CODE_S);
		if (!err_code) {
			LM_ERR("Failed to get error code from temporary json response\n");
			return -1;
		}

		switch (err_code->valueint) {
		case JSONRPC_PARSE_ERR_CODE:
			*page = xml_strerr[XMLRPC_ERR_PARSE];
			break;
		case JSONRPC_INVAL_REQ_CODE:
			*page = xml_strerr[XMLRPC_ERR_INVALID];
			break;
		case JSONRPC_NOT_FOUND_CODE:
			*page = xml_strerr[XMLRPC_ERR_METHOD];
			break;
		case JSONRPC_INVAL_PARAMS_CODE:
			*page = xml_strerr[XMLRPC_ERR_PARAMS];
			break;
		case JSONRPC_SERVER_ERR_CODE:
			*page = xml_strerr[XMLRPC_ERR_SERVER];
			break;
		default:
			err_msg = cJSON_GetObjectItem(item, JSONRPC_ERR_MSG_S);
			if (!err_msg) {
				LM_ERR("Failed to get error message from temporary json response\n");
				return -1;
			}

			MI_XMLRPC_PRINT_FAULT(page, err_code->valueint, err_msg->valuestring);
			if (page->len < 0) {
				LM_ERR("Failed to print xmlrpc fault\n");
				return -1;
			}
		}

		return 0;
	}

	item = cJSON_GetObjectItem(response, JSONRPC_RESULT_S);
	if (item) {  /* this is a successful reponse */
		buf = page->s;
		p = buf;

		MI_XMLRPC_HTTP_COPY(p, MI_XMLRPC_HTTP_XML_START);

		if (mi_xmlrpc_recur_write_res(&p, page->s, max_page_len, item) < 0) {
			LM_ERR("Failed to write XMLRPC reponse\n");
			return -1;
		}

		MI_XMLRPC_HTTP_COPY(p, MI_XMLRPC_HTTP_XML_STOP);

		page->len = p - page->s;

		return 0;
	}

	LM_ERR("Bad jsonrpc reponse: missing 'result'/'error' member\n");
	return -1;

error:
	LM_ERR("Buffer to small\n");
	return -1;
}
