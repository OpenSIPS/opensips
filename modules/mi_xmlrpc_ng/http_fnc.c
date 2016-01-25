/*
 * $Id$
 *
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * History:
 * ---------
 *  2013-03-04  first version (osas)
 */


#include <libxml/parser.h>

#include "../../str.h"
#include "../../ut.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../mi/mi.h"
#include "../../config.h"
#include "../../globals.h"
#include "../../locking.h"

#include "http_fnc.h"


#define MI_XMLRPC_HTTP_XML_METHOD_CALL_NODE "methodCall"
#define MI_XMLRPC_HTTP_XML_METHOD_NAME_NODE "methodName"
#define MI_XMLRPC_HTTP_XML_PARAMS_NODE      "params"
#define MI_XMLRPC_HTTP_XML_PARAM_NODE       "param"
#define MI_XMLRPC_HTTP_XML_VALUE_NODE       "value"
#define MI_XMLRPC_HTTP_XML_STRING_NODE      "string"

extern str http_root;

mi_xmlrpc_http_page_data_t html_page_data;

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

#define MI_XMLRPC_HTTP_COPY_3(p,str1,str2,str3)	\
do{	\
	if ((int)((p)-buf)+(str1).len+(str2).len+(str3).len>max_page_len) {	\
		goto error;	\
	}	\
	memcpy((p), (str1).s, (str1).len); (p) += (str1).len;	\
	memcpy((p), (str2).s, (str2).len); (p) += (str2).len;	\
	memcpy((p), (str3).s, (str3).len); (p) += (str3).len;	\
}while(0)

#define MI_XMLRPC_HTTP_COPY_4(p,str1,str2,str3,str4)	\
do{	\
	if ((int)((p)-buf)+(str1).len+(str2).len+(str3).len+(str4).len>max_page_len) {	\
		goto error;	\
	}	\
	memcpy((p), (str1).s, (str1).len); (p) += (str1).len;	\
	memcpy((p), (str2).s, (str2).len); (p) += (str2).len;	\
	memcpy((p), (str3).s, (str3).len); (p) += (str3).len;	\
	memcpy((p), (str4).s, (str4).len); (p) += (str4).len;	\
}while(0)

#define MI_XMLRPC_HTTP_COPY_5(p,s1,s2,s3,s4,s5)	\
do{	\
	if ((int)((p)-buf)+(s1).len+(s2).len+(s3).len+(s4).len+(s5).len>max_page_len) {	\
		goto error;	\
	}	\
	memcpy((p), (s1).s, (s1).len); (p) += (s1).len;	\
	memcpy((p), (s2).s, (s2).len); (p) += (s2).len;	\
	memcpy((p), (s3).s, (s3).len); (p) += (s3).len;	\
	memcpy((p), (s4).s, (s4).len); (p) += (s4).len;	\
	memcpy((p), (s5).s, (s5).len); (p) += (s5).len;	\
}while(0)

#define MI_XMLRPC_HTTP_COPY_6(p,s1,s2,s3,s4,s5,s6)	\
do{	\
	if ((int)((p)-buf)+(s1).len+(s2).len+(s3).len+(s4).len+(s5).len+(s6).len>max_page_len) {	\
		goto error;	\
	}	\
	memcpy((p), (s1).s, (s1).len); (p) += (s1).len;	\
	memcpy((p), (s2).s, (s2).len); (p) += (s2).len;	\
	memcpy((p), (s3).s, (s3).len); (p) += (s3).len;	\
	memcpy((p), (s4).s, (s4).len); (p) += (s4).len;	\
	memcpy((p), (s5).s, (s5).len); (p) += (s5).len;	\
	memcpy((p), (s6).s, (s6).len); (p) += (s6).len;	\
}while(0)

#define MI_XMLRPC_HTTP_COPY_7(p,s1,s2,s3,s4,s5,s6,s7)	\
do{	\
	if ((int)((p)-buf)+(s1).len+(s2).len+(s3).len+(s4).len+(s5).len+(s6).len+(s7).len>max_page_len) {	\
		goto error;	\
	}	\
	memcpy((p), (s1).s, (s1).len); (p) += (s1).len;	\
	memcpy((p), (s2).s, (s2).len); (p) += (s2).len;	\
	memcpy((p), (s3).s, (s3).len); (p) += (s3).len;	\
	memcpy((p), (s4).s, (s4).len); (p) += (s4).len;	\
	memcpy((p), (s5).s, (s5).len); (p) += (s5).len;	\
	memcpy((p), (s6).s, (s6).len); (p) += (s6).len;	\
	memcpy((p), (s7).s, (s7).len); (p) += (s7).len;	\
}while(0)

#define MI_XMLRPC_HTTP_COPY_10(p,s1,s2,s3,s4,s5,s6,s7,s8,s9,s10)	\
do{	\
	if ((int)((p)-buf)+(s1).len+(s2).len+(s3).len+(s4).len+(s5).len+(s6).len+(s7).len+(s8).len+(s9).len+(s10).len>max_page_len) {	\
		goto error;	\
	}	\
	memcpy((p), (s1).s, (s1).len); (p) += (s1).len;	\
	memcpy((p), (s2).s, (s2).len); (p) += (s2).len;	\
	memcpy((p), (s3).s, (s3).len); (p) += (s3).len;	\
	memcpy((p), (s4).s, (s4).len); (p) += (s4).len;	\
	memcpy((p), (s5).s, (s5).len); (p) += (s5).len;	\
	memcpy((p), (s6).s, (s6).len); (p) += (s6).len;	\
	memcpy((p), (s7).s, (s7).len); (p) += (s7).len;	\
	memcpy((p), (s8).s, (s8).len); (p) += (s8).len;	\
	memcpy((p), (s9).s, (s9).len); (p) += (s9).len;	\
	memcpy((p), (s10).s, (s10).len); (p) += (s10).len;	\
}while(0)

#define MI_XMLRPC_HTTP_COPY_11(p,s1,s2,s3,s4,s5,s6,s7,s8,s9,s10,s11)	\
do{	\
	if ((int)((p)-buf)+(s1).len+(s2).len+(s3).len+(s4).len+(s5).len+(s6).len+(s7).len+(s8).len+(s9).len+(s10).len+(s11).len>max_page_len) {	\
		goto error;	\
	}	\
	memcpy((p), (s1).s, (s1).len); (p) += (s1).len;	\
	memcpy((p), (s2).s, (s2).len); (p) += (s2).len;	\
	memcpy((p), (s3).s, (s3).len); (p) += (s3).len;	\
	memcpy((p), (s4).s, (s4).len); (p) += (s4).len;	\
	memcpy((p), (s5).s, (s5).len); (p) += (s5).len;	\
	memcpy((p), (s6).s, (s6).len); (p) += (s6).len;	\
	memcpy((p), (s7).s, (s7).len); (p) += (s7).len;	\
	memcpy((p), (s8).s, (s8).len); (p) += (s8).len;	\
	memcpy((p), (s9).s, (s9).len); (p) += (s9).len;	\
	memcpy((p), (s10).s, (s10).len); (p) += (s10).len;	\
	memcpy((p), (s11).s, (s11).len); (p) += (s11).len;	\
}while(0)

#define MI_XMLRPC_HTTP_COPY_12(p,s1,s2,s3,s4,s5,s6,s7,s8,s9,s10,s11,s12)	\
do{	\
	if ((int)((p)-buf)+(s1).len+(s2).len+(s3).len+(s4).len+(s5).len+(s6).len+(s7).len+(s8).len+(s9).len+(s10).len+(s11).len+(s12).len>max_page_len) {	\
		goto error;	\
	}	\
	memcpy((p), (s1).s, (s1).len); (p) += (s1).len;	\
	memcpy((p), (s2).s, (s2).len); (p) += (s2).len;	\
	memcpy((p), (s3).s, (s3).len); (p) += (s3).len;	\
	memcpy((p), (s4).s, (s4).len); (p) += (s4).len;	\
	memcpy((p), (s5).s, (s5).len); (p) += (s5).len;	\
	memcpy((p), (s6).s, (s6).len); (p) += (s6).len;	\
	memcpy((p), (s7).s, (s7).len); (p) += (s7).len;	\
	memcpy((p), (s8).s, (s8).len); (p) += (s8).len;	\
	memcpy((p), (s9).s, (s9).len); (p) += (s9).len;	\
	memcpy((p), (s10).s, (s10).len); (p) += (s10).len;	\
	memcpy((p), (s11).s, (s11).len); (p) += (s11).len;	\
	memcpy((p), (s12).s, (s12).len); (p) += (s12).len;	\
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


static const str MI_XMLRPC_HTTP_CR = str_init("\n");
static const str MI_XMLRPC_HTTP_SLASH = str_init("/");
static const str MI_XMLRPC_HTTP_SEMICOLON = str_init(" : ");

static const str MI_XMLRPC_HTTP_NODE_INDENT = str_init("\t");
static const str MI_XMLRPC_HTTP_NODE_SEPARATOR = str_init(":: ");
static const str MI_XMLRPC_HTTP_ATTR_SEPARATOR = str_init(" ");
static const str MI_XMLRPC_HTTP_ATTR_VAL_SEPARATOR = str_init("=");

static const str MI_XMLRPC_HTTP_XML_START = str_init("<?xml version=\"1.0\" "
"encoding=\"UTF-8\"?>\r\n<methodResponse>\r\n<params>\r\n<param><value><string>");
static const str MI_XMLRPC_HTTP_XML_STOP = str_init("</string></value></param>"
"\r\n</params>\r\n</methodResponse>\r\n");

static const str MI_XMLRPC_HTTP_ESC_LT =    str_init("&lt;");   /* < */
static const str MI_XMLRPC_HTTP_ESC_GT =    str_init("&gt;");   /* > */
static const str MI_XMLRPC_HTTP_ESC_AMP =   str_init("&amp;");  /* & */
static const str MI_XMLRPC_HTTP_ESC_QUOT =  str_init("&quot;"); /* " */
static const str MI_XMLRPC_HTTP_ESC_SQUOT = str_init("&#39;");  /* ' */


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

/*
xmlAttrPtr mi_xmlNodeGetAttrByName(xmlNodePtr node, const char *name)
{
	xmlAttrPtr attr = node->properties;
	while (attr) {
		if(xmlStrcasecmp(attr->name, (const xmlChar*)name)==0)
			return attr;
		attr = attr->next;
	}
	return NULL;
}
*/

/*
xmlNodePtr mi_xmlNodeGetAttrContentByName(xmlNodePtr node, const char *name)
{
	xmlAttrPtr attr = ph_xmlNodeGetAttrByName(node, name);
	if (attr) return (char*)xmlNodeGetContent(attr->children);
	else return NULL;
}
*/

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

/*
char *ph_xmlNodeGetNodeContentByName(xmlNodePtr node, const char *name)
{
	xmlNodePtr node1 = mi_xmlNodeGetNodeByName(node, name);
	if (node1) return (char*)xmlNodeGetContent(node1);
	else return NULL;
}
*/

void mi_xmlrpc_http_destroy_async_lock(void)
{
	if (mi_xmlrpc_http_lock) {
		lock_destroy(mi_xmlrpc_http_lock);
		lock_dealloc(mi_xmlrpc_http_lock);
	}
}


static int mi_xmlrpc_http_recur_flush_tree(char** pointer, char *buf, int max_page_len,
					struct mi_node *tree, int level);

int mi_xmlrpc_http_flush_content(str *page, int max_page_len,
				struct mi_root* tree);



int mi_xmlrpc_http_flush_tree(void* param, struct mi_root *tree)
{
	if (param==NULL) {
		LM_CRIT("null param\n");
		return 0;
	}
	mi_xmlrpc_http_page_data_t* html_p_data = (mi_xmlrpc_http_page_data_t*)param;
	mi_xmlrpc_http_flush_content(&html_p_data->page,
				html_p_data->buffer.len,
				tree);
	return 0;
}


static void mi_xmlrpc_http_close_async(struct mi_root *mi_rpl, struct mi_handler *hdl, int done)
{
	struct mi_root *shm_rpl = NULL;
	gen_lock_t* lock;
	mi_xmlrpc_http_async_resp_data_t *async_resp_data;
	int x;

	if (hdl==NULL) {
		LM_CRIT("null mi handler\n");
		return;
	}

	LM_DBG("mi_root [%p], hdl [%p], hdl->param [%p] and done [%u]\n",
		mi_rpl, hdl, hdl->param, done);

	if (!done) {
		/* we do not pass provisional stuff (yet) */
		if (mi_rpl) free_mi_tree( mi_rpl );
		return;
	}

	async_resp_data = (mi_xmlrpc_http_async_resp_data_t*)(hdl+1);
	lock = async_resp_data->lock;

	if (mi_rpl==NULL || (shm_rpl=clone_mi_tree( mi_rpl, 1))==NULL) {
		LM_WARN("Unable to process async reply [%p]\n", mi_rpl);
		/* mark it as invalid */
		shm_rpl = MI_XMLRPC_ASYNC_FAILED;
	}
	if (mi_rpl) free_mi_tree(mi_rpl);

	lock_get(lock);
	if (hdl->param==NULL) {
		hdl->param = shm_rpl;
		x = 0;
	} else {
		x = 1;
	}
	LM_DBG("shm_rpl [%p], hdl [%p], hdl->param [%p]\n",
		shm_rpl, hdl, hdl->param);
	lock_release(lock);

	if (x) {
		if (shm_rpl!=MI_XMLRPC_ASYNC_FAILED)
			free_shm_mi_tree(shm_rpl);
		shm_free(hdl);
	}

	return;
}


static inline struct mi_handler* mi_xmlrpc_http_build_async_handler(void)
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

struct mi_root* mi_xmlrpc_http_run_mi_cmd(const str* arg,
		str *page, str *buffer, struct mi_handler **async_hdl)
{
	struct mi_cmd *f;
	struct mi_node *node;
	struct mi_root *mi_cmd = NULL;
	struct mi_root *mi_rpl = NULL;
	struct mi_handler *hdl = NULL;
	str miCmd;
	xmlDocPtr doc;
	xmlNodePtr methodCall_node;
	xmlNodePtr methodName_node;
	xmlNodePtr params_node;
	xmlNodePtr param_node;
	xmlNodePtr value_node;
	xmlNodePtr string_node;
	str val;
	str esc_val = {NULL, 0};

	//LM_DBG("arg [%p]->[%.*s]\n", arg->s, arg->len, arg->s);
	doc = xmlParseMemory(arg->s, arg->len);
	if(doc==NULL){
		LM_ERR("Failed to parse xml document: [%s]\n", arg->s);
		return NULL;
	}
	methodCall_node = mi_xmlNodeGetNodeByName(doc->children,
						MI_XMLRPC_HTTP_XML_METHOD_CALL_NODE);
	if (methodCall_node==NULL) {
		LM_ERR("missing node %s\n", MI_XMLRPC_HTTP_XML_METHOD_CALL_NODE);
		goto xml_error;
	}
	methodName_node = mi_xmlNodeGetNodeByName(methodCall_node->children,
						MI_XMLRPC_HTTP_XML_METHOD_NAME_NODE);
	if (methodName_node==NULL) {
		LM_ERR("missing node %s\n", MI_XMLRPC_HTTP_XML_METHOD_NAME_NODE);
		goto xml_error;
	}
	miCmd.s = (char*)xmlNodeGetContent(methodName_node);
	if (miCmd.s==NULL) {
		LM_ERR("missing content for node %s\n",
				MI_XMLRPC_HTTP_XML_METHOD_NAME_NODE);
		goto xml_error;
	}
	miCmd.len = strlen(miCmd.s);
	LM_DBG("got methodName=%.*s\n", miCmd.len, miCmd.s);

	f = lookup_mi_cmd(miCmd.s, miCmd.len);
	if (f == NULL) {
		LM_ERR("unable to find mi command [%.*s]\n", miCmd.len, miCmd.s);
		goto xml_error;
	}

	if (f->flags&MI_ASYNC_RPL_FLAG) {
		/* We need to build an async handler */
		hdl = mi_xmlrpc_http_build_async_handler();
		if (hdl==NULL) {
			LM_ERR("failed to build async handler\n");
			goto xml_error;
		}
	} else {
		hdl = NULL;
	}

	if (f->flags&MI_NO_INPUT_FLAG) {
		mi_cmd = NULL;
	} else {
		if (arg->s) {
			mi_cmd = init_mi_tree(0,0,0);
			if (mi_cmd==NULL) {
				LM_ERR("the MI tree cannot be initialized!\n");
				goto xml_error;
			}
			params_node = mi_xmlNodeGetNodeByName(methodCall_node->children,
									MI_XMLRPC_HTTP_XML_PARAMS_NODE);
			if (params_node==NULL) {
				LM_ERR("missing node %s\n", MI_XMLRPC_HTTP_XML_PARAMS_NODE);
				goto xml_error;
			}
			for(param_node=params_node->children;
						param_node;param_node=param_node->next){
				if (xmlStrcasecmp(param_node->name,
					(const xmlChar*)MI_XMLRPC_HTTP_XML_PARAM_NODE) == 0) {
					value_node = mi_xmlNodeGetNodeByName(param_node->children,
								MI_XMLRPC_HTTP_XML_VALUE_NODE);
					if (value_node==NULL) {
						LM_ERR("missing node %s\n",
								MI_XMLRPC_HTTP_XML_VALUE_NODE);
						goto xml_error;
					}
					string_node = mi_xmlNodeGetNodeByName(value_node->children,
								MI_XMLRPC_HTTP_XML_STRING_NODE);
					if (string_node==NULL) {
						LM_ERR("missing node %s\n",
								MI_XMLRPC_HTTP_XML_STRING_NODE);
						goto xml_error;
					}
					val.s = (char*)xmlNodeGetContent(string_node);
					if(val.s==NULL){
						LM_ERR("No content for node [%s]\n",
								string_node->name);
						goto xml_error;
					}
					val.len = strlen(val.s);
					if(val.len==0){
						LM_ERR("Empty content for node [%s]\n",
								string_node->name);
						goto xml_error;
					}
					LM_DBG("got string param [%.*s]\n", val.len, val.s);

					esc_val.s = shm_malloc(val.len);
					if (esc_val.s == NULL) {
						free_mi_tree(mi_cmd);
						goto xml_error;
					}
					esc_val.len = unescape_xml(esc_val.s, val.s, val.len);
					LM_DBG("got escaped string param [%.*s]\n", esc_val.len, esc_val.s);

					node = &mi_cmd->node;
					if(!add_mi_node_child(node,0,NULL,0,esc_val.s,esc_val.len)){
						LM_ERR("cannot add the child node to the tree\n");
						free_mi_tree(mi_cmd);
						goto xml_error;
					}
				}
			}
			mi_cmd->async_hdl = hdl;
		} else {
			mi_cmd = NULL;
		}
	}

	html_page_data.page.s = buffer->s;
	html_page_data.page.len = 0;
	html_page_data.buffer.s = buffer->s;
	html_page_data.buffer.len = buffer->len;

	mi_rpl = run_mi_cmd(f, mi_cmd,
				(mi_flush_f *)mi_xmlrpc_http_flush_tree, &html_page_data);
	if (mi_rpl == NULL) {
		LM_ERR("failed to process the command\n");
		goto xml_error;
	} else {
		*page = html_page_data.page;
	}
	LM_DBG("got mi_rpl=[%p]\n",mi_rpl);

	*async_hdl = hdl;

	if (mi_cmd) free_mi_tree(mi_cmd);
	if(doc)xmlFree(doc);doc=NULL;
	if(esc_val.s);shm_free(esc_val.s);
	return mi_rpl;

xml_error:
	if (mi_cmd) free_mi_tree(mi_cmd);
	if (hdl) shm_free(hdl);
	*async_hdl = NULL;
	if(doc)xmlFree(doc);doc=NULL;
	if(esc_val.s);shm_free(esc_val.s);
	return NULL;
}


static inline int mi_xmlrpc_http_write_node(char** pointer, char* buf, int max_page_len,
					struct mi_node *node, int level)
{
	struct mi_attr *attr;
	str temp_holder;
	int temp_counter;
	int insert_node_separator;

	/* name and value */
	if (node->name.s!=NULL) {
		for(;level>0;level--) {
			MI_XMLRPC_HTTP_COPY(*pointer,
				MI_XMLRPC_HTTP_NODE_INDENT);
		}
		MI_XMLRPC_HTTP_COPY(*pointer,
				node->name);
		insert_node_separator = 1;
	} else {
		insert_node_separator = 0;
	}
	if (node->value.s!=NULL) {
		if (insert_node_separator) {
			MI_XMLRPC_HTTP_COPY(*pointer,
				MI_XMLRPC_HTTP_NODE_SEPARATOR);
			insert_node_separator = 0;
		}
		MI_XMLRPC_HTTP_ESC_COPY(*pointer, node->value,
				temp_holder, temp_counter);
	}
	/* attributes */
	for(attr=node->attributes;attr!=NULL;attr=attr->next) {
		if (insert_node_separator) {
			MI_XMLRPC_HTTP_COPY(*pointer,
				MI_XMLRPC_HTTP_NODE_SEPARATOR);
			insert_node_separator = 0;
		}
		if (attr->name.s!=NULL) {
			MI_XMLRPC_HTTP_COPY_3(*pointer,
					MI_XMLRPC_HTTP_ATTR_SEPARATOR,
					attr->name,
					MI_XMLRPC_HTTP_ATTR_VAL_SEPARATOR);
			MI_XMLRPC_HTTP_ESC_COPY(*pointer, attr->value,
					temp_holder, temp_counter);
		}
	}
	MI_XMLRPC_HTTP_COPY(*pointer, MI_XMLRPC_HTTP_CR);
	return 0;
error:
	LM_ERR("buffer 2 small: *pointer=[%p] buf=[%p] max_page_len=[%d]\n",
			*pointer, buf, max_page_len);
	return -1;
}


static int mi_xmlrpc_http_recur_flush_tree(char** pointer, char *buf, int max_page_len,
					struct mi_node *tree, int level)
{
	struct mi_node *kid, *tmp;
	int ret;

	for(kid = tree->kids ; kid ; ){
		if (!(kid->flags & MI_WRITTEN)) {
			if (mi_xmlrpc_http_write_node(pointer, buf, max_page_len,
							kid, level)!=0)
				return -1;
			kid->flags |= MI_WRITTEN;
		}
		if ((ret = mi_xmlrpc_http_recur_flush_tree(pointer, buf, max_page_len,
							tree->kids, level+1))<0){
			return -1;
		} else if (ret > 0) {
			return ret;
		}
		if (!(kid->flags & MI_NOT_COMPLETED)){
			tmp = kid;
			kid = kid->next;
			tree->kids = kid;

			if(!tmp->kids){
				/* this node does not have any kids */
				free_mi_node(tmp);
			}
		} else {
			/* the node will have more kids =>
			 * to keep the tree shape,
			 * do not flush any other node for now */
			return 1;
		}
	}
	return 0;
}


static int mi_xmlrpc_http_recur_write_tree(char** pointer, char *buf, int max_page_len,
					struct mi_node *tree, int level)
{
	for( ; tree ; tree=tree->next ) {
		if (!(tree->flags & MI_WRITTEN)) {
			if (mi_xmlrpc_http_write_node(pointer, buf, max_page_len,
									tree, level)!=0){
				return -1;
			}
		}
		if (tree->kids) {
			if (mi_xmlrpc_http_recur_write_tree(pointer, buf, max_page_len,
						tree->kids, level+1)<0){
				return -1;
			}
		}
	}
	return 0;
}


int mi_xmlrpc_http_build_header(str *page, int max_page_len,
				struct mi_root *tree, int flush)
{
	char *p, *buf;

	if (page->s == NULL) {
		LM_ERR("Please provide a valid page\n");
		return -1;
	}
	p = buf = page->s;

	if (tree) {
		LM_DBG("return code: %d\n", tree->code);
		if (!(tree->node.flags & MI_WRITTEN)) {
			MI_XMLRPC_HTTP_COPY(p, MI_XMLRPC_HTTP_XML_START);
			tree->node.flags |= MI_WRITTEN;
		}
		if (flush) {
			if (mi_xmlrpc_http_recur_flush_tree(&p, buf, max_page_len,
							&tree->node, 0)<0)
				return -1;
		} else {
			if (mi_xmlrpc_http_recur_write_tree(&p, buf, max_page_len,
							tree->node.kids, 0)<0)
				return -1;
		}
		MI_XMLRPC_HTTP_COPY(p, MI_XMLRPC_HTTP_XML_STOP);
	}

	page->len = p - page->s;
	return 0;
error:
	LM_ERR("buffer 2 small\n");
	page->len = p - page->s;
	return -1;
}


int mi_xmlrpc_http_build_content(str *page, int max_page_len,
				struct mi_root* tree)
{
	char *p, *buf;

	if (page->len==0) {
		if (0!=mi_xmlrpc_http_build_header(page, max_page_len, tree, 0))
			return -1;
	} else {
		buf = page->s;
		p = page->s + page->len;

		if (tree) { /* Build mi reply */
			if (mi_xmlrpc_http_recur_write_tree(&p, buf, max_page_len,
							tree->node.kids, 0)<0)
				return -1;
			page->len = p - page->s;
		}
	}
	return 0;
}


int mi_xmlrpc_http_build_page(str *page, int max_page_len,
				struct mi_root *tree)
{
	if (0!=mi_xmlrpc_http_build_content(page, max_page_len, tree))
		return -1;
	return 0;
}


int mi_xmlrpc_http_flush_content(str *page, int max_page_len,
				struct mi_root* tree)
{
	char *p, *buf;

	if (page->len==0)
		if (0!=mi_xmlrpc_http_build_header(page, max_page_len, tree, 1))
			return -1;
	buf = page->s;
	p = page->s + page->len;

	if (tree) { /* Build mi reply */
		if (mi_xmlrpc_http_recur_flush_tree(&p, buf, max_page_len,
						&tree->node, 0)<0)
			return -1;
		page->len = p - page->s;
	}
	return 0;
}
