/*
 * Copyright (C) 2011-2013 VoIP Embedded, Inc.
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


#include "../../str.h"
#include "../../ut.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../mi/mi.h"
#include "../../config.h"
#include "../../globals.h"
#include "../../locking.h"

#include "../../mi/mi_trace.h"
#include "../httpd/httpd_load.h"
#include "http_fnc.h"


extern str http_root;
extern int http_method;
extern trace_dest t_dst;
extern int mi_trace_mod_id;
extern httpd_api_t httpd_api;
str upSinceCTime;

http_mi_cmd_t* http_mi_cmds;
int http_mi_cmds_size;

gen_lock_t* mi_http_lock;


#define MI_HTTP_COPY(p,str)	\
do{	\
	if ((int)((p)-buf)+(str).len>max_page_len) {	\
		goto error;	\
	}	\
	memcpy((p), (str).s, (str).len); (p) += (str).len;	\
}while(0)

#define MI_HTTP_COPY_2(p,str1,str2)	\
do{	\
	if ((int)((p)-buf)+(str1).len+(str2).len>max_page_len) {	\
		goto error;	\
	}	\
	memcpy((p), (str1).s, (str1).len); (p) += (str1).len;	\
	memcpy((p), (str2).s, (str2).len); (p) += (str2).len;	\
}while(0)

#define MI_HTTP_COPY_3(p,str1,str2,str3)	\
do{	\
	if ((int)((p)-buf)+(str1).len+(str2).len+(str3).len>max_page_len) {	\
		goto error;	\
	}	\
	memcpy((p), (str1).s, (str1).len); (p) += (str1).len;	\
	memcpy((p), (str2).s, (str2).len); (p) += (str2).len;	\
	memcpy((p), (str3).s, (str3).len); (p) += (str3).len;	\
}while(0)

#define MI_HTTP_COPY_4(p,str1,str2,str3,str4)	\
do{	\
	if ((int)((p)-buf)+(str1).len+(str2).len+(str3).len+(str4).len>max_page_len) {	\
		goto error;	\
	}	\
	memcpy((p), (str1).s, (str1).len); (p) += (str1).len;	\
	memcpy((p), (str2).s, (str2).len); (p) += (str2).len;	\
	memcpy((p), (str3).s, (str3).len); (p) += (str3).len;	\
	memcpy((p), (str4).s, (str4).len); (p) += (str4).len;	\
}while(0)

#define MI_HTTP_COPY_5(p,s1,s2,s3,s4,s5)	\
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

#define MI_HTTP_COPY_6(p,s1,s2,s3,s4,s5,s6)	\
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

#define MI_HTTP_COPY_7(p,s1,s2,s3,s4,s5,s6,s7)	\
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

#define MI_HTTP_COPY_12(p,s1,s2,s3,s4,s5,s6,s7,s8,s9,s10,s11,s12)	\
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


#define MI_HTTP_ESC_COPY(p,str,temp_holder,temp_counter)	\
do{	\
	(temp_holder).s = (str).s;	\
	(temp_holder).len = 0;	\
	for((temp_counter)=0;(temp_counter)<(str).len;(temp_counter)++) {	\
		switch((str).s[(temp_counter)]) {	\
		case '<':	\
			(temp_holder).len = (temp_counter) - (temp_holder).len;	\
			MI_HTTP_COPY_2(p, (temp_holder), MI_HTTP_ESC_LT);	\
			(temp_holder).s = (str).s + (temp_counter) + 1;	\
			(temp_holder).len = (temp_counter) + 1;	\
			break;	\
		case '>':	\
			(temp_holder).len = (temp_counter) - (temp_holder).len;	\
			MI_HTTP_COPY_2(p, (temp_holder), MI_HTTP_ESC_GT);	\
			(temp_holder).s = (str).s + (temp_counter) + 1;	\
			(temp_holder).len = (temp_counter) + 1;	\
			break;	\
		case '&':	\
			(temp_holder).len = (temp_counter) - (temp_holder).len;	\
			MI_HTTP_COPY_2(p, (temp_holder), MI_HTTP_ESC_AMP);	\
			(temp_holder).s = (str).s + (temp_counter) + 1;	\
			(temp_holder).len = (temp_counter) + 1;	\
			break;	\
		case '"':	\
			(temp_holder).len = (temp_counter) - (temp_holder).len;	\
			MI_HTTP_COPY_2(p, (temp_holder), MI_HTTP_ESC_QUOT);	\
			(temp_holder).s = (str).s + (temp_counter) + 1;	\
			(temp_holder).len = (temp_counter) + 1;	\
			break;	\
		case '\'':	\
			(temp_holder).len = (temp_counter) - (temp_holder).len;	\
			MI_HTTP_COPY_2(p, (temp_holder), MI_HTTP_ESC_SQUOT);	\
			(temp_holder).s = (str).s + (temp_counter) + 1;	\
			(temp_holder).len = (temp_counter) + 1;	\
			break;	\
		case '\n': \
			(temp_holder).len = (temp_counter) - (temp_holder).len;	\
			MI_HTTP_COPY_2(p, (temp_holder), MI_HTTP_ESC_BREAK);	\
			(temp_holder).s = (str).s + (temp_counter) + 1;	\
			(temp_holder).len = (temp_counter) + 1;	\
			break;	\
		case '\t': \
			(temp_holder).len = (temp_counter) - (temp_holder).len;	\
			MI_HTTP_COPY_2(p, (temp_holder), MI_HTTP_ESC_TAB);	\
			(temp_holder).s = (str).s + (temp_counter) + 1;	\
			(temp_holder).len = (temp_counter) + 1;	\
			break;	\
		}	\
	}	\
	(temp_holder).len = (temp_counter) - (temp_holder).len;	\
	MI_HTTP_COPY(p, (temp_holder));	\
}while(0)

static const str MI_HTTP_METHOD[] = {
	str_init("GET"),
	str_init("POST")
};

static const str MI_HTTP_Response_Head_1 = str_init("<html><head><title>"\
	"OpenSIPS Management Interface</title>"\
	"<style type=\"text/css\">"\
		"body{margin:0;}body,p,div,td,th,tr,form,ol,ul,li,input,textarea,select,"\
		"a{font-family:\"lucida grande\",verdana,geneva,arial,helvetica,sans-serif;font-size:14px;}"\
		"a:hover{text-decoration:none;}a{text-decoration:underline;}"\
		".foot{padding-top:40px;font-size:10px;color:#333333;}"\
		".foot a{font-size:10px;color:#000000;}"
		"table.center{margin-left:auto;margin-right:auto;}"\
	"</style>"\
	"<meta http-equiv=\"Expires\" content=\"0\">"\
	"<meta http-equiv=\"Pragma\" content=\"no-cache\">");


static const str MI_HTTP_Response_Head_2 = str_init(\
"<link rel=\"icon\" type=\"image/png\" href=\"https://opensips.org/favicon.png\">"\
"</head>\n"\
"<body alink=\"#000000\" bgcolor=\"#ffffff\" link=\"#000000\" text=\"#000000\" vlink=\"#000000\">");

static const str MI_HTTP_Response_Title_Table_1 = str_init(\
"<table cellspacing=\"0\" cellpadding=\"5\" width=\"100%%\" border=\"0\">"\
	"<tr bgcolor=\"#BBDDFF\">"\
	"<td colspan=2 valign=\"top\" align=\"left\" bgcolor=\"#EFF7FF\" width=\"100%%\">"\
	"<br/><h2 align=\"center\">OpenSIPS MI HTML Interface</h2>"\
	"<p align=\"center\">");
static const str MI_HTTP_Response_Title_Table_2 = str_init(" is running since <i>");
static const str MI_HTTP_Response_Title_Table_3 = str_init("</i></p><br/></td></tr></table>\n<center>\n");

static const str MI_HTTP_Response_Menu_Table_1 = str_init("<table border=\"0\" cellpadding=\"3\" cellspacing=\"0\"><tbody><tr>\n");
static const str MI_HTTP_Response_Menu_Table_2 = str_init("<td><a href='");
static const str MI_HTTP_Response_Menu_Table_2b = str_init("<td><b><a href='");
static const str MI_HTTP_Response_Menu_Table_3 = str_init("'>");
static const str MI_HTTP_Response_Menu_Table_4 = str_init("</a><td>\n");
static const str MI_HTTP_Response_Menu_Table_4b = str_init("</a></b><td>\n");
static const str MI_HTTP_Response_Menu_Table_5 = str_init("</tr></tbody></table>\n");

static const str MI_HTTP_Response_Menu_Cmd_Table_1 = str_init("<table border=\"0\" cellpadding=\"3\" cellspacing=\"0\" width=\"90%\"><tbody>\n");
static const str MI_HTTP_Response_Menu_Cmd_tr_1 = str_init("<tr>\n");
static const str MI_HTTP_Response_Menu_Cmd_td_1a = str_init("	<td valign=\"top\" width=\"10%\"><a href='");
static const str MI_HTTP_Response_Menu_Cmd_td_3a = str_init("'>");
static const str MI_HTTP_Response_Menu_Cmd_td_4a = str_init("</a></td>\n");
static const str MI_HTTP_Response_Menu_Cmd_td_1b = str_init("	<td align=\"left\"><b>");
static const str MI_HTTP_Response_Menu_Cmd_td_1c = str_init("	<td valign=\"top\" align=\"left\" rowspan=\"");
static const str MI_HTTP_Response_Menu_Cmd_td_1d = str_init("	<td>");
static const str MI_HTTP_Response_Menu_Cmd_td_1e = str_init("	<td align=\"left\">");
static const str MI_HTTP_Response_Menu_Cmd_td_3c = str_init("\">");
static const str MI_HTTP_Response_Menu_Cmd_td_4b = str_init("</b></td>\n");
static const str MI_HTTP_Response_Menu_Cmd_td_4c = str_init("	</td>\n");
static const str MI_HTTP_Response_Menu_Cmd_td_4d = str_init("</td>\n");
static const str MI_HTTP_Response_Menu_Cmd_tr_2 = str_init("</tr>\n");
static const str MI_HTTP_Response_Menu_Cmd_Table_2 = str_init("</tbody></table>\n");

static const str MI_HTTP_NBSP = str_init("&nbsp;");
static const str MI_HTTP_SLASH = str_init("/");
static const str MI_HTTP_CODE_2 = str_init("</pre>");

static const str MI_HTTP_Post_1 = str_init("\n"\
"		<form name=\"input\" method=\"");

static const str MI_HTTP_Post_2 = str_init("\">\n"\
"			<input type=\"text\" name=\"arg\"/>\n"\
"			<input type=\"submit\" value=\"Submit\"/>\n"\
"		</form>\n");

static const str MI_HTTP_Response_Foot = str_init(\
"\n</center>\n<div align=\"center\" class=\"foot\" style=\"margin:20px auto\">"\
	"<span style='margin-left:5px;'></span>"\
	"<a href=\"https://opensips.org\">OpenSIPS web site</a><br/>"\
	"Copyright &copy; 2011-2015 <a href=\"http://www.voipembedded.com/\">VoIP Embedded, Inc.</a>"\
								". All rights reserved."\
"</div></body></html>");

#define MI_HTTP_ROWSPAN 5
static const str MI_HTTP_CMD_ROWSPAN = str_init("5");

static const str MI_HTTP_ESC_LT =    str_init("&lt;");   /* < */
static const str MI_HTTP_ESC_GT =    str_init("&gt;");   /* > */
static const str MI_HTTP_ESC_AMP =   str_init("&amp;");  /* & */
static const str MI_HTTP_ESC_QUOT =  str_init("&quot;"); /* " */
static const str MI_HTTP_ESC_SQUOT = str_init("&#39;");  /* ' */
static const str MI_HTTP_ESC_BREAK = str_init("<br>\n");
static const str MI_HTTP_ESC_TAB = str_init("&emsp;");


int mi_http_init_async_lock(void)
{
	mi_http_lock = lock_alloc();
	if (mi_http_lock==NULL) {
		LM_ERR("failed to create lock\n");
		return -1;
	}
	if (lock_init(mi_http_lock)==NULL) {
		LM_ERR("failed to init lock\n");
		return -1;
	}
	return 0;
}


void mi_http_destroy_async_lock(void)
{
	if (mi_http_lock) {
		lock_destroy(mi_http_lock);
		lock_dealloc(mi_http_lock);
	}
}


int mi_http_parse_url(const char* url, int* mod, int* cmd)
{
	int url_len = strlen(url);
	int index = 0;
	int i;
	int mod_len, cmd_len;

	if (url_len<0) {
		LM_ERR("Invalid url length [%d]\n", url_len);
		return -1;
	}
	if (url_len==0) return 0;
	if (url[0] != '/') {
		LM_ERR("URL starting with [%c] instead of'/'\n", *url);
		return -1;
	}
	index++;

	/* Looking for "mod" */
	if (index>=url_len)
		return 0;
	for(i=index;i<url_len && url[i]!='/';i++);
	mod_len = i - index;
	for(i=0;i<http_mi_cmds_size &&
		(mod_len!=http_mi_cmds[i].cmds[0].module.len ||
		strncmp(&url[index],http_mi_cmds[i].cmds[0].module.s,mod_len)!=0);
		i++);
	if (i==http_mi_cmds_size) {
		LM_ERR("Invalid mod [%.*s] in url [%s]\n",
			mod_len, &url[index], url);
		return -1;
	}
	*mod = i;
	LM_DBG("got mod [%d][%.*s]\n", *mod, mod_len, &url[index]);

	index += mod_len;
	LM_DBG("index=%d url_len=%d\n", index, url_len);
	if (index>=url_len)
		return 0;

	/* skip over '/' */
	index++;

	/* Looking for "cmd" */
	if (index>=url_len)
		return 0;
	for(i=index;i<url_len && url[i]!='/';i++);
	cmd_len = i - index;
	for(i=0;i<http_mi_cmds[*mod].size &&
		(cmd_len != http_mi_cmds[*mod].cmds[i].name.len ||
		strncmp(&url[index],http_mi_cmds[*mod].cmds[i].name.s,cmd_len)!=0);
		i++);
	if (i==http_mi_cmds[*mod].size) {
		LM_ERR("Invalid cmd [%.*s] in url [%s]\n",
			cmd_len, &url[index], url);
		return -1;
	}
	*cmd = i;
	LM_DBG("got cmd [%d][%.*s]\n", *cmd, cmd_len, &url[index]);
	index += cmd_len;
	if (index>=url_len)
		return 0;
	/* skip over '/' */
	index++;
	if (url_len - index>0) {
		LM_DBG("got extra [%s]\n", &url[index]);
	}

	return 0;
}

static void mi_http_close_async(mi_response_t *resp, struct mi_handler *hdl,
																	int done)
{
	mi_response_t *shm_resp = NULL;
	gen_lock_t* lock;
	mi_http_async_resp_data_t *async_resp_data;
	int x;

	if (hdl==NULL) {
		LM_CRIT("null mi handler\n");
		return;
	}

	LM_DBG("resp [%p], hdl [%p], hdl->param [%p], and done [%u]\n",
		resp, hdl, hdl->param, done);

	if (!done) {
		/* we do not pass provisional stuff (yet) */
		if (resp) free_mi_response( resp );
		return;
	}

	async_resp_data = (mi_http_async_resp_data_t*)(hdl+1);
	lock = async_resp_data->lock;

	if (resp==NULL || (shm_resp=shm_clone_mi_response(resp))==NULL) {
		LM_WARN("Unable to process async reply [%p]\n", resp);
		/* mark it as invalid */
		shm_resp = MI_HTTP_ASYNC_FAILED;
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
		if (shm_resp!=MI_HTTP_ASYNC_FAILED)
			free_shm_mi_response(shm_resp);
		shm_free(hdl);
	}

	return;
}

static inline struct mi_handler* mi_http_build_async_handler(void)
{
	struct mi_handler *hdl;
	mi_http_async_resp_data_t *async_resp_data;
	unsigned int len;

	len = sizeof(struct mi_handler)+sizeof(mi_http_async_resp_data_t);
	hdl = (struct mi_handler*)shm_malloc(len);
	if (hdl==NULL) {
		LM_ERR("oom\n");
		return NULL;
	}

	memset(hdl, 0, len);
	async_resp_data = (mi_http_async_resp_data_t*)(hdl+1);

	hdl->handler_f = mi_http_close_async;
	hdl->param = NULL;

	async_resp_data->lock = mi_http_lock;

	LM_DBG("hdl [%p], hdl->param [%p], mi_http_lock=[%p]\n",
		hdl, hdl->param, async_resp_data->lock);

	return hdl;
}

mi_response_t *mi_http_run_mi_cmd(int mod, int cmd, const str* arg,
			struct mi_handler **async_hdl,
			union sockaddr_union* cl_socket, int* is_traced)
{
	struct mi_cmd *f;
	struct mi_handler *hdl = NULL;
	str miCmd={NULL, 0};
	char *buf;
	mi_request_t req_item;
	mi_response_t *resp = NULL;

	/* initialize field to make sure it is not released in case of errors */
	req_item.req_obj = NULL;

	if (mod<0 && cmd<0) {
		LM_ERR("Incorect params: mod=[%d], cmd=[%d]\n", mod, cmd);
		goto error;
	}
	miCmd = http_mi_cmds[mod].cmds[cmd].name;
	f = lookup_mi_cmd(miCmd.s, miCmd.len);
	if (f == NULL) {
		LM_ERR("unable to find mi command [%.*s]\n", miCmd.len, miCmd.s);
		goto error;
	}

	if ( ! is_traced ) {
		LM_ERR("bad output is_traced param!\n");
		return 0;
	} else {
		*is_traced = is_mi_cmd_traced( mi_trace_mod_id, f);
	}

	if (f->flags&MI_ASYNC_RPL_FLAG) {
		/* We need to build an async handler */
		hdl = mi_http_build_async_handler();
		if (hdl==NULL) {
			LM_ERR("failed to build async handler\n");
			goto error;
		}
	} else {
		hdl = NULL;
	}

	memset(&req_item, 0, sizeof req_item);

	req_item.req_obj = cJSON_CreateObject();
	if (!req_item.req_obj) {
		LM_ERR("Failed to build temporary json request\n");
		goto error;
	}

	if (arg->s && arg->len) {
		buf = pkg_malloc(arg->len + 1);
		if (!buf) {
			LM_ERR("oom!\n");
			goto error;
		}
		memcpy(buf, arg->s, arg->len);
		buf[arg->len] = 0;

		req_item.params = cJSON_Parse(buf);
		if (!req_item.params) {
			LM_ERR("Failed to parse command params\n");
			goto error;
		}

		cJSON_AddItemToObject(req_item.req_obj, JSONRPC_PARAMS_S,
			req_item.params);
	}

	resp = handle_mi_request(&req_item, f, hdl);
	LM_DBG("got mi response = [%p]\n", resp);

	if ( !sv_socket ) {
		sv_socket = httpd_api.get_server_info();
	}

	if ( *is_traced ) {
		mi_trace_request(cl_socket, sv_socket, miCmd.s, miCmd.len,
			req_item.params, &backend, t_dst);
	}

	*async_hdl = hdl;

	if (req_item.req_obj)
		cJSON_Delete(req_item.req_obj);

	return resp;

error:
	mi_trace_request(cl_socket, sv_socket, miCmd.s, miCmd.len,
		NULL, &backend, t_dst);
	/* trace all errors */
	*is_traced = 1;

	if (req_item.req_obj)
		cJSON_Delete(req_item.req_obj);

	if (hdl) shm_free(hdl);
	*async_hdl  = NULL;
	return NULL;
}

int init_upSinceCTime(void)
{
	/* Build a cache value of initial startup time */
	upSinceCTime.s = (char*)pkg_malloc(26);
	if (upSinceCTime.s==NULL) {
		LM_ERR("oom\n");
		return -1;
	}
	ctime_r(&startup_time, upSinceCTime.s);
	upSinceCTime.len = strlen(upSinceCTime.s)-1;
	return 0;
}


int mi_http_init_cmds(void)
{
	int size, i;
	struct mi_cmd* cmds;
	http_mi_cmd_t *mi_cmd;

	/* Build a cache of all mi commands */
	get_mi_cmds(&cmds, &size);
	if (size<=0) {
		LM_ERR("Unable to get mi comands\n");
		return -1;
	}

	http_mi_cmds = (http_mi_cmd_t*)pkg_malloc(sizeof(http_mi_cmd_t));
	if (http_mi_cmds==NULL) {
		LM_ERR("oom\n");
		return -1;
	}

	http_mi_cmds->cmds = &cmds[0];
	http_mi_cmds->size = 0;
	http_mi_cmds_size = 1;
	mi_cmd = http_mi_cmds;

	for(i=0;i<size;i++){
		if(mi_cmd->cmds->module.s == cmds[i].module.s) {
			mi_cmd->size++;
		} else {
			mi_cmd = (http_mi_cmd_t*)pkg_realloc(http_mi_cmds,
				(http_mi_cmds_size+1)*sizeof(http_mi_cmd_t));
			if (mi_cmd==NULL) {
				LM_ERR("oom\n");
				return -1;
			}
			http_mi_cmds = mi_cmd;
			mi_cmd = &http_mi_cmds[http_mi_cmds_size];
			http_mi_cmds_size++;
			mi_cmd->cmds = &cmds[i];
			mi_cmd->size = 0;
			mi_cmd->size++;
		}
	}

	/* Build a cache value of initial startup time */
	return init_upSinceCTime();
}

static int mi_http_write_resp(char** p, char *buf, int max_page_len,
						mi_response_t *resp)
{
	mi_item_t *res;
	str unesc_buf;
	str tmp_s;
	int tmp_i;

	res = cJSON_GetObjectItem(resp, JSONRPC_ERROR_S);
	if (!res)
		res = cJSON_GetObjectItem(resp, JSONRPC_RESULT_S);
	if (!res) {
		LM_ERR("Invalid jsonrpc response object\n");
		return -1;
	}

	unesc_buf.s = cJSON_Print(res);
	if (!unesc_buf.s) {
		LM_ERR("Failed to print json response\n");
		return -1;
	}
	unesc_buf.len = strlen(unesc_buf.s);

	MI_HTTP_ESC_COPY(*p, unesc_buf, tmp_s, tmp_i);

	cJSON_PurgeString(unesc_buf.s);

	return 0;

error:
	LM_ERR("buffer 2 small\n");
	return -1;
}

int mi_http_build_content(str *page, int max_page_len,
				int mod, int cmd, mi_response_t *response)
{
	int i, j;
	char *p, *buf;

	if (page->s == NULL) {
		LM_ERR("Please provide a valid page\n");
		return -1;
	}
	p = buf = page->s;

	MI_HTTP_COPY_3(p,MI_HTTP_Response_Head_1,
			MI_HTTP_Response_Head_2,
			MI_HTTP_Response_Title_Table_1);
	if ((int)((p)-buf)+SERVER_HDR_LEN-8>max_page_len)
		goto error;
	memcpy(p, SERVER_HDR+8, SERVER_HDR_LEN-8);
	p += SERVER_HDR_LEN-8;
	MI_HTTP_COPY_3(p,MI_HTTP_Response_Title_Table_2,
			upSinceCTime,
			MI_HTTP_Response_Title_Table_3);

	/* Building module menu */
	MI_HTTP_COPY(p,MI_HTTP_Response_Menu_Table_1);
	for(i=0;i<http_mi_cmds_size;i++) {
		if(i!=mod) {
			MI_HTTP_COPY(p,MI_HTTP_Response_Menu_Table_2);
		} else {
			MI_HTTP_COPY(p,MI_HTTP_Response_Menu_Table_2b);
		}
		MI_HTTP_COPY(p,MI_HTTP_SLASH);
		if (http_root.len) {
			MI_HTTP_COPY_2(p,http_root,MI_HTTP_SLASH);
		}
		MI_HTTP_COPY_3(p,http_mi_cmds[i].cmds[0].module,
				MI_HTTP_Response_Menu_Table_3,
				http_mi_cmds[i].cmds[0].module);
		if(i!=mod) {
			MI_HTTP_COPY(p,MI_HTTP_Response_Menu_Table_4);
		} else {
			MI_HTTP_COPY(p,MI_HTTP_Response_Menu_Table_4b);
		}
	}
	MI_HTTP_COPY(p,MI_HTTP_Response_Menu_Table_5);

	if (response) { /* Build mi reply */
		/* Print comand name */
		MI_HTTP_COPY_4(p,MI_HTTP_Response_Menu_Cmd_Table_1,
				MI_HTTP_Response_Menu_Cmd_tr_1,
				MI_HTTP_Response_Menu_Cmd_td_1a,
				MI_HTTP_SLASH);
		if (http_root.len) {
			MI_HTTP_COPY_2(p,http_root, MI_HTTP_SLASH);
		}
		MI_HTTP_COPY_7(p,http_mi_cmds[mod].cmds[cmd].module,
				MI_HTTP_SLASH,
				http_mi_cmds[mod].cmds[cmd].name,
				MI_HTTP_Response_Menu_Cmd_td_3a,
				http_mi_cmds[mod].cmds[cmd].name,
				MI_HTTP_Response_Menu_Cmd_td_4a,
				MI_HTTP_Response_Menu_Cmd_td_1e);
		if (mi_http_write_resp(&p, buf, max_page_len, response) < 0)
			return -1;
		MI_HTTP_COPY(p,MI_HTTP_Response_Menu_Cmd_td_4d);
	} else if (mod>=0) { /* Building command menu */
		/* Build the list of comands for the selected module */
		MI_HTTP_COPY_4(p,MI_HTTP_Response_Menu_Cmd_Table_1,
				MI_HTTP_Response_Menu_Cmd_tr_1,
				MI_HTTP_Response_Menu_Cmd_td_1a,
				MI_HTTP_SLASH);
		if (http_root.len) {
			MI_HTTP_COPY_2(p,http_root,MI_HTTP_SLASH);
		}
		MI_HTTP_COPY_6(p,http_mi_cmds[mod].cmds[0].module,
				MI_HTTP_SLASH,
				http_mi_cmds[mod].cmds[0].name,
				MI_HTTP_Response_Menu_Cmd_td_3a,
				http_mi_cmds[mod].cmds[0].name,
				MI_HTTP_Response_Menu_Cmd_td_4a);
		if (cmd>=0) {
			MI_HTTP_COPY_3(p,MI_HTTP_Response_Menu_Cmd_td_1b,
					http_mi_cmds[mod].cmds[cmd].name,
					MI_HTTP_Response_Menu_Cmd_td_4b);
		}
		MI_HTTP_COPY(p,MI_HTTP_Response_Menu_Cmd_tr_2);
		for(j=1;j<http_mi_cmds[mod].size;j++) {
			MI_HTTP_COPY_3(p,MI_HTTP_Response_Menu_Cmd_tr_1,
					MI_HTTP_Response_Menu_Cmd_td_1a,
					MI_HTTP_SLASH);
			if (http_root.len) {
				MI_HTTP_COPY_2(p,http_root, MI_HTTP_SLASH);
			}
			MI_HTTP_COPY_6(p,http_mi_cmds[mod].cmds[j].module,
					MI_HTTP_SLASH,
					http_mi_cmds[mod].cmds[j].name,
					MI_HTTP_Response_Menu_Cmd_td_3a,
					http_mi_cmds[mod].cmds[j].name,
					MI_HTTP_Response_Menu_Cmd_td_4a);
			if (cmd>=0){
				if (j==1) {
					MI_HTTP_COPY_7(p,
						MI_HTTP_Response_Menu_Cmd_td_1c,
						MI_HTTP_CMD_ROWSPAN,
						MI_HTTP_Response_Menu_Cmd_td_3c,
						MI_HTTP_Post_1,
						MI_HTTP_METHOD[http_method],
						MI_HTTP_Post_2,
						MI_HTTP_Response_Menu_Cmd_td_4c);
				} else if (j>MI_HTTP_ROWSPAN) {
					MI_HTTP_COPY_3(p,
						MI_HTTP_Response_Menu_Cmd_td_1d,
						MI_HTTP_NBSP,
						MI_HTTP_Response_Menu_Cmd_td_4d);
				}
			}
			MI_HTTP_COPY(p,MI_HTTP_Response_Menu_Cmd_tr_2);
		}
		if (cmd>=0){
			if (j==1) {
				MI_HTTP_COPY_12(p,MI_HTTP_Response_Menu_Cmd_tr_1,
						MI_HTTP_Response_Menu_Cmd_td_1d,
						MI_HTTP_NBSP,
						MI_HTTP_Response_Menu_Cmd_td_4d,
						MI_HTTP_Response_Menu_Cmd_td_1c,
						MI_HTTP_CMD_ROWSPAN,
						MI_HTTP_Response_Menu_Cmd_td_3c,
						MI_HTTP_Post_1,
						MI_HTTP_METHOD[http_method],
						MI_HTTP_Post_2,
						MI_HTTP_Response_Menu_Cmd_td_4c,
						MI_HTTP_Response_Menu_Cmd_tr_2);
				j++;
			}
			for(;j<=MI_HTTP_ROWSPAN;j++) {
				MI_HTTP_COPY_5(p,MI_HTTP_Response_Menu_Cmd_tr_1,
						MI_HTTP_Response_Menu_Cmd_td_1d,
						MI_HTTP_NBSP,
						MI_HTTP_Response_Menu_Cmd_td_4d,
						MI_HTTP_Response_Menu_Cmd_tr_2);
			}
		}
		MI_HTTP_COPY_2(p,MI_HTTP_Response_Menu_Cmd_Table_2,
				MI_HTTP_Response_Foot);
	} else {
		MI_HTTP_COPY(p,MI_HTTP_Response_Foot);
	}

	page->len = p - page->s;
	return 0;
error:
	LM_ERR("buffer 2 small\n");
	page->len = p - page->s;
	return -1;
}

int mi_http_build_page(str *page, int max_page_len,
				int mod, int cmd, mi_response_t *response)
{
	char *p, *buf;

	if (0!=mi_http_build_content(page, max_page_len, mod, cmd, response))
		return -1;

	buf = page->s;
	p = page->s + page->len;

	if (response) { /* Build foot reply */
		MI_HTTP_COPY_5(p,MI_HTTP_CODE_2,
				MI_HTTP_Response_Menu_Cmd_td_4d,
				MI_HTTP_Response_Menu_Cmd_tr_2,
				MI_HTTP_Response_Menu_Cmd_Table_2,
				MI_HTTP_Response_Foot);
		page->len = p - page->s;
	}

	return 0;
error:
	LM_ERR("buffer 2 small\n");
	page->len = p - page->s;
	return -1;
}
