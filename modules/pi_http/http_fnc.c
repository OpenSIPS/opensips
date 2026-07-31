/*
 * Copyright (C) 2011-2013 VoIP Embedded Inc.
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
 * History:
 * ---------
 *  2011-09-20  first version (osas)
 */

#include "../../str.h"
#include "../../ut.h"
#include "../../db/db_ut.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../config.h"
#include "../../globals.h"
#include "../../socket_info.h"
#include "../../resolve.h"
#include "../../parser/parse_uri.h"
#include "../httpd/httpd_load.h"
#include "../../db/pi_framework.h"
#include "../../db/pi_framework_db.h"


#define PI_HTTP_XML_FRAMEWORK_NODE	"framework"
#define PI_HTTP_XML_DB_URL_NODE		"db_url"
#define PI_HTTP_XML_DB_TABLE_NODE	"db_table"
#define PI_HTTP_XML_TABLE_NAME_NODE	"table_name"
#define PI_HTTP_XML_DB_URL_ID_NODE	"db_url_id"

#define PI_HTTP_XML_MOD_NODE		"mod"
#define PI_HTTP_XML_MOD_NAME_NODE	"mod_name"
#define PI_HTTP_XML_CMD_NODE		"cmd"
#define PI_HTTP_XML_DB_TABLE_ID_NODE	"db_table_id"
#define PI_HTTP_XML_CMD_NAME_NODE	"cmd_name"
#define PI_HTTP_XML_CMD_TYPE_NODE	"cmd_type"
#define PI_HTTP_XML_CLAUSE_COLS_NODE	"clause_cols"
#define PI_HTTP_XML_QUERY_COLS_NODE	"query_cols"
#define PI_HTTP_XML_ORDER_BY_COLS_NODE	"order_by_cols"

#define PI_HTTP_XML_COLUMN_NODE		"column"
#define PI_HTTP_XML_COL_NODE		"col"

#define PI_HTTP_XML_FIELD_NODE		"field"
#define PI_HTTP_XML_LINK_CMD_NODE	"link_cmd"
#define PI_HTTP_XML_TYPE_NODE		"type"
#define PI_HTTP_XML_OPERATOR_NODE	"operator"
#define PI_HTTP_XML_VALUE_NODE		"value"
#define PI_HTTP_XML_VALIDATE_NODE	"validate"

#define PI_HTTP_XML_ID_ATTR		"id"

str http_root = str_init("pi");
int http_method = 0;
httpd_api_t httpd_api;

typedef struct pi_html_page_data_ {
	str page;
	str buffer;
	int mod;
	int cmd;
}pi_html_page_data_t;

pi_html_page_data_t html_page_data;

#define PI_HTTP_DB_UNDEF	0
#define PI_HTTP_DB_QUERY	1
#define PI_HTTP_DB_INSERT	2
#define PI_HTTP_DB_DELETE	3
#define PI_HTTP_DB_UPDATE	4
#define PI_HTTP_DB_REPLACE	5


#define PI_HTTP_COPY(p,str)	\
do{	\
	if ((int)((p)-buf)+(str).len>max_page_len) {	\
		goto error;	\
	}	\
	memcpy((p), (str).s, (str).len); (p) += (str).len;	\
}while(0)

#define PI_HTTP_COPY_2(p,str1,str2)	\
do{	\
	if ((int)((p)-buf)+(str1).len+(str2).len>max_page_len) {	\
		goto error;	\
	}	\
	memcpy((p), (str1).s, (str1).len); (p) += (str1).len;	\
	memcpy((p), (str2).s, (str2).len); (p) += (str2).len;	\
}while(0)

#define PI_HTTP_COPY_3(p,str1,str2,str3)	\
do{	\
	if ((int)((p)-buf)+(str1).len+(str2).len+(str3).len>max_page_len) {	\
		goto error;	\
	}	\
	memcpy((p), (str1).s, (str1).len); (p) += (str1).len;	\
	memcpy((p), (str2).s, (str2).len); (p) += (str2).len;	\
	memcpy((p), (str3).s, (str3).len); (p) += (str3).len;	\
}while(0)

#define PI_HTTP_COPY_4(p,str1,str2,str3,str4)	\
do{	\
	if ((int)((p)-buf)+(str1).len+(str2).len+(str3).len+(str4).len>max_page_len) {	\
		goto error;	\
	}	\
	memcpy((p), (str1).s, (str1).len); (p) += (str1).len;	\
	memcpy((p), (str2).s, (str2).len); (p) += (str2).len;	\
	memcpy((p), (str3).s, (str3).len); (p) += (str3).len;	\
	memcpy((p), (str4).s, (str4).len); (p) += (str4).len;	\
}while(0)

#define PI_HTTP_COPY_5(p,s1,s2,s3,s4,s5)	\
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

#define PI_HTTP_COPY_6(p,s1,s2,s3,s4,s5,s6)	\
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

#define PI_HTTP_COPY_8(p,s1,s2,s3,s4,s5,s6,s7,s8)	\
do{	\
	if ((int)((p)-buf)+(s1).len+(s2).len+(s3).len+(s4).len+(s5).len+(s6).len+(s7).len+(s8).len>max_page_len) {	\
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
}while(0)

#define PI_HTTP_COPY_9(p,s1,s2,s3,s4,s5,s6,s7,s8,s9)	\
do{	\
	if ((int)((p)-buf)+(s1).len+(s2).len+(s3).len+(s4).len+(s5).len+(s6).len+(s7).len+(s8).len+(s9).len>max_page_len) {	\
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
}while(0)

#define PI_HTTP_COPY_10(p,s1,s2,s3,s4,s5,s6,s7,s8,s9,s10)	\
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

#define PI_HTTP_COPY_11(p,s1,s2,s3,s4,s5,s6,s7,s8,s9,s10,s11)	\
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


#define PI_HTTP_COMPLETE_REPLY(page,buffer,mod,cmd,fmt,args...)	\
do{								\
	_len = snprintf((page)->s + (page)->len,		\
			(buffer)->len - (page)->len,		\
			fmt, ##args);				\
	if(_len<0)						\
		goto error;					\
	else							\
		(page)->len += _len;				\
	p = page->s + page->len;				\
	PI_HTTP_COPY(p,PI_HTTP_Response_Menu_Cmd_td_4d);	\
	page->len = p - page->s;				\
	if(pi_build_reply_footer((page), (buffer)->len)<0)	\
		goto error;					\
}while(0)


#define PI_HTTP_BUILD_REPLY(page,buffer,mod,cmd,fmt,args...)	\
do{								\
	if(pi_build_reply((page),(buffer)->len,(mod),(cmd))<0)	\
		goto error;					\
	_len = snprintf((page)->s + (page)->len,		\
			(buffer)->len - (page)->len,		\
			fmt, ##args);				\
	if(_len<0)						\
		goto error;					\
	else							\
		(page)->len += _len;				\
	p = page->s + page->len;				\
	PI_HTTP_COPY(p,PI_HTTP_Response_Menu_Cmd_td_4d);	\
	page->len = p - page->s;				\
	if(pi_build_reply_footer((page), (buffer)->len)<0)	\
		goto error;					\
}while(0)

/* */
#define PI_HTTP_ESC_COPY(p,str,temp_holder,temp_counter)	\
do{	\
	(temp_holder).s = (str).s;	\
	(temp_holder).len = 0;	\
	for((temp_counter)=0;(temp_counter)<(str).len;(temp_counter)++) {	\
		switch((str).s[(temp_counter)]) {	\
		case '<':	\
			(temp_holder).len = (temp_counter) - (temp_holder).len;	\
			PI_HTTP_COPY_2(p, (temp_holder), PI_HTTP_ESC_LT);	\
			(temp_holder).s = (str).s + (temp_counter) + 1;	\
			(temp_holder).len = (temp_counter) + 1;	\
			break;	\
		case '>':	\
			(temp_holder).len = (temp_counter) - (temp_holder).len;	\
			PI_HTTP_COPY_2(p, (temp_holder), PI_HTTP_ESC_GT);	\
			(temp_holder).s = (str).s + (temp_counter) + 1;	\
			(temp_holder).len = (temp_counter) + 1;	\
			break;	\
		case '&':	\
			(temp_holder).len = (temp_counter) - (temp_holder).len;	\
			PI_HTTP_COPY_2(p, (temp_holder), PI_HTTP_ESC_AMP);	\
			(temp_holder).s = (str).s + (temp_counter) + 1;	\
			(temp_holder).len = (temp_counter) + 1;	\
			break;	\
		case '"':	\
			(temp_holder).len = (temp_counter) - (temp_holder).len;	\
			PI_HTTP_COPY_2(p, (temp_holder), PI_HTTP_ESC_QUOT);	\
			(temp_holder).s = (str).s + (temp_counter) + 1;	\
			(temp_holder).len = (temp_counter) + 1;	\
			break;	\
		case '\'':	\
			(temp_holder).len = (temp_counter) - (temp_holder).len;	\
			PI_HTTP_COPY_2(p, (temp_holder), PI_HTTP_ESC_SQUOT);	\
			(temp_holder).s = (str).s + (temp_counter) + 1;	\
			(temp_holder).len = (temp_counter) + 1;	\
			break;	\
		}	\
	}	\
	(temp_holder).len = (temp_counter) - (temp_holder).len;	\
	PI_HTTP_COPY(p, (temp_holder));	\
}while(0)


static const str PI_HTTP_METHOD[] = {
	str_init("GET"),
	str_init("POST")
};

static const str PI_HTTP_Response_Head_1 = str_init("<html><head><title>"\
	"OpenSIPS Provisionning Interface</title>"\
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


static const str PI_HTTP_Response_Head_2 = str_init(\
"<link rel=\"icon\" type=\"image/png\" href=\"https://opensips.org/favicon.png\">"\
"</head>\n"\
"<body alink=\"#000000\" bgcolor=\"#ffffff\" link=\"#000000\" text=\"#000000\" vlink=\"#000000\">");

static const str PI_HTTP_Response_Title_Table_1 = str_init(\
"<table cellspacing=\"0\" cellpadding=\"5\" width=\"100%%\" border=\"0\">"\
	"<tr bgcolor=\"#BBDDFF\">"\
	"<td colspan=2 valign=\"top\" align=\"left\" bgcolor=\"#EFF7FF\" width=\"100%%\">"\
	"<br/><h2 align=\"center\">OpenSIPS Provisionning Interface</h2>");
static const str PI_HTTP_Response_Title_Table_3 = str_init("<br/></td></tr></table>\n<center>\n");

static const str PI_HTTP_Response_Menu_Table_1 = str_init("<table border=\"0\" cellpadding=\"3\" cellspacing=\"0\"><tbody><tr>\n");
static const str PI_HTTP_Response_Menu_Table_2 = str_init("<td><a href='");
static const str PI_HTTP_Response_Menu_Table_2b = str_init("<td><b><a href='");
static const str PI_HTTP_Response_Menu_Table_3 = str_init("'>");
static const str PI_HTTP_Response_Menu_Table_4 = str_init("</a><td>\n");
static const str PI_HTTP_Response_Menu_Table_4b = str_init("</a></b><td>\n");
static const str PI_HTTP_Response_Menu_Table_5 = str_init("</tr></tbody></table>\n");

static const str PI_HTTP_Response_Menu_Cmd_Table_1a = str_init("<table border=\"0\" cellpadding=\"3\" cellspacing=\"0\" width=\"90%\"><tbody>\n");
static const str PI_HTTP_Response_Menu_Cmd_Table_1b = str_init("<table border=\"1\" cellpadding=\"3\" cellspacing=\"0\" width=\"90%\"><tbody>\n");
static const str PI_HTTP_Response_Menu_Cmd_tr_1 = str_init("<tr>\n");
static const str PI_HTTP_Response_Menu_Cmd_td_1a = str_init("	<td width=\"10%\"><a href='");
static const str PI_HTTP_Response_Menu_Cmd_td_4a = str_init("</a></td>\n");
static const str PI_HTTP_Response_Menu_Cmd_td_1b = str_init("	<td align=\"left\"><b>");
static const str PI_HTTP_Response_Menu_Cmd_td_1c = str_init("	<td valign=\"top\" align=\"left\" rowspan=\"");
static const str PI_HTTP_Response_Menu_Cmd_td_1d = str_init("	<td>");
static const str PI_HTTP_Response_Menu_Cmd_td_1e = str_init("	<td colspan=\"99\">");
static const str PI_HTTP_Response_Menu_Cmd_td_1f = str_init("	<td rowspan=\"999999\">");
static const str PI_HTTP_Response_Menu_Cmd_td_3c = str_init("\">");
static const str PI_HTTP_Response_Menu_Cmd_td_4b = str_init("</b></td>\n");
static const str PI_HTTP_Response_Menu_Cmd_td_4c = str_init("	</td>\n");
static const str PI_HTTP_Response_Menu_Cmd_td_4d = str_init("</td>\n");
static const str PI_HTTP_Response_Menu_Cmd_tr_2 = str_init("</tr>\n");
static const str PI_HTTP_Response_Menu_Cmd_Table_2 = str_init("</tbody></table>\n");

static const str PI_HTTP_NBSP = str_init("&nbsp;");
static const str PI_HTTP_SLASH = str_init("/");
static const str PI_HTTP_SQUOT_GT = str_init("'>");

static const str PI_HTTP_ATTR_SEPARATOR = str_init(" ");
static const str PI_HTTP_ATTR_VAL_SEPARATOR = str_init("=");

static const str PI_HTTP_Post_Form_1a = str_init("\n"\
"		<form name=\"input\" method=\"");
static const str PI_HTTP_Post_Form_1b = str_init("\">\n"
"			<input type=hidden name=cmd value=\"on\">\n");

static const str PI_HTTP_Post_Input = str_init(\
"			");
static const str PI_HTTP_Post_Clause_Input = str_init("<br/>Clause:");
static const str PI_HTTP_Post_Values_Input = str_init("<br/>Values:");
static const str PI_HTTP_Post_Query_Input = str_init("<table border=\"0\" cellpadding=\"3\" cellspacing=\"0\"><tbody>\n");
static const str PI_HTTP_Post_Input_1 = str_init(\
"			<tr><td><b>");
static const str PI_HTTP_Post_Input_Text = str_init(\
"</b></td><td><input type=\"text\" name=\"");
static const str PI_HTTP_Post_Input_Select_1 = str_init(\
"</b></td><td><select name=\"");
static const str PI_HTTP_Post_Input_Select_2 = str_init("\"/>");
static const str PI_HTTP_Post_Input_Option_1 = str_init(\
"\n				<option value=\"");
static const str PI_HTTP_Post_Input_Option_2 = str_init("\">");
static const str PI_HTTP_Post_Input_Option_3 = str_init("</option>");
static const str PI_HTTP_Post_Input_Select_3 = str_init("</td></tr>\n");
static const str PI_HTTP_Post_Input_Hidden_1 = str_init(\
"			<input type=hidden name=\"");
static const str PI_HTTP_Post_Input_Hidden_2 = str_init("\" value=\"");
static const str PI_HTTP_Post_Input_Hidden_3 = str_init("\">\n");
static const str PI_HTTP_Post_Input_3 = str_init("\"/></td></tr>\n");
static const str PI_HTTP_Post_Input_4 = str_init(\
"			</tbody></table>\n");
static const str PI_HTTP_Post_Form_2 = str_init(\
"			<br/><input type=\"submit\" value=\"Submit\"/>\n"\
"		</form>\n");

static const str PI_HTTP_Response_Foot = str_init(\
"\n</center>\n<div align=\"center\" class=\"foot\" style=\"margin:20px auto\">"\
	"<span style='margin-left:5px;'></span>"\
	"<a href=\"https://opensips.org\">OpenSIPS web site</a><br/>"\
	"Copyright &copy; 2012-2015 <a href=\"http://www.voipembedded.com/\">VoIP Embedded, Inc.</a>"\
								". All rights reserved."\
"</div></body></html>");

#define PI_HTTP_ROWSPAN 20
static const str PI_HTTP_CMD_ROWSPAN = str_init("20");

static const str PI_HTTP_ESC_LT =    str_init("&lt;");   /* < */
static const str PI_HTTP_ESC_GT =    str_init("&gt;");   /* > */
static const str PI_HTTP_ESC_AMP =   str_init("&amp;");  /* & */
static const str PI_HTTP_ESC_QUOT =  str_init("&quot;"); /* " */
static const str PI_HTTP_ESC_SQUOT = str_init("&#39;");  /* ' */

static const str PI_HTTP_HREF_1 = str_init("<a href='/");
static const str PI_HTTP_HREF_2 = str_init("?cmd=pre&");
static const str PI_HTTP_HREF_3 = str_init("</a>");



int pi_build_form_imput(char **p, char *buf, str *page, int max_page_len,
		int mod, int cmd, str *clause, db_val_t *values)
{
	unsigned long i, j;
	char c;
	str op, arg;
	str val_str;
	str temp_holder;
	int temp_counter;
	pi_cmd_t *command;
	pi_mod_t *pi_modules;

	pi_modules = pi_framework_data->pi_modules;
	command = &pi_modules[mod].cmds[cmd];
	if(command->c_keys_size && (command->type==DB_CAP_QUERY ||
				command->type==DB_CAP_DELETE ||
				command->type==DB_CAP_UPDATE)){
		PI_HTTP_COPY_3(*p,PI_HTTP_Post_Input,
				PI_HTTP_Post_Clause_Input,
				PI_HTTP_Post_Query_Input);
		for(i=0;i<command->c_keys_size;i++){
			/* FIXME: we should escape c_ops */
			op.s = (char*)command->c_ops[i];
			op.len = strlen(op.s);
			arg.s = int2str(i, &arg.len);
			switch(command->c_vals[i].vals_size){
			case 0:
				PI_HTTP_COPY(*p, PI_HTTP_Post_Input_1);
				PI_HTTP_COPY(*p, *command->c_keys[i]);
				PI_HTTP_COPY(*p, PI_HTTP_ATTR_SEPARATOR);
				PI_HTTP_COPY(*p, op);
				PI_HTTP_COPY(*p, PI_HTTP_Post_Input_Text);
				PI_HTTP_COPY(*p, arg);
				if (i==0 && clause) {
					PI_HTTP_COPY(*p, PI_HTTP_Post_Input_Hidden_2);
					PI_HTTP_COPY(*p, *clause);
				}
				PI_HTTP_COPY(*p, PI_HTTP_Post_Input_3);
				break;
			case 1:
				PI_HTTP_COPY(*p, PI_HTTP_Post_Input_Hidden_1);
				PI_HTTP_COPY(*p, arg);
				PI_HTTP_COPY(*p, PI_HTTP_Post_Input_Hidden_2);
				PI_HTTP_COPY(*p, command->c_vals[i].vals[0]);
				PI_HTTP_COPY(*p, PI_HTTP_Post_Input_Hidden_3);
				break;
			default:
				PI_HTTP_COPY(*p, PI_HTTP_Post_Input_1);
				PI_HTTP_COPY(*p, *command->c_keys[i]);
				PI_HTTP_COPY(*p, PI_HTTP_ATTR_SEPARATOR);
				PI_HTTP_COPY(*p, op);
				LM_DBG("Here we need to enforce select\n");
				PI_HTTP_COPY(*p, PI_HTTP_Post_Input_Select_1);
				PI_HTTP_COPY(*p, arg);
				PI_HTTP_COPY(*p, PI_HTTP_Post_Input_Select_2);
				for(j=0;j<command->c_vals[i].vals_size;j++){
					PI_HTTP_COPY(*p, PI_HTTP_Post_Input_Option_1);
					PI_HTTP_COPY(*p, command->c_vals[i].vals[j]);
					PI_HTTP_COPY(*p, PI_HTTP_Post_Input_Option_2);
					PI_HTTP_COPY(*p, command->c_vals[i].ids[j]);
					PI_HTTP_COPY(*p, PI_HTTP_Post_Input_Option_3);
				}
				PI_HTTP_COPY(*p, PI_HTTP_Post_Input_Select_3);
			}
		}
		PI_HTTP_COPY(*p, PI_HTTP_Post_Input_4);
	}
	if(command->q_keys_size && (command->type==DB_CAP_INSERT ||
				command->type==DB_CAP_UPDATE ||
				command->type==DB_CAP_REPLACE)){
		PI_HTTP_COPY_3(*p,PI_HTTP_Post_Input,
				PI_HTTP_Post_Values_Input,
				PI_HTTP_Post_Query_Input);
		arg.s = &c; arg.len = 1;
		for(i=0,c='a';i<command->q_keys_size;i++,c++){
			if(c=='z'){
				LM_ERR("To many q_keys\n"); return -1;
			}
			switch(command->q_vals[i].vals_size){
			case 0:
				PI_HTTP_COPY(*p, PI_HTTP_Post_Input_1);
				PI_HTTP_COPY(*p, *command->q_keys[i]);
				PI_HTTP_COPY(*p, PI_HTTP_Post_Input_Text);
				PI_HTTP_COPY(*p, arg);
				if (values) {
					PI_HTTP_COPY(*p, PI_HTTP_Post_Input_Hidden_2);
					switch(command->q_types[i]){
					case DB_STR:
					case DB_STRING:
					case DB_BLOB:
						if(values[i].val.str_val.s==NULL){
							val_str.s = NULL; val_str.len = 0;
						} else {
							val_str.s = values[i].val.str_val.s;
							val_str.len = strlen(val_str.s);
						}
						LM_DBG("...got %.*s[0]=>"
							"[%.*s][%.*s]\n",
							command->q_keys[i]->len,
							command->q_keys[i]->s,
							values[i].val.str_val.len,
							values[i].val.str_val.s,
							val_str.len, val_str.s);
						if (val_str.len) {
							PI_HTTP_ESC_COPY(*p, val_str, temp_holder, temp_counter);
						}
						break;
					case DB_INT:
						val_str.s = *p;
						val_str.len = max_page_len - page->len;
						if(db_int2str(values[i].val.int_val,
									val_str.s, &val_str.len)!=0){
							LM_ERR("Unable to convert int [%d]\n",
								values[i].val.int_val);
							goto error;
						}
						*p += val_str.len;
						page->len += val_str.len;
						LM_DBG("   got %.*s[0]=>"
							"[%d][%.*s]\n",
							command->q_keys[i]->len,
							command->q_keys[i]->s,
							values[i].val.int_val,
							val_str.len, val_str.s);
						break;
					case DB_BITMAP:
						val_str.s = *p;
						val_str.len = max_page_len - page->len;
						if(db_int2str(values[i].val.bitmap_val,
									val_str.s, &val_str.len)!=0){
							LM_ERR("Unable to convert bitmap [%d]\n",
								values[i].val.bitmap_val);
							goto error;
						}
						*p += val_str.len;
						page->len += val_str.len;
						LM_DBG("   got %.*s[0]=>"
							"[%d][%.*s]\n",
							command->q_keys[i]->len,
							command->q_keys[i]->s,
							values[i].val.bitmap_val,
							val_str.len, val_str.s);
						break;
					case DB_BIGINT:
						val_str.s = *p;
						val_str.len = max_page_len - page->len;
						if(db_bigint2str(values[i].val.bigint_val,
									val_str.s, &val_str.len)!=0){
							LM_ERR("Unable to convert bigint [%-lld]\n",
								values[i].val.bigint_val);
							goto error;
						}
						*p += val_str.len;
						page->len += val_str.len;
						LM_DBG("   got %.*s[0]=>"
							"[%-lld][%.*s]\n",
							command->q_keys[i]->len,
							command->q_keys[i]->s,
							values[i].val.bigint_val,
							val_str.len, val_str.s);
						break;
					case DB_DOUBLE:
						val_str.s = *p;
						val_str.len = max_page_len - page->len;
						if(db_double2str(values[i].val.double_val,
									val_str.s, &val_str.len)!=0){
							LM_ERR("Unable to convert double [%-10.2f]\n",
								values[i].val.double_val);
							goto error;
						}
						*p += val_str.len;
						page->len += val_str.len;
						LM_DBG("   got %.*s[0]=>"
							"[%-10.2f][%.*s]\n",
							command->q_keys[i]->len,
							command->q_keys[i]->s,
							values[i].val.double_val,
							val_str.len, val_str.s);
						break;
					case DB_DATETIME:
						val_str.s = *p;
						val_str.len = max_page_len - page->len;
						if (db_time2str_nq(values[i].val.time_val,
									val_str.s, &val_str.len)!=0){
							LM_ERR("Unable to convert time [%ld]\n",
								(unsigned long int)values[i].val.time_val);
							goto error;
						}
						*p += val_str.len;
						page->len += val_str.len;
						LM_DBG("   got %.*s[0]=>"
							"[%ld][%.*s]\n",
							command->q_keys[i]->len,
							command->q_keys[i]->s,
							(unsigned long int)values[i].val.time_val,
							val_str.len, val_str.s);
						break;
					default:
						LM_ERR("unexpected type [%d] "
							"for [%.*s]\n",
							command->q_types[i],
							command->q_keys[i]->len,
							command->q_keys[i]->s);
					}
				}
				PI_HTTP_COPY(*p, PI_HTTP_Post_Input_3);
				break;
			case 1:
				PI_HTTP_COPY(*p, PI_HTTP_Post_Input_Hidden_1);
				PI_HTTP_COPY(*p, arg);
				PI_HTTP_COPY(*p, PI_HTTP_Post_Input_Hidden_2);
				PI_HTTP_COPY(*p, command->q_vals[i].vals[0]);
				PI_HTTP_COPY(*p, PI_HTTP_Post_Input_Hidden_3);
				break;
			default:
				PI_HTTP_COPY(*p, PI_HTTP_Post_Input_1);
				PI_HTTP_COPY(*p, *command->q_keys[i]);
				LM_DBG("Here we need to enforce select\n");
				PI_HTTP_COPY(*p, PI_HTTP_Post_Input_Select_1);
				PI_HTTP_COPY(*p, arg);
				PI_HTTP_COPY(*p, PI_HTTP_Post_Input_Select_2);
				for(j=0;j<command->q_vals[i].vals_size;j++){
					PI_HTTP_COPY(*p, PI_HTTP_Post_Input_Option_1);
					PI_HTTP_COPY(*p, command->q_vals[i].vals[j]);
					PI_HTTP_COPY(*p, PI_HTTP_Post_Input_Option_2);
					PI_HTTP_COPY(*p, command->q_vals[i].ids[j]);
					PI_HTTP_COPY(*p, PI_HTTP_Post_Input_Option_3);
				}
				PI_HTTP_COPY(*p, PI_HTTP_Post_Input_Select_3);
			}
		}
		PI_HTTP_COPY(*p, PI_HTTP_Post_Input_4);
	}
	return 0;
error:
	LM_ERR("buffer 2 small: *p=[%p] buf=[%p] max_page_len=[%d]\n",
			*p, buf, max_page_len);
	return -1;
}


int pi_build_header(str *page, int max_page_len, int mod, int cmd)
{
	int i;
	char *p, *buf;
	pi_mod_t *pi_modules;

	pi_modules = pi_framework_data->pi_modules;
	if (page->s == NULL) {
		LM_ERR("Please provide a valid page\n");
		return -1;
	}
	p = buf = page->s;

	PI_HTTP_COPY_4(p,PI_HTTP_Response_Head_1,
			PI_HTTP_Response_Head_2,
			PI_HTTP_Response_Title_Table_1,
			PI_HTTP_Response_Title_Table_3);
	/* Building module menu */
	PI_HTTP_COPY(p,PI_HTTP_Response_Menu_Table_1);
	for(i=0;i<pi_framework_data->pi_modules_size;i++) {
		if(i!=mod) {
			PI_HTTP_COPY(p,PI_HTTP_Response_Menu_Table_2);
		} else {
			PI_HTTP_COPY(p,PI_HTTP_Response_Menu_Table_2b);
		}
		PI_HTTP_COPY(p,PI_HTTP_SLASH);
		if (http_root.len) {
			PI_HTTP_COPY_2(p,http_root,PI_HTTP_SLASH);
		}
		PI_HTTP_COPY_3(p,pi_modules[i].module,
				PI_HTTP_Response_Menu_Table_3,
				pi_modules[i].module);
		if(i!=mod) {
			PI_HTTP_COPY(p,PI_HTTP_Response_Menu_Table_4);
		} else {
			PI_HTTP_COPY(p,PI_HTTP_Response_Menu_Table_4b);
		}
	}
	PI_HTTP_COPY(p,PI_HTTP_Response_Menu_Table_5);

	page->len = p - page->s;
	return 0;
error:
	LM_ERR("buffer 2 small\n");
	page->len = p - page->s;
	return -1;
}



int pi_build_reply(str *page, int max_page_len, int mod, int cmd)
{
	char *p, *buf;
	pi_mod_t *pi_modules;

	pi_modules = pi_framework_data->pi_modules;
	buf = page->s;
	p = page->s + page->len;

	/* Print comand name */
	PI_HTTP_COPY_4(p,PI_HTTP_Response_Menu_Cmd_Table_1b,
			PI_HTTP_Response_Menu_Cmd_tr_1,
			PI_HTTP_Response_Menu_Cmd_td_1a,
			PI_HTTP_SLASH);
	if (http_root.len) {
		PI_HTTP_COPY_2(p,http_root, PI_HTTP_SLASH);
	}
	PI_HTTP_COPY_6(p,pi_modules[mod].module,
			PI_HTTP_SLASH,
			pi_modules[mod].cmds[cmd].name,
			PI_HTTP_SQUOT_GT,
			pi_modules[mod].cmds[cmd].name,
			PI_HTTP_Response_Menu_Cmd_td_4a);
	/* Print cmd name */
	PI_HTTP_COPY_9(p,PI_HTTP_Response_Menu_Cmd_td_1e,
			pi_modules[mod].cmds[cmd].name,
			PI_HTTP_Response_Menu_Cmd_td_4d,
			PI_HTTP_Response_Menu_Cmd_tr_2,
			PI_HTTP_Response_Menu_Cmd_tr_1,
			PI_HTTP_Response_Menu_Cmd_td_1f,
			PI_HTTP_NBSP,
			PI_HTTP_Response_Menu_Cmd_td_4d,
			PI_HTTP_Response_Menu_Cmd_td_1d);

	page->len = p - page->s;
	return 0;
error:
	LM_ERR("buffer 2 small\n");
	page->len = p - page->s;
	return -1;
}

int pi_build_reply_footer(str *page, int max_page_len)
{
	char *p, *buf;
	/* Here we print the footer */
	buf = page->s;
	p = page->s + page->len;
	PI_HTTP_COPY_3(p,PI_HTTP_Response_Menu_Cmd_tr_2,
			PI_HTTP_Response_Menu_Cmd_Table_2,
			PI_HTTP_Response_Foot);
	page->len = p - page->s;
	return 0;
error:
	LM_ERR("buffer 2 small\n");
	page->len = p - page->s;
	return -1;
}

int pi_build_content(str *page, int max_page_len, int mod, int cmd, str *clause, db_val_t *values)
{
	char *p, *buf;
	int j;
	pi_mod_t *pi_modules;

	pi_modules = pi_framework_data->pi_modules;
	buf = page->s;
	p = page->s + page->len;

	if (mod>=0) { /* Building command menu */
		/* Build the list of comands for the selected module */
		PI_HTTP_COPY_4(p,PI_HTTP_Response_Menu_Cmd_Table_1a,
				PI_HTTP_Response_Menu_Cmd_tr_1,
				PI_HTTP_Response_Menu_Cmd_td_1a,
				PI_HTTP_SLASH);
		if (http_root.len) {
			PI_HTTP_COPY_2(p,http_root,PI_HTTP_SLASH);
		}
		PI_HTTP_COPY_6(p,pi_modules[mod].module,
				PI_HTTP_SLASH,
				pi_modules[mod].cmds[0].name,
				PI_HTTP_SQUOT_GT,
				pi_modules[mod].cmds[0].name,
				PI_HTTP_Response_Menu_Cmd_td_4a);
		if (cmd>=0) {
			PI_HTTP_COPY_3(p,PI_HTTP_Response_Menu_Cmd_td_1b,
					pi_modules[mod].cmds[cmd].name,
					PI_HTTP_Response_Menu_Cmd_td_4b);
		}
		PI_HTTP_COPY(p,PI_HTTP_Response_Menu_Cmd_tr_2);
		for(j=1;j<pi_modules[mod].cmds_size;j++) {
			PI_HTTP_COPY_3(p,PI_HTTP_Response_Menu_Cmd_tr_1,
					PI_HTTP_Response_Menu_Cmd_td_1a,
					PI_HTTP_SLASH);
			if (http_root.len) {
				PI_HTTP_COPY_2(p,http_root, PI_HTTP_SLASH);
			}
			PI_HTTP_COPY_6(p,pi_modules[mod].module,
					PI_HTTP_SLASH,
					pi_modules[mod].cmds[j].name,
					PI_HTTP_SQUOT_GT,
					pi_modules[mod].cmds[j].name,
					PI_HTTP_Response_Menu_Cmd_td_4a);
			if (cmd>=0){
				if (j==1) {
					PI_HTTP_COPY_6(p,
						PI_HTTP_Response_Menu_Cmd_td_1c,
						PI_HTTP_CMD_ROWSPAN,
						PI_HTTP_Response_Menu_Cmd_td_3c,
						PI_HTTP_Post_Form_1a,
						PI_HTTP_METHOD[http_method],
						PI_HTTP_Post_Form_1b);
					if(pi_build_form_imput(&p, buf, page, max_page_len,
							mod, cmd, clause, values)!=0)
						return -1;
					PI_HTTP_COPY_2(p, PI_HTTP_Post_Form_2,
						PI_HTTP_Response_Menu_Cmd_td_4c);
				} else if (j>PI_HTTP_ROWSPAN) {
					PI_HTTP_COPY_3(p,
						PI_HTTP_Response_Menu_Cmd_td_1d,
						PI_HTTP_NBSP,
						PI_HTTP_Response_Menu_Cmd_td_4d);
				}
			}
			PI_HTTP_COPY(p,PI_HTTP_Response_Menu_Cmd_tr_2);
		}
		if (cmd>=0){
			if (j==1) {
				PI_HTTP_COPY_10(p,PI_HTTP_Response_Menu_Cmd_tr_1,
						PI_HTTP_Response_Menu_Cmd_td_1d,
						PI_HTTP_NBSP,
						PI_HTTP_Response_Menu_Cmd_td_4d,
						PI_HTTP_Response_Menu_Cmd_td_1c,
						PI_HTTP_CMD_ROWSPAN,
						PI_HTTP_Response_Menu_Cmd_td_3c,
						PI_HTTP_Post_Form_1a,
						PI_HTTP_METHOD[http_method],
						PI_HTTP_Post_Form_1b);
				if(pi_build_form_imput(&p, buf, page, max_page_len,
						mod, cmd, clause, values)!=0)
					return -1;
				PI_HTTP_COPY_3(p, PI_HTTP_Post_Form_2,
						PI_HTTP_Response_Menu_Cmd_td_4c,
						PI_HTTP_Response_Menu_Cmd_tr_2);
				j++;
			}
			for(;j<=PI_HTTP_ROWSPAN;j++) {
				PI_HTTP_COPY_5(p,PI_HTTP_Response_Menu_Cmd_tr_1,
						PI_HTTP_Response_Menu_Cmd_td_1d,
						PI_HTTP_NBSP,
						PI_HTTP_Response_Menu_Cmd_td_4d,
						PI_HTTP_Response_Menu_Cmd_tr_2);
			}
		}
		PI_HTTP_COPY_2(p,PI_HTTP_Response_Menu_Cmd_Table_2,
				PI_HTTP_Response_Foot);
	} else {
		PI_HTTP_COPY(p,PI_HTTP_Response_Foot);
	}

	page->len = p - page->s;
	return 0;
error:
	LM_ERR("buffer 2 small\n");
	page->len = p - page->s;
	return -1;
}


int getVal(db_val_t *val, db_type_t val_type, db_key_t key, pi_db_table_t *table,
	str *arg, str *page, str *buffer, int mod, int cmd)
{
	char *p = page->s + page->len;
	char *buf = page->s;
	int _len, i;
	int max_page_len = buffer->len;
	pi_val_flags flags;

	str host;
	int port, proto;
	struct sip_uri uri;
	char c;

	for(i=0;i<table->cols_size;i++){
		if(table->cols[i].type==val_type &&
			table->cols[i].field.len==key->len &&
			strncmp(table->cols[i].field.s,key->s,key->len)==0){
			if(table->cols[i].validation==0) continue;
			flags = table->cols[i].validation;
			LM_DBG("[%.*s] has flags [%u]\n", key->len, key->s, flags);
			if(flags&PI_FLAG_P_HOST_PORT){
				//flags&= ~ PI_FLAG_P_HOST_PORT;
				if (parse_phostport(arg->s, arg->len,
						&host.s, &host.len,
						&port, &proto)!=0){
					PI_HTTP_BUILD_REPLY(page, buffer, mod, cmd,
						"Invalid [proto:]host[:port] for"
						"%.*s [%.*s].",
						key->len, key->s, arg->len,  arg->s);
					goto done;
				}
				LM_DBG("[%.*s]->[%d][%.*s][%d]\n",
					arg->len, arg->s, proto,
					host.len, host.s, port);
				continue;
			}
			LM_DBG("[%.*s] has flags [%d]\n", key->len, key->s, flags);
			if(flags&PI_FLAG_P_IPV4_PORT){
				//flags&= ~ PI_FLAG_P_IPV4_PORT;
				if (parse_phostport(arg->s, arg->len,
						&host.s, &host.len,
						&port, &proto)!=0){
					PI_HTTP_BUILD_REPLY(page, buffer, mod, cmd,
						"Invalid [proto:]IPv4[:port] for"
						" %.*s [%.*s].",
						key->len, key->s, arg->len,  arg->s);
					goto done;
				}
				LM_DBG("[%.*s]->[%d][%.*s][%d]\n",
					arg->len, arg->s, proto,
					host.len, host.s, port);
				if (str2ip(&host)==NULL) {
					PI_HTTP_BUILD_REPLY(page, buffer, mod, cmd,
						"Invalid IPv4 in [proto:]IPv4[:port]"
						" %.*s [%.*s][%.*s].",
						key->len, key->s,
						host.len, host.s,
						arg->len, arg->s);
					goto done;
				}
				continue;
			}
			LM_DBG("[%.*s] has flags [%d]\n", key->len, key->s, flags);
			if(flags&PI_FLAG_IPV4){
				//flags&= ~ PI_FLAG_IPV4;
				if (str2ip(arg)==NULL) {
					PI_HTTP_BUILD_REPLY(page, buffer, mod, cmd,
						"Invalid IPv4 for %.*s [%.*s].",
						key->len, key->s, arg->len, arg->s);
					goto done;
				}
				continue;
			}
			LM_DBG("[%.*s] has flags [%d]\n", key->len, key->s, flags);
			if(flags&PI_FLAG_URI){
				//flags&= ~ PI_FLAG_URI;
				if (parse_uri(arg->s, arg->len, &uri)<0){
					PI_HTTP_BUILD_REPLY(page, buffer, mod, cmd,
						"Invalid SIP URI for %.*s [%.*s].",
						key->len, key->s, arg->len, arg->s);
					goto done;
				}
				continue;
			}
			LM_DBG("[%.*s] has flags [%d]\n", key->len, key->s, flags);
			if(flags&PI_FLAG_URI_IPV4HOST){
				//flags&= ~ PI_FLAG_URI_IPV4HOST;
				if (parse_uri(arg->s, arg->len, &uri)<0){
					PI_HTTP_BUILD_REPLY(page, buffer, mod, cmd,
						"Invalid SIP URI for %.*s [%.*s].",
						key->len, key->s, arg->len, arg->s);
					goto done;
				}
				if (str2ip(&uri.host)==NULL) {
					PI_HTTP_BUILD_REPLY(page, buffer, mod, cmd,
						"Invalid IPv4 host in SIP URI for"
						" %.*s [%.*s][%.*s].",
						key->len, key->s,
						uri.host.len, uri.host.s,
						arg->len, arg->s);
					goto done;
				}
				continue;
			}
			LM_DBG("[%.*s] has flags [%d]\n", key->len, key->s, flags);
			if(flags){
				PI_HTTP_BUILD_REPLY(page, buffer, mod, cmd,
					"Unknown validation [%d] for %s.",
					table->cols[i].validation, key->s);
				goto done;
			}
		}
	}
	switch(val_type){
	case DB_STR:
	case DB_STRING:
	case DB_BLOB:
		if(arg->len){
			val->val.str_val.s = arg->s;
			val->val.str_val.len = arg->len;
		}
		break;
	case DB_INT:
		c = arg->s[arg->len];
		arg->s[arg->len] = '\0';
		if(db_str2int(arg->s,&val->val.int_val)<0){
			arg->s[arg->len] = c;
			PI_HTTP_BUILD_REPLY(page, buffer, mod, cmd,
				"Bogus field %.*s [%.*s].",
				key->len, key->s, arg->len, arg->s);
			goto done;
		}
		arg->s[arg->len] = c;
		break;
	case DB_BITMAP:
		c = arg->s[arg->len];
		arg->s[arg->len] = '\0';
		if(db_str2int(arg->s,(int*)&val->val.bitmap_val)<0){
			arg->s[arg->len] = c;
			PI_HTTP_BUILD_REPLY(page, buffer, mod, cmd,
				"Bogus field %.*s [%.*s].",
				key->len, key->s, arg->len, arg->s);
			goto done;
		}
		arg->s[arg->len] = c;
		break;
	case DB_BIGINT:
		c = arg->s[arg->len];
		arg->s[arg->len] = '\0';
		if(db_str2bigint(arg->s,&val->val.bigint_val)<0){
			arg->s[arg->len] = c;
			PI_HTTP_BUILD_REPLY(page, buffer, mod, cmd,
				"Bogus field %.*s [%.*s].",
				key->len, key->s, arg->len, arg->s);
			goto done;
		}
		arg->s[arg->len] = c;
		break;
	case DB_DOUBLE:
		c = arg->s[arg->len];
		arg->s[arg->len] = '\0';
		if(db_str2double(arg->s,&val->val.double_val)<0){
			arg->s[arg->len] = c;
			PI_HTTP_BUILD_REPLY(page, buffer, mod, cmd,
				"Bogus field %.*s [%.*s].",
				key->len, key->s, arg->len, arg->s);
			goto done;
		}
		arg->s[arg->len] = c;
		break;
	case DB_DATETIME:
		c = arg->s[arg->len];
		arg->s[arg->len] = '\0';
		if(db_str2time(arg->s,&val->val.time_val)<0){
			arg->s[arg->len] = c;
			PI_HTTP_BUILD_REPLY(page, buffer, mod, cmd,
				"Bogus field %.*s [%.*s].",
				key->len, key->s, arg->len, arg->s);
			goto done;
		}
		arg->s[arg->len] = c;
		break;
	default:
		PI_HTTP_BUILD_REPLY(page, buffer, mod, cmd,
			"Unexpected type [%d] for field [%.*s]\n",
			val_type, key->len, key->s);
		goto done;
	}
	page->len = p - page->s;
	return 0;
done:
	page->len = p - page->s;
	return 1;
error:
	LM_ERR("buffer 2 small\n");
	page->len = p - page->s;
	return -1;
}



int pi_run_cmd(int mod, int cmd,
			void *connection, void *con_cls,
			str *page, str *buffer)
{
	char *p;
	char *buf;
	int ret;

	str s_arg;
	str l_arg;
	str temp_holder;
	int temp_counter;
	int i;
	int j;
	int max_page_len;
	pi_cmd_t *command;

	int _len;
	int link_on;

	char tmp;
	char c[2];
	db_val_t *c_vals = NULL;
	db_val_t *q_vals = NULL;
	db_val_t *val;
	str val_str = {NULL, 0};
	int nr_rows;
	pi_db_url_t *db_url = NULL;
	db_res_t *res = NULL;
	db_val_t *values = NULL;
	db_row_t *rows;
	pi_mod_t *pi_modules;

	pi_modules = pi_framework_data->pi_modules;

	html_page_data.page.s = buffer->s;
	html_page_data.page.len = 0;
	html_page_data.buffer.s = buffer->s;
	html_page_data.buffer.len = buffer->len;
	html_page_data.mod = mod;
	html_page_data.cmd = cmd;
	max_page_len = buffer->len;

	if (0!=pi_build_header(page, buffer->len, mod, cmd)) return -1;
	buf = page->s;
	p = page->s + page->len;

	if (cmd<0) return pi_build_content(page, buffer->len, mod, cmd, NULL, NULL);

	httpd_api.lookup_arg(connection, "cmd", con_cls, &l_arg);
	if(l_arg.s==NULL) return pi_build_content(page, buffer->len, mod, cmd, NULL, NULL);

	LM_DBG("got arg cmd=[%.*s]\n", l_arg.len, l_arg.s);

	command = &pi_modules[mod].cmds[cmd];

	if (l_arg.len==3 && strncmp(l_arg.s, "pre", 3)==0) {
		/* We prebuild values only for update */
		if(command->type!=DB_CAP_UPDATE) {
			LM_ERR("command [%.*s] is not DB_CAP_UPDATE type\n",
				command->name.len, command->name.s);
			return pi_build_content(page, buffer->len, mod, cmd, NULL, NULL);
		}
		/* We prebuild values only for single clause update command */
		if(command->c_keys_size!=1) {
			LM_ERR("command [%.*s] has [%d] clause keys\n",
				command->name.len, command->name.s, command->c_keys_size);
			return pi_build_content(page, buffer->len, mod, cmd, NULL, NULL);
		}
		LM_DBG("[%.*s] with clause key [%.*s]\n",
			command->name.len, command->name.s,
			command->c_keys[0]->len, command->c_keys[0]->s);

		tmp = command->c_keys[0]->s[command->c_keys[0]->len];
		command->c_keys[0]->s[command->c_keys[0]->len] = '\0';
		LM_DBG("httpd_api.lookup_arg[%s]\n", command->c_keys[0]->s);
		httpd_api.lookup_arg(connection, command->c_keys[0]->s, con_cls, &l_arg);
		if(l_arg.s==NULL) {
			LM_ERR("missing clause key [%.*s] in args\n",
				command->c_keys[0]->len, command->c_keys[0]->s);
			command->c_keys[0]->s[command->c_keys[0]->len] = tmp;
			return pi_build_content(page, buffer->len, mod, cmd, NULL, NULL);
		}
		command->c_keys[0]->s[command->c_keys[0]->len] = tmp;

		LM_DBG("got clause [%.*s] with value [%.*s]\n",
			command->c_keys[0]->len, command->c_keys[0]->s, l_arg.len, l_arg.s);

		c_vals = (db_val_t*)pkg_malloc(command->c_keys_size*sizeof(db_val_t));
		if(c_vals==NULL){
			LM_ERR("oom\n");
			return -1;
		}
		memset(c_vals, 0, command->c_keys_size*sizeof(db_val_t));

		val = &c_vals[0];
		val->type = command->c_types[0];
		ret = getVal(val, command->c_types[0], command->c_keys[0],
				command->db_table, &l_arg, page, buffer, mod, cmd);
		if(ret<0)
			goto error;
		else if(ret>0)
			goto finish_page;

		/* Let's run the query to get the values for the record to update*/
		db_url = command->db_table->db_url;
		if(pi_use_table(command->db_table)<0){
			PI_HTTP_BUILD_REPLY(page, buffer, mod, cmd,
				"Error on table [%.*s].",
				command->db_table->name.len,
				command->db_table->name.s);
			goto finish_page;
		}

		if(db_url->dbf.query(*db_url->db_handle,
			command->c_keys, command->c_ops, c_vals,
			command->q_keys,
			command->c_keys_size,
			command->q_keys_size,
			command->o_keys?*command->o_keys:0, &res) < 0){
			PI_HTTP_COMPLETE_REPLY(page, buffer, mod, cmd,
				"Error while querying database.");
			goto finish_page;
		}
		nr_rows = RES_ROW_N(res);
		switch (nr_rows) {
		case 0:
			LM_ERR("no record on clause key [%.*s]\n",
				command->c_keys[0]->len, command->c_keys[0]->s);
			if(c_vals) {
				pkg_free(c_vals);
				c_vals = NULL;
			}
			goto finish_page;
		case 1:
			LM_DBG("got [%d] rows for key [%.*s]\n",
				nr_rows, command->c_keys[0]->len, command->c_keys[0]->s);
			break;
		default:
			LM_ERR("to many records [%d] on clause key [%.*s]\n",
				nr_rows, command->c_keys[0]->len, command->c_keys[0]->s);
			goto finish_page;
		}

		rows = RES_ROWS(res);
		values = ROW_VALUES(rows);
		ret = pi_build_content(page, buffer->len, mod, cmd, &l_arg, values);
		db_url->dbf.free_result(*db_url->db_handle, res);
		//res = NULL;
		return ret;
	} else if(l_arg.len==2 && strncmp(l_arg.s, "on", 2)==0) {
		/* allocate c_vals array */
		if(command->c_keys_size){
			c_vals = (db_val_t*)pkg_malloc(command->c_keys_size*sizeof(db_val_t));
			if(c_vals==NULL){
				LM_ERR("oom\n");
				return -1;
			}
			memset(c_vals, 0, command->c_keys_size*sizeof(db_val_t));
			for(i=0;i<command->c_keys_size;i++){
				s_arg.s = int2str(i, &s_arg.len);
				httpd_api.lookup_arg(connection, s_arg.s, con_cls, &l_arg);
				if(l_arg.s==NULL){
					PI_HTTP_BUILD_REPLY(page, buffer, mod, cmd,
						"No argument for clause field #%d: %.*s.",
						i, command->c_keys[i]->len,
						command->c_keys[i]->s);
					goto done;
				}
				s_arg.len = l_arg.len;
				if(s_arg.len==0){
					PI_HTTP_BUILD_REPLY(page, buffer, mod, cmd,
						"Empty argument for clause field #%d: %.*s.",
						i,command->c_keys[i]->len,
						command->c_keys[i]->s);
					goto done;
				}
				s_arg.s = l_arg.s;
				val = &c_vals[i];
				val->type = command->c_types[i];

				ret = getVal(val, command->c_types[i], command->c_keys[i],
					command->db_table, &s_arg, page, buffer, mod, cmd);
				if(ret<0)
					goto error;
				else if(ret>0)
					goto done;
			}
		}
	}
	if(command->q_keys_size && command->type!=DB_CAP_QUERY){
		q_vals = (db_val_t*)pkg_malloc(command->q_keys_size*sizeof(db_val_t));
		if(q_vals==NULL){
			LM_ERR("oom\n");
			return -1;
		}
		memset(q_vals, 0, command->q_keys_size*sizeof(db_val_t));
		c[1] = '\0';
		for(i=0,c[0]='a';i<command->q_keys_size;i++,(c[0])++){
			if(c[0]=='z'){
				PI_HTTP_BUILD_REPLY(page, buffer, mod, cmd,
					"Too many query values.");
				goto done;
			}
			LM_DBG("looking for arg [%s]\n", c);
			httpd_api.lookup_arg(connection, c, con_cls, &l_arg);
			if(l_arg.s==NULL){
				PI_HTTP_BUILD_REPLY(page, buffer, mod, cmd,
					"No argument for query field #%d: %.*s.",
					i, command->q_keys[i]->len,
					command->q_keys[i]->s);
				goto done;
			}
			s_arg.len = l_arg.len;
			if(s_arg.len==0 && (command->q_types[i]!=DB_STR &&
					command->q_types[i]!=DB_STRING &&
					command->q_types[i]!=DB_BLOB)){
				PI_HTTP_BUILD_REPLY(page, buffer, mod, cmd,
					"Empty argument for query field #%d: %.*s.",
					i, command->q_keys[i]->len,
					command->q_keys[i]->s);
				goto done;
			}
			s_arg.s = l_arg.s;
			val = &q_vals[i];
			val->type = command->q_types[i];
			ret = getVal(val, command->q_types[i], command->q_keys[i],
				command->db_table, &s_arg, page, buffer, mod, cmd);
			if(ret<0)
				goto error;
			else if(ret>0)
				goto done;

		}
	}

	db_url = command->db_table->db_url;
	if(pi_use_table(command->db_table)<0){
		PI_HTTP_BUILD_REPLY(page, buffer, mod, cmd,
			"Error on table [%.*s].",
			command->db_table->name.len,
			command->db_table->name.s);
		goto done;
	}
	if(pi_build_reply(page, buffer->len, mod, cmd)<0)
		goto error;
	p = page->s + page->len;
	switch (command->type) {
	case DB_CAP_QUERY:
		for(j=0;j<command->q_keys_size;j++){
			if(j)PI_HTTP_COPY(p,PI_HTTP_Response_Menu_Cmd_td_1d);
			PI_HTTP_COPY_2(p,*(command->q_keys[j]),
					PI_HTTP_Response_Menu_Cmd_td_4d);

		}
		if (DB_CAPABILITY(db_url->dbf, DB_CAP_FETCH)){
			if(db_url->dbf.query(*db_url->db_handle,
				command->c_keys, command->c_ops, c_vals,
				command->q_keys,
				command->c_keys_size,
				command->q_keys_size,
				command->o_keys?*command->o_keys:0, 0) < 0){
				PI_HTTP_COMPLETE_REPLY(page, buffer, mod, cmd,
					"Error while querying (fetch) database.");
				goto done;
			}
			if(db_url->dbf.fetch_result(*db_url->db_handle,
					&res, 100)<0){
				PI_HTTP_COMPLETE_REPLY(page, buffer, mod, cmd,
					"Fetching rows failed.");
				goto done;
			}
		}else{
			if(db_url->dbf.query(*db_url->db_handle,
				command->c_keys, command->c_ops, c_vals,
				command->q_keys,
				command->c_keys_size,
				command->q_keys_size,
				command->o_keys?*command->o_keys:0, &res) < 0){
				PI_HTTP_COMPLETE_REPLY(page, buffer, mod, cmd,
					"Error while querying database.");
				goto done;
			}
		}
		nr_rows = RES_ROW_N(res);
		do{
			LM_DBG("loading [%i] records from db\n", nr_rows);
			rows = RES_ROWS(res);
			for(i=0;i<nr_rows;i++){
				values = ROW_VALUES(rows + i);
				PI_HTTP_COPY(p,PI_HTTP_Response_Menu_Cmd_tr_1);
				for(j=0;j<command->q_keys_size;j++){
					PI_HTTP_COPY(p,PI_HTTP_Response_Menu_Cmd_td_1d);
					/* BEGIN */
					link_on = 0;
					if(command->link_cmd && command->link_cmd[j].s) {
						link_on = 1;
						PI_HTTP_COPY(p,PI_HTTP_HREF_1);
						if (http_root.len) {
							PI_HTTP_COPY_2(p,http_root, PI_HTTP_SLASH);
						}
						PI_HTTP_COPY_2(p,pi_modules[mod].module, PI_HTTP_SLASH);
						PI_HTTP_COPY(p,command->link_cmd[j]); /* this is the command */
						PI_HTTP_COPY_3(p,PI_HTTP_HREF_2,
								*command->q_keys[j],
								PI_HTTP_ATTR_VAL_SEPARATOR);
					}
					/* END */
					switch(command->q_types[j]){
					case DB_STR:
					case DB_STRING:
					case DB_BLOB:
						if(values[j].val.str_val.s==NULL){
							val_str.s = NULL; val_str.len = 0;
						} else {
							val_str.s = values[j].val.str_val.s;
							val_str.len = strlen(val_str.s);
						}
						LM_DBG("...got %.*s[%d]=>"
							"[%.*s][%.*s]\n",
							command->q_keys[j]->len,
							command->q_keys[j]->s, i,
							values[j].val.str_val.len,
							values[j].val.str_val.s,
							val_str.len, val_str.s);
						if (val_str.len) {
							if(link_on) {
								PI_HTTP_ESC_COPY(p, val_str, temp_holder, temp_counter);
								PI_HTTP_COPY(p,PI_HTTP_SQUOT_GT);
							}
							PI_HTTP_ESC_COPY(p, val_str, temp_holder, temp_counter);
						} else {
							if(link_on) {
								PI_HTTP_COPY(p, PI_HTTP_NBSP);
								PI_HTTP_COPY(p,PI_HTTP_SQUOT_GT);
							}
							PI_HTTP_COPY(p, PI_HTTP_NBSP);
						}
						break;
					case DB_INT:
						val_str.s = p;
						val_str.len = max_page_len - page->len;
						if(db_int2str(values[j].val.int_val,
									val_str.s, &val_str.len)!=0){
							LM_ERR("Unable to convert int [%d]\n",
								values[j].val.int_val);
							goto error;
						}
						p += val_str.len;
						page->len += val_str.len;
						if(link_on) PI_HTTP_COPY_2(p,PI_HTTP_SQUOT_GT,val_str);
						LM_DBG("   got %.*s[%d]=>"
							"[%d][%.*s]\n",
							command->q_keys[j]->len,
							command->q_keys[j]->s, i,
							values[j].val.int_val,
							val_str.len, val_str.s);
						break;
					case DB_BITMAP:
						val_str.s = p;
						val_str.len = max_page_len - page->len;
						if(db_int2str(values[j].val.bitmap_val,
									val_str.s, &val_str.len)!=0){
							LM_ERR("Unable to convert bitmap [%d]\n",
								values[j].val.bitmap_val);
							goto error;
						}
						p += val_str.len;
						page->len += val_str.len;
						if(link_on) PI_HTTP_COPY_2(p,PI_HTTP_SQUOT_GT,val_str);
						LM_DBG("   got %.*s[%d]=>"
							"[%d][%.*s]\n",
							command->q_keys[j]->len,
							command->q_keys[j]->s, i,
							values[j].val.bitmap_val,
							val_str.len, val_str.s);
						break;
					case DB_BIGINT:
						val_str.s = p;
						val_str.len = max_page_len - page->len;
						if(db_bigint2str(values[j].val.bigint_val,
									val_str.s, &val_str.len)!=0){
							LM_ERR("Unable to convert bigint [%-lld]\n",
								values[j].val.bigint_val);
							goto error;
						}
						p += val_str.len;
						page->len += val_str.len;
						if(link_on) PI_HTTP_COPY_2(p,PI_HTTP_SQUOT_GT,val_str);
						LM_DBG("   got %.*s[%d]=>"
							"[%-lld][%.*s]\n",
							command->q_keys[j]->len,
							command->q_keys[j]->s, i,
							values[j].val.bigint_val,
							val_str.len, val_str.s);
						break;
					case DB_DOUBLE:
						val_str.s = p;
						val_str.len = max_page_len - page->len;
						if(db_double2str(values[j].val.double_val,
									val_str.s, &val_str.len)!=0){
							LM_ERR("Unable to convert double [%-10.2f]\n",
								values[j].val.double_val);
							goto error;
						}
						p += val_str.len;
						page->len += val_str.len;
						if(link_on) PI_HTTP_COPY_2(p,PI_HTTP_SQUOT_GT,val_str);
						LM_DBG("   got %.*s[%d]=>"
							"[%-10.2f][%.*s]\n",
							command->q_keys[j]->len,
							command->q_keys[j]->s, i,
							values[j].val.double_val,
							val_str.len, val_str.s);
						break;
					case DB_DATETIME:
						val_str.s = p;
						val_str.len = max_page_len - page->len;
						if (db_time2str_nq(values[j].val.time_val,
									val_str.s, &val_str.len)!=0){
							LM_ERR("Unable to convert time [%ld]\n",
								(unsigned long int)values[j].val.time_val);
							goto error;
						}
						p += val_str.len;
						page->len += val_str.len;
						if(link_on) PI_HTTP_COPY_2(p,PI_HTTP_SQUOT_GT,val_str);
						LM_DBG("   got %.*s[%d]=>"
							"[%ld][%.*s]\n",
							command->q_keys[j]->len,
							command->q_keys[j]->s, i,
							(unsigned long int)values[j].val.time_val,
							val_str.len, val_str.s);
						break;
					default:
						LM_ERR("unexpected type [%d] "
							"for [%.*s]\n",
							command->q_types[j],
							command->q_keys[j]->len,
							command->q_keys[j]->s);
					}
					if(link_on) PI_HTTP_COPY(p,PI_HTTP_HREF_3);
					PI_HTTP_COPY(p,PI_HTTP_Response_Menu_Cmd_td_4d);
				}
				PI_HTTP_COPY(p,PI_HTTP_Response_Menu_Cmd_tr_2);
			}
			/* any more data to be fetched ?*/
			if (DB_CAPABILITY(db_url->dbf, DB_CAP_FETCH)){
				if(db_url->dbf.fetch_result(*db_url->db_handle,
					&res, 100)<0){
					LM_ERR("fetching more rows failed\n");
					goto error;
				}
				nr_rows = RES_ROW_N(res);
			}else{
				nr_rows = 0;
			}
		}while (nr_rows>0);
		db_url->dbf.free_result(*db_url->db_handle, res);
		res=NULL;
		goto finish_page;
		break;
	case DB_CAP_INSERT:
		if((db_url->dbf.insert(*db_url->db_handle,
			command->q_keys, q_vals, command->q_keys_size))!=0){
			PI_HTTP_COMPLETE_REPLY(page, buffer, mod, cmd,
					"Unable to add record to db.");
		}else{
			PI_HTTP_COMPLETE_REPLY(page, buffer, mod, cmd,
					"Record successfully added to db.");
		}
		goto done;
		break;
	case DB_CAP_DELETE:
		if((db_url->dbf.delete(*db_url->db_handle,
			command->c_keys, command->c_ops, c_vals,
			command->c_keys_size))!=0) {
			PI_HTTP_COMPLETE_REPLY(page, buffer, mod, cmd,
					"Unable to delete record.");
		}else{
			PI_HTTP_COMPLETE_REPLY(page, buffer, mod, cmd,
					"Record successfully deleted from db.");
		}
		goto done;
		break;
	case DB_CAP_UPDATE:
		if((db_url->dbf.update(*db_url->db_handle,
			command->c_keys, command->c_ops, c_vals,
			command->q_keys, q_vals,
			command->c_keys_size, command->q_keys_size))!=0){
			PI_HTTP_COMPLETE_REPLY(page, buffer, mod, cmd,
					"Unable to update record.");
		}else{
			PI_HTTP_COMPLETE_REPLY(page, buffer, mod, cmd,
					"Record successfully updated.");
		}
		goto done;
		break;
	case DB_CAP_REPLACE:
		if((db_url->dbf.replace(*db_url->db_handle,
			command->q_keys, q_vals, command->q_keys_size))!=0){
			PI_HTTP_COMPLETE_REPLY(page, buffer, mod, cmd,
					"Unable to replace record.");
		}else{
			PI_HTTP_COMPLETE_REPLY(page, buffer, mod, cmd,
					"Record successfully replaced.");
		}
		break;
	default:
		PI_HTTP_COMPLETE_REPLY(page, buffer, mod, cmd,
			"Corrupt data for mod=[%d] and cmd=[%d]\n", mod, cmd);
		goto done;
	}
	LM_ERR("You shoudn't end up here\n");
error:
	if (db_url && res)
		db_url->dbf.free_result(*db_url->db_handle, res);
	if(c_vals) pkg_free(c_vals);
	if(q_vals) pkg_free(q_vals);
	return -1;

finish_page:
	if(c_vals) pkg_free(c_vals);
	if(q_vals) pkg_free(q_vals);
	page->len = p - page->s;
	return pi_build_reply_footer(page, buffer->len);

done:
	if(c_vals) pkg_free(c_vals);
	if(q_vals) pkg_free(q_vals);
	return 0;
}
