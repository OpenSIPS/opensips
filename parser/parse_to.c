/*
 * Copyright (C) 2001-2003 Fhg Fokus
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
 * ---------
 * 2003-04-26 ZSW (jiri)
 * 2006-05-29 removed the NO_PINGTEL_TAG_HACK - it's conflicting the RFC 3261;
 *            TAG parameter must have value; other parameters are accepted
 *            without value (bogdan)
 */


#include "parse_to.h"
#include <stdlib.h>
#include <string.h>
#include "../dprint.h"
#include "msg_parser.h"
#include "parse_uri.h"
#include "../ut.h"
#include "../mem/mem.h"
#include "../errinfo.h"


enum {
	START_TO, DISPLAY_QUOTED, E_DISPLAY_QUOTED, DISPLAY_TOKEN, DISPLAY_TOKEN2,
	S_URI_ENCLOSED, URI_ENCLOSED, E_URI_ENCLOSED,
	URI_OR_TOKEN, MAYBE_URI_END, END, F_CR, F_LF, F_CRLF
};


enum {
	S_PARA_NAME=20, PARA_NAME, S_EQUAL, S_PARA_VALUE, TAG1, TAG2,
	TAG3, PARA_VALUE_TOKEN , PARA_VALUE_QUOTED, E_PARA_VALUE
};



#define add_param( _param , _body ) \
	do{\
		LM_DBG("%.*s=%.*s\n",param->name.len,ZSW(param->name.s),\
			param->value.len,ZSW(param->value.s));\
		if (!(_body)->param_lst)  (_body)->param_lst=(_param);\
		else (_body)->last_param->next=(_param);\
		(_body)->last_param =(_param);\
		if ((_param)->type==TAG_PARAM)\
			memcpy(&((_body)->tag_value),&((_param)->value),sizeof(str));\
		(_param) = 0;\
	}while(0);



void free_to_params(struct to_body* tb)
{
	struct to_param *tp=tb->param_lst;
	struct to_param *foo;
	while (tp){
		foo = tp->next;
		pkg_free(tp);
		tp=foo;
	}

	tb->param_lst = tb->last_param = NULL;
}


void free_to(struct to_body* tb)
{
	if (tb) {
		free_to( tb->next );
		free_to_params(tb);
		pkg_free(tb);
	}
}


static inline char* parse_to_param(char *buffer, char *end,
					struct to_body *to_b,
					int *returned_status,
					int multi)
{
	struct to_param *param;
	int status;
	int saved_status;
	char  *tmp;

	param=0;
	status=E_PARA_VALUE;
	saved_status=E_PARA_VALUE;
	for( tmp=buffer; tmp<end; tmp++)
	{
		switch(*tmp)
		{
			case ' ':
			case '\t':
				switch (status)
				{
					case TAG3:
						param->type=TAG_PARAM;
					case PARA_NAME:
					case TAG1:
					case TAG2:
						param->name.len = tmp-param->name.s;
						status = S_EQUAL;
						break;
					case PARA_VALUE_TOKEN:
						param->value.len = tmp-param->value.s;
						status = E_PARA_VALUE;
						add_param( param , to_b );
						break;
					case F_CRLF:
					case F_LF:
					case F_CR:
						/*previous=crlf and now =' '*/
						status=saved_status;
						break;
				}
				break;
			case '\n':
				switch (status)
				{
					case S_PARA_NAME:
					case S_EQUAL:
					case S_PARA_VALUE:
					case E_PARA_VALUE:
						saved_status=status;
						status=F_LF;
						break;
					case TAG3:
						param->type=TAG_PARAM;
					case PARA_NAME:
					case TAG1:
					case TAG2:
						param->name.len = tmp-param->name.s;
						saved_status = S_EQUAL;
						status = F_LF;
						break;
					case PARA_VALUE_TOKEN:
						param->value.len = tmp-param->value.s;
						saved_status = E_PARA_VALUE;
						status = F_LF;
						add_param( param , to_b );
						break;
					case F_CR:
						status=F_CRLF;
						break;
					case F_CRLF:
					case F_LF:
						status=saved_status;
						goto endofheader;
					default:
						goto parse_error;
				}
				break;
			case '\r':
				switch (status)
				{
					case S_PARA_NAME:
					case S_EQUAL:
					case S_PARA_VALUE:
					case E_PARA_VALUE:
						saved_status=status;
						status=F_CR;
						break;
					case TAG3:
						param->type=TAG_PARAM;
					case PARA_NAME:
					case TAG1:
					case TAG2:
						param->name.len = tmp-param->name.s;
						saved_status = S_EQUAL;
						status = F_CR;
						break;
					case PARA_VALUE_TOKEN:
						param->value.len = tmp-param->value.s;
						saved_status = E_PARA_VALUE;
						status = F_CR;
						add_param( param , to_b );
						break;
					case F_CRLF:
					case F_CR:
					case F_LF:
						status=saved_status;
						goto endofheader;
					default:
						goto parse_error;
				}
				break;
			case  0:
			case ',':
				switch (status)
				{
					case PARA_VALUE_QUOTED:
						break;
					case PARA_NAME:
						param->name.len = tmp-param->name.s;
					case S_EQUAL:
					case S_PARA_VALUE:
						if (param->type==TAG_PARAM)
							goto parse_error;
						param->value.s = tmp;
					case PARA_VALUE_TOKEN:
						status = E_PARA_VALUE;
						param->value.len = tmp-param->value.s;
						add_param( param , to_b );
					case E_PARA_VALUE:
						saved_status = status;
						if ( !multi && *tmp==',')
							goto parse_error;
						goto endofheader;
						break;
					default:
						goto parse_error;
				}
				break;
			case '\\':
				switch (status)
				{
					case PARA_VALUE_QUOTED:
						switch (*(tmp+1))
						{
							case '\r':
							case '\n':
								break;
							default:
								tmp++;
								break;
						}
						break;
					default:
						goto parse_error;
				}
				break;
			case '"':
				switch (status)
				{
					case S_PARA_VALUE:
						param->value.s = tmp+1;
						status = PARA_VALUE_QUOTED;
						break;
					case PARA_VALUE_QUOTED:
						param->value.len=tmp-param->value.s ;
						add_param( param , to_b );
						status = E_PARA_VALUE;
						break;
					case F_CRLF:
					case F_LF:
					case F_CR:
						/*previous=crlf and now !=' '*/
						goto endofheader;
					default:
						goto parse_error;
				}
				break;
			case ';' :
				switch (status)
				{
					case PARA_VALUE_QUOTED:
						break;
					case PARA_NAME:
						param->name.len = tmp-param->name.s;
					case S_EQUAL:
					case S_PARA_VALUE:
						if (param->type==TAG_PARAM)
							goto parse_error;
						param->value.s = tmp;
					case PARA_VALUE_TOKEN:
						param->value.len=tmp-param->value.s;
						add_param(param,to_b);
					case E_PARA_VALUE:
						param = (struct to_param*)
							pkg_malloc(sizeof(struct to_param));
						if (!param){
							LM_ERR("out of pkg memory\n" );
							goto error;
						}
						memset(param,0,sizeof(struct to_param));
						param->type=GENERAL_PARAM;
						status = S_PARA_NAME;
						break;
					case F_CRLF:
					case F_LF:
					case F_CR:
						/*previous=crlf and now !=' '*/
						goto endofheader;
					default:
						goto parse_error;
				}
				break;
			case 'T':
			case 't' :
				switch (status)
				{
					case PARA_VALUE_QUOTED:
					case PARA_VALUE_TOKEN:
					case PARA_NAME:
						break;
					case S_PARA_NAME:
						param->name.s = tmp;
						status = TAG1;
						break;
					case S_PARA_VALUE:
						param->value.s = tmp;
						status = PARA_VALUE_TOKEN;
						break;
					case TAG1:
					case TAG2:
					case TAG3:
						status = PARA_NAME;
						break;
					case F_CRLF:
					case F_LF:
					case F_CR:
						/*previous=crlf and now !=' '*/
						goto endofheader;
					default:
						goto parse_error;
				}
				break;
			case 'A':
			case 'a' :
				switch (status)
				{
					case PARA_VALUE_QUOTED:
					case PARA_VALUE_TOKEN:
					case PARA_NAME:
						break;
					case S_PARA_NAME:
						param->name.s = tmp;
						status = PARA_NAME;
						break;
					case S_PARA_VALUE:
						param->value.s = tmp;
						status = PARA_VALUE_TOKEN;
						break;
					case TAG1:
						status = TAG2;
						break;
					case TAG2:
					case TAG3:
						status = PARA_NAME;
						break;
					case F_CRLF:
					case F_LF:
					case F_CR:
						/*previous=crlf and now !=' '*/
						goto endofheader;
					default:
						goto parse_error;
				}
				break;
			case 'G':
			case 'g' :
				switch (status)
				{
					case PARA_VALUE_QUOTED:
					case PARA_VALUE_TOKEN:
					case PARA_NAME:
						break;
					case S_PARA_NAME:
						param->name.s = tmp;
						status = PARA_NAME;
						break;
					case S_PARA_VALUE:
						param->value.s = tmp;
						status = PARA_VALUE_TOKEN;
						break;
					case TAG1:
					case TAG3:
						status = PARA_NAME;
						break;
					case TAG2:
						status = TAG3;
						break;
					case F_CRLF:
					case F_LF:
					case F_CR:
						/*previous=crlf and now !=' '*/
						goto endofheader;
					default:
						goto parse_error;
				}
				break;
			case '=':
				switch (status)
				{
					case PARA_VALUE_QUOTED:
						break;
					case TAG3:
						param->type=TAG_PARAM;
					case PARA_NAME:
					case TAG1:
					case TAG2:
						param->name.len = tmp-param->name.s;
						status = S_PARA_VALUE;
						break;
					case S_EQUAL:
						status = S_PARA_VALUE;
						break;
					case F_CRLF:
					case F_LF:
					case F_CR:
						/*previous=crlf and now !=' '*/
						goto endofheader;
					default:
						goto parse_error;
				}
				break;
			default:
				switch (status)
				{
					case TAG1:
					case TAG2:
					case TAG3:
						status = PARA_NAME;
						break;
					case PARA_VALUE_TOKEN:
					case PARA_NAME:
					case PARA_VALUE_QUOTED:
						break;
					case S_PARA_NAME:
						param->name.s = tmp;
						status = PARA_NAME;
						break;
					case S_PARA_VALUE:
						param->value.s = tmp;
						status = PARA_VALUE_TOKEN;
						break;
					case F_CRLF:
					case F_LF:
					case F_CR:
						/*previous=crlf and now !=' '*/
						goto endofheader;
					default:
						LM_ERR("spitting out [%c] in status %d\n",*tmp,status );
						goto error;
				}
		}/*switch*/
	}/*for*/


endofheader:
	if (param) {
		if (saved_status==S_EQUAL||saved_status==S_PARA_VALUE) {
			saved_status = E_PARA_VALUE;
			param->value.s= 0;
			param->value.len=0;
			if (param->type==TAG_PARAM)
				goto parse_error;
			add_param(param, to_b);
		} else {
			pkg_free(param);
		}
	}
	*returned_status=saved_status;
	return tmp;

parse_error:
	LM_ERR("unexpected char [%c] in status %d: <<%.*s>> .\n",
		*tmp,status, (int)(tmp-buffer), ZSW(buffer));
error:
	if (param) pkg_free(param);
	free_to_params(to_b);
	to_b->error=PARSE_ERROR;
	*returned_status = status;
	return tmp;
}




static inline char* _parse_to(char* buffer, char *end, struct to_body *to_b,
																	int multi)
{
	int status;
	int saved_status;
	char  *tmp;
	char  *end_mark;
	struct to_body *first_b = to_b;

	status=START_TO;
	saved_status=START_TO;
	memset(to_b, 0, sizeof(struct to_body));
	to_b->error=PARSE_OK;
	end_mark=0;

	for( tmp=buffer; tmp<end; tmp++)
	{
		switch(*tmp)
		{
			case ' ':
			case '\t':
				switch (status)
				{
					case F_CRLF:
					case F_LF:
					case F_CR:
						/*previous=crlf and now =' '*/
						status=saved_status;
						break;
					case URI_ENCLOSED:
						to_b->uri.len = tmp - to_b->uri.s;
						status = E_URI_ENCLOSED;
						break;
					case URI_OR_TOKEN:
						status = MAYBE_URI_END;
						end_mark = tmp;
						break;
					case DISPLAY_TOKEN:
						end_mark = tmp;
						status = DISPLAY_TOKEN2;
						break;
				}
				break;
			case '\n':
				switch (status)
				{
					case URI_OR_TOKEN:
						end_mark = tmp;
						status = MAYBE_URI_END;
					case MAYBE_URI_END:
					case DISPLAY_TOKEN:
					case DISPLAY_TOKEN2:
					case E_DISPLAY_QUOTED:
					case END:
						saved_status=status;
						status=F_LF;
						break;
					case F_CR:
						status=F_CRLF;
						break;
					case F_CRLF:
					case F_LF:
						status=saved_status;
						goto endofheader;
					default:
						goto parse_error;
				}
				break;
			case '\r':
				switch (status)
				{
					case URI_OR_TOKEN:
						end_mark = tmp;
						status = MAYBE_URI_END;
						/* fall through */
					case MAYBE_URI_END:
					case DISPLAY_TOKEN:
					case DISPLAY_TOKEN2:
					case E_DISPLAY_QUOTED:
					case END:
						saved_status=status;
						status=F_CR;
						break;
					case F_CRLF:
					case F_CR:
					case F_LF:
						status=saved_status;
						goto endofheader;
					default:
						goto parse_error;
				}
				break;
			case 0:
				switch (status)
				{
					case URI_OR_TOKEN:
					case MAYBE_URI_END:
						to_b->uri.len = tmp - to_b->uri.s;
						/* fall through */
					case END:
						saved_status = status = END;
						goto endofheader;
					default:
						goto parse_error;
				}
				break;
			case ',':
				switch (status)
				{
					case DISPLAY_QUOTED:
					case URI_ENCLOSED:
						break;
					case URI_OR_TOKEN:
						/* the next transition cannot be determined here. The
						 * ',' maybe part of the username inside URI, or 
						 * it can be separator between 2 hdr parts. As this
						 * parsed is not URI aware (we do not actually parse
						 * the URI, but we simply skip it), we have no idea
						 * in which care we are..... For the moment, if the
						 * header is marked as single part, at least let's
						 * consider the ',' as part of the URI */
						if (multi==0)
							break;
					case MAYBE_URI_END:
						to_b->uri.len = tmp - to_b->uri.s;
						/* fall through */
					case END:
						if (multi==0)
							goto parse_error;
						to_b->next = (struct to_body*)
							pkg_malloc(sizeof(struct to_body));
						if (to_b->next==NULL) {
							LM_ERR("failed to allocate new TO body\n");
							goto error;
						}
						to_b = to_b->next;
						memset(to_b, 0, sizeof(struct to_body));
						to_b->error = PARSE_OK;
						saved_status = status = START_TO;
						end_mark=0;
						break;
					default:
						goto parse_error;
				}
				break;
			case '\\':
				switch (status)
				{
					case DISPLAY_QUOTED:
						tmp++; /* jump over next char */
						break;
					default:
						goto parse_error;
				}
				break;
			case '<':
				switch (status)
				{
					case START_TO:
						to_b->body.s=tmp;
						status = S_URI_ENCLOSED;
						break;
					case DISPLAY_QUOTED:
						break;
					case E_DISPLAY_QUOTED:
						status = S_URI_ENCLOSED;
						break;
					case URI_OR_TOKEN:
					case DISPLAY_TOKEN:
						end_mark = tmp;
						/* fall through */
					case DISPLAY_TOKEN2:
					case MAYBE_URI_END:
						to_b->display.len=end_mark-to_b->display.s;
						status = S_URI_ENCLOSED;
						break;
					case F_CRLF:
					case F_LF:
					case F_CR:
						/*previous=crlf and now !=' '*/
						goto endofheader;
					default:
						goto parse_error;
				}
				break;
			case '>':
				switch (status)
				{
					case DISPLAY_QUOTED:
						break;
					case URI_ENCLOSED:
						to_b->uri.len = tmp - to_b->uri.s;
						/* fall through */
					case E_URI_ENCLOSED:
						status = END;
						break;
					case F_CRLF:
					case F_LF:
					case F_CR:
						/*previous=crlf and now !=' '*/
						goto endofheader;
					default:
						goto parse_error;
				}
				break;
			case '"':
				switch (status)
				{
					case START_TO:
						to_b->body.s = tmp;
						to_b->display.s = tmp;
						status = DISPLAY_QUOTED;
						break;
					case DISPLAY_QUOTED:
						status = E_DISPLAY_QUOTED;
						to_b->display.len = tmp-to_b->display.s+1;
						break;
					case F_CRLF:
					case F_LF:
					case F_CR:
						/*previous=crlf and now !=' '*/
						goto endofheader;
					default:
						goto parse_error;
				}
				break;
			case ';' :
				switch (status)
				{
					case DISPLAY_QUOTED:
					case DISPLAY_TOKEN:
					case URI_ENCLOSED:
						break;
					case URI_OR_TOKEN:
						end_mark = tmp;
						/* fall through */
					case MAYBE_URI_END:
						to_b->uri.len = end_mark - to_b->uri.s;
						/* fall through */
					case END:
						to_b->body.len = tmp-to_b->body.s;
						tmp = parse_to_param(tmp,end,to_b,&saved_status,multi);
						if (to_b->error!=PARSE_ERROR && multi && *tmp==',') {
							/* continue with a new body instance */
							to_b->next = (struct to_body*)
								pkg_malloc(sizeof(struct to_body));
							if (to_b->next==NULL) {
								LM_ERR("failed to allocate new TO body\n");
								goto error;
							}
							to_b = to_b->next;
							memset(to_b, 0, sizeof(struct to_body));
							to_b->error=PARSE_OK;
							saved_status = status = START_TO;
							end_mark=0;
							break;
						} else {
							goto endofheader;
						}
					case F_CRLF:
					case F_LF:
					case F_CR:
						/*previous=crlf and now !=' '*/
						goto endofheader;
					default:
						goto parse_error;
				}
				break;
			default:
				switch (status)
				{
					case START_TO:
						to_b->uri.s = to_b->body.s = tmp;
						status = URI_OR_TOKEN;
						to_b->display.s=tmp;
						break;
					case S_URI_ENCLOSED:
						to_b->uri.s=tmp;
						status=URI_ENCLOSED;
						break;
					case MAYBE_URI_END:
					case DISPLAY_TOKEN2:
						status = DISPLAY_TOKEN;
					case DISPLAY_QUOTED:
					case DISPLAY_TOKEN:
					case URI_ENCLOSED:
					case URI_OR_TOKEN:
						break;
					case F_CRLF:
					case F_LF:
					case F_CR:
						/*previous=crlf and now !=' '*/
						goto endofheader;
					default:
						LM_DBG("spitting out [%c] in status %d\n",
						*tmp,status );
						goto error;
				}
		}/*char switch*/
	}/*for*/

endofheader:
	if (to_b->display.len==0) to_b->display.s=0;
	status=saved_status;
	LM_DBG("end of header reached, state=%d\n", status);
	/* check if error*/
	switch(status){
		case MAYBE_URI_END:
			to_b->uri.len = end_mark - to_b->uri.s;
		case END:
			to_b->body.len = tmp - to_b->body.s;
		case E_PARA_VALUE:
			break;
		default:
			LM_ERR("unexpected end of header in state %d\n", status);
			goto error;
	}

	LM_DBG("display={%.*s}, ruri={%.*s}\n",
		to_b->display.len, ZSW(to_b->display.s),
		to_b->uri.len, ZSW(to_b->uri.s));
	return tmp;

parse_error:
	LM_ERR("unexpected char [%c] in status %d: <<%.*s>> .\n",
		*tmp,status, (int)(tmp-buffer), buffer);
error:
	first_b->error=PARSE_ERROR;
	free_to_params(first_b);
	free_to(first_b->next);
	return tmp;

}


char* parse_to(char* buffer, char *end, struct to_body *to_b)
{
	return _parse_to( buffer, end, to_b, 0/*multi*/);
}


char* parse_multi_to(char* buffer, char *end, struct to_body *to_b)
{
	return _parse_to( buffer, end, to_b, 1/*multi*/);
}


/**
 *
 */
struct sip_uri *parse_to_uri(struct sip_msg *msg)
{
	struct to_body *tb = NULL;
	if(msg==NULL || msg->to==NULL || msg->to->parsed==NULL)
		return NULL;

	tb = get_to(msg);

	if(tb->parsed_uri.user.s!=NULL || tb->parsed_uri.host.s!=NULL)
		return &tb->parsed_uri;

	if (parse_uri(tb->uri.s, tb->uri.len , &tb->parsed_uri)<0)
	{
		LM_ERR("failed to parse To uri\n");
		memset(&tb->parsed_uri, 0, sizeof(struct sip_uri));
		set_err_info(OSER_EC_PARSER, OSER_EL_MEDIUM, "error parsing To uri");
		set_err_reply(400, "bad To uri");
		return NULL;
	}

	return &tb->parsed_uri;
}

int parse_to_header( struct sip_msg *msg)
{
	struct to_body* to_b;

	if ( !msg->to && ( parse_headers(msg,HDR_TO_F,0)==-1 || !msg->to)) {
		LM_ERR("bad msg or missing To header\n");
		goto error;
	}

	/* maybe the header is already parsed! */
	if (msg->to->parsed)
		return 0;

	/* bad luck! :-( - we have to parse it */
	/* first, get some memory */
	to_b = pkg_malloc(sizeof(struct to_body));
	if (to_b == 0) {
		LM_ERR("out of pkg_memory\n");
		goto error;
	}

	/* now parse it!! */
	memset(to_b, 0, sizeof(struct to_body));
	parse_to(msg->to->body.s,msg->to->body.s+msg->to->body.len+1,to_b);
	if (to_b->error == PARSE_ERROR) {
		LM_ERR("bad to header\n");
		pkg_free(to_b);
		set_err_info(OSER_EC_PARSER, OSER_EL_MEDIUM,
			"error parsing too header");
		set_err_reply(400, "bad header");
		goto error;
	}

	msg->to->parsed = to_b;

	return 0;
error:
	return -1;
}
