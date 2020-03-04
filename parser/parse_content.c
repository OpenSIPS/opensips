/*
 * Copyright (C) 2001-2003 FhG Fokus
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
 * 2003-08-04 parse_content_type_hdr separates type from subtype inside
 * the mime type (bogdan)
 * 2003-08-04 CPL subtype added (bogdan)
 * 2003-08-05 parse_accept_hdr function added (bogdan)
 * 2011-06-22 ISUP subtype added (roger)
 */


#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include "../mem/mem.h"
#include "../dprint.h"
#include "../str.h"
#include "../ut.h"
#include "../errinfo.h"
#include "parse_content.h"


#define is_mime_char(_c_) \
	(isalnum((int)_c_) || (_c_)=='-' || (_c_)=='+' || (_c_)=='.')
#define is_char_equal(_c_,_cs_) \
	( (isalpha((int)_c_)?(((_c_)|0x20)==(_cs_)):((_c_)==(_cs_)))==1 )


/*
 * Node of the type's tree; this tree contains all the known types;
 */
typedef struct type_node_s {
	char c;                      /* char contained by this node */
	unsigned char final;         /* says what mime type/subtype was detected
	                              * if string ends at this node */
	unsigned char nr_sons;       /* the number of sub-nodes */
	int next;                    /* the next sibling node */
}type_node_t;


static type_node_t type_tree[] = {
	{'t',TYPE_UNKNOWN,1,4}, /* 0 */
		{'e',TYPE_UNKNOWN,1,-1},
			{'x',TYPE_UNKNOWN,1,-1},
				{'t',TYPE_TEXT,0,-1},
	{'m',TYPE_UNKNOWN,2,19}, /* 4 */
		{'e',TYPE_UNKNOWN,1,11}, /* 5 */
			{'s',TYPE_UNKNOWN,1,-1},
				{'s',TYPE_UNKNOWN,1,-1},
					{'a',TYPE_UNKNOWN,1,-1},
						{'g',TYPE_UNKNOWN,1,-1},
							{'e',TYPE_MESSAGE,0,-1},
		{'u',TYPE_UNKNOWN,1,-1}, /* 11 */
			{'l',TYPE_UNKNOWN,1,-1},
				{'t',TYPE_UNKNOWN,1,-1},
					{'i',TYPE_UNKNOWN,1,-1},
						{'p',TYPE_UNKNOWN,1,-1},
							{'a',TYPE_UNKNOWN,1,-1},
								{'r',TYPE_UNKNOWN,1,-1},
									{'t',TYPE_MULTIPART,0,-1},
	{'a',TYPE_UNKNOWN,1,-1}, /* 19 */
		{'p',TYPE_UNKNOWN,1,-1},
			{'p',TYPE_UNKNOWN,1,-1},
				{'l',TYPE_UNKNOWN,1,-1},
					{'i',TYPE_UNKNOWN,1,-1},
						{'c',TYPE_UNKNOWN,1,-1},
							{'a',TYPE_UNKNOWN,1,-1},
								{'t',TYPE_UNKNOWN,1,-1},
									{'i',TYPE_UNKNOWN,1,-1},
										{'o',TYPE_UNKNOWN,1,-1},
											{'n',TYPE_APPLICATION,0,-1},
	};


static type_node_t subtype_tree[] = {
        {'p',SUBTYPE_UNKNOWN,2,12},  /* 0 */
		{'l',SUBTYPE_UNKNOWN,1,5},
			{'a',SUBTYPE_UNKNOWN,1,-1},
				{'i',SUBTYPE_UNKNOWN,1,-1},
					{'n',SUBTYPE_PLAIN,0,-1},
		{'i',SUBTYPE_UNKNOWN,1,-1}, /* 5 */
			{'d',SUBTYPE_UNKNOWN,1,-1},
				{'f',SUBTYPE_UNKNOWN,1,-1},
					{'+',SUBTYPE_UNKNOWN,1,-1},
						{'x',SUBTYPE_UNKNOWN,1,-1},
							{'m',SUBTYPE_UNKNOWN,1,-1},
								{'l',SUBTYPE_PIDFXML,0,-1},
	{'s',SUBTYPE_UNKNOWN,2,36}, /* 12 */
		{'d',SUBTYPE_UNKNOWN,1,15},
			{'p',SUBTYPE_SDP,0,-1},
	        {'i',SUBTYPE_UNKNOWN,1,-1},  /* 15 */
	                {'m',SUBTYPE_UNKNOWN,1,-1},
	                    {'p',SUBTYPE_UNKNOWN,1,-1},
	                        {'l',SUBTYPE_UNKNOWN,1,-1},
	                            {'e',SUBTYPE_UNKNOWN,1,-1},
	                                {'-',SUBTYPE_UNKNOWN,1,-1},
	                                    {'m',SUBTYPE_UNKNOWN,1,-1},
	                                        {'e',SUBTYPE_UNKNOWN,1,-1},
	                                            {'s',SUBTYPE_UNKNOWN,1,-1},
	                                                {'s',SUBTYPE_UNKNOWN,1,-1},
	                                                    {'a',SUBTYPE_UNKNOWN,1,-1},
	                                                        {'g',SUBTYPE_UNKNOWN,1,-1},
	                                                            {'e',SUBTYPE_UNKNOWN,1,-1},
	                                                                {'-',SUBTYPE_UNKNOWN,1,-1},
	                                                                    {'s',SUBTYPE_UNKNOWN,1,-1},
	                                                                        {'u',SUBTYPE_UNKNOWN,1,-1},
	                                                                            {'m',SUBTYPE_UNKNOWN,1,-1},
	                                                                                {'m',SUBTYPE_UNKNOWN,1,-1},
	                                                                                    {'a',SUBTYPE_UNKNOWN,1,-1},
	                                                                                        {'r',SUBTYPE_UNKNOWN,1,-1},
	                                                                                            {'y',SUBTYPE_SMS,0,-1},
	{'c',SUBTYPE_UNKNOWN,1,45}, /* 36 */
		{'p',SUBTYPE_UNKNOWN,2,-1},
			{'i',SUBTYPE_UNKNOWN,1,40},
				{'m',SUBTYPE_CPIM,0,-1},
	                {'l',SUBTYPE_UNKNOWN,1,-1}, /* 40 */
				{'+',SUBTYPE_UNKNOWN,1,-1},
					{'x',SUBTYPE_UNKNOWN,1,-1},
						{'m',SUBTYPE_UNKNOWN,1,-1},
							{'l',SUBTYPE_CPLXML,0,-1},
	{'r',SUBTYPE_UNKNOWN,2,59}, /* 45 */
		{'l',SUBTYPE_UNKNOWN,1,53},
			{'m',SUBTYPE_UNKNOWN,1,-1},
				{'i',SUBTYPE_UNKNOWN,1,-1},
					{'+',SUBTYPE_UNKNOWN,1,-1},
						{'x',SUBTYPE_UNKNOWN,1,-1},
							{'m',SUBTYPE_UNKNOWN,1,-1},
								{'l',SUBTYPE_RLMIXML,0,-1},
		{'e',SUBTYPE_UNKNOWN,1,-1}, /* 53 */
			{'l',SUBTYPE_UNKNOWN,1,-1},
				{'a',SUBTYPE_UNKNOWN,1,-1},
					{'t',SUBTYPE_UNKNOWN,1,-1},
						{'e',SUBTYPE_UNKNOWN,1,-1},
							{'d',SUBTYPE_RELATED,0,-1},
	{'l',SUBTYPE_UNKNOWN,1,68}, /* 59 */
		{'p',SUBTYPE_UNKNOWN,1,-1},
			{'i',SUBTYPE_UNKNOWN,1,-1},
				{'d',SUBTYPE_UNKNOWN,1,-1},
					{'f',SUBTYPE_UNKNOWN,1,-1},
						{'+',SUBTYPE_UNKNOWN,1,-1},
							{'x',SUBTYPE_UNKNOWN,1,-1},
								{'m',SUBTYPE_UNKNOWN,1,-1},
									{'l',SUBTYPE_LPIDFXML,0,-1},
	{'w',SUBTYPE_UNKNOWN,1,83}, /* 68 */
		{'a',SUBTYPE_UNKNOWN,1,-1},
			{'t',SUBTYPE_UNKNOWN,1,-1},
				{'c',SUBTYPE_UNKNOWN,1,-1},
					{'h',SUBTYPE_UNKNOWN,1,-1},
						{'e',SUBTYPE_UNKNOWN,1,-1},
							{'r',SUBTYPE_UNKNOWN,1,-1},
								{'i',SUBTYPE_UNKNOWN,1,-1},
									{'n',SUBTYPE_UNKNOWN,1,-1},
										{'f',SUBTYPE_UNKNOWN,1,-1},
											{'o',SUBTYPE_UNKNOWN,1,-1},
												{'+',SUBTYPE_UNKNOWN,1,-1},
													{'x',SUBTYPE_UNKNOWN,1,-1},
														{'m',SUBTYPE_UNKNOWN,1,-1},
															{'l',SUBTYPE_WATCHERINFOXML,0,-1},
	{'x',SUBTYPE_UNKNOWN,2,105}, /* 83 */
		{'p',SUBTYPE_UNKNOWN,1,92},
			{'i',SUBTYPE_UNKNOWN,1,-1},
				{'d',SUBTYPE_UNKNOWN,1,-1},
					{'f',SUBTYPE_UNKNOWN,1,-1},
						{'+',SUBTYPE_UNKNOWN,1,-1},
							{'x',SUBTYPE_UNKNOWN,1,-1},
								{'m',SUBTYPE_UNKNOWN,1,-1},
									{'l',SUBTYPE_XPIDFXML,0,-1},
		{'m',SUBTYPE_UNKNOWN,1,-1}, /* 92 */
			{'l',SUBTYPE_UNKNOWN,1,-1},
				{'+',SUBTYPE_UNKNOWN,1,-1},
					{'m',SUBTYPE_UNKNOWN,1,-1},
						{'s',SUBTYPE_UNKNOWN,1,-1},
							{'r',SUBTYPE_UNKNOWN,1,-1},
								{'t',SUBTYPE_UNKNOWN,1,-1},
									{'c',SUBTYPE_UNKNOWN,1,-1},
										{'.',SUBTYPE_UNKNOWN,1,-1},
											{'p',SUBTYPE_UNKNOWN,1,-1},
												{'i',SUBTYPE_UNKNOWN,1,-1},
													{'d',SUBTYPE_UNKNOWN,1,-1},
														{'f',SUBTYPE_XML_MSRTC_PIDF,0,-1},
	{'e',SUBTYPE_UNKNOWN,1,118}, /* 105 */
		{'x',SUBTYPE_UNKNOWN,1,-1},
			{'t',SUBTYPE_UNKNOWN,1,-1},
				{'e',SUBTYPE_UNKNOWN,1,-1},
					{'r',SUBTYPE_UNKNOWN,1,-1},
						{'n',SUBTYPE_UNKNOWN,1,-1},
							{'a',SUBTYPE_UNKNOWN,1,-1},
								{'l',SUBTYPE_UNKNOWN,1,-1},
									{'-',SUBTYPE_UNKNOWN,1,-1},
										{'b',SUBTYPE_UNKNOWN,1,-1},
											{'o',SUBTYPE_UNKNOWN,1,-1},
												{'d',SUBTYPE_UNKNOWN,1,-1},
													{'y',SUBTYPE_EXTERNAL_BODY,0,-1},
	{'m',SUBTYPE_UNKNOWN,1,123}, /* 118 */
	         {'i',SUBTYPE_UNKNOWN,1,-1},
			{'x',SUBTYPE_UNKNOWN,1,-1},
				{'e',SUBTYPE_UNKNOWN,1,-1},
					{'d',SUBTYPE_MIXED,0,-1},
	{'i',SUBTYPE_UNKNOWN,1,-1}, /* 123 */
		{'s',SUBTYPE_UNKNOWN,1,-1},
			{'u',SUBTYPE_UNKNOWN,1,-1},
				{'p',SUBTYPE_ISUP,0,-1},

        };
char str_contenttype[50];



char* parse_content_length( char* buffer, char* end, int* length)
{
	int number;
	char *p;
	int  size;

	p = buffer;
	/* search the beginning of the number */
	while ( p<end && (*p==' ' || *p=='\t' || (*p=='\r' && *(p+1)=='\n') ||
	(*p=='\n' && (*(p+1)==' '||*(p+1)=='\t')) ))
		p++;
	if (p==end)
		goto error;
	/* parse the number */
	size = 0;
	number = 0;
	while (p<end && *p>='0' && *p<='9') {
		number = number*10 + (*p)-'0';
		if (number<0) {
			LM_ERR("number overflow at pos %d in len number [%.*s]\n",
				(int)(p-buffer),(int)(end-buffer), buffer);
			return 0;
		}
		size ++;
		p++;
	}
	if (p==end || size==0)
		goto error;
	/* now we should have only spaces at the end */
	while ( p<end && (*p==' ' || *p=='\t' ||
	(*p=='\n' && (*(p+1)==' '||*(p+1)=='\t')) ))
		p++;
	if (p==end)
		goto error;
	/* the header ends proper? */
	if ( (*(p++)!='\n') && (*(p-1)!='\r' || *(p++)!='\n' ) )
		goto error;

	*length = number;
	return p;
error:
	LM_ERR("parse error near char [%d][%c]\n",*p,*p);
	return 0;
}



char* decode_mime_type(char *start, char *end, unsigned int *mime_type, content_t * con)
{
	int node;
	char *mark;
	char *p;

	p = start;

	LM_DBG("Decoding MIME type for:[%.*s]\n",(int)(end-start),start);

	/* search the beginning of the type */
	while ( p<end && (*p==' ' || *p=='\t' || (*p=='\r' && *(p+1)=='\n') ||
	(*p=='\n' && (*(p+1)==' '||*(p+1)=='\t')) ))
		p++;
	if (p==end)
		goto error;

	/* parse the type */
	if (*p=='*') {
		*mime_type = TYPE_ALL<<16;
		p++;
	} else {
		node = 0;
		mark = p;
		while (p<end && is_mime_char(*p)  ) {
			while ( node!=-1 && !is_char_equal(*p,type_tree[node].c) ){
				node = type_tree[node].next;
			}
			if (node!=-1 && type_tree[node].nr_sons)
				node++;
			p++;
		}
		if (p==end || mark==p)
			goto error;
		if (node!=-1)
			*mime_type = type_tree[node].final<<16;
		else
			*mime_type = TYPE_UNKNOWN<<16;
	}

	/* search the '/' separator */
	while ( p<end && (*p==' ' || *p=='\t' ||
	(*p=='\n' && (*(p+1)==' '||*(p+1)=='\t')) ))
		p++;
	if ( p==end || *(p++)!='/')
		goto error;

	/* search the beginning of the sub-type */
	while ( p<end && (*p==' ' || *p=='\t' ||
	(*p=='\n' && (*(p+1)==' '||*(p+1)=='\t')) ))
		p++;
	if (p==end)
		goto error;

	/* parse the sub-type */
	if (*p=='*') {
		*mime_type |= SUBTYPE_ALL;
		p++;
	} else {
		node = 0;
		mark = p;
		while (p<end && (is_mime_char(*p) || *p == '_')) {
			while(node!=-1 && !is_char_equal(*p,subtype_tree[node].c) )
				node = subtype_tree[node].next;
			if (node!=-1 && subtype_tree[node].nr_sons)
				node++;
			p++;
		}
		if (p==mark)
			goto error;
		if (node!=-1)
			*mime_type |= subtype_tree[node].final;
		else
			*mime_type |= SUBTYPE_UNKNOWN;
	}

	/* now its possible to have some spaces */
	while ( p<end && (*p==' ' || *p=='\t' ||
	(*p=='\n' && (*(p+1)==' '||*(p+1)=='\t')) ))
		p++;

	/* if there are params, ignore them!! -> eat everything to
	 * the end or to the first ',' */
	if ( p<end && *p==';' )
	{
		if( con == NULL)
			for(p++; p<end && *p!=','; p++);
		else
		{
			str params_str;
			param_hooks_t phooks;
			param_t * cur;

			params_str.s = p;
			params_str.len = end - p ;

			if (parse_params(&params_str, CLASS_ANY, &phooks, &con->params) < 0)
				goto error;

			p = params_str.s;

			cur = con->params;

			while(cur)
			{
				if( cur->name.len == 8 && !strncasecmp(cur->name.s,"boundary",cur->name.len ) )
					con->boundary = cur->body;

				if( cur->name.len == 5 && !strncasecmp(cur->name.s,"start",cur->name.len ) )
					con->start = cur->body;

				cur = cur ->next;
			}

		}
	}

	/* is this the correct end? */
	if (p!=end && *p!=',' )
		goto error;

	/* check the format of the decoded mime */
	if ((*mime_type)>>16==TYPE_ALL && ((*mime_type)&0x00ff)!=SUBTYPE_ALL) {
		LM_ERR("invalid mime format found "
			" <*/submime> in [%.*s]!!\n", (int)(end-start),start);
		return 0;
	}

	return p;
error:
	LM_ERR("parse error near in [%.*s] char"
		"[%d][%c] offset=%d\n", (int)(end-start),start,*p,*p,(int)(p-start));
	return 0;
}



/* returns: > 0 mime found
 *          = 0 hdr not found
 *          =-1 error */
int parse_content_type_hdr( struct sip_msg *msg )
{
	char *end;
	char *ret;
	unsigned int  mime;
	content_t * rez;

	/* is the header already found? */
	if ( msg->content_type==0 ) {
		/* if not, found it */
		if ( parse_headers(msg, HDR_CONTENTTYPE_F, 0)==-1)
			goto error;
		if ( msg->content_type==0 ) {
			LM_DBG("missing Content-Type header\n");
			return 0;
		}
	}

	/* maybe the header is already parsed! */
	if ( msg->content_type->parsed!=0)
		return get_content_type(msg);

	rez = (content_t*) pkg_malloc(sizeof (content_t));
	if (rez == NULL)
	{
		LM_ERR("Unable to allocate memory\n");
		goto error;
	}
	memset(rez, 0, sizeof (content_t));


	/* it seams we have to parse it! :-( */
	end = msg->content_type->body.s + msg->content_type->body.len;
	ret = decode_mime_type(msg->content_type->body.s, end , &mime, rez);
	if (ret==0)
		goto parse_error;
	if (ret!=end) {
		LM_ERR("the header CONTENT_TYPE contains "
			"more then one mime type :-(!\n");
		goto parse_error;
	}
	if ((mime&0x00ff)==SUBTYPE_ALL || (mime>>16)==TYPE_ALL) {
		LM_ERR("invalid mime with wildcard '*' in Content-Type hdr!\n");
		goto parse_error;
	}


	rez->type = mime;
	msg->content_type->parsed = rez;
	return mime;

parse_error:
	pkg_free(rez);
	set_err_info(OSER_EC_PARSER, OSER_EL_MEDIUM,
		"error parsing CT-TYPE header");
	set_err_reply(400, "bad headers");

error:
	return -1;
}



/* returns: > 0 ok
 *          = 0 hdr not found
 *          = -1 error */
int parse_accept_hdr( struct sip_msg *msg )
{
	static unsigned int mimes[MAX_MIMES_NR];
	int nr_mimes;
	unsigned int mime;
	char *end;
	char *ret;

	/* is the header already found? */
	if ( msg->accept==0 ) {
		/* if not, found it */
		if ( parse_headers(msg, HDR_ACCEPT_F, 0)==-1)
			goto error;
		if ( msg->accept==0 ) {
			LM_DBG("missing Accept header\n");
			return 0;
		}
	}

	/* maybe the header is already parsed! */
	if ( msg->accept->parsed!=0)
		return 1;

	/* it seams we have to parse it! :-( */
	ret = msg->accept->body.s;
	end = ret + msg->accept->body.len;
	nr_mimes = 0;
	while (1){
		ret = decode_mime_type(ret, end , &mime, NULL);
		if (ret==0)
			goto parse_error;
		/* a new mime was found  -> put it into array */
		if (nr_mimes==MAX_MIMES_NR) {
			LM_ERR("accept hdr contains more than"
				" %d mime type -> buffer overflow!!\n",MAX_MIMES_NR);
			goto error;
		}
		mimes[nr_mimes++] = mime;
		/* is another mime following? */
		if (ret==end )
			break;
		/* parse the mime separator ',' */
		if (*ret!=',' || ret+1==end) {
			LM_ERR("parse error between mimes at "
				"char <%x> (offset=%d) in <%.*s>!\n",
				*ret, (int)(ret-msg->accept->body.s),
				msg->accept->body.len, msg->accept->body.s);
			goto parse_error;
		}
		/* skip the ',' */
		ret++;
	}

	/* copy and link the mime buffer into the message */
	msg->accept->parsed = (void*)pkg_malloc((nr_mimes+1)*sizeof(int));
	if (msg->accept->parsed==0) {
		LM_ERR("no more pkg memory\n");
		goto error;
	}
	memcpy(msg->accept->parsed,mimes,nr_mimes*sizeof(int));
	/* make the buffer null terminated */
	((int*)msg->accept->parsed)[nr_mimes] = 0;

	return 1;

parse_error:
	set_err_info(OSER_EC_PARSER, OSER_EL_MEDIUM,
		"error parsing ACCEPT header");
	set_err_reply(400, "bad headers");
error:
	return -1;
}

void free_contenttype(content_t ** con)
{

	if (*con)
	{
		if((*con)->params)
			free_params((*con)->params);
		pkg_free(*con);
	}
	*con = 0;
}

char* convert_mime2string_CT(int contenttype)
{
	#define SET_TYPE_PTRS(_type_) \
		do { \
			subtype_start = type_start + sizeof(_type_) - 1; \
			memcpy(type_start, _type_, sizeof(_type_) - 1); \
		} while(0);

	#define SET_SUBTYPE_PTR(_subtype_) memcpy(subtype_start, _subtype_, sizeof(_subtype_))

	/* last 16 bits */
	int type = contenttype >> 16;
	/* only first 16 bits */
	int subtype = contenttype & (0xFF);
	char* type_start;
	char* subtype_start;

	memset(str_contenttype, 0 , sizeof(str_contenttype));
	type_start = str_contenttype;

	switch (type) {
		case TYPE_TEXT:
			SET_TYPE_PTRS("text/");
			break;
		case TYPE_MESSAGE:
			SET_TYPE_PTRS("message/");
			break;
		case TYPE_APPLICATION:
			SET_TYPE_PTRS("application/");
			break;
		case TYPE_MULTIPART:
			SET_TYPE_PTRS("multipart/");
			break;
		case TYPE_ALL:
			SET_TYPE_PTRS("*/");
			break;
		case TYPE_UNKNOWN:
			SET_TYPE_PTRS("unknown/");
			break;
		default:
			LM_ERR("invalid type\n");
			return 0;
	}

	switch (subtype) {
		case SUBTYPE_PLAIN:
			SET_SUBTYPE_PTR("plain");
			break;
		case SUBTYPE_CPIM:
			SET_SUBTYPE_PTR("cpim");
			break;
		case SUBTYPE_SDP:
			SET_SUBTYPE_PTR("sdp");
			break;
		case SUBTYPE_CPLXML:
			SET_SUBTYPE_PTR("cplxml");
			break;
		case SUBTYPE_PIDFXML:
			SET_SUBTYPE_PTR("pidfxml");
			break;
		case SUBTYPE_RLMIXML:
			SET_SUBTYPE_PTR("rlmixml");
			break;
		case SUBTYPE_RELATED:
			SET_SUBTYPE_PTR("related");
			break;
		case SUBTYPE_LPIDFXML:
			SET_SUBTYPE_PTR("lpidfxml");
			break;
		case SUBTYPE_XPIDFXML:
			SET_SUBTYPE_PTR("xpidfxml");
			break;
		case SUBTYPE_WATCHERINFOXML:
			SET_SUBTYPE_PTR("watcherinfoxml");
			break;
		case SUBTYPE_EXTERNAL_BODY:
			SET_SUBTYPE_PTR("external_body");
			break;
		case SUBTYPE_XML_MSRTC_PIDF:
			SET_SUBTYPE_PTR("xmlmsrtcpidf");
			break;
		case SUBTYPE_SMS:
			SET_SUBTYPE_PTR("sms");
			break;
		case SUBTYPE_MIXED:
			SET_SUBTYPE_PTR("mixed");
			break;
		case SUBTYPE_ISUP:
			SET_SUBTYPE_PTR("isup");
			break;
		case SUBTYPE_ALL:
			SET_SUBTYPE_PTR("*");
			break;
		case SUBTYPE_UNKNOWN:
			SET_SUBTYPE_PTR("unknown");
			break;
		default:
			LM_ERR("invalid subtype\n");
			return 0;
	}

	return str_contenttype;

#undef SET_TYPE_PTRS
#undef SET_SUBTYPE_PTR
}



