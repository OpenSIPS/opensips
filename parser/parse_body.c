/**
 * Copyright (C) 2009 Voice Sistem SRL
 * Copyright (C) 2016 OpenSIPS Solutions
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
 */

#include "../mem/mem.h"
#include "../ut.h"
#include "parse_body.h"
#include "parse_content.h"
#include "parse_hname2.h"
#include "parser_f.h"
#include "sdp/sdp_helpr_funcs.h"

#define parse_hname(_b,_e,_h) parse_hname2((_b),(_e),(_h))

static struct body_part * new_part(void)
{
	struct body_part * temp;

	temp = pkg_malloc(sizeof (struct body_part));

	if (temp == 0)
	{
		LM_ERR("Unable to allocate memory\n");
		return 0;
	}
	memset(temp, 0, sizeof (struct body_part));

	return temp;
};


static char* get_hdr_field_unparsed(char* buf, char* end,struct hdr_field* hdr)
{

	char* tmp;
	char *match;

	if ((*buf) == '\n' || (*buf) == '\r')
	{
		/* double crlf or lflf or crcr */
		LM_DBG("found end of header\n");
		hdr->type = HDR_EOH_T;
		return buf;
	}

	LM_DBG("Trying to get header:[%.*s]\n", (int)(end - buf), buf);

	tmp = parse_hname(buf, end, hdr);
	if (hdr->type == HDR_ERROR_T)
	{
		LM_ERR("bad header\n");
		goto error_bad_hdr;
	}

	/* eliminate leading whitespace */
	tmp = eat_lws_end(tmp, end);
	if (tmp >= end)
	{
		LM_ERR("hf empty\n");
		goto error_bad_hdr;
	}

	/* just skip over it */
	hdr->body.s = tmp;
	/* find end of header */
	/* find lf */
	do
	{
		match = q_memchr(tmp, '\n', end - tmp);
		if (match)
		{
			match++;
		} else
		{
			LM_ERR("bad body for <%s>(%d)\n", hdr->name.s, hdr->type);
			tmp = end;
			goto error_bad_hdr;
		}
		tmp = match;
	} while (match < end && ((*match == ' ') || (*match == '\t')));
	tmp = match;
	hdr->body.len = match - hdr->body.s;


	/* jku: if \r covered by current length, shrink it */
	trim_r(hdr->body);
	hdr->len = tmp - hdr->name.s;
	return tmp;

error_bad_hdr:
	LM_ERR("Unable to parse headers\n");

	hdr->type = HDR_ERROR_T;
	hdr->len = tmp - hdr->name.s;
	return tmp;
}


static char *find_line_delimiter(char* p, char* plimit, str delimiter)
{
	static char delimiterhead[3] = "--";
	char *cp, *cp1;

	/* Iterate through body */
	cp = p;
	for (;;) {
		if (cp >= plimit)
			return NULL;
		for(;;) {
			cp1 = l_memmem(cp, delimiterhead, plimit-cp, 2);
			if (cp1 == NULL)
				return NULL;
			/* We matched '--',
			 * now let's match the boundary delimiter */
			if (strncmp(cp1+2, delimiter.s, delimiter.len) == 0)
				break;
			else
				cp = cp1 + 2 + delimiter.len;
			if (cp >= plimit)
				return NULL;
		}
		if (cp1[-1] == '\n' || cp1[-1] == '\r')
			return cp1;
		if (plimit - cp1 < 2 + delimiter.len)
			return NULL;
		cp = cp1 + 2 + delimiter.len;
	}
}


static int parse_single_part(struct body_part *part, char * start, char * end)
{
	char * tmp, *body_end, * mime_end;
	unsigned int mime;

	part->all_data.s = start;
	part->all_data.len = end - start;
	part->mime = -1;

	LM_DBG("parsing part:[%.*s]\n",(int)(end-start),start);

	tmp = start;
	while (1)
	{
		struct hdr_field hd;
		memset(&hd, 0, sizeof (struct hdr_field));

		tmp = get_hdr_field_unparsed(tmp, end, &hd);
		if (tmp == NULL || hd.type == HDR_ERROR_T)
		{
			LM_ERR("Error parsing body part header\n");
			return -1;
		}

		if (hd.type == HDR_CONTENTTYPE_T)
		{
			body_end = hd.body.s + hd.body.len;
			mime_end = decode_mime_type(hd.body.s, body_end, &mime, NULL);

			if (mime_end == NULL)
			{
				LM_ERR("Error parsing MIME\n");
				return -1;
			}
			part->mime = mime;
		}

		if (hd.type == HDR_EOH_T)
		{
			/* remove the last \n\r from the body */
			tmp += 2;
			break;
		}
	}

	if (part->mime < 0)
		part->mime = ((TYPE_TEXT) << 16) + SUBTYPE_PLAIN;

	part->body.s = tmp;
	part->body.len = end - part->body.s;

	return 0;
};


inline struct sip_msg_body* parse_sip_body(struct sip_msg * msg)
{
	char *start, *end;
	int type = 0;
	struct body_part *part, *last;
	str delimiter, body;

	/* is body already parsed ? */
	if (msg->body)
		return msg->body;

	if ( get_body(msg,&body)!=0 || body.len==0)
		return 0;

	type = parse_content_type_hdr(msg);
	if (type <= 0)
		return 0;

	msg->body = pkg_malloc(sizeof (struct sip_msg_body));
	if (msg->body == 0)
	{
		LM_ERR("Unable to allocate memory\n");
		return 0;
	}
	memset(msg->body, 0, sizeof (struct sip_msg_body));

	msg->body->boundary = ((content_t *) msg->content_type->parsed)->boundary;

	if ((type >> 16) == TYPE_MULTIPART)
	{
		delimiter = ((content_t*) msg->content_type->parsed)->boundary;

		LM_DBG("Starting parsing with boundary = [%.*s]\n",
			delimiter.len, delimiter.s);

		start = find_line_delimiter( body.s, body.s + body.len, delimiter);
		if (start == NULL) {
			LM_ERR("Unable to parse multipart type:"
				" malformed - missing start delimiters\n");
			return 0;
		}

		/* mark as first part (no previous one) */
		last = NULL;

		while (1)
		{
			end = find_line_delimiter(start + 1, body.s + body.len,
				delimiter);
			if (end == NULL)
				break;

			/* is it the first part ? */
			if (last==NULL) {
				part = &msg->body->first;
			} else {
				if ( (part=new_part()) == NULL )
					return 0;
			}

			/* add 4 to delimiter 2 for "--" and 2 for "\n\r" */
			/* subtract 2 from end for last "\n\r" */
			if (parse_single_part(part, start + delimiter.len + 4, end-2)!=0) {
				LM_ERR("Unable to parse part:[%.*s]\n",(int)(end-start),start);
				return 0;
			}

			/* set the parsing for the next cycle */
			start = end;

			/* link the new part; note that the first part is part of 
			 * the body structure, no need to be linked */
			if (last) {
				last->next = part;
				last = part;
			}
			msg->body->part_count++;

		}

	} else {

		/* only one part in the body */
		part = &msg->body->first;

		part->mime = type;
		part->body = body;
		part->all_data = body;
		msg->body->part_count++;
	}

	return msg->body;

};

void free_sip_body(struct sip_msg_body *body)
{
	struct body_part * p, *tmp;

	if (body) {
		/* jump the first part, does not need to be freed */
		p = body->first.next;
		while(p) {
			tmp =  p;
			p = p->next;
			/* any need to free some parsed format of the part ? */
			if (tmp->parsed && tmp->free_parsed_f)
				tmp->free_parsed_f( tmp->parsed );
			pkg_free(tmp);
		}
		pkg_free(body);
	}
}

