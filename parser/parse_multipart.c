/**
 * $Id$
 *
 * Copyright (C) 2009 Voice Sistem SRL
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "../mem/mem.h"
#include "msg_parser.h"
#include "parse_content.h"
#include "parse_hname2.h"
#include "parser_f.h"
#include "../ut.h"
#include "sdp/sdp_helpr_funcs.h"

#define parse_hname(_b,_e,_h) parse_hname2((_b),(_e),(_h))

struct part * new_part(void)
{
	struct part * temp;

	temp = pkg_malloc(sizeof (struct part));

	if (temp == 0)
	{
		LM_ERR("Unable to allocate memory\n");
		return 0;
	}
	memset(temp, 0, sizeof (struct part));

	return temp;
};

char* get_hdr_field_unparsed(char* buf, char* end, struct hdr_field* hdr)
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

struct part * parse_single_part(char * start, char * end)
{
	struct part * ret;
	char * tmp, *body_end, * mime_end;
	unsigned int mime;


	if ((ret = new_part()) == 0)
		return 0;


	ret->all_data.s = start;
	ret->all_data.len = end - start;
	ret->content_type = -1;

	LM_DBG("parsing part:[%.*s]\n",(int)(end-start),start);

	tmp = start;
	while (1)
	{
		struct hdr_field hd;
		memset(&hd, 0, sizeof (struct hdr_field));

		tmp = get_hdr_field_unparsed(tmp, end, &hd);
		if (tmp == NULL || hd.type == HDR_ERROR_T)
		{
			LM_ERR("Error parsing header\n");
			return 0;
		}


		if (hd.type == HDR_CONTENTTYPE_T)
		{
			body_end = hd.body.s + hd.body.len;
			mime_end = decode_mime_type(hd.body.s, body_end, &mime, NULL);

			if (mime_end == NULL)
			{
				LM_ERR("Error parsing MIME\n");
				return 0;
			}
			ret->content_type = mime;
		}

		if (hd.type == HDR_EOH_T)
		{
			/* remove the last \n\r from the body */
			tmp += 2;
			break;
		}
	}

	if (ret->content_type < 0)
		ret->content_type = ((TYPE_TEXT) << 16) + SUBTYPE_PLAIN;

	ret->body.s = tmp;
	ret->body.len = end - ret->body.s;


	return ret;

};

inline struct multi_body * get_all_bodies(struct sip_msg * msg)
{
	char * start = 0, * end;
	int type = 0;
	struct part ** cur, * temp;
	str delimiter;

	/* is body already parsed ? */
	if (msg->multi)
		return msg->multi;

	start = get_body(msg);

	if (start == NULL || msg->content_length == NULL )
		return 0;

	if (msg->buf + msg->len - start < get_content_length(msg))
	{
		LM_ERR("Message is shorter than indicated by content length:"
			" got %d expected %ld\n", (int)(msg->buf + msg->len - start),
			get_content_length(msg));
		return NULL;
	}

	type = parse_content_type_hdr(msg);


	if (type <= 0)
		return 0;


	msg->multi = pkg_malloc(sizeof (struct multi_body));

	if (msg->multi == 0)
	{
		LM_ERR("Unable to allocate memory\n");
		return 0;
	}
	memset(msg->multi, 0, sizeof (struct multi_body));

	msg->multi->boundary = ((content_t *) msg->content_type->parsed)->boundary;
	cur = &msg->multi->first;

	if ((type >> 16) == TYPE_MULTIPART)
	{
		msg->multi->from_multi_part = 1;

		delimiter = ((content_t*) msg->content_type->parsed)->boundary;

		LM_DBG("Starting parsing with boundary = [%.*s]\n", delimiter.len, delimiter.s);

		start = find_sdp_line_delimiter(start, msg->buf + msg->len, delimiter);
		while (1)
		{
			end = find_sdp_line_delimiter(start + 1, msg->buf + msg->len, delimiter);
			if (end == NULL)
				break;

			/* add 4 to delimiter 2 for "--" and 2 for "\n\r" */
			/* subtract 2 from end for last "\n\r" */
			temp = parse_single_part(start + delimiter.len + 4, end-2);
			if (temp == NULL)
			{
				LM_ERR("Unable to parse part:[%.*s]\n",(int)(end-start),start);
				return 0;
			}


			*cur = temp;
			cur = &temp->next;
			start = end;
		}

	} else
	{
		msg->multi->from_multi_part = 0;


		if ((temp = new_part()) == 0)
			return 0;

		temp->content_type = type;

		temp->body.s = start;
		temp->body.len = get_content_length(msg);

		temp->all_data.s = start;
		temp->all_data.len = get_content_length(msg);

		*cur = temp;
		msg->multi->part_count++;


	}

	return msg->multi;

};

void free_multi_body(struct multi_body * multi)
{
	struct part * p, *tmp;

	p = multi->first;
	

	while(p)
	{
		tmp =  p;
		p = p->next;
		pkg_free(tmp);
	}
	pkg_free(multi);
}

