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

	LM_DBG("getting hdr from [%.*s...]\n",
		(int)((end-buf)<25?end-buf:25), buf);

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

	LM_DBG("parsing part [%.*s...]\n",
		(int)((end-start)<25?end-start:25), start);

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
			part->mime_s = hd.body;
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


int parse_sip_body(struct sip_msg * msg)
{
	char *start, *end;
	int type = 0;
	struct body_part *part, *last;
	str delimiter, body;

	/* is body already parsed ? */
	if (msg->body)
		return 0;

	if ( get_body(msg,&body)!=0 || body.len==0)
		return 0;

	type = parse_content_type_hdr(msg);
	if (type <= 0)
		return 0;

	msg->body = pkg_malloc(sizeof (struct sip_msg_body));
	if (msg->body == 0)
	{
		LM_ERR("Unable to allocate memory\n");
		return -1;
	}
	memset(msg->body, 0, sizeof (struct sip_msg_body));

	msg->body->body = body;

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
				return -1;
			}

			/* set the parsing for the next cycle */
			start = end;

			/* link the new part; note that the first part is part of 
			 * the body structure, no need to be linked */
			if (last)
				last->next = part;
			last = part;
			msg->body->part_count++;

		}

	} else {

		/* only one part in the body */
		part = &msg->body->first;

		part->mime = type;
		part->mime_s = msg->content_type->body;
		part->body = body;
		part->all_data = body;
		msg->body->part_count++;
	}

	msg->body->updated_part_count = msg->body->part_count;

	return 0;

};


struct body_part* add_body_part(struct sip_msg *msg, str *mime_s, str *body)
{
	struct body_part *part, *last;
	char *m;

	if ( parse_sip_body(msg)<0) {
		LM_ERR("failed to parse existing SIP body\n");
		return NULL;
	}

	if (msg->body==NULL) {

		/* the message has no body so far */
		msg->body = (struct sip_msg_body*)pkg_malloc(
			sizeof(struct sip_msg_body) + (body?body->len:0) + mime_s->len );
		if (!msg->body) {
			LM_ERR("No more pkg memory!\n");
			return NULL;
		}
		memset(msg->body, 0, sizeof(struct sip_msg_body));

		msg->body->part_count = 0;
		msg->body->updated_part_count = 1;
		msg->body->flags = SIP_BODY_FLAG_NEW;
		msg->body->boundary.s = NULL;
		msg->body->boundary.len = 0;

		part = &msg->body->first;
		m = (char*)(msg->body+1); /* pointer to mime */

	} else {

		/* allocate a new body part */
		part = (struct body_part*)pkg_malloc(
			sizeof(struct body_part) + (body?body->len:0) + mime_s->len );
		if (part==NULL) {
			LM_ERR("failed to allocated pkg mem\n");
			return NULL;
		}

		m = (char*)(part+1); /* pointer to mime */

		/* link new part at the end of the parts list */
		for (last=&msg->body->first; last->next ; last=last->next);
		last->next = part;

		msg->body->updated_part_count++;
	}

	memset( part, 0, sizeof(struct body_part) );

	part->flags = SIP_BODY_PART_FLAG_NEW;

	/* mime follows right after the part, in the same mem chunk */
	memcpy( m, mime_s->s, mime_s->len);
	part->mime_s.s = m;
	part->mime_s.len = mime_s->len;

	if (body) {
		/* body follows right after mime, in the same mem chunk */
		part->body.s = m + mime_s->len;
		memcpy( part->body.s, body->s, body->len);
		part->body.len = body->len;
	}

	return part;
}


int delete_body_part(struct sip_msg *msg, struct body_part *part)
{
	if (msg->body==NULL) {
		LM_BUG("deleting a body part, but body not found/parsed :-/\n");
		return -1;
	}

	/* mark the part as deleted */
	part->flags |= SIP_BODY_PART_FLAG_DELETED;

	msg->body->updated_part_count--;

	return 0;
}


static void *pb_pkg_malloc(unsigned long size)
{
	return pkg_malloc(size);
}

static void pb_pkg_free(void *p)
{
	pkg_free(p);
}

static void *pb_shm_malloc(unsigned long size)
{
	return shm_malloc(size);
}

static void pb_shm_free(void *p)
{
	shm_free(p);
}


void free_sip_body(struct sip_msg_body *body)
{
	struct body_part * p, *tmp;
	pb_free my_free;

	if (body) {
		my_free = (body->flags&SIP_BODY_FLAG_SHM) ? pb_shm_free : pb_pkg_free;
		/* the first part does not need to be freed */
		p = &body->first;
		if (p->parsed && p->free_parsed_f)
			p->free_parsed_f( p->parsed, my_free );
		/* following parts need to be also freed */
		p = p->next;
		while(p) {
			tmp =  p;
			p = p->next;
			/* any need to free some parsed format of the part ? */
			if (tmp->parsed && tmp->free_parsed_f)
				tmp->free_parsed_f( tmp->parsed, my_free );
			my_free(tmp);
		}
		my_free(body);
	}
}


/* Clones the sip_msg_body structure attached to a sip msg into shm or pkg
 * memory.
 * Parameters:
 *    * src_msg - the original sip_msg containing the sip_msg_body to be cloned
 *                It can be in shm or pkg and it is mandatory.
 *    * dst_msg - the destination sip_msg - this is need only when cloning into
 *                shm, as we need to translate to this new sip msg all the 
 *                pointers (from our structure) into inside the buffer of the
 *                sip msg; must be provided if cloning to shm;
 *    * p_dst   - the holder where the clone will be returned if success.
 *    * shared  - 1 if to SHM or 0 if to PKG
 */
int clone_sip_msg_body(struct sip_msg *src_msg, struct sip_msg *dst_msg,
									struct sip_msg_body **p_dst, int shared)
{
	struct sip_msg_body *dst, *src;
	struct body_part *p, *np;
	pb_malloc my_malloc;
	int extra_len;

	if (src_msg==NULL || src_msg->body==NULL) {
		*p_dst = NULL;
		return 0;
	}

	my_malloc = shared ? pb_shm_malloc : pb_pkg_malloc;
	src = src_msg->body;

	/* clone the SIP MSG BODY */
	extra_len = (src->flags&SIP_BODY_FLAG_NEW) ?
		src->first.mime_s.len+src->first.body.len : 0 ;
	if ( (dst=my_malloc(sizeof(struct sip_msg_body)+extra_len))==NULL ) {
		LM_ERR("failed to allocate new sip_msg_body clone (shared=%d)\n",
			shared);
		goto err;
	}
	memcpy( dst, src, sizeof(struct sip_msg_body)+extra_len);
	if (shared)
		dst->flags |= SIP_BODY_FLAG_SHM;
	else
		dst->flags &= ~SIP_BODY_FLAG_SHM;
	/* update the links inside it */
	if (dst_msg) { \
		dst->body.s = translate_pointer(dst_msg->buf ,src_msg->buf,
			src->body.s );
		dst->boundary.s = translate_pointer(dst_msg->buf ,src_msg->buf,
			src->boundary.s );
	}
	/* clone the body parts */
	for( p=&src->first,np=NULL ; p ; p=p->next) {
		if (np==NULL) { \
			/* first body part */
			np = &dst->first;
			extra_len = 0;
		} else {
			extra_len = (p->flags&SIP_BODY_PART_FLAG_NEW) ?
				p->mime_s.len+p->body.len : 0 ;
			if((np->next=my_malloc(sizeof(struct body_part)+extra_len))==NULL){
				LM_ERR("failed to allocate new body_part clone (shared=%d)\n",
					shared);
				goto err;
			} \
			np = np->next;
		} \
		memcpy( np, p, sizeof(struct body_part)+extra_len);
		/* update the links inside it */
		if (p->flags&SIP_BODY_PART_FLAG_NEW) {
			/* links are pointing inside the body_part structure */
			if (p==&src->first) {
				np->body.s = translate_pointer((char*)dst ,(char*)src,
					p->body.s);
				np->mime_s.s = translate_pointer((char*)dst, (char*)src,
					p->mime_s.s);
			} else {
				np->body.s = translate_pointer((char*)np ,(char*)p,
					p->body.s);
				np->mime_s.s = translate_pointer((char*)np, (char*)p,
					p->mime_s.s);
			}
		} else {
			/* links are pointing inside the sip msg body, so update only
			 * a new sip msg was provided */ \
			if (dst_msg) { \
				np->body.s = translate_pointer( dst_msg->buf,
					src_msg->buf, p->body.s );
				np->mime_s.s = translate_pointer( dst_msg->buf,
					src_msg->buf, p->mime_s.s );
				np->all_data.s = translate_pointer( dst_msg->buf,
						src_msg->buf, p->all_data.s );
			}
		}
		if (p->parsed && p->clone_parsed_f)
			np->parsed = p->clone_parsed_f(p, np, src_msg, dst_msg, my_malloc);
		else
			np->parsed = NULL;
	}

	*p_dst = dst;
	return 0;
err:
	if (dst) free_sip_body(dst);
	return -1;
}



