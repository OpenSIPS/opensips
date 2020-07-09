/*
 * SDP parser helpers
 *
 * Copyright (C) 2008 SOMA Networks, INC.
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
 *
 * History:
 * --------
 * 2007-09-09 ported helper functions from nathelper module (osas)
 * 2008-04-22 integrated RFC4975 attributes - patch provided by Denis Bilenko (denik)
 *
 */


#include "../../ut.h"
#include "../msg_parser.h"
#include "../parser_f.h"
#include "../parse_hname2.h"
#include "sdp.h"


static struct {
	const char *s;
	int len;
	int is_rtp;
} sup_ptypes[] = {
	{.s = "rtp/avp",   .len = 7, .is_rtp = 1},
	{.s = "udptl",     .len = 5, .is_rtp = 0},
	{.s = "rtp/avpf",  .len = 8, .is_rtp = 1},
	{.s = "rtp/savp",  .len = 8, .is_rtp = 1},
	{.s = "rtp/savpf", .len = 9, .is_rtp = 1},
	{.s = "udp",       .len = 3, .is_rtp = 0},
	{.s = "udp/bfcp",  .len = 8, .is_rtp = 0},
	{.s = NULL,        .len = 0, .is_rtp = 0}
};


int extract_rtpmap(str *body,
	str *rtpmap_payload, str *rtpmap_encoding, str *rtpmap_clockrate, str *rtpmap_parmas)
{
	char *cp, *cp1;
	int len;

	if (strncasecmp(body->s, "a=rtpmap:", 9) !=0) {
		/*LM_DBG("We are not pointing to an a=rtpmap: attribute =>`%.*s'\n", body->len, body->s); */
		return -1;
	}

	cp1 = body->s;

	rtpmap_payload->s = cp1 + 9; /* skip `a=rtpmap:' */
	rtpmap_payload->len = eat_line(rtpmap_payload->s, body->s + body->len -
	          rtpmap_payload->s) - rtpmap_payload->s;
	trim_len(rtpmap_payload->len, rtpmap_payload->s, *rtpmap_payload);
	len = rtpmap_payload->len;

	/* */
	cp = eat_token_end(rtpmap_payload->s, rtpmap_payload->s + rtpmap_payload->len);
	rtpmap_payload->len = cp - rtpmap_payload->s;
	if (rtpmap_payload->len <= 0 || cp == rtpmap_payload->s) {
		LM_ERR("no encoding in `a=rtpmap'\n");
		return -1;
	}
	len -= rtpmap_payload->len;
	rtpmap_encoding->s = cp;
	cp = eat_space_end(rtpmap_encoding->s, rtpmap_encoding->s + len);
	len -= cp - rtpmap_encoding->s;
	if (len <= 0 || cp == rtpmap_encoding->s) {
		LM_ERR("no encoding in `a=rtpmap:'\n");
		return -1;
	}

	rtpmap_encoding->s = cp;
	cp1 = (char*)l_memmem(cp, "/", len, 1);
	len -= cp1 - cp;
	if (cp1==NULL || len <= 1 || cp == cp1) {
		LM_ERR("invalid encoding in `a=rtpmap'\n");
		return -1;
	}
	rtpmap_encoding->len = cp1 - cp;

	/* skip the '/' char */
	cp = cp1+1;
	len--;

	cp1 = (char*)l_memmem(cp, "/", len, 1);
	if (cp1 == NULL) {
		rtpmap_clockrate->s = cp;
		rtpmap_clockrate->len = len;
		rtpmap_parmas->s = NULL;
		rtpmap_parmas->len = 0;
	} else {
		rtpmap_clockrate->s = cp;
		rtpmap_clockrate->len = cp1-cp;
		len -= cp1 - cp;
		if (len <= 1) {
			LM_ERR("invalid encoding in `a=rtpmap:'\n");
			return -1;
		}
		rtpmap_parmas->s = cp1 + 1;
		rtpmap_parmas->len = len - 1;
	}
	return 0;
}

int extract_fmtp( str *body, str *fmtp_payload, str *fmtp_string )
{
	char *cp, *cp1;
	int len;

	if (strncasecmp(body->s, "a=fmtp:", 7) !=0) {
		/*LM_DBG("We are not pointing to an a=fmtp: attribute =>`%.*s'\n", body->len, body->s); */
		return -1;
	}

	cp1 = body->s;

	fmtp_payload->s = cp1 + 7; /* skip `a=fmtp:' */
	fmtp_payload->len = eat_line(fmtp_payload->s, body->s + body->len -
		fmtp_payload->s) - fmtp_payload->s;
	trim_len(fmtp_payload->len, fmtp_payload->s, *fmtp_payload);
	len = fmtp_payload->len;

	/* */
	cp = eat_token_end(fmtp_payload->s, fmtp_payload->s + fmtp_payload->len);
	fmtp_payload->len = cp - fmtp_payload->s;
	if (fmtp_payload->len <= 0 || cp == fmtp_payload->s) {
		LM_ERR("no encoding in `a=fmtp:'\n");
		return -1;
	}
	len -= fmtp_payload->len;
	fmtp_string->s = cp;
	cp = eat_space_end(fmtp_string->s, fmtp_string->s + len);
	len -= cp - fmtp_string->s;
	if (len <= 0 || cp == fmtp_string->s) {
		LM_ERR("no encoding in `a=fmtp:'\n");
		return -1;
	}

	fmtp_string->s = cp;

	fmtp_string->len = eat_line(fmtp_string->s, body->s + body->len -
		fmtp_string->s) - fmtp_string->s;
	trim_len(fmtp_string->len, fmtp_string->s, *fmtp_string);

	return 0;
}

/* generic method for attribute extraction
 * field must has format "a=attrname:" */
int extract_field(str *body, str *value, str field)
{
	if (strncmp(body->s, field.s, field.len < body->len ? field.len : body->len) !=0) {
		/*LM_DBG("We are not pointing to an %.* attribute =>`%.*s'\n", field.len, field.s, body->len, body->s); */
		return -1;
	}

	value->s = body->s + field.len; /* skip `a=attrname:' */
	value->len = eat_line(value->s, body->s + body->len -
	          value->s) - value->s;
	trim_len(value->len, value->s, *value);

	return 0;
}


int extract_ptime(str *body, str *ptime)
{
	static const str field = str_init("a=ptime:");
	return extract_field(body, ptime, field);
}

int extract_accept_types(str *body, str *accept_types)
{
	static const str field = str_init("a=accept-types:");
	return extract_field(body, accept_types, field);
}

int extract_accept_wrapped_types(str *body, str *accept_wrapped_types)
{
	static const str field = str_init("a=accept-wrapped-types:");
	return extract_field(body, accept_wrapped_types, field);
}

int extract_max_size(str *body, str *max_size)
{
	static const str field = str_init("a=max-size:");
	return extract_field(body, max_size, field);
}

int extract_path(str *body, str *path)
{
	static const str field = str_init("a=path:");
	return extract_field(body, path, field);
}

int extract_rtcp(str *body, str *rtcp)
{
	static const str field = str_init("a=rtcp:");
	return extract_field(body, rtcp, field);
}

int extract_sendrecv_mode(str *body, str *sendrecv_mode, int *is_on_hold)
{
	char *cp1;

	cp1 = body->s;
	if ( !( (strncasecmp(cp1, "a=sendrecv", 10) == 0) ||
		(strncasecmp(cp1, "a=recvonly", 10) == 0))) {
		if ( !( (strncasecmp(cp1, "a=inactive", 10) == 0) ||
			(strncasecmp(cp1, "a=sendonly", 10) == 0) )) {
			return -1;
		} else {
			*is_on_hold = RFC3264_HOLD;
		}
	}

	sendrecv_mode->s = body->s + 2; /* skip `a=' */
	sendrecv_mode->len = 8; /* we know the length and therefore we don't need to overkill */
	/*
	sendrecv_mode->len = eat_line(sendrecv_mode->s, body->s + body->len -
		sendrecv_mode->s) - sendrecv_mode->s;
	trim_len(sendrecv_mode->len, sendrecv_mode->s, *sendrecv_mode);
	*/

	return 0;
}

int extract_bwidth(str *body, str *bwtype, str *bwwitdth)
{
	char *cp, *cp1;
	int len;

	cp1 = NULL;
	for (cp = body->s; (len = body->s + body->len - cp) > 0;) {
		cp1 = (char*)l_memmem(cp, "b=", len, 2);
		if (cp1 == NULL || cp1[-1] == '\n' || cp1[-1] == '\r')
			break;
		cp = cp1 + 2;
	}
	if (cp1 == NULL)
		return -1;

	bwtype->s = cp1 + 2;
	bwtype->len = eat_line(bwtype->s, body->s + body->len - bwtype->s) - bwtype->s;
	trim_len(bwtype->len, bwtype->s, *bwtype);

	cp = bwtype->s;
	len = bwtype->len;
	cp1 = (char*)l_memmem(cp, ":", len, 1);
	len -= cp1 - cp;
	if (len <= 0) {
		LM_ERR("invalid encoding in `b=%.*s'\n", bwtype->len, bwtype->s);
		return -1;
	}
	bwtype->len = cp1 - cp;

	/* skip ':' */
	bwwitdth->s = cp1 + 1;
	bwwitdth->len = len - 1;

	return 0;
}

int extract_mediaip(str *body, str *mediaip, int *pf, char *line)
{
	char *cp, *cp1;
	int len, nextisip;

	cp1 = NULL;
	for (cp = body->s; (len = body->s + body->len - cp) > 0;) {
		cp1 = (char*)l_memmem(cp, line, len, 2);
		if (cp1 == NULL || cp1[-1] == '\n' || cp1[-1] == '\r')
			break;
		cp = cp1 + 2;
	}
	if (cp1 == NULL)
		return -1;

	mediaip->s = cp1 + 2;
	mediaip->len = eat_line(mediaip->s, body->s + body->len - mediaip->s) - mediaip->s;
	trim_len(mediaip->len, mediaip->s, *mediaip);

	nextisip = 0;
	for (cp = mediaip->s; cp < mediaip->s + mediaip->len;) {
		len = eat_token_end(cp, mediaip->s + mediaip->len) - cp;
		if (nextisip == 1) {
			mediaip->s = cp;
			mediaip->len = len;
			nextisip++;
			break;
		}
		if (len == 3 && memcmp(cp, "IP", 2) == 0) {
			switch (cp[2]) {
			case '4':
				nextisip = 1;
				*pf = AF_INET;
				break;

			case '6':
				nextisip = 1;
				*pf = AF_INET6;
				break;

			default:
				break;
			}
		}
		/* consume all spaces starting from the second char after the token
		   First char after the token is the char that stoped the token
		   parsing, so it is space or \r / \n, so we simply skip it */
		cp = eat_space_end(cp + len + 1, mediaip->s + mediaip->len);
	}
	if (nextisip != 2 || mediaip->len == 0) {
		LM_ERR("no `IP[4|6]' in `%s' field\n",line);
		return -1;
	}
	return 1;
}

int extract_media_attr(str *body, str *mediamedia, str *mediaport, str *mediatransport, str *mediapayload, int *is_rtp)
{
	char *cp, *cp1;
	int len, i;

	cp1 = NULL;
	for (cp = body->s; (len = body->s + body->len - cp) > 0;) {
		cp1 = (char*)l_memmem(cp, "m=", len, 2);
		if (cp1 == NULL || cp1[-1] == '\n' || cp1[-1] == '\r')
			break;
		cp = cp1 + 2;
	}
	if (cp1 == NULL) {
		LM_ERR("no `m=' in SDP\n");
		return -1;
	}
	mediaport->s = cp1 + 2; /* skip `m=' */
	mediaport->len = eat_line(mediaport->s, body->s + body->len -
	  mediaport->s) - mediaport->s;
	trim_len(mediaport->len, mediaport->s, *mediaport);

	mediapayload->len = mediaport->len;
	mediamedia->s = mediaport->s;


	/* Skip media supertype and spaces after it */
	cp = eat_token_end(mediaport->s, mediaport->s + mediaport->len);
	mediaport->len -= cp - mediaport->s;
	mediamedia->len = mediapayload->len - mediaport->len;
	if (mediaport->len <= 0 || cp == mediaport->s) {
		LM_ERR("no port in `m='\n");
		return -1;
	}
	mediaport->s = cp;

	cp = eat_space_end(mediaport->s, mediaport->s + mediaport->len);
	mediaport->len -= cp - mediaport->s;
	if (mediaport->len <= 0 || cp == mediaport->s) {
		LM_ERR("no port in `m='\n");
		return -1;
	}

	/* Extract port */
	mediaport->s = cp;
	cp = eat_token_end(mediaport->s, mediaport->s + mediaport->len);
	mediatransport->len = mediaport->len - (cp - mediaport->s);
	/* coverity[copy_paste_error] false positive CID #40557 */
	if (mediatransport->len <= 0 || cp == mediaport->s) {
		LM_ERR("no port in `m='\n");
		return -1;
	}
	mediatransport->s = cp;
	mediaport->len = cp - mediaport->s;

	/* Skip spaces after port */
	cp = eat_space_end(mediatransport->s, mediatransport->s + mediatransport->len);
	mediatransport->len -= cp - mediatransport->s;
	if (mediatransport->len <= 0 || cp == mediatransport->s) {
		LM_ERR("no protocol type in `m='\n");
		return -1;
	}
	/* Extract protocol type */
	mediatransport->s = cp;
	cp = eat_token_end(mediatransport->s, mediatransport->s + mediatransport->len);
	if (cp == mediatransport->s) {
		LM_ERR("no protocol type in `m='\n");
		return -1;
	}
	mediatransport->len = cp - mediatransport->s;

	mediapayload->s = mediatransport->s + mediatransport->len;
	mediapayload->len -= mediapayload->s - mediamedia->s;
	cp = eat_space_end(mediapayload->s, mediapayload->s + mediapayload->len);
	mediapayload->len -= cp - mediapayload->s;
	mediapayload->s = cp;

	for (i = 0; sup_ptypes[i].s != NULL; i++)
		if (mediatransport->len == sup_ptypes[i].len &&
		    strncasecmp(mediatransport->s, sup_ptypes[i].s, mediatransport->len) == 0) {
			*is_rtp = sup_ptypes[i].is_rtp;
			return 0;
		}
	/* Unproxyable protocol type. Generally it isn't error. */
	return 0;
}


/*
 * Auxiliary for some functions.
 * Returns pointer to first character of found line, or NULL if no such line.
 */

char *find_sdp_line(char* p, char* plimit, char linechar)
{
	static char linehead[3] = "x=";
	char *cp, *cp1;
	linehead[0] = linechar;
	/* Iterate through body */
	cp = p;
	for (;;) {
		if (cp >= plimit)
			return NULL;
		cp1 = l_memmem(cp, linehead, plimit-cp, 2);
		if (cp1 == NULL)
			return NULL;
		/*
		 * As it is body, we assume it has previous line and we can
		 * lookup previous character.
		 */
		if (cp1[-1] == '\n' || cp1[-1] == '\r')
			return cp1;
		/*
		 * Having such data, but not at line beginning.
		 * Skip them and reiterate. l_memmem() will find next
		 * occurence.
		 */
		if (plimit - cp1 < 2)
			return NULL;
		cp = cp1 + 2;
	}
}



/*
 * Auxiliary for some functions.
 * Returns pointer to first character of found line, or NULL if no such line.
 */

char *find_sdp_line_complex(char* p, char* plimit, char * name)
{
	char *cp, *cp1;
	int len =  strlen(name);

	/* Iterate through body */
	cp = p;
	for (;;) {
		if (cp >= plimit)
			return NULL;
		cp1 = l_memmem(cp, name, plimit-cp, len);
		if (cp1 == NULL)
			return NULL;
		/*
		 * As it is body, we assume it has previous line and we can
		 * lookup previous character.
		 */
		if (cp1[-1] == '\n' || cp1[-1] == '\r')
			return cp1;
		/*
		 * Having such data, but not at line beginning.
		 * Skip them and reiterate. l_memmem() will find next
		 * occurence.
		 */
		if (plimit - cp1 < 2)
			return NULL;
		cp = cp1 + 2;
	}
}


/* This function assumes p points to a line of requested type. */
char * find_next_sdp_line(char* p, char* plimit, char linechar, char* defptr)
{
	char *t;
	if (p >= plimit || plimit - p < 3)
		return defptr;
	t = find_sdp_line(p + 2, plimit, linechar);
	return t ? t : defptr;
}


/* returns pointer to next header line, and fill hdr_f ;
 * if at end of header returns pointer to the last crlf  (always buf)*/
char* get_sdp_hdr_field(char* buf, char* end, struct hdr_field* hdr)
{

	char* tmp;
	char *match;

	if ((*buf)=='\n' || (*buf)=='\r'){
		/* double crlf or lflf or crcr */
		hdr->type=HDR_EOH_T;
		return buf;
	}

	tmp=parse_hname2(buf, end, hdr);
	if (hdr->type==HDR_ERROR_T){
		LM_ERR("bad header\n");
		goto error;
	}

	/* eliminate leading whitespace */
	tmp=eat_lws_end(tmp, end);
	if (tmp>=end) {
		LM_ERR("hf empty\n");
		goto error;
	}

	/* if header-field well-known, parse it, find its end otherwise ;
	 * after leaving the hdr->type switch, tmp should be set to the
	 * next header field
	 */
	switch(hdr->type){
		case HDR_CONTENTTYPE_T:
		case HDR_CONTENTDISPOSITION_T:
			/* just skip over it */
			hdr->body.s=tmp;
			/* find end of header */
			/* find lf */
			do{
				match=q_memchr(tmp, '\n', end-tmp);
				if (match){
					match++;
				}else {
					LM_ERR("bad body for <%s>(%d)\n", hdr->name.s, hdr->type);
					tmp=end;
					goto error;
				}
				tmp=match;
			}while( match<end &&( (*match==' ')||(*match=='\t') ) );
			tmp=match;
			hdr->body.len=match-hdr->body.s;
			break;
		default:
			LM_CRIT("unknown header type %d\n", hdr->type);
			goto error;
	}
	/* jku: if \r covered by current length, shrink it */
	trim_r( hdr->body );
	hdr->len=tmp-hdr->name.s;
	return tmp;
error:
	LM_DBG("error exit\n");
	hdr->type=HDR_ERROR_T;
	hdr->len=tmp-hdr->name.s;
	return tmp;
}

