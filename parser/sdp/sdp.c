/*
 * SDP parser interface
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
 * HISTORY:
 * --------
 * 2007-09-09 osas: ported and enhanced sdp parsing functions from nathelper module
 * 2008-04-22 osas: integrated RFC4975 attributes - patch provided by Denis Bilenko (denik)
 *
 */


#include "../../ut.h"
#include "../../trim.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../parser_f.h"
#include "../parse_content.h"
#include "../parse_body.h"
#include "sdp.h"
#include "sdp_helpr_funcs.h"

#define USE_PKG_MEM 0
#define USE_SHM_MEM 1

#define HOLD_IP_STR "0.0.0.0"
#define HOLD_IP_LEN 7

/**
 * Creates and initialize a new sdp_info structure
 */
static inline sdp_info_t* new_sdp(void)
{
	sdp_info_t* sdp;

	sdp = (sdp_info_t*)pkg_malloc(sizeof(sdp_info_t));
	if (sdp == NULL) {
		LM_ERR("No memory left\n");
		return NULL;
	}
	memset( sdp, 0, sizeof(sdp_info_t));

	return sdp;
}


/**
 * Alocate a new session cell.
 */
static inline sdp_session_cell_t *add_sdp_session(sdp_info_t* _sdp, int session_num, str* cnt_disp, str body)
{
	sdp_session_cell_t *session;
	int len;

	len = sizeof(sdp_session_cell_t);
	session = (sdp_session_cell_t*)pkg_malloc(len);
	if (session == NULL) {
		LM_ERR("No memory left\n");
		return NULL;
	}
	memset( session, 0, len);

	session->session_num = session_num;
	if (cnt_disp != NULL) {
		session->cnt_disp.s = cnt_disp->s;
		session->cnt_disp.len = cnt_disp->len;
	}

	session->body = body;

	/* Insert the new session */
	session->next = _sdp->sessions;
	_sdp->sessions = session;
	_sdp->sessions_num++;

	return session;
}

/**
 * Allocate a new stream cell.
 */
static inline sdp_stream_cell_t *add_sdp_stream(sdp_session_cell_t* _session, int stream_num,
		str* media, str* port, str* transport, str* payloads, int is_rtp, int pf, str* sdp_ip, str body)
{
	sdp_stream_cell_t *stream;
	int len;

	len = sizeof(sdp_stream_cell_t);
	stream = (sdp_stream_cell_t*)pkg_malloc(len);
	if (stream == NULL) {
		LM_ERR("No memory left\n");
		return NULL;
	}
	memset( stream, 0, len);

	stream->stream_num = stream_num;

	stream->media.s = media->s;
	stream->media.len = media->len;
	stream->port.s = port->s;
	stream->port.len = port->len;
	stream->transport.s = transport->s;
	stream->transport.len = transport->len;
	stream->payloads.s = payloads->s;
	stream->payloads.len = payloads->len;

	stream->is_rtp = is_rtp;

	stream->pf = pf;
	stream->ip_addr.s = sdp_ip->s;
	stream->ip_addr.len = sdp_ip->len;

	stream->body = body;

	/* Insert the new stream */
	stream->next = _session->streams;
	_session->streams = stream;
	_session->streams_num++;

	return stream;
}

/**
 * Allocate a new payload.
 */
static inline sdp_payload_attr_t *add_sdp_payload(sdp_stream_cell_t* _stream, int payload_num, str* payload)
{
	sdp_payload_attr_t *payload_attr;
	int len;

	len = sizeof(sdp_payload_attr_t);
	payload_attr = (sdp_payload_attr_t*)pkg_malloc(len);
	if (payload_attr == NULL) {
		LM_ERR("No memory left\n");
		return NULL;
	}
	memset( payload_attr, 0, len);

	payload_attr->payload_num = payload_num;
	payload_attr->rtp_payload.s = payload->s;
	payload_attr->rtp_payload.len = payload->len;

	/* Insert the new payload */
	payload_attr->next = _stream->payload_attr;
	_stream->payload_attr = payload_attr;
	_stream->payloads_num++;

	return payload_attr;
}

/**
 * Initialize fast access pointers.
 */
static inline sdp_payload_attr_t** init_p_payload_attr(sdp_stream_cell_t* _stream, int pkg)
{
	int payloads_num, i;
	sdp_payload_attr_t *payload;

	if (_stream == NULL) {
		LM_ERR("Invalid stream\n");
		return NULL;
	}
	payloads_num = _stream->payloads_num;
	if (payloads_num == 0) {
		LM_ERR("Invalid number of payloads\n");
		return NULL;
	}
	if (pkg == USE_PKG_MEM) {
		_stream->p_payload_attr = (sdp_payload_attr_t**)pkg_malloc(payloads_num * sizeof(sdp_payload_attr_t*));
	} else if (pkg == USE_SHM_MEM) {
		_stream->p_payload_attr = (sdp_payload_attr_t**)shm_malloc(payloads_num * sizeof(sdp_payload_attr_t*));
	} else {
		LM_ERR("undefined memory type\n");
		return NULL;
	}
	if (_stream->p_payload_attr == NULL) {
		LM_ERR("No memory left\n");
		return NULL;
	}

	--payloads_num;
	payload = _stream->payload_attr;
	for (i=0;i<=payloads_num;i++) {
		_stream->p_payload_attr[payloads_num-i] = payload;
		payload = payload->next;
	}

	return _stream->p_payload_attr;
}

/*
 * Setters ...
 */

void set_sdp_payload_attr(sdp_payload_attr_t *payload_attr, str *rtp_enc, str *rtp_clock, str *rtp_params)
{
	payload_attr->rtp_enc.s = rtp_enc->s;
	payload_attr->rtp_enc.len = rtp_enc->len;
	payload_attr->rtp_clock.s = rtp_clock->s;
	payload_attr->rtp_clock.len = rtp_clock->len;
	payload_attr->rtp_params.s = rtp_params->s;
	payload_attr->rtp_params.len = rtp_params->len;

	return;
}

void set_sdp_payload_fmtp(sdp_payload_attr_t *payload_attr, str *fmtp_string )
{
	if (payload_attr == NULL) {
		LM_ERR("Invalid payload location\n");
		return;
	}
	payload_attr->fmtp_string.s = fmtp_string->s;
	payload_attr->fmtp_string.len = fmtp_string->len;

	return;
}

/*
 * Getters ....
 */
sdp_session_cell_t* get_sdp_session(sdp_info_t* sdp, int session_num)
{
	sdp_session_cell_t *session;

	session = sdp->sessions;
	if (session_num >= sdp->sessions_num) return NULL;
	while (session) {
		if (session->session_num == session_num) return session;
		session = session->next;
	}
	return NULL;
}

sdp_stream_cell_t* get_sdp_stream(sdp_info_t* sdp, int session_num,
																int stream_num)
{
	sdp_session_cell_t *session;
	sdp_stream_cell_t *stream;

	if (sdp==NULL) return NULL;
	if (session_num >= sdp->sessions_num) return NULL;
	session = sdp->sessions;
	while (session) {
		if (session->session_num == session_num) {
			if (stream_num >= session->streams_num) return NULL;
			stream = session->streams;
			while (stream) {
				if (stream->stream_num == stream_num) return stream;
				stream = stream->next;
			}
			break;
		} else {
			session = session->next;
		}
	}

	return NULL;
}

sdp_payload_attr_t* get_sdp_payload4payload(sdp_stream_cell_t *stream, str *rtp_payload)
{
	sdp_payload_attr_t *payload;
	int i;

	if (stream == NULL) {
		LM_ERR("Invalid stream location\n");
		return NULL;
	}
	if (stream->p_payload_attr == NULL) {
		LM_ERR("Invalid access pointer to payloads\n");
		return NULL;
	}

	for (i=0;i<stream->payloads_num;i++) {
		payload = stream->p_payload_attr[i];
		if (rtp_payload->len == payload->rtp_payload.len &&
			(strncmp(rtp_payload->s, payload->rtp_payload.s, rtp_payload->len)==0)) {
			return payload;
		}
	}

	return NULL;
}

sdp_payload_attr_t* get_sdp_payload4index(sdp_stream_cell_t *stream, int index)
{
	if (stream == NULL) {
		LM_ERR("Invalid stream location\n");
		return NULL;
	}
	if (stream->p_payload_attr == NULL) {
		LM_ERR("Invalid access pointer to payloads\n");
		return NULL;
	}
	if (index >= stream->payloads_num) {
		LM_ERR("Out of range index [%d] for payload\n", index);
		return NULL;
	}

	return stream->p_payload_attr[index];
}

/**
 * Add SDP attribute.
 */
static inline int add_sdp_attr(str line, sdp_attr_t **list)
{
	char *p;
	static sdp_attr_t *last;
	sdp_attr_t *a = pkg_malloc(sizeof *a);
	if (!a) {
		LM_ERR("No memory left!\n");
		return -1;
	}
	memset(a, 0, sizeof *a);

	/* check for value separator : */
	p = q_memchr(line.s + 2, ':', line.len - 2);
	if (p) {
		a->attribute.s = line.s + 2;
		a->attribute.len = p - a->attribute.s;
		/* skip the separator */
		a->value.s = p + 1;
		a->value.len = line.len - (a->value.s - line.s);
		trim(&a->value);
	} else {
		a->attribute.s = line.s + 2;
		a->attribute.len = line.len - 2;
	}
	trim(&a->attribute);

	/* link it to the list */
	if (*list)
		last->next = a;
	else
		*list = a;
	/* we remember the last object added */
	last = a;

	return 0;
}

/**
 * SDP parser method.
 */
int parse_sdp_session(str *sdp_body, int session_num, str *cnt_disp, sdp_info_t* _sdp)
{
	str body = *sdp_body;
	str sdp_ip = {NULL,0};
	str sdp_media, sdp_port, sdp_transport, sdp_payload;
	str payload;
	str rtp_payload, rtp_enc, rtp_clock, rtp_params;
	int is_rtp;
	char *bodylimit;
	char *v1p, *o1p, *m1p, *m2p, *c1p, *c2p, *a1p, *a2p, *b1p;
	str tmpstr1;
	int stream_num, payloadnum, pf;
	sdp_session_cell_t *session;
	sdp_stream_cell_t *stream;
	sdp_payload_attr_t *payload_attr;
	int parse_payload_attr;
	str fmtp_string;

	/*
	 * Parsing of SDP body.
	 * Each session starts with v-line and each session may contain a few
	 * media descriptions (each starts with m-line).
	 * We have to change ports in m-lines, and also change IP addresses in
	 * c-lines which can be placed either in session header (fallback for
	 * all medias) or media description.
	 * Ports should be allocated for any media. IPs all should be changed
	 * to the same value (RTP proxy IP), so we can change all c-lines
	 * unconditionally.
	 */
	bodylimit = body.s + body.len;
	if (body.len < 2) {
		LM_ERR("body too short!\n");
		return -1;
	}
	v1p = body.s;
	/* skip over the first initial \r\n  (optional) */
	if (*v1p == '\r' || *v1p == '\n')
		v1p++;
	if (*v1p == '\r' || *v1p == '\n')
		v1p++;
	if (v1p + 1 >= bodylimit) {
		LM_ERR("body too short %ld!\n", bodylimit - v1p);
		return -1;
	}
	if (*v1p != 'v' || *(v1p+1) != '=') {
		LM_ERR("invalid SDP start: [%c%c]\n", *v1p, *(v1p + 1));
		return -1;
	}
	/* get session origin */
	o1p = find_sdp_line(v1p, bodylimit, 'o');
	if (o1p == NULL) {
		LM_ERR("no o= in session\n");
		return -1;
	}
	/* Have this session media description? */
	m1p = find_sdp_line(o1p, bodylimit, 'm');
	if (m1p == NULL) {
		LM_ERR("no m= in session\n");
		return -1;
	}
	/* Allocate a session cell */
	session = add_sdp_session(_sdp, session_num, cnt_disp, body);
	if (session == NULL) return -1;

	/* Get origin IP */
	tmpstr1.s = o1p;
	tmpstr1.len = bodylimit - tmpstr1.s; /* limit is session limit text */
	if (extract_mediaip(&tmpstr1, &session->o_ip_addr, &session->o_pf,"o=") == -1) {
		LM_ERR("can't extract origin media IP from the message\n");
		return -1;
	}

	/* Find c1p only between session begin and first media.
	 * c1p will give common c= for all medias. */
	c1p = find_sdp_line(o1p, m1p, 'c');

	if (c1p) {
		/* Extract session address */
		tmpstr1.s = c1p;
		tmpstr1.len = bodylimit - tmpstr1.s; /* limit is session limit text */
		if (extract_mediaip(&tmpstr1, &session->ip_addr, &session->pf,"c=") == -1) {
			LM_ERR("can't extract common media IP from the message\n");
			return -1;
		}
	}

	/* Find b1p only between session begin and first media.
	 * b1p will give common b= for all medias. */
	b1p = find_sdp_line(o1p, m1p, 'b');
	if (b1p) {
		tmpstr1.s = b1p;
		tmpstr1.len = m1p - b1p;
		extract_bwidth(&tmpstr1, &session->bw_type, &session->bw_width);
	}

	/* from b1p or o1p down to m1p we have session a= attributes */
	a1p = find_sdp_line((b1p?b1p:o1p), m1p, 'a');
	a2p = a1p;
	for (;;) {
		a1p = a2p;
		if (a1p == NULL || a1p >= m1p)
			break;
		a2p = find_next_sdp_line(a1p + 1, m1p, 'a', m1p);

		tmpstr1.s = a1p;
		tmpstr1.len = a2p - a1p;

		if (add_sdp_attr(tmpstr1, &session->attr) < 0)
			return -1;
	}

	/* Have session. Iterate media descriptions in session */
	m2p = m1p;
	stream_num = 0;
	for (;;) {
		m1p = m2p;
		if (m1p == NULL || m1p >= bodylimit)
			break;
		m2p = find_next_sdp_line(m1p, bodylimit, 'm', bodylimit);
		/* c2p will point to per-media "c=" */
		c2p = find_sdp_line(m1p, m2p, 'c');

		if (c2p) {
			/* Extract stream address */
			tmpstr1.s = c2p;
			tmpstr1.len = bodylimit - tmpstr1.s; /* limit is session limit text */
			if (extract_mediaip(&tmpstr1, &sdp_ip, &pf,"c=") == -1) {
				LM_ERR("can't extract media IP from the message\n");
				return -1;
			}
		} else {
			if (!c1p) {
				/* No "c=" */
				LM_ERR("can't find media IP in the message\n");
				return -1;
			}
			/* take the family from the more specific line */
			pf = session->pf;
		}

		/* Extract the port on sdp_port */
		tmpstr1.s = m1p;
		tmpstr1.len = m2p - m1p;
		if (extract_media_attr(&tmpstr1, &sdp_media, &sdp_port, &sdp_transport, &sdp_payload, &is_rtp) == -1) {
			LM_ERR("can't extract media attr from the message\n");
			return -1;
		}

		/* Allocate a stream cell */
		stream = add_sdp_stream(session, stream_num, &sdp_media, &sdp_port, &sdp_transport, &sdp_payload, is_rtp, pf, &sdp_ip, tmpstr1);
		if (stream == 0) return -1;

		/* increment total number of streams */
		_sdp->streams_num++;

		/* b1p will point to per-media "b=" */
		b1p = find_sdp_line(m1p, m2p, 'b');
		if (b1p) {
			tmpstr1.s = b1p;
			tmpstr1.len = m2p - b1p;
			extract_bwidth(&tmpstr1, &stream->bw_type, &stream->bw_width);
		}

		/* Parsing the payloads */
		tmpstr1.s = sdp_payload.s;
		tmpstr1.len = sdp_payload.len;
		payloadnum = 0;
		if (tmpstr1.len != 0) {
			for (;;) {
				a1p = eat_token_end(tmpstr1.s, tmpstr1.s + tmpstr1.len);
				payload.s = tmpstr1.s;
				payload.len = a1p - tmpstr1.s;
				payload_attr = add_sdp_payload(stream, payloadnum, &payload);
				if (payload_attr == NULL) return -1;
				tmpstr1.len -= payload.len;
				tmpstr1.s = a1p;
				a2p = eat_space_end(tmpstr1.s, tmpstr1.s + tmpstr1.len);
				tmpstr1.len -= a2p - a1p;
				tmpstr1.s = a2p;
				if (a1p >= tmpstr1.s)
					break;
				payloadnum++;
			}

			/* Initialize fast access pointers */
			if (NULL == init_p_payload_attr(stream, USE_PKG_MEM)) {
				return -1;
			}
			parse_payload_attr = 1;
		} else {
			parse_payload_attr = 0;
		}

		payload_attr = 0;
		/* Let's figure out the atributes */
		a1p = find_sdp_line(m1p, m2p, 'a');
		a2p = a1p;
		for (;;) {
			a1p = a2p;
			if (a1p == NULL || a1p >= m2p)
				break;
			tmpstr1.s = a2p;
			tmpstr1.len = m2p - a2p;

			if (parse_payload_attr && extract_ptime(&tmpstr1, &stream->ptime) == 0) {
				a1p = stream->ptime.s + stream->ptime.len;
			} else if (parse_payload_attr && extract_sendrecv_mode(&tmpstr1,
					&stream->sendrecv_mode, &stream->is_on_hold) == 0) {
				a1p = stream->sendrecv_mode.s + stream->sendrecv_mode.len;
			} else if (parse_payload_attr && extract_rtpmap(&tmpstr1, &rtp_payload, &rtp_enc, &rtp_clock, &rtp_params) == 0) {
				if (rtp_params.len != 0 && rtp_params.s != NULL) {
					a1p = rtp_params.s + rtp_params.len;
				} else {
					a1p = rtp_clock.s + rtp_clock.len;
				}
				payload_attr = (sdp_payload_attr_t*)get_sdp_payload4payload(stream, &rtp_payload);
				if (payload_attr)
					set_sdp_payload_attr(payload_attr, &rtp_enc, &rtp_clock, &rtp_params);
			} else if (extract_rtcp(&tmpstr1, &stream->rtcp_port) == 0) {
				a1p = stream->rtcp_port.s + stream->rtcp_port.len;
			} else if (parse_payload_attr && extract_fmtp(&tmpstr1,&rtp_payload,&fmtp_string) == 0){
				a1p = fmtp_string.s + fmtp_string.len;
				payload_attr = (sdp_payload_attr_t*)get_sdp_payload4payload(stream, &rtp_payload);
				set_sdp_payload_fmtp(payload_attr, &fmtp_string);
			} else if (extract_accept_types(&tmpstr1, &stream->accept_types) == 0) {
				a1p = stream->accept_types.s + stream->accept_types.len;
			} else if (extract_accept_wrapped_types(&tmpstr1, &stream->accept_wrapped_types) == 0) {
				a1p = stream->accept_wrapped_types.s + stream->accept_wrapped_types.len;
			} else if (extract_max_size(&tmpstr1, &stream->max_size) == 0) {
				a1p = stream->max_size.s + stream->max_size.len;
			} else if (extract_path(&tmpstr1, &stream->path) == 0) {
				a1p = stream->path.s + stream->path.len;
			/*} else { */
			/*	LM_DBG("else: `%.*s'\n", tmpstr1.len, tmpstr1.s); */
			}

			tmpstr1.s = a2p;
			a2p = find_next_sdp_line(a1p-1, m2p, 'a', m2p);
			tmpstr1.len = a2p - tmpstr1.s;

			if (add_sdp_attr(tmpstr1, &stream->attr) < 0)
				return -1;
		}
		/* Let's detect if the media is on hold by checking
		 * the good old "0.0.0.0" connection address */
		if (!stream->is_on_hold) {
			if (stream->ip_addr.s && stream->ip_addr.len) {
				if (stream->ip_addr.len == HOLD_IP_LEN &&
					strncmp(stream->ip_addr.s, HOLD_IP_STR, HOLD_IP_LEN)==0)
					stream->is_on_hold = RFC2543_HOLD;
			} else if (session->ip_addr.s && session->ip_addr.len) {
				if (session->ip_addr.len == HOLD_IP_LEN &&
					strncmp(session->ip_addr.s, HOLD_IP_STR, HOLD_IP_LEN)==0)
					stream->is_on_hold = RFC2543_HOLD;
			}
		}
		++stream_num;
	} /* Iterate medias/streams in session */
	return 0;
}


/**
 * Parse all SDP parts from the SIP body.
 *
 * returns the first found SDP on success
 * returns NULL if no SDP found or if error
 */
sdp_info_t* parse_sdp(struct sip_msg* _m)
{
	struct body_part *part;
	sdp_info_t *sdp, *ret;

	if ( parse_sip_body(_m)<0 || _m->body==NULL) {
		LM_DBG("message body has length zero\n");
		return NULL;
	}

	ret = NULL;

	/* iterate all body parts and look for the SDP mime */
	for( part=&_m->body->first ; part ; part=part->next) {

		/* skip body parts which were deleted or newly added */
		if (!is_body_part_received(part))
			continue;

		if ( part->mime != ((TYPE_APPLICATION<<16)+SUBTYPE_SDP) )
			continue;

		if (part->parsed) {
			if (!ret)
				ret = part->parsed;
			continue;
		}

		if ( (sdp=new_sdp())==NULL ) {
			LM_ERR("Can't create new sdp, skipping\n");
		} else {
			if (parse_sdp_session(&part->body, 0, NULL, sdp)<0) {
				LM_ERR("failed to parse SDP for body part, skipping\n");
				free_sdp( sdp );
			} else {
				part->parsed = (void*)sdp;
				part->free_parsed_f = (free_parsed_part_function)free_sdp;
				/* remember the first found SDP */
				if (!ret) ret = sdp;
			}
		}
	}

	return ret;
}

void free_sdp_content(sdp_info_t* sdp)
{
	sdp_session_cell_t *session, *l_session;
	sdp_stream_cell_t *stream, *l_stream;
	sdp_payload_attr_t *payload, *l_payload;
	sdp_attr_t *attr, *l_attr;

	LM_DBG("sdp = %p\n", sdp);
	if (sdp == NULL) return;
	LM_DBG("sdp = %p\n", sdp);
	session = sdp->sessions;
	LM_DBG("session = %p\n", session);
	while (session) {
		l_session = session;
		session = session->next;
		attr = l_session->attr;
		while (attr) {
			l_attr = attr;
			attr = attr->next;
			pkg_free(l_attr);
		}
		stream = l_session->streams;
		while (stream) {
			l_stream = stream;
			stream = stream->next;
			payload = l_stream->payload_attr;
			while (payload) {
				l_payload = payload;
				payload = payload->next;
				pkg_free(l_payload);
			}
			attr = l_stream->attr;
			while (attr) {
				l_attr = attr;
				attr = attr->next;
				pkg_free(l_attr);
			}
			if (l_stream->p_payload_attr) {
				pkg_free(l_stream->p_payload_attr);
			}
			pkg_free(l_stream);
		}
		pkg_free(l_session);
	}
}

void print_sdp_stream(sdp_stream_cell_t *stream, int level)
{
	sdp_payload_attr_t *payload;

	LM_GEN1(level, "....stream[%d]:%p=>%p {%p} '%.*s' '%.*s:%.*s:%.*s' '%.*s' [%d] '%.*s' '%.*s:%.*s' (%d)=>%p '%.*s' '%.*s' '%.*s' '%.*s' '%.*s' '%.*s'\n",
		stream->stream_num, stream, stream->next,
		stream->p_payload_attr,
		stream->media.len, stream->media.s,
		stream->ip_addr.len, stream->ip_addr.s, stream->port.len, stream->port.s,
		stream->rtcp_port.len, stream->rtcp_port.s,
		stream->transport.len, stream->transport.s, stream->is_rtp,
		stream->payloads.len, stream->payloads.s,
		stream->bw_type.len, stream->bw_type.s, stream->bw_width.len, stream->bw_width.s,
		stream->payloads_num, stream->payload_attr,
		stream->sendrecv_mode.len, stream->sendrecv_mode.s,
		stream->ptime.len, stream->ptime.s,
		stream->path.len, stream->path.s,
		stream->max_size.len, stream->max_size.s,
		stream->accept_types.len, stream->accept_types.s,
		stream->accept_wrapped_types.len, stream->accept_wrapped_types.s);
	payload = stream->payload_attr;
	while (payload) {
		LM_GEN1(level, "......payload[%d]:%p=>%p p_payload_attr[%d]:%p '%.*s' '%.*s' '%.*s' '%.*s' '%.*s'\n",
			payload->payload_num, payload, payload->next,
			payload->payload_num, stream->p_payload_attr[payload->payload_num],
			payload->rtp_payload.len, payload->rtp_payload.s,
			payload->rtp_enc.len, payload->rtp_enc.s,
			payload->rtp_clock.len, payload->rtp_clock.s,
			payload->rtp_params.len, payload->rtp_params.s,
			payload->fmtp_string.len, payload->fmtp_string.s);
		payload=payload->next;
	}
}

void print_sdp_session(sdp_session_cell_t *session, int level)
{
	sdp_stream_cell_t *stream = session==NULL ? NULL : session->streams;

	if (session==NULL) {
		LM_ERR("NULL session\n");
		return;
	}

	LM_GEN1(level, "..session[%d]:%p=>%p '%.*s' '%.*s' '%.*s' '%.*s:%.*s' (%d)=>%p\n",
		session->session_num, session, session->next,
		session->cnt_disp.len, session->cnt_disp.s,
		session->ip_addr.len, session->ip_addr.s,
		session->o_ip_addr.len, session->o_ip_addr.s,
		session->bw_type.len, session->bw_type.s, session->bw_width.len, session->bw_width.s,
		session->streams_num, session->streams);
	while (stream) {
		print_sdp_stream(stream, level);
		stream=stream->next;
	}
}


void print_sdp(sdp_info_t* sdp, int level)
{
	sdp_session_cell_t *session;

	LM_GEN1(level, "sdp:%p=>%p (%d:%d)\n", sdp, sdp->sessions, sdp->sessions_num, sdp->streams_num);
	session = sdp->sessions;
	while (session) {
		print_sdp_session(session, level);
		session = session->next;
	}
}

/*
 * Free cloned stream.
 */
void free_cloned_sdp_stream(sdp_stream_cell_t *_stream)
{
	sdp_stream_cell_t *stream, *l_stream;
	sdp_payload_attr_t *payload, *l_payload;

	stream = _stream;
	while (stream) {
		l_stream = stream;
		stream = stream->next;
		payload = l_stream->payload_attr;
		while (payload) {
			l_payload = payload;
			payload = payload->next;
			shm_free(l_payload);
		}
		if (l_stream->p_payload_attr) {
			shm_free(l_stream->p_payload_attr);
		}
		shm_free(l_stream);
	}
}

/*
 * Free cloned session.
 */
void free_cloned_sdp_session(sdp_session_cell_t *_session)
{
	sdp_session_cell_t *session, *l_session;

	session = _session;
	while (session) {
		l_session = session;
		session = l_session->next;
		free_cloned_sdp_stream(l_session->streams);
		shm_free(l_session);
	}
}

void free_cloned_sdp(sdp_info_t* sdp)
{
	free_cloned_sdp_session(sdp->sessions);
	shm_free(sdp);
}

sdp_payload_attr_t * clone_sdp_payload_attr(sdp_payload_attr_t *attr)
{
	sdp_payload_attr_t * clone_attr;
	int len;
	char *p;

	if (attr == NULL) {
		LM_ERR("arg:NULL\n");
		return NULL;
	}

	len = sizeof(sdp_payload_attr_t) +
			attr->rtp_payload.len +
			attr->rtp_enc.len +
			attr->rtp_clock.len +
			attr->rtp_params.len +
			attr->fmtp_string.len;
	clone_attr = (sdp_payload_attr_t*)shm_malloc(len);
	if (clone_attr == NULL) {
		LM_ERR("no more shm mem (%d)\n",len);
		return NULL;
	}
	memset( clone_attr, 0, len);
	p = (char*)(clone_attr+1);

	clone_attr->payload_num = attr->payload_num;

	if (attr->rtp_payload.len) {
		clone_attr->rtp_payload.s = p;
		clone_attr->rtp_payload.len = attr->rtp_payload.len;
		memcpy( p, attr->rtp_payload.s, attr->rtp_payload.len);
		p += attr->rtp_payload.len;
	}

	if (attr->rtp_enc.len) {
		clone_attr->rtp_enc.s = p;
		clone_attr->rtp_enc.len = attr->rtp_enc.len;
		memcpy( p, attr->rtp_enc.s, attr->rtp_enc.len);
		p += attr->rtp_enc.len;
	}

	if (attr->rtp_clock.len) {
		clone_attr->rtp_clock.s = p;
		clone_attr->rtp_clock.len = attr->rtp_clock.len;
		memcpy( p, attr->rtp_clock.s, attr->rtp_clock.len);
		p += attr->rtp_clock.len;
	}

	if (attr->rtp_params.len) {
		clone_attr->rtp_params.s = p;
		clone_attr->rtp_params.len = attr->rtp_params.len;
		memcpy( p, attr->rtp_params.s, attr->rtp_params.len);
		p += attr->rtp_params.len;
	}

	if (attr->fmtp_string.len) {
		clone_attr->fmtp_string.s = p;
		clone_attr->fmtp_string.len = attr->fmtp_string.len;
		memcpy( p, attr->fmtp_string.s, attr->fmtp_string.len);
		p += attr->fmtp_string.len;
	}

	return clone_attr;
}

sdp_stream_cell_t * clone_sdp_stream_cell(sdp_stream_cell_t *stream)
{
	sdp_stream_cell_t *clone_stream;
	sdp_payload_attr_t *clone_payload_attr, *payload_attr;
	int len, i;
	char *p;

	if (stream == NULL) {
		LM_ERR("arg:NULL\n");
		return NULL;
	}

	/* NOTE: we are not cloning RFC4975 attributes */
	len = sizeof(sdp_stream_cell_t) +
			stream->ip_addr.len +
			stream->media.len +
			stream->port.len +
			stream->transport.len +
			stream->sendrecv_mode.len +
			stream->ptime.len +
			stream->payloads.len +
			stream->bw_type.len +
			stream->bw_width.len +
			stream->rtcp_port.len;
	clone_stream = (sdp_stream_cell_t*)shm_malloc(len);
	if (clone_stream == NULL) {
		LM_ERR("no more shm mem (%d)\n",len);
		return NULL;
	}
	memset( clone_stream, 0, len);
	p = (char*)(clone_stream+1);

	payload_attr = NULL;
	for (i=0;i<stream->payloads_num;i++) {
		clone_payload_attr = clone_sdp_payload_attr(stream->p_payload_attr[i]);
		if (clone_payload_attr == NULL) {
			LM_ERR("unable to clone attributes for payload[%d]\n", i);
			goto error;
		}
		clone_payload_attr->next = payload_attr;
		payload_attr = clone_payload_attr;
	}
	clone_stream->payload_attr = payload_attr;

	clone_stream->payloads_num = stream->payloads_num;
	if (clone_stream->payloads_num) {
		if (NULL == init_p_payload_attr(clone_stream, USE_SHM_MEM)) {
			goto error;
		}
	}

	clone_stream->stream_num = stream->stream_num;
	clone_stream->pf = stream->pf;

	if (stream->ip_addr.len) {
		clone_stream->ip_addr.s = p;
		clone_stream->ip_addr.len = stream->ip_addr.len;
		memcpy( p, stream->ip_addr.s, stream->ip_addr.len);
		p += stream->ip_addr.len;
	}

	clone_stream->is_rtp = stream->is_rtp;

	if (stream->media.len) {
		clone_stream->media.s = p;
		clone_stream->media.len = stream->media.len;
		memcpy( p, stream->media.s, stream->media.len);
		p += stream->media.len;
	}

	if (stream->port.len) {
		clone_stream->port.s = p;
		clone_stream->port.len = stream->port.len;
		memcpy( p, stream->port.s, stream->port.len);
		p += stream->port.len;
	}

	if (stream->transport.len) {
		clone_stream->transport.s = p;
		clone_stream->transport.len = stream->transport.len;
		memcpy( p, stream->transport.s, stream->transport.len);
		p += stream->transport.len;
	}

	if (stream->sendrecv_mode.len) {
		clone_stream->sendrecv_mode.s = p;
		clone_stream->sendrecv_mode.len = stream->sendrecv_mode.len;
		memcpy( p, stream->sendrecv_mode.s, stream->sendrecv_mode.len);
		p += stream->sendrecv_mode.len;
	}

	if (stream->ptime.len) {
		clone_stream->ptime.s = p;
		clone_stream->ptime.len = stream->ptime.len;
		memcpy( p, stream->ptime.s, stream->ptime.len);
		p += stream->ptime.len;
	}

	if (stream->payloads.len) {
		clone_stream->payloads.s = p;
		clone_stream->payloads.len = stream->payloads.len;
		memcpy( p, stream->payloads.s, stream->payloads.len);
		p += stream->payloads.len;
	}

	if (stream->bw_type.len) {
		clone_stream->bw_type.s = p;
		clone_stream->bw_type.len = stream->bw_type.len;
		p += stream->bw_type.len;
	}

	if (stream->bw_width.len) {
		clone_stream->bw_width.s = p;
		clone_stream->bw_width.len = stream->bw_width.len;
		p += stream->bw_width.len;
	}

	if (stream->rtcp_port.len) {
		clone_stream->rtcp_port.s = p;
		clone_stream->rtcp_port.len = stream->rtcp_port.len;
		memcpy( p, stream->rtcp_port.s, stream->rtcp_port.len);
		p += stream->rtcp_port.len;
	}

	/* NOTE: we are not cloning RFC4975 attributes:
	 * - path
	 * - max_size
	 * - accept_types
	 * - accept_wrapped_types
	 */

	return clone_stream;
error:
	free_cloned_sdp_stream(clone_stream);
	return NULL;
}

sdp_session_cell_t * clone_sdp_session_cell(sdp_session_cell_t *session)
{
	sdp_session_cell_t *clone_session;
	sdp_stream_cell_t *clone_stream, *prev_clone_stream, *stream;
	int len, i;
	char *p;

	if (session == NULL) {
		LM_ERR("arg:NULL\n");
		return NULL;
	}
	len = sizeof(sdp_session_cell_t) +
		session->cnt_disp.len +
		session->ip_addr.len +
		session->o_ip_addr.len +
		session->bw_type.len +
		session->bw_width.len;
	clone_session = (sdp_session_cell_t*)shm_malloc(len);
	if (clone_session == NULL) {
		LM_ERR("no more shm mem (%d)\n",len);
		return NULL;
	}
	memset( clone_session, 0, len);
	p = (char*)(clone_session+1);

	if (session->streams_num) {
		stream=session->streams;
		clone_stream=clone_sdp_stream_cell(stream);
		if (clone_stream==NULL) {
			goto error;
		}
		clone_session->streams=clone_stream;
		prev_clone_stream=clone_stream;
		stream=stream->next;
		for (i=1;i<session->streams_num;i++) {
			clone_stream=clone_sdp_stream_cell(stream);
			if (clone_stream==NULL) {
				goto error;
			}
			prev_clone_stream->next=clone_stream;
			prev_clone_stream=clone_stream;
			stream=stream->next;
		}
	}

	clone_session->session_num = session->session_num;
	clone_session->pf = session->pf;
	clone_session->o_pf = session->o_pf;
	clone_session->streams_num = session->streams_num;

	if (session->cnt_disp.len) {
		clone_session->cnt_disp.s = p;
		clone_session->cnt_disp.len = session->cnt_disp.len;
		memcpy( p, session->cnt_disp.s, session->cnt_disp.len);
		p += session->cnt_disp.len;
	}

	if (session->ip_addr.len) {
		clone_session->ip_addr.s = p;
		clone_session->ip_addr.len = session->ip_addr.len;
		memcpy( p, session->ip_addr.s, session->ip_addr.len);
		p += session->ip_addr.len;
	}

	if (session->o_ip_addr.len) {
		clone_session->o_ip_addr.s = p;
		clone_session->o_ip_addr.len = session->o_ip_addr.len;
		memcpy( p, session->o_ip_addr.s, session->o_ip_addr.len);
		p += session->o_ip_addr.len;
	}

	if (session->bw_type.len) {
		clone_session->bw_type.s = p;
		clone_session->bw_type.len = session->bw_type.len;
		memcpy( p, session->bw_type.s, session->bw_type.len);
		p += session->bw_type.len;
	}

	if (session->bw_width.len) {
		clone_session->bw_width.s = p;
		clone_session->bw_width.len = session->bw_width.len;
		memcpy( p, session->bw_width.s, session->bw_width.len);
		p += session->bw_width.len;
	}

	return clone_session;
error:
	free_cloned_sdp_session(clone_session);
	return NULL;
}

sdp_info_t * clone_sdp_info(sdp_info_t *sdp_info)
{
	sdp_info_t *clone_sdp_info;
	sdp_session_cell_t *clone_session, *prev_clone_session, *session;
	int i, len;

	if (sdp_info==NULL) {
		LM_ERR("no sdp to clone\n");
		return NULL;
	}
	if (sdp_info->sessions_num == 0) {
		LM_ERR("no sessions to clone\n");
		return NULL;
	}

	len = sizeof(sdp_info_t);
	clone_sdp_info = (sdp_info_t*)shm_malloc(len);
	if (clone_sdp_info == NULL) {
		LM_ERR("no more shm mem (%d)\n",len);
		return NULL;
	}
	LM_DBG("clone_sdp_info: %p\n", clone_sdp_info);
	memset( clone_sdp_info, 0, len);
	LM_DBG("we have %d sessions\n", sdp_info->sessions_num);
	clone_sdp_info->sessions_num = sdp_info->sessions_num;
	clone_sdp_info->streams_num = sdp_info->streams_num;

	session=sdp_info->sessions;
	clone_session=clone_sdp_session_cell(session);
	if (clone_session==NULL) {
		goto error;
	}
	clone_sdp_info->sessions=clone_session;
	prev_clone_session=clone_session;
	session=session->next;
	for (i=1;i<sdp_info->sessions_num;i++) {
		clone_session=clone_sdp_session_cell(session);
		if (clone_session==NULL) {
			goto error;
		}
		prev_clone_session->next=clone_session;
		prev_clone_session=clone_session;
		session=session->next;
	}

	return clone_sdp_info;
error:
	free_cloned_sdp(clone_sdp_info);
	return NULL;
}

