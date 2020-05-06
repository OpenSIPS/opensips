/*
 * Send a reply
 *
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
 * --------
 * 2003-01-18: buffer overflow patch committed (Jan on behalf of Maxim)
 * 2003-01-21: Errors reported via Error-Info header field - janakj
 * 2003-09-11: updated to new build_lump_rpl() interface (bogdan)
 * 2003-11-11: build_lump_rpl() removed, add_lump_rpl() has flags (bogdan)
 */

/*!
 * \file
 * \brief SIP registrar module - Send a reply
 * \ingroup registrar
 */

#include <stdio.h>

#include "../../ut.h"
#include "../../parser/msg_parser.h"
#include "../../parser/parse_supported.h"
#include "../../data_lump_rpl.h"
#include "../../lib/reg/common.h"

#include "../usrloc/usrloc.h"

#include "reg_mod.h"
#include "reply.h"


#define MAX_CONTACT_BUFFER 1024

#define E_INFO "P-Registrar-Error: "
#define E_INFO_LEN (sizeof(E_INFO) - 1)

#define CONTACT_BEGIN "Contact: "
#define CONTACT_BEGIN_LEN (sizeof(CONTACT_BEGIN) - 1)

#define Q_PARAM ";q="
#define Q_PARAM_LEN (sizeof(Q_PARAM) - 1)

#define EXPIRES_PARAM ";expires="
#define EXPIRES_PARAM_LEN (sizeof(EXPIRES_PARAM) - 1)

#define SIP_PROTO "sip:"
#define SIP_PROTO_SIZE (sizeof(SIP_PROTO) - 1)

#define PUB_GRUU ";pub-gruu="
#define PUB_GRUU_SIZE (sizeof(PUB_GRUU) - 1)

#define TEMP_GRUU ";temp-gruu="
#define TEMP_GRUU_SIZE (sizeof(TEMP_GRUU) - 1)

#define SIP_INSTANCE ";+sip.instance="
#define SIP_INSTANCE_SIZE (sizeof(SIP_INSTANCE) - 1)

#define TEMP_GRUU_HEADER "tgruu."
#define TEMP_GRUU_HEADER_SIZE (sizeof(TEMP_GRUU_HEADER) - 1)

#define GR_PARAM ";gr="
#define GR_PARAM_SIZE (sizeof(GR_PARAM) - 1)

#define GR_NO_VAL ";gr"
#define GR_NO_VAL_SIZE (sizeof(GR_NO_VAL) - 1)

#define CONTACT_SEP ", "
#define CONTACT_SEP_LEN (sizeof(CONTACT_SEP) - 1)

str default_gruu_secret=str_init("0p3nS1pS");

/*! \brief
 * Buffer for Contact header field
 */
static struct {
	char* buf;
	int buf_len;
	int data_len;
} contact = {0, 0, 0};


static inline int calc_temp_gruu_len(str* aor,str* instance,str *callid)
{
	int time_len,temp_gr_len;

	int2str((unsigned long)get_act_time(),&time_len);
	temp_gr_len = time_len + aor->len + instance->len - 2 + callid->len + 3; /* <instance> and blank spaces */
	temp_gr_len = (temp_gr_len/3 + (temp_gr_len%3?1:0))*4; /* base64 encoding */
	return temp_gr_len;
}

/*! \brief
 * Calculate the length of buffer needed to
 * print contacts
 */
static inline unsigned int calc_buf_len(ucontact_t* c,int build_gruu,
		struct sip_msg *_m)
{
	unsigned int len;
	int qlen;
	struct socket_info *sock;

	len = 0;
	while(c) {
		if (VALID_CONTACT(c, get_act_time())) {
			if (len) len += CONTACT_SEP_LEN;
			len += 2 /* < > */ + c->c.len;
			qlen = len_q(c->q);
			if (qlen) len += Q_PARAM_LEN + qlen;
			len += EXPIRES_PARAM_LEN + INT2STR_MAX_LEN;
			if (c->received.s) {
				len += 1 /* ; */
					+ rcv_param.len
					+ 1 /* = */
					+ 1 /* dquote */
					+ c->received.len
					+ 1 /* dquote */
					;
			}
			if (build_gruu && c->instance.s) {
				sock = (c->sock)?(c->sock):(_m->rcv.bind_address);
				/* pub gruu */
				len += PUB_GRUU_SIZE
					+ 1 /* quote */
					+ SIP_PROTO_SIZE
					+ c->aor->len
					+ (reg_use_domain ?0:(1 /* @ */ + sock->name.len + 1 /* : */ + sock->port_no_str.len))
					+ GR_PARAM_SIZE
					+ (c->instance.len - 2)
					+ 1 /* quote */
					;
				/* temp gruu */
				len += TEMP_GRUU_SIZE
					+ 1 /* quote */
					+ SIP_PROTO_SIZE
					+ TEMP_GRUU_HEADER_SIZE
					+ calc_temp_gruu_len(c->aor,&c->instance,&c->callid)
					+ 1 /* @ */
					+ sock->name.len
					+ 1 /* : */
					+ sock->port_no_str.len
					+ GR_NO_VAL_SIZE
					+ 1 /* quote */
					;
				/* sip.instance */
				len += SIP_INSTANCE_SIZE
					+ 1 /* quote */
					+ (c->instance.len - 2)
					+ 1 /* quote */
					;
			}
		}
		c = c->next;
	}

	if (len) len += CONTACT_BEGIN_LEN + CRLF_LEN;
	return len;
}

#define MAX_TEMP_GRUU_SIZE	255
static char temp_gruu_buf[MAX_TEMP_GRUU_SIZE];

/* Returns memory from a statically allocated buffer */
char * build_temp_gruu(str *aor,str *instance,str *callid,int *len)
{
	int time_len,i;
	char *p;
	char *time_str = int2str((unsigned long)get_act_time(),&time_len);
	str *magic;

	*len = time_len + aor->len + instance->len + callid->len + 3 - 2; /* +3 blank spaces, -2 discarded chars of instance in memcpy below */
	p = temp_gruu_buf;

	memcpy(p,time_str,time_len);
	p+=time_len;
	*p++=' ';

	memcpy(p,aor->s,aor->len);
	p+=aor->len;
	*p++=' ';

	memcpy(p,instance->s+1,instance->len-2);
	p+=instance->len-2;
	*p++=' ';

	memcpy(p,callid->s,callid->len);

	LM_DBG("build temp gruu [%.*s]\n",*len,temp_gruu_buf);
	if (gruu_secret.s != NULL)
		magic = &gruu_secret;
	else
		magic = &default_gruu_secret;

	for (i=0;i<*len;i++)
		temp_gruu_buf[i] ^= magic->s[i%magic->len];
	return temp_gruu_buf;
}

/*! \brief
 * Allocate a memory buffer and print Contact
 * header fields into it
 */
int build_contact(ucontact_t* c,struct sip_msg *_m)
{
	char *p, *cp, *tmpgr;
	int fl, len,grlen;
	int build_gruu = 0;
	struct socket_info *sock;

	if (!disable_gruu && _m->supported && parse_supported(_m) == 0 &&
		(get_supported(_m) & F_SUPPORTED_GRUU))
		build_gruu=1;

	contact.data_len = calc_buf_len(c,build_gruu,_m);
	if (!contact.data_len) return 0;

	if (!contact.buf || (contact.buf_len < contact.data_len)) {
		if (contact.buf) pkg_free(contact.buf);
		contact.buf = (char*)pkg_malloc(contact.data_len);
		if (!contact.buf) {
			contact.data_len = 0;
			contact.buf_len = 0;
			LM_ERR("no pkg memory left\n");
			return -1;
		} else {
			contact.buf_len = contact.data_len;
		}
	}

	p = contact.buf;

	memcpy(p, CONTACT_BEGIN, CONTACT_BEGIN_LEN);
	p += CONTACT_BEGIN_LEN;

	fl = 0;
	while(c) {
		if (VALID_CONTACT(c, get_act_time())) {
			if (fl) {
				memcpy(p, CONTACT_SEP, CONTACT_SEP_LEN);
				p += CONTACT_SEP_LEN;
			} else {
				fl = 1;
			}

			*p++ = '<';
			memcpy(p, c->c.s, c->c.len);
			p += c->c.len;
			*p++ = '>';

			len = len_q(c->q);
			if (len) {
				memcpy(p, Q_PARAM, Q_PARAM_LEN);
				p += Q_PARAM_LEN;
				memcpy(p, q2str(c->q, 0), len);
				p += len;
			}

			memcpy(p, EXPIRES_PARAM, EXPIRES_PARAM_LEN);
			p += EXPIRES_PARAM_LEN;
			cp = int2str((int)(c->expires - get_act_time()), &len);
			memcpy(p, cp, len);
			p += len;

			if (c->received.s) {
				*p++ = ';';
				memcpy(p, rcv_param.s, rcv_param.len);
				p += rcv_param.len;
				*p++ = '=';
				*p++ = '\"';
				memcpy(p, c->received.s, c->received.len);
				p += c->received.len;
				*p++ = '\"';
			}

			if (build_gruu && c->instance.s) {
				sock = (c->sock)?(c->sock):(_m->rcv.bind_address);
				/* build pub GRUU */
				memcpy(p,PUB_GRUU,PUB_GRUU_SIZE);
				p += PUB_GRUU_SIZE;
				*p++ = '\"';
				memcpy(p,SIP_PROTO,SIP_PROTO_SIZE);
				p += SIP_PROTO_SIZE;
				memcpy(p,c->aor->s,c->aor->len);
				p += c->aor->len;
				if (!reg_use_domain) {
					*p++ = '@';
					memcpy(p,sock->name.s,sock->name.len);
					p += sock->name.len;
					*p++ = ':';
					memcpy(p,sock->port_no_str.s,sock->port_no_str.len);
					p += sock->port_no_str.len;
				}
				memcpy(p,GR_PARAM,GR_PARAM_SIZE);
				p += GR_PARAM_SIZE;
				memcpy(p,c->instance.s+1,c->instance.len-2);
				p += c->instance.len-2;
				*p++ = '\"';

				/* build temp GRUU */
				memcpy(p,TEMP_GRUU,TEMP_GRUU_SIZE);
				p += TEMP_GRUU_SIZE;
				*p++ = '\"';
				memcpy(p,SIP_PROTO,SIP_PROTO_SIZE);
				p += SIP_PROTO_SIZE;
				memcpy(p,TEMP_GRUU_HEADER,TEMP_GRUU_HEADER_SIZE);
				p += TEMP_GRUU_HEADER_SIZE;

				tmpgr = build_temp_gruu(c->aor,&c->instance,&c->callid,&grlen);
				base64encode((unsigned char *)p,
						(unsigned char *)tmpgr,grlen);
				p += calc_temp_gruu_len(c->aor,&c->instance,&c->callid);
				*p++ = '@';
				memcpy(p,sock->name.s,sock->name.len);
				p += sock->name.len;
				*p++ = ':';
				memcpy(p,sock->port_no_str.s,sock->port_no_str.len);
				p += sock->port_no_str.len;
				memcpy(p,GR_NO_VAL,GR_NO_VAL_SIZE);
				p += GR_NO_VAL_SIZE;
				*p++ = '\"';

				/* build +sip.instance */
				memcpy(p,SIP_INSTANCE,SIP_INSTANCE_SIZE);
				p += SIP_INSTANCE_SIZE;
				*p++ = '\"';
				memcpy(p,c->instance.s+1,c->instance.len-2);
				p += c->instance.len-2;
				*p++ = '\"';
			}
		}

		c = c->next;
	}

	memcpy(p, CRLF, CRLF_LEN);
	p += CRLF_LEN;

	contact.data_len = p - contact.buf;

	LM_DBG("created Contact HF: %.*s\n", contact.data_len, contact.buf);
	return 0;
}


#define RETRY_AFTER "Retry-After: "
#define RETRY_AFTER_LEN (sizeof(RETRY_AFTER) - 1)

static int add_retry_after(struct sip_msg* _m)
{
	char* buf, *ra_s;
 	int ra_len;

 	ra_s = int2str(retry_after, &ra_len);
 	buf = (char*)pkg_malloc(RETRY_AFTER_LEN + ra_len + CRLF_LEN);
 	if (!buf) {
 		LM_ERR("no pkg memory left\n");
 		return -1;
 	}
 	memcpy(buf, RETRY_AFTER, RETRY_AFTER_LEN);
 	memcpy(buf + RETRY_AFTER_LEN, ra_s, ra_len);
 	memcpy(buf + RETRY_AFTER_LEN + ra_len, CRLF, CRLF_LEN);
 	add_lump_rpl(_m, buf, RETRY_AFTER_LEN + ra_len + CRLF_LEN,
 		     LUMP_RPL_HDR | LUMP_RPL_NODUP);
 	return 0;
}

#define PATH "Path: "
#define PATH_LEN (sizeof(PATH) - 1)

static int add_path(struct sip_msg* _m, str* _p)
{
	char* buf;

 	buf = (char*)pkg_malloc(PATH_LEN + _p->len + CRLF_LEN);
 	if (!buf) {
 		LM_ERR("no pkg memory left\n");
 		return -1;
 	}
 	memcpy(buf, PATH, PATH_LEN);
 	memcpy(buf + PATH_LEN, _p->s, _p->len);
 	memcpy(buf + PATH_LEN + _p->len, CRLF, CRLF_LEN);
 	add_lump_rpl(_m, buf, PATH_LEN + _p->len + CRLF_LEN,
 		     LUMP_RPL_HDR | LUMP_RPL_NODUP);
 	return 0;
}

#define UNSUPPORTED "Unsupported: "
#define UNSUPPORTED_LEN (sizeof(UNSUPPORTED) - 1)

static int add_unsupported(struct sip_msg* _m, str* _p)
{
	char* buf;

 	buf = (char*)pkg_malloc(UNSUPPORTED_LEN + _p->len + CRLF_LEN);
 	if (!buf) {
 		LM_ERR("no pkg memory left\n");
 		return -1;
 	}
 	memcpy(buf, UNSUPPORTED, UNSUPPORTED_LEN);
 	memcpy(buf + UNSUPPORTED_LEN, _p->s, _p->len);
 	memcpy(buf + UNSUPPORTED_LEN + _p->len, CRLF, CRLF_LEN);
 	add_lump_rpl(_m, buf, UNSUPPORTED_LEN + _p->len + CRLF_LEN,
 		     LUMP_RPL_HDR | LUMP_RPL_NODUP);
 	return 0;
}

/*! \brief
 * Send a reply
 */
int send_reply(struct sip_msg* _m, unsigned int _flags)
{
	str unsup = str_init(SUPPORTED_PATH_STR);
	long code;
	str msg = str_init(MSG_200); /* makes gcc shut up */
	char* buf;

	if (contact.data_len > 0) {
		add_lump_rpl( _m, contact.buf, contact.data_len, LUMP_RPL_HDR|LUMP_RPL_NODUP|LUMP_RPL_NOFREE);
		contact.data_len = 0;
	}

	if (rerrno == R_FINE && (_flags&REG_SAVE_PATH_FLAG) && _m->path_vec.s) {
		if ( (_flags&REG_SAVE_PATH_OFF_FLAG)==0 ) {
			if (parse_supported(_m)<0 && (_flags&REG_SAVE_PATH_STRICT_FLAG)) {
				rerrno = R_PATH_UNSUP;
				if (add_unsupported(_m, &unsup) < 0)
					return -1;
				if (add_path(_m, &_m->path_vec) < 0)
					return -1;
			}
			else if (get_supported(_m) & F_SUPPORTED_PATH) {
				if (add_path(_m, &_m->path_vec) < 0)
					return -1;
			} else if ((_flags&REG_SAVE_PATH_STRICT_FLAG)) {
				rerrno = R_PATH_UNSUP;
				if (add_unsupported(_m, &unsup) < 0)
					return -1;
				if (add_path(_m, &_m->path_vec) < 0)
					return -1;
			}
		}
	}

	if (pn_enable)
		pn_append_rpl_fcaps(_m);

	code = rerr_codes[rerrno];
	switch (code) {
	case 200: init_str(&msg, MSG_200); break;
	case 400: init_str(&msg, MSG_400); break;
	case 420: init_str(&msg, MSG_420); break;
	case 500: init_str(&msg, MSG_500); break;
	case 503: init_str(&msg, MSG_503); break;
	case 555: init_str(&msg, MSG_555); break;
	}

	if (code != 200) {
		buf = (char*)pkg_malloc(E_INFO_LEN + error_info[rerrno].len + CRLF_LEN + 1);
		if (!buf) {
			LM_ERR("no pkg memory left\n");
			return -1;
		}
		memcpy(buf, E_INFO, E_INFO_LEN);
		memcpy(buf + E_INFO_LEN, error_info[rerrno].s, error_info[rerrno].len);
		memcpy(buf + E_INFO_LEN + error_info[rerrno].len, CRLF, CRLF_LEN);
		add_lump_rpl( _m, buf, E_INFO_LEN + error_info[rerrno].len + CRLF_LEN,
			LUMP_RPL_HDR|LUMP_RPL_NODUP);

		if (code >= 500 && code < 600 && retry_after) {
			if (add_retry_after(_m) < 0) {
				return -1;
			}
		}
	}

	if (sigb.reply(_m, code, &msg, NULL) == -1) {
		LM_ERR("failed to send %ld %.*s\n", code, msg.len,msg.s);
		return -1;
	} else return 0;
}


/*! \brief
 * Release contact buffer if any
 */
void free_contact_buf(void)
{
	if (contact.buf) {
		pkg_free(contact.buf);
		contact.buf = 0;
		contact.buf_len = 0;
		contact.data_len = 0;
	}
}
