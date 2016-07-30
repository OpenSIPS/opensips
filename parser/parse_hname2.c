/*
 * Fast 32-bit Header Field Name Parser
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
 * 2003-02-28 scratchpad compatibility abandoned (jiri)
 * 2003-01-27 next baby-step to removing ZT - PRESERVE_ZT (jiri)
 * 2003-05-01 added support for Accept HF (janakj)
 * 2006-02-17 Session-Expires, Min-SE (dhsueh@somanetworks.com)
 */


#include "parse_hname2.h"
#include "keys.h"
#include "../ut.h"  /* q_memchr */

#define LOWER_BYTE(b) ((b) | 0x20)
#define LOWER_DWORD(d) ((d) | 0x20202020)

/*
 * Skip all white-chars and return position of the first
 * non-white char
 */
static inline char* skip_ws(char* p, char *end)
{
	for(; p < end; p++) {
		if ((*p != ' ') && (*p != '\t')) return p;
	}
	return p;
}

/*
 * Parser macros
 */
#include "case_via.h"      /* Via */
#include "case_from.h"     /* From */
#include "case_to.h"       /* To */
#include "case_cseq.h"     /* CSeq */
#include "case_call.h"     /* Call-ID */
#include "case_cont.h"     /* Contact, Content-Type, Content-Length,
                              Content-Purpose, Content-Action,
                              Content-Disposition */
#include "case_rout.h"     /* Route */
#include "case_max.h"      /* Max-Forwards */
#include "case_reco.h"     /* Record-Route */
#include "case_path.h"     /* Path */
#include "case_auth.h"     /* Authorization */
#include "case_expi.h"     /* Expires */
#include "case_prox.h"     /* Proxy-Authorization, Proxy-Require */
#include "case_allo.h"     /* Allow */
#include "case_unsu.h"     /* Unsupported */
#include "case_even.h"     /* Event */
#include "case_acce.h"     /* Accept, Accept-Language */
#include "case_orga.h"     /* Organization */
#include "case_prio.h"     /* Priority */
#include "case_subj.h"     /* Subject */
#include "case_user.h"     /* User-Agent */
#include "case_supp.h"     /* Supported */
#include "case_dive.h"     /* Diversion */
#include "case_remo.h"     /* Remote-Party-ID */
#include "case_refe.h"     /* Refer-To */
#include "case_sess.h"     /* Session-Expires */
#include "case_min_.h"     /* Min-SE */
#include "case_p_pr.h"     /* P-Preferred-Identity */
#include "case_p_as.h"     /* P-Asserted-Identity */
#include "case_priv.h"     /* Privacy */
#include "case_retr.h"     /* Retry-After */
#include "case_www.h"      /* WWW-Authenticate */


#define READ(val) \
(*(val + 0) + (*(val + 1) << 8) + (*(val + 2) << 16) + (*(val + 3) << 24))


#define FIRST_QUATERNIONS       \
	case _via1_: via1_CASE; \
	case _from_: from_CASE; \
	case _to12_: to12_CASE; \
	case _cseq_: cseq_CASE; \
	case _call_: call_CASE; \
	case _cont_: cont_CASE; \
	case _rout_: rout_CASE; \
	case _max__: max_CASE;  \
	case _reco_: reco_CASE; \
	case _via2_: via2_CASE; \
	case _auth_: auth_CASE; \
	case _supp_: supp_CASE; \
	case _expi_: expi_CASE; \
	case _prox_: prox_CASE; \
	case _allo_: allo_CASE; \
	case _path_: path_CASE; \
	case _unsu_: unsu_CASE; \
	case _even_: even_CASE; \
	case _acce_: acce_CASE; \
	case _orga_: orga_CASE; \
	case _prio_: prio_CASE; \
	case _subj_: subj_CASE; \
	case _user_: user_CASE; \
	case _dive_: dive_CASE; \
	case _remo_: remo_CASE; \
	case _refe_: refe_CASE; \
	case _sess_: sess_CASE; \
	case _min__: min__CASE; \
	case _p_pr_: p_pr_CASE; \
	case _p_as_: p_as_CASE; \
	case _priv_: priv_CASE; \
	case _retr_: retr_CASE; \
	case _www__: www_CASE;  \


#define PARSE_COMPACT(id)      \
	switch(*(p + 1)) {         \
		case ' ':              \
		case '\t':             \
			hdr->type = id;    \
			hdr->name.len = 1; \
			p += 2;            \
			goto dc_end;       \
		case ':':              \
			hdr->type = id;    \
			hdr->name.len = 1; \
	 		return (p + 2);    \
	}


char* parse_hname2(char* begin, char* end, struct hdr_field* hdr)
{
	register char* p;
	register unsigned int val;

	if ((end - begin) < 4) {
		hdr->type = HDR_ERROR_T;
		return begin;
	}

	p = begin;

	val = LOWER_DWORD(READ(p));
	hdr->name.s = begin;

	switch(val) {

		FIRST_QUATERNIONS;

		default:
			switch(LOWER_BYTE(*p)) {
				case 't':
					switch(LOWER_BYTE(*(p + 1))) {
						case 'o':
							p += 2;
							hdr->type = HDR_TO_T;
							hdr->name.len = 2;
							goto dc_cont;
						case ' ':
						case '\t':
							p += 2;
							hdr->type = HDR_TO_T;
							hdr->name.len = 1;
							goto dc_end;
						case ':':
							hdr->type = HDR_TO_T;
							hdr->name.len = 1;
							return (p + 2);
					}
					break;
				case 'v': PARSE_COMPACT(HDR_VIA_T);           break;
				case 'f': PARSE_COMPACT(HDR_FROM_T);          break;
				case 'i': PARSE_COMPACT(HDR_CALLID_T);        break;
				case 'm': PARSE_COMPACT(HDR_CONTACT_T);       break;
				case 'l': PARSE_COMPACT(HDR_CONTENTLENGTH_T); break;
				case 'k': PARSE_COMPACT(HDR_SUPPORTED_T);     break;
				case 'c': PARSE_COMPACT(HDR_CONTENTTYPE_T);   break;
				case 'o': PARSE_COMPACT(HDR_EVENT_T);         break;
				case 'x': PARSE_COMPACT(HDR_SESSION_EXPIRES_T); break;
			}
			goto other;
	}
	/* the above swtich will never continue here */


 dc_end:
	/* HDR name entirely found, consume WS till colon */
	/* overflow during the "switch-case" parsing ? */
	if (p>=end)
		goto error;
	p = skip_ws(p, end);
	if (*p != ':')
		goto error;
	/* hdr type, name should be already set at this point */
	return (p+1);
	/*done*/


 dc_cont:
	/* HDR name partially found, see what's next */
	/* overflow during the "switch-case" parsing ? */
	if (p>=end)
		goto error;
	/* hdr type, name should be already set at this point (for partial finding) */
	switch (*p) {
		case ':' :
			return (p+1);
		case ' ':
		case '\t':
			/* consume spaces to the end of name */
			p = skip_ws( p+1, end);
			if (*p != ':')
				goto error;
			return (p+1);
		/* default: it seems the hdr name continues, fall to "other" */
	}


 other:
	/* Unknown header type */
	hdr->type = HDR_OTHER_T;
	/* if overflow during the "switch-case" parsing, the "while" will
	 * exit and we will fall in the "error" section */
	while ( p < end ) {
		switch (*p) {
			case ':' :
				hdr->name.len = p - hdr->name.s;
				return (p + 1);
			case ' ' :
			case '\t':
				hdr->name.len = p - hdr->name.s;
				p = skip_ws(p+1, end);
				if (*p != ':')
					goto error;
				return (p+1);
		}
		p++;
	}

 error:
	/* No double colon found, error.. */
	hdr->type = HDR_ERROR_T;
	hdr->name.s = 0;
	hdr->name.len = 0;
	return 0;
}
