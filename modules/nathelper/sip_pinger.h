/*
 * Copyright (C) 2005 Voice System SRL
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
 * History:
 * ---------
 * 2005-07-11  created (bogdan)
 */


#ifndef NATHELPER_OPTIONS_H_
#define NATHELPER_OPTIONS_H_

#include <stdlib.h>
#include <string.h>

#include "../../parser/parse_rr.h"
#include "../../str.h"
#include "../../ut.h"
#include "../../ip_addr.h"
#include "nh_table.h"

/* size of buffer used for building SIP PING req */
#define MAX_SIPPING_SIZE 65536

/* maximum number of hops */
#define MAX_FORWARD "70"

/* branch magic */
#define BMAGIC "z9hG4bK"
#define BMAGIC_LEN (sizeof(BMAGIC) - 1)

#define BSTART ";branch="


/* helping macros for building SIP PING ping request */
#define append_str( _p, _s) \
	do {\
		memcpy(_p,(_s).s,(_s).len);\
		_p += (_s).len;\
	}while(0)

#define append_fix( _p, _s) \
	do {\
		memcpy(_p, _s, sizeof(_s)-1);\
		_p += sizeof(_s)-1;\
	}while(0)

/* info used to generate SIP ping requests */
static int  sipping_fromtag = 0;
static char sipping_callid_buf[8];
static int  sipping_callid_cnt = 0;
static str  sipping_callid = {0,0};
static str  sipping_from = {0,0};
static str  sipping_method = {"OPTIONS",7};


static void init_sip_ping(void)
{
	int len;
	char *p;

	/* FROM tag - some random number */
	sipping_fromtag = rand();
	/* callid fix part - hexa string */
	len = 8;
	p = sipping_callid_buf;
	int2reverse_hex( &p, &len, rand() );
	sipping_callid.s = sipping_callid_buf;
	sipping_callid.len = 8-len;
	/* callid counter part */
	sipping_callid_cnt = rand();
}


static int parse_branch(str branch)
{
	int hash_id, label;
	char *end;

	if (branch.len < BMAGIC_LEN
			&& memcmp(branch.s, BMAGIC, BMAGIC_LEN)) {
		LM_ERR("invalid branch\n");
		return -1;
	}

	branch.s += BMAGIC_LEN;
	branch.len -= BMAGIC_LEN;

	end = q_memchr(branch.s, '.', branch.len);
	if (0 == end)
		return 1;

	hash_id = reverse_hex2int(branch.s, end-branch.s);

	branch.len -= (end-branch.s + 1);
	branch.s = end+1;

	label = reverse_hex2int(branch.s, branch.len);

	if (label > 0)
		/* removes also the current cell */
		remove_older_cells(hash_id, label);

	return 0;
}

static int sipping_rpl_filter(struct sip_msg *rpl)
{
	struct cseq_body* cseq_b;

	/* first check number of vias -> must be only one */
	if (parse_headers( rpl, HDR_VIA2_F, 0 )==-1 || (rpl->via2!=0))
		goto skip;

	/* check the method -> we need CSeq header */
	if ( (!rpl->cseq && parse_headers(rpl,HDR_CSEQ_F,0)!=0) || rpl->cseq==0 ) {
		LM_ERR("failed to parse CSeq\n");
		goto error;
	}
	cseq_b = (struct cseq_body*)rpl->cseq->parsed;
	if (cseq_b->method.len!=sipping_method.len ||
	strncmp(cseq_b->method.s,sipping_method.s,sipping_method.len)!=0)
		goto skip;

	/* check constant part of callid */
	if ( (!rpl->callid && parse_headers(rpl,HDR_CALLID_F,0)!=0) ||
	rpl->callid==0 ) {
		LM_ERR("failed to parse Call-ID\n");
		goto error;
	}
	if ( rpl->callid->body.len<=sipping_callid.len+1 ||
	strncmp(rpl->callid->body.s,sipping_callid.s,sipping_callid.len)!=0 ||
	rpl->callid->body.s[sipping_callid.len]!='-')
		goto skip;

	LM_DBG("reply for SIP natping filtered\n");
	/* it's a reply to a SIP NAT ping -> absorb it and stop any
	 * further processing of it */
	if (parse_branch(rpl->via1->branch->value))
			goto skip;

	return 0;
skip:
	return 1;
error:
	return -1;
}


/*
 */

static inline int
build_branch(char *branch, int *size,
		str *curi, udomain_t *d, uint64_t contact_id, int rm_on_to)
{

	int hash_id;
	int label;
	struct ping_cell *p_cell;

	/* we want all contact pings from a contact in one bucket*/
	hash_id = core_hash(curi, 0, 0) & (NH_TABLE_ENTRIES-1);

	if (rm_on_to) {
		if (0 == (p_cell = build_p_cell(d, contact_id)))
			goto out_memfault;
		insert_into_hash(p_cell, hash_id);
		label = p_cell->label;
	} else {
		label = 0;
	}

	memcpy( branch, BMAGIC, BMAGIC_LEN);

	branch += BMAGIC_LEN;

	int2reverse_hex(&branch, size, hash_id);

	*branch = '.';
	branch++;

	int2reverse_hex(&branch, size, label);
	*branch = '\0';

	return 0;

out_memfault:
	LM_ERR("no more shared memory\n");
	return -1;
}



/* build the buffer of a SIP ping request */
static inline char*
build_sipping(udomain_t *d, str *curi, struct socket_info* s,str *path,
		int *len_p, uint64_t contact_id, int rm_on_to)
{
#define s_len(_s) (sizeof(_s)-1)
	static char buf[MAX_SIPPING_SIZE];
	char *p, proto_str[4];
	str address, port;
	str st;
	int len;

	int  bsize = 100;
	str  sbranch;
	char branch[100];
	char *bbuild = branch;

	memcpy(bbuild, BSTART, sizeof(BSTART) - 1);
	bbuild += sizeof(BSTART) - 1;
	bsize -= (bbuild - branch);

	build_branch( bbuild, &bsize, curi, d, contact_id, rm_on_to);

	sbranch.s = branch;
	sbranch.len = strlen(branch);

	p = proto2str(s->proto, proto_str);
	*(p++) = ' ';
	st.s = proto_str;
	st.len = p - proto_str;

	if (s->adv_name_str.len)
		address = s->adv_name_str;
	else if (default_global_address.len)
		address = default_global_address;
	else
		address = s->address_str;
	if (s->adv_port_str.len)
		port = s->adv_port_str;
	else if (default_global_port.len)
		port = default_global_port;
	else
		port = s->port_no_str;

	/* quick proto uppercase */
	*((int *)st.s) &= ~((1 << 21) | (1 << 13) | (1 << 5));

	if ( sipping_method.len + 1 + curi->len + s_len(" SIP/2.0"CRLF) +
		s_len("Via: SIP/2.0/") + st.len + address.len +
		1 + port.len + strlen(branch) +
		(path->len ? (s_len(CRLF"Route: ") + path->len) : 0) +
		s_len(CRLF"From: ") +  sipping_from.len + s_len(";tag=") + 8 +
		s_len(CRLF"To: ") + curi->len +
		s_len(CRLF"Call-ID: ") + sipping_callid.len + 1 + 8 + 1 + 8 + 1 +
		address.len +
		s_len(CRLF"CSeq: 1 ") + sipping_method.len +
		s_len(CRLF"Max-Forwards: "MAX_FORWARD) +
		s_len(CRLF"Content-Length: 0" CRLF CRLF)
		> MAX_SIPPING_SIZE )
	{
		LM_ERR("len exceeds %d\n",MAX_SIPPING_SIZE);
		return 0;
	}

	p = buf;
	append_str( p, sipping_method);
	*(p++) = ' ';
	append_str( p, *curi);
	append_fix( p, " SIP/2.0"CRLF"Via: SIP/2.0/");
	append_str( p, st);
	append_str( p, address);
	*(p++) = ':';
	append_str( p, port);
	append_str( p, sbranch);
	if (path->len) {
		append_fix( p, CRLF"Route: ");
		append_str( p, *path);
	}
	append_fix( p, CRLF"From: ");
	append_str( p, sipping_from);
	append_fix( p, ";tag=");
	len = 8;
	int2reverse_hex( &p, &len, sipping_fromtag++ );
	append_fix( p, CRLF"To: ");
	append_str( p, *curi);
	append_fix( p, CRLF"Call-ID: ");
	append_str( p, sipping_callid);
	*(p++) = '-';
	len = 8;
	int2reverse_hex( &p, &len, sipping_callid_cnt++ );
	*(p++) = '-';
	len = 8;
	int2reverse_hex( &p, &len, get_ticks() );
	*(p++) = '@';
	append_str( p, address);
	append_fix( p, CRLF"CSeq: 1 ");
	append_str( p, sipping_method);
	append_fix( p, CRLF"Max-Forwards: "MAX_FORWARD);
	append_fix( p, CRLF"Content-Length: 0" CRLF CRLF);

	*len_p = p - buf;
	return buf;
}

#endif
