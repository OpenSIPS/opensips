/*
 * $Id$
 *
 * Route & Record-Route module
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * -------
 * 2003-04-04 Extracted from common.[ch] (janakj)
 * 2005-04-10 add_rr_param() function and all corresponing hooks added (bogdan)
 * 2006-02-14 record_route may take as param a string to be used as RR param;
 *            record_route and record_route_preset accept pseudo-variables in
 *            parameters; add_rr_param may be called from BRANCH and FAILURE
 *            routes (bogdan)
 */

/*!
 * \file
 * \brief Route & Record-Route module, loose routing support
 * \ingroup rr
 */

/*!
 * \defgroup rr Route & Record-Route Module
 */

#include <string.h>
#include "../../mem/mem.h"
#include "../../dprint.h"
#include "../../parser/parse_uri.h"
#include "../../parser/parse_from.h"
#include "../../str.h"
#include "../../data_lump.h"
#include "record.h"
#include "rr_mod.h"


#define RR_PREFIX "Record-Route: <sip:"
#define RR_PREFIX_LEN (sizeof(RR_PREFIX)-1)

#define RR_LR ";lr"
#define RR_LR_LEN (sizeof(RR_LR)-1)

#define RR_LR_FULL ";lr=on"
#define RR_LR_FULL_LEN (sizeof(RR_LR_FULL)-1)

#define RR_FROMTAG ";ftag="
#define RR_FROMTAG_LEN (sizeof(RR_FROMTAG)-1)

#define RR_R2 ";r2=on"
#define RR_R2_LEN (sizeof(RR_R2)-1)

#define RR_TERM ">"CRLF
#define RR_TERM_LEN (sizeof(RR_TERM)-1)

#define INBOUND  1  /* Insert inbound Record-Route */
#define OUTBOUND 0  /* Insert outbound Record-Route */

#define RR_PARAM_BUF_SIZE 512

/* index in the processing context for the RR adding :
      0 - RR not added, params not added 
      1 - RR not added, params added and buffered 
      2 - RR added
*/
int ctx_rrstat_idx;


/*! \brief
 * Extract username from the Request URI
 * First try to look at the original Request URI and if there
 * is no username use the new Request URI
 */
static inline int get_username(struct sip_msg* _m, str* _user)
{
	struct sip_uri puri;

	     /* first try to look at r-uri for a username */
	if (parse_uri(_m->first_line.u.request.uri.s, _m->first_line.u.request.uri.len, &puri) < 0) {
		LM_ERR("failed to parse R-URI\n");
		return -1;
	}

	/* no username in original uri -- hmm; maybe it is a uri
	 * with just host address and username is in a preloaded route,
	 * which is now no rewritten r-uri (assumed rewriteFromRoute
	 * was called somewhere in script's beginning)
	 */
	if (!puri.user.len && _m->new_uri.s) {
		if (parse_uri(_m->new_uri.s, _m->new_uri.len, &puri) < 0) {
			LM_ERR("failed to parse new_uri\n");
			return -2;
	        }
	}

	_user->s = puri.user.s;
	_user->len = puri.user.len;
	return 0;
}


static inline struct lump *insert_rr_param_lump(struct lump *before,
						char *s, int l)
{
	struct lump *rrp_l;
	char *s1;

	/* duplicate data in pkg mem */
	s1 = (char*)pkg_malloc(l);
	if (s1==0) {
		LM_ERR("no more pkg mem (%d)\n",l);
		return 0;
	}
	memcpy( s1, s, l);

	/* add lump */
	rrp_l = insert_new_lump_before( before, s1, l, HDR_RECORDROUTE_T);
	if (rrp_l==0) {
		LM_ERR("failed to add before lump\n");
		pkg_free(s1);
		return 0;
	}
	return rrp_l;
}


/*! \brief
 * build a Record-Route header field
 */
static inline int build_rr(struct lump* _l, struct lump* _l2, str* user,
						str *tag, str *params, struct lump *lp, int _inbound)
{
	char* prefix, *suffix, *term, *r2;
	int suffix_len, prefix_len;
	char *p;

	prefix_len = RR_PREFIX_LEN + (user->len ? (user->len + 1) : 0);
	suffix_len = RR_LR_LEN + (params?params->len:0) +
			((tag && tag->len) ? (RR_FROMTAG_LEN + tag->len) : 0);

	prefix = pkg_malloc(prefix_len);
	suffix = pkg_malloc(suffix_len);
	term = pkg_malloc(RR_TERM_LEN);
	r2 = pkg_malloc(RR_R2_LEN);

	if (!prefix || !suffix || !term || !r2) {
		LM_ERR("No more pkg memory\n");
		if (suffix) pkg_free(suffix);
		if (prefix) pkg_free(prefix);
		if (term) pkg_free(term);
		if (r2) pkg_free(r2);
		return -3;
	}

	memcpy(prefix, RR_PREFIX, RR_PREFIX_LEN);
	if (user->len) {
		memcpy(prefix + RR_PREFIX_LEN, user->s, user->len);
#ifdef ENABLE_USER_CHECK
		/* don't add the ignored user into a RR */
		if(i_user.len && i_user.len == user->len &&
				!strncmp(i_user.s, user->s, i_user.len))
		{
			if(prefix[RR_PREFIX_LEN]=='x')
				prefix[RR_PREFIX_LEN]='y';
			else
				prefix[RR_PREFIX_LEN]='x';
		}
#endif
		prefix[RR_PREFIX_LEN + user->len] = '@';
	}

	p = suffix;
	memcpy( p, RR_LR, RR_LR_LEN);
	p += RR_LR_LEN;

	if (tag && tag->len) {
		memcpy(p, RR_FROMTAG, RR_FROMTAG_LEN);
		p += RR_FROMTAG_LEN;
		memcpy(p, tag->s, tag->len);
		p += tag->len;
	}
	if (params && params->len) {
		memcpy(p, params->s, params->len);
		p += params->len;
	}

	memcpy(term, RR_TERM, RR_TERM_LEN);
	memcpy(r2, RR_R2, RR_R2_LEN);

	if (!(_l = insert_new_lump_after(_l, prefix, prefix_len, 0)))
		goto lump_err;
	prefix = 0;
	_l = insert_subst_lump_after(_l, _inbound?SUBST_RCV_ALL:SUBST_SND_ALL, 0);
	if (_l ==0 )
		goto lump_err;
	if (enable_double_rr) {
		if (!(_l = insert_cond_lump_after(_l, COND_IF_DIFF_REALMS, 0)))
			goto lump_err;
		if (!(_l = insert_new_lump_after(_l, r2, RR_R2_LEN, 0)))
			goto lump_err;
		r2 = 0;
	} else {
		pkg_free(r2);
		r2 = 0;
	}
	_l2 = insert_new_lump_before(_l2, suffix, suffix_len, HDR_RECORDROUTE_T);
	if (_l2 == 0)
		goto lump_err;
	suffix = 0;
	if ( lp ) {
		/* link the pending buffered params and go at the end of the list */
		for ( _l2->before = lp ; _l2 && _l2->before ; _l2=_l2->before);
	}
	if (!(_l2 = insert_new_lump_before(_l2, term, RR_TERM_LEN, 0)))
		goto lump_err;
	term = 0;
	return 0;

lump_err:
	LM_ERR("failed to insert lumps\n");
	if (prefix) pkg_free(prefix);
	if (suffix) pkg_free(suffix);
	if (r2) pkg_free(r2);
	if (term) pkg_free(term);
	return -4;
}


/*! \brief
 * Insert a new Record-Route header field
 * And also 2nd one if it is enabled and realm changed so
 * the 2nd record-route header will be necessary
 */
int record_route(struct sip_msg* _m, str *params)
{
	struct lump* l, *l2, *lp, *lp2, *ap;
	str user;
	struct to_body* from;
	str* tag;

	from = 0; /* Makes gcc happy */
	user.len = 0;
	lp = lp2 = NULL;

	if (add_username) {
		if (get_username(_m, &user) < 0) {
			LM_ERR("failed to extract username\n");
			return -1;
		}
	}

	if (append_fromtag) {
		if (parse_from_header(_m) < 0) {
			LM_ERR("From parsing failed\n");
			return -2;
		}
		from = (struct to_body*)_m->from->parsed;
		tag = &from->tag_value;
	} else {
		tag = 0;
	}

	l = anchor_lump(_m, _m->headers->name.s - _m->buf, HDR_RECORDROUTE_T);
	l2 = anchor_lump(_m, _m->headers->name.s - _m->buf, 0);
	if (!l || !l2) {
		LM_ERR("failed to create an anchor\n");
		return -3;
	}

	if (ctx_rrstat_get()==1) {
		/* look for pending RR params */
		for( ap=_m->add_rm ; ap ; ap=ap->next ) {
			if (ap->type==HDR_RECORDROUTE_T && ap->op==LUMP_NOP)
				/* found our phony anchor lump */
				break;
		}
		if (ap==NULL || ap->before==NULL || ap->before->before==NULL) {
			LM_CRIT("BUG: RR state is 1, but no/invalid phony lump found\n");
			return -1;
		}
		/* jump over the anchor and conditional lumps */
		lp = ap->before->before;
		ap->before->before = NULL;
		/* if double routing, make a copy of the buffered lumps for the
		   second route hdr. */
		if (enable_double_rr)
			lp2 = dup_lump_list(lp);
	}

	if (build_rr(l, l2, &user, tag, params, lp, OUTBOUND) < 0) {
		LM_ERR("failed to insert inbound Record-Route\n");
		return -4;
	}

	if (enable_double_rr) {
		l = anchor_lump(_m, _m->headers->name.s - _m->buf,HDR_RECORDROUTE_T);
		l2 = anchor_lump(_m, _m->headers->name.s - _m->buf, 0);
		if (!l || !l2) {
			LM_ERR("failed to create an anchor\n");
			return -5;
		}
		l = insert_cond_lump_after(l, COND_IF_DIFF_REALMS, 0);
		l2 = insert_cond_lump_before(l2, COND_IF_DIFF_REALMS, 0);
		if (!l || !l2) {
			LM_ERR("failed to insert conditional lump\n");
			return -6;
		}
		if (build_rr(l, l2, &user, tag, params, lp2, INBOUND) < 0) {
			LM_ERR("failed to insert outbound Record-Route\n");
			return -7;
		}
	}

	return 0;
}


/*! \brief
 * Insert manually created Record-Route header, no checks, no restrictions,
 * always adds lr parameter, only fromtag is added automatically when requested
 */
int record_route_preset(struct sip_msg* _m, str* _data)
{
	str user;
	struct to_body* from;
	struct lump* l, *lp, *ap;
	struct lump* l2;
	char *hdr, *suffix, *p, *term;
	int hdr_len, suffix_len;

	from = 0;
	user.len = 0;
	user.s = 0;

	if (add_username) {
		if (get_username(_m, &user) < 0) {
			LM_ERR("failed to extract username\n");
			return -1;
		}
	}

	if (append_fromtag) {
		if (parse_from_header(_m) < 0) {
			LM_ERR("From parsing failed\n");
			return -2;
		}
		from = (struct to_body*)_m->from->parsed;
	}

	hdr_len = RR_PREFIX_LEN;
	if (user.len)
		hdr_len += user.len + 1; /* @ */
	hdr_len += _data->len;

	suffix_len = 0;
	if (append_fromtag && from->tag_value.len) {
		suffix_len += RR_FROMTAG_LEN + from->tag_value.len;
	}

	suffix_len += RR_LR_LEN;

	hdr = pkg_malloc(hdr_len);
	term = pkg_malloc(RR_TERM_LEN);
	suffix = pkg_malloc(suffix_len);
	if (!hdr || !term || !suffix) {
		LM_ERR("no pkg memory left\n");
		return -4;
	}

	/* header */
	p = hdr;
	memcpy(p, RR_PREFIX, RR_PREFIX_LEN);
	p += RR_PREFIX_LEN;

	if (user.len) {
		memcpy(p, user.s, user.len);
		p += user.len;
		*p = '@';
		p++;
	}

	memcpy(p, _data->s, _data->len);
	p += _data->len;

	/*suffix*/
	p = suffix;
	if (append_fromtag && from->tag_value.len) {
		memcpy(p, RR_FROMTAG, RR_FROMTAG_LEN);
		p += RR_FROMTAG_LEN;
		memcpy(p, from->tag_value.s, from->tag_value.len);
		p += from->tag_value.len;
	}

	memcpy(p, RR_LR, RR_LR_LEN);
	p += RR_LR_LEN;

	memcpy(term, RR_TERM, RR_TERM_LEN);

	l = anchor_lump(_m, _m->headers->name.s - _m->buf, HDR_RECORDROUTE_T);
	l2 = anchor_lump(_m, _m->headers->name.s - _m->buf, 0);
	if (!l || !l2) {
		LM_ERR("failed to create lump anchor\n");
		goto error;
	}

	if (!(l=insert_new_lump_after(l, hdr, hdr_len, 0))) {
		LM_ERR("failed to insert new lump\n");
		goto error;
	}
	hdr = NULL;

	l2 = insert_new_lump_before(l2, suffix, suffix_len, HDR_RECORDROUTE_T);
	if (l2==NULL) {
		LM_ERR("failed to insert suffix lump\n");
		goto error;
	}
	suffix = NULL;

	if (ctx_rrstat_get()==1) {
		/* look for pending RR params */
		for( ap=_m->add_rm ; ap ; ap=ap->next ) {
			if (ap->type==HDR_RECORDROUTE_T && ap->op==LUMP_NOP)
				/* found our phony anchor lump */
				break;
		}
		if (ap==NULL || ap->before==NULL || ap->before->before==NULL) {
			LM_CRIT("BUG: RR state is 1, but no/invalid phony lump found\n");
			goto error;
		}
		/* jump over the anchor and conditional lumps */
		lp = ap->before->before;
		ap->before->before = NULL;
		/* link the pending buffered params and go at the end of the list */
		for ( l2->before = lp ; l2 && l2->before ; l2=l2->before);
	}

	if (!(l2=insert_new_lump_before(l2, term, RR_TERM_LEN, 0))) {
		LM_ERR("failed to insert term lump");
		goto error;
	}
	term = NULL;

	return 1;
error:
	if (hdr) pkg_free(hdr);
	if (term) pkg_free(term);
	if (suffix) pkg_free(suffix);
	return -1;
}


static struct lump *get_rr_param_lump( struct lump** root)
{
	struct lump *r, *crt, *last;
	/* look on the "before" branch for the last added lump */

	last = 0;
	for( crt=*root ; crt && !last ; crt=crt->next,(*root)=crt ) {
		/* check on before list */
		for( r=crt->before ; r ; r=r->before ) {
			/* we are looking for the lump that adds the
			 * suffix of the RR header */
			if ( r->type==HDR_RECORDROUTE_T && r->op==LUMP_ADD)
				last = r;
		}
	}
	return last;
}


/*! \brief
 * Appends a new Record-Route parameter
 */
int add_rr_param(struct sip_msg* msg, str* rr_param)
{
	struct lump *l, *a;
	struct lump *root;

	LM_DBG("adding (%.*s) %d\n",rr_param->len,rr_param->s, ctx_rrstat_get());

	switch ( ctx_rrstat_get() ) {

	case 2:
		/* RR was already done -> have to add a new lump before this one */
		root = msg->add_rm;
		if ( (l=get_rr_param_lump(&root))==NULL) {
			LM_CRIT("BUG - RR stat is 2 but no RR lump found\n");
			return -1;
		}
		if (insert_rr_param_lump( l, rr_param->s, rr_param->len)==0) {
			LM_ERR("failed to add lump\n");
			goto error;
		}
		/* double routing enabled? */
		if (enable_double_rr) {
			if (root && (l=get_rr_param_lump(&root))!=NULL) {
				if (insert_rr_param_lump(l,rr_param->s,
				rr_param->len)==0) {
					LM_ERR("failed to add 2nd lump\n");
					goto error;
				}
			}
		}
		break;

	case 1:
		/* RR not done, but some RR params are already buffered -> 
		   add a before lump to the existing buffering one */
		for( a=msg->add_rm ; a ; a=a->next ) {
			if (a->type==HDR_RECORDROUTE_T && a->op==LUMP_NOP)
				/* found our phony anchor lump */
				break;
		}
		if (a==NULL || a->before==NULL) {
			LM_CRIT("BUG: RR state is 1, but no phony lump found\n");
			goto error;
		}
		/* get the last param attached on the anchor */
		for( l=a->before ; l && l->before ; l=l->before);
		/* add the param */
		if (insert_rr_param_lump( l, rr_param->s, rr_param->len)==0) {
			LM_ERR("failed to add buffered lump\n");
			goto error;
		}
		break;

	case 0:
		/* RR not done, no other RR param added so far ->
		   create the phony anchor and the lump to it */
		a = anchor_lump( msg, msg->headers->name.s-msg->buf, HDR_RECORDROUTE_T);
		if (a==NULL) {
			LM_ERR("cannot create phony lump for buffering params\n");
			goto error;
		}
		l = insert_cond_lump_before( a, COND_FALSE, 0);
		if (l==NULL) {
			LM_ERR("cannot create conditional lump for buffering params\n");
			goto error;
		}
		if (insert_rr_param_lump( l, rr_param->s, rr_param->len)==0) {
			LM_ERR("failed to add buffered lump\n");
			goto error;
		}
		/* change the RR state, as first buffered RR param was added */
		ctx_rrstat_set(1);
		break;
	}

	return 0;
error:
	return -1;
}


