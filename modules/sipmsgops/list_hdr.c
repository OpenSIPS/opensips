/*
 * Copyright (C) 2017 OpenSIPS Project
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "../../dprint.h"
#include "../../data_lump.h"
#include "../../mem/mem.h"
#include "../../parser/msg_parser.h"
#include "../../parser/parse_list_hdr.h"

#include "list_hdr.h"

static struct hdr_field * _get_first_header(struct sip_msg *msg,
                                            int_str_t *hdr)
{
	struct hdr_field *it;

	/* be sure all SIP headers are parsed in the message */
	if (parse_headers(msg, HDR_EOH_F, 0) < 0) {
		LM_ERR("failed to parse all the SIP headers\n");
		return NULL;
	}

	if (!hdr->is_str) {
		/* header given by ID*/
		for (it = msg->headers; it; it = it->next)
			if (hdr->i == it->type)
				return it;

	} else {
		/* header given by string */
		for (it = msg->headers; it; it = it->next)
			if (it->type == HDR_OTHER_T &&
			it->name.len == hdr->s.len &&
			strncasecmp(it->name.s, hdr->s.s, it->name.len)==0)
				return it;
	}

	/* header not found */
	return NULL;
}


static inline struct hdr_field *_get_next_hdr(struct sip_msg *msg,
												struct hdr_field *hdr_start)
{
	struct hdr_field *hdr;

	if (hdr_start->type==HDR_OTHER_T) {

		/* unknown hdr type, so search by hdr name */
		for (hdr=hdr_start->next; hdr; hdr=hdr->next)
			if (hdr->type == HDR_OTHER_T &&
			hdr->name.len == hdr_start->name.len &&
			strncasecmp(hdr->name.s, hdr_start->name.s, hdr->name.len)==0)
				return hdr;

	} else {

		/* known hdr type, follow the "sibling" link */
		return hdr_start->sibling;

	}

	return NULL;
}


/* Checks if the option "val" is present in a CSV body-like header.
 * It searches through all instances of the header.
 * Input:
 *    - gp_hdr - the hdr name (ID or string/spec)
 *    - val - the option value (string/spec)
 * Returns true on the first occurace of the option in the header instances.
 */
int list_hdr_has_val(struct sip_msg *msg, int_str_t *match_hdr, str *val)
{
	struct hdr_field *hdr;
	struct list_hdr *lh, *lh_it;

	hdr = _get_first_header( msg, match_hdr);
	if (hdr==NULL)
		/* header not found*/
		return -1;

	do {

		/* parse the body of the header */
		if (parse_list_hdr( hdr->body.s, hdr->body.len, &lh)!=0) {
			LM_ERR("failed to parse body <%.*s> as CSV for hdr <%.*s>\n",
				hdr->body.len, hdr->body.s, hdr->name.len, hdr->name.s);
			return -1;
		}

		/* search the value in the list */
		for( lh_it=lh ; lh_it ; lh_it=lh_it->next ) {
			LM_DBG("testing option <%.*s>/%d against <%.*s>/%d\n",
				lh_it->token.len, lh_it->token.s, lh_it->token.len,
				val->len, val->s, val->len);
			if (lh_it->token.len==val->len &&
			strncasecmp(lh_it->token.s, val->s ,val->len)==0 ) {
				/* found */
				free_list_hdr(lh);
				return 1;
			}
		}

		free_list_hdr(lh);
		lh = NULL;

		/* not in this header, try the next hdr if any */
		hdr = _get_next_hdr(msg, hdr);
	} while (hdr!=NULL);

	/* value not found in any header instaces */
	return -1;
}


/* Searchs in the existing list of lumps the lump chain that deletes the
 * whole header and adds it again (as a whole) - this works a a full hdr
 * header replacement, covering hdr name and CRLF.
 */
static inline struct lump *_get_lump_by_hdr(struct sip_msg *msg,
														struct hdr_field *hdr)
{
	struct lump *l;

	for ( l=msg->add_rm; l ; l=l->next)
		if (l->op==LUMP_DEL && l->u.offset==(hdr->name.s-msg->buf)
		&& (l->flags&LUMP_FLAG_LISTHDR)
		&& l->len==hdr->len && hdr->type==l->type
		&& l->after && l->after->op==LUMP_SKIP
		&& l->after->after && l->after->after->op==LUMP_ADD) {
			/* we are on the right spot, just get the last ADD lump on after */
			l = l->after->after;
			while(l->after) l = l->after ;
			return l;
		}

	return NULL;
}


/* Creates the necessary lumps in order to push the new header value.
 * The whole change/update value process (for the header) is based on a
 * anchoring lump tree that deletes the header and adds the future new values.
 * A chain of "DEL-> SKIP->" is fix and the the new values will be chained
 * on the "after" SKIP branch
 * This works as a multi-time full hdr header replacement (covering hdr name 
 * and CRLF)
 */
static inline struct lump* _push_changes_into_lumps(struct sip_msg *msg,
						struct lump *l, struct hdr_field *hdr, str *body)
{
	struct lump *l1;

	/* is this the first change ? */
	if (l==NULL) {

		/* first change, so build on the static anchoring lump tree (where
		 * all the future changes will be attached ) */
		l = del_lump(msg, hdr->name.s-msg->buf, hdr->len, hdr->type);
		if (l==NULL) {
			LM_ERR("failed to insert del lump\n");
			return NULL;
		}
		l->flags |= LUMP_FLAG_LISTHDR;

		l = insert_skip_lump_after( l );
		if (l==NULL) {
			LM_ERR("failed to insert new skip lump after del\n");
			return NULL;
		}

	}

	/* add the new value to the existing anchoring lump tree */

	l1 = insert_new_lump_after( l, body->s, body->len, hdr->type);
	if (l1==NULL) {
		LM_ERR("failed to insert new lump after skip\n");
		return NULL;
	}

	return l1;
}


/* Adds a new option "val" to a CSV body-like header.
 * If the header does not exist, a new one will be added.
 * There is no check if the option already exists.
 * Input:
 *    - hdr - the hdr name (int if known, string otherwise)
 *    - val - the option value
 * Returns true upon successfully insertion.
 */
int list_hdr_add_val(struct sip_msg *msg, int_str_t *match_hdr, str *val)
{
	struct hdr_field *hdr;
	struct list_hdr *lh;
	struct lump *l;
	str body, old_hdr, new_hdr;
	char *p, *pos;

	hdr = _get_first_header( msg, match_hdr);
	if (hdr==NULL) {
		/* header not found*/
		// TODO - adding a completly new header ??
		return -1;
	}

	/* search for the lump corresponding to this hdr */
	l = _get_lump_by_hdr( msg, hdr);
	if (l) {
		/* header already modified, used the lump data as value */
		old_hdr.s = l->u.value;
		old_hdr.len = l->len;
	} else {
		/* first modification, use the original buffer as value */
		old_hdr.s = hdr->name.s;
		old_hdr.len = hdr->len;
	}

	if (old_hdr.len==0) {

		/* all original options were removed (current hdr status is to be
		 * entirly removed) -> rebuild it again */
		new_hdr.len = (hdr->len - hdr->body.len) + val->len;
		new_hdr.s = (char*)pkg_malloc( new_hdr.len );
		if (new_hdr.s==NULL) {
			LM_ERR("failed to allocate buffer for new body lump (needed %d)\n",
				new_hdr.len);
			return -1;
		}
		memcpy( new_hdr.s, hdr->name.s, hdr->body.s-hdr->name.s );
		p = new_hdr.s + (hdr->body.s-hdr->name.s);
		memcpy( p, val->s, val->len);
		p += val->len;
		memcpy( p, hdr->body.s+hdr->body.len ,
			(hdr->name.s+hdr->len)-(hdr->body.s+hdr->body.len) );

		LM_DBG("resulting new buffer is  <%.*s>\n", new_hdr.len, new_hdr.s );

		/* swap the buffers into the lump */
		pkg_free(l->u.value);
		l->u.value = new_hdr.s;
		l->len = new_hdr.len;

	} else {

		LM_DBG("adding new option <%.*s> to found buffer <%.*s>, hdr <%.*s>\n",
			val->len, val->s,
			old_hdr.len, old_hdr.s,
			hdr->name.len, hdr->name.s);
		/* get the body of the old body, based on hdr template :
		 *  - body starts at the same offset in the hdr buffer 
		 *  - body ends with the same offset (to the end) in the hdr buffer */
		body.s = old_hdr.s + (hdr->body.s - hdr->name.s);
		body.len = hdr->body.len + (old_hdr.len - hdr->len);

		/* parse the body, to be sure it is valid */
		if (parse_list_hdr( body.s, body.len, &lh)<0) {
			LM_ERR("failed to parse body <%.*s> as CSV for hdr <%.*s>\n",
				body.len, body.s, hdr->name.len, hdr->name.s);
			return -1;
		}
		// TODO - check for duplicates ??

		/* add the new value at the end of the old body */
		new_hdr.len = old_hdr.len + 1 /*','*/ + val->len;
		new_hdr.s = (char*)pkg_malloc( new_hdr.len );
		if (new_hdr.s==NULL) {
			LM_ERR("failed to allocate buffer for new body lump (needed %d)\n",
				new_hdr.len);
			return -1;
		}
		/* the lh list has the last option as first in the list, so we can
		 * simply add the new option (as index) right after the first option
		 * in list */
		if (lh)
			pos = lh->token.s + lh->token.len;
		else
			pos = body.s + body.len;
		memcpy( new_hdr.s, old_hdr.s, pos-old_hdr.s );
		p = new_hdr.s + (pos-old_hdr.s);
		*(p++) = lh?',':' ';
		memcpy( p, val->s, val->len);
		p += val->len;
		memcpy( p, pos, (old_hdr.s+old_hdr.len)-pos );
		free_list_hdr(lh);

		LM_DBG("resulting new buffer is  <%.*s>\n", new_hdr.len, new_hdr.s );

		/* add the new lumps for this change */
		if (_push_changes_into_lumps( msg, l, hdr, &new_hdr)==NULL) {
			LM_ERR("failed to insert lump with new changes\n");
			pkg_free(new_hdr.s);
			return -1;
		}
	}

	/* success */
	return 1;
}


int list_hdr_remove_val(struct sip_msg *msg, int_str_t *match_hdr, str *val)
{
	struct hdr_field *hdr;
	struct list_hdr *lh, *lh_it, *lh_prev;
	struct lump *l;
	str body, old_hdr, new_hdr;
	char *p;
	int removed = 0;

	hdr = _get_first_header( msg, match_hdr);
	if (hdr==NULL)
		/* header not found*/
		return -1;

	do {

		/* search for the lump corresponding to this hdr */
		l = _get_lump_by_hdr( msg, hdr);
		if (l) {
			/* header already modified, used the lump data as value */
			old_hdr.s = l->u.value;
			old_hdr.len = l->len;
		} else {
			/* first modification, use the original buffer as value */
			old_hdr.s = hdr->name.s;
			old_hdr.len = hdr->len;
		}

		if (old_hdr.len==0) {

			/* all original options were removed (current hdr status is to be
			 * entirly removed) so, just skip it */

		} else {

			LM_DBG("removing option <%.*s> from found buffer <%.*s>,"
				" hdr <%.*s>\n", val->len, val->s,
				old_hdr.len, old_hdr.s,
				hdr->name.len, hdr->name.s);
			/* get the body of the old body, based on hdr template :
			 *  - body starts at the same start offset in the hdr buffer 
			 *  - body ends with the same end offset in the hdr buffer */
			body.s = old_hdr.s + (hdr->body.s - hdr->name.s);
			body.len = hdr->body.len + (old_hdr.len - hdr->len);

			/* parse the body, to be sure it is valid */
			if (parse_list_hdr( body.s, body.len, &lh)<0) {
				LM_ERR("failed to parse body <%.*s> as CSV for hdr <%.*s>\n",
					body.len, body.s, hdr->name.len, hdr->name.s);
				return -1;
			}

			/* search the value in the list */
			for(lh_it=lh,lh_prev=NULL ;lh_it; lh_prev=lh_it,lh_it=lh_it->next){
				LM_DBG("testing option <%.*s>/%d against <%.*s>/%d\n",
					lh_it->token.len, lh_it->token.s, lh_it->token.len,
					val->len, val->s, val->len);
				if (lh_it->token.len==val->len &&
				strncasecmp(lh_it->token.s, val->s ,val->len)==0 ) {

					/* found, so remove it now */

					if (lh_it==lh && lh->next==NULL) {

						/* only one element in the list -> remove the whole 
						 * header now */
						new_hdr.s = NULL;
						new_hdr.len = 0;

					} else {

						/* remove only the current option/token */
						new_hdr.len = old_hdr.len - lh_it->token.len - 1;
						new_hdr.s = (char*)pkg_malloc( new_hdr.len );
						if (new_hdr.s==NULL) {
							LM_ERR("failed to allocate buffer for new body "
								"lump (needed %d)\n", new_hdr.len);
							return -1;
						}
						memcpy( new_hdr.s, old_hdr.s,
							lh_it->token.s-old_hdr.s );
						p = new_hdr.s + (lh_it->token.s-old_hdr.s);
						/* skip to the next option (do not write the current
						 * option) - KEEP in MIND that the lh list is in the
						 * revers order, so we actually jump to prev, not to
						 * next in order to get the following option token */
						if (lh_prev) {
							memcpy( p, lh_prev->token.s,
								(old_hdr.s+old_hdr.len)-lh_prev->token.s);
							p += (old_hdr.s+old_hdr.len)-lh_prev->token.s;
						} else {
							/* first in the linked list, last in the hdr ->
							 * shift back to remove the ',' of the last
							 * option/token */
							p -= lh->token.s - 
								(lh->next->token.s + lh->next->token.len);
							memcpy( p,
								lh->token.s+lh->token.len,
								(old_hdr.s+old_hdr.len)-
								(lh->token.s+lh->token.len));
							p += (old_hdr.s+old_hdr.len)-
								(lh->token.s+lh->token.len);
						}

						/* adjust the len according to what was actually 
						 * writen (we may allocated a bit more) */
						new_hdr.len = p - new_hdr.s;

					}

					LM_DBG("resulting new buffer is  <%.*s>\n",
						new_hdr.len, new_hdr.s );

					/* we have the new hdr value, push it as change in msg */
					if (_push_changes_into_lumps(msg,l,hdr,&new_hdr)==NULL) {
						LM_ERR("failed to insert lump with new changes\n");
						pkg_free(new_hdr.s);
						return -1;
					}

					removed++;
					/* only one removal per header for the moment */
					break;
				}
			}

			free_list_hdr(lh);
			lh = NULL;

		} /* done with this hdr instance */

		/* check the next hdr too, if any */
		hdr = _get_next_hdr(msg, hdr);
	} while (hdr!=NULL);

	return removed?1:-1;
}



