/*
 * Copyright (C) 2010-2014 OpenSIPS Solutions
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
 *  2003-01-19  support for duplication lump lists added (jiri)
 *  2003-03-31  added subst lumps --they expand in ip addr, port a.s.o (andrei)
 *  2003-04-01  added conditional lump support functions (andrei)
 *  2003-10-20  anchor_lump & del_lump will automatically choose the lump list
 *              based on  msg->eoh comparisons (andrei)
 *  2003-10-28  added extra checks (paranoia) for {anchor,del}_lump (andrei)
 *  2005-08-22  added init_lump_flags -initial flags- for all built lumps
 *              (bogdan)
 *  2005-08-23  del_nonshm_lump() -> del_flaged_lumps(LUMPFLAG_SHMEM) (bogdan)
 */

/*!
 * \file data_lump.c
 * \brief OpenSIPS Lump (internal message manipulation) functions
 */


#include "data_lump.h"
#include "dprint.h"
#include "mem/mem.h"
#include "globals.h"
#include "error.h"

#include <stdlib.h>
#include <string.h>

#ifdef DEBUG_DMALLOC
#include <dmalloc.h>
#endif

/*! \note WARNING: all lump add/insert operations expect a pkg_malloc'ed char*
 * pointer the will be DEALLOCATED when the sip_msg is destroyed! */

enum lump_dir { LD_NEXT, LD_BEFORE, LD_AFTER };

int init_lump_flags = 0;

/*! \brief adds a header to the end
 *  \return returns pointer if success, 0 on error
 *
 * WARNING: currently broken! 
 *   - lumps_len() needs to properly handle LUMP_ADD along the main chain of
 *     lumps before we can use this
 */
struct lump* append_new_lump(struct lump** list, char* new_hdr,
							unsigned int len, enum _hdr_types_t type)
{
	struct lump** t;
	struct lump* tmp;

	for (t=list;*t;t=&((*t)->next));

	tmp=pkg_malloc(sizeof(struct lump));
	if (tmp==0){
		LM_ERR("out of pkg memory\n");
		return 0;
	}

	memset(tmp,0,sizeof(struct lump));
	tmp->type=type;
	tmp->flags=init_lump_flags;
	tmp->op=LUMP_ADD;
	tmp->u.value=new_hdr;
	tmp->len=len;
	*t=tmp;
	return tmp;
}



/*! \brief inserts a header to the beginning
 *  \return returns pointer if success, 0 on error
 *
 * WARNING: currently broken! 
 *   - lumps_len() needs to properly handle LUMP_ADD along the main chain of
 *     lumps before we can use this
 */
struct lump* insert_new_lump(struct lump** list, char* new_hdr,
								unsigned int len, enum _hdr_types_t type)
{
	struct lump* tmp;

	tmp=pkg_malloc(sizeof(struct lump));
	if (tmp==0){
		LM_ERR("out of pkg memory\n");
		return 0;
	}
	memset(tmp,0,sizeof(struct lump));
	tmp->next=*list;
	tmp->type=type;
	tmp->flags=init_lump_flags;
	tmp->op=LUMP_ADD;
	tmp->u.value=new_hdr;
	tmp->len=len;
	*list=tmp;
	return tmp;
}



/*! \brief inserts a  header/data lump immediately after hdr
 * \return returns pointer on success, 0 on error */
struct lump* insert_new_lump_after( struct lump* after, char* new_hdr,
							unsigned int len, enum _hdr_types_t type)
{
	struct lump* tmp;

	tmp=pkg_malloc(sizeof(struct lump));
	if (tmp==0){
		ser_error=E_OUT_OF_MEM;
		LM_ERR("out of pkg memory\n");
		return 0;
	}
	memset(tmp,0,sizeof(struct lump));
	tmp->after=after->after;
	tmp->type=type;
	tmp->flags=init_lump_flags;
	tmp->op=LUMP_ADD;
	tmp->u.value=new_hdr;
	tmp->len=len;
	after->after=tmp;
	return tmp;
}



/*! \brief inserts a  header/data lump immediately before "before"
 * \return returns pointer on success, 0 on error */
struct lump* insert_new_lump_before( struct lump* before, char* new_hdr,
							unsigned int len, enum _hdr_types_t type)
{
	struct lump* tmp;

	tmp=pkg_malloc(sizeof(struct lump));
	if (tmp==0){
		ser_error=E_OUT_OF_MEM;
		LM_ERR("out of pkg memory\n");
		return 0;
	}
	memset(tmp,0,sizeof(struct lump));
	tmp->before=before->before;
	tmp->type=type;
	tmp->flags=init_lump_flags;
	tmp->op=LUMP_ADD;
	tmp->u.value=new_hdr;
	tmp->len=len;
	before->before=tmp;
	return tmp;
}



/*! \brief inserts a  subst lump immediately after hdr
 * \return returns pointer on success, 0 on error */
struct lump* insert_subst_lump_after( struct lump* after,enum lump_subst subst,
										enum _hdr_types_t type)
{
	struct lump* tmp;

	tmp=pkg_malloc(sizeof(struct lump));
	if (tmp==0){
		ser_error=E_OUT_OF_MEM;
		LM_ERR("out of pkg memory\n");
		return 0;
	}
	memset(tmp,0,sizeof(struct lump));
	tmp->after=after->after;
	tmp->type=type;
	tmp->flags=init_lump_flags;
	tmp->op=LUMP_ADD_SUBST;
	tmp->u.subst=subst;
	tmp->len=0;
	after->after=tmp;
	return tmp;
}



/*! \brief inserts a  subst lump immediately before "before"
 * \return returns pointer on success, 0 on error */
struct lump* insert_subst_lump_before(	struct lump* before,
										enum lump_subst subst,
										enum _hdr_types_t type)
{
	struct lump* tmp;

	tmp=pkg_malloc(sizeof(struct lump));
	if (tmp==0){
		ser_error=E_OUT_OF_MEM;
		LM_ERR("out of pkg memory\n");
		return 0;
	}
	memset(tmp,0,sizeof(struct lump));
	tmp->before=before->before;
	tmp->type=type;
	tmp->flags=init_lump_flags;
	tmp->op=LUMP_ADD_SUBST;
	tmp->u.subst=subst;
	tmp->len=0;
	before->before=tmp;
	return tmp;
}



/*! \brief inserts a  cond lump immediately after hdr
 * \return returns pointer on success, 0 on error */
struct lump* insert_cond_lump_after( struct lump* after,enum lump_conditions c,
										enum _hdr_types_t type)
{
	struct lump* tmp;

	tmp=pkg_malloc(sizeof(struct lump));
	if (tmp==0){
		ser_error=E_OUT_OF_MEM;
		LM_ERR("out of pkg memory\n");
		return 0;
	}
	memset(tmp,0,sizeof(struct lump));
	tmp->after=after->after;
	tmp->type=type;
	tmp->flags=init_lump_flags;
	tmp->op=LUMP_ADD_OPT;
	tmp->u.cond=c;
	tmp->len=0;
	after->after=tmp;
	return tmp;
}



/*! \brief inserts a  conditional lump immediately before "before"
 * \return returns pointer on success, 0 on error */
struct lump* insert_cond_lump_before(	struct lump* before,
										enum lump_conditions c,
										enum _hdr_types_t type)
{
	struct lump* tmp;

	tmp=pkg_malloc(sizeof(struct lump));
	if (tmp==0){
		ser_error=E_OUT_OF_MEM;
		LM_ERR("out of pkg memory\n");
		return 0;
	}
	memset(tmp,0,sizeof(struct lump));
	tmp->before=before->before;
	tmp->type=type;
	tmp->flags=init_lump_flags;
	tmp->op=LUMP_ADD_OPT;
	tmp->u.cond=c;
	tmp->len=0;
	before->before=tmp;
	return tmp;
}



/*! \brief inserts a skip lump immediately after hdr
 * \return returns pointer on success, 0 on error */
struct lump* insert_skip_lump_after( struct lump* after)
{
	struct lump* tmp;

	tmp=pkg_malloc(sizeof(struct lump));
	if (tmp==0){
		ser_error=E_OUT_OF_MEM;
		LM_ERR("out of pkg memory\n");
		return 0;
	}
	memset(tmp,0,sizeof(struct lump));
	tmp->after=after->after;
	tmp->flags=init_lump_flags;
	tmp->op=LUMP_SKIP;
	after->after=tmp;
	return tmp;
}



/*! \brief inserts a skip lump immediately before "before"
 * \return returns pointer on success, 0 on error */
struct lump* insert_skip_lump_before( struct lump* before )
{
	struct lump* tmp;

	tmp=pkg_malloc(sizeof(struct lump));
	if (tmp==0){
		ser_error=E_OUT_OF_MEM;
		LM_ERR("out of pkg memory\n");
		return 0;
	}
	memset(tmp,0,sizeof(struct lump));
	tmp->before=before->before;
	tmp->flags=init_lump_flags;
	tmp->op=LUMP_SKIP;
	before->before=tmp;
	return tmp;
}



/*! \brief removes an already existing header/data lump */
/* WARNING: this function adds the lump either to the msg->add_rm or
 * msg->body_lumps list, depending on the offset being greater than msg->eoh,
 * so msg->eoh must be parsed (parse with HDR_EOH) if you think your lump
 *  might affect the body!! */
struct lump* del_lump(struct sip_msg* msg, unsigned int offset,
		unsigned int len, enum _hdr_types_t type)
{
	struct lump* tmp;
	struct lump* prev, *t;
	struct lump** list;

	/* extra checks */
	if (offset>msg->len){
		LM_CRIT("offset exceeds message size (%d > %d)"
					" aborting...\n", offset, msg->len);
		abort();
	}
	if (offset+len>msg->len){
		LM_CRIT("offset + len exceeds message"
				" size (%d + %d > %d)\n", offset, len,  msg->len);
		abort();
	}
	if (len==0){
		LM_WARN("called with 0 len (offset =%d)\n",	offset);
	}

	tmp=pkg_malloc(sizeof(struct lump));
	if (tmp==0){
		LM_ERR("out of pkg memory\n");
		return 0;
	}
	memset(tmp,0,sizeof(struct lump));
	tmp->op=LUMP_DEL;
	tmp->type=type;
	tmp->flags=init_lump_flags;
	tmp->u.offset=offset;
	tmp->len=len;
	prev=0;
	/* check to see whether this might be a body lump */
	if ((msg->eoh) && (offset>(unsigned long)(msg->eoh-msg->buf)))
		list=&msg->body_lumps;
	else
		list=&msg->add_rm;
	for (t=*list;t; prev=t, t=t->next){
		/* insert it sorted after offset */
		if (((t->op==LUMP_DEL)||(t->op==LUMP_NOP))&&(t->u.offset>offset))
			break;
	}
	tmp->next=t;
	if (prev) prev->next=tmp;
	else *list=tmp;
	return tmp;
}



/*! \brief add an anchor
 * WARNING: this function adds the lump either to the msg->add_rm or
 * msg->body_lumps list, depending on the offset being greater than msg->eoh,
 * so msg->eoh must be parsed (parse with HDR_EOH) if you think your lump
 *  might affect the body!! */
struct lump* anchor_lump(struct sip_msg* msg, unsigned int offset,
						 enum _hdr_types_t type)
{
	struct lump* tmp;
	struct lump* prev, *t;
	struct lump** list;


	/* extra checks */
	if (offset>msg->len){
		LM_CRIT("offset exceeds message size (%d > %d)"
					" aborting...\n", offset, msg->len);
		abort();
	}

	tmp=pkg_malloc(sizeof(struct lump));
	if (tmp==0){
		ser_error=E_OUT_OF_MEM;
		LM_ERR("out of pkg memory\n");
		return 0;
	}
	memset(tmp,0,sizeof(struct lump));
	tmp->op=LUMP_NOP;
	tmp->type=type;
	tmp->flags=init_lump_flags;
	tmp->u.offset=offset;
	prev=0;
	/* check to see whether this might be a body lump */
	if ((msg->eoh) && (offset> (unsigned long)(msg->eoh-msg->buf)))
		list=&msg->body_lumps;
	else
		list=&msg->add_rm;

	for (t=*list;t; prev=t, t=t->next){
		/* insert it sorted after offset */
		if (((t->op==LUMP_DEL)||(t->op==LUMP_NOP))&&(t->u.offset>offset))
			break;
	}
	tmp->next=t;

	if (prev) prev->next=tmp;
	else *list=tmp;
	return tmp;
}



void free_lump(struct lump* lmp)
{
	if (lmp && (lmp->op==LUMP_ADD)){
		if (lmp->u.value){
			if (lmp->flags &(LUMPFLAG_SHMEM)){
				LM_CRIT("called on a not free-able lump:"
					"%p flags=%x\n", lmp, lmp->flags);
				abort();
			}else{
				pkg_free(lmp->u.value);
				lmp->u.value=0;
				lmp->len=0;
			}
		}
	}
}



void free_lump_list(struct lump* l)
{
	struct lump* t, *r, *foo,*crt;
	t=l;
	while(t){
		crt=t;
		t=t->next;

		r=crt->before;
		while(r){
			foo=r; r=r->before;
			free_lump(foo);
			pkg_free(foo);
		}
		r=crt->after;
		while(r){
			foo=r; r=r->after;
			free_lump(foo);
			pkg_free(foo);
		}

		/*clean current elem*/
		free_lump(crt);
		pkg_free(crt);
	}
}


/*! \brief* duplicate a lump list into pkg memory */
static struct lump *dup_lump_list_r( struct lump *l,
				enum lump_dir dir, int *error)
{
	int deep_error;
	struct lump *new_lump;

	deep_error=0; /* optimist: assume success in recursion */
	/* if at list end, terminate recursion successfully */
	if (!l) { *error=0; return 0; }
	/* otherwise duplicate current element */
	new_lump=pkg_malloc(sizeof(struct lump));
	if (!new_lump) { *error=1; return 0; }

	memcpy(new_lump, l, sizeof(struct lump));
	new_lump->flags=init_lump_flags;
	new_lump->next=new_lump->before=new_lump->after=0;
	if (new_lump->op==LUMP_ADD) {
		new_lump->u.value = pkg_malloc(l->len);
		if (!new_lump->u.value) { *error=1; return 0; }
		memcpy(new_lump->u.value,l->u.value,l->len);
	}

	switch(dir) {
		case LD_NEXT:
				new_lump->before=dup_lump_list_r(l->before,
								LD_BEFORE, &deep_error);
				if (deep_error) goto deeperror;
				new_lump->after=dup_lump_list_r(l->after,
								LD_AFTER, &deep_error);
				if (deep_error) goto deeperror;
				new_lump->next=dup_lump_list_r(l->next,
								LD_NEXT, &deep_error);
				break;
		case LD_BEFORE:
				new_lump->before=dup_lump_list_r(l->before,
								LD_BEFORE, &deep_error);
				break;
		case LD_AFTER:
				new_lump->after=dup_lump_list_r(l->after,
								LD_AFTER, &deep_error);
				break;
		default:
				LM_CRIT("unknown dir: %d\n", dir );
				deep_error=1;
	}
	if (deep_error) goto deeperror;

	*error=0;
	return new_lump;

deeperror:
	LM_ERR("out of pkg mem\n");
	free_lump(new_lump);
	*error=1;
	return 0;
}



/*! \brief full pkg copy of a lump list
 *
 * \return if either original list empty or error occur returns, 0
 * is returned, pointer to the copy otherwise
 */
struct lump* dup_lump_list( struct lump *l )
{
	int deep_error;

	deep_error=0;
	return dup_lump_list_r(l, LD_NEXT, &deep_error);
}



/*! \brief Delete flagged lumps
 */
void del_flaged_lumps( struct lump** lump_list, enum lump_flag flags )
{
	struct lump *r, *foo, *crt, **prev, *prev_r;

	prev = lump_list;
	crt = *lump_list;

	while (crt) {
		if ( crt->flags&flags ) {
			/* unlink it */
			foo = crt;
			crt = crt->next;
			foo->next = 0;
			/* update the 'next' link of the previous lump */
			*prev = crt;
			/* entire before/after list must be removed */
			free_lump_list( foo );
		} else {
			/* check on before and prev list for flaged lumps */
			r = crt->after;
			prev_r = crt;
			while(r){
				foo=r; r=r->after;
				if ( foo->flags&flags ) {
					prev_r->after = r;
					free_lump(foo);
					pkg_free(foo);
				} else {
					prev_r = foo;
				}
			}
			/* before */
			r = crt->before;
			prev_r = crt;
			while(r){
				foo=r; r=r->before;
				if ( foo->flags&flags ) {
					prev_r->before = r;
					free_lump(foo);
					pkg_free(foo);
				} else {
					prev_r = foo;
				}
			}
			/* go to next lump */
			prev = &(crt->next);
			crt = crt->next;
		}
	}
}


/*! \brief Delete not flagged lumps
 */
void del_notflaged_lumps( struct lump** lump_list, enum lump_flag not_flags )
{
	struct lump *r, *foo, *crt, **prev, *prev_r;

	prev = lump_list;
	crt = *lump_list;

	while (crt) {
		if ( (~crt->flags)&not_flags ) {
			/* unlink it */
			foo = crt;
			crt = crt->next;
			foo->next = 0;
			/* update the 'next' link of the previous lump */
			*prev = crt;
			/* entire before/after list must be removed */
			free_lump_list( foo );
		} else {
			/* check on after and before list for not_flaged lumps */
			r = crt->after;
			prev_r = crt;
			while(r){
				foo=r; r=r->after;
				if ( (~foo->flags)&not_flags ) {
					prev_r->after = r;
					free_lump(foo);
					pkg_free(foo);
				} else {
					prev_r = foo;
				}
			}
			/* before */
			r = crt->before;
			prev_r = crt;
			while(r){
				foo=r; r=r->before;
				if ( (~foo->flags)&not_flags ) {
					prev_r->before = r;
					free_lump(foo);
					pkg_free(foo);
				} else {
					prev_r = foo;
				}
			}
			/* go to next lump */
			prev = &(crt->next);
			crt = crt->next;
		}
	}
}

