/*
 * Route & Record-Route header field parser
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
 */

/**
 * History:
 * --------
 * 2003-10-07  parse_rr() split and added parse_rr_body()
 * 2003-10-21  duplicate_rr() duplicate the whole linked list of RR
 */
#include <string.h>
#include "parse_rr.h"
#include "../mem/mem.h"
#include "../mem/shm_mem.h"
#include "../dprint.h"
#include "../trim.h"
#include "../ut.h"
#include "../errinfo.h"

/*
 * Parse Route or Record-Route body
 */
static inline int do_parse_rr_body(char *buf, int len, rr_t **head)
{
	rr_t* r, *last;
	str s;
	param_hooks_t hooks;

	/* Make a temporary copy of the string pointer */
	if(buf==0 || len<=0)
	{
		LM_DBG("no body for record-route\n");
		r = NULL;
		*head = 0;
		goto parse_error;
	}
	s.s = buf;
	s.len = len;
	trim_leading(&s);

	last = 0;

	while(1) {
		/* Allocate and clear rr structure */
		r = (rr_t*)pkg_malloc(sizeof(rr_t));
		if (!r) {
			LM_ERR("no pkg memory left\n");
			goto error;
		}
		memset(r, 0, sizeof(rr_t));

		/* Parse name-addr part of the header */
		if (parse_nameaddr(&s, &r->nameaddr) < 0) {
			LM_ERR("failed to parse name-addr\n");
			goto parse_error;
		}
		r->len = r->nameaddr.len;

		/* Shift just behind the closing > */
		s.s = r->nameaddr.name.s + r->nameaddr.len;  /* Point just behind > */
		s.len -= r->nameaddr.len;

		trim_leading(&s); /* Skip any white-chars */

		if (s.len == 0) goto ok; /* Nothing left, finish */

		if (s.s[0] == ';') {         /* Route parameter found */
			s.s++;
			s.len--;
			trim_leading(&s);

			if (s.len == 0) {
				LM_ERR("failed to parse params\n");
				goto parse_error;
			}

			/* Parse all parameters */
			if (parse_params(&s, CLASS_ANY, &hooks, &r->params) < 0) {
				LM_ERR("failed to parse params\n");
				goto parse_error;
			}
			r->len = hooks.last_param->name.s + hooks.last_param->len
				 - r->nameaddr.name.s;

			/* Copy hooks */
			/*r->r2 = hooks.rr.r2; */

			trim_leading(&s);
			if (s.len == 0) goto ok;
		}

		if (s.s[0] != ',') {
			LM_ERR("invalid character '%c', comma expected\n", s.s[0]);
			goto parse_error;
		}

		/* Next character is comma or end of header*/
		s.s++;
		s.len--;
		trim_leading(&s);

		if (s.len == 0) {
			LM_ERR("text after comma missing\n");
			goto parse_error;
		}

		/* Append the structure as last parameter of the linked list */
		if (!*head) *head = r;
		if (last) last->next = r;
		last = r;
	}

 parse_error:
	LM_ERR("failed to parse RR headers\n");
 error:
	if (r) pkg_free(r);
	free_rr(head); /* Free any contacts created so far */
	return -1;

 ok:
	if (!*head) *head = r;
	if (last) last->next = r;
	return 0;
}

/*
 * Wrapper to do_parse_rr_body() for external calls
 */
int parse_rr_body(char *buf, int len, rr_t **head)
{
	return do_parse_rr_body(buf, len, head);
}

/*
 * Parse Route and Record-Route header fields
 */
int parse_rr(struct hdr_field* _h)
{
	rr_t* r = NULL;

	if (!_h) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}

	if (_h->parsed) {
		     /* Already parsed, return */
		return 0;
	}

	if(do_parse_rr_body(_h->body.s, _h->body.len, &r) < 0) {
		set_err_info(OSER_EC_PARSER, OSER_EL_MEDIUM,
			"error parsing RR headers");
		set_err_reply(400, "bad headers");
		return -1;
	}
	_h->parsed = (void*)r;
	return 0;
}

/*
 * Free list of rrs
 * _r is head of the list
 */
static inline void do_free_rr(rr_t** _r, int _shm)
{
	rr_t* ptr;

	while(*_r) {
		ptr = *_r;
		*_r = (*_r)->next;
		if (ptr->params) {
			if (_shm) shm_free_params(ptr->params);
			else free_params(ptr->params);
		}
		if (_shm) shm_free(ptr);
		else pkg_free(ptr);
	}
}


/*
 * Free list of rrs
 * _r is head of the list
 */

void free_rr(rr_t** _r)
{
	do_free_rr(_r, 0);
}


/*
 * Free list of rrs
 * _r is head of the list
 */

void shm_free_rr(rr_t** _r)
{
	do_free_rr(_r, 1);
}


/*
 * Print list of RRs, just for debugging
 */
void print_rr(FILE* _o, rr_t* _r)
{
	rr_t* ptr;

	ptr = _r;

	while(ptr) {
		fprintf(_o, "---RR---\n");
		print_nameaddr(_o, &ptr->nameaddr);
		fprintf(_o, "r2 : %p\n", ptr->r2);
		if (ptr->params) {
			print_params(ptr->params);
		}
		fprintf(_o, "len: %d\n", ptr->len);
		fprintf(_o, "---/RR---\n");
		ptr = ptr->next;
	}
}


/*
 * Translate all pointers in the structure and also
 * in all parameters in the list
 */
static inline void xlate_pointers(rr_t* _orig, rr_t* _r)
{
	param_t* ptr;
	_r->nameaddr.uri.s = translate_pointer(_r->nameaddr.name.s, _orig->nameaddr.name.s, _r->nameaddr.uri.s);

	ptr = _r->params;
	while(ptr) {
		     /*		if (ptr->type == P_R2) _r->r2 = ptr; */
		ptr->name.s = translate_pointer(_r->nameaddr.name.s, _orig->nameaddr.name.s, ptr->name.s);
		ptr->body.s = translate_pointer(_r->nameaddr.name.s, _orig->nameaddr.name.s, ptr->body.s);
		ptr = ptr->next;
	}
}


/*
 * Duplicate a single rr_t structure using pkg_malloc or shm_malloc
 */
static inline int do_duplicate_rr(rr_t** _new, rr_t* _r, int _shm, int _first)
{
	int len, ret;
	rr_t* res, *prev, *it;

	if (!_new || !_r) {
		LM_ERR("invalid parameter value\n");
		return -1;
	}
	prev  = NULL;
	*_new = NULL;
	it    = _r;
	while(it)
	{
		if (it->params) {
			len = it->params->name.s + it->params->len - it->nameaddr.name.s;
		} else {
			len = it->nameaddr.len;
		}

		if (_shm) res = shm_malloc(sizeof(rr_t) + len);
		else res = pkg_malloc(sizeof(rr_t) + len);
		if (!res) {
			LM_ERR("no shm memory left\n");
			goto error;
		}
		memcpy(res, it, sizeof(rr_t));

		res->nameaddr.name.s = (char*)res + sizeof(rr_t);
		memcpy(res->nameaddr.name.s, it->nameaddr.name.s, len);

		if (_shm) {
			ret = shm_duplicate_params(&res->params, it->params);
		} else {
			ret = duplicate_params(&res->params, it->params);
		}

		if (ret < 0) {
			LM_ERR("failed to duplicate parameters\n");
			if (_shm) shm_free(res);
			else pkg_free(res);
			goto error;
		}

		xlate_pointers(it, res);

		res->next=NULL;
		if(*_new==NULL)
			*_new = res;

		if (_first)
			return 0;

		if(prev)
			prev->next = res;
		prev = res;
		it = it->next;
	}
	return 0;
error:
	if (_shm) shm_free_rr(_new);
	else free_rr(_new);
	*_new = NULL;
	return -1;
}


/*
 * Duplicate a single rr_t structure or the whole list (based on
 * "first" param) using pkg_malloc
 */
int duplicate_rr(rr_t** _new, rr_t* _r, int first)
{
	return do_duplicate_rr(_new, _r, 0, first);
}


/*
 * Duplicate a single rr_t structure or the whole list (based on
 * "first" param) using shm_malloc
 */
int shm_duplicate_rr(rr_t** _new, rr_t* _r, int first)
{
	return do_duplicate_rr(_new, _r, 1, first);
}


/**
 * get first RR header and print comma separated bodies in oroute
 * - order = 0 normal; order = 1 reverse
 * - no_change = 1 do not perform any change/linking over the input hdr list
 *               (all parsing is localy done with no effect over the hdrs)
 * - nb_recs - input=skip number of rr; output=number of printed rrs
 */
int print_rr_body(struct hdr_field *iroute, str *oroute, int order,
									int no_change, unsigned int * nb_recs)
{
	rr_t *p;
	int n = 0, nr=0;
	int i = 0;
	int route_len;
#define MAX_RR_HDRS	64
	static str route[MAX_RR_HDRS];
	char *cp, *start;
	struct hdr_field tmp, *hdr;

	if(iroute==NULL)
		return 0;

	route_len= 0;
	memset(route, 0, MAX_RR_HDRS*sizeof(str));

	while (iroute!=NULL)
	{
		if (no_change) {
			memcpy( &tmp, iroute, sizeof(tmp));
			tmp.parsed = NULL;
			hdr=&tmp;
		}else{
			hdr=iroute;
		}
		if (parse_rr(hdr) < 0)
		{
			LM_ERR("failed to parse RR\n");
			goto error;
		}

		p =(rr_t*)hdr->parsed;
		while (p)
		{
			route[n].s = p->nameaddr.name.s;
			route[n].len = p->len;
			LM_DBG("current rr is %.*s\n", route[n].len, route[n].s);

			n++;
			if(n==MAX_RR_HDRS)
			{
				LM_ERR("too many RR\n");
				goto error;
			}
			p = p->next;
		}
		if (no_change)
			free_rr( (rr_t**)&tmp.parsed );
		iroute = iroute->sibling;
	}

	for(i=0;i<n;i++){
		if(!nb_recs || (nb_recs &&
		 ( (!order&& (i>=*nb_recs)) || (order && (i<=(n-*nb_recs)) )) ) )
		{
			route_len+= route[i].len;
			nr++;
		}

	}

	if(nb_recs)
		LM_DBG("skipping %i route records\n", *nb_recs);

	route_len += --nr; /* for commas */

	oroute->s=(char*)pkg_malloc(route_len);


	if(oroute->s==0)
	{
		LM_ERR("no more pkg mem\n");
		goto error;
	}
	cp = start = oroute->s;
	if(order==0)
	{
		i= (nb_recs == NULL) ? 0:*nb_recs;

		while (i<n)
		{
			memcpy(cp, route[i].s, route[i].len);
			cp += route[i].len;
			if (++i<n)
				*(cp++) = ',';
		}
	} else {

		i = (nb_recs == NULL) ? n-1 : (n-*nb_recs-1);

		while (i>=0)
		{
			memcpy(cp, route[i].s, route[i].len);
			cp += route[i].len;
			if (i-->0)
				*(cp++) = ',';
		}
	}
	oroute->len=cp - start;

	LM_DBG("out rr [%.*s]\n", oroute->len, oroute->s);
	LM_DBG("we have %i records\n", n);
	if(nb_recs != NULL)
		*nb_recs = (unsigned int)n;

	return 0;

error:
	return -1;
}



/*
 * Path must be available. Function returns the first uri
 * from Path without any duplication.
 */
int get_path_dst_uri(str *_p, str *_dst)
{
	rr_t *route = 0;

	LM_DBG("path for branch: '%.*s'\n",	_p->len, _p->s);

	if(parse_rr_body(_p->s, _p->len, &route) < 0) {
		LM_ERR("failed to parse Path body\n");
		return -1;
	}
	if(!route) {
		LM_ERR("failed to parse Path body no head found\n");
		return -1;
	}

	*_dst = route->nameaddr.uri;
	free_rr(&route);

	return 0;
}
