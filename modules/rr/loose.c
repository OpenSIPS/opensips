/*
 * Route & Record-Route module, loose routing support
 *
 * Copyright (C) 2009-2014 OpenSIPS Solutions
 * Copyright (C) 2001-2004 FhG Fokus
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
 * ---------
 * 2003-02-28 scratchpad compatibility abandoned (jiri)
 * 2003-01-27 next baby-step to removing ZT - PRESERVE_ZT (jiri)
 * 2005-04-10 check_route_param() and all hooks for keeping reference to
 *            Route params added (bogdan)
 * 2005-10-17 fixed socket selection when double routing changes
 *            the port or the IP address (bogdan)
 */

/*!
 * \file
 * \brief Route & Record-Route module, loose routing support
 * \ingroup rr
 */



#include <string.h>
#include "../../ut.h"
#include "../../str.h"
#include "../../dprint.h"
#include "../../context.h"
#include "../../forward.h"
#include "../../data_lump.h"
#include "../../socket_info.h"
#include "../../parser/parse_rr.h"
#include "../../parser/parse_uri.h"
#include "../../parser/parse_from.h"
#include "../../mem/mem.h"
#include "../../dset.h"
#include "loose.h"
#include "rr_cb.h"
#include "rr_mod.h"
#include "api.h"


#define RR_ERROR -1       /* An error occurred while processing route set */
#define RR_DRIVEN 1       /* The next hop is determined from the route set */
#define NOT_RR_DRIVEN -1  /* The next hop is not determined from the route set */

#define ROUTE_PREFIX "Route: <"
#define ROUTE_PREFIX_LEN (sizeof(ROUTE_PREFIX)-1)

#define ROUTE_SUFFIX ">\r\n"
#define ROUTE_SUFFIX_LEN (sizeof(ROUTE_SUFFIX)-1)

int ctx_rrparam_idx = -1;
int ctx_routing_idx = -1;

#define ctx_rrparam_get() \
	context_get_str(CONTEXT_GLOBAL, current_processing_ctx, ctx_rrparam_idx)

#define ctx_rrparam_set(_param) \
	context_put_str(CONTEXT_GLOBAL, current_processing_ctx, ctx_rrparam_idx, _param)

#define ctx_routing_get() \
	context_get_int(CONTEXT_GLOBAL, current_processing_ctx, ctx_routing_idx)

#define ctx_routing_set(_param) \
	context_put_int(CONTEXT_GLOBAL, current_processing_ctx, ctx_routing_idx, _param)


/*
 * Test whether we are processing pre-loaded route set
 * by looking at the To tag
 */
static int is_preloaded(struct sip_msg* msg)
{
	str tag;

	if (!msg->to && parse_headers(msg, HDR_TO_F, 0) == -1) {
		LM_ERR("failed to parse To header field\n");
		return -1;
	}

	if (!msg->to) {
		LM_ERR("To header field not found\n");
		return -1;
	}

	tag = get_to(msg)->tag_value;
	if (tag.s == 0 || tag.len == 0) {
		LM_DBG("Yes\n");
		return 1;
	}

	LM_DBG("No\n");
	return 0;
}


/*
 * Parse the message and find first occurrence of
 * Route header field. The function returns -1 or -2
 * on a parser error, 0 if there is a Route HF and
 * 1 if there is no Route HF.
 */
static inline int find_first_route(struct sip_msg* _m)
{
	if (parse_headers(_m, HDR_ROUTE_F, 0) == -1) {
		LM_ERR("failed to parse headers\n");
		return -1;
	} else {
		if (_m->route) {
			if (parse_rr(_m->route) < 0) {
				LM_ERR("failed to parse Route HF\n");
				return -2;
			}
			return 0;
		} else {
			LM_DBG("No Route headers found\n");
			return 1;
		}
	}
}


/*
 * Find out if a URI contains r2 parameter which indicates
 * that we put 2 record routes
 */
static inline int is_2rr(str* _params)
{
	str s;
	int i, state = 0;

	if (_params->len == 0) return 0;
	s = *_params;

	for(i = 0; i < s.len; i++) {
		switch(state) {
		case 0:
			switch(s.s[i]) {
			case ' ':
			case '\r':
			case '\n':
			case '\t':           break;
			case 'r':
			case 'R': state = 1; break;
			default:  state = 4; break;
			}
			break;

		case 1:
			switch(s.s[i]) {
			case '2': state = 2; break;
			default:  state = 4; break;
			}
			break;

		case 2:
			switch(s.s[i]) {
			case ';':  return 1;
			case '=':  return 1;
			case ' ':
			case '\r':
			case '\n':
			case '\t': state = 3; break;
			default:   state = 4; break;
			}
			break;

		case 3:
			switch(s.s[i]) {
			case ';':  return 1;
			case '=':  return 1;
			case ' ':
			case '\r':
			case '\n':
			case '\t': break;
			default:   state = 4; break;
			}
			break;

		case 4:
			switch(s.s[i]) {
			case '\"': state = 5; break;
			case ';':  state = 0; break;
			default:              break;
			}
			break;

		case 5:
			switch(s.s[i]) {
			case '\\': state = 6; break;
			case '\"': state = 4; break;
			default:              break;
			}
			break;

		case 6: state = 5; break;
		}
	}

	if ((state == 2) || (state == 3)) return 1;
	else return 0;
}


/*
 * Check if URI is myself
 */
#ifdef ENABLE_USER_CHECK
static inline int is_myself(str *_user, struct sip_uri* _uri)
#else
static inline int is_myself(struct sip_uri* _uri)
#endif
{
	int ret;
	unsigned short port;
	unsigned short proto;

	port = get_uri_port(_uri, &proto);

	ret = check_self(&_uri->host, port, proto);
	if (ret < 0) return 0;

#ifdef ENABLE_USER_CHECK
	if(i_user.len && i_user.len==_user->len
			&& !strncmp(i_user.s, _user->s, _user->len))
	{
		LM_DBG("this URI isn't mine\n");
		return -1;
	}
#endif

	return ret;
}


/*
 * Find and parse next Route header field
 */
static inline int find_next_route(struct sip_msg* _m, struct hdr_field** _hdr)
{
	struct hdr_field* ptr;

	ptr = (*_hdr)->next;

	     /* Try to find already parsed Route headers */
	while(ptr) {
		if (ptr->type == HDR_ROUTE_T) goto found;
		ptr = ptr->next;
	}

	     /* There are no already parsed Route headers, try to find next
	      * occurrence of Route header
	      */
	if (parse_headers(_m, HDR_ROUTE_F, 1) == -1) {
		LM_ERR("failed to parse headers\n");
		return -1;
	}

	if ((_m->last_header->type!=HDR_ROUTE_T) || (_m->last_header==*_hdr)) {
		LM_DBG("No next Route HF found\n");
		return 1;
	}

	ptr = _m->last_header;

 found:
	if (parse_rr(ptr) < 0) {
		LM_ERR("failed to parse Route body\n");
		return -2;
	}

	*_hdr = ptr;
	return 0;
}


/*
 * Put Request-URI as last Route header of a SIP
 * message, this is necessary when forwarding to
 * a strict router
 */
static inline int save_ruri(struct sip_msg* _m)
{
	struct lump* anchor;
	char *s;
	int len;

	     /* We must parse the whole message header here,
	      * because Request-URI must be saved in last
	      * Route HF in the message
	      */
	if (parse_headers(_m, HDR_EOH_F, 0) == -1) {
		LM_ERR("failed to parse message\n");
		return -1;
	}

	     /* Create an anchor */
	anchor = anchor_lump(_m, _m->unparsed - _m->buf, 0);
	if (anchor == 0) {
		LM_ERR("failed to get anchor\n");
		return -2;
	}

	     /* Create buffer for new lump */
	len = ROUTE_PREFIX_LEN + _m->first_line.u.request.uri.len + ROUTE_SUFFIX_LEN;
	s = (char*)pkg_malloc(len);
	if (!s) {
		LM_ERR("No memory pkg left\n");
		return -3;
	}

	     /* Create new header field */
	memcpy(s, ROUTE_PREFIX, ROUTE_PREFIX_LEN);
	memcpy(s + ROUTE_PREFIX_LEN, _m->first_line.u.request.uri.s, _m->first_line.u.request.uri.len);
	memcpy(s + ROUTE_PREFIX_LEN + _m->first_line.u.request.uri.len, ROUTE_SUFFIX, ROUTE_SUFFIX_LEN);

	LM_DBG("New header: '%.*s'\n", len, ZSW(s));

	     /* Insert it */
	if (insert_new_lump_before(anchor, s, len, 0) == 0) {
		pkg_free(s);
		LM_ERR("failed to insert lump\n");
		return -4;
	}

	return 0;
}


/*
 * input: uri - uri to be checked if has maddr
 * input: puri - parsed uri
 * outpu: uri - the uri to be used further
 */
#define RH_MADDR_PARAM_MAX_LEN 127 /* The max length of the maddr uri*/
static inline int get_maddr_uri(str *uri, struct sip_uri *puri)
{
	static char builturi[RH_MADDR_PARAM_MAX_LEN+1];
	struct sip_uri turi;

	if(uri==NULL || uri->s==NULL)
		return RR_ERROR;
	if(puri==NULL)
	{
		if (parse_uri(uri->s, uri->len, &turi) < 0)
		{
			LM_ERR("failed to parse the URI\n");
			return RR_ERROR;
		}
		puri = &turi;
	}

	if(puri->maddr.s==NULL)
		return 0;

	/* sip: + maddr + : + port */
	if( (puri->maddr_val.len) > ( RH_MADDR_PARAM_MAX_LEN - 10 ) )
	{
		LM_ERR( "Too long maddr parameter\n");
		return RR_ERROR;
	}
	memcpy( builturi, "sip:", 4 );
	memcpy( builturi+4, puri->maddr_val.s, puri->maddr_val.len );

	if( puri->port.len > 0 )
	{
		builturi[4+puri->maddr_val.len] =':';
		memcpy(builturi+5+puri->maddr_val.len, puri->port.s,
				puri->port.len);
	}

	uri->len = 4+puri->maddr_val.len
					+ ((puri->port.len>0)?(1+puri->port.len):0);
	builturi[uri->len]='\0';
	uri->s = builturi;

	LM_DBG("uri is %s\n", builturi );
	return 0;
}


/*
 * Logic necessary to forward request to strict routers
 *
 * Returns 0 on success, negative number on an error
 */
static inline int handle_sr(struct sip_msg* _m, struct hdr_field* _hdr, rr_t* _r)
{
	str uri;
	char* rem_off;
	int rem_len;

	/* Next hop is strict router, save R-URI here */
	if (save_ruri(_m) < 0) {
		LM_ERR("failed to save Request-URI\n");
		return -1;
	}

	/* Put the first Route in Request-URI */

	uri = _r->nameaddr.uri;
	if(get_maddr_uri(&uri, 0)!=0) {
		LM_ERR("failed to check maddr\n");
		return RR_ERROR;
	}
	if (set_ruri(_m, &uri) < 0) {
		LM_ERR("failed to rewrite request URI\n");
		return -2;
	}

	if (!_r->next) {
		rem_off = _hdr->name.s;
		rem_len = _hdr->len;
	} else {
		rem_off = _hdr->body.s;
		rem_len = _r->next->nameaddr.name.s - _hdr->body.s;
	}

	if (!del_lump(_m, rem_off - _m->buf, rem_len, 0)) {
		LM_ERR("failed to remove Route HF\n");
		return -9;
	}

	_r->deleted = 1;

	return 0;
}


/*
 * Find last route in the last Route header field,
 * if there was a previous route in the last Route header
 * field, it will be saved in _p parameter
 */
static inline int find_rem_target(struct sip_msg* _m, struct hdr_field** _h, rr_t** _l, rr_t** _p)
{
	struct hdr_field* ptr, *last;

	if (parse_headers(_m, HDR_EOH_F, 0) == -1) {
		LM_ERR("failed to parse message header\n");
		return -1;
	}

	ptr = _m->route;
	last = 0;

	while(ptr) {
		if (ptr->type == HDR_ROUTE_T) last = ptr;
		ptr = ptr->next;
	}

	if (last) {
		if (parse_rr(last) < 0) {
			LM_ERR("failed to parse last Route HF\n");
			return -2;
		}

		*_p = 0;
		*_l = (rr_t*)last->parsed;
		*_h = last;
		while ((*_l)->next) {
			*_p = *_l;
			*_l = (*_l)->next;
		}
		return 0;
	} else {
		LM_ERR("search for last Route HF failed\n");
		return 1;
	}
}

/*
 * Previous hop was a strict router, handle this case
 */
static inline int after_strict(struct sip_msg* _m)
{
	int res, rem_len;
	struct hdr_field* hdr;
	struct sip_uri puri;
	rr_t* rt, *prev, *del_rt;
	char* rem_off;
	str uri;
	struct socket_info *si;
	unsigned short port, proto;

	hdr = _m->route;
	rt = (rr_t*)hdr->parsed;
	uri = rt->nameaddr.uri;
	del_rt = NULL;

	if (parse_uri(uri.s, uri.len, &puri) < 0) {
		LM_ERR("failed to parse the first route URI\n");
		return RR_ERROR;
	}

	if ( enable_double_rr && is_2rr(&puri.params) &&
#ifdef ENABLE_USER_CHECK
	is_myself(&puri.user, &puri)
#else
	is_myself(&puri)
#endif
	) {
		/* double route may occure due different IP and port, so force as
		 * send interface the one advertise in second Route */
		set_sip_defaults( puri.port_no, puri.proto);
		si = grep_sock_info( &puri.host, puri.port_no, puri.proto);
		if (si) {
			_m->force_send_socket = si;
		} else {
			if (enable_socket_mismatch_warning)
				LM_WARN("no socket found to match 2nd RR [%d][%.*s:%d]\n",
					puri.proto, puri.host.len, puri.host.s, puri.port_no);
		}

		/* mark route hdr as deleted */
		rt->deleted = 1;

		if (!rt->next) {
			/* No next route in the same header, remove the whole header
			 * field immediately
			 */
			if (!del_lump(_m, hdr->name.s - _m->buf, hdr->len, 0)) {
				LM_ERR("failed to remove Route HF\n");
				return RR_ERROR;
			}

			res = find_next_route(_m, &hdr);
			if (res < 0) {
				LM_ERR("searching next route failed\n");
				return RR_ERROR;
			}
			if (res > 0) { /* No next route found */
				LM_DBG("No next URI found\n");
				return NOT_RR_DRIVEN;
			}
			rt = (rr_t*)hdr->parsed;
		} else rt = rt->next;

		/* parse the new found uri */
		uri = rt->nameaddr.uri;
		if (parse_uri(uri.s, uri.len, &puri) < 0) {
			LM_ERR("failed to parse URI\n");
			return RR_ERROR;
		}
	} else {
		port = _m->parsed_uri.port_no;
		proto = _m->parsed_uri.proto;
		set_sip_defaults(port, proto);
		si = grep_sock_info( &_m->parsed_uri.host, port, proto);
		if (si) {
			_m->force_send_socket = si;
		} else {
			if (enable_socket_mismatch_warning)
				LM_WARN("no socket found to match RR [%d][%.*s:%d]\n",
					proto, _m->parsed_uri.host.len, _m->parsed_uri.host.s, port);
		}
	}

	/* set the hooks for the params -bogdan
	 * important note: RURI is already parsed by the above function, so
	 * we just used it without any checking */
	ctx_rrparam_set( &_m->parsed_uri.params );

	if (is_strict(&puri.params)) {
		LM_DBG("Next hop: '%.*s' is strict router\n", uri.len, ZSW(uri.s));
		ctx_routing_set( ROUTING_SS );
		/* Previous hop was a strict router and the next hop is strict
		 * router too. There is no need to save R-URI again because it
		 * is saved already. In fact, in this case we will behave exactly
		 * like a strict router. */

		/* Note: when there is only one Route URI left (endpoint), it will
		 * always be a strict router because endpoints don't use ;lr parameter
		 * In this case we will simply put the URI in R-URI and forward it,
		 * which will work perfectly */
		if(get_maddr_uri(&uri, &puri)!=0) {
			LM_ERR("failed to check maddr\n");
			return RR_ERROR;
		}
		if (set_ruri(_m, &uri) < 0) {
			LM_ERR("failed to rewrite request URI\n");
			return RR_ERROR;
		}

		if (rt->next) {
			rem_off = hdr->body.s;
			rem_len = rt->next->nameaddr.name.s - hdr->body.s;
		} else {
			rem_off = hdr->name.s;
			rem_len = hdr->len;
		}
		if (!del_lump(_m, rem_off - _m->buf, rem_len, 0)) {
			LM_ERR("failed to remove Route HF\n");
			return RR_ERROR;
		}

		rt->deleted = 1;
	} else {
		LM_DBG("Next hop: '%.*s' is loose router\n",
			uri.len, ZSW(uri.s));

		ctx_routing_set( ROUTING_SL );

		if(get_maddr_uri(&uri, &puri)!=0) {
			LM_ERR("failed to check maddr\n");
			return RR_ERROR;
		}
		if (set_dst_uri(_m, &uri) < 0) {
			LM_ERR("failed to set dst_uri\n");
			return RR_ERROR;
		}

		/* Next hop is a loose router - Which means that is is not endpoint yet
		 * In This case we have to recover from previous strict routing, that
		 * means we have to find the last Route URI and put in in R-URI and
		 * remove the last Route URI. */
		if (rt != hdr->parsed) {
			/* There is a previous route uri which was 2nd uri of mine
			 * and must be removed here */
			rem_off = hdr->body.s;
			rem_len = rt->nameaddr.name.s - hdr->body.s;
			if (!del_lump(_m, rem_off - _m->buf, rem_len, 0)) {
				LM_ERR("failed to remove Route HF\n");
				return RR_ERROR;
			}

			del_rt = (rr_t*)hdr->parsed;
			/* mark route hdr as deleted */
			del_rt->deleted = 1;
		}

		res = find_rem_target(_m, &hdr, &rt, &prev);
		if (res < 0) {
			LM_ERR("searching for last Route URI failed\n");
			return RR_ERROR;
		} else if (res > 0) {
			/* No remote target is an error */
			return RR_ERROR;
		}

		uri = rt->nameaddr.uri;
		if(get_maddr_uri(&uri, 0)!=0) {
			LM_ERR("checking maddr failed\n");
			return RR_ERROR;
		}
		if (set_ruri(_m, &uri) < 0) {
			LM_ERR("failed to rewrite R-URI\n");
			return RR_ERROR;
		}

		/* mark remote contact route as deleted */
		rt->deleted = 1;

		/* The first character if uri will be either '<' when it is the
		 * only URI in a Route header field or ',' if there is more than
		 * one URI in the header field */
		LM_DBG("The last route URI: '%.*s'\n", rt->nameaddr.uri.len,
				ZSW(rt->nameaddr.uri.s));

		if (prev && prev!=del_rt) {
			rem_off = prev->nameaddr.name.s + prev->len;
			rem_len = rt->nameaddr.name.s + rt->len - rem_off;
		} else {
			rem_off = hdr->name.s;
			rem_len = hdr->len;
		}
		if (!del_lump(_m, rem_off - _m->buf, rem_len, 0)) {
			LM_ERR("failed to remove Route HF\n");
			return RR_ERROR;
		}

	}

	/* run RR callbacks -bogdan */
	run_rr_callbacks( _m, ctx_rrparam_get() );

	return RR_DRIVEN;
}


static inline int after_loose(struct sip_msg* _m, int preloaded)
{
	struct hdr_field* hdr;
	struct sip_uri puri;
	struct sip_uri puri2;
	rr_t* rt;
	int res;
	int status;
#ifdef ENABLE_USER_CHECK
	int ret;
#endif
	str uri;
	struct socket_info *si;
	int force_ss = 0;

	hdr = _m->route;
	rt = (rr_t*)hdr->parsed;
	uri = rt->nameaddr.uri;

	if (parse_uri(uri.s, uri.len, &puri) < 0) {
		LM_ERR("failed to parse the first route URI\n");
		return RR_ERROR;
	}

	/* IF the URI was added by me, remove it */
#ifdef ENABLE_USER_CHECK
	ret=is_myself(&puri.user, &puri);
	if (ret>0)
#else
	if (is_myself(&puri))
#endif
	{
		LM_DBG("Topmost route URI: '%.*s' is me\n",
			uri.len, ZSW(uri.s));
		/* set the hooks for the params -bogdan */
		ctx_rrparam_set( &puri.params );

		/* if last route in header, gonna get del_lumped now,
		 * if not, it will be taken care of later
		 * Mark it now as deleted */
		rt->deleted = 1;

		if (!rt->next) {
			/* No next route in the same header, remove the whole header
			 * field immediately
			 */
			if (!del_lump(_m, hdr->name.s - _m->buf, hdr->len, 0)) {
				LM_ERR("failed to remove Route HF\n");
				return RR_ERROR;
			}

			rt->deleted = 1;

			res = find_next_route(_m, &hdr);
			if (res < 0) {
				LM_ERR("failed to find next route\n");
				return RR_ERROR;
			}
			if (res > 0) { /* No next route found */
				LM_DBG("No next URI found!\n");
				status = (preloaded ? NOT_RR_DRIVEN : RR_DRIVEN);

				/*same case as LL , if there is no next route*/
				ctx_routing_set( ROUTING_LL );
				force_ss = 1;

				goto done;
			}
			rt = (rr_t*)hdr->parsed;
		} else rt = rt->next;

		if (enable_double_rr && is_2rr(&puri.params)) {
			force_ss = 0;
			/* double route may occure due different IP and port, so force as
			 * send interface the one advertise in second Route */
			if (parse_uri(rt->nameaddr.uri.s,rt->nameaddr.uri.len,&puri)<0) {
				LM_ERR("failed to parse the double route URI\n");
				return RR_ERROR;
			}
			set_sip_defaults( puri.port_no, puri.proto);
			si = grep_sock_info( &puri.host, puri.port_no, puri.proto);
			if (si) {
				_m->force_send_socket = si;
			} else {
				if (enable_socket_mismatch_warning)
					LM_WARN("no socket found to match 2nd RR [%d][%.*s:%d]\n",
						puri.proto, puri.host.len, puri.host.s, puri.port_no);
			}

			rt->deleted = 1;

			if (!rt->next) {
				/* No next route in the same header, remove the whole header
				 * field immediately */
				if (!del_lump(_m, hdr->name.s - _m->buf, hdr->len, 0)) {
					LM_ERR("failed to remove Route HF\n");
					return RR_ERROR;
				}

				res = find_next_route(_m, &hdr);
				if (res < 0) {
					LM_ERR("failed to find next route\n");
					return RR_ERROR;
				}
				if (res > 0) { /* No next route found */
					LM_DBG("no next URI found\n");
					status = (preloaded ? NOT_RR_DRIVEN : RR_DRIVEN);

					/* same case as LL , if there is no next route */
					ctx_routing_set( ROUTING_LL );

					goto done;
				}
				rt = (rr_t*)hdr->parsed;
			} else rt = rt->next;
		} else {
			force_ss = 1;
		}

		uri = rt->nameaddr.uri;
		if (parse_uri(uri.s, uri.len, &puri2) < 0) {
			LM_ERR("failed to parse the first route URI\n");
			return RR_ERROR;
		}
	} else {
#ifdef ENABLE_USER_CHECK
		/* check if it the ignored user */
		if(ret < 0)
			return NOT_RR_DRIVEN;
#endif
		LM_DBG("Topmost URI is NOT myself\n");
		memcpy(&puri2, &puri, sizeof(struct sip_uri));
	}

	LM_DBG("URI to be processed: '%.*s'\n", uri.len, ZSW(uri.s));
	if (is_strict(&puri2.params)) {
		LM_DBG("Next URI is a strict router\n");

		ctx_routing_set( ROUTING_LS );
		if (handle_sr(_m, hdr, rt) < 0) {
			LM_ERR("failed to handle strict router\n");
			return RR_ERROR;
		}
	} else {
		/* Next hop is loose router */
		LM_DBG("Next URI is a loose router\n");

		ctx_routing_set( ROUTING_LL );

		if(get_maddr_uri(&uri, &puri2)!=0) {
			LM_ERR("checking maddr failed\n");
			return RR_ERROR;
		}
		if (set_dst_uri(_m, &uri) < 0) {
			LM_ERR("failed to set dst_uri\n");
			return RR_ERROR;
		}

		/* There is a previous route uri which was 2nd uri of mine
		 * and must be removed here */
		if (rt != hdr->parsed) {
			if (!del_lump(_m, hdr->body.s - _m->buf,
			rt->nameaddr.name.s - hdr->body.s, 0)) {
				LM_ERR("failed to remove Route HF\n");
				return RR_ERROR;
			}

			((rr_t *)hdr->parsed)->deleted = 1;
		}
	}
	status = RR_DRIVEN;

done:
	if (force_ss && !preloaded)
		_m->force_send_socket = _m->rcv.bind_address;
	/* run RR callbacks -bogdan */
	run_rr_callbacks( _m, &puri.params );
	return status;
}


/*
 * Do loose routing as defined in RFC3261
 */
int loose_route(struct sip_msg* _m)
{
	int ret;

	ctx_routing_set(0);

	if (find_first_route(_m) != 0) {
		LM_DBG("There is no Route HF\n");
		return -1;
	}

	if (parse_sip_msg_uri(_m)<0) {
		LM_ERR("failed to parse Request URI\n");
		return -1;
	}

	ret = is_preloaded(_m);
	if (ret < 0) {
		return -1;
	} else if (ret == 1) {
		return after_loose(_m, 1);
	} else {
#ifdef ENABLE_USER_CHECK
		if (is_myself(&_m->parsed_uri.user, &_m->parsed_uri) && !(_m->parsed_uri.gr.s && _m->parsed_uri.gr.len)) {
#else
		if (is_myself(&_m->parsed_uri) && !(_m->parsed_uri.gr.s && _m->parsed_uri.gr.len)) {
#endif
			return after_strict(_m);
		} else {
			return after_loose(_m, 0);
		}
	}
}


int get_route_params(struct sip_msg *msg, str *val)
{
	if(msg==NULL)
		return -1;

	/* check if params are present */
	*val = *ctx_rrparam_get();
	if (val->s==NULL || val->len==0)
		return -1;

	return 0;
}


int check_route_param(struct sip_msg * msg, regex_t* re)
{
	regmatch_t pmatch;
	char bk;
	str params;
	str *rparams;

	/* check if params are present */
	rparams = ctx_rrparam_get();
	if (rparams->s==NULL || rparams->len==0)
		return -1;

	/* include also the first ';' */
	for( params=*rparams ; params.s[0]!=';' ; params.s--,params.len++ );

	/* do the well-known trick to convert to null terminted */
	bk = params.s[params.len];
	params.s[params.len] = 0;
	LM_DBG("params are <%s>\n", params.s);
	if (regexec( re, params.s, 1, &pmatch, 0)!=0) {
		params.s[params.len] = bk;
		return -1;
	} else {
		params.s[params.len] = bk;
		return 0;
	}
}



int get_route_param( struct sip_msg *msg, str *name, str *val)
{
	char *p;
	char *end;
	char c;
	int quoted;
	str *rparams;

	/* check if params are present */
	rparams = ctx_rrparam_get();
	if (rparams->s==NULL || rparams->len==0)
		goto notfound;

	end = rparams->s + rparams->len;
	p = rparams->s;

	/* parse the parameters string and find the "name" param */
	while ( end-p>name->len+2 ) {
		if (p!=rparams->s) {
			/* go to first ';' char */
			for( quoted=0 ; p<end && !(*p==';' && !quoted) ; p++ )
				if ( (*p=='"' || *p=='\'') && *(p-1)!='\\' )
					quoted ^= 0x1;
			if (p==end)
				goto notfound;
			p++;
		}
		/* get first non space char */
		while( p<end && (*p==' ' || *p=='\t') )
			p++;
		/* check the name - length first and content after */
		if ( end-p<name->len+2 )
			goto notfound;
		if ( memcmp(p,name->s,name->len)!=0 ) {
			p++;
			continue;
		}
		p+=name->len;
		while( p<end && (*p==' ' || *p=='\t') )
			p++;
		if (p==end|| *p==';') {
			/* empty val */
			val->len = 0;
			val->s = 0;
			goto found;
		}
		if (*(p++)!='=')
			continue;
		while( p<end && (*p==' ' || *p=='\t') )
			p++;
		if (p==end)
			goto notfound;
		/* get value */
		if ( *p=='\'' || *p=='"') {
			for( val->s = ++p ; p<end ; p++) {
				if ((*p=='"' || *p=='\'') && *(p-1)!='\\' )
					break;
			}
		} else {
			for( val->s=p ; p<end ; p++) {
				if ( (c=*p)==';' || c==' ' || c=='\t' )
					break;
			}
		}
		val->len = p-val->s;
		if (val->len==0)
			val->s = 0;
		goto found;
	}

notfound:
	return -1;
found:
	return 0;
}


int is_direction(struct sip_msg * msg, int dir)
{
	static str ftag_param = {"ftag",4};
	static unsigned int last_id = (unsigned int)-1;
	static unsigned int last_dir = 0;
	str ftag_val;
	str tag;

	if ( last_id==msg->id && last_dir!=0) {
		if (last_dir==RR_FLOW_UPSTREAM)
			goto upstream;
		else
			goto downstream;
	}

	ftag_val.s = 0;
	ftag_val.len = 0;

	if (get_route_param( msg, &ftag_param, &ftag_val)!=0) {
		LM_DBG("param ftag not found\n");
		goto downstream;
	}

	if ( ftag_val.s==0 || ftag_val.len==0 ) {
		LM_DBG("param ftag has empty val\n");
		goto downstream;
	}

	/* get the tag value from FROM hdr */
	if ( parse_from_header(msg)!=0 )
		goto downstream;

	tag = ((struct to_body*)msg->from->parsed)->tag_value;
	if (tag.s==0 || tag.len==0)
		goto downstream;

	/* compare the 2 strings */
	if (tag.len!=ftag_val.len || memcmp(tag.s,ftag_val.s,ftag_val.len))
		goto upstream;

downstream:
	last_id = msg->id;
	last_dir = RR_FLOW_DOWNSTREAM;
	return (dir==RR_FLOW_DOWNSTREAM)?0:-1;
upstream:
	last_id = msg->id;
	last_dir = RR_FLOW_UPSTREAM;
	return (dir==RR_FLOW_UPSTREAM)?0:-1;
}


str* get_remote_target(struct sip_msg *msg)
{
	int res;
	struct hdr_field *hdr;
	rr_t *rt,*prev;
	str *uri;
	int routing_type;

	if (msg == NULL) {
		LM_ERR("null sip msg\n");
		return 0;
	}

	routing_type = ctx_routing_get();
	if ((routing_type == ROUTING_LL) || (routing_type == ROUTING_LS))
		return &msg->first_line.u.request.uri;
	else if (routing_type == ROUTING_SL)
		/* set by loose_route(), recovered from previous strict routing */
		return &msg->new_uri;
	else if (routing_type == ROUTING_SS)
	{
		/* searching for last header field */
		res = find_rem_target(msg, &hdr, &rt, &prev);
		if (res < 0)
		{
			LM_ERR("searching for last Route URI failed\n");
			return 0;
		}
		else if (res > 0)
		{
			/* No remote target is an error */
			LM_ERR("couldn't find any remote target !\n");
			return 0;
		}

		uri = &rt->nameaddr.uri;
		if(get_maddr_uri(uri, 0)!=0)
		{
			LM_ERR("failed to check maddr\n");
			return 0;
		}

		return uri;
	}
	else
	{
		LM_ERR("Invalid routing type - %d\n",routing_type);
		return 0;
	}
}


#define MAX_RR_HDRS 64
str* get_route_set(struct sip_msg *msg,int *nr_routes)
{
	static str uris[MAX_RR_HDRS];
	struct hdr_field *it;
	rr_t *p;
	int n = 0;
	int routing_type;

	if (msg == NULL || msg->route == NULL)
	{
		LM_ERR("null sip msg or no route headers\n");
		return 0;
	}

	routing_type = ctx_routing_get();
	if (routing_type == ROUTING_SS || routing_type == ROUTING_LS)
	{
		/* must manually insert RURI, as it was part
		 * of the route deleted to make up for strict routing */
		uris[n++] = msg->new_uri;
	}

	it = msg->route;
	while (it != NULL)
	{
		if (parse_rr(it) < 0)
		{
			LM_ERR("failed to parse RR\n");
			return 0;
		}

		p = (rr_t*)it->parsed;
		while (p)
		{
			if (p->deleted == 0)
			{
				uris[n++] = p->nameaddr.uri;
				if(n==MAX_RR_HDRS)
				{
					LM_ERR("too many RR\n");
					return 0;
				}
			}
			else
				LM_DBG("Route [%.*s] has been deleted\n",p->nameaddr.uri.len,
						p->nameaddr.uri.s);
			p = p->next;
		}
		it = it->sibling;
	}


	/* if SS - remove last route */
	if (routing_type == ROUTING_SS)
		n--;

	if (nr_routes)
		*nr_routes = n;

	return uris;
}
