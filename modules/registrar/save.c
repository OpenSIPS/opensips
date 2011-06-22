/*
 * $Id$
 *
 * Process REGISTER request and send reply
 *
 * Copyright (C) 2001-2003 FhG Fokus
 * Copyright (C) 2006 Voice Sistem SRL
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
 * ----------
 * 2003-01-27 next baby-step to removing ZT - PRESERVE_ZT (jiri)
 * 2003-02-28 scrathcpad compatibility abandoned (jiri)
 * 2003-03-21 save_noreply added, patch provided by Maxim Sobolev 
 *            <sobomax@portaone.com> (janakj)
 * 2005-07-11 added sip_natping_flag for nat pinging with SIP method
 *            instead of UDP package (bogdan)
 * 2006-04-13 added tcp_persistent_flag for keeping the TCP connection as long
 *            as a TCP contact is registered (bogdan)
 * 2006-11-22 save_noreply and save_memory merged into save() (bogdan)
 * 2006-11-28 Added statistic support for the number of accepted/rejected 
 *            registrations. (Jeffrey Magder - SOMA Networks) 
 * 2007-02-24  sip_natping_flag moved into branch flags, so migrated to 
 *             nathelper module (bogdan)
 */
/*!
 * \file
 * \brief SIP registrar module - Process REGISTER request and send reply
 * \ingroup registrar   
 */  


#include "../../str.h"
#include "../../socket_info.h"
#include "../../parser/parse_allow.h"
#include "../../parser/parse_methods.h"
#include "../../parser/msg_parser.h"
#include "../../parser/parse_uri.h"
#include "../../parser/parse_expires.h"
#include "../../dprint.h"
#include "../../trim.h"
#include "../../ut.h"
#include "../../qvalue.h"
#include "../../dset.h"
#include "../../mod_fix.h"
#include "../../data_lump.h"
#ifdef USE_TCP
#include "../../tcp_server.h"
#endif
#include "../usrloc/usrloc.h"
#include "common.h"
#include "sip_msg.h"
#include "rerrno.h"
#include "reply.h"
#include "reg_mod.h"
#include "regtime.h"
#include "path.h"
#include "save.h"


struct save_ctx {
	unsigned int flags;
	str aor;
	unsigned int max_contacts;
};


/*! \brief
 * Process request that contained a star, in that case, 
 * we will remove all bindings with the given username 
 * from the usrloc and return 200 OK response
 */
static inline int star(udomain_t* _d, struct save_ctx *_sctx)
{
	urecord_t* r;
	ucontact_t* c;
	
	ul.lock_udomain(_d, &_sctx->aor);

	if (!ul.get_urecord(_d, &_sctx->aor, &r)) {
		c = r->contacts;
		while(c) {
			if (_sctx->flags&REG_SAVE_MEMORY_FLAG) {
				c->flags |= FL_MEM;
			} else {
				c->flags &= ~FL_MEM;
			}
			c = c->next;
		}
	}

	if (ul.delete_urecord(_d, &_sctx->aor, 0) < 0) {
		LM_ERR("failed to remove record from usrloc\n");
		
		     /* Delete failed, try to get corresponding
		      * record structure and send back all existing
		      * contacts
		      */
		rerrno = R_UL_DEL_R;
		if (!ul.get_urecord(_d, &_sctx->aor, &r)) {
			build_contact(r->contacts);
		}
		ul.unlock_udomain(_d, &_sctx->aor);
		return -1;
	}
	ul.unlock_udomain(_d, &_sctx->aor);
	return 0;
}


/*! \brief
 */
static struct socket_info *get_sock_hdr(struct sip_msg *msg)
{
	struct socket_info *sock;
	struct hdr_field *hf;
	str socks;
	str hosts;
	int port;
	int proto;

	if (parse_headers( msg, HDR_EOH_F, 0) == -1) {
		LM_ERR("failed to parse message\n");
		return 0;
	}

	hf = get_header_by_name( msg, sock_hdr_name.s, sock_hdr_name.len);
	if (hf==0)
		return 0;

	trim_len( socks.len, socks.s, hf->body );
	if (socks.len==0)
		return 0;

	if (parse_phostport( socks.s, socks.len, &hosts.s, &hosts.len, 
	&port, &proto)!=0) {
		LM_ERR("bad socket <%.*s> in \n",
			socks.len, socks.s);
		return 0;
	}
	set_sip_defaults( port, proto);
	sock = grep_sock_info(&hosts,(unsigned short)port,(unsigned short)proto);
	if (sock==0) {
		LM_ERR("non-local socket <%.*s>\n",	socks.len, socks.s);
		return 0;
	}

	LM_DBG("%d:<%.*s>:%d -> p=%p\n", proto,socks.len,socks.s,port_no,sock );

	return sock;
}



/*! \brief
 * Process request that contained no contact header
 * field, it means that we have to send back a response
 * containing a list of all existing bindings for the
 * given username (in To HF)
 */
static inline int no_contacts(udomain_t* _d, str* _a)
{
	urecord_t* r;
	int res;
	
	ul.lock_udomain(_d, _a);
	res = ul.get_urecord(_d, _a, &r);
	if (res < 0) {
		rerrno = R_UL_GET_R;
		LM_ERR("failed to retrieve record from usrloc\n");
		ul.unlock_udomain(_d, _a);
		return -1;
	}
	
	if (res == 0) {  /* Contacts found */
		build_contact(r->contacts);
	}
	ul.unlock_udomain(_d, _a);
	return 0;
}



/*! \brief
 * Fills the common part (for all contacts) of the info structure
 */
static inline ucontact_info_t* pack_ci( struct sip_msg* _m, contact_t* _c,
						unsigned int _e, unsigned int _f, unsigned int _flags)
{
	static ucontact_info_t ci;
	static str no_ua = str_init("n/a");
	static str callid;
	static str path_received = {0,0};
	static str path;
	static str received = {0,0};
	static int received_found;
	static unsigned int allowed, allow_parsed;
	static struct sip_msg *m = 0;
	int_str val;

	if (_m!=0) {
		memset( &ci, 0, sizeof(ucontact_info_t));

		/* Get callid of the message */
		callid = _m->callid->body;
		trim_trailing(&callid);
		if (callid.len > CALLID_MAX_SIZE) {
			rerrno = R_CALLID_LEN;
			LM_ERR("callid too long\n");
			goto error;
		}
		ci.callid = &callid;

		/* Get CSeq number of the message */
		if (str2int(&get_cseq(_m)->number, (unsigned int*)&ci.cseq) < 0) {
			rerrno = R_INV_CSEQ;
			LM_ERR("failed to convert cseq number\n");
			goto error;
		}

		/* set received socket */
		if ( _flags&REG_SAVE_SOCKET_FLAG) {
			ci.sock = get_sock_hdr(_m);
			if (ci.sock==0)
				ci.sock = _m->rcv.bind_address;
		} else {
			ci.sock = _m->rcv.bind_address;
		}

		/* additional info from message */
		if (parse_headers(_m, HDR_USERAGENT_F, 0) != -1 && _m->user_agent &&
		_m->user_agent->body.len>0 && _m->user_agent->body.len<UA_MAX_SIZE) {
			ci.user_agent = &_m->user_agent->body;
		} else {
			ci.user_agent = &no_ua;
		}

		/* extract Path headers */
		if ( _flags&REG_SAVE_PATH_FLAG ) {
			if (build_path_vector(_m, &path, &path_received, _flags) < 0) {
				rerrno = R_PARSE_PATH;
				goto error;
			}
			if (path.len && path.s) {
				ci.path = &path;
				/* save in msg too for reply */
				if (set_path_vector(_m, &path) < 0) {
					rerrno = R_PARSE_PATH;
					goto error;
				}
			}
		}

		ci.last_modified = act_time;

		/* set flags */
		ci.flags  = _f;
		ci.cflags =  getb0flags();

		/* get received */
		if (path_received.len && path_received.s) {
			ci.cflags |= ul.nat_flag;
			ci.received = path_received;
		}

		allow_parsed = 0; /* not parsed yet */
		received_found = 0; /* not found yet */
		m = _m; /* remember the message */
	}

	if(_c!=0) {
		/* Calculate q value of the contact */
		if (calc_contact_q(_c->q, &ci.q) < 0) {
			rerrno = R_INV_Q;
			LM_ERR("failed to calculate q\n");
			goto error;
		}

		/* set expire time */
		ci.expires = _e;

		/* Get methods of contact */
		if (_c->methods) {
			if (parse_methods(&(_c->methods->body), &ci.methods) < 0) {
				rerrno = R_PARSE;
				LM_ERR("failed to parse contact methods\n");
				goto error;
			}
		} else {
			/* check on Allow hdr */
			if (allow_parsed == 0) {
				if (m && parse_allow( m ) != -1) {
					allowed = get_allow_methods(m);
				} else {
					allowed = ALL_METHODS;
				}
				allow_parsed = 1;
			}
			ci.methods = allowed;
		}

		/* get received */
		if (ci.received.len==0) {
			if (_c->received) {
				ci.received = _c->received->body;
			} else {
				if (received_found==0) {
					memset(&val, 0, sizeof(int_str));
					if (rcv_avp_name>=0
								&& search_first_avp(rcv_avp_type, rcv_avp_name, &val, 0)
								&& val.s.len > 0) {
						if (val.s.len>RECEIVED_MAX_SIZE) {
							rerrno = R_CONTACT_LEN;
							LM_ERR("received too long\n");
							goto error;
						}
						received = val.s;
					} else {
						received.s = 0;
						received.len = 0;
					}
					received_found = 1;
				}
				ci.received = received;
			}
		}

	}

	return &ci;
error:
	return 0;
}



/*! \brief
 * Message contained some contacts, but record with same address
 * of record was not found so we have to create a new record
 * and insert all contacts from the message that have expires
 * > 0
 */
static inline int insert_contacts(struct sip_msg* _m, contact_t* _c,
								udomain_t* _d, str* _a, struct save_ctx *_sctx)
{
	ucontact_info_t* ci;
	urecord_t* r;
	ucontact_t* c;
	unsigned int cflags;
	int num;
	int e;
#ifdef USE_TCP
	int e_max;
	int tcp_check;
	struct sip_uri uri;
#endif

	cflags = (_sctx->flags&REG_SAVE_MEMORY_FLAG)?FL_MEM:FL_NONE;
#ifdef USE_TCP
	if ( (_m->flags&tcp_persistent_flag) &&
	(_m->rcv.proto==PROTO_TCP||_m->rcv.proto==PROTO_TLS)) {
		e_max = 0;
		tcp_check = 1;
	} else {
		e_max = tcp_check = 0;
	}
#endif

	for( num=0,r=0,ci=0 ; _c ; _c = get_next_contact(_c) ) {
		/* calculate expires */
		calc_contact_expires(_m, _c->expires, &e);
		/* Skip contacts with zero expires */
		if (e == 0)
			continue;

		if (_sctx->max_contacts && (num >= _sctx->max_contacts)) {
			if (_sctx->flags&REG_SAVE_FORCE_REG_FLAG) {
				/* we are overflowing the number of maximum contacts,
				   so remove the first (oldest) one to prevent this */
				if (r==NULL || r->contacts==NULL) {
					LM_CRIT("BUG - overflow detected with r=%p and "
						"contacts=%p\n",r,r->contacts);
					goto error;
				}
				if (ul.delete_ucontact( r, r->contacts)!=0) {
					LM_ERR("failed to remove contact\n");
					goto error;
				}
			} else {
				LM_INFO("too many contacts (%d) for AOR <%.*s>, max=%d\n", 
						num, _a->len, _a->s, _sctx->max_contacts);
				rerrno = R_TOO_MANY;
				goto error;
			}
		} else {
			num++;
		}

		if (r==0) {
			if (ul.insert_urecord(_d, _a, &r) < 0) {
				rerrno = R_UL_NEW_R;
				LM_ERR("failed to insert new record structure\n");
				goto error;
			}
		}

		/* pack the contact_info */
		if ( (ci=pack_ci( (ci==0)?_m:0, _c, e, cflags, _sctx->flags))==0 ) {
			LM_ERR("failed to extract contact info\n");
			goto error;
		}

		if ( r->contacts==0 ||
		ul.get_ucontact(r, &_c->uri, ci->callid, ci->cseq+1, &c)!=0 ) {
			if (ul.insert_ucontact( r, &_c->uri, ci, &c) < 0) {
				rerrno = R_UL_INS_C;
				LM_ERR("failed to insert contact\n");
				goto error;
			}
		} else {
			if (ul.update_ucontact( r, c, ci) < 0) {
				rerrno = R_UL_UPD_C;
				LM_ERR("failed to update contact\n");
				goto error;
			}
		}
#ifdef USE_TCP
		if (tcp_check) {
			/* parse contact uri to see if transport is TCP */
			if (parse_uri( _c->uri.s, _c->uri.len, &uri)<0) {
				LM_ERR("failed to parse contact <%.*s>\n", 
						_c->uri.len, _c->uri.s);
			} else if (uri.proto==PROTO_TCP || uri.proto==PROTO_TLS) {
				if (e_max) {
					LM_WARN("multiple TCP contacts on single REGISTER\n");
					if (e>e_max) e_max = e;
				} else {
					e_max = e;
				}
			}
		}
#endif
	}

	if (r) {
		if (r->contacts)
			build_contact(r->contacts);
		ul.release_urecord(r);
	}

#ifdef USE_TCP
	if ( tcp_check && e_max>0 ) {
		e_max -= act_time;
		force_tcp_conn_lifetime( &_m->rcv , e_max + 10 );
	}
#endif

	return 0;
error:
	if (r)
		ul.delete_urecord(_d, _a, r);
	return -1;
}



/*! \brief
 * Message contained some contacts and appropriate
 * record was found, so we have to walk through
 * all contacts and do the following:
 * 1) If contact in usrloc doesn't exists and
 *    expires > 0, insert new contact
 * 2) If contact in usrloc exists and expires
 *    > 0, update the contact
 * 3) If contact in usrloc exists and expires
 *    == 0, delete contact
 */
static inline int update_contacts(struct sip_msg* _m, urecord_t* _r,
										contact_t* _c, struct save_ctx *_sctx)
{
	ucontact_info_t *ci;
	ucontact_t* c;
	int e;
	unsigned int cflags;
	int ret;
	int num;
#ifdef USE_TCP
	int e_max;
	int tcp_check;
	struct sip_uri uri;
#endif

	/* mem flag */
	cflags = (_sctx->flags&REG_SAVE_MEMORY_FLAG)?FL_MEM:FL_NONE;

	/* pack the contact_info */
	if ( (ci=pack_ci( _m, 0, 0, cflags, _sctx->flags))==0 ) {
		LM_ERR("failed to initial pack contact info\n");
		goto error;
	}

	/* count how many contacts we have right now */
	num = 0;
	if (_sctx->max_contacts) {
		c = _r->contacts;
		while(c) {
			if (VALID_CONTACT(c, act_time)) num++;
			c = c->next;
		}
	}

#ifdef USE_TCP
	if ( (_m->flags&tcp_persistent_flag) &&
	(_m->rcv.proto==PROTO_TCP||_m->rcv.proto==PROTO_TLS)) {
		e_max = -1;
		tcp_check = 1;
	} else {
		e_max = tcp_check = 0;
	}
#endif

	for( ; _c ; _c = get_next_contact(_c) ) {
		/* calculate expires */
		calc_contact_expires(_m, _c->expires, &e);

		/* search for the contact*/
		ret = ul.get_ucontact( _r, &_c->uri, ci->callid, ci->cseq, &c);
		if (ret==-1) {
			LM_ERR("invalid cseq for aor <%.*s>\n",_r->aor.len,_r->aor.s);
			rerrno = R_INV_CSEQ;
			goto error;
		} else if (ret==-2) {
			continue;
		}

		if ( ret > 0 ) {
			/* Contact not found -> expired? */
			if (e==0)
				continue;

			/* we need to add a new contact -> too many ?? */
			if (_sctx->max_contacts && num>=_sctx->max_contacts) {
				if (_sctx->flags&REG_SAVE_FORCE_REG_FLAG) {
					/* we are overflowing the number of maximum contacts,
					   so remove the first (oldest) one to prevent this */
					if (_r==NULL || _r->contacts==NULL) {
						LM_CRIT("BUG - overflow detected with r=%p and "
							"contacts=%p\n",_r,_r->contacts);
						goto error;
					}
					if (ul.delete_ucontact( _r, _r->contacts)!=0) {
						LM_ERR("failed to remove contact\n");
						goto error;
					}
				} else {
					LM_INFO("too many contacts for AOR <%.*s>, max=%d\n",
						_r->aor.len, _r->aor.s, _sctx->max_contacts);
					rerrno = R_TOO_MANY;
					return -1;
				}
			}

			/* pack the contact_info */
			if ( (ci=pack_ci( 0, _c, e, 0, _sctx->flags))==0 ) {
				LM_ERR("failed to extract contact info\n");
				goto error;
			}

			if (ul.insert_ucontact( _r, &_c->uri, ci, &c) < 0) {
				rerrno = R_UL_INS_C;
				LM_ERR("failed to insert contact\n");
				goto error;
			}
		} else {
			/* Contact found */
			if (e == 0) {
				/* it's expired */
				if (_sctx->flags&REG_SAVE_MEMORY_FLAG) {
					c->flags |= FL_MEM;
				} else {
					c->flags &= ~FL_MEM;
				}

				if (ul.delete_ucontact(_r, c) < 0) {
					rerrno = R_UL_DEL_C;
					LM_ERR("failed to delete contact\n");
					goto error;
				}
			} else {
				/* do update */
				/* pack the contact specific info */
				if ( (ci=pack_ci( 0, _c, e, 0, _sctx->flags))==0 ) {
					LM_ERR("failed to pack contact specific info\n");
					goto error;
				}

				if (ul.update_ucontact(_r, c, ci) < 0) {
					rerrno = R_UL_UPD_C;
					LM_ERR("failed to update contact\n");
					goto error;
				}
			}
		}
#ifdef USE_TCP
		if (tcp_check) {
			/* parse contact uri to see if transport is TCP */
			if (parse_uri( _c->uri.s, _c->uri.len, &uri)<0) {
				LM_ERR("failed to parse contact <%.*s>\n", 
						_c->uri.len, _c->uri.s);
			} else if (uri.proto==PROTO_TCP || uri.proto==PROTO_TLS) {
				if (e_max>0) {
					LM_WARN("multiple TCP contacts on single REGISTER\n");
				}
				if (e>e_max) e_max = e;
			}
		}
#endif
	}

#ifdef USE_TCP
	if ( tcp_check && e_max>-1 ) {
		if (e_max) e_max -= act_time;
		force_tcp_conn_lifetime( &_m->rcv , e_max + 10 );
	}
#endif

	return 0;
error:
	return -1;
}


/*! \brief
 * This function will process request that
 * contained some contact header fields
 */
static inline int add_contacts(struct sip_msg* _m, contact_t* _c,
							udomain_t* _d, struct save_ctx *_sctx)
{
	int res;
	urecord_t* r;

	ul.lock_udomain(_d, &_sctx->aor);
	res = ul.get_urecord(_d, &_sctx->aor, &r);
	if (res < 0) {
		rerrno = R_UL_GET_R;
		LM_ERR("failed to retrieve record from usrloc\n");
		ul.unlock_udomain(_d, &_sctx->aor);
		return -2;
	}

	if (res == 0) { /* Contacts found */
		if (update_contacts(_m, r, _c, _sctx) < 0) {
			build_contact(r->contacts);
			ul.release_urecord(r);
			ul.unlock_udomain(_d, &_sctx->aor);
			return -3;
		}
		build_contact(r->contacts);
		ul.release_urecord(r);
	} else {
		if (insert_contacts(_m, _c, _d, &_sctx->aor, _sctx) < 0) {
			ul.unlock_udomain(_d, &_sctx->aor);
			return -4;
		}
	}
	ul.unlock_udomain(_d, &_sctx->aor);
	return 0;
}


/*! \brief
 * Process REGISTER request and save it's contacts
 */
#define is_cflag_set(_name) ((sctx.flags)&(_name))
int save_aux(struct sip_msg* _m, str* forced_binding, char* _d, char* _f, char* _s)
{
	struct save_ctx  sctx;
	contact_t* c;
	contact_t* forced_c;
	int st;
	str uri;
	str flags_s;
	pv_value_t val;

	rerrno = R_FINE;
	memset( &sctx, 0 , sizeof(sctx));
	sctx.max_contacts = -1;

	sctx.flags = 0;
	if (_f && _f[0]!=0) {
		if (fixup_get_svalue( _m, (gparam_p)_f, &flags_s)!=0) {
			LM_ERR("invalid flags parameter");
			return -1;
		}
		for( st=0 ; st< flags_s.len ; st++ ) {
			switch (flags_s.s[st]) {
				case 'm': sctx.flags |= REG_SAVE_MEMORY_FLAG; break;
				case 'r': sctx.flags |= REG_SAVE_NOREPLY_FLAG; break;
				case 's': sctx.flags |= REG_SAVE_SOCKET_FLAG; break;
				case 'v': sctx.flags |= REG_SAVE_PATH_RECEIVED_FLAG; break;
				case 'f': sctx.flags |= REG_SAVE_FORCE_REG_FLAG; break;
				case 'c':
					sctx.max_contacts = 0;
					while (st<flags_s.len-1 && isdigit(flags_s.s[st+1])) {
						sctx.max_contacts = sctx.max_contacts*10 + 
							flags_s.s[st+1] - '0';
						st++;
					}
					break;
				case 'p':
					if (st<flags_s.len-1) {
						st++;
						if (flags_s.s[st]=='2') {
							sctx.flags |= REG_SAVE_PATH_STRICT_FLAG; break; }
						if (flags_s.s[st]=='1') {
							sctx.flags |= REG_SAVE_PATH_LAZY_FLAG; break; }
						if (flags_s.s[st]=='0') {
							sctx.flags |= REG_SAVE_PATH_OFF_FLAG; break; }
					}
				default: LM_WARN("unsuported flag %c \n",flags_s.s[st]);
			}
		}
	}
	if(route_type == ONREPLY_ROUTE)
		sctx.flags |= REG_SAVE_NOREPLY_FLAG;

	/* if no max_contact per AOR is defined, use the global one */
	if (sctx.max_contacts == -1)
		sctx.max_contacts = max_contacts;

	if (parse_message(_m) < 0) {
		goto error;
	}

	if (forced_binding) {
		if (parse_contacts(forced_binding, &forced_c) < 0) {
			LM_ERR("Unable to parse forced binding [%.*s]\n",
				forced_binding->len, forced_binding->s);
			goto error;
		}
		/* prevent processing all the headers from the message */
		reset_first_contact();
		st = 0;
		c = forced_c;
	} else {
		if (check_contacts(_m, &st) > 0) {
			goto error;
		}
		c = get_first_contact(_m);
	}

	get_act_time();

	if (_s) {
		if (pv_get_spec_value( _m, (pv_spec_p)_s, &val)!=0) {
			LM_ERR("failed to get PV value\n");
			return -1;
		}
		if ( (val.flags&PV_VAL_STR)==0 ) {
			LM_ERR("PV vals is not string\n");
			return -1;
		}
		uri = val.rs;
	} else {
		uri = get_to(_m)->uri;
	}


	if (extract_aor( &uri, &sctx.aor) < 0) {
		LM_ERR("failed to extract Address Of Record\n");
		goto error;
	}

	if (c == 0) {
		if (st) {
			if (star((udomain_t*)_d, &sctx) < 0) goto error;
		} else {
			if (no_contacts((udomain_t*)_d, &sctx.aor) < 0) goto error;
		}
	} else {
		if (add_contacts(_m, c, (udomain_t*)_d, &sctx) < 0) goto error;
	}

	update_stat(accepted_registrations, 1);

	if (!is_cflag_set(REG_SAVE_NOREPLY_FLAG) && (send_reply(_m,sctx.flags)<0))
		return -1;

	return 1;
error:
	update_stat(rejected_registrations, 1);

	if ( !is_cflag_set(REG_SAVE_NOREPLY_FLAG) )
		send_reply(_m,sctx.flags);

	return 0;
}

#define MAX_FORCED_BINDING_LEN 256
int save(struct sip_msg* _m, char* _d, char* _f, char* _s)
{
	struct sip_msg* msg = _m;
	struct cell* t = NULL;
	contact_t* _c;
	contact_t* reply_c = NULL;
	contact_t* request_c = NULL;
	int st;
	int ret;
	int requested_exp = 0;
	int enforced_exp = 0;
	int_str val;
	struct lump* l;
	char* p;
	char forced_binding_buf[MAX_FORCED_BINDING_LEN];
	str forced_binding = {NULL, 0};
	str *binding_uri;

	if(_m->first_line.type != SIP_REPLY)
		return save_aux(_m, NULL, _d, _f, _s);

	memset(&val, 0, sizeof(int_str));
	if(!tmb.t_gett) {
		LM_ERR("TM module not loaded - can not save on reply\n");
		return -1;
	}
	t = tmb.t_gett();
	if(!t || t==T_UNDEFINED) {
		LM_ERR("Transaction not created on Register - can not save on reply\n");
		return -1;
	}
	msg = t->uas.request;
	if(!msg) {
		LM_ERR("NULL request - can not save on reply\n");
		return -1;
	}

	if (parse_message(_m) < 0) return -1;
	if (check_contacts(_m, &st) > 0) return -1;
	if (parse_message(msg) < 0) return -1;
	if (check_contacts(msg, &st) > 0) return -1;

	/* msg - request
	   _m  - reply 
	*/
	request_c = get_first_contact(msg);
	if(request_c) {
		/* For now, we deal only with the first contact
		 * FIXME: implement multiple contact handling - see check_contacts() */
		if(!request_c->expires || !request_c->expires->body.len) {
			if (((exp_body_t*)(msg->expires->parsed))->valid) {
				requested_exp = ((exp_body_t*)(msg->expires->parsed))->val;
			} else {
				LM_WARN("No expired defined\n");
			}
		} else {
			if (str2int(&(request_c->expires->body), (unsigned int*)&requested_exp)<0) {
				LM_ERR("unable to get expires from [%.*s]\n",
					request_c->expires->body.len, request_c->expires->body.s);
				return -1;
			}
		}
		LM_DBG("Binding received from client [%.*s] with requested expires [%d]\n",
				request_c->uri.len, request_c->uri.s, requested_exp);

		/* We will use the Contact from request:
		 *  - check if a modified contact was set in avp */
		if (mct_avp_name >= 0 &&
			search_first_avp(mct_avp_type,mct_avp_name,&val,0)
			&& val.s.len > 0) {
			LM_DBG("Binding sent to upper registrar [%.*s]\n",
					val.s.len, val.s.s);
			binding_uri = &val.s;
		} else {
			binding_uri = &request_c->uri;
		}

		if (requested_exp) {
			/* Let's get the contact from reply */
			_c = get_first_contact(_m);
			while (_c) {
				if (compare_uris(binding_uri, NULL, &_c->uri, NULL) == 0) {
					if(_c->expires && _c->expires->body.len) {
						if(str2int(&(_c->expires->body),
							(unsigned int*)&enforced_exp)<0) {
							LM_ERR("unable to get expires from [%.*s]\n",
								_c->expires->body.len,
								_c->expires->body.s);
							return -1;
						}
						LM_DBG("Binding received from upper registrar"
							" [%.*s] with imposed expires [%d]\n",
							_c->uri.len, _c->uri.s, enforced_exp);
						reply_c = _c;
						forced_binding.len = request_c->uri.len + 11 +
									reply_c->expires->body.len;
						if (forced_binding.len <= MAX_FORCED_BINDING_LEN) {
							forced_binding.s = forced_binding_buf;
							forced_binding_buf[0] = '<';
							memcpy(&forced_binding_buf[1],
								request_c->uri.s,
								request_c->uri.len);
							memcpy(&forced_binding_buf[request_c->uri.len + 1],
								">;expires=", 10);
							memcpy(&forced_binding_buf[request_c->uri.len + 11],
								reply_c->expires->body.s,
								reply_c->expires->body.len);
							LM_DBG("forcing binding [%.*s]\n",
								forced_binding.len,
								forced_binding.s);
							break;
						} else {
							LM_ERR("forced binding to BIG:"
								" %d > MAX_FORCED_BINDING_LEN\n",
								forced_binding.len);
							return -1;
						}
					}
				} else {
					LM_DBG("Unmatched binding [%.*s]\n",
							_c->uri.len, _c->uri.s);
				}
				_c = get_next_contact(_c);
			}
		}
		ret = save_aux(msg, forced_binding.s?&forced_binding:NULL, _d, _f, _s);
	} else {
		LM_DBG("No Contact in request => this is an interogation\n");
		ret = 1;
	}


	/* if the contact was changed in register - put the modif value */
	if(request_c && requested_exp && val.s.s) {
		if(reply_c) {
			LM_DBG("replacing contact uri [%.*s] with [%.*s]\n",
				reply_c->uri.len, reply_c->uri.s,
				request_c->uri.len, request_c->uri.s);
			/* replace with what was received in Register */
			/* reply_c->uri - now contains the initial received value */
			if((l=del_lump(_m, reply_c->uri.s - _m->buf, reply_c->uri.len, 0))==0) {
				LM_ERR("Failed to delete contact uri lump\n");
				ret = -1;
				goto done;
			}
			p = pkg_malloc( request_c->uri.len);
			if (p==0) {
				LM_ERR("no more pkg mem\n");
				ret = -1;
				goto done;
			}
			memcpy( p, request_c->uri.s, request_c->uri.len );
			if (insert_new_lump_after( l, p, request_c->uri.len, 0)==0) {
				LM_ERR("insert new lump failed\n");
				pkg_free(p);
				ret =-1;
				goto done;
			}
		}
	}

done:
	clean_msg_clone(t->uas.request, t->uas.request, t->uas.end_request);

	return ret;
}


int is_other_contact_f(struct sip_msg* msg, char* _d, char *_s)
{
	pv_spec_p spec = (pv_spec_p)_s;
	struct usr_avp *avp = NULL;
	urecord_t *r = NULL;
	str ip, contact;
	str uri, aor;
	ucontact_t *c;
	contact_t* ct;
	int exp, found;
	udomain_t* ud = (udomain_t*)_d;
	
	if (parse_message(msg) < 0) {
		LM_ERR("unable to parse message\n");
		return -2;
	}
	if (!ud) {
		LM_ERR("no location specified\n");
		return -2;
	}
	/* msg doesn't have contacts */
	if (!msg->contact ||
			!(ct = (((contact_body_t*)msg->contact->parsed)->contacts)))
		return -1;


	while (ct) {
		/* if expires is 0 */
		calc_contact_expires(msg, ct->expires, &exp);
		if (exp)
			break;
		ct = ct->next;
	}

	if (!ct) {
		LM_DBG("contact has expire 0\n");
		return -1;
	}

	uri = get_to(msg)->uri;
	if (extract_aor(&uri, &aor) < 0) {
		LM_ERR("failed to extract AOR record\n");
		return -2;
	}

	ul.lock_udomain(ud, &aor);
	ul.get_urecord(ud, &aor, &r);
	if (!r) {
		/* dont't test anything */
		LM_DBG("no contact found for aor=<%.*s>\n", aor.len, aor.s);
		found = -1;
		goto end;
	} else {
		c = r->contacts;
	}	

	while (c) {
		if (!c->received.len || !c->received.s || c->received.len < 4 /* sip:*/) {
			c = c->next;
			continue;
		}

		contact.s = c->received.s + 4;
		/* check for "sips:" */
		if (*contact.s == ':') {
			contact.len = c->received.len - 5;
			contact.s++;
		} else {
			/* skip "sip:" */
			contact.len = c->received.len - 4;
		}

		avp = NULL;
		found = 0;

		/* the ip should always be a string */
		while ((avp = search_first_avp(spec->pvp.pvn.u.isname.type,
						spec->pvp.pvn.u.isname.name.n, (int_str *)&ip, avp))!=0) {
			if (!(avp->flags & AVP_VAL_STR)) {
				LM_NOTICE("avp value should be string\n");
				continue;
			}
			if ((contact.len == ip.len || (contact.len>ip.len && contact.s[ip.len]==':'))
					&& !memcmp(contact.s, ip.s, ip.len)) {
				found = 1;
				break;
			}
		}

		if (!found) {
			LM_DBG("no contact <%.*s> registered earlier\n",
					contact.len, contact.s);
			found = 1;
			goto end;
		}

		c = c->next;
	}
	found = -1;

end:
	ul.unlock_udomain(ud, &aor);
	return found;
}
