/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
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
#include "../../parser/parse_supported.h"
#include "../../dprint.h"
#include "../../trim.h"
#include "../../ut.h"
#include "../../qvalue.h"
#include "../../dset.h"
#include "../../mod_fix.h"
#include "../../data_lump.h"
#include "../usrloc/usrloc.h"

#include "../../lib/reg/rerrno.h"
#include "../../lib/reg/sip_msg.h"
#include "../../lib/reg/ci.h"
#include "../../lib/reg/regtime.h"
#include "../../lib/reg/config.h"
#include "../../lib/reg/path.h"

#include "common.h"
#include "sip_msg.h"
#include "reply.h"
#include "reg_mod.h"
#include "save.h"
#include "lookup.h"

/*! \brief
 * Process request that contained a star, in that case,
 * we will remove all bindings with the given username
 * from the usrloc and return 200 OK response
 */
static inline int star(udomain_t* _d, struct save_ctx *_sctx,
		struct sip_msg *_m)
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

	if (ul.delete_urecord(_d, &_sctx->aor, NULL, 0) < 0) {
		LM_ERR("failed to remove record from usrloc\n");

		     /* Delete failed, try to get corresponding
		      * record structure and send back all existing
		      * contacts
		      */
		rerrno = R_UL_DEL_R;
		if (!ul.get_urecord(_d, &_sctx->aor, &r)) {
			build_contact(r->contacts,_m);
		}
		ul.unlock_udomain(_d, &_sctx->aor);
		return -1;
	}
	ul.unlock_udomain(_d, &_sctx->aor);
	return 0;
}




/*! \brief
 * Process request that contained no contact header
 * field, it means that we have to send back a response
 * containing a list of all existing bindings for the
 * given username (in To HF)
 */
static inline int no_contacts(udomain_t* _d, str* _a,struct sip_msg *_m)
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
		build_contact(r->contacts,_m);
	}
	ul.unlock_udomain(_d, _a);
	return 0;
}

/*! \brief
 */
static int set_sock_hdr(struct sip_msg *msg, ucontact_info_t *ci,
                        unsigned int reg_flags)
{
	struct socket_info *sock;
	struct hdr_field *hf;
	str socks;
	str hosts;
	int port;
	int proto;

	if (!msg || !(reg_flags & REG_SAVE_SOCKET_FLAG))
		return 1;

	if (parse_headers( msg, HDR_EOH_F, 0) == -1) {
		LM_ERR("failed to parse message\n");
		return 1;
	}

	hf = get_header_by_name( msg, sock_hdr_name.s, sock_hdr_name.len);
	if (hf==0)
		return 1;

	trim_len( socks.len, socks.s, hf->body );
	if (socks.len==0)
		return 1;

	if (parse_phostport( socks.s, socks.len, &hosts.s, &hosts.len,
	&port, &proto)!=0) {
		LM_ERR("bad socket <%.*s> in \n",
			socks.len, socks.s);
		return 1;
	}
	set_sip_defaults( port, proto);
	sock = grep_sock_info(&hosts,(unsigned short)port,(unsigned short)proto);
	if (sock==0) {
		LM_ERR("non-local socket <%.*s>\n",	socks.len, socks.s);
		return 1;
	}

	LM_DBG("%d:<%.*s>:%d -> p=%p\n", proto,socks.len,socks.s,port,sock );

	ci->sock = sock;
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
	int e_max;
	int tcp_check;
	struct sip_uri uri;

	cflags = (_sctx->flags&REG_SAVE_MEMORY_FLAG)?FL_MEM:FL_NONE;
	if (is_tcp_based_proto(_m->rcv.proto) && (_m->flags&tcp_persistent_flag)) {
		e_max = 0;
		tcp_check = 1;
	} else {
		e_max = tcp_check = 0;
	}

	for( num=0,r=0,ci=0 ; _c ; _c = get_next_contact(_c) ) {
		/* calculate expires */
		calc_contact_expires(_m, _c->expires, &e, _sctx);
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
				if (ul.delete_ucontact( r, r->contacts, 0)!=0) {
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
			if (ul.insert_urecord(_d, _a, &r, 0) < 0) {
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

		ci->cflags |= ul.nat_flag;
		set_sock_hdr(_m, ci, _sctx->flags);

		if ( r->contacts==0 ||
		ul.get_ucontact(r, &_c->uri, ci->callid, ci->cseq+1, &c)!=0 ) {
			if (ul.insert_ucontact( r, &_c->uri, ci, &c, 0) < 0) {
				rerrno = R_UL_INS_C;
				LM_ERR("failed to insert contact\n");
				goto error;
			}
		} else {
			if (ul.update_ucontact( r, c, ci, 0) < 0) {
				rerrno = R_UL_UPD_C;
				LM_ERR("failed to update contact\n");
				goto error;
			}
		}

		if (tcp_check) {
			/* parse contact uri to see if transport is TCP */
			if (parse_uri( _c->uri.s, _c->uri.len, &uri)<0) {
				LM_ERR("failed to parse contact <%.*s>\n",
						_c->uri.len, _c->uri.s);
			} else if ( is_tcp_based_proto(uri.proto) ) {
				if (e_max) {
					LM_WARN("multiple TCP contacts on single REGISTER\n");
					if (e>e_max) e_max = e;
				} else {
					e_max = e;
				}
			}
		}
	}

	if (r) {
		if (r->contacts) {
			build_contact(r->contacts,_m);
		}
		ul.release_urecord(r, 0);
	}

	if ( tcp_check && e_max>0 ) {
		e_max -= act_time;
		trans_set_dst_attr( &_m->rcv, DST_FCNTL_SET_LIFETIME,
			(void*)(long)(e_max + 10) );
	}

	return 0;
error:
	if (r)
		ul.delete_urecord(_d, _a, r, 0);
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
	ucontact_t *c, *c_last, *c_it;
	int e;
	unsigned int cflags;
	int ret;
	int num;
	int e_max;
	int tcp_check;
	struct sip_uri uri;

	/* mem flag */
	cflags = (_sctx->flags&REG_SAVE_MEMORY_FLAG)?FL_MEM:FL_NONE;

	/* pack the contact_info */
	if ( (ci=pack_ci( _m, 0, 0, cflags, _sctx->flags))==0 ) {
		LM_ERR("failed to initial pack contact info\n");
		goto error;
	}

	ci->cflags |= ul.nat_flag;
	set_sock_hdr(_m, ci, _sctx->flags);

	/* count how many contacts we have right now */
	num = 0;
	if (_sctx->max_contacts) {
		c = _r->contacts;
		while(c) {
			if (VALID_CONTACT(c, act_time)) num++;
			c = c->next;
		}
	}

	if (is_tcp_based_proto(_m->rcv.proto) && (_m->flags&tcp_persistent_flag)) {
		e_max = -1;
		tcp_check = 1;
	} else {
		e_max = tcp_check = 0;
	}

	for( ; _c ; _c = get_next_contact(_c) ) {
		/* calculate expires */
		calc_contact_expires(_m, _c->expires, &e, _sctx);

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
			while (_sctx->max_contacts && num>=_sctx->max_contacts) {
				if (_sctx->flags&REG_SAVE_FORCE_REG_FLAG) {
					/* we are overflowing the number of maximum contacts,
					   so remove the oldest valid one to prevent this */
					for( c_it=_r->contacts,c_last=NULL ; c_it ;
					c_it=c_it->next )
						if (VALID_CONTACT(c_it, act_time))
							c_last=c_it;
					if (c_last==NULL) {
						LM_CRIT("BUG - overflow detected but no valid "
							"contacts found :( \n");
						goto error;
					}
					LM_DBG("overflow on inserting new contact -> removing "
						"<%.*s>\n", c_last->c.len, c_last->c.s);
					if (ul.delete_ucontact( _r, c_last, 0)!=0) {
						LM_ERR("failed to remove contact\n");
						goto error;
					}
					num--;
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

			if (ul.insert_ucontact( _r, &_c->uri, ci, &c, 0) < 0) {
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

				if (ul.delete_ucontact(_r, c, 0) < 0) {
					rerrno = R_UL_DEL_C;
					LM_ERR("failed to delete contact\n");
					goto error;
				}
			} else {
				/* do update */
				/* if the contact to be updated is not valid, it will be after
				 * update, so need to compensate the total number of contact */
				if ( !VALID_CONTACT(c,act_time) )
					num++;
				while ( _sctx->max_contacts && num>_sctx->max_contacts ) {
					if (_sctx->flags&REG_SAVE_FORCE_REG_FLAG) {
						/* we are overflowing the number of maximum contacts,
						   so remove the first (oldest) one to prevent this
						   (but not the one to be updated !) */
						for( c_it=_r->contacts,c_last=NULL ; c_it ;
						c_it=c_it->next )
							if (VALID_CONTACT(c_it, act_time) && c_it!=c)
								c_last=c_it;
						if (c_last==NULL) {
							LM_CRIT("BUG - overflow detected but no "
								"valid contacts found :( \n");
							goto error;
						}
						LM_DBG("overflow on update -> removing contact "
							"<%.*s>\n", c_last->c.len, c_last->c.s);
						if (ul.delete_ucontact( _r, c_last, 0)!=0) {
							LM_ERR("failed to remove contact\n");
							goto error;
						}
						num--;
					} else {
						LM_INFO("too many contacts for AOR <%.*s>, max=%d\n",
							_r->aor.len, _r->aor.s, _sctx->max_contacts);
						rerrno = R_TOO_MANY;
						return -1;
					}
				}

				/* pack the contact specific info */
				if ( (ci=pack_ci( 0, _c, e, 0, _sctx->flags))==0 ) {
					LM_ERR("failed to pack contact specific info\n");
					goto error;
				}

				if (ul.update_ucontact(_r, c, ci, 0) < 0) {
					rerrno = R_UL_UPD_C;
					LM_ERR("failed to update contact\n");
					goto error;
				}
			}
		}
		if (tcp_check) {
			/* parse contact uri to see if transport is TCP */
			if (parse_uri( _c->uri.s, _c->uri.len, &uri)<0) {
				LM_ERR("failed to parse contact <%.*s>\n",
						_c->uri.len, _c->uri.s);
			} else if (is_tcp_based_proto(uri.proto)) {
				if (e_max>0) {
					LM_WARN("multiple TCP contacts on single REGISTER\n");
				}
				if (e>e_max) e_max = e;
			}
		}
	}

	if ( tcp_check && e_max>-1 ) {
		if (e_max) e_max -= act_time;
		trans_set_dst_attr( &_m->rcv, DST_FCNTL_SET_LIFETIME,
			(void*)(long)(e_max + 10) );
	}

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
			build_contact(r->contacts,_m);
			ul.release_urecord(r, 0);
			ul.unlock_udomain(_d, &_sctx->aor);
			return -3;
		}
		build_contact(r->contacts,_m);
		ul.release_urecord(r, 0);
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
	contact_t* forced_c = NULL;
	int st;
	str uri;
	str flags_s;
	pv_value_t val;

	rerrno = R_FINE;
	memset( &sctx, 0 , sizeof(sctx));
	sctx.max_contacts = -1;

	sctx.flags = 0;
	sctx.min_expires = min_expires;
	sctx.max_expires = max_expires;
	if ( _f ) {
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
				case 'e':
					sctx.min_expires = 0;
					while (st<flags_s.len-1 && isdigit(flags_s.s[st+1])) {
						sctx.min_expires = sctx.min_expires*10 +
							flags_s.s[st+1] - '0';
						st++;
					}
					break;
				case 'E':
					sctx.max_expires = 0;
					while (st<flags_s.len-1 && isdigit(flags_s.s[st+1])) {
						sctx.max_expires = sctx.max_expires*10 +
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
				default: LM_WARN("unsupported flag %c \n",flags_s.s[st]);
			}
		}
	}
	if(route_type == ONREPLY_ROUTE)
		sctx.flags |= REG_SAVE_NOREPLY_FLAG;

	/* if no max_contact per AOR is defined, use the global one */
	if (sctx.max_contacts == -1)
		sctx.max_contacts = max_contacts;

	if (parse_reg_headers(_m) < 0) {
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
			goto return_minus_one;
		}
		if ( (val.flags&PV_VAL_STR)==0 ) {
			LM_ERR("PV vals is not string\n");
			goto return_minus_one;
		}
		uri = val.rs;
	} else {
		uri = get_to(_m)->uri;
	}

	if (extract_aor( &uri, &sctx.aor,0,0) < 0) {
		LM_ERR("failed to extract Address Of Record\n");
		goto error;
	}

	if (c == 0) {
		if (st) {
			if (star((udomain_t*)_d, &sctx,_m) < 0) goto error;
		} else {
			if (no_contacts((udomain_t*)_d, &sctx.aor,_m) < 0) goto error;
		}
	} else {
		if (add_contacts(_m, c, (udomain_t*)_d, &sctx) < 0) goto error;
	}

	update_stat(accepted_registrations, 1);

	if (!is_cflag_set(REG_SAVE_NOREPLY_FLAG) && (send_reply(_m,sctx.flags)<0))
		goto return_minus_one;

	if (forced_c) free_contacts(&forced_c);

	return 1;
error:
	update_stat(rejected_registrations, 1);

	if ( !is_cflag_set(REG_SAVE_NOREPLY_FLAG) )
		send_reply(_m,sctx.flags);

	if (forced_c) free_contacts(&forced_c);

	return -2;

return_minus_one:
	if (forced_c) free_contacts(&forced_c);

	return -1;
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

	if (parse_reg_headers(_m) < 0) return -1;
	if (check_contacts(_m, &st) > 0) return -1;
	if (parse_reg_headers(msg) < 0) return -1;
	if (check_contacts(msg, &st) > 0) return -1;

	/* msg - request
	   _m  - reply
	*/
	request_c = get_first_contact(msg);
	if(request_c) {
		/* For now, we deal only with the first contact
		 * FIXME: implement multiple contact handling - see check_contacts() */
		if(!request_c->expires || !request_c->expires->body.len) {
			if (msg->expires && ((exp_body_t*)(msg->expires->parsed))->valid) {
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

int w_remove_2(struct sip_msg *msg, char *udomain, char *aor_gp)
{
	return _remove( msg, udomain, aor_gp, NULL, NULL);
}

int w_remove_3(struct sip_msg *msg, char *udomain, char *aor_gp, char *domain_gp)
{
	return _remove( msg, udomain, aor_gp, domain_gp, NULL);
}

/**
 * _remove - Delete an entire AOR entry or just one or more of its Contacts
 * Parameter format: _remove(domain, AOR[, Contact URI or plain hostname])
 *
 * @udomain:     (udomain_t *)
 * @aor_gp:      address-of-record as a SIP URI (plain string or pvar)
 * @contact_gp:  contact to be deleted or domain in front of multiple contacts
 *
 * @return:      1 on success, negative on failure
 */
int _remove(struct sip_msg *msg, char *udomain, char *aor_gp, char *domain_gp, char *ip_gp)
{
	struct sip_uri puri;
	struct hostent delete_he, *he;
	urecord_t *record;
	ucontact_t *contact, *it;
	str domain={ NULL, 0 }, ip={ NULL, 0 }, uri, aor_user, delete_user = { NULL, 0 };
	int err, count = 0;
	int delete_contact = 0;
	unsigned short delete_port;

	memset(&delete_he, 0, sizeof delete_he);

	if (fixup_get_svalue(msg, (gparam_p)aor_gp, &uri) != 0) {
		LM_ERR("failed to get gparam_t value\n");
		return E_UNSPEC;
	}

	if (extract_aor( &uri, &aor_user,0,0) < 0) {
		LM_ERR("failed to extract Address Of Record\n");
		return E_BAD_URI;
	}

	ul.lock_udomain((udomain_t *)udomain, &aor_user);

	if (ul.get_urecord((udomain_t *)udomain, &aor_user, &record) != 0) {
		LM_DBG("no record '%.*s' found!\n", aor_user.len, aor_user.s);
		err = 1;
		goto out_unlock;
	}

	/* if no contact uri param is given, delete the whole urecord entry */
	if (!domain_gp && !ip_gp) {
		if (ul.delete_urecord((udomain_t *)udomain, &aor_user, record, 0) != 0) {
			LM_ERR("failed to delete urecord for aor '%.*s'\n",
			        aor_user.len, aor_user.s);
			err = E_UNSPEC;
			goto out_unlock;
		}

		err = 1;
		goto out_unlock;
	}

	if (domain_gp) {
		if (fixup_get_svalue(msg, (gparam_p)domain_gp, &domain) != 0) {
			LM_ERR("failed to retrieve value of contact pv\n");
			err = E_UNSPEC;
			goto out_unlock;
		}
	}

	if (ip_gp) {
		if (fixup_get_svalue(msg, (gparam_p)ip_gp, &ip) != 0) {
			LM_ERR("failed to retrieve value of contact pv\n");
			err = E_UNSPEC;
			goto out_unlock;
		}
	}

	if (domain.s) {
		/* minimum two-letters for the domain name */
		if (domain.len < 5 || domain.s[0] != 's' || domain.s[1] != 'i' ||
			domain.s[2] != 'p' || (domain.s[3] != ':' &&
								(domain.s[3] != 's' || domain.s[4] != ':'))) {
			LM_ERR("Invalid domain given: '%.*s'\n", domain.len, domain.s);
			err = E_INVALID_PARAMS;
			goto out_unlock;
		} else {
			LM_DBG("parsing uri: %.*s\n", uri.len, uri.s);

			if (parse_uri(domain.s, domain.len, &puri) != 0) {
				LM_ERR("failed to parse contact uri: '%.*s'\n",
						domain.len, domain.s);
				err = E_BAD_URI;
				 goto out_unlock;
			}

			delete_user = puri.user;

			he = sip_resolvehost(&puri.host, &delete_port, &puri.proto, 0, NULL);
			if (!he) {
				LM_ERR("cannot resolve given uri: '%.*s'\n", uri.len, uri.s);
				err = E_UNSPEC;
				goto out_unlock;
			}

			if (puri.port_no > 0)
				delete_port  = puri.port_no;

			LM_DBG("Delete by contact: [ User %.*s | Host %s | Port %d ]\n",
					delete_user.len, delete_user.s,
					inet_ntoa(*(struct in_addr *)(he->h_addr_list[0])),
					delete_port);
		}
	}

	if (ip.s) {
		he = sip_resolvehost(&ip, &delete_port, NULL, 0, NULL);
		if (!he) {
			LM_ERR("cannot resolve given host: '%.*s'\n", uri.len, uri.s);
			err = E_UNSPEC;
			goto out_unlock;
		}

		LM_DBG("Delete by host: '%s'\n",
		        inet_ntoa(*(struct in_addr *)(he->h_addr_list[0])));

		if (hostent_cpy(&delete_he, he) != 0) {
			LM_ERR("no more pkg mem\n");
			err = E_OUT_OF_MEM;
			goto out_unlock;
		}
	}

	for (it = record->contacts; it; ) {
		contact = it;
		it = it->next;
		count++;

		LM_DBG("parsing contact uri '%.*s'\n", contact->c.len, contact->c.s);

		if (parse_uri(contact->c.s, contact->c.len, &puri) != 0) {
			LM_ERR("failed to parse contact uri: '%.*s'\n",
			        contact->c.len, contact->c.s);
			err = E_BAD_URI;
			goto out_unlock;
		}

		/* if necessary, solve the next_hop towards the contact */
		he = sip_resolvehost(&contact->next_hop.name,
		                     &contact->next_hop.port,
		                     &contact->next_hop.proto, 0, NULL);
		if (!he) {
			LM_ERR("failed to resolve next hop of contact '%.*s'\n",
			        contact->c.len, contact->c.s);
			continue;
		}

		LM_DBG("Contact: [ User %.*s | Host %s | Port %d ]\n",
		        puri.user.len, puri.user.s,
		        inet_ntoa(*(struct in_addr *)(he->h_addr_list[0])),
				puri.port_no);

		delete_contact = 0;

		if (ip.s) {
			if (!memcmp(delete_he.h_addr_list[0],
			            he->h_addr_list[0], he->h_length))
			{
				delete_contact = 1;
			}
		}

		if (domain.s) {
			if (delete_user.len == puri.user.len &&
			    delete_port == puri.port_no &&
			    !memcmp(delete_he.h_addr_list[0],
			            he->h_addr_list[0], he->h_length)
				&& !memcmp(delete_user.s, puri.user.s, puri.user.len))
			{
				delete_contact = 1;
			} else {
				/* might be 1 from above(ip search) */
				delete_contact = 0;
			}
		}

		if (delete_contact) {
			ul.delete_ucontact(record, contact, 0);
			count--;
		}
	}

	err = 1;

	/* remove the AOR if no more contacts are attached */
	if (count == 0) {
		if (ul.delete_urecord((udomain_t *)udomain, &aor_user, record, 0) != 0) {
			LM_ERR("failed to delete urecord for aor '%.*s'\n",
			        aor_user.len, aor_user.s);
			err = 1;
		}
	}

out_unlock:
	ul.unlock_udomain((udomain_t *)udomain, &aor_user);
	free_hostent(&delete_he);

	return err;
}

