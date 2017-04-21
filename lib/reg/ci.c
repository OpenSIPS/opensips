/*
 * Contact info packing functions
 *
 * Copyright (C) 2016-2017 OpenSIPS Solutions
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


#include "../../trim.h"
#include "../../parser/parse_methods.h"
#include "../../parser/parse_allow.h"

#include "ci.h"
#include "path.h"
#include "config.h"
#include "rerrno.h"
#include "sip_msg.h"
#include "regtime.h"


/*! \brief
 * Fills the common part (for all contacts) of the info structure
 */
ucontact_info_t *pack_ci(struct sip_msg* _m, contact_t* _c, unsigned int _e,
             unsigned int _f, unsigned int _nat_flag, unsigned int _reg_flags)
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
	static int_str attr_avp_value;
	static struct usr_avp *avp_attr;
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

		ci.sock = _m->rcv.bind_address;

		/* additional info from message */
		if (parse_headers(_m, HDR_USERAGENT_F, 0) != -1 && _m->user_agent &&
		_m->user_agent->body.len>0 && _m->user_agent->body.len<UA_MAX_SIZE) {
			ci.user_agent = &_m->user_agent->body;
		} else {
			ci.user_agent = &no_ua;
		}

		/* extract Path headers */
		if (_reg_flags & REG_SAVE_PATH_FLAG) {
			if (build_path_vector(_m, &path, &path_received, _reg_flags) < 0) {
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

		ci.last_modified = get_act_time();

		/* set flags */
		ci.flags  = _f;
		ci.cflags =  getb0flags(_m);

		/* get received */
		if (path_received.len && path_received.s) {
			ci.cflags |= _nat_flag;
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

		if (_c->instance) {
			ci.instance = _c->instance->body;
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

		/* additional information (script pvar) */
		if (attr_avp_name != -1) {
			avp_attr = search_first_avp(attr_avp_type, attr_avp_name,
										&attr_avp_value, NULL);
			if (avp_attr) {
				ci.attr = &attr_avp_value.s;

				LM_DBG("Attributes: %.*s\n", ci.attr->len, ci.attr->s);
			}
		}
	}

	return &ci;
error:
	return 0;
}
