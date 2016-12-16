/*
 * Support for:
 *  - REGISTER traffic throttling, optionally with contact aggregation
 *  - processing registrations upon receiving 200 OK replies
 *
 * This module is intended to be used as a middle layer SIP component in
 * environments where a large proportion of SIP UAs (e.g. mobile devices)
 * register at high enough frequencies that they actually degrade the
 * performance of their registrars.
 *
 * Copyright (C) 2016 OpenSIPS Solutions
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
 *  2016-07-06 initial version (liviu)
 */

#ifndef __MID_REG_
#define __MID_REG_

#include "../../parser/msg_parser.h"
#include "../../parser/contact/contact.h"
#include "../../script_cb.h"
#include "../../socket_info.h"

#include "../tm/tm_load.h"
#include "../signaling/signaling.h"

#include "../usrloc/usrloc.h"
#include "../usrloc/urecord.h"

enum mid_reg_mode {
	MID_REG_MIRROR,
	MID_REG_THROTTLE_CT,
	MID_REG_THROTTLE_AOR,
};

enum mid_reg_insertion_mode {
	INSERT_BY_CONTACT,
	INSERT_BY_PATH,
};

enum mid_reg_matching_mode {
	MATCH_BY_PARAM,
	MATCH_BY_USER,
};

struct mid_reg_info {
	/* De-registrations will be sent to this SIP URI */
	str ruri;
	str next_hop;

	str ct_uri;
	str ct_body; /* if present, overrides ct_uri */

	int max_contacts;
	int flags;
	int star;

	int expires;
	int expires_out;

	unsigned int last_register_out_ts;

	udomain_t *dom;
	str aor;

	str to;
	str from;
	str callid;
};

struct save_ctx {
	unsigned int flags;
	str aor;
	unsigned int max_contacts;
	unsigned int expires;
	int expires_out;
	int star;

	unsigned int min_expires;
	unsigned int max_expires;
};

extern str realm_prefix;
extern int case_sensitive;

extern int rerr_codes[];
extern str error_info[];

extern struct usrloc_api ul_api;
extern struct tm_binds tm_api;
extern struct sig_binds sig_api;

extern int default_expires;
extern int min_expires;
extern int max_expires;
extern int max_contacts;
extern int retry_after;
extern unsigned int outgoing_expires;

extern enum mid_reg_mode reg_mode;
extern enum mid_reg_insertion_mode insertion_mode;
extern enum mid_reg_matching_mode matching_mode;

extern str register_method;
extern str contact_hdr;
extern str expires_hdr;
extern str expires_param;

extern str matching_param;

extern int disable_gruu;
extern int reg_use_domain;

extern str rcv_param;

extern str gruu_secret;

extern int rcv_avp_name;
extern unsigned short rcv_avp_type;
extern int attr_avp_name;
extern unsigned short attr_avp_type;

extern int tcp_persistent_flag;

extern int ucontact_data_idx;
extern int urecord_data_idx;

void mri_free(struct mid_reg_info *mri);

void set_ct(struct mid_reg_info *ct);
struct mid_reg_info *get_ct(void);

time_t get_act_time(void);
void update_act_time(void);

int extract_aor(str* _uri, str* _a,str *sip_instance,str *call_id);

int calc_contact_q(param_t* _q, qvalue_t* _r);

int get_expires_hf(struct sip_msg* _m);

#endif /* __MID_REG_ */
