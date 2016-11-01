/*
 * Support for:
 *  - REGISTER traffic throttling, optionally with outbound contact aggregation
 *  - proxying REGISTER traffic while saving registration state
 *       (contact expirations are taken from the downstream UAS's 200 OK reply)
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

#include "../usrloc/usrloc.h"
#include "../usrloc/urecord.h"

enum mid_reg_mode {
	MID_REG_MIRROR,
	MID_REG_THROTTLE_CT,
	MID_REG_THROTTLE_AOR,
};

enum mid_reg_routing_mode {
	ROUTE_BY_CONTACT,
	ROUTE_BY_PATH,
};

enum mid_reg_matching_mode {
	MATCH_BY_PARAM,
	MATCH_BY_USER,
};

struct mid_reg_ct {
	/* De-registrations will be sent to this SIP URI */
	str ruri;

	str ct_uri;

	unsigned int max_contacts;
	unsigned int flags;

	unsigned int expires;
	unsigned int expires_out;

	unsigned int last_register_out_ts;

	udomain_t *dom;
	str aor;

	str to;
	str from;
	str callid;
};

typedef enum rerr {
	R_FINE = 0,   /*!< Everything went OK */
	R_UL_DEL_R,   /*!< Usrloc record delete failed */
	R_UL_GET_R,   /*!< Usrloc record get failed */
	R_UL_NEW_R,   /*!< Usrloc new record failed */
	R_INV_CSEQ,   /*!< Invalid CSeq value */
	R_UL_INS_C,   /*!< Usrloc insert contact failed */
	R_UL_INS_R,   /*!< Usrloc insert record failed */
	R_UL_DEL_C,   /*!< Usrloc contact delete failed */
	R_UL_UPD_C,   /*!< Usrloc contact update failed */
	R_TO_USER,    /*!< No username part in To URI */
	R_AOR_LEN,    /*!< Address Of Record too long */
	R_AOR_PARSE,  /*!< Error while parsing Address Of Record */
	R_INV_EXP,    /*!< Invalid expires parameter in contact */
	R_INV_Q,      /*!< Invalid q parameter in contact */
	R_PARSE,      /*!< Error while parsing message */
	R_TO_MISS,    /*!< Missing To header field */
	R_CID_MISS,   /*!< Missing Call-ID header field */
	R_CS_MISS,    /*!< Missing CSeq header field */
	R_PARSE_EXP,  /*!< Error while parsing Expires */
	R_PARSE_CONT, /*!< Error while parsing Contact */
	R_STAR_EXP,   /*!< star and expires != 0 */
	R_STAR_CONT,  /*!< star and more contacts */
	R_OOO,        /*!< Out-Of-Order request */
	R_RETRANS,    /*!< Request is retransmission */
	R_UNESCAPE,   /*!< Error while unescaping username */
	R_TOO_MANY,   /*!< Too many contacts */
	R_CONTACT_LEN,/*!< Contact URI or RECEIVED too long */
	R_CALLID_LEN, /*!< Callid too long */
	R_PARSE_PATH, /*!< Error while parsing Path */
	R_PATH_UNSUP  /*!< Path not supported by UAC */

} rerr_t;

struct save_ctx {
	unsigned int flags;
	str aor;
	unsigned int max_contacts;
	unsigned int expires;
	unsigned int expires_out;
};

extern str sock_hdr_name;
extern str realm_prefix;
extern int case_sensitive;

extern rerr_t rerrno;

extern int rerr_codes[];
extern str error_info[];

extern struct usrloc_api ul_api;
extern struct tm_binds tm_api;
extern struct sig_binds sig_api;

extern int default_expires;
extern int min_expires;
extern int max_expires;
extern unsigned int outbound_expires;

extern enum mid_reg_mode reg_mode;
extern enum mid_reg_routing_mode routing_mode;
extern enum mid_reg_matching_mode matching_mode;

extern str matching_param;

extern int disable_gruu;
extern int reg_use_domain;

extern int rcv_avp_name;
extern unsigned short rcv_avp_type;
extern int attr_avp_name;
extern unsigned short attr_avp_type;

extern int tcp_persistent_flag;

extern int ucontact_data_idx;

void set_ct(struct mid_reg_ct *ct);
struct mid_reg_ct *get_ct(void);

time_t get_act_time(void);
void update_act_time(void);

int extract_aor(str* _uri, str* _a,str *sip_instance,str *call_id);

int calc_contact_q(param_t* _q, qvalue_t* _r);

contact_t* get_first_contact(struct sip_msg* _m);
contact_t* get_next_contact(contact_t* _c);

int get_expires_hf(struct sip_msg* _m);

int parse_reg_headers(struct sip_msg *msg);

#endif /* __MID_REG_ */
