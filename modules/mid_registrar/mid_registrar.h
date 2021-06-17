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
 * Copyright (C) 2016-2020 OpenSIPS Solutions
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
	MR_REPLACE_USER,
	MR_APPEND_PARAM,
};

struct ct_mapping {
	str req_ct_uri;
	str new_username;
	int zero_expires;
	uint64_t ctid;

	int expires;
	unsigned int methods;
	qvalue_t q;
	str received;
	str instance;

	ucontact_t *uc;

	struct list_head list;
};

/* fields marked with [NEW] must be persisted into usrloc */
struct mid_reg_info {
	str main_reg_uri;      /* [NEW] De-REGISTER URI */
	str main_reg_next_hop; /* [NEW] De-REGISTER next hop */

	str ct_uri;  /* [NEW] De-REGISTER Contact hf value */

	str to;     /* [NEW] De-REGISTER */
	str from;   /* [NEW] De-REGISTER */
	str callid; /* De-REGISTER */

	unsigned int last_cseq;

	int reg_flags; /* temporary holder until response arrives */
	int star;      /* temporary holder until response arrives */

	int expires;     /* expires value (not a unix TS!) */

	int expires_out; /* [NEW] outgoing expires value (not a unix TS!) */
	                 /* used to absorb/relay new REGISTERs */

	unsigned int last_reg_ts; /* [NEW] used to absorb/relay new REGISTERs
	                                   marks the last successful reg */

	int skip_dereg;
	int max_contacts;
	struct list_head ct_mappings;

	udomain_t *dom; /* used during 200 OK ul_api operations */
	str aor;        /* used during both "reg out" and "resp in" */
	str ownership_tag; /* a sharing tag which helps decide ownership */
	struct ct_match cmatch; /* info regarding the contact matching mode */

	/* ucontact_info dup'ed fields */
	str user_agent;
	unsigned int ul_flags;
	unsigned int cflags;

	/* REGISTER-time state of the PN providers -- to be used at 200 OK
	 * without a re-parse of the REGISTER */
	void *pn_provider_state;

	int pending_replies;
	rw_lock_t *tm_lock;
};

extern rw_lock_t *tm_retrans_lk;

extern int case_sensitive;

extern struct sig_binds sig_api;

extern int retry_after;
extern unsigned int outgoing_expires;

extern enum mid_reg_mode reg_mode;
extern enum mid_reg_insertion_mode ctid_insertion;
extern str ctid_param;
extern str at_escape_str;

extern str register_method;
extern str contact_hdr;
extern str expires_hdr;
extern str expires_param;

extern str matching_param;

struct mid_reg_info *mri_alloc(void);
struct mid_reg_info *mri_dup(struct mid_reg_info *mri);
void mri_free(struct mid_reg_info *mri);

void set_ct(struct mid_reg_info *ct);
struct mid_reg_info *get_ct(void);

int get_expires_hf(struct sip_msg* _m);
str get_extra_ct_params(struct sip_msg *msg);

#endif /* __MID_REG_ */
