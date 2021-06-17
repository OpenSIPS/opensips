/*
 * common contact lookup code
 *
 * Copyright (C) 2020 OpenSIPS Solutions
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

#ifndef __LIB_REG_LOOKUP_H__
#define __LIB_REG_LOOKUP_H__

#include "../../parser/msg_parser.h"
#include "../../modules/usrloc/udomain.h"

#define REG_LOOKUP_METHODFILTER_FLAG   (1 << 0)
#define REG_LOOKUP_NOBRANCH_FLAG       (1 << 1)
#define REG_LOOKUP_UAFILTER_FLAG       (1 << 2)
#define REG_LOOKUP_GLOBAL_FLAG         (1 << 3)
#define REG_LOOKUP_MAX_LATENCY_FLAG    (1 << 4)
#define REG_LOOKUP_LATENCY_SORT_FLAG   (1 << 5)
#define REG_BRANCH_AOR_LOOKUP_FLAG     (1 << 6)
#define REG_LOOKUP_NO_RURI_FLAG        (1 << 7)

typedef enum _lookup_rc {
	LOOKUP_ERROR = -3,        /* internal error (oom, bug, etc.) */
	LOOKUP_METHOD_UNSUP = -2, /* contact(s) found, but method not compatible */
	LOOKUP_NO_RESULTS = -1,   /* no contacts or they all failed to match */
	LOOKUP_STOP_SCRIPT = 0,   /* SIP retransmission => stop the script */

	LOOKUP_OK = 1,            /* contact(s) found, at least 1 branch pushed */
	LOOKUP_PN_SENT = 2,       /* no branch pushed, but 1+ PN was sent */
} lookup_rc;


/**
 * Initialize the lookup support
 */
int reg_init_lookup(void);


/**
 * Look up the @aor_uri / request R-URI Address-of-Record in the user location
 * and fill in the R-URI, along with other branches, in preparation to route to
 * the found contacts.
 * @use_domain: how to extract the AoR from the R-URI (include '@host' part)
 * @aor_update: optional callback, invoked right after the AoR is extracted
 *              and un-escaped, where you may perform a quick edit on it.
 *      @aor: input/output parameter.  Nothing is freed, use a static buffer!
 *      Return: 0 (success), negative otherwise
 */
lookup_rc lookup(struct sip_msg *req, udomain_t *d, str *sflags, str *aor_uri,
                 int use_domain, int (*aor_update) (str *aor));


/**
 * @ct: the contact to push
 * @ruri_is_pushed: input/output.  Whether to push to R-URI or branch.
 *
 * Return:
 *     0 - success: contact pushed
 *     1 - success: nothing to push
 *     2 - success: contact not pushed, as it must be awoken by a PN first
 *    -1 - failure to push to R-URI
 *    -2 - failure to push to new branch
 */
int push_branch(struct sip_msg *msg, ucontact_t *ct, int *ruri_is_pushed);


/**
 * Parse the @input lookup flags string into a bitmask of @flags and any other
 * string or integer components.
 *
 * Return: 0 on success, -1 otherwise (internal error)
 */
int parse_lookup_flags(const str *input, unsigned int *flags, regex_t *ua_re,
                       int *regexp_flags, int *max_latency);


#endif /* __LIB_REG_LOOKUP_H__ */
