/**
 * SIP Push Notification support - RFC 8599
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 */

#ifndef __REG_PN_H__
#define __REG_PN_H__

#include "../../parser/msg_parser.h"
#include "../../parser/parse_uri.h"
#include "../../str_list.h"
#include "../../ut.h"

#include "../../modules/usrloc/ucontact.h"
#include "regtime.h"
#include "save_flags.h"

/* dual-purpose: it represents a provider and helps build a Feature-Caps hf */
struct pn_provider {
	str name;

	str feature_caps_query;
	int append_fcaps_query;

	str feature_caps;
	int append_fcaps;

	struct pn_provider *next;
};

#define PN_PROVIDER_RPL_FCAPS   (1UL << 0)
#define PN_PROVIDER_RPL_QFCAPS  (1UL << 1)
#define PN_PROVIDER_FLAGS       2

#define PN_MAX_PROVIDERS   (sizeof(unsigned long) / PN_PROVIDER_FLAGS)

enum pn_action {
	PN_NONE,             /* no 'pn-provider' was given */
	PN_UNSUPPORTED_PNS,  /* the given 'pn-provider' value is not supported */

	/* Query Network PNS Capabilities */
	PN_LIST_ALL_PNS,     /* cap query: only 'pn-provider' given, no value */
	PN_LIST_ONE_PNS,     /* cap query: a known 'pn-provider' value was given */

	/* while the 'pn-*' params are present and the contact must be matched
	 * using them, we must _not_ send any Push Notifications, since an upstream
	 * proxy has already indicated that it is doing so */
	PN_MATCH_PN_PARAMS,

	/* fully enable PN:
	 *    1. all required 'pn-*' params are present -- match these exclusively
	 *    2. generate PNs to this contact as required
	 */
	PN_ON,
};

/* common registrar PN modparams */
extern int pn_enable;
extern int pn_pnsreg_interval;
extern int pn_trigger_interval;
extern int pn_skip_pn_interval;
extern int pn_refresh_timeout;
extern int pn_enable_purr;
extern char *_pn_ct_params;
extern char *_pn_providers;

#define pn_async_cmds \
	{"pn_process_purr",  (acmd_function)pn_async_process_purr, { \
	    {CMD_PARAM_STR|CMD_PARAM_STATIC, domain_fixup, 0}, \
	    {0,0,0}}}

#define pn_modparams \
	{"pn_enable",           INT_PARAM, &pn_enable}, \
	{"pn_providers",        STR_PARAM, &_pn_providers}, \
	{"pn_ct_match_params",  STR_PARAM, &_pn_ct_params}, \
	{"pn_pnsreg_interval",  INT_PARAM, &pn_pnsreg_interval}, \
	{"pn_trigger_interval", INT_PARAM, &pn_trigger_interval}, \
	{"pn_skip_pn_interval", INT_PARAM, &pn_skip_pn_interval}, \
	{"pn_refresh_timeout",  INT_PARAM, &pn_refresh_timeout}, \
	{"pn_enable_purr",      INT_PARAM, &pn_enable_purr}


/* module dependencies */
struct module_dependency *pn_get_deps(param_export_t *param);

#define pn_modparam_deps \
	{"pn_enable", pn_get_deps}


/* useful fixups */
extern str_list *pn_ct_params;

#define OPENSIPS_PURR_LEN  (3 + 1/* . */ + 5 + 1/* . */ + 8)


/**
 * Initialize RFC 8599 support
 *
 * Return: 0 on success, -1 otherwise
 */
int pn_init(void);


/**
 * Validate the current opensips.cfg configuration.  To be used within the
 * script reloading hook.
 *
 * Return: 1 if valid, 0 otherwise
 */
int pn_cfg_validate(void);


/**
 * Perform any required RFC 8599 processing for a SIP REGISTER, including
 * handling for Feature-Caps headers arriving from upstream.
 *
 * Return: 0 on success, -1 on failure and should reply immediately
 */
int pn_inspect_request(struct sip_msg *req, const str *ct_uri,
                       struct save_ctx *sctx);


/**
 * Look for any RFC 8599 URI parameters and suggest the appropriate action
 */
enum pn_action pn_inspect_ct_params(struct sip_msg *req, const str *ct_uri);


/**
 * Only relevant for the 'PN proxy' scenario (i.e. mid-registrar).  Marks any
 * PNS requested by the UA in the Contact header, supported by this proxy and
 * not included in the incoming set of Feature-Caps hfs as such, by appending
 * a Feature-Caps for each of them.
 *
 *   Example way of advertising donwstream that 'fcm' is handled here:
 *		Feature-Caps: +sip.pns="fcm"
 *
 * Return: 0 on success, -1 on partial processing (internal error)
 */
int pn_append_req_fcaps(struct sip_msg *msg, void **pn_provider_state);


/**
 * Only relevant for the 'PN proxy' scenario (i.e. mid-registrar).  To be
 * called earliest on the 200 OK to the REGISTER, in order to restore the PN
 * provider flags, so the 200 OK Feature-Caps can be properly built.
 */
void pn_restore_provider_state(void *pn_provider_state);


/**
 * Append any required Feature-Caps header fields for a REGISTER or its 200 OK
 * in order to inform each next-hop party of our PN processing capabilities.
 *
 * @msg: the SIP message in processing (request or reply)
 *
 * Return: 0 on success, -1 on partial processing (internal error)
 */
int pn_append_rpl_fcaps(struct sip_msg *msg);


/**
 * Create the current transaction, wait for branches and generate PN events
 * for each PN-compatible contact from the given array.
 * @req: the current SIP request
 * @cts: array of PN-enabled contacts
 * @sz: array size
 *
 * Return:
 *	 success: 1 if at least one PN was sent, 2 otherwise
 *	 failure: 0 on retransmission, -1 on internal error
 */
int pn_awake_pn_contacts(struct sip_msg *req, ucontact_t **cts, int sz);


/**
 * Trigger an asynchronous Push Notification, by use of the
 * E_UL_CONTACT_REFRESH event + all required data, and return immediately.
 *
 * Return: 0 on success, -1 otherwise.
 */
int pn_trigger_pn(struct sip_msg *req, const ucontact_t *ct,
                  const struct sip_uri *ct_uri);


/**
 * Looks at the PN provider of the given usrloc @ct and copies over any
 * required Feature-Caps +sip.pnspurr URI parameter information, to be included
 * in the REGISTER reply.
 */
int pn_add_reply_purr(const ucontact_t *ct);


/**
 * Pack an usrloc @ct_id into a hex representation.
 *
 * NOTICE: returns a static buffer!
 */
char *pn_purr_pack(ucontact_id ct_id);


/**
 * Async, script-level handling for long-lived dialogs (PN RFC Section 6).
 * If a "pn-purr=xxx" value that matches both our format and an existing
 * registration is present in the R-URI, dest URI or Route headers, we then:
 *    - EBR-subscribe to E_UL_CONTACT_UPDATE events for the matched contact
 *    - raise the E_UL_CONTACT_REFRESH event, so a PN can be sent
 * @req: mid-dialog SIP request currently in processing
 * @ctx: the async ctx
 * @d: usrloc domain within which the 'pn-purr' value will be searched
 *
 * Should be called after loose_route().
 *
 * Return:
 *    1 on successful processing (including unknown pn-purr value format)
 *   -1 on internal error
 */
int pn_async_process_purr(struct sip_msg *req, async_ctx *ctx, udomain_t *d);


/**
 * Validate the format of a given @purr and unpack it into an usrloc @ct_id.
 *
 * Return: 0 on success, -1 on unrecognized PURR format
 */
int pn_purr_unpack(const str *purr, ucontact_id *ct_id);


/**
 * Check if the given Contact URI contains all required RFC 8599 URI parameters
 * @ct: the contact URI to be parsed
 * @parsed_uri: optional holder for the parsing result
 *
 * Return: 1 if true, 0 otherwise
 */
int pn_has_uri_params(const str *ct, struct sip_uri *parsed_uri);


/**
 * Remove any RFC 8599 URI parameters from the given parsed Contact URI,
 * write results to @out_uri
 * @puri: a parsed version of the input URI
 * @uri_len: the length of the input URI
 * @out_uri: the printed output URI, stripped of PN parameters
 *
 * Return: 0 on success, -1 otherwise
 */
int pn_remove_uri_params(struct sip_uri *puri, int uri_len, str *out_uri);


/* PN processing is enabled -- always check first during lookup() */
#define pn_on(ucontact) (ucontact->flags & FL_PN_ON)


/* Once pn_on() returns true, can we get away without a PN? :) */
#define pn_required(ucontact) \
	(((ucontact)->last_modified + pn_skip_pn_interval <= get_act_time()) || \
	 (ucontact)->last_modified == 0)


#endif /* __REG_PN_H__ */
