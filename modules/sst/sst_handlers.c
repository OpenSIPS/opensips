/*
 * Copyright (C) 2006 SOMA Networks, Inc.
 * Written by Ron Winacott (karwin)
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301
 * USA
 */

/**
 *\file
 *\brief Functions for the SST module
 */

/**
 * SST support:
 *
 * The Session-Expires header conveys the session interval for a SIP
 * call. It is placed in an INVITE request and is allowed in any 2xx
 * class response to an INVITE. Its presence indicates that the UAC
 * wishes to use the session timer for this call. Unlike the
 * SIP-Expires header, it can only contain a delta-time, which is the
 * current time, plus the session interval from the response.
 *
 * For example, if a UAS generates a 200 OK response to a re-INVITE
 * that contained a Session-Expires header with a value of 1800
 * seconds (30 minutes), the UAS computes the session expiration as 30
 * minutes after the time when the 200 OK response was sent. For each
 * proxy, the session expiration is 30 minutes after the time when the
 * 2xx was received or sent. For the UAC, the expiration time is 30
 * minutes after the receipt of the final response.
 *
 */

#include <stdio.h>  /* for snprintf() */
#include <string.h> /* for memset() */
#include <stdlib.h> /* For atoi() */

#include "../../pvar.h"
#include "../../parser/parse_sst.h"
#include "../../parser/parse_supported.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../data_lump.h"
#include "../../data_lump_rpl.h"
#include "../../ut.h"
#include "../../dprint.h"
#include "../../sr_module.h" /* Needed for find_export() */
#include "../signaling/signaling.h"
#include "../dialog/dlg_vals.h"

#include "sst_handlers.h"
#include "sst_mi.h"

/*
 * My own LM_*() macros to add the correct message prefix and
 * file/function/line number information to all LOG messages.
 */

#define DLOGMSG(msg) {									   \
		if (msg->first_line.type == SIP_REQUEST) {		   \
			LM_INFO("REQUEST: %.*s\n",			    	   \
					msg->first_line.u.request.method.len,  \
					msg->first_line.u.request.method.s);   \
		}												   \
		else {											   \
			LM_INFO("RESPONSE: %d %.*s\n",		    	   \
					msg->first_line.u.reply.statuscode,	   \
					msg->first_line.u.reply.reason.len,	   \
					msg->first_line.u.reply.reason.s);	   \
		}												   \
}

#ifndef MIN
#define MIN(a, b) (a<b?a:b)
#endif
#ifndef MAX
#define MAX(a, b) (a>b?a:b)
#endif

#define CHECK_AND_UPDATE_SST_INFO(info, field, value, dirty) \
	do {\
		if (info-> field != value) { \
			info-> field = value; \
			dirty = 1;\
		}\
	} while (0)

#define CHECK_AND_UPDATE_SST_INFO_TMP(info, field, value, dirty, tmp) \
	do {\
		tmp.field = value; \
		CHECK_AND_UPDATE_SST_INFO(info, field, tmp.field, dirty); \
	} while (0)


/**
 * The binding to the dialog module functions. Most importantly the
 * register_dlgcb function.
 */
extern struct dlg_binds *dlg_binds;

/**
 * A collection of information about SST in the current SIP message
 * being processed.
 */
typedef struct sst_msg_info_st {
	int supported; 		   	/* supported = timer in message */
	unsigned int min_se;   	/* The Min-SE: value or zero    */
	unsigned int se;		/* The Sesion-Expires: header   */
	enum sst_refresher refresher;/* The refresher (parse_sst.h)  */
} sst_msg_info_t;

/**
 * Local function prototypes See function definition for
 * documentation.
 */
#ifdef USE_CONFIRM_CALLBACK
static void sst_dialog_confirmed_CB(struct dlg_cell* did, int type,
		struct dlg_cb_params * params);
#endif /* USE_CONFIRM_CALLBACK */
static void sst_free_info(void* param);
static void sst_dialog_terminate_CB(struct dlg_cell* did, int type,
		struct dlg_cb_params * params);
static void sst_dialog_request_within_CB(struct dlg_cell* did, int type,
		struct dlg_cb_params * params);
static void sst_dialog_response_fwded_CB(struct dlg_cell* did, int type,
		struct dlg_cb_params * params);
static int send_response(struct sip_msg *request, int code, str *reason,
		char *header, int header_len);
static int append_header(struct sip_msg *msg, const char *header);
static int add_timer_ext(struct sip_msg *msg);
static int remove_minse_header(struct sip_msg *msg);
static int parse_msg_for_sst_info(struct sip_msg *msg, sst_msg_info_t *minfo);
static int send_reject(struct sip_msg *msg, unsigned int min_se);
static void set_dialog_lifetime(struct dlg_cell *dlg, unsigned int value);
static void setup_dialog_callbacks(struct dlg_cell *did, sst_info_t *info);

/**
 * The pointer to the stateless reply function This is used to send a
 * 422 reply if asked to with a Min-SE: header value to small.
 */
extern struct sig_binds sigb;

/**
 * Our Min-SE: header field value and test.
 */
static unsigned int sst_min_se = 0;

/**
 * Should the SE < sst_min_se be rehected with a 422 reply?
 */
static unsigned int sst_reject = 1;

/**
 * The value of the message flag to flag an INVITE we want to process
 * through the SST module.
 */
static int sst_flag = 0;

/**
 * Our Session-Expire minimum interval
 */
static unsigned int sst_interval = 0;


static str sst_422_rpl = str_init("Session Timer Too Small");
static str info_val_name = str_init("sst_info");


/**
 * This is not a public API. This function is called when the module
 * is loaded from the mod_init() function in sst.c to initialize the
 * callback handlers and local variables.
 *
 * @param timeout_avp_p - The pointer to the dialog modules timeout
 *                        AVP.
 * @param min_se - The minimum session expire value allowed by this
 *                PROXY.
 * @param flag - sst flag
 * @param reject - reject state
 * @param interval - The minimum session expire value used by this
 *                  PROXY
 */
void sst_handler_init(unsigned int min_se, int flag, unsigned int reject,
		unsigned int interval)
{
	sst_min_se = min_se;
	sst_flag = 1 << flag;
	sst_reject = reject;
	sst_interval = MAX(interval, sst_min_se);
}

/**
 * Every time a new dialog is created (from a new INVITE) the dialog
 * module will call this callback function. We need to track the
 * dialogs lifespan from this point forward until it is terminated
 * with a BYE, CANCEL, etc. In the process, we will see if either or
 * both ends of the conversation supports SIP Session Timers and setup
 * the dialog timeout to expire at the session timer expire time. Each
 * time the new re-INVITE is seen to update the SST, we will reset the
 * life span of the dialog to match it.
 *
 * This function will setup the other types of dialog callbacks
 * required to track the lifespan of the dialog. It will also start
 * the state tracking to figure out if and who supports SST.
 *
 * As per RFC4028: Request handling:
 *
 * - The proxy may insert a SE header if none found.
 * - The SE value can be anything >= Min-SE (if found)
 * - The proxy MUST NOT add a refresher parameter to the SE.
 *
 * - If SE is already there, the Proxy can reduce its value but no
 *   lower then the Min-SE value if present.
 * - If the SE value is >= Min-SE the proxy MUST NOT increase it!
 * - If the SE value is < Min-SE (settable by the proxy) the proxy
 *   MUST increase the SE value to >= the new Min-SE.
 * - The proxy MUST NOT insert or change the refresher parameter.
 *
 * - If the supported=timer is found, the proxy may reject the request
 *   with a 422 if the SE value is smaller then the local policy. The
 *   422 MUST hold the proxies Min-SE value >= 90.
 * - If support=timer is NOT indecated, the proxy can't reject with a
 *   422 but can include/increase the MIN-SE: to be = to local policy.
 *   and increase the SE to match the new Min-SE value.
 * - the proxy MUST NOT insert/change the Min-SE header if
 *   supported=timer is present. (DoS attacks)
 *
 * @param did - The dialog ID
 * @param type - The trigger event type (CREATED)
 * @param params - The pointer to nothing. As we did not attach
 *                anything to this callback in the dialog module.
 */
void sst_dialog_created_CB(struct dlg_cell *did, int type,
		struct dlg_cb_params * params)
{
	sst_info_t *info = NULL;
	sst_msg_info_t minfo;
	struct sip_msg* msg = params->msg;

	memset(&minfo, 0, sizeof(sst_msg_info_t));
	/*
	 * Only deal with messages flaged as SST interested.
	 */
	if ((msg->flags & sst_flag) != sst_flag) {
		LM_DBG("SST flag was not set for this request\n");
		return;
	}

	/*
	 * look only at INVITE
	 */
	if (msg->first_line.type != SIP_REQUEST ||
			msg->first_line.u.request.method_value != METHOD_INVITE) {
		LM_WARN("dialog create callback called with a non-INVITE request.\n");
		return;
	}

	/*
	 * Gather all he information about SST for this message
	 */
	if (parse_msg_for_sst_info(msg, &minfo)) {
		LM_ERR("failed to parse sst information\n");
		return;
	}

	info = (sst_info_t *)shm_malloc(sizeof(sst_info_t));
	if (info == NULL) {
		LM_ERR("No more shared memory!\n");
		return;
	}

	memset(info, 0, sizeof(sst_info_t));
	info->requester = (minfo.se?SST_UAC:SST_UNDF);
	info->supported = (minfo.supported?SST_UAC:SST_UNDF);
	info->interval = MAX(sst_interval, 90); /* For now, will set for real
										  * later */

	if (minfo.se != 0) {
		/*
		 * There is a SE already there, this is good, we just need to
		 * check the values out a little before passing it along.
		 */
		if (minfo.se < sst_min_se) {
			/*
			 * Problem, the requested Session-Expires is too small for
			 * our local policy. We need to fix it, or reject it or
			 * ignore it.
			 */
			if (!minfo.supported) {
				/*
				 * Increase the Min-SE: value in the request and
				 * forward it.
				 */
				char buf[80];
				if (minfo.min_se) {
					/* We need to update, which means, remove +
					 * insert */
					remove_minse_header(msg);
				}
				info->interval = MAX(sst_min_se, minfo.min_se);
				snprintf(buf, 80, "Min-SE: %d\r\n", info->interval);
				if (append_header(msg, buf)) {
					LM_ERR("Could not append modified Min-SE: header\n");
				}
			}
			else if (sst_reject) {
				/* Make sure that that all are at least 90 */
				send_reject(msg, MAX(MAX(sst_min_se, minfo.min_se), 90));
				shm_free(info);
				return;
			}
		}  /* end of se < sst_min_se */
		else {
			/* Use the INVITE SE: value */
			info->interval = minfo.se;
		}
	}
	else {
		/*
		 * No Session-Expire: stated in request.
		 */
		char buf[80];

		info->interval = MAX(minfo.min_se, sst_min_se);

		if (minfo.min_se && minfo.min_se < sst_min_se) {
			remove_minse_header(msg);
			snprintf(buf, 80, "Min-SE: %d\r\n", info->interval);
			if (append_header(msg, buf)) {
				LM_ERR("failed to append modified Min-SE: header\n");
				/* What to do? Let is slide, we can still work */
			}
		}

		info->interval = MAX(info->interval, sst_interval);
		info->requester = SST_PXY;
		snprintf(buf, 80, "Session-Expires: %d\r\n", info->interval);
		if (append_header(msg, buf)) {
			LM_ERR("failed to append Session-Expires header to proxy "
					"requested SST.\n");
			shm_free(info);
			return; /* Nothing we can do! */
		}
	}
	/* We keep the sst_info in the dialog's vals in case of restarting */
	/* No const here because of store_dlg_value's definition */
	str raw_info = {(char*)info, sizeof(sst_info_t)};
	if (dlg_binds->store_dlg_value(did, &info_val_name, &raw_info) != 0) {
		LM_ERR("No sst_info can be added to the dialog."
				"This dialog won't be considered after restart!\n");
	}

	dlg_binds->set_mod_flag(did, SST_DIALOG_FLAG);

	setup_dialog_callbacks(did, info);
	/* Early setup of default timeout */
	set_dialog_lifetime(did, info->interval);
	return;
}

void sst_dialog_loaded_CB(struct dlg_cell *did, int type,
		struct dlg_cb_params *params){

	/* Check if this is previously marked by sst module */
	if (!dlg_binds->is_mod_flag_set(did, SST_DIALOG_FLAG))
		return;

	/* We try to get the original sst info back */
	sst_info_t *info = (sst_info_t *)shm_malloc(sizeof(sst_info_t));

	if (info == NULL) {
		LM_ERR ("No more shared memory!\n");
		return;
	}

	memset(info, 0, sizeof(sst_info_t));

	str raw_info = {(char*)info, sizeof(sst_info_t)};
	if (dlg_binds->fetch_dlg_value(did, &info_val_name, &raw_info, 1) != 0){
		LM_ERR ("No sst_info found!\n");
		return;
	}

	setup_dialog_callbacks(did, info);
}

#ifdef USE_CONFIRM_CALLBACK
/**
 * Play time. Please ignore this call.
 */
static void sst_dialog_confirmed_CB(struct dlg_cell *did, int type,
		struct dlg_cb_params * params)
{
	struct sip_msg* msg = params->msg;

	LM_DBG("confirmed dialog CB %p\n", did);
	DLOGMSG(msg);
}
#endif /* USE_CONFIRM_CALLBACK */

/*
 * free function for dialog callbacks
 */
static void sst_free_info(void* param)
{
	sst_info_t* info = (sst_info_t *) param;

	if (info == NULL) {
		LM_ERR("null sst info!\n");
		return;
	}

	/*
	 * FIXME refcnt is 0 that means no dialog termination callback
	 * was called what shall we do here? For the moment we free
	 * the memory but this might crash if the free function is called
	 * multiple times
	 *
	 */
	if (info->refcnt == 0 || (--info->refcnt) == 0)
		shm_free(info);
}

/**
 * This callback is called when ever a dialog is terminated. The cause
 * of the termination can be normal, failed call, or expired. It is
 * the expired dialog we are really interested in.
 *
 * @param did - The Dialog ID / structure pointer. Used as an ID only.
 * @param type - The termination cause/reason.
 * @param params - The sst information
 */
static void sst_dialog_terminate_CB(struct dlg_cell* did, int type,
		struct dlg_cb_params * params)
{
	switch (type) {
		case DLGCB_FAILED:
			LM_DBG("DID %p failed (canceled). "
				"Terminating session.\n", did);
			break;
		case DLGCB_EXPIRED:
			/* In the case of expired, the msg is pointing at a
			 * FAKED_REPLY (-1)
			 */
			LM_DBG("Terminating session.\n");
			break;
		default: /* Normal termination. */
			LM_DBG("Terminating DID %p session\n", did);
			break;
	}

	((sst_info_t *)(*params->param))->refcnt++;

	return;
}

/**
 * Callback from the dialog module when the dialog is being updated in
 * its life span. We are only interested in the INVITE or UPDATE if
 * SST is supported and active for this dialog. In this case, we need
 * to update the expire time for the dialog based on the
 * Session-Expires: header in the reINVITE/UPDATE request.
 *
 * When this callback returns control to the dialog module it WILL
 * reset the timeout of the dialog. We need to make sure we set the
 * AVP here or the dialog timeout will be reset to the DEFAULT value
 * if this is a different transaction. (so the AVP value is gone)
 *
 * @param did - The dialog structure. The pointer is used as an ID.
 * @param type - The reason for the callback. DLGCB_REQ_WITHIN
 * @param params - The sst information
 */
static void sst_dialog_request_within_CB(struct dlg_cell* did, int type,
		struct dlg_cb_params * params)
{
	sst_info_t *info = (sst_info_t *)*(params->param);
	sst_info_t tmp_info;
	sst_msg_info_t minfo = {0,0,0,0};
	struct sip_msg* msg = params->msg;
	short info_dirty = 0;

	if (msg->first_line.type == SIP_REQUEST) {
		if ((msg->first_line.u.request.method_value == METHOD_INVITE ||
						msg->first_line.u.request.method_value == METHOD_UPDATE)) {

			LM_DBG("Update by a REQUEST. %.*s\n",
					msg->first_line.u.request.method.len,
					msg->first_line.u.request.method.s);
			if (parse_msg_for_sst_info(msg, &minfo)) {
				// FIXME: need an error message here
				return;
			}
			/* Early resetting of the value here */
			if (minfo.se > 0) {
				if (sst_interval > minfo.min_se)
					CHECK_AND_UPDATE_SST_INFO(info, interval, sst_interval, info_dirty);
				else
					CHECK_AND_UPDATE_SST_INFO_TMP(info, interval,
							MAX(minfo.se, sst_min_se), info_dirty, tmp_info);
			}
			CHECK_AND_UPDATE_SST_INFO_TMP(info, supported,
					(minfo.supported?SST_UAC:SST_UNDF), info_dirty, tmp_info);
			set_dialog_lifetime(did, info->interval);
		}
		else if (msg->first_line.u.request.method_value == METHOD_PRACK
		|| msg->first_line.u.request.method_value == METHOD_ACK) {
			/* Special case here. The PRACK will cause the dialog
			 * module to reset the timeout value to the ldg->lifetime
			 * value and look for the new AVP value bound to the
			 * 1XX/PRACK/200OK/ACK transaction and not to the
			 * INVITE/200OK avp value. So we need to set the AVP
			 * again!
			 */
			LM_DBG("ACK/PRACK workaround applied!%d\n", info->interval);
			set_dialog_lifetime(did, info->interval);
		}
	}
	else if (msg->first_line.type == SIP_REPLY) {
		if ((msg->first_line.u.reply.statuscode > 199 &&
						msg->first_line.u.reply.statuscode < 300)) {
			/*
			 * To spec (RFC) the internal time out value so not be reset
			 * until here.
			 */
			LM_DBG("Update by a REPLY %d %.*s\n",
					msg->first_line.u.reply.statuscode,
					msg->first_line.u.reply.reason.len,
					msg->first_line.u.reply.reason.s);
			if (parse_msg_for_sst_info(msg, &minfo)) {
				// FIXME: need an error message here
				return;
			}
			set_dialog_lifetime(did, minfo.se);
			CHECK_AND_UPDATE_SST_INFO_TMP(info, supported,
					(minfo.supported?SST_UAC:SST_UNDF), info_dirty, tmp_info);
			CHECK_AND_UPDATE_SST_INFO(info, interval, minfo.se, info_dirty);
		}
	}

	if (info_dirty){
		str raw_info = {(char*)info, sizeof(sst_info_t)};
		if (dlg_binds->store_dlg_value(did, &info_val_name, &raw_info) != 0) {
			LM_ERR("sst_info can't be updated\n");
		}
	}
}

/**
 * This callback is called on any response message in the lifespan of
 * the dialog. The callback is called just before the message is
 * copied to pkg memory so it is still mutable.
 *
 * @param did - The dialog structure. The pointer is used as an ID.
 * @param type - The reason for the callback. DLGCB_CONFIRMED
 * @param params - The sst information
 */
static void sst_dialog_response_fwded_CB(struct dlg_cell* did, int type,
		struct dlg_cb_params * params)
{
	struct sip_msg* msg = params->msg;
	int *param;
	short info_dirty = 0;

	/*
	 * This test to see if the message is a response sould ALWAYS be
	 * true. This callback should not get called for requests. But
	 * lets be safe.
	 */

	if (msg->first_line.type != SIP_REPLY)
		return;

	sst_msg_info_t minfo = {0,0,0,0};
	sst_info_t *info = (sst_info_t *)*(params->param);
	sst_info_t tmp_info;

	LM_DBG("Dialog seen REPLY %d %.*s\n",
			msg->first_line.u.reply.statuscode,
			msg->first_line.u.reply.reason.len,
			msg->first_line.u.reply.reason.s);
	/*
	 * Need to check to see if it is a 422 response. If it is,
	 * make sure our Min-SE: for this dialog is set at least as
	 * large as in the Min-SE: in the reply 422 message. If not,
	 * we will create an INVITE, 422 loop.
	 */
	if (msg->first_line.u.reply.statuscode == 422) {
		if (parse_msg_for_sst_info(msg, &minfo)) {
			LM_ERR("failed to prase sst information for thr 422 reply\n");
			return;
		}
		/* Make sure we do not try to use anything smaller */
		if (info->interval < minfo.min_se)
			CHECK_AND_UPDATE_SST_INFO(info, interval, minfo.min_se, info_dirty);

		goto update_info; /* There is nothing else to do with this */
	}
	/*
	 * We need to get the method this reply is for from the CSEQ
	 * body. The RFC states we can only play with 2XX from the
	 * INVITE or reINVTE/UPDATE.
	 */
	if (!msg->cseq && ((parse_headers(msg, HDR_CSEQ_F, 0) == -1) || !msg->cseq)) {
		LM_ERR("failed to parse CSeq\n");
		return;
	}

	/* 2XX replies to INVITES only !*/
	if (msg->first_line.u.reply.statuscode > 199 &&
			msg->first_line.u.reply.statuscode < 300 &&
			(get_cseq(msg)->method_id == METHOD_INVITE ||
					get_cseq(msg)->method_id == METHOD_UPDATE)) {
		if (parse_msg_for_sst_info(msg, &minfo)) {
			LM_ERR("failed to parse sst information for the 2XX reply\n");
			return;
		}
		LM_DBG("parsing 200 OK response %d / %d\n", minfo.supported, minfo.se);
		if (info->supported != SST_UAC) {
			CHECK_AND_UPDATE_SST_INFO_TMP(info, supported,
					(minfo.supported?SST_UAS:SST_UNDF),info_dirty, tmp_info);
		}
		if (minfo.se != 0) {
			if (sst_interval > minfo.min_se)
				CHECK_AND_UPDATE_SST_INFO(info, interval, sst_interval, info_dirty);
			else
				CHECK_AND_UPDATE_SST_INFO_TMP(info, interval,
						MAX(minfo.se, sst_min_se), info_dirty, tmp_info);
			LM_DBG("UAS supports timer\n");
			set_dialog_lifetime(did, info->interval);
		}
		else {
			/* no se header found, we want to resquest it. */
			if (info->supported == SST_UAC) {
				char se_buf[80];

				LM_DBG("UAC supports timer\n");
				LM_DBG("appending the Session-Expires: header to the 2XX reply."
						" UAC will deal with it.\n");
				/*
				 * GOOD! we can just insert the Session-Expires:
				 * header and forward back to the UAC and it will
				 * deal with refreshing the session.
				 */
				if (sst_interval > minfo.min_se)
					CHECK_AND_UPDATE_SST_INFO(info, interval, sst_interval,
							info_dirty);
				else
					CHECK_AND_UPDATE_SST_INFO_TMP(info, interval,
						MAX(minfo.se, sst_min_se), info_dirty, tmp_info);
				snprintf(se_buf, 80, "Session-Expires: %d;refresher=uac\r\n",
						info->interval);
				if (append_header(msg, se_buf)) {
					LM_ERR("failed to append Session-Expires header\n");
					return;
				}
				if (add_timer_ext(msg))
					LM_ERR("failed to append timer extension to Required\n");

				/* Set the dialog timeout HERE */
				set_dialog_lifetime(did, info->interval);
			}
			else {
				/* We are sunk, uac did not request it, and it
				 * does not support it */
				LM_DBG("UAC and UAS do not support timers!"
						" No session timers for this session.\n");
				param = find_param_export("dialog", "default_timeout", INT_PARAM);
				CHECK_AND_UPDATE_SST_INFO_TMP(info, interval,
						param?*param:12*3600, info_dirty, tmp_info);
				set_dialog_lifetime(did, info->interval);
			}
		}
	} /* End of 2XX for an INVITE */

update_info:
	if (info_dirty){
		str raw_info = {(char*)info, sizeof(sst_info_t)};
		if (dlg_binds->store_dlg_value(did, &info_val_name, &raw_info) != 0) {
			LM_ERR("sst_info can't be updated\n");
		}
	}
}

/**
 * The sstCheckMin() script command handler. Return 1 (true) if the
 * MIN-SE: of the message is too small compared to the sst_min_se
 * value. This will allow the script to reply to this INVITE with a
 * "422 Session Timer Too Small" response. if sst_min_se was never set
 * the recommended value of 1800 seconds will be used.
 *
 * If the flag (str1) is set to 1, the 422 reply will be sent with the
 * sst MIN_SE value in the header. If the flag is not set or is NULL,
 * no reply is sent.

 * @param msg  - The sip message from the script (INVITE only)
 * @param flag - Reply mode Flag. 0/NULL do not send reply, 1 send 422
 *               reply if Session-Expires is to small with the MIN-SE
 *               header in the reply
 * @param str2 - Not used.
 *
 * @return 1 if the MIN-SE is too small, -1 if it is OK, or It could
 *         not be checked.
 *
 * NOTE: returning 0 == drop message, 1 == true, -1 == false in the
 *       script.
 */
int sst_check_min(struct sip_msg *msg, int *flag)
{
	enum parse_sst_result result;
	struct session_expires se = {0,0};
	unsigned minse = 0;

	/*
	 * Only look in INVITES. We can't reply with a 422 to a 2xx reply
	 * now can we. This check can ONLY be done on the INVITE/UPDATE.
	 */
	if (msg->first_line.type == SIP_REQUEST &&
			msg->first_line.u.request.method_value == METHOD_INVITE) {
		/*
		 * First see if there is an Session-Expires: header.  If there
		 * is, also look for a MIN-SE: header. If there is, use the
		 * minimum value of the two to compare with srt1. All MUST not
		 * be less then 90 and 1800 is recomended. See RCF section 4.
		 */
		if ((result = parse_session_expires(msg, &se)) != parse_sst_success) {
			if (result != parse_sst_header_not_found) {
				LM_ERR("failed to parse Session-Expires headers.\n");
				return 0; /* Error drop the message */
			}
			/* Session-Expires not supported/stated */
			LM_DBG("No Session-Expires header found. retuning false (-1)\n");
			/*
			 * NOTE: 0 == drop message, 1 == true, -1 == false
			 */
			return -1;
		}

		/*
		 * We have a Session_expire header. Now look for the MIN-SE.
		 */
		if ((result = parse_min_se(msg, &minse)) != parse_sst_success) {
			if (result != parse_sst_header_not_found) {
				/*
				 * This is an error. The header was found but could
				 * not parse it.
				 */
				LM_ERR("failed to parse MIN-SE header.\n");
				return -1;
			}
			/*
			 * If not stated, use the value from the session-expires
			 * header
			 */
			LM_DBG("No MIN-SE header found.\n");
			minse = 90 /*this is the recommended value*/ /*se.interval*/;
		}

		LM_DBG("Session-Expires: %d; MIN-SE: %d\n",	se.interval, minse);

		/*
		 * Now compare our MIN-SE with the messages and see if it is
		 * too small. We will take the smaller of the messages
		 * Session-expires and min-se if stated.
		 */
		if (sst_min_se > MIN(minse, se.interval)) {
			/*
			 * Too small. See if we need to send the 422 and are able
			 * to send it.
			 */
			if (flag) {
				char minse_hdr[3+1+2+1+1+11+CRLF_LEN+2+1];
				int hdr_len = 3+1+2+1+1+11+CRLF_LEN+2;
				memset(minse_hdr, 0, hdr_len+1);
				hdr_len = snprintf(minse_hdr, hdr_len,
					"%s%d%s", "MIN-SE: ", sst_min_se,CRLF);
				LM_DBG("Sending 422: %.*s\n", hdr_len, minse_hdr);
				if (send_response(msg, 422, &sst_422_rpl, minse_hdr, hdr_len)){
					LM_ERR("Error sending 422 reply.\n");
				}
			}
			LM_DBG("Done returning true (1)\n");
			return 1; /* return true */
		}
	}
	LM_DBG("Done returning false (-1)\n");
	/*
	 * All is good.
	 */
	return -1; /* return false */
}

/**
 * Send a reply (response) to the passed in SIP request messsage with
 * the code and reason. If the header is not NULL (and header_len !=
 * 0) the add the header to the reply message.
 *
 * @param request The SIP request message to build the reply from.
 * @param code The response code. i.e 200
 * @param reason The response reason. i.e. "OK"
 * @param header the header block to add to the reply.
 * @param header_len The length of the header block. (header)
 *
 * @return 0 on success, none-zero on an error.
 */
static int send_response(struct sip_msg *request, int code, str *reason,
		char *header, int header_len)
{

	if (sigb.reply != 0) {
		/* Add new headers if not null or zero length */
		if ((header) && (header_len)) {
			if (add_lump_rpl(request, header, header_len, LUMP_RPL_HDR) == 0) {
				/* An error with adding the lump */
				LM_ERR("unable to append header.\n");
				return -1;
			}
		}
		/* Now using the sl function, send the reply/response */
		if (sigb.reply(request, code, reason, NULL) < 0) {
			LM_ERR("Unable to sent reply.\n");
			return -1;
		}
	}
	else {
		return -1;
	}
	return(0);
}

/**
 * Adds the timer extension to the Require header, if it does
 * not exist. Adds a new Require header if it does not exist.
 *
 * @param msg The message to add the extension to
 *
 * @return 0 on success, non-zero on failure.
 */
static int add_timer_ext(struct sip_msg *msg)
{
	struct hdr_field *require_hdr, *hdr;
	struct lump* anchor = NULL;
	char *s = NULL;
	int len = 0;
	unsigned int reqmask;

	LM_DBG("Appending timer extension\n");

	if (parse_headers(msg, HDR_EOH_F, 0) == -1) {
		LM_ERR("failed to parse headers in message.\n");
		return(1);
	}

	require_hdr = get_header_by_static_name(msg, "Require");
	if (!require_hdr) {
		LM_DBG("Require header does not exist - adding a new one\n");
		return append_header(msg, "Require: timer\r\n");
	}

	/* search through all the headers, if there is any timer in there */
	for (hdr = require_hdr; hdr; hdr = hdr->sibling) {
		/* XXX: it is ineficient to parse it every time
		 * but this is the only place it is used, and it
		 * is only called once.
		 * Calling Supported's parse function, the format
		 * is similar to Require's one */
		parse_supported_body(&(hdr->body), &reqmask);
		if (reqmask & F_SUPPORTED_TIMER) {
			LM_DBG("timer already in Require\n");
			return (0);
		}
	}
	LM_DBG("appending timer to the end of first Require header\n");

	/* timer not found - adding at the end of Require */
	if ((anchor = anchor_lump(msg, require_hdr->body.s +
				require_hdr->body.len - msg->buf, 0)) == 0) {
		LM_ERR("failed to get anchor to append header\n");
		return(1);
	}
	len = strlen(", timer");
	if ((s = (char *)pkg_malloc(len)) == 0) {
		LM_ERR("No more pkg memory. (size requested = %d)\n", len);
		return(1);
	}
	memcpy(s, ", timer", len);
	if (insert_new_lump_before(anchor, s, len, 0) == 0) {
		LM_ERR("failed to insert lump\n");
		pkg_free(s);
		return(1);
	}
	LM_DBG("Done appending extension successfully.\n");
	return(0);
}

/**
 * Given some header text, append it to the passed in message.
 *
 * @param msg The message to append the header text to.
 * @param header The header text to append.
 *
 * @return 0 on success, non-zero on failure.
 */
static int append_header(struct sip_msg *msg, const char *header)
{
	struct lump* anchor = NULL;
	char *s = NULL;
	int len = 0;

	LM_DBG("Appending header: %s", header);

	if (parse_headers(msg, HDR_EOH_F, 0) == -1) {
		LM_ERR("failed to parse headers in message.\n");
		return(1);
	}

	if ((anchor = anchor_lump(msg, msg->unparsed - msg->buf, 0)) == 0) {
		LM_ERR("failed to get anchor to append header\n");
		return(1);
	}
	len = strlen(header);
	if ((s = (char *)pkg_malloc(len)) == 0) {
		LM_ERR("No more pkg memory. (size requested = %d)\n", len);
		return(1);
	}
	memcpy(s, header, len);
	if (insert_new_lump_before(anchor, s, len, 0) == 0) {
		LM_ERR("failed to insert lump\n");
		pkg_free(s);
		return(1);
	}
	LM_DBG("Done appending header successfully.\n");
	return(0);
}

/**
 * Remove a header from a message if found.
 *
 * @param msg The message to look for the header to remove.
 * @param header The header name: text.
 *
 * @return 0 if the header was not found, >0 is successful, -1 on an
 *         error.
 */
static int remove_minse_header(struct sip_msg *msg)
{
	struct lump* anchor = NULL;
	struct hdr_field *hf = NULL;
	int cnt = 0;

	/* parse all headers as we want to get all MIN-SE headers*/
	if (parse_headers(msg, HDR_EOH_F, 0) == -1) {
		LM_ERR("failed to parse headers in message.\n");
		return(-1);
	}

	for (hf = msg->min_se; hf; hf = hf->sibling) {
		anchor = del_lump(msg, hf->name.s-msg->buf, hf->len, 0);
		if (anchor == 0) {
			LM_ERR("no more pkg memory\n");
			return -1;
		}
		cnt++;
	}
	return cnt;
}

/**
 * Set the dialog's AVP value so the dialog module will use this value
 * and not the default when returning from the dialog callback.
 *
 * @param dlg The current dialog
 * @param value The value you want to set the AVP to.
 */
static void set_dialog_lifetime(struct dlg_cell *dlg, unsigned int value)
{
	/* Set the dialog timeout HERE */
	dlg->lifetime = value;
	dlg->lifetime_dirty = 1;

	LM_DBG("set dialog timeout value to %d\n", value);
}

/**
 * Gether the message information about SST from the current message
 * being processed.
 *
 * @param msg The current message to parse.
 * @param minfo The SST information found in the message.
 *
 * @return 0 on success, -1 on a parsing error.
 */
static int parse_msg_for_sst_info(struct sip_msg *msg, sst_msg_info_t *minfo)
{
	int rtn = 0;
	struct session_expires se = {0,0};

	if (!msg || !minfo) {
		return (-1);
	}

	/*
	 * parse the supported infor
	 */
	minfo->supported = 0; /*Clear it */
	minfo->se = 0;
	minfo->refresher = sst_refresher_unspecified;
	minfo->min_se = 0;

	/*
	 * The parse_supported() will return 0 if found and parsed OK, -1
	 * if not found or an error parsing the one it did find! So assume
	 * it is not found if unsuccessful.
	 */
	if (msg->supported && parse_supported(msg) == 0 &&
	(get_supported(msg) & F_SUPPORTED_TIMER))
			minfo->supported = 1;

	/*
	 * Parse the Min-SE: header next.
	 */
	minfo->min_se = 0;
	if ((rtn = parse_min_se(msg, &minfo->min_se)) != parse_sst_success) {
		minfo->min_se = 0; /* Make sure it statys clean */
	}
	minfo->se = 0;
	if ((rtn = parse_session_expires(msg, &se)) == parse_sst_success) {
		minfo->se = se.interval;
		minfo->refresher = se.refresher;
	}
	return(0);
}

/**
 * Add the Min-SE: header and send a reply 422.
 *
 * @param msg The message to opperate on.
 * @param min_se The Min-SE: value to use in the heaader.
 *
 * @return 0 on success, -1 on error.
 */
static int send_reject(struct sip_msg *msg, unsigned int min_se)
{
	char tmp[8 /* "MIN-SE: " */ + INT2STR_MAX_LEN + 2 /* CRLF */ + 1 /* '\0' */];
	int hdr_len = 0;
	char *minse_hdr = NULL;

	hdr_len = snprintf(tmp, sizeof(tmp), "%s %d%s", "MIN-SE:", min_se, CRLF);
	if (send_response(msg, 422, &sst_422_rpl, minse_hdr, hdr_len)) {
		LM_ERR("Error sending 422 reply.\n");
		return(-1);
	}
	LM_DBG("Send reject reply 422 with Min-SE: %d\n", min_se);
	return(0);
}

/**
 * A helper function to setup all the callbacks from the dialog module
 * after we find intrest in the dialog.
 *
 * @param did The Dialog ID.
 * @param info The sst information.
 *
 */
static void setup_dialog_callbacks(struct dlg_cell *did, sst_info_t *info)
{
	/*
	 * Register for the other callbacks from the dialog.
	 */

#ifdef USE_CONFIRM_CALLBACK
	LM_DBG("Adding callback DLGCB_CONFIRMED\n");
	dlg_binds->register_dlgcb(did,
			DLGCB_CONFIRMED, sst_dialog_confirmed_CB, info, NULL);
#endif /* USE_CONFIRM_CALLBACK */

	LM_DBG("Adding callback "
			"DLGCB_FAILED|DLGCB_TERMINATED|DLGCB_EXPIRED\n");
	if (dlg_binds->register_dlgcb(did,
			DLGCB_FAILED|DLGCB_TERMINATED|DLGCB_EXPIRED,
			sst_dialog_terminate_CB, (void *)info, sst_free_info) != 0)
		LM_ERR("could not add the DLGCB_TERMINATED callback\n");

	LM_DBG("Adding callback DLGCB_REQ_WITHIN\n");
	/* This is for the reINVITE/UPDATE requests */
	dlg_binds->register_dlgcb(did, DLGCB_REQ_WITHIN,
			sst_dialog_request_within_CB, info, NULL);
	/*
	 * This is for the final configuration of who will do SST for
	 * us. In the DLGCB_CONFIRMED callback the message is
	 * immutable! we must do all the real work in the DLGCB_FRD
	 * callback were we can change the message.
	 */
	LM_DBG("Adding callback DLGCB_RESPONSE_FWDED|DLGCB_RESPONSE_WITHIN\n");
	dlg_binds->register_dlgcb(did, DLGCB_RESPONSE_FWDED|DLGCB_RESPONSE_WITHIN,
			sst_dialog_response_fwded_CB, info, NULL);

	LM_DBG("Adding mi handler\n");
	dlg_binds->register_dlgcb(did, DLGCB_MI_CONTEXT,
			sst_dialog_mi_context_CB, info, NULL);
}
