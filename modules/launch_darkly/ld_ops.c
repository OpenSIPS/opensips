/*
 * Copyright (C) 2023 Five9 Inc.
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 */


#include <launchdarkly/server_side/bindings/c/sdk.h>
#include <launchdarkly/bindings/c/context_builder.h>

#include "../../pvar.h"
#include "../../ut.h"

/* default streaming endpoint used when ServiceEndpoints is not customized
 * via LDServerConfigBuilder_ServiceEndpoints_StreamingBaseURL() - only used
 * for the informational log line below, not passed to the SDK */
#define LD_DEFAULT_STREAM_URI "https://stream.launchdarkly.com/all"

unsigned int connect_wait = 500;       //milliseconds
unsigned int re_init_interval = 10;    //seconds
char * sdk_key = NULL;

static LDServerSDK ld_sdk = NULL;
static unsigned int last_init_attempt_time = 0;
static enum LDLogLevel ld_log_level = LD_LOG_WARN;

void set_ld_log_level( char *log_level_s)
{
	/* FATAL/CRITICAL/TRACE aren't valid enum LDLogLevel values - map them
	 * onto their closest equivalent so existing modparam values still work */
	if (strcasecmp( log_level_s, "LD_LOG_FATAL")==0 ||
	strcasecmp( log_level_s, "LD_LOG_CRITICAL")==0 ||
	strcasecmp( log_level_s, "LD_LOG_ERROR")==0)
		ld_log_level = LD_LOG_ERROR;
	else
	if (strcasecmp( log_level_s, "LD_LOG_WARNING")==0 ||
	strcasecmp( log_level_s, "LD_LOG_WARN")==0)
		ld_log_level = LD_LOG_WARN;
	else
	if (strcasecmp( log_level_s, "LD_LOG_INFO")==0)
		ld_log_level = LD_LOG_INFO;
	else
	if (strcasecmp( log_level_s, "LD_LOG_DEBUG")==0 ||
	strcasecmp( log_level_s, "LD_LOG_TRACE")==0)
		ld_log_level = LD_LOG_DEBUG;
	else {
		LM_WARN("unrecognized '%s' LG log level, using LD_LOG_WARN\n",
			log_level_s);
	}
}


static bool _oss_log_enabled(enum LDLogLevel level, void *user_data)
{
	return level >= ld_log_level;
}


static void _oss_log_write(enum LDLogLevel level, char const *msg, void *user_data)
{
	/* enum LDLogLevel { LD_LOG_DEBUG=0, LD_LOG_INFO, LD_LOG_WARN, LD_LOG_ERROR } */
	static const int log_map[LD_LOG_ERROR+1] = {L_DBG, L_INFO, L_WARN, L_ERR};

	LM_GEN( log_map[level], "[LD] %s\n", msg);
}


static void ld_configure_logging(LDServerConfigBuilder cfg_builder)
{
	struct LDLogBackend backend;
	LDLoggingCustomBuilder custom_logging;

	LDLogBackend_Init(&backend);
	backend.Enabled = _oss_log_enabled;
	backend.Write = _oss_log_write;
	backend.UserData = NULL;

	custom_logging = LDLoggingCustomBuilder_New();
	LDLoggingCustomBuilder_Backend(custom_logging, backend);
	LDServerConfigBuilder_Logging_Custom(cfg_builder, custom_logging);
}


static int ld_client_init_attempt(void)
{
	LDServerConfigBuilder cfg_builder;
	LDServerConfig ld_cfg;
	LDStatus ld_status;
	bool ld_succeeded;

	/* maybe already connected? */
	if (ld_sdk)
		return 0;

	/* too soon to retry a new connect ?*/
	if (last_init_attempt_time!=0 &&
	(last_init_attempt_time + re_init_interval > get_ticks()) )
		return -2;

	LM_DBG("attempting LD client re-init\n");
	LM_INFO("waiting to initialize\n");

	/* the config (and its builder) are single-use, so we rebuild them
	 * on every attempt */
	cfg_builder = LDServerConfigBuilder_New( sdk_key );
	ld_configure_logging(cfg_builder);

	ld_status = LDServerConfigBuilder_Build(cfg_builder, &ld_cfg);
	if (!LDStatus_Ok(ld_status)) {
		LM_ERR("failed to build LD config: %s\n", LDStatus_Error(ld_status));
		LDStatus_Free(ld_status);
		last_init_attempt_time = get_ticks();
		return -1;
	}

	/* ownership of ld_cfg is transferred into the SDK instance */
	ld_sdk = LDServerSDK_New(ld_cfg);

	LM_INFO("connection to streaming url: %s\n", LD_DEFAULT_STREAM_URI);

	/* block for up to connect_wait ms while the SDK connects and fetches flags */
	LDServerSDK_Start(ld_sdk, connect_wait, &ld_succeeded);
	if (!ld_succeeded) {
		LDServerSDK_Free(ld_sdk);
		ld_sdk = NULL;
		last_init_attempt_time = get_ticks();
		return -1;
	}

	LM_INFO("initialized\n");

	last_init_attempt_time = 0;

	return 0;
}


int ld_init_child(void)
{
	if (ld_client_init_attempt()!=0)
		LM_ERR("LD client failed to initialize, proceeding offline\n");
	else
		LM_DBG("LD client initialized\n");

	return 0;
}


int ld_feature_enabled(str *feat, str *user, int user_extra_avp_id,
																int fallback)
{
	LDContextBuilder ctx_builder;
	LDContext ld_context;
	LDValue ld_val;
	LDEvalDetail ld_detail;
	LDEvalReason ld_reason;
	enum LDEvalReason_ErrorKind error_kind;
	bool ld_res;
	struct usr_avp *avp;
	int_str val;
	str s_nt, extra_key, extra_val;
	char *p;
	int ret;

	if (ld_sdk==NULL && ld_client_init_attempt()<0) {
		LM_ERR("not having a connected LD client :(\n");
		goto error;
	}

	if (pkg_nt_str_dup( &s_nt, user)<0) {
		LM_ERR("failed to pkg_nt duplicate the user\n");
		goto error;
	}
	ctx_builder = LDContextBuilder_New();
	LDContextBuilder_AddKind( ctx_builder, "user", s_nt.s);
	pkg_free(s_nt.s);

	/* do we have custom key-val pairs to add to the user? */
	if (user_extra_avp_id>=0) {
		avp = NULL;
		/* iterate all the AVPs with the keys */
		while ((avp=search_first_avp(AVP_VAL_STR,user_extra_avp_id,&val,avp))!=NULL) {
			/* split and evaluate the value part */
			if ( (p=q_memchr( val.s.s, '=', val.s.len))==NULL) {
				LM_ERR("extra <%.*s> has no key separtor '=', discarding\n",
					val.s.len, val.s.s);
				continue;
			}
			extra_key.s = val.s.s;
			extra_key.len = p-val.s.s;
			p++;
			if (p==val.s.s+val.s.len) {
				LM_ERR("extra <%.*s> has no value, discarding\n",
					val.s.len, val.s.s);
				continue;
			}
			extra_val.s = p;
			extra_val.len = val.s.s+val.s.len-p;

			/* create the new value */
			if (pkg_nt_str_dup( &s_nt, &extra_val)<0) {
				LM_ERR("failed to pkg_nt duplicate the extra value\n");
				goto error1;
			}

			ld_val = LDValue_NewString( s_nt.s );
			pkg_free(s_nt.s);

			/* add the value as key (LDContextBuilder_Attributes_Set
			 * consumes the LDValue we pass in) */
			if (pkg_nt_str_dup( &s_nt, &extra_key)<0) {
				LM_ERR("failed to pkg_nt duplicate the extra key\n");
				LDValue_Free(ld_val);
				goto error1;
			}
			if (!LDContextBuilder_Attributes_Set( ctx_builder, "user",
			s_nt.s, ld_val)) {
				LM_ERR("failed to add new key+val to user extra\n");
				pkg_free(s_nt.s);
				goto error1;
			}
			pkg_free(s_nt.s);
		}
	}

	/* now, run the check */
	if (pkg_nt_str_dup( &s_nt, feat)<0) {
		LM_ERR("failed to pkg_nt duplicate the feature name\n");
		goto error1;
	}

	ld_context = LDContextBuilder_Build(ctx_builder);

	ld_res = LDServerSDK_BoolVariationDetail( ld_sdk, ld_context, s_nt.s,
		fallback?true:false, &ld_detail);
	ret = ld_res ? 1 : -1;

	/* any error ? */
	if (LDEvalDetail_Reason(ld_detail, &ld_reason) &&
	LDEvalReason_Kind(ld_reason)==LD_EVALREASON_ERROR) {
		ret = 2 * ret; //return some internal error indication
		if (LDEvalReason_ErrorKind(ld_reason, &error_kind)) {
			switch (error_kind) {
				case LD_EVALREASON_ERROR_CLIENT_NOT_READY:
					LM_BUG("LD client not initialized at this point!?!\n");
					break;
				case LD_EVALREASON_ERROR_USER_NOT_SPECIFIED:
					LM_ERR("LD user is empty/NULL!\n");
					break;
				case LD_EVALREASON_ERROR_FLAG_NOT_FOUND:
					LM_ERR("the caller provided a flag key that did not match any known flag\n");
					break;
				case LD_EVALREASON_ERROR_WRONG_TYPE:
					LM_ERR("the result value was not of the requested type- expected LDServerSDK_BoolVariation\n");
					break;
				case LD_EVALREASON_ERROR_MALFORMED_FLAG:
					LM_ERR("internal inconsistency in the flag data, a rule specified a nonexistent variation\n");
					break;
				case LD_EVALREASON_ERROR_EXCEPTION:
					LM_ERR("an unexpected error happened that stopped evaluation\n");
					break;
				default:
					LM_ERR("unknown %d error reported by LDServerSDK_BoolVariationDetail\n",error_kind);
					break;
			}
		}
	}
	LDEvalDetail_Free(ld_detail);

	LM_DBG("feature flag %s is %s\n", s_nt.s, (ret>0)?"TRUE":"FALSE");
	pkg_free(s_nt.s);

	LDContext_Free(ld_context);
	return ret;

error1:
	LDContextBuilder_Free(ctx_builder);
error:
	return fallback?2:-2;
}
