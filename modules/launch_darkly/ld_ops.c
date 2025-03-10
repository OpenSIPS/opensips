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


#include <launchdarkly/api.h>

#include "../../pvar.h"
#include "../../ut.h"

unsigned int connect_wait = 500;       //milliseconds
unsigned int re_init_interval = 10;    //seconds
char * sdk_key = NULL;

static struct LDConfig *ld_cfg = NULL;
static struct LDClient *ld_client = NULL;
static unsigned int last_init_attempt_time = 0;
static int ld_log_level = LD_LOG_WARNING;

void set_ld_log_level( char *log_level_s)
{
	if (strcasecmp( log_level_s, "LD_LOG_FATAL")==0)
		ld_log_level = LD_LOG_FATAL;
	else
	if (strcasecmp( log_level_s, "LD_LOG_CRITICAL")==0)
		ld_log_level = LD_LOG_CRITICAL;
	else
	if (strcasecmp( log_level_s, "LD_LOG_ERROR")==0)
		ld_log_level = LD_LOG_ERROR;
	else
	if (strcasecmp( log_level_s, "LD_LOG_WARNING")==0)
		ld_log_level = LD_LOG_WARNING;
	else
	if (strcasecmp( log_level_s, "LD_LOG_INFO")==0)
		ld_log_level = LD_LOG_INFO;
	else
	if (strcasecmp( log_level_s, "LD_LOG_DEBUG")==0)
		ld_log_level = LD_LOG_DEBUG;
	else
	if (strcasecmp( log_level_s, "LD_LOG_TRACE")==0)
		ld_log_level = LD_LOG_TRACE;
	else {
		LM_WARN("unrecognized '%s' LG log level, using LD_LOG_WARNING\n",
			log_level_s);
	}
}


static void _oss_logger(const LDLogLevel level, const char *const text)
{
	/*
	enum  LDLogLevel {
		LD_LOG_FATAL = 0, LD_LOG_CRITICAL, LD_LOG_ERROR, LD_LOG_WARNING,
		LD_LOG_INFO, LD_LOG_DEBUG, LD_LOG_TRACE }
	*/
	int log_map[LD_LOG_TRACE+1] = {L_ALERT,L_CRIT,L_ERR,L_WARN,
		L_INFO, L_DBG, L_DBG};

	LM_GEN( log_map[level], "[LD] %s\n", text);
	return;
}



static int ld_client_init_attempt(void)
{
	/* maybe already connected? */
	if (ld_client)
		return 0;

	/* too soon to retry a new connect ?*/
	if (last_init_attempt_time!=0 &&
	(last_init_attempt_time + re_init_interval > get_ticks()) )
		return -2;

	LM_DBG("attempting LD client re-init\n");

	/* we do expect a valid ld config here */
	ld_client = LDClientInit( ld_cfg, connect_wait);
	if (!LDClientIsInitialized(ld_client)) {
		//LDClientClose(ld_client); this triggered a double free in LD lib :-/
		ld_client = NULL;
		last_init_attempt_time = get_ticks();
		return -1;
	}
	last_init_attempt_time = 0;

	return 0;
}


int ld_init_child(void)
{
	LDConfigureGlobalLogger( ld_log_level, _oss_logger);

	LDGlobalInit();

	LM_DBG("LD globally initialized, proceeding with the connect\n");

	ld_cfg = LDConfigNew( sdk_key );
	if (ld_cfg==NULL) {
		LM_ERR("failed to perform LD config\n");
		return -1;
	}

	if (ld_client_init_attempt()!=0)
		LM_ERR("LD client failed to initialize, proceeding offline\n");
	else
		LM_DBG("LD client initialized\n");

	return 0;
}


int ld_feature_enabled(str *feat, str *user, int user_extra_avp_id,
																int fallback)
{
	struct LDUser *ld_user;
	struct LDJSON *ld_extra, *ld_val;
	struct LDDetails ld_details;
	LDBoolean ld_res;
	struct usr_avp *avp;
	int_str val;
	str s_nt, extra_key, extra_val;
	char *p;

	if (ld_client==NULL && ld_client_init_attempt()<0) {
		LM_ERR("not having a connected LD client :(\n");
		goto error;
	}

	if (pkg_nt_str_dup( &s_nt, user)<0) {
		LM_ERR("failed to pkg_nt duplicate the user\n");
		goto error;
	}
	ld_user = LDUserNew( s_nt.s );
	pkg_free(s_nt.s);
	if (ld_user==NULL) {
		return -1;
		LM_ERR("failed to create new LD user\n");
		goto error;
	}

	/* do we have custom key-val pairs to add to the user? */
	if (user_extra_avp_id>=0) {
		avp = NULL;
		ld_extra = NULL;
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

			/* add the new extra to the user */
			if (ld_extra==NULL) {
				ld_extra = LDNewObject();
				if (ld_extra==NULL) {
					LM_ERR("failed to create new user object\n");
					goto error1;
				}
			}

			/* create the new value */
			if (pkg_nt_str_dup( &s_nt, &extra_val)<0) {
				LM_ERR("failed to pkg_nt duplicate the extra value\n");
				goto error1;
			}
			ld_val = LDNewText( s_nt.s );
			pkg_free(s_nt.s);
			if (ld_val==NULL) {
				LM_ERR("failed create new extra LD val\n");
				goto error1;
			}

			/* add the value as key */
			if (pkg_nt_str_dup( &s_nt, &extra_key)<0) {
				LM_ERR("failed to pkg_nt duplicate the extra key\n");
				goto error1;
			}
			if (!LDObjectSetKey( ld_extra, s_nt.s, ld_val)) {
				LM_ERR("failed to add new key+val to user extra\n");
				pkg_free(s_nt.s);
				goto error1;
			}
			pkg_free(s_nt.s);

		}

		if (ld_extra)
			LDUserSetCustom(ld_user, ld_extra);
	}

	/* now, run the check */
	if (pkg_nt_str_dup( &s_nt, feat)<0) {
		LM_ERR("failed to pkg_nt duplicate the feature name\n");
		goto error1;
	}
	ld_res = LDBoolVariation( ld_client, ld_user, s_nt.s,
		fallback?LDBooleanTrue:LDBooleanFalse, &ld_details);
	ld_res = ld_res ? 1 : -1;

	/* any error ? */
	if (ld_details.reason==LD_ERROR) {
		ld_res = 2 * ld_res; //return some internal error indication
		switch (ld_details.extra.errorKind) {
			case LD_CLIENT_NOT_READY:
				LM_BUG("LD client not initialized at this point!?!\n");
				break;
			case LD_NULL_KEY:
				LM_ERR("LD flag key is empty/NULL\n");
				break;
			case LD_STORE_ERROR:
				LM_ERR("LD internal exception with the flag store\n");
				break;
			case LD_FLAG_NOT_FOUND:
				LM_ERR("the caller provided a flag key that did not match any known flag\n");
				break;
			case LD_USER_NOT_SPECIFIED:
				LM_ERR("LD user is empty/NULL!\n");
				break;
			case LD_CLIENT_NOT_SPECIFIED:
				LM_BUG("LD client is NULL?!?!\n");
				break;
			case LD_MALFORMED_FLAG:
				LM_ERR("internal inconsistency in the flag data, a rule specified a nonexistent variation\n");
				break;
			case LD_WRONG_TYPE:
				LM_ERR("the result value was not of the requested type- expected LDBoolVariation\n");
				break;
			case LD_OOM:
				LM_ERR("LD clientran out of memory.\n");
				break;
			default:
				LM_ERR("unknown %d error reported by LDBoolVariation\n",ld_details.extra.errorKind);
				break;
		}
	}

	LM_DBG("feature flag %s is %s\n", s_nt.s, (ld_res>0)?"TRUE":"FALSE");
	pkg_free(s_nt.s);

	LDUserFree(ld_user);
	return ld_res;

error1:
	LDUserFree(ld_user);
error:
	return fallback?2:-2;
}
