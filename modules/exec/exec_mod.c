/*
 * execution module
 *
 * Copyright (C) 2001-2003 FhG Fokus
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
 * -------
 * 2003-03-11: New module interface (janakj)
 * 2003-03-16: flags export parameter added (janakj)
 */


#include <stdio.h>
#include <stdlib.h>

#include "../../sr_module.h"
#include "../../parser/msg_parser.h"
#include "../../str.h"
#include "../../dprint.h"
#include "../../parser/parse_uri.h"
#include "../../ut.h"
#include <sys/wait.h>

#include "exec.h"
#include "kill.h"
#include "exec_hf.h"




unsigned int time_to_kill=0;

static int mod_init( void );

inline static int w_exec(struct sip_msg* msg, str* cmd, str* in,
		pv_spec_t* out, pv_spec_t* err, pv_spec_t* avp_env);
inline static int w_async_exec(struct sip_msg* msg, async_ctx *ctx,
		str* cmd, str* in, pv_spec_t* out, pv_spec_t* err, pv_spec_t* avp_env);

static int fixup_check_avp(void** param);
static int fixup_check_var_setf(void** param);

inline static void exec_shutdown(void);

/*
 * Exported functions
 */

static acmd_export_t acmds[] = {
	{"exec", (acmd_function)w_async_exec, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT, fixup_check_var_setf, 0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT, fixup_check_var_setf, 0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT, fixup_check_avp, 0}, {0,0,0}}},
	{0,0,{{0,0,0}}}
};

static cmd_export_t cmds[] = {
	{"exec", (cmd_function)w_exec, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR|CMD_PARAM_OPT,0,0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT, fixup_check_var_setf, 0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT, fixup_check_var_setf, 0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT, fixup_check_avp, 0}, {0,0,0}},
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE|STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE|ONREPLY_ROUTE},
	{0,0,{{0,0,0}},0}
};

/*
 * Exported parameters
 */
static param_export_t params[] = {
	{"time_to_kill", INT_PARAM, &time_to_kill},
	{"setvars",      INT_PARAM, &setvars     },
	{0, 0, 0}
};


#ifdef STATIC_EXEC
struct module_exports exec_exports = {
#else
struct module_exports exports= {
#endif
	"exec",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,/* dlopen flags */
	0,				/* load function */
	NULL,           /* OpenSIPS module dependencies */
	cmds,           /* Exported functions */
	acmds,          /* Exported async functions */
	params,         /* Exported parameters */
	0,              /* exported statistics */
	0,              /* exported MI functions */
	0,              /* exported pseudo-variables */
	0,			 	/* exported transformations */
	0,              /* extra processes */
	0,              /* pre-initialization module */
	mod_init,       /* initialization module */
	0,              /* response function */
	exec_shutdown,  /* destroy function */
	0,              /* per-child init function */
	0               /* reload confirm function */
};

void exec_shutdown(void)
{

	if (time_to_kill) destroy_kill();

}


static int mod_init( void )
{
	LM_INFO("exec - initializing\n");
	if (time_to_kill)
		initialize_kill();

	return 0;
}


static int fixup_check_var_setf(void** param)
{
	if (((pv_spec_t*)*param)->setf == NULL) {
		LM_ERR("output var must be writable\n");
		return -1;
	}
	return 0;
}

static int fixup_check_avp(void** param)
{
	if (((pv_spec_t*)*param)->type != PVT_AVP) {
		LM_ERR("environment var must be an AVP\n");
		return -1;
	}
	return 0;
}

static inline int setenvvar(struct hf_wrapper** hf, int_str* value, int isstr, int idx)
{
	#define OSIPS_EXEC "OSIPS_EXEC_"


	int len=0;
	str sidx;

	sidx.s = int2str((unsigned long)idx, &sidx.len);

	(*hf)->envvar=pkg_malloc(strlen(OSIPS_EXEC) + sidx.len + 1/*=*/
					+ (isstr?(*value).s.len:INT2STR_MAX_LEN) + 1/*\0*/);
	if ((*hf)->envvar==0) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}

	memcpy((*hf)->envvar, OSIPS_EXEC, strlen(OSIPS_EXEC));
	len=strlen(OSIPS_EXEC);

	memcpy((*hf)->envvar+len, sidx.s, sidx.len);
	len+=sidx.len;

	(*hf)->envvar[len++] = '=';

	if (isstr) {
		memcpy((*hf)->envvar+len, value->s.s, value->s.len);
		(*hf)->envvar[len+ value->s.len] = '\0';
	} else {
		sidx.s = int2str((unsigned long)value->n, &sidx.len);
		memcpy((*hf)->envvar+len, sidx.s, sidx.len);
		(*hf)->envvar[len+ sidx.len] = '\0';
	}

	(*hf)->next_other=(*hf)->next_same=NULL;

	return 0;

	#undef OSIPS_EXEC

}

static struct hf_wrapper* get_avp_values_list(struct sip_msg* msg, pv_param_p avp)
{

	int avp_name, idx=0;
	unsigned short name_type;
	int_str value;
	struct usr_avp* avp_ptr=0;
	struct hf_wrapper *hf=0, *hf_head;

	if (pv_get_avp_name(msg, avp, &avp_name, &name_type) < 0) {
		LM_ERR("cannot get avp name\n");
		return 0;
	}

	if ((avp_ptr=search_first_avp( name_type, avp_name, &value, 0)) == 0) {
		LM_ERR("cannot get first avp value\n");
		return 0;
	}

	hf=pkg_malloc(sizeof(struct hf_wrapper));
	if (!hf)
		goto memerr;

	setenvvar(&hf, &value, (avp_ptr->flags & AVP_VAL_STR), idx++);
	hf_head=hf;

	while ((avp_ptr = search_next_avp( avp_ptr, &value)) != 0) {
		hf->next_other=pkg_malloc(sizeof(struct hf_wrapper));
		hf=hf->next_other;

		if (!hf)
			goto memerr;

		setenvvar(&hf, &value, (avp_ptr->flags & AVP_VAL_STR), idx++);
	}

	return hf_head;
memerr:
	LM_ERR("no more pkg mem\n");
	return 0;
}


inline static int w_exec(struct sip_msg* msg, str* cmd, str* in,
		pv_spec_t* out, pv_spec_t* err, pv_spec_t* avp_env)
{
	int ret;
	struct hf_wrapper *hf=0;
	environment_t* backup_env=0;

	if (msg == 0 || cmd == 0)
		return -1;

	if (avp_env != NULL) {
		if ((hf=get_avp_values_list(msg, &(avp_env->pvp))) == 0)
			return -1;
		backup_env=replace_env(hf);
		if (!backup_env) {
			LM_ERR("replace env failed\n");
			release_vars(hf);
			release_hf_struct(hf);
			return -1;
		}
		release_hf_struct(hf);
	}

	ret = exec_sync(msg, cmd, in, out, err);

	if (backup_env)
		unset_env(backup_env);

	return ret;
}


inline static int w_async_exec(struct sip_msg* msg, async_ctx *ctx,
		str* cmd, str* in, pv_spec_t* out, pv_spec_t* err, pv_spec_t* avp_env)
{
	struct hf_wrapper *hf=0;
	environment_t* backup_env=0;
	exec_async_param *param;
	int ret, fd;

	if (msg == 0 || cmd == 0)
		return -1;

	if (avp_env != NULL) {
		if ((hf=get_avp_values_list(msg, &(avp_env->pvp))) == 0)
			return -1;
		backup_env=replace_env(hf);
		if (!backup_env) {
			LM_ERR("replace env failed\n");
			release_vars(hf);
			release_hf_struct(hf);
			return -1;
		}
		release_hf_struct(hf);
	}

	/* better do this alloc now (before starting the async) to avoid
	 * the unplesant situation of having the async started and have a
	 * memory failure -> tricky to recover */
	param = (exec_async_param*)shm_malloc(sizeof(exec_async_param));
	if(param==NULL) {
		LM_ERR("failed to allocate new async param\n");
		if (backup_env) unset_env(backup_env);
		return -1;
	}

	ret = start_async_exec(msg, cmd, in, out, &fd);

	if (backup_env)
		unset_env(backup_env);

	/* populate resume point (if async started) */
	if (ret==1) {
		param->outvar = out;
		/* that ^^^^ is save as "out" is a in private mem, but in all
		 * processes (set before forking) */
		param->buf = NULL;
		ctx->resume_param = (void*)param;
		ctx->resume_f = resume_async_exec;
		async_status = fd;
	} else if (ret==2) {
		/* no IO done, but success */
		shm_free(param);
		ctx->resume_param = NULL;
		ctx->resume_f = NULL;
		async_status = ASYNC_NO_IO;
	} else {
		/* error */
		shm_free(param);
		ctx->resume_param = NULL;
		ctx->resume_f = NULL;
		async_status = ASYNC_NO_IO;
	}

	return ret;
}

