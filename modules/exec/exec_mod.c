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
#include "../../mod_fix.h"
#include "../../parser/parse_uri.h"
#include "../../ut.h"
#include <sys/wait.h>

#include "exec.h"
#include "kill.h"
#include "exec_hf.h"




unsigned int time_to_kill=0;

static int mod_init( void );

inline static int w_exec_dset(struct sip_msg* msg, char* cmd, char* foo);
inline static int w_exec_msg(struct sip_msg* msg, char* cmd, char* foo);
inline static int w_exec_avp(struct sip_msg* msg, char* cmd, char* avpl);
inline static int w_exec_getenv(struct sip_msg* msg, char* cmd, char* avpl);
inline static int w_exec(struct sip_msg* msg, char* cmd, char* in,
		char* out, char* err, char* avp_env);
inline static int w_async_exec(struct sip_msg* msg, async_ctx *ctx,
		char *cmd, char* out, char* in, char* err, char* avp_env );

static int exec_avp_fixup(void** param, int param_no);
static int exec_fixup(void** param, int param_no);

inline static void exec_shutdown(void);

/*
 * Exported functions
 */
static acmd_export_t acmds[] = {
	{"exec",  (acmd_function)w_async_exec,  5, exec_fixup },
	{"exec",  (acmd_function)w_async_exec,  4, exec_fixup },
	{"exec",  (acmd_function)w_async_exec,  3, exec_fixup },
	{"exec",  (acmd_function)w_async_exec,  2, exec_fixup },
	{"exec",  (acmd_function)w_async_exec,  1, exec_fixup },
	{0, 0, 0, 0}
};

static cmd_export_t cmds[] = {
	{"exec",         (cmd_function)w_exec,         5, exec_fixup, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE|STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE|ONREPLY_ROUTE},
	{"exec",         (cmd_function)w_exec,         4, exec_fixup, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE|STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE|ONREPLY_ROUTE},
	{"exec",         (cmd_function)w_exec,         3, exec_fixup, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE|STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE|ONREPLY_ROUTE},
	{"exec",         (cmd_function)w_exec,         2, exec_fixup, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE|STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE|ONREPLY_ROUTE},
	{"exec",         (cmd_function)w_exec,         1, exec_fixup, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE|STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE|ONREPLY_ROUTE},
	{"exec_dset",    (cmd_function)w_exec_dset,    1, exec_avp_fixup,  0,
		REQUEST_ROUTE|FAILURE_ROUTE},
	{"exec_msg",     (cmd_function)w_exec_msg,     1, exec_avp_fixup,  0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE|TIMER_ROUTE|EVENT_ROUTE|ONREPLY_ROUTE},
	{"exec_avp",     (cmd_function)w_exec_avp,     1, exec_avp_fixup,  0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE|STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE|ONREPLY_ROUTE},
	{"exec_avp",     (cmd_function)w_exec_avp,     2, exec_avp_fixup, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE|STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE|ONREPLY_ROUTE},
	{"exec_getenv",  (cmd_function)w_exec_getenv,  2, exec_avp_fixup, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE|STARTUP_ROUTE|TIMER_ROUTE|EVENT_ROUTE|ONREPLY_ROUTE},
	{0, 0, 0, 0, 0, 0}
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
	NULL,           /* OpenSIPS module dependencies */
	cmds,           /* Exported functions */
	acmds,          /* Exported async functions */
	params,         /* Exported parameters */
	0,              /* exported statistics */
	0,              /* exported MI functions */
	0,              /* exported pseudo-variables */
	0,              /* extra processes */
	mod_init,       /* initialization module */
	0,              /* response function */
	exec_shutdown,  /* destroy function */
	0               /* per-child init function */
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

inline static int w_exec_dset(struct sip_msg* msg, char* cmd, char* foo)
{
	str *uri;
	environment_t *backup;
	int ret;
	str command;

	if(msg==0 || cmd==0)
		return -1;

	backup=0;
	if (setvars) {
		backup=set_env(msg);
		if (!backup) {
			LM_ERR("no env created\n");
			return -1;
		}
	}

	if (msg->new_uri.s && msg->new_uri.len)
		uri=&msg->new_uri;
	else
		uri=&msg->first_line.u.request.uri;

	if(fixup_get_svalue(msg, (gparam_p)cmd, &command)!=0)
	{
		LM_ERR("invalid command parameter");
		return -1;
	}

	LM_DBG("executing [%s]\n", command.s);

	ret=exec_str(msg, command.s, uri->s, uri->len);
	if (setvars) {
		unset_env(backup);
	}
	return ret;
}


inline static int w_exec_msg(struct sip_msg* msg, char* cmd, char* foo)
{
	environment_t *backup;
	int ret;
	str command;

	if(msg==0 || cmd==0)
		return -1;

	backup=0;
	if (setvars) {
		backup=set_env(msg);
		if (!backup) {
			LM_ERR("no env created\n");
			return -1;
		}
	}

	if(fixup_get_svalue(msg, (gparam_p)cmd, &command)!=0)
	{
		LM_ERR("invalid command parameter");
		return -1;
	}

	LM_DBG("executing [%s]\n", command.s);

	ret=exec_msg(msg, command.s);
	if (setvars) {
		unset_env(backup);
	}
	return ret;
}

inline static int w_exec_avp(struct sip_msg* msg, char* cmd, char* avpl)
{
	environment_t *backup;
	int ret;
	str command;

	if(msg==0 || cmd==0)
		return -1;

	backup=0;
	if (setvars) {
		backup=set_env(msg);
		if (!backup) {
			LM_ERR("no env created\n");
			return -1;
		}
	}

	if(fixup_get_svalue(msg, (gparam_p)cmd, &command)!=0)
	{
		LM_ERR("invalid command parameter");
		return -1;
	}

	LM_DBG("executing [%s]\n", command.s);

	ret=exec_avp(msg, command.s, (pvname_list_p)avpl);
	if (setvars) {
		unset_env(backup);
	}
	return ret;
}

inline static int w_exec_getenv(struct sip_msg* msg, char* cmd, char* avpl)
{
	str command;

	if(msg==0 || cmd==0)
		return -1;

	if(fixup_get_svalue(msg, (gparam_p)cmd, &command)!=0)
	{
		LM_ERR("invalid command parameter");
		return -1;
	}

	LM_DBG("executing getenv [%s]\n", command.s);

	return exec_getenv(msg, command.s, (pvname_list_p)avpl);
}


static int exec_avp_fixup(void** param, int param_no)
{
	pvname_list_t *anlist = NULL;
	str s;

	s.s = (char*)(*param);
	if (param_no==1)
	{
		LM_WARN("You are using an obosolete function from the EXEC module!"
			"Please switch to the new exec() function\n");
		if(s.s==NULL)
		{
			LM_ERR("null format in P%d\n", param_no);
			return E_UNSPEC;
		}
		return fixup_spve_null(param, 1);
	} else if(param_no==2) {
		if(s.s==NULL)
		{
			LM_ERR("null format in P%d\n", param_no);
			return E_UNSPEC;
		}
		s.len =  strlen(s.s);
		anlist = parse_pvname_list(&s, PVT_AVP);
		if(anlist==NULL)
		{
			LM_ERR("bad format in P%d [%s]\n", param_no, s.s);
			return E_UNSPEC;
		}
		*param = (void*)anlist;
		return 0;
	}

	return 0;
}

static int exec_fixup(void** param, int param_no)
{
	gparam_p out_var;
	pv_elem_t* model;
	str s;

	if (*param)
	switch (param_no) {
		case 1: /* cmd */
			return fixup_spve(param);
		case 2: /* input vars */
			s.s = *param;
			s.len = strlen(s.s);
			if (pv_parse_format(&s, &model)) {
				LM_ERR("wrong format [%s] for param no %d!\n",
						(char*)*param, param_no);
				pkg_free(s.s);
				return E_UNSPEC;
			}
			*param = (void *)model;

			return 0;
		case 3: /* output var */
		case 4: /* error  var */
			if (fixup_spve(param)) {
				LM_ERR("cannot fix output var\n");
				return -1;
			}

			out_var = *param;
			if (out_var->type != GPARAM_TYPE_PVS) {
				LM_ERR("output var must be A varible\n");
				return -1;
			}

			if (out_var->v.pvs->setf == NULL) {
				LM_ERR("output var must be writable\n");
				return -1;
			}

			return 0;
		case 5: /* environment avp */
			if (fixup_spve(param)) {
				LM_ERR("cannot fix output var\n");
				return -1;
			}
			out_var = *param;
			if (out_var->type != GPARAM_TYPE_PVE) {
				LM_ERR("env var must be a single variable\n");
				return -1;
			}

			if (out_var->v.pve->spec.type != PVT_AVP) {
				LM_ERR("env var must be avp typed\n");
				return -1;
			}

			return 0;
		default:
			LM_ERR("Invalid parameter number %d\n", param_no);
			return -1;
	}
	return 0;
}


static inline int setenvvar(struct hf_wrapper** hf, int_str* value, int idx)
{
	#define OSIPS_EXEC "OSIPS_EXEC_"


	int len=0;
	str sidx;

	sidx.s = int2str((unsigned long)idx, &sidx.len);

	(*hf)->envvar=pkg_malloc(strlen(OSIPS_EXEC) + sidx.len + 1/*=*/
					+ (*value).s.len + 1/*\0*/);
	if ((*hf)->envvar==0) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}

	memcpy((*hf)->envvar, OSIPS_EXEC, strlen(OSIPS_EXEC));
	len=strlen(OSIPS_EXEC);

	memcpy((*hf)->envvar+len, sidx.s, sidx.len);
	len+=sidx.len;

	(*hf)->envvar[len++] = '=';

	memcpy((*hf)->envvar+len, value->s.s, value->s.len);

	(*hf)->envvar[len+ value->s.len] = '\0';

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

	setenvvar(&hf, &value, idx++);
	hf_head=hf;

	while (search_next_avp( avp_ptr, &value) != 0) {
		hf->next_other=pkg_malloc(sizeof(struct hf_wrapper));
		if (!hf)
			goto memerr;

		hf=hf->next_other;

		setenvvar(&hf, &value, idx++);

		avp_ptr = avp_ptr->next;
		if (avp_ptr->id > avp_name)
			break;
	}

	return hf_head;
memerr:
	LM_ERR("no more pkg mem\n");
	return 0;
}


inline static int w_exec(struct sip_msg* msg, char* cmd, char* in,
		char* out, char* err ,char* avp_env)
{
	str command;
	str input = {NULL, 0};
	int ret;
	struct hf_wrapper *hf=0;
	environment_t* backup_env=0;
	gparam_p outvar = (gparam_p)out;
	gparam_p errvar = (gparam_p)err;

	if (msg == 0 || cmd == 0)
		return -1;

	/* fetch command */
	if(fixup_get_svalue(msg, (gparam_p)cmd, &command)!=0) {
		LM_ERR("invalid command parameter");
		return -1;
	}

	/* fetch input */
	if (in != NULL) {
		if (pv_printf_s(msg, (pv_elem_p)in, &input)!=0)
			return -1;
	}

	if (avp_env != NULL) {
		if ((hf=get_avp_values_list(msg, &((gparam_p)avp_env)->v.pve->spec.pvp)) == 0)
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

	ret = exec_sync(msg, &command, &input, outvar, errvar);

	if (backup_env)
		unset_env(backup_env);

	return ret;
}


inline static int w_async_exec(struct sip_msg* msg, async_ctx *ctx,
					char* cmd, char* in, char* out, char* err, char* avp_env)
{
	str command;
	str input = {NULL, 0};
	struct hf_wrapper *hf=0;
	environment_t* backup_env=0;
	gparam_p outvar = (gparam_p)out;
	exec_async_param *param;
	int ret, fd;

	if (msg == 0 || cmd == 0)
		return -1;

	/* fetch command */
	if(fixup_get_svalue(msg, (gparam_p)cmd, &command)!=0) {
		LM_ERR("invalid command parameter\n");
		return -1;
	}

	/* fetch input */
	if (in != NULL) {
		if (pv_printf_s(msg, (pv_elem_p)in, &input)!=0)
			return -1;
	}

	if (avp_env != NULL) {
		if ((hf=get_avp_values_list(msg, &((gparam_p)avp_env)->v.pve->spec.pvp)) == 0)
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

	ret = start_async_exec(msg, &command, in?&input:NULL, outvar, &fd);

	if (backup_env)
		unset_env(backup_env);

	/* populate resume point (if async started) */
	if (ret==1) {
		param->outvar = outvar;
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

