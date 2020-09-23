/*
 * Copyright (C) 2004 FhG
 * Copyright (C) 2005-2006 Voice Sistem S.R.L.
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
 *  2004-09-09  initial module created (jiri)
 *  2006-05-31  flag range checked ; proper cleanup at module destroy ;
 *              got rid of memory allocation in fixup function ;
 *              optimized fixup function -> compute directly the bitmap ;
 *              allowed functions from BRANCH_ROUTE (bogdan)
 *
 * TODO:
 * -----
 * - named flags (takes a protected name list)
 *
 *
 * gflags module: global flags; it keeps a bitmap of flags
 * in shared memory and may be used to change behaviour
 * of server based on value of the flags. E.g.,
 *    if (is_gflag("1")) { t_relay_to_udp("10.0.0.1","5060"); }
 *    else { t_relay_to_udp("10.0.0.2","5060"); }
 * The benefit of this module is the value of the switch flags
 * can be manipulated by external applications such as web interface
 * or command line tools.
 *
 *
 */


/* flag buffer size for FIFO protocool */
#define MAX_FLAG_LEN 12
/* FIFO action protocol names */
#define FIFO_SET_GFLAG "set_gflag"
#define FIFO_IS_GFLAG "is_gflag"
#define FIFO_RESET_GFLAG "reset_gflag"
#define FIFO_GET_GFLAGS "get_gflags"

#include <stdio.h>
#include "../../sr_module.h"
#include "../../ut.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../mi/mi.h"



static int set_gflag(struct sip_msg*, void *);
static int reset_gflag(struct sip_msg*, void *);
static int is_gflag(struct sip_msg*, void *);

mi_response_t *mi_set_gflag(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_reset_gflag(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_is_gflag(const mi_params_t *params,
								struct mi_handler *async_hdl);
mi_response_t *mi_get_gflags(const mi_params_t *params,
								struct mi_handler *async_hdl);

static int fixup_gflags(void** param);

static int  mod_init(void);
static void mod_destroy(void);

static int initial=0;
static unsigned int *gflags=0;

static cmd_export_t cmds[]={
	{"set_gflag",    (cmd_function)set_gflag, {
		{CMD_PARAM_INT, fixup_gflags, 0}, {0,0,0}}, ALL_ROUTES},
	{"reset_gflag",  (cmd_function)reset_gflag, {
		{CMD_PARAM_INT, fixup_gflags, 0}, {0,0,0}}, ALL_ROUTES},
	{"is_gflag",     (cmd_function)is_gflag, {
		{CMD_PARAM_INT, fixup_gflags, 0}, {0,0,0}}, ALL_ROUTES},
	{0,0,{{0,0,0}},0}
};

static param_export_t params[]={
	{"initial", INT_PARAM, &initial},
	{0,0,0}
};

static mi_export_t mi_cmds[] = {
	{ FIFO_SET_GFLAG, 0, 0, 0, {
		{mi_set_gflag, {"bitmask", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ FIFO_RESET_GFLAG, 0, 0, 0, {
		{mi_reset_gflag, {"bitmask", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ FIFO_IS_GFLAG, 0, 0, 0, {
		{mi_is_gflag, {"bitmask", 0}},
		{EMPTY_MI_RECIPE}}
	},
	{ FIFO_GET_GFLAGS, 0, 0, 0, {
		{mi_get_gflags, {0}},
		{EMPTY_MI_RECIPE}}
	},
	{EMPTY_MI_EXPORT}
};

struct module_exports exports = {
	"gflags",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	NULL,            /* OpenSIPS module dependencies */
	cmds,        /* exported functions */
	0,           /* exported async functions */
	params,      /* exported parameters */
	0,           /* exported statistics */
	mi_cmds,     /* exported MI functions */
	0,           /* exported pseudo-variables */
	0,			 /* exported transformations */
	0,           /* extra processes */
	0,           /* module pre-initialization function */
	mod_init,    /* module initialization function */
	0,           /* response function*/
	mod_destroy, /* destroy function */
	0,           /* per-child init function */
	0            /* reload confirm function */
};


/**************************** fixup functions ******************************/
/**
 * convert char* to int and do bitwise right-shift
 * char* must be pkg_alloced and will be freed by the function
 */
static int fixup_gflags(void** param)
{
	unsigned int myint;

	myint = *(int*)*param;

	if ( myint >= 8*sizeof(*gflags) ) {
		LM_ERR("flag <%d> out of "
			"range [0..%zu]\n", myint, 8*sizeof(*gflags)-1);
		return E_CFG;
	}
	/* convert from flag index to flag bitmap */
	myint = 1 << myint;
	/* success -- change to int */
	*param=(void *)(long)myint;
	return 0;
}



/**************************** module functions ******************************/

static int set_gflag(struct sip_msg *bar, void *flag)
{
	(*gflags) |= (unsigned int)(long)flag;
	return 1;
}


static int reset_gflag(struct sip_msg *bar, void *flag)
{
	(*gflags) &= ~ ((unsigned int)(long)flag);
	return 1;
}


static int is_gflag(struct sip_msg *bar, void *flag)
{
	return ( (*gflags) & ((unsigned int)(long)flag)) ? 1 : -1;
}


/************************* MI functions *******************************/

mi_response_t *mi_set_gflag(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	unsigned int flag;
	str bitmask;

	if (get_mi_string_param(params, "bitmask", &bitmask.s, &bitmask.len) < 0)
		return init_mi_param_error();

	flag = 0;
	if( strno2int( &bitmask, &flag) <0)
		goto error;
	if (!flag) {
		LM_ERR("incorrect flag\n");
		goto error;
	}

	(*gflags) |= flag;

	return init_mi_result_ok();

error:
	return init_mi_error(400, MI_SSTR("Bad parameter value"));
}


mi_response_t *mi_reset_gflag(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	unsigned int flag;
	str bitmask;

	if (get_mi_string_param(params, "bitmask", &bitmask.s, &bitmask.len) < 0)
		return init_mi_param_error();

	flag = 0;
	if( strno2int( &bitmask, &flag) <0)
		goto error;
	if (!flag) {
		LM_ERR("incorrect flag\n");
		goto error;
	}

	(*gflags) &= ~ flag;

	return init_mi_result_ok();

error:
	return init_mi_error(400, MI_SSTR("Bad parameter value"));
}


mi_response_t *mi_is_gflag(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	unsigned int flag;
	str bitmask;

	if (get_mi_string_param(params, "bitmask", &bitmask.s, &bitmask.len) < 0)
		return init_mi_param_error();

	flag = 0;
	if( strno2int( &bitmask, &flag) <0)
		goto error_param;
	if (!flag) {
		LM_ERR("incorrect flag\n");
		goto error_param;
	}

	if( ((*gflags) & flag)== flag )
		return init_mi_result_bool(1);
	else
		return init_mi_result_bool(0);

error_param:
	return init_mi_error(400, MI_SSTR("Bad parameter value"));
}


mi_response_t *mi_get_gflags(const mi_params_t *params,
								struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;	

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;

	if (add_mi_string_fmt(resp_obj, MI_SSTR("hex"), "0x%X", (*gflags)) < 0)
		goto error;
	if (add_mi_string_fmt(resp_obj, MI_SSTR("dec"), "%u", (*gflags)) < 0)
		goto error;

	return resp;

error:
	free_mi_response(resp);
	return 0;
}



static int mod_init(void)
{
	gflags=(unsigned int *) shm_malloc(sizeof(unsigned int));
	if (!gflags) {
		LM_ERR(" no shmem\n");
		return -1;
	}
	*gflags=initial;
	return 0;
}


static void mod_destroy(void)
{
	if (gflags)
		shm_free(gflags);
}
