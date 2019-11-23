/*
 * sl module
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
 * --------
 *  2003-03-11  updated to the new module exports interface (andrei)
 *  2003-03-16  flags export parameter added (janakj)
 *  2003-03-19  all mallocs/frees replaced w/ pkg_malloc/pkg_free
 *  2005-03-01  force for stateless replies the incoming interface of
 *              the request (bogdan)
 *  2006-03-29  callbacks for sending replies added (bogdan)
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../ut.h"
#include "../../script_cb.h"
#include "../../mem/mem.h"
#include "../../pvar.h"
#include "sl_funcs.h"
#include "sl_api.h"




static int w_sl_send_reply(struct sip_msg* msg, int* code_i, str* code_s);
static int w_sl_reply_error(struct sip_msg* msg);
static int fixup_sl_send_reply(void** param);
static int mod_init(void);
static void mod_destroy(void);
/* module parameter */
int sl_enable_stats = 1;

/* statistic variables */
stat_var *tx_1xx_rpls;
stat_var *tx_2xx_rpls;
stat_var *tx_3xx_rpls;
stat_var *tx_4xx_rpls;
stat_var *tx_5xx_rpls;
stat_var *tx_6xx_rpls;
stat_var *sent_rpls;
stat_var *sent_err_rpls;
stat_var *rcv_acks;

static cmd_export_t cmds[]={
	{"sl_send_reply",(cmd_function)w_sl_send_reply, {	
		{CMD_PARAM_INT,fixup_sl_send_reply,0},
		{CMD_PARAM_STR,0,0}, {0,0,0}},
		REQUEST_ROUTE | ERROR_ROUTE},
	{"sl_reply_error",(cmd_function)w_sl_reply_error, {	
		{0,0,0}},
		REQUEST_ROUTE},
	{"load_sl", (cmd_function)load_sl, {{0,0,0}},0},
	{0,0,{{0,0,0}},0}
};

static param_export_t mod_params[]={
	{ "enable_stats",  INT_PARAM, &sl_enable_stats },
	{ 0,0,0 }
};


static stat_export_t mod_stats[] = {
	{"1xx_replies" ,       0,  &tx_1xx_rpls    },
	{"2xx_replies" ,       0,  &tx_2xx_rpls    },
	{"3xx_replies" ,       0,  &tx_3xx_rpls    },
	{"4xx_replies" ,       0,  &tx_4xx_rpls    },
	{"5xx_replies" ,       0,  &tx_5xx_rpls    },
	{"6xx_replies" ,       0,  &tx_6xx_rpls    },
	{"sent_replies" ,      0,  &sent_rpls      },
	{"sent_err_replies" ,  0,  &sent_err_rpls  },
	{"received_ACKs" ,     0,  &rcv_acks       },
	{0,0,0}
};




#ifdef STATIC_SL
struct module_exports sl_exports = {
#else
struct module_exports exports= {
#endif
	"sl",         /* module's name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	NULL,            /* OpenSIPS module dependencies */
	cmds,         /* exported functions */
	NULL,         /* exported async functions */
	mod_params,   /* param exports */
	mod_stats,    /* exported statistics */
	0,            /* exported MI functions */
	0,            /* exported pseudo-variables */
	0,			  /* exported transformations */
	0,            /* extra processes */
	0,            /* module pre-initialization function */
	mod_init,     /* module initialization function */
	0,            /* reply processing function */
	mod_destroy,
	0,            /* per-child init function */
	0             /* reload confirm function */
};




static int mod_init(void)
{
	LM_INFO("Initializing StateLess engine\n");

	/* if statistics are disabled, prevent their registration to core */
	if (sl_enable_stats==0)
#ifdef STATIC_SL
		sl_exports.stats = 0;
#else
		exports.stats = 0;
#endif

	/* filter all ACKs before script */
	if (register_script_cb(sl_filter_ACK, PRE_SCRIPT_CB|REQ_TYPE_CB, 0 )!=0) {
		LM_ERR("register_script_cb failed\n");
		return -1;
	}

	/* init internal SL stuff */
	if (sl_startup()!=0) {
		LM_ERR("sl_startup failed\n");
		return -1;
	}

	return 0;
}




static void mod_destroy(void)
{
	sl_shutdown();
}


static int fixup_sl_send_reply(void** param)
{
	if (*(int*)*param < 100 || *(int*)*param > 699) {
		LM_ERR("wrong code: %d, allowed values: 1xx - 6xx only!\n",
			*(int*)*param);
		return E_UNSPEC;
	}

	return 0;
}



static int w_sl_reply_error( struct sip_msg* msg)
{
	return sl_reply_error( msg );
}


static int w_sl_send_reply(struct sip_msg* msg, int* code_i, str* code_s)
{
	return sl_send_reply(msg, *code_i, code_s, NULL);
}


int load_sl( struct sl_binds *slb)
{
	if(slb==NULL)
		return -1;

	slb->reply      = sl_send_reply;
	slb->gen_totag  = sl_gen_totag;

	return 1;
}
