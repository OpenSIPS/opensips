/*
 * SIP Session Timer (sst) module - support for tracking dialogs and
 * SIP Session Timers.
 *
 * Copyright (C) 2006 SOMA Networks, INC.
 * Written by: Ron Winacott (karwin)
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
 *
 * History:
 * --------
 * 2006-05-11 initial version (karwin)
 * 2006-10-10 RFC compilent changes. Added the other flags (karwin)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../../sr_module.h"
#include "../signaling/signaling.h"
#include "sst_handlers.h" /* also includes sr_module.h needed by
                             handlers */



static int mod_init(void);


/** SIGNALING binds */
struct sig_binds sigb;

/*
 * statistic variables
 */
int sst_enable_stats = 1;
stat_var *expired_sst = 0;

/*
 * The default or script parameter for the requested MIN-SE: value for
 * this proxy. (in seconds) If the passed in value is 0, then this
 * proxy will except any value from the UAC as its min-SE value. If
 * the value is NOT set then the default will be asserted.
 */
unsigned int sst_minSE = 90;

/*
 * Should the PROXY (us) reject (with a 422 reply) and SE < sst_minSE
 * requests is it can. Default is YES.
 */
unsigned int sst_reject = 1;

/* The sst message flag value */
static int sst_flag = -1;
static char *sst_flag_str = 0;

/*
 * The sst minimum interval in Session-Expires header if OpenSIPS
 * request the use of session times. The used value will be the
 * maximum value between OpenSIPS minSE, UAS minSE and this value
*/
unsigned int sst_interval = 0;

/*
 * Binding to the dialog module
 */
struct dlg_binds dialog_st;
struct dlg_binds *dlg_binds = &dialog_st;

/*
 * Script commands we export.
 */
static cmd_export_t cmds[]={
	{"sstCheckMin", (cmd_function)sst_check_min, {
		{CMD_PARAM_INT|CMD_PARAM_OPT,0,0}, {0,0,0}},
		REQUEST_ROUTE | ONREPLY_ROUTE},
	{0,0,{{0,0,0}},0}
};

/*
 * Script parameters
 */
static param_export_t mod_params[]={
	{ "enable_stats", INT_PARAM, &sst_enable_stats			},
	{ "min_se", INT_PARAM, &sst_minSE						},
	{ "reject_to_small",		INT_PARAM, &sst_reject 		},
	{ "sst_flag",				STR_PARAM, &sst_flag_str	},
	{ "sst_interval",		INT_PARAM, &sst_interval		},
	{ 0,0,0 }
};

/*
 * Export the statistics we have
 */
static stat_export_t mod_stats[] = {
	{"expired_sst", 0,  &expired_sst},
	{0,0,0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "signaling", DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "dialog",    DEP_ABORT },
		/*
		 * FIXME: silent module load ordering, due to Session-Expires updates from sst
		 *        proper fix should involve dialog callback ordering
		 */
		{ MOD_TYPE_DEFAULT, "pua_dialoginfo", DEP_SILENT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

struct module_exports exports= {
	"sst",        /* module's name */
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,				 /* load function */
	&deps,           /* OpenSIPS module dependencies */
	cmds,         /* exported functions */
	0,            /* exported async functions */
	mod_params,   /* param exports */
	mod_stats,    /* exported statistics */
	0,            /* exported MI functions */
	0,            /* exported pseudo-variables */
	0,			  /* exported transformations */
	0,            /* extra processes */
	0,            /* module pre-initialization function */
	mod_init,     /* module initialization function */
	0,            /* reply processing function */
	0,            /* Destroy function */
	0,            /* per-child init function */
	0             /* reload confirm function */
};

/**
 * The initialization function, called when the module is loaded by
 * the script. This function is called only once.
 *
 * Bind to the dialog module and setup the callbacks. Also initialize
 * the shared memory to store our interninal information in.
 *
 * @return 0 to continue to load the OpenSIPS, -1 to stop the loading
 * and abort OpenSIPS.
 */
static int mod_init(void)
{
	LM_INFO("SIP Session Timer module - initializing\n");
	/*
	 * if statistics are disabled, prevent their registration to core.
	 */
	if (sst_enable_stats==0) {
		exports.stats = 0;
	}

	sst_flag = get_flag_id_by_name(FLAG_TYPE_MSG, sst_flag_str, 0);

	if (sst_flag == -1) {
		LM_ERR("no sst flag set!!\n");
		return -1;
	}
	else if (sst_flag > MAX_FLAG) {
		LM_ERR("invalid sst flag %d!!\n", sst_flag);
		return -1;
	}

	/* load SIGNALING API */
	if(load_sig_api(&sigb)< 0) {
		LM_ERR("can't load signaling functions\n");
		return -1;
	}

	/*
	 * Init the handlers
	 */
	sst_handler_init(sst_minSE, sst_flag, sst_reject,sst_interval);

	/*
	 * Register the main (static) dialog call back.
	 */
	if (load_dlg_api(&dialog_st) != 0) {
		LM_ERR("failed to load dialog hooks\n");
		return(-1);
	}

	/* Load dialog hooks */
	dialog_st.register_dlgcb(NULL, DLGCB_CREATED, sst_dialog_created_CB, NULL, NULL);

	if (dialog_st.register_dlgcb(NULL, DLGCB_LOADED, sst_dialog_loaded_CB,
				NULL, NULL) != 0) {
		LM_ERR("cannot register dialog_loaded callback\n");
		return -1;
	}

	/*
	 * We are GOOD-TO-GO.
	 */
	return 0;
}
