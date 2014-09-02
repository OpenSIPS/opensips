/**
 *
 * qrouting module: qrouting.c
 *
 * Copyright (C) 2004-2005 FhG Fokus
 * Copyright (C) 2006-2010 Voice Sistem SRL
 * Copyright (C) 2014 OpenSIPS Foundation
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History
 * -------
 *  2014-08-28  initial version (Mihai Tiganus)
 */
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>

#include "../../sr_module.h"
#include "../../str.h"
#include "../../timer.h"

#include "qr_stats.h"
#include "qr_acc.h"

#define T_PROC_LABEL "[qrouting]:sampling interval"

static int history = 30; /* the history span in minutes */
static int sampling_interval = 5; /* the sampling interval in seconds */
extern qr_rule_t * qr_rules_start;

str avp_invite_time_name_pdd = str_init("$avp(qr_invite_time_pdd)");
str avp_invite_time_name_ast = str_init("$avp(qr_invite_time_ast)");



/* timer use for creating the statistics */
struct sr_timer_process t_proc;

static cmd_export_t cmds[] = {
	{"test_acc",  (cmd_function)test_acc,   0,  0, 0,
		REQUEST_ROUTE|FAILURE_ROUTE|LOCAL_ROUTE},
	{0, 0, 0, 0, 0, 0}
};
static param_export_t params[] = {
	{"history", INT_PARAM, &history},
	{"sampling_interval", INT_PARAM, &sampling_interval},
	{0, 0, 0}
};

static int qr_init(void);
static int qr_child_init(int rank);
static int qr_exit(void);

static void timer_func(void);


struct module_exports exports = {
	"qrouting",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS, /* dlopen flags */
	0,           /* OpenSIPS module dependencies */
	cmds,            /* Exported functions */
	params,          /* Exported parameters */
	0,               /* exported statistics */
	0,         /* exported MI functions */
	0,               /* exported pseudo-variables */
	0,               /* additional processes */
	qr_init,         /* Module initialization function */
	(response_function) 0,
	(destroy_function) qr_exit,
	(child_init_function) qr_child_init /* per-child init function */
};

static int qr_init(void){
	qr_rule_t *my_rule; /* FIXME: testing purpose */
	LM_INFO("QR module\n");
	LM_DBG("history = %d, sampling_interval = %d\n", history,
			sampling_interval);
	register_timer_process(T_PROC_LABEL, (void*)timer_func, NULL,
			sampling_interval, 0);
	qr_n = (history * 60)/sampling_interval; /* the number of sampling
												intervals in history */

	if(load_tm_api(&tmb) == -1) {
		LM_ERR("failed to load tm functions\n");
	}

	/* FIXME:testing purpose */
	my_rule = qr_create_rule(1);
	qr_add_rule(my_rule);
	qr_rules_start->dest[0].dst.gw = qr_create_gw();

	/* AVP for storing the time when the INVITE was recvd
	 * for computing PDD*/
	if(parse_avp_spec(&avp_invite_time_name_pdd, &avp_invite_time_pdd) < 0) {
		LM_ERR("failed to get avp id\n");
		return -1;
	}

	return 0;
}

static int qr_child_init(int rank) {
	return 0;
}

static int qr_exit(void) {
	return 0;
}

static void timer_func(void) {

}
