/*
 * presence_callinfo module - Presence Handling of call-info events
 *
 * Copyright (C) 2010 Ovidiu Sas
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
 * History:
 * --------
 *  2010-03-11  initial version (osas)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../str.h"
#include "../../parser/msg_parser.h"
#include "../../mem/mem.h"
#include "../presence/bind_presence.h"
#include "add_events.h"
#include "presence_callinfo.h"


int call_info_timeout_notification = 1;
int line_seize_timeout_notification = 0;

/* module functions */
static int mod_init(void);
static int child_init(int);
static void destroy(void);

/* module variables */
add_event_t pres_add_event;

/* module exported commands */
static cmd_export_t cmds[] =
{
    {0,	0, 0, 0, 0, 0}
};

/* module exported paramaters */
static param_export_t params[] = {
    {"call_info_timeout_notification",  INT_PARAM, &call_info_timeout_notification},
    {"line_seize_timeout_notification", INT_PARAM, &line_seize_timeout_notification},
    {0, 0, 0}
};

/* module exports */
struct module_exports exports= {
    "presence_callinfo",	/* module name */
    MODULE_VERSION,		/* module version */
    DEFAULT_DLFLAGS,		/* dlopen flags */
    cmds,			/* exported functions */
    params,			/* exported parameters */
    0,				/* exported statistics */
    0,				/* exported MI functions */
    0,				/* exported pseudo-variables */
    0,				/* extra processes */
    mod_init,			/* module initialization function */
    (response_function) 0,	/* response handling function */
    destroy,			/* destroy function */
    child_init			/* per-child init function */
};
	
/*
 * init module function
 */
static int mod_init(void)
{
	presence_api_t pres;
    LM_INFO("initializing...\n");

    bind_presence_t bind_presence;

    bind_presence= (bind_presence_t)find_export("bind_presence", 1,0);
    if (!bind_presence) {
	LM_ERR("can't bind presence\n");
	return -1;
    }
    if (bind_presence(&pres) < 0) {
	LM_ERR("can't bind pua\n");
	return -1;
    }

    pres_add_event = pres.add_event;
    if (pres_add_event == NULL) {
	LM_ERR("could not import add_event\n");
	return -1;
    }
    if(callinfo_add_events() < 0) {
	LM_ERR("failed to add call-info events\n");
	return -1;		
    }	
    
    return 0;
}

static int child_init(int rank)
{
	LM_DBG("[%d] pid [%d]\n", rank, getpid());

	return 0;
}	

static void destroy(void)
{	
    LM_DBG("destroying module ...\n");

    return;
}
