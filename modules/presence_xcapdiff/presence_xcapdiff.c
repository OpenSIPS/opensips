/*
 * Copyright (C) 2008 AG Projects
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
 */

#include "../../sr_module.h"
#include "../presence/bind_presence.h"
#include "../pua/pua_bind.h"



str s_event_name = str_init("xcap-diff");
str s_content_type = str_init("application/xcap-diff+xml");

static int mod_init(void);

static param_export_t params[] = {
    {0, 0, 0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "presence", DEP_SILENT },
		{ MOD_TYPE_DEFAULT, "pua",      DEP_SILENT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

struct module_exports exports= {
    "presence_xcapdiff",        /* module name */
    MOD_TYPE_DEFAULT,           /* class of this module */
    MODULE_VERSION,             /* module version */
    DEFAULT_DLFLAGS,            /* dlopen flags */
    0,				            /* load function */
    &deps,                      /* OpenSIPS module dependencies */
    0,                          /* exported functions */
    0,                          /* exported async functions */
    params,                     /* exported parameters */
    0,                          /* exported statistics */
    0,                          /* exported MI functions */
    0,                          /* exported pseudo-variables */
    0,                          /* exported transformations */
    0,                          /* extra processes */
    0,                          /* module pre-initialization function */
    mod_init,                   /* module initialization function */
    (response_function) 0,      /* response handling function */
    0,                          /* destroy function */
    0,                          /* per-child init function */
    0                           /* reload confirm function */
};

static int
mod_init(void)
{
    bind_presence_t bind_presence;
    presence_api_t pres;
    bind_pua_t bind_pua;
    pres_ev_t event;
    pua_api_t pua;

    LM_INFO("initializing...\n");

    bind_presence = (bind_presence_t)find_export("bind_presence", 0);
    if (bind_presence) {
        if (bind_presence(&pres) < 0) {
            LM_ERR("could not bind to the presence module API\n");
            return -1;
        }

        memset(&event, 0, sizeof(pres_ev_t));
        event.name = s_event_name;
        event.content_type = s_content_type;
        event.default_expires = 3600;
        event.type = PUBL_TYPE;
        event.req_auth = 0;

        if (pres.add_event(&event) < 0) {
            LM_ERR("could not add xcap-diff event to presence\n");
            return -1;
        }
    } else {
        LM_NOTICE("subscribing to the xcap-diff event is not available as the presence module is not loaded\n");
    }

    bind_pua = (bind_pua_t)find_export("bind_pua", 0);
    if (bind_pua) {
        if (bind_pua(&pua) < 0) {
            LM_ERR("could not bind to the pua module API\n");
            return -1;
        }

        if(pua.add_event(XCAPDIFF_EVENT, s_event_name.s, s_content_type.s, 0) < 0) {
            LM_ERR("could not add xcap-diff event to pua\n");
            return -1;
        }
    } else {
        LM_NOTICE("publishing of xcap-diff events is not available as the pua module is not loaded\n");
    }

    return 0;
}


