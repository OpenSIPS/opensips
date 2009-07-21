/*
 * $Id$
 *
 * Copyright (C) 2009 Irina Stanescu
 * Copyright (C) 2009 Voice System

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
 * --------
 * 2009-07-20    First version (Irina Stanescu)
 */

/*
 * This is an implementation of the generic AAA Interface.
 */

#include "../../sr_module.h"
#include "../../mem/mem.h"
#include "../../aaa/aaa.h"
#include "rad.h"

MODULE_VERSION

int mod_init(void);

int aaa_radius_bind_api(aaa_prot *rad_prot);

static cmd_export_t cmds[]= {
	{"aaa_bind_api",  (cmd_function) aaa_radius_bind_api,  0, 0, 0, 0},
	{ 0,      0,                 0,     0,         0,  0}
};



struct module_exports exports= {
	"aaa_radius",				/* module name */
	0,							/* dlopen flags */
	cmds,						/* exported functions */
	0,							/* exported parameters */
	0,							/* exported statistics */
	0,							/* exported MI functions */
	0,							/* exported pseudo-variables */
	0,							/* extra processes */
	(init_function) mod_init,	/* module initialization function */
	0, 							/* response handling function */
	0, 							/* destroy function */
	0                  			/* per-child init function */
};


int aaa_radius_bind_api(aaa_prot *rad_prot) {

	if (!rad_prot) {
		return -1;
	}

	memset(rad_prot, 0, sizeof(aaa_prot));

	rad_prot->create_aaa_message = rad_create_message;
	rad_prot->destroy_aaa_message = rad_destroy_message;
	rad_prot->send_aaa_request = rad_send_message;
	rad_prot->init_prot = rad_init_prot;
	rad_prot->dictionary_find = rad_find;
	rad_prot->avp_add = rad_avp_add;
	rad_prot->avp_get = rad_avp_get;

	return 0;
}


int mod_init(void) {

	LM_DBG("aaa_radius module was initiated\n");
	return 0;
}

