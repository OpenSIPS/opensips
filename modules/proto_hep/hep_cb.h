/*
 * Copyright (C) 2015 - OpenSIPS Solutions
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
 *
 * History:
 * -------
 *  2015-09-03  first version (Ionut Ionita)
 */
#ifndef HEP_CB_H
#define HEP_CB_H

#include "hep.h"
#include "../../sr_module.h"

enum homer_versions { HOMER5 = 5, HOMER6 = 6 };
typedef int (*hep_cb_t)(void);


/* in order to register a callback one must import hep.h header
 * to know the hep_desc structure in which you receive all hep
 * headers and also the sip payload */
typedef int (*register_hep_cb_t)(hep_cb_t cb);

/* export homer version
 * this will help in order to know table definitions and homer dependent stuff
 */
typedef int (*get_homer_version_t)(void);

/*
 * receive message in hep route
 * it receives the route id
 * the hep context must have been set when calling this function
 *
 */

typedef struct proto_hep_api {
	register_hep_cb_t	 register_hep_cb;
	get_hep_ctx_id_t	 get_hep_ctx_id;
	get_homer_version_t	 get_homer_version;
} proto_hep_api_t;



typedef int (*bind_proto_hep_t)(proto_hep_api_t* api);
int bind_proto_hep(proto_hep_api_t *api);
typedef int (*load_hep_f)(proto_hep_api_t *api);

int run_hep_cbs(void);
void free_hep_cbs(void);

static inline int load_hep_api(proto_hep_api_t* api )
{
	load_hep_f load_hep;

	/* import the TM auto-loading function */
	if ( !(load_hep=(load_hep_f)find_export("load_hep", 0))) {
		LM_ERR("failed to import load_hep\n");
		return -1;
	}
	/* let the auto-loading function load all TM stuff */
	if (load_hep( api )==-1)
		return -1;

	return 0;
}


#endif

