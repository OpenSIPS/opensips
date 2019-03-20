/*
 * OpenSIPS configuration file pre-processing
 *
 * Copyright (C) 2019 OpenSIPS Solutions
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */


#include <unistd.h>
#include <errno.h>

#include "mem/mem.h"
#include "globals.h"
#include "daemonize.h"
#include "route.h"
#include "cfg_pp.h"


int cfg_parse_only_routes = 0;


int reload_routing_script(void)
{
	struct os_script_routes *sr, *sr_bk;
	char * curr_wdir=NULL;
	int ret;

	sr = new_sroutes_holder();
	if (sr==NULL) {
		LM_ERR("failed to allocate a new script routes holder\n");
		return -1;
	}

	LM_INFO("reparsing routes from <%s> file\n",cfg_file);

	sr_bk = sroutes;
	sroutes = sr;

	/* parse, but only the routes */
	cfg_parse_only_routes = 1;

	/* switch to the startup working dir, to be sure the file pathname 
	 * (as given at startup via cli) still match */
	if (startup_wdir) {
		if ( (curr_wdir=getcwd(NULL,0))==NULL) {
			LM_ERR("failed to determin the working dir %d/%s\n", errno,
				strerror(errno));
			goto error;
		}
		if (chdir(startup_wdir)<0){
			LM_CRIT("Cannot chdir to %s: %s\n", startup_wdir, strerror(errno));
			goto error;
		}
	}

	ret = parse_opensips_cfg( cfg_file, preproc);

	cfg_parse_only_routes = 0;

	/* revert to the original working dir */
	if (curr_wdir) {
		if (chdir(curr_wdir)<0){
			LM_CRIT("Cannot chdir to %s: %s\n", curr_wdir, strerror(errno));
		}
		free(curr_wdir);
		curr_wdir=NULL;
	}



	if (ret<0) {
		LM_ERR("parsing failed, abording\n");
		goto error;
	}

	LM_INFO("fixing the loaded routes\n");

	if (fix_rls()<0) {
		LM_ERR("fixing routes failed, abording\n");
		goto error;
	}

	LM_INFO("we are all good !!!! \n");

	/* restore previous set of routes */
	sroutes = sr_bk;

	free_route_lists(sr);
	pkg_free(sr);

	return 0;
error:
	if (curr_wdir) free(curr_wdir);
	free_route_lists(sr);
	pkg_free(sr);
	sroutes = sr_bk;
	return -1;
}
