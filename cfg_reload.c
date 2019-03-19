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


#include "mem/mem.h"
#include "globals.h"
#include "route.h"
#include "cfg_pp.h"

int cfg_parse_only_routes = 0;


int reload_routing_script(void)
{
	struct os_script_routes *sr, *sr_bk;
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

	/* FIXME - the cfg path will be affected by daemonize and working dir,
	 * so we need full path */

	ret = parse_opensips_cfg( cfg_file, NULL/*preproc FIXME*/);

	cfg_parse_only_routes = 0;

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
	free_route_lists(sr);
	pkg_free(sr);
	sroutes = sr_bk;
	return -1;
}
