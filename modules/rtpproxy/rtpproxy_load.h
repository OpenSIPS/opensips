/*
 * Copyright (C) 2003-2008 Sippy Software, Inc., http://www.sippysoft.com
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
 * ---------
 * 2017-06-26	razvanc: Initial version
 */

#ifndef _RTPPROXY_LOAD_H_
#define _RTPPROXY_LOAD_H_

#include "../../sr_module.h"

struct rtpproxy_binds {
};

typedef int(*load_rtpproxy_f)(struct rtpproxy_binds *rtpb);
int load_rtpproxy(struct rtpproxy_binds *rtpb);

static inline int load_rtpproxy_api(struct rtpproxy_binds *rtpb)
{
	load_rtpproxy_f load_rtpproxy;

	/* import the rtpproxy auto-loading function */
	if ( !(load_rtpproxy=(load_rtpproxy_f)find_export("load_rtpproxy", 0, 0))) {
		LM_ERR("failed to import load_rtpproxy\n");
		return -1;
	}
	/* let the auto-loading function load all rtpproxy stuff */
	if (load_rtpproxy(rtpb) == -1)
		return -1;

	return 0;
}

#endif /* _RTPPROXY_LOAD_H_ */

