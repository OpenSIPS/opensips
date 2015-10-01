/*
 * Copyright (C) 2015 - OpenSIPS Foundation
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
 *
 * History:
 * -------
 *  2015-02-xx  first version (razvanc)
 */

#ifndef _WS_COMMON_DEFS_H_
#define _WS_COMMON_DEFS_H_

#include "../../net/net_tcp.h"

/* wrapper around tcp request to add ws info */
struct ws_req {
	struct tcp_req tcp;
	unsigned int op;
	unsigned int mask;
	unsigned int is_masked;
};


#endif /* _WS_COMMON_DEFS_H_ */
