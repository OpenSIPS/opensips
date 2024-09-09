/*
 * Copyright (C) 2020 Sippy Software, Inc., http://www.sippysoft.com
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
 */

#ifndef _rtpproxy_vcmd_h
#define _rtpproxy_vcmd_h

struct rtpproxy_vcmd {
	struct iovec *vs;
	struct iovec *vu;
	int useritems;
};

#define RTPP_CMD_IOVEC(nitems, ...) \
	(struct iovec[nitems + 2]){{.iov_base = NULL /* cookie */}, __VA_ARGS__, \
	    {.iov_base = NULL /* terminator */}}
#define RTPP_CMD_IOVEC_STATIC(var, nitems, ...) \
	static struct iovec var[nitems + 2] = \
	    {{.iov_base = NULL /* cookie */}, __VA_ARGS__, {.iov_base = NULL /* terminator */}};

#define RTPP_VCMD_INIT(vcmd, nitems, ...) \
	(vcmd).vs = RTPP_CMD_IOVEC(nitems, __VA_ARGS__); \
	(vcmd).vu = (vcmd).vs + 1; \
	(vcmd).useritems = nitems; \

#define RTPP_VCMD_INIT_STATIC(vcmd, nitems, ...) \
	RTPP_CMD_IOVEC_STATIC(_var, nitems, __VA_ARGS__); \
	(vcmd).vs = _var; \
	(vcmd).vu = (vcmd).vs + 1; \
	(vcmd).useritems = nitems; \

#endif
