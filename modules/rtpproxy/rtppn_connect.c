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

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>

#include "../../mem/mem.h"

#include "rtpproxy.h"
#include "rtppn_connect.h"

static int try_connect(int s, const struct sockaddr *name, socklen_t namelen, int timeout)
{
	int oflags, nflags, cres, pres;
	struct pollfd pfd;

	oflags = fcntl(s, F_GETFL);
	if (oflags < 0)
		return -1;
	nflags = fcntl(s, F_SETFL, oflags | O_NONBLOCK);
	if (nflags < 0)
		return -1;

	cres = connect(s, name, namelen);
	if (cres < 0 && errno != EINPROGRESS)
		goto out;
	if (cres == 0)
		goto out;
	pfd.fd = s;
	pfd.events = POLLOUT;
	pres = poll(&pfd, 1, timeout);
	if (pres <= 0) {
		cres = -1;
	} else {
		cres = 0;
	}
out:
	fcntl(s, F_SETFL, oflags);
	return cres;
}

int connect_rtpp_node(struct rtpp_node *pnode)
{
	int n, s;
	char *cp, *hostname;
	struct addrinfo hints, *res;

	/*
	 * This is UDP, TCP, UDP6 or TCP6. Detect host and port; lookup host;
	 * do connect() in order to specify peer address
	 */
	hostname = (char*)pkg_malloc(sizeof(char) * (strlen(pnode->rn_address) + 1));
	if (hostname == NULL) {
		LM_ERR("no more pkg memory\n");
		goto e0;
	}
	strcpy(hostname, pnode->rn_address);

	cp = strrchr(hostname, ':');
	if (cp != NULL) {
		*cp = '\0';
		cp++;
	}
	if (cp == NULL || *cp == '\0')
		cp = DEFAULT_CPORT;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = 0;
	hints.ai_family = (pnode->rn_umode == CM_UDP6 || pnode->rn_umode == CM_TCP6) ? AF_INET6 : AF_INET;
	hints.ai_socktype = CM_STREAM(pnode) ? SOCK_STREAM : SOCK_DGRAM;
	if ((n = getaddrinfo(hostname, cp, &hints, &res)) != 0) {
		LM_ERR("%s\n", gai_strerror(n));
		goto e1;
	}

	s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (s == -1) {
		LM_ERR("can't create socket\n");
		goto e2;
	}
	if (CM_STREAM(pnode)) {
		n = try_connect(s, res->ai_addr, res->ai_addrlen, rtpproxy_tout);
	} else {
		n = connect(s, res->ai_addr, res->ai_addrlen);
	}
	if (n == -1) {
		LM_ERR("can't connect to a RTP proxy\n");
		goto e3;
	}
	memcpy(&pnode->addr.s, res->ai_addr, res->ai_addrlen);
	pkg_free(hostname);
	freeaddrinfo(res);
	LM_DBG("connected %s\n", pnode->rn_address);
	return s;
e3:
	close(s);
e2:
	freeaddrinfo(res);
e1:
	pkg_free(hostname);
e0:
	return -1;
}
