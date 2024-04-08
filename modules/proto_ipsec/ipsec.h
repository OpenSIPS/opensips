/*
 * Copyright (C) 2024 - OpenSIPS Solutions
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

#ifndef _IPSEC_H_
#define _IPSEC_H_

#include <libmnl/libmnl.h>
#include <linux/netlink.h>
#include <linux/xfrm.h>

#include "../../parser/parse_security.h"

enum ipsec_dir {
	IPSEC_POLICY_IN = XFRM_POLICY_IN,
	IPSEC_POLICY_OUT = XFRM_POLICY_OUT,
};

#define ipsec_socket mnl_socket

#include "../../str.h"
#include "../../socket_info.h"

struct ipsec_spi;
struct ipsec_endpoint {
	struct ip_addr ip;
	unsigned int spi_s, spi_c;
	unsigned short port_s, port_c;
};

struct ipsec_ctx {
	/* read-only values */
	struct ipsec_spi *spi_s, *spi_c;
	struct socket_info *server, *client;
	struct ipsec_algorithm_desc *alg, *ealg;
	struct ipsec_endpoint me;
	struct ipsec_endpoint ue;

	/* dynamic values - should be locked */
	gen_lock_t lock;
	int ref;
};

#define IPSEC_USER_SELECTOR 1387164160
#define IPSEC_POLICY_PRIORITY 1024

#define IPSEC_DEFAULT_MIN_SPI 65536
#define IPSEC_DEFAULT_MAX_SPI 262144

extern unsigned int ipsec_min_spi;
extern unsigned int ipsec_max_spi;

int ipsec_init(void);
void ipsec_destroy(void);
struct ipsec_socket *ipsec_new(void);
void ipsec_close(struct ipsec_socket *sock);
int ipsec_add_flow(struct ipsec_socket *sock, struct ipsec_ctx *ctx,
		str *ck, str *ik, enum ipsec_dir dir, int client);
void ipsec_rm_flow(struct ipsec_socket *sock, struct ipsec_ctx *ctx,
		enum ipsec_dir dir, int client);

/* ctx */
struct ipsec_ctx *ipsec_ctx_new(sec_agree_body_t *sa, struct ip_addr *ip,
		struct socket_info *ss, struct socket_info *sc);
void ipsec_ctx_push(struct ipsec_ctx *ctx);
struct ipsec_ctx *ipsec_ctx_get(void);

#endif /* _IPSEC_H_ */
