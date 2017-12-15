/*
 * Copyright (C) 2010 Sippy Software, Inc., http://www.sippysoft.com
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

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../../parser/msg_parser.h"
#include "../../msg_callbacks.h"
#include "../../proxy.h"
#include "../../mem/mem.h"

#include "rtpproxy.h"

void
rtpproxy_pre_fwd(struct sip_msg *msg, cb_type_t cb_type, void *mod_args, void *core_args)
{
    struct proxy_l *p;
    struct ip_addr ip;
    char *cp;
    struct force_rtpp_args *args;

    assert(cb_type == REQ_PRE_FORWARD);
    p = (struct proxy_l *)core_args;
    args = (struct force_rtpp_args *)mod_args;
    if (args->raddr.s != NULL)
        return;
    hostent2ip_addr(&ip, &p->host, p->addr_idx);
    cp = ip_addr2a(&ip);
    args->raddr.len = strlen(cp);
    if (ip.af == AF_INET) {
        args->raddr.s = pkg_malloc(args->raddr.len + 1);
        if (args->raddr.s == NULL) {
            LM_ERR("out of pkg memory\n");
            return;
        }
        sprintf(args->raddr.s, "%s", cp);
    } else {
        args->raddr.len += 2;
        args->raddr.s = pkg_malloc(args->raddr.len + 1);
        if (args->raddr.s == NULL) {
            LM_ERR("out of pkg memory\n");
            return;
        }
        sprintf(args->raddr.s, "[%s]", cp);
    }
    force_rtp_proxy_body(msg, args, NULL, NULL);
}

void
rtpproxy_pre_fwd_free(struct sip_msg *msg, cb_type_t cb_type, void *mod_args, void *core_args)
{
    struct force_rtpp_args *args;

    assert(cb_type == MSG_DESTROY);
    args = (struct force_rtpp_args *)mod_args;
    if (args->arg1 != NULL)
        pkg_free(args->arg1);
    if (args->arg2 != NULL)
        pkg_free(args->arg2);
    if (args->raddr.s != NULL)
        pkg_free(args->raddr.s);
    pkg_free(args);
}
