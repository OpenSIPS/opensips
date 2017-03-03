/**
 * $Id$
 *
 * Copyright (C) 2009 SIP-Router.org
 *
 * This file is part of opensips, a free SIP server. Ported from kamailio,
 * another free SIP server, in 2014.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*!
 * \file
 * \brief OpenSIPS topoh ::
 * \ingroup topoh
 * Module: \ref topoh
 */

#ifndef _TH_MSG_H_
#define _TH_MSG_H_

#include "../../parser/msg_parser.h"

int th_mask_via(struct sip_msg *msg);
int th_mask_callid(struct sip_msg *msg);
int th_mask_contact(struct sip_msg *msg);
int th_mask_record_route(struct sip_msg *msg);
int th_unmask_via(struct sip_msg *msg, str *cookie);
int th_unmask_callid(struct sip_msg *msg);
int th_flip_record_route(struct sip_msg *msg, int mode);
int th_unmask_ruri(struct sip_msg *msg);
int th_unmask_route(struct sip_msg *msg);
int th_unmask_refer_to(struct sip_msg *msg);
int th_update_hdr_replaces(struct sip_msg *msg);
char* th_msg_update(struct sip_msg *msg, unsigned int *olen);
int th_add_via_cookie(struct sip_msg *msg, struct via_body *via);
int th_add_hdr_cookie(struct sip_msg *msg);
struct hdr_field *th_get_hdr_cookie(struct sip_msg *msg);
int th_add_cookie(struct sip_msg *msg);
int th_route_direction(struct sip_msg *msg);
char* th_get_cookie(struct sip_msg *msg, int *clen);
int th_del_cookie(struct sip_msg *msg);
int th_skip_msg(struct sip_msg *msg);

#endif
